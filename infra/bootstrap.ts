/**
 * `bootstrap` stack — the one-shot schema-bootstrap ECS Task (ARCHITECTURE.md §8).
 *
 * mem9 does NOT create the PG `memories` table on the postgres backend — it only
 * VALIDATES `memories.app_id` + `idx_app` at startup and errors if missing
 * (docs/mem9-facts.md). So before mnemo-server can serve list/search we must
 * apply pgvector + the memories(vector 1024) schema + seed one tenant. This stack
 * defines a short-lived Fargate Task (docker/bootstrap/) that does exactly that,
 * idempotently.
 *
 * RUN-ON-DEPLOY: SST's `sst.aws.Task` defines the task definition but does not run
 * it automatically (it exposes `task.run()` for invocation from a Function). To
 * keep the run observable + out of the Pulumi graph (no local-exec provider), the
 * CI workflow runs it via `aws ecs run-task` AFTER `sst deploy` and waits for it
 * to exit 0. This stack exports the task ARN + network config to SSM so CI (and a
 * manual operator) can run it deterministically.
 *
 * The tenant id (== X-API-Key) is supplied via MEM9_TENANT_ID from the shared
 * stable identity in infra/tenant-identity.ts, so re-runs reuse the same key.
 */

import type { RuntimeCredentials } from "./runtime-credentials";
import type { DbOutputs } from "./db";
import { workloadImage, accountId, applicationRegion } from "./ecr";
import {execFileSync} from 'node:child_process';
import {ECSClient,DescribeTaskDefinitionCommand} from '@aws-sdk/client-ecs';
import {previewBootstrapContainer,previewBootstrapRegistration,previewRegistrationFromProviderArgs,buildNonrootPreviewPurposeMap} from '../scripts/lib/nonroot-preview-source.mjs';
import {parseNonrootJson} from '../scripts/lib/production-nonroot-contracts.mjs';
import {applyProductionNonrootTask,verifiedProductionNonrootTaskArn} from './nonroot-task-definition';
import type {PreviewBootstrapPurpose,NonrootPreviewScope,NonrootPreviewMapInput} from '../scripts/lib/nonroot-preview-source.mjs';
import { resolveVpc } from "./vpc";
import type { TenantIdentityOutputs } from "./tenant-identity";
import type { CognitoOutputs } from "./cognito";
import type { AuthConfig } from "./auth-config";
import type { ConsolidationPreviewConfig } from "./consolidation-runtime";
import type {ProductionRuntimeResources} from "./production-runtime";
import {protectLegacyRuntimeCredentials} from "./production-runtime";

const IMAGE_TAG = process.env.MEM9_IMAGE_TAG || "latest";

export interface BootstrapOutputs {
  taskDefinitionArn: Output<string>;
  previewPurposeBindings?:Output<string>;
}

function previewSourceTree():string {
  // This is the actual reviewed checkout identity, never a caller-supplied hash.
  execFileSync('git',['ls-files','--error-unmatch','infra/bootstrap.ts','scripts/lib/nonroot-preview-source.mjs'],{stdio:'pipe',timeout:10000});
  execFileSync('git',['diff','--quiet'],{stdio:'pipe',timeout:10000});
  execFileSync('git',['diff','--cached','--quiet'],{stdio:'pipe',timeout:10000});
  const tree=execFileSync('git',['rev-parse','HEAD^{tree}'],{encoding:'utf8',timeout:10000}).trim();
  if(!/^[a-f0-9]{40}$/.test(tree))throw Error('NonrootPreviewSource');return tree;
}

/**
 * @param cluster the ECS cluster from ecs() (bootstrap runs in the same cluster,
 *   subnets, and task SG so it reaches Aurora through the same 5432 path).
 * @param dbOut db()'s Outputs (Aurora writer host/port/db + the DB secret ARN;
 *   no RDS Proxy — see infra/db.ts).
 * @param identity stable tenant identity shared with mnemo-server and Gateway.
 */
export function bootstrap(
  cluster: sst.aws.Cluster,
  dbOut: DbOutputs,
  identity: TenantIdentityOutputs,
  cognito: CognitoOutputs | undefined,
  auth?: AuthConfig,
  consolidationPreview?: ConsolidationPreviewConfig,
  runtime?: RuntimeCredentials,
  production?: ProductionRuntimeResources,
): BootstrapOutputs {
  const prefix = `/mem9-on-aws/${$app.stage}`;
  const tags = { Project: "mem9-on-aws", Stage: $app.stage, ManagedBy: "sst" };
  const { privateSubnetIds } = resolveVpc();
  const region = aws.getRegionOutput().name;
  const [previewAlpha, previewBeta] = cognito?.previewNamespaceClients ?? [];
  const previewNamespaceFixtures =
    !auth?.oidc && cognito?.previewNamespaceClients.length === 2
      ? {
          MEM9_PREVIEW_NAMESPACE_DEFAULT_CLIENT_ID: cognito.clientId,
          MEM9_PREVIEW_NAMESPACE_ALPHA_CLIENT_ID: previewAlpha.clientId,
          MEM9_PREVIEW_NAMESPACE_ALPHA_SLUG: previewAlpha.namespaceSlug,
          MEM9_PREVIEW_NAMESPACE_ALPHA_GROUP: previewAlpha.cognitoGroup,
          MEM9_PREVIEW_NAMESPACE_BETA_CLIENT_ID: previewBeta.clientId,
          MEM9_PREVIEW_NAMESPACE_BETA_SLUG: previewBeta.namespaceSlug,
          MEM9_PREVIEW_NAMESPACE_BETA_GROUP: previewBeta.cognitoGroup,
        }
      : undefined;

  const numericPreview=/^pr-[1-9][0-9]*$/.test($app.stage);
  let image=workloadImage("bootstrap",IMAGE_TAG);
  if(numericPreview){
    if(!/^pr-[a-f0-9]{7}$/.test(IMAGE_TAG))throw Error('NonrootPreviewImageTag');
    image=aws.ecr.getImageOutput({repositoryName:'mem9-on-aws/preview/bootstrap',imageTag:IMAGE_TAG,registryId:accountId(),region:applicationRegion()}).imageDigest.apply(digest=>{
      if(!/^sha256:[a-f0-9]{64}$/.test(digest))throw Error('NonrootPreviewImageDigest');
      return $interpolate`${accountId()}.dkr.ecr.${applicationRegion()}.amazonaws.com/mem9-on-aws/preview/bootstrap@${digest}`;
    });
  }
  const defaultPurpose:PreviewBootstrapPurpose=production?.active?'bootstrap-runtime-verify':runtime?'bootstrap-runtime-bootstrap':'bootstrap-schema-seed';
  const previewPurposes:PreviewBootstrapPurpose[]=[defaultPurpose];
  if(runtime&&!production?.active){
    previewPurposes.push('bootstrap-runtime-verify');
    if(runtime.probeParameterArn)previewPurposes.push('bootstrap-admin-probe','bootstrap-admin-probe-cleanup');
  }
  if(consolidationPreview&&!production?.active)previewPurposes.push('preview-fixture-setup','preview-fixture-pause','preview-fixture-verify-planned','preview-fixture-verify-executed','preview-fixture-verify-repeated');
  let previewGenerated:Output<string>|undefined;

  // The one-shot task. arm64, sized small (psql + jq are light — the DDL is
  // trivial). Injects the DB pieces + the DB secret (JSON {username,password}) +
  // the tenant id. The entrypoint applies schema.sql then seeds the tenant.
  const task = new sst.aws.Task("Mem9Bootstrap", {
    cluster,
    architecture: "arm64",
    cpu: "0.25 vCPU",
    memory: "0.5 GB",
    image,
    environment: {
      // Workflow compatibility marker. The PR deploy path inspects an existing
      // task definition before deciding whether it can safely resume namespace
      // cutover in required mode or must first deploy this compatible revision.
      MEM9_NAMESPACE_BOOTSTRAP_VERSION: "1",
      ...(runtime ? {MEM9_RUNTIME_BOOTSTRAP_VERSION: "1"} : {}),
      ...(production?.active ? {MEM9_BOOTSTRAP_OPERATION:"runtime-verify"} : {}),
      MEM9_DB_HOST: dbOut.host,
      MEM9_DB_PORT: dbOut.port.apply((p) => String(p)),
      MEM9_DB_NAME: dbOut.database,
      MEM9_STAGE: $app.stage,
      MEM9_AUTH_MODE: auth?.mode ?? "managed",
      MEM9_COGNITO_ISSUER: auth?.oidc?.issuer ?? cognito!.issuer,
      // External providers own user/group lifecycle. Never pass the retained
      // legacy pool here alongside the new issuer to an operator command.
      MEM9_COGNITO_USER_POOL_ID: auth?.oidc ? "" : cognito!.userPoolId,
      AWS_REGION: region,
      ...(!production?.active ? previewNamespaceFixtures ?? {} : {}),
      ...(consolidationPreview&&!production?.active ? {MEM9_PREVIEW_GENERATION: consolidationPreview.generation} : {}),
    },
    // Secret injection (== ECS secrets valueFrom): the DB creds JSON + the tenant
    // id, both resolved from Secrets Manager at task start, never literals.
    ssm: {
      MEM9_DB_SECRET: production?.active ? production.administratorArn : dbOut.secretArn,
      ...(runtime ? {MEM9_RUNTIME_DB_SECRET: runtime.parameterArn} : {}),
      ...(runtime?.probeParameterArn&&!production?.active ? {MEM9_PROBE_ADMIN_CREDENTIAL: runtime.probeParameterArn} : {}),
      MEM9_TENANT_ID: identity.tenantSecretArn,
      ...(consolidationPreview&&!production?.active ? {
        MEM9_CONSOLIDATION_PREVIEW_CONFIG: consolidationPreview.arns.config,
        MEM9_PREVIEW_PLANNER_CREDENTIAL: consolidationPreview.arns.planner,
        MEM9_PREVIEW_EXECUTOR_CREDENTIAL: consolidationPreview.arns.executor,
        MEM9_PREVIEW_BACKEND_CREDENTIAL: consolidationPreview.arns.backend,
        MEM9_PREVIEW_SEED_CREDENTIAL: consolidationPreview.arns.seed,
      } : {}),
    },
    logging: { retention: "1 month" },
    transform: {
      taskDefinition: (args) => {
        args.tags = { ...(args.tags ?? {}), ...tags };
        if(production?.active)args.executionRoleArn=production.bootstrapExecutionRoleArn;
        if(numericPreview){
          // SST adds these after the transform; capture the exact expected tags.
          args.tags={...(args.tags ?? {}),'sst:app':$app.name,'sst:stage':$app.stage};
          args.trackLatest=false;
          // Each revision has a fixed purpose. Only its declared operation env
          // changes; roles, secrets and the original application remain shared.
          const raw=args.containerDefinitions as Output<string>;
          if(!raw||typeof raw.apply!=='function')throw Error('NonrootPreviewContainerOutput');
          args.containerDefinitions=raw.apply(text=>{
            const values=parseNonrootJson(text);
            if(!Array.isArray(values)||values.length!==1)throw Error('NonrootPreviewContainerSet');
            return JSON.stringify([previewBootstrapContainer(values[0],defaultPurpose,$app.stage)]);
          });
          previewGenerated=$jsonStringify({...args});
        }
        applyProductionNonrootTask(args,'bootstrap');
      },
      ...(production?{executionRole:(args:Record<string,unknown>)=>{
        if(!production.active){protectLegacyRuntimeCredentials(args,true);return;}
        args.inlinePolicies=[{name:"ProductionCredentialFence",policy:JSON.stringify({Version:"2012-10-17",Statement:[{
          Effect:"Deny",Action:["ssm:GetParameter","ssm:GetParameters","ssm:GetParametersByPath","secretsmanager:GetSecretValue","kms:Decrypt"],Resource:"*"}]})}];
      }}:{}),
      ...(production?{taskRole:(args:Record<string,unknown>)=>protectLegacyRuntimeCredentials(args,true)}:{}),
    },
  });
  const taskDefinitionArn=verifiedProductionNonrootTaskArn(task.taskDefinition,'bootstrap');

  let previewPurposeBindings:Output<string>|undefined;
  if(numericPreview){
    // The underlying task output resolves after SST has invoked its transform.
    // Reuse that exact family/roles/secret set for every additional revision.
    previewPurposeBindings=task.nodes.taskDefinition.apply(definition=>{
      if(!previewGenerated)throw Error('NonrootPreviewGeneratedDefinitionMissing');
      const scope=$jsonStringify({stage:$app.stage,account:accountId(),region:applicationRegion()}).apply(raw=>({...JSON.parse(raw),sourceTree:previewSourceTree()}) as NonrootPreviewScope);
      return previewGenerated.apply(raw=>scope.apply(context=>{
        const original=previewRegistrationFromProviderArgs(JSON.parse(raw));
        // ECS revisions in this family must register sequentially, including
        // the original definition owned by SST.
        let previousDefinition=definition;
        const records=previewPurposes.map(purpose=>{
          const registration=purpose===defaultPurpose?original:previewBootstrapRegistration(original,purpose,context);
          const {containerDefinitions,tags:registrationTags,...fields}=registration;
          let arn=task.taskDefinition;
          if(purpose!==defaultPurpose){
            const additional=new aws.ecs.TaskDefinition('Mem9BootstrapPurpose'+purpose.split('-').map(p=>p[0].toUpperCase()+p.slice(1)).join(''),{
              ...fields,containerDefinitions:JSON.stringify(containerDefinitions),
              tags:Object.fromEntries((registrationTags as Array<{key:string;value:string}>).map(t=>[t.key,t.value])),trackLatest:false,skipDestroy:true,
            } as ConstructorParameters<typeof aws.ecs.TaskDefinition>[1],{dependsOn:[previousDefinition]});
            previousDefinition=additional;arn=additional.arn;
          }
          return arn.apply(async taskDefinition=>{
            const client=new ECSClient({region:context.region});
            try{
              const result=await client.send(new DescribeTaskDefinitionCommand({taskDefinition,include:['TAGS']}),{abortSignal:AbortSignal.timeout(30000)});
              // Serialize only the SDK's data members; this retains every task
              // field and tag, including service-derived attribute sets.
              const observation=JSON.parse(JSON.stringify({taskDefinition:result.taskDefinition,tags:result.tags}));
              return {purpose,registration,observation};
            }finally{client.destroy();}
          });
        });
        return $jsonStringify(records).apply(rawRecords=>JSON.stringify(buildNonrootPreviewPurposeMap({scope:context,defaultPurpose,records:JSON.parse(rawRecords)} as NonrootPreviewMapInput)));
      }));
    });
    new aws.ssm.Parameter('BootstrapPurposeBindings',{name:`${prefix}/bootstrap/purpose-bindings`,type:'String',value:previewPurposeBindings,tags});
  }

  // Export the run inputs so CI can `aws ecs run-task` after deploy. The cluster
  // name + task-def ARN + the task SG + private subnets are all the network config
  // RunTask needs (awsvpc mode, no public IP — bootstrap reaches Aurora + pulls
  // the image over the private subnets' NAT/ECR path).
  new aws.ssm.Parameter("BootstrapTaskDefArn", {
    name: `${prefix}/bootstrap/task-def-arn`,
    type: "String",
    value: taskDefinitionArn,
    tags,
  });
  new aws.ssm.Parameter("BootstrapClusterName", {
    name: `${prefix}/bootstrap/cluster-name`,
    type: "String",
    value: cluster.nodes.cluster.name,
    tags,
  });
  new aws.ssm.Parameter("BootstrapTaskSgId", {
    name: `${prefix}/bootstrap/task-sg-id`,
    type: "String",
    value: dbOut.taskSecurityGroupId,
    tags,
  });
  new aws.ssm.Parameter("BootstrapSubnetIds", {
    name: `${prefix}/bootstrap/subnet-ids`,
    type: "StringList",
    value: privateSubnetIds.apply((ids) => ids.join(",")),
    tags,
  });

  return {
    taskDefinitionArn,
    ...(previewPurposeBindings?{previewPurposeBindings}:{}),
  };
}
