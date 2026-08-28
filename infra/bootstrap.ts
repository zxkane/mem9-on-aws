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

import type { DbOutputs } from "./db";
import { ecrImage } from "./ecr";
import { resolveVpc } from "./vpc";
import type { TenantIdentityOutputs } from "./tenant-identity";
import type { CognitoOutputs } from "./cognito";

const IMAGE_TAG = process.env.MEM9_IMAGE_TAG || "latest";

export interface BootstrapOutputs {
  taskDefinitionArn: Output<string>;
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
  cognito: CognitoOutputs,
): BootstrapOutputs {
  const prefix = `/mem9-on-aws/${$app.stage}`;
  const tags = { Project: "mem9-on-aws", Stage: $app.stage, ManagedBy: "sst" };
  const { privateSubnetIds } = resolveVpc();
  const region = aws.getRegionOutput().name;
  const [previewAlpha, previewBeta] = cognito.previewNamespaceClients;
  const previewNamespaceFixtures =
    cognito.previewNamespaceClients.length === 2
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

  const image = ecrImage("mem9-on-aws/bootstrap", IMAGE_TAG);

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
      MEM9_DB_HOST: dbOut.host,
      MEM9_DB_PORT: dbOut.port.apply((p) => String(p)),
      MEM9_DB_NAME: dbOut.database,
      MEM9_STAGE: $app.stage,
      MEM9_COGNITO_ISSUER: cognito.issuer,
      MEM9_COGNITO_USER_POOL_ID: cognito.userPoolId,
      AWS_REGION: region,
      ...(previewNamespaceFixtures ?? {}),
    },
    // Secret injection (== ECS secrets valueFrom): the DB creds JSON + the tenant
    // id, both resolved from Secrets Manager at task start, never literals.
    ssm: {
      MEM9_DB_SECRET: dbOut.secretArn,
      MEM9_TENANT_ID: identity.tenantSecretArn,
    },
    ...(previewNamespaceFixtures
      ? {
          permissions: [
            {
              actions: [
                "cognito-idp:CreateGroup",
                "cognito-idp:ListGroups",
                "cognito-idp:UpdateGroup",
              ],
              resources: [cognito.userPoolArn],
            },
          ],
        }
      : {}),
    logging: { retention: "1 month" },
    transform: {
      taskDefinition: (args) => {
        args.tags = { ...(args.tags ?? {}), ...tags };
      },
    },
  });

  // Export the run inputs so CI can `aws ecs run-task` after deploy. The cluster
  // name + task-def ARN + the task SG + private subnets are all the network config
  // RunTask needs (awsvpc mode, no public IP — bootstrap reaches Aurora + pulls
  // the image over the private subnets' NAT/ECR path).
  new aws.ssm.Parameter("BootstrapTaskDefArn", {
    name: `${prefix}/bootstrap/task-def-arn`,
    type: "String",
    value: task.taskDefinition,
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
    taskDefinitionArn: task.taskDefinition,
  };
}
