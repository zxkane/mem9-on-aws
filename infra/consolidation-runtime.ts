import type {DbOutputs} from "./db";
import type {EcsOutputs} from "./ecs";
import type {MaintenanceIdentityOutputs} from "./namespace-identity";
import {accountId,applicationRegion,workloadImage} from "./ecr";
import {disableTaskContainerPseudoTerminal} from "./ecs-task-definition";
import {isConsolidationPreview,previewGeneration,previewConfiguration} from "../scripts/lib/consolidation-preview-config.mjs";

type SecretKind="config"|"planner"|"executor"|"backend"|"seed"|"targets"|"tenant";
export interface ConsolidationPreviewConfig {
  generation:string;
  database:string;
  values:Record<SecretKind,Output<string>>;
  arns:Record<SecretKind,Output<string>>;
}
export interface ConsolidationWorker {
  kind:"planner"|"executor";
  containerName:string;
  generation:Input<string>;
  production?:boolean;
  enabled?:Output<boolean>;
  admission?:Output<string>;
  image?:Input<string>;
  sourceTag?:string;
  task:sst.aws.Task;
}
export interface ConsolidationWorkerConfig {
  generation:Input<string>;
  database:Input<string>;
  arns:Record<'planner'|'executor'|'targets'|'tenant',Output<string>>;
  production?:boolean;
  enabled?:Output<boolean>;
  admission?:Output<string>;
  image?:Input<string>;
  sourceTag?:string;
}
export function consolidationPreviewConfig():ConsolidationPreviewConfig|undefined {
  if(!isConsolidationPreview($app.stage))return;
  const generation=previewGeneration($app.stage);
  const tags={Project:"mem9-on-aws",Stage:$app.stage,ManagedBy:"sst"};
  const tenant=new random.RandomPassword("ConsolidationPreviewTenant",{length:64,special:false});
  const shape=previewConfiguration($app.stage,generation,"shape-only");
  const values={} as Record<SecretKind,Output<string>>;
  values.config=tenant.result.apply(secret=>JSON.stringify(previewConfiguration($app.stage,generation,secret)));
  values.tenant=values.config.apply(raw=>JSON.parse(raw).tenantId);
  values.targets=values.config.apply(raw=>JSON.stringify(JSON.parse(raw).namespaces));
  for(const kind of ["planner","executor","backend","seed"] as const){
    const title=kind[0].toUpperCase()+kind.slice(1);
    const password=new random.RandomPassword(`ConsolidationPreview${title}Password`,{length:48,special:false});
    const salt=new random.RandomPassword(`ConsolidationPreview${title}Salt`,{length:32,special:false});
    values[kind]=$jsonStringify({username:shape.usernames[kind],password:password.result,salt:salt.result});
  }
  const arns={} as Record<SecretKind,Output<string>>;
  for(const kind of Object.keys(values) as SecretKind[]){
    const parameter=new aws.ssm.Parameter(`ConsolidationPreview${kind[0].toUpperCase()+kind.slice(1)}`,{
      name:`/mem9-on-aws/${$app.stage}/consolidation-preview/${["planner","executor","backend","seed"].includes(kind)?kind+"-credential":kind}`,
      type:"SecureString",value:values[kind],tags,
    });
    arns[kind]=parameter.arn;
  }
  return {generation,database:shape.database,values,arns};
}

export function continuousConsolidationTasks(ecs:EcsOutputs,db:DbOutputs,config:ConsolidationWorkerConfig,identity:MaintenanceIdentityOutputs):ConsolidationWorker[]{
  if(!isConsolidationPreview($app.stage)&&!($app.stage==='prod'&&config.production))throw Error("PreviewWorkersOnly");
  if(config.production&&$app.stage!=='prod')throw Error('ProductionWorkersOnly');
  const tags={Project:"mem9-on-aws",Stage:$app.stage,ManagedBy:"sst"};
  const trust=$jsonStringify({Version:"2012-10-17",Statement:[{Effect:"Allow",Principal:{Service:"ecs-tasks.amazonaws.com"},Action:"sts:AssumeRole",
    Condition:{StringEquals:{"aws:SourceAccount":accountId()},ArnLike:{"aws:SourceArn":$interpolate`arn:aws:ecs:${applicationRegion()}:${accountId()}:*`}}}]});
  return (["planner","executor"] as const).map(kind=>{
    const containerName=`Mem9Consolidation${kind==="planner"?"Planner":"Executor"}`;
    const secrets:Record<string,Output<string>>={MEM9_WORKER_TARGETS:config.arns.targets,
      [kind==="planner"?"MEM9_PLANNER_DB_SECRET":"MEM9_EXECUTOR_DB_SECRET"]:config.arns[kind]};
    if(kind==="executor"){
      secrets.MEM9_TENANT_ID=config.arns.tenant;
      secrets.MEM9_SERVICE_TRANSPORT_SIGNING_KEYS=identity.serviceParameterArns.consolidation;
    }
    const parameters=Object.values(secrets);
    const task=new sst.aws.Task(containerName,{
      cluster:ecs.cluster,architecture:"arm64",cpu:"0.5 vCPU",memory:"1 GB",
      image:config.production?config.image!:workloadImage("llm-proxy",process.env.MEM9_IMAGE_TAG||"latest"),entrypoint:["node"],command:["/app/scripts/consolidation-worker.mjs"],
      environment:{MEM9_STAGE:$app.stage,MEM9_WORKER_KIND:kind,MEM9_WORKER_GENERATION:config.generation,
        MEM9_DB_HOST:db.host,MEM9_DB_PORT:db.port.apply(String),MEM9_DB_NAME:config.database,
        MEM9_BASE_URL:$interpolate`http://${ecs.serviceDnsName}:8080`,
        MEM9_SERVICE_TRANSPORT_ISSUER:"maintenance:consolidation",
        MEM9_SERVICE_TRANSPORT_SIGNING_REVISION:identity.revision,
        MEM9_WORKER_SLICE_SECONDS:config.production?'180':kind==="executor"?"450":"180",
        ...(config.production?{MEM9_WORKER_MAX_SECONDS:kind==='planner'?'780':'240'}:{})},
      ssm:secrets,permissions:[],logging:{retention:"1 month"},
      transform:{taskDefinition:args=>{disableTaskContainerPseudoTerminal(args,containerName);args.tags={...(args.tags as Record<string,string> ?? {}),...tags};},
        taskRole:args=>{args.assumeRolePolicy=trust;},
        executionRole:args=>{
          args.assumeRolePolicy=trust;
          // Replace SST's wildcard secret reader, retaining its ECR/log baseline.
          args.inlinePolicies=[{name:"WorkerParameters",policy:$jsonStringify({Version:"2012-10-17",Statement:[
            {Effect:"Allow",Action:["ssm:GetParameters"],Resource:parameters},
            {Effect:"Allow",Action:["kms:Decrypt"],Resource:"*",Condition:{StringEquals:{"kms:ViaService":$interpolate`ssm.${applicationRegion()}.amazonaws.com`,
              "kms:EncryptionContext:PARAMETER_ARN":parameters}}},
          ]})}];
        }},
    });
    return {kind,containerName,generation:config.generation,production:config.production,enabled:config.enabled,admission:config.admission,image:config.image,sourceTag:config.sourceTag,task};
  });
}
