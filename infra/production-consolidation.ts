import {createHash} from 'node:crypto';
import {accountId,applicationRegion,pinnedProductionImage,selectedDataSourceTag,selectedDataRelease} from './ecr';
import type {VerifiedDataRelease} from '../scripts/lib/production-data-release.mjs';
import type {ProductionRuntimeResources} from './production-runtime';
import type {TenantIdentityOutputs} from './tenant-identity';
import type {ConsolidationWorkerConfig} from './consolidation-runtime';
import type {DbOutputs} from './db';
import type {EcsOutputs} from './ecs';
import {productionArtifactAdmission} from '../scripts/lib/production-artifacts.mjs';
import {runtimeTaskTrust,runtimeExecutionPolicy} from './production-runtime';
import {resolveVpc} from './vpc';
import {applyProductionNonrootTask,verifiedProductionNonrootTaskArn} from './nonroot-task-definition';

export interface ProductionConsolidationConfig extends ConsolidationWorkerConfig {
  production:true;
  enabled:Output<boolean>;
  executionEnabled:true;
  admission:Output<string>;
  image:Output<string>;
  operatorImage:Output<string>;
  sourceTag:string|Output<string>;
  controlSourceTag:string;
  dataRelease?:Output<VerifiedDataRelease&{parameterVersion:number}>;
  usernames:{planner:string;executor:string};
}

export function productionConsolidationOperators(ecs:EcsOutputs,db:DbOutputs,runtime:ProductionRuntimeResources,config:ProductionConsolidationConfig){
  if($app.stage!=='prod'||runtime.mode!=='active')throw Error('ProductionWorkerOperatorRequiresRuntime');
  const tags={Project:'mem9-on-aws',Stage:'prod',ManagedBy:'sst'};
  const reportParameters=Array.from({length:4},(_,index)=>new aws.ssm.Parameter(`ProductionCanaryReport${index}`,{
    name:`/mem9-on-aws/prod/consolidation-runtime/canary-report-${index}`,type:'SecureString',value:'-',tags,
  }));
  const tasks=Object.fromEntries((['provision','control','promotion'] as const).map(kind=>{
    const name=kind==='provision'?'ProdMem9Bootstrap':kind==='promotion'?'PromoteMem9Bootstrap':'ControlMem9Bootstrap';
    const secrets:Record<string,Output<string>>={MEM9_DB_SECRET:runtime.administratorArn};
    if(kind==='provision')Object.assign(secrets,{MEM9_PLANNER_DB_SECRET:config.arns.planner,MEM9_EXECUTOR_DB_SECRET:config.arns.executor,MEM9_WORKER_TARGETS:config.arns.targets});
    else if(kind==='promotion')reportParameters.forEach((parameter,index)=>{secrets[`MEM9_CANARY_REPORT_${index}`]=parameter.arn;});
    const task=new sst.aws.Task(name,{
      cluster:ecs.cluster,architecture:'arm64',cpu:'0.5 vCPU',memory:'1 GB',
      image:config.operatorImage,entrypoint:['node'],command:['/bootstrap/operator/scripts/production-consolidation-operator.mjs'],
      environment:{MEM9_STAGE:'prod',AWS_REGION:applicationRegion(),MEM9_DB_HOST:db.host,MEM9_DB_PORT:db.port.apply(String),MEM9_DB_NAME:db.database,
        MEM9_WORKER_GENERATION:config.generation,MEM9_PRODUCTION_WORKER_OPERATOR:kind,
        MEM9_WORKER_IMAGE:config.image,MEM9_WORKER_SOURCE_TAG:config.sourceTag,MEM9_CONTROL_SOURCE_TAG:config.controlSourceTag,
        MEM9_RETAINED_DATA_RELEASE_HASH:config.dataRelease?config.dataRelease.apply(value=>value.hash):'none',
        MEM9_RETAINED_DATA_RELEASE_VERSION:config.dataRelease?config.dataRelease.apply(value=>String(value.parameterVersion)):'0',
        MEM9_RETAINED_DATA_RELEASE_EXPIRES_MS:config.dataRelease?config.dataRelease.apply(value=>String(value.data.expiresMs)):'0'},ssm:secrets,permissions:[],logging:{retention:'1 month'},
      transform:{taskRole:args=>{args.assumeRolePolicy=$jsonStringify(runtimeTaskTrust());},
        executionRole:args=>{args.assumeRolePolicy=$jsonStringify(runtimeTaskTrust());args.inlinePolicies=[{name:'ProductionWorkerOperator',policy:$jsonStringify(runtimeExecutionPolicy(Object.values(secrets),[]))}];},
        taskDefinition:args=>{args.tags={...(args.tags??{}),...tags};applyProductionNonrootTask(args,kind);}},
    });
    return [kind,{taskDefinition:verifiedProductionNonrootTaskArn(task.taskDefinition,kind),containerName:name,image:config.operatorImage}];
  }));
  new aws.ssm.Parameter('ProductionWorkerOperatorManifest',{name:'/mem9-on-aws/prod/consolidation-runtime/operator-manifest',type:'SecureString',tags,
    value:$jsonStringify({version:config.dataRelease?3:1,stage:'prod',region:applicationRegion(),account:accountId(),cluster:ecs.clusterName,clusterArn:ecs.cluster.nodes.cluster.arn,
      subnets:resolveVpc().privateSubnetIds,securityGroup:db.taskSecurityGroupId,generation:config.generation,sourceTag:config.sourceTag,workerImage:config.image,
      controlSourceTag:config.controlSourceTag,...(config.dataRelease?{
        dataReleaseHash:config.dataRelease.apply(value=>value.hash),dataReleaseParameter:'/mem9-on-aws/prod/consolidation-runtime/data-release',
        dataReleaseParameterVersion:config.dataRelease.apply(value=>value.parameterVersion)}:{}),
      host:db.host,port:db.port,database:db.database,administratorCredential:runtime.administratorArn,
      plannerCredential:config.arns.planner,executorCredential:config.arns.executor,targetsParameter:config.arns.targets,operators:tasks})});
}

export function productionConsolidationConfig(runtime:ProductionRuntimeResources|undefined,identity:TenantIdentityOutputs,db:DbOutputs):ProductionConsolidationConfig|undefined {
  if($app.stage!=='prod'||runtime?.mode!=='active')return;
  const tags={Project:'mem9-on-aws',Stage:'prod',ManagedBy:'sst'},prefix='/mem9-on-aws/prod/consolidation-runtime';
  const controlSourceTag=process.env.MEM9_IMAGE_TAG||'',sourceTag=selectedDataSourceTag(controlSourceTag),dataRelease=selectedDataRelease();
  const image=pinnedProductionImage('llm-proxy',controlSourceTag),operatorImage=pinnedProductionImage('bootstrap',controlSourceTag);
  const enabled=new sst.Secret('ProductionConsolidationEnabled','0').value.apply(value=>{
    if(!['0','1'].includes(value))throw Error('InvalidProductionConsolidationOptIn');return value==='1';
  });
  const configuredAdmission=new sst.Secret('ProductionConsolidationAdmission','unverified').value;
  const admission=enabled.apply(running=>configuredAdmission.apply(value=>{
    if((running&&!/^[a-f0-9]{64}$/.test(value))||(!running&&value!=='unverified'&&!/^[a-f0-9]{64}$/.test(value)))throw Error('InvalidProductionConsolidationAdmission');
    return value==='unverified'?value:image.apply(uri=>typeof sourceTag==='string'?productionArtifactAdmission(value,sourceTag,uri):
      sourceTag.apply(tag=>productionArtifactAdmission(value,tag,uri)));
  }));
  const generation=new random.RandomId('ProductionConsolidationGeneration',{byteLength:32});
  const usernames={planner:'mem9_planner_'+createHash('sha256').update('prod').digest('hex').slice(0,12),
    executor:'mem9_executor_'+createHash('sha256').update('prod').digest('hex').slice(0,12)};
  const credentials={} as Record<'planner'|'executor',Output<string>>;
  for(const kind of ['planner','executor'] as const){
    const title=kind[0].toUpperCase()+kind.slice(1);
    const password=new random.RandomPassword(`Production${title}Password`,{length:48,special:false});
    const salt=new random.RandomPassword(`Production${title}Salt`,{length:32,special:false});
    credentials[kind]=new aws.ssm.Parameter(`Production${title}Credential`,{name:prefix+'/'+kind+'-credential',type:'SecureString',tags,
      value:$jsonStringify({username:usernames[kind],password:password.result,salt:salt.result})}).arn;
  }
  new aws.ssm.Parameter('ProductionWorkerGeneration',{name:prefix+'/generation',type:'SecureString',value:generation.hex,tags});
  // Reuse the canonical tenant identity through the same SSM injection path as
  // preview workers. No independent client/key or wider SecretARN boundary.
  const tenant=new aws.ssm.Parameter('ProductionExecutorTenant',{name:prefix+'/tenant',type:'SecureString',
    value:identity.tenantSecretArn.apply(()=>identity.tenantId),tags});
  // HTTP execution still requires SQL admission. Recurring deliveries stay
  // disabled until the real canary is promoted with its new admission token.
  return {production:true,enabled,executionEnabled:true,admission,image,operatorImage,sourceTag,controlSourceTag,dataRelease,generation:generation.hex,database:db.database,usernames,
    arns:{...credentials,tenant:tenant.arn,
      targets:$interpolate`arn:aws:ssm:${applicationRegion()}:${accountId()}:parameter/mem9-on-aws/prod/maintenance/targets`}};
}
