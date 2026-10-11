import type {ConsolidationPreviewConfig} from './consolidation-runtime';
import type {EcsOutputs} from './ecs';
import type {DbOutputs} from './db';
import type {ProductionRuntimeResources} from './production-runtime';
import {accountId,applicationRegion,selectedDataRelease} from './ecr';
import {resolveVpc} from './vpc';
import {isConsolidationPreview,validatePreviewContext} from '../scripts/lib/consolidation-preview-config.mjs';
import {POST_RUNTIME_OPERATOR,POST_RUNTIME_PURPOSES,postRuntimeTaskTrust,postRuntimeExecutionPolicy,postRuntimeCredentialReferences,postRuntimeOperatorEnvironment,bindPostRuntimePurposeMap} from '../scripts/lib/post-runtime-preview-route.mjs';
import {controlLaunchPolicy} from '../scripts/lib/production-nonroot-launch.mjs';
import {ECSClient,DescribeTaskDefinitionCommand} from '@aws-sdk/client-ecs';
import {applyNonrootControlTask} from './nonroot-task-definition';
import {previewRegistrationFromProviderArgs} from '../scripts/lib/nonroot-preview-source.mjs';
import {parseNonrootJson} from '../scripts/lib/production-nonroot-contracts.mjs';

export function verifiedPostRuntimePreview(stage:string,context:{kind:string;runtimeNonce:string},generation:string):Output<any>{
  if(!isConsolidationPreview(stage))throw Error('InvalidPostRuntimePreviewContext');
  validatePreviewContext(context);
  const release=selectedDataRelease();if(!release)throw Error('RetainedPreviewReleaseRequired');
  const region=applicationRegion(),prefix=`/mem9-on-aws/${stage}/runtime/`;
  const parameter=(name:string)=>aws.ssm.getParameterOutput({name:prefix+name,region,withDecryption:true}).apply(value=>value.value);
  return $jsonStringify({account:accountId(),region,runtime:parameter('production-state'),manifest:parameter('production-manifest'),release:release.apply(value=>value.data)}).apply(raw=>{
    const value=JSON.parse(raw);value.runtime=JSON.parse(value.runtime);value.manifest=JSON.parse(value.manifest);
    const {runtime,manifest,release:data}=value;
    if(runtime.nonce!==context.runtimeNonce||runtime.stage!==stage||runtime.phase!=='complete'||runtime.status!=='running'||
      manifest.mode!=='active'||manifest.stage!==stage||manifest.account!==value.account||manifest.region!==value.region||
      data.stage!==stage||data.account!==value.account||data.region!==value.region||data.runtimeNonce!==context.runtimeNonce||
      data.generation!==generation||!/^[a-f0-9]{40}$/.test(data.controlSourceTree??''))throw Error('InvalidPostRuntimePreviewContext');
    return {...value,controlSourceTree:data.controlSourceTree};
  });
}

export function postRuntimePreviewOperator(ecs:EcsOutputs,db:DbOutputs,config:ConsolidationPreviewConfig|undefined,runtime:ProductionRuntimeResources|undefined){
  if(!config?.context)return;
  const stage=$app.stage;
  if(!isConsolidationPreview(stage)||runtime?.mode!=='active'||!config.verification)throw Error('InvalidPostRuntimePreviewContext');
  const tag=process.env.MEM9_IMAGE_TAG;if(!/^pr-[a-f0-9]{7}$/.test(tag??''))throw Error('InvalidPostRuntimePreviewImage');
  const region=applicationRegion(),account=accountId(),tags={Project:'mem9-on-aws',Stage:stage,ManagedBy:'sst'};
  const image=aws.ecr.getImageOutput({repositoryName:'mem9-on-aws/preview/bootstrap',imageTag:tag!,registryId:account,region});
  const key=aws.kms.getKeyOutput({keyId:'alias/aws/ssm',region});
  const references={MEM9_DB_SECRET:runtime.administratorArn,MEM9_CONSOLIDATION_PREVIEW_CONFIG:config.arns.config,
    MEM9_PREVIEW_PLANNER_CREDENTIAL:config.arns.planner,MEM9_PREVIEW_EXECUTOR_CREDENTIAL:config.arns.executor,
    MEM9_PREVIEW_BACKEND_CREDENTIAL:config.arns.backend,MEM9_PREVIEW_SEED_CREDENTIAL:config.arns.seed};
  const inputs=$jsonStringify({proof:config.verification,credentials:references,kmsKeyArn:key.arn,rootDigest:image.imageDigest,
    host:db.host,port:db.port,database:db.database,subnets:resolveVpc().privateSubnetIds,securityGroup:db.taskSecurityGroupId}).apply(raw=>{
    const value=JSON.parse(raw),proof=value.proof,expected=postRuntimeCredentialReferences(stage,proof.account,proof.region);
    if(Object.keys(expected).some(k=>value.credentials[k]!==expected[k])||proof.manifest.administratorCredential!==expected.MEM9_DB_SECRET||
      !/^sha256:[a-f0-9]{64}$/.test(value.rootDigest)||
      !new RegExp('^arn:aws:kms:'+proof.region+':'+proof.account+':key/[a-f0-9-]{36}$').test(value.kmsKeyArn)||
      ['host','port','database','securityGroup'].some(k=>value[k]!==proof.manifest[k])||
      JSON.stringify([...value.subnets].sort())!==JSON.stringify([...proof.manifest.subnets].sort()))throw Error('InvalidPostRuntimePreviewContext');
    return {...value,account:proof.account,region:proof.region,controlSourceTree:proof.controlSourceTree,
      image:`${proof.account}.dkr.ecr.${proof.region}.amazonaws.com/mem9-on-aws/preview/bootstrap@${value.rootDigest}`};
  });
  let generatedRegistration:Output<string>|undefined;
  const task=new sst.aws.Task(POST_RUNTIME_OPERATOR,{cluster:ecs.cluster,architecture:'arm64',cpu:'0.25 vCPU',memory:'0.5 GB',
    image:inputs.apply(v=>v.image),entrypoint:['node'],command:['/bootstrap/operator/scripts/consolidation-preview-fixture.mjs'],
    environment:inputs.apply(v=>postRuntimeOperatorEnvironment({...v,stage,generation:config.generation,context:config.context})),
    ssm:inputs.apply(v=>v.credentials),permissions:[],logging:{retention:'1 month'},
    transform:{
      taskRole:args=>{
        args.assumeRolePolicy=inputs.apply(v=>JSON.stringify(postRuntimeTaskTrust(v.account,v.region)));
        args.permissionsBoundary=inputs.apply(v=>`arn:aws:iam::${v.account}:policy/mem9-on-aws-workload-boundary`);
        args.managedPolicyArns=[];args.inlinePolicies=[];
      },
      executionRole:args=>{
        args.assumeRolePolicy=inputs.apply(v=>JSON.stringify(postRuntimeTaskTrust(v.account,v.region)));
        args.permissionsBoundary=inputs.apply(v=>`arn:aws:iam::${v.account}:policy/mem9-on-aws-workload-boundary`);
        args.managedPolicyArns=['arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'];
        args.inlinePolicies=[{name:'PostRuntimePreviewSecrets',policy:inputs.apply(v=>JSON.stringify(postRuntimeExecutionPolicy(Object.values(v.credentials) as string[],v.kmsKeyArn,v.region)))}];
      },
      taskDefinition:args=>{
        args.tags={...(args.tags as Record<string,string>??{}),...tags,'sst:app':$app.name,'sst:stage':$app.stage};
        args.trackLatest=false;
        const definitions=args.containerDefinitions as Output<string>;
        if(!definitions||typeof definitions.apply!=='function')throw Error('InvalidPostRuntimePreviewDefinition');
        args.containerDefinitions=definitions.apply(raw=>{
          const values=structuredClone(parseNonrootJson(raw)) as Array<Record<string,unknown>>;
          if(!Array.isArray(values)||values.length!==1||values[0].name!==POST_RUNTIME_OPERATOR)throw Error('InvalidPostRuntimePreviewDefinition');
          Object.assign(values[0],{readonlyRootFilesystem:true,pseudoTerminal:false});
          return JSON.stringify(values);
        });
        applyNonrootControlTask(args,POST_RUNTIME_OPERATOR,'post-runtime-fixture');
        generatedRegistration=$jsonStringify({...args});
      },
    },
  });
  const route=$jsonStringify({version:1,kind:'post-runtime-preview-operator',stage,account,region,generation:config.generation,context:config.context,
      controlSourceTree:inputs.apply(v=>v.controlSourceTree),clusterArn:inputs.apply(v=>v.proof.manifest.clusterArn),taskDefinitionArn:task.taskDefinition,
      containerName:POST_RUNTIME_OPERATOR,image:inputs.apply(v=>v.image),taskRoleArn:task.nodes.taskRole.arn,executionRoleArn:task.nodes.executionRole.arn,
      subnets:inputs.apply(v=>v.subnets),securityGroup:db.taskSecurityGroupId,host:db.host,port:db.port,database:db.database,kmsKeyArn:key.arn,credentials:references});
  const guardedRoute=task.nodes.taskDefinition.apply(definition=>{
    if(!generatedRegistration)throw Error('NonrootPreviewGeneratedDefinitionMissing');
    return generatedRegistration.apply(raw=>route.apply(routeText=>{
      const value=JSON.parse(routeText),registration=previewRegistrationFromProviderArgs(JSON.parse(raw));
      // Keep the base pause definition first in the dependency chain even
      // when its purpose appears later in the map's preserved order.
      let previousDefinition=definition;
      const records=POST_RUNTIME_PURPOSES.map(purpose=>{
        const target:Record<string,unknown>=structuredClone(registration);
        if(purpose!=='preview-fixture-pause'){
          const c=(target.containerDefinitions as Array<Record<string,unknown>>)[0];
          c.environment=(c.environment as Array<{name:string;value:string}>).map(e=>e.name==='MEM9_BOOTSTRAP_OPERATION'?{...e,value:'consolidation-preview-'+purpose.slice('preview-fixture-'.length)}:e);
          target.containerDefinitions=[controlLaunchPolicy(purpose,c)];
        }
        const {containerDefinitions,tags:definitionTags,...fields}=target;
        let arn=task.taskDefinition;
        if(purpose!=='preview-fixture-pause'){
          const additional=new aws.ecs.TaskDefinition('Mem9PostFixturePurpose'+purpose.split('-').map(p=>p[0].toUpperCase()+p.slice(1)).join(''),{
            ...fields,containerDefinitions:JSON.stringify(containerDefinitions),tags:Object.fromEntries((definitionTags as Array<{key:string;value:string}>).map(t=>[t.key,t.value])),
            trackLatest:false,skipDestroy:true,
          } as ConstructorParameters<typeof aws.ecs.TaskDefinition>[1],{dependsOn:[previousDefinition]});
          previousDefinition=additional;arn=additional.arn;
        }
        return arn.apply(async taskDefinition=>{
          const client=new ECSClient({region:value.region});
          try{
            const response=await client.send(new DescribeTaskDefinitionCommand({taskDefinition,include:['TAGS']}),{abortSignal:AbortSignal.timeout(30000)});
            return {purpose,registration:target,observation:JSON.parse(JSON.stringify({taskDefinition:response.taskDefinition,tags:response.tags}))};
          }finally{client.destroy();}
        });
      });
      return $jsonStringify(records).apply(text=>JSON.stringify(bindPostRuntimePurposeMap(value,JSON.parse(text))));
    }));
  });
  new aws.ssm.Parameter('PostRuntimePreviewOperator',{name:`/mem9-on-aws/${stage}/consolidation-preview/operator`,type:'String',tags,value:guardedRoute});
  return task;
}
