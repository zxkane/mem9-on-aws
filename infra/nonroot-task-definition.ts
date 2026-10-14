import {dataLaunchPolicy,controlLaunchPolicy} from '../scripts/lib/production-nonroot-launch.mjs';
import type {ControlLaunchOptions} from '../scripts/lib/production-nonroot-launch.mjs';
import {copyNonrootJson,nonrootHash,parseNonrootJson} from '../scripts/lib/production-nonroot-contracts.mjs';
import {previewRegistrationFromProviderArgs} from '../scripts/lib/nonroot-preview-source.mjs';
import {selectedDataRelease} from './ecr';
import {getNonrootTargetRegistration,assertNonrootTaskDefinitionReadback} from '../scripts/lib/production-nonroot-proof.mjs';
import {ECSClient,DescribeTaskDefinitionCommand} from '@aws-sdk/client-ecs';

type DefinitionsOutput={apply(callback:(raw:string)=>string):unknown};
export type NonrootDataComponent='mnemo-server'|'qwen3-embed'|'llm-proxy'|'planner'|'executor';

/** Applies the fixed launch delta to SST's complete container JSON. This is
 * source construction only: production callers must first authenticate the
 * deployment descriptor and exact task plan, then verify AWS readback. */
function transformContainer(input:object,name:string,transform:(value:unknown)=>unknown):void{
 const args=input as Record<string,unknown>;
 const definitions=args.containerDefinitions as DefinitionsOutput|undefined;
 if(!definitions||typeof definitions.apply!=='function')throw Error('NonrootContainerDefinitionsRequired');
 args.containerDefinitions=definitions.apply(raw=>transformDefinitions(raw,name,transform));
}
function transformDefinitions(raw:string,name:string,transform:(value:unknown)=>unknown):string{
  const parsed=parseNonrootJson(raw);
  if(!Array.isArray(parsed))throw Error('NonrootContainerSetInvalid');
  const values=[...parsed] as Array<{name?:string}>;
  if(values.length===0||values.length>64||values.some(value=>!value||typeof value!=='object'||Array.isArray(value)||typeof value.name!=='string')||
   new Set(values.map(value=>value.name)).size!==values.length)throw Error('NonrootContainerSetInvalid');
  const index=values.findIndex(value=>value.name===name);if(index<0)throw Error('NonrootContainerMissing');
  // SST emits the Docker spelling. Translate that one known field to the ECS
  // spelling before validation; two spellings would be ambiguous to the API.
  const target={...values[index]} as Record<string,unknown>;
  if(Object.hasOwn(target,'entrypoint')){
   if(Object.hasOwn(target,'entryPoint'))throw Error('NonrootAmbiguousEntrypoint');
   target.entryPoint=target.entrypoint;delete target.entrypoint;
  }
  values[index]=transform(target) as {name?:string};
  return JSON.stringify(values);
}

export function applyNonrootDataTask(args:object,component:NonrootDataComponent):void{
 const name=component==='planner'?'Mem9ConsolidationPlanner':component==='executor'?'Mem9ConsolidationExecutor':component;
 transformContainer(args,name,value=>dataLaunchPolicy(component,value));
}

export function applyNonrootControlTask(args:object,containerName:string,purpose:string,options:ControlLaunchOptions={}):void{
 transformContainer(args,containerName,value=>controlLaunchPolicy(purpose,value,options));
}

export type ProductionNonrootTaskKey='backend'|'planner'|'executor'|'bootstrap'|'control'|'promotion'|'provision'|'transition';
const controlTasks={bootstrap:['Mem9Bootstrap','bootstrap-runtime-verify'],control:['ControlMem9Bootstrap','consolidation-control'],
 promotion:['PromoteMem9Bootstrap','consolidation-promote'],provision:['ProdMem9Bootstrap','denied-provision'],transition:['TransitionMem9Bootstrap','denied-transition']} as const;
const same=(a:unknown,b:unknown,code:string)=>{if(nonrootHash(a)!==nonrootHash(b))throw Error(code);};
function productionSelection(){return $app.stage==='prod'?selectedDataRelease():undefined;}

/** Gates the complete generated registration before the provider sees any
 * changed container fields. The opaque context is never serialized to JSON. */
export function applyProductionNonrootTask(input:object,key:ProductionNonrootTaskKey):void{
 const selection=productionSelection();if(!selection)return;
 const args=input as Record<string,unknown>,original={...args};
 const prepared=$jsonStringify(original).apply(raw=>selection.apply(selected=>{
  const fields=structuredClone(parseNonrootJson(raw)) as Record<string,unknown>;
  if(selected.data.version!==3)return fields;
  const expected=getNonrootTargetRegistration(selected.nonrootDeploymentContext,key);
  if(typeof fields.containerDefinitions!=='string')throw Error('NonrootContainerDefinitionsRequired');
  let definitions=fields.containerDefinitions;
  if(key==='backend'){
   for(const name of ['mnemo-server','qwen3-embed','llm-proxy'] as const)
    definitions=transformDefinitions(definitions,name,value=>dataLaunchPolicy(name,value));
  }else if(key==='planner'||key==='executor'){
   definitions=transformDefinitions(definitions,key==='planner'?'Mem9ConsolidationPlanner':'Mem9ConsolidationExecutor',value=>dataLaunchPolicy(key,value));
  }else{
   const [name,purpose]=controlTasks[key];definitions=transformDefinitions(definitions,name,value=>controlLaunchPolicy(purpose,value));
  }
  fields.containerDefinitions=definitions;fields.trackLatest=false;
  // These are the existing provider default tags from sst.config.ts. Make them
  // explicit so the complete registration comparison includes them as well.
  fields.tags={Project:'mem9-on-aws',Stage:'prod',ManagedBy:'sst',...(fields.tags as Record<string,string>|undefined)};
  same(previewRegistrationFromProviderArgs(fields),expected,'NonrootGeneratedRegistrationMismatch');
  return fields;
 }));
 args.containerDefinitions=prepared.apply(value=>value.containerDefinitions);
 args.trackLatest=prepared.apply(value=>value.trackLatest);
 args.tags=prepared.apply(value=>value.tags);
}

/** The checked ARN is the dependency used by Service/RunTask consumers. A
 * registration alone cannot release it. Revalidate the context after the read. */
export function verifiedProductionNonrootTaskArn(arn:Input<string>,key:ProductionNonrootTaskKey):Output<string>{
 const selection=productionSelection();
 if(!selection&&arn&&typeof arn==='object'&&'apply'in arn)return arn as Output<string>;
 const value=$jsonStringify({arn});
 return value.apply(raw=>{
  const ref=(parseNonrootJson(raw) as {arn:string}).arn;
  if(!selection)return ref;
  return selection.apply(async selected=>{
   if(selected.data.version!==3)return ref;
   getNonrootTargetRegistration(selected.nonrootDeploymentContext,key);
   const client=new ECSClient({region:selected.data.region});
   try{
    const response=await client.send(new DescribeTaskDefinitionCommand({taskDefinition:ref,include:['TAGS']}),{abortSignal:AbortSignal.timeout(30000)});
    const expected=getNonrootTargetRegistration(selected.nonrootDeploymentContext,key);
    const definition=JSON.parse(JSON.stringify(response.taskDefinition));
    if(!definition||definition.taskDefinitionArn!==ref||!Array.isArray(definition.requiresAttributes)||
      definition.requiresAttributes.some((a:unknown)=>!a||typeof a!=='object'||Object.keys(a).join()!=='name'||typeof (a as {name?:unknown}).name!=='string'))throw Error('NonrootRegistrationMetadataRequired');
    if(Object.hasOwn(expected,'tags'))definition.tags=response.tags;
    else if(response.tags?.length)throw Error('NonrootUnboundRegistrationTags');
    if(Object.hasOwn(expected,'tags')){
     if(!Array.isArray(definition.tags)||definition.tags.some((t:unknown)=>!t||typeof t!=='object'||Object.keys(t).sort().join()!=='key,value'))throw Error('NonrootRegistrationTags');
     definition.tags.sort((a:{key:string},b:{key:string})=>a.key.localeCompare(b.key));
    }
    return assertNonrootTaskDefinitionReadback(selected.nonrootDeploymentContext,key,definition);
   }finally{client.destroy();}
  });
 }) as Output<string>;
}

export function applyProductionNonrootService(input:object):void{
 const selection=productionSelection();if(!selection)return;
 const args=input as Record<string,unknown>,original={...args};
 args.taskDefinition=verifiedProductionNonrootTaskArn(original.taskDefinition as Input<string>,'backend');
 const gated=(field:string,target:unknown)=>selection.apply(selected=>{
  if(selected.data.version!==3)return original[field];
  getNonrootTargetRegistration(selected.nonrootDeploymentContext,'backend');
  if(field==='desiredCount'&&original.desiredCount!==1)throw Error('NonrootOrdinaryDeploymentMustRemainRunning');
  return target;
 });
 args.desiredCount=gated('desiredCount',1);
 args.deploymentMinimumHealthyPercent=gated('deploymentMinimumHealthyPercent',100);
 args.deploymentMaximumPercent=gated('deploymentMaximumPercent',200);
 args.deploymentCircuitBreaker=gated('deploymentCircuitBreaker',{enable:true,rollback:false});
}

/** Called only with the authenticated retained getter result. Missing original
 * request bytes are a HOLD, never an invitation to reconstruct from the target. */
export function retainedProductionFallbackArgs(value:unknown):Record<string,unknown>{
 const binding=copyNonrootJson(value) as {taskDefinitionArn?:string;definition?:Record<string,unknown>;registrationBody?:Record<string,unknown>};
 if(!binding||typeof binding!=='object'||Object.keys(binding).sort().join()!=='definition,registrationBody,taskDefinitionArn'||!binding.registrationBody||!binding.definition)throw Error('NonrootRetainedRegistrationBodyRequired');
 const body=structuredClone(binding.registrationBody),definition=structuredClone(binding.definition);
 if(typeof binding.taskDefinitionArn!=='string'||!/^arn:aws:ecs:[a-z0-9-]+:\d{12}:task-definition\/[A-Za-z0-9_-]+:[1-9][0-9]*$/.test(binding.taskDefinitionArn)||
   !Number.isSafeInteger(definition.revision)||Number(definition.revision)<1||binding.taskDefinitionArn!==definition.taskDefinitionArn||definition.family!==body.family||
   binding.taskDefinitionArn!==`arn:aws:ecs:${binding.taskDefinitionArn.split(':')[3]}:${binding.taskDefinitionArn.split(':')[4]}:task-definition/${body.family}:${definition.revision}`)throw Error('NonrootRetainedDefinitionIdentity');
 for(const key of ['taskDefinitionArn','revision','registeredAt','registeredBy','deregisteredAt','deleteRequestedAt','status','requiresAttributes','compatibilities'])delete definition[key];
 same(definition,body,'NonrootRetainedRegistrationMismatch');
 const {containerDefinitions,tags,...fields}=body;
 if(!Array.isArray(containerDefinitions)||!Array.isArray(tags))throw Error('NonrootRetainedRegistrationBodyRequired');
 const tagRows=tags as Array<{key:string;value:string}>;
 if(tagRows.some(t=>!t||Object.keys(t).sort().join()!=='key,value'||typeof t.key!=='string'||typeof t.value!=='string')||new Set(tagRows.map(t=>t.key)).size!==tagRows.length)throw Error('NonrootRetainedRegistrationTags');
 const args={...fields,containerDefinitions:JSON.stringify(containerDefinitions),tags:Object.fromEntries(tagRows.map(t=>[t.key,t.value])),skipDestroy:true};
 // Validate the exact supported provider/API field mapping without introducing
 // trackLatest into the existing dormant resource's declaration.
 same(previewRegistrationFromProviderArgs({...args,trackLatest:false}),body,'NonrootRetainedRegistrationMismatch');
 return args;
}
