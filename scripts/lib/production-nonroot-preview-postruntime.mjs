import {DescribeTaskDefinitionCommand} from '@aws-sdk/client-ecs';
import {loadPostRuntimeOperator,nonrootPreviewObservation} from './post-runtime-preview-aws.mjs';
import {inspectPostRuntimePurposeMap,selectGuardedPostRuntimeRoute,validatePostRuntimeDefinition,POST_RUNTIME_PURPOSES} from './post-runtime-preview-route.mjs';
import {parseNonrootJson,copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';

const need=(ok,code='NonrootPreviewPostRuntimeInvalid')=>{if(!ok)throw Error(code);};

/** Common IAM/image/key evidence is read once. Every purpose still gets its
 * own exact protected definition readback; a shared image is not a shared
 * invocation permission. No current-production root context is involved. */
export async function collectPreviewPostRuntimeFacts({scope,parameters,send,metadataReads}){
 const prefix=`/mem9-on-aws/${scope.stage}`,names=[prefix+'/consolidation-preview/operator',prefix+'/runtime/production-state',prefix+'/runtime/production-manifest'];
 const parameter=parameters.get(names[0]);if(!parameter)return {};
 need(names.every(name=>parameters.has(name)),'NonrootPreviewPostRuntimeParameters');
 const map=inspectPostRuntimePurposeMap(parseNonrootJson(parameter.Value),scope);
 const expected={stage:scope.stage,account:scope.account,region:scope.region,controlSourceTree:scope.sourceTree,context:map.route.context,generation:map.route.generation,
  runtime:parseNonrootJson(parameters.get(names[1]).Value),manifest:parseNonrootJson(parameters.get(names[2]).Value)};
 const selected=map.bindings.some(b=>b.purpose==='preview-fixture-pause')?'preview-fixture-pause':map.bindings[0].purpose;
 const clients=Object.fromEntries(['sts','iam','ecs'].map(service=>[service,{send:command=>send(service,command)}]));
 clients.ssm={send:async command=>{
  need(command.constructor.name==='GetParametersCommand'&&command.input.WithDecryption===true&&hash(command.input.Names)===hash(names),'NonrootPreviewPostRuntimeReadScope');
  return {Parameters:names.map(name=>parameters.get(name)),InvalidParameters:[]};
 }};
 const common=await loadPostRuntimeOperator(clients,{...expected,purpose:selected},metadataReads),bindings=[];
 for(const binding of map.bindings){
  const route=selectGuardedPostRuntimeRoute(map,expected,binding.purpose);
  const observation=binding.purpose===selected?common.observation:nonrootPreviewObservation(await send('ecs',new DescribeTaskDefinitionCommand({taskDefinition:binding.taskDefinitionArn,include:['TAGS']})));
  validatePostRuntimeDefinition(observation.taskDefinition,route,observation);bindings.push({purpose:binding.purpose,route,observation});
 }
 const facts={'post-runtime-observation':{map,parameters:names.map(name=>parameters.get(name)),common,bindings}};
 for(const item of bindings)facts['post-runtime-purpose:'+item.purpose]=item;
 if(POST_RUNTIME_PURPOSES.every(purpose=>bindings.some(b=>b.purpose===purpose))){
  facts['post-runtime-fixture-route']=facts['post-runtime-observation'];
  facts['consolidation-fixture-route']=facts['post-runtime-observation'];
 }
 return copyNonrootJson(facts);
}
