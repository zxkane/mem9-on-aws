import {GetParametersCommand} from '@aws-sdk/client-ssm';
import {DescribeTaskDefinitionCommand} from '@aws-sdk/client-ecs';
import {inspectNonrootPreviewPurposeMap,verifyNonrootPreviewPurposeReadback} from './nonroot-preview-source.mjs';
import {nonrootPreviewObservation} from './post-runtime-preview-aws.mjs';
import {copyNonrootJson,nonrootHash as hash,NONROOT_HARDENING_POLICY} from './production-nonroot-contracts.mjs';
import {readControlSourceFile} from './production-control-source.mjs';
import {previewOperationsForEvidence} from './production-nonroot-preview-operations.mjs';
import {collectPreviewWorkloadFacts} from './production-nonroot-preview-workloads.mjs';
import {collectPreviewPostRuntimeFacts} from './production-nonroot-preview-postruntime.mjs';
import {nonrootControlMetadataReads} from './production-nonroot-control-reads.mjs';

const contexts=new WeakMap(),phases=new Set(['preupdate','preconfigure','presst','prereadiness']);
const need=(ok,code='NonrootPreviewTargetInvalid')=>{if(!ok)throw Error(code);};
const same=(a,b,code)=>need(hash(a)===hash(b),code);
const scopeOf=value=>Object.fromEntries(['stage','account','region','sourceTree'].map(key=>[key,value[key]]));
const namesFor=stage=>['purpose-bindings','cluster-name','subnet-ids','task-sg-id'].map(suffix=>`/mem9-on-aws/${stage}/bootstrap/${suffix}`);
export const PREVIEW_SOURCE_PLAN_FILES=Object.freeze(['infra/nonroot-task-definition.ts','infra/ecs.ts','infra/bootstrap.ts','infra/consolidation.ts',
 'scripts/lib/nonroot-preview-source.mjs','scripts/lib/production-nonroot-launch.mjs']);
const workloadNamesFor=stage=>['ecs/cluster-name','ecs/service-name','ecs/task-definition','ecs/image-selection','consolidation-preview/manifest','consolidation-runtime/data-release'].map(suffix=>`/mem9-on-aws/${stage}/${suffix}`);

export async function captureNonrootPreviewSourcePlan(context,scope){
 need(context?.tree===scope.sourceTree,'NonrootPreviewPlanSource');
 const files=[];for(const path of PREVIEW_SOURCE_PLAN_FILES){const {file}=await readControlSourceFile(context,path);files.push(file);}
 return copyNonrootJson({version:1,kind:'nonroot-preview-source-plan',...scope,policyHash:hash(NONROOT_HARDENING_POLICY),files});
}

/** Named, read-only bootstrap inventory. It does not certify a backend,
 * process identity, or a future task that has not been registered. */
export async function collectNonrootPreviewTarget(clients,{stage,account,region,sourceTree,sourceRevision,phase,sourceReceiptHash,sourceContext,metadataReads,env=process.env,clock=Date.now}){
 need(/^pr-[1-9][0-9]*$/.test(stage??'')&&/^\d{12}$/.test(account??'')&&/^[a-z]{2}(?:-[a-z]+)+-\d$/.test(region??'')&&/^[a-f0-9]{40}$/.test(sourceTree??''));
 need(phases.has(phase)&&/^[a-f0-9]{64}$/.test(sourceReceiptHash??'')&&typeof clock==='function');
 const scope={stage,account,region,sourceTree},names=namesFor(stage),startedMs=clock();
 need(Number.isSafeInteger(startedMs)&&startedMs>0);
 const calls=[],facts={};
 if(sourceContext)facts['planned-source-controls']=await captureNonrootPreviewSourcePlan(sourceContext,scope);
 const send=async(service,command)=>{
  need(clock()>=startedMs&&clock()<startedMs+300000,'NonrootPreviewPhaseExpired');
  const event={service,api:command.constructor.name,requestHash:hash(command.input),status:'attempted'};calls.push(event);
  try{const response=await clients[service].send(command,{abortSignal:AbortSignal.timeout(30000)});
   Object.assign(event,{status:'completed',responseHash:hash(JSON.parse(JSON.stringify(response)))});return response;
  }catch(error){event.status='failed';throw error;}
 };
 const read=async()=>{
  const response=await send('ssm',new GetParametersCommand({Names:names,WithDecryption:false}));
  const rows=response.Parameters??[],missing=response.InvalidParameters??[];
  need(Array.isArray(rows)&&Array.isArray(missing));
  const seen=[...rows.map(row=>row.Name),...missing];
  need(new Set(seen).size===seen.length&&hash(seen.slice().sort())===hash(names.slice().sort()),'NonrootPreviewParameterInventory');
  if(rows.length===0){need(phase==='preupdate','NonrootPreviewTargetNotRegistered');return {state:'absent',parameters:[],missing:names};}
  need(missing.length===0,'NonrootPreviewParameterInventory');
  const parameters=names.map(name=>{
   const p=rows.find(row=>row.Name===name);
   need(p.ARN===`arn:aws:ssm:${region}:${account}:parameter${name}`&&p.Type===(name===names[2]?'StringList':'String')&&typeof p.Value==='string'&&Number.isSafeInteger(p.Version)&&p.Version>0,'NonrootPreviewParameterBinding');
   return {Name:p.Name,Type:p.Type,ARN:p.ARN,Version:p.Version,Value:p.Value};
  });
  return {state:'registered',parameters,missing:[]};
 };
 const first=await read(),definitions=[];
 facts['stage-inventory']=copyNonrootJson(first);
 if(first.state==='registered'){
  const [purpose,clusterParameter,subnetsParameter,securityGroupParameter]=first.parameters;
  const map=inspectNonrootPreviewPurposeMap(purpose.Value,scope),cluster=clusterParameter.Value,subnets=subnetsParameter.Value.split(','),securityGroup=securityGroupParameter.Value;
  need(new RegExp('^mem9-on-aws-'+stage+'-[A-Za-z0-9_-]+$').test(cluster)&&map.family===cluster+'-Mem9Bootstrap','NonrootPreviewNetwork');
  need(subnets.length>0&&subnets.length<=16&&new Set(subnets).size===subnets.length&&subnets.every(s=>/^subnet-(?:[a-f0-9]{8}|[a-f0-9]{17})$/.test(s))&&/^sg-(?:[a-f0-9]{8}|[a-f0-9]{17})$/.test(securityGroup),'NonrootPreviewNetwork');
  for(const row of map.bindings){
   const response=await send('ecs',new DescribeTaskDefinitionCommand({taskDefinition:row.taskDefinitionArn,include:['TAGS']}));
   const observation=nonrootPreviewObservation(response);
   verifyNonrootPreviewPurposeReadback(map,row.purpose,observation,scope);
   definitions.push({purpose:row.purpose,observation});
   facts['bootstrap-purpose:'+row.purpose]={mapHash:hash(map),binding:row,observation};
  }
  facts['bootstrap-purpose-bindings']={map,parameters:first.parameters,definitions};
  const fixturePurposes=['setup','pause','verify-planned','verify-executed','verify-repeated'].map(name=>'preview-fixture-'+name);
  if(fixturePurposes.every(purpose=>Object.hasOwn(facts,'bootstrap-purpose:'+purpose)))facts['consolidation-fixture-route']={kind:'bootstrap-purpose-route',bindings:fixturePurposes.map(purpose=>facts['bootstrap-purpose:'+purpose])};
 }
 let workloads;
 const readWorkloads=async()=>{
  const names=workloadNamesFor(stage),response=await send('ssm',new GetParametersCommand({Names:names,WithDecryption:true})),parameters=response.Parameters??[],missing=response.InvalidParameters??[];
  need(Array.isArray(parameters)&&Array.isArray(missing),'NonrootPreviewWorkloadParameters');
  const seen=[...parameters.map(p=>p.Name),...missing];need(new Set(seen).size===seen.length&&hash(seen.slice().sort())===hash(names.slice().sort()),'NonrootPreviewWorkloadParameters');
  const rows=parameters.map(p=>{
   need(p.ARN===`arn:aws:ssm:${region}:${account}:parameter${p.Name}`&&p.Type===(p.Name===names.at(-1)?'SecureString':'String')&&typeof p.Value==='string'&&Number.isSafeInteger(p.Version)&&p.Version>0,'NonrootPreviewWorkloadParameters');
   return {Name:p.Name,Type:p.Type,ARN:p.ARN,Version:p.Version,Value:p.Value};
  }).sort((a,b)=>a.Name.localeCompare(b.Name));
  return {parameters:rows,missing:missing.slice().sort()};
 };
 if(sourceRevision){
  workloads=await readWorkloads();
  Object.assign(facts,await collectPreviewWorkloadFacts({scope,sourceRevision,parameters:new Map(workloads.parameters.map(p=>[p.Name,p])),send,now:clock()}));
  facts['stage-inventory']={bootstrap:first,workloads};
 }
 let postRuntime;
 const readPostRuntime=async()=>{
  const prefix=`/mem9-on-aws/${stage}`,names=[prefix+'/consolidation-preview/operator',prefix+'/runtime/production-state',prefix+'/runtime/production-manifest'];
  const response=await send('ssm',new GetParametersCommand({Names:names,WithDecryption:true})),parameters=response.Parameters??[],missing=response.InvalidParameters??[];
  need(Array.isArray(parameters)&&Array.isArray(missing),'NonrootPreviewPostRuntimeParameters');
  const seen=[...parameters.map(p=>p.Name),...missing];need(new Set(seen).size===seen.length&&hash(seen.slice().sort())===hash(names.slice().sort()),'NonrootPreviewPostRuntimeParameters');
  const rows=parameters.map(p=>{
   need(p.ARN===`arn:aws:ssm:${region}:${account}:parameter${p.Name}`&&p.Type===(p.Name===names[0]?'String':'SecureString')&&Number.isSafeInteger(p.Version)&&p.Version>0&&typeof p.Value==='string','NonrootPreviewPostRuntimeParameters');
   return {Name:p.Name,Type:p.Type,ARN:p.ARN,Version:p.Version,Value:p.Value};
  }).sort((a,b)=>a.Name.localeCompare(b.Name));return {parameters:rows,missing:missing.slice().sort()};
 };
 if(sourceRevision&&phase==='prereadiness'){
  postRuntime=await readPostRuntime();
  if(postRuntime.parameters.some(p=>p.Name.endsWith('/consolidation-preview/operator'))){
   const reads=metadataReads??nonrootControlMetadataReads(scope,{env,calls});
   Object.assign(facts,await collectPreviewPostRuntimeFacts({scope,parameters:new Map(postRuntime.parameters.map(p=>[p.Name,p])),send,metadataReads:reads}));
  }
 }
 same(await read(),first,'NonrootPreviewParameterChanged');
 if(workloads)same(await readWorkloads(),workloads,'NonrootPreviewWorkloadParametersChanged');
 if(postRuntime)same(await readPostRuntime(),postRuntime,'NonrootPreviewPostRuntimeParametersChanged');
 const observedMs=clock(),expiresMs=startedMs+300000;
 need(Number.isSafeInteger(observedMs)&&observedMs>=startedMs&&observedMs<expiresMs,'NonrootPreviewPhaseExpired');
 const coverage=Object.keys(facts).sort(),operations=previewOperationsForEvidence({phase,facts});
 const record=copyNonrootJson({version:2,kind:'nonroot-preview-target-observation',coverage,...scope,phase,
  state:first.state,parameters:first.parameters,missing:first.missing,definitions,facts,operations,calls,startedMs,observedMs,expiresMs});
 const handle=Object.freeze({kind:'nonroot-preview-target-context'});contexts.set(handle,{record,sourceReceiptHash});return handle;
}

/** Reading this receipt is local. Absence authorizes no task launch and never
 * becomes a registered target merely because another step has run. */
export function nonrootPreviewPhaseEvidence(context,{stage,account,region,sourceTree,phase,sourceReceiptHash,effect='observation',now=Date.now()}){
 const state=contexts.get(context);need(state,'NonrootPreviewContextRequired');
 const r=state.record;same(scopeOf(r),{stage,account,region,sourceTree},'NonrootPreviewPhaseScope');
 need(phase===r.phase&&sourceReceiptHash===state.sourceReceiptHash,'NonrootPreviewPhaseMismatch');
 need(Number.isSafeInteger(now)&&now>=r.observedMs&&now<r.expiresMs,'NonrootPreviewPhaseExpired');
 need(['observation','launch'].includes(effect));if(effect==='launch')need(r.state==='registered','NonrootPreviewTargetNotRegistered');
 return copyNonrootJson({phaseEvidence:r,phaseReceipt:{version:2,kind:'nonroot-preview-phase-receipt',...scopeOf(r),phase,
  sourceReceiptHash,targetState:r.state,coverage:r.coverage,operationsHash:hash(r.operations),phaseEvidenceHash:hash(r),observedMs:r.observedMs,expiresMs:r.expiresMs}});
}
