/** Inert late root inputs from the actual CI collector. This conveys neither
 * a process handle nor a security PASS; the owner still observes/audits root. */
import {copyNonrootJson,nonrootHash as hash,inspectNonrootRecord,parseNonrootJson,NONROOT_LIMITS} from './production-nonroot-contracts.mjs';
import {futureRootScope,futureRootAuditLocation} from './ci-smoke-owner-delivery.mjs';
import {createHash} from 'node:crypto';
import {types} from 'node:util';
import {nonrootArchiveBindings,nonrootArchiveInventory,nonrootArchiveResolvers} from './production-nonroot-archive.mjs';
import {verifyProspectiveCiRootRequestPolicy} from './ci-smoke-root-request-cost.mjs';
const need=(v,c='CiRootRequest')=>{if(!v)throw Error(c);};
const exact=(v,keys)=>need(v&&Object.keys(v).sort().join()===keys.slice().sort().join(),'CiRootRequestFields');
export const CI_ROOT_REQUEST_BYTES=1048576;
const sha=raw=>createHash('sha256').update(raw).digest('hex');
const reserve=(chargeLocal,n)=>{if(chargeLocal){const result=chargeLocal(n);need(!result||typeof result.then!=='function','CiRootSynchronousBudget');}};
/** Count encoded bytes without serialization or invoking user accessors. Each
 * node/key and string scan is prepaid before visiting it. This is only sizing:
 * the existing inert-JSON and record validators still validate every value. */
function jsonBytes(value,chargeLocal,limit=CI_ROOT_REQUEST_BYTES){
 let bytes=0,nodes=0;const active=new Set();
 const add=n=>{bytes+=n;need(bytes<=limit,'CiRootRequestBound');};
 const string=v=>{
  need(v.length<=limit-bytes,'CiRootRequestBound');reserve(chargeLocal,2*v.length+16);add(2);
  for(let i=0;i<v.length;i++){
   const c=v.charCodeAt(i);
   if(c===34||c===92||c===8||c===9||c===10||c===12||c===13)add(2);
   else if(c<32)add(6);
   else if(c<128)add(1);
   else if(c<2048)add(2);
   else if(c>=0xd800&&c<=0xdbff){const low=v.charCodeAt(++i);need(low>=0xdc00&&low<=0xdfff,'CiRootRequestJson');add(4);}
   else{need(c<0xdc00||c>0xdfff,'CiRootRequestJson');add(3);}
  }
 };
 function visit(v,depth){
  reserve(chargeLocal,32);need(depth<=NONROOT_LIMITS.maxJsonDepth&&++nodes<=100000,'CiRootRequestJson');
  if(v===null||typeof v==='boolean'){add(v===false?5:4);return;}
  if(typeof v==='string'){string(v);return;}
  if(typeof v==='number'){need(Number.isSafeInteger(v)&&!Object.is(v,-0),'CiRootRequestJson');add(String(v).length);return;}
  need(v&&typeof v==='object'&&!types.isProxy(v)&&!active.has(v),'CiRootRequestJson');
  const array=Array.isArray(v),proto=Object.getPrototypeOf(v);need(array?proto===Array.prototype:proto===Object.prototype||proto===null,'CiRootRequestJson');
  active.add(v);add(2);let count=0;
  // Avoid materializing a full keys/descriptors array merely to price a copy.
  for(const key in v){
   if(!Object.hasOwn(v,key))continue;
   reserve(chargeLocal,32);if(count)add(1);
   if(array)need(key===String(count),'CiRootRequestJson');else{string(key);add(1);}
   const d=Object.getOwnPropertyDescriptor(v,key);need(d&&Object.hasOwn(d,'value'),'CiRootRequestJson');
   visit(d.value,depth+1);count++;
  }
  if(array)need(count===v.length,'CiRootRequestJson');active.delete(v);
 }
 visit(value,0);return bytes;
}
export const isFinalCiRootScope=scope=>scope?.kind==='target'&&scope.jobKey==='deploy-prod'&&scope.route==='deploy-prod'&&scope.checkpoint==='deploy-prod/23'&&scope.phase==='prereadiness';
function controlRefs(deploymentSource){
 const d=inspectNonrootRecord('DeploymentSourceRecordV2',deploymentSource),launches=d.deployedControlBuild.resolvedLaunches;
 need(launches.length===5&&launches.map(l=>l.taskKey).sort().join()==='bootstrap,control,promotion,provision,transition','CiRootOriginalSlots');
 return [d.resolvedTaskPlan,d.actualMain.authenticatedSource,...launches.map(l=>l.registrationBody)];
}
/** Closed seven-object data, never source history or a root observation. */
export function inspectCiRootControlOriginals(rows,{deploymentSource,source,chargeLocal}={}){
 reserve(chargeLocal,8*jsonBytes({rows,deploymentSource,source},chargeLocal,3*CI_ROOT_REQUEST_BYTES)+2048);
 need(Array.isArray(rows)&&rows.length===7,'CiRootOriginalCount');
 const refs=controlRefs(deploymentSource),seen=new Set();let total=0;
 return rows.map((row,index)=>{
  exact(row,['purpose','ref','base64']);inspectNonrootRecord('JsonRef',row.ref);
  need((index<2?['source','build']:['task-definition']).includes(row.purpose)&&hash(row.ref)===hash(refs[index]),'CiRootOriginalReference');
  const key=hash(row.ref);need(!seen.has(key),'CiRootOriginalDuplicate');seen.add(key);
  need(row.ref.bytesLength>0&&row.ref.bytesLength<=CI_ROOT_REQUEST_BYTES&&typeof row.base64==='string'&&row.base64.length===4*Math.ceil(row.ref.bytesLength/3),'CiRootOriginalBytes');
  total+=row.ref.bytesLength;need(total<=CI_ROOT_REQUEST_BYTES,'CiRootOriginalBound');
  const bytes=Buffer.from(row.base64,'base64');need(bytes.toString('base64')===row.base64&&bytes.length===row.ref.bytesLength&&sha(bytes)===row.ref.bytesHash,'CiRootOriginalBytes');
  const value=parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(bytes));need(hash(value)===row.ref.canonicalHash,'CiRootOriginalCanonical');
  if(index===0){inspectNonrootRecord('ResolvedTaskPlanV1',value);need(value.deployedControlBuildHash===hash(deploymentSource.deployedControlBuild)&&hash(value.controlLaunches)===hash(deploymentSource.deployedControlBuild.resolvedLaunches),'CiRootOriginalPlan');}
  if(index===1)need(hash(value)===hash(source),'CiRootOriginalSource');
  if(index>=2)need(hash(value)===deploymentSource.deployedControlBuild.resolvedLaunches[index-2].registrationBodyHash,'CiRootOriginalRegistration');
  return {purpose:row.purpose,ref:row.ref,bytes};
 });
}

/** Select from the complete producer archive, including reused inventory rows.
 * Reserve selection, object reads/copies and base64 work before touching bytes. */
export async function selectCiRootControlOriginals({archive,deploymentSource,source,chargeLocal}){
 need(typeof chargeLocal==='function','CiRootOriginalBudget');
 const sourceBytes=jsonBytes(deploymentSource,chargeLocal)+jsonBytes(source,chargeLocal);reserve(chargeLocal,8*sourceBytes+2048);
 const refs=controlRefs(deploymentSource),total=refs.reduce((n,r)=>n+r.bytesLength,0);
 need(total>0&&total<=Math.floor(CI_ROOT_REQUEST_BYTES*3/4),'CiRootOriginalBound');
 reserve(chargeLocal,2*nonrootArchiveBindings(archive).manifestRef.bytesLength+10*total+2048);
 const inventory=nonrootArchiveInventory(archive),resolvers=nonrootArchiveResolvers(archive),rows=[];
 for(const ref of refs){
  const matches=inventory.files.filter(row=>row.encoding==='json'&&row.ref.bytesHash===ref.bytesHash&&row.ref.canonicalHash===ref.canonicalHash&&row.ref.bytesLength===ref.bytesLength);
  need(matches.length===1,'CiRootOriginalInventory');const row=matches[0],raw=await resolvers.resolveJson(ref);
  rows.push({purpose:row.purpose,ref:row.ref,base64:raw.toString('base64')});
 }
 inspectCiRootControlOriginals(rows,{deploymentSource,source,chargeLocal});return rows;
}
export const CI_ROOT_REQUEST_POLICY=Object.freeze({version:1,kind:'ci-root-request-and-ready',requestBytes:CI_ROOT_REQUEST_BYTES,responseBytes:16384,readyWireBytes:8388608,readyResponseBytes:1048576,readyCalls:128,localBytes:33554432,unknownBytes:8388608});
export function inspectCiRootRequestPolicy(policy,scope){if(policy?.version===2)verifyProspectiveCiRootRequestPolicy(policy,scope);else need(hash(policy)===hash(CI_ROOT_REQUEST_POLICY),'CiRootCostPolicy');return policy;}
export function ciRootRequestBudget(policy=CI_ROOT_REQUEST_POLICY,scope){if(policy.version===2)verifyProspectiveCiRootRequestPolicy(policy,scope);else need(hash(policy)===hash(CI_ROOT_REQUEST_POLICY),'CiRootCostPolicy');return {ecrRequests:0,logicalBytes:policy.localBytes,httpBodyBytes:policy.requestBytes+policy.responseBytes+policy.readyWireBytes+policy.unknownBytes,uncompressedBytes:0,processedEntries:0};}
export function ciRootRequestKey(config,scope){need(hash(scope)===hash(futureRootScope(scope.checkpoint)),'CiRootRequestScope');return `decisions/prod/ci-grants/${config.startup.grantSetId}/${hash(scope.checkpoint)}/root-request.json`;}
export function createCiRootRequest({config,scope,binding,startupReceipt,parameter,source,deploymentSource,targetObservation,requestedMs,controlOriginals},{chargeLocal,bounded=false}={}){
 const final=isFinalCiRootScope(scope);if(final||bounded)reserve(chargeLocal,4*jsonBytes(binding,chargeLocal));if(!final)need(controlOriginals===undefined,'CiRootOriginalScope');
 const value={version:final?2:1,kind:'ci-prepaid-root-audit-request',bindingHash:hash(binding),scope,nonce:startupReceipt.nonce,artifactId:startupReceipt.artifactId,proofHash:config.startup.proofHash,descriptorHash:config.startup.descriptorHash,parameterVersion:parameter.Version,source,deploymentSource,targetObservation,requestedMs,...(final?{controlOriginals}: {})};
 return verifyCiRootRequest(value,{config,scope,binding,startupReceipt,now:requestedMs,chargeLocal,bounded});
}
export function verifyCiRootRequest(value,{config,scope,binding,startupReceipt,now,chargeLocal,bounded=false}){
 const final=isFinalCiRootScope(scope);if(final||bounded)reserve(chargeLocal,8*(jsonBytes(value,chargeLocal)+jsonBytes(binding,chargeLocal)));
 const v=copyNonrootJson(value);exact(v,['version','kind','bindingHash','scope','nonce','artifactId','proofHash','descriptorHash','parameterVersion','source','deploymentSource','targetObservation','requestedMs',...(final?['controlOriginals']:[])]);
 need(v.version===(final?2:1)&&v.kind==='ci-prepaid-root-audit-request'&&hash(v.scope)===hash(scope)&&hash(scope)===hash(futureRootScope(scope.checkpoint)),'CiRootRequestScope');
 need(v.bindingHash===hash(binding)&&v.nonce===startupReceipt.nonce&&v.artifactId===startupReceipt.artifactId&&v.proofHash===config.startup.proofHash&&v.descriptorHash===config.startup.descriptorHash&&v.parameterVersion===config.target.parameterVersion,'CiRootRequestBinding');
 const s=v.source;need(s.repository===binding.source.repository&&s.run?.id===binding.source.runId&&s.run?.attempt===binding.source.runAttempt&&s.checkout?.sha===binding.source.mainRevision&&s.checkout?.tree===binding.source.mainTree,'CiRootRequestSource');
 const d=inspectNonrootRecord('DeploymentSourceRecordV2',v.deploymentSource);need(d.proofHash===v.proofHash&&d.descriptorHash===v.descriptorHash&&d.parameterVersion===v.parameterVersion,'CiRootRequestDeployment');
 need(v.targetObservation?.serviceObservation?.descriptorHash===v.descriptorHash&&v.targetObservation.serviceObservation.parameterVersion===v.parameterVersion,'CiRootRequestTarget');
 need(Number.isSafeInteger(v.requestedMs)&&v.requestedMs<=now&&now-v.requestedMs<=300000&&now<config.startup.notAfter,'CiRootRequestExpired');
 if(!final)need(Buffer.byteLength(JSON.stringify(v))<=CI_ROOT_REQUEST_BYTES,'CiRootRequestBound');if(final)inspectCiRootControlOriginals(v.controlOriginals,{deploymentSource:d,source:s});return Object.freeze(v);
}
/** Serialization is priced before allocating either the JSON text or bytes. */
export function encodeCiRootRequest(value,{chargeLocal,bounded=false}={}){
 if(value.version===2||bounded)reserve(chargeLocal,2*jsonBytes(value,chargeLocal));
 return Buffer.from(JSON.stringify(value));
}
export function decodeCiRootRequest(raw,expected){need(raw instanceof Uint8Array&&raw.length>0&&raw.length<=CI_ROOT_REQUEST_BYTES,'CiRootRequestBound');if(isFinalCiRootScope(expected.scope))reserve(expected.chargeLocal,4*raw.length);return verifyCiRootRequest(parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(raw)),expected);}
export function ciRootReadyStatus(config,scope,archiveHash){
 need(/^[a-f0-9]{64}$/.test(archiveHash),'CiRootReadyHash');futureRootAuditLocation(config,scope);
 return Object.freeze({state:'success',context:'mem9-root/'+hash({grantSetId:config.startup.grantSetId,checkpoint:scope.checkpoint}),description:archiveHash});
}

/** Closed replay of the actual request PUT and owner-ready observations.
 * Callers supply pinned raw bytes, so whitespace/ignored fields remain billed.
 * This returns evidence only, never a request or acquisition capability. */
export function verifyCiRootExchange(exchange,records,expected){
 const P=CI_ROOT_REQUEST_POLICY,sha=b=>createHash('sha256').update(b).digest('hex');
 const {config,scope,binding,startupReceipt,completedMs,openedMs,deadlineMs,deploymentSource}=expected;
 exact(exchange,['version','archiveHash','requestRef','observedWireBytes','records',...(exchange.version===2?['localAccountingRef']:[])]);
 if(exchange.version===2){need(expected.rootPolicy?.version===2,'CiRootCostPolicy');inspectCiRootRequestPolicy(expected.rootPolicy,scope);}
 need([1,2].includes(exchange.version)&&/^[a-f0-9]{64}$/.test(exchange.archiveHash)&&Array.isArray(records)&&records.length===exchange.records.length&&records.length>=7&&records.length<=4+3*P.readyCalls,'CiRootReplayRecords');
 let next=0;
 const take=name=>{const row=records[next],pin=exchange.records[next++];need(row?.name===name&&pin?.name===name&&hash(row.ref)===hash(pin.ref)&&row.bytes instanceof Uint8Array&&sha(row.bytes)===pin.ref.sha256,'CiRootReplayRecord');return {...row,value:parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(row.bytes))};};
 const time=n=>need(Number.isSafeInteger(n)&&n>=openedMs&&n<=completedMs&&n<deadlineMs,'CiRootReplayTime');
 time(completedMs);
 const request=take('root-request');need(hash(request.ref)===hash(exchange.requestRef),'CiRootReplayRequest');
 const value=decodeCiRootRequest(request.bytes,{config,scope,binding,startupReceipt,now:completedMs});
 need(hash(value.deploymentSource)===hash(deploymentSource),'CiRootReplayDeployment');time(value.requestedMs);
 const intent=take('root-put-intent'),dispatch=take('root-put-dispatch'),put=take('root-put-complete');
 exact(intent.value,['version','requestRef','key','requestBytes','responseCap','openedMs']);exact(dispatch.value,['intentRef','requestHash','requestBytes','dispatchedMs']);exact(put.value,['intentRef','status','responseHash','requestBytes','responseBytes','observedWireBytes','completedMs']);
 need(intent.value.version===1&&hash(intent.value.requestRef)===hash(request.ref)&&intent.value.key===ciRootRequestKey(config,scope)&&intent.value.requestBytes===request.bytes.length&&intent.value.responseCap===P.responseBytes,'CiRootReplayPut');
 need(hash(dispatch.value.intentRef)===hash(intent.ref)&&dispatch.value.requestHash===request.ref.sha256&&dispatch.value.requestBytes===request.bytes.length&&hash(put.value.intentRef)===hash(intent.ref)&&put.value.status===200&&put.value.requestBytes===request.bytes.length&&Number.isSafeInteger(put.value.responseBytes)&&put.value.responseBytes>=0&&put.value.responseBytes<=P.responseBytes&&/^[a-f0-9]{64}$/.test(put.value.responseHash)&&put.value.observedWireBytes===request.bytes.length+put.value.responseBytes,'CiRootReplayPut');
 for(const n of [intent.value.openedMs,dispatch.value.dispatchedMs,put.value.completedMs])time(n);
 need(value.requestedMs<=intent.value.openedMs&&intent.value.openedMs<=dispatch.value.dispatchedMs&&dispatch.value.dispatchedMs<=put.value.completedMs,'CiRootReplayOrder');
 let wire=put.value.observedWireBytes,githubWire=0,page=1,priorCompleted=put.value.completedMs,nextPoll=0,ready=false,count=0;
 const status=ciRootReadyStatus(config,scope,exchange.archiveHash);
 while(next<records.length){
  need(!ready&&++count<=P.readyCalls,'CiRootReplayAfterReady');
  const i=take('root-ready-'+count+'-intent'),raw=take('root-ready-'+count+'-response'),r=take('root-ready-'+count+'-complete');
  exact(i.value,['path','responseCap','requestedMs']);exact(r.value,['intentRef','responseRef','status','responseHash','responseBytes','completedMs']);time(i.value.requestedMs);time(r.value.completedMs);
  need(i.value.path===`/repos/${binding.source.repository}/commits/${binding.source.mainRevision}/statuses?per_page=100&page=${page}`&&i.value.responseCap===P.readyResponseBytes&&i.value.requestedMs>=Math.max(priorCompleted,nextPoll)&&r.value.completedMs>=i.value.requestedMs,'CiRootReplayReadyIntent');
  need(hash(r.value.intentRef)===hash(i.ref)&&hash(r.value.responseRef)===hash(raw.ref)&&r.value.status===200&&r.value.responseHash===raw.ref.sha256&&r.value.responseBytes===raw.bytes.length&&raw.bytes.length<=P.readyResponseBytes&&githubWire+P.readyResponseBytes<=P.readyWireBytes&&Array.isArray(raw.value)&&raw.value.length<=100,'CiRootReplayReadyResponse');
  wire+=raw.bytes.length;githubWire+=raw.bytes.length;priorCompleted=r.value.completedMs;
  const matching=raw.value.filter(v=>v?.context===status.context);
  if(matching.length){need(matching.every(v=>v.creator?.id===config.startup.ownerGithubActorId&&Object.entries(status).every(([k,x])=>v[k]===x)),'CiRootReplayReadyOwner');ready=true;}
  if(raw.value.length<100||page===3){page=1;nextPoll=priorCompleted+5000;}else{page++;nextPoll=0;}
 }
 need(ready&&wire===exchange.observedWireBytes&&githubWire<=P.readyWireBytes,'CiRootReplayIncomplete');
 return Object.freeze({archiveHash:exchange.archiveHash,observedWireBytes:wire,request:value,readyCalls:count});
}
