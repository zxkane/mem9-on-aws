/** Inert late root inputs from the actual CI collector. This conveys neither
 * a process handle nor a security PASS; the owner still observes/audits root. */
import {copyNonrootJson,nonrootHash as hash,inspectNonrootRecord,parseNonrootJson} from './production-nonroot-contracts.mjs';
import {futureRootScope,futureRootAuditLocation} from './ci-smoke-owner-delivery.mjs';
import {createHash} from 'node:crypto';
const need=(v,c='CiRootRequest')=>{if(!v)throw Error(c);};
const exact=(v,keys)=>need(v&&Object.keys(v).sort().join()===keys.slice().sort().join(),'CiRootRequestFields');
export const CI_ROOT_REQUEST_BYTES=1048576;
export const CI_ROOT_REQUEST_POLICY=Object.freeze({version:1,kind:'ci-root-request-and-ready',requestBytes:CI_ROOT_REQUEST_BYTES,responseBytes:16384,readyWireBytes:8388608,readyResponseBytes:1048576,readyCalls:128,localBytes:33554432,unknownBytes:8388608});
export function ciRootRequestBudget(){return {ecrRequests:0,logicalBytes:CI_ROOT_REQUEST_POLICY.localBytes,httpBodyBytes:CI_ROOT_REQUEST_POLICY.requestBytes+CI_ROOT_REQUEST_POLICY.responseBytes+CI_ROOT_REQUEST_POLICY.readyWireBytes+CI_ROOT_REQUEST_POLICY.unknownBytes,uncompressedBytes:0,processedEntries:0};}
export function ciRootRequestKey(config,scope){need(hash(scope)===hash(futureRootScope(scope.checkpoint)),'CiRootRequestScope');return `decisions/prod/ci-grants/${config.startup.grantSetId}/${hash(scope.checkpoint)}/root-request.json`;}
export function createCiRootRequest({config,scope,binding,startupReceipt,parameter,source,deploymentSource,targetObservation,requestedMs}){
 const value={version:1,kind:'ci-prepaid-root-audit-request',bindingHash:hash(binding),scope:copyNonrootJson(scope),nonce:startupReceipt.nonce,artifactId:startupReceipt.artifactId,proofHash:config.startup.proofHash,descriptorHash:config.startup.descriptorHash,parameterVersion:parameter.Version,source:copyNonrootJson(source),deploymentSource:copyNonrootJson(deploymentSource),targetObservation:copyNonrootJson(targetObservation),requestedMs};
 return verifyCiRootRequest(value,{config,scope,binding,startupReceipt,now:requestedMs});
}
export function verifyCiRootRequest(value,{config,scope,binding,startupReceipt,now}){
 const v=copyNonrootJson(value);exact(v,['version','kind','bindingHash','scope','nonce','artifactId','proofHash','descriptorHash','parameterVersion','source','deploymentSource','targetObservation','requestedMs']);
 need(v.version===1&&v.kind==='ci-prepaid-root-audit-request'&&hash(v.scope)===hash(scope)&&hash(scope)===hash(futureRootScope(scope.checkpoint)),'CiRootRequestScope');
 need(v.bindingHash===hash(binding)&&v.nonce===startupReceipt.nonce&&v.artifactId===startupReceipt.artifactId&&v.proofHash===config.startup.proofHash&&v.descriptorHash===config.startup.descriptorHash&&v.parameterVersion===config.target.parameterVersion,'CiRootRequestBinding');
 const s=v.source;need(s.repository===binding.source.repository&&s.run?.id===binding.source.runId&&s.run?.attempt===binding.source.runAttempt&&s.checkout?.sha===binding.source.mainRevision&&s.checkout?.tree===binding.source.mainTree,'CiRootRequestSource');
 const d=inspectNonrootRecord('DeploymentSourceRecordV2',v.deploymentSource);need(d.proofHash===v.proofHash&&d.descriptorHash===v.descriptorHash&&d.parameterVersion===v.parameterVersion,'CiRootRequestDeployment');
 need(v.targetObservation?.serviceObservation?.descriptorHash===v.descriptorHash&&v.targetObservation.serviceObservation.parameterVersion===v.parameterVersion,'CiRootRequestTarget');
 need(Number.isSafeInteger(v.requestedMs)&&v.requestedMs<=now&&now-v.requestedMs<=300000&&now<config.startup.notAfter,'CiRootRequestExpired');
 need(Buffer.byteLength(JSON.stringify(v))<=CI_ROOT_REQUEST_BYTES,'CiRootRequestBound');return Object.freeze(v);
}
export function decodeCiRootRequest(raw,expected){need(raw instanceof Uint8Array&&raw.length>0&&raw.length<=CI_ROOT_REQUEST_BYTES,'CiRootRequestBound');return verifyCiRootRequest(parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(raw)),expected);}
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
 exact(exchange,['version','archiveHash','requestRef','observedWireBytes','records']);
 need(exchange.version===1&&/^[a-f0-9]{64}$/.test(exchange.archiveHash)&&Array.isArray(records)&&records.length===exchange.records.length&&records.length>=7&&records.length<=4+3*P.readyCalls,'CiRootReplayRecords');
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
