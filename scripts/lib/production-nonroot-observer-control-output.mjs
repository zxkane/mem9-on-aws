import {selectObserverPrivatePeer} from './production-nonroot-observer-peer-inventory.mjs';
/** Original read-only observer predicates; no owner/provider creation. */
/** DATA replay of the fixed P producer. This cannot mint task, source,
 * credential or payment authority; acquisition supplies those originals. */
import {isIP} from 'node:net';
import {need,exact,hash,sha,zero} from './production-nonroot-engineering-json.mjs';
import {parseAcquisitionJson} from './ci-smoke-acquisition-format.mjs';
import {inspectObserverControlDelivery,observerDataHash,observerCounter,OBSERVER_COUNTER_KEYS,OBSERVER_CONTROL_ROUTE_SLOTS} from './production-nonroot-observer-delivery.mjs';
import {inspectObserverJobStatus,inspectObserverMcpInitialization,inspectObserverMcpStatus,selectObserverStatusTool,observerPrivateStatusPath} from './production-nonroot-observer-route-protocol.mjs';

export const CONTROL_OUTPUT_BYTES=65536;
export const observerControlUnsafe=/(?:\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=._-]{12,}|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"(?:access_token|id_token|refresh_token|SecretAccessKey|SessionToken)"\s*:|(?:authorization|x-api-key)\s*[:=]\s*(?!\*{3})\S{8,})/i;
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const same=(a,b,code)=>need(observerDataHash(a)===observerDataHash(b),code);
const time=(n,d)=>Number.isSafeInteger(n)&&n>=d.startedMs&&n<=d.deadlineMs;
const within=(a,b)=>OBSERVER_COUNTER_KEYS.every(k=>a[k]<=b[k]);
const publicSlots=['runtime/container-metadata','runtime/task-metadata','source/jwks'];
const pending=['context','output','runtime-finalization'];
export function inspectObserverControlOutput(raw,{delivery:d,task,guard}){
 inspectObserverControlDelivery(d);need(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=CONTROL_OUTPUT_BYTES,'ObserverControlOutputBound');
 const value=parseAcquisitionJson(raw,CONTROL_OUTPUT_BYTES);
 exact(value,['version','kind','authority','owner','operation','captureId','sourceTree','stage','deliveryHash','identity','coverageComplete','observations','runtime',...(Object.hasOwn(value,'failure')?['failure']:[])]);
 need(value.version===1&&value.kind==='fixed-observer-route-observation'&&value.authority===false,'ObserverControlOutputKind');
 for(const k of ['owner','operation','captureId','sourceTree','stage'])need(value[k]===d[k],'ObserverControlOutputBinding');
 need(value.deliveryHash===observerDataHash(d)&&typeof value.coverageComplete==='boolean','ObserverControlDeliveryBinding');
 exact(guard,['event','outcome','purpose','pid','noNewPrivs','manifestSha256']);
 need(guard.event==='nonroot_guard'&&guard.outcome==='passed'&&guard.purpose==='preview-observer-route-probe-v1'&&guard.noNewPrivs===1&&Number.isSafeInteger(guard.pid)&&guard.pid>0&&guard.manifestSha256===d.manifestSha256,'ObserverControlGuard');
 need(task.taskDefinitionArn===d.taskDefinitionArn&&task.clusterArn===d.clusterArn&&task.lastStatus==='STOPPED'&&task.enableExecuteCommand===false&&Array.isArray(task.containers),'ObserverControlTask');
 const apps=task.containers.filter(c=>c.name===d.containerName);need(apps.length===1&&apps[0].exitCode===0&&[d.controlImage.rootDigest,d.controlImage.arm64Digest].includes(apps[0].imageDigest),'ObserverControlTaskExit');
 const identity=value.identity,app=apps[0];
 exact(identity,['taskArn','taskDefinitionArn','runtimeId','containerName','image','imageId','containerMetadata','taskMetadata']);
 need(identity.taskArn===task.taskArn&&identity.taskDefinitionArn===task.taskDefinitionArn&&identity.runtimeId===app.runtimeId&&identity.containerName===app.name&&identity.image===app.image&&typeof identity.image==='string'&&identity.image.endsWith('@'+d.controlImage.rootDigest)&&typeof identity.imageId==='string'&&identity.imageId.length>0,'ObserverControlIdentity');
 for(const ref of [identity.containerMetadata,identity.taskMetadata]){exact(ref,['sha256','bytesLength']);need(hex(ref.sha256)&&Number.isSafeInteger(ref.bytesLength)&&ref.bytesLength>0&&ref.bytesLength<=1048576,'ObserverControlMetadataRef');}
 const rows=value.observations;need(Array.isArray(rows)&&rows.length>0&&rows.length<=6,'ObserverControlRouteCoverage');
 let last=d.startedMs,refused=null;
 for(let i=0;i<rows.length;i++){
  const r=rows[i],isRefused=r.kind==='connection-refused',response=Object.hasOwn(r,'response');
  exact(r,['slot','method','urlHash','requestHash','startedMs','completedMs','dnsAddresses','attemptedAddress','requestClosed','responseClosed','kind','statusCode','connectedPeer','responseHash','responseBytes',...(isRefused?['code']:[]),...(response?['response']:[])]);
  need(r.slot===OBSERVER_CONTROL_ROUTE_SLOTS[i]&&r.method===(i<2?'GET':'POST')&&r.urlHash===sha(i<2?d.route.privateOrigin+observerPrivateStatusPath(d.route.jobId):d.route.gatewayUrl)&&hex(r.requestHash),'ObserverControlRouteBinding');
  need(time(r.startedMs,d)&&time(r.completedMs,d)&&r.startedMs>=last&&r.completedMs>=r.startedMs&&r.requestClosed===true&&r.responseClosed===true,'ObserverControlRouteLifetime');last=r.completedMs;
  need(Array.isArray(r.dnsAddresses)&&r.dnsAddresses.length>0&&r.dnsAddresses.length<=64&&new Set(r.dnsAddresses).size===r.dnsAddresses.length&&r.dnsAddresses.every(ip=>isIP(ip)===4)&&r.attemptedAddress===selectObserverPrivatePeer(d,r.slot,r.dnsAddresses),'ObserverControlDns');
  if(isRefused){need(i<2&&i===rows.length-1&&r.code==='ECONNREFUSED'&&r.connectedPeer===null&&r.statusCode===null&&r.responseHash===null&&r.responseBytes===0&&!response,'ObserverControlRefusal');refused=r;continue;}
  const limit=d.allocation.slots.find(s=>s.id===r.slot).responseBytes;
  need(r.kind==='http-response'&&r.dnsAddresses.includes(r.connectedPeer)&&(d.version!==3||r.connectedPeer===r.attemptedAddress)&&Number.isSafeInteger(r.statusCode)&&r.statusCode>=200&&r.statusCode<=599&&!(r.statusCode>=300&&r.statusCode<400)&&hex(r.responseHash)&&Number.isSafeInteger(r.responseBytes)&&r.responseBytes>=0&&r.responseBytes<=limit,'ObserverControlHttpResponse');
  if(i===0||i===2)need([401,403].includes(r.statusCode)&&!response,'ObserverControlUnauthenticated');
  else{
   need(r.statusCode>=200&&r.statusCode<300&&response,'ObserverControlAuthenticated');
   if(i===1)inspectObserverJobStatus(r.response,d.route.jobId);
   if(i===3)inspectObserverMcpInitialization(r.response);
   if(i===4){exact(r.response,['tools','selectedStatusTool']);need(selectObserverStatusTool({tools:r.response.tools})===r.response.selectedStatusTool,'ObserverControlSelectedTool');}
   if(i===5)inspectObserverMcpStatus(r.response,d.route.jobId);
  }
 }
 need(!Object.hasOwn(value,'failure')&&(refused?value.coverageComplete===false:value.coverageComplete===true&&rows.length===6),'ObserverControlDeclaredCoverage');
 const runtime=value.runtime;exact(runtime,['retained','records','publicObjects','localFinalizationSlots','hostPaymentProven']);
 need(runtime.hostPaymentProven===false,'ObserverControlNoSelfPayment');same(runtime.localFinalizationSlots,['context','output'],'ObserverControlPendingFinalization');
 observerCounter(runtime.retained);need(Array.isArray(runtime.records)&&Array.isArray(runtime.publicObjects)&&runtime.publicObjects.length===3,'ObserverControlRuntimeRecords');
 const claimed=d.allocation.slots.filter(s=>!OBSERVER_CONTROL_ROUTE_SLOTS.includes(s.id)||rows.some(r=>r.slot===s.id));
 const retained=zero();for(const s of claimed)for(const k of OBSERVER_COUNTER_KEYS)retained[k]+=s.counter[k];same(runtime.retained,retained,'ObserverControlRetainedCounter');
 const expected=claimed.filter(s=>!pending.includes(s.id)),records=new Map();need(runtime.records.length===expected.length,'ObserverControlRecordCoverage');
 for(const r of runtime.records){
  exact(r,['slot','startedMs','completedMs','retained','used','observationHash','closed']);
  const original=expected.find(s=>s.id===r.slot);need(original&&!records.has(r.slot)&&r.closed===true&&time(r.startedMs,d)&&time(r.completedMs,d)&&r.completedMs>=r.startedMs&&hex(r.observationHash),'ObserverControlRecordBinding');
  observerCounter(r.retained);observerCounter(r.used);same(r.retained,original.counter,'ObserverControlRecordRetention');need(within(r.used,r.retained)&&r.used.logicalBytes>=65536,'ObserverControlRecordUsage');records.set(r.slot,r);
 }
 const record=(id,observation)=>need(records.get(id)?.observationHash===observerDataHash(observation),'ObserverControlRecordObservation');
 for(const r of rows){record(r.slot,r);const paid=records.get(r.slot);need(paid.startedMs<=r.startedMs&&paid.completedMs>=r.completedMs,'ObserverControlRequestRecordTime');}
 record('source/registry',{registryHash:d.route.registryHash,deliveryHash:value.deliveryHash});record('credential-adapter',{fields:6});
 for(const [name,b]of Object.entries(d.credentialBindings))record('source/'+name,{arn:b.arn,version:b.version,sha256:b.sha256,bytesLength:b.bytesLength});
 const objects=new Map();
 for(const r of runtime.publicObjects){
  exact(r,['slot','sha256','bytesLength','base64']);need(publicSlots.includes(r.slot)&&!objects.has(r.slot)&&hex(r.sha256)&&Number.isSafeInteger(r.bytesLength)&&r.bytesLength>0&&r.bytesLength<=d.allocation.slots.find(s=>s.id===r.slot).responseBytes&&typeof r.base64==='string','ObserverControlPublicObject');
  const bytes=Buffer.from(r.base64,'base64');need(bytes.toString('base64')===r.base64&&bytes.length===r.bytesLength&&sha(bytes)===r.sha256,'ObserverControlPublicObjectHash');
  const max=r.slot==='source/jwks'?65536:1048576;need(bytes.length<=max,'ObserverControlPublicObjectBound');
  const decoded=parseAcquisitionJson(bytes,max);need(!observerControlUnsafe.test(bytes.toString('utf8'))&&!observerControlUnsafe.test(JSON.stringify(decoded)),'ObserverControlUnsafePublicObject');
  objects.set(r.slot,{raw:bytes,value:decoded,sha256:r.sha256,bytesLength:r.bytesLength});record(r.slot,{sha256:r.sha256,bytesLength:r.bytesLength,status:200});
 }
 const cr=objects.get(publicSlots[0]),tr=objects.get(publicSlots[1]),jwks=objects.get(publicSlots[2]).value;
 for(const [ref,obj]of [[identity.containerMetadata,cr],[identity.taskMetadata,tr]])same(ref,{sha256:obj.sha256,bytesLength:obj.bytesLength},'ObserverControlMetadataHash');
 const c=cr.value,t=tr.value,matches=t.Containers?.filter(x=>x.Name===d.containerName&&x.DockerId===c.DockerId);
 need(t.TaskARN===task.taskArn&&[d.clusterArn,d.clusterArn.split('/').at(-1)].includes(t.Cluster)&&'arn:aws:ecs:'+d.region+':'+d.account+':task-definition/'+t.Family+':'+t.Revision===d.taskDefinitionArn&&t.LaunchType==='FARGATE','ObserverControlMetadataTask');
 need(matches?.length===1&&c.Name===d.containerName&&c.DockerId===identity.runtimeId&&c.Image===identity.image&&c.ImageID===identity.imageId&&matches[0].Image===c.Image&&matches[0].ImageID===c.ImageID,'ObserverControlMetadataContainer');
 exact(jwks,['keys']);need(Array.isArray(jwks.keys)&&jwks.keys.length>0&&jwks.keys.length<=16&&jwks.keys.every(k=>k&&typeof k==='object'&&!Object.hasOwn(k,'d')),'ObserverControlPublicJwks');
 return {authority:false,value,rawSha256:sha(raw),rawBytes:raw.length,coverage:refused?'private-refusal':'complete',privateObservations:rows.filter(r=>r.slot.startsWith('private-')),ingressObservations:rows.filter(r=>r.slot.startsWith('ingress-')),pendingFinalization:[...pending],finalizationEvidence:'exact guarded source plus original STOPPED task exit0; no fabricated post-output receipt'};
}

/** Canonical responseHash is the original timeline's parsed-object hash.
 * The independent raw wire hashes remain in the full observation archive. */
export function observerPrivateTimelineRoute(checked,{delivery,probeSourceHash,serviceArn}){
 need(checked.authority===false&&hex(probeSourceHash)&&typeof serviceArn==='string','ObserverControlRouteSource');
 const rows=checked.privateObservations,first=rows[0],last=rows.at(-1),path=observerPrivateStatusPath(delivery.route.jobId),startedMs=first.startedMs,completedMs=last.completedMs;
 const common={startedMs,completedMs,probeSourceHash,method:'GET',path,unauthenticatedStatus:rows.length===2?first.statusCode:null,authenticatedStatus:last.statusCode,dnsAddresses:last.dnsAddresses,requestIdHash:hash({owner:delivery.owner,service:serviceArn,startedMs})};
 if(checked.coverage==='private-refusal')return {...common,version:1,kind:'known-connection-failure',authority:false,requestAuthenticated:rows.length===2,attemptedAddress:last.attemptedAddress,attemptedPort:8080,connectedPeer:null,transportError:'ECONNREFUSED',requestStartedMs:last.startedMs,requestCompletedMs:last.completedMs,responseHash:null,response:null};
 need(checked.coverage==='complete'&&rows.length===2,'ObserverControlRouteIncomplete');return {...common,remoteAddress:last.connectedPeer,responseHash:hash(last.response),response:last.response};
}
