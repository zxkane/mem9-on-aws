import {descriptorOperations,descriptorGuard} from './production-nonroot-descriptor-processing.mjs';
/** Prospective carrier HTTP addition only; original templates without it stay legacy. */
const K=1024,M=K*K,need=(v,c='CarrierHttpPolicy')=>{if(!v)throw Error(c);};
const P=Object.freeze({version:1,kind:'carrier-bounded-raw-http',requestMs:30000,drainMs:1000,unknownBytes:8*M,recordBytes:4096,recordChargeBytes:16384,argumentBytes:16384,requestMetadataBytes:131072,responseMetadataBytes:16384,streamFrameBytes:65536,frameMetadataOperations:4,boundaryMetadataOperations:64,metadataOperationBytes:4096,ownerPlanBytes:49152,ownerEvidenceBytes:3*M});
export const describeCarrierHttpPolicy=()=>({...P});
export function carrierHttpLocalAdmission(row,requestBytes,actor='ci'){need(['ci','owner'].includes(actor));return 2*P.argumentBytes+2*row.responseBytes+8*requestBytes+2*(P.requestMetadataBytes+P.responseMetadataBytes)+(P.boundaryMetadataOperations+P.frameMetadataOperations*Math.ceil((row.responseBytes+1)/P.streamFrameBytes))*P.metadataOperationBytes+(actor==='owner'?3*4*P.ownerPlanBytes:0);}
export function inspectCarrierHttpPolicy(v){need(v&&Object.keys(v).sort().join()===Object.keys(P).sort().join()&&Object.keys(P).every(k=>v[k]===P[k]));return describeCarrierHttpPolicy();}
function githubAggregate(t){
 const normal=t.fundedLocal.ci.logicalBytes-(t.bounds.contextBytes+2*M+4*16384);let best=0;
 for(let n=0;n<=244;n++)best=Math.max(best,Math.max(0,Math.min(n*8*M,Math.floor((normal-n*(2*16384+2*16*M+2*16384))/8))));
 return best+16*M;
}
export function carrierHttpCatalog(t,actor){
 inspectCarrierHttpPolicy(t.httpPolicy);need(['ci','owner'].includes(actor));
 const row=(id,count,requestBytes,responseBytes,aggregateBytes=count*(requestBytes+responseBytes))=>({id,count,requestBytes,responseBytes,aggregateBytes});
 return actor==='ci'?[
  row('github',244,0,16*M,githubAggregate(t)),row('artifact-create',1,16*K,64*K),row('artifact-block',1,64*K,64*K),row('artifact-commit',1,16*K,64*K),row('artifact-finalize',1,16*K,64*K)
 ]:[row('github',127,16*K,M),row('artifact-redirect',1,0,64*K),row('artifact-download',1,0,64*K),row('secret-key',1,0,M),row('secret-put',1,128*K,M)];
}
export function carrierHttpAdditionalBudget(t,{descriptorWork}={}){const {JSON}=descriptorOperations(descriptorWork,DESCRIPTOR_BASE_OPERATIONS);descriptorGuard(descriptorWork,t);
 inspectCarrierHttpPolicy(t.httpPolicy);const zero=()=>({ecrRequests:0,logicalBytes:0,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0}),out={};
 for(const actor of ['ci','owner']){const bytes=carrierHttpCatalog(t,actor).reduce((n,r)=>n+r.aggregateBytes,0);out[actor]={...zero(),logicalBytes:bytes,httpBodyBytes:bytes};}
 return out;
}
export function inspectCarrierHttpEvidence(value,t,actor,events,expectedBinding,{descriptorWork}={}){const {JSON}=descriptorOperations(descriptorWork,DESCRIPTOR_BASE_OPERATIONS);descriptorGuard(descriptorWork,value,t,events,expectedBinding);
 const rows=carrierHttpCatalog(t,actor);need(value?.version===1&&value.kind==='carrier-raw-http-evidence'&&value.actor===actor&&Array.isArray(value.rows),'CarrierHttpEvidence');
 need(value.binding&&Object.keys(value.binding).sort().join()==='grantHash,planHash'&&Object.values(value.binding).every(v=>/^[a-f0-9]{64}$/.test(v)),'CarrierHttpEvidenceBinding');if(expectedBinding)need(['planHash','grantHash'].every(k=>value.binding[k]===expectedBinding[k]),'CarrierHttpEvidenceBinding');
 need(value.rows.length===rows.length,'CarrierHttpEvidence');let active=0;
 for(const [i,row]of rows.entries()){const v=value.rows[i];need(v.id===row.id&&Number.isSafeInteger(v.calls)&&v.calls>=0&&v.calls<=row.count&&Number.isSafeInteger(v.requestBytes)&&v.requestBytes>=0&&Number.isSafeInteger(v.responseBytes)&&v.responseBytes>=0&&v.requestBytes+v.responseBytes<=row.aggregateBytes+P.unknownBytes,'CarrierHttpEvidence');need(Number.isSafeInteger(v.unknown)&&v.unknown>=0&&v.unknown<=1,'CarrierHttpEvidence');active+=v.unknown;}
 need(active<=1&&typeof value.held==='boolean'&&typeof value.closed==='boolean','CarrierHttpEvidence');
 if(events!==undefined){const replay=replayCarrierHttpEvents(events,t,actor,value.binding,{descriptorWork});need(JSON.stringify(replay.rows)===JSON.stringify(value.rows),'CarrierHttpReplayTotals');need(!replay.held||value.held,'CarrierHttpReplayHeld');}
 return value;
}
export function replayCarrierHttpEvents(events,t,actor,expectedBinding=events[0]?.binding,{descriptorWork}={}){const {JSON}=descriptorOperations(descriptorWork,DESCRIPTOR_BASE_OPERATIONS);descriptorGuard(descriptorWork,events,t,expectedBinding);
 need(Array.isArray(events)&&events.length<=1024,'CarrierHttpReplay');const catalog=carrierHttpCatalog(t,actor),rows=catalog.map(r=>({id:r.id,calls:0,requestBytes:0,responseBytes:0,unknown:0}));let current,sequence=0,held=false;
 for(const e of events){
  need(e&&e.version===1&&e.kind==='carrier-http-intent'&&e.actor===actor&&e.binding&&expectedBinding&&['planHash','grantHash'].every(k=>e.binding[k]===expectedBinding[k]),'CarrierHttpReplayBinding');const index=catalog.findIndex(r=>r.id===e.id),p=catalog[index],r=rows[index];need(p,'CarrierHttpReplay');
  if(!Object.hasOwn(e,'outcome')){
   need(!current&&!held&&e.ordinal===++sequence&&r.calls<p.count&&['GET','POST','PUT'].includes(e.method)&&/^[a-f0-9]{64}$/.test(e.urlHash),'CarrierHttpReplayIntent');
   need(Number.isSafeInteger(e.requestBytes)&&e.requestBytes>=0&&e.requestBytes<=p.requestBytes&&e.responseBytes===p.responseBytes&&r.requestBytes+r.responseBytes+e.requestBytes+p.responseBytes<=p.aggregateBytes,'CarrierHttpReplayBudget');r.calls++;current=e;
  }else{
   need(current&&['actor','id','ordinal','method','urlHash','requestBytes','responseBytes'].every(k=>e[k]===current[k]),'CarrierHttpReplayPair');
   need(Number.isSafeInteger(e.observedRequestBytes)&&e.observedRequestBytes>=0&&e.observedRequestBytes<=e.requestBytes&&Number.isSafeInteger(e.observedResponseBytes)&&e.observedResponseBytes>=0&&e.observedResponseBytes<=e.responseBytes+1,'CarrierHttpReplayBytes');
   if(e.outcome==='complete'){need(e.observedRequestBytes===e.requestBytes&&e.observedResponseBytes<=e.responseBytes&&[200,201,204,302].includes(e.status)&&/^[a-f0-9]{64}$/.test(e.requestHash)&&/^[a-f0-9]{64}$/.test(e.responseHash),'CarrierHttpReplayComplete');}
   else if(e.outcome==='unknown'){need(e.chargedUnknownBytes===e.requestBytes+e.responseBytes+P.unknownBytes&&Number.isSafeInteger(e.hashedResponseBytes)&&e.hashedResponseBytes>=0&&e.hashedResponseBytes<=e.observedResponseBytes&&/^[a-f0-9]{64}$/.test(e.partialResponseHash),'CarrierHttpReplayUnknown');r.unknown++;held=true;}
   else{need(e.outcome==='not-dispatched'&&e.observedRequestBytes===0&&e.observedResponseBytes===0&&e.chargedUnknownBytes===0,'CarrierHttpReplayUnsubmitted');held=true;}
   r.requestBytes+=e.observedRequestBytes;r.responseBytes+=e.observedResponseBytes;current=undefined;
  }
 }
 need(!current,'CarrierHttpReplayIncomplete');return {rows,held};
}

const DESCRIPTOR_BASE_OPERATIONS={JSON};
