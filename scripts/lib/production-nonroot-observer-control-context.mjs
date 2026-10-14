import {describeObserverContextProcessing,verifyObserverRouteCredentials,createObserverPrivateHeaders,clearObserverVerifiedCredentials} from './production-nonroot-observer-route-credentials.mjs';
export {describeObserverContextProcessing,verifyObserverRouteCredentials,createObserverPrivateHeaders,clearObserverVerifiedCredentials};
import {OBSERVER_PEER_LOCAL,inspectObserverPeerInventory,selectObserverPrivatePeer} from './production-nonroot-observer-peer-inventory.mjs';
import {createHash} from 'node:crypto';
import {observerPrivateStatusPath,inspectObserverRouteProbeInput,describeObserverRouteProbeWork} from './production-nonroot-observer-route-probe.mjs';
import * as runtime from './production-nonroot-observer-runtime-provider.mjs';
import {observerDataHash,observerBytesHash,observerZeroCounter,OBSERVER_COUNTER_KEYS} from './production-nonroot-observer-delivery.mjs';

const contexts=new WeakMap(),usedGuards=new WeakSet(),local=logicalBytes=>({...observerZeroCounter(),logicalBytes});

const need=(v,code='ObserverContextRejected')=>{if(!v)throw Object.assign(Error(code),{code,hold:true});};
const sha=b=>createHash('sha256').update(b).digest('hex');
const names=['accessToken','jwks','registry','identitySigningKeys','transportSigningKeys','tenantKey'];
const exact=(v,keys)=>need(v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join()===keys.toSorted().join());

/** The provider's private WeakMap is the sole source of task/permit custody.
 * This never accepts a clock, verifier, fetcher, reader or success callback. */
export async function openObserverControlContext(delivery,guardInvocation,provider){
 // The installed entry owns the opaque invocation. An operator-tree copy,
 // even with identical bytes, has a different WeakMap and is not authority.
 const {requireGuardedObserverInvocation}=await import('/bootstrap/nonroot-dispatch.mjs');
 const guard=requireGuardedObserverInvocation(guardInvocation);
 need(!usedGuards.has(guardInvocation),'ObserverContextGuardOnce');usedGuards.add(guardInvocation);
 const contextPermit=runtime.claimObserverRuntimeProcessing(provider,'context');
 let outputPermit,context;
 try{
  // The literal bound is independent of attacker-selected decoded lengths.
  // Debit before delivery hashing, cloning, registry or credential work.
  const contextLocal=64*262144+16*6*65536+32*65536+6*4096+128*4096+(delivery.version===3?OBSERVER_PEER_LOCAL:0);
  runtime.chargeObserverRuntimeProcessing(provider,contextPermit,contextLocal);
  const value=inspectObserverRouteProbeInput(delivery);if(value.version===3)inspectObserverPeerInventory(value.peerInventory,value);const deliveryHash=observerDataHash(value),quote=describeObserverRouteProbeWork(value);
  outputPermit=runtime.claimObserverRuntimeProcessing(provider,'output');
  runtime.chargeObserverRuntimeProcessing(provider,outputPermit,quote.output.processingLocal);
  const state=runtime.observerRuntimeState(provider);
  need(guard.purpose==='preview-observer-route-probe-v1'&&guard.manifestSha256===value.manifestSha256&&state.deliveryHash===deliveryHash&&state.startedMs===value.startedMs&&state.deadlineMs===value.deadlineMs,'ObserverContextBinding');
  need(state.payloadSha256===guard.payloadSha256&&state.owner===value.owner&&state.operation===value.operation&&state.captureId===value.captureId&&state.taskRoleArn===value.taskRoleArn,'ObserverContextOriginalProvider');
  need(state.identity?.taskDefinitionArn===value.taskDefinitionArn&&state.identity.containerName===value.containerName&&typeof state.identity.taskArn==='string','ObserverContextTask');
  for(const term of [quote.context,quote.output,...quote.slots]){
   const row=value.allocation.slots.find(r=>r.id===term.id);need(row&&OBSERVER_COUNTER_KEYS.every(k=>row.counter[k]>=term.charge[k]),'ObserverContextAllocation');
  }
  const s={provider,guardInvocation,contextPermit,outputPermit,delivery:structuredClone(value),deliveryHash,identity:state.identity,quote,requests:new Map(),credentialsActive:false,credentialsUsed:false,failed:false,closed:false,outputDone:false,contextDone:false,privateExpiry:null,tokenExpiry:null};
  context=Object.freeze({
   assertCurrent(){const p=contexts.get(context);need(p&&!p.closed,'ObserverContextClosed');requireGuardedObserverInvocation(p.guardInvocation);runtime.assertObserverRuntimeRequest(provider,p.contextPermit);},
   get deliveryVersion(){context.assertCurrent();return s.delivery.version;},
   get deliveryHash(){context.assertCurrent();return s.deliveryHash;},
   get identity(){context.assertCurrent();return structuredClone(s.identity);},
   now(){context.assertCurrent();return Date.now();},
   beginRequest(id,request){
    context.assertCurrent();need(s.credentialsActive&&!s.requests.has(id),'ObserverContextRequestOnce');const term=s.quote.slots.find(r=>r.id===id);need(term,'ObserverContextSlot');
    const isPrivate=id.startsWith('private-');need(request&&request.method===(isPrivate?'GET':'POST')&&request.url===(isPrivate?s.delivery.route.privateOrigin+observerPrivateStatusPath(s.delivery.route.jobId):s.delivery.route.gatewayUrl),'ObserverContextRequestBinding');
    const permit=runtime.claimObserverRuntimeRequest(provider,id);s.requests.set(id,{permit,id,done:false,io:null,deadlineMs:Math.min(s.delivery.deadlineMs,id==='private-auth'?(s.privateExpiry??0):id.includes('unauth')?s.delivery.deadlineMs:(s.tokenExpiry??0))});
    runtime.chargeObserverRuntimeRequest(provider,permit,local(term.processingLocal));context.assertRequest(permit);return permit;
   },
   assertRequest(permit){context.assertCurrent();runtime.assertObserverRuntimeRequest(provider,permit);const p=[...s.requests.values()].find(p=>p.permit===permit);need(p&&!p.done&&Date.now()<p.deadlineMs,'ObserverContextRequestExpired');},
   selectPrivatePeer(permit,addresses){context.assertRequest(permit);const p=[...s.requests.entries()].find(([,p])=>p.permit===permit);need(p,'ObserverContextRequest');if(s.delivery.version===3)need(s.delivery.peerInventory.completedMs<=Date.now(),'ObserverPeerFuture');return selectObserverPrivatePeer(s.delivery,p[0],addresses);},
   requestLimits(permit){context.assertRequest(permit);const limits=runtime.observerRuntimeRequestLimits(provider,permit),p=[...s.requests.values()].find(p=>p.permit===permit);return {...limits,deadlineMs:Math.min(limits.deadlineMs,p.deadlineMs)};},
   chargeWire(permit,bytes){context.assertRequest(permit);runtime.chargeObserverRuntimeRequest(provider,permit,{...observerZeroCounter(),httpBodyBytes:bytes});},
   retainIo(permit,io){context.assertRequest(permit);runtime.retainObserverRuntimeIo(provider,permit,io);[...s.requests.values()].find(p=>p.permit===permit).io=io;},
   finishRequest(permit,observation){context.assertRequest(permit);const result=runtime.finishObserverRuntimeRequest(provider,permit,observation);[...s.requests.values()].find(p=>p.permit===permit).done=true;return result;},
   failRequest(permit){s.failed=true;const p=[...s.requests.values()].find(p=>p.permit===permit);if(p&&!p.done){runtime.failObserverRuntimeRequest(provider,permit);p.done=true;}},
   async withCredentials(consume){
    context.assertCurrent();need(!s.credentialsUsed&&typeof consume==='function','ObserverContextCredentialsOnce');s.credentialsUsed=true;
    try{
     const result=await runtime.withObserverRuntimeCredentials(provider,async(raw,receipt)=>{
      context.assertCurrent(); // callback resumes under the original permit
      exact(raw,names);for(const name of names)need(raw[name] instanceof Uint8Array&&raw[name].byteLength>0&&raw[name].byteLength<=65536,'ObserverContextRawCredential');
      need(observerDataHash(receipt.identity)===observerDataHash(s.identity),'ObserverContextCredentialTask');
      for(const name of ['tenantKey','identitySigningKeys','transportSigningKeys']){
       const binding=s.delivery.credentialBindings[name],r=receipt.sources[name];
       need(r?.arn===binding.arn&&r.version===binding.version&&r.sha256===binding.sha256&&r.bytesLength===binding.bytesLength&&raw[name].length===binding.bytesLength&&sha(raw[name])===binding.sha256,'ObserverContextCredentialSource');
      }
      need(raw.jwks.length===receipt.jwks.bytesLength&&sha(raw.jwks)===receipt.jwks.sha256&&raw.accessToken.length===receipt.token.bytesLength&&sha(raw.accessToken)===receipt.token.sha256,'ObserverContextOriginalRaw');
      const verified=verifyObserverRouteCredentials(s.delivery.route,raw,Date.now());s.tokenExpiry=verified.claims.exp*1000;s.credentialsActive=true;
      const credentials=Object.freeze({
       privateHeaders(){context.assertCurrent();need(s.credentialsActive,'ObserverContextCredentialsClosed');const signed=createObserverPrivateHeaders(s.delivery.route,verified,Date.now(),s.delivery.deadlineMs);s.privateExpiry=signed.receipt.expiresMs;return signed;},
       ingressHeaders(){context.assertCurrent();need(s.credentialsActive&&Date.now()<s.tokenExpiry,'ObserverContextCredentialsClosed');return {Authorization:'Bearer '+verified.accessToken};},
      });
      try{const value=await consume(credentials);context.assertCurrent();return value;}
      finally{s.credentialsActive=false;clearObserverVerifiedCredentials(verified);}
     });context.assertCurrent();return result;
    }catch(e){s.failed=true;throw e;}
   },
  });contexts.set(context,s);return context;
 }catch(e){
  if(outputPermit)try{runtime.failObserverRuntimeRequest(provider,outputPermit);}catch{}
  try{runtime.failObserverRuntimeRequest(provider,contextPermit);}catch{}
  throw e;
 }
}

export function requireObserverControlContext(context){
 const s=contexts.get(context);need(s&&!s.closed,'ObserverOriginalControlContext');context.assertCurrent();return context;
}

/** Prepare and debit output while its original context/output permits are
 * still live. This is route DATA, not a task-cleanup or host-payment receipt. */
export function encodeObserverRouteObservation(context,value){
 requireObserverControlContext(context);const s=contexts.get(context);runtime.assertObserverRuntimeRequest(s.provider,s.outputPermit);
 need(!s.outputDone&&!s.credentialsActive&&[...s.requests.values()].every(p=>p.done&&p.io?.request?.closed===true&&(!p.io.response||p.io.response.closed===true)),'ObserverContextPendingIo');
  const providerState=runtime.observerRuntimeState(s.provider);
  const raw=JSON.stringify({...value,runtime:{retained:providerState.retained,records:providerState.records,publicObjects:providerState.publicObjects,localFinalizationSlots:['context','output'],hostPaymentProven:false}})+'\n';need(Buffer.byteLength(raw)<=65536,'ObserverContextOutputBound');return raw;
}
export function finishObserverRouteObservation(context,raw){
 requireObserverControlContext(context);const s=contexts.get(context);runtime.assertObserverRuntimeRequest(s.provider,s.outputPermit);need(!s.outputDone&&typeof raw==='string'&&Buffer.byteLength(raw)<=65536,'ObserverContextOutputBound');
 runtime.finishObserverRuntimeRequest(s.provider,s.outputPermit,{sha256:observerBytesHash(raw),bytesLength:Buffer.byteLength(raw)});s.outputDone=true;
}

export async function closeObserverControlContext(context){
 const s=contexts.get(context);need(s&&!s.closed,'ObserverOriginalControlContext');
 let failure=s.failed?Error('ObserverContextHeld'):null;
 try{
  if(!s.failed){context.assertCurrent();need(!s.credentialsActive&&s.outputDone&&[...s.requests.values()].every(p=>p.done),'ObserverContextPendingIo');runtime.finishObserverRuntimeRequest(s.provider,s.contextPermit,{deliveryHash:s.deliveryHash});s.contextDone=true;}
 }catch(e){s.failed=true;failure=e;}
 s.closed=true;
 // No decoder/hash/clone runs in P after this await. D performs its bounded
 // original cleanup and constructs its own receipt before returning it.
 if(failure){try{await runtime.closeObserverRuntimeProvider(s.provider);}finally{throw failure;}}
 return await runtime.closeObserverRuntimeProvider(s.provider);
}
