import {OBSERVER_PEER_LOCAL,inspectObserverPeerInventory,selectObserverPrivatePeer} from './production-nonroot-observer-peer-inventory.mjs';
import {createHash,createPublicKey,verify,constants} from 'node:crypto';
import {canonicalJson,parseClientRegistry,classifyAccessToken,parseSigningKeys,createInternalContext,verifyInternalContext,createTransportEnvelope,verifyTransportEnvelope,CONTEXT_TTL_SECONDS} from '../../infra/gateway/namespace-auth.mjs';
import {observerPrivateStatusPath,inspectObserverRouteProbeInput,describeObserverRouteProbeWork} from './production-nonroot-observer-route-probe.mjs';
import * as runtime from './production-nonroot-observer-runtime-provider.mjs';
import {observerDataHash,observerBytesHash,observerZeroCounter,OBSERVER_COUNTER_KEYS} from './production-nonroot-observer-delivery.mjs';

const contexts=new WeakMap(),usedGuards=new WeakSet(),local=logicalBytes=>({...observerZeroCounter(),logicalBytes});

const need=(v,code='ObserverContextRejected')=>{if(!v)throw Object.assign(Error(code),{code,hold:true});};
const sha=b=>createHash('sha256').update(b).digest('hex');
const hash=v=>sha(canonicalJson(v));
const names=['accessToken','jwks','registry','identitySigningKeys','transportSigningKeys','tenantKey'];
const exact=(v,keys)=>need(v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join()===keys.toSorted().join());
const text=raw=>{need(raw instanceof Uint8Array&&raw.byteLength>0&&raw.byteLength<=65536);return new TextDecoder('utf-8',{fatal:true}).decode(raw);};
const parse=raw=>JSON.parse(text(raw));
const decodePart=part=>{need(typeof part==='string'&&/^[A-Za-z0-9_-]+$/.test(part));const b=Buffer.from(part,'base64url');need(b.length<=65536&&b.toString('base64url')===part);return parse(b);};

/** Pure bounded cryptographic processing price, additional to D's original
 * source retrieval/transport/cleanup work. This is not a payment capability. */
export function describeObserverContextProcessing(lengths){
 exact(lengths,names);for(const n of Object.values(lengths))need(Number.isSafeInteger(n)&&n>0&&n<=65536);
 return Object.freeze({authority:false,logicalBytes:16*Object.values(lengths).reduce((a,b)=>a+b,0)+32*65536+6*4096,
  rsaVerification:1,internalMacCreate:1,internalMacVerify:1,transportMacCreate:1,transportMacVerify:1,maximumRsaBits:4096});
}

/** Pure verification core reused from the reviewed sample context producer.
 * The fixed runtime context must assert its original permit and prepay the
 * complete processing term before calling this synchronous function. Returned
 * transient values are never a runtime context or an original owner handle. */
export function verifyObserverRouteCredentials(route,raw,nowMs){
 let identityKeys,transportKeys;
 try{
  exact(raw,names);for(const name of names)text(raw[name]);
  need(Number.isSafeInteger(nowMs)&&nowMs>0);const now=Math.floor(nowMs/1000),token=text(raw.accessToken),parts=token.split('.');need(parts.length===3);
  const header=decodePart(parts[0]);exact(header,Object.hasOwn(header,'typ')?['alg','kid','typ']:['alg','kid']);
  need(header.alg==='RS256'&&(!header.typ||header.typ==='JWT')&&typeof header.kid==='string'&&header.kid.length>0&&header.kid.length<=256);
  const jwks=parse(raw.jwks);exact(jwks,['keys']);need(Array.isArray(jwks.keys)&&jwks.keys.length>0&&jwks.keys.length<=16);
  for(const key of jwks.keys)need(key&&typeof key==='object'&&!['d','p','q','dp','dq','qi','oth','k'].some(k=>Object.hasOwn(key,k)),'ObserverContextPrivateJwk');
  const matching=jwks.keys.filter(k=>k.kid===header.kid);need(matching.length===1);const jwk=matching[0];
  need(jwk.kty==='RSA'&&jwk.alg==='RS256'&&jwk.use==='sig'&&jwk.e==='AQAB'&&typeof jwk.n==='string'&&/^[A-Za-z0-9_-]+$/.test(jwk.n)&&Buffer.from(jwk.n,'base64url').length<=512&&!Object.hasOwn(jwk,'d'));
  const key=createPublicKey({key:jwk,format:'jwk'});need(key.asymmetricKeyType==='rsa'&&key.asymmetricKeyDetails.modulusLength>=2048&&key.asymmetricKeyDetails.modulusLength<=4096&&key.asymmetricKeyDetails.publicExponent===65537n);
  const signature=Buffer.from(parts[2],'base64url');need(signature.toString('base64url')===parts[2]&&signature.length===Math.ceil(key.asymmetricKeyDetails.modulusLength/8)&&verify('RSA-SHA256',Buffer.from(parts[0]+'.'+parts[1]),{key,padding:constants.RSA_PKCS1_PADDING},signature));
  const claims=decodePart(parts[1]);
  need(claims.iss===route.issuer&&Number.isSafeInteger(claims.iat)&&claims.iat<=now&&Number.isSafeInteger(claims.exp)&&claims.exp>=now+CONTEXT_TTL_SECONDS&&claims.exp>claims.iat&&(!Object.hasOwn(claims,'nbf')||Number.isSafeInteger(claims.nbf)&&claims.nbf<=now));
  need(claims.scope==='mem9-mcp/read','ObserverContextReadScope');
  need(sha(raw.registry)===route.registryHash,'ObserverContextRegistry');
  const registry=parseClientRegistry(text(raw.registry));need(registry.issuer===route.issuer&&(registry.audience??null)===route.audience);
  const identity=classifyAccessToken(token,registry);need(identity.principalType==='m2m'&&hash(identity)===route.identityHash,'ObserverContextIdentity');
  identityKeys=parseSigningKeys(text(raw.identitySigningKeys));transportKeys=parseSigningKeys(text(raw.transportSigningKeys));
  // Distinct source references are checked by D. Actual key material is also
  // kept separate here; a single r3 keyring cannot stand in for both sources.
  for(const a of identityKeys.keys.values())for(const b of transportKeys.keys.values())need(!a.equals(b),'ObserverContextDistinctKeys');
  const tenantKey=text(raw.tenantKey);need(tenantKey.length<=16384&&!/[\r\n\x00]/.test(tenantKey));
  return {identity,claims,identityKeys,transportKeys,tenantKey,accessToken:token};
 }catch{
  for(const keys of [identityKeys,transportKeys])if(keys)for(const key of keys.keys.values())key.fill(0);
  throw Object.assign(Error('ObserverContextRejected'),{code:'ObserverContextRejected',hold:true});
 }
}

/** Synchronous same-frame operation. Caller must assert its current original
 * permit immediately before this call, including after any preceding await. */
export function createObserverPrivateHeaders(route,verified,nowMs,deadlineMs){
 need(Number.isSafeInteger(nowMs)&&Number.isSafeInteger(deadlineMs)&&nowMs<deadlineMs);
 const now=Math.floor(nowMs/1000),expiresMs=(now+CONTEXT_TTL_SECONDS)*1000;
 need(expiresMs<=deadlineMs&&expiresMs<=verified.claims.exp*1000,'ObserverContextExpiry');
 const invocation={tool:'get_ingest_job_status',arguments:{job_id:route.jobId}};
 const context=createInternalContext({identity:verified.identity,invocation,keys:verified.identityKeys,now});
 const internal=verifyInternalContext({context,invocation,keys:verified.identityKeys,now});
 const path=observerPrivateStatusPath(route.jobId),envelope=createTransportEnvelope({issuer:route.transportIssuer,method:'GET',path,body:'',identity:internal,keys:verified.transportKeys,now});
 const checked=verifyTransportEnvelope({envelope,issuer:route.transportIssuer,method:'GET',path,body:'',keys:verified.transportKeys,now});
 need(checked.expires_at===now+CONTEXT_TTL_SECONDS&&checked.expires_at*1000===expiresMs);
 return {headers:{['x-api-key']:verified.tenantKey,'x-mem9-transport':envelope},
  receipt:{authority:false,identityHash:hash(verified.identity),tokenHash:sha(verified.accessToken),contextHash:hash(context),envelopeHash:sha(envelope),issuedMs:now*1000,expiresMs}};
}

export function clearObserverVerifiedCredentials(value){
 for(const keys of [value?.identityKeys,value?.transportKeys])if(keys)for(const key of keys.keys.values())key.fill(0);
 if(value){value.accessToken='';value.tenantKey='';}
}

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
