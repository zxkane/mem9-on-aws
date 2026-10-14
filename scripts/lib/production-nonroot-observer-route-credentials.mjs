/** Pure credential processing shared by host baseline and CONTROL runtime.
 * Callers retain their own original permits, prepayment and cleanup. */
import {createHash,createPublicKey,verify,constants} from 'node:crypto';
import {canonicalJson,parseClientRegistry,classifyAccessToken,parseSigningKeys,createInternalContext,verifyInternalContext,createTransportEnvelope,verifyTransportEnvelope,CONTEXT_TTL_SECONDS} from '../../infra/gateway/namespace-auth.mjs';
import {observerPrivateStatusPath} from './production-nonroot-observer-route-protocol.mjs';

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
