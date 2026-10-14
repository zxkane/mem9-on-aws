import {describe,it,expect} from 'vitest';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {rolldown} from 'rolldown';
import {verifyObserverRouteCredentials,createObserverPrivateHeaders,clearObserverVerifiedCredentials,describeObserverContextProcessing} from './lib/production-nonroot-observer-control-context.mjs';
import * as contextExports from './lib/production-nonroot-observer-control-context.mjs';
import * as credentialExports from './lib/production-nonroot-observer-route-credentials.mjs';
import {canonicalJson,classifyAccessToken,parseClientRegistry,parseSigningKeys,verifyTransportEnvelope} from '../infra/gateway/namespace-auth.mjs';
import {requireGuardedObserverInvocation} from '../docker/bootstrap/nonroot-dispatch.mjs';
import {resolveGuardPurpose} from '../docker/bootstrap/nonroot-identity.mjs';
import {requireObserverControlContext} from './lib/production-nonroot-observer-control-context.mjs';
const pair=generateKeyPairSync('rsa',{modulusLength:2048}),publicKey={...pair.publicKey.export({format:'jwk'}),kid:'fixture-rsa',alg:'RS256',use:'sig'};
const sha=b=>createHash('sha256').update(b).digest('hex'),hash=v=>sha(canonicalJson(v));
const b64=v=>Buffer.from(JSON.stringify(v)).toString('base64url');
function fixture(change=()=>{}){
 const issuer='https://issuer.example.com',registry={human:['fixture-human'],m2m:['fixture-read'],issuer,audience:'fixture-api'};
 const claims={iss:issuer,aud:'fixture-api',token_use:'access',client_id:'fixture-read',scope:'mem9-mcp/read',iat:900,exp:7200};change({claims,registry});
 const signingInput=b64({alg:'RS256',kid:'fixture-rsa',typ:'JWT'})+'.'+b64(claims),token=signingInput+'.'+sign('RSA-SHA256',Buffer.from(signingInput),pair.privateKey).toString('base64url');
 const raw={accessToken:Buffer.from(token),jwks:Buffer.from(JSON.stringify({keys:[publicKey]})),registry:Buffer.from(JSON.stringify(registry)),identitySigningKeys:Buffer.from(JSON.stringify({current:Buffer.alloc(32,7).toString('base64url')})),transportSigningKeys:Buffer.from(JSON.stringify({current:Buffer.alloc(32,9).toString('base64url')})),tenantKey:Buffer.from('synthetic-tenant-key')};
 let identity;try{identity=classifyAccessToken(token,parseClientRegistry(raw.registry.toString()));}catch{identity=null;}
 return {raw,route:{issuer,audience:'fixture-api',identityHash:hash(identity),registryHash:sha(raw.registry),jobId:'a'.repeat(32),transportIssuer:'fixture-transport'},token};
}
describe('real crypto cores only; no original runtime provider or host payment claim',()=>{
 it('shares the exact credential function exports without exporting runtime handles',()=>{
  const names=['describeObserverContextProcessing','verifyObserverRouteCredentials','createObserverPrivateHeaders','clearObserverVerifiedCredentials'];
  expect(Object.keys(credentialExports).sort()).toEqual(names.sort());
  for(const name of names)expect(contextExports[name]).toBe(credentialExports[name]);
 });
 it('scans the complete host credential dependency graph without container runtime imports',async()=>{
  const entry=fileURLToPath(new URL('./lib/production-nonroot-observer-route-credentials.mjs',import.meta.url));
  let modules=[];
  const bundle=await rolldown({input:entry,platform:'node',treeshake:false,
   onwarn:warning=>{throw Error(warning.code);},
   plugins:[{name:'credential-closure',buildEnd(){modules=[...this.getModuleIds()];}}]});
  try{await bundle.generate({format:'esm',codeSplitting:false});}finally{await bundle.close();}
  expect(modules).toContain(entry);
  expect(modules.some(path=>path.endsWith('/infra/gateway/namespace-auth.mjs'))).toBe(true);
  expect(modules.some(path=>path.endsWith('/infra/gateway/service-auth.mjs'))).toBe(true);
  for(const path of modules)expect(path).not.toMatch(/nonroot-dispatch|observer-control-context|observer-runtime-provider|observer-route-probe/);
 });
 it('allows only the exact preview purpose and fixed module; JSON cannot become a guard or runtime context',()=>{
  const purpose='preview-observer-route-probe-v1',env={MEM9_STAGE:'pr-273',MEM9_OBSERVER_CONTROL_DELIVERY:'{"version":1}'};
  expect(resolveGuardPurpose(purpose,env)).toEqual({kind:'observer',module:'/bootstrap/operator/scripts/lib/production-nonroot-observer-route-probe.mjs',operation:purpose});
  for(const bad of [{...env,MEM9_STAGE:'prod'},{...env,MEM9_API_KEY:'not-allowed'},{...env,MNEMO_DSN:'not-allowed'},{...env,MEM9_OBSERVER_CONTROL_DELIVERY:'x'.repeat(8193)}])expect(()=>resolveGuardPurpose(purpose,bad)).toThrow();
  expect(()=>resolveGuardPurpose(purpose+'-other',env)).toThrow();
  expect(()=>requireGuardedObserverInvocation({purpose,manifestSha256:'a'.repeat(64),payloadSha256:'b'.repeat(64)})).toThrow();
  expect(()=>requireObserverControlContext({success:true})).toThrow();
 });
 it('preserves the existing bootstrap and consolidation purpose routes',()=>{
  expect(resolveGuardPurpose('bootstrap-runtime-verify',{MEM9_STAGE:'pr-273',MEM9_BOOTSTRAP_OPERATION:'runtime-verify',MEM9_RUNTIME_BOOTSTRAP_VERSION:'1'})).toEqual({kind:'module',module:'/bootstrap/operator/scripts/runtime-bootstrap.mjs',operation:'runtime-verify'});
  expect(resolveGuardPurpose('consolidation-control',{MEM9_STAGE:'prod',MEM9_PRODUCTION_WORKER_OPERATOR:'control'}).operation).toBe('control');
  expect(()=>resolveGuardPurpose('consolidation-control',{MEM9_STAGE:'pr-273',MEM9_PRODUCTION_WORKER_OPERATOR:'control'})).toThrow();
 });
 it('uses actual namespace verification with distinct keys and a fresh30s envelope',()=>{
  const f=fixture(),verified=verifyObserverRouteCredentials(f.route,f.raw,1000000);
  try{
   const a=createObserverPrivateHeaders(f.route,verified,1000000,1100000),b=createObserverPrivateHeaders(f.route,verified,1030000,1100000);
   const keys=parseSigningKeys(f.raw.transportSigningKeys.toString());
   const checked=verifyTransportEnvelope({envelope:a.headers['x-mem9-transport'],issuer:f.route.transportIssuer,method:'GET',path:'/v1alpha2/mem9s/ingest-jobs/'+f.route.jobId,body:'',keys,now:1000});
   expect(checked.expires_at-checked.issued_at).toBe(30);expect(a.receipt.expiresMs).toBe(1030000);expect(b.receipt.envelopeHash).not.toBe(a.receipt.envelopeHash);
   expect(JSON.stringify(a.receipt)).not.toContain(f.token);expect(JSON.stringify(a.receipt)).not.toContain('synthetic-tenant-key');
   expect(()=>verifyTransportEnvelope({envelope:a.headers['x-mem9-transport'],issuer:f.route.transportIssuer,method:'POST',path:'/v1alpha2/mem9s/ingest-jobs/'+f.route.jobId,body:'',keys,now:1000})).toThrow();
   expect(()=>createObserverPrivateHeaders(f.route,verified,1000000,1029999)).toThrow();
  }finally{clearObserverVerifiedCredentials(verified);}
  expect(verified.accessToken).toBe('');expect(verified.tenantKey).toBe('');expect([...verified.identityKeys.keys.values()].every(k=>k.every(n=>n===0))).toBe(true);
 });
 for(const [name,change]of [
  ['wrong issuer',({claims})=>claims.iss='https://foreign.example.com'],
  ['wrong audience',({claims})=>claims.aud='foreign'],
  ['expired',({claims})=>claims.exp=999],
  ['future issued',({claims})=>claims.iat=1001],
  ['not active',({claims})=>claims.nbf=1001],
  ['no read scope',({claims})=>claims.scope='mem9-mcp/write'],
  ['overprivileged scopes',({claims})=>claims.scope='mem9-mcp/read mem9-mcp/write'],
  ['human client',({claims})=>{claims.client_id='fixture-human';claims.sub='human-subject';}],
 ])it('rejects '+name,()=>{const f=fixture(change);expect(()=>verifyObserverRouteCredentials(f.route,f.raw,1000000)).toThrow('ObserverContextRejected');});
 for(const [name,change]of [
  ['wrong signature',f=>{const parts=f.raw.accessToken.toString().split('.');parts[2]=Buffer.alloc(256,1).toString('base64url');f.raw.accessToken=Buffer.from(parts.join('.'));}],
  ['wrong identity',f=>f.route.identityHash='0'.repeat(64)],
  ['wrong registry bytes',f=>f.raw.registry=Buffer.from(f.raw.registry.toString()+' ')],
  ['same keyring',f=>f.raw.transportSigningKeys=Buffer.from(f.raw.identitySigningKeys)],
  ['private unselected JWK',f=>f.raw.jwks=Buffer.from(JSON.stringify({keys:[publicKey,{...publicKey,kid:'foreign',d:'private'}]}))],
  ['extra source',f=>f.raw.callback=Buffer.from('forbidden')],
  ['oversize source',f=>f.raw.tenantKey=Buffer.alloc(65537)],
 ])it('rejects '+name,()=>{const f=fixture();change(f);expect(()=>verifyObserverRouteCredentials(f.route,f.raw,1000000)).toThrow('ObserverContextRejected');});
 it('describes processing for six actual sources separately from acquisition and request credit',()=>{
  const f=fixture(),lengths=Object.fromEntries(Object.entries(f.raw).map(([k,b])=>[k,b.length])),q=describeObserverContextProcessing(lengths);
  expect(q.authority).toBe(false);expect(q.logicalBytes).toBe(16*Object.values(lengths).reduce((a,b)=>a+b,0)+32*65536+6*4096);
  expect(()=>describeObserverContextProcessing({...lengths,signingKeys:1})).toThrow();
 });
});
