import {test} from 'vitest';
import assert from 'node:assert/strict';
import {copyObserverCredentialByteInputs,OBSERVER_CREDENTIAL_BYTE_FIELDS,observerRuntimeState,assertObserverRuntimeCurrent,claimObserverRuntimeProcessing,claimObserverRuntimeRequest} from './lib/production-nonroot-observer-runtime-provider.mjs';
test('byte adapter passes exactly P six original Uint8Array inputs including original JWKS whitespace',()=>{
 const raw=Object.fromEntries(OBSERVER_CREDENTIAL_BYTE_FIELDS.map(k=>[k,Buffer.from(k==='jwks'?' { "keys" : [] }\n':k)]));const result=copyObserverCredentialByteInputs(raw);
 assert.deepEqual(Object.keys(result),OBSERVER_CREDENTIAL_BYTE_FIELDS);for(const k of Object.keys(raw)){assert.ok(result[k] instanceof Uint8Array);assert.deepEqual(result[k],raw[k]);assert.notEqual(result[k],raw[k]);}
 assert.equal(result.jwks.toString(),' { "keys" : [] }\n');assert.ok(!Object.hasOwn(result,'clientId')&&!Object.hasOwn(result,'clientSecret'));
});
for(const [name,change]of [['extra clientSecret',r=>r.clientSecret=Buffer.from('synthetic')],['parsed JWKS',r=>r.jwks={keys:[]}],['string key',r=>r.tenantKey='synthetic'],['oversized source',r=>r.accessToken=Buffer.alloc(65537)],['missing source',r=>delete r.registry]])test('reject '+name,()=>{const raw=Object.fromEntries(OBSERVER_CREDENTIAL_BYTE_FIELDS.map(k=>[k,Buffer.from(k)]));change(raw);assert.throws(()=>copyObserverCredentialByteInputs(raw));});
test('DATA or callback objects cannot become a native runtime provider/processing payer',()=>{
 for(const h of [{},{authority:true},{reserveLocal(){},now:()=>1}]){assert.throws(()=>observerRuntimeState(h));assert.throws(()=>assertObserverRuntimeCurrent(h));assert.throws(()=>claimObserverRuntimeRequest(h,'private-unauth'));assert.throws(()=>claimObserverRuntimeProcessing(h,'context'));}
});
