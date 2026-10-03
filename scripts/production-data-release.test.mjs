import {it,expect} from 'vitest';
import {inspectDataRelease,requireActiveDataRelease} from './lib/production-data-release.mjs';
const now=1800000000000,hex=n=>n.toString(16).padStart(64,'0');
function fixture(){
 const data={version:1,stage:'prod',account:'123456789012',region:'ap-northeast-1',controlSourceTree:'a'.repeat(40),
  dataRevision:'b'.repeat(40),dataSourceTree:'c'.repeat(40),dataSourceTag:'mem9-bbbbbbb',
  images:Object.fromEntries(['llm-proxy','mnemo-server','qwen3-embed'].map((name,i)=>[name,{rootDigest:'sha256:'+hex(i+1),arm64Digest:'sha256:'+hex(i+10)}])),
  parentProofHash:hex(20),backendBindingHash:hex(21),runtimeNonce:'d'.repeat(32),generation:hex(22),targetsHash:hex(23),schemaDigest:hex(24),operatorDigest:hex(25),
  buildInputsHash:hex(26),securityEvidenceHash:hex(27),policyHash:hex(28),authorizationId:'e'.repeat(32),issuedMs:now-1000,expiresMs:now+3600000};
 const expected={stage:'prod',account:data.account,region:data.region,controlSourceTree:data.controlSourceTree};return {data,expected};
}
it('separates current control identity from exact retained data artifacts',()=>{
 const f=fixture(),verified=requireActiveDataRelease(JSON.stringify(f.data),f.expected,{now});
 expect(verified.data.dataSourceTag).toBe('mem9-bbbbbbb');expect(verified.hash).toMatch(/^[a-f0-9]{64}$/);
 expect(verified.images['mnemo-server']).toBe('123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/mnemo-server@'+f.data.images['mnemo-server'].rootDigest);
});
it('rejects missing, unknown, foreign and ambiguous release fields',()=>{
 for(const change of [f=>{f.data.stage='pr-7';},f=>{f.data.account='0'.repeat(12);},f=>{f.data.region='us-west-2';},
  f=>{f.data.controlSourceTree='f'.repeat(40);},f=>{f.data.dataSourceTag='mem9-ccccccc';},f=>{delete f.data.images['qwen3-embed'];},
  f=>{f.data.images.extra=f.data.images['llm-proxy'];},f=>{f.data.images['llm-proxy'].rootDigest=f.data.images['llm-proxy'].arm64Digest;},
  f=>{f.data.extra=true;},f=>{delete f.data.securityEvidenceHash;},f=>{f.data.authorizationId='invalid';}]){
  const f=fixture();change(f);expect(()=>requireActiveDataRelease(f.data,f.expected,{now})).toThrow('DataReleaseInvalid');
 }
});
it('binds independently observed parent, runtime, recipe and security evidence',()=>{
 for(const field of ['parentProofHash','backendBindingHash','runtimeNonce','generation','targetsHash','schemaDigest','operatorDigest','buildInputsHash','securityEvidenceHash','policyHash']){
  const f=fixture();expect(()=>requireActiveDataRelease(f.data,{...f.expected,bindings:{[field]:'f'.repeat(field==='runtimeNonce'?32:64)}},{now})).toThrow('DataReleaseBindingMismatch');
 }
});
it('expires new use without losing the ability to inspect historical evidence',()=>{
 const f=fixture();expect(()=>inspectDataRelease(f.data,f.expected)).not.toThrow();
 for(const clock of [f.data.issuedMs-1,f.data.expiresMs,f.data.expiresMs+1])expect(()=>requireActiveDataRelease(f.data,f.expected,{now:clock})).toThrow('DataReleaseAuthorizationExpired');
 f.data.expiresMs=f.data.issuedMs+86400001;expect(()=>inspectDataRelease(f.data,f.expected)).toThrow('DataReleaseInvalid');
});
it('never permits production data images through a preview context',()=>{
 const f=fixture();expect(()=>requireActiveDataRelease(f.data,{...f.expected,stage:'pr-7'},{now})).toThrow('DataReleaseInvalid');
 f.data.stage='pr-7';f.data.dataSourceTag='pr-bbbbbbb';
 expect(requireActiveDataRelease(f.data,{...f.expected,stage:'pr-7'},{now}).images['llm-proxy']).toContain('/mem9-on-aws/preview/llm-proxy@');
});
