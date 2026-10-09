import {it,expect} from 'vitest';
import {inspectDataRelease,requireActiveDataRelease} from './lib/production-data-release.mjs';
import {IMAGE_TRANSITION_LIMITS_HASH} from './lib/production-image-transition.mjs';
import {NONROOT_LIMITS_HASH} from './lib/production-nonroot-contracts.mjs';
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

function imageRelease(){
 const f=fixture();f.data.version=2;
 f.data.transition={version:1,kind:'image-security-upgrade',proofHash:hex(30),predecessorHash:hex(31),limitsHash:IMAGE_TRANSITION_LIMITS_HASH};
 return f;
}
it('inspects an explicitly typed image-security target without claiming it is serving',()=>{
 const f=imageRelease(),result=requireActiveDataRelease(JSON.stringify(f.data),f.expected,{now});
 expect(result.data.version).toBe(2);expect(result.data.transition).toEqual(f.data.transition);
 expect(result.data.parentProofHash).toBe(f.data.parentProofHash);
 expect(result.data.backendBindingHash).toBe(f.data.backendBindingHash);
 expect(result.images['mnemo-server'].endsWith('@'+f.data.images['mnemo-server'].rootDigest)).toBe(true);
});
it('keeps legacy records strict and rejects unknown image-security commitments',()=>{
 for(const mutate of [f=>{delete f.data.transition;},f=>{f.data.transition.kind='other';},
  f=>{f.data.transition.version=2;},f=>{f.data.transition.proofHash='unknown';},
  f=>{delete f.data.transition.predecessorHash;},f=>{f.data.transition.compatible=true;},
  f=>{f.data.transition.limitsHash='';},f=>{f.data.version=3;}]){
  const f=imageRelease();mutate(f);expect(()=>inspectDataRelease(f.data,f.expected)).toThrow();
 }
 const f=imageRelease();f.data.version=1;expect(()=>inspectDataRelease(f.data,f.expected)).toThrow();
});
it('does not renew image-security expiry during historical inspection',()=>{
 const f=imageRelease();expect(()=>inspectDataRelease(f.data,f.expected)).not.toThrow();
 expect(()=>requireActiveDataRelease(f.data,f.expected,{now:f.data.expiresMs})).toThrow('DataReleaseAuthorizationExpired');
});
it('rejects duplicate decoded JSON keys in the explicit image-security descriptor',()=>{
 const f=imageRelease(),raw=JSON.stringify(f.data).replace('{','{"version":2,');
 expect(()=>inspectDataRelease(raw,f.expected)).toThrow();
});
function nonrootRelease(){const f=fixture();f.data.version=3;f.data.transition={version:2,kind:'image-security-nonroot-upgrade',proofHash:hex(30),predecessorHash:hex(31),limitsHash:NONROOT_LIMITS_HASH};return f;}
it('parses only the explicit descriptor-v3 nonroot transition without issuing authority',()=>{
 const f=nonrootRelease(),r=requireActiveDataRelease(JSON.stringify(f.data),f.expected,{now});expect(r.data).toEqual(f.data);expect(r).not.toHaveProperty('context');expect(r).not.toHaveProperty('authorized');
});
it.each(['old-transition','unknown-transition','extra','duplicate','accessor'])('rejects v3 %s without widening legacy shapes',defect=>{
 const f=nonrootRelease();let raw=f.data,calls=0;
 if(defect==='old-transition')f.data.transition.version=1;if(defect==='unknown-transition')f.data.transition.kind='other';if(defect==='extra')f.data.approved=true;
 if(defect==='duplicate')raw=JSON.stringify(raw).replace('{','{"version":3,');
 if(defect==='accessor')Object.defineProperty(f.data,'account',{enumerable:true,get(){calls++;return '123456789012';}});
 expect(()=>inspectDataRelease(raw,f.expected)).toThrow();expect(calls).toBe(0);
});
