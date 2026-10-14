import {it,expect} from 'vitest';
import {issueProductionDataRelease,PRODUCTION_DATA_RELEASE_PARAMETER as name} from './lib/production-data-issuance.mjs';
import {inspectDataRelease} from './lib/production-data-release.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
const now=1800000000000,h=c=>c.repeat(64);
function fixture(){
  const data={version:1,stage:'prod',account:'123456789012',region:'ap-northeast-1',controlSourceTree:'a'.repeat(40),dataRevision:'b'.repeat(40),dataSourceTree:'c'.repeat(40),dataSourceTag:'mem9-bbbbbbb',
    images:Object.fromEntries(['llm-proxy','mnemo-server','qwen3-embed'].map((n,i)=>[n,{rootDigest:'sha256:'+h(String(i+1)),arm64Digest:'sha256:'+h(String(i+4))}])),
    runtimeNonce:'d'.repeat(32),authorizationId:'e'.repeat(32),issuedMs:now-1000,expiresMs:now+300000,
    ...Object.fromEntries(['parentProofHash','backendBindingHash','generation','targetsHash','schemaDigest','operatorDigest','buildInputsHash','securityEvidenceHash','policyHash'].map(n=>[n,h('a')]))};
  const review={version:1,kind:'retained-data-policy-review',sourceEvidenceHash:h('a'),freshBuildSecurityHash:h('b')};data.policyHash=hash(review);
  const expected={account:data.account,region:data.region,controlRevision:'a'.repeat(40),controlSourceTree:data.controlSourceTree,
    ...Object.fromEntries(['sourceEvidenceHash','materialHash','runtimeHash','buildInputsHash','securityEvidenceHash','parentProofHash'].map(n=>[n,h('a')])),policyHash:data.policyHash,freshBuildSecurityHash:review.freshBuildSecurityHash};
  const authorization={...inspectDataRelease(data,{stage:data.stage,account:data.account,region:data.region,controlSourceTree:data.controlSourceTree}),review};
  let clock=now,parameter=null;const calls=[];
  const snapshot=()=>({...expected,executionEnabled:false,dispatcherEnabled:false,enabledSchedules:0,activeWorkers:0,activeAdministration:0,benchmarkRemaining:0,parameter});
  const deps={now:()=>clock,priorAttempt:async()=>null,inspect:async()=>snapshot(),archive:async()=>calls.push('archive'),acquireMutex:async()=>({owner:data.authorizationId}),
    acquireGate:async()=>({owner:data.authorizationId}),assertFence:async()=>{},recordIntent:async()=>calls.push('intent'),
    putParameter:async input=>{calls.push('put');expect(input).toEqual({Name:name,Type:'SecureString',Value:JSON.stringify(data),Overwrite:false});parameter={...input,Version:1,ARN:`arn:aws:ssm:${data.region}:${data.account}:parameter${name}`};return {Version:1};},
    readback:async()=>parameter,recordVerified:async()=>calls.push('verified'),restoreGate:async()=>calls.push('gate-release'),releaseMutex:async()=>calls.push('mutex-release'),recordOutcome:async()=>{}};
  return {deps,authorization,expected,data,calls,snapshot,expire:()=>{clock=data.expiresMs;},setParameter:v=>{parameter=v;}};
}
it('creates only the exact protected record once and releases only after verified readback',async()=>{
  const f=fixture();expect((await issueProductionDataRelease(f.deps,f)).phase).toBe('complete');
  expect(f.calls).toEqual(['archive','intent','put','verified','gate-release','mutex-release']);
});
it('never creates an image-security descriptor through legacy issuance',async()=>{
 const f=fixture();f.authorization.data.version=2;
 await expect(issueProductionDataRelease(f.deps,f)).rejects.toThrow('DataReleaseIssuanceIdentity');
 expect(f.calls).toEqual([]);
});
it('reconciles a lost response by exact readback without repeating the write',async()=>{
  const f=fixture(),put=f.deps.putParameter;f.deps.putParameter=async input=>{await put(input);throw Error('TransportLost');};
  expect((await issueProductionDataRelease(f.deps,f)).phase).toBe('complete');expect(f.calls.filter(x=>x==='put')).toHaveLength(1);
});
it('never writes after a durable intent already exists or when pre-write authorization expires',async()=>{
  const f=fixture();f.deps.priorAttempt=async()=>({sent:true});await expect(issueProductionDataRelease(f.deps,f)).rejects.toThrow('DataReleaseReconciliationRequired');expect(f.calls).toEqual([]);
  const g=fixture();g.deps.recordIntent=async()=>g.expire();expect((await issueProductionDataRelease(g.deps,g)).phase).toBe('rejected');expect(g.calls).not.toContain('put');
});
it('retains both fences after an unknown write, post-write expiry, or changed snapshot',async()=>{
  for(const change of ['unknown','expired','changed']){
    const f=fixture(),put=f.deps.putParameter,inspect=f.deps.inspect;
    f.deps.putParameter=async input=>{if(change==='unknown'){f.calls.push('put');throw Error('TransportLost');}const r=await put(input);if(change==='expired')f.expire();return r;};
    f.deps.inspect=async()=>{const r=await inspect();if(change==='changed'&&f.calls.includes('put'))r.runtimeHash=h('b');return r;};
    expect((await issueProductionDataRelease(f.deps,f)).phase).toBe('held');expect(f.calls).not.toContain('gate-release');expect(f.calls).not.toContain('mutex-release');
  }
});
it('reports an issued authorization with pending mutex cleanup after gate restoration',async()=>{
  const f=fixture();f.deps.releaseMutex=async()=>{throw Error('MutexReleaseUnknown');};
  const result=await issueProductionDataRelease(f.deps,f);expect(result.phase).toBe('issued_cleanup_pending');expect(result.verified).toBe(true);expect(result.gateRestored).toBe(true);
});
it('rejects fresh-build scan drift before writing and retains fences if it drifts afterward',async()=>{
  for(const after of [false,true]){
    const f=fixture(),inspect=f.deps.inspect;let reads=0;
    f.deps.inspect=async()=>{const value=await inspect();if(++reads>=(after?3:2))value.freshBuildSecurityHash=h('c');return value;};
    const result=await issueProductionDataRelease(f.deps,f);expect(result.phase).toBe(after?'held':'rejected');
    expect(f.calls.filter(v=>v==='put').length).toBe(after?1:0);if(after)expect(f.calls).not.toContain('gate-release');
  }
});
