import {it,expect} from 'vitest';
import {supersedeProductionDataRelease,reconcileProductionDataSupersession,validateSupersessionLineage,
  SUPERSESSION_ADMISSION_MAX_AGE_MS,SUPERSESSION_EVIDENCE_MAX_AGE_MS,SUPERSESSION_OPERATION_MAX_MS,
  supersessionOperationDeadline,assertSupersessionOperationWindow} from './lib/production-data-supersession.mjs';
import {PRODUCTION_DATA_RELEASE_PARAMETER as name} from './lib/production-data-issuance.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
const now=1800000000000,h=c=>c.repeat(64),id=c=>c.repeat(32);
const timingOf=a=>({issuedMs:a.data.issuedMs,reviewedMs:a.review.reviewedMs,expiresMs:a.data.expiresMs});
function fixture(){
 const old={version:1,stage:'prod',account:'123456789012',region:'ap-northeast-1',controlSourceTree:'a'.repeat(40),dataRevision:'b'.repeat(40),dataSourceTree:'c'.repeat(40),dataSourceTag:'mem9-bbbbbbb',
  images:Object.fromEntries(['llm-proxy','mnemo-server','qwen3-embed'].map((key,i)=>[key,{rootDigest:'sha256:'+h(String(i+1)),arm64Digest:'sha256:'+h(String(i+4))}])),
  runtimeNonce:id('d'),authorizationId:id('e'),issuedMs:now-86400000,expiresMs:now-1,
  ...Object.fromEntries(['parentProofHash','backendBindingHash','generation','targetsHash','schemaDigest','operatorDigest','buildInputsHash','securityEvidenceHash','policyHash'].map(k=>[k,h('a')]))};
 const review={version:1,kind:'retained-data-policy-review',decision:'within-existing-policy',controlSourceTree:'a'.repeat(40),sourceEvidenceHash:h('1'),parentProofHash:old.parentProofHash,
  buildInputsHash:old.buildInputsHash,securityEvidenceHash:old.securityEvidenceHash,freshBuildSecurityHash:h('2'),policySourcesHash:h('3'),reviewedMs:now-500,expiresMs:now+3600000};
 const data={...structuredClone(old),authorizationId:id('f'),issuedMs:now-500,expiresMs:review.expiresMs,policyHash:hash(review)};
 const authorization={data,hash:hash(data),review};
 const predecessor={Name:name,Type:'SecureString',ARN:`arn:aws:ssm:${old.region}:${old.account}:parameter${name}`,Version:1,Value:JSON.stringify(old),LastModifiedDate:new Date(now-86400000).toISOString(),DataType:'text'};
 const lineage=[{parameterVersion:1,predecessorHash:null,authorization:old,authorizationHash:hash(old)}];
 const expected={account:data.account,region:data.region,controlRevision:'a'.repeat(40),controlSourceTree:data.controlSourceTree,sourceEvidenceHash:review.sourceEvidenceHash,
  materialHash:h('4'),runtimeHash:h('5'),buildInputsHash:data.buildInputsHash,securityEvidenceHash:data.securityEvidenceHash,freshBuildSecurityHash:review.freshBuildSecurityHash,
  policyHash:data.policyHash,parentProofHash:data.parentProofHash,rootHash:h('6'),writerBoundaryHash:h('7'),lineageHash:hash(lineage)};
 const authenticatedExpected=structuredClone(expected);
 let clock=now,parameter=structuredClone(predecessor),stored=null,intent=null,acquisitionIntent=null,receipt=null,abortReceipt=null,outcome=null,gateActive=false,mutexActive=false,gateDescriptor=null,mutexDescriptor=null,gateReleased=null,mutexReleased=null,mutexReleaseIntent=null;const calls=[];
 const snapshot=()=>({...authenticatedExpected,observedMs:clock,fenceOwner:data.authorizationId,rootVerified:true,writersSerialized:true,executionEnabled:false,dispatcherEnabled:false,enabledSchedules:0,activeWorkers:0,activeAdministration:0,activeContinuations:0,benchmarkRemaining:0,parameter});
 const deps={now:()=>clock,priorAttempt:async()=>intent,inspect:async()=>{calls.push('inspect');return snapshot();},archive:async record=>{calls.push('archive');stored=structuredClone(record);},readArchive:async()=>stored,
  recordAcquisitionIntent:async v=>{calls.push('acquisition-intent');acquisitionIntent=structuredClone(v);},readAcquisitionIntent:async()=>acquisitionIntent,
  acquireMutex:async op=>{calls.push('mutex');mutexActive=true;mutexDescriptor={owner:op.owner};return mutexDescriptor;},acquireGate:async op=>{calls.push('gate');gateActive=true;gateDescriptor={owner:op.owner};return gateDescriptor;},assertFence:async gate=>{calls.push('fence');if(!mutexActive||gate&&!gateActive)throw Error('FenceNotOwned');},
  recordIntent:async v=>{calls.push('intent');intent=structuredClone(v);},readIntent:async()=>intent,
  putParameter:async input=>{calls.push('put');expect(input).toEqual({Name:name,Type:'SecureString',Value:JSON.stringify(data),Overwrite:true});parameter={...predecessor,Value:input.Value,Version:2,LastModifiedDate:new Date(clock).toISOString()};return {Version:2};},
  readback:async()=>parameter,recordVerified:async v=>{calls.push('verified');receipt=structuredClone(v);},readVerified:async()=>receipt,
  restoreGate:async()=>{if(gateReleased){if(gateActive)throw Error('GateChanged');return;}calls.push('release-gate');gateActive=false;gateReleased={owner:data.authorizationId};},
  releaseMutex:async()=>{if(mutexReleased){if(mutexActive)throw Error('MutexChanged');return;}
    if(!mutexActive){if(!mutexReleaseIntent)throw Error('MutexAbsenceUnproven');calls.push('ack-mutex');mutexReleased={owner:data.authorizationId};return;}
    calls.push('release-mutex');mutexActive=false;mutexReleased={owner:data.authorizationId};},
  assertRecoveryOwner:async()=>{},
  assertRemainingFenceOwnership:async(gate,mutex,operation)=>{expect(operation.owner).toBe(data.authorizationId);expect(gate).toEqual(gateDescriptor);expect(mutex).toEqual(mutexDescriptor);
    if(gateDescriptor&&(gateReleased?gateActive:!gateActive)||mutexDescriptor&&(mutexReleased?mutexActive:!mutexActive&&!mutexReleaseIntent))throw Error('ReleaseOwnershipChanged');},
  readAborted:async()=>abortReceipt,recordAborted:async v=>{abortReceipt=structuredClone(v);},readFences:async()=>({mutex:mutexDescriptor,gate:gateDescriptor,gateReleased,mutexReleased}),recordOutcome:async v=>{outcome=structuredClone(v);}};
 return {deps,input:{authorization,expected,predecessor,lineage},old,data,review,calls,snapshot,getArchive:()=>stored,getIntent:()=>intent,getOutcome:()=>outcome,
  setClock:v=>clock=v,setParameter:v=>parameter=v,setArchive:v=>stored=v,
  mutexAbsent:(authenticatedIntent=true)=>{mutexActive=false;mutexReleased=null;mutexReleaseIntent=authenticatedIntent?{owner:data.authorizationId}:null;},
  timing:({issuedMs=data.issuedMs,reviewedMs=review.reviewedMs,expiresMs=data.expiresMs})=>{data.issuedMs=issuedMs;data.expiresMs=expiresMs;review.reviewedMs=reviewedMs;review.expiresMs=expiresMs;data.policyHash=hash(review);authorization.hash=hash(data);expected.policyHash=data.policyHash;Object.assign(authenticatedExpected,expected);}};
}
it('supersedes only the exact expired record after fresh in-fence inspection and durable readback',async()=>{
 const f=fixture(),old=structuredClone(f.input.predecessor);const result=await supersedeProductionDataRelease(f.deps,f.input);
 expect(result.phase).toBe('complete');expect(result.parameterVersion).toBe(2);expect(f.calls.filter(x=>x==='put')).toHaveLength(1);
 expect(f.calls.indexOf('archive')).toBeLessThan(f.calls.indexOf('put'));expect(f.calls.lastIndexOf('inspect')).toBeGreaterThan(f.calls.indexOf('put'));
 expect(f.getArchive().predecessor).toEqual(old);expect(f.input.predecessor).toEqual(old);expect(f.old.authorizationId).not.toBe(f.data.authorizationId);
 expect(f.calls.slice(-2)).toEqual(['release-gate','release-mutex']);
});
it('requires contiguous complete lineage and never reuses an earlier authorization ID',()=>{
 const f=fixture();expect(validateSupersessionLineage(f.input.lineage,f.input.predecessor,f.data.authorizationId)).toBe(hash(f.input.lineage));
 for(const chain of [[],[{...f.input.lineage[0],parameterVersion:2}],[{...f.input.lineage[0],authorizationHash:h('9')}],f.input.lineage.concat(f.input.lineage)])expect(()=>validateSupersessionLineage(chain,f.input.predecessor,f.data.authorizationId)).toThrow();
 expect(()=>validateSupersessionLineage(f.input.lineage,f.input.predecessor,f.old.authorizationId)).toThrow();
});
it('does not route an image-security change through legacy supersession',async()=>{
 const f=fixture();f.data.version=2;f.input.authorization.hash=hash(f.data);
 await expect(supersedeProductionDataRelease(f.deps,f.input)).rejects.toThrow('DataReleaseSupersessionInputInvalid');
 expect(f.calls).not.toContain('put');
 const g=fixture();g.old.version=2;g.input.predecessor.Value=JSON.stringify(g.old);g.input.lineage[0].authorizationHash=hash(g.old);
 expect(()=>validateSupersessionLineage(g.input.lineage,g.input.predecessor,g.data.authorizationId)).toThrow('DataReleaseLineageInvalid');
});
for(const key of ['images','runtimeNonce','generation','parentProofHash','targetsHash','dataRevision','dataSourceTree','dataSourceTag','backendBindingHash','schemaDigest','operatorDigest','buildInputsHash'])it('rejects changed retained binding '+key+' before any mutation',async()=>{
 const f=fixture();f.data[key]=key==='images'?{}:key==='runtimeNonce'?id('1'):h('1');f.input.authorization.hash=hash(f.data);
 await expect(supersedeProductionDataRelease(f.deps,f.input)).rejects.toThrow();expect(f.calls).not.toContain('put');
});
it('does not turn a currently active predecessor or stale policy review into renewal authority',async()=>{
 const f=fixture();f.old.expiresMs=now+1000;f.input.predecessor.Value=JSON.stringify(f.old);f.input.lineage[0].authorizationHash=hash(f.old);
 await expect(supersedeProductionDataRelease(f.deps,f.input)).rejects.toThrow();expect(f.calls).not.toContain('put');
 const g=fixture();g.review.reviewedMs=now-300001;g.data.policyHash=hash(g.review);g.input.authorization.hash=hash(g.data);g.input.expected.policyHash=g.data.policyHash;
 await expect(supersedeProductionDataRelease(g.deps,g.input)).rejects.toThrow();expect(g.calls).not.toContain('put');
});
for(const key of ['executionEnabled','dispatcherEnabled','activeContinuations','benchmarkRemaining','activeWorkers','activeAdministration','enabledSchedules','rootVerified','writersSerialized','rootHash','writerBoundaryHash'])it('rechecks '+key+' after acquiring the fence',async()=>{
 const f=fixture(),inspect=f.deps.inspect;let reads=0;f.deps.inspect=async()=>{const s=await inspect();if(++reads===2)s[key]=typeof s[key]==='boolean'?!s[key]:typeof s[key]==='number'?1:h('9');return s;};
 const r=await supersedeProductionDataRelease(f.deps,f.input);expect(r.phase).toBe('rejected');expect(f.calls).not.toContain('put');
});
it('archives must be complete and unchanged before any overwrite',async()=>{
 const f=fixture();f.deps.readArchive=async()=>null;await expect(supersedeProductionDataRelease(f.deps,f.input)).rejects.toThrow();expect(f.calls).not.toContain('put');
});
it('does not overwrite a concurrently replaced predecessor',async()=>{
 const f=fixture(),inspect=f.deps.inspect;let reads=0;f.deps.inspect=async()=>{const s=await inspect();if(++reads===2)s.parameter={...s.parameter,Version:2};return s;};
 expect((await supersedeProductionDataRelease(f.deps,f.input)).phase).toBe('rejected');expect(f.calls).not.toContain('put');
});
it('reconciles a lost successful Put response from exact next-version readback',async()=>{
 const f=fixture(),put=f.deps.putParameter;f.deps.putParameter=async v=>{await put(v);throw Error('ResponseLost');};expect((await supersedeProductionDataRelease(f.deps,f.input)).phase).toBe('complete');expect(f.calls.filter(x=>x==='put')).toHaveLength(1);
});
for(const change of ['unknown','jump','expiry','root'])it('retains fences on post-write '+change,async()=>{
 const f=fixture(),put=f.deps.putParameter,inspect=f.deps.inspect;
 f.deps.putParameter=async v=>{if(change==='unknown')throw Error('Unknown');const r=await put(v);if(change==='jump'){f.setParameter({...f.snapshot().parameter,Version:3});return {Version:3};}if(change==='expiry')f.setClock(f.data.expiresMs);return r;};
 if(change==='root')f.deps.inspect=async()=>{const s=await inspect();if(f.calls.includes('put'))s.rootHash=h('8');return s;};
 expect((await supersedeProductionDataRelease(f.deps,f.input)).phase).toBe('held');expect(f.calls).not.toContain('release-gate');expect(f.calls).not.toContain('release-mutex');
});
it('preserves the durable intent and never resubmits after an unknown outcome',async()=>{
 const f=fixture();f.deps.putParameter=async()=>{f.calls.push('put');throw Error('Unknown');};expect((await supersedeProductionDataRelease(f.deps,f.input)).phase).toBe('held');
 await expect(supersedeProductionDataRelease(f.deps,f.input)).rejects.toThrow('ReconciliationRequired');expect(f.calls.filter(x=>x==='put')).toHaveLength(1);
});
it('repeated recovery performs no additional authorization write and keeps original timestamps',async()=>{
 const f=fixture();await supersedeProductionDataRelease(f.deps,f.input);const frozen=structuredClone(f.getArchive());
 expect((await reconcileProductionDataSupersession(f.deps,frozen)).phase).toBe('complete');expect((await reconcileProductionDataSupersession(f.deps,frozen)).phase).toBe('complete');
 expect(f.calls.filter(x=>x==='put')).toHaveLength(1);expect(f.getArchive()).toEqual(frozen);
});
it('recovers a pre-write uncertain gate acquisition with durable ownership and no intent',async()=>{
 const f=fixture(),acquire=f.deps.acquireGate;f.deps.acquireGate=async(...args)=>{await acquire(...args);throw Object.assign(Error('GateAckLost'),{hold:true});};
 expect((await supersedeProductionDataRelease(f.deps,f.input)).phase).toBe('held');expect(f.getIntent()).toBeNull();expect(f.calls).not.toContain('put');
 expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe('aborted');expect(f.calls).not.toContain('put');expect(f.getArchive()).not.toBeNull();
 expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe('aborted');
 await expect(supersedeProductionDataRelease(f.deps,f.input)).rejects.toThrow('ReconciliationRequired');
});
it('does not abort an uncertain pre-write acquisition when another issuer may still be active',async()=>{
 const f=fixture(),acquire=f.deps.acquireGate;f.deps.acquireGate=async(...args)=>{await acquire(...args);throw Object.assign(Error('GateAckLost'),{hold:true});};
 await supersedeProductionDataRelease(f.deps,f.input);f.deps.assertRecoveryOwner=async()=>{throw Error('IssuerStillRunning');};
 await expect(reconcileProductionDataSupersession(f.deps,f.getArchive())).rejects.toThrow('IssuerStillRunning');expect(f.calls).not.toContain('release-gate');
});
it.each(['operation-expired','expired','lost-fence'])('retains fences if receipt persistence becomes %s',async change=>{
 const f=fixture(),record=f.deps.recordVerified;f.deps.recordVerified=async value=>{await record(value);if(change==='operation-expired')f.setClock(f.data.issuedMs+30*60*1000);if(change==='expired')f.setClock(f.data.expiresMs);if(change==='lost-fence')f.deps.assertFence=async()=>{throw Error('FenceLost');};};
 const result=await supersedeProductionDataRelease(f.deps,f.input);expect(result.phase).toBe('held');expect(f.calls).not.toContain('release-gate');expect(f.calls).not.toContain('release-mutex');
});
it('recovers a verified write after gate release without requiring an active gate',async()=>{
 const f=fixture(),release=f.deps.releaseMutex;let fail=true;f.deps.releaseMutex=async()=>{if(fail){fail=false;throw Error('ReleaseLost');}return release();};
 expect((await supersedeProductionDataRelease(f.deps,f.input)).phase).toBe('issued_cleanup_pending');
 expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe('complete');expect(f.calls.filter(x=>x==='put')).toHaveLength(1);
});
it('an aborted attempt can finish interrupted release without reacquiring the gate',async()=>{
 const f=fixture(),acquire=f.deps.acquireGate,release=f.deps.releaseMutex;f.deps.acquireGate=async(...args)=>{await acquire(...args);throw Object.assign(Error('GateAckLost'),{hold:true});};
 await supersedeProductionDataRelease(f.deps,f.input);let fail=true;f.deps.releaseMutex=async()=>{if(fail){fail=false;throw Error('ReleaseLost');}return release();};
 expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe('held');expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe('aborted');expect(f.calls).not.toContain('put');
});
it('rechecks authority after the final asynchronous fence assertion',async()=>{
 const f=fixture(),record=f.deps.recordVerified,assertFence=f.deps.assertFence;let recorded=false;
 f.deps.recordVerified=async v=>{await record(v);recorded=true;};f.deps.assertFence=async(...args)=>{await assertFence(...args);if(recorded)f.setClock(f.data.expiresMs);};
 expect((await supersedeProductionDataRelease(f.deps,f.input)).phase).toBe('held');expect(f.calls).not.toContain('release-gate');
});
it('rechecks recovery snapshot age after the last asynchronous fence assertion',async()=>{
 const f=fixture(),record=f.deps.recordVerified;let fail=true;
 f.deps.recordVerified=async v=>{if(fail){fail=false;throw Error('ReceiptLost');}return record(v);};
 expect((await supersedeProductionDataRelease(f.deps,f.input)).phase).toBe('held');
 const assertFence=f.deps.assertFence;let checks=0;f.setClock(now+299000);
 const inspect=f.deps.inspect;f.deps.inspect=async()=>({...await inspect(),observedMs:now});
 f.deps.assertFence=async(...args)=>{await assertFence(...args);if(++checks===3)f.setClock(now+301000);};
 expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe('held');expect(f.calls).not.toContain('release-gate');
});
for(const mode of ['issue','reconcile'])for(const key of ['rootHash','activeWorkers','enabledSchedules','executionEnabled','dispatcherEnabled'])it(`rechecks ${key} after ${mode} receipt persistence`,async()=>{
 const f=fixture(),record=f.deps.recordVerified,inspect=f.deps.inspect;
 if(mode==='reconcile'){
  f.deps.recordVerified=async()=>{throw Error('ReceiptUnavailable');};
  expect((await supersedeProductionDataRelease(f.deps,f.input)).phase).toBe('held');
 }
 let persisted=false;
 f.deps.recordVerified=async value=>{await record(value);persisted=true;};
 f.deps.inspect=async(...args)=>{const s=await inspect(...args);if(persisted)s[key]=typeof s[key]==='boolean'?true:typeof s[key]==='number'?1:h('8');return s;};
 const result=mode==='issue'?await supersedeProductionDataRelease(f.deps,f.input):await reconcileProductionDataSupersession(f.deps,f.getArchive());
 expect(result.phase).toBe('held');expect(f.calls).not.toContain('release-gate');expect(f.calls).not.toContain('release-mutex');
});
it.each([false,true])('recovers a proven unsent intent after interrupted cleanup=%s',async interrupted=>{
 const f=fixture(),record=f.deps.recordIntent,release=f.deps.releaseMutex;
 f.deps.recordIntent=async v=>{await record(v);f.setClock(f.data.expiresMs);};
 if(interrupted){let failed=false;f.deps.releaseMutex=async(...args)=>{if(!failed){failed=true;throw Error('ReleaseUnavailable');}return release(...args);};}
 expect((await supersedeProductionDataRelease(f.deps,f.input)).phase).toBe(interrupted?'held':'rejected');
 expect(f.getIntent()).not.toBeNull();expect(f.calls).not.toContain('put');
 expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe('aborted');
 expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe('aborted');
 expect(f.calls).not.toContain('put');
});
it('terminally recovers archive-only interruption with positive no-acquisition evidence',async()=>{
 const f=fixture(),archive=f.deps.archive;f.deps.archive=async v=>{await archive(v);throw Error('ArchiveResponseLost');};
 await expect(supersedeProductionDataRelease(f.deps,f.input)).rejects.toThrow('ArchiveResponseLost');
 expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe('aborted');
 expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe('aborted');
 expect(f.calls).not.toContain('mutex');expect(f.calls).not.toContain('put');expect(f.calls).not.toContain('release-mutex');
});
it('cannot turn an uncertain mutex acquisition into an archive-only abort',async()=>{
 const f=fixture();f.deps.acquireMutex=async()=>{throw Object.assign(Error('MutexOutcomeUnknown'),{hold:true});};
 expect((await supersedeProductionDataRelease(f.deps,f.input)).phase).toBe('held');
 expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe('held');
 expect(f.calls).not.toContain('put');expect(f.calls).not.toContain('release-mutex');
});
it('does not accept an unsent receipt whose intent binding was changed',async()=>{
 const f=fixture(),record=f.deps.recordIntent,aborted=f.deps.readAborted;
 f.deps.recordIntent=async v=>{await record(v);f.setClock(f.data.expiresMs);};await supersedeProductionDataRelease(f.deps,f.input);
 f.deps.readAborted=async()=>({...await aborted(),intentHash:h('8')});
 expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe('held');
});
it('does not infer unsent from an unchanged parameter with an existing intent',async()=>{
 const f=fixture();f.deps.putParameter=async()=>{throw Error('UnknownTransportOutcome');};await supersedeProductionDataRelease(f.deps,f.input);
 expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe('held');
 expect(f.calls).not.toContain('release-gate');expect(await f.deps.readAborted()).toBeNull();
});
it('released fences retain authenticated descriptors without pretending the resources remain active',async()=>{
 const f=fixture();await supersedeProductionDataRelease(f.deps,f.input);
 const fences=await f.deps.readFences();await expect(f.deps.assertFence(fences.gate,fences.mutex)).rejects.toThrow('FenceNotOwned');
 f.deps.assertFence=async()=>{throw Error('ReleasedFenceCannotBeReasserted');};
 expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe('complete');
});
it('rejects missing acquisition descriptors even if release receipts exist',async()=>{
 const f=fixture();await supersedeProductionDataRelease(f.deps,f.input);const read=f.deps.readFences;
 f.deps.readFences=async()=>({...await read(),mutex:null,gate:null});
 expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe('held');
});
it('rejects fabricated historical lineage against independently authenticated archive evidence',async()=>{
 const f=fixture(),initial={...f.old,authorizationId:f.data.authorizationId};
 const authentic=[{parameterVersion:1,predecessorHash:null,authorization:initial,authorizationHash:hash(initial)},
  {parameterVersion:2,predecessorHash:hash(initial),authorization:f.old,authorizationHash:hash(f.old)}];
 const fabricated=structuredClone(authentic);fabricated[0].authorization.authorizationId=id('9');fabricated[0].authorizationHash=hash(fabricated[0].authorization);fabricated[1].predecessorHash=fabricated[0].authorizationHash;
 f.input.predecessor.Version=2;f.setParameter(structuredClone(f.input.predecessor));f.input.lineage=fabricated;f.input.expected.lineageHash=hash(fabricated);
 const inspect=f.deps.inspect;f.deps.inspect=async()=>({...await inspect(),lineageHash:hash(authentic)});
 await expect(supersedeProductionDataRelease(f.deps,f.input)).rejects.toThrow('SnapshotChanged');expect(f.calls).not.toContain('archive');
});
it('rejects a modified recovery envelope before any cleanup',async()=>{
 const f=fixture();await supersedeProductionDataRelease(f.deps,f.input);const changed=structuredClone(f.getArchive());changed.operation.owner=id('1');
 await expect(reconcileProductionDataSupersession(f.deps,changed)).rejects.toThrow('ArchiveUnverified');
});
for(const key of ['rootHash','activeWorkers','enabledSchedules','executionEnabled','dispatcherEnabled','parameter'])it('retains owned fences when issuer abort receipt persistence changes '+key,async()=>{
 const f=fixture(),recordIntent=f.deps.recordIntent,recordAbort=f.deps.recordAborted,inspect=f.deps.inspect;
 f.deps.recordIntent=async value=>{await recordIntent(value);f.setClock(f.data.expiresMs);};
 let persisted=false;
 f.deps.recordAborted=async value=>{await recordAbort(value);persisted=true;if(key==='parameter')f.setParameter({...f.input.predecessor,Version:2});};
 f.deps.inspect=async(...args)=>{const s=await inspect(...args);if(persisted&&key!=='parameter')s[key]=typeof s[key]==='boolean'?true:typeof s[key]==='number'?1:h('8');return s;};
 expect((await supersedeProductionDataRelease(f.deps,f.input)).phase).toBe('held');
 expect(f.calls).not.toContain('put');expect(f.calls).not.toContain('release-gate');expect(f.calls).not.toContain('release-mutex');
});
for(const [kind,reader]of [['acquisition','readAcquisitionIntent'],['intent','readIntent'],['verified','readVerified']])for(const mode of ['missing','mismatched'])it(`requires ${kind} durable readback when ${mode}`,async()=>{
 const f=fixture(),read=f.deps[reader];
 f.deps[reader]=async(...args)=>{const value=await read(...args);return value===null?null:mode==='missing'?null:{...value,unexpected:true};};
 const result=await supersedeProductionDataRelease(f.deps,f.input);
 expect(result.phase).not.toBe('complete');
 if(kind==='acquisition')expect(f.calls).not.toContain('mutex');
 if(kind!=='verified')expect(f.calls).not.toContain('put');
 else {expect(f.calls.filter(x=>x==='put')).toHaveLength(1);expect(f.calls).not.toContain('release-gate');expect(f.calls).not.toContain('release-mutex');}
});

it('exports separate admission, snapshot and immutable operation time contracts',()=>{
 const f=fixture(),a=f.input.authorization;
 expect(SUPERSESSION_ADMISSION_MAX_AGE_MS).toBe(300000);expect(SUPERSESSION_EVIDENCE_MAX_AGE_MS).toBe(300000);expect(SUPERSESSION_OPERATION_MAX_MS).toBe(1800000);
 f.timing({issuedMs:now-1000,reviewedMs:now-2000});expect(supersessionOperationDeadline(timingOf(a))).toBe(now-2000+1800000);
 f.timing({issuedMs:now-3000,reviewedMs:now-1000});expect(supersessionOperationDeadline(timingOf(a))).toBe(now-3000+1800000);
 f.timing({expiresMs:now+1000});expect(supersessionOperationDeadline(timingOf(a))).toBe(now+1000);
 expect(assertSupersessionOperationWindow(timingOf(a),now,{initial:true})).toBe(now+1000);
 expect(()=>assertSupersessionOperationWindow(timingOf(a),now+1000)).toThrow();
 expect(assertSupersessionOperationWindow(timingOf(a),now+3600000,{historical:true})).toBe(now+1000);
});
for(const field of ['issuedMs','reviewedMs'])it.each([300000,300001])('initial '+field+' age %s is checked before dependent work',async age=>{
 const f=fixture();f.timing({[field]:now-age});const touched=[];
 const deps=Object.fromEntries(Object.entries(f.deps).map(([name,fn])=>[name,name==='now'?fn:async(...args)=>{touched.push(name);return fn(...args);} ]));
 if(age===300000){expect((await supersedeProductionDataRelease(deps,f.input)).phase).toBe('complete');}
 else{await expect(supersedeProductionDataRelease(deps,f.input)).rejects.toThrow('EvidenceExpired');expect(touched).toEqual([]);}
});
for(const field of ['issuedMs','reviewedMs'])for(const value of [now+1,now-0.5,NaN,Infinity,'invalid',null,0])it(`${field} rejects ${String(value)} even for historical validation`,()=>{
 const f=fixture(),a=structuredClone(f.input.authorization);if(field==='issuedMs')a.data.issuedMs=value;else a.review.reviewedMs=value;
 for(const mode of [{initial:true},{},{historical:true}])expect(()=>assertSupersessionOperationWindow(timingOf(a),now,mode)).toThrow();
});
it('historical protocol entry rejects future or noninteger review times before reading any dependency',async()=>{
 for(const reviewedMs of [now+1,now-0.5]){
  const f=fixture();await supersedeProductionDataRelease(f.deps,f.input);const envelope=f.getArchive();envelope.authorization.review.reviewedMs=reviewedMs;let reads=0;
  f.deps.readArchive=async()=>{reads++;return envelope;};
  await expect(reconcileProductionDataSupersession(f.deps,envelope)).rejects.toThrow('TimeInvalid');expect(reads).toBe(0);
 }
});
it('allows five distinct fresh collections over five minutes: one runner collection and exactly four public collections',async()=>{
 const f=fixture(),frozen=structuredClone(f.input);let clock=now;const observed=[];
 f.deps.inspect=async()=>{clock+=75000;f.setClock(clock);const s=f.snapshot();observed.push(s.observedMs);f.calls.push('inspect');return s;};
 await f.deps.inspect(); // The private runner prepares authorization from this first collection.
 expect((await supersedeProductionDataRelease(f.deps,f.input)).phase).toBe('complete');
 expect(observed).toHaveLength(5);expect(new Set(observed).size).toBe(5);expect(clock-now).toBeGreaterThan(300000);expect(f.calls.filter(x=>x==='put')).toHaveLength(1);
 expect(f.input).toEqual(frozen);expect(f.getArchive().authorization).toEqual(frozen.authorization);
 expect(f.getArchive()).not.toHaveProperty('startedMs');expect(f.getArchive()).not.toHaveProperty('deadlineMs');
});
for(const phase of [1,2,3,4])for(const invalid of ['old','future','fractional'])it(`rejects ${invalid} snapshot in public collection ${phase}`,async()=>{
 const f=fixture(),inspect=f.deps.inspect;let count=0;f.deps.inspect=async(...args)=>{const s=await inspect(...args);if(++count===phase)s.observedMs=invalid==='old'?now-300001:invalid==='future'?now+1:now-0.5;return s;};
 if(phase===1)await expect(supersedeProductionDataRelease(f.deps,f.input)).rejects.toThrow('SnapshotNotFresh');
 else expect((await supersedeProductionDataRelease(f.deps,f.input)).phase).not.toBe('complete');
 expect(f.calls.filter(x=>x==='put')).toHaveLength(phase<=2?0:1);
});
for(const boundary of ['acquisition-intent','mutex','gate','write-intent','put','verified','gate-release','mutex-release'])it('checks immutable D at '+boundary+' after preceding asynchronous work',async()=>{
 const f=fixture(),deadline=f.data.issuedMs+1800000;let advanced=false;
 const advance=()=>{if(!advanced){advanced=true;f.setClock(deadline);}};
 if(boundary==='acquisition-intent'){const read=f.deps.readArchive;f.deps.readArchive=async(...args)=>{const v=await read(...args);if(v)advance();return v;};}
 if(boundary==='mutex'){const read=f.deps.readAcquisitionIntent;f.deps.readAcquisitionIntent=async(...args)=>{const v=await read(...args);if(v)advance();return v;};}
 if(boundary==='gate'){const acquire=f.deps.acquireMutex;f.deps.acquireMutex=async(...args)=>{const v=await acquire(...args);advance();return v;};}
 if(boundary==='write-intent'){const check=f.deps.assertFence;f.deps.assertFence=async(...args)=>{await check(...args);advance();};}
 if(boundary==='put'){const record=f.deps.recordIntent;f.deps.recordIntent=async(...args)=>{await record(...args);advance();};}
 if(boundary==='verified'){const check=f.deps.assertFence;f.deps.assertFence=async(...args)=>{await check(...args);if(f.calls.includes('put'))advance();};}
 if(boundary==='gate-release'){const read=f.deps.readVerified;f.deps.readVerified=async(...args)=>{const v=await read(...args);if(v)advance();return v;};}
 if(boundary==='mutex-release'){const release=f.deps.restoreGate;f.deps.restoreGate=async(...args)=>{await release(...args);advance();};}
 const r=await supersedeProductionDataRelease(f.deps,f.input);expect(r.phase).not.toBe('complete');
 const forbidden={'acquisition-intent':'acquisition-intent',mutex:'mutex',gate:'gate','write-intent':'intent',put:'put',verified:'verified','gate-release':'release-gate','mutex-release':'release-mutex'}[boundary];expect(f.calls).not.toContain(forbidden);
 if(['verified','gate-release','mutex-release'].includes(boundary))expect(f.calls.filter(x=>x==='put')).toHaveLength(1);else expect(f.calls).not.toContain('put');
 if(boundary==='put'){expect(f.getIntent()).not.toBeNull();expect(await f.deps.readAborted()).not.toBeNull();}
});
it('earlier descriptor expiry and restarting cannot extend the immutable operation deadline',async()=>{
 const f=fixture();f.timing({expiresMs:now+1000});const record=f.deps.recordIntent;f.deps.recordIntent=async value=>{await record(value);f.setClock(now+1000);};
 expect((await supersedeProductionDataRelease(f.deps,f.input)).phase).toBe('rejected');const saved=structuredClone(f.getArchive());
 f.setClock(now+3600000);await expect(supersedeProductionDataRelease(f.deps,f.input)).rejects.toThrow();expect(f.calls).not.toContain('put');expect(f.getArchive()).toEqual(saved);
 expect((await reconcileProductionDataSupersession(f.deps,saved)).phase).toBe('aborted');expect(f.getArchive()).toEqual(saved);
});

async function partialRelease(kind){
 const f=fixture(),release=f.deps.releaseMutex;let pending=true;
 f.deps.releaseMutex=async(...args)=>{if(pending){pending=false;throw Error('ReleaseUnavailable');}return release(...args);};
 if(kind==='abort'){const record=f.deps.recordIntent;f.deps.recordIntent=async value=>{await record(value);f.setClock(f.data.expiresMs);};}
 await supersedeProductionDataRelease(f.deps,f.input);expect((await f.deps.readFences()).gateReleased).not.toBeNull();expect((await f.deps.readFences()).mutexReleased).toBeNull();return f;
}
for(const kind of ['successor','abort'])for(const change of ['unavailable','stale','rootHash','writerBoundaryHash','activeWorkers','parameter'])it(`${kind} partial release refuses ${change} current audit`,async()=>{
 const f=await partialRelease(kind),inspect=f.deps.inspect;f.deps.inspect=async arg=>{expect(arg).toEqual({owner:f.data.authorizationId,remainingFences:true});if(change==='unavailable')throw Error('AuditUnavailable');const s=await inspect(arg);if(change==='stale')s.observedMs-=300001;else if(change==='parameter')s.parameter={...s.parameter,Version:3};else s[change]=change==='activeWorkers'?1:h('8');return s;};
 expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe('held');expect(f.calls).not.toContain('release-mutex');expect(f.calls.filter(x=>x==='put')).toHaveLength(kind==='abort'?0:1);
});
for(const kind of ['successor','abort'])it(`${kind} partial release rechecks freshness and ownership after asynchronous release preparation`,async()=>{
 const f=await partialRelease(kind),guard=f.deps.assertRemainingFenceOwnership,inspect=f.deps.inspect;let observed,afterAudit=false;
 f.deps.inspect=async arg=>{const s=await inspect(arg);observed=s.observedMs;afterAudit=true;return s;};
 f.deps.assertRemainingFenceOwnership=async(...args)=>{await guard(...args);if(afterAudit)f.setClock(observed+300001);};
 expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe('held');expect(f.calls).not.toContain('release-mutex');
});
for(const kind of ['successor','abort'])it(`${kind} qualified partial release audits once, releases only the remaining mutex and cannot Put`,async()=>{
 const f=await partialRelease(kind),before=f.calls.length,inspect=f.deps.inspect;f.deps.inspect=async arg=>{expect(arg).toEqual({owner:f.data.authorizationId,remainingFences:true});return inspect(arg);};
 expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe(kind==='abort'?'aborted':'complete');
 const recovery=f.calls.slice(before);expect(recovery.filter(x=>x==='inspect')).toHaveLength(1);expect(recovery.filter(x=>x==='release-mutex')).toHaveLength(1);expect(recovery).not.toContain('release-gate');expect(recovery).not.toContain('put');
});
it('both released fences use authenticated historical acknowledgment without a current audit or resource mutation',async()=>{
 const f=fixture();await supersedeProductionDataRelease(f.deps,f.input);const saved=structuredClone(f.getArchive()),before=f.calls.length;let guards=0;
 const guard=f.deps.assertRemainingFenceOwnership;f.deps.assertRemainingFenceOwnership=async(...args)=>{guards++;await guard(...args);};f.deps.inspect=async()=>{throw Error('HistoricalRootChanged');};f.deps.assertFence=async()=>{throw Error('ReleasedGateMustNotBeActive');};
 f.setClock(f.data.expiresMs+1000);const result=await reconcileProductionDataSupersession(f.deps,saved);expect(result.phase).toBe('complete');expect(result.expired).toBe(true);expect(guards).toBeGreaterThan(0);expect(f.calls.slice(before)).toEqual([]);expect(f.getArchive()).toEqual(saved);
});
it('both released acknowledgment holds when the helper cannot authenticate actual released state',async()=>{
 const f=fixture();await supersedeProductionDataRelease(f.deps,f.input);f.deps.assertRemainingFenceOwnership=async()=>{throw Error('ReleasedStateUnverified');};expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe('held');
});
for(const kind of ['successor','abort'])it(`${kind} accepts an absent mutex only with authenticated pending release intent, without another delete`,async()=>{
 const f=await partialRelease(kind);f.mutexAbsent();const before=f.calls.length;
 expect((await reconcileProductionDataSupersession(f.deps,f.getArchive())).phase).toBe(kind==='abort'?'aborted':'complete');
 const calls=f.calls.slice(before);expect(calls.filter(x=>x==='inspect')).toHaveLength(1);expect(calls).toContain('ack-mutex');expect(calls).not.toContain('release-mutex');expect(calls).not.toContain('put');
 const unknown=await partialRelease(kind);unknown.mutexAbsent(false);expect((await reconcileProductionDataSupersession(unknown.deps,unknown.getArchive())).phase).toBe('held');expect(unknown.calls).not.toContain('ack-mutex');
});
it('time helpers reject invalid clocks and unsafe deadline arithmetic without mutating fields',()=>{
 const times={issuedMs:now,reviewedMs:now,expiresMs:now+3600000},saved=structuredClone(times);
 for(const at of [NaN,Infinity,now+0.5,'invalid',0])expect(()=>assertSupersessionOperationWindow(times,at,{historical:true})).toThrow('TimeInvalid');
 expect(()=>supersessionOperationDeadline({...times,issuedMs:Number.MAX_SAFE_INTEGER-2,reviewedMs:Number.MAX_SAFE_INTEGER-2,expiresMs:Number.MAX_SAFE_INTEGER})).toThrow('TimeInvalid');
 expect(()=>assertSupersessionOperationWindow(times,now,{initial:true,historical:true})).toThrow('TimeInvalid');expect(times).toEqual(saved);
});
it('operation deadline is exclusive while the snapshot five-minute boundary remains inclusive',async()=>{
 const times={issuedMs:now-2000,reviewedMs:now-1000,expiresMs:now+3600000},deadline=supersessionOperationDeadline(times);
 expect(assertSupersessionOperationWindow(times,deadline-1)).toBe(deadline);expect(()=>assertSupersessionOperationWindow(times,deadline)).toThrow('OperationExpired');
 const f=fixture(),inspect=f.deps.inspect;f.deps.inspect=async(...args)=>({...await inspect(...args),observedMs:now-300000});expect((await supersedeProductionDataRelease(f.deps,f.input)).phase).toBe('complete');
});
for(const boundary of ['put','verified','mutex-release'])it('rechecks the existing snapshot after '+boundary+' preparation exceeds five minutes',async()=>{
 const f=fixture();
 if(boundary==='put'){const record=f.deps.recordIntent;f.deps.recordIntent=async value=>{await record(value);f.setClock(now+300001);};}
 if(boundary==='verified'){const check=f.deps.assertFence;f.deps.assertFence=async(...args)=>{await check(...args);if(f.calls.includes('put'))f.setClock(now+300001);};}
 if(boundary==='mutex-release'){const release=f.deps.restoreGate;f.deps.restoreGate=async(...args)=>{await release(...args);f.setClock(now+300001);};}
 const result=await supersedeProductionDataRelease(f.deps,f.input);expect(result.phase).not.toBe('complete');expect(f.calls).not.toContain(boundary==='mutex-release'?'release-mutex':boundary);
});
it('caller changes during awaited work cannot reset the approved immutable time anchor',async()=>{
 const f=fixture(),original=structuredClone(f.input),record=f.deps.recordAcquisitionIntent;
 f.deps.recordAcquisitionIntent=async value=>{await record(value);const later=now+1800000;f.setClock(later);f.timing({issuedMs:later,reviewedMs:later,expiresMs:later+3600000});};
 const result=await supersedeProductionDataRelease(f.deps,f.input);expect(result.phase).not.toBe('complete');expect(f.calls).not.toContain('mutex');expect(f.calls).not.toContain('put');expect(f.getArchive().authorization).toEqual(original.authorization);
});
for(const proof of ['valid','changed-predecessor','missing-abort-readback'])it('held deadline-only pre-Put error uses only '+proof+' no-send proof',async()=>{
 const f=fixture(),check=f.deps.assertFence,record=f.deps.recordAborted;let expired=false,cleanup=false;
 f.deps.assertFence=async(...args)=>{await check(...args);if(!expired&&!cleanup){expired=true;f.setClock(f.data.issuedMs+1800000);if(proof==='changed-predecessor')f.setParameter({...f.input.predecessor,Version:2});throw Object.assign(Error('DataReleaseSupersessionOperationExpired'),{hold:true});}};
 f.deps.recordAborted=async value=>{await record(value);cleanup=true;};if(proof==='missing-abort-readback')f.deps.readAborted=async()=>null;
 const result=await supersedeProductionDataRelease(f.deps,f.input);expect(result.phase).toBe(proof==='valid'?'rejected':'held');expect(f.calls).not.toContain('put');
 if(proof==='valid'){expect(await f.deps.readAborted()).not.toBeNull();expect(f.calls).toContain('release-gate');expect(f.calls).toContain('release-mutex');}
 else{expect(f.calls).not.toContain('release-gate');expect(f.calls).not.toContain('release-mutex');}
});
for(const boundary of ['acquisition','intent','child-cleanup'])it('held deadline cannot erase uncertain '+boundary+' outcome',async()=>{
 const f=fixture(),expire=()=>{f.setClock(f.data.issuedMs+1800000);return Object.assign(Error('DataReleaseSupersessionOperationExpired'),{hold:true});};
 if(boundary==='acquisition'){const acquire=f.deps.acquireGate;f.deps.acquireGate=async(...args)=>{await acquire(...args);throw expire();};}
 if(boundary==='intent'){const record=f.deps.recordIntent;f.deps.recordIntent=async(...args)=>{await record(...args);throw expire();};}
 if(boundary==='child-cleanup')f.deps.assertFence=async()=>{throw Object.assign(expire(),{code:'ECLEANUP',cleanupComplete:false});};
 expect((await supersedeProductionDataRelease(f.deps,f.input)).phase).toBe('held');expect(f.calls).not.toContain('put');expect(f.calls).not.toContain('release-gate');expect(f.calls).not.toContain('release-mutex');
});
