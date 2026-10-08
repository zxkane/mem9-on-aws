import {it,expect} from 'vitest';
import {imageTransitionFixture,imageTransitionServingFixture} from './production-image-transition.fixture.mjs';
import {buildImageTransitionProof,imageTransitionContextBindings,bindImageTransitionAuthorization} from './lib/production-image-transition-proof.mjs';
import {supersedeProductionImageRelease,reconcileProductionImageRelease} from './lib/production-image-supersession.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
const name='/mem9-on-aws/prod/consolidation-runtime/data-release',h=c=>c.repeat(64);
async function fixture(){
 const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),served=imageTransitionServingFixture(f,built),b=imageTransitionContextBindings(built.context);
 let clock=f.predecessor.expiresMs+1;const review={...served.review,reviewedMs:clock,expiresMs:clock+3600000};
 const data={...served.data,issuedMs:clock,expiresMs:review.expiresMs,policyHash:hash(review)};
 const transition=bindImageTransitionAuthorization(built.context,{review,now:clock}),owner=data.authorizationId;
 const predecessor={Name:name,Type:'SecureString',ARN:`arn:aws:ssm:${data.region}:${data.account}:parameter${name}`,Version:1,Value:JSON.stringify(f.predecessor),LastModifiedDate:new Date(f.now).toISOString(),DataType:'text'};
 const lineage=[{parameterVersion:1,predecessorHash:null,authorization:f.predecessor,authorizationHash:hash(f.predecessor)}];
 const expected={account:data.account,region:data.region,controlRevision:f.input.control.revision,controlSourceTree:data.controlSourceTree,
  sourceEvidenceHash:b.control.sourceEvidenceHash,dataOriginSourceEvidenceHash:b.dataOrigin.sourceEvidenceHash,transitionProofHash:built.proofHash,
  materialHash:h('a'),runtimeHash:h('b'),buildInputsHash:data.buildInputsHash,securityEvidenceHash:data.securityEvidenceHash,freshBuildSecurityHash:review.freshBuildSecurityHash,
  policyHash:data.policyHash,parentProofHash:data.parentProofHash,rootHash:h('c'),writerBoundaryHash:h('d'),lineageHash:hash(lineage),rootState:b.rootState,parameterProtection:{KeyId:'alias/aws/ssm',Tier:'Standard',DataType:'text'}};
 const input={authorization:{data,hash:hash(data),review},expected,predecessor,lineage},calls=[],records=new Map();
 let parameter=structuredClone(predecessor),archive=null,gateReleased=false,mutexReleased=false;
 const mutex={owner,etag:'fixture-lock'},gate={owner,before:{value:'false'}};
 const snapshot=options=>({...structuredClone(expected),parameter:structuredClone(parameter),rootVerified:true,writersSerialized:true,executionEnabled:false,dispatcherEnabled:false,enabledSchedules:0,activeWorkers:0,activeAdministration:0,activeContinuations:0,benchmarkRemaining:0,observedMs:clock,...(options?.owner?{fenceOwner:owner}:{})});
 const deps={now:()=>clock,priorAttempt:async()=>null,readArchive:async()=>archive,archive:async value=>{calls.push('archive');archive=structuredClone(value);},readImageTransitionProof:async()=>built.proof,
  inspect:async options=>{calls.push('inspect');return snapshot(options);},readback:async()=>structuredClone(parameter),acquireMutex:async()=>{calls.push('acquire-mutex');return mutex;},acquireGate:async()=>{calls.push('acquire-gate');return gate;},
  assertFence:async()=>{},assertRecoveryOwner:async()=>{},assertRemainingFenceOwnership:async()=>{},
  putParameter:async value=>{calls.push('put');expect(value).toEqual({Name:name,Type:'SecureString',Value:JSON.stringify(data),Overwrite:true,...expected.parameterProtection});parameter={...predecessor,Version:2,Value:value.Value};return {Version:2};},
  restoreGate:async()=>{calls.push('release-gate');gateReleased=true;},releaseMutex:async()=>{calls.push('release-mutex');mutexReleased=true;},recordOutcome:async value=>records.set('outcome',structuredClone(value)),
  readFences:async()=>({mutex,gate,...(gateReleased?{gateReleased:{owner}}:{}),...(mutexReleased?{mutexReleased:{owner}}:{})})};
 for(const [writer,reader,key]of [['recordIntent','readIntent','intent'],['recordAcquisitionIntent','readAcquisitionIntent','acquire'],['recordVerified','readVerified','verified'],['recordAborted','readAborted','aborted']]){
  deps[writer]=async value=>{calls.push(key);records.set(key,structuredClone(value));};deps[reader]=async()=>records.get(key)??null;
 }
 return {f,built,transition,input,data,review,expected,deps,calls,records,snapshot,getArchive:()=>archive,setClock:value=>{clock=value;},clock:()=>clock};
}
it('publishes one typed target with full archived proof and unchanged root/protection',async()=>{
 const f=await fixture(),before=structuredClone(f.input.predecessor),r=await supersedeProductionImageRelease(f.deps,f.input,{transition:f.transition});
 expect(r.phase).toBe('complete');expect(r.parameterVersion).toBe(2);expect(f.calls.filter(x=>x==='put')).toHaveLength(1);
 expect(f.input.predecessor).toEqual(before);expect(f.getArchive().kind).toBe('image-security-transition');expect(f.getArchive().expected.rootState).toEqual(f.expected.rootState);
 expect(f.calls.slice(-2)).toEqual(['release-gate','release-mutex']);
});
it('cannot substitute schema-shaped or cloned proof contexts for verification',async()=>{
 for(const fake of [{},structuredClone((await fixture()).transition)]){
  const f=await fixture();await expect(supersedeProductionImageRelease(f.deps,f.input,{transition:fake})).rejects.toThrow();expect(f.calls).toEqual([]);
 }
});
it('requires the complete immutable image proof before any parameter write',async()=>{
 const f=await fixture();f.deps.readImageTransitionProof=async()=>null;
 await expect(supersedeProductionImageRelease(f.deps,f.input,{transition:f.transition})).rejects.toThrow('ImageReleaseProofArchiveUnverified');expect(f.calls).not.toContain('put');
});
it.each(['rootState','parameterProtection','transitionProofHash','sourceEvidenceHash'])('rejects fresh snapshot drift in %s',async field=>{
 const f=await fixture(),inspect=f.deps.inspect;let reads=0;f.deps.inspect=async options=>{const s=await inspect(options);if(++reads===2)s[field]=field==='rootState'?{...s.rootState,changedRows:0}:field==='parameterProtection'?{...s.parameterProtection,KeyId:'other'}:h('f');return s;};
 const r=await supersedeProductionImageRelease(f.deps,f.input,{transition:f.transition});expect(['rejected','held']).toContain(r.phase);expect(f.calls).not.toContain('put');
});
it('requires an authentic final review hash rather than the static artifact policy hash',async()=>{
 const f=await fixture();f.data.policyHash=f.review.artifactPolicyHash;f.input.authorization.hash=hash(f.data);f.expected.policyHash=f.data.policyHash;
 await expect(supersedeProductionImageRelease(f.deps,f.input,{transition:f.transition})).rejects.toThrow('ImageReleasePolicyReviewInvalid');expect(f.calls).toEqual([]);
});
it('does not repeat a write when its successful response is lost',async()=>{
 const f=await fixture(),put=f.deps.putParameter;f.deps.putParameter=async value=>{await put(value);throw Error('LostResponse');};
 const r=await supersedeProductionImageRelease(f.deps,f.input,{transition:f.transition});expect(r.phase).toBe('complete');expect(f.calls.filter(x=>x==='put')).toHaveLength(1);
});
it('holds an unknown write and never releases its fences',async()=>{
 const f=await fixture();f.deps.putParameter=async()=>{f.calls.push('put');throw Error('Unknown');};
 const r=await supersedeProductionImageRelease(f.deps,f.input,{transition:f.transition});expect(r.phase).toBe('held');expect(r.sent).toBe(true);expect(f.calls).not.toContain('release-gate');expect(f.calls).not.toContain('release-mutex');
});
it('reconciles exact issued evidence without using another Put callback',async()=>{
 const f=await fixture();expect((await supersedeProductionImageRelease(f.deps,f.input,{transition:f.transition})).phase).toBe('complete');
 f.calls.length=0;f.deps.putParameter=async()=>{throw Error('MustNotPut');};
 const r=await reconcileProductionImageRelease(f.deps,f.getArchive(),{transition:f.transition});expect(r.phase).toBe('complete');expect(r.writeAttempted).toBe(false);expect(f.calls).not.toContain('put');
});
it('rejects an invocation whose initial review freshness already expired',async()=>{
 const f=await fixture();f.setClock(f.data.issuedMs+1800000);
 await expect(supersedeProductionImageRelease(f.deps,f.input,{transition:f.transition})).rejects.toThrow('DataReleaseSupersessionEvidenceExpired');expect(f.calls).toEqual([]);
});
it('does not write if the operation deadline expires after initial admission',async()=>{
 const f=await fixture(),acquire=f.deps.acquireGate;
 f.deps.acquireGate=async(...args)=>{const gate=await acquire(...args);f.setClock(f.data.issuedMs+1800000);return gate;};
 const r=await supersedeProductionImageRelease(f.deps,f.input,{transition:f.transition});
 expect(r.error).toBe('DataReleaseSupersessionOperationExpired');expect(f.calls).not.toContain('put');expect(r.phase).toBe('rejected');
});
