import {it,expect} from 'vitest';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {verifyContinuationReceiptSet,verifyContinuationCommitWindow} from './lib/production-canary-continuation-proof.mjs';
const h=c=>c.repeat(64);
function fixture(){
  const release={sourceTree:'a'.repeat(40),coordinatorDigest:h('b'),schemaDigest:h('c'),operatorDigest:h('d'),runtimeNonce:'e'.repeat(32),sourceTag:'mem9-aaaaaaa',workerImage:'image@sha256:'+h('f')};
  const backend={taskArn:'old'},nextBackend={taskArn:'new'},nextRelease={...release,sourceTree:'b'.repeat(40)};
  const action=n=>({namespace:'namespace',id:h(String(n)),result:{action_id:h(String(n)),status:'applied',changed_rows:2}});
  const original={verification:{generation:h('a'),validationId:'a'.repeat(32),targets:['namespace'],workerImage:release.workerImage,sourceTag:release.sourceTag,backendBindingHash:hash(backend),
    receipts:2,changedRows:4,sourceRows:2,protectedRows:1,plannerOid:11,executorOid:12,releaseHash:hash(release),protectedBaselineHash:h('b'),replayResultHash:'',conservationHash:h('c')},
    replayActions:[action(1),action(2)],receiptWindow:{firstCommittedMs:1000,lastCommittedMs:2000,committedMs:[1000,2000]}};
  original.verification.replayResultHash=hash(original.replayActions.map(a=>[a.namespace,a.id,a.result]));
  const attemptId='b'.repeat(32),compatibility={version:2,parentProofHash:hash(original.verification),generation:original.verification.generation,targetsHash:hash(['namespace']),
    previous:{release,backendBindingHash:hash(backend)},current:{release:nextRelease,backendBinding:nextBackend}};
  const current=structuredClone(original);current.replayActions.push(action(3));current.receiptWindow={firstCommittedMs:1000,lastCommittedMs:5000,committedMs:[1000,2000,5000]};
  Object.assign(current.verification,{attemptId,parentProofHash:hash(original.verification),receipts:3,changedRows:6,sourceRows:3,releaseHash:hash(nextRelease),backendBindingHash:hash(nextBackend),
    replayResultHash:hash(current.replayActions.map(a=>[a.namespace,a.id,a.result]))});
  return {original,current,context:{attemptId,compatibility},loaded:{samples:[{kind:'read',startedMs:4000,finishedMs:6000},{kind:'write_ack',startedMs:4100,finishedMs:6100}]}};
}
it('preserves historical receipt identity while accepting separately certified control/backend bindings',()=>{
  const f=fixture();expect(verifyContinuationReceiptSet(f.original,f.current,f.context).newTimes).toEqual([5000]);
  expect(()=>verifyContinuationReceiptSet(f.original,f.current,{...f.context,allowNew:false})).toThrow();
});
it('rejects replaced historical timestamps, baseline, role identities and uncertified releases',()=>{
  for(const mutate of [f=>{f.current.receiptWindow.committedMs[0]++;f.current.receiptWindow.firstCommittedMs++;},f=>{f.current.verification.plannerOid++;},
    f=>{f.current.verification.protectedBaselineHash=h('0');},f=>{f.current.verification.releaseHash=h('0');},f=>{f.current.verification.parentProofHash=h('0');}]){
    const f=fixture();mutate(f);expect(()=>verifyContinuationReceiptSet(f.original,f.current,f.context)).toThrow('CanaryContinuationEvidenceInvalid');
  }
});
it('requires every new commit inside both fresh windows, excluding the historical commits',()=>{
  const f=fixture();expect(verifyContinuationCommitWindow(f.original,f.current,f.loaded,f.context).newActions).toHaveLength(1);
  f.loaded.samples[1].startedMs=5001;expect(()=>verifyContinuationCommitWindow(f.original,f.current,f.loaded,f.context)).toThrow('CanaryContinuationEvidenceInvalid');
});
