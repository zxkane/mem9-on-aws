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
it('V3 continuation preserves original receipts and rejects transition downgrade or fabricated authority equality',()=>{
 const f=fixture(),c=f.context.compatibility,image='123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/llm-proxy@sha256:'+h('f');
 c.version=3;c.dataReleaseHash=h('1');c.previous.release.workerImage=image;c.current.release.workerImage=image;
 c.current.backendBinding={taskArn:'arn:aws:ecs:ap-northeast-1:123456789012:task/mem9-on-aws-prod-Fixture/'+'a'.repeat(32),taskDefinitionArn:'arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-on-aws-prod-Fixture-Mem9RuntimeServer:2',containers:['llm-proxy','mnemo-server','qwen3-embed'].map(name=>({name,imageDigest:'sha256:'+h('e')}))};
 c.images=Object.fromEntries(['worker','llm-proxy','mnemo-server','qwen3-embed'].map(name=>[name,{previousRoot:'sha256:'+h('f'),currentRoot:'sha256:'+h('f'),previousChild:'sha256:'+h('e'),currentChild:'sha256:'+h('e')}]));
 c.material=Object.fromEntries(['planner','executor','backend','network','authority','credentials'].map(name=>[name,{previous:h('1'),current:['backend','authority'].includes(name)?h('2'):h('1')}]));
 c.transition={version:1,kind:'bootstrap-boundary-tightening',proofHash:h('3'),backendProjectionHash:h('4')};
 Object.assign(f.original.verification,{workerImage:image,releaseHash:hash(c.previous.release)});c.parentProofHash=hash(f.original.verification);
 Object.assign(f.current.verification,{workerImage:image,parentProofHash:c.parentProofHash,releaseHash:hash(c.current.release),backendBindingHash:hash(c.current.backendBinding)});
 expect(verifyContinuationReceiptSet(f.original,f.current,f.context).newTimes).toEqual([5000]);
 c.version=2;expect(()=>verifyContinuationReceiptSet(f.original,f.current,f.context)).toThrow('CanaryTransitionCertificateInvalid');
 c.version=3;c.material.authority.current=c.material.authority.previous;expect(()=>verifyContinuationReceiptSet(f.original,f.current,f.context)).toThrow('CanaryTransitionCertificateInvalid');
});
