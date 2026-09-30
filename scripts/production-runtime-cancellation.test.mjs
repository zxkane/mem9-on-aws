import {describe,it,expect} from 'vitest';
import {cancellationHash,validateCancellationIntent,cancellationCheckpoint,validateRecoveryEvent,verifyCancellationTakeover,assertCancellationSourceSteps} from './lib/production-runtime-cancellation.mjs';

const sha=letter=>letter.repeat(40),hash=letter=>letter.repeat(64);
const at=Date.now(),repo='example/project';
function fixture(){
  const identity={stage:'pr-7',database:'synthetic'};
  const state={identity,operation_nonce:'a'.repeat(32),phase:'password_fenced',status:'running',epoch:1,sequence:8,last_hash:hash('b'),started_ms:at-60000,deadline_ms:at-60000+7200000};
  const intent={version:1,stage:'pr-7',nonce:state.operation_nonce,sourceRunId:'101',sourceAttempt:1,sourceSha:sha('c'),sourceTree:sha('d'),
    operatorDigest:hash('e'),schemaDigest:hash('f'),coordinatorDigest:hash('a'),identityHash:cancellationHash(identity),preservationHash:hash('c'),createdAt:at-120000};
  const checkpoint=cancellationCheckpoint(intent,state,at);
  const event={repository:{full_name:repo},workflow_run:{id:101,run_attempt:1,event:'workflow_dispatch',path:'.github/workflows/infra-ci.yml',
    head_sha:intent.sourceSha,head_repository:{full_name:repo},conclusion:'cancelled'}};
  const restored={...state,status:'restored',epoch:3,sequence:11,last_hash:hash('d'),rehearsal_preservation:{hash:intent.preservationHash,count:3},
    cancellation_history:[{sequence:8,epoch:1,phase:'password_fenced',status:'running',hash:checkpoint.eventHash,kind:'phase'},
      {sequence:9,epoch:2,phase:'password_fenced',status:'recovering',hash:hash('e'),kind:'recovery'},
      {sequence:11,epoch:3,phase:'password_fenced',status:'restored',hash:hash('d'),kind:'recovery'}]};
  return {state,intent,checkpoint,event,restored};
}
describe('preview cancellation proof boundaries',()=>{
  it('binds a real committed checkpoint to the exact intent',()=>{
    const f=fixture();expect(validateCancellationIntent(f.intent,f.state)).toEqual(f.intent);
    expect(f.checkpoint).toMatchObject({status:'awaiting_cancellation',epoch:1,eventHash:f.state.last_hash,deadlineMs:f.state.deadline_ms});
    expect(()=>cancellationCheckpoint(f.intent,{...f.state,phase:'runtime_prepared'},at)).toThrow();
    expect(()=>validateCancellationIntent({...f.intent,stage:'prod'},{...f.state,identity:{stage:'prod'}})).toThrow();
  });
  it('requires the exact cancelled GitHub attempt and ignores unrelated additive payload fields',()=>{
    const f=fixture();expect(validateRecoveryEvent({...f.event,additiveField:true},f.intent,repo)).toMatchObject({runId:'101',attempt:1});
    for(const patch of [{run_attempt:2},{id:102},{head_sha:sha('e')},{conclusion:'failure'},{event:'pull_request'},{path:'unrelated.yml'},
      {head_repository:{full_name:'foreign/project'}}])expect(()=>validateRecoveryEvent({...f.event,workflow_run:{...f.event.workflow_run,...patch}},f.intent,repo)).toThrow();
  });
  it('requires higher-epoch recovery and restored events plus exact preserved data/deadline',()=>{
    const f=fixture();expect(()=>verifyCancellationTakeover(f.intent,f.checkpoint,f.state,f.restored)).not.toThrow();
    for(const patch of [{epoch:1},{status:'running'},{phase:'transferred'},{deadline_ms:f.restored.deadline_ms+1},
      {rehearsal_preservation:{count:3,hash:hash('f')}},{cancellation_history:[]}])
      expect(()=>verifyCancellationTakeover(f.intent,f.checkpoint,f.state,{...f.restored,...patch})).toThrow();
    expect(()=>verifyCancellationTakeover(f.intent,f.checkpoint,{...f.state,sequence:9,last_hash:hash('e')},f.restored)).toThrow();
  });
  it('requires successful arming and skipped outer recovery/cleanup in the exact source job',()=>{
    const {intent}=fixture();
    const job={name:'Preview runtime credential rehearsal (pr-7)',head_sha:intent.sourceSha,status:'completed',conclusion:'cancelled',
      steps:[['Arm preview cancellation rehearsal','success'],['Restore interrupted preview runtime','skipped'],['Remove disposable rehearsal','skipped']]
        .map(([name,conclusion])=>({name,conclusion,status:'completed'}))};
    expect(()=>assertCancellationSourceSteps(job,intent)).not.toThrow();
    for(const patch of [{steps:[]},{head_sha:sha('f')},{conclusion:'failure'},
      {steps:[...job.steps,job.steps[0]]},{steps:job.steps.map(step=>({...step,conclusion:'success'}))}])
      expect(()=>assertCancellationSourceSteps({...job,...patch},intent)).toThrow();
  });
});
