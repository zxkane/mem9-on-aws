import {describe,it,expect} from 'vitest';
import {cancellationRehearsal} from './lib/production-runtime-cancellation-runner.mjs';
import {cancellationHash} from './lib/production-runtime-cancellation.mjs';

const hex=(letter,n=64)=>letter.repeat(n);
async function fixture(){
  const stage='pr-7',repo='example/project',time=Date.now();
  const records=new Map(),calls=[],env={GITHUB_RUN_ID:'101',GITHUB_RUN_ATTEMPT:'1',GITHUB_SHA:hex('a',40),GITHUB_REPOSITORY:repo,MEM9_RUNTIME_CANCELLATION_DRILL:'1'};
  const release={sourceSha:env.GITHUB_SHA,sourceTree:hex('b',40),operatorDigest:hex('c'),schemaDigest:hex('d'),coordinatorDigest:hex('e')};
  const identity={stage,database:'synthetic',operatorDigest:release.operatorDigest,schemaDigest:release.schemaDigest};
  const ctx={state:{identity,operation_nonce:'a'.repeat(32),phase:'prepared',status:'running',epoch:1,sequence:1,last_hash:hex('a'),started_ms:null,deadline_ms:null},
    plan:{sourceRunId:'101',sourceRunAttempt:1},armed:false,receiptFailure:false,race:false,receiverFailure:false};
  const original={id:101,run_attempt:1,event:'workflow_dispatch',path:'.github/workflows/infra-ci.yml',head_sha:release.sourceSha,
    head_repository:{full_name:repo},status:'completed',conclusion:'cancelled'};
  const actor={runId:'202',attempt:1,workflowRef:`${repo}/.github/workflows/runtime-recovery.yml@refs/heads/main`,workflowSha:hex('f',40)};
  const worker=cancellationRehearsal({env,stage,getPlan:()=>ctx.plan,now:()=>time,release:async()=>release,
    readRecord:async key=>records.get(key),writeRecord:async(key,value)=>{
      if(key==='cancellation-receipt'&&ctx.receiptFailure==='before')throw Error('SyntheticPublicationFailure');
      records.set(key,structuredClone(value));
      if(key==='cancellation-receipt'&&ctx.receiptFailure==='after')throw Error('SyntheticLostReadback');
    },
    readState:async()=>structuredClone(ctx.state),armedOutput:async()=>{ctx.armed=true;},
    claimSource:async()=>{ctx.plan={sourceRunId:env.GITHUB_RUN_ID,sourceRunAttempt:Number(env.GITHUB_RUN_ATTEMPT)};if(ctx.race)ctx.state.last_hash=hex('e');},
    sleep:async()=>{throw Error('SyntheticRunnerCancelled');},
    readEvent:async()=>({repository:{full_name:repo},workflow_run:original}),
    execute:async(_file,args)=>{
      const path=args[1];
      if(path.includes('/101/attempts/1/jobs'))return {stdout:JSON.stringify({total_count:1,jobs:[{
        name:`Preview runtime credential rehearsal (${stage})`,head_sha:original.head_sha,status:'completed',conclusion:'cancelled',
        steps:[['Arm preview cancellation rehearsal','success'],['Restore interrupted preview runtime','skipped'],['Remove disposable rehearsal','skipped']]
          .map(([name,conclusion])=>({name,conclusion,status:'completed'})),
      }]})};
      if(path.endsWith('/101/attempts/1'))return {stdout:JSON.stringify(original)};
      if(path.endsWith('/202/attempts/1'))return {stdout:JSON.stringify({id:202,run_attempt:1,event:'workflow_run',path:'.github/workflows/runtime-recovery.yml',head_branch:'main',
        head_sha:actor.workflowSha,status:'completed',conclusion:ctx.receiverFailure?'failure':'success'})};
      throw Error('UnexpectedGitHubRequest');
    },
    invoke:async(op,state,extra)=>{
      calls.push(op);
      if(op==='rehearsal-preservation')return {...structuredClone(ctx.state),rehearsal_preservation:{count:3,hash:hex('f')},
        cancellation_history:ctx.history??[]};
      if(op==='resume'){
        if(state.epoch!==ctx.state.epoch||extra.expected_hash!==ctx.state.last_hash)throw Error('RecoveryEvidenceChanged');
        ctx.state={...ctx.state,status:'running',epoch:ctx.state.epoch+1,sequence:ctx.state.sequence+1,last_hash:hex('b')};return structuredClone(ctx.state);
      }
      throw Error('UnexpectedOperation');
    }});
  await worker.arm();
  const intent=records.get('cancellation-intent');
  ctx.state={...ctx.state,phase:'runtime_prepared',started_ms:time-60000,deadline_ms:time-60000+7200000};
  await worker.beforeFence(ctx.state);
  ctx.state={...ctx.state,phase:'password_fenced',sequence:8,last_hash:hex('b')};
  await expect(worker.afterFence(ctx.state)).rejects.toThrow('SyntheticRunnerCancelled');
  const before=structuredClone(ctx.state),checkpoint=records.get('cancellation-checkpoint');
  Object.assign(env,{GITHUB_RUN_ID:actor.runId,GITHUB_RUN_ATTEMPT:String(actor.attempt),GITHUB_EVENT_NAME:'workflow_run',MEM9_RUNTIME_RECOVERY_RUN_ID:intent.sourceRunId,
    GITHUB_WORKFLOW_REF:actor.workflowRef,GITHUB_WORKFLOW_SHA:actor.workflowSha});
  ctx.state={...ctx.state,status:'restored',epoch:3,sequence:11,last_hash:hex('d')};
  ctx.history=[{sequence:8,epoch:1,phase:'password_fenced',status:'running',hash:checkpoint.eventHash,kind:'phase'},
    {sequence:9,epoch:2,phase:'password_fenced',status:'recovering',hash:hex('c'),kind:'recovery'},
    {sequence:11,epoch:3,phase:'password_fenced',status:'restored',hash:ctx.state.last_hash,kind:'recovery'}];
  const recover=()=>worker.afterRestoration(before,ctx.state,{verification_hash:hex('e')});
  const resume=()=>{Object.assign(env,{GITHUB_RUN_ID:'303',GITHUB_RUN_ATTEMPT:'1',GITHUB_EVENT_NAME:'workflow_dispatch'});return worker.resume();};
  return {ctx,records,calls,env,worker,checkpoint,intent,before,recover,resume};
}
describe('independent cancellation evidence orchestration',()=>{
  it('publishes only real takeover, verifies both attempts, then resumes with the exact database event fence',async()=>{
    const f=await fixture();expect(f.ctx.armed).toBe(true);
    await f.recover();const receipt=f.records.get('cancellation-receipt');expect(receipt.receiver.runId).toBe('202');
    const state=await f.resume();expect(state.epoch).toBe(4);expect(state.deadline_ms).toBe(f.checkpoint.deadlineMs);
    const accepted=f.records.get('cancellation-accepted');expect(accepted.receiptHash).toBe(cancellationHash(receipt));
    expect(await f.worker.evidence({...state,phase:'complete'})).toMatchObject({sourceRunId:'101',sourceAttempt:1});
  });
  it.each(['before','after'])('keeps restored runtime but refuses acceptance after %s publication failure',async failure=>{
    const f=await fixture();f.ctx.receiptFailure=failure;
    await expect(f.recover()).rejects.toThrow();
    expect(f.ctx.state.status).toBe('restored');expect(f.records.has('cancellation-accepted')).toBe(false);
    expect(f.calls).not.toContain('resume');
  });
  it('does not accept a failed receiver even when its receipt was written',async()=>{
    const f=await fixture();await f.recover();f.ctx.receiverFailure=true;
    await expect(f.resume()).rejects.toThrow();expect(f.calls).not.toContain('resume');
  });
  it('rejects the resume race inside the database invocation, before acceptance publication',async()=>{
    const f=await fixture();await f.recover();f.ctx.race=true;
    await expect(f.resume()).rejects.toThrow('RecoveryEvidenceChanged');
    expect(f.ctx.state.status).toBe('restored');expect(f.records.has('cancellation-accepted')).toBe(false);
  });
  it('rejects an advanced checkpoint after restoration without modifying the restored state',async()=>{
    const f=await fixture();
    await expect(f.worker.afterRestoration({...f.before,sequence:9,last_hash:hex('a')},f.ctx.state,{verification_hash:hex('e')})).rejects.toThrow();
    expect(f.ctx.state.status).toBe('restored');expect(f.records.has('cancellation-receipt')).toBe(false);
  });
});
