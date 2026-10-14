import {describe,it,expect} from 'vitest';
import {runProductionCanaryFlow} from './lib/production-canary-flow.mjs';
const backendBinding={taskArn:'synthetic-backend',taskDefinitionArn:'synthetic-definition',containers:[]};

function fixture({queuedActions=5,sampleFails=false}={}){
  const calls=[],saved=[];let statusCalls=0;
  const deps={
    verifyScheduling:async()=>({backendBinding}),disableScheduling:async()=>{},activateScheduling:async()=>{},
    admin:async(op)=>{calls.push(op);if(op==='status')return statusCalls++?{queuedActions}:{setupPhase:undefined};
      if(op==='baseline')return {validationId:'a'.repeat(32)};if(op==='cleanup-benchmark')return {remaining:0};
      if(['plan','canary'].includes(op))return {admission:'9'.repeat(32)};return {};},
    recoverDeliveries:async()=>calls.push('recover-deliveries'),quiesce:async()=>calls.push('quiesce'),
    persist:async state=>saved.push(structuredClone(state)),
    sample:async()=>{if(sampleFails)throw Error('SyntheticSampleFailure');return {};},
    wake:async()=>{calls.push('wake');return {};},
  };
  return {deps,calls,saved};
}
describe('production canary orchestration failure boundaries',()=>{
  it('promotes only after loaded sampling, two matching replays, cleanup and a fresh snapshot',async()=>{
    const epoch=Date.now()-300000,calls=[],writes=[],proof={validationId:'a'.repeat(32),generation:'b'.repeat(64),receipts:5,replayResultHash:'c'.repeat(64),conservationHash:'d'.repeat(64)};
    proof.workerImage='example/worker@sha256:'+'e'.repeat(64);const imageDigest='sha256:'+'f'.repeat(64);
    const receiptWindow={firstCommittedMs:epoch+110000,lastCommittedMs:epoch+125000,committedMs:[epoch+110000,epoch+125000]};
    const cohort=start=>({version:1,workloadHash:'e'.repeat(64),samplesPerKind:150,warmupsPerKind:5,concurrency:1,cadenceMs:250,
      samples:Array.from({length:300},(_,i)=>({kind:i%2?'write_ack':'read',index:Math.floor(i/2),ok:true,startedMs:start+i*250,finishedMs:start+i*250+100,latencyMs:100}))});
    let promoted=false;
    const deps={verifyScheduling:async()=>({backendBinding}),disableScheduling:async()=>{calls.push('disable-scheduling');},activateScheduling:async()=>{calls.push('activate-scheduling');return {};},
      admin:async(op,options)=>{calls.push(op);if(op==='status')return promoted?{setupPhase:'promote',enabled:true,dispatcherEnabled:true,admission:'8'.repeat(64),backendBinding}:{setupPhase:'prepared',queuedActions:5};
      if(op==='baseline'){expect(options.backendBinding).toEqual(backendBinding);return {validationId:proof.validationId};}
      if(['plan','canary'].includes(op))return {admission:'9'.repeat(32)};
      if(op==='cleanup-benchmark')return {remaining:0};
      if(op==='verify-canary')return {verification:proof,replayActions:[{}],receiptWindow};
      if(op==='promote'){promoted=true;return {performance:{}};}return {};},
      recoverDeliveries:async()=>{},quiesce:async()=>{},persist:async()=>{},
      sample:async(_id,phase,{samplesPerKind,onWrite})=>{
        expect(samplesPerKind).toBe(150);
        const ref={id:phase,version:1,agentId:'mem9-canary-'+proof.validationId,contentHash:'f'.repeat(64)};writes.push(ref);
        await onWrite({...ref,phase,index:0,warmup:false});return cohort(epoch+(phase==='baseline'?0:100000));},
      wake:async(kind,options,...rest)=>{
        if(typeof options!=='object'){calls.push(options);return {};}
        const {wave,onRunning}=options;calls.push(kind+':'+wave);
        if(kind==='planner'){await onRunning();return {kind:'planner',startedMs:epoch+90000,stoppedMs:epoch+200000,exitCode:0,image:proof.workerImage,imageDigest};}
        if(wave==='apply'){expect(calls).toContain('planner:plan');return {kind:'executor',startedMs:epoch+105000,stoppedMs:epoch+160000,exitCode:0,image:proof.workerImage,imageDigest};}
        const i=wave==='repeat-a'?1:2;
        return {invocation:String(i).repeat(32),taskArn:'synthetic-'+i,startedMs:epoch+210000+i*10000,stoppedMs:epoch+211000+i*10000,image:proof.workerImage,imageDigest,record:{matched:5,resultHash:proof.replayResultHash}};
      }};
    expect((await runProductionCanaryFlow(deps)).phase).toBe('running');
    expect(calls.indexOf('promote')).toBeGreaterThan(calls.indexOf('executor:repeat-b'));
    expect(calls.indexOf('executor:apply')).toBeGreaterThan(calls.indexOf('planner:plan'));
    expect(calls.indexOf('promote')).toBeGreaterThan(calls.indexOf('cleanup-benchmark'));
    expect(calls.indexOf('activate-scheduling')).toBeGreaterThan(calls.indexOf('promote'));
    expect(writes).toHaveLength(2);
    promoted=false;calls.length=0;
    await expect(runProductionCanaryFlow({...deps,activateScheduling:async()=>{throw Error('SyntheticActivationFailure');}})).rejects.toThrow('SyntheticActivationFailure');
    expect(calls.lastIndexOf('pause')).toBeGreaterThan(calls.indexOf('promote'));
    expect(calls.lastIndexOf('disable-scheduling')).toBeGreaterThan(calls.lastIndexOf('pause'));
  });
  it('fails before replays when the covering planner stops before the loaded cohort ends',async()=>{
    const epoch=Date.now()-300000,calls=[],imageDigest='sha256:'+'f'.repeat(64),image='example/worker@sha256:'+'e'.repeat(64);
    const receiptWindow={firstCommittedMs:epoch+110000,lastCommittedMs:epoch+110000,committedMs:[epoch+110000]};
    const cohort=start=>({version:1,workloadHash:'e'.repeat(64),samplesPerKind:150,warmupsPerKind:5,concurrency:1,cadenceMs:250,
      samples:Array.from({length:300},(_,i)=>({kind:i%2?'write_ack':'read',index:Math.floor(i/2),ok:true,startedMs:start+i*250,finishedMs:start+i*250+100,latencyMs:100}))});
    const deps={verifyScheduling:async()=>({backendBinding}),disableScheduling:async()=>calls.push('disable-scheduling'),
      admin:async op=>{calls.push(op);if(op==='status')return {setupPhase:'prepared',queuedActions:5};if(op==='baseline')return {validationId:'a'.repeat(32)};
        if(['plan','canary'].includes(op))return {admission:'9'.repeat(32)};if(op==='cleanup-benchmark')return {remaining:0};
        if(op==='verify-canary')return {verification:{},replayActions:[{}],receiptWindow};return {};},
      recoverDeliveries:async()=>{},quiesce:async()=>{},persist:async()=>{},
      sample:async(_id,phase,{onWrite})=>{await onWrite({id:phase,version:1,agentId:'mem9-canary-'+'a'.repeat(32),contentHash:'f'.repeat(64),phase,index:0,warmup:false});return cohort(epoch+(phase==='baseline'?0:100000));},
      wake:async(kind,options)=>{
        if(typeof options!=='object')return {};calls.push(kind+':'+options.wave);
        if(kind==='planner'){await options.onRunning();return {kind,startedMs:epoch+90000,stoppedMs:epoch+120000,exitCode:0,image,imageDigest};}
        return {kind,startedMs:epoch+105000,stoppedMs:epoch+130000,exitCode:0,image,imageDigest};
      }};
    await expect(runProductionCanaryFlow(deps)).rejects.toThrow('CanaryPerformanceNotVerified');
    expect(calls).not.toContain('executor:repeat-a');expect(calls).not.toContain('promote');
    expect(calls.lastIndexOf('pause')).toBeGreaterThan(calls.indexOf('verify-canary'));
    expect(calls).toContain('cleanup-benchmark');
  });
  it('never activates execution when planning did not produce enough eligible actions',async()=>{
    const f=fixture({queuedActions:0});
    await expect(runProductionCanaryFlow(f.deps,{planningWaves:1})).rejects.toThrow('InsufficientCanaryActions');
    expect(f.calls).not.toContain('canary');expect(f.calls).not.toContain('promote');
    expect(f.calls.filter(call=>call==='pause')).toHaveLength(2);
    expect(f.saved.at(-1).phase).toBe('failed');
  });
  it('uses the persisted binding on restart and pauses when that evidence is rejected',async()=>{
    const calls=[];
    const deps={admin:async op=>{calls.push(op);return {setupPhase:'promote',enabled:true,dispatcherEnabled:true,backendBinding};},
      verifyScheduling:async options=>{expect(options.backendBinding).toBe(backendBinding);throw Error('ProductionBackendArtifactChanged');},
      disableScheduling:async()=>calls.push('disabled')};
    await expect(runProductionCanaryFlow(deps)).rejects.toThrow('ProductionBackendArtifactChanged');expect(calls).toEqual(['status','pause','disabled']);
  });
  it('pauses and retains failed measurement state without promotion',async()=>{
    const f=fixture({sampleFails:true});
    await expect(runProductionCanaryFlow(f.deps)).rejects.toThrow('SyntheticSampleFailure');
    expect(f.calls.indexOf('baseline')).toBeGreaterThan(f.calls.indexOf('quiesce'));
    expect(f.calls).not.toContain('canary');expect(f.calls).not.toContain('promote');
    expect(f.calls).toContain('cleanup-benchmark');
    expect(f.saved.at(-1).phase).toBe('failed');
  });
});
