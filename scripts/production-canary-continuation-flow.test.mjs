import {it,expect} from 'vitest';
import {runProductionContinuationFlow} from './lib/production-canary-continuation-flow.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';

function fixture({queued=0}={}){
  const h=c=>c.repeat(64),attemptId='b'.repeat(32),calls=[],saved=[];
  const oldRelease={sourceTree:'a'.repeat(40),coordinatorDigest:h('a'),schemaDigest:h('b'),operatorDigest:h('c'),runtimeNonce:'d'.repeat(32),sourceTag:'mem9-aaaaaaa',workerImage:'worker@sha256:'+h('e')};
  const nextRelease={...oldRelease,sourceTree:'b'.repeat(40)},backend={taskArn:'old'},nextBackend={taskArn:'new'};
  const actions=[1,2].map(n=>({namespace:'namespace',id:h(String(n)),result:{action_id:h(String(n)),status:'applied',changed_rows:2}}));
  const original={verification:{generation:h('a'),validationId:'a'.repeat(32),targets:['namespace'],workerImage:oldRelease.workerImage,sourceTag:oldRelease.sourceTag,
    backendBindingHash:hash(backend),releaseHash:hash(oldRelease),protectedBaselineHash:h('f'),conservationHash:h('d'),receipts:2,changedRows:4,sourceRows:2,protectedRows:1,plannerOid:11,executorOid:12,
    replayResultHash:hash(actions.map(a=>[a.namespace,a.id,a.result]))},backendBinding:backend,replayActions:actions,receiptWindow:{firstCommittedMs:1000,lastCommittedMs:2000,committedMs:[1000,2000]}};
  const compatibility={version:1,parentProofHash:hash(original.verification),generation:h('a'),targetsHash:hash(['namespace']),previous:{release:oldRelease,backendBindingHash:hash(backend)},current:{release:nextRelease,backendBinding:nextBackend}};
  const inspected={...original,backendBinding:nextBackend,verification:{...original.verification,attemptId,parentProofHash:hash(original.verification),releaseHash:hash(nextRelease),backendBindingHash:hash(nextBackend)}};
  let began=false;
  const deps={guard:async()=>{},persist:async state=>{saved.push(structuredClone(state));},disableScheduling:async()=>calls.push('disable'),recoverDeliveries:async()=>calls.push('recover'),
    quiesce:async()=>calls.push('quiesce'),verifyQuiet:async()=>{},release:async()=>calls.push('release'),hold:async()=>calls.push('hold'),abortWakes:()=>{},
    admin:async(op,args)=>{calls.push(op);if(op==='status')return {setupPhase:'canary',validationId:original.verification.validationId,canaryUsed:4,queuedActions:queued,enabled:false,dispatcherEnabled:false,
      ...(began?{attempt:{id:attemptId,phase:'created',frozen:false}}:{})};
      if(op==='begin-continuation'){expect(args.parentProofHash).toBe(hash(original.verification));expect(saved.at(-1).phase).toBe('beginning');began=true;return {attemptId};}
      if(op==='inspect-canary')return inspected;if(op==='resume-plan')return {admission:'9'.repeat(32)};if(op==='cleanup-benchmark')return {remaining:0};return {};},
    wake:async(kind,options)=>{calls.push('wake-'+kind);await options.onIntent({stage:'prod',nonce:'1'.repeat(32),wave:options.wave,containerName:'Mem9ConsolidationPlanner',taskDefinitionArn:'planner-definition'});return {kind,invocation:'1'.repeat(32),taskDefinitionArn:'planner-definition',record:{classified:1,slices:1,failedSlices:0}};},
    sample:async()=>{calls.push('sample');throw Error('SyntheticSamplingFailure');},
  };
  return {deps,original,attemptId,compatibility,calls,saved,inspected};
}
it('uses canonical continuation and planning-only admission when no executable candidate exists',async()=>{
  const f=fixture();const result=await runProductionContinuationFlow(f.deps,f,{maxDiscoveryWaves:1});
  expect(result.phase).toBe('failed');expect(result.errorCode).toBe('NoExecutableCandidate');
  expect(f.calls).toContain('begin-continuation');expect(f.calls).toContain('resume-plan');expect(f.calls).not.toContain('canary');
  expect(f.calls).not.toContain('prepare');expect(f.calls).not.toContain('baseline');expect(f.calls).not.toContain('verify-canary');
  expect(f.calls.at(-1)).toBe('release');
});
it('cleans a failed baseline without freezing or enabling the active continuation',async()=>{
  const f=fixture({queued:1});const result=await runProductionContinuationFlow(f.deps,f);
  expect(result.phase).toBe('failed');expect(result.errorCode).toBe('SyntheticSamplingFailure');
  expect(f.calls).not.toContain('canary');expect(f.calls).not.toContain('verify-canary');expect(f.calls).toContain('cleanup-benchmark');
  expect(f.calls.filter(x=>x==='inspect-canary').length).toBeGreaterThanOrEqual(3);
});
it('rejects a valid but undeclared N100 baseline before admitting execution',async()=>{
  const f=fixture({queued:1});f.deps.sample=async()=>({version:1,workloadHash:'f'.repeat(64),samplesPerKind:100,warmupsPerKind:5,concurrency:1,cadenceMs:250,
    samples:Array.from({length:200},(_,i)=>({kind:i%2?'write_ack':'read',index:Math.floor(i/2),ok:true,startedMs:1000+i*250,finishedMs:1100+i*250,latencyMs:100}))});
  const result=await runProductionContinuationFlow(f.deps,f);expect(result.errorCode).toBe('ContinuationCohortInvalid');expect(f.calls).not.toContain('canary');expect(f.calls).not.toContain('verify-canary');
});
it('launches one executor from the first measured acknowledgment and verifies recurring delivery before completion',async()=>{
  const f=fixture({queued:1}),epoch=Date.now()-600000,h=c=>c.repeat(64),baseAdmin=f.deps.admin;
  const current=structuredClone(f.inspected),action={namespace:'namespace',id:h('3'),result:{action_id:h('3'),status:'applied',changed_rows:2}};
  current.replayActions.push(action);current.receiptWindow={firstCommittedMs:1000,lastCommittedMs:epoch+230000,committedMs:[1000,2000,epoch+230000]};
  Object.assign(current.verification,{receipts:3,changedRows:6,sourceRows:3,conservationHash:h('9'),replayResultHash:hash(current.replayActions.map(a=>[a.namespace,a.id,a.result]))});
  let wrote=false,promoted=false,nonce=0,executors=0;
  let activeWrites=0,maxWrites=0;
  f.deps.persist=async value=>{
    activeWrites++;maxWrites=Math.max(maxWrites,activeWrites);const original=JSON.stringify(value);
    await new Promise(resolve=>setTimeout(resolve,value.executorRequested?1:4));
    expect(JSON.stringify(value)).toBe(original);f.saved.push(structuredClone(value));activeWrites--;
  };
  const admission=h('8');
  f.deps.admin=async(op,args)=>{
    if(op==='status'){const s=await baseAdmin(op,args);return promoted?{...s,setupPhase:'promote',enabled:true,dispatcherEnabled:true,admission,activationSeed:h('7'),backendBinding:current.backendBinding}:{...s,canaryUsed:wrote?6:4};}
    if(op==='canary'){f.calls.push(op);return {admission:'9'.repeat(32)};}
    if(op==='inspect-canary'||op==='verify-canary'){f.calls.push(op);return wrote?current:f.inspected;}
    if(op==='promote'){f.calls.push(op);expect(args.dailyRows).toBe(1000);promoted=true;return {phase:'promote'};}
    return baseAdmin(op,args);
  };
  const cohort=start=>({version:1,workloadHash:h('5'),samplesPerKind:150,warmupsPerKind:5,concurrency:1,cadenceMs:250,
    samples:Array.from({length:300},(_,i)=>({kind:i%2?'write_ack':'read',index:Math.floor(i/2),ok:true,startedMs:start+i*250,finishedMs:start+i*250+100,latencyMs:100}))});
  f.deps.sample=async(id,phase,options)=>{
    expect(options.samplesPerKind).toBe(150);
    const ref={id:phase,version:1,agentId:'mem9-canary-'+id,contentHash:h('4'),phase,index:0};
    if(phase==='loaded')await options.onWrite({...ref,id:'warmup',warmup:true});
    await options.onWrite({...ref,warmup:false});
    if(phase==='loaded'){await options.onWrite({...ref,warmup:false});f.calls.push('sampler-continued');}
    return cohort(epoch+(phase==='baseline'?10000:200000));
  };
  f.deps.wake=async(kind,options)=>{
    const invocation=String(++nonce).repeat(32),taskDefinitionArn='definition-'+kind;
    await options.onIntent({stage:'prod',nonce:invocation,wave:options.wave,containerName:'Mem9Consolidation'+(kind==='planner'?'Planner':'Executor'),taskDefinitionArn});
    if(options.onRunning)await options.onRunning({taskArn:'task-'+nonce});
    const start=kind==='planner'?190000:options.wave==='apply'?225000:options.wave==='repeat-a'?310000:320000;
    if(options.wave==='apply'){executors++;wrote=true;f.calls.push('apply');}
    return {kind,wave:options.wave,invocation,taskArn:'task-'+invocation,taskDefinitionArn,startedMs:epoch+start,stoppedMs:epoch+(kind==='planner'?300000:options.wave==='apply'?260000:start+1000),
      exitCode:0,image:current.verification.workerImage,imageDigest:'sha256:'+h('f'),record:{kind,classified:20,slices:2,failedSlices:0,matched:3,resultHash:current.verification.replayResultHash}};
  };
  f.deps.calibrate=async state=>({verificationHash:hash(state.verified.verification),dailyRows:1000,basisPoints:5000,estimatedDrainHours:0.1});
  f.deps.activateScheduling=async()=>{f.calls.push('activate');return {};};
  f.deps.observeRecurring=async()=>{
    f.calls.push('observe');const records=Object.fromEntries(['planner','executor'].map(kind=>{
      const proof={version:1,kind,generation:current.verification.generation,admission,image:current.verification.workerImage,exitCode:0,slices:1,failedSlices:0,classified:0,changedRows:0,
        scheduledMs:epoch+400000,startedMs:epoch+401000,stoppedMs:epoch+402000,taskArn:'periodic-'+kind,taskDefinitionArn:'definition-'+kind,
        recordHash:h('1'),overridesHash:h('2'),launchEventHash:h('3'),launchEventId:'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',schedulerIdentity:{arn:'scheduler-role',roleId:'role-id'}};
      return [kind,{...proof,evidenceHash:hash(proof)}];
    }));return {...records,admission,generation:current.verification.generation};
  };
  f.deps.verifyScheduling=async()=>f.calls.push('verify-running');
  const result=await runProductionContinuationFlow(f.deps,f);
  expect(result.phase).toBe('running_verified');expect(executors).toBe(1);expect(f.calls).toContain('sampler-continued');
  expect(f.calls.indexOf('verify-canary')).toBeGreaterThan(f.calls.indexOf('apply'));
  expect(f.calls.indexOf('activate')).toBeGreaterThan(f.calls.indexOf('promote'));expect(f.calls.indexOf('observe')).toBeGreaterThan(f.calls.indexOf('activate'));
  expect(f.calls.at(-1)).toBe('release');expect(result.replays).toHaveLength(2);expect(result.launches.every(x=>x.journal)).toBe(true);
  expect(maxWrites).toBe(1);
});
