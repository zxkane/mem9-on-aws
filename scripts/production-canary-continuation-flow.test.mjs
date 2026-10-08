import {it,expect} from 'vitest';
import {runProductionContinuationFlow} from './lib/production-canary-continuation-flow.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {IMAGE_TRANSITION_LIMITS_HASH} from './lib/production-image-transition.mjs';
import {captureCurrentCanaryCapacity} from './lib/production-current-capacity.mjs';
import {calibrateProductionContinuation} from './lib/production-canary-calibration.mjs';
import {normalizeCanaryTask} from './lib/production-canary-material.mjs';

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
function imageFixture({queued=2,pairs=5}={}){
 const f=fixture({queued}),h=c=>c.repeat(64),c=f.compatibility,prefix='123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/llm-proxy@sha256:';
 c.version=4;c.dataReleaseHash=h('8');c.transition={version:1,kind:'image-security-upgrade',proofHash:h('9'),predecessorHash:h('0'),limitsHash:IMAGE_TRANSITION_LIMITS_HASH,projectionHash:h('1')};
 c.previous.release.workerImage=prefix+h('e');c.current.release.workerImage=prefix+h('d');c.current.release.sourceTag='mem9-bbbbbbb';
 c.current.backendBinding={taskArn:'arn:aws:ecs:ap-northeast-1:123456789012:task/mem9-on-aws-prod-Test/'+'c'.repeat(32),taskDefinitionArn:'arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-on-aws-prod-Test-Backend:2',containers:['llm-proxy','mnemo-server','qwen3-embed'].map(name=>({name,imageDigest:'sha256:'+h('d')}))};
 c.images=Object.fromEntries(['worker','llm-proxy','mnemo-server','qwen3-embed'].map(name=>[name,{previousRoot:'sha256:'+h('e'),previousChild:'sha256:'+h('1'),currentRoot:'sha256:'+h('d'),currentChild:'sha256:'+h('f')}]));
 c.material=Object.fromEntries(['planner','executor','backend','network','authority','credentials'].map(name=>[name,{previous:h('6'),current:['network','credentials'].includes(name)?h('6'):h('7')}]));
 f.capacityDefinition={taskDefinitionArn:'arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-on-aws-prod-Test-Executor:2',family:'mem9-on-aws-prod-Test-Executor',revision:2,networkMode:'awsvpc',runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},requiresCompatibilities:['FARGATE'],cpu:'512',memory:'1024',taskRoleArn:'arn:aws:iam::123456789012:role/task',executionRoleArn:'arn:aws:iam::123456789012:role/execution',containerDefinitions:[{name:'Mem9ConsolidationExecutor',image:c.current.release.workerImage,environment:[],secrets:[]}]};
 c.material.executor.current=hash(normalizeCanaryTask(f.capacityDefinition,{account:'123456789012',region:'ap-northeast-1',images:new Map([[c.current.release.workerImage,{registryId:'123456789012',repositoryName:'mem9-on-aws/llm-proxy',rootDigest:c.images.worker.currentRoot,arm64Digest:c.images.worker.currentChild}]])}));
 f.original.replayActions=Array.from({length:pairs},(_,i)=>({namespace:'namespace',id:h(String(i+1)),result:{action_id:h(String(i+1)),status:'applied',changed_rows:2}}));
 f.original.receiptWindow={firstCommittedMs:1000,lastCommittedMs:pairs*1000,committedMs:Array.from({length:pairs},(_,i)=>(i+1)*1000)};
 Object.assign(f.original.verification,{workerImage:c.previous.release.workerImage,releaseHash:hash(c.previous.release),receipts:pairs,changedRows:pairs*2,sourceRows:pairs,replayResultHash:hash(f.original.replayActions.map(a=>[a.namespace,a.id,a.result]))});
 c.parentProofHash=hash(f.original.verification);
 f.inspected={...structuredClone(f.original),backendBinding:c.current.backendBinding,verification:{...f.original.verification,attemptId:f.attemptId,parentProofHash:c.parentProofHash,workerImage:c.current.release.workerImage,sourceTag:c.current.release.sourceTag,releaseHash:hash(c.current.release),backendBindingHash:hash(c.current.backendBinding)}};
 const originalAdmin=f.deps.admin;
 f.deps.admin=async(op,args)=>{if(op==='inspect-canary'){f.calls.push(op);return f.inspected;}const value=await originalAdmin(op,args);return op==='status'?{...value,canaryUsed:pairs*2}:value;};
 return f;
}
for(const queued of [0,1])it('V4 discovers sufficient real queued work or holds before canary: '+queued,async()=>{
 const f=imageFixture({queued}),before=structuredClone(f.original),r=await runProductionContinuationFlow(f.deps,f,{maxDiscoveryWaves:2});
 expect(r.phase).toBe('held');expect(r.errorCode).toBe('InsufficientCurrentCapacityCandidates');expect(f.calls.filter(c=>c==='wake-planner')).toHaveLength(2);
 expect(f.calls).not.toContain('canary');expect(f.calls).not.toContain('sample');expect(f.calls).not.toContain('release');expect(f.original).toEqual(before);
});
it('V4 rejects insufficient remaining lifetime allowance before any operation',async()=>{
 const f=imageFixture({pairs:9});await expect(runProductionContinuationFlow(f.deps,f)).rejects.toThrow();expect(f.calls).toEqual([]);
});
it('V4 rechecks real queue availability after the baseline before canary admission',async()=>{
 const f=imageFixture(),admin=f.deps.admin;let sampled=false;
 f.deps.admin=async(op,args)=>{const value=await admin(op,args);return op==='status'&&sampled?{...value,queuedActions:1}:value;};
 f.deps.sample=async()=>{sampled=true;return {version:1,workloadHash:'a'.repeat(64),samplesPerKind:150,warmupsPerKind:5,concurrency:1,cadenceMs:250,
  samples:Array.from({length:300},(_,i)=>({kind:i%2?'write_ack':'read',index:Math.floor(i/2),ok:true,startedMs:1000+i*250,finishedMs:1100+i*250,latencyMs:100}))};};
 const result=await runProductionContinuationFlow(f.deps,f);expect(result.phase).toBe('held');expect(result.errorCode).toBe('InsufficientCurrentCapacityCandidates');expect(f.calls).not.toContain('canary');
});
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
for(const scenario of ['legacy','current','partial','legacy-calibration'])it(scenario+' continuation preserves single-apply measurement and promotion gates',async()=>{
  const imageSecurity=scenario!=='legacy',f=imageSecurity?imageFixture():fixture({queued:1}),epoch=Date.now()-600000,h=c=>c.repeat(64),baseAdmin=f.deps.admin,newPairs=imageSecurity&&scenario!=='partial'?2:1;
  const current=structuredClone(f.inspected),times=[];
  for(let i=0;i<newPairs;i++){const id=h(String(f.original.replayActions.length+i+1));current.replayActions.push({namespace:'namespace',id,result:{action_id:id,status:'applied',changed_rows:2}});times.push(epoch+230000+i*5000);}
  current.receiptWindow={firstCommittedMs:1000,lastCommittedMs:times.at(-1),committedMs:[...f.original.receiptWindow.committedMs,...times]};
  Object.assign(current.verification,{receipts:f.original.verification.receipts+newPairs,changedRows:f.original.verification.changedRows+newPairs*2,sourceRows:f.original.verification.sourceRows+newPairs,conservationHash:h('9'),replayResultHash:hash(current.replayActions.map(a=>[a.namespace,a.id,a.result]))});
  let wrote=false,promoted=false,nonce=0,executors=0;
  let activeWrites=0,maxWrites=0;
  f.deps.persist=async value=>{
    activeWrites++;maxWrites=Math.max(maxWrites,activeWrites);const original=JSON.stringify(value);
    await new Promise(resolve=>setTimeout(resolve,value.executorRequested?1:4));
    expect(JSON.stringify(value)).toBe(original);f.saved.push(structuredClone(value));activeWrites--;
  };
  const admission=h('8');
  f.deps.admin=async(op,args)=>{
    if(op==='status'){const s=await baseAdmin(op,args);return promoted?{...s,setupPhase:'promote',enabled:true,dispatcherEnabled:true,admission,activationSeed:h('7'),backendBinding:current.backendBinding}:{...s,canaryUsed:wrote?current.verification.changedRows:f.original.verification.changedRows};}
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
    const invocation=String(++nonce).repeat(32),taskDefinitionArn=imageSecurity&&kind==='executor'?f.capacityDefinition.taskDefinitionArn:'definition-'+kind;
    const start=kind==='planner'?190000:options.wave==='apply'?225000:options.wave==='repeat-a'?310000:320000;
    const imageJournal=imageSecurity&&options.wave==='apply'?{version:1,account:'123456789012',region:'ap-northeast-1',cluster:'mem9-on-aws-prod-Test',clusterArn:'arn:aws:ecs:ap-northeast-1:123456789012:cluster/mem9-on-aws-prod-Test',generation:current.verification.generation,when:epoch+start-1000,deadline:epoch+start+480000,taskRoleArn:f.capacityDefinition.taskRoleArn,executionRoleArn:f.capacityDefinition.executionRoleArn,targetHash:h('a'),overridesHash:hash({containerOverrides:[{name:'Mem9ConsolidationExecutor',environment:[{name:'MEM9_WORKER_GENERATION',value:current.verification.generation},{name:'MEM9_WORKER_INVOCATION',value:invocation},{name:'MEM9_WORKER_ADMISSION',value:options.admission}]}]})}:{};
    await options.onIntent({...imageJournal,stage:'prod',nonce:invocation,wave:options.wave,containerName:'Mem9Consolidation'+(kind==='planner'?'Planner':'Executor'),taskDefinitionArn});
    if(options.onRunning)await options.onRunning({taskArn:'task-'+nonce});
    if(options.wave==='apply'){executors++;wrote=true;f.calls.push('apply');}
    const startedMs=epoch+start,stoppedMs=epoch+(kind==='planner'?300000:options.wave==='apply'?260000:start+1000);
    return {kind,wave:options.wave,invocation,taskArn:imageSecurity?'arn:aws:ecs:ap-northeast-1:123456789012:task/mem9-on-aws-prod-Test/'+invocation:'task-'+invocation,taskDefinitionArn,startedMs,stoppedMs,
      exitCode:0,image:current.verification.workerImage,imageDigest:'sha256:'+h('f'),record:{kind,stage:'prod',invocation,outcome:'complete',startedMs,finishedMs:stoppedMs,classified:20,slices:2,failedSlices:0,changedRows:options.wave==='apply'?newPairs*2:0,matched:current.verification.receipts,resultHash:current.verification.replayResultHash}};
  };
  f.deps.calibrate=async state=>{
    if(!imageSecurity||scenario==='legacy-calibration')return {verificationHash:hash(state.verified.verification),dailyRows:1000,basisPoints:5000,estimatedDrainHours:0.1};
    const d=state.deliveries.find(v=>v.kind==='executor'&&v.wave==='apply'),definition=f.capacityDefinition;
    const task={taskArn:d.taskArn,clusterArn:'arn:aws:ecs:ap-northeast-1:123456789012:cluster/mem9-on-aws-prod-Test',taskDefinitionArn:d.taskDefinitionArn,lastStatus:'STOPPED',launchType:'FARGATE',cpu:definition.cpu,memory:definition.memory,startedAt:new Date(d.startedMs-1000).toISOString(),stoppedAt:new Date(d.stoppedMs+1000).toISOString(),attributes:[{name:'ecs.cpu-architecture',value:'arm64'}],containers:[{name:'Mem9ConsolidationExecutor',image:d.image,imageDigest:d.imageDigest,exitCode:0}],overrides:{containerOverrides:[{name:'Mem9ConsolidationExecutor',environment:[{name:'MEM9_WORKER_GENERATION',value:current.verification.generation},{name:'MEM9_WORKER_INVOCATION',value:d.invocation},{name:'MEM9_WORKER_ADMISSION',value:'9'.repeat(32)}]}]}};
    const clients={ecs:{send:async command=>command.constructor.name==='DescribeTasksCommand'?{tasks:[task],failures:[]}:{taskDefinition:definition}}};
    const launch=state.launches.find(v=>v.kind==='executor'&&v.wave==='apply').journal;
    const capacity=await captureCurrentCanaryCapacity(clients,{delivery:d,launch,attemptId:f.attemptId,dataRevision:'b'.repeat(40),compatibility:f.compatibility});
    const proof=current.verification,census={event:'backlog_census',at:new Date().toISOString(),targetNamespaces:1,targetsHash:hash(proof.targets),controls:{enabled:false,retired_roles:1,execution_receipts:proof.receipts},workerSetup:{generation:proof.generation,validationId:proof.validationId,targetsHash:hash(proof.targets)},exactCandidateUpperBound:{groups:1,rows:2,surplus:1,largest_group:2}};
    return calibrateProductionContinuation(state,f.original,capacity,census,{attemptId:f.attemptId,compatibility:f.compatibility,controlRevision:'c'.repeat(40),dataRevision:'b'.repeat(40),dailyRows:1000,basisPoints:5000});
  };
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
  if(['partial','legacy-calibration'].includes(scenario)){
    expect(result.phase).toBe('held');expect(result.errorCode).toBe(scenario==='partial'?'CurrentCapacityBatchIncomplete':'CurrentCapacityCalibrationRequired');
    expect(result.failureVerification.verification.changedRows).toBe(10+newPairs*2);expect(f.original.verification.changedRows).toBe(10);expect(executors).toBe(1);
    expect(f.calls).not.toContain('promote');expect(f.calls).not.toContain('release');expect(f.calls).not.toContain('prepare');return;
  }
  expect(result.phase).toBe('running_verified');expect(executors).toBe(1);expect(f.calls).toContain('sampler-continued');
  expect(f.calls.indexOf('verify-canary')).toBeGreaterThan(f.calls.indexOf('apply'));
  expect(f.calls.indexOf('activate')).toBeGreaterThan(f.calls.indexOf('promote'));expect(f.calls.indexOf('observe')).toBeGreaterThan(f.calls.indexOf('activate'));
  expect(f.calls.at(-1)).toBe('release');expect(result.replays).toHaveLength(2);expect(result.launches.every(x=>x.journal)).toBe(true);
  expect(maxWrites).toBe(1);
});
