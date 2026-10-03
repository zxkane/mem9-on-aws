import {it,expect} from 'vitest';
import {calibrateProductionContinuation} from './lib/production-canary-calibration.mjs';
import {normalizeCanaryTask} from './lib/production-canary-material.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
const h=c=>c.repeat(64),account='123456789012',region='ap-northeast-1',now=1800000000000;
function fixture(){
  const image=`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/llm-proxy@sha256:${h('a')}`,child='sha256:'+h('b'),attemptId='b'.repeat(32),oldTime=now-10800000;
  const release={sourceTree:'a'.repeat(40),coordinatorDigest:h('a'),sourceTag:'mem9-aaaaaaa',workerImage:image,schemaDigest:h('c'),operatorDigest:h('d'),runtimeNonce:'c'.repeat(32)},nextRelease={...release,sourceTree:'b'.repeat(40)};
  const definition={family:'mem9-on-aws-prod-Test-Executor',revision:1,taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/mem9-on-aws-prod-Test-Executor:1`,
    networkMode:'awsvpc',runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},requiresCompatibilities:['FARGATE'],cpu:'512',memory:'1024',
    taskRoleArn:`arn:aws:iam::${account}:role/task`,executionRoleArn:`arn:aws:iam::${account}:role/exec`,containerDefinitions:[{name:'Mem9ConsolidationExecutor',image,environment:[],secrets:[]}]};
  const actions=Array.from({length:5},(_,i)=>({namespace:'namespace',id:h(String(i+1)),result:{action_id:h(String(i+1)),status:'applied',changed_rows:2}})),times=actions.map((_,i)=>oldTime+i*20000);
  const backend={taskArn:'old'},nextBackend={taskArn:'new'};
  const original={verification:{generation:h('d'),validationId:'d'.repeat(32),targets:['namespace'],sourceTag:release.sourceTag,workerImage:image,backendBindingHash:hash(backend),releaseHash:hash(release),
    receipts:5,changedRows:10,sourceRows:5,protectedRows:1,plannerOid:11,executorOid:12,protectedBaselineHash:h('e'),conservationHash:h('f'),replayResultHash:hash(actions.map(a=>[a.namespace,a.id,a.result]))},
    replayActions:actions,receiptWindow:{firstCommittedMs:times[0],lastCommittedMs:times.at(-1),committedMs:times}};
  const current=structuredClone(original);current.replayActions.push({namespace:'namespace',id:h('6'),result:{action_id:h('6'),status:'applied',changed_rows:2}});
  current.receiptWindow={firstCommittedMs:times[0],lastCommittedMs:now-170000,committedMs:[...times,now-170000]};
  Object.assign(current.verification,{attemptId,parentProofHash:hash(original.verification),receipts:6,changedRows:12,sourceRows:6,releaseHash:hash(nextRelease),backendBindingHash:hash(nextBackend),replayResultHash:hash(current.replayActions.map(a=>[a.namespace,a.id,a.result]))});
  const context={account,region,images:new Map([[image,{registryId:account,repositoryName:'mem9-on-aws/llm-proxy',rootDigest:'sha256:'+h('a'),arm64Digest:child}]])};
  const executorHash=hash(normalizeCanaryTask(definition,context));
  const compatibility={parentProofHash:hash(original.verification),generation:original.verification.generation,targetsHash:hash(['namespace']),previous:{release,backendBindingHash:hash(backend)},current:{release:nextRelease,backendBinding:nextBackend},
    images:Object.fromEntries(['worker','mnemo-server','qwen3-embed','llm-proxy'].map(k=>[k,{previousRoot:'sha256:'+h('a'),currentRoot:'sha256:'+h('a'),previousChild:child,currentChild:child}])),
    material:Object.fromEntries(['planner','executor','backend','network','authority','credentials'].map(k=>[k,{previous:k==='executor'?executorHash:h('a'),current:k==='executor'?executorHash:h('a')}]))};
  const invocation='e'.repeat(32),delivery={kind:'executor',wave:'apply',invocation,taskArn:'old-capacity-task',taskDefinitionArn:definition.taskDefinitionArn,startedMs:oldTime-1000,stoppedMs:oldTime+83000,exitCode:0,image,imageDigest:child};
  delivery.record={kind:'executor',stage:'prod',invocation,failedSlices:0,slices:1,changedRows:10,startedMs:delivery.startedMs,finishedMs:delivery.stoppedMs};
  const capacity={sourceRevision:'a'.repeat(40),definition,delivery,task:{taskArn:delivery.taskArn,taskDefinitionArn:delivery.taskDefinitionArn,lastStatus:'STOPPED',launchType:'FARGATE',
    cpu:'512',memory:'1024',startedAt:new Date(oldTime-2000).toISOString(),stoppedAt:new Date(oldTime+90000).toISOString(),attributes:[{name:'ecs.cpu-architecture',value:'arm64'}],containers:[{exitCode:0,image,imageDigest:child}],
    overrides:{containerOverrides:[{name:'Mem9ConsolidationExecutor',environment:[{name:'MEM9_WORKER_GENERATION',value:original.verification.generation},{name:'MEM9_WORKER_INVOCATION',value:invocation},{name:'MEM9_WORKER_ADMISSION',value:'f'.repeat(32)}]}]}}};
  const cohort=start=>({version:1,workloadHash:h('a'),samplesPerKind:150,warmupsPerKind:5,concurrency:1,cadenceMs:250,samples:Array.from({length:300},(_,i)=>({kind:i%2?'write_ack':'read',index:Math.floor(i/2),ok:true,startedMs:start+i*250,finishedMs:start+i*250+100,latencyMs:100}))});
  const report={version:1,verificationHash:hash(current.verification),baseline:cohort(now-400000),loaded:cohort(now-200000),receipts:current.receiptWindow,
    activity:[{kind:'planner',startedMs:now-210000,stoppedMs:now-120000,exitCode:0,image,imageDigest:child},{kind:'executor',startedMs:now-180000,stoppedMs:now-160000,exitCode:0,image,imageDigest:child}],
    replays:['repeat-a','repeat-b'].map((wave,i)=>({wave,invocation:String(i+1).repeat(32),taskHash:h('a'),matched:6,resultHash:current.verification.replayResultHash,beforeHash:current.verification.conservationHash,afterHash:current.verification.conservationHash,startedMs:now-100000+i*10000,finishedMs:now-99000+i*10000,image,imageDigest:child}))};
  const census={event:'backlog_census',at:new Date(now-1000).toISOString(),targetNamespaces:1,targetsHash:hash(['namespace']),controls:{enabled:false,retired_roles:1,execution_receipts:6},workerSetup:{generation:original.verification.generation,validationId:original.verification.validationId,targetsHash:hash(['namespace'])},exactCandidateUpperBound:{groups:1,rows:2,surplus:1,largest_group:2}};
  return {state:{phase:'calibrating',benchmarkRemaining:0,verified:current,report},original,capacity,census,options:{attemptId,compatibility,controlRevision:'b'.repeat(40),now}};
}
const run=f=>calibrateProductionContinuation(f.state,f.original,f.capacity,f.census,f.options);
it('uses the whole original batch rate with first-burst exclusion, duty cycle and headroom',()=>{
  const f=fixture(),value=run(f);expect(value.spanSeconds).toBe(80);expect(value.steadyChangedRows).toBe(8);expect(value.estimatedDailyCapacity).toBe(3456);expect(value.dailyRows).toBe(1000);expect(value.remainingCostUpperBound).toBe(2);
  expect(value.dataSourceTag).toBe('mem9-aaaaaaa');expect(value.controlRevision).toBe('b'.repeat(40));
});
it('rejects changed execution configuration, incomplete capacity, stale census and an unachievable drain target',()=>{
  for(const change of [f=>{f.capacity.definition.cpu='1024';},f=>{f.capacity.delivery.record.changedRows=8;},f=>{f.census.at=new Date(now-300001).toISOString();},
    f=>{f.census.exactCandidateUpperBound={groups:5000,rows:10000,surplus:5000,largest_group:2};},f=>{f.state.benchmarkRemaining=1;}]){
    const f=fixture();change(f);expect(()=>run(f)).toThrow();
  }
});
