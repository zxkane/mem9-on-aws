import {it,expect} from 'vitest';
import {calibrateProductionContinuation} from './lib/production-canary-calibration.mjs';
import {normalizeCanaryTask} from './lib/production-canary-material.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {IMAGE_TRANSITION_LIMITS_HASH} from './lib/production-image-transition.mjs';
import {asNonrootCertificate} from './production-nonroot-runtime.fixture.mjs';
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
function transitionFixture(){
 const f=fixture(),c=f.options.compatibility;c.version=3;c.dataReleaseHash=h('c');c.transition={version:1,kind:'bootstrap-boundary-tightening',proofHash:h('d'),backendProjectionHash:h('e')};
 c.material.authority.current=h('f');c.material.backend.current=h('e');c.current.backendBinding={taskArn:`arn:aws:ecs:${region}:${account}:task/mem9-on-aws-prod-Test/`+'a'.repeat(32),taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/mem9-on-aws-prod-Test-Backend:2`,containers:['llm-proxy','mnemo-server','qwen3-embed'].map(name=>({name,imageDigest:'sha256:'+h('a')}))};
 f.state.verified.verification.backendBindingHash=hash(c.current.backendBinding);f.state.report.verificationHash=hash(f.state.verified.verification);return f;
}
it('V3 calibration preserves original receipts and capacity while retaining unequal authority hashes',()=>{
 const f=transitionFixture(),before=structuredClone(f.original),value=run(f);expect(value.estimatedDailyCapacity).toBe(3456);expect(value.capacityReceipts).toBe(5);expect(f.original).toEqual(before);expect(f.options.compatibility.material.authority.previous).not.toBe(f.options.compatibility.material.authority.current);
});
it('V3 calibration rejects a malformed commitment or unrelated execution-material change',()=>{
 for(const key of ['commitment','executor']){const f=transitionFixture();if(key==='commitment')f.options.compatibility.transition.proofHash='bad';else f.options.compatibility.material.executor.current=h('9');expect(()=>run(f)).toThrow();}
});

function currentImageFixture({pairs=2}={}){
 const f=fixture(),c=f.options.compatibility,attemptId=f.options.attemptId,dataRevision='7'.repeat(40),image=`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/llm-proxy@sha256:${h('7')}`;
 c.version=4;c.dataReleaseHash=h('8');c.transition={version:1,kind:'image-security-upgrade',proofHash:h('9'),predecessorHash:h('0'),limitsHash:IMAGE_TRANSITION_LIMITS_HASH,projectionHash:h('1')};
 c.current.release={...c.current.release,sourceTag:'mem9-'+dataRevision.slice(0,7),workerImage:image};
 c.images=Object.fromEntries(['worker','llm-proxy','mnemo-server','qwen3-embed'].map(name=>[name,{previousRoot:'sha256:'+h('a'),previousChild:'sha256:'+h('b'),currentRoot:'sha256:'+h('7'),currentChild:'sha256:'+h('8')}]));
 c.material.planner.current=h('2');c.material.backend.current=h('3');c.material.authority.current=h('4');
 const cluster=`arn:aws:ecs:${region}:${account}:cluster/mem9-on-aws-prod-Test`;
 c.current.backendBinding={taskArn:cluster.replace(':cluster/',':task/')+'/'+'a'.repeat(32),taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/mem9-on-aws-prod-Test-Backend:2`,containers:['llm-proxy','mnemo-server','qwen3-embed'].map(name=>({name,imageDigest:'sha256:'+h('7')}))};
 const current=structuredClone(f.original),times=Array.from({length:pairs},(_,i)=>now-175000+i*5000);
 for(let i=0;i<pairs;i++)current.replayActions.push({namespace:'namespace',id:(i+6).toString(16).padStart(64,'0'),result:{action_id:(i+6).toString(16).padStart(64,'0'),status:'applied',changed_rows:2}});
 current.receiptWindow={...current.receiptWindow,lastCommittedMs:times.at(-1),committedMs:[...current.receiptWindow.committedMs,...times]};
 Object.assign(current.verification,{attemptId,parentProofHash:c.parentProofHash,workerImage:image,sourceTag:c.current.release.sourceTag,receipts:5+pairs,changedRows:10+pairs*2,sourceRows:5+pairs,
  releaseHash:hash(c.current.release),backendBindingHash:hash(c.current.backendBinding),replayResultHash:hash(current.replayActions.map(a=>[a.namespace,a.id,a.result]))});
 f.state.verified=current;f.state.report.verificationHash=hash(current.verification);f.state.report.receipts=current.receiptWindow;
 for(const a of f.state.report.activity){a.image=image;a.imageDigest='sha256:'+h('8');if(a.kind==='executor')a.stoppedMs=now-140000;}
 for(const replay of f.state.report.replays){replay.image=image;replay.imageDigest='sha256:'+h('8');replay.matched=5+pairs;replay.resultHash=current.verification.replayResultHash;}
 const definition=structuredClone(f.capacity.definition);definition.revision=2;definition.taskDefinitionArn=definition.taskDefinitionArn.replace(/:1$/,':2');definition.containerDefinitions[0].image=image;
 c.material.executor.current=hash(normalizeCanaryTask(definition,{account,region,images:new Map([[image,{registryId:account,repositoryName:'mem9-on-aws/llm-proxy',rootDigest:'sha256:'+h('7'),arm64Digest:'sha256:'+h('8')}]])}));
 const delivery={...f.capacity.delivery,taskArn:cluster.replace(':cluster/',':task/')+'/'+'b'.repeat(32),taskDefinitionArn:definition.taskDefinitionArn,startedMs:now-180000,stoppedMs:now-140000,image,imageDigest:'sha256:'+h('8')};
 delivery.record={...delivery.record,outcome:'complete',changedRows:pairs*2,startedMs:delivery.startedMs,finishedMs:delivery.stoppedMs};
 const task={...f.capacity.task,clusterArn:cluster,taskArn:delivery.taskArn,taskDefinitionArn:definition.taskDefinitionArn,startedAt:new Date(now-181000).toISOString(),stoppedAt:new Date(now-139000).toISOString(),containers:[{name:definition.containerDefinitions[0].name,image,imageDigest:delivery.imageDigest,exitCode:0}]};
 const launch={version:1,stage:'prod',region,account,cluster:'mem9-on-aws-prod-Test',clusterArn:cluster,generation:c.generation,nonce:delivery.invocation,wave:'apply',when:delivery.startedMs-1000,deadline:delivery.stoppedMs+1000,
  taskDefinitionArn:definition.taskDefinitionArn,containerName:'Mem9ConsolidationExecutor',taskRoleArn:definition.taskRoleArn,executionRoleArn:definition.executionRoleArn,targetHash:h('f'),overridesHash:hash({containerOverrides:task.overrides.containerOverrides})};
 f.capacity={version:1,kind:'current-apply-capacity',attemptId,dataRevision,dataReleaseHash:c.dataReleaseHash,observedMs:now-1000,definition,delivery,launch,task};
 f.state.deliveries=[structuredClone(delivery)];f.state.launches=[{kind:'executor',wave:'apply',journal:structuredClone(launch)}];f.state.executorRequested=true;f.options.dataRevision=dataRevision;f.census.controls.execution_receipts=5+pairs;
 return f;
}
it('V4 measures the complete current apply delta while preserving the original receipt set and allowance',()=>{
 const f=currentImageFixture(),before=structuredClone(f.original),value=run(f);
 expect(value.capacitySource).toBe('current-apply');expect(value.capacityReceipts).toBe(2);expect(value.steadyChangedRows).toBe(2);expect(value.spanSeconds).toBe(5);
 expect(value.existingSpent).toBe(10);expect(value.newChangedRows).toBe(4);expect(f.state.verified.verification.changedRows).toBe(14);expect(f.original).toEqual(before);
});
it('V4 accepts the full remaining allowance without creating another budget',()=>{
 const f=currentImageFixture({pairs:5}),value=run(f);expect(value.capacityReceipts).toBe(5);expect(value.newChangedRows).toBe(10);expect(f.state.verified.verification.changedRows).toBe(20);
});
function nonrootCapacityFixture(){
 const f=currentImageFixture();f.options.compatibility=asNonrootCertificate(f.options.compatibility);
 const container=f.capacity.definition.containerDefinitions[0];Object.assign(container,{user:'1000:1000',privileged:false,linuxParameters:{capabilities:{drop:['ALL']}},entryPoint:['/usr/bin/setpriv','--no-new-privs','--','node'],command:['/app/scripts/consolidation-worker.mjs']});
 const c=f.options.compatibility,image=c.current.release.workerImage;
 c.material.executor.current=hash(normalizeCanaryTask(f.capacity.definition,{account,region,images:new Map([[image,{registryId:account,repositoryName:'mem9-on-aws/llm-proxy',rootDigest:c.images.worker.currentRoot,arm64Digest:c.images.worker.currentChild}]])}));
 return f;
}
it('V5 calibrates only the current prefixed apply task and retains original spent/cap',()=>{
 const f=nonrootCapacityFixture(),original=structuredClone(f.original),value=run(f);
 expect(value.capacitySource).toBe('current-apply');expect(value.newChangedRows).toBe(4);expect(value.existingSpent).toBe(10);expect(f.original).toEqual(original);
});
for(const defect of ['unprefixed','root','added-capability','dropped-capability','old-capacity','replay'])it('V5 current capacity rejects '+defect,()=>{
 const f=nonrootCapacityFixture(),container=f.capacity.definition.containerDefinitions[0],c=f.options.compatibility;
 if(defect==='unprefixed')container.entryPoint=['node'];if(defect==='root')container.user='0:0';if(defect==='added-capability')container.linuxParameters.capabilities.add=['SYS_ADMIN'];if(defect==='dropped-capability')container.linuxParameters.capabilities.drop=[];
 if(defect==='old-capacity')f.capacity=fixture().capacity;if(defect==='replay')f.capacity.delivery.wave='repeat-a';
 if(!['old-capacity','replay'].includes(defect)){const image=c.current.release.workerImage;c.material.executor.current=hash(normalizeCanaryTask(f.capacity.definition,{account,region,images:new Map([[image,{registryId:account,repositoryName:'mem9-on-aws/llm-proxy',rootDigest:c.images.worker.currentRoot,arm64Digest:c.images.worker.currentChild}]])}));}
 expect(()=>run(f)).toThrow();
});
for(const defect of ['one-pair','over-budget','historical-capacity','replay-capacity','cross-batch','subset','full-revision','task-window','read-window','write-window','old-image','wrong-definition','stale-census'])it('V4 calibration holds '+defect,()=>{
 const f=currentImageFixture({pairs:defect==='one-pair'?1:defect==='over-budget'?6:2});
 if(defect==='historical-capacity')f.capacity=fixture().capacity;
 if(defect==='replay-capacity')f.capacity.delivery.wave='repeat-a';
 if(defect==='cross-batch')f.state.deliveries.push({...f.state.deliveries[0],invocation:'1'.repeat(32)});
 if(defect==='subset'){f.capacity.delivery.record.changedRows=2;f.state.deliveries[0].record.changedRows=2;}
 if(defect==='full-revision')f.capacity.dataRevision=f.options.dataRevision.slice(0,7)+'8'.repeat(33);
 if(defect==='task-window')f.capacity.task.startedAt=new Date(now-170000).toISOString();
 if(defect==='read-window'||defect==='write-window'){const kind=defect==='read-window'?'read':'write_ack';for(const s of f.state.report.loaded.samples.filter(s=>s.kind===kind)){s.startedMs+=50000;s.finishedMs+=50000;}}
 if(defect==='old-image')f.capacity.task.containers[0].imageDigest='sha256:'+h('b');
 if(defect==='wrong-definition')f.capacity.definition.cpu='1024';
 if(defect==='stale-census')f.census.at=new Date(now-300001).toISOString();
 expect(()=>run(f)).toThrow();
});
