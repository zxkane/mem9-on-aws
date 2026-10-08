import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {inspectContinuationReceiptSet,verifyContinuationReceiptSet,verifyContinuationCommitWindow} from './production-canary-continuation-proof.mjs';
import {normalizeCanaryTask} from './production-canary-material.mjs';
import {verifyCanaryReport} from './production-canary-report.mjs';
import {inspectCanaryTransitionCertificate} from './production-canary-transition.mjs';
import {inspectImageTransitionCertificate} from './production-image-transition.mjs';
import {verifyCurrentCanaryCapacity} from './production-current-capacity.mjs';

const fail=()=>{throw Error('ProductionBudgetCalibrationIndeterminate');};
const integer=(v,min=0)=>Number.isSafeInteger(v)&&v>=min;

/** Reuse the whole original successful apply batch only through an exact
 * data/material compatibility certificate. Performance and census stay fresh.
 */
export function calibrateProductionContinuation(state,original,capacity,census,{attemptId,compatibility,controlRevision,dataRevision,dailyRows=1000,basisPoints=5000,now=Date.now()}){
  if(compatibility?.version===4)return calibrateCurrentImage(state,original,capacity,census,{attemptId,compatibility,controlRevision,dataRevision,dailyRows,basisPoints,now});
  const transition=compatibility?.version===3?inspectCanaryTransitionCertificate(compatibility):null;
  const old=inspectContinuationReceiptSet(original),current=state?.verified,context={attemptId,compatibility};
  verifyContinuationReceiptSet(original,current,context);
  if(state.phase!=='calibrating'||state.benchmarkRemaining!==0||state.report?.verificationHash!==hash(current.verification)||
    state.report.baseline?.samplesPerKind!==150||state.report.loaded?.samplesPerKind!==150||
    !/^[a-f0-9]{40}$/.test(controlRevision??'')||!integer(dailyRows,21)||dailyRows>50000||!integer(basisPoints,1)||basisPoints>5000)fail();
  verifyCanaryReport(state.report,current.verification,current.receiptWindow,{now});
  verifyContinuationCommitWindow(original,current,state.report.loaded,context);
  if(old.actions.length<2||old.actions.some(a=>a.result.changed_rows!==2))fail();
  for(const kind of ['worker','mnemo-server','qwen3-embed','llm-proxy']){
    const image=compatibility.images?.[kind];if(!image||image.previousChild!==image.currentChild||!/^sha256:[a-f0-9]{64}$/.test(image.currentChild??''))fail();
  }
  for(const kind of transition?['planner','executor','network','credentials']:['planner','executor','backend','network','authority','credentials']){
    const material=compatibility.material?.[kind];if(!material||material.previous!==material.current||!/^[a-f0-9]{64}$/.test(material.current??''))fail();
  }
  const d=capacity?.delivery,task=capacity?.task,definition=capacity?.definition;
  const image=old.proof.workerImage.match(/^([0-9]{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com\/mem9-on-aws\/llm-proxy@(sha256:[a-f0-9]{64})$/);
  if(!image||!/^([a-f0-9]{40})$/.test(capacity?.sourceRevision??'')||old.proof.sourceTag!=='mem9-'+capacity.sourceRevision.slice(0,7)||
    d?.kind!=='executor'||d.wave!=='apply'||d.exitCode!==0||d.image!==old.proof.workerImage||
    !integer(d.startedMs,1)||!integer(d.stoppedMs,d.startedMs)||d.startedMs>old.times[0]||d.stoppedMs<old.times.at(-1)||d.stoppedMs>now||
    task?.taskArn!==d.taskArn||task.taskDefinitionArn!==d.taskDefinitionArn||definition?.taskDefinitionArn!==d.taskDefinitionArn||
    task.lastStatus!=='STOPPED'||task.launchType!=='FARGATE'||task.cpu!==definition.cpu||task.memory!==definition.memory||task.enableExecuteCommand===true||
    task.attributes?.filter(a=>a.name==='ecs.cpu-architecture').length!==1||task.attributes.find(a=>a.name==='ecs.cpu-architecture').value!=='arm64'||
    !Number.isSafeInteger(Date.parse(task.startedAt))||!Number.isSafeInteger(Date.parse(task.stoppedAt))||d.startedMs<Date.parse(task.startedAt)-5000||d.stoppedMs>Date.parse(task.stoppedAt)+5000||
    task.containers?.length!==1||task.containers[0].exitCode!==0||
    task.containers[0].image!==d.image||task.containers[0].imageDigest!==d.imageDigest||
    ![compatibility.images.worker.previousRoot,compatibility.images.worker.previousChild].includes(d.imageDigest)||
    d.record?.kind!=='executor'||d.record.stage!=='prod'||d.record.invocation!==d.invocation||d.record.failedSlices!==0||!integer(d.record.slices,1)||
    d.record.changedRows!==old.proof.changedRows||d.record.startedMs!==d.startedMs||d.record.finishedMs!==d.stoppedMs)fail();
  const catalog=new Map([[d.image,{registryId:image[1],repositoryName:'mem9-on-aws/llm-proxy',rootDigest:image[3],arm64Digest:compatibility.images.worker.previousChild}]]);
  if(hash(normalizeCanaryTask(definition,{account:image[1],region:image[2],images:catalog}))!==compatibility.material.executor.previous)fail();
  const overrides=task.overrides?.containerOverrides;
  if(overrides?.length!==1||overrides[0].name!==definition.containerDefinitions[0].name||
    Object.keys(overrides[0]).sort().join()!==['environment','name'].join()||
    Object.keys(task.overrides).some(k=>!['containerOverrides','taskRoleArn','executionRoleArn','inferenceAcceleratorOverrides'].includes(k))||
    task.overrides.inferenceAcceleratorOverrides?.length||
    ['taskRoleArn','executionRoleArn'].some(k=>task.overrides[k]&&task.overrides[k]!==definition[k]))fail();
  const env=overrides[0].environment;
  if(!Array.isArray(env)||env.length!==3||new Set(env.map(e=>e.name)).size!==3)fail();
  const values=Object.fromEntries(env.map(e=>[e.name,e.value]));
  if(values.MEM9_WORKER_GENERATION!==old.proof.generation||values.MEM9_WORKER_INVOCATION!==d.invocation||!/^[a-f0-9]{32}$/.test(values.MEM9_WORKER_ADMISSION??''))fail();
  const at=Date.parse(census?.at),bound=census?.exactCandidateUpperBound,setup=census?.workerSetup,proof=current.verification;
  const targetsHash=hash([...proof.targets].sort());
  if(census?.event!=='backlog_census'||!Number.isSafeInteger(at)||at>now||now-at>300000||census.targetsHash!==targetsHash||census.targetNamespaces!==proof.targets.length||
    census.controls?.enabled!==false||!integer(census.controls.retired_roles,1)||census.controls.execution_receipts!==proof.receipts||
    setup?.generation!==proof.generation||setup.validationId!==proof.validationId||setup.targetsHash!==targetsHash||
    !bound||!['groups','rows','surplus','largest_group'].every(k=>integer(bound[k]))||bound.rows!==bound.groups*2||bound.rows-bound.groups!==bound.surplus||bound.largest_group!==(bound.groups?2:0))fail();
  const spanSeconds=(old.times.at(-1)-old.times[0])/1000,steadyChangedRows=old.actions.slice(1).reduce((sum,a)=>sum+a.result.changed_rows,0);
  const estimatedDailyCapacity=Math.floor(steadyChangedRows/spanSeconds*86400*0.8*0.5),remainingCostUpperBound=bound.surplus*2;
  if(!(spanSeconds>0)||!integer(estimatedDailyCapacity,1)||dailyRows>estimatedDailyCapacity||remainingCostUpperBound>3*Math.min(dailyRows,estimatedDailyCapacity))fail();
  return {version:1,scope:'exact-lossless-pairs',controlRevision,dataSourceTag:proof.sourceTag,verificationHash:hash(proof),generation:proof.generation,validationId:proof.validationId,targetsHash,
    capacityEvidenceHash:hash({original,capacity,compatibility}),censusHash:hash(census),capacityAgeMs:now-d.stoppedMs,capacityReceipts:old.actions.length,
    spanSeconds,steadyChangedRows,dutyCycle:0.8,headroom:0.5,estimatedDailyCapacity,dailyRows,basisPoints,remainingCostUpperBound,
    estimatedDrainHours:remainingCostUpperBound/Math.min(dailyRows,estimatedDailyCapacity)*24,checkedAt:now};
}

/** An image-security upgrade cannot reuse historical throughput. Its complete
 * single apply delta supplies the rate; the historical set remains immutable. */
function calibrateCurrentImage(state,original,capacity,census,{attemptId,compatibility,controlRevision,dataRevision,dailyRows,basisPoints,now}){
  inspectImageTransitionCertificate(compatibility);
  const old=inspectContinuationReceiptSet(original),current=state?.verified,context={attemptId,compatibility};
  const extension=verifyContinuationReceiptSet(original,current,context),{newActions,newTimes}=extension;
  if(state.phase!=='calibrating'||state.benchmarkRemaining!==0||state.executorRequested!==true||
    state.report?.verificationHash!==hash(current.verification)||state.report.baseline?.samplesPerKind!==150||state.report.loaded?.samplesPerKind!==150||
    !/^[a-f0-9]{40}$/.test(controlRevision??'')||!/^[a-f0-9]{40}$/.test(dataRevision??'')||
    !integer(dailyRows,21)||dailyRows>50000||!integer(basisPoints,1)||basisPoints>5000||
    newActions.length<2||newActions.some(a=>a.result.changed_rows!==2))fail();
  verifyCanaryReport(state.report,current.verification,current.receiptWindow,{now});
  verifyContinuationCommitWindow(original,current,state.report.loaded,context);
  const newChangedRows=newActions.reduce((sum,a)=>sum+a.result.changed_rows,0),remainingAllowance=20-old.proof.changedRows;
  if(newChangedRows>remainingAllowance||current.verification.changedRows!==old.proof.changedRows+newChangedRows)fail();
  if(!Array.isArray(state.deliveries))fail();
  const applies=state.deliveries.filter(d=>d.kind==='executor'&&d.wave==='apply');if(applies.length!==1)fail();
  if(!Array.isArray(state.launches))fail();const launches=state.launches.filter(d=>d.kind==='executor'&&d.wave==='apply');if(launches.length!==1)fail();
  const {delivery:d,task}=verifyCurrentCanaryCapacity(capacity,{delivery:applies[0],launch:launches[0].journal,attemptId,dataRevision,compatibility,now});
  if(d.record.changedRows!==newChangedRows||newTimes.some(t=>t<d.startedMs||t>d.stoppedMs||t<Date.parse(task.startedAt)||t>Date.parse(task.stoppedAt)))fail();
  const activity=state.report.activity.filter(a=>a.kind==='executor');
  if(activity.length!==1||['startedMs','stoppedMs','exitCode','image','imageDigest'].some(k=>activity[0][k]!==d[k]))fail();
  const proof=current.verification,targetsHash=hash([...proof.targets].sort()),at=Date.parse(census?.at),bound=census?.exactCandidateUpperBound,setup=census?.workerSetup;
  if(census?.event!=='backlog_census'||!Number.isSafeInteger(at)||at>now||now-at>300000||census.targetsHash!==targetsHash||census.targetNamespaces!==proof.targets.length||
    census.controls?.enabled!==false||!integer(census.controls.retired_roles,1)||census.controls.execution_receipts!==proof.receipts||
    setup?.generation!==proof.generation||setup.validationId!==proof.validationId||setup.targetsHash!==targetsHash||
    !bound||!['groups','rows','surplus','largest_group'].every(k=>integer(bound[k]))||bound.rows!==bound.groups*2||bound.rows-bound.groups!==bound.surplus||bound.largest_group!==(bound.groups?2:0))fail();
  const spanSeconds=(newTimes.at(-1)-newTimes[0])/1000,steadyChangedRows=newActions.slice(1).reduce((sum,a)=>sum+a.result.changed_rows,0);
  const estimatedDailyCapacity=Math.floor(steadyChangedRows/spanSeconds*86400*0.8*0.5),remainingCostUpperBound=bound.surplus*2;
  if(!(spanSeconds>0)||!integer(estimatedDailyCapacity,1)||dailyRows>estimatedDailyCapacity||remainingCostUpperBound>3*Math.min(dailyRows,estimatedDailyCapacity))fail();
  return {version:2,scope:'exact-lossless-pairs',capacitySource:'current-apply',attemptId,controlRevision,dataRevision,dataSourceTag:proof.sourceTag,
    dataReleaseHash:compatibility.dataReleaseHash,verificationHash:hash(proof),generation:proof.generation,validationId:proof.validationId,targetsHash,
    capacityEvidenceHash:hash({original,current,capacity,compatibility,newActions,newTimes}),censusHash:hash(census),capacityAgeMs:now-d.stoppedMs,
    capacityReceipts:newActions.length,existingSpent:old.proof.changedRows,remainingAllowance,newChangedRows,spanSeconds,steadyChangedRows,
    dutyCycle:0.8,headroom:0.5,estimatedDailyCapacity,dailyRows,basisPoints,remainingCostUpperBound,
    estimatedDrainHours:remainingCostUpperBound/Math.min(dailyRows,estimatedDailyCapacity)*24,checkedAt:now};
}
