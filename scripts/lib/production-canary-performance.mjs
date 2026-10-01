const fail=()=>{throw Error('CanaryPerformanceNotVerified');};
const time=value=>Number.isSafeInteger(value)&&value>0;
const p95=values=>[...values].sort((a,b)=>a-b)[Math.ceil(values.length*0.95)-1];

function cohort(value){
  if(value?.version!==1||typeof value.workloadHash!=='string'||!/^[a-f0-9]{64}$/.test(value.workloadHash)||
    !Number.isInteger(value.samplesPerKind)||value.samplesPerKind<100||value.samplesPerKind>500||
    value.warmupsPerKind!==5||value.concurrency!==1||value.cadenceMs!==250||!Array.isArray(value.samples)||value.samples.length!==value.samplesPerKind*2)fail();
  let previous=0;
  for(const [index,sample] of value.samples.entries()){
    if(sample.kind!==(index%2?'write_ack':'read')||sample.index!==Math.floor(index/2)||sample.ok!==true||
      !time(sample.startedMs)||!time(sample.finishedMs)||sample.startedMs<previous||sample.finishedMs<sample.startedMs||
      !Number.isFinite(sample.latencyMs)||sample.latencyMs<=0||sample.latencyMs>30000||
      Math.abs(sample.finishedMs-sample.startedMs-sample.latencyMs)>2)fail();
    previous=sample.finishedMs;
  }
  return value;
}

export function verifyCanaryPerformance({baseline,loaded,activity,receipts}){
  cohort(baseline);cohort(loaded);
  if(baseline.workloadHash!==loaded.workloadHash||baseline.samplesPerKind!==loaded.samplesPerKind||
    baseline.samples.at(-1).finishedMs>=loaded.samples[0].startedMs||
    loaded.samples[0].startedMs-baseline.samples.at(-1).finishedMs>3600000||
    !Array.isArray(activity)||!activity.length||activity.length>100||
    activity.some(task=>!['planner','executor'].includes(task.kind)||task.exitCode!==0||!time(task.startedMs)||!time(task.stoppedMs)||task.stoppedMs<task.startedMs)||
    !activity.some(task=>task.kind==='executor')||!time(receipts?.firstCommittedMs)||!time(receipts.lastCommittedMs)||
    receipts.lastCommittedMs<receipts.firstCommittedMs||!Array.isArray(receipts.committedMs)||!receipts.committedMs.length||receipts.committedMs.length>20||
    receipts.committedMs.some(value=>!time(value))||Math.min(...receipts.committedMs)!==receipts.firstCommittedMs||Math.max(...receipts.committedMs)!==receipts.lastCommittedMs)fail();
  // Every measured loaded request must occur during observed worker activity.
  // Also require actual canary commits during each class's sampling window.
  if(loaded.samples.some(sample=>!activity.some(task=>sample.startedMs>=task.startedMs&&sample.finishedMs<=task.stoppedMs)))fail();
  const result={};
  for(const kind of ['read','write_ack']){
    const before=baseline.samples.filter(sample=>sample.kind===kind),after=loaded.samples.filter(sample=>sample.kind===kind);
    if(!receipts.committedMs.some(value=>value>=after[0].startedMs&&value<=after.at(-1).finishedMs))fail();
    const baselineP95Ms=p95(before.map(sample=>sample.latencyMs)),loadedP95Ms=p95(after.map(sample=>sample.latencyMs));
    if(loadedP95Ms>baselineP95Ms*1.1)fail();
    result[kind]={samples:before.length,baselineP95Ms,loadedP95Ms,ratio:loadedP95Ms/baselineP95Ms};
  }
  return result;
}
