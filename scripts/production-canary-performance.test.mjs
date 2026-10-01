import {describe,it,expect} from 'vitest';
import {verifyCanaryPerformance} from './lib/production-canary-performance.mjs';

function cohort(start,scale=1){
  return {version:1,workloadHash:'a'.repeat(64),samplesPerKind:100,warmupsPerKind:5,concurrency:1,cadenceMs:250,
    samples:Array.from({length:200},(_,i)=>({kind:i%2?'write_ack':'read',index:Math.floor(i/2),ok:true,
      startedMs:start+i*250,finishedMs:start+i*250+Math.ceil((i%2?120:100)*scale),latencyMs:(i%2?120:100)*scale}))};
}
function fixture(scale=1.05){
  const start=Date.now()-200000;
  return {baseline:cohort(start),loaded:cohort(start+100000,scale),
    activity:[{kind:'executor',startedMs:start+90000,stoppedMs:start+150000,exitCode:0}],
    receipts:{firstCommittedMs:start+110000,lastCommittedMs:start+125000,committedMs:[start+110000,start+125000]}};
}
describe('foreground canary performance evidence',()=>{
  it('compares unrounded read and write-ack p95 from equal validated cohorts under actual activity',()=>{
    const result=verifyCanaryPerformance(fixture(1.0999));
    expect(result.read.baselineP95Ms).toBe(100);expect(result.read.loadedP95Ms).toBe(109.99000000000001);
    expect(result.write_ack.loadedP95Ms).toBeCloseTo(131.988);expect(result.read.samples).toBe(100);
  });
  it.each(['slow','errors','missing','workload','concurrency','no-activity','no-commit','partial-activity'])('rejects %s evidence without changing denominators',kind=>{
    const f=fixture();
    if(kind==='slow')f.loaded=cohort(f.loaded.samples[0].startedMs,1.1001);
    if(kind==='errors')f.loaded.samples[0].ok=false;
    if(kind==='missing')f.loaded.samples.pop();
    if(kind==='workload')f.loaded.workloadHash='b'.repeat(64);
    if(kind==='concurrency')f.loaded.concurrency=2;
    if(kind==='no-activity')f.activity=[];
    if(kind==='no-commit')f.receipts.firstCommittedMs=f.receipts.lastCommittedMs=f.loaded.samples.at(-1).finishedMs+10000;
    if(kind==='partial-activity')f.activity[0].stoppedMs=f.loaded.samples[20].startedMs;
    expect(()=>verifyCanaryPerformance(f)).toThrow('CanaryPerformanceNotVerified');
  });
  it('rejects a cohort entirely between two commits even when the overall commit range overlaps',()=>{
    const f=fixture(),begin=f.loaded.samples[0].startedMs,end=f.loaded.samples.at(-1).finishedMs;
    f.receipts={firstCommittedMs:begin-1000,lastCommittedMs:end+1000,committedMs:[begin-1000,end+1000]};
    expect(()=>verifyCanaryPerformance(f)).toThrow('CanaryPerformanceNotVerified');
  });
});
