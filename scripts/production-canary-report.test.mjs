import {describe,it,expect} from 'vitest';
import {encodeCanaryReport,decodeCanaryReport,verifyCanaryReport,canaryReportFragments,canaryReportDigest,readCanaryReportFragments} from './lib/production-canary-report.mjs';
import {productionConsolidationOverrides} from './run-production-consolidation.mjs';
import {canaryEvidenceHash} from './lib/production-canary-verification.mjs';
import {gzipSync,gunzipSync} from 'node:zlib';

function fixture(){
  const epoch=Date.now()-1000000;
  const sample=start=>({version:1,workloadHash:'a'.repeat(64),samplesPerKind:100,warmupsPerKind:5,concurrency:1,cadenceMs:250,
    samples:Array.from({length:200},(_,i)=>({kind:i%2?'write_ack':'read',index:Math.floor(i/2),ok:true,
      startedMs:start+i*250,finishedMs:start+i*250+101,latencyMs:100.123456789}))});
  const proof={generation:'b'.repeat(64),validationId:'c'.repeat(32),receipts:5,replayResultHash:'d'.repeat(64),conservationHash:'e'.repeat(64)};
  proof.workerImage='example/worker@sha256:'+'e'.repeat(64);const imageDigest='sha256:'+'f'.repeat(64);
  const receipts={firstCommittedMs:epoch+110000,lastCommittedMs:epoch+125000,committedMs:[epoch+110000,epoch+125000]};
  const report={version:1,verificationHash:canaryEvidenceHash(proof),baseline:sample(epoch+1000),loaded:sample(epoch+100000),receipts,
    activity:[{kind:'executor',startedMs:epoch+90000,stoppedMs:epoch+160000,exitCode:0,image:proof.workerImage,imageDigest}],
    replays:[0,1].map(i=>({wave:i?'repeat-b':'repeat-a',invocation:String(i+1).repeat(32),taskHash:String(i+1).repeat(64),
      matched:5,resultHash:proof.replayResultHash,beforeHash:proof.conservationHash,afterHash:proof.conservationHash,startedMs:epoch+200000+i*10000,finishedMs:epoch+201000+i*10000,image:proof.workerImage,imageDigest}))};
  return {proof,receipts,report};
}
function largeTimingFixture(){
  const f=fixture();let seed=42;
  const random=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed/4294967296;};
  const cohort=origin=>{
    let at=origin;const samples=[];
    for(let i=0;i<300;i++){
      const latencyMs=500+random()*800,startedMs=at,finishedMs=at+Math.round(latencyMs)+(i%3)-1;
      samples.push({kind:i%2?'write_ack':'read',index:Math.floor(i/2),ok:true,startedMs,finishedMs,latencyMs});at=finishedMs;
    }
    return {...f.report.baseline,samplesPerKind:150,samples};
  };
  f.report.baseline=cohort(Date.now()-1000000);
  f.report.loaded=cohort(f.report.baseline.samples.at(-1).finishedMs+1000);
  const first=f.report.loaded.samples[0].startedMs,last=f.report.loaded.samples.at(-1).finishedMs;
  const committedMs=[60,100,140,180,220].map(i=>f.report.loaded.samples[i].startedMs);
  f.receipts={firstCommittedMs:committedMs[0],lastCommittedMs:committedMs.at(-1),committedMs};f.report.receipts=f.receipts;
  f.report.activity[0]={...f.report.activity[0],startedMs:first-1000,stoppedMs:last+1000};
  f.report.replays=f.report.replays.map((r,i)=>({...r,startedMs:last+2000+i*10000,finishedMs:last+3000+i*10000}));
  return f;
}
describe('bound production canary report',()=>{
  it('preserves complete full-precision N150 cohorts within unchanged report and fragment limits',()=>{
    const f=largeTimingFixture();
    for(const c of [f.report.baseline,f.report.loaded])expect(c.samples.at(-1).finishedMs-c.samples[0].startedMs).toBeLessThan(300000);
    const encoded=encodeCanaryReport(f.report);
    expect(encoded.length).toBeLessThanOrEqual(12000);
    const fragments=canaryReportFragments(encoded);
    expect(fragments).toHaveLength(4);expect(fragments.every(p=>p.length<=3500)).toBe(true);
    const env=Object.fromEntries(fragments.map((p,i)=>['MEM9_CANARY_REPORT_'+i,p]));
    const decoded=decodeCanaryReport(readCanaryReportFragments(env,canaryReportDigest(encoded)));
    expect(decoded).toEqual(f.report);
    expect(verifyCanaryReport(decoded,f.proof,f.receipts).replayCount).toBe(2);
  });
  it('rejects invalid compact timing markers, gaps, residuals and integer overflow',()=>{
    const f=largeTimingFixture(),encoded=encodeCanaryReport(f.report);
    const packed=JSON.parse(gunzipSync(Buffer.from(encoded,'base64')).toString('utf8'));
    expect(packed.baseline.encoding).toBe('delta-wall-v1');
    expect(packed.baseline.timing.some(([,residual])=>residual<0)).toBe(true);
    expect(packed.baseline.timing.some(([,residual])=>residual>0)).toBe(true);
    for(const mutate of [
      p=>{p.baseline.encoding='unknown';},
      p=>{p.baseline.timing[0][0]=1;},
      p=>{p.baseline.timing[1][0]=-1;},
      p=>{p.baseline.timing[1][1]=99;},
      p=>{p.baseline.origin=Number.MAX_SAFE_INTEGER;},
    ]){
      const changed=structuredClone(packed);mutate(changed);
      const body=gzipSync(Buffer.from(JSON.stringify(changed)),{level:9}).toString('base64');
      expect(()=>decodeCanaryReport(body)).toThrow('ProductionCanaryReportInvalid');
    }
  });
  it('keeps realistic unrounded timing entropy outside the complete ECS request envelope',()=>{
    const f=fixture();let seed=73419;
    const random=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed/4294967296;};
    for(const c of [f.report.baseline,f.report.loaded])for(const sample of c.samples){
      sample.startedMs+=Math.floor(random()*15);sample.latencyMs=100+random()*9;sample.finishedMs=sample.startedMs+Math.ceil(sample.latencyMs);
    }
    const encoded=encodeCanaryReport(f.report),fragments=canaryReportFragments(encoded),hash=canaryReportDigest(encoded);
    const env=Object.fromEntries(fragments.map((part,index)=>['MEM9_CANARY_REPORT_'+index,part]));
    expect(encoded.length).toBeGreaterThan(6000);expect(fragments.every(part=>part.length<=3500)).toBe(true);
    expect(decodeCanaryReport(readCanaryReportFragments(env,hash))).toEqual(f.report);
    const request={operation:'promote',invocation:'a'.repeat(32),deadline:Date.now()+60000,dailyRows:6000,basisPoints:5000,canaryReportHash:hash,
      acceptance:{version:1,sourceTree:'b'.repeat(40),coordinatorDigest:'c'.repeat(64),catalogEvidence:'synthetic-'.repeat(440)}};
    const wire=JSON.stringify(productionConsolidationOverrides('PromoteMem9Bootstrap',request));
    expect(Buffer.byteLength(wire)).toBeLessThan(8192);expect(wire).not.toContain(encoded);
    expect(()=>readCanaryReportFragments({...env,MEM9_CANARY_REPORT_1:'-'},hash)).toThrow();
    expect(()=>readCanaryReportFragments(env,'f'.repeat(64))).toThrow();
  });
  it('compresses exact unrounded timing data and verifies both cached Scheduler replays',()=>{
    const f=fixture(),encoded=encodeCanaryReport(f.report),decoded=decodeCanaryReport(encoded);
    expect(decoded).toEqual(f.report);expect(encoded.length).toBeLessThan(4000);
    expect(verifyCanaryReport(decoded,f.proof,f.receipts).replayCount).toBe(2);
  });
  it('rejects different receipts, counter changes, failed samples and malformed compression',()=>{
    const f=fixture();f.report.replays[1].afterHash='f'.repeat(64);
    expect(()=>verifyCanaryReport(f.report,f.proof,f.receipts)).toThrow('ProductionCanaryReportInvalid');
    f.report.loaded.samples[0].ok=false;expect(()=>encodeCanaryReport(f.report)).toThrow();
    expect(()=>decodeCanaryReport('invalid')).toThrow();
  });
});
