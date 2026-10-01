import {describe,it,expect} from 'vitest';
import {encodeCanaryReport,decodeCanaryReport,verifyCanaryReport,canaryReportFragments,canaryReportDigest,readCanaryReportFragments} from './lib/production-canary-report.mjs';
import {productionConsolidationOverrides} from './run-production-consolidation.mjs';
import {canaryEvidenceHash} from './lib/production-canary-verification.mjs';

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
describe('bound production canary report',()=>{
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
