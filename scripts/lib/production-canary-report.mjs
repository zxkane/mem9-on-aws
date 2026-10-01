import {gzipSync,gunzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {canaryEvidenceHash} from './production-canary-verification.mjs';
import {verifyCanaryPerformance} from './production-canary-performance.mjs';

const fail=()=>{throw Error('ProductionCanaryReportInvalid');};
export const canaryReportDigest=encoded=>createHash('sha256').update(encoded).digest('hex');
export function canaryReportFragments(encoded){
  decodeCanaryReport(encoded);
  return Array.from({length:4},(_,index)=>encoded.slice(index*3500,(index+1)*3500)||'-');
}
export function readCanaryReportFragments(env,expectedHash){
  if(!/^[a-f0-9]{64}$/.test(expectedHash??''))fail();
  const fragments=Array.from({length:4},(_,index)=>env['MEM9_CANARY_REPORT_'+index]);
  if(fragments.some(value=>typeof value!=='string'||!value.length||value.length>3500))fail();
  const encoded=fragments.map(value=>value==='-'?'':value).join('');
  if(canaryReportDigest(encoded)!==expectedHash)fail();
  decodeCanaryReport(encoded);return encoded;
}
export function encodeBenchmarkRefs(refs){
  return gzipSync(Buffer.from(JSON.stringify(refs)),{level:9}).toString('base64');
}
export function decodeBenchmarkRefs(encoded){
  if(typeof encoded!=='string'||encoded.length>12000||!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded))fail();
  let refs;try{refs=JSON.parse(gunzipSync(Buffer.from(encoded,'base64'),{maxOutputLength:50000}).toString('utf8'));}catch{fail();}
  if(!Array.isArray(refs)||!refs.length||refs.length>50||new Set(refs.map(ref=>ref.id)).size!==refs.length||refs.some(ref=>
    Object.keys(ref).sort().join()!==['id','version','agentId','contentHash'].sort().join()||typeof ref.id!=='string'||!ref.id||ref.id.length>128||
    ref.version!==1||!/^mem9-canary-[a-f0-9]{32}$/.test(ref.agentId??'')||!/^[a-f0-9]{64}$/.test(ref.contentHash??'')))fail();
  return refs;
}
const pack=cohort=>({version:cohort.version,workloadHash:cohort.workloadHash,samplesPerKind:cohort.samplesPerKind,
  warmupsPerKind:cohort.warmupsPerKind,concurrency:cohort.concurrency,cadenceMs:cohort.cadenceMs,
  origin:cohort.samples[0].startedMs,timing:cohort.samples.map(sample=>[sample.startedMs-cohort.samples[0].startedMs,sample.finishedMs-cohort.samples[0].startedMs,sample.latencyMs])});
const unpack=cohort=>{
  if(!cohort||!Number.isSafeInteger(cohort.origin)||!Array.isArray(cohort.timing)||cohort.timing.length>1000||
    cohort.timing.some(value=>!Array.isArray(value)||value.length!==3||!value.every(Number.isFinite)))fail();
  const {origin,timing,...metadata}=cohort;
  return {...metadata,samples:timing.map(([start,end,latencyMs],i)=>({kind:i%2?'write_ack':'read',index:Math.floor(i/2),ok:true,
    startedMs:origin+start,finishedMs:origin+end,latencyMs}))};
};

export function encodeCanaryReport(report){
  // Encoding is only for complete, already-validated successful cohorts. No
  // failed sample or caller-supplied response body can disappear in packing.
  verifyCanaryPerformance(report);
  const packed={version:report.version,verificationHash:report.verificationHash,baseline:pack(report.baseline),loaded:pack(report.loaded),
    activity:report.activity,replays:report.replays,receipts:report.receipts};
  return gzipSync(Buffer.from(JSON.stringify(packed)),{level:9}).toString('base64');
}

export function decodeCanaryReport(encoded){
  if(typeof encoded!=='string'||encoded.length>12000||!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded))fail();
  let value;try{value=JSON.parse(gunzipSync(Buffer.from(encoded,'base64'),{maxOutputLength:200000}).toString('utf8'));}catch{fail();}
  if(!value||Object.keys(value).sort().join()!==['version','verificationHash','baseline','loaded','activity','replays','receipts'].sort().join())fail();
  return {...value,baseline:unpack(value.baseline),loaded:unpack(value.loaded)};
}

export function verifyCanaryReport(report,proof,receiptWindow,{now=Date.now()}={}){
  if(report?.version!==1||report.verificationHash!==canaryEvidenceHash(proof)||!isDeepStrictEqual(report.receipts,receiptWindow)||
    !Array.isArray(report.replays)||report.replays.length!==2||new Set(report.replays.map(replay=>replay.invocation)).size!==2)fail();
  if(now-(report.loaded?.samples?.at(-1)?.finishedMs??0)>3600000)fail();
  if(typeof proof.workerImage!=='string'||!/@sha256:[a-f0-9]{64}$/.test(proof.workerImage)||
    !Array.isArray(report.activity)||report.activity.some(task=>task.image!==proof.workerImage||!/^sha256:[a-f0-9]{64}$/.test(task.imageDigest??'')))fail();
  const executorDigests=new Set(report.activity.filter(task=>task.kind==='executor').map(task=>task.imageDigest));
  if(executorDigests.size!==1)fail();
  let previous=report.loaded?.samples?.at(-1)?.finishedMs;
  for(const [index,replay] of report.replays.entries()){
    if(replay.image!==proof.workerImage||!executorDigests.has(replay.imageDigest)||
      replay.wave!==(index?'repeat-b':'repeat-a')||!/^[a-f0-9]{32}$/.test(replay.invocation??'')||
      !/^[a-f0-9]{64}$/.test(replay.taskHash??'')||replay.matched!==proof.receipts||replay.resultHash!==proof.replayResultHash||
      replay.beforeHash!==proof.conservationHash||replay.afterHash!==proof.conservationHash||
      !Number.isSafeInteger(replay.startedMs)||!Number.isSafeInteger(replay.finishedMs)||replay.startedMs<previous||replay.finishedMs<replay.startedMs||replay.finishedMs>now+5000)fail();
    previous=replay.finishedMs;
  }
  return {performance:verifyCanaryPerformance(report),reportHash:canaryEvidenceHash(report),replayCount:2};
}
