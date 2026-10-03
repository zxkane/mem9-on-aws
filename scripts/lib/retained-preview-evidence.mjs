import {createHash} from 'node:crypto';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
const fail=()=>{throw Error('RetainedPreviewEvidenceInvalid');};
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join();
const hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
export function extractRetainedPreviewEvidence(log){
  const records=[];
  for(const line of log.split(/\r?\n/)){
    const start=line.indexOf('{"event":"retained_data_preview"');if(start<0)continue;
    let record;try{record=JSON.parse(line.slice(start));}catch{fail();}
    if(record.phase==='complete')records.push(record.evidence);
  }
  if(records.length!==1)fail();return records[0];
}
export function verifyRetainedPreviewEvidence(value,expected,{now=Date.now()}={}){
  const keys=['version','kind','stage','runId','runAttempt','controlRevision','controlSourceTree','dataRunId','dataRevision','dataSourceTree','controlTag','dataTag','accountHash','region',
    'runtimeNonceHash','schemaDigest','operatorDigest','coordinatorDigest','dataReleaseHash','buildInputsHash','images','bootstrap','workers','checks','completedMs'];
  if(!exact(value,keys)||value.version!==1||value.kind!=='retained-data-preview'||!/^pr-[1-9][0-9]*$/.test(value.stage??'')||
    !/^[1-9][0-9]*$/.test(value.runId??'')||!Number.isSafeInteger(value.runAttempt)||value.runAttempt<1||!/^[1-9][0-9]*$/.test(value.dataRunId??'')||
    !['controlRevision','controlSourceTree','dataRevision','dataSourceTree'].every(k=>hex(value[k],40))||value.dataSourceTree===value.controlSourceTree||
    !/^pr-[a-f0-9]{7}$/.test(value.controlTag??'')||value.dataTag!=='pr-'+value.dataRevision.slice(0,7)||value.controlTag===value.dataTag||
    !['accountHash','runtimeNonceHash','schemaDigest','operatorDigest','coordinatorDigest','dataReleaseHash','buildInputsHash'].every(k=>hex(value[k]))||
    !Number.isSafeInteger(value.completedMs)||value.completedMs>now||now-value.completedMs>86400000)fail();
  for(const [key,source]of Object.entries({stage:'stage',runId:'runId',runAttempt:'runAttempt',controlRevision:'commit',controlSourceTree:'sourceTree',region:'region',schemaDigest:'schemaDigest',operatorDigest:'operatorDigest',coordinatorDigest:'coordinatorDigest'}))if(value[key]!==expected[source])fail();
  if(!/^[0-9]{12}$/.test(expected.account??'')||value.accountHash!==createHash('sha256').update(expected.account).digest('hex'))fail();
  const components=['llm-proxy','mnemo-server','qwen3-embed'];if(!exact(value.images,components)||!exact(value.workers,['planner','executor']))fail();
  for(const image of [...Object.values(value.images),value.bootstrap])if(!exact(image,['rootDigest','arm64Digest'])||
    !/^sha256:[a-f0-9]{64}$/.test(image.rootDigest??'')||!/^sha256:[a-f0-9]{64}$/.test(image.arm64Digest??'')||image.rootDigest===image.arm64Digest)fail();
  if(!Object.values(value.workers).every(v=>hex(v)))fail();
  const checks=['selectedData','currentControl','runtimeBootstrap','scheduler','workerData','mcp','oauth'];
  if(!exact(value.checks,checks)||checks.some(key=>value.checks[key]!==true))fail();
  return {hash:hash(value),runId:value.runId,runAttempt:value.runAttempt,dataRunId:value.dataRunId,dataSourceTree:value.dataSourceTree};
}
