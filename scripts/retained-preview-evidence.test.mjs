import {it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {extractRetainedPreviewEvidence,verifyRetainedPreviewEvidence} from './lib/retained-preview-evidence.mjs';
const h=c=>c.repeat(64),now=1800000000000;
function fixture(){
  const expected={stage:'pr-7',runId:'42',runAttempt:1,commit:'a'.repeat(40),sourceTree:'b'.repeat(40),account:'123456789012',region:'ap-northeast-1',schemaDigest:h('1'),operatorDigest:h('2'),coordinatorDigest:h('3')};
  const images=Object.fromEntries(['llm-proxy','mnemo-server','qwen3-embed'].map(name=>[name,{rootDigest:'sha256:'+h('4'),arm64Digest:'sha256:'+h('5')}]));
  const value={version:1,kind:'retained-data-preview',stage:expected.stage,runId:expected.runId,runAttempt:1,controlRevision:expected.commit,controlSourceTree:expected.sourceTree,dataRunId:'40',dataRevision:'c'.repeat(40),dataSourceTree:'d'.repeat(40),
    controlTag:'pr-aaaaaaa',dataTag:'pr-ccccccc',accountHash:createHash('sha256').update(expected.account).digest('hex'),region:expected.region,runtimeNonceHash:h('6'),schemaDigest:expected.schemaDigest,operatorDigest:expected.operatorDigest,coordinatorDigest:expected.coordinatorDigest,
    dataReleaseHash:h('7'),buildInputsHash:h('8'),images,bootstrap:{rootDigest:'sha256:'+h('9'),arm64Digest:'sha256:'+h('a')},workers:{planner:h('b'),executor:h('c')},
    checks:Object.fromEntries(['selectedData','currentControl','runtimeBootstrap','scheduler','workerData','mcp','oauth'].map(k=>[k,true])),completedMs:now-1000};
  return {expected,value};
}
it('binds the distinct retained-data/current-control result to its actual workflow source',()=>{
  const f=fixture();expect(verifyRetainedPreviewEvidence(f.value,f.expected,{now}).runId).toBe('42');
  expect(extractRetainedPreviewEvidence('timestamp '+JSON.stringify({event:'retained_data_preview',phase:'complete',evidence:f.value}))).toEqual(f.value);
});
it('rejects all-new substitution, wrong scope, stale evidence or incomplete checks',()=>{
  for(const mutate of [f=>{f.value.dataSourceTree=f.value.controlSourceTree;},f=>{f.value.stage='prod';},f=>{f.value.completedMs=now-86400001;},f=>{f.value.checks.workerData=false;},f=>{f.value.accountHash=h('0');},f=>{f.value.extra=true;}]){
    const f=fixture();mutate(f);expect(()=>verifyRetainedPreviewEvidence(f.value,f.expected,{now})).toThrow('RetainedPreviewEvidenceInvalid');
  }
  const f=fixture(),line=JSON.stringify({event:'retained_data_preview',phase:'complete',evidence:f.value});expect(()=>extractRetainedPreviewEvidence(line+'\n'+line)).toThrow();
});
