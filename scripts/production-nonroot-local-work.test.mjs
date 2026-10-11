import {test} from 'vitest';
import assert from 'node:assert/strict';
import {originalLocalWorkScopeHash,inspectOriginalLocalWorkData,verifyOriginalLocalWorkEvents,ORIGINAL_LOCAL_WORK_JOURNAL_LOCAL as J,ORIGINAL_LOCAL_WORK_RECORD_BYTES as W,ORIGINAL_LOCAL_WORK_QUANTUM as Q} from './lib/production-nonroot-local-work.mjs';
const zero=()=>({ecrRequests:0,logicalBytes:0,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0});
const binding={owner:'a'.repeat(32),executionId:'b'.repeat(32),planHash:'c'.repeat(64),publicationHash:'d'.repeat(64)},subjectHash='e'.repeat(64),deadlineMs=2*10**12;
function data(scope='legacy',kind='journal',ordinal=1){return {scope,scopeHash:originalLocalWorkScopeHash({scope,subjectHash,binding,deadlineMs}),ordinal,kind,workBytes:kind==='journal'?J:Q,journalBytes:J,reserveDebit:{...zero(),logicalBytes:(kind==='journal'?J:Q)+J},...(kind==='journal'?{targetLogicalBytes:Q}:{})};}
const options=(scope='legacy')=>({scope,subjectHash,binding,deadlineMs,beforeSequence:10});
function rows(scope='legacy'){return [{sequence:1,type:'local-work',data:data(scope)},{sequence:2,type:'logical',data:{purpose:scope==='legacy'?'metadata':'archive',bytes:Q,reserveDebit:{...zero(),logicalBytes:Q}}}];}
test('source and journal work are separate from unchanged processing quantum',()=>{
 assert.equal(J,40960);assert.equal(Q,65536);assert.equal(inspectOriginalLocalWorkData(data()).logicalBytes,81920);assert.equal(inspectOriginalLocalWorkData(data('legacy','source')).logicalBytes,Q+J);
 assert.equal(verifyOriginalLocalWorkEvents(rows(),options()).logicalBytes,2*J);assert.equal(verifyOriginalLocalWorkEvents(rows('carrier-preparation'),options('carrier-preparation')).logicalBytes,2*J);
});
test('old history with no local work is preserved; scope/payee/deadline substitutions reject',()=>{
 assert.deepEqual(verifyOriginalLocalWorkEvents([],options()).sequences,[]);
 for(const patch of [{subjectHash:'f'.repeat(64)},{deadlineMs:deadlineMs+1},{binding:{...binding,executionId:'f'.repeat(32)}},{beforeSequence:1}])assert.throws(()=>verifyOriginalLocalWorkEvents(rows(),{...options(),...patch}),/LocalWorkBinding/);
 assert.throws(()=>inspectOriginalLocalWorkData(data('carrier-preparation','source')),/LocalWorkQuantum/);
});
test('exact fields, next record, ordinal and original body payment cannot be forged',()=>{
 for(const mutate of [r=>r[0].data.ordinal++,r=>r[0].data.extra=true,r=>r[0].data.journalBytes--,r=>r[0].data.reserveDebit.logicalBytes--,r=>r[1].data.bytes--,r=>r[1].data.reserveDebit.logicalBytes--,r=>r[1].data.purpose='archive',r=>r.splice(1,1)]){const r=rows();mutate(r);assert.throws(()=>verifyOriginalLocalWorkEvents(r,options()),/LocalWork/);}
 const r=rows();r.push(...rows().map(e=>({...e,sequence:e.sequence+2})));assert.throws(()=>verifyOriginalLocalWorkEvents(r,options()),/LocalWorkBinding/);
});
test('full fixed event widths include v2 revision/counters at maximal scalar widths',()=>{
 const maximal={ecrRequests:20000,logicalBytes:64*1024**3,httpBodyBytes:32*1024**3,uncompressedBytes:64*1024**3,processedEntries:1000000};
 for(const scope of ['legacy','carrier-preparation'])for(const kind of scope==='legacy'?['source','journal']:['journal'])for(const version of [1,2]){
  const d=data(scope,kind,19999);if(kind==='source'){d.workBytes=Math.floor(maximal.logicalBytes/Q)*Q;d.reserveDebit.logicalBytes=d.workBytes+J;}else d.targetLogicalBytes=maximal.logicalBytes;
  const e={version,...(version===2?{budgetRevision:{version:2,limitsHash:'f'.repeat(64),envelopeHash:'f'.repeat(64),historyHeadHash:'f'.repeat(64)}}:{}),sequence:19999,...binding,previousHash:'f'.repeat(64),type:'local-work',data:d,spent:maximal,remaining:maximal};
  assert(Buffer.byteLength(JSON.stringify(e)+'\n')<=W);
 }
});
