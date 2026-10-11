/** Original COPY local work records. These prices are DATA; only the
 * original native ledger can debit and issue a live local-work scope. */
import {nonrootHash as hash} from './production-nonroot-contracts.mjs';
const need=(v,c)=>{if(!v)throw Error(c);};
const keys=['ecrRequests','logicalBytes','httpBodyBytes','uncompressedBytes','processedEntries'];
const natural=n=>Number.isSafeInteger(n)&&n>=0;
const exact=(v,k)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===k.toSorted().join(),'LocalWorkFields');
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
export const ORIGINAL_LOCAL_WORK_QUANTUM=65536;
export const ORIGINAL_LOCAL_WORK_RECORD_BYTES=2048;
// Complete fixed ledger record: canonical hash/copies/encoding/write plus
// file/directory metadata and sync. The record pays its own bound once;
// producing a billing record never recursively creates another invoice.
export const ORIGINAL_LOCAL_WORK_JOURNAL_LOCAL=16*ORIGINAL_LOCAL_WORK_RECORD_BYTES+8192;
export function originalLocalWorkScopeHash({scope,subjectHash,binding,deadlineMs}){
 need(['legacy','carrier-preparation'].includes(scope)&&hex(subjectHash)&&natural(deadlineMs),'LocalWorkScope');
 return hash({kind:'original-copy-local-work',scope,subjectHash,binding,deadlineMs});
}
export function inspectOriginalLocalWorkData(d){
 exact(d,['scope','scopeHash','ordinal','kind','workBytes','journalBytes','reserveDebit',...(d?.kind==='journal'?['targetLogicalBytes']:[])]);
 need(['legacy','carrier-preparation'].includes(d.scope)&&hex(d.scopeHash)&&natural(d.ordinal)&&d.ordinal>0,'LocalWorkScope');
 need(['source','journal'].includes(d.kind)&&natural(d.workBytes)&&d.workBytes>0&&d.journalBytes===ORIGINAL_LOCAL_WORK_JOURNAL_LOCAL,'LocalWorkPrice');
 if(d.kind==='source')need(d.scope==='legacy'&&d.workBytes%ORIGINAL_LOCAL_WORK_QUANTUM===0,'LocalWorkQuantum');
 else need(d.workBytes===ORIGINAL_LOCAL_WORK_JOURNAL_LOCAL&&natural(d.targetLogicalBytes),'LocalWorkJournalTarget');
 const n=d.workBytes+d.journalBytes;need(natural(n),'LocalWorkPrice');exact(d.reserveDebit,keys);
 for(const k of keys)need(d.reserveDebit[k]===(k==='logicalBytes'?n:0),'LocalWorkDebit');
 return {...d.reserveDebit};
}
export function verifyOriginalLocalWorkEvents(events,{scope,subjectHash,binding,deadlineMs,beforeSequence}){
 const expected=originalLocalWorkScopeHash({scope,subjectHash,binding,deadlineMs}),rows=[];let total=0;
 for(const [i,e]of events.entries())if(e.type==='local-work'&&e.data.scope===scope){
  const charge=inspectOriginalLocalWorkData(e.data);need(e.data.scopeHash===expected&&e.data.ordinal===rows.length+1&&e.sequence<beforeSequence,'LocalWorkBinding');
  if(e.data.kind==='journal'){
   const next=events[i+1],purpose=scope==='legacy'?'metadata':'archive';
   need(next?.type==='logical'&&next.sequence===e.sequence+1&&next.data.purpose===purpose&&next.data.bytes===e.data.targetLogicalBytes,'LocalWorkJournalTarget');
   exact(next.data,['purpose','bytes','reserveDebit']);exact(next.data.reserveDebit,keys);for(const key of keys)need(next.data.reserveDebit[key]===(key==='logicalBytes'?e.data.targetLogicalBytes:0),'LocalWorkJournalTarget');
  }
  total+=charge.logicalBytes;need(natural(total),'LocalWorkPrice');rows.push(e.sequence);
 }
 return {scope,scopeHash:expected,sequences:rows,logicalBytes:total,firstSequence:rows[0]??null,lastSequence:rows.at(-1)??null};
}
