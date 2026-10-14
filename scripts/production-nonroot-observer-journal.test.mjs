// Synthetic ledger reconciliation only; source/owner admission is not minted.
import {test} from 'vitest';
import assert from 'node:assert/strict';
import {hash,zero,add,local} from './lib/production-nonroot-engineering-json.mjs';
import {OBSERVER_ACCOUNTING_V3,observerAccountingJournalRecords} from './lib/production-nonroot-observer-accounting.mjs';
import {verifyNonrootObserverJournal} from './lib/production-nonroot-observer-journal.mjs';

function fixture(kind,atMs,{cleanupRow=true,version=3}={}){
 const plan={version,owner:'a'.repeat(32),operation:'b'.repeat(32),startedMs:1000,deadlineMs:10000,cleanupReserveMs:2000,
  ownerRef:{path:'/synthetic/owner.json',sha256:'c'.repeat(64),bytesLength:100},capacity:zero(),
  ...(version===3?{accounting:OBSERVER_ACCOUNTING_V3,processingPolicy:{fixture:true}}:{})};
 const rows=[{id:'authorize',charge:local(1)},{id:'mutation',action:'DeleteService',requestBytes:32,responseBytes:32,cleanup:cleanupRow,charge:local(1)}];
 const records=6*rows.length+64+observerAccountingJournalRecords(plan,rows),charge=local(records*(16*65536+4096)),total=add(charge,...rows.map(r=>r.charge));plan.capacity=total;
 const quote={version:version===3?2:1,kind:version===3?'original-observer-host-verification-work':'original-observer-full-work',authority:false,planHash:hash(plan),rows,journal:{records,recordBytes:65536,charge},total,...(version===3?{accounting:plan.accounting}:{})};
 const events=[],emit=(kind,data,atMs=1000)=>events.push({kind,data,atMs,sequence:events.length+1});
 emit('reservation',{planHash:hash(plan),quoteHash:hash(quote),reserved:total,ownerRef:plan.ownerRef,consumed:charge,...(version===3?{accounting:plan.accounting}:{})});
 emit('prepaid',{id:'authorize',charge:rows[0].charge});emit('owner-authenticated',{ownerRef:plan.ownerRef,planHash:hash(plan)});
 emit('prepaid',{id:'mutation',charge:rows[1].charge});
 emit('provider-intent',{id:'mutation',action:'DeleteService',requestHash:hash({}),requestBytes:32,responseBytes:32},1001);
 emit('provider-response',{id:'mutation',action:'DeleteService',statusCode:200,rawHash:'d'.repeat(64),rawBytes:2,requestHash:hash({}),startedMs:1001,completedMs:1002,joined:true},1002);
 if(kind)emit(kind,{id:'mutation'},atMs);
 emit('invocation-closed',{id:'mutation',complete:true,used:zero(),retained:rows[1].charge},cleanupRow?9999:7999);
 emit('terminal',{},9999);
 const terminal={consumed:total,retainedReservation:total,...(version===3?{accounting:plan.accounting}:{})};
 const journal={records:events,terminal,archive:{owner:plan.owner,operation:plan.operation}};
 const {ownerRef,...approved}=plan;
 const reader={current(){},paid:{debit(n){assert(Number.isSafeInteger(n)&&n>=0);}},async json(ref){assert.deepEqual(ref,ownerRef);return {version:1,kind:'original-preview-overlap-isolated-owner-v1',owner:plan.owner,operation:plan.operation,planHash:hash(approved)};}};
 return ()=>verifyNonrootObserverJournal(journal,{reader,plan,quote});
}

for(const kind of ['ownership-cleanup','ownership-response'])test(kind+' can use the original cleanup reserve',async()=>{
 await fixture(kind,9998)();
 await assert.rejects(fixture(kind,10000),/ObserverArchivedJournalLifetime/);
});
test('normal ownership response cannot borrow cleanup time',async()=>{
 await fixture('ownership-response',7998,{cleanupRow:false})();
 await assert.rejects(fixture('ownership-response',8000,{cleanupRow:false}),/ObserverArchivedJournalLifetime/);
});
for(const kind of ['ownership-obligation','resource-admission-verified'])test(kind+' stays before the normal cutoff',async()=>{
 await fixture(kind,7998)();
 await assert.rejects(fixture(kind,8000),/ObserverArchivedJournalLifetime/);
});
for(const version of [1,2])test('legacy '+version+' provider cleanup keeps its original window',async()=>{await fixture(null,0,{version})();});
