import {OBSERVER_ACCOUNTING_V3,observerAccountingJournalRecords,inspectObserverAccounting} from './production-nonroot-observer-accounting.mjs';
/** Read original observer records through the caller's authenticated archive.
 * Historical path fields bind records; they never select host filesystem IO. */
import {posix} from 'node:path';
import {need,exact,hex,hash,sha,json,canonical,same,ref,counter,zero,add,COUNTERS} from './production-nonroot-engineering-json.mjs';

const PURPOSE='original-preview-overlap-isolated-owner-v1';
const RECORD_BYTES=65536;
const kinds=new Set(['reservation','prepaid','owner-authenticated','invocation-closed',
 'provider-intent','provider-response','rehearsal-A-authenticated','observer-run-material','terminal','resource-admission-verified','ownership-obligation','ownership-response','ownership-cleanup']);
const admissionKinds=new Set(['resource-admission-verified','ownership-obligation','ownership-response','ownership-cleanup']);
const integer=n=>Number.isSafeInteger(n)&&n>=0;
const within=(a,b)=>COUNTERS.every(k=>a[k]<=b[k]);

export async function readNonrootObserverJournal(run,{reader,maximumRecords}){
 reader.current();reader.paid.debit(65536);
 exact(run,['authority','productionGO','terminal','archive']);
 need(run.authority===false&&run.productionGO===false,'ObserverArchivedRun');
 const terminal=run.terminal,archive=run.archive;
 exact(terminal,['authority','productionGO','complete','held','unknown','terminal','records','retainedReservation','consumed',...(Object.hasOwn(terminal,'accounting')?['accounting']:[])]);
 need(terminal.authority===false&&terminal.productionGO===false&&terminal.complete===true&&terminal.held===false&&terminal.unknown===false,'ObserverArchivedRunIncomplete');
 if(Object.hasOwn(terminal,'accounting'))same(terminal.accounting,OBSERVER_ACCOUNTING_V3,'ObserverArchivedAccounting');
 counter(terminal.retainedReservation);counter(terminal.consumed);
 exact(archive,['version','kind','authority','owner','operation','directory','index','objects','putRecords','putBytes']);
 need(archive.version===1&&archive.kind==='original-observer-archive-reference'&&archive.authority===false&&hex(archive.owner,32)&&hex(archive.operation,32),'ObserverArchivedDescriptor');
 need(typeof archive.directory==='string'&&Buffer.byteLength(archive.directory)<=4096&&posix.resolve(archive.directory)===archive.directory&&posix.basename(archive.directory)==='data','ObserverArchivedDirectory');
 const directory=posix.dirname(archive.directory);
 need(posix.basename(directory)===archive.owner+'-'+archive.operation,'ObserverArchivedDirectory');
 ref(archive.index);need(archive.index.path===posix.join(archive.directory,archive.index.sha256),'ObserverArchivedIndexRef');
 need([archive.objects,archive.putRecords,archive.putBytes].every(integer)&&archive.objects>0&&archive.objects<=archive.putRecords,'ObserverArchivedDescriptor');
 need(integer(maximumRecords)&&maximumRecords>0&&maximumRecords<=1000000&&Array.isArray(terminal.records)&&terminal.records.length>=5&&terminal.records.length<=maximumRecords,'ObserverArchivedJournalBound');
 reader.paid.debit(8192*terminal.records.length+65536);
 ref(terminal.terminal);same(terminal.terminal,terminal.records.at(-1),'ObserverArchivedTerminalRef');
 let previous='0'.repeat(64),lastMs=0;
 const records=[],byKind=new Map();
 for(const [index,r] of terminal.records.entries()){
  reader.current();ref(r);
  need(r.path===posix.join(directory,String(index+1).padStart(6,'0')+'.json')&&r.bytesLength>0&&r.bytesLength<=RECORD_BYTES,'ObserverArchivedRecordRef');
  const raw=await reader.readBytes(r,RECORD_BYTES);reader.current();
  reader.paid.debit(32*raw.length+4096);
  const value=json(raw,RECORD_BYTES);
  exact(value,['version','kind','purpose','owner','operation','sequence','previous','atMs','data']);
  need(value.version===1&&kinds.has(value.kind)&&(!admissionKinds.has(value.kind)||Object.hasOwn(terminal,'accounting'))&&value.purpose===PURPOSE&&value.owner===archive.owner&&value.operation===archive.operation&&value.sequence===index+1&&value.previous===previous,'ObserverArchivedJournalChain');
  need(integer(value.atMs)&&value.atMs>=lastMs,'ObserverArchivedJournalClock');
  need(Buffer.from(canonical(value)+'\n').equals(raw)&&sha(raw)===r.sha256,'ObserverArchivedJournalEncoding');
  previous=r.sha256;lastMs=value.atMs;records.push(value);
  if(!byKind.has(value.kind))byKind.set(value.kind,[]);
  byKind.get(value.kind).push(value);
 }
 for(const kind of ['reservation','owner-authenticated','observer-run-material','terminal','rehearsal-A-authenticated'])need(byKind.get(kind)?.length===1,'ObserverArchivedJournalSingleton');
 need(records[0].kind==='reservation'&&records.at(-1).kind==='terminal','ObserverArchivedJournalOrder');
 const end=records.at(-1).data;
 exact(end,['complete','held','unknown','retainedReservation','consumed','outputs',...(Object.hasOwn(terminal,'accounting')?['accounting']:[])]);
 if(Object.hasOwn(terminal,'accounting'))same(end.accounting,terminal.accounting,'ObserverArchivedAccounting');
 need(end.complete===true&&end.held===false&&end.unknown===false,'ObserverArchivedRunIncomplete');
 same(end.retainedReservation,terminal.retainedReservation,'ObserverArchivedTerminalReservation');
 same(end.consumed,terminal.consumed,'ObserverArchivedTerminalConsumption');
 exact(end.outputs,['archive']);same(end.outputs.archive,archive,'ObserverArchivedTerminalArchive');
 const material=byKind.get('observer-run-material')[0];
 exact(material.data,['ref','planHash','quoteHash']);
 need(hex(material.data.planHash)&&hex(material.data.quoteHash),'ObserverArchivedMaterialBinding');
 reader.current();
 return {run,archive,terminal,records,byKind,materialRef:material.data.ref,completedMs:lastMs};
}

/** Reconcile the original retained charges. The caller separately recompiles
 * the original plan/quote; this function does not treat quote DATA as authority. */
export async function verifyNonrootObserverJournal(journal,{reader,plan,quote}){
 reader.current();reader.paid.debit(65536+8192*journal.records.length);
 inspectObserverAccounting(plan);
 exact(quote,['version','kind','authority','planHash','rows','journal','total',...(plan.version===3?['accounting']:[])]);
 need(quote.version===(plan.version===3?2:1)&&quote.kind===(plan.version===3?'original-observer-host-verification-work':'original-observer-full-work')&&quote.authority===false&&quote.planHash===hash(plan),'ObserverArchivedQuote');
 need(Object.hasOwn(journal.terminal,'accounting')===(plan.version===3),'ObserverArchivedAccountingVersion');
 if(plan.version===3){same(quote.accounting,plan.accounting,'ObserverArchivedAccounting');same(journal.terminal.accounting,plan.accounting,'ObserverArchivedAccounting');need(Object.hasOwn(plan,'processingPolicy'),'ObserverAccountingProcessingPolicy');}
 need(plan.owner===journal.archive.owner&&plan.operation===journal.archive.operation&&integer(plan.startedMs)&&integer(plan.deadlineMs)&&integer(plan.cleanupReserveMs)&&plan.startedMs<plan.deadlineMs-plan.cleanupReserveMs,'ObserverArchivedPlan');
 need(Array.isArray(quote.rows)&&quote.rows.length>0&&quote.rows.length<=1000000,'ObserverArchivedQuoteRows');
 counter(plan.capacity);counter(quote.total);
 exact(quote.journal,['records','recordBytes','charge']);counter(quote.journal.charge);
 need(quote.journal.records===6*quote.rows.length+64+observerAccountingJournalRecords(plan,quote.rows)&&quote.journal.recordBytes===RECORD_BYTES&&journal.records.length<=quote.journal.records,'ObserverArchivedJournalQuote');
 const journalCharge={...zero(),logicalBytes:quote.journal.records*(16*RECORD_BYTES+4096)};
 counter(journalCharge);same(quote.journal.charge,journalCharge,'ObserverArchivedJournalCharge');
 reader.paid.debit(8192*quote.rows.length);
 const rows=new Map();
 for(const row of quote.rows){need(typeof row.id==='string'&&row.id.length>0&&row.id.length<=1024&&!rows.has(row.id),'ObserverArchivedQuoteRow');counter(row.charge);rows.set(row.id,row);}
 same(add(journalCharge,...quote.rows.map(r=>r.charge)),quote.total,'ObserverArchivedQuoteTotal');
 need(within(quote.total,plan.capacity),'ObserverArchivedPlanCapacity');
 const planHash=hash(plan),quoteHash=hash(quote),reservation=journal.records[0];
 exact(reservation.data,['planHash','quoteHash','reserved','ownerRef','consumed',...(plan.version===3?['accounting']:[])]);
 if(plan.version===3)same(reservation.data.accounting,plan.accounting,'ObserverArchivedAccounting');
 need(reservation.data.planHash===planHash&&reservation.data.quoteHash===quoteHash,'ObserverArchivedReservationBinding');
 same(reservation.data.reserved,quote.total,'ObserverArchivedReservation');same(reservation.data.consumed,journalCharge,'ObserverArchivedReservation');same(reservation.data.ownerRef,plan.ownerRef,'ObserverArchivedOwnerRef');
 const paid=new Map(),closed=new Map(),intents=new Map(),providers=new Map();let consumed=journalCharge,authenticated=false;
 for(const event of journal.records){
  reader.current();reader.paid.debit(4096);
  const d=event.data;
  const rowEvent=['prepaid','invocation-closed','provider-intent','provider-response'].includes(event.kind);
  const cleanup=event.kind==='terminal'||rowEvent&&rows.get(d.id)?.cleanup===true||plan.version===3&&(event.kind==='ownership-cleanup'||event.kind==='ownership-response'&&rows.get(d.id)?.cleanup===true);
  need(event.atMs>=plan.startedMs&&event.atMs<plan.deadlineMs-(cleanup?0:plan.cleanupReserveMs),'ObserverArchivedJournalLifetime');
  if(event.kind==='prepaid'){
   exact(d,['id','charge']);const row=rows.get(d.id);
   need(row&&!paid.has(d.id)&&(authenticated||d.id==='authorize'),'ObserverArchivedPrepayment');
   need(event.atMs<plan.deadlineMs-(row.cleanup?0:plan.cleanupReserveMs),'ObserverArchivedJournalLifetime');
   same(d.charge,row.charge,'ObserverArchivedPrepayment');consumed=add(consumed,d.charge);need(within(consumed,quote.total),'ObserverArchivedConsumption');paid.set(d.id,event);
  }else if(event.kind==='owner-authenticated'){
   exact(d,['ownerRef','planHash']);need(!authenticated&&paid.has('authorize')&&d.planHash===planHash,'ObserverArchivedOwner');same(d.ownerRef,plan.ownerRef,'ObserverArchivedOwner');authenticated=true;
  }else if(event.kind==='invocation-closed'){
   exact(d,['id','complete','used','retained']);const row=rows.get(d.id);
   need(authenticated&&paid.has(d.id)&&!closed.has(d.id)&&d.id!=='authorize'&&d.complete===true,'ObserverArchivedInvocation');
   counter(d.used);same(d.retained,row.charge,'ObserverArchivedInvocation');need(within(d.used,row.charge),'ObserverArchivedInvocationUse');
   if(row.action)need(providers.has(d.id),'ObserverArchivedProviderMissing');
   closed.set(d.id,event);
  }else if(event.kind==='provider-intent'){
   exact(d,['id','action','requestHash','requestBytes','responseBytes']);const row=rows.get(d.id);
   need(authenticated&&paid.has(d.id)&&!closed.has(d.id)&&!intents.has(d.id)&&row.action===d.action&&hex(d.requestHash)&&d.requestBytes===row.requestBytes&&d.responseBytes===row.responseBytes,'ObserverArchivedProviderIntent');intents.set(d.id,event);
  }else if(event.kind==='provider-response'){
   exact(d,['id','action','statusCode','rawHash','rawBytes','requestHash','startedMs','completedMs','joined']);const row=rows.get(d.id),intent=intents.get(d.id);
   need(authenticated&&intent&&!providers.has(d.id)&&!closed.has(d.id)&&d.action===row.action&&d.requestHash===intent.data.requestHash&&hex(d.rawHash)&&integer(d.rawBytes)&&d.rawBytes<=row.responseBytes&&d.joined===true,'ObserverArchivedProviderResponse');
   need(d.statusCode===200&&integer(d.startedMs)&&integer(d.completedMs)&&d.startedMs>=intent.atMs&&d.completedMs>=d.startedMs&&d.completedMs<=event.atMs,'ObserverArchivedProviderResponse');providers.set(d.id,d);
  }else if(event.kind==='observer-run-material'){
   need(authenticated&&paid.has('run-material')&&!closed.has('run-material')&&d.planHash===planHash&&d.quoteHash===quoteHash,'ObserverArchivedRunMaterial');
  }else if(event.kind==='rehearsal-A-authenticated'){
   need(authenticated,'ObserverArchivedRehearsalOrder');
  }
 }
 need(authenticated&&paid.has('authorize')&&[...paid.keys()].every(id=>id==='authorize'||closed.has(id))&&[...intents.keys()].every(id=>providers.has(id)),'ObserverArchivedOpenInvocation');
 same(consumed,journal.terminal.consumed,'ObserverArchivedConsumption');same(quote.total,journal.terminal.retainedReservation,'ObserverArchivedRetainedReservation');
 // The original authorization record is read from the authenticated archive,
 // never from the historical ownerRef.path on this machine.
 const owner=await reader.json(plan.ownerRef,65536);reader.current();
 const {ownerRef,...approved}=plan;
 same(owner,{version:1,kind:PURPOSE,owner:plan.owner,operation:plan.operation,planHash:hash(approved)},'ObserverArchivedOriginalOwner');
 const admissionEvents=journal.records.filter(e=>admissionKinds.has(e.kind));need(admissionEvents.length<=observerAccountingJournalRecords(plan,quote.rows),'ObserverAdmissionJournalBound');
 return {providers,paid,closed,consumed,planHash,quoteHash,admissionEvents};
}
