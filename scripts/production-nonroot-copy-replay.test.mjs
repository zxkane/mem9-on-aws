import {describe,it,expect,beforeAll} from 'vitest';
import {copyReplayAccountingFixture,raw,sha,keys} from './production-nonroot-copy-replay.fixture.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {verifyNonrootCombinedCopyAccounting,verifyNonrootCacheReadAccounting} from './lib/production-nonroot-cache.mjs';
import {verifyNonrootCopyReplayStart} from './lib/production-nonroot-copy-replay.mjs';
import {nonrootAccountingPolicy} from './lib/production-nonroot-budget-revision.mjs';
let original;
beforeAll(async()=>{original=await copyReplayAccountingFixture();});
const fresh=()=>structuredClone(original),verify=f=>verifyNonrootCombinedCopyAccounting(f.record,f.options);
const inspect=f=>verifyNonrootCopyReplayStart(f.context.values.L,{startRaw:f.record.startRaw,copyCheckpoint:f.options.copyCheckpoint,copyReceipt:f.options.copyReceipt,policy:nonrootAccountingPolicy(f.options.expectedBudgetRevision,f.options.expectedBudgetRevision,f.options.expectedBudgetCeiling),expectedCopyReplay:f.context});
function rebind(f,{keepBadLengths=false}={}){
 const x=f.context;
 for(const k of ['Cp','N','L','K1','K2','J','S']){
  if(k==='K2')x.values.K2.nodeHash=hash(x.values.N);
  if(k==='J'&&!keepBadLengths)for(const n of ['N','L'])x.values.J[n].bytesLength=raw(x.values[n]).length;
  x.refs[k].sha256=sha(raw(x.values[k]));
 }
 f.record.startRaw=raw(x.values.L).toString('base64');f.options.copyReceipt.combinedPass.ledgerStartHash=x.refs.L.sha256;
}
function adoption(f){
 const old=f.options.copyCheckpoint,start={version:2,kind:'custody-ledger-start',budgetRevision:old.budgetRevision,binding:old.binding,startingCounters:old.counters,reserve:old.remainingReservation,deadlineMs:f.start.deadlineMs,mode:'adoption'};
 const event={version:2,budgetRevision:old.budgetRevision,sequence:1,...old.binding,previousHash:null,type:'sealed',data:{reason:'completed'},spent:old.counters,remaining:old.remainingReservation};
 const checkpoint={binding:old.binding,startingCounters:old.counters,counters:old.counters,remainingReservation:old.remainingReservation,eventCount:1,lastEventHash:hash(event),active:0,sealed:true,budgetRevision:old.budgetRevision};
 return {version:3,kind:'nonroot-cache-read-accounting',start,startRaw:raw(start).toString('base64'),events:[event],checkpoint,fundingPlans:[],combinedCopy:f.record};
}

describe('original COPY prefix public accounting',()=>{
 it('validates full original join and every combined accounting event',()=>{
  const f=fresh();expect(verify(f)).toEqual(f.readUsage);
  expect(f.record.events.filter(e=>e.type==='filesystem')).toHaveLength(6);
  expect(f.record.events.filter(e=>e.type==='scan-pool-completed')).toHaveLength(3);
  expect(Buffer.from(f.record.startRaw,'base64')).toEqual(raw(f.context.values.L));
 });
 it('allows the original pre-S verification without asserting a completed S',async()=>{
  const f=await copyReplayAccountingFixture({settled:false});expect(verify(f)).toEqual(f.readUsage);
 });
 it('forwards the same join through adoption without allowing copyReplay on its own start',()=>{
  const f=fresh(),r=adoption(f),before=JSON.stringify(r),out=verifyNonrootCacheReadAccounting(r,{...f.options,readUsage:f.readUsage});
  expect(out.readUsage).toEqual(f.readUsage);expect(JSON.stringify(r)).toBe(before);
  r.start.copyReplay=f.start.copyReplay;r.startRaw=raw(r.start).toString('base64');
  expect(()=>verifyNonrootCacheReadAccounting(r,f.options)).toThrow('NonrootCacheFields');
 });
 it('rejects nested adoption when the original join context was dropped',()=>{
  const f=fresh(),r=adoption(f);delete f.options.expectedCopyReplay;
  expect(()=>verifyNonrootCacheReadAccounting(r,f.options)).toThrow('NonrootCopyReplayExpectedJoin');
 });
 it('replays original join DATA inside the existing accounting record without a new record or native claim',()=>{
  const f=fresh();f.record.copyReplay=f.context;delete f.options.expectedCopyReplay;
  expect(verify(f)).toEqual(f.readUsage);expect(verifyNonrootCacheReadAccounting(adoption(f),f.options).readUsage).toEqual(f.readUsage);
 });
 it('rejects conflicting explicit/record join data and a record success flag',()=>{
  const f=fresh();f.record.copyReplay=structuredClone(f.context);f.record.copyReplay.values.S.status='HELD';
  expect(()=>verify(f)).toThrow('NonrootCopyReplayContextConflict');
  delete f.options.expectedCopyReplay;f.record.copyReplay={completed:true,paid:true};expect(()=>verify(f)).toThrow('NonrootCopyReplayFields');
 });
 it('requires original S for adoption even though pre-S completion verification is allowed',async()=>{
  const f=await copyReplayAccountingFixture({settled:false});expect(verify(f)).toEqual(f.readUsage);
  expect(()=>verifyNonrootCacheReadAccounting(adoption(f),f.options)).toThrow('NonrootCopyReplaySettlementRequired');
 });
 it('fails closed when a prospective L has no independently supplied originals',()=>{
  const f=fresh();delete f.options.expectedCopyReplay;expect(()=>verify(f)).toThrow('NonrootCopyReplayExpectedJoin');
 });
 it('rejects downgrade/removal even after the outer raw L hash is updated',()=>{
  const f=fresh(),s=JSON.parse(Buffer.from(f.record.startRaw,'base64'));delete s.copyReplay;
  f.record.startRaw=raw(s).toString('base64');f.options.copyReceipt.combinedPass.ledgerStartHash=sha(raw(s));
  expect(()=>verify(f)).toThrow('NonrootCopyReplayExpectedJoin');
 });
 it('rejects a caller success object instead of a complete original join',()=>{
  const f=fresh();f.options.expectedCopyReplay={completed:true,paid:true};expect(()=>verify(f)).toThrow('NonrootCopyReplayFields');
 });
 for(const member of ['Cp','K1','K2','J','N','L','S'])it('rejects changed complete '+member+' bytes',()=>{
  const f=fresh();f.context.values[member].unapproved=true;expect(()=>verify(f)).toThrow();
 });
 for(const field of ['P','completion','T','baselineCounters'])for(const dimension of keys)it('rejects changed '+field+'.'+dimension+' even with a rehashed L',()=>{
  const f=fresh(),s=f.context.values.L;s.copyReplay[field][dimension]++;
  f.context.refs.L.sha256=sha(raw(s));f.record.startRaw=raw(s).toString('base64');f.options.copyReceipt.combinedPass.ledgerStartHash=f.context.refs.L.sha256;
  expect(()=>verify(f)).toThrow();
 });
 for(const mutate of [
  x=>{x.values.J.delta.logicalBytes++;},x=>{x.values.J.N.bytesLength++;},x=>{x.values.J.L.bytesLength++;},
  x=>{x.values.K2.previousRef=x.refs.Cp;},x=>{x.values.N.data.charge.logicalBytes++;},
  x=>{x.values.N.data.copyReplay.sourceManifestHash='0'.repeat(64);},x=>{x.values.Cp.witnessHash='not-a-hash';},
  x=>{x.values.S.status='HELD';},x=>{x.values.S.replayReceipts.completion.replays=12;},
  x=>{x.values.S.replayReceipts.preclaim.funding='source-preparation';},x=>{x.values.S.refund.logicalBytes=1;},
 ])it('rejects a repinned invalid original join relation '+String(mutate),()=>{
  const f=fresh();mutate(f.context);for(const key of ['Cp','K1','K2','J','N','S'])f.context.refs[key].sha256=sha(raw(f.context.values[key]));
  expect(()=>verify(f)).toThrow();
 });
 for(const [name,mutate,code,lengths]of [
  ['delta',x=>{x.values.J.delta.logicalBytes++;},'UpgradeDelta'],
  ['N length',x=>{x.values.J.N.bytesLength++;},'UpgradeLength',true],
  ['L length',x=>{x.values.J.L.bytesLength++;},'UpgradeLength',true],
  ['checkpoint order',x=>{x.values.K2.previousRef=x.refs.Cp;},'CheckpointOrder'],
  ['occupancy',x=>{x.values.N.data.charge={...x.values.N.data.charge,logicalBytes:x.values.N.data.charge.logicalBytes+1};},'NodeOccupancy'],
  ['source',x=>{x.values.N.data.copyReplay.sourceManifestHash='0'.repeat(64);},'NodePrefix'],
  ['witness',x=>{x.values.Cp.witnessHash='bad';},'Claim'],
  ['held',x=>{x.values.S.status='HELD';},'Settlement'],
  ['missing replay',x=>{x.values.S.replayReceipts.completion.replays=12;},'SettlementReplay'],
  ['source-only credit',x=>{x.values.S.replayReceipts.preclaim.funding='source-preparation';},'SettlementReplay'],
  ['refund',x=>{x.values.S.refund.logicalBytes=1;},'Refund'],
 ])it('rechecks semantic '+name+' after every affected raw reference is repinned',()=>{
  const f=fresh();mutate(f.context);rebind(f,{keepBadLengths:lengths});expect(()=>inspect(f)).toThrow('NonrootCopyReplay'+code);
 });
 it('rejects redistribution between baseline and P even when L starting counters stay unchanged',()=>{
  const f=fresh(),before=JSON.stringify(f.context.values.L.startingCounters);
  const r=f.context.values.L.copyReplay;
  r.baselineCounters={...r.baselineCounters,logicalBytes:r.baselineCounters.logicalBytes-1};r.P={...r.P,logicalBytes:r.P.logicalBytes+1};
  rebind(f);expect(JSON.stringify(f.context.values.L.startingCounters)).toBe(before);expect(()=>inspect(f)).toThrow('NonrootCopyReplayBaseline');
 });
 for(const which of ['config','envelope','budget'])it('rejects substituted '+which+' data without accepting its self-declared success',()=>{
  const f=fresh();if(which==='config')f.context.config.startingCounters.logicalBytes++;
  if(which==='envelope')f.context.envelope.knownRemaining.logicalBytes++;
  if(which==='budget')f.context.budget.nonC.preclaim.logicalBytes--;
  expect(()=>verify(f)).toThrow();
 });
 for(const which of ['spent','remaining','response','source','filesystem','scan','seal'])it('retains full underlying accounting rejection: '+which,()=>{
  const f=fresh();if(which==='spent')f.record.events[0].spent.logicalBytes++;
  if(which==='remaining')f.record.events[0].remaining.httpBodyBytes++;
  if(which==='response')f.record.events.find(e=>e.type==='completed').data.charged++;
  if(which==='source')f.record.events.find(e=>e.type==='cache-complete').data.digest='sha256:'+'0'.repeat(64);
  if(which==='filesystem')f.record.events.find(e=>e.type==='filesystem'&&e.data.phase==='combined').data.processedEntries++;
  if(which==='scan')f.record.events.find(e=>e.type==='scan-pool-completed').data.response.imageScanStatus.status='IN_PROGRESS';
  if(which==='seal')f.record.events.pop();expect(()=>verify(f)).toThrow();
 });
 it('keeps the original 32768-character start bound',()=>{
  const f=fresh();f.record.startRaw+='A'.repeat(32769);expect(()=>verify(f)).toThrow('NonrootCacheStartRaw');
 });
 it('does not invoke accessors in supplied join data',()=>{
  const f=fresh();let calls=0;Object.defineProperty(f.context,'poison',{enumerable:true,get(){calls++;return 1;}});
  expect(()=>verify(f)).toThrow();expect(calls).toBe(0);
 });
 it('preserves full original bytes instead of accepting canonical-only reordered N',()=>{
  const f=fresh();f.context.values.N=Object.fromEntries(Object.entries(f.context.values.N).reverse());
  expect(()=>verify(f)).toThrow('NonrootCopyReplayOriginalBytes');
 });
 it('rejects a legacy node inserted into an otherwise repinned prospective join',()=>{
  const f=fresh();f.context.values.N.version=2;rebind(f);expect(()=>inspect(f)).toThrow('NonrootCopyReplayNode');
 });
 it('reconstructs counter validation instead of using a supplied policy callback',()=>{
  const f=fresh();f.context.values.L.reserve={...f.context.values.L.reserve,logicalBytes:-1};rebind(f);
  const policy={...nonrootAccountingPolicy(f.options.expectedBudgetRevision,f.options.expectedBudgetRevision,f.options.expectedBudgetCeiling),counter:()=>{}};
  expect(()=>verifyNonrootCopyReplayStart(f.context.values.L,{startRaw:f.record.startRaw,copyCheckpoint:f.options.copyCheckpoint,copyReceipt:f.options.copyReceipt,policy,expectedCopyReplay:f.context})).toThrow('NonrootBudgetCounter');
 });
 it('cannot select legacy/adoption using the new field',()=>{
  for(const mode of ['adoption','copy']){const f=fresh(),s=f.context.values.L;s.mode=mode;s.version=1;
   const policy=nonrootAccountingPolicy(f.options.expectedBudgetRevision,f.options.expectedBudgetRevision,f.options.expectedBudgetCeiling);
   expect(()=>verifyNonrootCopyReplayStart(s,{startRaw:raw(s).toString('base64'),copyCheckpoint:f.options.copyCheckpoint,copyReceipt:f.options.copyReceipt,policy,expectedCopyReplay:f.context})).toThrow('NonrootCopyReplayVersion');
  }
 });
});
