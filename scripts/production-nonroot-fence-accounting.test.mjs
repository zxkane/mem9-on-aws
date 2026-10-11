import {test} from 'vitest';
import assert from 'node:assert/strict';
import {fenceAccountingFixture} from './production-nonroot-fence.fixture.mjs';
import {describeNonrootFenceAcquisitionBudget,inspectNonrootFenceAcquisitionBudget,createNonrootFenceAcquisitionPlan,nonrootFenceAcquisitionPrepaymentData,verifyNonrootFenceAcquisitionPlan,describeBeforeCopyFenceCalls} from './lib/production-nonroot-fence-accounting.mjs';
import {NONROOT_REMAINING_WORK_CAPS_V2} from './lib/production-nonroot-budget-revision.mjs';
import {nonrootFinalizationLimits} from './lib/production-nonroot-finalization-accounting.mjs';
for(const provider of ['static-temporary','instance-metadata'])test('closed '+provider+' budget includes complete normal/abort and independent unknown lanes',()=>{
 const f=fenceAccountingFixture(provider),b=f.budget;
 assert.deepEqual(inspectNonrootFenceAcquisitionBudget(b),b);assert.deepEqual(b.calls,describeBeforeCopyFenceCalls(provider));
 const wire=Object.values(b.calls).reduce((n,c)=>n+c.count*(c.requestBytes+c.responseBytes),0);
 assert.equal(b.charge.httpBodyBytes,wire+2*8388608);assert.equal(b.charge.logicalBytes,b.limits.normalLocalBytes+b.limits.cleanupLocalBytes);
 assert.equal(b.charge.ecrRequests,0);assert.equal(b.charge.uncompressedBytes,0);assert.equal(b.charge.processedEntries,0);
 assert.equal(b.calls['mutex.put'].count,1);assert.equal(b.calls['mutex.delete'].count,1);assert.equal(b.calls['cleanup.github.patch'].count,1);
 assert.equal(NONROOT_REMAINING_WORK_CAPS_V2.logicalBytes,64*1024**3);
});
for(const field of ['charge','limits','calls','specHash','version'])test('budget rejects changed '+field,()=>{
 const b=structuredClone(fenceAccountingFixture().budget);
 if(field==='charge')b.charge.logicalBytes--;
 if(field==='limits')b.limits.cleanupLocalBytes--;
 if(field==='calls')b.calls['mutex.put'].count++;
 if(field==='specHash')b.specHash='not a hash';
 if(field==='version')b.version=2;
 assert.throws(()=>inspectNonrootFenceAcquisitionBudget(b));
});
test('plan independently binds all protected expected values and exact prepayment',()=>{
 const {expected}=fenceAccountingFixture(),p=createNonrootFenceAcquisitionPlan(expected),d=nonrootFenceAcquisitionPrepaymentData(p);
 assert.deepEqual(verifyNonrootFenceAcquisitionPlan(p,expected),{plan:p,...d});assert.equal(d.allocationId,d.planHash);assert.deepEqual(d.charge,d.reserveDebit);
 for(const key of ['ledgerStartHash','ownerAuthorizationHash','parentStartHash','deadlineMs']){
  const changed=structuredClone(expected);changed[key]=key==='deadlineMs'?expected.deadlineMs+1:'0'.repeat(64);assert.throws(()=>verifyNonrootFenceAcquisitionPlan(p,changed),/NonrootFenceIndependentBinding/);
 }
});
test('no caller-selected cap, extra operation, or alternate owner can describe an acquisition',()=>{
 const f=fenceAccountingFixture();for(const change of [{authority:true},{configHash:'f'.repeat(64)},{owner:'f'.repeat(32)}])assert.throws(()=>describeNonrootFenceAcquisitionBudget({...f.spec,...change},f.issuers));
});

test('COPY payment replay requires one exact full debit between original carrier and root payments',async()=>{
 const {verifyNonrootFenceAcquisitionPayment}=await import('./lib/production-nonroot-fence-accounting.mjs');
 const {expected}=fenceAccountingFixture(),plan=createNonrootFenceAcquisitionPlan(expected),data=nonrootFenceAcquisitionPrepaymentData(plan),payment={version:1,plan},event={sequence:5,type:'prepayment',data};
 const opts={expected,events:[event],carrierSequence:4,rootSequence:6};
 assert.equal(verifyNonrootFenceAcquisitionPayment(payment,opts).sequence,5);
 for(const events of [[],[event,event],[{...event,sequence:4}],[{...event,sequence:6}],[{...event,data:{...data,charge:{...data.charge,logicalBytes:data.charge.logicalBytes-1}}}]])assert.throws(()=>verifyNonrootFenceAcquisitionPayment(payment,{...opts,events}));
 assert.throws(()=>verifyNonrootFenceAcquisitionPayment(payment,{...opts,expected:{...expected,ownerAuthorizationHash:'f'.repeat(64)}}));
});

test('the acquisition prepays all handoff calls and LOCAL without changing publisher policies',()=>{
 const b=fenceAccountingFixture('instance-metadata').budget;
 const rows=Object.entries(b.calls).filter(([k])=>k.startsWith('handoff.')).map(([,v])=>v);
 const count=action=>rows.filter(r=>r.action===action).reduce((n,r)=>n+r.count,0);
 assert.equal(count('GetObject'),14);assert.equal(count('PutObject'),5);assert.equal(count('GithubGet'),7);
 assert(rows.every(r=>r.lane==='normal'));
 assert.equal(b.limits.localPricing.normal.handoff,2180522016);
 assert(b.limits.localPricing.normal.handoffJournal>0);
 assert.equal(b.limits.feeOwnership.handoff,'this allocation');
 assert.equal(nonrootFinalizationLimits(2).localBytes,1073741824);
 assert.equal(nonrootFinalizationLimits(3).localBytes,2147483648);
 assert.equal(nonrootFinalizationLimits(3).cleanupLocalBytes,16777216);
 for(const field of ['handoff','handoffJournal']){
  const changed=structuredClone(b);changed.limits.localPricing.normal[field]--;
  assert.throws(()=>inspectNonrootFenceAcquisitionBudget(changed),/NonrootFenceBudgetChanged/);
 }
 const changed=structuredClone(b);delete changed.calls['handoff.mutex.read'];
 assert.throws(()=>inspectNonrootFenceAcquisitionBudget(changed),/NonrootFenceBudgetChanged/);
});
