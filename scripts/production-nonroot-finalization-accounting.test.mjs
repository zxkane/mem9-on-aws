import {test} from 'vitest';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {describeNonrootFinalizationBudget,createNonrootFinalizationPlan,nonrootFinalizationPrepaymentData,verifyNonrootFinalizationPlan,inspectNonrootFinalizationBudget,NONROOT_FINALIZATION_LIMITS} from './lib/production-nonroot-finalization-accounting.mjs';
import {verifyNonrootCacheReadAccounting} from './lib/production-nonroot-cache.mjs';
import {NONROOT_REMAINING_WORK_CAPS_V2,NONROOT_REMAINING_WORK_LIMITS_HASH_V2} from './lib/production-nonroot-budget-revision.mjs';

const zero=()=>({ecrRequests:0,logicalBytes:0,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0}),sha=b=>createHash('sha256').update(b).digest('hex');
const revision={version:2,limitsHash:NONROOT_REMAINING_WORK_LIMITS_HASH_V2,envelopeHash:hash('complete envelope'),historyHeadHash:hash('immutable history')};
function fixture({budgetVersion=2,startingLogicalBytes=0}={}){
 const scope={copyOwner:'a'.repeat(32),account:'123456789012',region:'us-east-1',runtimeNonce:'b'.repeat(32),authorizationId:'c'.repeat(32),bucket:'example-finalization',kmsKeyArn:'arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',lockKey:'runtime-publication-locks/prod/witness.json',parameterProtection:{KeyId:'alias/aws/ssm',Tier:'Standard',DataType:'text'},sourceRevision:'d'.repeat(40),sourceTree:'e'.repeat(40),rootBindingHash:hash('root'),priorParameter:{version:1,valueHash:sha('prior protected value')}};
 const issuer={source:{provider:'instance-metadata',hash:hash('authenticated original source')},scope:{account:scope.account,personalAccount:'2'.repeat(12),region:scope.region,owner:scope.authorizationId,runtimeNonce:scope.runtimeNonce,anchorOwner:'f'.repeat(32),bucket:scope.bucket,ssmKeyArn:'arn:aws:kms:us-east-1:123456789012:key/bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee',s3KeyArn:scope.kmsKeyArn,parameterProtection:scope.parameterProtection}};
 const budget=budgetVersion===2?describeNonrootFinalizationBudget(scope,issuer):describeNonrootFinalizationBudget(scope,issuer,{version:budgetVersion}),ledgerBinding={owner:scope.copyOwner,executionId:'f'.repeat(32),planHash:hash('COPY config'),publicationHash:hash('COPY publication')};
 const copyReceipt={version:2,owner:scope.copyOwner,planHash:ledgerBinding.planHash,publicationHash:ledgerBinding.publicationHash,destinationReadback:{reads:[{repositoryName:'example',digest:'sha256:'+hash('blob'),size:1,mediaType:'application/octet-stream'}]}};
 const starting={...zero(),logicalBytes:startingLogicalBytes};
 const reserve={...budget.charge,logicalBytes:budget.charge.logicalBytes+1,uncompressedBytes:3,processedEntries:3},copyCheckpoint={binding:ledgerBinding,startingCounters:{...starting},counters:{...starting},remainingReservation:reserve,eventCount:1,lastEventHash:hash('COPY sealed'),active:0,sealed:true,budgetRevision:revision};
 const start={version:2,kind:'custody-ledger-start',binding:ledgerBinding,startingCounters:{...starting},reserve,deadlineMs:123456,mode:'adoption',budgetRevision:revision},raw=Buffer.from(JSON.stringify(start)+'\n');
 const expected={budget,ledgerBinding,ledgerStartHash:sha(raw),copyCheckpointHash:hash(copyCheckpoint),archiveManifestHash:hash('actual archive'),budgetRevision:revision,deadlineMs:start.deadlineMs},plan=createNonrootFinalizationPlan(expected);
 const events=[],spent={...starting},remaining={...reserve};
 const emit=(type,data)=>{
  if(data.reserveDebit)for(const k of Object.keys(spent)){remaining[k]-=data.reserveDebit[k];spent[k]+=data.reserveDebit[k];}
  const event={version:2,sequence:events.length+1,...ledgerBinding,previousHash:events.length?hash(events.at(-1)):null,type,data,spent:{...spent},remaining:{...remaining},budgetRevision:revision};events.push(event);
 };
 const d=copyReceipt.destinationReadback.reads[0],key=d.repositoryName+'\0'+d.digest;
 emit('cache-begin',{key,descriptor:{digest:d.digest,size:d.size,mediaType:d.mediaType},origin:'completed-destination-cache',reserveDebit:{...zero(),logicalBytes:1}});emit('cache-complete',{key,digest:d.digest,physicalBytes:1});
 for(const component of ['llm-proxy','mnemo-server','qwen3-embed'])emit('filesystem',{component,phase:'adoption',uncompressedBytes:1,processedEntries:1,reserveDebit:{...zero(),uncompressedBytes:1,processedEntries:1}});
 emit('prepayment',nonrootFinalizationPrepaymentData(plan));emit('sealed',{reason:'completed'});
 const checkpoint={binding:ledgerBinding,startingCounters:start.startingCounters,counters:spent,remainingReservation:remaining,eventCount:events.length,lastEventHash:hash(events.at(-1)),active:0,sealed:true,budgetRevision:revision};
 const record={version:2,kind:'nonroot-cache-read-accounting',start,events,checkpoint,startRaw:raw.toString('base64'),fundingPlans:[],finalizationPlan:plan};
 const options={copyCheckpoint,copyReceipt,expectedBudgetRevision:revision,expectedBudgetCeiling:NONROOT_REMAINING_WORK_CAPS_V2,expectedFinalization:{budget,archiveManifestHash:expected.archiveManifestHash}};
 return {scope,issuer,budget,expected,plan,record,options};
}

test('closed publisher budget includes both fresh issuers inside the same quota and full archive maximum',()=>{
 const f=fixture();assert.equal(f.budget.archive.maximumBytes,33554432);assert.equal(f.budget.issuers.normalWireBytes,827392);assert.equal(f.budget.issuers.localBytes,33554432);
 assert.equal(f.budget.charge.httpBodyBytes,142606336);assert.equal(f.budget.additionalAfterCopy.httpBodyBytes+f.budget.archive.replacesDataArchiveWireBytes,f.budget.charge.httpBodyBytes);
 assert.equal(f.budget.issuers.sharesPublisherUnknown,true);assert.deepEqual(inspectNonrootFinalizationBudget(f.budget),f.budget);
});
test('default v2 budget, plan and replay record retain their original exact bytes',()=>{
 const f=fixture();assert.equal(NONROOT_FINALIZATION_LIMITS.localBytes,1073741824);
 assert.equal(sha(JSON.stringify(f.budget)),'57f1a60e5365dfe033e05cf703bf261a576b6ae89df66c53780984386206a9f4');
 assert.equal(sha(JSON.stringify(f.plan)),'46c7083d5488db4b8edc32be154306a56c5e016460a100312d7b9b3149762b08');
 assert.equal(sha(JSON.stringify(f.record)),'d6f312d1ac4a7822a0f67d6a0781a8d4eef8df086bc4bd3da8ef77d01c53d45f');
 assert.deepEqual(describeNonrootFinalizationBudget(f.scope,f.issuer,{version:2}),f.budget);
});
test('explicit v3 changes only version and full LOCAL allocation by one GiB',()=>{
 const old=fixture(),next=fixture({budgetVersion:3}),expected=structuredClone(old.budget);
 expected.version=3;expected.limits.localBytes=2147483648;expected.charge.logicalBytes=2147483648;expected.additionalAfterCopy.logicalBytes=2147483648;
 assert.deepEqual(next.budget,expected);assert.deepEqual(inspectNonrootFinalizationBudget(next.budget),next.budget);
 assert.equal(next.budget.limits.cleanupLocalBytes,16777216);assert.equal(next.budget.issuers.localBytes,33554432);
 assert(Object.isFrozen(next.budget.limits)&&Object.isFrozen(next.budget.limits.counts));
 const replay=verifyNonrootCacheReadAccounting(next.record,next.options);
 assert.equal(replay.counters.logicalBytes,2147483649);assert.equal(replay.counters.httpBodyBytes,old.budget.charge.httpBodyBytes);
 assert.deepEqual(replay.remainingReservation,zero());assert.notEqual(hash(old.plan),hash(next.plan));
});
test('unknown policy versions and changed v3 quotas or underpayment reject',()=>{
 const f=fixture();for(const version of [1,4,'3',null]){
  assert.throws(()=>describeNonrootFinalizationBudget(f.scope,f.issuer,{version}));
  assert.throws(()=>inspectNonrootFinalizationBudget({...f.budget,version}));
 }
 const missing=structuredClone(f.budget);delete missing.version;assert.throws(()=>inspectNonrootFinalizationBudget(missing));
 const v3=fixture({budgetVersion:3}).budget;
 for(const mutate of [x=>x.limits.localBytes++,x=>x.limits.cleanupLocalBytes++,x=>x.limits.normalWireBytes++,x=>x.limits.maxRequests++,x=>x.limits.counts['s3.PutObject']++,x=>x.charge.logicalBytes=1073741824,x=>x.additionalAfterCopy.logicalBytes=1073741824]){const bad=structuredClone(v3);mutate(bad);assert.throws(()=>inspectNonrootFinalizationBudget(bad));}
 assert.throws(()=>describeNonrootFinalizationBudget(f.scope,f.issuer,{version:3,localBytes:3221225472}));
});
test('policy substitution cannot replace the independently expected original allocation',()=>{
 const old=fixture(),next=fixture({budgetVersion:3});
 assert.throws(()=>verifyNonrootFinalizationPlan(next.plan,old.expected),/FinalizationIndependentBinding/);
 assert.throws(()=>verifyNonrootFinalizationPlan(old.plan,next.expected),/FinalizationIndependentBinding/);
 assert.throws(()=>verifyNonrootCacheReadAccounting(next.record,{...next.options,expectedFinalization:old.options.expectedFinalization}),/FinalizationIndependentBinding/);
});
test('v3 respects the exact global LOCAL boundary without borrowing or refunds',()=>{
 const limit=NONROOT_REMAINING_WORK_CAPS_V2.logicalBytes;
 assert.equal(limit,64*1073741824);
 const at=fixture({budgetVersion:3,startingLogicalBytes:limit-2147483649});
 assert.equal(verifyNonrootCacheReadAccounting(at.record,at.options).counters.logicalBytes,limit);
 const over=fixture({budgetVersion:3,startingLogicalBytes:limit-2147483648});
 assert.throws(()=>verifyNonrootCacheReadAccounting(over.record,over.options));
});
test('v3 duplicate and post-seal payments remain invalid',()=>{
 const f=fixture({budgetVersion:3}),copy=structuredClone(f.record),event=copy.events.at(-2);
 copy.events.splice(-1,0,{...structuredClone(event),sequence:event.sequence+1,previousHash:hash(event)});
 assert.throws(()=>verifyNonrootCacheReadAccounting(copy,f.options),/NonrootFinalizationPrepaymentOnce/);
 const after=structuredClone(f.record);after.events.push({...structuredClone(event),sequence:after.events.length+1,previousHash:hash(after.events.at(-1))});
 assert.throws(()=>verifyNonrootCacheReadAccounting(after,f.options),/NonrootCacheEventChain/);
});
test('actual public adoption replay accepts one closed finalization prepayment before seal',()=>{
 const f=fixture(),r=verifyNonrootCacheReadAccounting(f.record,f.options);assert.equal(r.finalizationPlanHash,hash(f.plan));assert.equal(r.counters.logicalBytes,f.budget.charge.logicalBytes+1);assert.equal(r.counters.httpBodyBytes,f.budget.charge.httpBodyBytes);
 assert.deepEqual(r.remainingReservation,zero());assert.equal(r.fundingPlanHashes,undefined);
});
for(const k of ['ledgerStartHash','archiveManifestHash','copyCheckpointHash','deadlineMs'])test('rehashed '+k+' cannot override independent publication binding',()=>{
 const f=fixture(),plan=structuredClone(f.plan);plan[k]=typeof plan[k]==='number'?plan[k]+1:hash('changed '+k);
 assert.throws(()=>verifyNonrootFinalizationPlan(plan,f.expected),/FinalizationIndependentBinding/);
});
for(const k of ['sourceRevision','sourceTree','rootBindingHash','priorParameter','parameterProtection','authorizationId'])test('protected '+k+' must match independently pinned budget',()=>{
 const f=fixture(),scope=structuredClone(f.scope);scope[k]=k==='priorParameter'?{version:2,valueHash:hash('new')}:k==='parameterProtection'?{...scope[k],KeyId:f.issuer.scope.ssmKeyArn}:typeof scope[k]==='string'?'0'.repeat(scope[k].length):{};
 const issuer=structuredClone(f.issuer);issuer.scope.parameterProtection=scope.parameterProtection;issuer.scope.owner=scope.authorizationId;
 const changed=createNonrootFinalizationPlan({...f.expected,budget:describeNonrootFinalizationBudget(scope,issuer)});
 assert.throws(()=>verifyNonrootFinalizationPlan(changed,f.expected),/FinalizationIndependentBinding/);
});
test('missing expectation, missing plan and arbitrary generic prepayment fail closed',()=>{
 const f=fixture();assert.throws(()=>verifyNonrootCacheReadAccounting(f.record,{...f.options,expectedFinalization:undefined}),/NonrootFinalizationExpected/);
 const missing=structuredClone(f.record);delete missing.finalizationPlan;assert.throws(()=>verifyNonrootCacheReadAccounting(missing,f.options),/NonrootFinalizationExpected/);
 const generic=structuredClone(f.record);generic.events.at(-2).data.planHash=hash('unapproved');assert.throws(()=>verifyNonrootCacheReadAccounting(generic,f.options),/NonrootCacheFundingEvent/);
});
test('duplicate payment and payment after sealed event are rejected independently of supplied checkpoint',()=>{
 const f=fixture(),copy=structuredClone(f.record),event=copy.events.at(-2);copy.events.splice(-1,0,{...structuredClone(event),sequence:event.sequence+1,previousHash:hash(event)});
 assert.throws(()=>verifyNonrootCacheReadAccounting(copy,f.options),/NonrootFinalizationPrepaymentOnce/);
 const after=structuredClone(f.record);after.events.push({...structuredClone(event),sequence:after.events.length+1,previousHash:hash(after.events.at(-1))});assert.throws(()=>verifyNonrootCacheReadAccounting(after,f.options),/NonrootCacheEventChain/);
});
