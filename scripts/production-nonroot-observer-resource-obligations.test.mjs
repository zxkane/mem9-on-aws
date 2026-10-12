import {test} from 'vitest';
import assert from 'node:assert/strict';
import {fixture,replayFixture,resource,hash,canonical,OBSERVER_MUTATION_ACTIONS} from './production-nonroot-observer-resource.fixture.mjs';
const facts=f=>({plan:f.plan,policy:f.policy,layout:f.layout,quotaOriginal:f.originals[0],usageOriginal:f.originals[1],verifiedAtMs:f.verifiedAtMs});
test('five actual pure cohort constructions have identical native/public resource layout',()=>{
 const f=fixture(),native=new Map([...f.models].map(([k,m])=>{const v=structuredClone(m);delete v.runTemplates;return [k,v];}));
 assert.deepEqual(resource.describeObserverResourceLayout({...f,models:native}),f.layout);
 assert.equal(f.layout.peakCpuUnits,5*(2+4)*256);assert.equal(f.layout.peakMemoryMiB,5*(2+4)*512);
 assert.equal(f.layout.launches.length,20);assert.equal(f.layout.cases.length,5);assert.equal(Object.isFrozen(f.layout),true);
});
test('work covers two original copies, normal+2 full-input traversals and all put multiplicities',()=>{
 const f=fixture(),w=resource.observerResourceWorkBounds(f),rows=f.quote.rows.filter(r=>OBSERVER_MUTATION_ACTIONS.includes(r.action)),normal=rows.filter(r=>!r.cleanup).length;
 const copies=f.quote.rows.filter(r=>r.id.startsWith('resource-admission/')).reduce((n,r)=>n+16*r.requestBytes+16*r.responseBytes+4096,0);
 assert.ok(w.admission.logicalBytes>=resource.OBSERVER_RESOURCE_DERIVE_LOCAL+copies+32*(normal+2)*f.plan.inputsRef.bytesLength);
 assert.equal(w.materialRecords,6+4*rows.length);
 assert.ok(w.materialBytes>=rows.reduce((n,r)=>n+r.responseBytes+r.requestBytes+4*16384,0));
 assert.equal(w.admission.httpBodyBytes,0);assert.ok(w.cleanup.logicalBytes>0);
 const small=structuredClone(f.plan);small.inputsRef.bytesLength=1024;assert.ok(w.admission.logicalBytes>resource.observerResourceWorkBounds({plan:small,quote:f.quote}).admission.logicalBytes);
});
test('whole plan/quote growth and response width increase required work; invalid upper rejects',()=>{
 const f=fixture(),w=resource.observerResourceWorkBounds(f);f.plan.source.files.push({path:'/synthetic/'+'x'.repeat(8192),sha256:'f'.repeat(64),bytesLength:10});assert.ok(resource.observerResourceWorkBounds(f).admission.logicalBytes>w.admission.logicalBytes);
 f.quote.rows[0].responseBytes*=2;assert.ok(resource.observerResourceWorkBounds(f).materialBytes>w.materialBytes);f.plan.inputsRef.bytesLength=33554433;assert.throws(()=>resource.observerResourceWorkBounds(f),/ObserverResourceInputBound/);
});
for(const key of ['cpu','memory','ephemeralStorage','taskRoleArn','executionRoleArn','inferenceAcceleratorOverrides'])test('reject task resource override '+key,()=>assert.throws(()=>resource.inspectObserverResourceRunOverrides({[key]:'1'}),/ObserverResourceOverride/));
for(const key of ['cpu','memory','memoryReservation','resourceRequirements'])test('reject container resource override '+key,()=>assert.throws(()=>resource.inspectObserverResourceRunOverrides({containerOverrides:[{name:'Control',[key]:1}]}),/ObserverResourceOverride/));
test('CONTROL environment and command overrides remain data; template resources rejected',()=>{
 assert.equal(resource.inspectObserverResourceRunOverrides({containerOverrides:[{name:'Control',command:['synthetic'],environment:[{name:'PAYLOAD',value:'synthetic'}]}]}),undefined);
 const f=fixture();f.models.values().next().value.runTemplates.get('control').overrides={cpu:'4096'};assert.throws(()=>resource.describeObserverResourceLayout(f),/ObserverResourceOverride/);
});
test('layout catches service surge, task count and wrong-account image',()=>{
 for(const edit of [m=>m.create.deploymentConfiguration.maximumPercent=201,m=>m.runTemplates.get('planner').count=2,m=>m.definitions.get('baseline').containerDefinitions[0].image='example.com/not-bound@sha256:'+'a'.repeat(64)]){const f=fixture();edit(f.models.values().next().value);assert.throws(()=>resource.describeObserverResourceLayout(f),/ObserverResource/);}
});
test('fractional live values use floor quota, maximum ceil usage and integer-only output',()=>{
 const f=fixture(),v=resource.verifyObserverResourceFacts(facts(f));assert.equal(v.quotaCpuUnits,102528);assert.equal(v.usageMaximumCpuUnits,768);assert.equal(v.capacityReservation,false);assert.doesNotThrow(()=>canonical(v));
 f.originals[1].value.Datapoints[1].Maximum=0.01;assert.equal(resource.verifyObserverResourceFacts(facts(f)).usageMaximumCpuUnits,257);
});
test('unknown, stale, duplicate, average-only and wrong scope evidence all fail',()=>{
 const edits=[f=>f.originals[1].value.Datapoints=[],f=>f.policy.maxUsageAgeMs=60000,f=>f.originals[1].value.Datapoints.push(f.originals[1].value.Datapoints[0]),f=>delete f.originals[1].value.Datapoints[0].Maximum,f=>f.originals[0].value.Quota.QuotaArn+='wrong',f=>f.originals[0].value.Quota.Value=1,f=>f.originals[1].input.Statistics=['Average'],f=>f.originals[1].value.Datapoints[0].Maximum=NaN];
 for(const edit of edits){const f=fixture();edit(f);assert.throws(()=>resource.verifyObserverResourceFacts(facts(f)),/ObserverResource/);}
});
test('first admission freshness accepts preceding aligned minute; future and expired reject',()=>{
 const f=fixture();f.originals[1].startedMs+=1000;f.originals[1].completedMs+=1000;f.verifiedAtMs+=1000;assert.doesNotThrow(()=>resource.verifyObserverResourceFacts(facts(f)));
 f.verifiedAtMs+=120001;assert.throws(()=>resource.verifyObserverResourceFacts(facts(f)),/ObserverResourceOriginal/);
});
test('all mutation kinds get bounded original-owner-directory obligations including registrations',()=>{
 const f=fixture(),directory='/synthetic/claims/'+f.plan.owner+'-'+f.plan.operation;
 for(const row of f.quote.rows.filter(r=>OBSERVER_MUTATION_ACTIONS.includes(r.action))){const value=resource.describeObserverOwnershipTemplate({...f,inputHash:hash(f.input),admissionHash:'f'.repeat(64),ownerDirectory:directory,id:row.id});assert.equal(value.action,row.action);assert.equal(value.planHash,hash(f.plan));assert.equal(value.reconciliation.directory,directory);assert.ok(Buffer.byteLength(canonical(value))<=16384);assert.equal(value.authority,false);}
 assert.throws(()=>resource.describeObserverOwnershipTemplate({...f,inputHash:hash(f.input),admissionHash:'f'.repeat(64),ownerDirectory:'/imaginary',id:f.quote.rows[2].id}),/ObserverOwnershipDirectory/);
});
test('definition deletion means retirement, never physical deletion',()=>{
 const f=fixture(),id='synthetic-0/delete-definition',arn=f.ecs+'task-definition/synthetic:1',o={id,action:'DeleteTaskDefinitions',statusCode:200,startedMs:f.verifiedAtMs,completedMs:f.verifiedAtMs+1,input:{taskDefinitions:[arn]},value:{taskDefinitions:[{taskDefinitionArn:arn,status:'DELETE_IN_PROGRESS'}],failures:[]}};
 assert.deepEqual(resource.inspectObserverOwnershipResponse({plan:f.plan,obligation:{id,action:o.action},original:o}),[{kind:'definition',arn,state:'DELETE_IN_PROGRESS',physicalDeletionObserved:false}]);
});
test('run-index membership rejects a metadata ref even if global archive contains it',async()=>{
 const f=replayFixture({omitObject:({admissionRef})=>admissionRef.bytesHash});await assert.rejects(f.run,/ObserverOwnershipRunObject/);assert.equal(f.usage().reads,0);
});
test('sealed original payer after await stops before consuming decoded record',async()=>{
 const f=replayFixture({afterRead:s=>s.hold()});await assert.rejects(f.run,/OriginalPayerClosed/);assert.equal(f.usage().reads,1);
});
test('full resource replay with actual SDK/archive reader, registration response and cleanup returns DATA only',async()=>{
 const f=replayFixture();assert.deepEqual(await f.run(),{providerIds:['resource-admission/fargate-quota','resource-admission/fargate-usage']});assert.ok(f.usage().reads>75);
});
test('unexecuted but durable obligations need no invented responses',async()=>{
 const f=replayFixture({actualMutation:false});assert.equal((await f.run()).providerIds.length,2);
});
test('raw member absent from run index rejects although retained in outer archive',async()=>{
 const f=replayFixture({omitObject:({files})=>files.find(x=>x.encoding==='bytes').ref.sha256});await assert.rejects(f.run,/ObserverOwnershipRunObject/);
});
test('changed bound admission layout and capacity reject',async()=>{
 for(const field of ['layout','capacity']){const f=replayFixture({editRecord:r=>{if(r.kind==='observer-resource-admission'){if(field==='layout')r.layout={...r.layout,peakCpuUnits:r.layout.peakCpuUnits+1};else r.capacity={...r.capacity,quotaCpuUnits:r.capacity.quotaCpuUnits+1};}}});await assert.rejects(f.run,/ObserverResource(LayoutChanged|CapacityChanged)/);}
});
test('missing prewritten obligation, duplicate response and missing closure reject',async()=>{
 const edits=[records=>records.splice(records.findIndex(e=>e.kind==='ownership-obligation'),1),records=>{const at=records.findIndex(e=>e.kind==='ownership-response');records.splice(at,0,records[at]);},(_,{closed})=>closed.delete('synthetic-0/register-baseline')];
 for(const edit of edits){const f=replayFixture({editEvents:edit});await assert.rejects(f.run,/ObserverOwnership(ObligationCoverage|Response|Payment)/);}
});
test('prewritten obligations must precede provider intent, including registration',async()=>{
 const f=replayFixture({editEvents:records=>{const event=records.find(e=>e.kind==='ownership-obligation');event.sequence=records.find(e=>e.kind==='provider-intent'&&e.data.id==='synthetic-0/register-baseline').sequence+1;}});await assert.rejects(f.run,/ObserverOwnershipBeforeMutation/);
});
test('first dispatch freshness uses original provider start, not earlier intent',async()=>{
 const f=replayFixture({editEvents:(_,{providers})=>{providers.get('synthetic-0/register-baseline').startedMs+=300000;}});await assert.rejects(f.run,/ObserverResourceFirstMutationStale/);
});
test('cleanup coverage, physical deletion and exact original bindings cannot be substituted',async()=>{
 const edits=[r=>{if(r.kind==='observer-ownership-cleanup')r.obligationHashes.pop();},r=>{if(r.kind==='observer-ownership-cleanup')r.definitionDispositions=[{state:'DELETE_IN_PROGRESS',executionAuthorityRetired:true,physicalDeletionObserved:true}];},r=>{if(r.kind==='observer-ownership-response')r.bindings=r.bindings.map(v=>({...v,arn:v.arn+'wrong'}));}];
 for(const editRecord of edits){const f=replayFixture({editRecord});await assert.rejects(f.run,/ObserverOwnership(CleanupCoverage|CleanupDispositions|ResponseBinding)/);}
});
