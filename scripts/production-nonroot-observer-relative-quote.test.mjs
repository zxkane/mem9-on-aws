// Synthetic quote DATA only. These paths and contracts cannot admit a native run.
import {test,afterEach,vi} from 'vitest';
import assert from 'node:assert/strict';
import {quoteNonrootObserverOperation,inspectNonrootObserverPlan} from './lib/production-nonroot-observer-plan.mjs';
import {quoteObserverLogPages,createObserverLogPageReplay} from './lib/production-nonroot-observer-data-logs.mjs';
import {replayNonrootArchivedData} from './lib/production-nonroot-observer-data-replay.mjs';
import {bindObserverReplayWork} from './lib/production-nonroot-observer-archive-reader.mjs';
import * as sourceApi from './lib/production-nonroot-observer-data-source.mjs';
import {inspectDataObservationPlan,describeDataObservationGeometry} from './lib/production-nonroot-data-observer.mjs';
import * as workerApi from './lib/production-nonroot-observer-worker-job.mjs';
import {OBSERVER_ACCOUNTING_V3} from './lib/production-nonroot-observer-accounting.mjs';
import {IMAGE_TRANSITION_LIMITS} from './lib/production-image-transition.mjs';
import {hash} from './lib/production-nonroot-engineering-json.mjs';

// BEGIN SYNTHETIC FIXTURE
export function relativeQuoteFixture(version=3){
 const z=()=>({ecrRequests:0,logicalBytes:0,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0}),local=n=>({...z(),logicalBytes:n});
 const owner='a'.repeat(32),operation='b'.repeat(32),account='123456789012',region='ap-northeast-1',startedMs=1700000000000;
 const names=['successful-handover','prefix-start-failure','sidecar-readiness-failure','post-liveness-regression','nonterminal-timeout'],backend=['llm-proxy','qwen3-embed','mnemo-server'],workers=['planner','executor'];
 const ref=path=>({path,sha256:'c'.repeat(64),bytesLength:1});
 const cases=names.map((name,i)=>{const started=startedMs+1000+i*18000,runtimeRoles=i===0?[...backend,...workers]:i===3?backend:[];return {name,stage:'pr-42',serviceName:'mem9-observe-'+owner.slice(0,12)+'-pr-42-'+name,family:'mem9-observe-'+owner.slice(0,12)+'-pr-42-'+name,startedMs:started,deadlineMs:started+17000,sampleTimes:[started+8000,started+10000],runtimeRoles,baselinePolls:1,cleanupPolls:1,...(version!==1?{logPollTimes:[started+15000],definitionBytes:{baseline:1,control:1,...Object.fromEntries(runtimeRoles.filter(r=>workers.includes(r)).map(r=>[r,1]))}}:{})};});
 const roleGeometry=(role,c)=>{const worker=workers.includes(role);return {role,inputBytes:1,compiledBytes:1,expandedBytes:1,compressedBytes:1,bootstrapBytes:1,files:1,fileBytes:1,episodes:2,snapshots:6,polls:10,
  ...(version===3&&!worker?{}:{executions:worker||version===1?1:2}),
  ...(version!==1?{caseName:c.name,planHash:'d'.repeat(64),compiledHash:'e'.repeat(64),filesystemLookupLocal:1,targetContainerBytes:1}:{}),
  ...(version===3?{executionScope:worker?'single-explicit-worker':'autonomous-service',...(worker?{completionLogTimes:[c.startedMs+7000]}:{})}: {})};};
 const packageCatalog={version:1,kind:'reviewed-host-package-subgraph',authority:false,completeHostClosure:false,files:[],bindings:[],fileBindings:[],literalRequires:[],esmEdges:[]};
 const sourceModel={hostCatalogPath:'/synthetic-observer/host-catalog.local.json',packageCatalogJson:JSON.stringify(packageCatalog),parserFiles:[{path:'/synthetic-observer/parser.cjs',sha256:'f'.repeat(64),bytes:1}],baseRoleArn:'arn:aws:iam::'+account+':role/synthetic-observer'};
 const plan={version,kind:'original-data-observer-operation',owner,operation,ownerRef:ref('/synthetic-observer/owner'),inputsRef:ref('/synthetic-observer/inputs'),startedMs,deadlineMs:startedMs+100000,cleanupReserveMs:1000,
  capacity:{ecrRequests:IMAGE_TRANSITION_LIMITS.maxEcrCalls,logicalBytes:IMAGE_TRANSITION_LIMITS.maxTransferredBytes,httpBodyBytes:IMAGE_TRANSITION_LIMITS.maxTransferredBytes,uncompressedBytes:IMAGE_TRANSITION_LIMITS.maxUncompressedBytes,processedEntries:IMAGE_TRANSITION_LIMITS.maxFsEntries},
  source:{files:[{...ref(sourceModel.hostCatalogPath),mode:384,uid:0}],roots:[sourceModel.hostCatalogPath],node:{...ref('/synthetic-observer/node'),mode:493,uid:0},versions:{},env:{}},
  scope:{account,personalAccount:'9'.repeat(12),region,stsRegion:'us-west-2',clusterArn:`arn:aws:ecs:${region}:${account}:cluster/synthetic`,taskRoleArns:[`arn:aws:iam::${account}:role/synthetic-worker`],logGroupArns:[`arn:aws:logs:${region}:${account}:log-group:/synthetic/worker`],rootParameterArn:`arn:aws:ssm:${region}:${account}:parameter/synthetic/root`,discoveryServiceArns:[`arn:aws:servicediscovery:${region}:${account}:service/srv-synthetic`],sourceCredentialsRef:ref('/synthetic-observer/credentials'),sourceExpiresMs:startedMs+100000,baseRoleArn:sourceModel.baseRoleArn},cases,
  geometry:{sourcePassLocal:1048576,sourcePreparation:local(1048576),roles:version===1?[...backend,...workers].map(role=>roleGeometry(role,cases[0])):cases.flatMap(c=>[...backend,...c.runtimeRoles.filter(role=>workers.includes(role))].map(role=>roleGeometry(role,c))),cache:z(),prerequisiteReplay:z(),materialBytes:1,materialRecords:1,rawPageBytes:4096,listPages:1,taskLimit:2,logPages:1,logPolls:1,logEvents:8,maxMessageBytes:1024,issuerSourceBytes:1,contextSourceBytes:1,
   control:{source:z(),cache:z(),proof:z(),runtime:z(),rawDeliveryBytes:1024,compressedDeliveryBytes:512,taskPolls:1,logPages:1},...(version===3?{admission:local(1),admissionCleanup:local(1)}:{})},
  ...(version===3?{accounting:structuredClone(OBSERVER_ACCOUNTING_V3)}:{})};
 return {plan,sourceModel};
}
// END SYNTHETIC FIXTURE
const work=()=>({assertCurrent(){},chargeLocal(n){assert(Number.isSafeInteger(n)&&n>=0);}});
const quote=f=>quoteNonrootObserverOperation(f.plan,{sourceModel:f.sourceModel,work:work()});
const geometry={rawPageBytes:4096,logPolls:1,logPages:1,logEvents:8,maxMessageBytes:1024,captures:2};
const LEGACY_QUOTE_HASHES={
 1:'dee0a7b7ee2a0fda23dd58231d826ee4d37d12ef7aa42164a52e664a7d000a05',
 2:'82d44d468b3c8c08ad7c00236be066f71c5a217f0080883e12421af88bd626be',
 3:'545450cdd4c7dc36d2dc69f81ea4464e1c7e7f6c83c1d76925207e548da07850',
};
afterEach(()=>vi.restoreAllMocks());

for(const version of [1,2,3])test('unmarked observation V1 keeps the exact outer v'+version+' quote golden',()=>{
 assert.equal(hash(quote(relativeQuoteFixture(version))),LEGACY_QUOTE_HASHES[version]);
});
test('log V1 default and explicit selectors retain every original field and charge',()=>{
 const fields={pages:1,rawBytes:4096,captures:2,maxGuardCalls:7,guardLocal:114688};
 for(const worker of [false,true]){const expected={logicalBytes:worker?39527424:38478848,...fields};assert.deepEqual(quoteObserverLogPages(geometry,worker),expected);assert.deepEqual(quoteObserverLogPages(geometry,worker,1),expected);}
});
test('log V2 adds the bounded anchor traversal without adding geometry or quote fields',()=>{
 const old=quoteObserverLogPages(geometry,true),current=quoteObserverLogPages(geometry,true,2);
 assert.deepEqual(current,{...old,logicalBytes:old.logicalBytes+2293760});
});
for(const version of [null,0,3,'2',false])test('log rejects invalid observation version '+String(version),()=>{assert.throws(()=>quoteObserverLogPages(geometry,true,version),/ObservationVersion/);});
test('log V2 cannot select a non-worker tariff or smuggle extra geometry',()=>{
 assert.throws(()=>quoteObserverLogPages(geometry,false,2),/ObservationVersion/);
 assert.throws(()=>quoteObserverLogPages({...geometry,observationVersion:2},true,2));
});
test('bound worker version selects the same INTERNAL replay quote before page reads',()=>{
 const spy=vi.spyOn(workerApi,'observerWorkerAnchorLocal');
 createObserverLogPageReplay({binding:'a'.repeat(64),stream:'synthetic',group:'/synthetic',startedMs:1,endMs:1000,geometry,worker:{observationVersion:2}});
 assert.deepEqual(spy.mock.calls,[[2]]);
});
test('borrowed worker version getters and proxies are refused without being evaluated',()=>{
 let reads=0;const worker={get observationVersion(){reads++;return 2;}};
 const descriptor={binding:'a'.repeat(64),stream:'synthetic',group:'/synthetic',startedMs:1,endMs:1000,geometry,worker};
 assert.throws(()=>createObserverLogPageReplay(descriptor));assert.equal(reads,0);
 assert.throws(()=>createObserverLogPageReplay({...descriptor,worker:new Proxy({observationVersion:2},{})}));
});
test('V2 adds launch, log parsing and independent proof replay on original rows only',()=>{
 const f=relativeQuoteFixture(),old=quote(f),before=hash(f.plan),workers=f.plan.geometry.roles.filter(r=>['planner','executor'].includes(r.role));
 workers.forEach(r=>r.observationVersion=2);const current=quote(f);assert.notEqual(hash(f.plan),before);
 assert.deepEqual(current.rows.map(r=>r.id),old.rows.map(r=>r.id));assert.deepEqual(current.journal,old.journal);
 const expected=new Map([['replay',2*(2293760+2342912)]]);
 for(const r of workers){expected.set(r.caseName+'/launch/'+r.role+'/0',2342912);expected.set(r.caseName+'/log-work/'+r.role,2293760);}
 for(const row of current.rows){const prior=old.rows.find(r=>r.id===row.id);assert.deepEqual(row,{...prior,charge:{...prior.charge,logicalBytes:prior.charge.logicalBytes+(expected.get(row.id)??0)}});}
 assert.deepEqual(current.total,{...old.total,logicalBytes:old.total.logicalBytes+18546688});
 const base=current.total.logicalBytes;f.plan.processingPolicy={version:2,kind:'source-quoted-cumulative-processing',maximumLocal:base+18432};f.plan.capacity.logicalBytes=base+18432;
 assert.equal(quote(f).total.logicalBytes,f.plan.processingPolicy.maximumLocal);
});
for(const [name,edit]of [
 ['backend marker',p=>p.geometry.roles[0].observationVersion=2],
 ...[1,null,0,3,'2',false].map(value=>['invalid marker '+String(value),p=>p.geometry.roles.find(r=>r.role==='planner').observationVersion=value]),
])test('plan refuses '+name,()=>{const f=relativeQuoteFixture();edit(f.plan);assert.throws(()=>inspectNonrootObserverPlan(f.plan,{sourceModel:f.sourceModel,work:work()}),/ObservationVersion/);});
for(const version of [1,2])test('valid legacy outer v'+version+' refuses a worker V2 marker',()=>{
 const f=relativeQuoteFixture(version);assert.doesNotThrow(()=>quote(f));
 f.plan.geometry.roles.find(r=>r.role==='planner').observationVersion=2;
 assert.throws(()=>inspectNonrootObserverPlan(f.plan,{sourceModel:f.sourceModel,work:work()}),/ObservationVersion/);
});
test('relative quote rejects unsafe totals and an unavailable current replay payer',()=>{
 const f=relativeQuoteFixture(),r=f.plan.geometry.roles.find(r=>r.role==='planner');r.observationVersion=2;r.snapshots=Number.MAX_SAFE_INTEGER;
 assert.throws(()=>quote(f));
 assert.throws(()=>quoteNonrootObserverOperation(f.plan,{sourceModel:f.sourceModel,work:{assertCurrent(){throw Error('CurrentPayerHeld');},chargeLocal(){throw Error('must not charge');}}}),/CurrentPayerHeld/);
});

// Isolate only the authenticated source accessor. The original replay entry
// and payer adapter run unchanged; no archive IO or runtime proof is supplied.
function replayPaymentFixture(version,balance,{retireOnCharge=false}={}){
 const {plan}=relativeQuoteFixture(),casePlan=plan.cases[0],role='planner',source={},charges=[];
 const r=plan.geometry.roles.find(r=>r.role===role);if(version===2)r.observationVersion=2;
 const image={rootDigest:'sha256:'+'1'.repeat(64),arm64Digest:'sha256:'+'2'.repeat(64),configDigest:'sha256:'+'3'.repeat(64)};
 const target={name:'synthetic-worker',logConfiguration:{logDriver:'awslogs',options:{'awslogs-region':plan.scope.region,'awslogs-group':'/synthetic/worker','awslogs-stream-prefix':'observer'}}};
 const observation=inspectDataObservationPlan({version,kind:'bounded-data-observation',...(version===2?{clock:'observed-worker-exec'}:{}),owner:plan.owner,operation:plan.operation,launchNonce:'5'.repeat(32),sourceTree:'6'.repeat(40),role,image,
  startedMs:casePlan.startedMs,latestArmMs:casePlan.startedMs+1000,observationEndMs:casePlan.deadlineMs-1000,deadlineMs:casePlan.deadlineMs,armingLimitMs:100,cleanupReserveMs:1000,
  episodes:[{index:0,offsetMs:2000,durationMs:100,sampleEveryMs:100},{index:1,offsetMs:4000,durationMs:100,sampleEveryMs:100}],limits:{readBytes:268435456,rawBytes:1048576,initialProcesses:128,finalProcesses:128,combinedIdentities:256}});
 const contract={target,binding:'3'.repeat(64),plan:observation,snapshotCount:describeDataObservationGeometry(observation).totalSnapshotCount};assert.equal(contract.snapshotCount,r.snapshots);
 const definition={containerDefinitions:[target]},definitionArn=`arn:aws:ecs:${plan.scope.region}:${plan.scope.account}:task-definition/synthetic:1`;
 const task={taskArn:`arn:aws:ecs:${plan.scope.region}:${plan.scope.account}:task/synthetic/task`,taskDefinitionArn:definitionArn,enableExecuteCommand:false,containers:[{name:target.name,runtimeId:'synthetic-runtime',imageDigest:image.rootDigest}]};
 const capture={version:1,kind:'original-data-observation-log-capture',authority:false,owner:plan.owner,caseName:casePlan.name,role,taskArn:task.taskArn,runtimeId:'synthetic-runtime',definitionArn,definitionHash:hash(definition),sourceBinding:contract.binding,stream:'observer/synthetic-worker/task',pages:[],captures:[],rawPageBytes:0,eventCount:0,nonObservationBytes:0,nonObservationHash:'4'.repeat(64),observerRetirementObserved:false};
 let current=true,reads=0;
 const paid=bindObserverReplayWork({assertCurrent(){assert(current,'CurrentReplayHeld');},chargeLocal(n){assert(n<=balance,'CurrentReplayCapacity');balance-=n;charges.push(n);if(retireOnCharge)current=false;}});
 const reader={paid,current:paid.current,readBytes(){reads++;throw Error('UnexpectedArchiveRead');}};
 vi.spyOn(sourceApi,'requireNonrootObserverDataSources').mockImplementation((candidate,options)=>{assert.equal(candidate,source);assert.equal(options.reader,reader);return {plan,contracts:new Map([[casePlan.name+'/'+role,contract]])};});
 return {run:()=>replayNonrootArchivedData({version:1,kind:'original-observer-DATA-replay-input',capture,outputs:[]},{reader,source,casePlan,definition,task,providers:new Map(),objects:new Map(),recordedMs:casePlan.startedMs}),charges,get reads(){return reads;},get balance(){return balance;}};
}
test('current archived replay keeps V1 prepayment exact and retains it on a later refusal',async()=>{
 const amount=39527424+workerApi.OBSERVER_WORKER_BIND_LOCAL,f=replayPaymentFixture(1,amount);
 await assert.rejects(f.run(),/ObserverWorkerOriginalRequest/);
 assert.deepEqual(f.charges,[amount]);assert.equal(f.balance,0);assert.equal(f.reads,0);
});
test('current archived V2 replay prepays parser and independent proof before consuming DATA',async()=>{
 const amount=39527424+workerApi.OBSERVER_WORKER_BIND_LOCAL+2293760+2342912,f=replayPaymentFixture(2,amount);
 await assert.rejects(f.run(),/ObserverWorkerOriginalRequest/);
 assert.equal(f.charges.reduce((n,v)=>n+v,0),amount);assert.equal(f.balance,0);assert.equal(f.reads,0);
});
test('native escrow cannot replace insufficient CURRENT replay proof prepayment',async()=>{
 const amount=39527424+workerApi.OBSERVER_WORKER_BIND_LOCAL+2293760,f=replayPaymentFixture(2,amount);
 await assert.rejects(f.run(),/CurrentReplayCapacity/);assert.equal(f.reads,0);
});
test('current replay rechecks retirement after payment without refund or archive IO',async()=>{
 const amount=39527424+workerApi.OBSERVER_WORKER_BIND_LOCAL,f=replayPaymentFixture(1,amount,{retireOnCharge:true});
 await assert.rejects(f.run(),/CurrentReplayHeld/);assert.equal(f.balance,0);assert.deepEqual(f.charges,[amount]);assert.equal(f.reads,0);
});
