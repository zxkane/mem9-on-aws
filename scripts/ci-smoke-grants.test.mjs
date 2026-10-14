import {rootPrerequisiteProfileDelta} from './lib/production-nonroot-prerequisites.mjs';
import {it,expect,vi,afterEach} from 'vitest';
import {readFileSync} from 'node:fs';
import {createFutureFundingPlan,inspectFutureFundingPlan,verifyFutureGrantSet,inspectFutureCallProfiles,createFutureSourceReader,FUTURE_OWNER_PUBLICATION} from './lib/ci-smoke-grants.mjs';
import * as grants from './lib/ci-smoke-grants.mjs';
import {NONROOT_REMAINING_WORK_LIMITS_HASH_V2} from './lib/production-nonroot-budget-revision.mjs';
import {CI_SMOKE_ARCHIVE_LIMITS} from './lib/ci-smoke-private-archive.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {sha,zero,addCounters,replayAccounting} from './lib/ci-smoke-acquisition-format.mjs';
import {ROOT_OWNER_CATALOG,ROOT_OWNER_POOL_POLICY} from './lib/production-nonroot-root-owner-accounting.mjs';

afterEach(()=>vi.restoreAllMocks());
const identity=()=>({version:1,id:'identity',kind:'EXACT',action:'GetCallerIdentity',request:{},requestBytes:1024,responseBytes:4096,count:1,ecr:false});
const rootPhases=[[9,'preupdate'],[17,'preconfigure'],[19,'presst'],[21,'preupdate'],[23,'prereadiness']];
function rootTemplate(){
 const old=profileTemplate(),f=fixture(),target=old.consumers[1];
 const template={...old,version:2,consumers:[old.consumers[0],...rootPhases.map(([n,phase])=>({...structuredClone(target),scope:{kind:'target',jobKey:'deploy-prod',route:'deploy-prod',phase,checkpoint:'deploy-prod/'+n}}))]};
 template.owner={...old.owner,roots:{version:1,kind:'future-owner-root-template',rootBindingHash:f.input.binding.anchors.rootBindingHash,carrierTemplateHash:hash({synthetic:'carrier-template'}),carrierSlot:{owner:f.catalog.ledgerBinding.owner,executionId:f.catalog.ledgerBinding.executionId,slotNonce:'d'.repeat(32)},source:f.catalog.source}};
 return {template,f};
}
it('R14 reserves exactly five actual TARGET root quotas in all budget counters',()=>{
 const {template}=rootTemplate(),without={...structuredClone(template),version:1};delete without.owner.roots;
 const before=grants.measureFutureProfileTemplateBudget(without),after=grants.measureFutureProfileTemplateBudget(template);
 expect(after.ecrRequests-before.ecrRequests).toBe(5*29);
 expect(after.logicalBytes-before.logicalBytes).toBe(5*134217728);
 expect(after.httpBodyBytes-before.httpBodyBytes).toBe(5*52838400);
 expect(after.uncompressedBytes).toBe(before.uncompressedBytes);expect(after.processedEntries).toBe(before.processedEntries);
});
for(const [name,change]of [
 ['missing checkpoint',t=>t.consumers.pop()],['extra target',t=>t.consumers.push({...structuredClone(t.consumers[1]),scope:{...t.consumers[1].scope,checkpoint:'deploy-prod/999'}})],
 ['wrong /9 phase',t=>t.consumers[1].scope.phase='prereadiness'],['wrong /21 phase',t=>t.consumers[4].scope.phase='presst'],
 ['wrong route',t=>t.consumers[1].scope.route='runtime-cutover-prod'],['wrong job',t=>t.consumers[1].scope.jobKey='other-job'],
 ['caller count',t=>t.owner.roots.count=1],['caller budget',t=>t.owner.roots.budget=zero()],['caller cleanup',t=>t.owner.roots.cleanupLocalBytes=0],
 ['premature carrier build',t=>t.owner.roots.carrierBuildHash='a'.repeat(64)],['future proof',t=>t.owner.roots.proofHash='a'.repeat(64)],
 ['future run',t=>t.owner.roots.runId=1],['bad carrier slot',t=>t.owner.roots.carrierSlot.slotNonce=null],['missing roots',t=>delete t.owner.roots],
])it('R14 closed root template rejects '+name,()=>{const {template}=rootTemplate();change(template);expect(()=>grants.measureFutureProfileTemplateBudget(template)).toThrow();});
function rootFunding(){
 const {template,f}=rootTemplate(),catalog={...f.catalog,...template,kind:'future-ci-profile-catalog'},roots=template.owner.roots;
 const input={...f.input,catalogRaw:Buffer.from(JSON.stringify(catalog)).toString('base64')};
 const rootCarrier={...roots,kind:'future-owner-root-carrier',carrierBuildHash:hash({synthetic:'actual-carrier'}),image:{account:'123456789012',region:'us-west-2',repositoryName:'mem9-on-aws/preview/bootstrap',rootDigest:'sha256:'+'a'.repeat(64),arm64Digest:'sha256:'+'b'.repeat(64),configDigest:'sha256:'+'c'.repeat(64)}};
 const plan=createFutureFundingPlan({...input,rootCarrier});return {template,f,catalog,input,rootCarrier,plan};
}
it('future roots bind the core 163 plus fixed collector catalog with the explicit two-ECR delta',()=>{
 const {plan}=rootFunding(),roots=plan.owner.roots;
 expect(Object.entries(ROOT_OWNER_CATALOG).filter(([k])=>!k.startsWith('prerequisite.')&&!k.startsWith('health.')).reduce((n,[,r])=>n+r.count,0)).toBe(163);
 const fixedCollectors=Object.values(ROOT_OWNER_CATALOG).filter(r=>r===ROOT_OWNER_CATALOG['prerequisite.securityGroups']);
 expect(fixedCollectors).toEqual([{service:'ec2',action:'DescribeSecurityGroups',count:2,requestBytes:16384,responseBytes:1048576,lane:'normal'}]);
 expect(Object.values(ROOT_OWNER_CATALOG).reduce((n,r)=>n+r.count,0)).toBe(163+rootPrerequisiteProfileDelta().calls);
 expect(rootPrerequisiteProfileDelta().calls).toBe(362);
 expect(roots.catalogHash).toBe(hash(ROOT_OWNER_CATALOG));expect(roots.policy).toEqual(ROOT_OWNER_POOL_POLICY);
 expect(roots.policyHash).toBe(hash(ROOT_OWNER_POOL_POLICY));expect(inspectFutureFundingPlan(plan).planHash).toBe(hash(plan));
 expect(roots.slots).toHaveLength(5);
 for(const slot of roots.slots)expect(slot.budget).toEqual({ecrRequests:29,logicalBytes:134217728,httpBodyBytes:52838400,uncompressedBytes:0,processedEntries:0});
});
for(const [name,change]of [
 ['old 155-operation catalog',c=>{for(const k of Object.keys(c))if(k.startsWith('prerequisite.')||k.startsWith('health.')||['issuer.sourceToken','issuer.sourceCredentials'].includes(k))delete c[k];}],
 ['old 163-operation catalog without collector funding',c=>{for(const k of Object.keys(c))if(k.startsWith('prerequisite.')||k.startsWith('health.'))delete c[k];}],
 ['same count with different IMDS allocation',c=>{c['issuer.sourceToken'].count--;c['issuer.sourceCredentials'].count++;}],
 ['same count with a larger response cap',c=>{c['issuer.sourceCredentials'].responseBytes++;}],
])it('R16 rejects '+name+' even with self-consistent replacement policy hashes',()=>{
 const plan=structuredClone(rootFunding().plan),catalog=structuredClone(ROOT_OWNER_CATALOG);change(catalog);
 const roots=plan.owner.roots;roots.catalogHash=hash(catalog);roots.policy.catalogHash=roots.catalogHash;roots.policyHash=hash(roots.policy);
 expect(()=>inspectFutureFundingPlan(plan)).toThrow();
});
it('R14 plan needs real late carrier data, commits it and derives distinct phase-bound slots',()=>{
 const {template,input,rootCarrier,plan}=rootFunding();expect(()=>createFutureFundingPlan(input)).toThrow();expect(plan.version).toBe(2);expect(plan.rootCarrier).toEqual(rootCarrier);
 expect(plan.budget).toEqual(grants.measureFutureProfileTemplateBudget(template));
 expect(plan.owner.roots.slots.map(s=>[s.scope.checkpoint,s.scope.phase])).toEqual(rootPhases.map(([n,p])=>['deploy-prod/'+n,p]));
 expect(inspectFutureFundingPlan(plan).planHash).toBe(hash(plan));
 for(const key of ['rootBindingHash','carrierTemplateHash','source','carrierSlot']){
  const bad=structuredClone(rootCarrier);bad[key]=key==='source'?{...bad.source,candidateTree:'f'.repeat(40)}:key==='carrierSlot'?{...bad.carrierSlot,executionId:'f'.repeat(32)}:'f'.repeat(64);
  expect(()=>createFutureFundingPlan({...input,rootCarrier:bad})).toThrow();
 }
 const changed=structuredClone(plan);changed.owner.roots.slots[0].budget.httpBodyBytes--;expect(()=>inspectFutureFundingPlan(changed)).toThrow();
});
function rootGrant(){
 const f=rootFunding(),start=structuredClone(f.f.grantSet.debit.start);start.reserve={ecrRequests:1000,logicalBytes:2000000000,httpBodyBytes:2000000000,uncompressedBytes:10000000,processedEntries:1000};
 const startRaw=Buffer.from(JSON.stringify(start)+'\n'),plan=createFutureFundingPlan({...f.input,rootCarrier:f.rootCarrier,ledgerStartHash:sha(startRaw)}),funding=inspectFutureFundingPlan(plan);
 const prior=structuredClone(f.f.grantSet.debit.events.slice(0,-1));for(const event of prior)event.remaining={...start.reserve};prior[1].previousHash=hash(prior[0]);
 const spent=addCounters(prior.at(-1).spent,plan.budget),remaining=Object.fromEntries(Object.keys(zero()).map(k=>[k,start.reserve[k]-plan.budget[k]]));
 const paid={version:1,sequence:prior.length+1,...start.binding,previousHash:hash(prior.at(-1)),type:'prepayment',data:{allocationId:funding.planHash,planHash:funding.planHash,scopeHash:funding.scopeHash,charge:plan.budget,reserveDebit:plan.budget},spent,remaining};
 const events=[...prior,paid],checkpoint={binding:start.binding,startingCounters:start.startingCounters,counters:spent,remainingReservation:remaining,eventCount:events.length,lastEventHash:hash(paid),active:0,sealed:false};
 const grantSet={...plan,version:3,kind:'owner-prepaid-future-grant-set',authority:false,allocationId:funding.planHash,planHash:funding.planHash,debit:{start,startRaw:startRaw.toString('base64'),events,checkpoint}};
 return {grantSet,expected:{grantSetId:plan.grantSetId,grantHash:hash(grantSet),ledgerStartHash:plan.ledgerStartHash,catalogHash:plan.catalogHash}};
}
it('R14 v3 grant replays the real-shaped full debit prefix and selects five distinct owner allocations without another debit',()=>{
 const f=rootGrant(),before=JSON.stringify(f.grantSet),funded=verifyFutureGrantSet(f),ids=new Set();expect(funded.rootCarrier).toEqual(f.grantSet.rootCarrier);
 expect(funded.owner.roots.budget).toEqual({ecrRequests:145,logicalBytes:671088640,httpBodyBytes:264192000,uncompressedBytes:0,processedEntries:0});
 for(const slot of funded.owner.roots.slots){const allocation=grants.selectFutureOwnerRootAllocation({...f,scope:slot.scope});ids.add(allocation.allocationId);expect(allocation.budget).toEqual(slot.budget);expect(allocation.authority).toBe(false);expect(allocation.debitEventHash).toBe(hash(f.grantSet.debit.events.at(-1)));expect(allocation.policy.cleanupLocalBytes).toBeGreaterThan(0);expect(allocation.policy.cleanupLocalBytes).toBeLessThan(allocation.policy.localBytes);}
 expect(ids.size).toBe(5);expect(JSON.stringify(f.grantSet)).toBe(before);
 const scope=funded.owner.roots.slots[0].scope;expect(()=>grants.selectFutureOwnerRootAllocation({...f,scope:{...scope,phase:'presst'}})).toThrow();expect(()=>grants.selectFutureOwnerRootAllocation({...f,scope:{...scope,checkpoint:'deploy-prod/21'}})).not.toThrow();
});
for(const [name,change]of [
 ['missing original debit',g=>g.debit.events.pop()],['root budget subtracted',g=>g.budget.httpBodyBytes-=52838400],
 ['omitted root allocation',g=>g.owner.roots.slots.pop()],['phase alias',g=>g.owner.roots.slots[0].scope.phase='presst'],
 ['cleanup starvation',g=>g.owner.roots.policy.cleanupLocalBytes=0],['increased normal quota',g=>g.owner.roots.policy.normalWireBytes++],
 ['catalog substitution',g=>{const c=JSON.parse(Buffer.from(g.catalogRaw,'base64'));c.owner.roots.carrierTemplateHash='f'.repeat(64);g.catalogRaw=Buffer.from(JSON.stringify(c)).toString('base64');}],
 ['late root mismatch',g=>g.rootCarrier.rootBindingHash='f'.repeat(64)],['late source mismatch',g=>g.rootCarrier.source.candidateTree='f'.repeat(40)],
 ['receipt paid flag',g=>g.debit.paid=true],['version downgrade',g=>g.version=2],
])it('R14 v3 independent verification rejects '+name,()=>{const f=structuredClone(rootGrant());change(f.grantSet);f.expected.grantHash=hash(f.grantSet);expect(()=>verifyFutureGrantSet(f)).toThrow();});
function targetProfiles(){return [
 {version:1,id:'tasks',kind:'EXACT',action:'ListTasks',request:{cluster:'synthetic-cluster',serviceName:'synthetic-service',desiredStatus:'RUNNING',maxResults:2},requestBytes:1024,responseBytes:4096,count:1,ecr:false},
 {version:1,id:'describe',kind:'CURRENT_TASKS_FROM_SCOPED_LIST',action:'DescribeTasks',request:{cluster:'synthetic-cluster',include:['TAGS']},late:{field:'tasks',fromProfile:'tasks',maxItems:2},requestBytes:1024,responseBytes:8192,count:1,ecr:false},
 {version:1,id:'definition',kind:'DEFINITION_FROM_VALIDATED_TASK_OR_SERVICE',action:'DescribeTaskDefinition',request:{include:['TAGS']},late:{field:'taskDefinition',fromProfile:'describe',source:'task'},requestBytes:1024,responseBytes:16384,count:2,ecr:false},
 {version:1,id:'control',kind:'CONTROL_ARTIFACT_FROM_AUTHENTICATED_BUILD',action:'BatchGetImage',request:{registryId:'123456789012',repositoryName:'mem9-on-aws/bootstrap'},late:{field:'imageIds',buildContractKey:'deployed-bootstrap',artifact:'root'},requestBytes:1024,responseBytes:16384,count:1,ecr:true},
 ];}
function fixture(){
 const source={repository:'example/repository',prNumber:17,candidateRevision:'a'.repeat(40),candidateTree:'b'.repeat(40),baseRevision:'c'.repeat(40)};
 const ledgerBinding={owner:'a'.repeat(32),executionId:'b'.repeat(32),planHash:hash({synthetic:'completed-copy-plan'}),publicationHash:hash({synthetic:'completed-copy-publication'})};
 const copyCheckpoint={binding:ledgerBinding,startingCounters:zero(),counters:{...zero(),ecrRequests:4,httpBodyBytes:4096},remainingReservation:{ecrRequests:100,logicalBytes:100000000,httpBodyBytes:500000000,uncompressedBytes:10000000,processedEntries:1000},eventCount:1,lastEventHash:hash({synthetic:'copy-terminal'}),active:0,sealed:true};
 const issuedMs=1700000000000,start={version:1,kind:'custody-ledger-start',binding:ledgerBinding,startingCounters:copyCheckpoint.counters,reserve:copyCheckpoint.remainingReservation,deadlineMs:issuedMs+2700000,mode:'adoption'},startRaw=Buffer.from(JSON.stringify(start)+'\n');
 const binding={grantSetId:hash({synthetic:'grant'}),source,anchors:{predecessorParameterHash:hash({synthetic:'expired-predecessor'}),rootBindingHash:hash({synthetic:'preserved-root'}),copyCheckpointHash:hash(copyCheckpoint),authorizationId:'e'.repeat(32),nextParameterVersion:2}};
 const catalog={version:1,kind:'future-ci-profile-catalog',source,ledgerBinding,
  consumers:[{scope:{kind:'source',jobKey:'build-image-transition-control',route:'build-image-transition-control',phase:'source',checkpoint:'build-image-transition-control/source'},reader:{version:1,kind:'source-two-reader',terminalResponseBytes:4096},localBudget:{...zero(),logicalBytes:31}},
   {scope:{kind:'target',jobKey:'deploy-prod',route:'deploy-prod',phase:'presst',checkpoint:'deploy-prod/19'},profiles:targetProfiles(),localBudget:{...zero(),logicalBytes:37},handshake:{terminalResponseBytes:8192}}],
  owner:{publication:FUTURE_OWNER_PUBLICATION,localBudget:{...zero(),logicalBytes:41}},finalization:{profiles:[identity()],localBudget:{...zero(),logicalBytes:43}},localBudget:{...zero(),logicalBytes:47}};
 const input={binding,catalogRaw:Buffer.from(JSON.stringify(catalog)+'\n').toString('base64'),ledgerStartHash:sha(startRaw),ownerGithubActorId:42,ownerStateDirectory:'/synthetic/adoption/grant-'+binding.grantSetId,issuedMs};
 const plan=createFutureFundingPlan(input),funding=inspectFutureFundingPlan(plan),events=[];let spent={...start.startingCounters},remaining={...start.reserve};
 const append=(type,data)=>{const event={version:1,sequence:events.length+1,...ledgerBinding,previousHash:events.length?hash(events.at(-1)):null,type,data,spent:{...spent},remaining:{...remaining}};events.push(event);return event;};
 append('reservation',{id:1,action:'GetCallerIdentity',requestHash:hash({}),bound:4096,ecr:false,reserveDebit:zero()});spent=addCounters(spent,{...zero(),httpBodyBytes:256});append('completed',{id:1,charged:256,responseHash:hash({synthetic:'identity'})});
 spent=addCounters(spent,plan.budget);remaining=Object.fromEntries(Object.entries(remaining).map(([k,v])=>[k,v-plan.budget[k]]));
 append('prepayment',{allocationId:funding.planHash,planHash:funding.planHash,scopeHash:funding.scopeHash,charge:plan.budget,reserveDebit:plan.budget});
 const checkpoint={binding:ledgerBinding,startingCounters:start.startingCounters,counters:spent,remainingReservation:remaining,eventCount:events.length,lastEventHash:hash(events.at(-1)),active:0,sealed:false};
 const debit={start,startRaw:startRaw.toString('base64'),events,checkpoint};
 const grantSet={...plan,version:2,kind:'owner-prepaid-future-grant-set',authority:false,planHash:funding.planHash,allocationId:funding.planHash,debit};
 const expected={grantSetId:plan.grantSetId,grantHash:hash(grantSet),ledgerStartHash:plan.ledgerStartHash,catalogHash:plan.catalogHash};
 return {input,catalog,plan,funding,grantSet,expected,copyCheckpoint,append};
}
function badGrant(f,change){const grantSet=structuredClone(f.grantSet);change(grantSet);return {grantSet,expected:{...f.expected,grantHash:hash(grantSet)}};}

function profileTemplate(){
 return {version:1,kind:'production-future-profile-template',consumers:[
  {scope:{kind:'source',jobKey:'build-image-transition-control',route:'build-image-transition-control',phase:'source',checkpoint:'build-image-transition-control/source'},reader:{version:1,kind:'source-two-reader',terminalResponseBytes:4096},localBudget:{...zero(),logicalBytes:31}},
  {scope:{kind:'target',jobKey:'deploy-prod',route:'deploy-prod',phase:'presst',checkpoint:'deploy-prod/19'},profiles:targetProfiles(),localBudget:{...zero(),logicalBytes:37},handshake:{terminalResponseBytes:8192}},
 ],owner:{publication:FUTURE_OWNER_PUBLICATION,localBudget:{...zero(),logicalBytes:41}},finalization:{profiles:[identity()],localBudget:{...zero(),logicalBytes:43}},localBudget:{...zero(),logicalBytes:47}};
}
it('measures the complete template SUM without any ledger, source, hash, clock or grant',()=>{
 const template=profileTemplate(),before=JSON.stringify(template);
 vi.spyOn(Date,'now').mockImplementation(()=>{throw Error('NoClockAllowed');});
 const budget=grants.measureFutureProfileTemplateBudget(template);
 expect(budget).toEqual({ecrRequests:1,logicalBytes:35212487,httpBodyBytes:93932544,uncompressedBytes:0,processedEntries:0});
 expect(Object.isFrozen(budget)).toBe(true);expect(JSON.stringify(template)).toBe(before);
});
it('template measurement and funding share owner/consumer/handshake/finalization/local accounting',()=>{
 const f=fixture(),template=profileTemplate();expect(grants.measureFutureProfileTemplateBudget(template)).toEqual(f.plan.budget);
 const larger=structuredClone(template);larger.consumers[0].reader.terminalResponseBytes+=1024;larger.consumers[1].handshake.terminalResponseBytes+=1024;
 larger.owner.localBudget.logicalBytes+=17;larger.finalization.localBudget.uncompressedBytes=23;larger.localBudget.processedEntries=5;
 const budget=grants.measureFutureProfileTemplateBudget(larger);
 // Below the existing 16KiB pending-response floor, the target GET allowance
 // stays fixed; only its owner write/readback grows. Source has three bodies.
 expect(budget.logicalBytes-f.plan.budget.logicalBytes).toBe(5*1024+17);expect(budget.httpBodyBytes-f.plan.budget.httpBodyBytes).toBe(5*1024);
 expect(budget.uncompressedBytes).toBe(23);expect(budget.processedEntries).toBe(5);
 const catalog={...f.catalog,consumers:larger.consumers,owner:larger.owner,finalization:larger.finalization,localBudget:larger.localBudget};
 expect(createFutureFundingPlan({...f.input,catalogRaw:Buffer.from(JSON.stringify(catalog)).toString('base64')}).budget).toEqual(budget);
 const floor=structuredClone(template);floor.consumers[1].handshake.terminalResponseBytes=16384;
 const above=structuredClone(floor);above.consumers[1].handshake.terminalResponseBytes+=1024;
 expect(grants.measureFutureProfileTemplateBudget(above).httpBodyBytes-grants.measureFutureProfileTemplateBudget(floor).httpBodyBytes).toBe(14*1024);
});
it('preserves pre-existing funding plan and grant bytes exactly',()=>{
 const f=fixture();expect(hash(f.plan)).toBe('d435ec6fb57ebc62d8b6b31b24827dc8a9311de9413f29bfd19cf46e82c8a2d1');
 expect(sha(JSON.stringify(f.plan))).toBe('cb8b9322686e40112013776c9d4f8da23b79fd6aae3d085f96d49bf7df1143f2');
 expect(sha(JSON.stringify(f.grantSet))).toBe('9ad8f3bbe3b58604c9dfd962b256628d1881cb9181e14ca0fc77a554aa520973');
});
for(const [name,change]of [
 ['version',t=>t.version=2],['kind',t=>t.kind='future-ci-profile-catalog'],['authority',t=>t.authority=true],['ledger',t=>t.ledgerBinding={}],['clock',t=>t.issuedMs=1],['final hash',t=>t.proofHash='a'.repeat(64)],
 ['duplicate consumer',t=>t.consumers.push(structuredClone(t.consumers[0]))],['consumer bound',t=>t.consumers=Array(129).fill(t.consumers[0])],['wrong source phase',t=>t.consumers[0].scope.phase='preupdate'],
 ['source request Put',t=>t.consumers[0].profiles=[identity()]],['source cap',t=>t.consumers[0].reader.terminalResponseBytes=1048577],['target cap',t=>t.consumers[1].handshake.terminalResponseBytes=1048577],
 ['profile count',t=>t.consumers[1].profiles[0].count=257],['late selector',t=>t.consumers[1].profiles[1].late.jsonPath='$.tasks'],['tag enum',t=>t.consumers[1].profiles[1].request.include=['OTHER']],
 ['owner request cap',t=>t.owner.publication.calls[0].requestBytes=0],['local network',t=>t.owner.localBudget.httpBodyBytes=1],['missing finalization',t=>delete t.finalization],
 ['total cap overflow',t=>{t.localBudget.logicalBytes=12884901888;}],
])it('pure template budget rejects '+name,()=>{const t=structuredClone(profileTemplate());change(t);expect(()=>grants.measureFutureProfileTemplateBudget(t)).toThrow();});
it('pure template budget rejects getters without invoking them',()=>{
 const t=profileTemplate();let calls=0;Object.defineProperty(t,'localBudget',{enumerable:true,get(){calls++;return zero();}});
 expect(()=>grants.measureFutureProfileTemplateBudget(t)).toThrow();expect(calls).toBe(0);
});

it('verifies complete static plan, all prepaid SUM components and original debit chain',()=>{
 const f=fixture(),v=verifyFutureGrantSet(f);expect(v.authority).toBe(false);expect(v.fundingPlan).toEqual(f.plan);expect(v.anchors).toEqual(f.input.binding.anchors);expect(v.source).toEqual(f.input.binding.source);
 expect(v.planHash).toBe(hash(f.plan));expect(v.planHash).toBe(f.grantSet.debit.events.at(-1).data.allocationId);expect(v.debitEventHash).toBe(hash(f.grantSet.debit.events.at(-1)));
 for(const k of Object.keys(zero()))expect(v.budget[k]).toBe(v.owner.budget[k]+v.finalization.budget[k]+v.localBudget[k]+v.consumers.reduce((sum,c)=>sum+c.budget[k],0));
 expect(v.owner.publication.calls.map(c=>[c.action,c.requestBytes,c.responseBytes,c.count,c.ecr])).toEqual([['GetCallerIdentity',1024,4096,1,false],['PutObject',16384,16384,1,false],['GetObject',0,16384,1,false]]);
 expect(v.owner.publication.budget.httpBodyBytes).toBe(53*1024+8388608);expect(v.owner.claims).toHaveLength(2);
 for(const [index,claim] of v.owner.claims.entries()){
  expect(claim.calls[0]).toMatchObject({action:'GetCallerIdentity',requestBytes:1024,responseBytes:4096,count:1,ecr:false});
  const consumer=v.consumers[index],source=consumer.scope.kind==='source',terminal=(source?consumer.reader:consumer.handshake).terminalResponseBytes,base=(source?53:245)*1024;
  expect(claim.budget.logicalBytes).toBe(base+2*terminal);expect(claim.budget.httpBodyBytes).toBe(base+2*terminal+8388608);
  for(const call of claim.calls.filter(c=>c.action==='GetObject'))expect(call.requestBytes).toBe(0);
 }
 expect(v.consumers[0].reader).toMatchObject({maxGetAttempts:12,minKnownPendingPollMs:5000,maxDurationMs:90000,pendingBodyBytes:16384,unknownOvershoots:1});
 expect(v.notAfter).toBe(f.input.issuedMs+7200000);expect(v).not.toHaveProperty('startupConfig');expect(v).not.toHaveProperty('dispatch');expect(Object.isFrozen(v.fundingPlan)).toBe(true);
});

it('rejects the previous zero-wire owner identity allocation instead of adding a free call',()=>{
 const f=fixture(),catalog=structuredClone(f.catalog);catalog.owner.publication.calls[0].requestBytes=0;
 expect(()=>createFutureFundingPlan({...f.input,catalogRaw:Buffer.from(JSON.stringify(catalog)).toString('base64')})).toThrow();
 const plan=structuredClone(f.plan);plan.owner.claims[0].calls[0].requestBytes=0;
 expect(()=>inspectFutureFundingPlan(plan)).toThrow();
});

it('funding and sealed accounting can exist before any final proof or descriptor hash',()=>{
 const f=fixture(),originalHash=f.expected.grantHash,v=verifyFutureGrantSet(f);
 for(const value of [f.plan,f.grantSet,f.grantSet.debit.events.at(-1)])for(const key of ['descriptorHash','proofHash','startupConfig','runBinding','runId','runAttempt'])expect(JSON.stringify(value)).not.toContain('"'+key+'"');
 const events=structuredClone(f.grantSet.debit.events),last=events.at(-1);events.push({...last,sequence:events.length+1,previousHash:hash(last),type:'sealed',data:{reason:'completed'}});
 const checkpoint={...f.grantSet.debit.checkpoint,sealed:true,eventCount:events.length,lastEventHash:hash(events.at(-1))};
 const replay=replayAccounting(events,{binding:f.grantSet.debit.start.binding,startingCounters:f.grantSet.debit.start.startingCounters,reserve:f.grantSet.debit.start.reserve});expect(replay.sealed).toBe(true);expect(replay.spent).toEqual(checkpoint.counters);
 // Synthetic dependency check, not a production proof or authorization.
 const proof={kind:'synthetic-final-proof',fundingPlans:[v.fundingPlan],accounting:{start:f.grantSet.debit.start,events,checkpoint}};
 const descriptor={kind:'synthetic-final-descriptor',authorizationId:v.anchors.authorizationId,proofHash:hash(proof)};
 expect(hash(descriptor)).toMatch(/^[a-f0-9]{64}$/);expect(hash(f.grantSet)).toBe(originalHash);expect(verifyFutureGrantSet(f).planHash).toBe(v.planHash);
});

it('does not consult a clock or treat funding expiry as predecessor authorization',()=>{
 const f=fixture();vi.spyOn(Date,'now').mockImplementation(()=>{throw Error('NoClockAllowed');});
 expect(verifyFutureGrantSet(f).notAfter).toBe(f.input.issuedMs+7200000);
 expect(createFutureFundingPlan({...f.input,operatorNotAfter:f.input.issuedMs+30000}).notAfter).toBe(f.input.issuedMs+30000);
 expect(createFutureFundingPlan({...f.input,operatorNotAfter:f.input.issuedMs+9000000}).notAfter).toBe(f.input.issuedMs+7200000);
 expect(()=>createFutureFundingPlan({...f.input,operatorNotAfter:f.input.issuedMs})).toThrow();
 expect(()=>createFutureFundingPlan({...f.input,authorizationNotAfter:f.input.issuedMs-1})).toThrow();
});

for(const key of ['descriptorHash','proofHash','grantHash','debit','startupConfig','runBinding','runId'])it('static funding plan rejects downstream or unknown field '+key,()=>{
 const f=fixture();expect(()=>inspectFutureFundingPlan({...f.plan,[key]:'f'.repeat(64)})).toThrow();
});
for(const key of ['descriptorHash','proofHash'])it('rejects old pre-seal final authorization field '+key,()=>{const f=fixture();expect(()=>createFutureFundingPlan({...f.input,binding:{...f.input.binding,[key]:'f'.repeat(64)}})).toThrow();expect(()=>verifyFutureGrantSet(badGrant(f,g=>{g[key]='f'.repeat(64);}))).toThrow();});
for(const [label,change] of [
 ['catalog hash',p=>{p.catalogHash='0'.repeat(64);}],['catalog bytes',p=>{p.catalogRaw=Buffer.from('{}').toString('base64');}],
 ['missing catalog',p=>{delete p.catalogRaw;}],['budget',p=>{p.budget.logicalBytes--;}],['owner allowance',p=>{p.owner.publication.budget.httpBodyBytes--;}],
 ['handshake count',p=>{p.consumers[1].handshake.calls[1].count=13;}],['renewed notAfter',p=>{p.notAfter++;}],['invalid issue time',p=>{p.issuedMs=Number.MAX_SAFE_INTEGER;}],
 ['owner alternate directory',p=>{p.ownerStateDirectory='/synthetic/other';}],['relative owner directory',p=>{p.ownerStateDirectory='relative/grant-'+p.grantSetId;}],
 ['future main source',p=>{p.source.mainRevision='a'.repeat(40);}],['unknown root field',p=>{p.anchors.proofHash='a'.repeat(64);}],['null authorization ID',p=>{p.anchors.authorizationId=null;}],
 ['zero next parameter version',p=>{p.anchors.nextParameterVersion=0;}],['unsafe next parameter version',p=>{p.anchors.nextParameterVersion=Number.MAX_SAFE_INTEGER+1;}],
])it('static plan rejects '+label,()=>{const p=structuredClone(fixture().plan);change(p);expect(()=>inspectFutureFundingPlan(p)).toThrow();});

for(const [label,change] of [
 ['missing debit',g=>{g.debit.events=[];}],['changed prior event',g=>{g.debit.events[1].data.charged=0;}],['changed event chain',g=>{g.debit.events[2].previousHash='a'.repeat(64);}],
 ['changed paid amount',g=>{g.debit.events[2].data.charge.logicalBytes--;}],['changed scope',g=>{g.debit.events[2].data.scopeHash='a'.repeat(64);}],
 ['wrong allocation',g=>{g.allocationId='a'.repeat(64);}],['counter reset',g=>{g.debit.start.startingCounters.httpBodyBytes=0;}],['checkpoint lie',g=>{g.debit.checkpoint.counters.httpBodyBytes=0;}],
 ['paid flag',g=>{g.paid=true;}],['sealed prefix rewrite',g=>{g.debit.checkpoint.sealed=true;}],['changed copy anchor',g=>{g.anchors.copyCheckpointHash='a'.repeat(64);}],
 ['changed root',g=>{g.anchors.rootBindingHash='a'.repeat(64);}],['changed predecessor',g=>{g.anchors.predecessorParameterHash='a'.repeat(64);}],
 ['changed authorization ID',g=>{g.anchors.authorizationId='a'.repeat(32);}],['changed parameter version',g=>{g.anchors.nextParameterVersion++;}],
])it('grant verifier rejects '+label+' even when only envelope hash is recomputed',()=>{const f=fixture();expect(()=>verifyFutureGrantSet(badGrant(f,change))).toThrow();});
it('requires the four independent roots and refuses the previous six-root shape',()=>{
 const f=fixture();for(const key of Object.keys(f.expected))expect(()=>verifyFutureGrantSet({...f,expected:{...f.expected,[key]:'0'.repeat(64)}})).toThrow();
 expect(()=>verifyFutureGrantSet({...f,expected:{...f.expected,descriptorHash:'a'.repeat(64),proofHash:'b'.repeat(64)}})).toThrow();
});

for(const taskTags of [false,true])for(const definitionTags of [false,true])it(`preserves exact optional TAGS requests: tasks=${taskTags}, definition=${definitionTags}`,()=>{
 const p=targetProfiles();if(!taskTags)delete p[1].request.include;if(!definitionTags)delete p[2].request.include;
 const inspected=inspectFutureCallProfiles(p);expect(inspected).toEqual(p);expect(Object.hasOwn(inspected[1].request,'include')).toBe(taskTags);expect(Object.hasOwn(inspected[2].request,'include')).toBe(definitionTags);
});
for(const index of [1,2])for(const include of [[],['OTHER'],['TAGS','OTHER'],['TAGS','TAGS'],'TAGS',null])it(`rejects noncanonical include at profile ${index}: ${JSON.stringify(include)}`,()=>{
 const p=targetProfiles();p[index].request.include=include;expect(()=>inspectFutureCallProfiles(p)).toThrow();
});
it('optional include does not admit extra request fields or prefill the late-bound field',()=>{
 for(const [index,extra] of [[1,{tasks:['synthetic-task']}],[1,{unknown:true}],[2,{taskDefinition:'synthetic-definition'}],[2,{cluster:'synthetic-cluster'}]]){
  const p=targetProfiles();delete p[index].request.include;Object.assign(p[index].request,extra);expect(()=>inspectFutureCallProfiles(p)).toThrow();
 }
 const missingCluster=targetProfiles();delete missingCluster[1].request.cluster;expect(()=>inspectFutureCallProfiles(missingCluster)).toThrow();
});
it('catalog and plan hashes distinguish omitted include from an explicit TAGS request',()=>{
 const f=fixture(),catalog=structuredClone(f.catalog);delete catalog.consumers[1].profiles[1].request.include;delete catalog.consumers[1].profiles[2].request.include;
 const plan=createFutureFundingPlan({...f.input,catalogRaw:Buffer.from(JSON.stringify(catalog)+'\n').toString('base64')});
 expect(inspectFutureFundingPlan(plan).planHash).not.toBe(f.funding.planHash);expect(plan.catalogHash).not.toBe(f.plan.catalogHash);expect(plan.budget).toEqual(f.plan.budget);
 expect(plan.consumers[1].profiles[1].request).toEqual({cluster:'synthetic-cluster'});expect(plan.consumers[1].profiles[2].request).toEqual({});
 const altered=structuredClone(f.plan);delete altered.consumers[1].profiles[1].request.include;expect(()=>inspectFutureFundingPlan(altered)).toThrow();
});

it('CONTROL descendant manifest reads have explicit pre-funded count and byte caps',()=>{
 const f=fixture(),catalog=structuredClone(f.catalog),profile={...catalog.consumers[1].profiles[3],id:'control-manifests',late:{field:'imageIds',buildContractKey:'deployed-bootstrap',artifact:'manifest'},count:3,responseBytes:4194304};
 catalog.consumers[1].profiles.push(profile);expect(inspectFutureCallProfiles(catalog.consumers[1].profiles).at(-1)).toEqual(profile);
 const plan=createFutureFundingPlan({...f.input,catalogRaw:Buffer.from(JSON.stringify(catalog)+'\n').toString('base64')});
 expect(plan.budget.ecrRequests-f.plan.budget.ecrRequests).toBe(3);expect(plan.budget.logicalBytes-f.plan.budget.logicalBytes).toBe(3*(1024+4194304));expect(plan.budget.httpBodyBytes-f.plan.budget.httpBodyBytes).toBe(3*(1024+4194304));
 expect(inspectFutureFundingPlan(plan).planHash).not.toBe(f.funding.planHash);
 const changed=structuredClone(plan);changed.consumers[1].profiles.at(-1).count++;
 expect(()=>inspectFutureFundingPlan(changed)).toThrow();
 expect(()=>verifyFutureGrantSet(badGrant(f,g=>{g.consumers[1].profiles[3].late.artifact='manifest';g.consumers[1].profiles[3].count=3;}))).toThrow();
});
for(const [label,change] of [
 ['unknown artifact',p=>{p.late.artifact='manifest-any';}],['DATA repository',p=>{p.request.repositoryName='mem9-on-aws/mnemo-server';}],
 ['wildcard registry',p=>{p.request.registryId='*';}],['caller digest list',p=>{p.request.imageIds=[{imageDigest:'sha256:'+'a'.repeat(64)}];}],
 ['wrong late field',p=>{p.late.field='repositoryName';}],['different build contract',p=>{p.late.buildContractKey='unreviewed';}],
 ['manifest scan',p=>{p.action='DescribeImageScanFindings';p.late.field='imageId';}],['manifest download',p=>{p.action='GetDownloadUrlForLayer';p.late.field='layerDigest';}],
 ['unbounded count',p=>{p.count=257;}],['unbounded response',p=>{p.responseBytes=8388609;}],
])it('CONTROL manifest variant rejects '+label,()=>{
 const p=targetProfiles().at(-1);p.late.artifact='manifest';change(p);expect(()=>inspectFutureCallProfiles([p])).toThrow();
});

for(const [label,change] of [
 ['unknown kind',p=>{p[1].kind='CALLBACK';}],['JSONPath',p=>{p[1].late.jsonPath='$.tasks[*]';}],['arbitrary late field',p=>{p[1].late.field='cluster';}],
 ['unscoped list',p=>{delete p[0].request.serviceName;}],['forward reference',p=>{p[1].late.fromProfile='definition';}],['different cluster',p=>{p[1].request.cluster='other';}],
 ['unbounded task count',p=>{p[1].late.maxItems=101;}],['DATA substitution',p=>{p[3].request.repositoryName='mem9-on-aws/mnemo-server';}],['unknown build',p=>{p[3].late.buildContractKey='other';}],
 ['free URL',p=>{p[3].request.url='https://example.com/free';}],['callback',p=>{p[1].late.fromProfile=()=>[];}],['regex',p=>{p[1].late.fromProfile=/tasks/;}],
 ['service mutation',p=>{p[0].action='UpdateService';}],['unknown request field',p=>{p[0].request.futureJobId=0;}],
])it('portable profile rejects '+label,()=>{const p=targetProfiles();change(p);expect(()=>inspectFutureCallProfiles(p)).toThrow();});
it('never invokes a getter from untrusted plan JSON',()=>{const p=structuredClone(fixture().plan);let calls=0;Object.defineProperty(p,'budget',{enumerable:true,get(){calls++;return zero();}});expect(()=>inspectFutureFundingPlan(p)).toThrow();expect(calls).toBe(0);});
it('has no private filesystem dependency, startup import or AWS execution callsite',()=>{
 const source=readFileSync(new URL('./lib/ci-smoke-grants.mjs',import.meta.url),'utf8');
 expect(source).not.toMatch(/from\s+['"](?:\/|node:fs|node:child_process|@aws-sdk)/);expect(source).not.toMatch(/ci-smoke-startup|Date\.now\(|fetch\(/);
});

it('R5 source has exactly two restricted readers, no private request PUT, and one serial overshoot',()=>{
 const f=fixture(),source=f.plan.consumers[0],r=source.reader,B=r.terminalResponseBytes;
 expect(r.operations.map(o=>[o.purpose,o.action,o.requestBytes,o.responseBytes,o.count,o.ecr])).toEqual([
  ['ci-assume','AssumeRoleWithWebIdentity',131072,131072,1,false],
  ['ci-identity','GetCallerIdentity',1024,131072,1,false],
  ['ci-envelope','GetObject',0,CI_SMOKE_ARCHIVE_LIMITS.envelopeBytes,1,false],
  ['allowance-assume','AssumeRoleWithWebIdentity',131072,131072,1,false],
  ['allowance-identity','GetCallerIdentity',1024,131072,1,false],
  ['allowance-known404','GetObject',0,16384,11,false],
  ['allowance-terminal','GetObject',0,B,1,false],
 ]);
 expect(r.operations.reduce((sum,o)=>sum+o.count,0)).toBe(17);
 expect(r).toMatchObject({version:1,kind:'source-two-reader',maxGetAttempts:12,maxKnownPendingAttempts:11,minKnownPendingPollMs:5000,maxDurationMs:90000,pendingBodyBytes:16384,unknownOvershoots:1,overshootBytes:8388608});
 const bytes=2*(131072+131072)+2*(1024+131072)+33554432+11*16384+B;
 expect(r.budget).toEqual({...zero(),logicalBytes:bytes,httpBodyBytes:bytes+8388608});expect(source.budget).toEqual(addCounters(r.budget,source.localBudget));
 expect(source).not.toHaveProperty('profiles');expect(source).not.toHaveProperty('handshake');
 for(const operation of r.operations)expect(operation).not.toHaveProperty('request');
 expect(f.plan.owner.claims[0].calls.map(c=>[c.purpose,c.action])).toEqual([['identity','GetCallerIdentity'],['create-claim','PutObject'],['publish-response','PutObject'],['confirm-response','GetObject']]);
 expect(f.plan.owner.claims[0].budget).toEqual({...zero(),logicalBytes:53*1024+2*B,httpBodyBytes:53*1024+2*B+8388608});
});

it('R5 changes only source, preserving target profiles, handshake and owner request read',()=>{
 const f=fixture(),target=f.plan.consumers[1];expect(target.profiles).toEqual(targetProfiles());expect(target).not.toHaveProperty('reader');
 expect(target.handshake.calls.map(c=>[c.action,c.requestBytes,c.responseBytes,c.count])).toEqual([['PutObject',16384,16384,1],['GetObject',0,16384,12]]);
 expect(target.handshake.budget).toEqual({...zero(),logicalBytes:14*16384,httpBodyBytes:14*16384+8388608});
 expect(f.plan.owner.claims[1].calls.map(c=>c.purpose)).toEqual(['identity','create-claim','request','publish-response','confirm-response']);
 expect(f.plan.owner.claims[1].budget.logicalBytes).toBe(245*1024+2*8192);
});

for(const B of [1,16384,1048576])it(`R5 source terminal cap ${B} is prepaid exactly once`,()=>{
 const r=createFutureSourceReader({version:1,kind:'source-two-reader',terminalResponseBytes:B});expect(r.budget.logicalBytes).toBe(33554432+946*1024+B);expect(r.budget.httpBodyBytes-r.budget.logicalBytes).toBe(8388608);
});
for(const B of [0,-1,1048577,Number.MAX_SAFE_INTEGER,1.5,null])it(`R5 rejects invalid source terminal cap ${B}`,()=>{
 expect(()=>createFutureSourceReader({version:1,kind:'source-two-reader',terminalResponseBytes:B})).toThrow();
});
for(const key of ['operations','profiles','request','jwt','sessionName','Policy','RoleArn','envelopeBytes','overshootBytes','maxGetAttempts','selector'])it('R5 source configuration rejects caller field '+key,()=>{
 expect(()=>createFutureSourceReader({version:1,kind:'source-two-reader',terminalResponseBytes:4096,[key]:'caller-controlled'})).toThrow();
});
for(const [label,change] of [
 ['extra STS',r=>{r.operations[0].count=2;}],['zero STS request',r=>{r.operations[0].requestBytes=0;}],['small STS response',r=>{r.operations[3].responseBytes=4096;}],
 ['zero identity request',r=>{r.operations[1].requestBytes=0;}],['small identity response',r=>{r.operations[4].responseBytes=4096;}],['small envelope',r=>{r.operations[2].responseBytes=4096;}],
 ['twelve known-pending responses plus terminal',r=>{r.operations[5].count=12;}],['repeated terminal',r=>{r.operations[6].count=2;}],['second overshoot',r=>{r.unknownOvershoots=2;}],
 ['renewed polling duration',r=>{r.maxDurationMs=180000;}],['missing cleanup/local budget',r=>{r.budget.httpBodyBytes=0;}],['private request put',r=>{r.operations[2].action='PutObject';}],
])it('R5 plan rejects mutated source '+label,()=>{const p=structuredClone(fixture().plan);change(p.consumers[0].reader);expect(()=>inspectFutureFundingPlan(p)).toThrow();});

for(const variant of ['old-source','extra-private-handshake','missing-reader','target-with-reader','source-owner-request'])it('R5 rejects '+variant+' instead of widening the source route',()=>{
 const f=fixture(),catalog=structuredClone(f.catalog),source=catalog.consumers[0];
 if(variant==='old-source'){delete source.reader;source.profiles=[identity()];source.handshake={terminalResponseBytes:4096};}
 else if(variant==='extra-private-handshake')source.handshake={terminalResponseBytes:4096};
 else if(variant==='missing-reader')delete source.reader;
 else if(variant==='target-with-reader')catalog.consumers[1].reader=source.reader;
 else {const p=structuredClone(f.plan);p.owner.claims[0].calls.splice(1,0,{purpose:'request',action:'GetObject',requestBytes:0,responseBytes:16384,count:1,ecr:false});expect(()=>inspectFutureFundingPlan(p)).toThrow();return;}
 expect(()=>createFutureFundingPlan({...f.input,catalogRaw:Buffer.from(JSON.stringify(catalog)).toString('base64')})).toThrow();
});

it('R6 target owner prepays all twelve exact request GETs; source numeric bounds remain unchanged',()=>{
 const f=fixture(),source=f.plan.consumers[0],target=f.plan.consumers[1],owner=f.plan.owner.claims[1],B=target.handshake.terminalResponseBytes;
 expect(owner.calls[2]).toEqual({purpose:'request',action:'GetObject',count:12,requestBytes:0,responseBytes:16384,ecr:false});
 expect(owner.budget).toEqual({...zero(),logicalBytes:245*1024+2*B,httpBodyBytes:245*1024+2*B+8388608});
 expect(owner.budget.logicalBytes-(69*1024+2*B)).toBe(11*16384);expect(owner.unknownOvershoots).toBe(1);
 expect(owner.requestPolling).toEqual({purpose:'request',knownPendingStatuses:[403,404],maxGetAttempts:12,maxKnownPendingAttempts:11,minKnownPendingPollMs:5000,maxDurationMs:90000,pendingBodyBytes:16384});
 expect(source.reader.knownPendingStatuses).toEqual([403,404]);expect(target.handshake.knownPendingStatuses).toEqual([403,404]);
 expect(source.reader.operations[5]).toEqual({purpose:'allowance-known404',action:'GetObject',count:11,requestBytes:0,responseBytes:16384,ecr:false});
 expect(source.reader.budget).toEqual({...zero(),logicalBytes:33554432+946*1024+source.reader.terminalResponseBytes,httpBodyBytes:33554432+946*1024+source.reader.terminalResponseBytes+8388608});
 expect(f.plan.owner.claims[0]).not.toHaveProperty('requestPolling');expect(f.plan.owner.claims[0].calls.map(c=>c.purpose)).toEqual(['identity','create-claim','publish-response','confirm-response']);
});

for(const [label,change] of [
 ['old one-GET allowance',p=>{p.owner.claims[1].calls[2].count=1;}],['thirteenth GET',p=>{p.owner.claims[1].calls[2].count=13;}],
 ['old underpayment',p=>{p.owner.claims[1].budget.logicalBytes-=11*16384;p.owner.claims[1].budget.httpBodyBytes-=11*16384;}],
 ['unknown status',p=>{p.owner.claims[1].requestPolling.knownPendingStatuses=[403,404,500];}],['not fully specified statuses',p=>{p.consumers[0].reader.knownPendingStatuses=[404];}],
 ['shorter poll interval',p=>{p.consumers[1].handshake.minKnownPendingPollMs=0;}],['extra owner unknown',p=>{p.owner.claims[1].unknownOvershoots=2;}],
 ['retry confirm GET',p=>{p.owner.claims[1].requestPolling.purpose='confirm-response';}],['changed stable purpose',p=>{p.consumers[0].reader.operations[5].purpose='allowance-known-pending';}],
 ['old field alias',p=>{p.consumers[0].reader.maxKnown404Attempts=11;}],['old absence field alias',p=>{p.consumers[1].handshake.notFoundBodyBytes=16384;}],
])it('R6 strict funding plan rejects '+label,()=>{const f=fixture(),p=structuredClone(f.plan);change(p);expect(()=>inspectFutureFundingPlan(p)).toThrow();});

it('R6 cannot rewrite the owner GET count after the original debit',()=>{
 const f=fixture();expect(()=>verifyFutureGrantSet(badGrant(f,g=>{g.owner.claims[1].calls[2].count=1;g.owner.claims[1].budget.logicalBytes-=11*16384;g.owner.claims[1].budget.httpBodyBytes-=11*16384;}))).toThrow();
});

it('R7 commits claim-before-request order without changing any paid caps or SOURCE operations',()=>{
 const f=fixture(),target=f.plan.owner.claims[1],B=f.plan.consumers[1].handshake.terminalResponseBytes;
 expect(target.calls.map(c=>[c.purpose,c.action,c.count,c.requestBytes,c.responseBytes])).toEqual([
  ['identity','GetCallerIdentity',1,1024,4096],
  ['create-claim','PutObject',1,16384,16384],
  ['request','GetObject',12,0,16384],
  ['publish-response','PutObject',1,B,16384],
  ['confirm-response','GetObject',1,0,B],
 ]);
 expect(target.budget).toEqual({...zero(),logicalBytes:245*1024+2*B,httpBodyBytes:245*1024+2*B+8388608});expect(target.unknownOvershoots).toBe(1);
 expect(f.plan.owner.claims[0].calls.map(c=>c.purpose)).toEqual(['identity','create-claim','publish-response','confirm-response']);
});
it('R7 rejects the prior request-before-claim sequence even with unchanged SUM',()=>{
 const f=fixture(),plan=structuredClone(f.plan),calls=plan.owner.claims[1].calls;[calls[1],calls[2]]=[calls[2],calls[1]];
 expect(plan.budget).toEqual(f.plan.budget);expect(hash(plan)).not.toBe(f.funding.planHash);expect(()=>inspectFutureFundingPlan(plan)).toThrow();
 expect(()=>verifyFutureGrantSet(badGrant(f,g=>{const calls=g.owner.claims[1].calls;[calls[1],calls[2]]=[calls[2],calls[1]];}))).toThrow();
});

// Codec tests only. Native payment + worker acceptance is separately exercised
// with the real owner ledger; these synthetic documents mint no capability.
function revisedGrant(){
 const f=fixture(),revision={version:2,limitsHash:NONROOT_REMAINING_WORK_LIMITS_HASH_V2,envelopeHash:hash('compiled-fixture'),historyHeadHash:hash('history-fixture')};
 const start={...f.grantSet.debit.start,version:2,budgetRevision:revision,startingCounters:{...zero(),logicalBytes:13*1024**3,httpBodyBytes:13*1024**3}},compiledCeiling=Object.fromEntries(Object.keys(zero()).map(k=>[k,start.startingCounters[k]+start.reserve[k]]));
 const startRaw=Buffer.from(JSON.stringify(start));f.catalog.cumulativeLimitsHash=revision.limitsHash;
 const plan=createFutureFundingPlan({...f.input,catalogRaw:Buffer.from(JSON.stringify(f.catalog)).toString('base64'),ledgerStartHash:sha(startRaw),budgetRevision:revision,compiledCeiling});
 const ph=hash(plan),spent=Object.fromEntries(Object.keys(zero()).map(k=>[k,start.startingCounters[k]+plan.budget[k]])),remaining=Object.fromEntries(Object.keys(zero()).map(k=>[k,start.reserve[k]-plan.budget[k]]));
 const event={version:2,budgetRevision:revision,sequence:1,...start.binding,previousHash:null,type:'prepayment',data:{allocationId:ph,planHash:ph,scopeHash:hash({version:1,kind:'future-ci-grant-set',grantSetId:plan.grantSetId}),charge:plan.budget,reserveDebit:plan.budget},spent,remaining};
 const debit={start,startRaw:startRaw.toString('base64'),events:[event],checkpoint:{binding:start.binding,budgetRevision:revision,startingCounters:start.startingCounters,counters:spent,remainingReservation:remaining,eventCount:1,lastEventHash:hash(event),active:0,sealed:false}};
 const grantSet={...plan,version:2,kind:'owner-prepaid-future-grant-set',authority:false,allocationId:ph,planHash:ph,debit};
 return {grantSet,expected:{grantSetId:plan.grantSetId,grantHash:hash(grantSet),ledgerStartHash:plan.ledgerStartHash,catalogHash:plan.catalogHash,budgetRevision:revision,compiledCeiling}};
}
it('R18 future grant replays v2 cumulative history against an independent compiled ceiling',()=>{
 const f=revisedGrant(),v=verifyFutureGrantSet(f);expect(v.ownerCounters.logicalBytes).toBeGreaterThan(12*1024**3);expect(v.budgetRevision).toEqual(f.expected.budgetRevision);
});
it.each(['missing-revision','missing-ceiling','changed-envelope','changed-history','lower-ceiling','event-relabel','checkpoint-relabel','self-raised-ceiling'])('R18 future grant rejects %s',fault=>{
 const f=revisedGrant();
 if(fault==='missing-revision')delete f.expected.budgetRevision;
 if(fault==='missing-ceiling')delete f.expected.compiledCeiling;
 if(fault==='changed-envelope')f.expected.budgetRevision={...f.expected.budgetRevision,envelopeHash:hash('other')};
 if(fault==='changed-history')f.expected.budgetRevision={...f.expected.budgetRevision,historyHeadHash:hash('other')};
 if(fault==='lower-ceiling')f.expected.compiledCeiling={...f.expected.compiledCeiling,logicalBytes:f.expected.compiledCeiling.logicalBytes-1};
 if(fault==='event-relabel')f.grantSet.debit.events[0].version=1;
 if(fault==='checkpoint-relabel')delete f.grantSet.debit.checkpoint.budgetRevision;
 if(fault==='self-raised-ceiling')f.grantSet.compiledCeiling={...f.grantSet.compiledCeiling,logicalBytes:f.grantSet.compiledCeiling.logicalBytes+1};
 f.expected.grantHash=hash(f.grantSet);expect(()=>verifyFutureGrantSet(f)).toThrow();
});
it('R18 future aggregate compilation requires the fixed static flag before exceeding legacy LOCAL caps',()=>{
 const t=profileTemplate();t.localBudget.logicalBytes=13*1024**3;
 expect(()=>grants.measureFutureProfileTemplateBudget(t)).toThrow();
 t.cumulativeLimitsHash=NONROOT_REMAINING_WORK_LIMITS_HASH_V2;expect(grants.measureFutureProfileTemplateBudget(t).logicalBytes).toBeGreaterThan(13*1024**3);
 t.cumulativeLimitsHash=hash('arbitrary-limit');expect(()=>grants.measureFutureProfileTemplateBudget(t)).toThrow();
});
