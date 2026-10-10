import {it,expect,vi} from 'vitest';
import {parseContinuationInspection,encodeContinuationInspection,continuationInspectionDefinition} from './lib/production-continuation-inspection.mjs';
import {controlLaunchPolicy} from './lib/production-nonroot-launch.mjs';
import {resolveGuardPurpose} from '../docker/bootstrap/nonroot-identity.mjs';
import {validateContinuationRootInput,captureContinuationCensus,runContinuationInspection} from './production-continuation-inspection.mjs';
import {auditRootTransaction,rootAuditSourceClosure} from './lib/production-continuation-root.mjs';
import {imageTransitionFixture,imageTransitionServingFixture} from './production-image-transition.fixture.mjs';
import {buildImageTransitionProof,buildCanaryCompatibilityV4} from './lib/production-image-transition-proof.mjs';
import {asNonrootCertificate} from './production-nonroot-runtime.fixture.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {createHash,randomBytes} from 'node:crypto';
import {deflateRawSync} from 'node:zlib';
import {readFile} from 'node:fs/promises';
import pg from 'pg';
import {schemaAdministratorRole} from './lib/production-runtime-config.mjs';
import {runAuditLease,probeReleased,stampPublicationInspectionRequest,validatePublicationInspectionRequest,PUBLICATION_STARTUP_MS,PUBLICATION_WATCHDOG_MS} from './lib/production-continuation-publication.mjs';

const id='a'.repeat(32),now=1800000000000;
function base(){return {family:'mem9-on-aws-prod-Control',taskRoleArn:'task-role',executionRoleArn:'execution-role',networkMode:'awsvpc',runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},requiresCompatibilities:['FARGATE'],cpu:'512',memory:'1024',containerDefinitions:[controlLaunchPolicy('consolidation-control',{name:'ControlMem9Bootstrap',image:'example@sha256:'+'b'.repeat(64),environment:[{name:'MEM9_STAGE',value:'prod'},{name:'MEM9_PRODUCTION_WORKER_OPERATOR',value:'control'},{name:'MEM9_DB_HOST',value:'example.com'}],secrets:[{name:'MEM9_DB_SECRET',valueFrom:'credential-reference'}],logConfiguration:{logDriver:'awslogs',options:{}}})]};}
it('maps only the fixed inspection purpose to a source-manifested module',()=>{
 const env={MEM9_STAGE:'prod',MEM9_PRODUCTION_WORKER_OPERATOR:'control',MEM9_CONTINUATION_OPERATION:'root-audit'};
 expect(resolveGuardPurpose('continuation-inspection',env).module).toBe('/bootstrap/operator/scripts/production-continuation-inspection.mjs');
 for(const operation of ['eval','prepare','promote','./module.mjs',''])expect(()=>resolveGuardPurpose('continuation-inspection',{...env,MEM9_CONTINUATION_OPERATION:operation})).toThrow();
 expect(()=>resolveGuardPurpose('continuation-inspection',{...env,MEM9_STAGE:'pr-7'})).toThrow();
});
it('retains the exact guard and image for a roleless, credential-free parser definition',()=>{
 const original=base(),before=structuredClone(original),request={operation:'begin-continuation',invocation:id,deadline:now+60000};
 const d=continuationInspectionDefinition(original,{operation:'parse-begin',invocation:id,request,now});
 expect(original).toEqual(before);expect(d.taskRoleArn).toBeUndefined();expect(d.executionRoleArn).toBe(original.executionRoleArn);
 const c=d.containerDefinitions[0];expect(c.entryPoint).toEqual(['/bin/setpriv','--no-new-privs','--','/usr/local/bin/node','/bootstrap/nonroot-dispatch.mjs','continuation-inspection']);
 expect(c.command).toEqual([]);expect(c.user).toBe('1000:1000');expect(c.linuxParameters.capabilities).toEqual({drop:['ALL']});expect(c.secrets).toEqual([]);
 expect(c.environment.map(e=>e.name)).not.toContain('MEM9_DB_HOST');expect(c.environment.at(-1)).toEqual({name:'MEM9_PRODUCTION_CONSOLIDATION_REQUEST',value:JSON.stringify(request)});
 expect(c.entryPoint).not.toContain('-e');
});
it('rejects unknown operations and a changed baseline instead of selecting code from a request',()=>{
 for(const operation of ['eval','prepare','promote'])expect(()=>continuationInspectionDefinition(base(),{operation,invocation:id,request:{}})).toThrow();
 const d=structuredClone(base());d.containerDefinitions[0].entryPoint=['node'];expect(()=>continuationInspectionDefinition(d,{operation:'root-audit',invocation:id,request:{}})).toThrow();
});
it('parses an exact finite root/census envelope and binds invocation/deadline before credential use',()=>{
 const value={version:1,operation:'capacity-census',invocation:id,owner:id,deadline:now+60000,input:{}};
 expect(parseContinuationInspection(JSON.stringify(value),{operation:value.operation,invocation:id,now})).toEqual(value);
 for(const mutate of [v=>{v.operation='eval';},v=>{v.invocation='b'.repeat(32);},v=>{v.deadline=now;},v=>{v.module='./x.mjs';},v=>{v.version=2;}]){
  const bad=structuredClone(value);mutate(bad);expect(()=>parseContinuationInspection(JSON.stringify(bad),{operation:value.operation,invocation:id,now})).toThrow();
 }
 expect(()=>parseContinuationInspection(JSON.stringify(value).replace('"version":1','"version":1,"version":1'),{operation:value.operation,invocation:id,now})).toThrow();
});

it('round trips the bounded data envelope and rejects overflow, trailing data and a changed digest',()=>{
 const value={version:1,operation:'root-audit',invocation:id,owner:id,deadline:now+60000,input:{certificate:'a'.repeat(6000)}};
 const options={operation:value.operation,invocation:id,now};const wire=encodeContinuationInspection(value);
 expect(Buffer.byteLength(wire)).toBeLessThan(6400);expect(parseContinuationInspection(wire,options)).toEqual(value);
 expect(()=>encodeContinuationInspection({...value,input:{body:'a'.repeat(32768)}})).toThrow();
 expect(()=>encodeContinuationInspection({...value,input:{body:randomBytes(6000).toString('hex')}})).toThrow('ContinuationInspectionWireLimit');
 for(const mutate of [v=>{v.bytes++;},v=>{v.sha256='0'.repeat(64);},v=>{v.body=Buffer.concat([Buffer.from(v.body,'base64'),Buffer.from([1])]).toString('base64');},v=>{v.module='other';}]){
  const bad=JSON.parse(wire);mutate(bad);expect(()=>parseContinuationInspection(JSON.stringify(bad),options)).toThrow();
 }
 const bomb=JSON.parse(wire);bomb.body=deflateRawSync(Buffer.alloc(32769)).toString('base64');bomb.bytes=32768;expect(()=>parseContinuationInspection(JSON.stringify(bomb),options)).toThrow();
});

let rootInput;
async function input(){
 if(!rootInput){
  const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built),previous=JSON.parse(f.input.bootstrapProof.previousText),parent=f.input.bootstrapProof.parent;
  const certificate=asNonrootCertificate(buildCanaryCompatibilityV4(previous,s.current,parent,{transition:s.authorizationContext,selection:s.selection,now:f.now}));
  const role=kind=>'mem9_'+kind+'_'+createHash('sha256').update('prod').digest('hex').slice(0,12);
  rootInput={invocation:id,owner:id,runtimeNonce:certificate.current.release.runtimeNonce,rootBinding:{parentProofHash:certificate.parentProofHash,validationId:parent.validationId,generation:parent.generation,spent:parent.changedRows,cap:20},certificate,parent:{verification:parent},dependencyHash:'d'.repeat(64),deployed:{revision:s.current.revision,sourceTree:s.current.sourceTree},rootConfig:{host:'example.com',port:5432,database:'mem9',generation:parent.generation,targets:parent.targets,workerImage:s.current.workerImage,sourceTag:s.current.sourceTag,acceptance:{sourceTree:s.current.sourceTree,coordinatorDigest:s.current.coordinatorDigest},planner:{username:role('planner')},executor:{username:role('executor')},dataRelease:{hash:certificate.dataReleaseHash,data:{version:3,transition:Object.fromEntries(['version','kind','proofHash','predecessorHash','limitsHash'].map(k=>[k,certificate.transition[k]]))}}}};
 }
 return structuredClone(rootInput);
}
async function inspectionEntryFixture(operation){
 const value=await input();
 value.dependencyHash=await rootAuditSourceClosure(name=>readFile(new URL('../'+name,import.meta.url),'utf8'));
 const started=Date.now(),deadline=started+60000,r=value.rootConfig;
 const envelope={version:1,operation,invocation:id,owner:id,deadline,input:value};
 return {started,deadline,env:{MEM9_STAGE:'prod',MEM9_PRODUCTION_WORKER_OPERATOR:'control',MEM9_CONTINUATION_OPERATION:operation,
  MEM9_OPERATOR_INVOCATION:id,MEM9_CONTINUATION_INSPECTION_REQUEST:JSON.stringify(envelope),MEM9_DB_HOST:r.host,MEM9_DB_PORT:String(r.port),MEM9_DB_NAME:r.database,
  MEM9_CONTROL_SOURCE_TAG:'mem9-'+value.deployed.revision.slice(0,7),MEM9_WORKER_GENERATION:value.certificate.generation,
  MEM9_WORKER_IMAGE:r.workerImage,MEM9_WORKER_SOURCE_TAG:r.sourceTag,MEM9_RETAINED_DATA_RELEASE_HASH:value.certificate.dataReleaseHash}};
}
it.each(['root-audit','capacity-census'])('valid %s inputs reach the credential edge after asynchronous source verification',async operation=>{
 const {env}=await inspectionEntryFixture(operation);let credentialGets=0;
 Object.defineProperty(env,'MEM9_DB_SECRET',{get(){credentialGets++;throw Error('SyntheticCredentialEdge');}});
 const client=vi.spyOn(pg,'Client').mockImplementation(function(){throw Error('UnexpectedDatabaseClient');});
 try{await expect(runContinuationInspection(env)).rejects.toThrow('SyntheticCredentialEdge');expect(credentialGets).toBe(1);expect(client).not.toHaveBeenCalled();}
 finally{client.mockRestore();}
});
it.each(['root-audit','capacity-census'])('%s expires during asynchronous preparation before reading credentials',async operation=>{
 const {env,started,deadline}=await inspectionEntryFixture(operation);let clock=started,credentialGets=0;
 const time=vi.spyOn(Date,'now').mockImplementation(()=>clock),client=vi.spyOn(pg,'Client').mockImplementation(function(){throw Error('UnexpectedDatabaseClient');});
 Object.defineProperty(env,'MEM9_DB_SECRET',{get(){credentialGets++;throw Error('SyntheticCredentialEdge');}});
 try{
  const pending=runContinuationInspection(env);clock=deadline+1;
  await expect(pending).rejects.toThrow('ContinuationInspectionDeadline');
  expect(credentialGets).toBe(0);expect(client).not.toHaveBeenCalled();
 }finally{client.mockRestore();time.mockRestore();}
});
it.each(['root-audit','capacity-census'].flatMap(operation=>['before-connect','after-connect'].map(phase=>[operation,phase])))('%s retains its absolute deadline %s',async(operation,phase)=>{
 const {env,started,deadline}=await inspectionEntryFixture(operation);let clock=started,credentialGets=0;
 const time=vi.spyOn(Date,'now').mockImplementation(()=>clock);
 const db={connect:vi.fn(async()=>{if(phase==='after-connect')clock=deadline+1;}),query:vi.fn(async()=>({rows:[]})),end:vi.fn(async()=>{})};
 const client=vi.spyOn(pg,'Client').mockImplementation(function(){if(phase==='before-connect')clock=deadline+1;return db;});
 Object.defineProperty(env,'MEM9_DB_SECRET',{get(){credentialGets++;return JSON.stringify({username:schemaAdministratorRole('prod'),password:'synthetic-password'});}});
 try{
  await expect(runContinuationInspection(env)).rejects.toThrow('ContinuationInspectionDeadline');
  expect(credentialGets).toBe(1);expect(client).toHaveBeenCalledTimes(1);
  expect(db.connect).toHaveBeenCalledTimes(phase==='before-connect'?0:1);expect(db.query).not.toHaveBeenCalled();expect(db.end).toHaveBeenCalledTimes(1);
 }finally{client.mockRestore();time.mockRestore();}
});
it('binds the complete original root and current source without accepting a changed parent/cap/target',async()=>{
 const value=await input();expect(validateContinuationRootInput(value,{owner:id,invocation:id})).toEqual(value);
 for(const mutate of [v=>{v.rootBinding.cap=21;},v=>{v.parent.verification.changedRows++;},v=>{v.rootConfig.targets=['other'];},v=>{v.deployed.sourceTree='0'.repeat(40);},v=>{v.rootConfig.dataRelease.data.version=2;},v=>{v.certificate.version=4;},v=>{v.script='arbitrary';}]){
  const bad=structuredClone(value);mutate(bad);expect(()=>validateContinuationRootInput(bad,{owner:id,invocation:id})).toThrow();
 }
});
it('uses only SELECT and parameter-bound namespace targets for capacity census',async()=>{
 const value=await input(),targets=value.parent.verification.targets,calls=[];
 const db={query:async(sql,args)=>{calls.push({sql,args});expect(sql).toMatch(/^SELECT /);expect(sql).not.toMatch(/\b(?:INSERT|UPDATE|DELETE|ALTER|CREATE|DROP|TRUNCATE)\b/);
  if(sql.startsWith('SELECT memory_type'))return {rows:[{memory_type:'insight',state:'active',count:4}]};
  if(sql.startsWith('SELECT count(*)::int AS groups'))return {rows:[{groups:2,rows:4,surplus:2,largest_group:2}]};
  if(sql.startsWith('SELECT enabled'))return {rows:[{enabled:false,dispatcher_enabled:false,retired_roles:1,execution_receipts:value.rootBinding.spent/2}]};
  if(sql.startsWith('SELECT generation'))return {rows:[{generation:value.certificate.generation,validation_id:value.rootBinding.validationId,targets,phase:'canary',canary_used:value.rootBinding.spent,receipt_verification:null}]};
  return {rows:[{count:0}]};}};
 const result=await captureContinuationCensus(db,value,now);expect(result.targetsHash).toBe(hash(targets));expect(result.benchmarkRemaining).toBe(0);expect(result.exactCandidateUpperBound.rows).toBe(4);
 expect(calls.filter(c=>c.sql.includes('public.memories')).every(c=>targets.includes(c.args[0])&&c.sql.includes('namespace_id=$1'))).toBe(true);
 expect(JSON.stringify(result)).not.toContain('content');expect(calls).toHaveLength(5);
});
it('sums every namespace and retains the largest group without cross-namespace merging',async()=>{
 const value=await input();value.rootConfig.targets=['namespace-a','namespace-b'];value.parent.verification.targets=value.rootConfig.targets;
 const targets=value.rootConfig.targets,seen=[];
 const db={query:async(sql,args)=>{
  if(sql.includes('public.memories')){expect(targets).toContain(args[0]);seen.push(args[0]);}
  const second=args?.[0]===targets[1];
  if(sql.startsWith('SELECT memory_type'))return {rows:[{memory_type:'insight',state:'active',count:second?6:4}]};
  if(sql.startsWith('SELECT count(*)::int AS groups'))return {rows:[second?{groups:1,rows:6,surplus:5,largest_group:6}:{groups:2,rows:4,surplus:2,largest_group:2}]};
  if(sql.startsWith('SELECT generation'))return {rows:[{generation:value.certificate.generation,validation_id:value.rootBinding.validationId,targets,phase:'canary',canary_used:value.rootBinding.spent,receipt_verification:null}]};
  if(sql.startsWith('SELECT enabled'))return {rows:[{enabled:false,dispatcher_enabled:false,retired_roles:1,execution_receipts:5}]};
  return {rows:[{count:0}]};
 }};
 const result=await captureContinuationCensus(db,value,now);expect(result.counts).toEqual([{memory_type:'insight',state:'active',count:10}]);expect(result.exactCandidateUpperBound).toEqual({groups:3,rows:10,surplus:7,largest_group:6});expect(seen).toEqual([targets[0],targets[0],targets[0],targets[1],targets[1],targets[1]]);
});
it('keeps the original audit read-only and does not initialize a new attempt',async()=>{
 const value=await input(),queries=[],p=value.parent.verification;
 const audit={changedRows:p.changedRows,receipts:p.receipts,conservationHash:p.conservationHash,parentProofHash:hash(p),executionEnabled:false,dispatcherEnabled:false,benchmarkRemaining:0,rootIdentity:'e'.repeat(64)};
 const db={query:async(sql,args)=>{queries.push(sql);expect(sql).toMatch(/^SELECT /);return {rows:sql.includes('transaction_timestamp')?[{observed_ms:now}]:[{present:false}]};}};
 const result=await auditRootTransaction(db,value,{currentCanaryAttempt:async()=>null,auditPausedCanary:async()=>audit});
 expect(result.rootEvidence.kind).toBe('paused');expect(result.rootHash).toBe(audit.rootIdentity);expect(queries).toHaveLength(2);
 await expect(auditRootTransaction(db,value,{currentCanaryAttempt:async()=>null,auditPausedCanary:async()=>({...audit,changedRows:audit.changedRows+2})})).rejects.toThrow('RootChanged');
});
it('runs the actual begin parser without credentials and rejects a wrong purpose/extra SQL before any DB use',async()=>{
 const value=await input(),request={operation:'begin-continuation',invocation:id,deadline:Date.now()+60000,attemptId:id,parentProofHash:value.certificate.parentProofHash,compatibility:value.certificate};
 const env={MEM9_STAGE:'prod',MEM9_PRODUCTION_WORKER_OPERATOR:'control',MEM9_CONTINUATION_OPERATION:'parse-begin',MEM9_OPERATOR_INVOCATION:id,MEM9_PRODUCTION_CONSOLIDATION_REQUEST:JSON.stringify(request)};
 const log=vi.spyOn(console,'log').mockImplementation(()=>{});
 try{
  await runContinuationInspection(env);const parsed=JSON.parse(log.mock.calls[0][0]);expect(parsed.status).toBe('parsed');expect(parsed.requestHash).toBe(createHash('sha256').update(env.MEM9_PRODUCTION_CONSOLIDATION_REQUEST).digest('hex'));
  await expect(runContinuationInspection({...env,MEM9_DB_SECRET:'{}'})).rejects.toThrow('ContinuationParserCredentials');
  await expect(runContinuationInspection({...env,MEM9_CONTINUATION_OPERATION:'eval'})).rejects.toThrow();
  await expect(runContinuationInspection({...env,MEM9_PRODUCTION_CONSOLIDATION_REQUEST:JSON.stringify({...request,sql:'SELECT 1'})})).rejects.toThrow();
 }finally{log.mockRestore();}
});
it('preserves publication lease acquisition, read-only heartbeats and release proof',async()=>{
 let at=now,locked=false;const queries=[],events=[],controller=new AbortController();
 const db={query:async(sql)=>{
  queries.push(sql);
  if(sql.includes('pg_try_advisory_lock')){locked=true;return {rows:[{result:true}]};}
  if(sql.includes('pg_advisory_unlock')){locked=false;return {rows:[{result:true}]};}
  if(sql.includes('clock_timestamp'))return {rows:[{result:at}]};
  if(sql.includes('pg_locks'))return {rows:[{result:locked}]};
  if(sql.includes('backend_start'))return {rows:[{pid:7,started:'1800000000000000'}]};
  if(sql.includes('transaction_read_only'))return {rows:[{result:true}]};
  return {rows:[]};
 }};
 await runAuditLease(db,{nonce:id},{audit:async()=>({synthetic:true}),emit:value=>events.push(value),now:()=>at,sleep:async ms=>{at+=ms;if(at>=now+20)controller.abort();},signal:controller.signal,leaseMs:30,heartbeatMs:10});
 expect(queries).toContain('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');expect(queries).toContain('ROLLBACK');expect(locked).toBe(false);
 expect(events[0].type).toBe('ready');expect(events.some(e=>e.type==='heartbeat'&&e.readOnly===true)).toBe(true);expect(events.at(-1)).toMatchObject({type:'released',released:true,readOnlyAtRelease:true});
});
it('rejects a still-present audit backend and a failed advisory unlock',async()=>{
 let at=now;
 const present={query:async()=>({rows:[{result:1}]})};
 await expect(probeReleased(present,{nonce:id,session:{pid:7,started:'1800000000000000'}},{now:()=>at,sleep:async ms=>{at+=ms;},timeoutMs:10})).rejects.toThrow('AuditReleaseUnproven');
 const failedUnlock={query:async sql=>({rows:[{result:sql.includes('count(*)')?0:!sql.includes('pg_advisory_unlock')}]})};
 await expect(probeReleased(failedUnlock,{nonce:id},{now:()=>now})).rejects.toThrow('ProbeUnlockFailed');
});
async function publicationEnv(){
 const value=await input(),c=value.certificate,witness={...value.rootConfig.acceptance,dataReleaseHash:c.dataReleaseHash,continuation:{version:2,parentProofHash:c.parentProofHash,certificateHash:hash(c),sourceTree:c.current.release.sourceTree,fixture:{hash:'a'.repeat(64),runId:'7',runAttempt:1},readinessHash:c.transition.runtimeEvidenceHash,descriptorHash:c.dataReleaseHash}};
 const request=stampPublicationInspectionRequest({kind:'audit',nonce:id,runtimeNonce:value.runtimeNonce,witness,engineVersion:'17.6',mode:'paused-canary',compatibility:c,dataRelease:value.rootConfig.dataRelease});
 const raw=JSON.stringify(request),env={MEM9_STAGE:'prod',MEM9_PRODUCTION_WORKER_OPERATOR:'control',MEM9_CONTINUATION_OPERATION:'publication-audit',MEM9_PUBLICATION_INVOCATION:id,MEM9_PUBLICATION_REQUEST:raw,MEM9_PUBLICATION_REQUEST_HASH:createHash('sha256').update(raw).digest('hex'),MEM9_PUBLICATION_DEADLINE_MS:String(request.deadlineMs)};
 return {env,request};
}
it('binds the publication hash/nonce/absolute time window without restamping or changing lease/watchdog limits',async()=>{
 const {env,request}=await publicationEnv();expect(validatePublicationInspectionRequest(env)).toEqual(request);
 expect(request.deadlineMs-request.issuedMs).toBe(PUBLICATION_STARTUP_MS+PUBLICATION_WATCHDOG_MS);expect(PUBLICATION_WATCHDOG_MS).toBe(360000);
 expect(()=>stampPublicationInspectionRequest(request)).toThrow('PublicationRequestAlreadyStamped');
 const d=continuationInspectionDefinition(base(),{operation:'publication-audit',invocation:id,request});const e=Object.fromEntries(d.containerDefinitions[0].environment.map(row=>[row.name,row.value]));
 expect(e.MEM9_PUBLICATION_REQUEST_HASH).toBe(env.MEM9_PUBLICATION_REQUEST_HASH);expect(e.MEM9_PUBLICATION_DEADLINE_MS).toBe(env.MEM9_PUBLICATION_DEADLINE_MS);
});
it('the independent valid publication fixture reaches the actual handler credential edge',async()=>{
 const {env}=await publicationEnv();let reads=0;
 Object.defineProperty(env,'MEM9_DB_SECRET',{get(){reads++;throw Error('SyntheticValidatedCredentialEdge');}});
 await expect(runContinuationInspection(env)).rejects.toThrow('SyntheticValidatedCredentialEdge');expect(reads).toBe(1);
});
it.each(['nonce','missing-hash','hash','missing-deadline','deadline','expired-start','future-start','extra-field','wrong-source','wrong-descriptor','wrong-operation'])('actual publication handler rejects %s before touching a credential getter',async defect=>{
 const {env,request}=await publicationEnv();let reads=0;
 if(defect==='nonce')env.MEM9_PUBLICATION_INVOCATION='b'.repeat(32);
 if(defect==='missing-hash')delete env.MEM9_PUBLICATION_REQUEST_HASH;if(defect==='hash')env.MEM9_PUBLICATION_REQUEST_HASH='0'.repeat(64);
 if(defect==='missing-deadline')delete env.MEM9_PUBLICATION_DEADLINE_MS;if(defect==='deadline')env.MEM9_PUBLICATION_DEADLINE_MS=String(request.deadlineMs+1);
 if(defect==='expired-start')request.issuedMs-=PUBLICATION_STARTUP_MS+1000;if(defect==='future-start')request.issuedMs+=100000;
 if(defect==='extra-field')request.sql='SELECT 1';if(defect==='wrong-source')request.witness.sourceTree='0'.repeat(40);
 if(defect==='wrong-descriptor')request.dataRelease.data.version=2;if(defect==='wrong-operation')env.MEM9_CONTINUATION_OPERATION='publication-probe';
 if(['expired-start','future-start','extra-field','wrong-source','wrong-descriptor'].includes(defect)){
  if(defect.endsWith('start')){request.deadlineMs=request.issuedMs+PUBLICATION_STARTUP_MS+PUBLICATION_WATCHDOG_MS;env.MEM9_PUBLICATION_DEADLINE_MS=String(request.deadlineMs);}
  env.MEM9_PUBLICATION_REQUEST=JSON.stringify(request);env.MEM9_PUBLICATION_REQUEST_HASH=createHash('sha256').update(env.MEM9_PUBLICATION_REQUEST).digest('hex');
 }
 Object.defineProperty(env,'MEM9_DB_SECRET',{get(){reads++;throw Error('CredentialMustNotBeRead');}});
 await expect(runContinuationInspection(env)).rejects.toThrow();expect(reads).toBe(0);
});
