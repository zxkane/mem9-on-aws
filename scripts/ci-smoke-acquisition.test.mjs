import {it,expect,vi,afterEach} from 'vitest';
import {mkdtemp,writeFile,readFile,mkdir,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';import {Readable} from 'node:stream';
import {S3Client,GetObjectCommand} from '@aws-sdk/client-s3';
import {openCiSmokeAcquisition,acquisitionOwnerKey,createCiSmokeAcquisitionConfig,openCiSmokeDeploymentLocalReplay} from './lib/ci-smoke-acquisition.mjs';
import {hash,sha,zero,prepaidSlotBudget,validCheckpoint,parseAcquisitionJson} from './lib/ci-smoke-acquisition-format.mjs';
import {createNonrootBudgetedReads} from './lib/production-nonroot-budget-transport.mjs';
import {GetParametersCommand} from '@aws-sdk/client-ssm';
import {DescribeTaskDefinitionCommand} from '@aws-sdk/client-ecs';
import {PRODUCTION_DATA_RELEASE_PARAMETER as parameterName} from './lib/production-data-issuance.mjs';
import {PREVIEW_ACQUISITION_LIMITS} from './lib/ci-smoke-preview-acquisition.mjs';
const cleanup=[];afterEach(async()=>{vi.restoreAllMocks();for(const path of cleanup.splice(0))await rm(path,{recursive:true,force:true});});
async function fixture({checkpoint='deploy-prod/21',jobKey='deploy-prod',preview=jobKey.endsWith('preview'),extraCalls=[],phase='preupdate',localBudget:localAllowance=zero()}={}){
 const root=await mkdtemp(join(tmpdir(),'acquisition-fixture-'));cleanup.push(root);const put=async(name,value)=>{const raw=Buffer.isBuffer(value)?value:Buffer.from(JSON.stringify(value)),path=join(root,name);await writeFile(path,raw,{mode:0o600});return {path,sha256:sha(raw)};},now=Date.now(),proof={synthetic:'proof'},descriptor={version:3,stage:'prod',account:'123456789012',region:'us-east-1',runtimeNonce:'a'.repeat(32),authorizationId:'b'.repeat(32),expiresMs:now+600000,transition:{proofHash:hash(proof)}};
 const scope={descriptorHash:hash(descriptor),proofHash:hash(proof),sourceTree:'c'.repeat(40),repository:'example/repository',mainRevision:'d'.repeat(40),runId:77,runAttempt:1,jobKey,route:jobKey,phase,checkpoint,account:descriptor.account,region:descriptor.region},binding={owner:'e'.repeat(32),executionId:'f'.repeat(32),planHash:'1'.repeat(64),publicationHash:'2'.repeat(64)};
 if(preview){scope.descriptorHash=null;scope.proofHash=null;scope.target={kind:'preview-bootstrap',stage:'pr-17'};}
 const seed={version:1,kind:'owner-ci-acquisition-seed',expected:{scope,ledgerBinding:binding,ledgerStartHash:'0'.repeat(64),catalogHash:'3'.repeat(64)},descriptor,parameterVersion:3,expiresMs:now+300000,allocation:{bucket:'example-owned-artifacts',key:'',sha256:'0'.repeat(64),bytesLength:1,requestBytes:4096,responseBytes:33554432,kmsKeyArn:'arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',bucketKeyEnabled:true}};seed.allocation.key=acquisitionOwnerKey(seed);
 const calls=[{action:'GetObject',request:{Bucket:seed.allocation.bucket,Key:seed.allocation.key,ExpectedBucketOwner:scope.account},requestBytes:4096,responseBytes:33554432,ecr:false},{action:'GetParameters',request:preview?{Names:['purpose-bindings','cluster-name','subnet-ids','task-sg-id'].map(n=>'/mem9-on-aws/pr-17/bootstrap/'+n),WithDecryption:false}:{Names:[parameterName],WithDecryption:true},requestBytes:2048,responseBytes:32768,ecr:false},...extraCalls],localBudget=localAllowance,budget=prepaidSlotBudget(calls,localBudget),plan={version:1,kind:'named-prepayment-plan',catalogHash:seed.expected.catalogHash,ledgerBinding:binding,scope,calls,localBudget,budget},allocationId=hash(plan),starting={ecrRequests:7,logicalBytes:1000,httpBodyBytes:2000,uncompressedBytes:0,processedEntries:0};
 const start={version:1,kind:'custody-ledger-start',binding,startingCounters:starting,reserve:budget,deadlineMs:now+180000,mode:'adoption'},startRaw=Buffer.from(JSON.stringify(start)+'\n');seed.expected.ledgerStartHash=sha(startRaw);const counters=Object.fromEntries(Object.keys(starting).map(k=>[k,starting[k]+budget[k]]));
 const event={version:1,sequence:1,...binding,previousHash:null,type:'prepayment',data:{allocationId,planHash:hash(plan),scopeHash:hash(scope),charge:budget,reserveDebit:budget},spent:counters,remaining:zero()},allocation={version:2,kind:'owner-prepaid-named-allocation',authority:false,allocationId,plan,runEvidence:{observedMs:now-1000,run:{id:scope.runId,run_attempt:1,head_sha:scope.mainRevision,head_branch:'main',event:'push',path:'.github/workflows/infra-ci.yml',status:'in_progress',created_at:new Date(now-10000).toISOString(),repository:{full_name:scope.repository}},commit:{sha:scope.mainRevision,tree:{sha:scope.sourceTree}}},debit:{start,startRaw:startRaw.toString('base64'),events:[event],checkpoint:{binding,startingCounters:starting,counters,remainingReservation:zero(),eventCount:1,lastEventHash:hash(event),active:0,sealed:false}}};
 let allocationRaw=Buffer.from(JSON.stringify(allocation));seed.allocation.sha256=sha(allocationRaw);seed.allocation.bytesLength=allocationRaw.length;const seedRef=await put('owner-seed.json',seed),sourceReceipt={current:{repository:scope.repository,runId:77,runAttempt:1,job:jobKey,revision:scope.mainRevision},checkout:{revision:scope.mainRevision,tree:scope.sourceTree},commitment:{synthetic:true},observedMs:now-500,expiresMs:now+300000},sourceRef=await put('source.json',sourceReceipt);
 const env={GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:scope.repository,GITHUB_RUN_ID:'77',GITHUB_RUN_ATTEMPT:'1',GITHUB_JOB:jobKey,GITHUB_SHA:scope.mainRevision,AWS_REGION:scope.region,MEM9_DEPLOY_ROLE_ARN:'arn:aws:iam::'+scope.account+':role/github-actions-mem9-on-aws-'+(preview?'preview':'prod'),RUNNER_TEMP:root,STAGE:preview?'pr-17':'prod',MEM9_CI_ACQUISITION_CONFIG:JSON.stringify({version:1,kind:'owner-ci-acquisition-config',account:scope.account,region:scope.region,ownerRoot:{runtimeNonce:descriptor.runtimeNonce,authorizationId:descriptor.authorizationId},ledgerBinding:binding,ledgerStartHash:seed.expected.ledgerStartHash,catalogHash:seed.expected.catalogHash,expiresMs:seed.expiresMs,target:preview?{kind:'preview-bootstrap'}:{kind:'production-data-release',descriptor,parameterVersion:seed.parameterVersion},storage:Object.fromEntries(['bucket','requestBytes','responseBytes','kmsKeyArn','bucketKeyEnabled'].map(k=>[k,seed.allocation[k]]))}),MEM9_CI_SMOKE_SOURCE_RECEIPT:sourceRef.path,MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH:sourceRef.sha256,AWS_ACCESS_KEY_ID:'ASIA'+'A'.repeat(16),AWS_SECRET_ACCESS_KEY:'synthetic-not-issued',AWS_SESSION_TOKEN:'synthetic-not-issued'},host={env,cwd:root,checkout:async()=>sourceReceipt.checkout},input={env,scope:{route:jobKey,phase:scope.phase,checkpoint},sourceReceipt,host};
 const originalSend=S3Client.prototype.send;const send=vi.spyOn(S3Client.prototype,'send').mockImplementation(async function(command,...args){if(command.input.Key!==seed.allocation.key)return originalSend.call(this,command,...args);return {$metadata:{httpStatusCode:200},ContentLength:allocationRaw.length,ServerSideEncryption:'aws:kms',SSEKMSKeyId:seed.allocation.kmsKeyArn,BucketKeyEnabled:true,Body:Readable.from([allocationRaw])};});
 const response=preview?{InvalidParameters:calls[1].request.Names,Parameters:[]}:{InvalidParameters:[],Parameters:[{Name:parameterName,Type:'SecureString',ARN:`arn:aws:ssm:${scope.region}:${scope.account}:parameter${parameterName}`,Version:3,Value:JSON.stringify(descriptor)}]};
 return {root,put,seed,allocation,input,send,response,calls,async rewriteSeed(){const cfg=JSON.parse(env.MEM9_CI_ACQUISITION_CONFIG);cfg.storage=Object.fromEntries(['bucket','requestBytes','responseBytes','kmsKeyArn','bucketKeyEnabled'].map(k=>[k,seed.allocation[k]]));env.MEM9_CI_ACQUISITION_CONFIG=JSON.stringify(cfg);},async changeAllocation(fn){fn(allocation);allocationRaw=Buffer.from(JSON.stringify(allocation));seed.allocation.sha256=sha(allocationRaw);seed.allocation.bytesLength=allocationRaw.length;await this.rewriteSeed();},async bundle(){const b=preview?{kind:'nonroot-preview-phase-bundle',source:{revision:scope.mainRevision,sourceTree:scope.sourceTree},phaseReceipt:{phase:scope.phase,sourceReceiptHash:sourceRef.sha256,observedMs:Date.now(),expiresMs:seed.expiresMs,stage:'pr-17',account:scope.account,region:scope.region,sourceTree:scope.sourceTree}}:{version:2,kind:'image-security-nonroot-deployment-bundle',phase:'deployment',source:{checkout:{sha:scope.mainRevision,tree:scope.sourceTree}},parameter:{Name:parameterName,Type:'SecureString',ARN:`arn:aws:ssm:${scope.region}:${scope.account}:parameter${parameterName}`,Version:3,Value:JSON.stringify(descriptor)},proof,phaseReceipt:{phase:scope.phase,sourceReceiptHash:sourceRef.sha256,observedMs:Date.now(),expiresMs:seed.expiresMs}};return put('new-bundle.json',b);}};
}
it('opens from an independent owner seed without a future phase bundle, checks first live descriptor, and binds bundle afterwards',async()=>{const f=await fixture(),slot=await openCiSmokeAcquisition(f.input);expect(f.send).toHaveBeenCalledTimes(1);expect(f.send.mock.calls[0][0].input).toEqual(f.calls[0].request);expect(slot.authority).toBe(false);const meter=await slot.beforeRead('GetParameters',f.calls[1].request);meter.finalGuard();meter.charge(100);await meter.complete(f.response,sha(JSON.stringify(f.response)));const result=await slot.finish({bundleRef:await f.bundle()});expect(result.authority).toBe(false);await expect(openCiSmokeAcquisition(f.input)).rejects.toMatchObject({code:'EEXIST'});expect(f.send).toHaveBeenCalledTimes(1);});
it('missing independent seed fails before S3/SSM/ECR',async()=>{const f=await fixture();delete f.input.env.MEM9_CI_ACQUISITION_CONFIG;await expect(openCiSmokeAcquisition(f.input)).rejects.toThrow('CiAcquisitionOwnerConfigRequired');expect(f.send).not.toHaveBeenCalled();});
it('a live descriptor different from the owner anchor holds with no followup permission',async()=>{const f=await fixture(),slot=await openCiSmokeAcquisition(f.input),meter=await slot.beforeRead('GetParameters',f.calls[1].request);meter.finalGuard();f.response.Parameters[0].Value=JSON.stringify({...f.seed.descriptor,runtimeNonce:'0'.repeat(32)});await expect(meter.complete(f.response,sha(JSON.stringify(f.response)))).rejects.toThrow('CiAcquisitionLiveDescriptor');await expect(slot.beforeRead('GetParameters',f.calls[1].request)).rejects.toThrow('CiAcquisitionClosed');});
it('allocation cannot replace independent ledger anchors with a self-consistent counter reset',async()=>{const f=await fixture();await f.changeAllocation(a=>{a.debit.start.startingCounters.httpBodyBytes=0;a.debit.startRaw=Buffer.from(JSON.stringify(a.debit.start)+'\n').toString('base64');});await expect(openCiSmokeAcquisition(f.input)).rejects.toThrow('PrepaidLedgerAnchor');expect(f.send).toHaveBeenCalledTimes(1);});
it('an unprotected object prefix and wrong expected owner scope are rejected before fetching',async()=>{const f=await fixture();const cfg=JSON.parse(f.input.env.MEM9_CI_ACQUISITION_CONFIG);cfg.ownerRoot.runtimeNonce='wrong';f.input.env.MEM9_CI_ACQUISITION_CONFIG=JSON.stringify(cfg);await expect(openCiSmokeAcquisition(f.input)).rejects.toThrow();expect(f.send).not.toHaveBeenCalled();});
for(const [jobKey,index]of [['runtime-cutover-prod',7],['runtime-cutover-preview',6],['runtime-cutover-preview',10]])it('accepts the exact shared composite path '+jobKey+'/'+index,async()=>{const checkpoint=jobKey+'/'+index+'/.github/actions/runtime-cutover/action.yml/2',f=await fixture({jobKey,checkpoint});expect(validCheckpoint(jobKey,checkpoint)).toBe(true);const slot=await openCiSmokeAcquisition(f.input);expect(slot.authority).toBe(false);expect(validCheckpoint(jobKey,jobKey+'/999/.github/actions/runtime-cutover/action.yml/2')).toBe(false);});
it('current job/run/source cannot replay another allocation',async()=>{const f=await fixture();f.input.env.GITHUB_RUN_ATTEMPT='2';await expect(openCiSmokeAcquisition(f.input)).rejects.toThrow('CiAcquisitionSourceJob');expect(f.send).not.toHaveBeenCalled();});
it('local work is blocked before the live descriptor and writes have no allocation',async()=>{const f=await fixture(),slot=await openCiSmokeAcquisition(f.input);expect(()=>slot.reserveLocal(zero())).toThrow('CiAcquisitionLiveDescriptorFirst');await expect(slot.beforeRead('PutParameter',{})).rejects.toThrow();});
it('owner object response protection and raw bytes are mandatory',async()=>{const f=await fixture();f.send.mockResolvedValue({$metadata:{httpStatusCode:200},ContentLength:2,ServerSideEncryption:'AES256',Body:Readable.from(['{}'])});await expect(openCiSmokeAcquisition(f.input)).rejects.toThrow('CiAcquisitionOwnerResponse');await expect(openCiSmokeAcquisition(f.input)).rejects.toMatchObject({code:'EEXIST'});});
it('preview reads only its own bootstrap parameters, has no prod descriptor, and accepts a memory-only preview bundle',async()=>{const f=await fixture({jobKey:'deploy-preview',checkpoint:'deploy-preview/21',preview:true}),slot=await openCiSmokeAcquisition(f.input);expect(slot.authorizationSeed.kind).toBe('preview-independent-verification');expect(slot.authorizationSeed.descriptor).toBeUndefined();expect(JSON.parse(f.input.env.MEM9_CI_ACQUISITION_CONFIG).target).toEqual({kind:'preview-bootstrap'});const identity=await slot.beforeRead('GetCallerIdentity',{});identity.finalGuard();const who={Account:f.seed.expected.scope.account,Arn:'arn:aws:sts::'+f.seed.expected.scope.account+':assumed-role/github-actions-mem9-on-aws-preview/fixture'};await identity.complete(who,sha(JSON.stringify(who)));const m=await slot.beforeRead('GetParameters',f.calls[1].request);m.finalGuard();await m.complete(f.response,sha(JSON.stringify(f.response)));const file=await f.bundle(),value=JSON.parse(await readFile(file.path));const done=await slot.finish({bundleRef:{value,canonicalHash:hash(value)}});expect(done.authority).toBe(false);});
it('preview cannot use production SSM or a production allocation',async()=>{const f=await fixture({jobKey:'deploy-preview',checkpoint:'deploy-preview/21',preview:true});delete f.input.env.MEM9_CI_ACQUISITION_CONFIG;const slot=await openCiSmokeAcquisition(f.input);await expect(slot.beforeRead('GetParameters',{Names:[parameterName],WithDecryption:true})).rejects.toThrow('PreviewAcquisitionParameterScope');expect(f.send).not.toHaveBeenCalled();});
it.each(['DescribeServices','ListTasks'])('accepts the fixed SST service name only inside the scoped preview cluster for %s',async action=>{
 for(const valid of [true,false]){
  const f=await fixture({jobKey:'deploy-preview',checkpoint:'deploy-preview/21',preview:true}),slot=await openCiSmokeAcquisition(f.input);
  const identity=await slot.beforeRead('GetCallerIdentity',{});identity.finalGuard();
  const who={Account:f.seed.expected.scope.account,Arn:'arn:aws:sts::'+f.seed.expected.scope.account+':assumed-role/github-actions-mem9-on-aws-preview/fixture'};
  await identity.complete(who,sha(JSON.stringify(who)));
  const request={cluster:'mem9-on-aws-'+(valid?'pr-17':'pr-18')+'-Cluster-example',...(action==='DescribeServices'?{services:['Mem9Server']}:{serviceName:'Mem9Server',desiredStatus:'RUNNING',maxResults:100})};
  if(valid){const read=await slot.beforeRead(action,request);read.finalGuard();await read.complete({},sha('{}'));}
  else await expect(slot.beforeRead(action,request)).rejects.toThrow('PreviewAcquisitionEcsScope');
 }
});
it('allows the actual IAM/KMS read set but never a mutation',()=>{for(const action of ['GetRole','ListRolePolicies','ListAttachedRolePolicies','GetRolePolicy','GetPolicy','GetPolicyVersion','DescribeKey'])expect(prepaidSlotBudget([{action,request:{},requestBytes:4096,responseBytes:8192,ecr:false}],zero()).ecrRequests).toBe(0);for(const action of ['PutRolePolicy','CreateKey','PutParameter','RunTask'])expect(()=>prepaidSlotBudget([{action,request:{},requestBytes:4096,responseBytes:8192,ecr:false}],zero())).toThrow();});
it('uses the bounded 32MiB transport parser without truncation or duplicate-key acceptance',()=>{const bytes=Buffer.from(JSON.stringify({payload:'x'.repeat(8388609)}));expect(parseAcquisitionJson(bytes).payload.length).toBe(8388609);expect(()=>parseAcquisitionJson(Buffer.from('{"a":1,"\\u0061":2}'))).toThrow('CiAcquisitionDuplicateKey');expect(()=>parseAcquisitionJson(Buffer.alloc(33554433))).toThrow('CiAcquisitionJsonSize');});
it('creates static owner config from independent ledger/catalog records with no future run or allocation fields',async()=>{const f=await fixture(),c=JSON.parse(f.input.env.MEM9_CI_ACQUISITION_CONFIG),raw=Buffer.from(f.allocation.debit.startRaw,'base64'),catalog=Buffer.from(JSON.stringify({kind:'cumulative-acquisition-catalog',ledgerBinding:c.ledgerBinding})),made=createCiSmokeAcquisitionConfig({account:c.account,region:c.region,ownerRoot:c.ownerRoot,ledgerStartBytes:raw,catalogBytes:catalog,expiresMs:c.expiresMs,target:c.target,storage:c.storage});expect(made.ledgerStartHash).toBe(sha(raw));expect(made.catalogHash).toBe(sha(catalog));expect(made.runId).toBeUndefined();expect(made.sourceReceiptHash).toBeUndefined();expect(made.allocationHash).toBeUndefined();});
it('composes with the real budget transport complete(response,responseHash) contract',async()=>{const f=await fixture(),acquisition=await openCiSmokeAcquisition(f.input),raw=Buffer.from(JSON.stringify(f.response));let httpCalls=0;const requestHandler={async handle(){httpCalls++;return {response:{statusCode:200,headers:{'content-type':'application/x-amz-json-1.1','content-length':String(raw.length)},body:Readable.from([raw])}};},destroy(){}};const transport=createNonrootBudgetedReads({region:f.seed.expected.scope.region,env:f.input.env,metadataReads:acquisition,requestHandler});try{await transport.clients.ssm.send(new GetParametersCommand(f.calls[1].request));expect(httpCalls).toBe(1);const done=await acquisition.finish({bundleRef:await f.bundle()});expect(done.authority).toBe(false);const files=await readFile(done.receiptRef.path,'utf8');expect(files).toContain('"ownerRefund":0');}finally{transport.close();}});
it('source CI preview runs before any production ledger/config exists and performs zero owner-allocation reads',async()=>{const f=await fixture({jobKey:'deploy-preview',checkpoint:'deploy-preview/21'});delete f.input.env.MEM9_CI_ACQUISITION_CONFIG;const slot=await openCiSmokeAcquisition(f.input),m=await slot.beforeRead('GetCallerIdentity',{});m.finalGuard();const who={Account:f.seed.expected.scope.account,Arn:'arn:aws:sts::'+f.seed.expected.scope.account+':assumed-role/github-actions-mem9-on-aws-preview/fixture'};await m.complete(who,sha(JSON.stringify(who)));const read=await slot.beforeRead('GetParameters',f.calls[1].request);read.finalGuard();await read.complete(f.response,sha(JSON.stringify(f.response)));const done=await slot.finish({bundleRef:await f.bundle()}),record=JSON.parse(await readFile(done.receiptRef.path));expect(record.productionLedger).toBeNull();expect(record.reads).toBe(2);expect(f.send).not.toHaveBeenCalled();});
it('runs the entire preview readiness sequence with distinct budgets but one unchanged source/job deadline',async()=>{
 const f=await fixture({jobKey:'deploy-preview',checkpoint:'deploy-preview/16',phase:'prereadiness'}),started=Date.now();
 let clock=started;vi.spyOn(Date,'now').mockImplementation(()=>clock);
 // Establish the original synthetic job window once, before any checkpoint.
 f.input.sourceReceipt.expiresMs=started+3600000;
 const sourceRef=await f.put('source.json',f.input.sourceReceipt);
 f.input.env.MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH=sourceRef.sha256;
 delete f.input.env.MEM9_CI_ACQUISITION_CONFIG;
 const sourceBytes=await readFile(sourceRef.path),records=[];
 const checkpoints=[16,17,18,19,20,21,22,23,24,26];
 // Long Scheduler, Canary, performance and human steps are synthetic timings.
 const minutesBefore=[0,1,1,18,12,1,1,8,1,8];
 for(let i=0;i<checkpoints.length;i++){
  clock+=minutesBefore[i]*60000;
  const checkpoint='deploy-preview/'+checkpoints[i],input={...f.input,scope:{...f.input.scope,checkpoint}};
  const slot=await openCiSmokeAcquisition(input),who={Account:f.seed.expected.scope.account,Arn:'arn:aws:sts::'+f.seed.expected.scope.account+':assumed-role/github-actions-mem9-on-aws-preview/fixture'};
  for(const [action,request,response]of [['GetCallerIdentity',{},who],['GetParameters',f.calls[1].request,f.response]]){
   const read=await slot.beforeRead(action,request);read.finalGuard();read.charge(100);await read.complete(response,sha(JSON.stringify(response)));
  }
  const value={kind:'nonroot-preview-phase-bundle',source:{sourceTree:f.input.sourceReceipt.checkout.tree},phaseReceipt:{phase:'prereadiness',sourceReceiptHash:sourceRef.sha256,observedMs:clock,expiresMs:Math.min(clock+300000,f.input.sourceReceipt.expiresMs),stage:'pr-17',account:f.seed.expected.scope.account,region:f.seed.expected.scope.region,sourceTree:f.input.sourceReceipt.checkout.tree}};
  const done=await slot.finish({bundleRef:{value,canonicalHash:hash(value)}}),complete=JSON.parse(await readFile(done.receiptRef.path)),claim=JSON.parse(await readFile(complete.claimRef.path));
  expect(claim.scope.checkpoint).toBe(checkpoint);expect(claim.startedMs).toBe(clock);
  expect(claim.deadlineMs).toBe(Math.min(f.input.sourceReceipt.expiresMs,clock+PREVIEW_ACQUISITION_LIMITS.durationMs));
  expect(claim.sourceReceiptRef).toEqual(sourceRef);expect(claim.productionLedger).toBeNull();
  expect(complete.reads).toBe(2);expect(complete.observedWireBytes).toBe(200);expect(done.authority).toBe(false);
  records.push({ref:complete.claimRef,raw:await readFile(complete.claimRef.path)});
 }
 expect(new Set(records.map(x=>x.ref.path)).size).toBe(checkpoints.length);
 for(const record of records)expect(await readFile(record.ref.path)).toEqual(record.raw);
 expect(await readFile(sourceRef.path)).toEqual(sourceBytes);expect(f.send).not.toHaveBeenCalled();
 clock=f.input.sourceReceipt.expiresMs;
 await expect(openCiSmokeAcquisition(f.input)).rejects.toThrow('PreviewAcquisitionExpired');
 expect(await readFile(sourceRef.path)).toEqual(sourceBytes);
});
it.each(['source-bytes','attempt','job','revision','role','expired-source'])('cannot obtain a fresh preview checkpoint after %s drift',async defect=>{
 const f=await fixture({jobKey:'deploy-preview',checkpoint:'deploy-preview/19',phase:'prereadiness'});
 if(defect==='source-bytes')await writeFile(f.input.env.MEM9_CI_SMOKE_SOURCE_RECEIPT,'{}',{mode:0o600});
 if(defect==='attempt')f.input.env.GITHUB_RUN_ATTEMPT='2';
 if(defect==='job')f.input.env.GITHUB_JOB='deploy-prod';
 if(defect==='revision')f.input.env.GITHUB_SHA='f'.repeat(40);
 if(defect==='role')f.input.env.MEM9_DEPLOY_ROLE_ARN=f.input.env.MEM9_DEPLOY_ROLE_ARN.replace('-preview','-prod');
 if(defect==='expired-source')vi.spyOn(Date,'now').mockReturnValue(f.input.sourceReceipt.expiresMs);
 await expect(openCiSmokeAcquisition(f.input)).rejects.toThrow();expect(f.send).not.toHaveBeenCalled();
});
it.each(['caller','unknown'])('a fresh checkpoint holds on %s failure without retry or claim reset',async defect=>{
 const f=await fixture({jobKey:'deploy-preview',checkpoint:'deploy-preview/19',phase:'prereadiness'}),slot=await openCiSmokeAcquisition(f.input),read=await slot.beforeRead('GetCallerIdentity',{});
 read.finalGuard();read.charge(100);
 if(defect==='caller')await expect(read.complete({Account:'9'.repeat(12),Arn:'arn:aws:sts::'+'9'.repeat(12)+':assumed-role/foreign/fixture'},sha('{}'))).rejects.toThrow('PreviewAcquisitionCaller');
 else await read.unknown();
 await expect(slot.beforeRead('GetCallerIdentity',{})).rejects.toThrow();
 await expect(openCiSmokeAcquisition(f.input)).rejects.toMatchObject({code:'EEXIST'});
 expect(f.send).not.toHaveBeenCalled();
});
it.each(['preupdate','preconfigure','presst','prereadiness'])('the derived 40-call ceiling cannot reset in preview phase %s',async phase=>{
 expect(PREVIEW_ACQUISITION_LIMITS).toEqual({maxCalls:40,durationMs:300000,responseBytes:4194304,requestBytes:16384,journalBytes:4194304,localSourceBytes:33554432});
 const f=await fixture({jobKey:'deploy-preview',checkpoint:'deploy-preview/26',phase}),slot=await openCiSmokeAcquisition(f.input),who={Account:f.seed.expected.scope.account,Arn:'arn:aws:sts::'+f.seed.expected.scope.account+':assumed-role/github-actions-mem9-on-aws-preview/fixture'};
 for(let i=0;i<PREVIEW_ACQUISITION_LIMITS.maxCalls;i++){
  const first=i===0,read=await slot.beforeRead(first?'GetCallerIdentity':'GetParameters',first?{}:f.calls[1].request),response=first?who:f.response;
  read.finalGuard();read.charge(100);await read.complete(response,sha(JSON.stringify(response)));
 }
 await expect(slot.beforeRead('GetParameters',f.calls[1].request)).rejects.toThrow('PreviewAcquisitionCallLimit');
 await expect(openCiSmokeAcquisition(f.input)).rejects.toMatchObject({code:'EEXIST'});expect(f.send).not.toHaveBeenCalled();
});
it('prices both additional raw definition readbacks through the real transport and journal',async()=>{
 const f=await fixture({jobKey:'deploy-preview',checkpoint:'deploy-preview/21',phase:'prereadiness'}),slot=await openCiSmokeAcquisition(f.input);
 const who={Account:f.seed.expected.scope.account,Arn:'arn:aws:sts::'+f.seed.expected.scope.account+':assumed-role/github-actions-mem9-on-aws-preview/fixture'};
 for(let i=0;i<38;i++){
  const read=await slot.beforeRead(i?'GetParameters':'GetCallerIdentity',i?f.calls[1].request:{}),response=i?f.response:who;
  read.finalGuard();read.charge(100);await read.complete(response,sha(JSON.stringify(response)));
 }
 let httpCalls=0,actualWire=3800;
 const raw=Buffer.from(JSON.stringify({taskDefinition:{family:'mem9-on-aws-pr-17-Cluster-Mem9Bootstrap',revision:1,status:'ACTIVE'},tags:[]}));
 const requestHandler={async handle(request){httpCalls++;actualWire+=Buffer.byteLength(request.body)+raw.length;
  return {response:{statusCode:200,headers:{'content-type':'application/x-amz-json-1.1','content-length':String(raw.length)},body:Readable.from([raw])}};
 },destroy(){}};
 const transport=createNonrootBudgetedReads({region:f.seed.expected.scope.region,env:f.input.env,metadataReads:slot,requestHandler});
 try{
  for(const revision of [11,12])await transport.clients.ecs.send(new DescribeTaskDefinitionCommand({taskDefinition:`arn:aws:ecs:${f.seed.expected.scope.region}:${f.seed.expected.scope.account}:task-definition/mem9-on-aws-pr-17-Cluster-Mem9Bootstrap:${revision}`,include:['TAGS']}));
  const done=await slot.finish({bundleRef:await f.bundle()}),record=JSON.parse(await readFile(done.receiptRef.path));
  expect(record.reads).toBe(40);expect(record.observedWireBytes).toBe(actualWire);expect(record.productionLedger).toBeNull();expect(httpCalls).toBe(2);
  const header=Buffer.byteLength(JSON.stringify({version:1,claimRef:record.claimRef,index:40,action:'x'.repeat(32),request:null}))-4;
  expect(40*(header+16384-1024)).toBeLessThanOrEqual(PREVIEW_ACQUISITION_LIMITS.journalBytes);
 }finally{transport.close();}
});
it('streamed GetObject composes with the real transport and leaves Body readable for the caller',async()=>{const q={Bucket:'example-owned-artifacts',Key:'decisions/prod/control-build/77/1/example.json',ExpectedBucketOwner:'123456789012'},f=await fixture({extraCalls:[{action:'GetObject',request:q,requestBytes:4096,responseBytes:4096,ecr:false}]}),slot=await openCiSmokeAcquisition(f.input);let n=0;const payload=Buffer.from('{"synthetic":"control-capture"}'),handler={async handle(){const raw=++n===1?Buffer.from(JSON.stringify(f.response)):payload;return {response:{statusCode:200,headers:{'content-length':String(raw.length),'content-type':'application/json'},body:Readable.from([raw])}};},destroy(){}};
 const transport=createNonrootBudgetedReads({region:f.seed.expected.scope.region,env:f.input.env,metadataReads:slot,requestHandler:handler});try{await transport.clients.ssm.send(new GetParametersCommand(f.calls[1].request));const object=await transport.clients.s3.send(new GetObjectCommand(q));expect(object.Body).toBeInstanceOf(Readable);expect(await object.Body.transformToString()).toBe(payload.toString());const done=await slot.finish({bundleRef:await f.bundle()});expect(done.authority).toBe(false);expect(n).toBe(2);}finally{transport.close();}});
it('complete never serializes a supplied S3 stream or its internals',async()=>{const q={Bucket:'example-owned-artifacts',Key:'decisions/prod/control-build/77/1/example.json',ExpectedBucketOwner:'123456789012'},f=await fixture({extraCalls:[{action:'GetObject',request:q,requestBytes:4096,responseBytes:4096,ecr:false}]}),slot=await openCiSmokeAcquisition(f.input),first=await slot.beforeRead('GetParameters',f.calls[1].request);first.finalGuard();await first.complete(f.response,sha(JSON.stringify(f.response)));const read=await slot.beforeRead('GetObject',q);read.finalGuard();const body=Readable.from(['payload']);body.toJSON=()=>{throw Error('StreamMustNotBeSerialized');};await read.complete({Body:body,ContentLength:7},sha('payload'));expect(await body.toArray()).toEqual(['payload']);await slot.finish({bundleRef:await f.bundle()});});

async function localReplayFixture({phase='presst',allowance=1000,spent=400}={}){
 const f=await fixture({phase,checkpoint:phase==='presst'?'deploy-prod/19':'deploy-prod/17',localBudget:{...zero(),logicalBytes:allowance,uncompressedBytes:2000,processedEntries:10}});
 const slot=await openCiSmokeAcquisition(f.input),read=await slot.beforeRead('GetParameters',f.calls[1].request);
 read.finalGuard();await read.complete(f.response,sha(JSON.stringify(f.response)));
 slot.reserveLocal({...zero(),logicalBytes:spent});
 const bundleRef=await f.bundle(),completed=await slot.finish({bundleRef});
 const input={env:f.input.env,completionRef:completed.receiptRef,bundleRef,knownParameter:{...f.response.Parameters[0],LastModifiedDate:new Date()}};
 return {...f,slot,completed,input};
}
it.each(['preconfigure','presst'])('restores unused prepaid local work for %s without a second cloud read',async phase=>{
 const f=await localReplayFixture({phase}),local=await openCiSmokeDeploymentLocalReplay(f.input);
 expect(local.beforeRead).toBeUndefined();expect(local.authority).toBe(false);
 expect(local.reserveLocal({...zero(),logicalBytes:200})).toMatchObject({logicalBytes:600});
 const result=await local.finish(),record=JSON.parse(await readFile(result.receiptRef.path));
 expect(record.startingLocalUsed.logicalBytes).toBe(400);expect(record.localUsed.logicalBytes).toBe(600);expect(record.ownerRefund).toBe(0);
 expect(f.send).toHaveBeenCalledTimes(1);
 await expect(openCiSmokeDeploymentLocalReplay(f.input)).rejects.toMatchObject({code:'EEXIST'});
 expect(f.send).toHaveBeenCalledTimes(1);
});
it('cannot reset previous local use, borrow network allowance, or retry a held local claim',async()=>{
 const f=await localReplayFixture({allowance:400}),local=await openCiSmokeDeploymentLocalReplay(f.input);
 expect(()=>local.reserveLocal({...zero(),logicalBytes:1})).toThrow('CiLocalReplayBudget');
 expect(()=>local.reserveLocal(zero())).toThrow('CiLocalReplayClosed');await local.hold();
 await expect(openCiSmokeDeploymentLocalReplay(f.input)).rejects.toMatchObject({code:'EEXIST'});
});
it.each(['parameter-version','bundle-reference','run','expired','allocation-bytes'])('rejects local replay with changed %s',async defect=>{
 const f=await localReplayFixture();
 if(defect==='parameter-version')f.input.knownParameter.Version++;
 if(defect==='bundle-reference')f.input.bundleRef={...f.input.bundleRef,sha256:'f'.repeat(64)};
 if(defect==='run')f.input.env={...f.input.env,GITHUB_RUN_ATTEMPT:'2'};
 if(defect==='expired')vi.spyOn(Date,'now').mockReturnValue(f.seed.expiresMs+1);
 if(defect==='allocation-bytes'){
  const done=JSON.parse(await readFile(f.completed.receiptRef.path));await writeFile(done.allocationRef.path,'{}',{mode:0o600});
 }
 await expect(openCiSmokeDeploymentLocalReplay(f.input)).rejects.toThrow();expect(f.send).toHaveBeenCalledTimes(1);
});
