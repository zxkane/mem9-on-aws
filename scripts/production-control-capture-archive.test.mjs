import {beforeAll,it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {Readable} from 'node:stream';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {captureNonrootControlBuildAction,completeNonrootControlBuildAction} from './lib/production-nonroot-control-build.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {createNonrootBudgetedReads} from './lib/production-nonroot-budget-transport.mjs';
import {encodeControlBuildCapture,decodeControlBuildCapture,inspectControlBuildCommitment,controlBuildArchiveKey,controlBuildArchiveLocation,putControlBuildCapture,getControlBuildCapture,inspectControlBuildTransferReceipt} from './lib/production-control-capture-archive.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const json=v=>Buffer.from(JSON.stringify(v,null,2)+'\n');
let f,records;
beforeAll(async()=>{
 f=await nonrootDeploymentFixture();
 const job={...f.rawJob,status:'in_progress',conclusion:null,started_at:new Date(f.now-10000).toISOString(),completed_at:null,
  steps:[{number:1,name:f.job.steps[0].name,status:'completed',conclusion:'success',started_at:new Date(f.now-9000).toISOString(),completed_at:new Date(f.now-2000).toISOString()}]};
 const capture=await captureNonrootControlBuildAction({contract:f.contract,source:f.source,run:{...f.rawRun,status:'in_progress',conclusion:null},job,
  metadata:JSON.stringify({'containerimage.digest':f.build.image.rootDigest,'containerimage.config.digest':f.build.image.configDigest},null,2)+'\n',outputDigest:f.build.image.rootDigest,observedMs:f.now},f.options());
 const prepared={version:1,kind:'control-build-prepared',identity:{repository:f.source.repository,revision:f.source.checkout.sha,runId:f.source.run.id,attempt:f.source.run.attempt},
  bundleHash:'a'.repeat(64),contractHash:hash(f.contract),fingerprint:{tree:f.source.checkout.tree,copyClosureHash:'b'.repeat(64),dockerfileHash:'c'.repeat(64),ignoreHash:'d'.repeat(64)},preparedMs:f.now-10000};
 records={prepared,capture};
});
function fixture(){
 const input={prepared:json(records.prepared),capture:json(records.capture)},encoded=encodeControlBuildCapture(input),account='123456789012',region='us-east-1',bucket='example-control-evidence',bucketArn='arn:aws:s3:::'+bucket;
 const config={stage:'prod',account,region,bucket,bucketArn,objectArn:bucketArn+'/'+controlBuildArchiveKey('prod',encoded.commitment),roleArn:'arn:aws:iam::'+account+':role/ExampleProductionRole',encryption:{algorithm:'aws:kms',keyArn:'arn:aws:kms:'+region+':'+account+':key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',bucketKeyEnabled:true}};
 return {input,encoded,config};
}
function transport(x,mutate){
 const calls=[],handler={destroyed:false,async handle(request,options){calls.push({request,options});
  const response={statusCode:200,headers:{'content-length':String(request.method==='GET'?x.encoded.bytes.length:0),'x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':x.config.encryption.keyArn,'x-amz-server-side-encryption-bucket-key-enabled':'true','x-amz-checksum-sha256':Buffer.from(x.encoded.commitment.envelopeSha256,'hex').toString('base64'),etag:'"synthetic-etag"'},body:Readable.from(request.method==='GET'?[x.encoded.bytes]:[])};
  return {response:mutate?await mutate(response,request):response};},destroy(){handler.destroyed=true;}};return {calls,handler};
}
const options=(x,t)=>({config:x.config,credentials:{accessKeyId:'ASIA'+'A'.repeat(16),secretAccessKey:'synthetic-not-issued',sessionToken:'synthetic-not-issued',expiration:new Date(f.now+900000)},now:()=>f.now,deadlineMs:f.now+30000,requestHandler:t.handler});
function borrowed(x,mutate){
 const calls=[],client={destroy(){throw Error('parent client must remain owned');},async send(command,options){calls.push({command,options});const r={$metadata:{httpStatusCode:200},ContentLength:x.encoded.bytes.length,ServerSideEncryption:'aws:kms',SSEKMSKeyId:x.config.encryption.keyArn,BucketKeyEnabled:true,Body:Readable.from([x.encoded.bytes])};return mutate?mutate(r):r;}};
 return {client,calls,options:{config:x.config,client,deadlineMs:f.now+30000,now:()=>f.now}};
}
it('round-trips exact prepared/capture/metadata bytes from the real capture producer',()=>{
 const x=fixture(),d=decodeControlBuildCapture(x.encoded.bytes,x.encoded.commitment);
 expect(d.prepared).toEqual(records.prepared);expect(d.capture).toEqual(records.capture);expect(d.preparedBytes).toEqual(x.input.prepared);expect(d.captureBytes).toEqual(x.input.capture);expect(d.envelopeBytes).toEqual(x.encoded.bytes);
 d.envelopeBytes.fill(0);expect(x.encoded.bytes[0]).toBe(123);expect(d.capture.job.completed_at).toBeNull();expect(d).not.toHaveProperty('authorized');
});
it('accepts inert record objects and emits only public-safe fixed commitment keys',()=>{
 const c=encodeControlBuildCapture(records).commitment;
 expect(Object.keys(c).sort()).toEqual(['version','kind','runId','runAttempt','sourceRevision','sourceTree','buildJobId','outputDigest','envelopeSha256','bytesLength'].sort());
 expect(inspectControlBuildCommitment(c)).toEqual(c);expect(JSON.stringify(c)).not.toMatch(/123456789012|arn:|amazonaws|bucket|metadata|credential/);
});
it('derives only the existing decisions/prod lifecycle key and strict config',()=>{
 const x=fixture(),c=x.encoded.commitment;
 expect(controlBuildArchiveKey('prod',c)).toBe(`decisions/prod/control-build/${c.runId}/${c.runAttempt}/${c.envelopeSha256}.json`);
 expect(controlBuildArchiveLocation(x.config,c).key).toBe(controlBuildArchiveKey('prod',c));
 for(const stage of ['pr-1','prod/../','prod*'])expect(()=>controlBuildArchiveKey(stage,c)).toThrow();
 for(const patch of [{objectArn:x.config.objectArn+'*'},{endpoint:'https://example.com'},{stage:'pr-1'},{roleArn:x.config.roleArn.replace('123456789012','0'.repeat(12))}])expect(()=>controlBuildArchiveLocation({...x.config,...patch},c)).toThrow();
});
it.each(['runId','runAttempt','sourceRevision','sourceTree','buildJobId','outputDigest','envelopeSha256','bytesLength'])('rejects changed public %s',key=>{
 const x=fixture(),c={...x.encoded.commitment};c[key]=typeof c[key]==='number'?c[key]+1:key==='outputDigest'?'sha256:'+'f'.repeat(64):'f'.repeat(c[key].length);
 expect(()=>decodeControlBuildCapture(x.encoded.bytes,c)).toThrow();
});
it.each(['contract','identity','fingerprint','after-action','too-old','future-action','action','job','run','source','source-ref','metadata','completed-job','unknown'])('rejects internally inconsistent %s capture',fault=>{
 const r=structuredClone(records);
 if(fault==='contract')r.prepared.contractHash='f'.repeat(64);
 if(fault==='identity')r.prepared.identity.attempt++;
 if(fault==='fingerprint')r.prepared.fingerprint.tree='f'.repeat(40);
 if(fault==='after-action')r.prepared.preparedMs=r.capture.observedMs;
 if(fault==='too-old')r.prepared.preparedMs=r.capture.observedMs-1800001;
 if(fault==='future-action')r.capture.action.completed_at=new Date(f.now+1).toISOString();
 if(fault==='action')r.capture.job.steps.push({...r.capture.action});
 if(fault==='job')r.capture.job.run_attempt++;
 if(fault==='run')r.capture.run.head_branch='other';
 if(fault==='source')r.capture.source.main.sha='f'.repeat(40);
 if(fault==='source-ref')r.capture.actualMain.authenticatedSource.bytesHash='f'.repeat(64);
 if(fault==='metadata')r.capture.metadata='{"containerimage.digest":"'+r.capture.outputDigest+'","containerimage.digest":"'+r.capture.outputDigest+'"}';
 if(fault==='completed-job')r.capture.job.completed_at=new Date(f.now).toISOString();
 if(fault==='unknown')r.capture.authorized=true;
 expect(()=>encodeControlBuildCapture(r)).toThrow();
});
it('rejects duplicate envelope keys, raw invalid UTF8, oversized input and noncanonical encoding',()=>{
 const x=fixture(),e=JSON.parse(x.encoded.bytes);
 for(const raw of [Buffer.from('{"version":1,"version":1}'),Buffer.from([255]),json({...e,approved:true}),json({...e,prepared:{...e.prepared,base64:e.prepared.base64+'\n'}})]){
  expect(()=>decodeControlBuildCapture(raw,{...x.encoded.commitment,envelopeSha256:sha(raw),bytesLength:raw.length})).toThrow();
 }
 expect(()=>encodeControlBuildCapture({...records,capture:Buffer.alloc(4194305)})).toThrow();
});
it('rejects accessors without invoking them',()=>{
 let calls=0;const x=fixture(),r={...records};Object.defineProperty(r,'prepared',{enumerable:true,get(){calls++;return records.prepared;}});
 expect(()=>encodeControlBuildCapture(r)).toThrow();const config={...x.config};Object.defineProperty(config,'stage',{enumerable:true,get(){calls++;return 'prod';}});
 expect(()=>controlBuildArchiveLocation(config,x.encoded.commitment)).toThrow();expect(calls).toBe(0);
});
it('performs exactly one conditional PUT with original bytes and measured receipt through the real SDK',async()=>{
 const x=fixture(),t=transport(x),out=await putControlBuildCapture(x.encoded,options(x,t));
 expect(t.calls).toHaveLength(1);const r=t.calls[0].request;expect(r.method).toBe('PUT');expect(r.hostname).toBe('s3.us-east-1.amazonaws.com');expect(r.headers['if-none-match']).toBe('*');expect(r.headers['x-amz-expected-bucket-owner']).toBe(x.config.account);expect(r.headers['x-amz-acl']).toBeUndefined();expect(Buffer.from(r.body)).toEqual(x.encoded.bytes);
 expect(out.commitment).toEqual(x.encoded.commitment);expect(t.handler.destroyed).toBe(true);expect(inspectControlBuildTransferReceipt(out.transferReceipt)).toMatchObject({operation:'PutObject',requests:1,requestBodyBytes:x.encoded.bytes.length,responseBodyBytes:0,complete:true});
});
it('uses one parent-budgeted GET without credentials, new client, retry or parent client destruction',async()=>{
 const x=fixture(),t=borrowed(x),out=await getControlBuildCapture(x.encoded.commitment,t.options);
 expect(t.calls).toHaveLength(1);expect(t.calls[0].command.constructor.name).toBe('GetObjectCommand');expect(t.calls[0].command.input).toEqual({Bucket:x.config.bucket,Key:controlBuildArchiveKey('prod',x.encoded.commitment),ExpectedBucketOwner:x.config.account});
 expect(t.calls[0].options.abortSignal).toBeInstanceOf(AbortSignal);expect(out.prepared).toEqual(records.prepared);expect(out.capture).toEqual(records.capture);expect(out.transferReceipt).toMatchObject({requests:1,requestBodyBytes:0,responseBodyBytes:x.encoded.bytes.length,complete:true});
});
it('charges the original catalog exactly once through the actual budgeted SDK wrapper',async()=>{
 const x=fixture(),t=transport(x),charges=[],reservations=[],completions=[];
 const reads=createNonrootBudgetedReads({region:x.config.region,env:{AWS_ACCESS_KEY_ID:'ASIA'+'A'.repeat(16),AWS_SECRET_ACCESS_KEY:'synthetic-not-issued',AWS_SESSION_TOKEN:'synthetic-not-issued'},requestHandler:t.handler,
  metadataReads:{async beforeRead(action,input){reservations.push({action,input});return {caps:{requestBytes:0,responseBytes:x.encoded.bytes.length},finalGuard(){},charge(bytes){charges.push(bytes);},async complete(result,digest){completions.push({result,digest});},async unknown(){throw Error('unexpected unknown');}};},reserveLocal(){throw Error('no new local budget');},finish(){throw Error('caller owns completion');}}});
 try{
  const out=await getControlBuildCapture(x.encoded.commitment,{config:x.config,client:reads.clients.s3,deadlineMs:f.now+30000,now:()=>f.now});
  expect(out.capture).toEqual(records.capture);expect(t.calls).toHaveLength(1);expect(reservations).toHaveLength(1);expect(reservations[0].action).toBe('GetObject');expect(charges.reduce((a,b)=>a+b,0)).toBe(x.encoded.bytes.length);expect(completions).toHaveLength(1);expect(completions[0].digest).toBe(x.encoded.commitment.envelopeSha256);expect(t.handler.destroyed).toBe(false);
 }finally{reads.close();}
 expect(t.handler.destroyed).toBe(true);
});
it('retains parent budget refusal with zero HTTP dispatch and no fallback',async()=>{
 const x=fixture(),t=transport(x);let reservations=0;
 const reads=createNonrootBudgetedReads({region:x.config.region,env:{AWS_ACCESS_KEY_ID:'ASIA'+'A'.repeat(16),AWS_SECRET_ACCESS_KEY:'synthetic-not-issued',AWS_SESSION_TOKEN:'synthetic-not-issued'},requestHandler:t.handler,
  metadataReads:{async beforeRead(){reservations++;throw Error('original-catalog-exhausted');},reserveLocal(){throw Error('no new local budget');},finish(){throw Error('caller owns completion');}}});
 try{await expect(getControlBuildCapture(x.encoded.commitment,{config:x.config,client:reads.clients.s3,deadlineMs:f.now+30000,now:()=>f.now})).rejects.toThrow('ControlCaptureTransferHeld');expect(reservations).toBe(1);expect(t.calls).toHaveLength(0);expect(t.handler.destroyed).toBe(false);}finally{reads.close();}
});
it('also supports an explicitly credentialed reader with the same one-call bounded transport',async()=>{
 const x=fixture(),t=transport(x),out=await getControlBuildCapture(x.encoded.commitment,options(x,t));expect(out.capture).toEqual(records.capture);expect(t.calls).toHaveLength(1);expect(t.handler.destroyed).toBe(true);
});
it('appends real completed-job evidence only after decoding; the original job stays in progress',async()=>{
 const x=fixture(),t=borrowed(x),d=await getControlBuildCapture(x.encoded.commitment,t.options);
 const job={...d.capture.job,status:'completed',conclusion:'success',completed_at:new Date(f.now+1000).toISOString()};
 const completed=completeNonrootControlBuildAction(d.capture,{contract:f.contract,run:d.capture.run,job,buildLog:Buffer.from(`#7 exporting manifest list ${f.build.image.rootDigest}\n#7 exporting config ${f.build.image.configDigest}\n#7 DONE 1.0s\n`),now:f.now+2000});
 expect(completed.captureHash).toBe(hash(d.capture));expect(d.capture.job.completed_at).toBeNull();
});
it.each(['length','hash','encryption','key','bucket-key','overflow','stream'])('holds a parent GET on %s and closes its response body',async fault=>{
 const x=fixture();let body;const t=borrowed(x,r=>{
  if(fault==='length')r.ContentLength=1;if(fault==='hash')r.Body=Readable.from([Buffer.alloc(x.encoded.bytes.length)]);
  if(fault==='encryption')r.ServerSideEncryption='AES256';if(fault==='key')r.SSEKMSKeyId+='wrong';if(fault==='bucket-key')r.BucketKeyEnabled=false;
  if(fault==='overflow')r.Body=Readable.from([x.encoded.bytes,Buffer.from('extra')]);
  if(fault==='stream')r.Body=Readable.from((async function*(){yield Buffer.from('partial');throw Error('synthetic-secret-error');})());
  body=r.Body;return r;
 });
 await expect(getControlBuildCapture(x.encoded.commitment,t.options)).rejects.toMatchObject({message:'ControlCaptureTransferHeld',transferReceipt:{complete:false,requests:1}});expect(t.calls).toHaveLength(1);expect(body.closed).toBe(true);
});
it('reports unknown PUT as HOLD, no retry and no external error text',async()=>{
 const x=fixture(),t=transport(x,()=>{throw Error('synthetic-secret-error');});
 await expect(putControlBuildCapture(x.encoded,options(x,t))).rejects.toMatchObject({message:'ControlCaptureTransferHeld',transferReceipt:{complete:false,requests:1,requestBodyBytes:x.encoded.bytes.length}});expect(t.calls).toHaveLength(1);expect(t.handler.destroyed).toBe(true);
});
it.each(['checksum','encryption','overflow','status'])('holds invalid PUT %s responses with one attempt',async fault=>{
 const x=fixture(),t=transport(x,r=>{if(fault==='checksum')r.headers['x-amz-checksum-sha256']=Buffer.alloc(32).toString('base64');if(fault==='encryption')r.headers['x-amz-server-side-encryption']='AES256';if(fault==='overflow')r.body=Readable.from([Buffer.alloc(65537)]);if(fault==='status')r.statusCode=503;return r;});
 await expect(putControlBuildCapture(x.encoded,options(x,t))).rejects.toThrow('ControlCaptureTransferHeld');expect(t.calls).toHaveLength(1);
});
it('makes zero calls on expired/aborted/missing-credential or conflicting client options',async()=>{
 const x=fixture(),t=transport(x),b=borrowed(x);
 for(const patch of [{deadlineMs:f.now},{signal:AbortSignal.abort()},{credentials:undefined},{credentials:{...options(x,t).credentials,expiration:new Date(f.now-1)}}])await expect(putControlBuildCapture(x.encoded,{...options(x,t),...patch})).rejects.toThrow();
 for(const patch of [{deadlineMs:f.now},{signal:AbortSignal.abort()},{credentials:options(x,t).credentials},{requestHandler:t.handler}])await expect(getControlBuildCapture(x.encoded.commitment,{...b.options,...patch})).rejects.toThrow();
 expect(t.calls).toHaveLength(0);expect(b.calls).toHaveLength(0);
});
it('rechecks deadline immediately after asynchronous client return',async()=>{
 const x=fixture();let clock=f.now,body;const t=borrowed(x,r=>{clock=f.now+30000;body=r.Body;return r;});
 await expect(getControlBuildCapture(x.encoded.commitment,{...t.options,now:()=>clock})).rejects.toThrow();expect(t.calls).toHaveLength(1);expect(body.closed).toBe(true);
});
it('aborts a stalled reader and proves body closure',async()=>{
 const x=fixture(),controller=new AbortController();let body;
 const t=borrowed(x,r=>{body=new Readable({read(){queueMicrotask(()=>controller.abort());}});return {...r,Body:body};});
 await expect(getControlBuildCapture(x.encoded.commitment,{...t.options,signal:controller.signal})).rejects.toThrow('ControlCaptureTransferHeld');expect(body.closed).toBe(true);
});
it('retains sticky ECLEANUP if positive stream termination cannot be proved',async()=>{
 const x=fixture(),t=borrowed(x,r=>({...r,ContentLength:1,Body:new Readable({read(){},destroy(){}})}));
 await expect(getControlBuildCapture(x.encoded.commitment,{...t.options,deadlineMs:f.now+20})).rejects.toMatchObject({code:'ECLEANUP',transferReceipt:{complete:false}});
});
it('honors independent source/contract/fingerprint expectations without rebinding the producer bundle hash',async()=>{
 const x=fixture(),expected={contractHash:records.capture.contractHash,source:records.capture.source,fingerprint:records.prepared.fingerprint};
 const t=transport(x);await expect(putControlBuildCapture(x.encoded,{...options(x,t),expected})).resolves.toHaveProperty('etag');
 for(const patch of [{contractHash:'f'.repeat(64)},{source:{...expected.source,ref:'refs/heads/other'}},{fingerprint:{...expected.fingerprint,ignoreHash:'f'.repeat(64)}}]){
  const t=transport(x);await expect(putControlBuildCapture(x.encoded,{...options(x,t),expected:{...expected,...patch}})).rejects.toThrow();expect(t.calls).toHaveLength(0);
 }
});
it('holds decode failures after transfer without losing its actual measured receipt',async()=>{
 const x=fixture(),raw=Buffer.from('{}'),c={...x.encoded.commitment,envelopeSha256:sha(raw),bytesLength:raw.length};
 x.config.objectArn=x.config.bucketArn+'/'+controlBuildArchiveKey('prod',c);const t=borrowed(x,r=>({...r,ContentLength:raw.length,Body:Readable.from([raw])}));
 await expect(getControlBuildCapture(c,t.options)).rejects.toMatchObject({message:'ControlBuildCaptureReplayHeld',transferReceipt:{requests:1,responseBodyBytes:2,complete:true}});
});
it.each(['expired','reversed'])('does not return a successful receipt after %s cleanup time',async fault=>{
 const x=fixture(),t=transport(x);let clock=f.now;t.handler.destroy=()=>{t.handler.destroyed=true;clock=fault==='expired'?f.now+30000:f.now-1;};
 await expect(putControlBuildCapture(x.encoded,{...options(x,t),now:()=>clock})).rejects.toMatchObject({message:'ControlCaptureTransferHeld',transferReceipt:{complete:false,requests:1}});expect(t.calls).toHaveLength(1);
});
it('rejects receipt authority fields, forged bounds and incomplete successful byte totals',async()=>{
 const x=fixture(),t=borrowed(x),{transferReceipt:r}=await getControlBuildCapture(x.encoded.commitment,t.options);
 for(const patch of [{approved:true},{requests:2},{responseBodyBound:r.responseBodyBound+1},{responseBodyBytes:r.responseBodyBytes-1},{completedMs:null}])expect(()=>inspectControlBuildTransferReceipt({...r,...patch})).toThrow();
});
