import test,{mock} from 'node:test';
import assert from 'node:assert/strict';
import {Readable} from 'node:stream';
import {lstat,readFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import fsPromises from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import {fixture,admission,sha} from './fixture.mjs';
import {productionControlCompositionSessionPolicy,productionControlCompositionProtectedSourcePolicy,productionControlCompositionLocations,openProductionControlCompositionTransport,openProductionControlCompositionProtectedSourceTransport} from '../lib/production-control-composition-transport.mjs';
import {GetParametersCommand} from '@aws-sdk/client-ssm';
import {GetObjectCommand} from '@aws-sdk/client-s3';
import {GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {PRODUCTION_DATA_RELEASE_PARAMETER} from '../lib/production-data-issuance.mjs';
import {productionControlCompositionSnapshot} from '../lib/production-control-composition-lifetime.mjs';
import {composeProductionControl,inspectProductionControlCompositionOutput,closeProductionControlCompositionOutput} from '../lib/production-control-composition-producer.mjs';
import {publishProductionControlComposition} from '../lib/production-control-composition-publisher.mjs';
import {inspectCompositionStsXml} from '../lib/production-control-composition-xml.mjs';
import {materializeProductionControlCompositionPacks,requireProductionControlCompositionPacks,closeProductionControlCompositionPacks} from '../lib/production-control-composition-packs.mjs';
import {readControlSourceFile} from '../lib/production-control-source.mjs';
import {requireProductionControlCompositionAllocation} from '../lib/production-control-composition-lifetime.mjs';
import {closeProductionControlCompositionAllocation} from '../lib/production-control-composition-lifetime.mjs';
import {verifyProductionControlCompositionProtectedSource} from '../lib/production-control-composition-protected-source.mjs';
import {acquireProductionControlCompositionBase,requireProductionControlCompositionBase,closeProductionControlCompositionBase} from '../lib/production-control-composition-base.mjs';
import {inspectProductionControlCompositionEnvelope,completeProductionControlCompositionEnvelope} from '../lib/production-control-composition-reader.mjs';
import {runProductionControlComposition} from '../lib/production-control-composition-controller.mjs';
import {nativeContract} from './consumer.fixture.mjs';
import {completeProductionControlCompositionBuildCapture,getProductionControlCompositionCaptureBytes} from '../lib/production-control-composition-capture-reader.mjs';
import {productionControlCompositionCommitment} from '../lib/production-control-composition-reader.mjs';
import {collectNonrootControlImage} from '../lib/production-nonroot-control-download.mjs';
import {captureNonrootControlArtifact} from '../lib/production-nonroot-control-build.mjs';
import {createNonrootBudgetedReads} from '../lib/production-nonroot-budget-transport.mjs';

test('native capsule consumer retains original bytes and exact raw registry graph/FS after completed-job replay',async()=>{
 const f=await fixture({transport:true});let a,out,t,reads,download;
 try{
  const contract=await nativeContract(f);a=await admission(f);out=await composeProductionControl(a);const published=registry(a),raw=captureService(a,published);
  t=await openProductionControlCompositionTransport({allocation:a.allocation,env:{...env(a),GITHUB_TOKEN:'synthetic-github'}},{requestHandler:raw});
  await publishProductionControlComposition({output:out,allocation:a.allocation,transport:t});const done=await t.capture(),envelope=JSON.parse(raw.stored);
  const checked=inspectProductionControlCompositionEnvelope(raw.stored,{ref:done.ref,plan:f.plan,actualMain:a.actualMain});
  const now=Date.now(),run=checked.observations.run,job=structuredClone(checked.observations.jobs.jobs[0]);
  job.status='completed';job.conclusion='success';job.started_at=job.steps[0].started_at;job.completed_at=new Date(now).toISOString();
  Object.assign(job.steps[0],{status:'completed',conclusion:'success',completed_at:job.completed_at});
  const commitment=productionControlCompositionCommitment({grantSetId:a.config.startup.grantSetId,ref:done.ref,capture:done.capture}),buildLog=Buffer.from('MEM9_CONTROL_COMPOSITION_CAPTURE '+JSON.stringify(commitment)+'\n');
  const input={commitment,contract,source:JSON.parse(Buffer.from(envelope.source.bytesBase64,'base64')),run,job,buildLog,now};
  const completed=completeProductionControlCompositionBuildCapture(raw.stored,input);
  assert.deepEqual(completed.envelopeBytes,raw.stored);assert.deepEqual(completed.sourceBytes,Buffer.from(envelope.source.bytesBase64,'base64'));
  for(const mutate of [v=>v.job.id++,v=>v.job.run_attempt++,v=>{v.job.name='another job';},v=>{v.source.checkout.sha='f'.repeat(40);},v=>{v.commitment.rootDigest='sha256:'+'f'.repeat(64);},v=>{v.contract.recipe.composition.planHash='f'.repeat(64);}]){
   const changed=structuredClone(input);mutate(changed);assert.throws(()=>completeProductionControlCompositionBuildCapture(raw.stored,changed));
  }
  assert.throws(()=>completeProductionControlCompositionBuildCapture(raw.stored,{...input,buildLog:Buffer.from(buildLog.toString()+buildLog.toString())}),/LogCommitment/);
  const calls=[],locals=[],metadataReads={reserveLocal(q){locals.push(q);},async finish(){throw Error('CallerOwnsFinish');},async beforeRead(action,request){calls.push({action,request});return {caps:{requestBytes:16384,responseBytes:8388608},finalGuard(){},charge(){},async complete(){},async unknown(){calls.push({unknown:true});}};}};
  const reply=bytes=>({response:{statusCode:200,headers:{'content-length':String(bytes.length)},body:Readable.from([bytes],{objectMode:false})}});
  const readerTransport={async handle(request){
   if(request.headers['x-amz-target']){
    const q=JSON.parse(Buffer.from(request.body).toString()),action=request.headers['x-amz-target'].split('.').at(-1);let result;
    assert.equal(q.registryId,contract.output.account);assert.equal(q.repositoryName,contract.output.repositoryName);
    if(action==='BatchGetImage'){const d=q.imageIds[0].imageDigest,b=published.objects.get(d);assert.ok(b);result={images:[{registryId:q.registryId,repositoryName:q.repositoryName,imageId:{imageDigest:d},imageManifest:b.toString(),imageManifestMediaType:JSON.parse(b).mediaType}],failures:[]};}
    else{
     assert.equal(action,'GetDownloadUrlForLayer');const date=new Date().toISOString().replace(/[-:]/g,'').replace(/\.\d{3}/,'');
     const url=new URL('https://prod-'+contract.output.region+'-starport-layer-bucket.s3.'+contract.output.region+'.amazonaws.com/'+q.layerDigest.slice(7));
     for(const[k,v]of Object.entries({'X-Amz-Algorithm':'AWS4-HMAC-SHA256','X-Amz-Date':date,'X-Amz-Expires':'300','X-Amz-Credential':'synthetic/'+date.slice(0,8)+'/'+contract.output.region+'/s3/aws4_request','X-Amz-SignedHeaders':'host','X-Amz-Signature':'a'.repeat(64)}))url.searchParams.set(k,v);
     result={layerDigest:q.layerDigest,downloadUrl:url.href};
    }
    return reply(Buffer.from(JSON.stringify(result)));
   }
   const bytes=published.objects.get('sha256:'+request.path.slice(1));assert.ok(bytes);return reply(bytes);
  },destroy(){}};
  reads=createNonrootBudgetedReads({region:contract.output.region,env:{AWS_ACCESS_KEY_ID:'synthetic',AWS_SECRET_ACCESS_KEY:'synthetic',AWS_SESSION_TOKEN:'synthetic'},metadataReads,requestHandler:readerTransport});
  download=await collectNonrootControlImage({capture:completed.capture,contract,budgetedReads:reads,metadataReads,tempRoot:f.directory});
  const artifact=await captureNonrootControlArtifact(completed.capture,{graph:download.graph,filesystem:download.filesystem});
  assert.deepEqual(artifact.inventory,envelope.inventory);assert.deepEqual(artifact.filesystem,envelope.capture.filesystem);
  assert.equal(calls.filter(q=>q.unknown).length,0);assert.ok(calls.some(q=>q.action==='S3BlobGet'));assert.ok(locals.some(q=>q.uncompressedBytes>0));
  const downloaded=download;await download.close();download=null;await assert.rejects(lstat(downloaded.cacheDirectory),{code:'ENOENT'});
 }finally{await download?.close();reads?.close();await t?.close();if(out)await closeProductionControlCompositionOutput(out);await a?.close();await f.remove();}
});

test('native capsule paid reader rejects protection/body faults and closes stalled original stream at its deadline',async()=>{
 const raw=Buffer.from('{}'),commitment={version:1,kind:'native-control-composition-commitment',grantSetId:'a'.repeat(64),planHash:'b'.repeat(64),envelopeSha256:sha(raw),bytesLength:raw.length,
  rootDigest:'sha256:'+'c'.repeat(64),arm64Digest:'sha256:'+'d'.repeat(64),configDigest:'sha256:'+'e'.repeat(64),mainRevision:'1'.repeat(40),mainTree:'2'.repeat(40),runId:1,runAttempt:1,jobId:1};
 const base={bucket:'example-ci-reader',kmsKeyArn:'synthetic-key',account:'123456789012',commitment,expectedGrantSetId:commitment.grantSetId};
 for(const fault of [null,'key','mode','long','hash','stall']){
  const body=fault==='stall'?new Readable({read(){}}):Readable.from([fault==='long'?Buffer.from('long'):fault==='hash'?Buffer.from('[]'):raw],{objectMode:fault==='mode'});
  let calls=0;const client={async send(command){calls++;assert.deepEqual(command.input,{Bucket:base.bucket,Key:'decisions/prod/ci-composition/'+commitment.grantSetId+'/capture.json',ExpectedBucketOwner:base.account});
   return {$metadata:{httpStatusCode:200},ContentLength:raw.length,ServerSideEncryption:'aws:kms',SSEKMSKeyId:fault==='key'?'wrong':base.kmsKeyArn,BucketKeyEnabled:true,Body:body};}};
  const promise=getProductionControlCompositionCaptureBytes({...base,client,deadlineMs:Date.now()+(fault==='stall'?40:1000)});
  if(fault)await assert.rejects(promise);else assert.deepEqual(await promise,raw);
  assert.equal(calls,1);assert.equal(body.closed,true);
 }
});

function rawService(a,{wrongIdentity=false,failOidc=false}={}){
 const calls=[],bodies=[];let name,arn;
 return {calls,bodies,destroyed:false,async handle(request){
  const params=new URLSearchParams(request.body??''),action=params.get('Action')??'oidc';
  calls.push({action,body:request.body,host:request.hostname});let text;
  if(action==='oidc')text=JSON.stringify({value:'synthetic.header.signature'});
  else if(action==='AssumeRoleWithWebIdentity'){
   name=params.get('RoleSessionName');arn='arn:aws:sts::123456789012:assumed-role/github-actions-mem9-on-aws-prod/'+name;
   text='<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIASYNTHETIC</AccessKeyId><SecretAccessKey>synthetic-secret</SecretAccessKey><SessionToken>synthetic-session</SessionToken><Expiration>'+new Date(Date.now()+900000).toISOString()+'</Expiration></Credentials><AssumedRoleUser><Arn>'+arn+'</Arn><AssumedRoleId>AROA:'+name+'</AssumedRoleId></AssumedRoleUser></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>';
  }else text='<GetCallerIdentityResponse><GetCallerIdentityResult><Account>'+(wrongIdentity?'9'.repeat(12):'123456789012')+'</Account><Arn>'+arn+'</Arn><UserId>AROA:'+name+'</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>';
  const body=Readable.from([Buffer.from(text)],{objectMode:false});bodies.push(body);
  return {response:{statusCode:failOidc?500:200,headers:{'content-type':action==='oidc'?'application/json':'text/xml'},body}};
 },destroy(){this.destroyed=true;}};
}
function env(a){return {...a.env,ACTIONS_ID_TOKEN_REQUEST_URL:'https://pipelines.actions.githubusercontent.com/synthetic/_apis/distributedtask/hubs/build/plans/00000000-0000-4000-8000-000000000001/jobs/00000000-0000-4000-8000-000000000002/idtoken?api-version=2.0',ACTIONS_ID_TOKEN_REQUEST_TOKEN:'synthetic-token'};}
test('main policy and original raw SDK identity have explicit registry/repository scope',async()=>{
 const f=await fixture({transport:true});let a,t;try{
  a=await admission(f);const p=productionControlCompositionSessionPolicy(a.allocation);assert.ok(Buffer.byteLength(p)<=2048);
  assert.ok(p.includes('mem9-on-aws/bootstrap'));assert.ok(p.includes('mem9-on-aws/preview/bootstrap'));
  const raw=rawService(a);t=await openProductionControlCompositionTransport({allocation:a.allocation,env:env(a)},{requestHandler:raw});
  assert.deepEqual(raw.calls.map(c=>c.action),['oidc','AssumeRoleWithWebIdentity','GetCallerIdentity']);
  await assert.rejects(t.complete('bad','sha256:'+'a'.repeat(64)),/PublicationRequired/);
  assert.equal(raw.calls.length,3);await t.close();t=null;assert.equal(raw.destroyed,true);assert.ok(raw.bodies.every(b=>b.closed));
 }finally{await t?.close();await a?.close();await f.remove();}
});
for(const failure of ['wrongIdentity','failOidc'])test('raw '+failure+' holds once and drains before cleanup',async()=>{
 const f=await fixture({transport:true});let a;try{
  a=await admission(f);const raw=rawService(a,{[failure]:true});
  await assert.rejects(openProductionControlCompositionTransport({allocation:a.allocation,env:env(a)},{requestHandler:raw}));
  assert.equal(raw.calls.length,failure==='failOidc'?1:3);assert.equal(raw.destroyed,true);assert.ok(raw.bodies.every(b=>b.closed));
  assert.equal(productionControlCompositionSnapshot(a.allocation).held,true);
 }finally{await a?.close();await f.remove();}
});
function registry(a,{wrongComplete=false,failPart=false}={}){
 const auth=rawService(a),calls=[],uploads=new Map(),objects=new Map();let serial=0;
 return {calls,objects,auth,async handle(request){
  const target=request.headers['x-amz-target'];
  if(!target)return auth.handle(request);
  const action=target.split('.').at(-1),q=JSON.parse(request.body);calls.push({action,request:q});
  assert.equal(q.registryId,'123456789012');assert.equal(q.repositoryName,'mem9-on-aws/bootstrap');
  let r;
  if(action==='BatchCheckLayerAvailability')r={layers:q.layerDigests.map(layerDigest=>({layerDigest,layerAvailability:'UNAVAILABLE'})),failures:[]};
  else if(action==='InitiateLayerUpload'){
   const uploadId='00000000-0000-4000-8000-'+String(++serial).padStart(12,'0');uploads.set(uploadId,[]);
   r={registryId:q.registryId,repositoryName:q.repositoryName,uploadId,partSize:5242880};
  }else if(action==='UploadLayerPart'){
   const chunks=uploads.get(q.uploadId),b=Buffer.from(q.layerPartBlob,'base64');
   assert.equal(q.partFirstByte,chunks.reduce((n,b)=>n+b.length,0));assert.equal(q.partLastByte,q.partFirstByte+b.length-1);chunks.push(b);
   if(failPart)throw Error('synthetic-lost-part-response');
   r={registryId:q.registryId,repositoryName:q.repositoryName,uploadId:q.uploadId,lastByteReceived:q.partLastByte};
  }else if(action==='CompleteLayerUpload'){
   const bytes=Buffer.concat(uploads.get(q.uploadId)),digest='sha256:'+sha(bytes);assert.deepEqual(q.layerDigests,[digest]);objects.set(digest,bytes);
   r={registryId:wrongComplete?'9'.repeat(12):q.registryId,repositoryName:q.repositoryName,uploadId:q.uploadId,layerDigest:digest};
  }else if(action==='PutImage'){
   const bytes=Buffer.from(q.imageManifest);assert.equal('sha256:'+sha(bytes),q.imageDigest);objects.set(q.imageDigest,bytes);
   const doc=JSON.parse(q.imageManifest);for(const d of doc.manifests??[doc.config,...doc.layers,...(doc.subject?[doc.subject]:[])])assert.ok(objects.has(d.digest));
   r={image:{registryId:q.registryId,repositoryName:q.repositoryName,imageId:{imageDigest:q.imageDigest}}};
  }else if(action==='BatchGetImage'){
   const digest=q.imageIds[0].imageDigest,raw=objects.get(digest);
   r={images:[{registryId:q.registryId,repositoryName:q.repositoryName,imageId:{imageDigest:digest},imageManifest:raw.toString(),imageManifestMediaType:JSON.parse(raw).mediaType}],failures:[]};
  }else throw Error('unpriced action');
  return {response:{statusCode:200,headers:{'content-type':'application/x-amz-json-1.1'},body:Readable.from([Buffer.from(JSON.stringify(r))],{objectMode:false})}};
 },destroy(){auth.destroy();}};
}
test('native output publishes every inherited byte with multipart requests and exact registry readback',async()=>{
 const f=await fixture({transport:true,inheritedBytes:6*1048576});let a,out,t;try{
  a=await admission(f);out=await composeProductionControl(a);const raw=registry(a);
  t=await openProductionControlCompositionTransport({allocation:a.allocation,env:env(a)},{requestHandler:raw});
  const done=await publishProductionControlComposition({output:out,allocation:a.allocation,transport:t}),built=inspectProductionControlCompositionOutput(out);
  assert.equal(done.graphHash,built.record.graphHash);assert.equal(raw.calls.filter(c=>c.action==='PutImage').length,3);
  assert.equal(raw.calls.filter(c=>c.action==='BatchGetImage').length,3);
  assert.ok(raw.calls.filter(c=>c.action==='UploadLayerPart').some(c=>c.request.partFirstByte>0));
  for(const d of built.graph.inventory.nodes){assert.ok(raw.objects.has(d.digest));assert.equal(raw.objects.get(d.digest).length,d.size);assert.equal('sha256:'+sha(raw.objects.get(d.digest)),d.digest);}
  await assert.rejects(t.complete('unowned','sha256:'+'0'.repeat(64)),/PublicationOrder|CompleteDigest/);
 }finally{await t?.close();if(out)await closeProductionControlCompositionOutput(out);await a?.close();await f.remove();}
});
for(const failure of ['wrongComplete','failPart'])test('publication '+failure+' holds the original allocation without another upload or manifest',async()=>{
 const f=await fixture({transport:true});let a,out,t;try{
  a=await admission(f);out=await composeProductionControl(a);const raw=registry(a,{[failure]:true});
  t=await openProductionControlCompositionTransport({allocation:a.allocation,env:env(a)},{requestHandler:raw});
  await assert.rejects(publishProductionControlComposition({output:out,allocation:a.allocation,transport:t}));
  assert.equal(raw.calls.filter(c=>c.action==='InitiateLayerUpload').length,1);assert.equal(raw.calls.filter(c=>c.action==='PutImage').length,0);
  const count=raw.calls.length;await assert.rejects(t.initiate());assert.equal(raw.calls.length,count);
  assert.equal(productionControlCompositionSnapshot(a.allocation).held,true);
 }finally{await t?.close();if(out)await closeProductionControlCompositionOutput(out);await a?.close();await f.remove();}
});
test('STS XML rejects attribute shadowing, duplicate namespace attributes and entity expansion before SDK decoding',()=>{
 const valid='<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn</Arn><UserId>id</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>';
 assert.equal(inspectCompositionStsXml(Buffer.from(valid),'GetCallerIdentity'),true);
 for(const bad of [valid.replace('<Account>',`<Account Account="${'9'.repeat(12)}">`),valid.replace('xmlns=', 'xmlns=\"duplicate\" xmlns='),
  '<!DOCTYPE x [<!ENTITY a \"boom\">]>'+valid,valid.replace('</Account>','</Account><Account>123456789012</Account>')])
  assert.throws(()=>inspectCompositionStsXml(Buffer.from(bad),'GetCallerIdentity'),/StsXml/);
});

function captureService(a,base,{fault}={}){
 const q=productionControlCompositionLocations(a.allocation),m=a.actualMain,calls=[];let stored;
 const start=new Date(Date.now()-10000).toISOString();
 const run={id:m.workflowRun,run_attempt:m.workflowAttempt,head_sha:m.mainRevision,event:'push',head_branch:'main',path:m.workflowPath,
  repository:{full_name:m.repository},status:'in_progress',conclusion:null};
 const job={id:555,run_id:m.workflowRun,run_attempt:m.workflowAttempt,head_sha:m.mainRevision,name:'Build image transition control',status:'in_progress',conclusion:null,
  steps:[{name:'Build & push image transition bootstrap (arm64)',status:'in_progress',conclusion:null,started_at:start}]};
 if(fault==='run')run.id++;
 if(fault==='attempt')run.run_attempt++;
 if(fault==='source')run.head_sha='f'.repeat(40);
 if(fault==='job')job.run_id++;
 if(fault==='step')job.steps[0].status='completed';
 const headers=bytes=>({'content-length':String(bytes.length),'x-amz-server-side-encryption':'aws:kms',
  'x-amz-server-side-encryption-aws-kms-key-id':q.kmsKeyArn,'x-amz-server-side-encryption-bucket-key-enabled':'true',
  'x-amz-checksum-sha256':Buffer.from(sha(bytes),'hex').toString('base64')});
 const reply=(bytes,extra={})=>({response:{statusCode:200,headers:{'content-length':String(bytes.length),...extra},body:Readable.from([bytes],{objectMode:false})}});
 return {calls,get stored(){return stored;},async handle(r){
  if(r.hostname==='api.github.com'){
   calls.push({method:r.method,path:r.path});assert.equal(r.method,'GET');assert.equal(r.headers.authorization,'Bearer synthetic-github');
   const path='/repos/'+m.repository+'/actions/runs/'+m.workflowRun+'/attempts/'+m.workflowAttempt;
   assert.ok(r.path===path||r.path===path+'/jobs');
   if(r.path===path)return reply(Buffer.from(JSON.stringify(run)));
   assert.deepEqual(r.query,{per_page:'100'});
   const jobs=fault==='duplicateJob'?[job,job]:[job];
   return reply(Buffer.from(JSON.stringify({total_count:fault==='count'?2:jobs.length,jobs})),fault==='pagination'?{link:'<https://api.github.com/next>; rel="next"'}:{});
  }
  if(r.hostname==='s3.'+q.region+'.amazonaws.com'&&r.path==='/'+q.bucket+'/'+q.capture){
   calls.push({method:r.method,path:r.path});assert.equal(r.path,'/'+q.bucket+'/'+q.capture);
   assert.equal(r.headers['x-amz-expected-bucket-owner'],q.account);
   if(r.method==='PUT'){
    assert.equal(stored,undefined);assert.equal(r.headers['if-none-match'],'*');stored=Buffer.from(r.body);
    assert.equal(r.headers['x-amz-checksum-sha256'],headers(stored)['x-amz-checksum-sha256']);
    const h=headers(stored);delete h['content-length'];
    if(fault==='putChecksum')h['x-amz-checksum-sha256']='wrong';
    if(fault==='putKms')h['x-amz-server-side-encryption-aws-kms-key-id']='wrong';
    return reply(Buffer.alloc(0),h);
   }
   assert.equal(r.method,'GET');assert.equal(r.headers['x-amz-checksum-mode'],'ENABLED');assert.ok(stored);
   const h=headers(stored);if(fault==='getKms')h['x-amz-server-side-encryption-aws-kms-key-id']='wrong';
   const bytes=Buffer.from(stored);if(fault==='drift')bytes[bytes.length-2]^=1;
   return reply(bytes,h);
  }
  return base.handle(r);
 },destroy(){base.destroy();}};
}
test('capture is created internally from exact raw job observations and immutable native output, then read back',async()=>{
 const f=await fixture({transport:true});let a,out,t;try{
  a=await admission(f);out=await composeProductionControl(a);const raw=captureService(a,registry(a));
  t=await openProductionControlCompositionTransport({allocation:a.allocation,env:{...env(a),GITHUB_TOKEN:'synthetic-github'}},{requestHandler:raw});
  assert.equal(t.putCapture,undefined);assert.equal(t.getCapture,undefined);
  await publishProductionControlComposition({output:out,allocation:a.allocation,transport:t});
  const done=await t.capture(),envelope=JSON.parse(raw.stored);
  assert.equal(done.ref.sha256,sha(raw.stored));assert.equal(done.ref.bytesLength,raw.stored.length);
  assert.deepEqual(envelope.capture,done.capture);assert.deepEqual(envelope.inventory,inspectProductionControlCompositionOutput(out).graph.inventory);
  for(const o of Object.values(envelope.observations)){const b=Buffer.from(o.bytesBase64,'base64');assert.equal(sha(b),o.sha256);assert.equal(b.length,o.bytesLength);}
  assert.deepEqual(raw.calls.map(c=>c.method),['GET','GET','PUT','GET']);
  const expected={ref:done.ref,plan:f.plan,actualMain:a.actualMain};
  const checked=inspectProductionControlCompositionEnvelope(raw.stored,expected);
  assert.equal(checked.authority,false);
  const run=checked.observations.run,job=structuredClone(checked.observations.jobs.jobs[0]),now=Date.now();
  job.status='completed';job.conclusion='success';job.started_at=job.steps[0].started_at;job.completed_at=new Date(now).toISOString();
  Object.assign(job.steps[0],{status:'completed',conclusion:'success',completed_at:job.completed_at});
  assert.equal(completeProductionControlCompositionEnvelope(raw.stored,expected,{run,job,now}).completion.completedMs,now);
  for(const mutate of [e=>{e.capture.actualMain.mainRevision='f'.repeat(40);},e=>{e.capture.rootDescriptor.annotations={extra:'outer'};},
   e=>{e.capture.image.configDigest=e.inventory.nodes.find(n=>n.mediaType==='application/vnd.oci.empty.v1+json').digest;},
   e=>{e.capture.filesystem.entryCount--;},e=>{e.statement.predicate.runDetails.builder.id='buildkit';},e=>{e.observations.run.bytesBase64='AAAA';}]){
   const changed=structuredClone(envelope);mutate(changed);const bytes=Buffer.from(JSON.stringify(changed));
   assert.throws(()=>inspectProductionControlCompositionEnvelope(bytes,{...expected,ref:{sha256:sha(bytes),bytesLength:bytes.length}}));
  }
  for(const mutate of [j=>{j.conclusion='failure';},j=>{j.run_attempt++;},j=>{j.steps[0].completed_at=new Date(done.capture.completedMs-1).toISOString();}]){
   const changed=structuredClone(job);mutate(changed);assert.throws(()=>completeProductionControlCompositionEnvelope(raw.stored,expected,{run,job:changed,now}));
  }
  await assert.rejects(t.capture(),/PublicationOrder/);assert.equal(raw.calls.length,4);
 }finally{await t?.close();if(out)await closeProductionControlCompositionOutput(out);await a?.close();await f.remove();}
});
for(const fault of ['argument','run','attempt','source','job','step','duplicateJob','count','pagination','putChecksum','putKms','getKms','drift'])test('capture '+fault+' fails closed without a second write',async()=>{
 const f=await fixture({transport:true});let a,out,t;try{
  a=await admission(f);out=await composeProductionControl(a);const raw=captureService(a,registry(a),{fault});
  t=await openProductionControlCompositionTransport({allocation:a.allocation,env:{...env(a),GITHUB_TOKEN:'synthetic-github'}},{requestHandler:raw});
  await publishProductionControlComposition({output:out,allocation:a.allocation,transport:t});
  await assert.rejects(fault==='argument'?t.capture(Buffer.from('forged')):t.capture());
  assert.equal(productionControlCompositionSnapshot(a.allocation).held,true);
  assert.ok(raw.calls.filter(c=>c.method==='PUT').length<=1);
  if(['argument','run','attempt','source','job','step','duplicateJob','count','pagination'].includes(fault))assert.equal(raw.stored,undefined);
  const count=raw.calls.length;await assert.rejects(t.capture());assert.equal(raw.calls.length,count);
 }finally{await t?.close();if(out)await closeProductionControlCompositionOutput(out);await a?.close();await f.remove();}
});

function packService(a,f,base,{fault}={}){
 const q=productionControlCompositionLocations(a.allocation),calls=[];
 return {calls,async handle(r){
  if(r.hostname!=='s3.'+q.region+'.amazonaws.com')return base.handle(r);
  assert.equal(r.method,'GET');assert.equal(r.headers['x-amz-expected-bucket-owner'],q.account);assert.equal(r.headers['x-amz-checksum-mode'],'ENABLED');
  const name=['tools','source'].find(n=>r.path==='/'+q.bucket+'/'+q[n]);assert.ok(name);calls.push(name);
  const original=f.packBodies[name],body=Buffer.from(original),checksum=Buffer.from(sha(original),'hex').toString('base64');
  if(fault==='wire')body[body.length-1]^=1;
  if(fault==='lost')throw Error('synthetic-pack-response-lost');
  const chunkBytes=body.length>1048576?65536:117;
  return {response:{statusCode:200,headers:{'content-length':String(body.length),'x-amz-checksum-sha256':fault==='checksum'?'wrong':checksum,
   'x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':fault==='kms'?'wrong':q.kmsKeyArn,
   'x-amz-server-side-encryption-bucket-key-enabled':'true'},body:Readable.from((async function*(){for(let at=0;at<body.length;at+=chunkBytes)yield body.subarray(at,at+chunkBytes);})(),{objectMode:false})}};
 },destroy(){base.destroy();}};
}
test('paid pack acquisition reconstructs the complete native Git tree and composes from verified extracted bytes',async()=>{
 const f=await fixture({transport:true,packed:true});let a,t,p,out;try{
  a=await admission(f);const raw=packService(a,f,registry(a));t=await openProductionControlCompositionTransport({allocation:a.allocation,env:env(a)},{requestHandler:raw});
  p=await materializeProductionControlCompositionPacks({allocation:a.allocation,transport:t});
  const materialized=requireProductionControlCompositionPacks(p,a.allocation);assert.equal(materialized.sourceContext.tree,f.source.candidateTree);
  for(const [path,expected]of f.src.map)assert.deepEqual((await readControlSourceFile(materialized.sourceContext,path)).bytes,expected);
  assert.deepEqual(raw.calls,['tools','source']);
  assert.equal(materialized.usage.uncompressedBytes,f.input.packs.tools.uncompressedBytes+f.input.packs.source.uncompressedBytes);
  assert.equal(materialized.usage.processedEntries,f.input.packs.tools.processedEntries+f.input.packs.source.processedEntries);
  out=await composeProductionControl({...a,sourceContext:materialized.sourceContext});
  await assert.rejects(materializeProductionControlCompositionPacks({allocation:a.allocation,transport:t}),/PacksRepeated/);assert.equal(raw.calls.length,2);
  const location=join(requireProductionControlCompositionAllocation(a.allocation).directory,'packs','source',sha(f.src.map.get('scripts/a.mjs')));
  await writeFile(location,Buffer.from('changed'));
  await assert.rejects(readControlSourceFile(materialized.sourceContext,'scripts/a.mjs'),/PackChanged/);
 }finally{await t?.close();if(out)await closeProductionControlCompositionOutput(out);if(p)await closeProductionControlCompositionPacks(p);await a?.close();await f.remove();}
});
for(const fault of ['wire','lost','checksum','kms','tarPath','tarMode','tarContent','terminator','truncated'])test('pack '+fault+' holds the original allocation and removes exact owned extraction paths',async()=>{
 const mutatePack=(name,b)=>{
  if(name!=='tools')return b;
  if(fault==='tarPath')b[0]=47;
  if(fault==='tarMode')b[100]=49;
  if(fault==='tarContent'){
   // Alter the content-addressed member while retaining its manifest digest.
   const size=parseInt(b.subarray(124,135).toString(),8),at=512+Math.ceil(size/512)*512+512+512;b[at]^=1;
  }
  if(fault==='terminator')b[b.length-1]=1;
  return fault==='truncated'?b.subarray(0,b.length-512):b;
 };
 const f=await fixture({transport:true,packed:true,mutatePack});let a,t;try{
  a=await admission(f);const directory=requireProductionControlCompositionAllocation(a.allocation).directory,raw=packService(a,f,registry(a),{fault});
  t=await openProductionControlCompositionTransport({allocation:a.allocation,env:env(a)},{requestHandler:raw});
  await assert.rejects(materializeProductionControlCompositionPacks({allocation:a.allocation,transport:t}));
  assert.equal(productionControlCompositionSnapshot(a.allocation).held,true);
  await assert.rejects(lstat(join(directory,'packs')),{code:'ENOENT'});
  const count=raw.calls.length;await assert.rejects(materializeProductionControlCompositionPacks({allocation:a.allocation,transport:t}));assert.equal(raw.calls.length,count);
 }finally{await t?.close();await a?.close();await f.remove();}
});

function baseService(a,f,base,{fault}={}){
 const calls=[],region=a.config.region,repositoryName=f.input.base.image.repositoryName;
 const reply=v=>({response:{statusCode:200,headers:{},body:Readable.from([Buffer.isBuffer(v)?v:Buffer.from(JSON.stringify(v))],{objectMode:false})}});
 return {calls,async handle(r){
  if(r.hostname.startsWith('prod-'+region+'-starport-layer-bucket.s3.')){
   const digest='sha256:'+r.path.slice(1),raw=Buffer.from(f.data.get(digest));calls.push({action:'blob',digest});
   if(fault==='blob')raw[0]^=1;
   return reply(raw);
  }
  if(r.headers['x-amz-target']){
   const q=JSON.parse(r.body),action=r.headers['x-amz-target'].split('.').at(-1);
   if(q.repositoryName===repositoryName){
    calls.push({action,request:q});assert.equal(q.registryId,a.config.account);
    if(action==='BatchGetImage'){
     const digest=q.imageIds[0].imageDigest,raw=f.data.get(digest),d=f.input.base.inventory.nodes.find(d=>d.digest===digest);
     return reply({images:[{registryId:q.registryId,repositoryName,imageId:{imageDigest:fault==='manifest'?'sha256:'+'0'.repeat(64):digest},imageManifest:raw.toString(),imageManifestMediaType:d.mediaType}],failures:[]});
    }
    assert.equal(action,'GetDownloadUrlForLayer');const date=new Date().toISOString().replace(/[-:]/g,'').slice(0,15)+'Z';
    const location=new URL('https://prod-'+region+'-starport-layer-bucket.s3.'+region+'.amazonaws.com/'+q.layerDigest.slice(7));
    location.searchParams.set('X-Amz-Algorithm','AWS4-HMAC-SHA256');location.searchParams.set('X-Amz-SignedHeaders','host');location.searchParams.set('X-Amz-Date',date);
    location.searchParams.set('X-Amz-Expires','900');location.searchParams.set('X-Amz-Credential','synthetic/'+date.slice(0,8)+'/'+region+'/s3/aws4_request');location.searchParams.set('X-Amz-Signature','a'.repeat(64));
    if(fault==='origin')location.hostname='example.invalid';
    return reply({layerDigest:q.layerDigest,downloadUrl:location.href});
   }
  }
  return base.handle(r);
 },destroy(){base.destroy();}};
}
test('main reacquires every base descriptor under its own quota before full graph and filesystem verification',async()=>{
 const f=await fixture({transport:true,packed:true});let a,t,p,b,out;try{
  a=await admission(f,{preloadBase:false});const raw=baseService(a,f,packService(a,f,registry(a)));
  t=await openProductionControlCompositionTransport({allocation:a.allocation,env:env(a)},{requestHandler:raw});
  p=await materializeProductionControlCompositionPacks({allocation:a.allocation,transport:t});
  b=await acquireProductionControlCompositionBase({allocation:a.allocation,transport:t});const bound=requireProductionControlCompositionBase(b,a.allocation);
  assert.notEqual(bound.baseGraph,a.baseGraph);assert.deepEqual(bound.baseGraph.inventory,f.input.base.inventory);
  assert.equal(raw.calls.filter(c=>c.action==='BatchGetImage').length,f.plan.base.manifestNodes);
  assert.equal(raw.calls.filter(c=>c.action==='blob').length,f.plan.base.blobNodes);
  out=await composeProductionControl({...a,...bound,sourceContext:requireProductionControlCompositionPacks(p,a.allocation).sourceContext});
  assert.equal(inspectProductionControlCompositionOutput(out).record.planHash,f.plan.planHash);
 }finally{await t?.close();if(out)await closeProductionControlCompositionOutput(out);if(b)await closeProductionControlCompositionBase(b);if(p)await closeProductionControlCompositionPacks(p);await a?.close();await f.remove();}
});
for(const fault of ['blob','manifest','origin'])test('base '+fault+' cannot leave a reusable acquisition or owned cache',async()=>{
 const f=await fixture({transport:true});let a,t;try{
  a=await admission(f);const directory=requireProductionControlCompositionAllocation(a.allocation).directory,raw=baseService(a,f,registry(a),{fault});
  t=await openProductionControlCompositionTransport({allocation:a.allocation,env:env(a)},{requestHandler:raw});
  await assert.rejects(acquireProductionControlCompositionBase({allocation:a.allocation,transport:t}));
  assert.equal(productionControlCompositionSnapshot(a.allocation).held,true);await assert.rejects(lstat(join(directory,'acquired-base')),{code:'ENOENT'});
  const count=raw.calls.length;await assert.rejects(acquireProductionControlCompositionBase({allocation:a.allocation,transport:t}));assert.equal(raw.calls.length,count);
 }finally{await t?.close();await a?.close();await f.remove();}
});

for(const fault of ['wrongMain','unpinnedRuntime','lostPack'])test('foreground controller '+fault+' closes original allocation and exact owned resources',async()=>{
 const f=await fixture({transport:true,packed:true});let a;try{
  a=await admission(f,{preloadBase:false});const directory=requireProductionControlCompositionAllocation(a.allocation).directory;
  const original=registry(a),raw=baseService(a,f,packService(a,f,original,{fault:fault==='lostPack'?'lost':undefined}));
  await assert.rejects(runProductionControlComposition({...a,actualMain:fault==='wrongMain'?{...a.actualMain,mainRevision:'e'.repeat(40)}:a.actualMain,env:env(a)},
   {requestHandler:raw}),fault==='unpinnedRuntime'?/NativeNodePath/:undefined);
  const snapshot=productionControlCompositionSnapshot(a.allocation);assert.equal(snapshot.closed,true);assert.equal(snapshot.held,true);assert.equal(snapshot.refund,0);
  for(const path of ['packs','acquired-base','output'])await assert.rejects(lstat(join(directory,path)),{code:'ENOENT'});
  if(fault==='wrongMain')assert.equal(original.auth.calls.length,0);else assert.equal(original.auth.destroyed,true);
 }finally{await a?.close();await f.remove();}
});

test('foreground native-tool controller completes real hashes, acquisition, publication, capture and original accounting',async()=>{
 const f=await fixture({transport:true,packed:true,nativeTools:true});let a;try{
  a=await admission(f,{preloadBase:false});const directory=requireProductionControlCompositionAllocation(a.allocation).directory;
  const raw=captureService(a,baseService(a,f,packService(a,f,registry(a))));
  const done=await runProductionControlComposition({...a,env:{...env(a),GITHUB_TOKEN:'synthetic-github'}},{requestHandler:raw});
  assert.equal(done.accounting.closed,true);assert.equal(done.accounting.held,false);assert.equal(done.accounting.refund,0);
  assert.equal(done.capture.ref.sha256,sha(raw.stored));
  for(const path of ['packs','acquired-base','output'])await assert.rejects(lstat(join(directory,path)),{code:'ENOENT'});
  const events=(await readFile(join(directory,'journal.jsonl'),'utf8')).trim().split('\n').map(JSON.parse);
  assert.deepEqual(events.filter(e=>e.event==='runtime-checked').map(e=>e.data.phase),['packs','source','base','composed','published','captured']);
  assert.deepEqual(events.at(-1).spent,done.accounting.spent);
  for(const [k,v]of Object.entries(done.accounting.spent))assert.ok(v<=done.accounting.quota[k],k);
  assert.equal(done.accounting.spent.uncompressedBytes,f.input.packs.tools.uncompressedBytes+f.input.packs.source.uncompressedBytes+f.input.base.uncompressedBytes+f.plan.bounds.uncompressedBytes);
  assert.equal(done.accounting.spent.processedEntries,f.input.packs.tools.processedEntries+f.input.packs.source.processedEntries+f.input.base.processedEntries+f.plan.bounds.processedEntries);
 }finally{await a?.close();await f.remove();}
});

test('late response after abort drains its original body before transport cleanup settles',async()=>{
 const f=await fixture({transport:true});let a;try{
  a=await admission(f);const raw=rawService(a),original=raw.handle.bind(raw),abort=new AbortController();
  raw.handle=async r=>{await new Promise(resolve=>setTimeout(resolve,30));return original(r);};
  const timer=setTimeout(()=>abort.abort(),5);
  try{await assert.rejects(openProductionControlCompositionTransport({allocation:a.allocation,env:env(a),signal:abort.signal},{requestHandler:raw}));}finally{clearTimeout(timer);}
  assert.equal(raw.calls.length,1);assert.equal(raw.destroyed,true);assert.ok(raw.bodies.every(b=>b.closed));
  assert.equal(productionControlCompositionSnapshot(a.allocation).held,true);
 }finally{await a?.close();await f.remove();}
});
test('object-mode raw response rejects before SDK parsing and still closes the body',async()=>{
 const f=await fixture({transport:true});let a,body;try{
  a=await admission(f);const raw={async handle(){body=Readable.from([Buffer.from('{"value":"synthetic.header.signature"}')]);return {response:{statusCode:200,headers:{},body}};},destroy(){}};
  await assert.rejects(openProductionControlCompositionTransport({allocation:a.allocation,env:env(a)},{requestHandler:raw}),/Response/);
  assert.equal(body.closed,true);assert.equal(productionControlCompositionSnapshot(a.allocation).held,true);
 }finally{await a?.close();await f.remove();}
});

test('ambient SDK auto/default/profile/endpoint/retry settings cannot create extra I/O',async()=>{
 const f=await fixture({transport:true});let a,t;const changed={AWS_DEFAULTS_MODE:'auto',AWS_PROFILE:'unpriced-profile',AWS_CONFIG_FILE:'/synthetic/unpriced-config',
  AWS_SHARED_CREDENTIALS_FILE:'/synthetic/unpriced-credentials',AWS_ENDPOINT_URL_STS:'https://example.invalid',AWS_MAX_ATTEMPTS:'20',AWS_REGION:'eu-west-1'};
 const old=Object.fromEntries(Object.keys(changed).map(k=>[k,process.env[k]])),traps=[],calls=[];
 try{
  a=await admission(f);Object.assign(process.env,changed);
  for(const [object,key]of [[fsPromises,'readFile'],[http,'request'],[http,'get'],[https,'request'],[https,'get']]){
   traps.push(mock.method(object,key,()=>{calls.push(key);throw Error('unpriced-ambient-io');}));
  }
  const raw=rawService(a);t=await openProductionControlCompositionTransport({allocation:a.allocation,env:env(a)},{requestHandler:raw});
  assert.deepEqual(raw.calls.map(c=>c.action),['oidc','AssumeRoleWithWebIdentity','GetCallerIdentity']);assert.deepEqual(calls,[]);
  assert.ok(raw.calls.filter(c=>c.action!=='oidc').every(c=>c.host==='sts.us-west-2.amazonaws.com'));
 }finally{
  for(const trap of traps)trap.mock.restore();for(const [k,v]of Object.entries(old))if(v===undefined)delete process.env[k];else process.env[k]=v;
  await t?.close();await a?.close();await f.remove();
 }
});

test('separate protected-source session keeps exact parameter/archive scope and uses real SDK decoding',async()=>{
 const f=await fixture({transport:true});let a,t;try{
  a=await admission(f,{preloadBase:false});const auth=rawService(a),calls=[],q=productionControlCompositionLocations(a.allocation),root=a.config.ownerRoot;
  const prefix='data-authorizations/'+root.runtimeNonce+'/'+root.authorizationId+'/';
  const raw={async handle(r){
   if(r.hostname==='ssm.'+q.region+'.amazonaws.com'){
    calls.push('parameter');assert.equal(r.headers['x-amz-target'],'AmazonSSM.GetParameters');
    assert.deepEqual(JSON.parse(r.body),{Names:[PRODUCTION_DATA_RELEASE_PARAMETER],WithDecryption:true});
    const b=Buffer.from(JSON.stringify({Parameters:[{Name:PRODUCTION_DATA_RELEASE_PARAMETER,Type:'SecureString',Value:JSON.stringify(a.config.target.descriptor),Version:a.config.target.parameterVersion,
     ARN:'arn:aws:ssm:'+q.region+':'+q.account+':parameter'+PRODUCTION_DATA_RELEASE_PARAMETER,LastModifiedDate:Date.now()/1000}],InvalidParameters:[]}));
    return {response:{statusCode:200,headers:{'content-type':'application/x-amz-json-1.1'},body:Readable.from([b],{objectMode:false})}};
   }
   if(r.hostname==='s3.'+q.region+'.amazonaws.com'){
    calls.push(r.path);assert.equal(r.method,'GET');assert.equal(r.headers['x-amz-expected-bucket-owner'],q.account);
    assert.ok(['operation.json','nonroot-proof-archive.json'].some(n=>r.path==='/'+q.bucket+'/'+prefix+n));
    return {response:{statusCode:200,headers:{'content-length':'2',etag:'"synthetic"','x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':q.kmsKeyArn,
     'x-amz-server-side-encryption-bucket-key-enabled':'true'},body:Readable.from([Buffer.from('{}')],{objectMode:false})}};
   }
   return auth.handle(r);
  },destroy(){auth.destroy();}};
  const policy=productionControlCompositionProtectedSourcePolicy(a.allocation);assert.ok(Buffer.byteLength(policy)<=2048);
  assert.ok(!policy.includes('PutObject')&&!policy.includes('ecr:'));
  t=await openProductionControlCompositionProtectedSourceTransport({allocation:a.allocation,env:env(a)},{requestHandler:raw});
  assert.equal(t.bindOutput,undefined);assert.equal(t.capture,undefined);
  await t.clients.sts.send(new GetCallerIdentityCommand({}));
  for(let i=0;i<2;i++)assert.equal((await t.clients.ssm.send(new GetParametersCommand({Names:[PRODUCTION_DATA_RELEASE_PARAMETER],WithDecryption:true}))).Parameters[0].Version,a.config.target.parameterVersion);
  for(const name of ['operation.json','nonroot-proof-archive.json']){
   const r=await t.clients.s3.send(new GetObjectCommand({Bucket:q.bucket,Key:prefix+name,ExpectedBucketOwner:q.account}));
   assert.ok(r.Body instanceof Readable);let text='';for await(const b of r.Body)text+=b.toString();assert.equal(text,'{}');
  }
  assert.equal(auth.calls.length,4);assert.equal(calls.length,4);
  await assert.rejects(t.clients.s3.send(new GetObjectCommand({Bucket:q.bucket,Key:prefix+'other',ExpectedBucketOwner:q.account})),/ProtectedArchive/);assert.equal(calls.length,4);
 }finally{await t?.close();await a?.close();await f.remove();}
});

for(const dirty of [false,true])test('protected-source failure reports confirmed cleanup '+(!dirty)+' without inspecting error text',async()=>{
 const f=await fixture({transport:true});let a;try{
  a=await admission(f,{preloadBase:false,sourceLocalBytes:1048576});const e=env(a),raw=rawService(a,{wrongIdentity:true});
  if(dirty)raw.destroy=()=>{throw Error('synthetic-close-rejection');};
  const host={env:e,async run(){throw Error('unexpected Git');}};
  await assert.rejects(verifyProductionControlCompositionProtectedSource({allocation:a.allocation,env:e,host,sourceReceiptHash:'a'.repeat(64)},
   {requestHandler:raw}),error=>{assert.equal(error.cleanupComplete,!dirty);return true;});
  assert.equal(productionControlCompositionSnapshot(a.allocation).held,true);
  if(dirty)assert.throws(()=>closeProductionControlCompositionAllocation(a.allocation,{cleanupComplete:false}),/CleanupHeld/);
 }finally{await a?.close();await f.remove();}
});
