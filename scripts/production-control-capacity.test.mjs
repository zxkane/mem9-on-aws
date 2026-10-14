import {it as test} from 'vitest';
import assert from 'node:assert/strict';
import {Readable} from 'node:stream';
import {createHash} from 'node:crypto';
import {createNonrootBudgetedReads} from './lib/production-nonroot-budget-transport.mjs';
import {createPrepaidControlCacheBudget} from './lib/production-image-graph.mjs';
import { FUTURE_CONTROL_CAPACITY, inspectFutureControlCapacity, measureFutureControlCapacity,
  createFutureControlWireMeter, verifyFutureControlGraphCapacity, futureControlCoreLocalFloor } from './lib/production-control-capacity.mjs';

const M=1048576;
const profile=(action,count,responseBytes=8*M)=>({kind:'CONTROL_ARTIFACT_FROM_AUTHENTICATED_BUILD',action,count,requestBytes:action==='S3BlobGet'?0:16384,responseBytes,late:{artifact:action==='S3BlobGet'?'layer':'root'}});
const profiles=[profile('BatchGetImage',3),profile('GetDownloadUrlForLayer',66,16384),profile('S3BlobGet',66,660*M),profile('DescribeImageScanFindings',1)];
test('closed quota replaces independent blob maxima, preserving all operations',()=>{
 const b=measureFutureControlCapacity(profiles,FUTURE_CONTROL_CAPACITY);
 assert.equal(b.ecrRequests,70);assert.equal(b.httpBodyBytes,727842816);assert.equal(b.logicalBytes,727842816);
 assert.throws(()=>inspectFutureControlCapacity({...FUTURE_CONTROL_CAPACITY,httpBodyBytes:727842817}));
 assert.throws(()=>measureFutureControlCapacity([...profiles,profile('PutImage',1)],FUTURE_CONTROL_CAPACITY));
});
test('serial admission, quota exhaustion, and one conservative unknown without prefix double count',()=>{
 const m=createFutureControlWireMeter(FUTURE_CONTROL_CAPACITY);
 const first=m.admit(profile('S3BlobGet',1,700*M));
 assert.equal(first.caps.responseBytes,FUTURE_CONTROL_CAPACITY.httpBodyBytes);first.charge(0);first.charge(100);first.complete();
 const second=m.admit(profile('S3BlobGet',1,700*M));
 assert.throws(()=>m.admit(profile('S3BlobGet',1,1)),/Concurrent/);
 second.charge(0);second.charge(27);second.unknown();
 assert.equal(m.snapshot().observedWireBytes,127);
 assert.equal(m.snapshot().conservativeWireBytes,100+second.caps.responseBytes+8*M);
 assert.equal(m.snapshot().unknowns,1);assert.throws(()=>m.admit(profiles[0]));
});
test('cap holds are narrowed before dispatch, errors still consume raw bytes',()=>{
 const m=createFutureControlWireMeter(FUTURE_CONTROL_CAPACITY),a=m.admit(profile('S3BlobGet',1,2**30));
 assert.equal(a.caps.responseBytes,FUTURE_CONTROL_CAPACITY.httpBodyBytes);
 a.charge(0);a.charge(a.caps.responseBytes);a.complete();
 assert.throws(()=>m.admit(profile('BatchGetImage',1)),/Quota/);
});
test('full descriptor population is checked, including attestations and conflicting extras',()=>{
 const nodes=[{digest:'sha256:'+'1'.repeat(64),size:10,mediaType:'application/vnd.oci.image.index.v1+json'},
 {digest:'sha256:'+'2'.repeat(64),size:11,mediaType:'application/vnd.oci.image.config.v1+json'},
 {digest:'sha256:'+'3'.repeat(64),size:12,mediaType:'application/vnd.in-toto+json'}];
 assert.equal(verifyFutureControlGraphCapacity(nodes,FUTURE_CONTROL_CAPACITY).graphBytes,33);
 assert.throws(()=>verifyFutureControlGraphCapacity([...nodes,{...nodes[2],size:13}],FUTURE_CONTROL_CAPACITY),/Conflict/);
 assert.throws(()=>verifyFutureControlGraphCapacity([...nodes,{digest:'sha256:'+'4'.repeat(64),size:660*M,mediaType:'application/vnd.oci.image.layer.v1.tar'}],FUTURE_CONTROL_CAPACITY),/Graph/);
});
test('660MiB satisfies only the core floor; it supplies no spare byte for guard/journal',()=>{
 assert.equal(futureControlCoreLocalFloor(660*M),2*1024*M);
 assert.equal(FUTURE_CONTROL_CAPACITY.capacityVerified,false);
});

function trackedBody(mode){
 const stats={produced:0,returned:0,reads:0,destroyed:0},total=12*M;
 const body=new Readable({objectMode:mode==='object',highWaterMark:64,
  read(n){stats.reads++;const size=mode==='raw'?Math.min(n,total-stats.produced):total;stats.produced+=size;this.push(Buffer.alloc(size,120));if(stats.produced===total)this.push(null);},
  destroy(error,done){setImmediate(()=>{stats.destroyed++;done(error);});}});
 if(mode==='decoded')body.setEncoding('utf8');
 const original=body.read;body.read=function(n){const value=original.call(this,n);if(value!==null)stats.returned+=Buffer.byteLength(value);return value;};
 return {body,stats};
}
const credentials={AWS_ACCESS_KEY_ID:'ASIASYNTHETIC',AWS_SECRET_ACCESS_KEY:'synthetic',AWS_SESSION_TOKEN:'synthetic'};
test('Dalton object-mode 12MiB reproducer consumes zero source bytes before rejection and cleanup',async()=>{
 const body=Readable.from([Buffer.alloc(12*M)]),originalRead=body.read.bind(body),meter=createFutureControlWireMeter(FUTURE_CONTROL_CAPACITY);
 let sourceConsumed=0,requestBytes=0,destroyed=0;body.read=n=>{const bytes=originalRead(n);if(bytes)sourceConsumed+=bytes.byteLength;return bytes;};
 const acquisition={controlCapacity:FUTURE_CONTROL_CAPACITY,reserveLocal(){},finish(){},async beforeRead(){return {...meter.admit(profile('BatchGetImage',1,128)),finalGuard(){}};}};
 const handler={destroy(){destroyed++;},async handle(request){requestBytes=Buffer.byteLength(request.body);return {response:{statusCode:500,headers:{'content-length':String(12*M)},body}};}};
 const transport=createNonrootBudgetedReads({region:'us-east-1',env:credentials,metadataReads:acquisition,requestHandler:handler});
 try{
  await assert.rejects(transport.readJson('ecr','BatchGetImage',{registryId:'123456789012',repositoryName:'mem9-on-aws/bootstrap',imageIds:[{imageDigest:'sha256:'+'a'.repeat(64)}]}));
  assert.equal(sourceConsumed,0);const s=meter.snapshot();assert.equal(s.observedWireBytes,requestBytes);assert.equal(s.conservativeWireBytes,8405120);assert.equal(s.unknowns,1);assert.equal(s.active,false);assert.equal(s.held,true);
  assert.equal(body.destroyed,true);assert.equal(body.closed,true);assert.equal(body.readableLength,0);
 }finally{transport.close();assert.equal(destroyed,1);}
});
for(const mode of ['object','decoded','raw'])test('raw metadata '+mode+' stream accounts upstream consumption, one unknown and awaited cleanup',async()=>{
 const meter=createFutureControlWireMeter(FUTURE_CONTROL_CAPACITY),{body,stats}=trackedBody(mode);let requestBytes=0,calls=0,destroyed=0;
 const acquisition={controlCapacity:FUTURE_CONTROL_CAPACITY,reserveLocal(){},finish(){},async beforeRead(){const slot=meter.admit(profile('BatchGetImage',1,128));return {...slot,finalGuard(){}};}};
 const handler={destroy(){destroyed++;},async handle(request){calls++;requestBytes=Buffer.byteLength(request.body);return {response:{statusCode:500,headers:{'content-length':String(12*M)},body}};}};
 const transport=createNonrootBudgetedReads({region:'us-east-1',env:credentials,metadataReads:acquisition,requestHandler:handler});
 try{
  await assert.rejects(transport.readJson('ecr','BatchGetImage',{registryId:'123456789012',repositoryName:'mem9-on-aws/bootstrap',imageIds:[{imageDigest:'sha256:'+'a'.repeat(64)}]}));
  const s=meter.snapshot();assert.equal(calls,1);assert.equal(stats.returned,mode==='raw'?129:0);
  if(mode==='raw'){assert(stats.produced>=129);assert(stats.produced<=512);}else{assert.equal(stats.reads,0);assert.equal(stats.produced,0);}
  assert.equal(s.observedWireBytes,requestBytes+stats.returned);assert.equal(s.unknowns,1);assert.equal(s.conservativeWireBytes,16384+128+8*M);
  assert(requestBytes+stats.produced<=s.conservativeWireBytes);assert.equal(stats.destroyed,1);assert.equal(body.closed,true);
  await assert.rejects(transport.readJson('ecr','BatchGetImage',{}),/Held/);assert.equal(calls,1);
 }finally{transport.close();assert.equal(destroyed,1);}
});
for(const mode of ['object','decoded','raw'])test('raw blob '+mode+' stream rejects before consumer or bounds the direct pull and drains',async()=>{
 const meter=createFutureControlWireMeter(FUTURE_CONTROL_CAPACITY),{body,stats}=trackedBody(mode),size=128,layerDigest='sha256:'+createHash('sha256').update(Buffer.alloc(size,120)).digest('hex');
 let calls=0,destroyed=0,metadataBytes=0,consumed=0,consumerCalls=0;
 const acquisition={controlCapacity:FUTURE_CONTROL_CAPACITY,reserveLocal(){},finish(){},async beforeRead(action){const slot=meter.admit(profile(action,1,action==='S3BlobGet'?size:16384));return {...slot,finalGuard(){}};}};
 const handler={destroy(){destroyed++;},async handle(request){calls++;
  if(request.hostname.startsWith('api.ecr.')){
   const date=new Date().toISOString().replace(/[-:]/g,'').replace(/\.\d{3}/,'');
   const params=new URLSearchParams({'X-Amz-Algorithm':'AWS4-HMAC-SHA256','X-Amz-Credential':'ASIASYNTHETIC/'+date.slice(0,8)+'/us-east-1/s3/aws4_request','X-Amz-Date':date,'X-Amz-Expires':'900','X-Amz-SignedHeaders':'host','X-Amz-Signature':'a'.repeat(64)});
   const raw=Buffer.from(JSON.stringify({layerDigest,downloadUrl:'https://prod-us-east-1-starport-layer-bucket.s3.us-east-1.amazonaws.com/object?'+params}));
   metadataBytes=Buffer.byteLength(request.body)+raw.length;return {response:{statusCode:200,headers:{'content-length':String(raw.length)},body:Readable.from([raw],{objectMode:false})}};
  }
  return {response:{statusCode:200,headers:{'content-length':String(size)},body}};
 }};
 const transport=createNonrootBudgetedReads({region:'us-east-1',env:credentials,metadataReads:acquisition,requestHandler:handler});
 try{
  await transport.readJson('ecr','GetDownloadUrlForLayer',{registryId:'123456789012',repositoryName:'mem9-on-aws/bootstrap',layerDigest});
  await assert.rejects(transport.readBlob({repositoryName:'mem9-on-aws/bootstrap',layerDigest},{account:'123456789012',size,consume:async stream=>{consumerCalls++;for await(const chunk of stream)consumed+=chunk.length;}}));
  assert.equal(calls,2);assert.equal(consumed,0);assert.equal(consumerCalls,mode==='raw'?1:0);assert.equal(stats.returned,mode==='raw'?129:0);
  if(mode==='raw'){assert(stats.produced>=129);assert(stats.produced<=512);}else{assert.equal(stats.reads,0);assert.equal(stats.produced,0);}
  const s=meter.snapshot();assert.equal(s.observedWireBytes,metadataBytes+stats.returned);assert.equal(s.unknowns,1);assert.equal(s.conservativeWireBytes,metadataBytes+size+8*M);
  assert(metadataBytes+stats.produced<=s.conservativeWireBytes);assert.equal(stats.destroyed,1);assert.equal(body.closed,true);
  await assert.rejects(transport.readBlob({repositoryName:'mem9-on-aws/bootstrap',layerDigest},{account:'123456789012',size,consume:async()=>{}}),/Held/);assert.equal(calls,2);
 }finally{transport.close();assert.equal(destroyed,1);}
});
test('per-pass FS limits remain enforced even when a target plus its replay owns more LOCAL',()=>{
 const reserveLocal=()=>{};
 const budget=createPrepaidControlCacheBudget({metadataReads:{controlCapacity:FUTURE_CONTROL_CAPACITY,reserveLocal}});
 budget.uncompressed(2*1024*M);assert.throws(()=>budget.uncompressed(1),/ImageUncompressedLimit/);
 const entries=createPrepaidControlCacheBudget({metadataReads:{controlCapacity:FUTURE_CONTROL_CAPACITY,reserveLocal}});
 for(let i=0;i<50000;i++)entries.entry();assert.throws(()=>entries.entry(),/ImageFilesystemEntryLimit/);
});
