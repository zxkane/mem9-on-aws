import {it,expect} from 'vitest';
import {Readable} from 'node:stream';
import {createHash} from 'node:crypto';
import {GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {GetParametersCommand} from '@aws-sdk/client-ssm';
import {GetObjectCommand} from '@aws-sdk/client-s3';
import {DescribeTasksCommand,RunTaskCommand} from '@aws-sdk/client-ecs';
import {GetRoleCommand} from '@aws-sdk/client-iam';
import {createNonrootBudgetedReads} from './lib/production-nonroot-budget-transport.mjs';

const env={AWS_ACCESS_KEY_ID:'synthetic-access',AWS_SECRET_ACCESS_KEY:'synthetic-secret',AWS_SESSION_TOKEN:'synthetic-session'};
const identity='<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:sts::123456789012:assumed-role/example/test</Arn><UserId>synthetic</UserId></GetCallerIdentityResult><ResponseMetadata><RequestId>synthetic</RequestId></ResponseMetadata></GetCallerIdentityResponse>';
function fixture({reply=identity,limit=8192,deny=false,networkError=false}={}){
 const events=[];
 const acquisition={beforeRead:async(action,request)=>{events.push(['reserve',action,request]);if(deny)throw Error('NoAllocation');return {caps:{requestBytes:4096,responseBytes:limit},finalGuard(){events.push(['guard']);},charge(n){events.push(['charge',n]);},async complete(response,responseHash){events.push(['complete',responseHash,response]);},async unknown(){events.push(['unknown']);}};},reserveLocal(c){events.push(['local',c]);},finish(){throw Error('CallerOwnsFinish');}};
 const transport={async handle(request){events.push(['http',request.hostname,Buffer.byteLength(request.body??'')]);if(networkError)throw Error('offline');return {response:{statusCode:200,headers:{'content-type':'text/xml'},body:Readable.from([Buffer.from(typeof reply==='function'?reply(request):reply)])}};},destroy(){events.push(['destroy']);}};
 const reader=createNonrootBudgetedReads({region:'ap-northeast-1',env,metadataReads:acquisition,requestHandler:transport});
 return {reader,events,acquisition};
}
it('reserves the first identity read before dispatch and measures original HTTP bodies',async()=>{
 const f=fixture();try{
  const r=await f.reader.clients.sts.send(new GetCallerIdentityCommand({}));expect(r.Account).toBe('123456789012');
  expect(f.events[0]).toEqual(['reserve','GetCallerIdentity',{}]);expect(f.events.findIndex(e=>e[0]==='guard')).toBeLessThan(f.events.findIndex(e=>e[0]==='http'));
  expect(f.events.filter(e=>e[0]==='charge').reduce((n,e)=>n+e[1],0)).toBe(Buffer.byteLength(identity)+f.events.find(e=>e[0]==='http')[2]);
  expect(f.events.filter(e=>e[0]==='complete')).toHaveLength(1);expect(f.events.some(e=>e[0]==='unknown')).toBe(false);
  const completion=f.events.find(e=>e[0]==='complete');expect(completion[1]).toBe(createHash('sha256').update(identity).digest('hex'));expect(completion[2]).toBe(r);
 }finally{f.reader.close();}
});
it('rejects mutation commands and invokes no reservation or HTTP transport',()=>{
 const f=fixture();try{expect(()=>f.reader.clients.ecs.send(new RunTaskCommand({cluster:'synthetic'}))).toThrow('NonrootReadOnlyCommand');expect(f.events).toEqual([]);}finally{f.reader.close();}
});
it('checks the last guard before HTTP and holds the slot if it expires during reservation',async()=>{
 const f=fixture(),original=f.acquisition.beforeRead;
 f.acquisition.beforeRead=async(...args)=>({...await original(...args),finalGuard(){throw Error('OriginalDeadlineExpired');}});
 try{
  await expect(f.reader.clients.sts.send(new GetCallerIdentityCommand({}))).rejects.toThrow('OriginalDeadlineExpired');
  expect(f.events.some(e=>e[0]==='http')).toBe(false);expect(f.events.filter(e=>e[0]==='unknown')).toHaveLength(1);
 }finally{f.reader.close();}
});
it('rejects a request larger than its allocation before signing dispatch',async()=>{
 const f=fixture(),original=f.acquisition.beforeRead;
 f.acquisition.beforeRead=async(...args)=>({...await original(...args),caps:{requestBytes:1,responseBytes:8192}});
 try{
  await expect(f.reader.clients.sts.send(new GetCallerIdentityCommand({}))).rejects.toThrow('NonrootRequestBodyLimit');
  expect(f.events.some(e=>e[0]==='http')).toBe(false);expect(f.events.filter(e=>e[0]==='unknown')).toHaveLength(1);
 }finally{f.reader.close();}
});
it('shares the same acquisition with ECS, IAM and native KMS reads',async()=>{
 const f=fixture({reply:request=>request.hostname==='iam.amazonaws.com'?'<GetRoleResponse><GetRoleResult><Role><RoleName>synthetic</RoleName></Role></GetRoleResult></GetRoleResponse>':'{}'});
 try{
  await f.reader.clients.ecs.send(new DescribeTasksCommand({cluster:'synthetic',tasks:['synthetic']}));
  // AWS query parsing remains the real SDK path even for an empty result.
  await f.reader.clients.iam.send(new GetRoleCommand({RoleName:'synthetic'}));
  await f.reader.readJson('kms','DescribeKey',{KeyId:'alias/aws/ssm'});
  expect(f.events.filter(e=>e[0]==='reserve').map(e=>e[1])).toEqual(['DescribeTasks','GetRole','DescribeKey']);
  expect(f.events.filter(e=>e[0]==='http').map(e=>e[1])).toEqual(['ecs.ap-northeast-1.amazonaws.com','iam.amazonaws.com','kms.ap-northeast-1.amazonaws.com']);
 }finally{f.reader.close();}
});
it('measures and closes an interrupted S3 stream before returning HOLD',async()=>{
 const f=fixture();let body;
 const transport={async handle(){body=Readable.from((async function*(){yield Buffer.from('partial');throw Error('truncated');})());return {response:{statusCode:200,headers:{},body}};},destroy(){}};
 const reader=createNonrootBudgetedReads({region:'ap-northeast-1',env,metadataReads:f.acquisition,requestHandler:transport});
 try{
  await expect(reader.clients.s3.send(new GetObjectCommand({Bucket:'synthetic-bucket',Key:'capture.json',ExpectedBucketOwner:'123456789012'}))).rejects.toThrow('NonrootBudgetReadFailed');
  expect(body.destroyed).toBe(true);expect(f.events.some(e=>e[0]==='charge'&&e[1]===7)).toBe(true);
  expect(f.events.filter(e=>e[0]==='unknown')).toHaveLength(1);expect(f.events.some(e=>e[0]==='complete')).toBe(false);
 }finally{reader.close();f.reader.close();}
});
it('forwards local charges without new counters, refunds, or finish',()=>{
 const f=fixture(),charge={ecrRequests:0,logicalBytes:12,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0};
 try{f.reader.reserveLocal(charge);expect(f.events).toEqual([['local',charge]]);}finally{f.reader.close();}
});
it('fails before all transport if the bridge is missing or the exact allocation rejects',async()=>{
 expect(()=>createNonrootBudgetedReads({region:'ap-northeast-1',env})).toThrow('NonrootAcquisitionRequired');
 const f=fixture({deny:true});try{await expect(f.reader.clients.sts.send(new GetCallerIdentityCommand({}))).rejects.toThrow('NoAllocation');expect(f.events.some(e=>e[0]==='http')).toBe(false);}finally{f.reader.close();}
});
it.each(['overflow','network','invalid-json'])('holds %s without settlement or another request',async defect=>{
 const f=fixture(defect==='overflow'?{limit:10}:defect==='network'?{networkError:true}:{reply:'not-json'});
 try{
  await expect(f.reader.clients.ssm.send(new GetParametersCommand({Names:['/synthetic'],WithDecryption:false}))).rejects.toThrow();
  expect(f.events.filter(e=>e[0]==='unknown')).toHaveLength(1);expect(f.events.some(e=>e[0]==='complete')).toBe(false);
  await expect(f.reader.clients.sts.send(new GetCallerIdentityCommand({}))).rejects.toThrow('NonrootAcquisitionHeld');
  expect(f.events.filter(e=>e[0]==='http')).toHaveLength(1);
 }finally{f.reader.close();}
});
it('uses the same reservation for native ECR metadata and never invokes the old CLI',async()=>{
 const f=fixture({reply:'{"images":[],"failures":[]}'});
 try{
  const input={repositoryName:'mem9-on-aws/llm-proxy',imageDigest:'sha256:'+'a'.repeat(64)};
  const result=await f.reader.readEcr('batch-get-image',input,{account:'123456789012'});
  expect(result).toEqual({images:[],failures:[]});expect(f.events[0]).toEqual(['reserve','BatchGetImage',{registryId:'123456789012',repositoryName:input.repositoryName,imageIds:[{imageDigest:input.imageDigest}]}]);
  expect(f.events.filter(e=>e[0]==='complete')).toHaveLength(1);
 }finally{f.reader.close();}
});

function blobFixture({data=Buffer.from('synthetic immutable layer'),body,replyStatus=200,urlHost,replyDigest,limit=8192}={}){
 const f=fixture({limit}),digest='sha256:'+createHash('sha256').update(data).digest('hex'),events=f.events;
 const timestamp=new Date().toISOString().replace(/[-:]/g,'').replace(/\.\d{3}/,'');
 const url=new URL('https://'+(urlHost??'prod-ap-northeast-1-starport-layer-bucket.s3.ap-northeast-1.amazonaws.com')+'/synthetic-layer');
 for(const [name,value] of Object.entries({'X-Amz-Algorithm':'AWS4-HMAC-SHA256','X-Amz-Date':timestamp,'X-Amz-Expires':'300','X-Amz-Credential':'synthetic/'+timestamp.slice(0,8)+'/ap-northeast-1/s3/aws4_request','X-Amz-SignedHeaders':'host','X-Amz-Signature':'a'.repeat(64)}))url.searchParams.set(name,value);
 let stream;
 const transport={async handle(request){
  events.push(['request',request]);
  if(request.hostname==='api.ecr.ap-northeast-1.amazonaws.com')return {response:{statusCode:200,headers:{},body:Readable.from([Buffer.from(JSON.stringify({downloadUrl:url.href,layerDigest:replyDigest??digest}))])}};
  stream=body?body(data):Readable.from([data.subarray(0,5),data.subarray(5)]);
  return {response:{statusCode:replyStatus,headers:{'content-length':String(data.length)},body:stream}};
 },destroy(){}};
 const reader=createNonrootBudgetedReads({region:'ap-northeast-1',env,metadataReads:f.acquisition,requestHandler:transport});
 const request={repositoryName:'mem9-on-aws/bootstrap',layerDigest:digest},scope={account:'123456789012',size:data.length};
 return {reader,events,request,scope,digest,data,get stream(){return stream;},getUrl:()=>reader.readJson('ecr','GetDownloadUrlForLayer',{registryId:scope.account,...request}),close(){reader.close();f.reader.close();}};
}
it('streams CONTROL layer bytes only from an authenticated earlier ECR URL and commits the actual digest',async()=>{
 const f=blobFixture();try{
  const response=await f.getUrl();response.downloadUrl='https://example.com/untrusted';
  const chunks=[];await f.reader.readBlob(f.request,{...f.scope,consume:async stream=>{for await(const bytes of stream)chunks.push(Buffer.from(bytes));}});
  expect(Buffer.concat(chunks).equals(f.data)).toBe(true);
  expect(f.events.filter(e=>e[0]==='reserve').map(e=>e[1])).toEqual(['GetDownloadUrlForLayer','S3BlobGet']);
  const request=f.events.filter(e=>e[0]==='request')[1][1];expect(request.hostname).toBe('prod-ap-northeast-1-starport-layer-bucket.s3.ap-northeast-1.amazonaws.com');
  expect(request.method).toBe('GET');expect(request.headers.authorization).toBeUndefined();expect(request.headers['x-amz-security-token']).toBeUndefined();
  const complete=f.events.filter(e=>e[0]==='complete').at(-1);expect(complete[1]).toBe(f.digest.slice(7));expect(complete[2]).toEqual({...f.request,size:f.data.length});
  expect(f.stream.destroyed).toBe(true);
  await expect(f.reader.readBlob(f.request,{...f.scope,consume:async()=>{}})).rejects.toThrow('NonrootBlobUrlRequired');
 }finally{f.close();}
});
it('does not allow an unbound URL, other account, or unapproved CONTROL digest to dispatch a blob request',async()=>{
 for(const defect of ['unbound','account','digest']){
  const f=blobFixture();try{
   if(defect!=='unbound')await f.getUrl();
   await expect(f.reader.readBlob({...f.request,...(defect==='digest'?{layerDigest:'sha256:'+'b'.repeat(64)}:{})},{...f.scope,...(defect==='account'?{account:'0'.repeat(12)}:{}),consume:async()=>{}})).rejects.toThrow('NonrootBlobUrlRequired');
   expect(f.events.filter(e=>e[0]==='request'&&e[1].method==='GET')).toHaveLength(0);
  }finally{f.close();}
 }
});
it.each(['redirect','truncated','digest','consumer-stops'])('holds a %s blob without a completed receipt or retry',async defect=>{
 const f=blobFixture({...(defect==='redirect'?{replyStatus:302}:{}),...(defect==='truncated'?{body:data=>Readable.from([data.subarray(0,5)])}:{}),...(defect==='digest'?{body:data=>Readable.from([Buffer.alloc(data.length,120)])}:{})});
 try{
  await f.getUrl();const consume=async stream=>{for await(const _ of stream){if(defect==='consumer-stops')break;}};
  await expect(f.reader.readBlob(f.request,{...f.scope,consume})).rejects.toThrow('NonrootBudgetReadFailed');
  expect(f.events.filter(e=>e[0]==='complete')).toHaveLength(1);expect(f.events.filter(e=>e[0]==='unknown')).toHaveLength(1);expect(f.stream.destroyed).toBe(true);
  await expect(f.reader.clients.sts.send(new GetCallerIdentityCommand({}))).rejects.toThrow('NonrootAcquisitionHeld');
  expect(f.events.filter(e=>e[0]==='request')).toHaveLength(2);
 }finally{f.close();}
});
it.each(['host','digest'])('rejects a mismatched ECR download %s before a URL can become usable',async defect=>{
 const f=blobFixture(defect==='host'?{urlHost:'example.com'}:{replyDigest:'sha256:'+'b'.repeat(64)});
 try{await expect(f.getUrl()).rejects.toThrow('NonrootBudgetReadFailed');expect(f.events.filter(e=>e[0]==='complete')).toHaveLength(0);expect(f.events.filter(e=>e[0]==='unknown')).toHaveLength(1);}
 finally{f.close();}
});
it('streams a valid layer beyond the metadata buffering limit without buffering the response',async()=>{
 const size=33*1024*1024,data=Buffer.alloc(size,7),f=blobFixture({data,limit:size,body:bytes=>Readable.from((async function*(){for(let offset=0;offset<bytes.length;offset+=65536)yield bytes.subarray(offset,offset+65536);})())});
 try{await f.getUrl();let observed=0,largest=0;await f.reader.readBlob(f.request,{...f.scope,consume:async stream=>{for await(const bytes of stream){observed+=bytes.length;largest=Math.max(largest,bytes.length);}}});expect(observed).toBe(size);expect(largest).toBeLessThanOrEqual(65536);expect(f.events.filter(e=>e[0]==='complete').at(-1)[1]).toBe(f.digest.slice(7));}
 finally{f.close();}
});
it('reserves and guards blob dispatch before HTTP, rejecting a cap smaller than the authenticated size',async()=>{
 const f=blobFixture();try{
  await f.getUrl();await expect(f.reader.readBlob(f.request,{...f.scope,size:10000,consume:async()=>{}})).rejects.toThrow('NonrootBlobBudget');
  expect(f.events.filter(e=>e[0]==='request')).toHaveLength(1);expect(f.events.filter(e=>e[0]==='unknown')).toHaveLength(1);
 }finally{f.close();}
});
it('aborts and drains an unfinished blob without publishing a completed receipt',async()=>{
 const f=blobFixture({body:()=>new Readable({read(){}})}),controller=new AbortController();
 try{await f.getUrl();await expect(f.reader.readBlob(f.request,{...f.scope,signal:controller.signal,consume:async stream=>{controller.abort();for await(const _ of stream){}}})).rejects.toThrow('NonrootBudgetReadFailed');expect(f.stream.closed).toBe(true);expect(f.events.filter(e=>e[0]==='complete')).toHaveLength(1);expect(f.events.filter(e=>e[0]==='unknown')).toHaveLength(1);}
 finally{f.close();}
});
it('reports ECLEANUP when a blob body cannot be positively drained',async()=>{
 const f=blobFixture({body:data=>new Readable({read(){this.push(data);this.push(null);},destroy(){}})});
 try{await f.getUrl();await expect(f.reader.readBlob(f.request,{...f.scope,consume:async stream=>{await stream[Symbol.asyncIterator]().next();}})).rejects.toMatchObject({code:'ECLEANUP'});expect(f.events.filter(e=>e[0]==='complete')).toHaveLength(1);expect(f.events.filter(e=>e[0]==='unknown')).toHaveLength(1);}
 finally{f.close();}
});
