/** Original raw service fixtures only; no native accessor or verifier replacements. */
import assert from 'node:assert/strict';
import {Readable} from 'node:stream';
import {sha} from './fixture.mjs';
import {productionControlCompositionLocations} from '../lib/production-control-composition-transport.mjs';
const syntheticForeignAccount='9'.repeat(12);
export function rawService(a,{wrongIdentity=false,failOidc=false}={}){
 const calls=[],bodies=[];let name,arn;
 return {calls,bodies,destroyed:false,async handle(request){
  const params=new URLSearchParams(request.body??''),action=params.get('Action')??'oidc';
  calls.push({action,body:request.body,host:request.hostname});let text;
  if(action==='oidc')text=JSON.stringify({value:'synthetic.header.signature'});
  else if(action==='AssumeRoleWithWebIdentity'){
   name=params.get('RoleSessionName');arn='arn:aws:sts::123456789012:assumed-role/github-actions-mem9-on-aws-prod/'+name;
   text='<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIASYNTHETIC</AccessKeyId><SecretAccessKey>synthetic-secret</SecretAccessKey><SessionToken>synthetic-session</SessionToken><Expiration>'+new Date(Date.now()+900000).toISOString()+'</Expiration></Credentials><AssumedRoleUser><Arn>'+arn+'</Arn><AssumedRoleId>AROA:'+name+'</AssumedRoleId></AssumedRoleUser></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>';
  }else text='<GetCallerIdentityResponse><GetCallerIdentityResult><Account>'+(wrongIdentity?syntheticForeignAccount:'123456789012')+'</Account><Arn>'+arn+'</Arn><UserId>AROA:'+name+'</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>';
  const body=Readable.from([Buffer.from(text)],{objectMode:false});bodies.push(body);
  return {response:{statusCode:failOidc?500:200,headers:{'content-type':action==='oidc'?'application/json':'text/xml'},body}};
 },destroy(){this.destroyed=true;}};
}
export function env(a){return {...a.env,ACTIONS_ID_TOKEN_REQUEST_URL:'https://pipelines.actions.githubusercontent.com/synthetic/_apis/distributedtask/hubs/build/plans/00000000-0000-4000-8000-000000000001/jobs/00000000-0000-4000-8000-000000000002/idtoken?api-version=2.0',ACTIONS_ID_TOKEN_REQUEST_TOKEN:'synthetic-token'};}
export function registry(a,{wrongComplete=false,failPart=false}={}){
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
   r={registryId:wrongComplete?syntheticForeignAccount:q.registryId,repositoryName:q.repositoryName,uploadId:q.uploadId,layerDigest:digest};
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
export function captureService(a,base,{fault}={}){
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
export function packService(a,f,base,{fault}={}){
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
export function baseService(a,f,base,{fault}={}){
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
