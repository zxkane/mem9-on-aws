/** Fixed R9 SDK transport. No ambient credential chain, endpoint override,
 * registry Docker client, retry or caller-selected policy/action. */
import {createHash,randomBytes} from 'node:crypto';
import {Readable} from 'node:stream';
import {Agent} from 'node:https';
import {S3Client,GetObjectCommand,PutObjectCommand} from '@aws-sdk/client-s3';
import {STSClient,AssumeRoleWithWebIdentityCommand,GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {NodeHttpHandler} from '@smithy/node-http-handler';
import {SignatureV4} from '@smithy/signature-v4';
import {Hash} from '@smithy/hash-node';
import {HttpRequest} from '@smithy/protocol-http';
import {assertCarrierConsumer} from './ci-carrier-consumer.mjs';
import {carrierObjectKeys} from './ci-carrier-before-copy.mjs';
import {parseAcquisitionJson,need,sha} from './ci-smoke-acquisition-format.mjs';

export function carrierSessionPolicy(plan){
 const t=plan.template,q=t.scope,k=carrierObjectKeys(t),repo=n=>'arn:aws:ecr:'+q.region+':'+q.account+':repository/'+n,s3=n=>'arn:aws:s3:::'+q.bucket+'/'+k[n];
 const reads=['ecr:BatchGetImage','ecr:GetDownloadUrlForLayer'],writes=['ecr:BatchCheckLayerAvailability','ecr:InitiateLayerUpload','ecr:UploadLayerPart','ecr:CompleteLayerUpload','ecr:PutImage'];
 const actions=['sts:GetCallerIdentity',...reads,...writes,'s3:GetObject','s3:PutObject','kms:GenerateDataKey','kms:Decrypt'];
 const Statement=[{Effect:'Deny',NotAction:actions,Resource:'*'},
  {Effect:'Allow',Action:'sts:GetCallerIdentity',Resource:'*'},
  {Effect:'Allow',Action:reads,Resource:repo(t.base.repositoryName)},
  {Effect:'Allow',Action:writes,Resource:repo(q.repositoryName)},
  {Effect:'Allow',Action:'s3:GetObject',Resource:[s3('grant'),s3('context'),s3('fixture')]},
  {Effect:'Allow',Action:'s3:PutObject',Resource:s3('result')},
  {Effect:'Allow',Action:['kms:GenerateDataKey','kms:Decrypt'],Resource:q.kmsKeyArn,Condition:{StringEquals:{'kms:ViaService':'s3.'+q.region+'.amazonaws.com','kms:CallerAccount':q.account,'kms:EncryptionContext:aws:s3:arn':'arn:aws:s3:::'+q.bucket}}},
  {Effect:'Deny',Action:'*',Resource:'*',Condition:{DateGreaterThanEquals:{'aws:CurrentTime':new Date(plan.deadlineMs).toISOString()}}},
 ];
 const Policy=JSON.stringify({Version:'2012-10-17',Statement});need(Buffer.byteLength(Policy)<=2048,'CarrierSessionPolicySize');return Policy;
}
function oidcLocation(env){
 need(env.ACTIONS_ID_TOKEN_REQUEST_URL===process.env.ACTIONS_ID_TOKEN_REQUEST_URL&&env.ACTIONS_ID_TOKEN_REQUEST_TOKEN===process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN,'CarrierOidcEnvironment');
 const u=new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL),uuid='[a-fA-F0-9-]{36}';
 need(u.protocol==='https:'&&!u.username&&!u.password&&!u.port&&!u.hash&&/^[a-z0-9-]+\.actions\.githubusercontent\.com$/.test(u.hostname)&&new RegExp('^/[A-Za-z0-9_-]+/_apis/distributedtask/hubs/build/plans/'+uuid+'/jobs/'+uuid+'/idtoken$').test(u.pathname),'CarrierOidcEndpoint');
 const ks=[...u.searchParams.keys()];need(new Set(ks).size===ks.length&&ks.every(k=>['api-version','audience'].includes(k))&&u.searchParams.get('api-version')==='2.0'&&(!u.searchParams.has('audience')||u.searchParams.get('audience')==='sts.amazonaws.com'),'CarrierOidcEndpoint');u.searchParams.set('audience','sts.amazonaws.com');return u;
}
function blobLocation(value,region){
 const u=new URL(value);need(u.protocol==='https:'&&!u.username&&!u.password&&!u.port&&!u.hash&&['prod-'+region+'-starport-layer-bucket.s3.'+region+'.amazonaws.com','prod-'+region+'-starport-layer-bucket.s3-'+region+'.amazonaws.com'].includes(u.hostname),'CarrierBlobEndpoint');
 const q=u.searchParams,date=q.get('X-Amz-Date'),expiry=q.get('X-Amz-Expires');need(new Set(q.keys()).size===[...q.keys()].length&&q.get('X-Amz-Algorithm')==='AWS4-HMAC-SHA256'&&/^\d{8}T\d{6}Z$/.test(date??'')&&/^[1-9][0-9]*$/.test(expiry??'')&&Number(expiry)<=604800&&q.get('X-Amz-SignedHeaders')==='host'&&/^[a-f0-9]{64}$/.test(q.get('X-Amz-Signature')??'')&&q.get('X-Amz-Credential')?.endsWith('/'+date.slice(0,8)+'/'+region+'/s3/aws4_request'),'CarrierBlobSignature');
 const at=Date.parse(date.slice(0,4)+'-'+date.slice(4,6)+'-'+date.slice(6,8)+'T'+date.slice(9,11)+':'+date.slice(11,13)+':'+date.slice(13,15)+'Z');need(at<=Date.now()+30000&&Date.now()<at+Number(expiry)*1000,'CarrierBlobExpired');return u;
}
export function createCarrierTransport({consumer,env},seams={}){
 assertCarrierConsumer(consumer);need(Object.keys(seams).every(k=>k==='requestHandler'||k==='oidcLocation'),'CarrierTransportSeams');
 const {config,binding}=consumer.admission,p=config.plan,t=p.template,q=t.scope,keys=carrierObjectKeys(t),agent=seams.requestHandler?null:new Agent({keepAlive:false,maxSockets:1,rejectUnauthorized:true});
 const http=seams.requestHandler??new NodeHttpHandler({httpsAgent:agent,connectionTimeout:5000,requestTimeout:30000});let current,credentials,credentialDeadline=p.deadlineMs,closed=false,held=false;
 const streams=new Set(),downloads=new Map(),clients=[],secretBuffers=new Set();
 const check=()=>{consumer.check();need(!closed&&!held&&Date.now()<credentialDeadline,'CarrierTransportHeld');};
 const timeout=()=>AbortSignal.timeout(Math.max(1,Math.min(30000,p.deadlineMs-Date.now(),credentialDeadline-Date.now())));
 async function exchange(request,options={}){
  check();const c=current;need(c&&!c.dispatched,'CarrierTransportReservation');const expected=c.service==='oidc'?c.oidc.hostname:c.service==='blob'?c.location.hostname:(c.service==='ecr'?'api.ecr':c.service)+'.'+q.region+'.amazonaws.com';
  need(request.protocol==='https:'&&request.hostname===expected&&!request.port,'CarrierTransportEndpoint');
  need(request.path===(c.service==='oidc'?c.oidc.pathname:c.service==='blob'?c.location.pathname:c.service==='s3'?'/'+q.bucket+'/'+c.key:'/'),'CarrierTransportPath');
  need(request.method===(c.service==='oidc'||c.service==='blob'||c.action==='GetObject'?'GET':c.action==='PutObject'?'PUT':'POST'),'CarrierTransportMethod');
  if(c.service==='s3'){
   need(request.headers['x-amz-expected-bucket-owner']===q.account&&Object.keys(request.query??{}).every(k=>k==='x-id'),'CarrierTransportS3Owner');
   if(c.action==='PutObject')need(request.headers['if-none-match']==='*'&&request.headers['x-amz-server-side-encryption']==='aws:kms'&&request.headers['x-amz-server-side-encryption-aws-kms-key-id']===q.kmsKeyArn&&request.headers['x-amz-server-side-encryption-bucket-key-enabled']==='true','CarrierTransportS3Protection');
  }
  if(c.service==='ecr')need(request.headers['x-amz-target']==='AmazonEC2ContainerRegistry_V20150921.'+c.action&&Object.keys(request.query??{}).length===0,'CarrierTransportEcrTarget');
  const body=request.body===undefined?Buffer.alloc(0):Buffer.from(request.body);c.requestBytes+=body.length;need(c.requestBytes<=c.reservation.caps.requestBytes,'CarrierTransportRequestLimit');c.reservation.finalGuard();c.reservation.charge(body.length);c.dispatched=true;
  const result=await http.handle(request,{...options,abortSignal:options.abortSignal??timeout()}),r=result.response;need(r&&Number.isInteger(r.statusCode)&&r.body instanceof Readable,'CarrierTransportResponse');streams.add(r.body);r.body.once('close',()=>streams.delete(r.body));
  const digest=createHash('sha256'),chunks=[];let received=0;
  const stream=(async function*(){try{for await(const v of r.body){check();need(v instanceof Uint8Array,'CarrierTransportBody');const b=Buffer.from(v);received+=b.length;c.responseBytes+=b.length;c.reservation.charge(b.length);need(c.responseBytes<=c.reservation.caps.responseBytes,'CarrierTransportResponseLimit');digest.update(b);yield b;}
   if(r.headers?.['content-length']!==undefined)need(/^(?:0|[1-9][0-9]*)$/.test(String(r.headers['content-length']))&&Number(r.headers['content-length'])===received,'CarrierTransportLength');
  }finally{r.body.destroy();}})();
  try{if(c.consume&&r.statusCode===200)c.consumed=await c.consume(stream);else{for await(const b of stream){need(received<=33554432,'CarrierTransportMetadataLimit');chunks.push(b);}}}
  finally{await stream.return?.();}
  c.responseHash=digest.digest('hex');need(r.statusCode===200,'CarrierTransportHttp');c.status=200;
  const raw=Buffer.concat(chunks);if(c.service==='ecr'||c.service==='oidc')c.raw=raw;if(c.service==='sts'||c.service==='oidc')secretBuffers.add(raw);
  return {response:{...r,body:Readable.from([raw])}};
 }
 const sdkOptions={region:q.region,ignoreConfiguredEndpointUrls:true,maxAttempts:1,credentials:async()=>{check();need(credentials,'CarrierNoAmbientCredentials');return credentials;},requestHandler:{handle:exchange,destroy(){}}};
 const sts=new STSClient({...sdkOptions,endpoint:'https://sts.'+q.region+'.amazonaws.com'}),s3=new S3Client({...sdkOptions,endpoint:'https://s3.'+q.region+'.amazonaws.com',forcePathStyle:true,followRegionRedirects:false,requestChecksumCalculation:'WHEN_REQUIRED',responseChecksumValidation:'WHEN_REQUIRED'});clients.push(sts,s3);
 async function call(purpose,service,action,input,send,{consume,key,location}={}){
  check();need(!current,'CarrierTransportSerial');const request=structuredClone(input),reservation=await consumer.beforeRequest(purpose,action,request);current={service,action,reservation,dispatched:false,requestBytes:0,responseBytes:0,consume,key,location};const c=current;
  try{const result=await send(request,c);need(c.status===200&&c.responseHash,'CarrierTransportIncomplete');await reservation.complete(Object.fromEntries(Object.entries(result).filter(([k])=>k!=='Body')),c.responseHash);result.Body?.destroy();return consume?c.consumed:result;}
  catch{held=true;await reservation.unknown();throw Error('CarrierTransportHeld');}finally{current=undefined;}
 }
 const ecr=(purpose,action,input)=>call(purpose,'ecr',action,input,async request=>{
  const wire={...request,...(request.layerPartBlob?{layerPartBlob:Buffer.from(request.layerPartBlob).toString('base64')}:{} )},body=JSON.stringify(wire),hostname='api.ecr.'+q.region+'.amazonaws.com';
  const signed=await new SignatureV4({credentials,region:q.region,service:'ecr',sha256:Hash.bind(null,'sha256')}).sign(new HttpRequest({protocol:'https:',hostname,method:'POST',path:'/',headers:{host:hostname,'content-type':'application/x-amz-json-1.1','x-amz-target':'AmazonEC2ContainerRegistry_V20150921.'+action,'content-length':String(Buffer.byteLength(body))},body}));
  const r=await exchange(signed,{abortSignal:timeout()});r.response.body.destroy();return parseAcquisitionJson(current.raw,Math.min(33554432,current.reservation.caps.responseBytes));
 });
 const object=n=>({Bucket:q.bucket,Key:keys[n],ExpectedBucketOwner:q.account});
 return Object.freeze({
  async assume(){
   const Policy=carrierSessionPolicy(p),RoleSessionName='carrier-'+binding.runId+'-'+binding.runAttempt+'-'+randomBytes(8).toString('hex'),input={RoleArn:q.previewRoleArn,RoleSessionName,DurationSeconds:2700,Policy};
   return call('assume','sts','AssumeRoleWithWebIdentity',input,async(request,c)=>{
    const url=seams.oidcLocation?.(env)??oidcLocation(env);c.service='oidc';c.oidc=url;
    const out=await exchange({protocol:'https:',hostname:url.hostname,method:'GET',path:url.pathname,query:Object.fromEntries(url.searchParams),headers:{authorization:'Bearer '+env.ACTIONS_ID_TOKEN_REQUEST_TOKEN,accept:'application/json'}},{abortSignal:timeout()});out.response.body.destroy();
    const token=parseAcquisitionJson(c.raw,131072);need(typeof token.value==='string'&&/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token.value),'CarrierOidcToken');
    c.service='sts';c.dispatched=false;let response,command=new AssumeRoleWithWebIdentityCommand({...request,WebIdentityToken:token.value});
    try{response=await sts.send(command,{abortSignal:timeout()});}finally{command.input.WebIdentityToken='';token.value='';c.raw?.fill(0);}
    const v=response.Credentials;need(v&&typeof v.AccessKeyId==='string'&&/^ASIA[A-Z0-9]{16}$/.test(v.AccessKeyId)&&typeof v.SecretAccessKey==='string'&&v.SecretAccessKey.length===40&&typeof v.SessionToken==='string'&&v.SessionToken.length>0&&v.Expiration instanceof Date&&v.Expiration.getTime()>=p.deadlineMs&&v.Expiration.getTime()<=Date.now()+2705000,'CarrierSessionCredentials');
    credentialDeadline=Math.min(p.deadlineMs,v.Expiration.getTime());credentials={accessKeyId:v.AccessKeyId,secretAccessKey:v.SecretAccessKey,sessionToken:v.SessionToken};for(const k of ['AccessKeyId','SecretAccessKey','SessionToken'])v[k]='';return {AssumedRoleUser:response.AssumedRoleUser};
   });
  },
  identity:()=>call('ciIdentity','sts','GetCallerIdentity',{},request=>sts.send(new GetCallerIdentityCommand(request),{abortSignal:timeout()})),
  getGrant:()=>call('grantGet','s3','GetObject',object('grant'),request=>s3.send(new GetObjectCommand(request),{abortSignal:timeout()}),{key:keys.grant,consume:async stream=>{const all=[];let n=0;for await(const b of stream){n+=b.length;need(n<=t.bounds.grantBytes,'CarrierGrantBytes');all.push(b);}consumer.reserveLocal({...zeroLocal(),logicalBytes:n});return parseAcquisitionJson(Buffer.concat(all,n),t.bounds.grantBytes);}}),
  getContext:consume=>call('contextGet','s3','GetObject',object('context'),request=>s3.send(new GetObjectCommand(request),{abortSignal:timeout()}),{key:keys.context,consume}),
  getFixture:consume=>call('fixtureGet','s3','GetObject',object('fixture'),request=>s3.send(new GetObjectCommand(request),{abortSignal:timeout()}),{key:keys.fixture,consume}),
  baseManifest:d=>ecr('baseManifest','BatchGetImage',{registryId:q.account,repositoryName:t.base.repositoryName,imageIds:[{imageDigest:d.digest}]}),
  async baseBlob(d,consume){
   const r=await ecr('baseUrl','GetDownloadUrlForLayer',{registryId:q.account,repositoryName:t.base.repositoryName,layerDigest:d.digest}),location=blobLocation(r.downloadUrl,q.region);downloads.set(d.digest,location);
   need(downloads.has(d.digest),'CarrierBlobLocation');downloads.delete(d.digest);
   return call('baseBlob','blob','S3BlobGet',{repositoryName:t.base.repositoryName,layerDigest:d.digest},async()=>{const r=await exchange({protocol:'https:',hostname:location.hostname,method:'GET',path:location.pathname,query:Object.fromEntries(location.searchParams),headers:{host:location.host}},{abortSignal:timeout()});r.response.body.destroy();return {repositoryName:t.base.repositoryName,layerDigest:d.digest,size:d.size};},{location,consume});
  },
  availability:layerDigests=>ecr('availability','BatchCheckLayerAvailability',{registryId:q.account,repositoryName:q.repositoryName,layerDigests}),
  initiate:()=>ecr('initiate','InitiateLayerUpload',{registryId:q.account,repositoryName:q.repositoryName}),
  part:input=>ecr('part','UploadLayerPart',{registryId:q.account,repositoryName:q.repositoryName,...input}),
  complete:input=>ecr('complete','CompleteLayerUpload',{registryId:q.account,repositoryName:q.repositoryName,...input}),
  putManifest:(d,raw)=>ecr('manifestPut','PutImage',{registryId:q.account,repositoryName:q.repositoryName,imageDigest:d.digest,imageManifest:Buffer.from(raw).toString('utf8'),imageManifestMediaType:d.mediaType}),
  putResult:raw=>{const request={...object('result'),Body:raw,ContentLength:raw.length,IfNoneMatch:'*',ServerSideEncryption:'aws:kms',SSEKMSKeyId:q.kmsKeyArn,BucketKeyEnabled:true,ChecksumSHA256:Buffer.from(sha(raw),'hex').toString('base64')};return call('resultPut','s3','PutObject',request,r=>s3.send(new PutObjectCommand(r),{abortSignal:timeout()}),{key:keys.result});},
  async close(){if(closed)return;closed=true;for(const b of streams)b.destroy();for(const client of clients)client.destroy();http.destroy();agent?.destroy();if(credentials){credentials.accessKeyId='';credentials.secretAccessKey='';credentials.sessionToken='';}for(const b of secretBuffers)b.fill(0);
   if(streams.size){let timer;const drained=await Promise.race([Promise.all([...streams].map(b=>b.closed?Promise.resolve():new Promise(resolve=>b.once('close',resolve)))).then(()=>true),new Promise(resolve=>{timer=setTimeout(()=>resolve(false),1000);})]);clearTimeout(timer);if(!drained)throw Object.assign(Error('ECLEANUP'),{code:'ECLEANUP'});}
  },
 });
}
const zeroLocal=()=>({ecrRequests:0,httpBodyBytes:0,logicalBytes:0,uncompressedBytes:0,processedEntries:0});
