/** Fixed authenticated main transport. SDK providers are explicit and each
 * original quota slot permits one HTTP dispatch, including redirects/errors.
 * The transport has no arbitrary action, endpoint, key or credential API. */
import {createHash,randomBytes} from 'node:crypto';
import {Agent} from 'node:https';
import {Readable} from 'node:stream';
import {STSClient,AssumeRoleWithWebIdentityCommand,GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {SSMClient,GetParametersCommand} from '@aws-sdk/client-ssm';
import {S3Client,GetObjectCommand} from '@aws-sdk/client-s3';
import {SignatureV4} from '@smithy/signature-v4';
import {Hash} from '@smithy/hash-node';
import {HttpRequest} from '@smithy/protocol-http';
import {NodeHttpHandler} from '@smithy/node-http-handler';
import {parseAcquisitionJson} from './ci-smoke-acquisition-format.mjs';
import {nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {productionControlCompositionCatalog} from './production-control-composition-catalog.mjs';
import {compositionNeed as need,encodeCompositionJson,PRODUCTION_CONTROL_COMPOSITION_LIMITS as L} from './production-control-composition.mjs';
import {requireProductionControlCompositionAllocation,beginProductionControlCompositionRequest,recordProductionControlComposition,holdProductionControlComposition} from './production-control-composition-lifetime.mjs';
import {inspectProductionControlCompositionOutput,captureProductionControlComposition} from './production-control-composition-producer.mjs';
import {inspectCompositionStsXml} from './production-control-composition-xml.mjs';
import {PRODUCTION_DATA_RELEASE_PARAMETER} from './production-data-issuance.mjs';
import {describeProductionControlCompositionLocations} from './production-control-composition-locations.mjs';
import {requireBoundProductionControlCompositionRuntime,productionControlCompositionRuntimeCapture} from './production-control-composition-runtime.mjs';

const sessions=new WeakMap(),STS_REGION='us-west-2',sha=b=>createHash('sha256').update(b).digest('hex');
async function* rawChunks(stream,limit){
 need(stream instanceof Readable&&stream.readableObjectMode===false&&stream.readableEncoding===null,'ControlCompositionRawByteStream');let n=0;
 while(n<=limit){
  const chunk=stream.read(Math.min(65536,limit-n+1));
  if(chunk!==null){need(chunk instanceof Uint8Array,'ControlCompositionRawByteStream');n+=chunk.length;yield chunk;continue;}
  if(stream.readableEnded)return;
  if(stream.destroyed)throw stream.errored??Error('ControlCompositionResponseClosed');
  await new Promise((resolve,reject)=>{
   const clear=()=>{stream.off('readable',ready);stream.off('end',ready);stream.off('close',closed);stream.off('error',failed);};
   const ready=()=>{clear();resolve();},failed=e=>{clear();reject(e);},closed=()=>{clear();stream.readableEnded?resolve():reject(Error('ControlCompositionResponseClosed'));};
   stream.once('readable',ready);stream.once('end',ready);stream.once('close',closed);stream.once('error',failed);
  });
 }
}
export function productionControlCompositionLocations(allocation){
 return describeProductionControlCompositionLocations(requireProductionControlCompositionAllocation(allocation).config);
}
export function productionControlCompositionSessionPolicy(allocation){
 const a=requireProductionControlCompositionAllocation(allocation),q=productionControlCompositionLocations(allocation);
 const repo=name=>'arn:aws:ecr:'+q.region+':'+q.account+':repository/'+name,obj=name=>'arn:aws:s3:::'+q.bucket+'/'+q[name];
 const reads=['ecr:BatchGetImage','ecr:GetDownloadUrlForLayer'],writes=['ecr:BatchCheckLayerAvailability','ecr:InitiateLayerUpload','ecr:UploadLayerPart','ecr:CompleteLayerUpload','ecr:PutImage'];
 const actions=['sts:GetCallerIdentity',...reads,...writes,'s3:GetObject','s3:PutObject','kms:GenerateDataKey','kms:Decrypt'];
 const policy={Version:'2012-10-17',Statement:[
  {Effect:'Deny',NotAction:actions,Resource:'*'},
  {Effect:'Allow',Action:'sts:GetCallerIdentity',Resource:'*'},
  {Effect:'Allow',Action:[...reads,'s3:GetObject'],Resource:[repo(a.plan.input.base.image.repositoryName),repo('mem9-on-aws/bootstrap'),...(a.plan.version===1?[obj('tools')]:[]),obj('source'),obj('capture')]},
  {Effect:'Allow',Action:[...writes,'s3:PutObject'],Resource:[repo('mem9-on-aws/bootstrap'),obj('capture')]},
  {Effect:'Allow',Action:['kms:GenerateDataKey','kms:Decrypt'],Resource:q.kmsKeyArn,Condition:{StringEquals:{
   'kms:ViaService':'s3.'+q.region+'.amazonaws.com','kms:CallerAccount':q.account,'kms:EncryptionContext:aws:s3:arn':'arn:aws:s3:::'+q.bucket}}},
  {Effect:'Deny',Action:'*',Resource:'*',Condition:{DateGreaterThanEquals:{'aws:CurrentTime':new Date(a.deadlineMs).toISOString()}}},
 ]};
 const text=JSON.stringify(policy);
 if(Buffer.byteLength(text)>2048)throw Object.assign(Error('ControlCompositionPolicySize'),{policyBytes:Buffer.byteLength(text),limit:2048});
 return text;
}
export function productionControlCompositionProtectedSourcePolicy(allocation){
 const a=requireProductionControlCompositionAllocation(allocation),q=productionControlCompositionLocations(allocation),r=a.config.ownerRoot;
 const prefix='arn:aws:s3:::'+q.bucket+'/data-authorizations/'+r.runtimeNonce+'/'+r.authorizationId+'/';
 const policy={Version:'2012-10-17',Statement:[
  {Effect:'Deny',NotAction:['sts:GetCallerIdentity','ssm:GetParameters','s3:GetObject','kms:Decrypt'],Resource:'*'},
  {Effect:'Allow',Action:'sts:GetCallerIdentity',Resource:'*'},
  {Effect:'Allow',Action:'ssm:GetParameters',Resource:'arn:aws:ssm:'+q.region+':'+q.account+':parameter'+PRODUCTION_DATA_RELEASE_PARAMETER},
  {Effect:'Allow',Action:'s3:GetObject',Resource:[prefix+'operation.json',prefix+'nonroot-proof-archive.json']},
  {Effect:'Allow',Action:'kms:Decrypt',Resource:q.kmsKeyArn,Condition:{StringEquals:{'kms:ViaService':'s3.'+q.region+'.amazonaws.com','kms:CallerAccount':q.account,'kms:EncryptionContext:aws:s3:arn':'arn:aws:s3:::'+q.bucket}}},
  {Effect:'Deny',Action:'*',Resource:'*',Condition:{DateGreaterThanEquals:{'aws:CurrentTime':new Date(a.deadlineMs).toISOString()}}},
 ]};
 const text=JSON.stringify(policy);need(Buffer.byteLength(text)<=2048,'ControlCompositionPolicySize');return text;
}
function oidc(env){
 const u=new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
 need(u.protocol==='https:'&&!u.username&&!u.password&&!u.port&&!u.hash&&/^[a-z0-9-]+\.actions\.githubusercontent\.com$/.test(u.hostname)&&
  typeof env.ACTIONS_ID_TOKEN_REQUEST_TOKEN==='string'&&env.ACTIONS_ID_TOKEN_REQUEST_TOKEN.length>0,'ControlCompositionOidc');
 need([...u.searchParams.keys()].every(k=>['api-version','audience'].includes(k))&&new Set(u.searchParams.keys()).size===[...u.searchParams.keys()].length&&
  (!u.searchParams.has('audience')||u.searchParams.get('audience')==='sts.amazonaws.com'),'ControlCompositionOidc');
 u.searchParams.set('audience','sts.amazonaws.com');return u;
}
function blobUrl(raw,region){
 const u=new URL(raw);
 need(u.protocol==='https:'&&!u.username&&!u.password&&!u.port&&!u.hash&&
  ['prod-'+region+'-starport-layer-bucket.s3.'+region+'.amazonaws.com','prod-'+region+'-starport-layer-bucket.s3-'+region+'.amazonaws.com'].includes(u.hostname),'ControlCompositionBlobOrigin');
 const q=u.searchParams,date=q.get('X-Amz-Date'),seconds=q.get('X-Amz-Expires');
 need(q.get('X-Amz-Algorithm')==='AWS4-HMAC-SHA256'&&q.get('X-Amz-SignedHeaders')==='host'&&/^[a-f0-9]{64}$/.test(q.get('X-Amz-Signature')??'')&&
  /^\d{8}T\d{6}Z$/.test(date??'')&&/^[1-9][0-9]*$/.test(seconds??'')&&Number(seconds)<=604800&&
  q.get('X-Amz-Credential')?.endsWith('/'+date.slice(0,8)+'/'+region+'/s3/aws4_request')&&new Set(q.keys()).size===[...q.keys()].length,'ControlCompositionBlobSignature');
 const at=Date.parse(date.slice(0,4)+'-'+date.slice(4,6)+'-'+date.slice(6,8)+'T'+date.slice(9,11)+':'+date.slice(11,13)+':'+date.slice(13,15)+'Z');
 need(at<=Date.now()+30000&&Date.now()<at+Number(seconds)*1000,'ControlCompositionBlobExpired');return u;
}
export async function openProductionControlCompositionTransport({allocation,env,signal},seams={}){
 return openTransport({allocation,env,signal},seams,'composition');
}
export async function openProductionControlCompositionProtectedSourceTransport({allocation,env,signal},seams={}){
 return openTransport({allocation,env,signal},seams,'protected-source');
}
async function openTransport({allocation,env,signal},seams,purpose){
 need(Object.keys(seams).every(k=>k==='requestHandler'),'ControlCompositionTransportSeam');
 const admitted=requireProductionControlCompositionAllocation(allocation),q=productionControlCompositionLocations(allocation);
 if(admitted.plan.version===2)requireBoundProductionControlCompositionRuntime(allocation);
 need(hash(admitted.funding.catalog)===hash(productionControlCompositionCatalog(admitted.plan)),'ControlCompositionTransportCatalog');
 need(!env.AWS_ACCESS_KEY_ID&&!env.AWS_SECRET_ACCESS_KEY&&!env.AWS_SESSION_TOKEN,'ControlCompositionAmbientCredentials');
 const sourceMode=purpose==='protected-source',slotId=id=>sourceMode?'guard-'+id:id;
 const policy=(sourceMode?productionControlCompositionProtectedSourcePolicy:productionControlCompositionSessionPolicy)(allocation),url=oidc(env),agent=seams.requestHandler?null:new Agent({keepAlive:false,maxSockets:1,rejectUnauthorized:true});
 const http=seams.requestHandler??new NodeHttpHandler({httpsAgent:agent,connectionTimeout:5000,requestTimeout:30000});
 const controller=new AbortController(),pending=new Set(),bodies=new Set(),decodedBodies=new Set(),signedRequests=new Set(),buffers=new Set(),extraClients=[];
 let current,credentials,credentialHash,credentialDeadline=admitted.deadlineMs,closed=false,held=false,sts,publication;
 const secretObjects=new Set();
 const abort=()=>{controller.abort();for(const b of [...bodies,...decodedBodies])b.destroy?.();};
 signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
 const check=()=>{requireProductionControlCompositionAllocation(allocation);need(!closed&&!held&&!controller.signal.aborted&&Date.now()<credentialDeadline,'ControlCompositionTransportHeld');
  if(credentials)need(hash({accessKeyId:credentials.accessKeyId,secretAccessKey:credentials.secretAccessKey,sessionToken:credentials.sessionToken,expiration:credentials.expiration.toISOString()})===credentialHash,'ControlCompositionCredentialsChanged');};
 const track=p=>{const promise=Promise.resolve(p).finally(()=>pending.delete(promise));pending.add(promise);promise.catch(()=>{});return promise;};
 async function exchange(request){
  check();const c=current;need(c&&!c.dispatched,'ControlCompositionTransportSlot');
  const expected=c.url??new URL('https://'+(c.service==='ecr'?'api.ecr.'+q.region:c.service==='sts'?'sts.'+STS_REGION:c.service==='ssm'?'ssm.'+q.region:'s3.'+q.region)+'.amazonaws.com'+(c.key?'/'+q.bucket+'/'+c.key:'/'));
  need(request.protocol==='https:'&&request.hostname===expected.hostname&&!request.port&&request.path===expected.pathname&&request.method===c.method,'ControlCompositionTransportEndpoint');
  need(hash(request.query??{})===hash(Object.fromEntries(expected.searchParams)),'ControlCompositionTransportQuery');
  if(c.service==='ecr')need(request.headers['x-amz-target']==='AmazonEC2ContainerRegistry_V20150921.'+c.action,'ControlCompositionEcrAction');
  if(c.service==='ssm')need(request.headers['x-amz-target']==='AmazonSSM.GetParameters','ControlCompositionSsmAction');
  const raw=request.body??Buffer.alloc(0);need(typeof raw==='string'||raw instanceof Uint8Array,'ControlCompositionRequestBody');
  if(c.bodyHash)need(sha(raw)===c.bodyHash,'ControlCompositionSerializedBodyChanged');
  need(Buffer.byteLength(raw)<=c.slot.caps.requestBytes,'ControlCompositionRequestBytes');
  if(c.service==='sts')need(new URLSearchParams(raw).get('Action')===c.action,'ControlCompositionStsAction');
  c.slot.charge(Buffer.byteLength(raw));c.slot.dispatch();c.dispatched=true;signedRequests.add(request);
  const aborter=AbortSignal.any([controller.signal,AbortSignal.timeout(Math.max(1,Math.min(30000,credentialDeadline-Date.now())))]);
  let rejectAbort;const stopped=new Promise((_,reject)=>{rejectAbort=()=>reject(Error('ControlCompositionRequestAborted'));aborter.addEventListener('abort',rejectAbort,{once:true});});
  try{
   const arrival=track(Promise.resolve(http.handle(request,{abortSignal:aborter})).then(result=>{
    const body=result?.response?.body;if(body&&typeof body.destroy==='function'){bodies.add(body);if(aborter.aborted||closed)body.destroy();}
    aborter.throwIfAborted();return result;
   }));
   const result=await Promise.race([arrival,stopped]),r=result.response;
   need(r&&Number.isInteger(r.statusCode)&&r.body instanceof Readable&&r.body.readableObjectMode===false&&r.body.readableEncoding===null,'ControlCompositionResponse');
   bodies.add(r.body);const chunks=[],digest=createHash('sha256');let total=0;
   const consume=async()=>{for await(const rawChunk of rawChunks(r.body,r.statusCode===200?c.slot.caps.responseBytes:L.unknownBytes)){
    check();need(rawChunk instanceof Uint8Array&&rawChunk.length<=8388608,'ControlCompositionResponseChunk');c.slot.charge(rawChunk.length);
    total+=rawChunk.length;need(total<=(r.statusCode===200?c.slot.caps.responseBytes:L.unknownBytes),'ControlCompositionResponseBytes');
    digest.update(rawChunk);if(c.consume&&r.statusCode===200)await c.consume(rawChunk);else{need(total<=33554432,'ControlCompositionResponseBuffer');chunks.push(Buffer.from(rawChunk));}
   }};
   await Promise.race([track(consume()),stopped]);
   if(r.headers?.['content-length']!==undefined)need(/^(?:0|[1-9][0-9]*)$/.test(String(r.headers['content-length']))&&Number(r.headers['content-length'])===total,'ControlCompositionResponseLength');
   c.responseHash=digest.digest('hex');c.responseHeaders=r.headers;c.responseBytes=total;
   need(r.statusCode===200,'ControlCompositionHttp');
   const body=Buffer.concat(chunks);for(const b of chunks)buffers.add(b);buffers.add(body);
   if(c.service==='sts')inspectCompositionStsXml(body,c.action);c.raw=body;
   if(sourceMode&&c.service==='s3'){const decoded=Readable.from([body],{objectMode:false});decodedBodies.add(decoded);return {response:{...r,body:decoded}};}
   return {response:{...r,body}};
  }finally{aborter.removeEventListener('abort',rejectAbort);for(const b of bodies)b.destroy();for(const b of [...bodies])if(b.closed)bodies.delete(b);}
 }
 const sdk={region:STS_REGION,endpoint:'https://sts.'+STS_REGION+'.amazonaws.com',ignoreConfiguredEndpointUrls:true,defaultsMode:'legacy',retryMode:'standard',
  maxAttempts:1,useFipsEndpoint:false,useDualstackEndpoint:false,credentials:async()=>{check();need(credentials,'ControlCompositionNoAmbientCredentials');return credentials;},
  requestHandler:{handle:exchange,destroy(){}}};
 async function call(id,service,action,input,send,{url,method='POST',key,consume}={}){
  check();need(!current,'ControlCompositionTransportConcurrent');
  const c={id,service,action,url,method,key,consume,dispatched:false,slot:beginProductionControlCompositionRequest(allocation,id,{service,action,requestHash:sha(JSON.stringify(input))})};current=c;
  try{const result=await send();need(c.responseHash,'ControlCompositionIncompleteResponse');c.slot.complete(c.responseHash);return {result,headers:c.responseHeaders,raw:c.raw,bytes:c.responseBytes};}
  catch(error){held=true;try{c.slot.unknown(error.message);}finally{abort();}throw error;}
  finally{current=null;for(const r of signedRequests){if(r.headers){delete r.headers.authorization;delete r.headers.Authorization;delete r.headers['x-amz-security-token'];}r.body=undefined;}signedRequests.clear();}
 }
 const sign=async(service,request)=>new SignatureV4({service,region:q.region,credentials,sha256:Hash.bind(null,'sha256')}).sign(new HttpRequest(request));
 async function ecr(id,action,input,createInput=()=>input){
  need(input.registryId===q.account&&[admitted.plan.input.base.image.repositoryName,'mem9-on-aws/bootstrap'].includes(input.repositoryName),'ControlCompositionEcrScope');
  return (await call(id,'ecr',action,{registryId:input.registryId,repositoryName:input.repositoryName,action},async()=>{const body=JSON.stringify(createInput());current.bodyHash=sha(body);const signed=await sign('ecr',{protocol:'https:',hostname:'api.ecr.'+q.region+'.amazonaws.com',method:'POST',path:'/',headers:{
   host:'api.ecr.'+q.region+'.amazonaws.com','content-type':'application/x-amz-json-1.1','x-amz-target':'AmazonEC2ContainerRegistry_V20150921.'+action},body});await exchange(signed);return parseAcquisitionJson(current.raw);})).result;
 }
 async function objectGet(name,consume){
  const key=q[name],id=name==='capture'?'capture-get':name+'-get';
  return call(id,'s3','GetObject',{bucket:q.bucket,key},async()=>exchange(await sign('s3',{protocol:'https:',hostname:'s3.'+q.region+'.amazonaws.com',method:'GET',path:'/'+q.bucket+'/'+key,
   headers:{host:'s3.'+q.region+'.amazonaws.com','x-amz-expected-bucket-owner':q.account,'x-amz-checksum-mode':'ENABLED'}})),{key,method:'GET',consume});
 }
 function inspectObjectHeaders(headers,digest){
  need(headers?.['x-amz-server-side-encryption']==='aws:kms'&&headers['x-amz-server-side-encryption-aws-kms-key-id']===q.kmsKeyArn&&
   headers['x-amz-server-side-encryption-bucket-key-enabled']==='true','ControlCompositionObjectEncryption');
  need(headers['x-amz-checksum-sha256']===Buffer.from(digest,'hex').toString('base64')&&
   (!headers['x-amz-checksum-type']||headers['x-amz-checksum-type']==='FULL_OBJECT'),'ControlCompositionObjectChecksum');
  need(!headers['content-encoding']&&!headers['content-range']&&!headers['x-amz-delete-marker'],'ControlCompositionObjectEncoding');
 }
 async function getPack(name,consume){
  need(typeof consume==='function','ControlCompositionPackConsumer');const d=admitted.plan.input.packs[name].ref,h=createHash('sha256');let size=0;
  const response=await objectGet(name,async b=>{need(size+b.length<=d.bytesLength,'ControlCompositionPackSize');h.update(b);size+=b.length;await consume(b);});
  need(size===d.bytesLength&&h.digest('hex')===d.sha256,'ControlCompositionPackDigest');inspectObjectHeaders(response.headers,d.sha256);
  return Object.freeze({bytesLength:size,sha256:d.sha256});
 }
 async function githubCapture(id,suffix){
  const s=admitted.binding.source,path='/repos/'+s.repository+'/actions/runs/'+s.runId+'/attempts/'+s.runAttempt+suffix;
  const location=new URL('https://api.github.com'+path);
  if(suffix)location.searchParams.set('per_page','100');
  need(typeof env.GITHUB_TOKEN==='string'&&env.GITHUB_TOKEN.length>0&&env.GITHUB_TOKEN.length<=65536,'ControlCompositionGithubToken');
  const result=await call(id,'github',suffix?'GetJobs':'GetRun',{path:location.pathname,query:Object.fromEntries(location.searchParams)},async()=>{
   await exchange(new HttpRequest({protocol:'https:',hostname:location.hostname,path:location.pathname,query:Object.fromEntries(location.searchParams),method:'GET',
    headers:{authorization:'Bearer '+env.GITHUB_TOKEN,accept:'application/vnd.github+json','user-agent':'mem9-control-composition','x-github-api-version':'2022-11-28'}}));
   return parseAcquisitionJson(current.raw,suffix?4194304:1048576);
  },{url:location,method:'GET'});
  need(!result.headers?.link||!String(result.headers.link).includes('rel="next"'),'ControlCompositionCapturePagination');return result;
 }
 async function close(){
  if(closed)return;closed=true;abort();signal?.removeEventListener('abort',abort);
  let problem;try{sts?.destroy();for(const c of extraClients)c.destroy();http.destroy();agent?.destroy();}catch(error){problem=error;}
  let timeout;const drained=await Promise.race([Promise.allSettled([...pending]).then(async()=>{await Promise.all([...bodies,...decodedBodies].filter(b=>!b.closed).map(b=>new Promise(resolve=>b.once('close',resolve))));return true;}),
   new Promise(resolve=>{timeout=setTimeout(()=>resolve(false),1000);})]);clearTimeout(timeout);
  for(const b of buffers)b.fill(0);buffers.clear();
  for(const o of secretObjects)for(const k of ['AccessKeyId','SecretAccessKey','SessionToken','WebIdentityToken','value'])if(Object.hasOwn(o,k))o[k]='';
  if(credentials){credentials.accessKeyId='';credentials.secretAccessKey='';credentials.sessionToken='';credentials.expiration.setTime(0);}
  if(!drained||problem)throw Object.assign(Error('ControlCompositionTransportCleanup'),{code:'ECLEANUP'});
 }
 try{
  const token=await call(slotId('oidc'),'github','OidcToken',{origin:url.origin,path:url.pathname},async()=>{await exchange(new HttpRequest({protocol:'https:',hostname:url.hostname,path:url.pathname,
   query:Object.fromEntries(url.searchParams),method:'GET',headers:{authorization:'bearer '+env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}}));return parseAcquisitionJson(current.raw,65536);},{url,method:'GET'});
  need(typeof token.result.value==='string'&&token.result.value.length<=65536&&/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token.result.value),'ControlCompositionOidcToken');
  sts=new STSClient(sdk);const name=(sourceMode?'control-source-':'control-compose-')+admitted.binding.source.runId+'-'+admitted.binding.source.runAttempt+'-'+randomBytes(6).toString('hex');
  secretObjects.add(token.result);const input={RoleArn:q.roleArn,RoleSessionName:name,WebIdentityToken:token.result.value,Policy:policy,DurationSeconds:900};secretObjects.add(input);
  const assumed=(await call(slotId('assume'),'sts','AssumeRoleWithWebIdentity',{roleArn:q.roleArn,sessionName:name,policyHash:sha(policy)},()=>sts.send(new AssumeRoleWithWebIdentityCommand(input)))).result;
  input.WebIdentityToken='';token.result.value='';
  const c=assumed.Credentials,expectedArn='arn:aws:sts::'+q.account+':assumed-role/github-actions-mem9-on-aws-prod/'+name;if(c)secretObjects.add(c);
  need(c&&['AccessKeyId','SecretAccessKey','SessionToken'].every(k=>typeof c[k]==='string'&&c[k].length>0&&c[k].length<=65536)&&c.Expiration instanceof Date&&
   assumed.AssumedRoleUser?.Arn===expectedArn&&assumed.AssumedRoleUser.AssumedRoleId.endsWith(':'+name),'ControlCompositionSessionIdentity');
  credentialDeadline=Math.min(admitted.deadlineMs,c.Expiration.getTime());need(credentialDeadline>Date.now()+30000,'ControlCompositionCredentialExpiry');
  credentials={accessKeyId:c.AccessKeyId,secretAccessKey:c.SecretAccessKey,sessionToken:c.SessionToken,expiration:c.Expiration};
  credentialHash=hash({accessKeyId:credentials.accessKeyId,secretAccessKey:credentials.secretAccessKey,sessionToken:credentials.sessionToken,expiration:credentials.expiration.toISOString()});
  const identity=(await call(slotId('identity'),'sts','GetCallerIdentity',{},()=>sts.send(new GetCallerIdentityCommand({})))).result;
  need(identity.Account===q.account&&identity.Arn===expectedArn&&identity.UserId===assumed.AssumedRoleUser.AssumedRoleId,'ControlCompositionSessionIdentity');
  for(const k of ['AccessKeyId','SecretAccessKey','SessionToken'])c[k]='';
  const guard=fn=>async(...args)=>{try{return await fn(...args);}catch(error){held=true;holdProductionControlComposition(allocation,error.message);abort();throw error;}};
  if(sourceMode){
   const ssm=new SSMClient({...sdk,region:q.region,endpoint:'https://ssm.'+q.region+'.amazonaws.com'});
   const s3=new S3Client({...sdk,region:q.region,endpoint:'https://s3.'+q.region+'.amazonaws.com',forcePathStyle:true,followRegionRedirects:false,
    useArnRegion:false,useAccelerateEndpoint:false,disableMultiregionAccessPoints:true,requestChecksumCalculation:'WHEN_REQUIRED',responseChecksumValidation:'WHEN_REQUIRED'});
   extraClients.push(ssm,s3);
   const root=admitted.config.ownerRoot,prefix='data-authorizations/'+root.runtimeNonce+'/'+root.authorizationId+'/',source=admitted.binding.source;
   const clients=Object.freeze({
    sts:Object.freeze({send:guard(async command=>{
     need(command instanceof GetCallerIdentityCommand&&Object.keys(command.input).length===0,'ControlCompositionProtectedIdentity');
     const result=(await call('guard-identity','sts','GetCallerIdentity',{},()=>sts.send(new GetCallerIdentityCommand({})))).result;
     need(result.Account===q.account&&result.Arn===expectedArn&&result.UserId===assumed.AssumedRoleUser.AssumedRoleId,'ControlCompositionSessionIdentity');return result;
    })}),
    ssm:Object.freeze({send:guard(async command=>{
     const wanted={Names:[PRODUCTION_DATA_RELEASE_PARAMETER],WithDecryption:true};
     need(command instanceof GetParametersCommand&&hash(command.input)===hash(wanted),'ControlCompositionProtectedParameter');
     const result=(await call('guard-parameter','ssm','GetParameters',wanted,()=>ssm.send(new GetParametersCommand(wanted)))).result;
     const values=result.Parameters;need(Array.isArray(values)&&values.length===1&&(!result.InvalidParameters||result.InvalidParameters.length===0),'ControlCompositionProtectedParameter');
     const p=values[0];need(p.Name===PRODUCTION_DATA_RELEASE_PARAMETER&&p.Type==='SecureString'&&p.Version===admitted.config.target.parameterVersion&&
      p.ARN==='arn:aws:ssm:'+q.region+':'+q.account+':parameter'+PRODUCTION_DATA_RELEASE_PARAMETER&&typeof p.Value==='string'&&
      hash(parseAcquisitionJson(Buffer.from(p.Value),65536))===hash(admitted.config.target.descriptor),'ControlCompositionProtectedParameter');return result;
    })}),
    s3:Object.freeze({send:guard(async command=>{
     const key=command.input?.Key,which=key===prefix+'operation.json'?'operation':key===prefix+'nonroot-proof-archive.json'?'archive':null;
     const wanted={Bucket:q.bucket,Key:key,ExpectedBucketOwner:q.account};need(which&&command instanceof GetObjectCommand&&hash(command.input)===hash(wanted),'ControlCompositionProtectedArchive');
     const location=new URL('https://s3.'+q.region+'.amazonaws.com/'+q.bucket+'/'+key);location.searchParams.set('x-id','GetObject');
     const result=(await call('guard-'+which,'s3','GetObject',wanted,()=>s3.send(new GetObjectCommand(wanted)),{url:location,key,method:'GET'})).result;
     need(result.ServerSideEncryption==='aws:kms'&&result.SSEKMSKeyId===q.kmsKeyArn&&result.BucketKeyEnabled===true,'ControlCompositionObjectEncryption');return result;
    })}),
   });
   const api=Object.freeze({clients,github:guard(async path=>{
    const selected=path==='commits/main'?['guard-main','GetCommit']:path==='commits/'+source.mainRevision?['guard-commit','GetCommit']:
     path==='pulls/'+source.prNumber?['guard-pr','GetPullRequest']:path==='actions/runs/'+source.runId+'/attempts/'+source.runAttempt?['guard-run','GetRun']:null;
    need(selected&&typeof env.GITHUB_TOKEN==='string'&&env.GITHUB_TOKEN.length>0,'ControlCompositionProtectedGithub');
    const location=new URL('https://api.github.com/repos/'+source.repository+'/'+path);
    return (await call(selected[0],'github',selected[1],{path},async()=>{
     await exchange(new HttpRequest({protocol:'https:',hostname:location.hostname,path:location.pathname,method:'GET',headers:{authorization:'Bearer '+env.GITHUB_TOKEN,
      accept:'application/vnd.github+json','user-agent':'mem9-control-composition','x-github-api-version':'2022-11-28'}}));return parseAcquisitionJson(current.raw,8388608);
    },{url:location,method:'GET'})).result;
   }),close});
   sessions.set(api,{allocation,check,locations:q,purpose});return api;
  }
  const pub=()=>{check();need(publication,'ControlCompositionPublicationRequired');inspectProductionControlCompositionOutput(publication.output);return publication;};
  const api=Object.freeze({
   bindOutput(output){
    check();need(!publication,'ControlCompositionPublicationRepeated');const value=inspectProductionControlCompositionOutput(output);
    need(value.record.allocationId===admitted.id&&value.record.planHash===admitted.plan.planHash,'ControlCompositionPublicationBinding');
    publication={output,record:value.record,nodes:new Map(value.graph.inventory.nodes.map(d=>[d.digest,d])),phase:'availability',available:new Set(),uploaded:new Set(),published:new Set(),readbacks:new Set(),missing:[],active:null};
   },
   async availability(digests){
    const p=pub();need(p.phase==='availability','ControlCompositionPublicationOrder');
    const blobs=[...p.nodes.values()].filter(d=>!d.mediaType.includes('manifest')&&!d.mediaType.includes('image.index')).map(d=>d.digest).sort();
    need(hash(digests)===hash(blobs),'ControlCompositionAvailabilityScope');
    const r=await ecr('availability','BatchCheckLayerAvailability',{registryId:q.account,repositoryName:'mem9-on-aws/bootstrap',layerDigests:digests});
    need(Array.isArray(r.layers)&&r.layers.length===blobs.length&&Array.isArray(r.failures)&&r.failures.length===0,'ControlCompositionAvailability');
    const seen=new Set();for(const row of r.layers){
     need(blobs.includes(row.layerDigest)&&!seen.has(row.layerDigest)&&['AVAILABLE','UNAVAILABLE'].includes(row.layerAvailability),'ControlCompositionAvailability');seen.add(row.layerDigest);
     if(row.layerAvailability==='AVAILABLE'){need(row.layerSize===p.nodes.get(row.layerDigest).size,'ControlCompositionAvailabilitySize');p.available.add(row.layerDigest);}
     else p.missing.push(p.nodes.get(row.layerDigest));
    }
    p.missing.sort((a,b)=>a.digest.localeCompare(b.digest));p.phase=p.missing.length?'upload':'manifests';return r;
   },
   async initiate(){
    const p=pub();need(p.phase==='upload'&&!p.active&&p.missing.length,'ControlCompositionPublicationOrder');
    const r=await ecr('initiate','InitiateLayerUpload',{registryId:q.account,repositoryName:'mem9-on-aws/bootstrap'});
    need(r.registryId===q.account&&r.repositoryName==='mem9-on-aws/bootstrap'&&/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(r.uploadId)&&
     Number.isSafeInteger(r.partSize)&&r.partSize>=L.partBytes,'ControlCompositionUploadIdentity');
    p.active={id:r.uploadId,descriptor:p.missing[0],offset:0,digest:createHash('sha256')};return r;
   },
   async part(uploadId,offset,bytes){
    const p=pub(),u=p.active;need(p.phase==='upload'&&u&&u.id===uploadId&&u.offset===offset&&bytes instanceof Uint8Array&&
     bytes.length===Math.min(L.partBytes,u.descriptor.size-offset)&&bytes.length>0,'ControlCompositionPart');
    const input={registryId:q.account,repositoryName:'mem9-on-aws/bootstrap',uploadId,partFirstByte:offset,partLastByte:offset+bytes.length-1};
    let sent;const r=await ecr('part','UploadLayerPart',input,()=>{sent=Buffer.from(bytes);return {...input,layerPartBlob:sent.toString('base64')};});
    need(r.registryId===q.account&&r.repositoryName==='mem9-on-aws/bootstrap'&&r.uploadId===uploadId&&r.lastByteReceived===offset+bytes.length-1,'ControlCompositionPartResponse');
    u.digest.update(sent);u.offset+=sent.length;return r;
   },
   async complete(uploadId,digest){
    const p=pub(),u=p.active;need(p.phase==='upload'&&u&&u.id===uploadId&&u.descriptor.digest===digest&&u.offset===u.descriptor.size&&
     'sha256:'+u.digest.digest('hex')===digest,'ControlCompositionCompleteDigest');
    const r=await ecr('complete','CompleteLayerUpload',{registryId:q.account,repositoryName:'mem9-on-aws/bootstrap',uploadId,layerDigests:[digest]});
    need(r.registryId===q.account&&r.repositoryName==='mem9-on-aws/bootstrap'&&r.uploadId===uploadId&&r.layerDigest===digest,'ControlCompositionCompleteResponse');
    p.uploaded.add(digest);p.missing.shift();p.active=null;if(!p.missing.length)p.phase='manifests';return r;
   },
   async putManifest(descriptor,bytes,{root=false}={}){need(bytes instanceof Uint8Array&&bytes.length===descriptor.size&&'sha256:'+sha(bytes)===descriptor.digest,'ControlCompositionManifestBytes');
    const p=pub();need(p.phase==='manifests'&&hash(p.nodes.get(descriptor.digest))===hash(descriptor)&&!p.published.has(descriptor.digest)&&
     root===(descriptor.digest===p.record.image.rootDigest),'ControlCompositionManifestScope');
    const doc=parseAcquisitionJson(bytes,L.manifestBytes),children=doc.manifests??[doc.config,...doc.layers,...(doc.subject?[doc.subject]:[])];
    for(const d of children)need(d&&(d.mediaType.includes('manifest')||d.mediaType.includes('image.index')?p.published.has(d.digest):p.available.has(d.digest)||p.uploaded.has(d.digest)),'ControlCompositionManifestOrder');
    const r=await ecr('manifest-put','PutImage',{registryId:q.account,repositoryName:'mem9-on-aws/bootstrap',imageDigest:descriptor.digest,imageManifest:Buffer.from(bytes).toString('utf8'),imageManifestMediaType:descriptor.mediaType,
     ...(root?{imageTag:'mem9-'+admitted.binding.source.mainRevision.slice(0,7)}:{})});
    need(r.image?.registryId===q.account&&r.image.repositoryName==='mem9-on-aws/bootstrap'&&r.image.imageId?.imageDigest===descriptor.digest,'ControlCompositionPutImageResponse');
    p.published.add(descriptor.digest);if(p.published.size===3)p.phase='readback';return r;},
   async manifest(descriptor,{base=false}={}){const repositoryName=base?admitted.plan.input.base.image.repositoryName:'mem9-on-aws/bootstrap';
    const p=base?null:pub();
    need(base?admitted.plan.input.base.inventory.nodes.some(d=>hash(d)===hash(descriptor)):p.phase==='readback'&&p.published.has(descriptor.digest)&&!p.readbacks.has(descriptor.digest),'ControlCompositionManifestScope');
    const result=await ecr(base?'base-manifest':'manifest-readback','BatchGetImage',{registryId:q.account,repositoryName,imageIds:[{imageDigest:descriptor.digest}]});
    need(Array.isArray(result.images)&&result.images.length===1&&Array.isArray(result.failures)&&result.failures.length===0,'ControlCompositionManifestResponse');
    const image=result.images[0];need(image.registryId===q.account&&image.repositoryName===repositoryName&&image.imageId?.imageDigest===descriptor.digest&&
     image.imageManifestMediaType===descriptor.mediaType&&typeof image.imageManifest==='string','ControlCompositionManifestResponse');
    const raw=Buffer.from(image.imageManifest);need(raw.length===descriptor.size&&'sha256:'+sha(raw)===descriptor.digest,'ControlCompositionManifestDigest');
    if(p){p.readbacks.add(descriptor.digest);if(p.readbacks.size===3)p.phase='capture';}return raw;},
   async baseBlob(descriptor,consume){const nodes=admitted.plan.input.base.inventory.nodes.filter(d=>!d.mediaType.includes('manifest')&&!d.mediaType.includes('image.index'));
    const index=nodes.findIndex(d=>hash(d)===hash(descriptor));need(index>=0,'ControlCompositionBaseDescriptor');
    const result=await ecr('base-url','GetDownloadUrlForLayer',{registryId:q.account,repositoryName:admitted.plan.input.base.image.repositoryName,layerDigest:descriptor.digest});
    need(result.layerDigest===descriptor.digest,'ControlCompositionBaseUrl');const location=blobUrl(result.downloadUrl,q.region),digest=createHash('sha256');let n=0;
    await call('base-blob-'+index,'s3','S3BlobGet',{digest:descriptor.digest},()=>exchange(new HttpRequest({protocol:'https:',hostname:location.hostname,path:location.pathname,query:Object.fromEntries(location.searchParams),method:'GET',headers:{}})),
     {url:location,method:'GET',consume:async b=>{n+=b.length;need(n<=descriptor.size,'ControlCompositionBaseSize');digest.update(b);await consume(b);}});
    need(n===descriptor.size&&'sha256:'+digest.digest('hex')===descriptor.digest,'ControlCompositionBaseDigest');},
   ...(admitted.plan.version===1?{getTools:consume=>getPack('tools',consume)}:{}),getSource:consume=>getPack('source',consume),
   async capture(...args){
    need(args.length===0,'ControlCompositionCaptureArguments');const p=pub();need(p.phase==='capture','ControlCompositionPublicationOrder');
    const run=await githubCapture('capture-run',''),jobs=await githubCapture('capture-jobs','/jobs');
    need(Array.isArray(jobs.result.jobs)&&jobs.result.total_count===jobs.result.jobs.length&&jobs.result.jobs.length<=100,'ControlCompositionCaptureJobs');
    const selected=jobs.result.jobs.filter(j=>j.name==='Build image transition control');need(selected.length===1,'ControlCompositionCaptureJob');
    const key=q.capture;let bytes,digest,capture;
    const written=await call('capture-put','s3','PutObject',{bucket:q.bucket,key,planHash:admitted.plan.planHash,outputRoot:p.record.image.rootDigest},async()=>{
     // Admission precedes all capture serialization. There is no caller-supplied body.
     capture=captureProductionControlComposition(p.output,{run:run.result,job:selected[0]});
     const observed=r=>({sha256:sha(r.raw),bytesLength:r.bytes,bytesBase64:r.raw.toString('base64')});
     const sourceBytes=encodeCompositionJson(admitted.source,65536);
     const source={ref:{bytesHash:sha(sourceBytes),bytesLength:sourceBytes.length,canonicalHash:hash(admitted.source)},bytesBase64:sourceBytes.toString('base64')};
     need(hash(source.ref)===hash(capture.actualMain.authenticatedSource),'ControlCompositionOriginalSource');
     const envelope={version:admitted.plan.version,kind:'native-control-composition-envelope',plan:admitted.plan,source,capture,statement:p.record.statement,
      inventory:inspectProductionControlCompositionOutput(p.output).graph.inventory,observations:{run:observed(run),jobs:observed(jobs)},
      ...(admitted.plan.version===2?{runtimeObservation:productionControlCompositionRuntimeCapture(allocation)}:{})};
     bytes=encodeCompositionJson(envelope);digest=sha(bytes);current.bodyHash=digest;
     return exchange(await sign('s3',{protocol:'https:',hostname:'s3.'+q.region+'.amazonaws.com',method:'PUT',path:'/'+q.bucket+'/'+key,
      headers:{host:'s3.'+q.region+'.amazonaws.com','content-type':'application/json','content-length':String(bytes.length),'x-amz-expected-bucket-owner':q.account,'if-none-match':'*',
       'x-amz-checksum-sha256':Buffer.from(digest,'hex').toString('base64'),'x-amz-server-side-encryption':'aws:kms',
       'x-amz-server-side-encryption-aws-kms-key-id':q.kmsKeyArn,'x-amz-server-side-encryption-bucket-key-enabled':'true'},body:bytes}));
    },{key,method:'PUT'});
    inspectObjectHeaders(written.headers,digest);p.phase='capture-readback';
    const readback=await objectGet('capture');inspectObjectHeaders(readback.headers,digest);
    need(readback.bytes===bytes.length&&sha(readback.raw)===digest&&readback.raw.equals(bytes),'ControlCompositionCaptureReadback');
    p.phase='captured';const ref=Object.freeze({sha256:digest,bytesLength:bytes.length});
    recordProductionControlComposition(allocation,'captured',{ref,key,jobId:capture.enclosing.jobId,rootDescriptor:p.record.rootDescriptor});
    return Object.freeze({version:admitted.plan.version,kind:'native-control-composition-capture-publication',authority:false,ref,key,capture});
   },
   close,
  });
  const guarded=Object.freeze(Object.fromEntries(Object.entries(api).map(([key,fn])=>[key,key==='close'?fn:async(...args)=>{
   try{return await fn(...args);}catch(error){held=true;holdProductionControlComposition(allocation,error.message);abort();throw error;}
  }])));
  sessions.set(guarded,{allocation,check,locations:q,purpose});return guarded;
 }catch(error){held=true;holdProductionControlComposition(allocation,error.message);try{await close();}catch(cleanup){throw Object.assign(cleanup,{cause:error,cleanupComplete:false});}
  if(Object.isExtensible(error)){error.cleanupComplete=true;throw error;}
  throw Object.assign(new Error(error.message,{cause:error}),{name:error.name,cleanupComplete:true});
 }
}
export function requireProductionControlCompositionTransport(handle,allocation){
 const s=sessions.get(handle);need(s&&s.allocation===allocation&&s.purpose==='composition','ControlCompositionNativeTransport');s.check();return s.locations;
}
