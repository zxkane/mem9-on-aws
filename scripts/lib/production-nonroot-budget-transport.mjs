/** All network reads consume the caller's prepaid acquisition. This module
 * measures original HTTP bodies; SDK objects and CLI stdout are not wire
 * measurements. It neither creates counters nor finishes the caller's slot. */
import {createHash} from 'node:crypto';
import {Readable} from 'node:stream';
import {SSMClient,GetParameterCommand,GetParametersCommand} from '@aws-sdk/client-ssm';
import {S3Client,GetObjectCommand} from '@aws-sdk/client-s3';
import {STSClient,GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {ECSClient,DescribeTaskDefinitionCommand,DescribeTasksCommand,DescribeServicesCommand,ListTasksCommand} from '@aws-sdk/client-ecs';
import {IAMClient,GetRoleCommand,ListRolePoliciesCommand,ListAttachedRolePoliciesCommand,GetRolePolicyCommand} from '@aws-sdk/client-iam';
import {NodeHttpHandler} from '@smithy/node-http-handler';
import {SignatureV4} from '@smithy/signature-v4';
import {Hash} from '@smithy/hash-node';
import {HttpRequest} from '@smithy/protocol-http';
import {parseImageTransitionJson} from './production-image-transition-proof.mjs';
import {verifyCanaryFixtureImageIndex} from './production-canary-material.mjs';

const need=(ok,code)=>{if(!ok)throw Error(code);};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const integer=n=>Number.isSafeInteger(n)&&n>=0;
const spec={ssm:[SSMClient,[GetParameterCommand,GetParametersCommand]],s3:[S3Client,[GetObjectCommand]],
 sts:[STSClient,[GetCallerIdentityCommand]],ecs:[ECSClient,[DescribeTaskDefinitionCommand,DescribeTasksCommand,DescribeServicesCommand,ListTasksCommand]],
 iam:[IAMClient,[GetRoleCommand,ListRolePoliciesCommand,ListAttachedRolePoliciesCommand,GetRolePolicyCommand]]};
const nativeActions={ecr:new Set(['BatchGetImage','DescribeImageScanFindings','GetDownloadUrlForLayer','BatchCheckLayerAvailability','DescribeRepositories','GetLifecyclePolicy']),kms:new Set(['DescribeKey'])};
const bytesOf=value=>{if(value===undefined)return Buffer.alloc(0);need(typeof value==='string'||value instanceof Uint8Array,'NonrootRequestBody');return typeof value==='string'?Buffer.from(value):Buffer.from(value.buffer,value.byteOffset,value.byteLength);};
const repository=name=>/^mem9-on-aws\/(?:preview\/)?(?:bootstrap|llm-proxy|mnemo-server|qwen3-embed)$/.test(name??'');
const digest=value=>typeof value==='string'&&/^sha256:[a-f0-9]{64}$/.test(value);
const downloadKey=q=>JSON.stringify([q.registryId,q.repositoryName,q.layerDigest]);
function downloadUrl(raw,region){
 need(typeof raw==='string'&&raw.length<=32768,'NonrootBlobUrl');let url;try{url=new URL(raw);}catch{throw Error('NonrootBlobUrl');}
 const hosts=[`prod-${region}-starport-layer-bucket.s3.${region}.amazonaws.com`,`prod-${region}-starport-layer-bucket.s3-${region}.amazonaws.com`];
 need(url.protocol==='https:'&&hosts.includes(url.hostname)&&!url.username&&!url.password&&!url.port&&!url.hash,'NonrootBlobUrl');
 const q=url.searchParams,keys=[...q.keys()],date=q.get('X-Amz-Date'),expires=q.get('X-Amz-Expires'),credential=q.get('X-Amz-Credential');
 need(new Set(keys).size===keys.length&&q.get('X-Amz-Algorithm')==='AWS4-HMAC-SHA256'&&/^\d{8}T\d{6}Z$/.test(date??'')&&/^[1-9]\d*$/.test(expires??'')&&Number(expires)<=604800&&q.get('X-Amz-SignedHeaders')==='host'&&/^[a-f0-9]{64}$/.test(q.get('X-Amz-Signature')??'')&&typeof credential==='string'&&credential.endsWith('/'+date.slice(0,8)+'/'+region+'/s3/aws4_request'),'NonrootBlobUrl');
 const issued=Date.parse(date.slice(0,4)+'-'+date.slice(4,6)+'-'+date.slice(6,8)+'T'+date.slice(9,11)+':'+date.slice(11,13)+':'+date.slice(13,15)+'Z');
 need(Number.isSafeInteger(issued)&&issued<=Date.now()+30000&&Date.now()<issued+Number(expires)*1000,'NonrootBlobUrlExpired');return url;
}
async function closeBody(body){
 if(!body)return;if(!(body instanceof Readable))throw Object.assign(Error('ECLEANUP'),{code:'ECLEANUP'});body.destroy();if(body.closed)return;
 await new Promise((resolve,reject)=>{const done=()=>{clearTimeout(timer);resolve();},timer=setTimeout(()=>{body.off('close',done);reject(Object.assign(Error('ECLEANUP'),{code:'ECLEANUP'}));},1000);body.once('close',done);if(body.closed)done();});
}

function rawByteBody(body){
 need(body instanceof Readable&&body.readableObjectMode===false&&body.readableEncoding===null,'NonrootRawByteBody');
 return body;
}
/** Read the provider's raw byte stream directly. Adapting an object stream
 * would first consume its entire upstream chunk, outside this byte bound. */
async function* boundedRawBody(stream,cap){
 rawByteBody(stream);
 let count=0;
  while(count<=cap){
   rawByteBody(stream);
   const chunk=stream.read(Math.min(65536,cap-count+1));
   if(chunk!==null){need(chunk instanceof Uint8Array,'NonrootResponseBody');count+=chunk.length;yield chunk;continue;}
   if(stream.readableEnded)return;
   if(stream.destroyed)throw stream.errored??Error('NonrootResponseClosed');
   await new Promise((resolve,reject)=>{
    const clear=()=>{stream.off('readable',ready);stream.off('end',ready);stream.off('close',closed);stream.off('error',failed);};
    const ready=()=>{clear();resolve();},failed=e=>{clear();reject(e);},closed=()=>{clear();stream.readableEnded?resolve():reject(Error('NonrootResponseClosed'));};
    stream.once('readable',ready);stream.once('end',ready);stream.once('close',closed);stream.once('error',failed);
   });
  }
}

export function assertNonrootMetadataReads(value){
 need(value&&['beforeRead','reserveLocal','finish'].every(key=>typeof value[key]==='function'),'NonrootAcquisitionRequired');
 return value;
}

export function createNonrootBudgetedReads({region,env,metadataReads,requestHandler}){
 const acquisition=assertNonrootMetadataReads(metadataReads);
 need(/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(region??''),'NonrootTransportRegion');
 need(env&&['AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN'].every(key=>typeof env[key]==='string'&&env[key].length>0),'NonrootTransportTemporaryCredentials');
 const credentials={accessKeyId:env.AWS_ACCESS_KEY_ID,secretAccessKey:env.AWS_SECRET_ACCESS_KEY,sessionToken:env.AWS_SESSION_TOKEN};
 const transport=requestHandler??new NodeHttpHandler({connectionTimeout:5000,requestTimeout:30000});
 need(typeof transport.handle==='function'&&typeof transport.destroy==='function','NonrootTransportHandler');
 const host=service=>service==='iam'?'iam.amazonaws.com':`${service==='ecr'?'api.ecr':service}.${region}.amazonaws.com`;
 let current,held=false,closed=false;
 const check=()=>need(!held&&!closed,'NonrootAcquisitionHeld');
 const sdk=new Map(),clients={},downloads=new Map();

 async function http(service,request,options={}){
  check();const slot=current;need(slot?.service===service&&!slot.dispatched,'NonrootUnallocatedTransport');
  need(request.protocol==='https:'&&request.hostname===host(service)&&!request.port&&['POST','GET'].includes(request.method),'NonrootTransportEndpoint');
  const body=bytesOf(request.body),caps=slot.reservation.caps;
  need(body.length<=caps.requestBytes,'NonrootRequestBodyLimit');
  slot.reservation.finalGuard();slot.dispatched=true;slot.reservation.charge(body.length);
  const pending=transport.handle(request,options); // no await between guard and dispatch
  const response=(await pending).response;
  need(response&&integer(response.statusCode),'NonrootTransportResponse');
  const stream=response.body;
  need(stream instanceof Uint8Array||stream&&typeof stream[Symbol.asyncIterator]==='function','NonrootResponseBody');
  const chunks=[];let size=0;
  const abort=()=>stream.destroy?.(Error('NonrootTransportAborted'));
  options.abortSignal?.addEventListener('abort',abort,{once:true});
  try{
   options.abortSignal?.throwIfAborted();
   for await(const chunk of acquisition.controlCapacity?boundedRawBody(stream,caps.responseBytes):stream instanceof Uint8Array?[stream]:stream){
    options.abortSignal?.throwIfAborted();need(chunk instanceof Uint8Array,'NonrootResponseBody');
    slot.reservation.charge(chunk.byteLength);size+=chunk.byteLength;
    need(size<=caps.responseBytes&&size<=32*1024*1024,'NonrootResponseBodyLimit');chunks.push(Buffer.from(chunk));
   }
   const length=response.headers?.['content-length'];
   if(length!==undefined)need(/^(?:0|[1-9][0-9]*)$/.test(String(length))&&Number(length)===size,'NonrootResponseBodyLength');
   const raw=Buffer.concat(chunks,size);slot.responseHash=sha(raw);slot.body=raw;
   return {response:{...response,body:Readable.from([raw])}};
  }finally{options.abortSignal?.removeEventListener('abort',abort);if(acquisition.controlCapacity&&stream instanceof Readable)await closeBody(stream);else stream.destroy?.();}
 }
 async function read(service,action,input,use){
  check();need(!current,'NonrootConcurrentAcquisition');
  // Snapshot before the durable reservation so an awaiting caller cannot
  // change the request subsequently sent by the SDK or native signer.
  const request=structuredClone(input);const slot={service,dispatched:false};current=slot;let result;
  try{
   slot.reservation=await acquisition.beforeRead(action,request);
   const r=slot.reservation;
   need(r&&['finalGuard','charge','complete','unknown'].every(key=>typeof r[key]==='function')&&integer(r.caps?.requestBytes)&&integer(r.caps?.responseBytes)&&r.caps.responseBytes>0,'NonrootReadReservation');
   result=await use(request);
   need(slot.dispatched&&slot.responseHash,'NonrootTransportIncomplete');
   // The bridge checks the actual caller/descriptor response. Streaming S3
   // bodies are retained for the caller; their original bytes are committed
   // by responseHash, never serialized as Node stream internals.
   const response=service==='s3'?Object.fromEntries(Object.entries(result).filter(([key])=>key!=='Body')):result;
   await r.complete(response,slot.responseHash);return result;
  }catch(error){
   if(result?.Body instanceof Readable)result.Body.destroy();
   held=true;if(slot.reservation)await slot.reservation.unknown();
   if(error.code==='ECLEANUP')throw error;
   if(!slot.dispatched)throw error;
   throw Error('NonrootBudgetReadFailed');
  }finally{current=undefined;}
 }
 for(const [service,[Client,commands]]of Object.entries(spec)){
  const client=new Client({region:service==='iam'?'us-east-1':region,endpoint:'https://'+host(service),credentials,maxAttempts:1,
   ignoreConfiguredEndpointUrls:true,followRegionRedirects:false,forcePathStyle:true,
   requestChecksumCalculation:'WHEN_REQUIRED',responseChecksumValidation:'WHEN_REQUIRED',
   requestHandler:{handle:(request,options)=>http(service,request,options),destroy(){}}});
  sdk.set(service,client);
  clients[service]=Object.freeze({send(command,options={}){
   const Command=commands.find(C=>command instanceof C);need(Command,'NonrootReadOnlyCommand');
   return read(service,Command.name.replace(/Command$/,''),command.input,input=>client.send(new Command(input),{...options,abortSignal:options.abortSignal?AbortSignal.any([options.abortSignal,AbortSignal.timeout(30000)]):AbortSignal.timeout(30000)}));
  }});
 }
 async function readJson(service,action,input){
  need(nativeActions[service]?.has(action),'NonrootReadOnlyCommand');
  const layer=service==='ecr'&&action==='GetDownloadUrlForLayer';
  if(layer)need(Object.keys(input).sort().join()==='layerDigest,registryId,repositoryName'&&/^\d{12}$/.test(input.registryId)&&repository(input.repositoryName)&&digest(input.layerDigest),'NonrootBlobScope');
  // Retain the request independently of mutable caller/SDK response objects.
  const requested=structuredClone(input);let location;
  const result=await read(service,action,requested,async request=>{
   const signer=new SignatureV4({credentials,region,service,sha256:Hash.bind(null,'sha256')}),body=JSON.stringify(request);
   const target=(service==='ecr'?'AmazonEC2ContainerRegistry_V20150921':'TrentService')+'.'+action;
   const signed=await signer.sign(new HttpRequest({protocol:'https:',hostname:host(service),method:'POST',path:'/',headers:{host:host(service),'content-type':'application/x-amz-json-1.1','x-amz-target':target,'content-length':String(Buffer.byteLength(body))},body}));
   const {response}=await http(service,signed,{abortSignal:AbortSignal.timeout(30000)});
   response.body.destroy();need(response.statusCode===200,'NonrootNativeReadStatus');
   need(current.body.length<=8*1024*1024,'NonrootNativeResponseLimit');
   const parsed=parseImageTransitionJson(new TextDecoder('utf-8',{fatal:true}).decode(current.body));
   if(layer){need(parsed.layerDigest===request.layerDigest,'NonrootBlobDigest');location=downloadUrl(parsed.downloadUrl,region).href;}
   return parsed;
  });
  if(layer)downloads.set(downloadKey(requested),location);return result;
 }
 /** The URL is acquired through a completed ECR reservation in this process.
  * Only bytes flow to the trusted cache consumer; neither credentials nor the
  * presigned URL enter the completion record or a caller-controlled request. */
 async function readBlob(input,{account,size,consume,signal}={}){
  check();need(input&&Object.keys(input).sort().join()==='layerDigest,repositoryName'&&repository(input.repositoryName)&&digest(input.layerDigest)&&/^\d{12}$/.test(account??'')&&integer(size)&&size<=2147483648&&typeof consume==='function','NonrootBlobScope');
  const request=structuredClone(input),key=downloadKey({registryId:account,...request});
  need(downloads.has(key),'NonrootBlobUrlRequired');const location=downloads.get(key);downloads.delete(key);
  return read('s3blob','S3BlobGet',request,async wanted=>{
   const slot=current,caps=slot.reservation.caps;need(size<=caps.responseBytes,'NonrootBlobBudget');
   const controller=new AbortController(),combined=AbortSignal.any([controller.signal,...(signal?[signal]:[])]),timer=setTimeout(()=>controller.abort(),30000);
   let body,completed=false,count=0,abortListener,networkSettled=false;
   const aborted=new Promise((_,reject)=>{abortListener=()=>{body?.destroy();reject(Error('NonrootBlobAborted'));};combined.addEventListener('abort',abortListener,{once:true});if(combined.aborted)abortListener();});
   const hash=createHash('sha256');let pending;
   try{
    combined.throwIfAborted();const url=downloadUrl(location,region),query=Object.fromEntries(url.searchParams);
    const outgoing=new HttpRequest({protocol:'https:',hostname:url.hostname,method:'GET',path:url.pathname,headers:{host:url.hostname},query});
    check();slot.reservation.finalGuard();slot.dispatched=true;slot.reservation.charge(0);
    pending=transport.handle(outgoing,{abortSignal:combined}); // no await after dispatch guard
    pending.then(result=>{networkSettled=true;if(combined.aborted)result?.response?.body?.destroy?.();},()=>{networkSettled=true;});
    const response=(await Promise.race([pending,aborted])).response;body=response?.body;
    need(body instanceof Readable,'NonrootBlobBody');
    if(acquisition.controlCapacity)rawByteBody(body);
    // Never follow redirects or forward our AWS session to the layer service.
    need(response.statusCode===200&&/^(?:0|[1-9][0-9]*)$/.test(response.headers?.['content-length']??'')&&Number(response.headers['content-length'])===size&&[undefined,'identity'].includes(response.headers['content-encoding']),'NonrootBlobResponse');
    const stream=(async function*(){
     for await(const chunk of acquisition.controlCapacity?boundedRawBody(body,Math.min(size,caps.responseBytes)):body){check();combined.throwIfAborted();need(chunk instanceof Uint8Array,'NonrootBlobBody');slot.reservation.charge(chunk.byteLength);count+=chunk.byteLength;need(count<=size&&count<=caps.responseBytes,'NonrootBlobBodyLimit');hash.update(chunk);yield chunk;}
     need(count===size,'NonrootBlobBodyLength');const actual=hash.digest('hex');need(actual===wanted.layerDigest.slice(7),'NonrootBlobDigest');slot.responseHash=actual;completed=true;
    })();
    try{await Promise.race([Promise.resolve().then(()=>consume(stream)),aborted]);need(completed,'NonrootBlobIncomplete');}
    finally{await closeBody(body);}
    return {...wanted,size:count};
   }finally{
    clearTimeout(timer);controller.abort();combined.removeEventListener('abort',abortListener);await closeBody(body);
    if(pending&&!networkSettled){transport.destroy();await Promise.race([pending.catch(()=>{}),new Promise(resolve=>setTimeout(resolve,1000))]);if(!networkSettled)throw Object.assign(Error('ECLEANUP'),{code:'ECLEANUP'});}
   }
  });
 }
 async function readEcr(operation,input,{account}){
  need(/^\d{12}$/.test(account??'')&&repository(input.repositoryName)&&digest(input.imageDigest),'NonrootEcrReadScope');
  need(['batch-get-image','describe-image-scan-findings'].includes(operation),'NonrootEcrReadOperation');
  const request={registryId:account,repositoryName:input.repositoryName};
  if(operation==='batch-get-image'){need(input.nextToken===undefined,'NonrootEcrReadToken');request.imageIds=[{imageDigest:input.imageDigest}];}
  else{request.imageId={imageDigest:input.imageDigest};request.maxResults=1000;if(input.nextToken!==undefined){need(typeof input.nextToken==='string'&&input.nextToken.length>0&&input.nextToken.length<=8192,'NonrootEcrReadToken');request.nextToken=input.nextToken;}}
  return readJson('ecr',operation==='batch-get-image'?'BatchGetImage':'DescribeImageScanFindings',request);
 }
 function controlMetadata(scope){
  need(/^\d{12}$/.test(scope.account??'')&&scope.region===region,'NonrootControlReadScope');
  return Object.freeze({async artifact(route){
   const repositoryName='mem9-on-aws/preview/bootstrap',prefix=`${scope.account}.dkr.ecr.${region}.amazonaws.com/${repositoryName}@`;
   need(route.account===scope.account&&route.region===region&&typeof route.image==='string'&&route.image.startsWith(prefix),'NonrootControlReadScope');
   const rootDigest=route.image.slice(prefix.length);need(/^sha256:[a-f0-9]{64}$/.test(rootDigest),'NonrootControlReadScope');
   return verifyCanaryFixtureImageIndex(await readJson('ecr','BatchGetImage',{registryId:scope.account,repositoryName,imageIds:[{imageDigest:rootDigest}]}),{account:scope.account,repositoryName,rootDigest});
  },async key(route){
   need(route.account===scope.account&&route.region===region,'NonrootControlReadScope');
   const key=(await readJson('kms','DescribeKey',{KeyId:'alias/aws/ssm'})).KeyMetadata;
   need(key?.Arn===route.kmsKeyArn&&key.AWSAccountId===scope.account&&key.Enabled===true&&key.KeyState==='Enabled'&&key.KeyManager==='AWS','NonrootControlKeyMismatch');return key.Arn;
  }});
 }
 return Object.freeze({clients:Object.freeze(clients),readEcr,readJson,readBlob,controlMetadata,...(acquisition.controlCapacity?{controlCapacity:acquisition.controlCapacity}:{}),
  reserveLocal(charge){check();try{return acquisition.reserveLocal(charge);}catch(error){held=true;throw error;}},
  close(){if(closed)return;closed=true;downloads.clear();for(const client of sdk.values())client.destroy();transport.destroy();credentials.accessKeyId='';credentials.secretAccessKey='';credentials.sessionToken='';},
 });
}
