/** Source-only prepaid rendezvous. No ambient AWS credentials, request Put,
 * deployment authority, caller-selected key/policy, or capability restoration. */
import {Agent} from 'node:https';
import {Readable} from 'node:stream';
import {beginProductionControlCompositionSource,productionControlCompositionSourceReceipt,activateProductionControlCompositionSource,abandonProductionControlCompositionSource} from './production-control-composition-lifetime.mjs';
import {copyNonrootJson,parseNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {inspectCiSmokeCommitment,ciSmokeArchiveLocation} from './ci-smoke-private-archive.mjs';
import {makeCiStartupRunBinding,openCiSmokeStartup,consumeCiSmokeStartup} from './ci-smoke-startup.mjs';
import {captureNonrootMainSource} from './production-nonroot-source-reader.mjs';
import {createFutureSourceReader,FUTURE_HANDSHAKE_POLICY as HANDSHAKE} from './ci-smoke-grants.mjs';
import {verifyFutureAllowance} from './ci-smoke-future-allowance.mjs';
import {inspectFutureAcquisitionConfig,futureAcquisitionScope} from './ci-smoke-future-config.mjs';
export {inspectFutureAcquisitionConfig as inspectCiSmokeReaderConfig} from './ci-smoke-future-config.mjs';

const KiB=1024,MiB=1024*KiB;
const need=(ok,code='CiSourceAllowanceInvalid')=>{if(!ok)throw Error(code);};
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'CiSourceAllowanceFields');
const positive=n=>Number.isSafeInteger(n)&&n>0;
const same=(a,b,code='CiSourceAllowanceBinding')=>need(hash(a)===hash(b),code);
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
const SOURCE_ROUTES=new Set(['deploy-prod','runtime-cutover-prod','verify-production-image-transition','build-image-transition-control']);
function sourceScope(value,config){
 const s=copyNonrootJson(value);exact(s,['kind','jobKey','route','phase','checkpoint']);
 need(s.kind==='source'&&SOURCE_ROUTES.has(s.route)&&s.jobKey===s.route&&s.phase==='source'&&s.checkpoint===s.route+'/source','CiSourceAllowanceScope');
 need(config.startup.consumers.some(c=>hash(c)===hash(s)),'CiSourceAllowanceUnfundedScope');return s;
}
export function sourceAllowanceLocation(value){
 exact(value,['config','scope','roleArn']);const c=inspectFutureAcquisitionConfig(value.config),scope=sourceScope(value.scope,c),bounded=futureAcquisitionScope(c,scope);
 need(typeof value.roleArn==='string'&&new RegExp('^arn:aws:iam::'+c.account+':role/(?:[A-Za-z0-9_+=,.@-]+/)*github-actions-mem9-on-aws-prod$').test(value.roleArn),'CiSourceAllowanceRole');
 const key=bounded.responseKey,bucketArn='arn:aws:s3:::'+c.storage.bucket;
 return freeze({stage:'prod',account:c.account,region:c.region,bucket:c.storage.bucket,bucketArn,objectArn:bucketArn+'/'+key,roleArn:value.roleArn,key,expectedBucketOwner:c.account,
  encryption:{algorithm:'aws:kms',keyArn:c.storage.kmsKeyArn,bucketKeyEnabled:true}});
}
/** Shared response/debit verification plus the closed source reader profile.
 * This returns data only; it cannot reconstruct a startup capability. */
export function verifyCiSmokeSourceAllowanceResponse({response,config,binding,pending,now,deadlineMs}){
 const c=inspectFutureAcquisitionConfig(config),scope=sourceScope(pending.scope,c),requestHash=hash({nonce:pending.nonce,scopeHash:pending.scopeHash});
 const result=verifyFutureAllowance(response,{config:c,scope,startupReceipt:pending,binding,requestHash,maximumExpiresMs:deadlineMs,now});
 const bounded=futureAcquisitionScope(c,scope),reader=createFutureSourceReader({version:1,kind:'source-two-reader',terminalResponseBytes:bounded.responseBytes});
 need(result.consumer.reader,'CiSourceAllowanceReaderProfile');same(result.consumer.reader,reader,'CiSourceAllowanceReaderProfile');
 return freeze({grantSetId:result.funded.grantSetId,grantHash:result.funded.grantHash,bindingHash:pending.bindingHash,scope,nonce:pending.nonce,notAfter:result.expiresMs,requestHash,responseHash:hash(response)});
}

const cleanupError=()=>Object.assign(Error('CiSourceAllowanceCleanupHeld'),{code:'ECLEANUP'});
/** Fixed object transport: serialized request and all raw HTTP response bodies
 * are bounded before SDK parsing. It has no endpoint/key/policy config seam. */
async function objectTransport({location,deadlineMs,signal,now,check,allowance,responseBytes,transport:injected},use){
 const {NodeHttpHandler}=await import('@smithy/node-http-handler');check();
 const agent=injected?undefined:new Agent({keepAlive:false,maxSockets:1,rejectUnauthorized:true});
 const transport=injected??new NodeHttpHandler({httpsAgent:agent,connectionTimeout:5000,requestTimeout:Math.min(30000,deadlineMs-now())});
 const controller=new AbortController(),bodies=new Set(),pending=new Set(),requests=new Set();let held=false,destroyed=false,calls=0,closed=false,lastCompletedResponse;
 const close=body=>{try{if(body&&!body.destroyed)body.destroy();}catch{held=true;}};
 const scrub=()=>{for(const request of requests)try{delete request.headers.authorization;delete request.headers.Authorization;delete request.headers['x-amz-security-token'];request.body=undefined;}catch{held=true;}};
 const abort=()=>{controller.abort();for(const b of bodies)close(b);scrub();};signal.addEventListener('abort',abort,{once:true});if(signal.aborted)abort();
 const timer=setTimeout(abort,Math.max(1,deadlineMs-now()));
 const guard=()=>{check();need(!closed&&!controller.signal.aborted&&now()<deadlineMs,'CiSourceAllowanceExpired');};
 let rejectAbort;const aborted=new Promise((_,reject)=>{rejectAbort=()=>reject(Error('CiSourceAllowanceAborted'));});aborted.catch(()=>{});controller.signal.addEventListener('abort',rejectAbort,{once:true});
 const track=p=>{const q=Promise.resolve(p).finally(()=>pending.delete(q));pending.add(q);q.catch(()=>{});return q;};
 const destroy=()=>{if(!destroyed){destroyed=true;transport.destroy();}};
 const handler={completedResponse:()=>lastCompletedResponse,handle(request,options){
  guard();need(++calls<=(allowance?HANDSHAKE.maxGetAttempts:1),'CiSourceAllowanceReadCount');
  lastCompletedResponse=undefined;
  requests.add(request);
  need(request.protocol==='https:'&&request.hostname===`s3.${location.region}.amazonaws.com`&&request.method==='GET'&&request.path==='/'+location.bucket+'/'+location.key,'CiSourceAllowanceEndpoint');
  need(request.body===undefined||typeof request.body==='string'||request.body instanceof Uint8Array,'CiSourceAllowanceRequest');
  need(Buffer.byteLength(request.body??'')===0,'CiSourceAllowanceRequestCap');
  // Metadata is bounded independently of the body; no caller can smuggle a
  // second selector via query, headers, version IDs or redirects.
  need(Object.keys(request.query??{}).every(k=>k==='x-id'&&request.query[k]==='GetObject'),'CiSourceAllowanceQuery');
  need(request.headers['x-amz-expected-bucket-owner']===location.account&&Buffer.byteLength(JSON.stringify(request.headers))+request.path.length<=16*KiB,'CiSourceAllowanceHeaders');
  const operation=track((async()=>{
   let body;const chunks=[];let size=0;
   try{
    guard();const out=await transport.handle(request,{...options,abortSignal:controller.signal});body=out.response?.body;
    need(body&&typeof body[Symbol.asyncIterator]==='function'&&typeof body.destroy==='function','CiSourceAllowanceBody');bodies.add(body);guard();
    const status=out.response.statusCode,limit=status===200?responseBytes:allowance&&calls===HANDSHAKE.maxGetAttempts?Math.min(HANDSHAKE.pendingBodyBytes,responseBytes):HANDSHAKE.pendingBodyBytes;
    const declared=out.response.headers?.['content-length'];if(declared!==undefined)need(/^[0-9]+$/.test(declared)&&Number(declared)<=limit,'CiSourceAllowanceBodyCap');
    for await(const chunk of body){guard();need(chunk instanceof Uint8Array,'CiSourceAllowanceBody');size+=chunk.length;need(size<=limit,'CiSourceAllowanceBodyCap');chunks.push(Buffer.from(chunk));}
    guard();if(declared!==undefined)need(Number(declared)===size,'CiSourceAllowanceBodyLength');
    need(status===200||allowance&&HANDSHAKE.knownPendingStatuses.includes(status),'CiSourceAllowanceHttp');
    // This receipt is created by the exact-request transport after all bytes
    // were received and bounded; an SDK error name cannot create it.
    lastCompletedResponse=Object.freeze({status,bytes:size,attempt:calls});
    const output=Readable.from([Buffer.concat(chunks,size)]);bodies.add(output);return {response:{...out.response,body:output}};
   }finally{close(body);}
  })());return Promise.race([operation,aborted]);
 },destroy};
 try{guard();return await Promise.race([track(Promise.resolve().then(()=>use(handler,controller.signal))),aborted]);}
 finally{
  closed=true;clearTimeout(timer);abort();signal.removeEventListener('abort',abort);
  try{destroy();agent?.destroy();}catch{held=true;}
  let timeout;const drain=async()=>{await Promise.allSettled([...pending]);await Promise.all([...bodies].filter(b=>!b.closed).map(b=>new Promise(resolve=>b.once('close',resolve))));};
  const complete=await Promise.race([drain().then(()=>true),new Promise(resolve=>{timeout=setTimeout(()=>resolve(false),1000);})]);clearTimeout(timeout);controller.signal.removeEventListener('abort',rejectAbort);
  scrub();
  if(!complete||held)throw cleanupError();
 }
}

/** Runs in the original source action process. verifySmoke is the original
 * full decoder/verifier, not a workflow-selected module or a JSON success flag.
 * Seams substitute clocks/HTTP/GitHub artifact transport only in local tests. */
export async function withCiSmokeSourceAllowance(input,verifySmoke,seams={}){return withSourceAllowance(input,verifySmoke,seams,false);}
export async function withCiSmokeCompositionSourceAllowance(input,verifySmoke,seams={}){return withSourceAllowance(input,verifySmoke,seams,true);}
async function withSourceAllowance(input,verifySmoke,seams,composition){
 exact(input,['env','scope','host','config','commitment','jobExpiresMs',...(composition?['compositionRoot','signal']:[])]);
 need(Object.keys(seams).every(k=>['now','sleep','artifactClient','smokeSessionTransport','allowanceSessionTransport','smokeObjectTransport','allowanceObjectTransport'].includes(k)),'CiSourceAllowanceSeam');
 const {env,host}=input,now=seams.now??Date.now,sleep=seams.sleep??(ms=>new Promise(resolve=>setTimeout(resolve,ms)));
 need(typeof verifySmoke==='function'&&typeof now==='function'&&typeof sleep==='function','CiSourceAllowanceInput');
 const raw=env.MEM9_CI_ACQUISITION_CONFIG;need(typeof raw==='string'&&Buffer.byteLength(raw)<=65536,'CiSourceAllowanceConfigRequired');
 const config=inspectFutureAcquisitionConfig(parseNonrootJson(raw,{maxBytes:65536})),scope=sourceScope(input.scope,config),bounded=futureAcquisitionScope(config,scope),commitment=inspectCiSmokeCommitment(input.commitment);
 need(host?.env===env&&typeof host.run==='function'&&typeof host.api==='function'&&typeof host.checkout==='function','CiSourceAllowanceHost');
 const firstLocation=ciSmokeArchiveLocation(input.config,commitment),originalConfigHash=hash(input.config),location=sourceAllowanceLocation({config,scope,roleArn:firstLocation.roleArn});
 need(firstLocation.account===config.account&&firstLocation.region===config.region&&firstLocation.bucket===config.storage.bucket&&firstLocation.encryption.keyArn===config.storage.kmsKeyArn&&firstLocation.encryption.bucketKeyEnabled===true&&env.AWS_REGION===config.region,'CiSourceAllowanceReaderBinding');
 const sessions=await import('./ci-smoke-session.mjs'),{buildCiSmokeAllowanceReadPolicy}=sessions;
 const withCiSmokeReadSession=composition?sessions.withCiSmokeCompositionReadSession:sessions.withCiSmokeReadSession;
 const withCiSmokeAllowanceReadSession=composition?sessions.withCiSmokeCompositionAllowanceReadSession:sessions.withCiSmokeAllowanceReadSession;
 // Check the second policy's serialized size before even the first reader.
 buildCiSmokeAllowanceReadPolicy({config,scope,roleArn:firstLocation.roleArn});
 const openedMs=now(),receiptExpiresMs=Math.min(input.jobExpiresMs,config.startup.notAfter,config.target.descriptor.expiresMs),deadlineMs=Math.min(receiptExpiresMs,openedMs+840000);
 need(positive(input.jobExpiresMs)&&positive(openedMs)&&openedMs>=config.target.descriptor.issuedMs&&openedMs<deadlineMs,'CiSourceAllowanceExpired');
 const environment=()=>hash(Object.fromEntries(['GITHUB_REPOSITORY','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_JOB','GITHUB_SHA','GITHUB_WORKFLOW_SHA','GITHUB_EVENT_NAME','GITHUB_REF','AWS_REGION'].map(k=>[k,env[k]??null]))),environmentHash=environment();
 const check=()=>{const t=now();need(positive(t)&&t>=openedMs&&t<deadlineMs&&env.MEM9_CI_ACQUISITION_CONFIG===raw&&environment()===environmentHash&&hash(input.config)===originalConfigHash,'CiSourceAllowanceExpired');};check();
 const source=await captureNonrootMainSource({git:args=>host.run('git',args),api:path=>host.api(path)},env,config.startup.source);check();
 const binding=makeCiStartupRunBinding(config.startup,source),startup=await openCiSmokeStartup({env,host,config:config.startup,scope,source},{now,sleep,...(seams.artifactClient?{artifactClient:seams.artifactClient}:{})});check();
 const compositionSource=composition?beginProductionControlCompositionSource(startup,{expected:{config,scope,binding,maximumExpiresMs:receiptExpiresMs,now:now()},source,env,tempRoot:input.compositionRoot,signal:input.signal}):null;
 const pending=compositionSource?productionControlCompositionSourceReceipt(compositionSource):consumeCiSmokeStartup(startup,{bindingHash:hash(binding),scope,now:now()});check();
 let compositionActivated=false,compositionResponse;
 try{
 const sessionSeam=transport=>({now,assertCurrent:check,...(transport?{requestHandler:transport}:{})});
 const observed=await withCiSmokeReadSession({config:input.config,commitment,env,deadlineMs,...(composition?{signal:input.signal}:{})},context=>objectTransport({location:firstLocation,deadlineMs,signal:context.signal,now,check,allowance:false,responseBytes:32*MiB,transport:seams.smokeObjectTransport},(requestHandler,signal)=>verifySmoke({...context,requestHandler,signal,deadlineMs})),sessionSeam(seams.smokeSessionTransport));
 // The await above includes the original wrapper's physical drain and secret
 // erasure. Any failure exits here; the allowance session cannot overlap it.
 check();const allowanceDeadline=Math.min(deadlineMs,now()+HANDSHAKE.maxDurationMs);
 const allowance=await withCiSmokeAllowanceReadSession({config,scope,roleArn:firstLocation.roleArn,env,deadlineMs:allowanceDeadline,...(composition?{signal:input.signal}:{})},async context=>{
  return objectTransport({location,deadlineMs:allowanceDeadline,signal:context.signal,now,check,allowance:true,responseBytes:bounded.responseBytes,transport:seams.allowanceObjectTransport},async(requestHandler,signal)=>{
   const {S3Client,GetObjectCommand}=await import('@aws-sdk/client-s3');check();let client;
   try{
    client=new S3Client({region:config.region,endpoint:`https://s3.${config.region}.amazonaws.com`,forcePathStyle:true,followRegionRedirects:false,ignoreConfiguredEndpointUrls:true,maxAttempts:1,...(composition?{defaultsMode:'legacy',retryMode:'standard',useFipsEndpoint:false,useDualstackEndpoint:false,useArnRegion:false,useAccelerateEndpoint:false,disableMultiregionAccessPoints:true}:{}),credentials:context.credentials,requestChecksumCalculation:'WHEN_REQUIRED',responseChecksumValidation:'WHEN_REQUIRED',requestHandler});
    for(let attempt=0;attempt<HANDSHAKE.maxGetAttempts;attempt++){
     check();need(!signal.aborted&&now()<allowanceDeadline,'CiSourceAllowanceExpired');let response;
     try{response=await client.send(new GetObjectCommand({Bucket:location.bucket,Key:location.key,ExpectedBucketOwner:location.account}),{abortSignal:signal});}
     catch(error){
      const completed=requestHandler.completedResponse();
      need(completed&&HANDSHAKE.knownPendingStatuses.includes(completed.status)&&completed.attempt===attempt+1,'CiSourceAllowanceReadHeld');
      need(attempt<HANDSHAKE.maxKnownPendingAttempts&&now()+HANDSHAKE.minKnownPendingPollMs<allowanceDeadline,'CiSourceAllowancePending');await sleep(HANDSHAKE.minKnownPendingPollMs);continue;
     }
     need(response.$metadata?.httpStatusCode===200&&response.ServerSideEncryption==='aws:kms'&&response.SSEKMSKeyId===config.storage.kmsKeyArn&&response.BucketKeyEnabled===true&&positive(response.ContentLength)&&response.ContentLength<=bounded.responseBytes,'CiSourceAllowanceCustody');
     const chunks=[];let bytes=0;try{for await(const chunk of response.Body){check();need(now()<allowanceDeadline&&chunk instanceof Uint8Array,'CiSourceAllowanceBody');bytes+=chunk.length;need(bytes<=bounded.responseBytes,'CiSourceAllowanceBodyCap');chunks.push(Buffer.from(chunk));}}finally{response.Body?.destroy();}
     need(bytes===response.ContentLength,'CiSourceAllowanceBodyLength');const parsed=parseNonrootJson(Buffer.concat(chunks,bytes).toString('utf8'),{maxBytes:bounded.responseBytes});
     const verified=verifyCiSmokeSourceAllowanceResponse({response:parsed,config,binding,pending,now:now(),deadlineMs:receiptExpiresMs});
     if(composition)compositionResponse=parsed;return verified;
    }
    throw Error('CiSourceAllowancePending');
   }finally{client?.destroy();}
  });
 },sessionSeam(seams.allowanceSessionTransport));
 check();need(now()<allowance.notAfter,'CiSourceAllowanceExpired');
 const compositionAllocation=composition?await activateProductionControlCompositionSource(compositionSource,compositionResponse):undefined;compositionActivated=composition;
 return Object.freeze({observed,allowance,expiresMs:Math.min(receiptExpiresMs,allowance.notAfter),...(composition?{compositionAllocation}:{})});
 }finally{if(compositionSource&&!compositionActivated)try{abandonProductionControlCompositionSource(compositionSource);}catch{}}
}
