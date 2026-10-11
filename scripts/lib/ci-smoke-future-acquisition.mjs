import {createFutureControlWireMeter,isFutureControlCapacityProfile,verifyFutureControlGraphCapacity,inspectFutureControlCapacity} from './production-control-capacity.mjs';
import {normalizeImageDigestResponse,imageResponseFromSdk} from './production-image-response.mjs';
/** CFG2 funded TARGET acquisition. No funding, new clock, session issuance,
 * arbitrary endpoint, or business authority is created by these records. */
import {Agent} from 'node:https';
import {createHash} from 'node:crypto';
import {Readable} from 'node:stream';
import {mkdir,lstat,realpath,readdir} from 'node:fs/promises';
import {readFileSync,lstatSync,openSync,writeSync,fsyncSync,closeSync,constants} from 'node:fs';
import {join,resolve} from 'node:path';
import {parseDocument} from 'yaml';
import {S3Client,PutObjectCommand,GetObjectCommand} from '@aws-sdk/client-s3';
import {NodeHttpHandler} from '@smithy/node-http-handler';
import {copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {sha,need,exact,same,hex,integer,zero,counter,COUNTERS,parseAcquisitionJson} from './ci-smoke-acquisition-format.mjs';
import {inspectFutureAcquisitionConfig,futureAcquisitionScope} from './ci-smoke-future-config.mjs';
import {FUTURE_HANDSHAKE_POLICY as HANDSHAKE} from './ci-smoke-grants.mjs';
import {verifyFutureAllowance} from './ci-smoke-future-allowance.mjs';
import {submitCiRootRequest} from './ci-smoke-root-request-io.mjs';
import {verifyCiRootExchange,CI_ROOT_REQUEST_POLICY,selectCiRootControlOriginals} from './ci-smoke-root-request.mjs';
import {verifyProspectiveCiRootRequestPolicy,verifyCiRootCostCheckpoints,CI_ROOT_COST_MODEL,CI_ROOT_LOCAL_JOURNAL_MAX_ROWS} from './ci-smoke-root-request-cost.mjs';
import {createCiRootReplaySnapshot} from './ci-smoke-root-replay.mjs';
import {captureNonrootMainSource} from './production-nonroot-source-reader.mjs';
import {makeCiStartupRunBinding,openCiSmokeStartup,consumeCiSmokeStartup} from './ci-smoke-startup.mjs';
import {smokePrivateRead,smokePrivateWrite} from './ci-smoke-host.mjs';
import {PRODUCTION_DATA_RELEASE_PARAMETER as parameterName} from './production-data-issuance.mjs';
import {inspectControlBuildCommitment,controlBuildArchiveKey} from './production-control-capture-archive.mjs';
import {extractProductionControlCompositionCommitment,inspectProductionControlCompositionCommitment} from './production-control-composition-reader.mjs';
import {completeProductionControlCompositionBuildCapture,productionControlCompositionCaptureKey} from './production-control-composition-capture-reader.mjs';
import {nonrootAuthorizationBindings,assertNonrootDataRelease} from './production-nonroot-proof.mjs';
import {nonrootArchiveResolvers} from './production-nonroot-archive.mjs';
import {captureNonrootControlBuildAction,completeNonrootControlBuildAction} from './production-nonroot-control-build.mjs';
import {validateImageDescriptor,IMAGE_MEDIA} from './production-image-graph.mjs';
import {allocateCiSmokeControlResources,sealControlResources as sealOwnedControlResources,verifyControlResources,linkControlResourceCompletion} from './ci-smoke-control-resources.mjs';
import {NONROOT_POSTAPPLY_LIMITS,isNonrootPostApplyCheckpoint} from './nonroot-postapply.mjs';
import {readCompletedPostApplyArtifact,writePostApplyCaptureAllocation} from './nonroot-postapply-capture.mjs';

const MAX=33554432,K=1024,UNKNOWN=8*1024*K,parse=raw=>parseAcquisitionJson(Buffer.from(raw));
const positive=n=>integer(n)&&n>0,digest=v=>typeof v==='string'&&/^sha256:[a-f0-9]{64}$/.test(v);
const cleanError=()=>Object.assign(Error('CiFutureCleanupHeld'),{code:'ECLEANUP'});
function immutable(ref){const s=lstatSync(ref.path);need(s.isFile()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&s.nlink===1&&(s.mode&511)===0o600&&s.size<=MAX&&sha(readFileSync(ref.path))===ref.sha256,'CiFutureLocalChanged');}
async function read(ref){exact(ref,['path','sha256']);need(hex(ref.sha256),'CiFutureReference');const raw=await smokePrivateRead(ref.path,MAX);need(sha(raw)===ref.sha256,'CiFutureLocalChanged');return parse(raw);}
async function directory(env){need(typeof env.RUNNER_TEMP==='string'&&resolve(env.RUNNER_TEMP)===env.RUNNER_TEMP&&await realpath(env.RUNNER_TEMP)===env.RUNNER_TEMP,'CiFutureDirectory');const dir=join(env.RUNNER_TEMP,'mem9-ci-future-acquisitions');try{await mkdir(dir,{mode:0o700});}catch(e){if(e.code!=='EEXIST')throw e;}const s=await lstat(dir);need(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&(s.mode&511)===0o700&&await realpath(dir)===dir,'CiFutureDirectory');return dir;}
const save=async(dir,name,value)=>{const path=join(dir,name+'.json');return {path,sha256:await smokePrivateWrite(path,value)};};
function currentSource(env,source,config,scope,now){
 const c=source.current;need(env.GITHUB_ACTIONS==='true'&&env.STAGE==='prod'&&env.GITHUB_EVENT_NAME==='push'&&env.GITHUB_REF==='refs/heads/main'&&['deploy-prod','runtime-cutover-prod'].includes(scope.route)&&env.GITHUB_JOB===scope.jobKey&&env.GITHUB_JOB===scope.route&&env.AWS_REGION===config.region,'CiFutureJob');
 need(c?.repository===env.GITHUB_REPOSITORY&&c.runId===Number(env.GITHUB_RUN_ID)&&c.runAttempt===Number(env.GITHUB_RUN_ATTEMPT)&&c.job===env.GITHUB_JOB&&c.revision===env.GITHUB_SHA&&source.checkout?.revision===env.GITHUB_SHA&&source.checkout.tree===config.startup.source.candidateTree,'CiFutureSource');
 need(positive(source.observedMs)&&positive(source.expiresMs)&&source.observedMs<=now&&now<source.expiresMs,'CiFutureSourceExpired');
}
function descriptor(response,config){
 need(response&&(response.InvalidParameters??[]).length===0&&response.Parameters?.length===1,'CiFutureDescriptor');const p=response.Parameters[0];
 need(p.Name===parameterName&&p.Type==='SecureString'&&p.ARN===`arn:aws:ssm:${config.region}:${config.account}:parameter${parameterName}`&&p.Version===config.target.parameterVersion&&typeof p.Value==='string'&&hash(parse(p.Value))===config.startup.descriptorHash,'CiFutureDescriptor');
 return Object.fromEntries(['Name','Type','ARN','Version','Value'].map(k=>[k,p[k]]));
}
function localJournal(path,starting,budget){
 const fd=openSync(path,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600),digest=createHash('sha256');let used={...counter(starting)},size=0,closed=false,count=0;
 return {get used(){return {...used};},checkpoint(){need(!closed,'CiFutureLocalClosed');fsyncSync(fd);return {sequence:count,prefixHash:digest.copy().digest('hex')};},charge(value){need(!closed,'CiFutureLocalClosed');counter(value);need(value.ecrRequests===0&&value.httpBodyBytes===0,'CiFutureLocalNetwork');const next={};for(const k of COUNTERS){next[k]=used[k]+value[k];need(integer(next[k])&&next[k]<=budget[k],'CiFutureLocalBudget');}
  const bytes=Buffer.from(JSON.stringify(value)+'\n');need(size+bytes.length<=MAX&&count<CI_ROOT_LOCAL_JOURNAL_MAX_ROWS,'CiFutureLocalJournalLimit');let at=0;while(at<bytes.length)at+=writeSync(fd,bytes,at,bytes.length-at);digest.update(bytes);size+=bytes.length;count++;used=next;return {...used};
 },finish(){need(!closed,'CiFutureLocalClosed');fsyncSync(fd);closeSync(fd);closed=true;return {path,sha256:sha(readFileSync(path))};},close(){if(!closed){try{fsyncSync(fd);}finally{closeSync(fd);closed=true;}}}};
}
function replayLocal(ref,start,budget,findCharge){immutable(ref);let used={...counter(start)};const raw=readFileSync(ref.path,'utf8');need(raw===''||raw.endsWith('\n'),'CiFutureLocalJournal');const lines=raw?raw.slice(0,-1).split('\n'):[],matches=[],digest=createHash('sha256');need(lines.length<=CI_ROOT_LOCAL_JOURNAL_MAX_ROWS,'CiFutureLocalJournal');for(const [i,line] of lines.entries()){const c=parse(line);counter(c);need(c.ecrRequests===0&&c.httpBodyBytes===0,'CiFutureLocalNetwork');digest.update(line+'\n');if(findCharge&&hash(c)===hash(findCharge))matches.push({sequence:i+1,prefixHash:digest.copy().digest('hex')});for(const k of COUNTERS){used[k]+=c[k];need(integer(used[k])&&used[k]<=budget[k],'CiFutureLocalBudget');}}return findCharge?{used,matches}:used;}

/** A fixed native S3 Put/Get exchange. Unknown Put/GET is terminal. A fully
 * received bounded 403/404 is pending, never proof that the object is absent. */
async function rendezvous({env,selected,request,check,expiresMs,now,sleep,saveRecord,requestHandler}){
 need(['AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN'].every(k=>typeof env[k]==='string'&&env[k].length>0&&env[k].length<=65536),'CiFutureCredentials');
 const credentials={accessKeyId:env.AWS_ACCESS_KEY_ID,secretAccessKey:env.AWS_SECRET_ACCESS_KEY,sessionToken:env.AWS_SESSION_TOKEN};
 const agent=requestHandler?undefined:new Agent({keepAlive:false,maxSockets:1,rejectUnauthorized:true}),transport=requestHandler??new NodeHttpHandler({httpsAgent:agent,connectionTimeout:5000,requestTimeout:30000});
 const deadline=Math.min(expiresMs,now()+HANDSHAKE.maxDurationMs),controller=new AbortController(),pending=new Set(),bodies=new Set(),requests=new Set(),records=[];let client,current,sequence=0,destroyed=false,cleanupFailed=false;
 const track=p=>{const q=Promise.resolve(p).finally(()=>pending.delete(q));pending.add(q);q.catch(()=>{});return q;};
 const close=b=>{try{b?.destroy?.();}catch{cleanupFailed=true;}};
 const scrub=()=>{for(const r of requests)try{delete r.headers.authorization;delete r.headers['x-amz-security-token'];r.body=undefined;}catch{cleanupFailed=true;}};
 const abort=()=>{controller.abort();for(const b of bodies)close(b);scrub();};const timer=setTimeout(abort,Math.max(1,deadline-now()));
 const guard=()=>{check();need(!controller.signal.aborted&&now()<deadline,'CiFutureHandshakeExpired');};
 let rejectAbort;const aborted=new Promise((_,reject)=>{rejectAbort=()=>reject(Error('CiFutureHandshakeAborted'));});aborted.catch(()=>{});controller.signal.addEventListener('abort',rejectAbort,{once:true});
 const wait=p=>Promise.race([track(p),aborted]);
 const destroy=()=>{if(!destroyed){destroyed=true;transport.destroy();}};
 const handler={handle(r,options){guard();need(current&&!current.sent,'CiFutureHandshakeDispatch');const put=current.action==='PutObject',key=put?selected.requestKey:selected.responseKey;
  requests.add(r);need(r.protocol==='https:'&&r.hostname===`s3.${selected.region}.amazonaws.com`&&!r.port&&r.path==='/'+selected.bucket+'/'+key&&r.method===(put?'PUT':'GET'),'CiFutureHandshakeEndpoint');
  need(Object.keys(r.query??{}).every(k=>k==='x-id'&&r.query[k]===current.action),'CiFutureHandshakeQuery');
  need(r.headers['x-amz-expected-bucket-owner']===selected.expectedBucketOwner&&(!put||r.headers['if-none-match']==='*'),'CiFutureHandshakeScope');
  const bytes=r.body===undefined?Buffer.alloc(0):typeof r.body==='string'?Buffer.from(r.body):r.body;need(bytes instanceof Uint8Array&&bytes.length<=(put?16384:0),'CiFutureHandshakeRequestCap');if(put)need(sha(bytes)===sha(JSON.stringify(request)),'CiFutureHandshakeRequestChanged');
  const slot=current;guard();slot.sent=true;slot.requestBytes=bytes.length;
  return wait((async()=>{let body;try{const out=await transport.handle(r,{...options,abortSignal:controller.signal});body=out.response?.body;need(body&&typeof body[Symbol.asyncIterator]==='function','CiFutureHandshakeBody');bodies.add(body);guard();
   const status=out.response.statusCode,cap=put||status!==200?HANDSHAKE.pendingBodyBytes:selected.responseBytes,chunks=[];let size=0;for await(const chunk of body){guard();need(chunk instanceof Uint8Array,'CiFutureHandshakeBody');size+=chunk.length;need(size<=cap,'CiFutureHandshakeBodyCap');chunks.push(Buffer.from(chunk));}
   const length=out.response.headers?.['content-length'];if(length!==undefined)need(/^[0-9]+$/.test(length)&&Number(length)===size,'CiFutureHandshakeBodyLength');
   slot.raw=Buffer.concat(chunks,size);slot.status=status;slot.responseHash=sha(slot.raw);guard();const stream=Readable.from([slot.raw]);bodies.add(stream);return {response:{...out.response,body:stream}};
  }finally{close(body);}})());
 },destroy};
 async function send(action,input){guard();current={action,sent:false,requestBytes:0};const index=++sequence,intent=await saveRecord('handshake-intent-'+index,{version:1,index,action,requestHash:hash(action==='PutObject'?request:input),ownerRefund:0});guard();let result,error;
  try{result=await wait(client.send(action==='PutObject'?new PutObjectCommand(input):new GetObjectCommand(input),{abortSignal:controller.signal}));}
  catch(e){error=e;}
  const slot=current;records.push({intent,result:await saveRecord('handshake-result-'+index,{version:1,index,status:slot.status??null,responseHash:slot.responseHash??null,requestBytes:slot.requestBytes,responseBytes:slot.raw?.length??0,unknown:!slot.responseHash,ownerRefund:0})});
  if(error){if(action==='GetObject'&&HANDSHAKE.knownPendingStatuses.includes(slot.status)&&slot.responseHash)return null;throw Error('CiFutureHandshakeHeld');}
  guard();need(slot.status===200,'CiFutureHandshakeStatus');if(action==='PutObject')need(typeof result.ETag==='string'&&result.ETag.length>0,'CiFuturePutResult');
  need(result.ServerSideEncryption==='aws:kms'&&result.SSEKMSKeyId===selected.kmsKeyArn&&result.BucketKeyEnabled===true,'CiFutureHandshakeEncryption');result.Body?.destroy();return slot.raw;
 }
 try{
  client=new S3Client({region:selected.region,endpoint:`https://s3.${selected.region}.amazonaws.com`,forcePathStyle:true,followRegionRedirects:false,ignoreConfiguredEndpointUrls:true,maxAttempts:1,credentials,requestChecksumCalculation:'WHEN_REQUIRED',responseChecksumValidation:'WHEN_REQUIRED',requestHandler:handler});
  await send('PutObject',{Bucket:selected.bucket,Key:selected.requestKey,ExpectedBucketOwner:selected.expectedBucketOwner,IfNoneMatch:'*',ContentType:'application/json',ServerSideEncryption:'aws:kms',SSEKMSKeyId:selected.kmsKeyArn,BucketKeyEnabled:true,Body:Buffer.from(JSON.stringify(request))});
  for(let i=0;i<HANDSHAKE.maxGetAttempts;i++){const raw=await send('GetObject',{Bucket:selected.bucket,Key:selected.responseKey,ExpectedBucketOwner:selected.expectedBucketOwner});if(raw)return {raw,records};need(i<HANDSHAKE.maxKnownPendingAttempts&&now()+HANDSHAKE.minKnownPendingPollMs<deadline,'CiFutureAllowancePending');await wait(sleep(HANDSHAKE.minKnownPendingPollMs));}
  throw Error('CiFutureAllowancePending');
 }finally{
  clearTimeout(timer);abort();try{client?.destroy();destroy();agent?.destroy();}catch{cleanupFailed=true;}
  let timeout;const drain=async()=>{await Promise.allSettled([...pending]);await Promise.all([...bodies].filter(b=>!b.closed).map(b=>new Promise(resolve=>b.once('close',resolve))));};
  const done=await Promise.race([drain().then(()=>true),new Promise(resolve=>{timeout=setTimeout(()=>resolve(false),1000);})]);clearTimeout(timeout);controller.signal.removeEventListener('abort',rejectAbort);scrub();credentials.accessKeyId='';credentials.secretAccessKey='';credentials.sessionToken='';if(!done||cleanupFailed)throw cleanError();
 }
}

function ecsArn(value,config,kind){return typeof value==='string'&&value.startsWith(`arn:aws:ecs:${config.region}:${config.account}:${kind}/`);}
function project(action,response,request,config){
 if(action==='GetCallerIdentity'){need(response.Account===config.account&&typeof response.Arn==='string'&&response.Arn.startsWith(`arn:aws:sts::${config.account}:assumed-role/github-actions-mem9-on-aws-prod/`),'CiFutureCaller');return {Account:response.Account,Arn:response.Arn};}
 if(action==='GetParameters'&&request.Names.includes(parameterName))return {Parameters:[descriptor(response,config)],InvalidParameters:[]};
 if(action==='ListTasks'){need(Array.isArray(response.taskArns)&&!response.nextToken&&new Set(response.taskArns).size===response.taskArns.length&&response.taskArns.length<=request.maxResults&&response.taskArns.every(v=>ecsArn(v,config,'task')),'CiFutureTaskList');return {taskArns:response.taskArns};}
 if(action==='DescribeTasks'||action==='DescribeServices'){
  need((response.failures??[]).length===0,'CiFutureEcsResponse');const field=action==='DescribeTasks'?'tasks':'services',rows=response[field];need(Array.isArray(rows)&&rows.length<=100,'CiFutureEcsResponse');
  const cluster=request.cluster.startsWith('arn:')?request.cluster:`arn:aws:ecs:${config.region}:${config.account}:cluster/${request.cluster}`;
  return {[field]:rows.map(row=>{need(row.clusterArn===cluster,'CiFutureEcsCluster');if(field==='tasks'){need(request.tasks.includes(row.taskArn)&&ecsArn(row.taskArn,config,'task')&&ecsArn(row.taskDefinitionArn,config,'task-definition'),'CiFutureTask');return {taskArn:row.taskArn,taskDefinitionArn:row.taskDefinitionArn};}
   need(ecsArn(row.serviceArn,config,'service')&&request.services.some(s=>s===row.serviceArn||s===row.serviceName)&&ecsArn(row.taskDefinition,config,'task-definition'),'CiFutureService');return {serviceArn:row.serviceArn,taskDefinition:row.taskDefinition};})};
 }
 if(action==='BatchGetImage')return copyNonrootJson(imageResponseFromSdk(response));
 if(action==='DescribeImageScanFindings'){
  need(response?.registryId===request.registryId&&response.repositoryName===request.repositoryName&&response.imageId?.imageDigest===request.imageId.imageDigest,'CiFutureScanScope');
  // A later-token profile has not been funded by the current closed codec.
  // Never permit a caller to finish this slot with a truncated first page.
  need(response.nextToken===undefined||response.nextToken===null||response.nextToken==='','CiFutureScanPaginationUnsupported');
  return {registryId:response.registryId,repositoryName:response.repositoryName,imageId:{imageDigest:response.imageId.imageDigest}};
 }
 if(action==='S3BlobGet'){exact(response,['repositoryName','layerDigest','size']);need(response.repositoryName===request.repositoryName&&response.layerDigest===request.layerDigest&&integer(response.size),'CiFutureBlob');return copyNonrootJson(response);}
 return null; // Never serialize a Body stream, download URL, token, or unrelated payload.
}
function manifest(response,expected,chargeLocal){
 const {raw}=normalizeImageDigestResponse(imageResponseFromSdk(response),{registryId:expected.account,repositoryName:expected.repositoryName,imageDigest:expected.digest},chargeLocal);return {document:parse(raw.toString()),bytes:raw.length};
}
function profileMachine(profiles,config,control,chargeLocal=()=>{},capacity){
 const controlDigest=control?.kind==='native-control-composition-commitment'?control.rootDigest:control?.outputDigest;
 const counts=profiles.map(()=>0),responses=new Map(),manifests=new Map(),blobs=new Map();let root,arm,buildBinding;const capacityNodes=new Map(),finishedManifests=new Set();
 if(capacity)inspectFutureControlCapacity(capacity);
 const capacityNode=d=>{if(!capacity)return;const old=capacityNodes.get(d.digest);need(!old||old.size===d.size&&old.mediaType===d.mediaType,'CiFutureControlDescriptor');capacityNodes.set(d.digest,d);verifyFutureControlGraphCapacity([...capacityNodes.values()],capacity);};
 function requestFor(p){
  if(p.kind==='EXACT')return [p.request];
  if(p.kind==='OWNER_ROOT_ARTIFACT_FROM_FUNDED_CHECKPOINT'){
   const {runtimeNonce,authorizationId}=config.ownerRoot;return [{...p.request,Key:`data-authorizations/${runtimeNonce}/${authorizationId}/ci-grants/${config.startup.grantSetId}/${hash(p.late.checkpoint)}/root-audit.json`}];
  }
  const from=responses.get(p.late.fromProfile);
  if(p.kind==='CURRENT_TASKS_FROM_SCOPED_LIST'){need(from?.action==='ListTasks','CiFutureProfileDependency');return {tasks:from.value.taskArns,max:p.late.maxItems};}
  if(p.kind==='DEFINITION_FROM_VALIDATED_TASK_OR_SERVICE'){need(from,'CiFutureProfileDependency');const rows=p.late.source==='task'?from.value.tasks:from.value.services;need(Array.isArray(rows),'CiFutureProfileDependency');return [...new Set(rows.map(r=>r.taskDefinitionArn??r.taskDefinition))].map(taskDefinition=>({...p.request,taskDefinition}));}
  need(p.kind==='CONTROL_ARTIFACT_FROM_AUTHENTICATED_BUILD'&&control,'CiFutureControlBinding');const a=p.late.artifact;let values;
  if(a==='private-capsule')values=[control.kind==='native-control-composition-commitment'?productionControlCompositionCaptureKey(control.grantSetId):controlBuildArchiveKey('prod',control)];else{
   need(buildBinding,'CiFutureControlBuildRequired');
   if(a==='root')values=[controlDigest];else if(a==='arm64'){need(root,'CiFutureControlRoot');values=[root];}
   else if(a==='manifest')values=[...manifests.keys()].filter(d=>d!==controlDigest);
   else {need(root,'CiFutureControlRoot');values=[...blobs.values()].filter(row=>row.kind===(a==='config'?'config':'layer')).map(row=>row.descriptor.digest);}
  }
  if(p.late.field==='layerDigests')return {field:'layerDigests',values,max:100};
  return values.map(v=>({...p.request,[p.late.field]:p.late.field==='imageIds'?[{imageDigest:v}]:p.late.field==='imageId'?{imageDigest:v}:p.late.field==='layerDigests'?[v]:v}));
 }
 return {counts,responses,bind(value){need(!buildBinding,'CiFutureControlAlreadyBound');need(value.rootDigest===controlDigest&&digest(value.configDigest),'CiFutureControlBinding');buildBinding=value;},select(action,request){
  for(let i=0;i<profiles.length;i++){const p=profiles[i];if(p.action!==action||counts[i]>=p.count)continue;let choices;try{choices=requestFor(p);}catch{continue;}
   let match;if(Array.isArray(choices))match=choices.some(q=>hash(q)===hash(request));else{const field=choices.field??'tasks',items=request[field],other=Object.fromEntries(Object.entries(request).filter(([k])=>k!==field));match=Array.isArray(items)&&items.length>0&&items.length<=choices.max&&new Set(items).size===items.length&&items.every(t=>(choices.values??choices.tasks).includes(t))&&hash(other)===hash(p.request);}
   if(match){if(capacity&&isFutureControlCapacityProfile(p)&&['S3BlobGet','GetDownloadUrlForLayer'].includes(action)){need(finishedManifests.has(controlDigest)&&[...manifests.keys()].every(d=>finishedManifests.has(d)),'CiFutureControlMetadataIncomplete');const d=blobs.get(request.layerDigest)?.descriptor;need(d&&(action==='GetDownloadUrlForLayer'||d.size<=p.responseBytes),'CiFutureControlBlobCapacity');}return {index:i,profile:p};}
  }throw Error('CiFutureProfileRequest');
 },complete(index,request,value){const p=profiles[index];counts[index]++;responses.set(p.id,{action:p.action,value});
  if(p.action==='S3BlobGet'&&p.kind==='CONTROL_ARTIFACT_FROM_AUTHENTICATED_BUILD'){const d=blobs.get(request.layerDigest)?.descriptor;need(d&&d.size===value.size,'CiFutureBlobSize');}
  if(p.kind==='CONTROL_ARTIFACT_FROM_AUTHENTICATED_BUILD'&&p.action==='BatchGetImage'){
   const wanted=request.imageIds[0].imageDigest,decoded=manifest(value,{account:config.account,repositoryName:p.request.repositoryName,digest:wanted},chargeLocal),m=decoded.document;
   need(m.schemaVersion===2,'CiFutureControlManifest');capacityNode({digest:wanted,size:decoded.bytes,mediaType:m.mediaType});finishedManifests.add(wanted);const announced=manifests.get(wanted);if(announced)need(announced.size===decoded.bytes&&announced.mediaType===m.mediaType,'CiFutureControlManifest');
   if([IMAGE_MEDIA.index,IMAGE_MEDIA.dockerIndex].includes(m.mediaType)){
    need(Array.isArray(m.manifests)&&m.manifests.length<=128,'CiFutureControlRoot');
    if(wanted===controlDigest){const rows=m.manifests.filter(r=>r.platform?.os==='linux'&&r.platform.architecture==='arm64');need(rows.length===1,'CiFutureControlRoot');root=rows[0].digest;}
    for(const d of m.manifests){validateImageDescriptor(d,'manifest');capacityNode(d);need(d.digest!==controlDigest&&d.digest!==wanted,'CiFutureControlCycle');const old=manifests.get(d.digest);if(old)need(old.size===d.size&&old.mediaType===d.mediaType,'CiFutureControlDescriptor');else manifests.set(d.digest,d);}
    need(manifests.size<=128,'CiFutureControlGraphLimit');
   }else{
    need([IMAGE_MEDIA.manifest,IMAGE_MEDIA.dockerManifest].includes(m.mediaType)&&Array.isArray(m.layers)&&m.layers.length<=2048,'CiFutureControlManifest');validateImageDescriptor(m.config,'blob');
    if(wanted===root){need(m.config.digest===buildBinding.configDigest,'CiFutureControlBuildConfig');arm={config:m.config,layers:m.layers};}
    if(m.subject){validateImageDescriptor(m.subject,'manifest');need(manifests.has(m.subject.digest)||m.subject.digest===controlDigest,'CiFutureControlSubject');}
    for(const [kind,items]of [['config',[m.config]],['layer',m.layers]])for(const d of items){validateImageDescriptor(d,'blob');capacityNode(d);const old=blobs.get(d.digest);if(old)need(old.descriptor.size===d.size&&old.descriptor.mediaType===d.mediaType,'CiFutureControlDescriptor');else blobs.set(d.digest,{kind,descriptor:d});}need(blobs.size<=2048,'CiFutureControlGraphLimit');
   }
  }
 }};
}
function fundedComposition(funded){
 const rows=funded.consumers.filter(c=>c.composition);need(rows.length<=1,'CiFutureCompositionCoverage');
 if(!rows.length)return null;
 const c=rows[0];need(c.scope.kind==='source'&&c.scope.jobKey==='build-image-transition-control','CiFutureCompositionScope');
 return c.composition.plan;
}
function compositionCommitment(value,binding,funded,jobId){
 const c=inspectProductionControlCompositionCommitment(value),plan=fundedComposition(funded);need(plan,'CiFutureCompositionRequired');
 need(c.grantSetId===funded.grantSetId&&c.planHash===plan.planHash&&c.runId===binding.source.runId&&c.runAttempt===binding.source.runAttempt&&c.mainRevision===binding.source.mainRevision&&c.mainTree===binding.source.mainTree&&(jobId===undefined||c.jobId===jobId),'CiFutureControlCommitment');return c;
}
async function controlCommitment(host,binding,check,funded){
 check();const workflow=parseDocument(await host.run('git',['show','HEAD:.github/workflows/infra-ci.yml'])).toJS(),job=workflow.jobs?.['build-image-transition-control'];need(typeof job?.name==='string','CiFutureControlJob');
 const list=await host.api(`actions/runs/${binding.source.runId}/attempts/${binding.source.runAttempt}/jobs?per_page=100`);need(list.total_count===list.jobs?.length&&list.total_count<=100,'CiFutureControlJobs');const jobs=list.jobs.filter(j=>j.name===job.name);need(jobs.length===1,'CiFutureControlJob');const j=jobs[0];
 need(j.status==='completed'&&j.conclusion==='success'&&j.run_id===binding.source.runId&&j.run_attempt===binding.source.runAttempt&&j.head_sha===binding.source.mainRevision,'CiFutureControlJob');
 const log=await host.readLog(j.id);need(typeof log==='string'&&Buffer.byteLength(log)<=8388608,'CiFutureControlLog');
 const native=fundedComposition(funded),step=job.steps?.filter(s=>s.id==='bootstrap');
 if(native){need(step?.length===1&&step[0].uses==='./.github/actions/control-composition','CiFutureCompositionJob');const c=compositionCommitment(extractProductionControlCompositionCommitment(Buffer.from(log)),binding,funded,j.id);check();return c;}
 need(!step?.some(s=>s.uses==='./.github/actions/control-composition'),'CiFutureCompositionRequired');
 const rows=log.split('\n').map(l=>l.replace(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z\s+/,'' )).filter(l=>l.startsWith('MEM9_CONTROL_BUILD_COMMITMENT '));need(rows.length===1,'CiFutureControlCommitment');const c=inspectControlBuildCommitment(parse(rows[0].slice('MEM9_CONTROL_BUILD_COMMITMENT '.length)));
 need(c.runId===binding.source.runId&&c.runAttempt===binding.source.runAttempt&&c.sourceRevision===binding.source.mainRevision&&c.sourceTree===binding.source.mainTree&&c.buildJobId===j.id,'CiFutureControlCommitment');check();return c;
}
function bundleCheck(bundle,config,scope,sourceRef,openedMs,now){
 const p=bundle.phaseReceipt;need(bundle.kind==='image-security-nonroot-deployment-bundle'&&bundle.phase==='deployment'&&bundle.source?.checkout?.sha===bundle.source?.main?.sha&&bundle.source.checkout.tree===config.startup.source.candidateTree&&hash(parse(bundle.parameter?.Value??''))===config.startup.descriptorHash&&hash(bundle.proof)===config.startup.proofHash,'CiFutureBundle');
 need(p?.phase===scope.phase&&p.sourceReceiptHash===sourceRef.sha256&&positive(p.observedMs)&&p.observedMs>=openedMs&&p.observedMs<=now&&positive(p.expiresMs)&&now<p.expiresMs&&p.expiresMs<=config.target.descriptor.expiresMs,'CiFutureBundle');
 descriptor({Parameters:[bundle.parameter]},config);return p;
}

export async function openFutureCiSmokeAcquisition(input,seams={}){
 exact(input,['env','scope','sourceReceipt','host']);need(Object.keys(seams).every(k=>['now','sleep','artifactClient','requestHandler','controlResourceDocker','rootGithubRequest'].includes(k)),'CiFutureSeam');const {env,host,sourceReceipt}=input,now=seams.now??Date.now,sleep=seams.sleep??(ms=>new Promise(resolve=>setTimeout(resolve,ms)));
 need(typeof now==='function'&&typeof sleep==='function'&&host?.env===env&&typeof host.checkout==='function'&&typeof host.run==='function'&&typeof host.api==='function','CiFutureHost');
 const raw=env.MEM9_CI_ACQUISITION_CONFIG;need(typeof raw==='string'&&Buffer.byteLength(raw)<=65536,'CiFutureConfigRequired');const config=inspectFutureAcquisitionConfig(parse(raw));exact(input.scope,['route','phase','checkpoint']);const scope={kind:'target',jobKey:env.GITHUB_JOB,...input.scope},selected=futureAcquisitionScope(config,scope),openedMs=now();currentSource(env,sourceReceipt,config,scope,openedMs);
 const sourceRef={path:env.MEM9_CI_SMOKE_SOURCE_RECEIPT,sha256:env.MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH};need(sourceRef.path===join(env.RUNNER_TEMP,'mem9-ci-smoke-source','receipt.json'),'CiFutureSourcePath');same(await read(sourceRef),sourceReceipt,'CiFutureSource');same(await host.checkout(),sourceReceipt.checkout,'CiFutureCheckout');
 const expiresMs=Math.min(sourceReceipt.expiresMs,config.startup.notAfter,config.target.descriptor.expiresMs),identity=()=>hash(Object.fromEntries(['GITHUB_REPOSITORY','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_JOB','GITHUB_SHA','GITHUB_WORKFLOW_SHA','GITHUB_EVENT_NAME','GITHUB_REF','AWS_REGION'].map(k=>[k,env[k]??null]))),initialIdentity=identity();
 const check=()=>{need(now()>=openedMs&&now()<expiresMs&&env.MEM9_CI_ACQUISITION_CONFIG===raw&&identity()===initialIdentity,'CiFutureExpired');immutable(sourceRef);};check();
 const source=await captureNonrootMainSource({git:args=>host.run('git',args),api:path=>host.api(path)},env,config.startup.source),binding=makeCiStartupRunBinding(config.startup,source);check();
 const handle=await openCiSmokeStartup({env,host,config:config.startup,scope,source},{now,sleep,...(seams.artifactClient?{artifactClient:seams.artifactClient}:{})}),startupReceipt=consumeCiSmokeStartup(handle,{bindingHash:hash(binding),scope,now:now()});check();
 const postApply=config.version===3&&isNonrootPostApplyCheckpoint(scope)?await readCompletedPostApplyArtifact({env,binding,config,scope,now:now()}):undefined;check();
 const dir=await directory(env),prefix='target-'+hash({bindingHash:hash(binding),scope}),saveRecord=(name,value)=>save(dir,prefix+'-'+name,value),request={version:postApply?2:1,kind:'ci-prepaid-acquisition-request',bindingHash:hash(binding),scope,nonce:startupReceipt.nonce,artifactId:startupReceipt.artifactId,artifactDigest:startupReceipt.artifactDigest,sourceReceiptHash:sourceRef.sha256,...(postApply?{postApply}:{})},requestHash=hash(request);
 need(Buffer.byteLength(JSON.stringify(request))<=16384,'CiFutureRequestCap');
 const claim={version:1,kind:'ci-future-acquisition-claim',scope,binding,startupReceipt,sourceReceiptRef:sourceRef,configHash:sha(raw),openedMs,expiresMs,requestHash,ownerRefund:0},claimRef=await saveRecord('claim',claim),requestRef=await saveRecord('request',request);
 let accepted,allowanceRef,handshakeRefs,control=null,controlRef=null,controlBuildRef=null,usage,held=false,closed=false,active=null,identitySeen=false,descriptorSeen=false,resourceAllocation=null,resourceExpected=null,sealedResourceRef=null,rootExchangeRef=null,rootStarted=false;const reads=[];
 const hold=async()=>{held=true;usage?.close();try{await saveRecord('held',{version:1,claimRef,ownerRefund:0});}catch(e){if(e.code!=='EEXIST')throw e;}};
 try{
  const exchange=await rendezvous({env,selected,request,check,expiresMs,now,sleep,saveRecord,requestHandler:seams.requestHandler});handshakeRefs=exchange.records;const response=parse(exchange.raw);
  accepted=verifyFutureAllowance(response,{config,scope,startupReceipt,binding,requestHash,maximumExpiresMs:expiresMs,now:now()});allowanceRef=await saveRecord('allowance',exchange.raw);
  need(!accepted.consumer.reader&&Array.isArray(accepted.consumer.profiles),'CiFutureTargetGrant');
  if(accepted.consumer.profiles.some(p=>p.kind==='CONTROL_ARTIFACT_FROM_AUTHENTICATED_BUILD')){control=await controlCommitment(host,binding,check,accepted.funded);controlRef=await saveRecord('control',control);}
  usage=localJournal(join(dir,prefix+'-local.ndjson'),zero(),accepted.consumer.localBudget);
  if(postApply)usage.charge({...zero(),logicalBytes:NONROOT_POSTAPPLY_LIMITS.readerLocalBytes});
 }catch(e){await hold();throw e;}
 const paid=accepted.consumer,machine=profileMachine(paid.profiles,config,control,n=>usage.charge({ecrRequests:0,logicalBytes:n,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0}),paid.controlCapacity),controlWire=paid.controlCapacity?createFutureControlWireMeter(paid.controlCapacity):null,current=()=>{check();need(!held&&!closed&&now()<accepted.expiresMs,'CiFutureClosed');immutable(claimRef);immutable(requestRef);immutable(allowanceRef);};let wire=0,rootWork=null,preparedOriginals=null;
 const beginRootWork=()=>{
  current();need(paid.rootRequest?.version===2&&descriptorSeen&&controlBuildRef&&resourceAllocation&&!active&&!rootStarted,'CiFutureRootRequestOrder');
  const quote=verifyProspectiveCiRootRequestPolicy(paid.rootRequest,scope);rootStarted=true;active={root:true};
  const debit={...zero(),logicalBytes:quote.roundedLocalBytes};usage.charge(debit);const position=usage.checkpoint();
  rootWork={quote,debit,position,used:Object.fromEntries(Object.keys(quote.work).map(k=>[k,0])),checkpoints:[],requestHash:null};
 };
 const consumeRoot=(stage,n)=>{
  need(rootWork&&!closed&&!held&&now()<accepted.expiresMs&&Object.hasOwn(rootWork.used,stage)&&integer(n),'CiFutureRootCredit');
  need(rootWork.used[stage]+n<=rootWork.quote.work[stage],'CiFutureRootCreditExceeded');rootWork.used[stage]+=n;
 };
 const rootCheckpoint=(stage,isHeld=false)=>{
  const r=rootWork;need(r&&r.checkpoints.length<CI_ROOT_COST_MODEL.checkpointCount,'CiFutureRootCheckpoint');
  r.checkpoints.push({version:1,claimRef,scopeHash:hash(scope),catalogHash:hash(r.quote),requestHash:r.requestHash,sequence:r.checkpoints.length+1,stage,used:{...r.used},previousHash:r.checkpoints.length?hash(r.checkpoints.at(-1)):null,held:isHeld});
 };
 const writeRootAccounting=async isHeld=>{
  const r=rootWork;if(!r||r.accountingAttempted)return r?.accountingRef;
  const bytes=6*r.quote.records.accounting;
  need(r.used.records+bytes<=r.quote.work.records,'CiFutureRootCreditExceeded');r.used.records+=bytes;
  if(isHeld)rootCheckpoint(r.requestHash?'transport':'selection',true);else{rootCheckpoint('records');rootCheckpoint('cleanup');}
  r.accountingAttempted=true;
  r.accountingRef=await saveRecord('root-local-accounting',{version:1,claimRef,scopeHash:hash(scope),catalogHash:hash(r.quote),debitSequence:r.position.sequence,journalPrefixHash:r.position.prefixHash,debit:r.debit,checkpoints:r.checkpoints});return r.accountingRef;
 };
 return Object.freeze({authority:false,...(paid.controlCapacity?{controlCapacity:paid.controlCapacity}:{}),authorizationSeed:Object.freeze({kind:'production-data-release',descriptor:config.target.descriptor,descriptorHash:config.startup.descriptorHash,proofHash:config.startup.proofHash,parameterVersion:config.target.parameterVersion}),
  rootAuditReadBinding(){current();need(paid.profiles.filter(p=>p.kind==='OWNER_ROOT_ARTIFACT_FROM_FUNDED_CHECKPOINT'&&p.late.checkpoint===scope.checkpoint).length===1,'CiFutureRootReadNotFunded');return Object.freeze({scope,grantSetId:config.startup.grantSetId,storage:config.storage,ownerRoot:config.ownerRoot,proofHash:config.startup.proofHash,descriptorHash:config.startup.descriptorHash,parameterVersion:config.target.parameterVersion,runId:source.run.id,runAttempt:source.run.attempt,...(scope.checkpoint==='deploy-prod/23'?{targetFunding:{grantSetId:accepted.funded.grantSetId,grantHash:accepted.funded.grantHash,planHash:accepted.funded.planHash,debitEventHash:accepted.funded.debitEventHash,controlSource:accepted.funded.source,template:accepted.funded.owner.delivery.template,slot:accepted.funded.owner.delivery.slots.find(s=>s.kind==='target-window'),issuedMs:accepted.funded.issuedMs,notAfter:Math.min(accepted.funded.notAfter,accepted.expiresMs)}}:{})});},
  async prepareRootRequestOriginals({archive,deploymentSource,source:givenSource}){try{
   need(scope.checkpoint==='deploy-prod/23','CiFutureRootOriginalScope');same(givenSource,source,'CiFutureRootRequestSource');beginRootWork();
   const rows=await selectCiRootControlOriginals({archive,deploymentSource,source:givenSource,chargeLocal:n=>consumeRoot('selection',n)});current();
   preparedOriginals={rows,deploymentHash:hash(deploymentSource),sourceHash:hash(givenSource)};rootCheckpoint('selection');return rows;
  }catch(e){try{await writeRootAccounting(true);}finally{await hold();}throw e;}},
  rootRequestPolicyVersion(){return paid.rootRequest?.version??null;},
  async requestRootAudit(input){try{
   current();const prospective=paid.rootRequest?.version===2;
   if(prospective){
    if(scope.checkpoint==='deploy-prod/23')need(rootWork&&preparedOriginals&&hash(input.controlOriginals)===hash(preparedOriginals.rows)&&hash(input.deploymentSource)===preparedOriginals.deploymentHash&&hash(input.source)===preparedOriginals.sourceHash,'CiFutureRootOriginalBinding');
    else beginRootWork();
    need(active?.root&&!rootWork.submitted,'CiFutureRootRequestOrder');rootWork.submitted=true;
   }else{need(paid.rootRequest&&descriptorSeen&&controlBuildRef&&resourceAllocation&&!active&&!rootStarted,'CiFutureRootRequestOrder');rootStarted=true;active={root:true};}
   const b=nonrootAuthorizationBindings(input.context);need(b.proofHash===config.startup.proofHash&&hash(input.records.proof)===b.proofHash&&input.phase===scope.phase,'CiFutureRootRequestProof');same(input.source,source,'CiFutureRootRequestSource');
   const records=[],rootSave=async(name,value)=>{
    if(prospective){
     need(Buffer.byteLength(join(dir,prefix+'-'+name+'.json'))<=CI_ROOT_COST_MODEL.referencePathBytes,'CiRootReplayPathBound');
     if(value instanceof Uint8Array)consumeRoot(name==='root-request'?'request':'transport',value.length);
     else{const r=rootWork.quote.records,key={'root-put-intent':'putIntent','root-put-dispatch':'putDispatch','root-put-complete':'putComplete','root-request-held':'held'}[name]??(/^root-ready-[1-9][0-9]*-intent$/.test(name)?'readyIntent':/^root-ready-[1-9][0-9]*-complete$/.test(name)?'readyComplete':null);need(key,'CiFutureRootRecord');consumeRoot(key==='held'?'cleanup':'records',6*r[key]);}
    }else{const bytes=value instanceof Uint8Array?value.length:Buffer.byteLength(JSON.stringify(value));usage.charge({...zero(),logicalBytes:bytes});}
    const written=await saveRecord(name,value),ref=prospective?{path:name+'.json',sha256:written.sha256}:written;records.push({name,ref});if(prospective&&name==='root-request'){rootWork.requestHash=ref.sha256;rootCheckpoint('request');}return ref;
   };
   const result=await submitCiRootRequest({parameter:input.parameter,source:input.source,deploymentSource:input.deploymentSource,targetObservation:input.targetObservation,...(input.controlOriginals?{controlOriginals:input.controlOriginals}:{})},{env,config,scope,binding,startupReceipt,check:current,chargeLocal:n=>usage.charge({...zero(),logicalBytes:n}),...(prospective?{chargeWork:consumeRoot}:{}),save:rootSave,deadlineMs:Math.min(expiresMs,accepted.expiresMs),requestHandler:seams.requestHandler,...(seams.rootGithubRequest?{githubRequest:seams.rootGithubRequest}:{}),sleep});
   wire+=result.observedWireBytes;let localAccountingRef;
   if(prospective){
    consumeRoot('records',6*rootWork.quote.records.exchange);rootCheckpoint('transport');const ref=await writeRootAccounting(false);localAccountingRef={path:'root-local-accounting.json',sha256:ref.sha256};
   }
   rootExchangeRef=await saveRecord('root-exchange-complete',{version:prospective?2:1,...result,records,...(prospective?{localAccountingRef}:{})});active=null;return result;
  }catch(e){try{await writeRootAccounting(true);}finally{await hold();}throw e;}},
  async allocateControlResources(){try{current();need(descriptorSeen&&!active&&controlBuildRef&&!resourceAllocation,'CiFutureResourceOrder');active={resources:true};const built=await read(controlBuildRef);
   resourceExpected={claimRef,scope,bindingHash:hash(binding),sourceReceiptRef:sourceRef,configHash:sha(raw),run:{repository:source.repository,runId:source.run.id,runAttempt:source.run.attempt,jobKey:scope.jobKey,revision:source.checkout.sha},rootDigest:built.rootDigest,configDigest:built.configDigest};
   resourceAllocation=await allocateCiSmokeControlResources({env,expected:resourceExpected},{now,...(seams.controlResourceDocker?{docker:seams.controlResourceDocker}:{})});active=null;return resourceAllocation;
  }catch(e){await hold();throw e;}},
  async sealControlResources({bundleRef}){try{current();need(!active&&bundleRef,'CiFutureResourceOrder');const bundle=Object.hasOwn(bundleRef,'value')?bundleRef.value:await read(bundleRef),required=Boolean(bundle.controlCache)||paid.profiles.some(p=>p.kind==='CONTROL_ARTIFACT_FROM_AUTHENTICATED_BUILD'&&p.late.artifact!=='private-capsule');
   if(!required){need(!resourceAllocation,'CiFutureResourcesUnexpected');return null;}need(resourceAllocation&&bundle.controlCache&&!sealedResourceRef,'CiFutureResourcesRequired');
   active={resources:true};sealedResourceRef=await sealOwnedControlResources(resourceAllocation.handle,{bundleRef});active=null;return sealedResourceRef;
  }catch(e){await hold();throw e;}},
  async bindControlBuild({context,records,build}){try{current();need(descriptorSeen&&!active&&control&&!controlBuildRef,'CiFutureControlBindOrder');active={binding:true};
   const b=nonrootAuthorizationBindings(context);need(b.proofHash===config.startup.proofHash&&hash(records.proof)===b.proofHash,'CiFutureControlProof');assertNonrootDataRelease(context,{current:config.target.descriptor,controlSourceTree:config.startup.source.candidateTree,now:now()});
   const contract=records.proof.taskPlan.deployedControlBuildContract,native=fundedComposition(accepted.funded);same(build.contract,contract,'CiFutureControlContract');same(build.commitment,control,'CiFutureControlCommitment');
   need((contract.version===2)===Boolean(native),'CiFutureControlRecipeVersion');need(build.completion.observedMs<=now(),'CiFutureControlCompletion');let captured,completion,image;
   if(native){
    same(build.source,source,'CiFutureControlSource');const checked=completeProductionControlCompositionBuildCapture(build.envelopeBytes,{commitment:control,contract,source,run:build.completion.run,job:build.completion.job,buildLog:build.buildLog,metadataReads:{reserveLocal:charge=>usage.charge(charge)},now:build.completion.observedMs});
    same(checked.plan,native,'CiFutureControlPlan');captured=checked.capture;completion=checked.completion;image=captured.image;
   }else{
    same(build.capture.source,source,'CiFutureControlSource');captured=await captureNonrootControlBuildAction({...build.capture,contract},{...nonrootArchiveResolvers(records.proofArchive),expected:{sourceContext:build.sourceContext}});
    completion=completeNonrootControlBuildAction(captured,{contract,run:build.completion.run,job:build.completion.job,buildLog:build.buildLog,now:build.completion.observedMs});
    image={rootDigest:captured.outputDigest,configDigest:parse(captured.metadata)['containerimage.config.digest']};
   }
   same(captured,build.capture,'CiFutureControlCapture');same(completion,build.completion,'CiFutureControlCompletion');
   const value={rootDigest:image.rootDigest,configDigest:image.configDigest,contractHash:hash(contract),captureHash:hash(captured),completionHash:hash(completion),jobId:native?control.jobId:control.buildJobId,sourceTree:native?control.mainTree:control.sourceTree};
   current();controlBuildRef=await saveRecord('control-build',value);machine.bind(value);active=null;return Object.freeze({rootDigest:value.rootDigest,repositoryName:'mem9-on-aws/bootstrap',account:config.account,region:config.region});
  }catch(e){await hold();throw e;}},
  async beforeRead(action,input){try{current();need(!active,'CiFutureConcurrentRead');active={};const request=copyNonrootJson(input);if(!identitySeen)need(action==='GetCallerIdentity','CiFutureIdentityFirst');else if(!descriptorSeen)need(action==='GetParameters'&&hash(request)===hash({Names:[parameterName],WithDecryption:true}),'CiFutureDescriptorFirst');
   const chosen=machine.select(action,request),p=chosen.profile,controlSlot=controlWire&&isFutureControlCapacityProfile(p)?controlWire.admit(p):null,caps=controlSlot?.caps??{requestBytes:p.requestBytes,responseBytes:p.responseBytes,overshootBytes:UNKNOWN},index=reads.length+1,intentRef=await saveRecord('read-'+index,{version:1,index,profileIndex:chosen.index,action,request,requestHash:hash(request),caps:{requestBytes:caps.requestBytes,responseBytes:caps.responseBytes},ownerRefund:0});current();let dispatched=false,settled=false,charged=0;
   return Object.freeze({caps,finalGuard(){try{current();need(!dispatched&&!settled,'CiFutureDispatch');dispatched=true;}catch(e){held=true;throw e;}},charge(n){try{need(dispatched&&!settled&&integer(n),'CiFutureCharge');controlSlot?.charge(n);charged+=n;wire+=n;need(charged<=caps.requestBytes+caps.responseBytes+UNKNOWN&&wire<=paid.budget.httpBodyBytes,'CiFutureChargeCap');}catch(e){held=true;throw e;}},async complete(response,responseHash){try{current();need(dispatched&&!settled&&hex(responseHash)&&charged<=caps.requestBytes+caps.responseBytes,'CiFutureCompletion');const value=project(action,response,request,config);machine.complete(chosen.index,request,value);if(action==='GetCallerIdentity')identitySeen=true;if(action==='GetParameters'&&request.Names.includes(parameterName))descriptorSeen=true;
    if(action==='S3BlobGet')need('sha256:'+responseHash===request.layerDigest,'CiFutureBlobHash');
    const resultRef=await saveRecord('result-'+index,{version:1,index,responseHash,charged,value,ownerRefund:0});reads.push({intentRef,resultRef});controlSlot?.complete();settled=true;active=null;
   }catch(e){await hold();throw e;}},async unknown(){if(settled)return;controlSlot?.unknown();settled=true;active=null;await hold();}});
  }catch(e){await hold();throw e;}},
  reserveLocal(value){try{current();need(descriptorSeen,'CiFutureDescriptorFirst');return usage.charge(value);}catch(e){held=true;usage.close();throw e;}},
  hold,
  async finish({bundleRef,resourceReceiptRef}={}){try{current();need(!active&&identitySeen&&descriptorSeen&&bundleRef,'CiFutureIncomplete');let ref=bundleRef,bundle;if(Object.hasOwn(bundleRef,'value')){exact(bundleRef,['value','canonicalHash']);bundle=bundleRef.value;need(hash(bundle)===bundleRef.canonicalHash,'CiFutureBundleHash');ref=await saveRecord('bundle',bundle);}else bundle=await read(bundleRef);
   bundleCheck(bundle,config,scope,sourceRef,openedMs,now());same(bundle.source,source,'CiFutureBundleSource');const requiresResources=Boolean(bundle.controlCache)||paid.profiles.some(p=>p.kind==='CONTROL_ARTIFACT_FROM_AUTHENTICATED_BUILD'&&p.late.artifact!=='private-capsule');
   if(requiresResources){need(bundle.controlCache&&resourceReceiptRef&&resourceAllocation&&sealedResourceRef,'CiFutureResourcesRequired');same(resourceReceiptRef,sealedResourceRef,'CiFutureResourceReceipt');await verifyControlResources({env,resourceReceiptRef,expected:{...resourceExpected,bundleRef:ref,controlCache:bundle.controlCache}});}else need(!resourceReceiptRef&&!resourceAllocation,'CiFutureResourcesUnexpected');
   current();const localRef=usage.finish();closed=true;
   need(!paid.rootRequest||rootExchangeRef,'CiFutureRootRequestIncomplete');
   const receiptRef=await saveRecord('complete',{version:rootExchangeRef?3:requiresResources?2:1,kind:'ci-future-acquisition-complete',claimRef,requestRef,allowanceRef,handshakeRefs,controlRef,controlBuildRef,reads,localRef,localUsed:usage.used,bundleRef:ref,observedWireBytes:wire,completedMs:now(),ownerRefund:0,...(requiresResources?{resourceReceiptRef}: {}),...(rootExchangeRef?{rootExchangeRef}:{})});
   if(requiresResources)await linkControlResourceCompletion({env,resourceReceiptRef,completionRef:receiptRef});return {authority:false,receiptRef};
  }catch(e){await hold();throw e;}},
 });
}

/** Same-job local adoption of a successful completed slot. This does not call
 * GitHub/AWS, reopen the startup capability, or add another funding counter. */
export async function openFutureCiSmokeLocalReplay({env,completionRef,bundleRef,knownParameter}){
 let rootSnapshot,rootReplayConsume,earlyLocalClaimRef,earlyLocalPrefix,earlyLocalDirectory;
 try{
 need(env.GITHUB_JOB==='deploy-prod'&&env.STAGE==='prod','CiFutureLocalJob');const configRaw=env.MEM9_CI_ACQUISITION_CONFIG;need(typeof configRaw==='string'&&Buffer.byteLength(configRaw)<=65536,'CiFutureConfigRequired');const config=inspectFutureAcquisitionConfig(parse(configRaw)),done=await read(completionRef);
 exact(done,['version','kind','claimRef','requestRef','allowanceRef','handshakeRefs','controlRef','controlBuildRef','reads','localRef','localUsed','bundleRef','observedWireBytes','completedMs','ownerRefund',...(done.version>=2?['resourceReceiptRef']:[]),...(done.version===3?['rootExchangeRef']:[])]);need([1,2,3].includes(done.version)&&done.kind==='ci-future-acquisition-complete'&&done.ownerRefund===0,'CiFutureLocalCompletion');same(done.bundleRef,bundleRef,'CiFutureLocalBundle');
 const claim=await read(done.claimRef);exact(claim,['version','kind','scope','binding','startupReceipt','sourceReceiptRef','configHash','openedMs','expiresMs','requestHash','ownerRefund']);need(claim.version===1&&claim.kind==='ci-future-acquisition-claim'&&claim.ownerRefund===0&&claim.configHash===sha(configRaw),'CiFutureLocalClaim');
 const scope=claim.scope,selected=futureAcquisitionScope(config,scope);need(scope.kind==='target'&&scope.route==='deploy-prod'&&['preconfigure','presst'].includes(scope.phase)&&scope.checkpoint===(scope.phase==='presst'?'deploy-prod/19':'deploy-prod/17'),'CiFutureLocalCheckpoint');
 const source=await read(claim.sourceReceiptRef),bundle=await read(bundleRef),request=await read(done.requestRef),response=await read(done.allowanceRef);currentSource(env,source,config,scope,Date.now());
 const binding=makeCiStartupRunBinding(config.startup,bundle.source);same(binding,claim.binding,'CiFutureLocalBinding');
 exact(request,['version','kind','bindingHash','scope','nonce','artifactId','artifactDigest','sourceReceiptHash']);
 same(request,{version:1,kind:'ci-prepaid-acquisition-request',bindingHash:hash(binding),scope,nonce:claim.startupReceipt.nonce,artifactId:claim.startupReceipt.artifactId,artifactDigest:claim.startupReceipt.artifactDigest,sourceReceiptHash:claim.sourceReceiptRef.sha256},'CiFutureLocalRequest');need(hash(request)===claim.requestHash,'CiFutureLocalRequest');
 need(lstatSync(done.allowanceRef.path).size<=selected.responseBytes,'CiFutureLocalResponseCap');
 const accepted=verifyFutureAllowance(response,{config,scope,startupReceipt:claim.startupReceipt,binding,requestHash:claim.requestHash,maximumExpiresMs:Math.min(source.expiresMs,claim.expiresMs),now:Date.now()}),paid=accepted.consumer;
 const rootQuote=paid.rootRequest?.version===2?verifyProspectiveCiRootRequestPolicy(paid.rootRequest,scope):null;
 const parameter=Object.fromEntries(['Name','Type','ARN','Version','Value'].map(k=>[k,knownParameter?.[k]]));same(bundle.parameter,parameter,'CiFutureLocalParameter');const phase=bundleCheck(bundle,config,scope,claim.sourceReceiptRef,claim.openedMs,Date.now());
 const requiresResources=Boolean(bundle.controlCache)||paid.profiles.some(p=>p.kind==='CONTROL_ARTIFACT_FROM_AUTHENTICATED_BUILD'&&p.late.artifact!=='private-capsule');
 need(requiresResources?done.version>=2&&bundle.controlCache:done.version===1,'CiFutureResourcesRequired');need(Boolean(paid.rootRequest)===(done.version===3),'CiFutureRootReplayRequired');
 if(requiresResources){const image=bundle.deploymentSource?.deployedControlBuild?.image;need(image&&done.controlBuildRef,'CiFutureResourcesRequired');await verifyControlResources({env,resourceReceiptRef:done.resourceReceiptRef,completionRef,expected:{claimRef:done.claimRef,scope,bindingHash:hash(binding),sourceReceiptRef:claim.sourceReceiptRef,configHash:claim.configHash,run:{repository:source.current.repository,runId:source.current.runId,runAttempt:source.current.runAttempt,jobKey:source.current.job,revision:source.current.revision},rootDigest:image.rootDigest,configDigest:image.configDigest,bundleRef,controlCache:bundle.controlCache}});}
 need(positive(done.completedMs)&&done.completedMs>=claim.openedMs&&done.completedMs<=Date.now(),'CiFutureLocalTime');
 const dir=await directory(env),prefix='target-'+hash({bindingHash:hash(binding),scope}),refs=[completionRef,done.claimRef,done.requestRef,done.allowanceRef,done.localRef,claim.sourceReceiptRef,bundleRef],expectedNames=new Set([prefix+'-complete.json',prefix+'-claim.json',prefix+'-request.json',prefix+'-allowance.json',prefix+'-local.ndjson']);
 for(const [ref,suffix]of [[completionRef,'complete.json'],[done.claimRef,'claim.json'],[done.requestRef,'request.json'],[done.allowanceRef,'allowance.json'],[done.localRef,'local.ndjson']])need(ref.path===join(dir,prefix+'-'+suffix),'CiFutureLocalPath');
 need(Array.isArray(done.handshakeRefs)&&done.handshakeRefs.length>=2&&done.handshakeRefs.length<=13,'CiFutureLocalHandshake');
 for(const [i,pair]of done.handshakeRefs.entries()){
  exact(pair,['intent','result']);const a=await read(pair.intent),r=await read(pair.result),action=i===0?'PutObject':'GetObject';
  exact(a,['version','index','action','requestHash','ownerRefund']);exact(r,['version','index','status','responseHash','requestBytes','responseBytes','unknown','ownerRefund']);
  need(a.version===1&&r.version===1&&a.index===i+1&&r.index===i+1&&a.action===action&&a.ownerRefund===0&&r.ownerRefund===0&&r.unknown===false&&hex(r.responseHash),'CiFutureLocalHandshake');
  need(a.requestHash===hash(i===0?request:{Bucket:selected.bucket,Key:selected.responseKey,ExpectedBucketOwner:selected.expectedBucketOwner}),'CiFutureLocalHandshake');
  need((i===0||i===done.handshakeRefs.length-1?r.status===200:[403,404].includes(r.status))&&integer(r.requestBytes)&&r.requestBytes===(i===0?Buffer.byteLength(JSON.stringify(request)):0)&&integer(r.responseBytes)&&r.responseBytes<=(i===0||[403,404].includes(r.status)?16384:selected.responseBytes),'CiFutureLocalHandshake');
  if(i===done.handshakeRefs.length-1)need(r.responseHash===done.allowanceRef.sha256&&r.responseBytes===lstatSync(done.allowanceRef.path).size,'CiFutureLocalHandshake');
  for(const [ref,suffix]of [[pair.intent,'handshake-intent-'],[pair.result,'handshake-result-']]){const name=prefix+'-'+suffix+(i+1)+'.json';need(ref.path===join(dir,name),'CiFutureLocalPath');expectedNames.add(name);refs.push(ref);}
 }
 let control=null;if(done.controlRef){
  if(fundedComposition(accepted.funded))control=compositionCommitment(await read(done.controlRef),binding,accepted.funded);
  else{control=inspectControlBuildCommitment(await read(done.controlRef));need(control.runId===binding.source.runId&&control.runAttempt===binding.source.runAttempt&&control.sourceRevision===binding.source.mainRevision&&control.sourceTree===binding.source.mainTree,'CiFutureLocalControl');}
  need(done.controlRef.path===join(dir,prefix+'-control.json'),'CiFutureLocalPath');expectedNames.add(prefix+'-control.json');refs.push(done.controlRef);
 }
 const machine=profileMachine(paid.profiles,config,control,()=>{},paid.controlCapacity),controlWire=paid.controlCapacity?createFutureControlWireMeter(paid.controlCapacity):null;need(Array.isArray(done.reads)&&done.reads.length>=2&&done.reads.length<=65536,'CiFutureLocalReads');let wire=0,who=false,live=false,rootArchiveHash,rootReads=0,rootPaid;
 if(done.rootExchangeRef){
  if(rootQuote){
   rootPaid=replayLocal(done.localRef,zero(),paid.localBudget,{...zero(),logicalBytes:rootQuote.roundedLocalBytes});same(rootPaid.used,done.localUsed,'CiFutureLocalUsage');need(rootPaid.matches.length>0,'CiFutureRootPrepayment');
   earlyLocalDirectory=dir;earlyLocalPrefix=prefix+'-local-replay-'+(scope.phase==='presst'?'sst':'configure');
   earlyLocalClaimRef=await save(dir,earlyLocalPrefix+'-claim',{version:1,kind:'ci-future-local-replay',completionRef,bundleRef,scope,startingLocalUsed:rootPaid.used,expiresMs:Math.min(claim.expiresMs,source.expiresMs,config.startup.notAfter,accepted.expiresMs,phase.expiresMs),ownerRefund:0});
   let consumed=0;
   rootReplayConsume=n=>{need(integer(n)&&consumed+n<=rootQuote.work.replay,'CiFutureRootReplayBudget');consumed+=n;};
   rootSnapshot=createCiRootReplaySnapshot({directory:dir,prefix,scope,consume:rootReplayConsume});
  }
  need(done.rootExchangeRef.path===join(dir,prefix+'-root-exchange-complete.json'),'CiFutureLocalPath');if(!rootSnapshot)refs.push(done.rootExchangeRef);expectedNames.add(prefix+'-root-exchange-complete.json');
  const exchange=rootSnapshot?parse(rootSnapshot.read(done.rootExchangeRef)):await read(done.rootExchangeRef);exact(exchange,['version','archiveHash','requestRef','observedWireBytes','records',...(rootQuote?['localAccountingRef']:[])]);need(exchange.version===(rootQuote?2:1)&&hex(exchange.archiveHash)&&Array.isArray(exchange.records)&&exchange.records.length<=4+3*CI_ROOT_REQUEST_POLICY.readyCalls,'CiFutureRootReplay');
  const rows=[];for(const r of exchange.records){exact(r,['name','ref']);need(/^(?:root-request|root-put-(?:intent|dispatch|complete)|root-ready-[1-9][0-9]*-(?:intent|response|complete))$/.test(r.name)&&r.ref.path===(rootQuote?r.name+'.json':join(dir,prefix+'-'+r.name+'.json')),'CiFutureRootReplayPath');
   const physicalRef=rootQuote?{path:join(dir,prefix+'-'+r.ref.path),sha256:r.ref.sha256}:r.ref;
   const bytes=rootSnapshot?rootSnapshot.read(physicalRef):await smokePrivateRead(r.ref.path,CI_ROOT_REQUEST_POLICY.requestBytes);rows.push({name:r.name,ref:r.ref,bytes});if(!rootSnapshot)refs.push(r.ref);need(!expectedNames.has(prefix+'-'+r.name+'.json'),'CiFutureRootReplayDuplicate');expectedNames.add(prefix+'-'+r.name+'.json');
  }
  if(rootQuote){
   need(exchange.localAccountingRef.path==='root-local-accounting.json','CiFutureRootReplayPath');expectedNames.add(prefix+'-root-local-accounting.json');
   const accounting=parse(rootSnapshot.read({path:join(dir,prefix+'-'+exchange.localAccountingRef.path),sha256:exchange.localAccountingRef.sha256}));exact(accounting,['version','claimRef','scopeHash','catalogHash','debitSequence','journalPrefixHash','debit','checkpoints']);
   need(accounting.version===1&&rootPaid.matches.some(r=>r.sequence===accounting.debitSequence&&r.prefixHash===accounting.journalPrefixHash),'CiFutureRootPrepayment');
   same(accounting.claimRef,done.claimRef,'CiFutureRootPrepayment');need(accounting.scopeHash===hash(scope)&&accounting.catalogHash===hash(rootQuote),'CiFutureRootPrepayment');
   const accountingResult=verifyCiRootCostCheckpoints(accounting.checkpoints,{claimRef:done.claimRef,scopeHash:hash(scope),requestHash:exchange.requestRef.sha256,debit:accounting.debit},{checkpoint:scope.checkpoint});need(!accountingResult.held,'CiFutureRootPrepayment');
   rootReplayConsume(rootQuote.replay.decoderLocalBytes);
  }
  const verified=verifyCiRootExchange(exchange,rows,{config,scope,binding,startupReceipt:claim.startupReceipt,openedMs:claim.openedMs,completedMs:done.completedMs,deadlineMs:Math.min(claim.expiresMs,accepted.expiresMs),deploymentSource:bundle.deploymentSource,...(rootQuote?{rootPolicy:paid.rootRequest}:{})});
  wire+=verified.observedWireBytes;rootArchiveHash=verified.archiveHash;
 }
 if(done.controlBuildRef){const built=await read(done.controlBuildRef),deployed=bundle.deploymentSource?.deployedControlBuild;need(deployed&&built.rootDigest===deployed.image.rootDigest&&built.configDigest===deployed.image.configDigest&&built.contractHash===deployed.contractHash&&built.jobId===deployed.workflow.jobId&&built.sourceTree===deployed.source.tree,'CiFutureLocalControlBuild');machine.bind(built);need(done.controlBuildRef.path===join(dir,prefix+'-control-build.json'),'CiFutureLocalPath');expectedNames.add(prefix+'-control-build.json');refs.push(done.controlBuildRef);}
 for(const [i,pair]of done.reads.entries()){
  exact(pair,['intentRef','resultRef']);const intent=await read(pair.intentRef),result=await read(pair.resultRef);exact(intent,['version','index','profileIndex','action','request','requestHash','caps','ownerRefund']);exact(result,['version','index','responseHash','charged','value','ownerRefund']);
  need(intent.version===1&&result.version===1&&intent.index===i+1&&result.index===i+1&&intent.ownerRefund===0&&result.ownerRefund===0&&hex(result.responseHash)&&hash(intent.request)===intent.requestHash,'CiFutureLocalRead');
  if(!who)need(intent.action==='GetCallerIdentity','CiFutureIdentityFirst');else if(!live)need(intent.action==='GetParameters'&&hash(intent.request)===hash({Names:[parameterName],WithDecryption:true}),'CiFutureDescriptorFirst');
  const choice=machine.select(intent.action,intent.request);need(choice.index===intent.profileIndex,'CiFutureLocalProfile');const capacitySlot=controlWire&&isFutureControlCapacityProfile(choice.profile)?controlWire.admit(choice.profile):null,caps=capacitySlot?.caps??choice.profile;same(intent.caps,{requestBytes:caps.requestBytes,responseBytes:caps.responseBytes},'CiFutureLocalCaps');
  need(integer(result.charged)&&result.charged<=intent.caps.requestBytes+intent.caps.responseBytes,'CiFutureLocalCharge');capacitySlot?.charge(result.charged);capacitySlot?.complete();wire+=result.charged;
  if(choice.profile.kind==='OWNER_ROOT_ARTIFACT_FROM_FUNDED_CHECKPOINT'){need(++rootReads===1&&rootArchiveHash&&result.responseHash===rootArchiveHash,'CiFutureRootReplayArchive');}
  const value=project(intent.action,result.value,intent.request,config);same(value,result.value,'CiFutureLocalProjection');machine.complete(choice.index,intent.request,value);if(intent.action==='S3BlobGet')need('sha256:'+result.responseHash===intent.request.layerDigest,'CiFutureBlobHash');if(intent.action==='GetCallerIdentity')who=true;if(intent.action==='GetParameters'&&intent.request.Names.includes(parameterName))live=true;
  for(const[ref,suffix]of [[pair.intentRef,'read-'],[pair.resultRef,'result-']]){const name=prefix+'-'+suffix+(i+1)+'.json';need(ref.path===join(dir,name),'CiFutureLocalPath');expectedNames.add(name);refs.push(ref);}
 }
 need(who&&live&&wire===done.observedWireBytes&&wire<=paid.budget.httpBodyBytes&&(!paid.rootRequest||rootReads===1),'CiFutureLocalCharge');const used=rootPaid?.used??replayLocal(done.localRef,zero(),paid.localBudget);same(used,done.localUsed,'CiFutureLocalUsage');
 if(bundleRef.path===join(dir,prefix+'-bundle.json'))expectedNames.add(prefix+'-bundle.json');
 const names=(await readdir(dir)).filter(n=>n.startsWith(prefix+'-')&&!n.startsWith(prefix+'-local-replay-'));need(names.length===expectedNames.size&&names.every(n=>expectedNames.has(n)),'CiFutureLocalUnsettled');
 const expiresMs=Math.min(claim.expiresMs,source.expiresMs,config.startup.notAfter,accepted.expiresMs,phase.expiresMs),identity=hash(source.current),contextCheck=()=>{need(Date.now()<expiresMs&&env.MEM9_CI_ACQUISITION_CONFIG===configRaw,'CiFutureLocalExpired');currentSource(env,source,config,scope,Date.now());need(hash(source.current)===identity,'CiFutureLocalSource');},check=()=>{contextCheck();if(rootQuote)rootReplayConsume(rootQuote.journal.rowBytes);for(const ref of refs)immutable(ref);};check();
 const localPrefix=prefix+'-local-replay-'+(scope.phase==='presst'?'sst':'configure'),claimRef=earlyLocalClaimRef??await save(dir,localPrefix+'-claim',{version:1,kind:'ci-future-local-replay',completionRef,bundleRef,scope,startingLocalUsed:used,expiresMs,ownerRefund:0}),usage=localJournal(join(dir,localPrefix+'.ndjson'),used,paid.localBudget);let closed=false;
 const current=()=>{need(!closed,'CiFutureLocalClosed');check();};return Object.freeze({authority:false,expiresMs,...(paid.controlCapacity?{controlCapacity:paid.controlCapacity}:{}),reserveLocal(value){try{current();return usage.charge(value);}catch(e){closed=true;usage.close();rootSnapshot?.close();throw e;}},async finish(){try{current();if(rootSnapshot){rootSnapshot.finish();contextCheck();}
  const capture=config.version===3&&scope.phase==='presst';if(capture)usage.charge({...zero(),logicalBytes:NONROOT_POSTAPPLY_LIMITS.captureLocalBytes});
  const localRef=usage.finish();closed=true;
  if(capture)await writePostApplyCaptureAllocation({env,config,binding,scope,localRef,claimRef,localBudget:paid.localBudget,localUsed:usage.used,expiresMs});
  return {authority:false,receiptRef:await save(dir,localPrefix+'-complete',{version:1,kind:'ci-future-local-complete',claimRef,completionRef,bundleRef,localRef,localUsed:usage.used,ownerRefund:0,completedMs:Date.now()})};}catch(e){closed=true;usage.close();rootSnapshot?.close();try{await save(dir,localPrefix+'-held',{version:1,claimRef,ownerRefund:0});}catch(writeError){if(writeError.code!=='EEXIST')throw writeError;}throw e;}},async hold(){closed=true;usage.close();rootSnapshot?.close();try{await save(dir,localPrefix+'-held',{version:1,claimRef,ownerRefund:0});}catch(e){if(e.code!=='EEXIST')throw e;}}});
 }catch(e){rootSnapshot?.close();if(earlyLocalClaimRef)try{await save(earlyLocalDirectory,earlyLocalPrefix+'-held',{version:1,claimRef:earlyLocalClaimRef,ownerRefund:0});}catch(writeError){if(writeError.code!=='EEXIST')throw writeError;}throw e;}
}
