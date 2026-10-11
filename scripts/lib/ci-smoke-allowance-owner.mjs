/** One prepaid owner checkpoint. Artifact discovery is GitHub-only; the
 * durable checkpoint start precedes every AWS call. No uncertain AWS sequence
 * is resumed. The response is funding data, never deployment authority. */
import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {open,lstat,realpath,readdir} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {Readable} from 'node:stream';
import {Agent} from 'node:https';
import {crc32,inflateRawSync} from 'node:zlib';
import {STSClient,GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {S3Client,GetObjectCommand,PutObjectCommand} from '@aws-sdk/client-s3';
import {NodeHttpHandler} from '@smithy/node-http-handler';
import {copyNonrootJson,parseNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {ciOwnerPublicationPreparation} from './ci-smoke-startup-owner.mjs';
import {readCiOwnerPublishedRunBinding} from './ci-smoke-startup-owner-publisher.mjs';
import {ciStartupCheckpointSelection} from './ci-smoke-startup.mjs';
import {verifyFutureGrantSet,FUTURE_HANDSHAKE_POLICY} from './ci-smoke-grants.mjs';
import {inspectFutureAcquisitionConfig,futureAcquisitionScope,futureGrantExpectations} from './ci-smoke-future-config.mjs';
import {verifyFutureAllowance} from './ci-smoke-future-allowance.mjs';
import {smokePrivateRead} from './ci-smoke-host.mjs';
import {decodeNonrootPostApplyArtifact,inspectNonrootPostApplyIdentity,isNonrootPostApplyCheckpoint} from './nonroot-postapply.mjs';

const postApplyReceipts=new WeakMap();
const allowanceObservations=new WeakMap();
export function ciOwnerAllowanceObservation(receipt){const s=allowanceObservations.get(receipt);need(s&&Date.now()<s.expiresMs,'CiOwnerAllowanceReceipt');return copyNonrootJson(s);}
export function ciOwnerPostApplyDeployment(receipt){const s=postApplyReceipts.get(receipt);need(s&&Date.now()<s.expiresMs,'CiOwnerPostApplyReceipt');return copyNonrootJson(s);}

const fail=code=>{throw Object.assign(Error(code),{code,hold:true});};
const need=(v,code='CiAllowanceOwnerInvalid')=>{if(!v)fail(code);};
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'CiAllowanceOwnerFields');
const positive=n=>Number.isSafeInteger(n)&&n>0;
const hex=s=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s);
const sha=b=>createHash('sha256').update(b).digest('hex');
const raw=v=>Buffer.from(JSON.stringify(v));
const same=(a,b,code='CiAllowanceOwnerBinding')=>need(hash(a)===hash(b),code);
const parse=(b,max=1048576)=>parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(b),{maxBytes:max});
const bytes=b=>b===undefined?Buffer.alloc(0):typeof b==='string'?Buffer.from(b):b instanceof Uint8Array?Buffer.from(b):fail('CiAllowanceOwnerBody');

async function journal(path,prefix,chargeLocal){
 need(typeof path==='string'&&resolve(path)===path&&await realpath(path)===path,'CiAllowanceOwnerDirectory');
 const original=await lstat(path);
 const check=async()=>{const s=await lstat(path);need(await realpath(path)===path&&s.isDirectory()&&s.uid===process.getuid()&&(s.mode&511)===448&&s.ino===original.ino&&s.dev===original.dev,'CiAllowanceOwnerDirectory');};
 await check();
 const save=async(name,value)=>{
  await check();const data=Buffer.isBuffer(value)?value:raw(value);need(data.length<=1048576,'CiAllowanceOwnerRecordLimit');chargeLocal?.(data.length);const file=join(path,prefix+name),fd=await open(file,'wx',0o600);
  try{await fd.writeFile(data);await fd.sync();}finally{await fd.close();}
  const d=await open(path,'r');try{await d.sync();}finally{await d.close();}await check();return {path:file,sha256:sha(data)};
 };
 const read=async(name,ref)=>{
  await check();const file=join(path,prefix+name);if(ref){exact(ref,['path','sha256']);need(ref.path===file&&hex(ref.sha256),'CiAllowanceOwnerReference');}
  const data=await smokePrivateRead(file,1048576,chargeLocal);if(ref)need(sha(data)===ref.sha256,'CiAllowanceOwnerRecordChanged');await check();
  return {bytes:data,value:name.endsWith('.json')?parse(data):undefined,ref:{path:file,sha256:sha(data)}};
 };
 return {save,read,check,names:async()=>(await readdir(path)).filter(n=>n.startsWith(prefix)).map(n=>n.slice(prefix.length))};
}

function githubTransport(env,deadline){
 const childEnv={PATH:'/usr/bin:/bin',HOME:env.HOME,GH_HOST:'github.com',GH_PROMPT_DISABLED:'1',GH_PAGER:''};
 for(const key of ['GH_CONFIG_DIR','XDG_CONFIG_HOME','GH_TOKEN','GITHUB_TOKEN'])if(typeof env[key]==='string'&&env[key])childEnv[key]=env[key];
 return ({path,method='GET',body,binary=false})=>new Promise((resolve,reject)=>{
  const remaining=deadline-Date.now();if(remaining<=0)return reject(Error('CiAllowanceOwnerExpired'));
  need(['GET','POST'].includes(method)&&(!binary||method==='GET')&&(!body||raw(body).length<=4096),'CiAllowanceOwnerGithubRequest');
  const child=execFile('/usr/bin/gh',['api','--hostname','github.com','--method',method,path,...(body?['--input','-']:[])],{env:childEnv,encoding:'buffer',maxBuffer:binary?65536:1048576,timeout:Math.min(30000,remaining),killSignal:'SIGKILL'},(error,out)=>{
   if(error)return reject(Error('CiAllowanceOwnerGithubHeld'));try{resolve(binary?out:parse(out));}catch{reject(Error('CiAllowanceOwnerGithubBody'));}
  });child.stdin.end(body?JSON.stringify(body):undefined);
 });
}

/** Parse the single tiny ZIP member without extracting paths. Both stored and
 * deflated official archives are bounded before decompression; ZIP64, links,
 * additional members, encryption, trailing data and ambiguous sizes fail. */
function artifactPayload(input){
 const b=bytes(input);need(b.length>=120&&b.length<=65536,'CiAllowanceArtifactZip');const end=b.length-22;
 need(b.readUInt32LE(end)===0x06054b50&&b.readUInt16LE(end+4)===0&&b.readUInt16LE(end+6)===0&&b.readUInt16LE(end+8)===1&&b.readUInt16LE(end+10)===1&&b.readUInt16LE(end+20)===0,'CiAllowanceArtifactZip');
 const central=b.readUInt32LE(end+16),centralSize=b.readUInt32LE(end+12);
 need(central>=30&&central+centralSize===end&&central+46<=end&&b.readUInt32LE(central)===0x02014b50,'CiAllowanceArtifactZip');
 const flags=b.readUInt16LE(central+8),method=b.readUInt16LE(central+10),crc=b.readUInt32LE(central+16),packed=b.readUInt32LE(central+20),size=b.readUInt32LE(central+24),nameLength=b.readUInt16LE(central+28),extraLength=b.readUInt16LE(central+30),commentLength=b.readUInt16LE(central+32),mode=b.readUInt32LE(central+38)>>>16;
 need([0,8,0x800,0x808].includes(flags)&&[0,8].includes(method)&&size>0&&size<=1024&&packed<=65536&&b.readUInt16LE(central+34)===0&&b.readUInt32LE(central+42)===0&&commentLength===0&&extraLength===0&&nameLength===10&&central+46+nameLength===end,'CiAllowanceArtifactZip');
 need((mode&0xf000)===0||(mode&0xf000)===0x8000,'CiAllowanceArtifactZipType');
 need(b.subarray(central+46,central+56).toString()==='claim.json'&&b.readUInt32LE(0)===0x04034b50&&b.readUInt16LE(6)===flags&&b.readUInt16LE(8)===method&&b.readUInt16LE(26)===10&&b.readUInt16LE(28)===0&&b.subarray(30,40).toString()==='claim.json','CiAllowanceArtifactZip');
 const dataEnd=40+packed;need(dataEnd<=central,'CiAllowanceArtifactZip');
 if(flags&8){
  need(b.readUInt32LE(14)===0&&b.readUInt32LE(18)===0&&b.readUInt32LE(22)===0&&central-dataEnd===16&&b.readUInt32LE(dataEnd)===0x08074b50&&b.readUInt32LE(dataEnd+4)===crc&&b.readUInt32LE(dataEnd+8)===packed&&b.readUInt32LE(dataEnd+12)===size,'CiAllowanceArtifactZip');
 }else need(dataEnd===central&&b.readUInt32LE(14)===crc&&b.readUInt32LE(18)===packed&&b.readUInt32LE(22)===size,'CiAllowanceArtifactZip');
 const payload=method===0?b.subarray(40,dataEnd):inflateRawSync(b.subarray(40,dataEnd),{maxOutputLength:1024});
 need(payload.length===size&&crc32(payload)===crc,'CiAllowanceArtifactZipIntegrity');const value=parse(payload,1024);exact(value,['nonce','scopeHash']);need(hex(value.nonce)&&hex(value.scopeHash),'CiAllowanceArtifactPayload');return value;
}

const inboxName=(config,scope)=>'mem9-start-'+hash({grantSetId:config.startup.grantSetId,checkpoint:scope.checkpoint});
function artifactRun(run,binding,at){
 const source=binding.source;
 need(run.id===source.runId&&run.run_attempt===source.runAttempt&&run.head_sha===source.mainRevision&&run.head_branch==='main'&&run.event==='push'&&run.path===source.workflowPath&&run.repository?.full_name===source.repository&&run.status==='in_progress','CiAllowanceArtifactRun');
 const started=Date.parse(run.run_started_at);need(positive(started)&&started<=at,'CiAllowanceArtifactRunTime');return started;
}
function oldestArtifact(history,name){
 need(Array.isArray(history)&&history.length>0&&history.length<=100,'CiAllowanceArtifactHistory');const ids=new Set();
 for(const item of history){need(positive(item?.id)&&item.name===name&&!ids.has(item.id)&&positive(Date.parse(item.created_at)),'CiAllowanceArtifactHistory');ids.add(item.id);}
 return [...history].sort((a,b)=>Date.parse(a.created_at)-Date.parse(b.created_at)||a.id-b.id)[0];
}
async function githubRead(api,path,check){
 check();const value=copyNonrootJson(await api({method:'GET',path}));check();need(raw(value).length<=1048576,'CiAllowanceGithubLimit');return value;
}
async function chooseInbox({binding,scope,config,api,check}){
 const base='repos/'+binding.source.repository+'/',run=await githubRead(api,base+'actions/runs/'+binding.source.runId,check);artifactRun(run,binding,Date.now());
 const name=inboxName(config,scope),result=await githubRead(api,base+`actions/runs/${binding.source.runId}/artifacts?name=${encodeURIComponent(name)}&per_page=100&page=1`,check);
 need(Number.isSafeInteger(result.total_count)&&result.total_count>0&&result.total_count<=100&&Array.isArray(result.artifacts)&&result.artifacts.length===result.total_count,'CiAllowanceArtifactHistory');
 const picked=oldestArtifact(result.artifacts,name);return {run,history:result.artifacts,artifactId:picked.id,chosenMs:Date.now()};
}
function verifyChosenArtifact({binding,scope,config,confirmedMs,snapshot,metadata,finalRun,zip,observedMs}){
 need(positive(snapshot.chosenMs)&&snapshot.chosenMs<=observedMs&&observedMs<=Date.now(),'CiAllowanceArtifactTime');
 const runStartedMs=artifactRun(snapshot.run,binding,snapshot.chosenMs),name=inboxName(config,scope),picked=oldestArtifact(snapshot.history,name);
 need(snapshot.artifactId===picked.id,'CiAllowanceArtifactChoice');
 const fields=['id','name','size_in_bytes','digest','expired','created_at','expires_at','workflow_run'];
 const projection=a=>Object.fromEntries(fields.map(k=>[k,a[k]]));
 same(projection(picked),projection(metadata),'CiAllowanceArtifactChanged');
 const createdMs=Date.parse(metadata.created_at),expiresMs=Date.parse(metadata.expires_at);
 need(metadata.expired===false&&positive(metadata.size_in_bytes)&&metadata.size_in_bytes<=65536&&/^sha256:[a-f0-9]{64}$/.test(metadata.digest??'')&&positive(createdMs)&&createdMs>=runStartedMs&&createdMs>=Math.floor(confirmedMs/1000)*1000&&createdMs<=snapshot.chosenMs&&positive(expiresMs)&&expiresMs>=config.startup.notAfter,'CiAllowanceArtifactExpiry');
 need(metadata.workflow_run?.id===binding.source.runId&&metadata.workflow_run.head_sha===binding.source.mainRevision&&metadata.workflow_run.head_branch==='main','CiAllowanceArtifactRun');
 need(zip.length===metadata.size_in_bytes&&'sha256:'+sha(zip)===metadata.digest,'CiAllowanceArtifactDigest');const payload=artifactPayload(zip),bindingHash=hash(binding);
 need(payload.scopeHash===hash({bindingHash,scope}),'CiAllowanceArtifactScope');
 need(artifactRun(finalRun,binding,observedMs)===runStartedMs,'CiAllowanceArtifactRunTime');
 const receipt={bindingHash,scope,nonce:payload.nonce,scopeHash:payload.scopeHash,artifactId:metadata.id,artifactName:name,artifactDigest:metadata.digest.slice(7),notAfter:config.startup.notAfter};
 return {receipt,payload,zip,observations:{metadata,finalRun,observedMs}};
}
async function readChosenArtifact(options){
 const {binding,snapshot,api,archive,check}=options,base='repos/'+binding.source.repository+'/';
 const metadata=await githubRead(api,base+'actions/artifacts/'+snapshot.artifactId,check);
 check();const zip=bytes(await archive({method:'GET',path:base+'actions/artifacts/'+snapshot.artifactId+'/zip'}));check();
 const finalRun=await githubRead(api,base+'actions/runs/'+binding.source.runId,check);
 return verifyChosenArtifact({...options,metadata,zip,finalRun,observedMs:Date.now()});
}

function ownerCalls(kind,limit){
 const op=(purpose,action,requestBytes,responseBytes,count=1)=>({purpose,action,count,requestBytes,responseBytes,ecr:false});
 return [op('identity','GetCallerIdentity',1024,4096),op('create-claim','PutObject',16384,16384),...(kind==='target'?[op('request','GetObject',0,FUTURE_HANDSHAKE_POLICY.pendingBodyBytes,FUTURE_HANDSHAKE_POLICY.maxGetAttempts)]:[]),op('publish-response','PutObject',limit,16384),op('confirm-response','GetObject',0,limit)];
}
function requestPolling(claim,kind){
 if(kind!=='target'){need(!Object.hasOwn(claim,'requestPolling'),'CiAllowanceOwnerCatalog');return undefined;}
 const keys=['knownPendingStatuses','maxGetAttempts','maxKnownPendingAttempts','minKnownPendingPollMs','maxDurationMs','pendingBodyBytes'],policy=claim.requestPolling;
 exact(policy,['purpose',...keys]);same(policy,{purpose:'request',...Object.fromEntries(keys.map(k=>[k,FUTURE_HANDSHAKE_POLICY[k]]))},'CiAllowanceOwnerCatalog');return policy;
}
const oneAttempt=profile=>({...profile,count:1});
async function closeResponse(body){
 need(body instanceof Readable,'CiAllowanceOwnerResponse');body.destroy();if(body.closed)return;
 await new Promise((resolve,reject)=>{
  const done=()=>{clearTimeout(timer);resolve();},timer=setTimeout(()=>{body.off('close',done);reject(Object.assign(Error('CiAllowanceOwnerCleanup'),{code:'ECLEANUP'}));},1000);
  body.once('close',done);if(body.closed)done();
 });
}
function protectedObject(value,storage){need(value?.ServerSideEncryption==='aws:kms'&&value.SSEKMSKeyId===storage.kmsKeyArn&&value.BucketKeyEnabled===true&&typeof value.ETag==='string'&&value.ETag.length>0&&value.ETag.length<=256,'CiAllowanceObjectProtection');}
export function inspectCiOwnerTargetRequest(b,receipt,scope,bindingHash,config,binding){
 const post=config.version===3&&isNonrootPostApplyCheckpoint(scope),q=parse(b,16384);exact(q,['version','kind','bindingHash','scope','nonce','artifactId','artifactDigest','sourceReceiptHash',...(post?['postApply']:[])]);
 need(q.version===(post?2:1)&&q.kind==='ci-prepaid-acquisition-request'&&q.bindingHash===bindingHash&&q.nonce===receipt.nonce&&q.artifactId===receipt.artifactId&&q.artifactDigest===receipt.artifactDigest&&hex(q.sourceReceiptHash),'CiAllowanceOwnerTargetRequest');same(q.scope,scope);
 if(post)inspectNonrootPostApplyIdentity(decodeNonrootPostApplyArtifact(q.postApply),{binding,config,scope,now:Date.now()});return hash(q);
}
function identity(r,config,roleArn){
 const prefix=`arn:aws:sts::${config.account}:assumed-role/${roleArn.split('/').at(-1)}/`;
 need(r.Account===config.account&&r.Arn?.startsWith(prefix)&&/^[A-Za-z0-9+=,.@_-]{1,64}$/.test(r.Arn.slice(prefix.length)),'CiAllowanceOwnerCaller');
}
async function temporaryCredentials(ref,chargeLocal){
 exact(ref,['path','sha256']);need(hex(ref.sha256),'CiAllowanceCredentials');const b=await smokePrivateRead(ref.path,65536,chargeLocal);let value;
 try{
  need(sha(b)===ref.sha256,'CiAllowanceCredentials');value={...parse(b,65536)};exact(value,['accessKeyId','secretAccessKey','sessionToken','expiration']);
  need(/^ASIA[A-Z0-9]{16}$/.test(value.accessKeyId)&&typeof value.secretAccessKey==='string'&&value.secretAccessKey.length===40&&typeof value.sessionToken==='string'&&value.sessionToken.length>0&&value.sessionToken.length<=16384,'CiAllowanceCredentials');
  const expiresMs=Date.parse(value.expiration);need(positive(expiresMs)&&Date.now()<expiresMs,'CiAllowanceCredentialsExpired');
  return {value:{accessKeyId:value.accessKeyId,secretAccessKey:value.secretAccessKey,sessionToken:value.sessionToken},expiresMs};
 }finally{b.fill(0);if(value)for(const key of ['accessKeyId','secretAccessKey','sessionToken'])value[key]='';}
}

function winnerStatus(status,announcement,actorId){
 need(positive(status?.id)&&status.creator?.id===actorId&&Object.entries(announcement.payload).every(([k,v])=>status[k]===v),'CiAllowanceWinnerResponse');
}
async function winnerHistory(j,{announcement,announcementRef,claimConfirmedRef,actorId,confirmedMs},wanted){
 const names=(await j.names()).filter(n=>n.startsWith('winner-'));
 need(names.every(n=>/^winner-[1-3]-(intent|actor|post|response|complete|failed)\.json$/.test(n)),'CiAllowanceWinnerHistory');
 let completed,requested;
 for(let i=1;i<=3;i++){
  if(!names.some(n=>n.startsWith(`winner-${i}-`)))continue;
  need(Array.from({length:i},(_,k)=>`winner-${k+1}-intent.json`).every(n=>names.includes(n)),'CiAllowanceWinnerHistory');
  const attempt=await j.read(`winner-${i}-intent.json`),v=attempt.value;
  exact(v,['version','attempt','claimConfirmedRef','announcementRef','actorId','startedMs']);
  need(v.version===1&&v.attempt===i&&v.actorId===actorId&&positive(v.startedMs)&&v.startedMs>=confirmedMs,'CiAllowanceWinnerHistory');same(v.claimConfirmedRef,claimConfirmedRef);same(v.announcementRef,announcementRef);
  if(!names.includes(`winner-${i}-complete.json`))continue;
  const found=await j.read(`winner-${i}-complete.json`),c=found.value;
  exact(c,['version','attemptRef','actorRef','postRef','statusRef','completedMs']);same(c.attemptRef,attempt.ref);
  const actor=await j.read(`winner-${i}-actor.json`,c.actorRef),post=await j.read(`winner-${i}-post.json`,c.postRef),status=await j.read(`winner-${i}-response.json`,c.statusRef);
  exact(post.value,['version','attemptRef','announcementRef','postedMs']);same(post.value.attemptRef,attempt.ref);same(post.value.announcementRef,announcementRef);
  need(c.version===1&&actor.value.id===actorId&&post.value.version===1&&post.value.postedMs>=v.startedMs&&positive(c.completedMs)&&c.completedMs>=post.value.postedMs&&c.completedMs<=Date.now(),'CiAllowanceWinnerHistory');winnerStatus(status.value,announcement,actorId);
  if(wanted&&hash(wanted)===hash(found.ref))requested=found;
  completed??=found;
 }
 if(wanted){need(requested,'CiAllowanceWinnerHistory');return requested;}return completed;
}
async function publishWinner(j,state,{api,repository,check}){
 // This helper is entered only after the caller has verified the exact
 // conditional claim's durable known-200 receipt. It has no AWS method.
 const request=async q=>{check();const response=copyNonrootJson(await api(q));check();need(raw(response).length<=1048576,'CiAllowanceGithubLimit');return response;};
 for(let i=1;i<=3;i++){
  const completed=await winnerHistory(j,state);if(completed)return completed;
  let attemptRef;
  try{attemptRef=await j.save(`winner-${i}-intent.json`,{version:1,attempt:i,claimConfirmedRef:state.claimConfirmedRef,announcementRef:state.announcementRef,actorId:state.actorId,startedMs:Date.now()});}
  catch(e){if(e.code==='EEXIST')continue;throw e;}
  try{
   const actor=await request({method:'GET',path:'user'}),actorRef=await j.save(`winner-${i}-actor.json`,actor);need(actor.id===state.actorId,'CiAllowanceWinnerActor');
   const postRef=await j.save(`winner-${i}-post.json`,{version:1,attemptRef,announcementRef:state.announcementRef,postedMs:Date.now()});
   const status=await request({method:'POST',path:'repos/'+repository+'/'+state.announcement.path,body:state.announcement.payload}),statusRef=await j.save(`winner-${i}-response.json`,status);winnerStatus(status,state.announcement,state.actorId);
   const value={version:1,attemptRef,actorRef,postRef,statusRef,completedMs:Date.now()},ref=await j.save(`winner-${i}-complete.json`,value);return {value,ref};
  }catch(error){
   await j.save(`winner-${i}-failed.json`,{version:1,attemptRef,code:error.code==='CiAllowanceWinnerActor'?'CiAllowanceWinnerActor':'CiAllowanceWinnerDeliveryUnknown',failedMs:Date.now()});
   if(error.code==='CiAllowanceWinnerActor')throw error;
  }
 }
 const completed=await winnerHistory(j,state);if(completed)return completed;
 fail('CiAllowanceWinnerDeliveryHeld');
}

export async function respondCiOwnerAllowance(input,options={}){
 exact(input,['preparation','config','scope','grantSet','roleArn','credentialsRef','maximumExpiresMs']);need(Object.keys(options).every(k=>['env','githubApi','downloadArtifact','requestHandler','sleep','chargeLocal'].includes(k)),'CiAllowanceOwnerOptions');
 const sleep=options.sleep??(ms=>new Promise(resolve=>setTimeout(resolve,ms)));need(typeof sleep==='function','CiAllowanceOwnerOptions');
 const prepared=ciOwnerPublicationPreparation(input.preparation),config=inspectFutureAcquisitionConfig(input.config),selected=futureAcquisitionScope(config,input.scope),scope=selected.scope;
 same(config.startup,prepared.config);same({account:config.account,region:config.region,...config.ownerRoot},prepared.scope);
 const grantSet=copyNonrootJson(input.grantSet),roots=futureGrantExpectations(config),funded=verifyFutureGrantSet({grantSet,expected:roots});
 same(funded,prepared.funding);const claimBudget=funded.owner.claims.find(c=>c.checkpoint===scope.checkpoint);
 need(claimBudget,'CiAllowanceOwnerUnfunded');same(claimBudget.calls,ownerCalls(scope.kind,selected.responseBytes),'CiAllowanceOwnerCatalog');
 need(claimBudget.unknownOvershoots===1&&claimBudget.overshootBytes===8388608,'CiAllowanceOwnerCatalog');
 const polling=requestPolling(claimBudget,scope.kind),isPending=(purpose,status)=>Boolean(polling&&purpose===polling.purpose&&polling.knownPendingStatuses.includes(status));
 need(!funded.owner.delivery||typeof options.chargeLocal==='function','CiAllowanceDeliveryLocalRequired');
 const storage={...config.storage,roleArn:input.roleArn},published=await readCiOwnerPublishedRunBinding({preparation:input.preparation,storage},{chargeLocal:options.chargeLocal}),{binding,bindingHash}=published;
 need(positive(input.maximumExpiresMs),'CiAllowanceOwnerExpiry');const expiresMs=Math.min(input.maximumExpiresMs,config.startup.notAfter,funded.notAfter),durationMs=polling?.maxDurationMs??90000;
 need(Date.now()<expiresMs,'CiAllowanceOwnerExpired');
 const checkpointHash=hash(scope.checkpoint),j=await journal(funded.ownerStateDirectory,'checkpoint-'+checkpointHash+'-',options.chargeLocal);
 const fixedChoice={version:2,kind:'owner-ci-artifact-choice',bindingHash,publicationRef:published.confirmationRef,configHash:hash(config),scope,grantHash:config.startup.grantHash,budgetHash:hash(claimBudget),expiresMs};
 let choice,fresh=false,startRef,wire=0,secret,start,artifact,selection,postApply;
 const completedResult=value=>{const result=Object.freeze(value);allowanceObservations.set(result,{scope,binding,config,expiresMs,startupReceipt:artifact.receipt});if(postApply)postApplyReceipts.set(result,{artifact:postApply,scope,binding,config,expiresMs});return result;};
 try{choice=await j.read('choice.json');}catch(e){if(e.code!=='ENOENT')throw e;}
 if(!choice){
  need((await j.names()).length===0,'CiAllowanceOwnerHistoryMissing');const openedMs=Date.now(),deadlineMs=Math.min(expiresMs,openedMs+durationMs);
  const check=()=>need(Date.now()>=openedMs&&Date.now()<deadlineMs,'CiAllowanceOwnerExpired');
  const api=options.githubApi??githubTransport(options.env??process.env,deadlineMs);
  const snapshot=await chooseInbox({binding,scope,config,api,check}),value={...fixedChoice,snapshot,openedMs,deadlineMs};
  // This create-only choice fixes the candidate even if its subsequent ZIP
  // or metadata is invalid. Another invocation never searches for a substitute.
  choice={value,ref:await j.save('choice.json',value)};fresh=true;
 }
 const {snapshot,openedMs,deadlineMs,...fixed}=choice.value;same(fixed,fixedChoice,'CiAllowanceOwnerCheckpointConflict');
 need(positive(openedMs)&&positive(deadlineMs)&&openedMs>=funded.issuedMs&&openedMs<=snapshot.chosenMs&&snapshot.chosenMs<deadlineMs&&deadlineMs<=Math.min(expiresMs,openedMs+durationMs),'CiAllowanceOwnerHistory');
 const check=()=>need(Date.now()>=openedMs&&Date.now()<deadlineMs,'CiAllowanceOwnerExpired');
 const transport=githubTransport(options.env??process.env,deadlineMs),api=options.githubApi??transport,archive=options.downloadArtifact??(request=>transport({...request,binary:true}));
 const hold=async(code)=>{try{await j.save('held.json',{version:2,choiceRef:choice.ref,...(startRef?{startRef}:{}),code,observedBodyBytes:wire,prepaidBudget:claimBudget.budget,refund:0});}catch(e){if(e.code!=='EEXIST')throw e;}};
 const format=receipt=>ciStartupCheckpointSelection(config.startup,binding,scope,Object.fromEntries(['nonce','scopeHash','artifactId','artifactDigest'].map(k=>[k,receipt[k]])));
 if(fresh){
  try{
   artifact=await readChosenArtifact({binding,scope,config,confirmedMs:published.confirmedMs,snapshot,api,archive,check});selection=format(artifact.receipt);
   const artifactRefs={zipRef:await j.save('artifact.zip',artifact.zip),observationsRef:await j.save('artifact-observations.json',artifact.observations),receiptRef:await j.save('artifact-receipt.json',artifact.receipt)};
   const claimRef=await j.save('claim.json',selection.claim),announcementRef=await j.save('announcement.json',selection.announcement);
   check();secret=await temporaryCredentials(input.credentialsRef,options.chargeLocal);check();
   const value={version:2,kind:'owner-ci-checkpoint-start',choiceRef:choice.ref,artifactRefs,claimRef,announcementRef,selectionHash:hash(selection),startedMs:Date.now(),awsDeadlineMs:Math.min(deadlineMs,secret.expiresMs)};
   start={value,ref:await j.save('start.json',value)};startRef=start.ref;
  }catch(e){if(secret)Object.keys(secret.value).forEach(k=>secret.value[k]='');await hold(e.code??'CiAllowanceOwnerSelectionHeld');throw e;}
 }else{
  need(!(await j.names()).includes('held.json'),'CiAllowanceOwnerHeld');
  try{start=await j.read('start.json');}catch{fail('CiAllowanceOwnerHeld');}startRef=start.ref;
  exact(start.value,['version','kind','choiceRef','artifactRefs','claimRef','announcementRef','selectionHash','startedMs','awsDeadlineMs']);same(start.value.choiceRef,choice.ref);
  const refs=start.value.artifactRefs;exact(refs,['zipRef','observationsRef','receiptRef']);
  const zip=(await j.read('artifact.zip',refs.zipRef)).bytes,observations=(await j.read('artifact-observations.json',refs.observationsRef)).value;
  exact(observations,['metadata','finalRun','observedMs']);artifact=verifyChosenArtifact({binding,scope,config,confirmedMs:published.confirmedMs,snapshot,zip,...observations});
  same((await j.read('artifact-receipt.json',refs.receiptRef)).value,artifact.receipt);selection=format(artifact.receipt);
  same((await j.read('claim.json',start.value.claimRef)).value,selection.claim);same((await j.read('announcement.json',start.value.announcementRef)).value,selection.announcement);
 }
 const {startedMs,awsDeadlineMs}=start.value;
 need(start.value.version===2&&start.value.kind==='owner-ci-checkpoint-start'&&start.value.selectionHash===hash(selection)&&positive(startedMs)&&positive(awsDeadlineMs)&&startedMs>=snapshot.chosenMs&&startedMs<awsDeadlineMs&&awsDeadlineMs<=deadlineMs,'CiAllowanceOwnerHistory');
 const verifyResponse=(response,requestHash)=>verifyFutureAllowance(response,{config,scope,startupReceipt:artifact.receipt,binding,requestHash,maximumExpiresMs:expiresMs,now:Date.now()});
 async function verifyCalls(record,{claimOnly=false,response,winner}={}){
  need(Array.isArray(record.calls)&&record.calls.length<=(claimOnly?2:claimBudget.calls.reduce((n,c)=>n+c.count,0))&&positive(record.completedMs)&&record.completedMs>=startedMs&&record.completedMs<awsDeadlineMs,'CiAllowanceOwnerHistory');
  let observed=0,requestHash=hash(artifact.payload),written,profileIndex=0,attempts=0,retryAfterMs=0,requestSourceRef=start.value.artifactRefs.receiptRef,requestCompletedMs=winner?.value.completedMs??0,responseStartedMs;
  for(const [i,refs]of record.calls.entries()){
   const intent=(await j.read(`aws-${i+1}-intent.json`,refs.intentRef)).value,result=(await j.read(`aws-${i+1}-result.json`,refs.resultRef)).value;
   exact(refs,['intentRef','resultRef']);exact(intent,['version','startHash','caps','request','reservedMs']);exact(result,['version','intentHash','dispatchRef','status','requestBodyRef','responseBodyRef','response','completedMs']);
   const profile=claimBudget.calls[profileIndex];need(profile&&++attempts<=profile.count,'CiAllowanceOwnerHistory');
   const c=oneAttempt(profile),dispatch=(await j.read(`aws-${i+1}-dispatch.json`,result.dispatchRef)).value;
   exact(dispatch,['version','intentRef','requestBodyRef','method','host','path','requestBytes','dispatchedMs']);
   same(intent.caps,c,'CiAllowanceOwnerHistory');same(dispatch.intentRef,refs.intentRef,'CiAllowanceOwnerHistory');same(dispatch.requestBodyRef,result.requestBodyRef,'CiAllowanceOwnerHistory');
   const unreadable=isPending(c.purpose,result.status);
   need(intent.version===1&&result.version===1&&dispatch.version===1&&intent.startHash===startRef.sha256&&result.intentHash===refs.intentRef.sha256&&(result.status===200||unreadable)&&intent.reservedMs>=Math.max(startedMs,retryAfterMs)&&intent.reservedMs<=dispatch.dispatchedMs&&dispatch.dispatchedMs<=result.completedMs&&result.completedMs<=record.completedMs,'CiAllowanceOwnerHistory');
   const req=(await j.read(`aws-${i+1}-request.bin`,result.requestBodyRef)).bytes,res=(await j.read(`aws-${i+1}-response.bin`,result.responseBodyRef)).bytes;
   need(req.length===dispatch.requestBytes&&req.length<=c.requestBytes&&res.length<=c.responseBytes,'CiAllowanceOwnerHistory');observed+=req.length+res.length;
   const isSts=c.action==='GetCallerIdentity',key=c.purpose==='request'?selected.requestKey:c.purpose==='create-claim'?selected.responseKey.replace(/response\.json$/,'claim.json'):selected.responseKey;
   need(dispatch.method===(isSts?'POST':c.action==='PutObject'?'PUT':'GET')&&dispatch.host===`${isSts?'sts':'s3'}.${config.region}.amazonaws.com`&&dispatch.path===(isSts?'/':'/'+storage.bucket+'/'+key),'CiAllowanceOwnerHistory');
   if(isSts){same(intent.request,{});need(req.toString()==='Action=GetCallerIdentity&Version=2011-06-15','CiAllowanceOwnerHistory');identity(result.response,config,storage.roleArn);}
   else{
    need(intent.request.Bucket===storage.bucket&&intent.request.Key===key&&intent.request.ExpectedBucketOwner===config.account,'CiAllowanceOwnerHistory');
    if(!unreadable)protectedObject(result.response,storage);
    if(c.action==='GetObject'){exact(intent.request,['Bucket','Key','ExpectedBucketOwner']);need(req.length===0&&(unreadable?result.response===null:result.response.ContentLength===res.length),'CiAllowanceOwnerHistory');}
    else need(intent.request.IfNoneMatch==='*'&&intent.request.ServerSideEncryption==='aws:kms'&&intent.request.SSEKMSKeyId===storage.kmsKeyArn&&intent.request.BucketKeyEnabled===true&&intent.request.ContentLength===req.length&&intent.request.Body.sha256===sha(req)&&intent.request.Body.bytes===req.length,'CiAllowanceOwnerHistory');
   }
   if(['request','publish-response','confirm-response'].includes(c.purpose))need(winner&&intent.reservedMs>=winner.value.completedMs,'CiAllowanceWinnerOrder');
   if(unreadable){need(res.length<=polling.pendingBodyBytes&&attempts<=polling.maxKnownPendingAttempts,'CiAllowanceOwnerHistory');retryAfterMs=result.completedMs+polling.minKnownPendingPollMs;continue;}
   retryAfterMs=0;profileIndex++;attempts=0;
   if(c.purpose==='create-claim')need(req.equals(raw(selection.claim)),'CiAllowanceOwnerClaimHistory');
   if(c.purpose==='request'){requestHash=inspectCiOwnerTargetRequest(res,artifact.receipt,scope,bindingHash,config,binding);postApply=parse(res,16384).postApply;requestSourceRef=refs.resultRef;requestCompletedMs=result.completedMs;}
   if(c.purpose==='publish-response'){need(req.equals(response.bytes),'CiAllowanceOwnerHistory');written=result.response;responseStartedMs=intent.reservedMs;}
   if(c.purpose==='confirm-response')need(res.equals(response.bytes)&&result.response.ETag===written.ETag&&(result.response.VersionId??null)===(written.VersionId??null),'CiAllowanceOwnerHistory');
  }

  need(profileIndex===(claimOnly?2:claimBudget.calls.length)&&observed===record.observedBodyBytes&&observed<=claimBudget.budget.httpBodyBytes,'CiAllowanceOwnerHistory');
  return {requestHash,requestSourceRef,requestCompletedMs,responseStartedMs};
 }
 const winnerState=confirmed=>({announcement:selection.announcement,announcementRef:start.value.announcementRef,claimConfirmedRef:confirmed.ref,actorId:config.startup.ownerGithubActorId,confirmedMs:confirmed.value.confirmedMs});
 if(!fresh){
  let confirmed;try{confirmed=await j.read('claim-confirmed.json');}catch{fail('CiAllowanceOwnerHeld');}
  const c=confirmed.value;exact(c,['version','startRef','claimRef','selectionHash','calls','observedBodyBytes','confirmedMs']);
  need(c.version===2&&c.selectionHash===hash(selection),'CiAllowanceOwnerClaimHistory');same(c.startRef,startRef);same(c.claimRef,start.value.claimRef);
  await verifyCalls({...c,completedMs:c.confirmedMs},{claimOnly:true});
  const names=await j.names();
  if(names.includes('complete.json')){
   const complete=(await j.read('complete.json')).value;
   exact(complete,['version','startRef','claimConfirmedRef','winnerRef','requestObservationRef','responseRef','requestHash','calls','observedBodyBytes','completedMs']);
   need(complete.version===2,'CiAllowanceOwnerHistory');same(complete.startRef,startRef);same(complete.claimConfirmedRef,confirmed.ref);same(complete.calls.slice(0,2),c.calls);
   const winner=await winnerHistory(j,winnerState(confirmed),complete.winnerRef),response=await j.read('response.json',complete.responseRef);
   const observed=await verifyCalls(complete,{response,winner});need(complete.requestHash===observed.requestHash,'CiAllowanceOwnerHistory');verifyResponse(response.value,observed.requestHash);
   const request=(await j.read('request-observed.json',complete.requestObservationRef)).value;
   exact(request,['version','kind','startRef','claimRef','winnerRef','requestHash','requestSourceRef','observedMs']);
   same(request.startRef,startRef);same(request.claimRef,start.value.claimRef);same(request.winnerRef,winner.ref);same(request.requestSourceRef,observed.requestSourceRef);
   need(request.version===1&&request.kind==='owner-ci-request-observation'&&request.requestHash===observed.requestHash&&request.observedMs>=observed.requestCompletedMs&&request.observedMs<=observed.responseStartedMs,'CiAllowanceOwnerRequestHistory');
   return completedResult({phase:'owner-allowance-confirmed',responseRef:complete.responseRef,bindingHash,checkpointHash,expiresMs,awsCalls:0});
  }
  // A new invocation can only deliver the already fixed announcement. It
  // cannot continue any request/read/write portion of the original AWS run.
  need(!names.some(n=>/^aws-([3-9]|[1-9][0-9]+)-/.test(n)),'CiAllowanceOwnerHeld');check();need(Date.now()<awsDeadlineMs,'CiAllowanceOwnerAwsExpired');
  const winner=await publishWinner(j,winnerState(confirmed),{api,repository:binding.source.repository,check:()=>{check();need(Date.now()<awsDeadlineMs,'CiAllowanceOwnerAwsExpired');}});
  return Object.freeze({phase:'owner-winner-announced',claimRef:start.value.claimRef,winnerRef:winner.ref,bindingHash,checkpointHash,awsCalls:0});
 }
 let agent,http,sts,s3,current,nextProfile=0,profileAttempts=0;const calls=[],requests=new Set();
 const guard=async()=>{check();await j.check();need(Date.now()<awsDeadlineMs,'CiAllowanceOwnerAwsExpired');};
 try{
  agent=new Agent({keepAlive:false,maxSockets:1,rejectUnauthorized:true});http=options.requestHandler??new NodeHttpHandler({httpsAgent:agent,connectionTimeout:5000,requestTimeout:30000});
  const handler={async handle(request,sendOptions){
   await guard();const slot=current;need(slot&&!slot.dispatched,'CiAllowanceOwnerUnexpectedRequest');requests.add(request);
   const c=slot.caps,isSts=c.action==='GetCallerIdentity',expectedMethod=isSts?'POST':c.action==='PutObject'?'PUT':'GET',body=bytes(request.body),expectedBody=isSts?Buffer.from('Action=GetCallerIdentity&Version=2011-06-15'):bytes(slot.input.Body);
   need(request.protocol==='https:'&&!request.port&&request.hostname===`${isSts?'sts':'s3'}.${config.region}.amazonaws.com`&&request.method===expectedMethod&&request.path===(isSts?'/':'/'+storage.bucket+'/'+slot.input.Key),'CiAllowanceOwnerRequestScope');
   need(Object.keys(request.query??{}).every(k=>!isSts&&k==='x-id'&&request.query[k]===c.action),'CiAllowanceOwnerRequestQuery');
   need(body.equals(expectedBody)&&body.length<=c.requestBytes&&Buffer.byteLength(JSON.stringify(request.headers))<=32768,'CiAllowanceOwnerRequestLimit');
   if(!isSts)need(request.headers['x-amz-expected-bucket-owner']===config.account,'CiAllowanceOwnerBucket');
   if(c.action==='PutObject')need(request.headers['if-none-match']==='*'&&request.headers['x-amz-server-side-encryption']==='aws:kms'&&request.headers['x-amz-server-side-encryption-aws-kms-key-id']===storage.kmsKeyArn&&request.headers['x-amz-server-side-encryption-bucket-key-enabled']==='true','CiAllowanceOwnerPutScope');
   slot.requestBodyRef=await j.save(`aws-${slot.index}-request.bin`,body);
   slot.dispatchRef=await j.save(`aws-${slot.index}-dispatch.json`,{version:1,intentRef:slot.intentRef,requestBodyRef:slot.requestBodyRef,method:request.method,host:request.hostname,path:request.path,requestBytes:body.length,dispatchedMs:Date.now()});
   await guard();slot.dispatched=true;wire+=body.length;need(wire<=claimBudget.budget.httpBodyBytes,'CiAllowanceOwnerBudget');const result=await http.handle(request,sendOptions),r=result.response,stream=r?.body;
   need(stream&&typeof stream[Symbol.asyncIterator]==='function','CiAllowanceOwnerResponse');const chunks=[];let length=0;const abort=()=>stream.destroy?.(Error('CiAllowanceOwnerAborted'));
   sendOptions?.abortSignal?.addEventListener('abort',abort,{once:true});
   let returned;
   try{
    need(Buffer.byteLength(JSON.stringify(r.headers??{}))<=16384,'CiAllowanceOwnerResponseHeaders');
    for await(const chunk of stream){await guard();need(chunk instanceof Uint8Array,'CiAllowanceOwnerResponse');length+=chunk.length;wire+=chunk.length;need(length<=c.responseBytes&&wire<=claimBudget.budget.httpBodyBytes,'CiAllowanceOwnerResponseLimit');chunks.push(Buffer.from(chunk));}
    const b=Buffer.concat(chunks,length);if(r.headers?.['content-length']!==undefined)need(String(length)===r.headers['content-length'],'CiAllowanceOwnerResponseLength');
    slot.responseBodyRef=await j.save(`aws-${slot.index}-response.bin`,b);slot.body=b;slot.status=r.statusCode;await guard();returned={response:{...r,body:Readable.from([b])}};
   }finally{sendOptions?.abortSignal?.removeEventListener('abort',abort);await closeResponse(stream);}
   slot.received=true;return returned;
  },destroy(){}};
  const settings={region:config.region,credentials:secret.value,maxAttempts:1,ignoreConfiguredEndpointUrls:true,requestHandler:handler};
  sts=new STSClient({...settings,endpoint:`https://sts.${config.region}.amazonaws.com`});s3=new S3Client({...settings,endpoint:`https://s3.${config.region}.amazonaws.com`,forcePathStyle:true,followRegionRedirects:false,requestChecksumCalculation:'WHEN_REQUIRED',responseChecksumValidation:'WHEN_REQUIRED'});
  const send=async(purpose,client,command,validate)=>{
   await guard();const index=calls.length+1,profile=claimBudget.calls[nextProfile];need(profile?.purpose===purpose&&profileAttempts<profile.count,'CiAllowanceOwnerCallOrder');const caps=oneAttempt(profile);
   const request={...command.input};if(request.Body)request.Body={sha256:sha(request.Body),bytes:request.Body.length};
   const intentRef=await j.save(`aws-${index}-intent.json`,{version:1,startHash:startRef.sha256,caps,request,reservedMs:Date.now()});
   profileAttempts++;const slot=current={index,caps,input:command.input,intentRef,dispatched:false,received:false},signal=AbortSignal.timeout(Math.max(1,Math.min(30000,awsDeadlineMs-Date.now())));let out;
   try{
    try{out=await client.send(command,{abortSignal:signal});}
    catch(error){
     // Only a fully received, bounded negative HTTP response is retryable.
     // It says nothing about existence or authorization. SDK retries stay off.
     if(!(isPending(purpose,slot.status)&&slot.received&&slot.body.length<=polling.pendingBodyBytes&&!signal.aborted&&error.code!=='ECLEANUP'&&error.name!=='AbortError'))throw error;
    }
    await guard();signal.throwIfAborted();const unreadable=isPending(purpose,slot.status)&&slot.received;
    if(!unreadable){need(slot.received&&slot.status===200,'CiAllowanceOwnerHttpStatus');validate(out,slot.body);}
    const response=unreadable?null:JSON.parse(JSON.stringify(Object.fromEntries(Object.entries(out).filter(([k])=>k!=='Body')))),completedMs=Date.now();
    const resultRef=await j.save(`aws-${index}-result.json`,{version:1,intentHash:intentRef.sha256,dispatchRef:slot.dispatchRef,status:slot.status,requestBodyRef:slot.requestBodyRef,responseBodyRef:slot.responseBodyRef,response,completedMs});calls.push({intentRef,resultRef});
    if(!unreadable){nextProfile++;profileAttempts=0;}return {response:out,status:slot.status,completedMs};
   }finally{out?.Body?.destroy?.();current=undefined;}
  };
  const put=(key,b)=>new PutObjectCommand({Bucket:storage.bucket,Key:key,ExpectedBucketOwner:config.account,IfNoneMatch:'*',Body:b,ContentLength:b.length,ContentType:'application/json',ServerSideEncryption:'aws:kms',SSEKMSKeyId:storage.kmsKeyArn,BucketKeyEnabled:true,ChecksumAlgorithm:'SHA256',ChecksumSHA256:Buffer.from(sha(b),'hex').toString('base64')});
  await send('identity',sts,new GetCallerIdentityCommand({}),r=>identity(r,config,storage.roleArn));
  await send('create-claim',s3,put(selected.responseKey.replace(/response\.json$/,'claim.json'),raw(selection.claim)),r=>protectedObject(r,storage));
  await guard();const confirmation={version:2,startRef,claimRef:start.value.claimRef,selectionHash:hash(selection),calls:[...calls],observedBodyBytes:wire,confirmedMs:Date.now()};
  const confirmed={value:confirmation,ref:await j.save('claim-confirmed.json',confirmation)};
  const winner=await publishWinner(j,winnerState(confirmed),{api,repository:binding.source.repository,check:()=>{check();need(Date.now()<awsDeadlineMs,'CiAllowanceOwnerAwsExpired');}});
  await guard();
  const get=key=>new GetObjectCommand({Bucket:storage.bucket,Key:key,ExpectedBucketOwner:config.account});
  let requestHash=hash(artifact.payload),requestSourceRef=start.value.artifactRefs.receiptRef;
  if(scope.kind==='target')for(let attempt=1;attempt<=polling.maxGetAttempts;attempt++){
   const result=await send('request',s3,get(selected.requestKey),(r,b)=>{
    protectedObject(r,storage);need(r.ContentLength===b.length,'CiAllowanceOwnerRequestLength');requestHash=inspectCiOwnerTargetRequest(b,artifact.receipt,scope,bindingHash,config,binding);postApply=parse(b,16384).postApply;
   });
   if(result.status===200){requestSourceRef=calls.at(-1).resultRef;break;}
   need(attempt<=polling.maxKnownPendingAttempts&&attempt<polling.maxGetAttempts,'CiAllowanceOwnerRequestExhausted');
   const retryAt=result.completedMs+polling.minKnownPendingPollMs;need(retryAt<awsDeadlineMs,'CiAllowanceOwnerAwsExpired');await sleep(Math.max(0,retryAt-Date.now()));await guard();need(Date.now()>=retryAt,'CiAllowanceOwnerRetryDelay');
  }
  const requestObservationRef=await j.save('request-observed.json',{version:1,kind:'owner-ci-request-observation',startRef,claimRef:start.value.claimRef,winnerRef:winner.ref,requestHash,requestSourceRef,observedMs:Date.now()});
  const response={version:1,kind:'owner-ci-allowance-response',runBinding:binding,scope,nonce:artifact.receipt.nonce,artifactId:artifact.receipt.artifactId,requestHash,grantSet,expiresMs};verifyResponse(response,requestHash);
  const responseBytes=raw(response);need(responseBytes.length<=selected.responseBytes,'CiAllowanceOwnerEnvelope');const responseRef=await j.save('response.json',response);
  verifyResponse(response,requestHash);const {response:written}=await send('publish-response',s3,put(selected.responseKey,responseBytes),r=>protectedObject(r,storage));
  await send('confirm-response',s3,get(selected.responseKey),(r,b)=>{protectedObject(r,storage);need(b.equals(responseBytes)&&r.ContentLength===b.length&&r.ETag===written.ETag&&(r.VersionId??null)===(written.VersionId??null),'CiAllowanceOwnerReadback');verifyResponse(parse(b),requestHash);});
  await guard();await j.save('complete.json',{version:2,startRef,claimConfirmedRef:confirmed.ref,winnerRef:winner.ref,requestObservationRef,responseRef,requestHash,calls,observedBodyBytes:wire,completedMs:Date.now()});
  return completedResult({phase:'owner-allowance-confirmed',responseRef,bindingHash,checkpointHash,expiresMs,awsCalls:calls.length});
 }catch(error){if(error.code==='CiAllowanceWinnerDeliveryHeld')throw error;await hold(/^[A-Za-z][A-Za-z0-9_-]{0,100}$/.test(error.code??'')?error.code:'CiAllowanceOwnerOperationHeld');fail('CiAllowanceOwnerHeld');}
 finally{
  let failed=false;for(const resource of [sts,s3,http,agent])try{resource?.destroy();}catch{failed=true;}
  for(const request of requests){delete request.headers.authorization;delete request.headers['x-amz-security-token'];request.body=undefined;}
  Object.keys(secret.value).forEach(k=>secret.value[k]='');if(failed){await hold('CiAllowanceOwnerCleanup');fail('CiAllowanceOwnerCleanup');}
 }
}
