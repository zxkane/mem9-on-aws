/** Dedicated owner publication, funded before the original ledger seal.
 * Its durable single-start journal permits one AWS sequence. A confirmed
 * sequence can only repeat the identical GitHub announcement, at most three
 * times. Neither a JSON flag nor this publication is business authority. */
import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {open,lstat,realpath,readdir} from 'node:fs/promises';
import {lstatSync,realpathSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {Readable} from 'node:stream';
import {Agent} from 'node:https';
import {STSClient,GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {S3Client,PutObjectCommand,GetObjectCommand} from '@aws-sdk/client-s3';
import {NodeHttpHandler} from '@smithy/node-http-handler';
import {ciOwnerPublicationPreparation,captureCiOwnerRunBinding} from './ci-smoke-startup-owner.mjs';
import {ciStartupAnnouncementFromGithub,makeCiStartupRunBindingFromGithub} from './ci-smoke-startup.mjs';
import {FUTURE_OWNER_PUBLICATION} from './ci-smoke-grants.mjs';
import {copyNonrootJson,parseNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {smokePrivateRead} from './ci-smoke-host.mjs';

const fail=code=>{throw Object.assign(Error(code),{code,hold:true});};
const need=(ok,code='CiOwnerPublisherInvalid')=>{if(!ok)fail(code);};
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'CiOwnerPublisherFields');
const same=(a,b,code)=>need(hash(a)===hash(b),code);
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const positive=n=>Number.isSafeInteger(n)&&n>0;
const sha=b=>createHash('sha256').update(b).digest('hex');
const raw=v=>Buffer.from(JSON.stringify(v));
const parse=b=>parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(b),{maxBytes:1048576});
const safeCode=e=>typeof e?.code==='string'&&/^[A-Za-z][A-Za-z0-9_.-]{0,127}$/.test(e.code)?e.code:'CiOwnerOperationFailed';
const bodyBytes=v=>v===undefined?Buffer.alloc(0):typeof v==='string'?Buffer.from(v):v instanceof Uint8Array?Buffer.from(v.buffer,v.byteOffset,v.byteLength):fail('CiOwnerRequestBody');

async function ownerDirectory(path,chargeLocal){
 need(typeof path==='string'&&resolve(path)===path&&await realpath(path)===path,'CiOwnerStateDirectory');
 const initial=await lstat(path);need(initial.isDirectory()&&initial.uid===process.getuid()&&(initial.mode&511)===448,'CiOwnerStateDirectory');
 const check=()=>{const s=lstatSync(path);need(realpathSync(path)===path&&s.isDirectory()&&s.dev===initial.dev&&s.ino===initial.ino&&s.uid===initial.uid&&(s.mode&511)===448,'CiOwnerStateChanged');};
 const save=async(name,value)=>{
  check();const bytes=Buffer.isBuffer(value)?value:raw(value);need(bytes.length<=1048576,'CiOwnerRecordLimit');chargeLocal?.(bytes.length);const file=join(path,name);
  const fd=await open(file,'wx',0o600);try{await fd.writeFile(bytes);await fd.sync();}finally{await fd.close();}
  const directory=await open(path,'r');try{await directory.sync();}finally{await directory.close();}check();return {path:file,sha256:sha(bytes)};
 };
 const read=async(name,ref)=>{
  check();const file=join(path,name);if(ref){exact(ref,['path','sha256']);need(ref.path===file&&hex(ref.sha256),'CiOwnerRecordReference');}
  const bytes=await smokePrivateRead(file,1048576,chargeLocal);if(ref)need(sha(bytes)===ref.sha256,'CiOwnerRecordChanged');check();return {bytes,value:name.endsWith('.json')?parse(bytes):undefined,ref:{path:file,sha256:sha(bytes)}};
 };
 return {path,check,save,read};
}
function storageBinding(value,scope){
 const s=copyNonrootJson(value);exact(s,['bucket','kmsKeyArn','roleArn',...(Object.hasOwn(s,'bucketKeyEnabled')?['bucketKeyEnabled']:[])]);
 need(s.bucketKeyEnabled===undefined||s.bucketKeyEnabled===true,'CiOwnerStorage');
 need(/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(s.bucket)&&!s.bucket.includes('..')&&!/^[0-9.]+$/.test(s.bucket),'CiOwnerStorage');
 need(new RegExp('^arn:aws:kms:'+scope.region+':'+scope.account+':key/(?:[a-f0-9-]{36}|mrk-[a-f0-9]{32})$').test(s.kmsKeyArn),'CiOwnerStorageKey');
 need(new RegExp('^arn:aws:iam::'+scope.account+':role/[A-Za-z0-9_+=,.@/-]{1,512}$').test(s.roleArn),'CiOwnerStorageRole');return copyNonrootJson({...s,bucketKeyEnabled:true});
}
async function credentials(ref,chargeLocal){
 exact(ref,['path','sha256']);need(hex(ref.sha256),'CiOwnerCredentialsReference');
 const bytes=await smokePrivateRead(ref.path,65536,chargeLocal);let decoded;
 try{
  need(sha(bytes)===ref.sha256,'CiOwnerCredentialsChanged');decoded={...parse(bytes)};exact(decoded,['accessKeyId','secretAccessKey','sessionToken','expiration']);
  need(/^ASIA[A-Z0-9]{16}$/.test(decoded.accessKeyId)&&typeof decoded.secretAccessKey==='string'&&decoded.secretAccessKey.length===40&&typeof decoded.sessionToken==='string'&&decoded.sessionToken.length>0&&decoded.sessionToken.length<=16384,'CiOwnerTemporaryCredentials');
  const expiresMs=Date.parse(decoded.expiration);need(typeof decoded.expiration==='string'&&positive(expiresMs)&&Date.now()<expiresMs,'CiOwnerCredentialsExpired');
  return {value:{accessKeyId:decoded.accessKeyId,secretAccessKey:decoded.secretAccessKey,sessionToken:decoded.sessionToken},expiresMs};
 }finally{bytes.fill(0);if(decoded)for(const key of ['accessKeyId','secretAccessKey','sessionToken'])decoded[key]='';}
}
function defaultGithub(env,deadline){
 const childEnv={PATH:'/usr/bin:/bin',HOME:env.HOME,GH_HOST:'github.com',GH_PROMPT_DISABLED:'1',GH_PAGER:''};
 for(const key of ['GH_CONFIG_DIR','XDG_CONFIG_HOME','GH_TOKEN','GITHUB_TOKEN'])if(typeof env[key]==='string'&&env[key])childEnv[key]=env[key];
 return ({method,path,body})=>new Promise((resolve,reject)=>{
  const remaining=deadline-Date.now();if(remaining<=0)return reject(Error('CiOwnerGithubExpired'));
  const args=['api','--hostname','github.com','--method',method,path,...(body?['--input','-']:[])];
  const child=execFile('/usr/bin/gh',args,{env:childEnv,encoding:'utf8',timeout:Math.min(remaining,30000),maxBuffer:1048576,killSignal:'SIGKILL'},(error,stdout)=>{
   if(error)return reject(Error('CiOwnerGithubFailed'));try{resolve(parse(Buffer.from(stdout)));}catch{reject(Error('CiOwnerGithubResponse'));}
  });child.stdin.end(body?JSON.stringify(body):undefined);
 });
}
function caller(value,scope,storage){
 const name=storage.roleArn.split('/').at(-1),prefix=`arn:aws:sts::${scope.account}:assumed-role/${name}/`;
 need(value?.Account===scope.account&&typeof value.Arn==='string'&&value.Arn.startsWith(prefix)&&/^[A-Za-z0-9+=,.@_-]{1,64}$/.test(value.Arn.slice(prefix.length)),'CiOwnerCallerMismatch');
}
function encryption(value,storage){need(value?.ServerSideEncryption==='aws:kms'&&value.SSEKMSKeyId===storage.kmsKeyArn&&value.BucketKeyEnabled===storage.bucketKeyEnabled&&typeof value.ETag==='string'&&value.ETag.length>0&&value.ETag.length<=256,'CiOwnerObjectProtection');}
function requests(scope,storage,key,bytes){
 const object={Bucket:storage.bucket,Key:key,ExpectedBucketOwner:scope.account};
 return [{},{...object,Body:bytes,ContentLength:bytes.length,ContentType:'application/json',IfNoneMatch:'*',ServerSideEncryption:'aws:kms',SSEKMSKeyId:storage.kmsKeyArn,BucketKeyEnabled:true,ChecksumAlgorithm:'SHA256',ChecksumSHA256:Buffer.from(sha(bytes),'hex').toString('base64')},object];
}
function requestRecord(input){const value={...input};if(Object.hasOwn(value,'Body'))value.Body={sha256:sha(value.Body),bytesLength:value.Body.length};return value;}
function publicRequest(request,index,scope,storage,key,bytes){
 const expectedHost=index===1?`sts.${scope.region}.amazonaws.com`:`s3.${scope.region}.amazonaws.com`;
 need(request.protocol==='https:'&&request.hostname===expectedHost&&!request.port&&request.path===(index===1?'/':'/'+storage.bucket+'/'+key)&&request.method===(index===1?'POST':index===2?'PUT':'GET'),'CiOwnerRequestScope');
 const query=request.query??{};need(Object.keys(query).length===0||(index>1&&Object.keys(query).length===1&&query['x-id']===(index===2?'PutObject':'GetObject')),'CiOwnerRequestQuery');
 const body=bodyBytes(request.body),headers={};
 if(index===1)need(body.toString()==='Action=GetCallerIdentity&Version=2011-06-15','CiOwnerIdentityRequest');
 else{
  headers['x-amz-expected-bucket-owner']=scope.account;
  if(index===2)Object.assign(headers,{'if-none-match':'*','content-type':'application/json','content-length':String(bytes.length),'x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':storage.kmsKeyArn,'x-amz-server-side-encryption-bucket-key-enabled':'true','x-amz-checksum-sha256':Buffer.from(sha(bytes),'hex').toString('base64')});
  need(Object.entries(headers).every(([k,v])=>request.headers?.[k]===v),'CiOwnerObjectRequest');
  need(index===2?body.equals(bytes):body.length===0,'CiOwnerRequestBody');
 }
 // Persist only these fixed non-secret headers; never credentials or SigV4.
 return {protocol:request.protocol,hostname:request.hostname,path:request.path,method:request.method,query,headers};
}

async function publicationHistory(dir,{config,scope,storage,publication,stamp,start,bytes,fixedRequests,bindingHash}){
 const budget=publication.budget,key=stamp.key;let confirmation;
  const {startedMs,awsDeadlineMs,...stored}=start.value;same(stored,stamp,'CiOwnerPublicationConflict');need(positive(startedMs)&&positive(awsDeadlineMs)&&startedMs<=awsDeadlineMs,'CiOwnerPublicationHistory');
  need(!(await readdir(dir.path)).includes('run-binding-held.json'),'CiOwnerPublicationHeld');
  try{confirmation=(await dir.read('run-binding-confirmed.json')).value;}catch{fail('CiOwnerPublicationHeld');}
  exact(confirmation,['version','startRef','bindingRef','sourceRef','bindingHash','publicationHash','calls','observedBodyBytes','confirmedMs']);
  same(confirmation.startRef,start.ref,'CiOwnerPublicationHistory');need(confirmation.version===1&&confirmation.bindingHash===bindingHash&&confirmation.publicationHash===hash(publication)&&positive(confirmation.confirmedMs)&&confirmation.confirmedMs>=startedMs&&confirmation.confirmedMs<awsDeadlineMs,'CiOwnerPublicationHistory');
  need((await dir.read('run-binding-body.json',confirmation.bindingRef)).bytes.equals(bytes),'CiOwnerPublicationHistory');
  await dir.read('run-binding-source.json',confirmation.sourceRef);
  need(Array.isArray(confirmation.calls)&&confirmation.calls.length===3,'CiOwnerPublicationHistory');let total=0;const results=[];
  for(const [index,call]of confirmation.calls.entries()){
   exact(call,['intentRef','dispatchRef','resultRef']);const n=index+1,c=publication.calls[index];
   const intent=(await dir.read(`aws-${n}-intent.json`,call.intentRef)).value,dispatch=(await dir.read(`aws-${n}-dispatch.json`,call.dispatchRef)).value,result=(await dir.read(`aws-${n}-result.json`,call.resultRef)).value;
   exact(intent,['version','index','action','startHash','caps','request','prepaidReservation','reservedMs']);
   exact(dispatch,['version','index','intentHash','request','requestBodyRef','requestBodyBytes','requestBodyHash','dispatchedMs']);
   exact(result,['version','index','dispatchHash','status','bodyRef','responseBodyBytes','response','completedMs']);
   same(intent.request,requestRecord(fixedRequests[index]),'CiOwnerPublicationHistory');
   same(intent.prepaidReservation,{logicalBytes:c.requestBytes+c.responseBytes,httpBodyBytes:c.requestBytes+c.responseBytes,ecrRequests:0},'CiOwnerPublicationHistory');
   need(intent.index===n&&intent.action===c.action&&intent.startHash===start.ref.sha256&&hash(intent.caps)===hash(c)&&dispatch.index===n&&dispatch.intentHash===call.intentRef.sha256&&result.index===n&&result.dispatchHash===call.dispatchRef.sha256&&result.status===200,'CiOwnerPublicationHistory');
   need(intent.version===1&&dispatch.version===1&&result.version===1&&positive(intent.reservedMs)&&intent.reservedMs>=startedMs&&intent.reservedMs<=dispatch.dispatchedMs&&dispatch.dispatchedMs<=result.completedMs&&result.completedMs<=confirmation.confirmedMs,'CiOwnerPublicationHistory');
   const request=await dir.read(`aws-${n}-request.bin`,dispatch.requestBodyRef);
   need(request.bytes.length===dispatch.requestBodyBytes&&sha(request.bytes)===dispatch.requestBodyHash,'CiOwnerPublicationHistory');
   same(publicRequest({...dispatch.request,body:request.bytes},n,scope,storage,key,bytes),dispatch.request,'CiOwnerPublicationHistory');
   const response=await dir.read(`aws-${n}-response.bin`,result.bodyRef);
   need(dispatch.requestBodyBytes<=c.requestBytes&&result.responseBodyBytes===response.bytes.length&&result.responseBodyBytes<=c.responseBytes,'CiOwnerPublicationHistory');
   if(n===3)need(response.bytes.equals(bytes),'CiOwnerPublicationHistory');
   total+=dispatch.requestBodyBytes+result.responseBodyBytes;results.push(result.response);
  }
  need(total===confirmation.observedBodyBytes&&total<=budget.httpBodyBytes,'CiOwnerPublicationHistory');caller(results[0],scope,storage);encryption(results[1],storage);encryption(results[2],storage);same(results[1].ETag,results[2].ETag,'CiOwnerPublicationHistory');
  need(results[2].ContentLength===bytes.length&&(results[1].VersionId??null)===(results[2].VersionId??null),'CiOwnerPublicationHistory');
 return confirmation;
}

/** Read-only verification of the existing publication history. Requires the
 * genuine preparation; no caller-supplied JSON can stand in for a publication. */
export async function readCiOwnerPublishedRunBinding({preparation,storage:storageValue},{chargeLocal}={}){
 const prepared=ciOwnerPublicationPreparation(preparation),{config,funding,scope}=prepared;
 need(!funding.owner.delivery||typeof chargeLocal==='function','CiOwnerDeliveryLocalRequired');
 const storage=storageBinding(storageValue,scope),publication=funding.owner.publication,dir=await ownerDirectory(funding.ownerStateDirectory,chargeLocal);
 const start=await dir.read('run-binding-start.json'),confirmed=await dir.read('run-binding-confirmed.json');
 const source=await dir.read('run-binding-source.json',confirmed.value.sourceRef);
 const binding=makeCiStartupRunBindingFromGithub(config,source.value.observations),bindingHash=hash(binding),bytes=raw(binding);
 same(source.value.binding,binding,'CiOwnerPublicationHistory');
 const key=`data-authorizations/${scope.runtimeNonce}/${scope.authorizationId}/ci-grants/${config.grantSetId}/run-binding.json`;
 const stamp={version:1,kind:'ci-owner-run-binding-start',grantSetId:config.grantSetId,configHash:hash(config),bindingHash,scopeHash:hash(scope),storageHash:hash(storage),publicationHash:hash(publication),bodyHash:sha(bytes),key};
 const confirmation=await publicationHistory(dir,{config,scope,storage,publication,stamp,start,bytes,fixedRequests:requests(scope,storage,key,bytes),bindingHash});
 ciOwnerPublicationPreparation(preparation);
 return copyNonrootJson({binding,bindingHash,bindingRef:confirmation.bindingRef,confirmationRef:confirmed.ref,confirmedMs:confirmation.confirmedMs});
}

export async function publishCiOwnerRunBinding(input,options={}){
 exact(input,['preparation','runId','runAttempt','storage','credentialsRef']);need(Object.keys(options).every(k=>['env','requestHandler','githubApi','chargeLocal'].includes(k)),'CiOwnerPublisherOptions');
 const prepared=ciOwnerPublicationPreparation(input.preparation),{config,funding,scope}=prepared;
 const storage=storageBinding(input.storage,scope),publication=funding.owner.publication,{budget,...policy}=publication;
 same(policy,FUTURE_OWNER_PUBLICATION,'CiOwnerPublicationBudget');
 need(!funding.owner.delivery||typeof options.chargeLocal==='function','CiOwnerDeliveryLocalRequired');
 const dir=await ownerDirectory(funding.ownerStateDirectory,options.chargeLocal),env=options.env??process.env;
 const ownerCheck=()=>{dir.check();need(Date.now()>=prepared.preparedMs&&Date.now()<config.notAfter,'CiOwnerPublicationExpired');};
 const github=options.githubApi??defaultGithub(env,config.notAfter);need(typeof github==='function','CiOwnerGithubAdapter');
 const gh=async request=>{ownerCheck();let response;try{response=await github(request);}catch{fail('CiOwnerGithubRequestHeld');}ownerCheck();need(Buffer.byteLength(JSON.stringify(response))<=1048576,'CiOwnerGithubResponseLimit');return copyNonrootJson(response);};
 const source=await captureCiOwnerRunBinding({config,runId:input.runId,runAttempt:input.runAttempt},{env,api:path=>gh({method:'GET',path:'repos/'+config.source.repository+'/'+path})});
 const binding=source.binding,bindingHash=hash(binding),bytes=raw(binding);need(bytes.length<=16384,'CiOwnerBindingSize');
 const key=`data-authorizations/${scope.runtimeNonce}/${scope.authorizationId}/ci-grants/${config.grantSetId}/run-binding.json`;
 const fixedRequests=requests(scope,storage,key,bytes);
 const stamp={version:1,kind:'ci-owner-run-binding-start',grantSetId:config.grantSetId,configHash:hash(config),bindingHash,scopeHash:hash(scope),storageHash:hash(storage),publicationHash:hash(publication),bodyHash:sha(bytes),key};
 let start,confirmation,created=false,secret;
 try{start=await dir.read('run-binding-start.json');}catch(error){if(error.code!=='ENOENT')throw error;}
 if(start){
  confirmation=await publicationHistory(dir,{config,scope,storage,publication,stamp,start,bytes,fixedRequests,bindingHash});
 }else{
  const names=await readdir(dir.path);need(!names.some(n=>n.startsWith('run-binding-')||n.startsWith('aws-')||n.startsWith('announcement-')),'CiOwnerPublicationHistoryMissing');
  secret=await credentials(input.credentialsRef,options.chargeLocal);const startedMs=Date.now(),awsDeadlineMs=Math.min(config.notAfter,secret.expiresMs,startedMs+90000);
  try{start={ref:await dir.save('run-binding-start.json',{...stamp,startedMs,awsDeadlineMs})};created=true;}
  catch(error){for(const k of Object.keys(secret.value))secret.value[k]='';throw error;}
  let transport,agent,sts,s3,current,wire=0;
  const check=()=>{ownerCheck();need(Date.now()<awsDeadlineMs&&Date.now()<secret.expiresMs,'CiOwnerAwsExpired');};
  const hold=async error=>{try{await dir.save('run-binding-held.json',{version:1,startRef:start.ref,code:safeCode(error),observedBodyBytes:wire,prepaidBudget:budget,ownerRefund:0});}catch(e){if(e.code!=='EEXIST')throw e;}};
  try{
   const bindingRef=await dir.save('run-binding-body.json',bytes),sourceRef=await dir.save('run-binding-source.json',source),calls=[];
   agent=new Agent({keepAlive:false,maxSockets:1,rejectUnauthorized:true});transport=options.requestHandler??new NodeHttpHandler({httpsAgent:agent,connectionTimeout:5000,requestTimeout:30000});
   const handler={async handle(request,sendOptions){
    check();const slot=current,c=slot?.caps;need(slot&&!slot.dispatched,'CiOwnerUnexpectedRequest');
    const requestBody=bodyBytes(request.body);need(requestBody.length<=c.requestBytes,'CiOwnerRequestLimit');
    const recordedRequest=publicRequest(request,slot.index,scope,storage,key,bytes),requestBodyRef=await dir.save(`aws-${slot.index}-request.bin`,requestBody);
    slot.dispatchRef=await dir.save(`aws-${slot.index}-dispatch.json`,{version:1,index:slot.index,intentHash:slot.intentRef.sha256,request:recordedRequest,requestBodyRef,requestBodyBytes:requestBody.length,requestBodyHash:sha(requestBody),dispatchedMs:Date.now()});
    check();slot.dispatched=true;wire+=requestBody.length;need(wire<=budget.httpBodyBytes,'CiOwnerPublicationBudget');
    const response=(await transport.handle(request,sendOptions)).response;slot.status=response?.statusCode;
    const stream=response?.body;need(stream instanceof Uint8Array||stream&&typeof stream[Symbol.asyncIterator]==='function','CiOwnerResponseBody');
    const pieces=[];let count=0;const abort=()=>stream.destroy?.(Error('CiOwnerReadAborted'));sendOptions?.abortSignal?.addEventListener('abort',abort,{once:true});
    try{
     for await(const chunk of stream instanceof Uint8Array?[stream]:stream){check();need(chunk instanceof Uint8Array,'CiOwnerResponseBody');count+=chunk.length;wire+=chunk.length;need(count<=c.responseBytes&&wire<=budget.httpBodyBytes,'CiOwnerResponseLimit');pieces.push(Buffer.from(chunk));}
     const body=Buffer.concat(pieces,count),length=response.headers?.['content-length'];if(length!==undefined)need(Number(length)===body.length,'CiOwnerResponseLength');
     slot.raw=body;slot.bodyRef=await dir.save(`aws-${slot.index}-response.bin`,body);check();return {response:{...response,body:Readable.from([body])}};
    }finally{sendOptions?.abortSignal?.removeEventListener('abort',abort);stream.destroy?.();}
   },destroy(){}};
   const clientOptions={region:scope.region,credentials:secret.value,maxAttempts:1,ignoreConfiguredEndpointUrls:true,requestHandler:handler};
   sts=new STSClient({...clientOptions,endpoint:`https://sts.${scope.region}.amazonaws.com`});
   s3=new S3Client({...clientOptions,endpoint:`https://s3.${scope.region}.amazonaws.com`,forcePathStyle:true,followRegionRedirects:false,requestChecksumCalculation:'WHEN_REQUIRED',responseChecksumValidation:'WHEN_REQUIRED'});
   const send=async(index,client,command,validate)=>{
    check();const caps=publication.calls[index-1],request=requestRecord(command.input);
    const intentRef=await dir.save(`aws-${index}-intent.json`,{version:1,index,action:caps.action,startHash:start.ref.sha256,caps,request,prepaidReservation:{logicalBytes:caps.requestBytes+caps.responseBytes,httpBodyBytes:caps.requestBytes+caps.responseBytes,ecrRequests:0},reservedMs:Date.now()});
    const slot=current={index,caps,intentRef,dispatched:false};let response;
    try{
     response=await client.send(command,{abortSignal:AbortSignal.timeout(Math.max(1,Math.min(30000,awsDeadlineMs-Date.now())))});check();need(slot.status===200&&slot.bodyRef,'CiOwnerHttpStatus');validate(response,slot.raw);
     const plain=JSON.parse(JSON.stringify(Object.fromEntries(Object.entries(response).filter(([k])=>k!=='Body'))));
     const resultRef=await dir.save(`aws-${index}-result.json`,{version:1,index,dispatchHash:slot.dispatchRef.sha256,status:slot.status,bodyRef:slot.bodyRef,responseBodyBytes:slot.raw.length,response:plain,completedMs:Date.now()});
     calls.push({intentRef,dispatchRef:slot.dispatchRef,resultRef});return plain;
    }finally{response?.Body?.destroy?.();current=undefined;}
   };
   await send(1,sts,new GetCallerIdentityCommand(fixedRequests[0]),r=>caller(r,scope,storage));
   const put=await send(2,s3,new PutObjectCommand(fixedRequests[1]),r=>encryption(r,storage));
   await send(3,s3,new GetObjectCommand(fixedRequests[2]), (r,body)=>{encryption(r,storage);need(r.ContentLength===bytes.length&&body.equals(bytes)&&r.ETag===put.ETag&&(r.VersionId??null)===(put.VersionId??null),'CiOwnerBindingReadback');});
   check();confirmation={version:1,startRef:start.ref,bindingRef,sourceRef,bindingHash,publicationHash:hash(publication),calls,observedBodyBytes:wire,confirmedMs:Date.now()};await dir.save('run-binding-confirmed.json',confirmation);
  }catch(error){await hold(error);fail('CiOwnerPublicationHeld');}
  finally{
   let failed=false;for(const item of [sts,s3,transport,agent])try{item?.destroy();}catch{failed=true;}
   for(const k of Object.keys(secret.value))secret.value[k]='';secret=undefined;
   if(failed){await hold({code:'ECLEANUP'});fail('ECLEANUP');}
  }
 }
 ownerCheck();const announced=ciStartupAnnouncementFromGithub(config,source.observations),bodyRef=await (async()=>{
  try{const previous=await dir.read('run-binding-announcement.json');same(previous.value,announced,'CiOwnerAnnouncementChanged');return previous.ref;}
  catch(error){if(error.code!=='ENOENT')throw error;return dir.save('run-binding-announcement.json',announced);}
 })();
 const announcementNames=(await readdir(dir.path)).filter(n=>n.startsWith('announcement-'));
 need(announcementNames.every(n=>/^announcement-[1-3]-(intent|actor|post|response|complete)\.json$/.test(n)),'CiOwnerAnnouncementHistory');
 for(let i=1;i<=3;i++)if(announcementNames.some(n=>n.startsWith(`announcement-${i}-`)))
  need(Array.from({length:i},(_,j)=>`announcement-${j+1}-intent.json`).every(n=>announcementNames.includes(n)),'CiOwnerAnnouncementHistory');
 const priorAttempt=async i=>{
  const value=(await dir.read(`announcement-${i}-intent.json`)).value;
  exact(value,['version','bindingHash','bodyRef','expectedActorId','attempt','startedMs']);
  need(value.version===1&&value.bindingHash===bindingHash&&value.expectedActorId===config.ownerGithubActorId&&value.attempt===i&&positive(value.startedMs)&&value.startedMs>=confirmation.confirmedMs&&value.startedMs<=Date.now(),'CiOwnerAnnouncementHistory');
  same(value.bodyRef,bodyRef,'CiOwnerAnnouncementHistory');
 };
 for(let i=1;i<=3;i++)if(announcementNames.includes(`announcement-${i}-intent.json`))await priorAttempt(i);
 let index,attemptRef;
 for(let i=1;i<=3;i++){
  try{attemptRef=await dir.save(`announcement-${i}-intent.json`,{version:1,bindingHash,bodyRef,expectedActorId:config.ownerGithubActorId,attempt:i,startedMs:Date.now()});index=i;break;}
  catch(error){if(error.code!=='EEXIST')throw error;await priorAttempt(i);}
 }
 need(index,'CiOwnerAnnouncementLimit');
 const user=await gh({method:'GET',path:'user'});await dir.save(`announcement-${index}-actor.json`,user);need(user.id===config.ownerGithubActorId,'CiOwnerGithubActor');
 await dir.save(`announcement-${index}-post.json`,{version:1,attemptRef,bodyRef,bindingHash,postedMs:Date.now()});
 const status=await gh({method:'POST',path:'repos/'+config.source.repository+'/'+announced.path,body:announced.payload});
 await dir.save(`announcement-${index}-response.json`,status);
 need(status.creator?.id===config.ownerGithubActorId&&positive(status.id)&&Object.entries(announced.payload).every(([k,v])=>status[k]===v),'CiOwnerAnnouncementResponse');
 const announcementRef=await dir.save(`announcement-${index}-complete.json`,{version:1,attemptRef,bodyRef,bindingHash,statusId:status.id,completedMs:Date.now()});
 return Object.freeze({phase:'owner-run-binding-announced',bindingHash,bindingRef:confirmation.bindingRef,announcementRef,awsCalls:created?3:0,authority:false});
}
