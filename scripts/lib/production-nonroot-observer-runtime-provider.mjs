/** Fixed CONTROL runtime provider. The remote meter bounds work already paid
 * by the host before RunTask; delivery JSON grants no host credit/authority.
 * No alternate fetch, reader, clock, SDK, endpoint or credential callbacks. */
import {describeObserverProviderFinalization} from './production-nonroot-observer-finalization-work.mjs';
export {describeObserverProviderFinalization} from './production-nonroot-observer-finalization-work.mjs';
import http from 'node:http';
import https from 'node:https';
import {SSMClient,GetParameterCommand} from '@aws-sdk/client-ssm';
import {SecretsManagerClient,GetSecretValueCommand} from '@aws-sdk/client-secrets-manager';
import {parseAcquisitionJson} from './ci-smoke-acquisition-format.mjs';
import {inspectObserverControlDelivery,decodeObserverControlDelivery,OBSERVER_DELIVERY_ENV,OBSERVER_CONTROL_PURPOSE,OBSERVER_COUNTER_KEYS,observerCounter,observerZeroCounter,observerNeed as need,observerDataHash as hash,observerBytesHash as sha} from './production-nonroot-observer-delivery.mjs';

const providers=new WeakMap(),permits=new WeakMap();
const local=n=>({...observerZeroCounter(),logicalBytes:n}),wire=n=>({...observerZeroCounter(),httpBodyBytes:n});
function state(handle,{cleanup=false}={}){
 const s=providers.get(handle);need(s&&!s.closed&&(cleanup||!s.held),'RuntimeProvider');
 if(!cleanup)need(Date.now()>=s.delivery.startedMs&&Date.now()<s.delivery.deadlineMs,'RuntimeDeadline');return s;
}
function consume(s,p,charge){
 observerCounter(charge);for(const k of OBSERVER_COUNTER_KEYS){const n=p.used[k]+charge[k];if(!Number.isSafeInteger(n)||n>p.row.counter[k]){s.held=true;throw Error('ObserverRuntimeCounter');}p.used[k]=n;}
}
export function claimObserverRuntimeRequest(handle,id){
 const s=state(handle),row=s.delivery.allocation.slots.find(r=>r.id===id);need(row&&!s.used.has(id),'RuntimeSlot');
 // Debit the entire declared invocation before any owned reader/request. A
 // failed invocation remains in used and retained, even before dispatch.
 s.used.add(id);for(const k of OBSERVER_COUNTER_KEYS){s.retained[k]+=row.counter[k];need(s.retained[k]<=s.delivery.allocation.charge[k],'RuntimeReservation');}
 const handlePermit=Object.freeze({kind:'observer-runtime-permit'});permits.set(handlePermit,{handle,row,used:observerZeroCounter(),io:null,done:false,startedMs:Date.now()});s.permits.add(handlePermit);return handlePermit;
}
export function assertObserverRuntimeRequest(handle,permit){state(handle);const p=permits.get(permit);need(p?.handle===handle&&!p.done,'RuntimePermit');return Object.freeze({id:p.row.id,kind:p.row.kind,requestBytes:p.row.requestBytes,responseBytes:p.row.responseBytes});}
export function assertObserverRuntimeCurrent(handle){state(handle);}
export function chargeObserverRuntimeRequest(handle,permit,charge){const s=state(handle),p=permits.get(permit);need(p?.handle===handle&&!p.done,'RuntimePermit');consume(s,p,charge);}
export function observerRuntimeRequestLimits(handle,permit){state(handle);const p=permits.get(permit);need(p?.handle===handle&&!p.done,'RuntimePermit');return Object.freeze({requestBytes:p.row.requestBytes,responseBytes:p.row.responseBytes,deadlineMs:providers.get(handle).delivery.deadlineMs});}
export function retainObserverRuntimeIo(handle,permit,io){state(handle);const p=permits.get(permit);need(p?.handle===handle&&!p.done&&!p.io&&io&&typeof io==='object','RuntimeIo');p.io=io;}
export function finishObserverRuntimeRequest(handle,permit,observation){
 const s=state(handle),p=permits.get(permit);need(p?.handle===handle&&!p.done,'RuntimePermit');
 if(p.row.kind==='http')need(p.io?.request?.closed===true&&(!p.io.response||p.io.response.closed===true),'RuntimePhysicalClose');
 consume(s,p,local(65536));hash(observation);p.done=true;
 const record=Object.freeze({slot:p.row.id,startedMs:p.startedMs,completedMs:Date.now(),retained:structuredClone(p.row.counter),used:structuredClone(p.used),observationHash:hash(observation),closed:true});s.records.push(record);return record;
}
export function failObserverRuntimeRequest(handle,permit){
 const s=state(handle,{cleanup:true}),p=permits.get(permit);need(p?.handle===handle&&!p.done,'RuntimePermit');s.held=true;p.done=true;
 const closed=p.row.kind==='local'||p.io?.request?.closed===true&&(!p.io.response||p.io.response.closed===true);s.unknown ||=!closed;
 s.records.push(Object.freeze({slot:p.row.id,startedMs:p.startedMs,completedMs:Date.now(),retained:structuredClone(p.row.counter),used:structuredClone(p.used),closed,held:true}));
}
async function closeIo(io,deadline){
 const all=[io.request,io.response].filter(Boolean),listeners=[];let timer,first;
 try{
  const joins=all.map(x=>x.closed===true?Promise.resolve():new Promise(resolve=>{const fn=()=>{if(x.closed===true)resolve();};try{x.on('close',fn);listeners.push([x,fn]);fn();}catch(error){first??=error;}}));
  for(const x of all)if(x.closed!==true)try{x.destroy();}catch(error){first??=error;}
  try{await Promise.race([Promise.all(joins),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('ObserverRuntimeCloseUnknown')),Math.max(0,Math.min(1000,deadline-Date.now())));})]);}catch(error){first??=error;}
  if(!all.every(x=>x.closed===true))first??=Error('ObserverRuntimePhysicalClose');
 }finally{clearTimeout(timer);for(const [x,fn]of listeners)try{x.off('close',fn);}catch(error){first??=error;}}
 if(first)throw Object.assign(Error('ObserverRuntimeCloseUnknown'),{cleanupUnknown:true});
}
async function request(handle,permit,{url,method='GET',headers={},body=Buffer.alloc(0),secret=false}){
 const s=state(handle),p=permits.get(permit);need(p?.handle===handle&&!p.done&&p.row.kind==='http','RuntimePermit');
 const target=new URL(url),io={request:null,response:null},parts=[];let raw,timer,total=0,status,responseHeaders,transferred=false;
 retainObserverRuntimeIo(handle,permit,io);
 try{
  const payload=Buffer.from(body),headerBytes=Buffer.byteLength(JSON.stringify(headers));need(payload.length+headerBytes<=p.row.requestBytes,'RuntimeRequestBound');
  chargeObserverRuntimeRequest(handle,permit,wire(payload.length+headerBytes));chargeObserverRuntimeRequest(handle,permit,local(16*(payload.length+headerBytes)+65536));
  const response=await new Promise((resolve,reject)=>{
   let done=false;const finish=(error,result)=>{if(done)return;done=true;clearTimeout(timer);error?reject(error):resolve(result);};
   const q=(target.protocol==='https:'?https:http).request(target,{method,headers,agent:false},r=>{
    io.response=r;status=r.statusCode;responseHeaders=r.headers;
    r.on('data',chunk=>{try{state(handle);need(chunk instanceof Uint8Array&&total+chunk.length<=p.row.responseBytes,'RuntimeResponseBound');chargeObserverRuntimeRequest(handle,permit,wire(chunk.length));chargeObserverRuntimeRequest(handle,permit,local(32*chunk.length));total+=chunk.length;parts.push(Buffer.from(chunk));}catch(e){finish(e);r.destroy();q.destroy();}});
    r.once('end',()=>finish(null,r));r.once('aborted',()=>finish(Error('ObserverRuntimeAborted')));r.once('error',e=>finish(e));
   });io.request=q;q.once('error',e=>finish(e));q.once('close',()=>{if(!done)finish(Error('ObserverRuntimePrematureClose'));});
   timer=setTimeout(()=>{finish(Error('ObserverRuntimeDeadline'));q.destroy();},Math.max(1,Math.min(15000,s.delivery.deadlineMs-Date.now())));q.end(payload);
  });
  assertObserverRuntimeRequest(handle,permit);await closeIo(io,s.delivery.deadlineMs);assertObserverRuntimeRequest(handle,permit);
  need(response.statusCode===200&&(!responseHeaders['content-length']||Number(responseHeaders['content-length'])===total),'RuntimeUnknownResponse');
  chargeObserverRuntimeRequest(handle,permit,local(16*total+65536));raw=Buffer.concat(parts,total);
  if(secret)s.secretBuffers.add(raw);
  // Only physical IO has closed. Its original source permit remains live for
  // the owning consumer's decode and exact source/version/binding validation.
  transferred=true;return {raw,status,headers:responseHeaders,permit,secret};
 }finally{
  clearTimeout(timer);let closeFailure;try{await closeIo(io,s.delivery.deadlineMs);}catch(error){s.held=true;s.unknown=true;closeFailure=error;}
  if(secret)for(const part of parts)part.fill(0);
  if(!transferred||closeFailure){raw?.fill(0);if(raw)s.secretBuffers.delete(raw);if(!p.done)failObserverRuntimeRequest(handle,permit);}
  if(closeFailure)throw closeFailure;
 }
}
function json(raw,cap){return parseAcquisitionJson(raw,cap);}
function metadataUrls(){
 const uri=process.env.ECS_CONTAINER_METADATA_URI_V4,relative=process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI;
 need(typeof uri==='string'&&/^http:\/\/169\.254\.170\.2\/v4\/[A-Za-z0-9-]+$/.test(uri),'RuntimeMetadataEndpoint');
 need(typeof relative==='string'&&/^\/v2\/credentials\/[A-Za-z0-9-]+$/.test(relative)&&!process.env.AWS_CONTAINER_CREDENTIALS_FULL_URI&&!process.env.AWS_ACCESS_KEY_ID&&!process.env.AWS_SECRET_ACCESS_KEY&&!process.env.AWS_SESSION_TOKEN,'RuntimeCredentialEndpoint');
 return {container:uri,task:uri+'/task',credentials:'http://169.254.170.2'+relative};
}
export async function openObserverRuntimeProvider(delivery,guardInvocation){
 // The only verifier is the source-bound real bootstrap; callers cannot pass
 // an alternative guard function. This export is supplied by the P increment.
 const {requireGuardedObserverInvocation}=await import('/bootstrap/nonroot-dispatch.mjs');
 const guard=requireGuardedObserverInvocation(guardInvocation);inspectObserverControlDelivery(delivery);
 const decoded=decodeObserverControlDelivery(process.env[OBSERVER_DELIVERY_ENV]??'');
 need(guard.purpose===OBSERVER_CONTROL_PURPOSE&&guard.manifestSha256===delivery.manifestSha256&&guard.payloadSha256===decoded.wireSha256&&decoded.deliveryHash===hash(delivery),'RuntimeGuardBinding');
 const handle=Object.freeze({kind:'original-observer-runtime-provider'}),s={delivery:structuredClone(delivery),used:new Set(),retained:observerZeroCounter(),permits:new Set(),records:[],held:false,unknown:false,closed:false,credentials:null,identity:null,credentialReads:false,publicObjects:[],secretBuffers:new Set(),finalization:null,snapshotCalls:0,finalizationReady:false};s.payloadSha256=decoded.wireSha256;providers.set(handle,s);
 const sensitive=[];
 try{
  const finalization=claimObserverRuntimeRequest(handle,'runtime-finalization');s.finalization=finalization;
  chargeObserverRuntimeRequest(handle,finalization,local(describeObserverProviderFinalization(delivery).logicalBytes));s.finalizationReady=true;
  const admission=claimObserverRuntimeRequest(handle,'source/registry');chargeObserverRuntimeRequest(handle,admission,local(32*262144+65536));finishObserverRuntimeRequest(handle,admission,{registryHash:delivery.route.registryHash,deliveryHash:hash(delivery)});
  const urls=metadataUrls(),containerPermit=claimObserverRuntimeRequest(handle,'runtime/container-metadata');
  const cr=await request(handle,containerPermit,{url:urls.container});assertObserverRuntimeRequest(handle,containerPermit);
  const container=json(cr.raw,1048576),taskPermit=claimObserverRuntimeRequest(handle,'runtime/task-metadata');
  const tr=await request(handle,taskPermit,{url:urls.task});assertObserverRuntimeRequest(handle,taskPermit);assertObserverRuntimeRequest(handle,containerPermit);
  const task=json(tr.raw,1048576),arn='arn:aws:ecs:'+delivery.region+':'+delivery.account+':';
  need(typeof task.TaskARN==='string'&&task.TaskARN.startsWith(arn+'task/'+delivery.clusterArn.split('/').at(-1)+'/')&&[delivery.clusterArn,delivery.clusterArn.split('/').at(-1)].includes(task.Cluster)&&arn+'task-definition/'+task.Family+':'+task.Revision===delivery.taskDefinitionArn&&task.LaunchType==='FARGATE','RuntimeTaskBinding');
  const matches=task.Containers?.filter(c=>c.Name===delivery.containerName&&c.DockerId===container.DockerId);need(matches?.length===1&&container.Name===delivery.containerName&&typeof container.DockerId==='string'&&container.DockerId.length<=256,'RuntimeContainerBinding');
  need(container.Image.endsWith('@'+delivery.controlImage.rootDigest)&&matches[0].Image===container.Image&&matches[0].ImageID===container.ImageID,'RuntimeImageBinding');
  // ImageID is retained for host comparison, not guessed to be a manifest or
  // config digest. Host checks the actual immutable ECS image pair separately.
  s.identity={taskArn:task.TaskARN,taskDefinitionArn:delivery.taskDefinitionArn,runtimeId:container.DockerId,containerName:container.Name,image:container.Image,imageId:container.ImageID,containerMetadata:{sha256:sha(cr.raw),bytesLength:cr.raw.length},taskMetadata:{sha256:sha(tr.raw),bytesLength:tr.raw.length}};
  settlePublicSource(handle,cr);settlePublicSource(handle,tr);
  const credentialPermit=claimObserverRuntimeRequest(handle,'runtime/task-credentials');
  const credential=await request(handle,credentialPermit,{url:urls.credentials,secret:true});sensitive.push(credential.raw);assertObserverRuntimeRequest(handle,credentialPermit);
  const c=json(credential.raw,65536);need(c.RoleArn===delivery.taskRoleArn&&/^ASIA[A-Z0-9]{16}$/.test(c.AccessKeyId)&&typeof c.SecretAccessKey==='string'&&typeof c.Token==='string'&&Date.parse(c.Expiration)>=delivery.deadlineMs,'RuntimeCredentialIdentity');
  s.credentials={accessKeyId:c.AccessKeyId,secretAccessKey:c.SecretAccessKey,sessionToken:c.Token};finishObserverRuntimeRequest(handle,credentialPermit,{roleArn:c.RoleArn,expiration:c.Expiration,sha256:sha(credential.raw),bytesLength:credential.raw.length});return handle;
 }catch(error){s.held=true;await closeObserverRuntimeProvider(handle).catch(()=>{});throw Object.assign(Error('ObserverRuntimePreparationHeld'),{cleanupUnknown:s.unknown});}
 finally{for(const b of sensitive){b.fill(0);s.secretBuffers.delete(b);}}
}
async function readSecret(handle,name){
 const s=state(handle);need(s.identity&&s.credentials,'RuntimePrepared');const b=s.delivery.credentialBindings[name],ssm=b.store==='ssm',permit=claimObserverRuntimeRequest(handle,'source/'+name);
 const input=ssm?{Name:b.arn+':'+b.version,WithDecryption:b.valueType==='SecureString'}:{SecretId:b.arn,VersionId:b.version};let raw,output,transferred=false;
 const transportComplete=Error('ObserverOriginalRawSourceReceived');
 const handler={async handle(q){
  need(q.protocol==='https:'&&q.hostname===new URL(b.endpoint).hostname&&q.method==='POST'&&q.path==='/'&&!q.port&&!Object.keys(q.query??{}).length,'RuntimeSecretEndpoint');
  const body=Buffer.from(q.body??'');need(hash(json(body,65536))===hash(input)&&q.headers['x-amz-target']===(ssm?'AmazonSSM.GetParameter':'secretsmanager.GetSecretValue'),'RuntimeSecretRequest');
  const result=await request(handle,permit,{url:b.endpoint,method:'POST',headers:q.headers,body,secret:true});raw=result.raw;assertObserverRuntimeRequest(handle,permit);
  // Use the installed SDK's actual request serialization/signing, then keep
  // response decoding in our own resumed frame under its original permit.
  // This private sentinel is reachable only after the real bounded HTTP read.
  // No SDK JSON decoder can run between handler return and the caller guard.
  throw transportComplete;
 },destroy(){}};
 const Client=ssm?SSMClient:SecretsManagerClient,Command=ssm?GetParameterCommand:GetSecretValueCommand;
 const client=new Client({region:b.region,credentials:s.credentials,endpoint:b.endpoint,maxAttempts:1,defaultsMode:'legacy',retryMode:'standard',ignoreConfiguredEndpointUrls:true,useFipsEndpoint:false,useDualstackEndpoint:false,requestHandler:handler});
 try{
  try{await client.send(new Command(input));throw Error('ObserverMissingRawSource');}catch(error){if(error!==transportComplete)throw error;}
  assertObserverRuntimeRequest(handle,permit);need(raw,'RuntimeRawSourceRequired');const value=json(raw,permits.get(permit).row.responseBytes),record=ssm?value.Parameter:value;
  need(record&&record.ARN===b.arn&&(ssm?record.Version===b.version&&record.Name===b.arn.split(':parameter')[1]&&record.Type===b.valueType:record.VersionId===b.version&&record.SecretBinary===undefined),'RuntimeSecretVersion');
  const text=ssm?record.Value:record.SecretString;need(typeof text==='string'&&Buffer.byteLength(text)===b.bytesLength&&sha(text)===b.sha256,'RuntimeSecretHash');output=Buffer.from(text);s.secretBuffers.add(output);finishObserverRuntimeRequest(handle,permit,{arn:b.arn,version:b.version,sha256:sha(output),bytesLength:output.length});transferred=true;return output;
 }catch(error){if(!permits.get(permit).done)failObserverRuntimeRequest(handle,permit);throw error;}
 finally{try{client.destroy();}catch{s.held=true;s.unknown=true;}raw?.fill(0);if(raw)s.secretBuffers.delete(raw);if(!transferred&&output){output.fill(0);s.secretBuffers.delete(output);}}
}
export const OBSERVER_CREDENTIAL_BYTE_FIELDS=Object.freeze(['accessToken','jwks','registry','identitySigningKeys','transportSigningKeys','tenantKey']);
/** Pure byte adapter only, not an authenticated context or payer. */
export function copyObserverCredentialByteInputs(raw){
 need(raw&&Object.keys(raw).length===6&&OBSERVER_CREDENTIAL_BYTE_FIELDS.every(k=>raw[k] instanceof Uint8Array&&raw[k].byteLength>0&&raw[k].byteLength<=65536),'RuntimeCredentialByteFields');
 return Object.fromEntries(OBSERVER_CREDENTIAL_BYTE_FIELDS.map(k=>[k,Buffer.from(raw[k])]));
}
export async function withObserverRuntimeCredentials(handle,consume){
 const s=state(handle);need(s.identity&&!s.credentialReads&&typeof consume==='function','RuntimeCredentialsOnce');s.credentialReads=true;
 const buffers=[];let values,clientId,clientSecret,response;
 try{
  clientId=await readSecret(handle,'clientId');buffers.push(clientId);state(handle);
  clientSecret=await readSecret(handle,'clientSecret');buffers.push(clientSecret);state(handle);
  const original={registry:Buffer.from(s.delivery.registry)};buffers.push(original.registry);
  for(const name of ['tenantKey','identitySigningKeys','transportSigningKeys']){const b=await readSecret(handle,name);buffers.push(b);state(handle);original[name]=b;}
  const jwksPermit=claimObserverRuntimeRequest(handle,'source/jwks'),jwks=await request(handle,jwksPermit,{url:s.delivery.route.jwksUri});buffers.push(jwks.raw);assertObserverRuntimeRequest(handle,jwksPermit);
  need(jwks.raw.length<=65536,'RuntimeJwksBound');const document=json(jwks.raw,65536);need(document&&Object.keys(document).length===1&&Array.isArray(document.keys)&&document.keys.length>0&&document.keys.length<=16&&document.keys.every(k=>k&&typeof k==='object'&&!Object.hasOwn(k,'d')),'RuntimeJwksShape');original.jwks=jwks.raw;settlePublicSource(handle,jwks);
  const basic=Buffer.from(encodeURIComponent(clientId.toString('utf8'))+':'+encodeURIComponent(clientSecret.toString('utf8')));buffers.push(basic);
  const tokenPermit=claimObserverRuntimeRequest(handle,'source/token'),token=await request(handle,tokenPermit,{url:s.delivery.route.tokenEndpoint,method:'POST',headers:{Authorization:'Basic '+basic.toString('base64'),'Content-Type':'application/x-www-form-urlencoded'},body:Buffer.from(new URLSearchParams({grant_type:'client_credentials',scope:'mem9-mcp/read'}).toString()),secret:true});buffers.push(token.raw);assertObserverRuntimeRequest(handle,tokenPermit);
  response=json(token.raw,65536);need(typeof response.access_token==='string'&&response.token_type?.toLowerCase()==='bearer'&&Number.isSafeInteger(response.expires_in)&&response.expires_in>0,'RuntimeTokenResponse');original.accessToken=Buffer.from(response.access_token,'utf8');buffers.push(original.accessToken);s.secretBuffers.add(original.accessToken);
  finishObserverRuntimeRequest(handle,tokenPermit,{sha256:sha(token.raw),bytesLength:token.raw.length,tokenSha256:sha(original.accessToken),tokenBytes:original.accessToken.length});
  // The complete six-buffer copy is prepaid before allocation; source retrieval
  // and P's independent full crypto-processing term are separate original slots.
  const copyPermit=claimObserverRuntimeProcessing(handle,'credential-adapter');
  chargeObserverRuntimeProcessing(handle,copyPermit,8*OBSERVER_CREDENTIAL_BYTE_FIELDS.reduce((n,k)=>n+original[k].byteLength,0)+65536);
  values=copyObserverCredentialByteInputs(original);buffers.push(...Object.values(values));finishObserverRuntimeProcessing(handle,copyPermit,{fields:6});
  return await consume(values,{identity:structuredClone(s.identity),sources:Object.fromEntries(Object.entries(s.delivery.credentialBindings).map(([k,b])=>[k,{arn:b.arn,version:b.version,valueType:b.valueType,kms:b.kms,sha256:b.sha256,bytesLength:b.bytesLength}])),jwks:{sha256:sha(jwks.raw),bytesLength:jwks.raw.length},token:{sha256:sha(original.accessToken),bytesLength:original.accessToken.length,responseSha256:sha(token.raw),responseBytes:token.raw.length}});
 }catch{ s.held=true;throw Error('ObserverRuntimeCredentialsHeld'); }
 finally{for(const b of buffers){b.fill(0);s.secretBuffers.delete(b);}if(response)response.access_token='';if(values)for(const key of Object.keys(values))values[key]=undefined;clientId=null;clientSecret=null;}
}
export function claimObserverRuntimeProcessing(handle,id){need(['context','output','credential-adapter'].includes(id),'RuntimeProcessingSlot');const s=state(handle);need(s.delivery.allocation.slots.find(r=>r.id===id)?.kind==='local','RuntimeProcessingKind');return claimObserverRuntimeRequest(handle,id);}
export function chargeObserverRuntimeProcessing(handle,permit,logicalBytes){const row=assertObserverRuntimeRequest(handle,permit);need(row.kind==='local'&&['context','output','credential-adapter'].includes(row.id)&&Number.isSafeInteger(logicalBytes)&&logicalBytes>0,'RuntimeProcessingCharge');chargeObserverRuntimeRequest(handle,permit,local(logicalBytes));}
export function assertObserverRuntimeProcessing(handle,permit){const row=assertObserverRuntimeRequest(handle,permit);need(row.kind==='local','RuntimeProcessingKind');}
export function finishObserverRuntimeProcessing(handle,permit,record){assertObserverRuntimeProcessing(handle,permit);return finishObserverRuntimeRequest(handle,permit,record);}
export function observerRuntimeState(handle){const s=state(handle);need(s.finalizationReady&&++s.snapshotCalls<=8,'RuntimeSnapshotBound');return Object.freeze({purpose:OBSERVER_CONTROL_PURPOSE,owner:s.delivery.owner,operation:s.delivery.operation,caseName:s.delivery.caseName,sampleIndex:s.delivery.sampleIndex,captureId:s.delivery.captureId,manifestSha256:s.delivery.manifestSha256,payloadSha256:s.payloadSha256,account:s.delivery.account,region:s.delivery.region,clusterArn:s.delivery.clusterArn,taskRoleArn:s.delivery.taskRoleArn,nowMs:Date.now(),identity:structuredClone(s.identity),deliveryHash:hash(s.delivery),startedMs:s.delivery.startedMs,deadlineMs:s.delivery.deadlineMs,retained:structuredClone(s.retained),records:structuredClone(s.records),publicObjects:structuredClone(s.publicObjects)});}

function settlePublicSource(handle,result){
 const p=assertObserverRuntimeRequest(handle,result.permit),s=state(handle),raw=result.raw;
 chargeObserverRuntimeRequest(handle,result.permit,local(16*raw.length+65536));
 need(!/(?:\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=._-]{12,}|"(?:access_token|id_token|refresh_token|SecretAccessKey|SessionToken)"\s*:)/i.test(raw.toString('utf8')),'RuntimeUnsafePublicResponse');
 s.publicObjects.push({slot:p.id,sha256:sha(raw),bytesLength:raw.length,base64:raw.toString('base64')});
 return finishObserverRuntimeRequest(handle,result.permit,{sha256:sha(raw),bytesLength:raw.length,status:result.status});
}
export async function closeObserverRuntimeProvider(handle){
 const s=state(handle,{cleanup:true});let failure;
 for(const permit of s.permits){
  if(permit===s.finalization)continue;const p=permits.get(permit);
  if(p.io)try{await closeIo(p.io,s.delivery.deadlineMs);}catch(error){s.held=true;s.unknown=true;failure??=error;}
  if(!p.done)try{failObserverRuntimeRequest(handle,permit);}catch(error){s.held=true;s.unknown=true;failure??=error;}
 }
 for(const b of s.secretBuffers)try{b.fill(0);}catch(error){s.held=true;s.unknown=true;failure??=error;}s.secretBuffers.clear();
 if(s.credentials)for(const key of Object.keys(s.credentials))s.credentials[key]='';s.credentials=null;
 s.held ||=Date.now()>=s.delivery.deadlineMs;
 // This original cleanup permit is fully prepaid before the first source IO.
 // Closed source/P processing permits are never reopened for final copying.
 const final=s.finalization&&permits.get(s.finalization);
 if(!s.finalizationReady||!final||final.done){s.closed=true;throw Object.assign(Error('ObserverRuntimeCleanupHeld'),{cleanupUnknown:s.unknown});}
 const receipt=Object.freeze({authority:false,held:s.held,cleanupUnknown:s.unknown,identity:structuredClone(s.identity),deliveryHash:hash(s.delivery),retained:structuredClone(s.retained),records:structuredClone(s.records),publicObjects:structuredClone(s.publicObjects)});
 final.done=true;s.closed=true;
 if(failure||s.held||s.unknown)throw Object.assign(Error('ObserverRuntimeCleanupHeld'),{cleanupUnknown:s.unknown,receipt});
 return receipt;
}
