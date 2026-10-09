/** Private, bounded CI evidence transport. No import-time I/O, default AWS
 * credentials, session issuance, executable loading or deployment authority. */
import {createHash} from 'node:crypto';
import {types} from 'node:util';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {inspectCiSmokeRecord,inspectCiSmokeResult,parseCiSmokeJson,validateCiSmokeProducedEvidence} from './ci-smoke-evidence.mjs';

export const CI_SMOKE_ARCHIVE_LIMITS=Object.freeze({envelopeBytes:33554432,objectBytes:8388608,objects:4096,sessionSeconds:900,policyBytes:2048});
const ROOTS=['result','source','isolation','observations','commandBindings','commandCatalog'];
const SHA=/^[a-f0-9]{64}$/,GIT=/^[a-f0-9]{40}$/,DIGEST=/^sha256:[a-f0-9]{64}$/;
const fail=code=>{throw Error(code);},need=(ok,code='CiSmokeArchiveInvalid')=>{if(!ok)fail(code);};
const cleanupError=()=>Object.assign(Error('CiSmokeArchiveCleanupHeld'),{code:'ECLEANUP'});
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const integer=(v,min=0,max=Number.MAX_SAFE_INTEGER)=>need(Number.isSafeInteger(v)&&v>=min&&v<=max);
const exact=(v,keys)=>{
 need(v&&typeof v==='object'&&!types.isProxy(v)&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v)),'CiSmokeArchiveFields');
 const descriptors=Object.getOwnPropertyDescriptors(v),actual=Reflect.ownKeys(descriptors);
 need(actual.every(k=>typeof k==='string'&&descriptors[k].enumerable&&Object.hasOwn(descriptors[k],'value'))&&JSON.stringify(actual.sort())===JSON.stringify([...keys].sort()),'CiSmokeArchiveFields');
};
const same=(a,b)=>need(hash(a)===hash(b),'CiSmokeArchiveBinding');

// Reject accessors/proxies before serialization. The larger envelope bound is
// local to this transport and does not widen the protected evidence parser.
function data(value,maxBytes=CI_SMOKE_ARCHIVE_LIMITS.envelopeBytes){
 let nodes=0,size=0;const active=new Set();
 const copy=(v,depth)=>{
  need(++nodes<=250000&&depth<=64,'CiSmokeArchiveDepth');
  if(v===null||typeof v==='boolean'){size+=5;return v;}
  if(typeof v==='number'){integer(v);size+=String(v).length;return v;}
  if(typeof v==='string'){need(v.isWellFormed(),'CiSmokeArchiveUtf8');size+=Buffer.byteLength(v)+2;need(size<=maxBytes,'CiSmokeArchiveLimit');return v;}
  need(v&&typeof v==='object'&&!types.isProxy(v)&&!active.has(v),'CiSmokeArchiveData');const array=Array.isArray(v),proto=Object.getPrototypeOf(v);
  need(array?proto===Array.prototype:proto===Object.prototype||proto===null,'CiSmokeArchiveData');const ds=Object.getOwnPropertyDescriptors(v),keys=Reflect.ownKeys(ds);need(keys.every(k=>typeof k==='string'),'CiSmokeArchiveData');active.add(v);size+=2;
  let out;if(array){const n=ds.length?.value;integer(n,0,250000);need(keys.length===n+1);out=[];for(let i=0;i<n;i++){const d=ds[i];need(d?.enumerable&&Object.hasOwn(d,'value'));out.push(copy(d.value,depth+1));}}
  else{out={};for(const key of keys){const d=ds[key];need(d.enumerable&&Object.hasOwn(d,'value'));size+=Buffer.byteLength(key)+3;Object.defineProperty(out,key,{value:copy(d.value,depth+1),enumerable:true});}}
  active.delete(v);need(size<=maxBytes,'CiSmokeArchiveLimit');return Object.freeze(out);
 };return copy(value,0);
}
function parseEnvelope(bytes){
 need(bytes instanceof Uint8Array&&bytes.byteLength>0&&bytes.byteLength<=CI_SMOKE_ARCHIVE_LIMITS.envelopeBytes,'CiSmokeArchiveLimit');
 let text;try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{fail('CiSmokeArchiveUtf8');}let at=0;
 const ws=()=>{while(/[\x20\t\r\n]/.test(text[at]??'!'))at++;};
 const string=()=>{const start=at;need(text[at++]==='"');let escape=false;while(at<text.length){const c=text[at++];if(!escape&&c==='"')return JSON.parse(text.slice(start,at));if(escape)escape=false;else if(c==='\\')escape=true;}fail('CiSmokeArchiveJson');};
 const scan=depth=>{need(depth<=64,'CiSmokeArchiveDepth');ws();const c=text[at];
  if(c==='{'){at++;ws();const keys=new Set();if(text[at]==='}'){at++;return;}while(true){ws();const key=string();need(!keys.has(key),'CiSmokeArchiveDuplicateKey');keys.add(key);ws();need(text[at++]===':');scan(depth+1);ws();if(text[at]==='}'){at++;return;}need(text[at++ ]===',');}}
  if(c==='['){at++;ws();if(text[at]===']'){at++;return;}while(true){scan(depth+1);ws();if(text[at]===']'){at++;return;}need(text[at++ ]===',');}}
  if(c==='"'){string();return;}const start=at;while(at<text.length&&!/[\x20\t\r\n,}\]]/.test(text[at]))at++;need(at>start);JSON.parse(text.slice(start,at));
 };
 try{scan(0);ws();need(at===text.length);return data(JSON.parse(text));}catch(e){if(e instanceof SyntaxError)fail('CiSmokeArchiveJson');throw e;}
}

const commitmentKeys=['version','kind','runId','runAttempt','sourceRevision','sourceTree','buildJobId','smokeJobId','outputDigest','arm64Digest','configDigest','resultHash','envelopeSha256','bytesLength'];
export function inspectCiSmokeCommitment(value){
 const c=data(value,4096);exact(c,commitmentKeys);need(c.version===1&&c.kind==='ci-smoke-private-commitment');
 for(const k of ['runId','runAttempt','buildJobId','smokeJobId'])integer(c[k],1);
 for(const k of ['sourceRevision','sourceTree'])need(GIT.test(c[k]));for(const k of ['outputDigest','arm64Digest','configDigest'])need(DIGEST.test(c[k]));for(const k of ['resultHash','envelopeSha256'])need(SHA.test(c[k]));integer(c.bytesLength,1,CI_SMOKE_ARCHIVE_LIMITS.envelopeBytes);return c;
}
function commitmentFor(result,bytes){
 const selected=Object.fromEntries(['runId','runAttempt','sourceRevision','sourceTree','buildJobId','smokeJobId','outputDigest','arm64Digest','configDigest'].map(k=>[k,result[k]]));
 return inspectCiSmokeCommitment({version:1,kind:'ci-smoke-private-commitment',...selected,resultHash:hash(result),envelopeSha256:sha(bytes),bytesLength:bytes.length});
}
function inspectGraph(records,objects){
 const refs=data(records,8192);exact(refs,ROOTS);need(objects instanceof Map&&objects.size>0&&objects.size<=CI_SMOKE_ARCHIVE_LIMITS.objects,'CiSmokeArchiveInventory');
 const used=new Set(),parsed=new Map(),visiting=new Set();
 const readBytes=ref=>{inspectCiSmokeRecord('ByteRef',ref);const bytes=objects.get(ref.sha256);need(bytes&&bytes.length===ref.bytesLength&&sha(bytes)===ref.sha256,'CiSmokeArchiveReference');used.add(ref.sha256);return Buffer.from(bytes);};
 const readJson=ref=>{
  inspectCiSmokeRecord('JsonRef',ref);const bytes=readBytes({sha256:ref.bytesHash,bytesLength:ref.bytesLength});let value=parsed.get(ref.bytesHash);
  if(!value){try{value=parseCiSmokeJson(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{fail('CiSmokeArchiveRecordJson');}parsed.set(ref.bytesHash,value);}
  need(hash(value)===ref.canonicalHash,'CiSmokeArchiveCanonicalHash');return {bytes,value};
 };
 const visit=value=>{
  if(!value||typeof value!=='object')return;
  if(Object.hasOwn(value,'bytesHash')){const {value:next}=readJson(value);need(!visiting.has(value.bytesHash),'CiSmokeArchiveCycle');if(expanded.has(value.bytesHash))return;visiting.add(value.bytesHash);visit(next);visiting.delete(value.bytesHash);expanded.add(value.bytesHash);return;}
  if(Object.hasOwn(value,'sha256')&&Object.hasOwn(value,'bytesLength')){readBytes(value);return;}
  if(Object.hasOwn(value,'gitMode')&&Object.hasOwn(value,'sha256')){inspectCiSmokeRecord('FilePin',value);readBytes({sha256:value.sha256,bytesLength:value.bytes});return;}
  for(const next of Object.values(value))visit(next);
 };
 const expanded=new Set();for(const ref of Object.values(refs)){inspectCiSmokeRecord('JsonRef',ref);visit(ref);}
 need(used.size===objects.size,'CiSmokeArchiveInventory');const values=Object.fromEntries(ROOTS.map(k=>[k,readJson(refs[k]).value]));inspectCiSmokeResult(values.result);
 return {refs,records:Object.freeze(values),readJson:ref=>readJson(ref).bytes,readBytes};
}
export function encodeCiSmokeEnvelope(value){
 exact(value,['records','objects']);const records=data(value.records,8192),rows=value.objects;need(Array.isArray(rows)&&!types.isProxy(rows)&&Object.getPrototypeOf(rows)===Array.prototype&&rows.length>0&&rows.length<=CI_SMOKE_ARCHIVE_LIMITS.objects,'CiSmokeArchiveInventory');
 const ds=Object.getOwnPropertyDescriptors(rows);need(Reflect.ownKeys(ds).length===rows.length+1,'CiSmokeArchiveInventory');
 const objects=new Map();let decoded=0,estimated=Buffer.byteLength(JSON.stringify(records))+128;
 for(let i=0;i<rows.length;i++){need(ds[i]?.enumerable&&Object.hasOwn(ds[i],'value'),'CiSmokeArchiveInventory');const row=ds[i].value;exact(row,['sha256','bytes']);need(typeof row.sha256==='string'&&SHA.test(row.sha256)&&row.bytes instanceof Uint8Array&&!types.isProxy(row.bytes)&&row.bytes.byteLength<=CI_SMOKE_ARCHIVE_LIMITS.objectBytes&&!objects.has(row.sha256),'CiSmokeArchiveInventory');const bytes=Buffer.from(row.bytes);need(sha(bytes)===row.sha256,'CiSmokeArchiveObjectHash');decoded+=bytes.length;estimated+=4*Math.ceil(bytes.length/3)+160;need(decoded<=CI_SMOKE_ARCHIVE_LIMITS.envelopeBytes&&estimated<=CI_SMOKE_ARCHIVE_LIMITS.envelopeBytes,'CiSmokeArchiveLimit');objects.set(row.sha256,bytes);}
 const checked=inspectGraph(records,objects);
 const envelope={version:1,kind:'ci-smoke-private-envelope',records:checked.refs,objects:[...objects].sort(([a],[b])=>a<b?-1:a>b?1:0).map(([sha256,bytes])=>({sha256,bytesLength:bytes.length,base64:bytes.toString('base64')}))};
 const bytes=Buffer.from(JSON.stringify(envelope));need(bytes.length<=CI_SMOKE_ARCHIVE_LIMITS.envelopeBytes,'CiSmokeArchiveLimit');return {bytes,commitment:commitmentFor(checked.records.result,bytes)};
}
export function decodeCiSmokeEnvelope(raw,publicCommitment){
 const c=inspectCiSmokeCommitment(publicCommitment);need(raw instanceof Uint8Array&&raw.byteLength===c.bytesLength,'CiSmokeArchiveCommitment');const snapshot=Buffer.from(raw);need(sha(snapshot)===c.envelopeSha256,'CiSmokeArchiveCommitment');const e=parseEnvelope(snapshot);exact(e,['version','kind','records','objects']);need(e.version===1&&e.kind==='ci-smoke-private-envelope');
 need(Array.isArray(e.objects)&&e.objects.length>0&&e.objects.length<=CI_SMOKE_ARCHIVE_LIMITS.objects,'CiSmokeArchiveInventory');const objects=new Map();let total=0,last='';
 for(const row of e.objects){exact(row,['sha256','bytesLength','base64']);need(typeof row.base64==='string'&&SHA.test(row.sha256)&&row.sha256>last,'CiSmokeArchiveInventory');last=row.sha256;integer(row.bytesLength,0,CI_SMOKE_ARCHIVE_LIMITS.objectBytes);need(row.base64.length===4*Math.ceil(row.bytesLength/3),'CiSmokeArchiveEncoding');const bytes=Buffer.from(row.base64,'base64');need(bytes.length===row.bytesLength&&bytes.toString('base64')===row.base64&&sha(bytes)===row.sha256,'CiSmokeArchiveObjectHash');total+=bytes.length;need(total<=CI_SMOKE_ARCHIVE_LIMITS.envelopeBytes,'CiSmokeArchiveLimit');objects.set(row.sha256,bytes);}
 const checked=inspectGraph(e.records,objects);same(commitmentFor(checked.records.result,snapshot),c);return Object.freeze({...checked,commitment:c,envelopeBytes:Buffer.from(snapshot)});
}

export function ciSmokeArchiveKey(stage,commitment){
 const c=inspectCiSmokeCommitment(commitment);need(typeof stage==='string'&&/^(?:prod|pr-[1-9][0-9]{0,9})$/.test(stage),'CiSmokeArchiveStage');
 return `decisions/${stage}/ci-smoke/${c.runId}/${c.runAttempt}/${c.envelopeSha256}.json`;
}
export function ciSmokeArchiveLocation(value,commitment){
 const c=data(value,8192);return privateArchiveLocation(c,ciSmokeArchiveKey(c.stage,commitment));
}
function privateArchiveLocation(value,key){
 const c=data(value,8192);exact(c,['stage','account','region','bucket','bucketArn','objectArn','roleArn','encryption']);
 need(typeof c.account==='string'&&/^[0-9]{12}$/.test(c.account)&&typeof c.region==='string'&&/^[a-z]{2}(?:-[a-z]+)+-[1-9][0-9]*$/.test(c.region),'CiSmokeArchiveScope');
 need(typeof c.bucket==='string'&&/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(c.bucket)&&!c.bucket.includes('..')&&!/^[0-9.]+$/.test(c.bucket),'CiSmokeArchiveBucket');
 need(c.bucketArn==='arn:aws:s3:::'+c.bucket&&c.objectArn===c.bucketArn+'/'+key,'CiSmokeArchiveObjectScope');
 need(typeof c.roleArn==='string'&&new RegExp('^arn:aws:iam::'+c.account+':role/[A-Za-z0-9_+=,.@/-]{1,512}$').test(c.roleArn),'CiSmokeArchiveRoleScope');
 const e=c.encryption;exact(e,['algorithm','keyArn','bucketKeyEnabled']);need(typeof e.bucketKeyEnabled==='boolean');
 if(e.algorithm==='aws:kms')need(typeof e.keyArn==='string'&&new RegExp('^arn:aws:kms:'+c.region+':'+c.account+':key/(?:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}|mrk-[a-f0-9]{32})$').test(e.keyArn),'CiSmokeArchiveKmsScope');
 else need(e.algorithm==='AES256'&&e.keyArn===null&&e.bucketKeyEnabled===false,'CiSmokeArchiveEncryption');
 return Object.freeze({...c,key,expectedBucketOwner:c.account});
}
// Dedicated CONTROL capture prefix. This is not a raw-byte bypass for the
// smoke codec or for protected data-authorizations objects.
export function controlCaptureArchiveLocation(value,selector){
 const c=data(value,8192),s=data(selector,4096);exact(s,['runId','runAttempt','envelopeSha256','bytesLength']);integer(s.runId,1);integer(s.runAttempt,1);integer(s.bytesLength,1,4194304);need(SHA.test(s.envelopeSha256)&&c.stage==='prod','ControlCaptureScope');
 return privateArchiveLocation(c,`decisions/prod/control-build/${s.runId}/${s.runAttempt}/${s.envelopeSha256}.json`);
}
export function buildCiSmokeReadPolicy(config,commitment){
 const c=ciSmokeArchiveLocation(config,commitment),kms=c.encryption.algorithm==='aws:kms',actions=['sts:GetCallerIdentity','s3:GetObject',...(kms?['kms:Decrypt']:[])];
 const Statement=[
  {Effect:'Deny',NotAction:actions,Resource:'*'},
  {Effect:'Allow',Action:'sts:GetCallerIdentity',Resource:'*'},
  {Effect:'Allow',Action:'s3:GetObject',Resource:c.objectArn,Condition:{StringEquals:{'s3:ResourceAccount':c.account}}},
  {Effect:'Deny',Action:'s3:GetObject',NotResource:c.objectArn},
  {Effect:'Deny',Action:'s3:GetObject',Resource:'*',Condition:{StringNotEquals:{'s3:ResourceAccount':c.account}}},
 ];
 if(kms){
  // With Bucket Keys the KMS context is the bucket ARN. The S3 explicit deny
  // above still limits data access to exactly the selected object.
  const conditions={'kms:ViaService':`s3.${c.region}.amazonaws.com`,'kms:CallerAccount':c.account,'kms:EncryptionContext:aws:s3:arn':c.encryption.bucketKeyEnabled?c.bucketArn:c.objectArn};
  Statement.push({Effect:'Allow',Action:'kms:Decrypt',Resource:c.encryption.keyArn,Condition:{StringEquals:conditions}},{Effect:'Deny',Action:'kms:Decrypt',NotResource:c.encryption.keyArn});
  // Separate denies implement OR: any absent/wrong condition must defeat
  // even a direct resource-policy Allow to this session.
  for(const [key,value]of Object.entries(conditions))Statement.push({Effect:'Deny',Action:'kms:Decrypt',Resource:'*',Condition:{StringNotEquals:{[key]:value}}});
 }
 const Policy=JSON.stringify({Version:'2012-10-17',Statement});need(Buffer.byteLength(Policy)<=CI_SMOKE_ARCHIVE_LIMITS.policyBytes,'CiSmokeArchivePolicyLimit');return Object.freeze({Policy,DurationSeconds:900});
}

function assertEncryption(response,config){
 need(response.ServerSideEncryption===config.encryption.algorithm,'CiSmokeArchiveEncryption');
 if(config.encryption.algorithm==='aws:kms')need(response.SSEKMSKeyId===config.encryption.keyArn&&response.BucketKeyEnabled===config.encryption.bucketKeyEnabled,'CiSmokeArchiveEncryption');
 else need(response.SSEKMSKeyId===undefined&&response.BucketKeyEnabled!==true,'CiSmokeArchiveEncryption');
}
function sessionCredentials(credentials){
 need(credentials&&typeof credentials==='object','CiSmokeArchiveSessionRequired');const {accessKeyId,secretAccessKey,sessionToken,expiration}=credentials;
 need([accessKeyId,secretAccessKey,sessionToken].every(v=>typeof v==='string'&&v.length>0)&&expiration instanceof Date&&Number.isSafeInteger(expiration.getTime()),'CiSmokeArchiveSessionRequired');
 return {accessKeyId,secretAccessKey,sessionToken,expiration:new Date(expiration)};
}

async function withClient(commitment,options,operation){
 return withLocatedClient(ciSmokeArchiveLocation(options.config,commitment),options,operation);
}
async function withLocatedClient(config,options,operation,meter){
 const now=options.now??Date.now;need(typeof now==='function');let held=sessionCredentials(options.credentials);integer(options.deadlineMs,1);
 const expires=held.expiration.getTime(),check=()=>{const t=now();integer(t,1);need(!controller.signal.aborted&&t<options.deadlineMs&&t<expires,'CiSmokeArchiveExpired');};
 const controller=new AbortController();if(options.signal?.aborted)controller.abort();const abort=()=>controller.abort();options.signal?.addEventListener('abort',abort,{once:true});
 let client,transport,body,cleanupFailed=false;const started=now();let timer;
 try{
  need(options.deadlineMs<=started+900000&&options.deadlineMs<=expires,'CiSmokeArchiveDeadline');
  check();timer=setTimeout(abort,Math.max(1,options.deadlineMs-started));timer.unref?.();
  const [{S3Client,PutObjectCommand,GetObjectCommand},{NodeHttpHandler}]=await Promise.all([import('@aws-sdk/client-s3'),import('@smithy/node-http-handler')]);check();
  transport=options.requestHandler??new NodeHttpHandler({connectionTimeout:5000,requestTimeout:Math.min(30000,options.deadlineMs-now())});
  const handler={async handle(request,sendOptions){
   check();need(request.protocol==='https:'&&request.hostname===`s3.${config.region}.amazonaws.com`,'CiSmokeArchiveEndpoint');
   if(!meter)return transport.handle(request,sendOptions);
   need(meter.requests===0,'ControlCaptureRequestCount');meter.requests++;
   need(request.body===undefined||request.body instanceof Uint8Array||typeof request.body==='string','ControlCaptureRequestBody');meter.requestBodyBytes=request.body===undefined?0:Buffer.byteLength(request.body);
   need(meter.requestBodyBytes<=meter.requestBodyBound,'ControlCaptureRequestLimit');
   const response=await transport.handle(request,sendOptions);body=response.response?.body;check();
   if(meter.operation==='PutObject'||response.response?.statusCode!==200){
    need(body&&typeof body[Symbol.asyncIterator]==='function','ControlCaptureResponseBody');const chunks=[];
    for await(const chunk of body){check();need(chunk instanceof Uint8Array);meter.responseBodyBytes+=chunk.byteLength;need(meter.responseBodyBytes<=meter.responseBodyBound,'ControlCaptureResponseLimit');chunks.push(Buffer.from(chunk));}
    const raw=Buffer.concat(chunks);check();need(response.response.statusCode===200,'ControlCaptureHttp');response.response.body=raw;
   }
   return response;
  },destroy(){transport.destroy();}};
  client=new S3Client({region:config.region,endpoint:`https://s3.${config.region}.amazonaws.com`,forcePathStyle:true,followRegionRedirects:false,maxAttempts:1,ignoreConfiguredEndpointUrls:true,requestChecksumCalculation:'WHEN_REQUIRED',responseChecksumValidation:'WHEN_REQUIRED',credentials:async()=>{check();need(held,'CiSmokeArchiveSessionClosed');return held;},requestHandler:handler});
  const closeBody=()=>{if(body&&!body.destroyed){try{need(typeof body.destroy==='function');body.destroy();}catch{cleanupFailed=true;}}};controller.signal.addEventListener('abort',closeBody,{once:true});
  try{return await operation({config,check,signal:controller.signal,PutObjectCommand,GetObjectCommand,send:command=>{check();return client.send(command,{abortSignal:controller.signal});},setBody:value=>{body=value;}});}
  finally{
   controller.signal.removeEventListener('abort',closeBody);closeBody();
   if(body&&!body.closed){
    try{await new Promise((resolve,reject)=>{
     need(typeof body.once==='function'&&typeof body.off==='function');
     const onError=()=>{},onClose=()=>{clearTimeout(wait);body.off('error',onError);resolve();};
     const wait=setTimeout(()=>{body.off('close',onClose);body.off('error',onError);reject(Error('CiSmokeArchiveDrain'));},Math.max(1,Math.min(1000,options.deadlineMs-now())));
     body.once('close',onClose);body.on('error',onError);if(body.closed)onClose();
    });}catch{cleanupFailed=true;}
   }
  }
 }finally{
  clearTimeout(timer);controller.abort();options.signal?.removeEventListener('abort',abort);
  try{if(client)client.destroy();else transport?.destroy();}catch{cleanupFailed=true;}
  if(held){held.accessKeyId='';held.secretAccessKey='';held.sessionToken='';held=null;}
  if(cleanupFailed)throw cleanupError();
 }
}

/** A successful return is a private storage receipt, never source/admission
 * authority. The caller owns the durable operation journal and call ledger;
 * any thrown PutHeld must remain unresolved, with no automatic retry. */
export async function putCiSmokeEnvelope(encoded,options){
 exact(encoded,['bytes','commitment']);need(encoded.bytes instanceof Uint8Array&&encoded.bytes.byteLength<=CI_SMOKE_ARCHIVE_LIMITS.envelopeBytes,'CiSmokeArchiveLimit');
 const bytes=Buffer.from(encoded.bytes),decoded=decodeCiSmokeEnvelope(bytes,encoded.commitment),now=options.now??Date.now;
 await validateCiSmokeProducedEvidence(decoded.records.result,{readJson:decoded.readJson,readBytes:decoded.readBytes,expected:options.expected,now:now()});
 try{return await withClient(decoded.commitment,options,async({config,check,PutObjectCommand,send})=>{
  const checksum=Buffer.from(decoded.commitment.envelopeSha256,'hex').toString('base64'),input={Bucket:config.bucket,Key:config.key,ExpectedBucketOwner:config.account,Body:bytes,ContentLength:bytes.length,ContentType:'application/json',IfNoneMatch:'*',ChecksumAlgorithm:'SHA256',ChecksumSHA256:checksum,ServerSideEncryption:config.encryption.algorithm};
  if(config.encryption.algorithm==='aws:kms'){input.SSEKMSKeyId=config.encryption.keyArn;input.BucketKeyEnabled=config.encryption.bucketKeyEnabled;}
  check();const response=await send(new PutObjectCommand(input));check();assertEncryption(response,config);
  need(response.$metadata?.httpStatusCode===200&&response.ChecksumSHA256===checksum&&typeof response.ETag==='string'&&response.ETag.length>0&&response.ETag.length<=256,'CiSmokeArchivePutReadback');
  need(response.VersionId===undefined||typeof response.VersionId==='string'&&response.VersionId.length>0&&response.VersionId.length<=1024,'CiSmokeArchivePutReadback');
  return Object.freeze({commitment:decoded.commitment,etag:response.ETag,versionId:response.VersionId??null});
 });}catch(error){if(error?.code==='ECLEANUP')throw cleanupError();fail('CiSmokePrivatePutHeld');}
}
export async function getCiSmokeEnvelope(commitment,options){
 const c=inspectCiSmokeCommitment(commitment);
 try{return await withClient(c,options,async({config,check,GetObjectCommand,send,setBody})=>{
  // Do not request a version, extra metadata API or KMS checksum mode. The
  // exact original bytes are independently hashed against the GitHub commitment.
  const response=await send(new GetObjectCommand({Bucket:config.bucket,Key:config.key,ExpectedBucketOwner:config.account}));setBody(response.Body);check();
  need(response.$metadata?.httpStatusCode===200&&response.ContentLength===c.bytesLength,'CiSmokeArchiveGetLength');assertEncryption(response,config);
  const body=response.Body;need(body&&typeof body[Symbol.asyncIterator]==='function'&&typeof body.destroy==='function','CiSmokeArchiveBody');const parts=[];let length=0;
  for await(const chunk of body){check();need(chunk instanceof Uint8Array,'CiSmokeArchiveBody');length+=chunk.byteLength;need(length<=c.bytesLength&&length<=CI_SMOKE_ARCHIVE_LIMITS.envelopeBytes,'CiSmokeArchiveLimit');parts.push(Buffer.from(chunk));}
  check();need(length===c.bytesLength,'CiSmokeArchiveGetLength');const decoded=decodeCiSmokeEnvelope(Buffer.concat(parts,length),c);check();return decoded;
 });}catch(error){if(error?.code==='ECLEANUP')throw cleanupError();fail('CiSmokePrivateGetHeld');}
}

function controlMeter(operation,selector,options){
 const now=options.now??Date.now;
 const startedMs=now();integer(startedMs,1);
 return {version:1,kind:'control-build-capture-transfer',operation,accounting:options.client?'parent-client':'owned-http',envelopeSha256:selector.envelopeSha256,bytesLength:selector.bytesLength,requests:0,requestBodyBytes:0,responseBodyBytes:0,requestBodyBound:operation==='PutObject'?selector.bytesLength:0,responseBodyBound:operation==='GetObject'?selector.bytesLength:65536,startedMs,completedMs:null,complete:false};
}
function finishControlMeter(meter,options,complete){
 const time=(options.now??Date.now)();meter.completedMs=Number.isSafeInteger(time)&&time>=meter.startedMs?time:null;
 meter.complete=complete&&meter.completedMs!==null;
 if(complete)need(meter.complete&&time<options.deadlineMs&&(!options.credentials||time<options.credentials.expiration.getTime()),'ControlCaptureCompletionTime');
 return data(meter,4096);
}
function controlTransferError(error,meter,options){
 const held=error?.code==='ECLEANUP'?cleanupError():Error('ControlCaptureTransferHeld');held.transferReceipt=finishControlMeter(meter,options,false);return held;
}
export async function putControlCaptureBytes(bytes,selector,options){
 const config=controlCaptureArchiveLocation(options.config,selector);need(bytes instanceof Uint8Array&&!types.isProxy(bytes)&&bytes.byteLength===selector.bytesLength,'ControlCaptureBytes');
 need(options.client===undefined,'ControlCaptureWriterOwned');
 const snapshot=Buffer.from(bytes),meter=controlMeter('PutObject',selector,options);
 need(sha(snapshot)===selector.envelopeSha256,'ControlCaptureBytes');
 try{
  const receipt=await withLocatedClient(config,options,async({check,PutObjectCommand,send})=>{
   const checksum=Buffer.from(selector.envelopeSha256,'hex').toString('base64'),input={Bucket:config.bucket,Key:config.key,ExpectedBucketOwner:config.account,Body:snapshot,ContentLength:snapshot.length,ContentType:'application/json',IfNoneMatch:'*',ChecksumAlgorithm:'SHA256',ChecksumSHA256:checksum,ServerSideEncryption:config.encryption.algorithm};
   if(config.encryption.algorithm==='aws:kms'){input.SSEKMSKeyId=config.encryption.keyArn;input.BucketKeyEnabled=config.encryption.bucketKeyEnabled;}
   check();const response=await send(new PutObjectCommand(input));check();assertEncryption(response,config);
   need(response.$metadata?.httpStatusCode===200&&response.ChecksumSHA256===checksum&&typeof response.ETag==='string'&&response.ETag.length>0&&response.ETag.length<=256,'ControlCapturePutReadback');
   need(response.VersionId===undefined||typeof response.VersionId==='string'&&response.VersionId.length>0&&response.VersionId.length<=1024,'ControlCapturePutReadback');
   return {etag:response.ETag,versionId:response.VersionId??null};
  },meter);
  return Object.freeze({...receipt,transferReceipt:finishControlMeter(meter,options,true)});
 }catch(error){throw controlTransferError(error,meter,options);}
}
export async function getControlCaptureBytes(selector,options){
 const config=controlCaptureArchiveLocation(options.config,selector),meter=controlMeter('GetObject',selector,options);
 try{
  const run=options.client?withBorrowedControlReader:withLocatedClient;
  const bytes=await run(config,options,async({check,GetObjectCommand,send,setBody})=>{
   const response=await send(new GetObjectCommand({Bucket:config.bucket,Key:config.key,ExpectedBucketOwner:config.account}));setBody(response.Body);check();
   need(response.$metadata?.httpStatusCode===200&&response.ContentLength===selector.bytesLength,'ControlCaptureGetLength');assertEncryption(response,config);
   const stream=response.Body;need(stream&&typeof stream[Symbol.asyncIterator]==='function'&&typeof stream.destroy==='function','ControlCaptureResponseBody');const chunks=[];
   for await(const chunk of stream){check();need(chunk instanceof Uint8Array);meter.responseBodyBytes+=chunk.byteLength;need(meter.responseBodyBytes<=meter.responseBodyBound,'ControlCaptureResponseLimit');chunks.push(Buffer.from(chunk));}
   const raw=Buffer.concat(chunks);check();need(raw.length===selector.bytesLength&&sha(raw)===selector.envelopeSha256,'ControlCaptureBytes');return raw;
  },meter);
  return Object.freeze({bytes,transferReceipt:finishControlMeter(meter,options,true)});
 }catch(error){throw controlTransferError(error,meter,options);}
}

// The supplied client already owns endpoint/session/retry constraints and the
// whole-operation ledger. Count this one SDK dispatch as parent-client, never
// manufacture a second session or destroy the parent's client.
async function withBorrowedControlReader(config,options,operation,meter){
 need(options.credentials===undefined&&options.requestHandler===undefined&&typeof options.client?.send==='function','ControlCaptureReaderOptions');
 const now=options.now??Date.now,controller=new AbortController();integer(options.deadlineMs,1);
 const start=now();integer(start,1);need(options.deadlineMs>start&&options.deadlineMs<=start+900000,'CiSmokeArchiveDeadline');
 let body,timer,cleanupFailed=false;
 const close=()=>{if(body&&!body.destroyed){try{need(typeof body.destroy==='function');body.destroy();}catch{cleanupFailed=true;}}};
 const abort=()=>{controller.abort();close();};
 const check=()=>{const t=now();integer(t,1);need(!controller.signal.aborted&&t>=start&&t<options.deadlineMs,'CiSmokeArchiveExpired');};
 if(options.signal?.aborted)abort();options.signal?.addEventListener('abort',abort,{once:true});
 try{
  check();timer=setTimeout(abort,options.deadlineMs-start);timer.unref?.();
  const {GetObjectCommand}=await import('@aws-sdk/client-s3');check();
  return await operation({config,check,GetObjectCommand,setBody:value=>{body=value;},send:command=>{
   check();need(command instanceof GetObjectCommand&&meter.requests===0,'ControlCaptureRequestCount');meter.requests++;
   return options.client.send(command,{abortSignal:controller.signal});
  }});
 }finally{
  clearTimeout(timer);abort();options.signal?.removeEventListener('abort',abort);
  if(body&&!body.closed){
   try{await new Promise((resolve,reject)=>{
    need(typeof body.once==='function'&&typeof body.off==='function');
    const error=()=>{},closed=()=>{clearTimeout(wait);body.off('error',error);resolve();};
    const wait=setTimeout(()=>{body.off('close',closed);body.off('error',error);reject(Error('ControlCaptureDrain'));},Math.max(1,Math.min(1000,options.deadlineMs-now())));
    body.once('close',closed);body.on('error',error);if(body.closed)closed();
   });}catch{cleanupFailed=true;}
  }
  if(cleanupFailed)throw cleanupError();
 }
}
