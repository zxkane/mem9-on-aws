/** A prepaid READ-ONLY acquisition. The owner seed hash is deployment
 * configuration, independent of the allocation object. Neither a seed nor a
 * budget receipt replaces source/proof/phase verification or permits writes. */
import {S3Client,GetObjectCommand} from '@aws-sdk/client-s3';
import {NodeHttpHandler} from '@smithy/node-http-handler';
import {Readable} from 'node:stream';
import {mkdir,lstat,realpath} from 'node:fs/promises';
import {readFileSync,lstatSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {smokePrivateRead,smokePrivateWrite} from './ci-smoke-host.mjs';
import {PRODUCTION_DATA_RELEASE_PARAMETER} from './production-data-issuance.mjs';
import {hash,sha,need,exact,same,hex,integer,counter,zero,COUNTERS,scopeCheck,verifyPrepaidAllocationDocument,parseAcquisitionJson} from './ci-smoke-acquisition-format.mjs';
import {openPreviewCiSmokeAcquisition} from './ci-smoke-preview-acquisition.mjs';

const MAX=33554432,parse=raw=>parseAcquisitionJson(Buffer.from(raw));
/** Owner-side configuration export from independent existing records. This
 * performs no AWS/GitHub write and contains no future run or observed hashes. */
export function createCiSmokeAcquisitionConfig({account,region,ownerRoot,ledgerStartBytes,catalogBytes,expiresMs,target,storage}){
 const start=parse(ledgerStartBytes),catalog=parse(catalogBytes);need(start.kind==='custody-ledger-start'&&start.mode==='adoption'&&catalog.kind==='cumulative-acquisition-catalog','CiAcquisitionConfigRecords');same(start.binding,catalog.ledgerBinding,'CiAcquisitionConfigLedger');
 return {version:1,kind:'owner-ci-acquisition-config',account,region,ownerRoot:structuredClone(ownerRoot),ledgerBinding:structuredClone(start.binding),ledgerStartHash:sha(ledgerStartBytes),catalogHash:sha(catalogBytes),expiresMs,target:structuredClone(target),storage:structuredClone(storage)};
}
function sameJob(scope,env,source){
 need(env.GITHUB_ACTIONS==='true'&&scope.repository===env.GITHUB_REPOSITORY&&scope.runId===Number(env.GITHUB_RUN_ID)&&scope.runAttempt===Number(env.GITHUB_RUN_ATTEMPT)&&scope.jobKey===env.GITHUB_JOB&&scope.mainRevision===env.GITHUB_SHA&&scope.region===env.AWS_REGION,'CiAcquisitionJob');
 const c=source.current;need(c?.repository===scope.repository&&c.runId===scope.runId&&c.runAttempt===scope.runAttempt&&c.job===scope.jobKey&&c.revision===scope.mainRevision&&source.checkout?.revision===scope.mainRevision&&source.checkout.tree===scope.sourceTree,'CiAcquisitionSourceJob');
 need(integer(source.observedMs)&&integer(source.expiresMs)&&source.observedMs<=Date.now()&&Date.now()<source.expiresMs,'CiAcquisitionSourceExpired');
}
export function acquisitionOwnerKey(seed){const d=seed.ownerRoot??seed.descriptor,s=seed.expected.scope;need(hex(d.runtimeNonce,32)&&hex(d.authorizationId,32),'CiAcquisitionOwnerScope');return `data-authorizations/${d.runtimeNonce}/${d.authorizationId}/ci-acquisitions/${s.runId}/${s.runAttempt}/${s.jobKey}/${hash(s.checkpoint)}.json`;}
/** Static owner-protected configuration is set before the workflow is queued.
 * Actual run/job/source fields come from the already verified local receipt.
 * No future run, receipt hash, allocation hash or bundle is predicted here. */
export function acquisitionSeedFromConfig(config,{env,scope,sourceReceipt}){
 exact(config,['version','kind','account','region','ownerRoot','ledgerBinding','ledgerStartHash','catalogHash','expiresMs','target','storage']);need(config.version===1&&config.kind==='owner-ci-acquisition-config','CiAcquisitionOwnerConfig');exact(config.ownerRoot,['runtimeNonce','authorizationId']);
 const preview=config.target.kind==='preview-bootstrap';exact(config.target,preview?['kind']:['kind','descriptor','parameterVersion']);need(preview?/^pr-[1-9][0-9]*$/.test(env.STAGE??''):config.target.kind==='production-data-release'&&env.STAGE==='prod','CiAcquisitionTargetKind');need(preview?['deploy-preview','runtime-cutover-preview'].includes(scope.route):['deploy-prod','runtime-cutover-prod'].includes(scope.route),'CiAcquisitionRouteBudgetKind');
 const d=config.target.descriptor,s={descriptorHash:preview?null:hash(d),proofHash:preview?null:d.transition?.proofHash,sourceTree:sourceReceipt.checkout.tree,repository:env.GITHUB_REPOSITORY,mainRevision:env.GITHUB_SHA,runId:Number(env.GITHUB_RUN_ID),runAttempt:Number(env.GITHUB_RUN_ATTEMPT),jobKey:env.GITHUB_JOB,...scope,account:config.account,region:config.region,...(preview?{target:{kind:'preview-bootstrap',stage:env.STAGE}}:{})};
 const seed={version:1,kind:preview?'owner-ci-preview-acquisition-seed':'owner-ci-acquisition-seed',ownerRoot:config.ownerRoot,expected:{scope:s,ledgerBinding:config.ledgerBinding,ledgerStartHash:config.ledgerStartHash,catalogHash:config.catalogHash},...(preview?{preview:{stage:env.STAGE}}:{descriptor:d,parameterVersion:config.target.parameterVersion}),expiresMs:config.expiresMs,allocation:{...config.storage,key:'',sha256:null,bytesLength:null}};seed.allocation.key=acquisitionOwnerKey(seed);return inspectAcquisitionSeed(seed);
}
export function inspectAcquisitionSeed(seed){
 const preview=seed.kind==='owner-ci-preview-acquisition-seed';exact(seed,['version','kind','expected',...(seed.ownerRoot?['ownerRoot']:[]),...(preview?['preview']:['descriptor','parameterVersion']),'expiresMs','allocation']);need(seed.version===1&&(preview||seed.kind==='owner-ci-acquisition-seed'),'CiAcquisitionSeed');
 exact(seed.expected,['scope','ledgerBinding','ledgerStartHash','catalogHash']);scopeCheck(seed.expected.scope);need(hex(seed.expected.ledgerStartHash)&&hex(seed.expected.catalogHash),'CiAcquisitionAnchor');
 const s=seed.expected.scope,d=seed.descriptor;need(integer(seed.expiresMs)&&Date.now()<seed.expiresMs,'CiAcquisitionSeedExpired');if(preview){exact(seed.preview,['stage']);need(s.target?.kind==='preview-bootstrap'&&s.target.stage===seed.preview.stage&&s.descriptorHash===null&&s.proofHash===null,'CiAcquisitionPreviewScope');}else{need(!s.target&&hash(d)===s.descriptorHash&&d.transition?.proofHash===s.proofHash&&d.account===s.account&&d.region===s.region&&integer(seed.parameterVersion)&&seed.parameterVersion>0&&seed.expiresMs<=d.expiresMs,'CiAcquisitionSeedDescriptor');if(seed.ownerRoot)same(seed.ownerRoot,{runtimeNonce:d.runtimeNonce,authorizationId:d.authorizationId},'CiAcquisitionOwnerScope');}
 const a=seed.allocation;exact(a,['bucket','key','sha256','bytesLength','requestBytes','responseBytes','kmsKeyArn','bucketKeyEnabled']);need(/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(a.bucket)&&!a.bucket.includes('..')&&a.key===acquisitionOwnerKey(seed)&&(a.sha256===null&&a.bytesLength===null||hex(a.sha256)&&integer(a.bytesLength)&&a.bytesLength>0&&a.bytesLength<=a.responseBytes)&&a.responseBytes<=MAX&&integer(a.requestBytes)&&a.requestBytes>0&&a.requestBytes<=16384&&a.bucketKeyEnabled===true,'CiAcquisitionOwnerObject');need(new RegExp('^arn:aws:kms:'+s.region+':'+s.account+':key/(?:[a-f0-9-]{36}|mrk-[a-f0-9]{32})$').test(a.kmsKeyArn),'CiAcquisitionKms');return seed;
}
function immutable(ref){const s=lstatSync(ref.path);need(s.isFile()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&s.nlink===1&&(s.mode&511)===0o600&&sha(readFileSync(ref.path))===ref.sha256,'CiAcquisitionLocalChanged');}
async function directory(env){need(typeof env.RUNNER_TEMP==='string'&&resolve(env.RUNNER_TEMP)===env.RUNNER_TEMP&&await realpath(env.RUNNER_TEMP)===env.RUNNER_TEMP,'CiAcquisitionTemp');const path=join(env.RUNNER_TEMP,'mem9-ci-acquisitions');try{await mkdir(path,{mode:0o700});}catch(e){if(e.code!=='EEXIST')throw e;}const s=await lstat(path);need(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&(s.mode&511)===0o700&&await realpath(path)===path,'CiAcquisitionDirectory');return path;}
async function save(dir,name,value){const path=join(dir,name);return {path,sha256:await smokePrivateWrite(path,value)};}
async function readOwnerAllocation(seed,env,check){
 const a=seed.allocation,s=seed.expected.scope;need([env.AWS_ACCESS_KEY_ID,env.AWS_SECRET_ACCESS_KEY,env.AWS_SESSION_TOKEN].every(v=>typeof v==='string'&&v.length>0),'CiAcquisitionCredentials');
 const held={accessKeyId:env.AWS_ACCESS_KEY_ID,secretAccessKey:env.AWS_SECRET_ACCESS_KEY,sessionToken:env.AWS_SESSION_TOKEN},controller=new AbortController();let body,client,cleanupFailed=false;
 const transport=new NodeHttpHandler({connectionTimeout:5000,requestTimeout:30000}),timer=setTimeout(()=>{controller.abort();body?.destroy();client?.destroy();},30000);
 try{
  const handler={handle(request,options){check();need(request.protocol==='https:'&&request.hostname===`s3.${s.region}.amazonaws.com`&&request.method==='GET'&&request.path==='/'+a.bucket+'/'+a.key,'CiAcquisitionEndpoint');return transport.handle(request,options);},destroy(){transport.destroy();}};
  client=new S3Client({region:s.region,endpoint:`https://s3.${s.region}.amazonaws.com`,forcePathStyle:true,followRegionRedirects:false,ignoreConfiguredEndpointUrls:true,maxAttempts:1,credentials:held,requestChecksumCalculation:'WHEN_REQUIRED',responseChecksumValidation:'WHEN_REQUIRED',requestHandler:handler});
  check();const response=await client.send(new GetObjectCommand({Bucket:a.bucket,Key:a.key,ExpectedBucketOwner:s.account}),{abortSignal:controller.signal});body=response.Body;
  need(response.$metadata?.httpStatusCode===200&&integer(response.ContentLength)&&response.ContentLength>0&&response.ContentLength<=a.responseBytes&&(a.bytesLength===null||response.ContentLength===a.bytesLength)&&response.ServerSideEncryption==='aws:kms'&&response.SSEKMSKeyId===a.kmsKeyArn&&response.BucketKeyEnabled===true&&body instanceof Readable,'CiAcquisitionOwnerResponse');
  const chunks=[];let size=0;for await(const chunk of body){check();controller.signal.throwIfAborted();need(chunk instanceof Uint8Array,'CiAcquisitionBody');size+=chunk.length;need(size<=response.ContentLength&&size<=a.responseBytes,'CiAcquisitionBodyCap');chunks.push(chunk);}need(size===response.ContentLength,'CiAcquisitionBodyLength');const raw=Buffer.concat(chunks,size);if(a.sha256!==null)need(sha(raw)===a.sha256,'CiAcquisitionOwnerHash');return raw;
 }finally{
  clearTimeout(timer);controller.abort();body?.destroy();
  if(body&&!body.closed)try{await new Promise((ok,bad)=>{const done=()=>{clearTimeout(t);ok();},t=setTimeout(()=>{body.off('close',done);bad(Error('CiAcquisitionDrain'));},1000);body.once('close',done);if(body.closed)done();});}catch{cleanupFailed=true;}
  try{client?.destroy();transport.destroy();}catch{cleanupFailed=true;}held.accessKeyId='';held.secretAccessKey='';held.sessionToken='';if(cleanupFailed)throw Object.assign(Error('ECLEANUP'),{code:'ECLEANUP'});
 }
}

/** MEM9_CI_ACQUISITION_CONFIG is static owner-protected deployment configuration,
 * never generated from the candidate allocation. Its single owner-object Get
 * is reserved in the fixed catalog and charged in calls[0]. The
 * existing owner publisher accounts for its Put separately in the same ledger. */
export async function openCiSmokeAcquisition({env,scope,sourceReceipt,host}){
 exact(scope,['route','phase','checkpoint']);need(host&&typeof host.checkout==='function'&&host.env===env,'CiAcquisitionHost');
 if(['deploy-preview','runtime-cutover-preview'].includes(scope.route))return openPreviewCiSmokeAcquisition({env,scope,sourceReceipt,host});
 if(typeof env.MEM9_CI_ACQUISITION_CONFIG==='string'&&Buffer.byteLength(env.MEM9_CI_ACQUISITION_CONFIG)<=65536&&[2,3].includes(parse(env.MEM9_CI_ACQUISITION_CONFIG).version)){
  const {openFutureCiSmokeAcquisition}=await import('./ci-smoke-future-acquisition.mjs');return openFutureCiSmokeAcquisition({env,scope,sourceReceipt,host});
 }
 need(typeof env.MEM9_CI_ACQUISITION_CONFIG==='string'&&Buffer.byteLength(env.MEM9_CI_ACQUISITION_CONFIG)<=65536,'CiAcquisitionOwnerConfigRequired');const configRaw=env.MEM9_CI_ACQUISITION_CONFIG,configHash=sha(configRaw),seed=acquisitionSeedFromConfig(parse(configRaw),{env,scope,sourceReceipt}),s=seed.expected.scope;for(const k of ['route','phase','checkpoint'])need(scope[k]===s[k],'CiAcquisitionScope');sameJob(s,env,sourceReceipt);
 const sourceRef={path:env.MEM9_CI_SMOKE_SOURCE_RECEIPT,sha256:env.MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH};need(hex(sourceRef.sha256),'CiAcquisitionSourceRef');const sourceRaw=await smokePrivateRead(sourceRef.path,MAX);need(sha(sourceRaw)===sourceRef.sha256,'CiAcquisitionSourceHash');same(parse(sourceRaw),sourceReceipt,'CiAcquisitionSourceChanged');same(await host.checkout(),sourceReceipt.checkout,'CiAcquisitionCheckout');
 const expiresMs=Math.min(seed.expiresMs,sourceReceipt.expiresMs),check=()=>{need(Date.now()<expiresMs,'CiAcquisitionExpired');need(sha(env.MEM9_CI_ACQUISITION_CONFIG)===configHash,'CiAcquisitionConfigChanged');immutable(sourceRef);},dir=await directory(env),key=hash(Object.fromEntries(['repository','runId','runAttempt','jobKey','route','checkpoint'].map(k=>[k,s[k]]))),prefix='acquisition-'+key,openedMs=Date.now();check();
 const claimRef=await save(dir,prefix+'-claim.json',{version:1,kind:'ci-prepaid-slot-claim',scope:s,configHash,sourceReceiptRef:sourceRef,openedMs,expiresMs,ownerRefund:0});let paid,allocationRef,wire=0,active=false,next=1,sealed=false,liveMatched=false;const localUsed=zero();
 const hold=async code=>{sealed=true;await save(dir,prefix+'-held.json',{version:1,claimRef,code,ownerRefund:0});};
 try{
  const raw=await readOwnerAllocation(seed,env,check);paid=verifyPrepaidAllocationDocument(parse(raw),seed.expected);const first=paid.calls[0],expectedRequest={Bucket:seed.allocation.bucket,Key:seed.allocation.key,ExpectedBucketOwner:s.account};need(first.action==='GetObject'&&first.ecr===false,'CiAcquisitionBootstrapPrepaid');same(first.request,expectedRequest,'CiAcquisitionBootstrapObject');need(first.requestBytes===seed.allocation.requestBytes&&first.responseBytes===seed.allocation.responseBytes,'CiAcquisitionBootstrapCap');wire=raw.length;
  allocationRef=await save(dir,prefix+'-allocation.json',raw);check();
 }catch(e){await hold(e.code==='ECLEANUP'?'ECLEANUP':'CiAcquisitionBootstrapHeld');throw e;}
 const current=()=>{check();need(!sealed,'CiAcquisitionClosed');};
 const preview=s.target?.kind==='preview-bootstrap',previewNames=preview?['purpose-bindings','cluster-name','subnet-ids','task-sg-id'].map(n=>'/mem9-on-aws/'+s.target.stage+'/bootstrap/'+n):[];
 const previewDescriptor=response=>{const rows=response?.Parameters??[],missing=response?.InvalidParameters??[];need(Array.isArray(rows)&&Array.isArray(missing),'CiAcquisitionPreviewRead');const all=[...rows.map(p=>p.Name),...missing];need(new Set(all).size===all.length&&hash(all.toSorted())===hash(previewNames.toSorted()),'CiAcquisitionPreviewRead');if(rows.length===0)need(s.phase==='preupdate','CiAcquisitionPreviewAbsent');else{need(missing.length===0,'CiAcquisitionPreviewPartial');for(const p of rows)need(p.ARN===`arn:aws:ssm:${s.region}:${s.account}:parameter${p.Name}`&&typeof p.Value==='string'&&integer(p.Version)&&p.Version>0,'CiAcquisitionPreviewRead');}liveMatched=true;};
 const liveDescriptor=response=>{need((response?.InvalidParameters??[]).length===0&&response.Parameters?.length===1,'CiAcquisitionLiveDescriptor');const p=response.Parameters[0];need(p.Name===PRODUCTION_DATA_RELEASE_PARAMETER&&p.Type==='SecureString'&&p.ARN===`arn:aws:ssm:${s.region}:${s.account}:parameter${PRODUCTION_DATA_RELEASE_PARAMETER}`&&p.Version===seed.parameterVersion&&typeof p.Value==='string','CiAcquisitionLiveDescriptor');const data=parse(p.Value);need(hash(data)===s.descriptorHash&&data.transition?.proofHash===s.proofHash&&Date.now()<data.expiresMs,'CiAcquisitionLiveDescriptor');liveMatched=true;};
 return Object.freeze({authority:false,authorizationSeed:Object.freeze(preview?{kind:'preview-bootstrap',stage:s.target.stage,account:s.account,region:s.region,sourceTree:s.sourceTree}:{kind:'production-data-release',descriptor:structuredClone(seed.descriptor),descriptorHash:s.descriptorHash,proofHash:s.proofHash,parameterVersion:seed.parameterVersion}),
  async beforeRead(action,request){try{current();need(!active&&next<paid.calls.length,'CiAcquisitionCallCount');const c=paid.calls[next];need(c.action===action,'CiAcquisitionCall');same(c.request,request,'CiAcquisitionRequest');if(preview&&['GetParameter','GetParameters'].includes(action)){const names=action==='GetParameter'?[request.Name]:request.Names;need(Array.isArray(names)&&names.every(n=>typeof n==='string'&&n.startsWith('/mem9-on-aws/'+s.target.stage+'/')),'CiAcquisitionPreviewParameterScope');}if(preview&&['BatchGetImage','DescribeImageScanFindings','GetDownloadUrlForLayer','BatchCheckLayerAvailability','DescribeRepositories','GetLifecyclePolicy'].includes(action))need(request.repositoryName?.startsWith('mem9-on-aws/preview/')||request.repositoryNames?.every(n=>n.startsWith('mem9-on-aws/preview/')),'CiAcquisitionPreviewRepositoryScope');if(!liveMatched){need(['GetCallerIdentity','GetParameters'].includes(action),'CiAcquisitionLiveDescriptorFirst');if(action==='GetParameters')same(request,preview?{Names:previewNames,WithDecryption:false}:{Names:[PRODUCTION_DATA_RELEASE_PARAMETER],WithDecryption:true},'CiAcquisitionLiveDescriptorFirst');}active=true;const index=next;let dispatched=false,settled=false,charged=0;await save(dir,prefix+'-read-'+index+'.json',{version:1,claimRef,index,action,request,caps:{requestBytes:c.requestBytes,responseBytes:c.responseBytes}});
   return Object.freeze({caps:{requestBytes:c.requestBytes,responseBytes:c.responseBytes,overshootBytes:8388608},finalGuard(){try{current();need(!dispatched&&!settled,'CiAcquisitionDispatch');dispatched=true;}catch(e){sealed=true;throw e;}},charge(n){try{need(dispatched&&!settled&&integer(n),'CiAcquisitionCharge');charged+=n;wire+=n;need(charged<=c.requestBytes+c.responseBytes+8388608&&wire<=paid.budget.httpBodyBytes,'CiAcquisitionCap');}catch(e){sealed=true;throw e;}},async complete(response,responseHash){try{current();need(dispatched&&!settled&&hex(responseHash)&&charged<=c.requestBytes+c.responseBytes,'CiAcquisitionComplete');if(action==='GetParameters'){if(preview&&hash(request.Names)===hash(previewNames))previewDescriptor(response);else if(!preview&&request.Names.includes(PRODUCTION_DATA_RELEASE_PARAMETER))liveDescriptor(response);}if(action==='GetCallerIdentity')need(response.Account===s.account,'CiAcquisitionCaller');settled=true;await save(dir,prefix+'-result-'+index+'.json',{version:1,claimRef,index,responseHash,charged});next++;active=false;}catch(e){sealed=true;throw e;}},async unknown(){if(settled)return;settled=true;active=false;await hold('CiAcquisitionReadUnknown');}});
  }catch(e){sealed=true;throw e;}},
  reserveLocal(charge){try{current();need(liveMatched,'CiAcquisitionLiveDescriptorFirst');counter(charge);need(charge.ecrRequests===0&&charge.httpBodyBytes===0,'CiAcquisitionLocalCharge');const updated={};for(const k of COUNTERS){updated[k]=localUsed[k]+charge[k];need(updated[k]<=paid.localBudget[k],'CiAcquisitionLocalCap');}Object.assign(localUsed,updated);return {...localUsed};}catch(e){sealed=true;throw e;}},
  async finish({bundleRef}={}){
   try{current();need(liveMatched&&!active&&next===paid.calls.length,'CiAcquisitionIncomplete');need(bundleRef,'CiAcquisitionBundleRequired');let b,ref;
    if(Object.hasOwn(bundleRef,'value')){exact(bundleRef,['value','canonicalHash']);const raw=Buffer.from(JSON.stringify(structuredClone(bundleRef.value)));need(raw.length<=MAX,'CiAcquisitionBundleSize');b=parse(raw);need(hash(b)===bundleRef.canonicalHash,'CiAcquisitionBundleHash');ref=await save(dir,prefix+'-bundle.json',raw);}
    else{exact(bundleRef,['path','sha256']);need(hex(bundleRef.sha256),'CiAcquisitionBundleRequired');const raw=await smokePrivateRead(bundleRef.path,MAX);need(sha(raw)===bundleRef.sha256,'CiAcquisitionBundleHash');b=parse(raw);ref=bundleRef;}
    const p=b.phaseReceipt;
    if(preview)need(b.kind==='nonroot-preview-phase-bundle'&&b.source?.sourceTree===s.sourceTree&&p?.stage===s.target.stage&&p.account===s.account&&p.region===s.region&&p.sourceTree===s.sourceTree,'CiAcquisitionPreviewBundle');
    else need(b.kind==='image-security-nonroot-deployment-bundle'&&b.source?.checkout?.tree===s.sourceTree&&typeof b.parameter?.Value==='string'&&hash(parse(b.parameter.Value))===s.descriptorHash&&hash(b.proof)===s.proofHash,'CiAcquisitionBundleBinding');
    need(p?.phase===s.phase&&p.sourceReceiptHash===sourceRef.sha256&&p.observedMs>=openedMs&&p.observedMs<=Date.now()&&Date.now()<p.expiresMs,'CiAcquisitionBundleBinding');sealed=true;
    const receiptRef=await save(dir,prefix+'-complete.json',{version:1,claimRef,allocationRef,allocationId:paid.allocationId,sourceReceiptRef:sourceRef,bundleRef:ref,sourceReceiptHash:sourceRef.sha256,bundleHash:ref.sha256,observedWireBytes:wire,localUsed,originalPrepaidBudget:paid.budget,ownerRefund:0,authority:false});return {authority:false,receiptRef};
   }catch(e){sealed=true;throw e;}
  },
 });
}

/** Reuse only unused, already debited LOCAL work in the same deployment job.
 * The network acquisition remains closed. This handle has no network method,
 * never reopens the owner ledger, and cannot extend admission or refund work. */
export async function openCiSmokeDeploymentLocalReplay({env,completionRef,bundleRef,knownParameter}){
 if(typeof env.MEM9_CI_ACQUISITION_CONFIG==='string'&&Buffer.byteLength(env.MEM9_CI_ACQUISITION_CONFIG)<=65536&&[2,3].includes(parse(env.MEM9_CI_ACQUISITION_CONFIG).version)){
  const {openFutureCiSmokeLocalReplay}=await import('./ci-smoke-future-acquisition.mjs');return openFutureCiSmokeLocalReplay({env,completionRef,bundleRef,knownParameter});
 }
 need(env.GITHUB_ACTIONS==='true'&&env.STAGE==='prod'&&env.GITHUB_JOB==='deploy-prod','CiLocalReplayJob');
 const read=async ref=>{
  exact(ref,['path','sha256']);need(hex(ref.sha256),'CiLocalReplayReference');
  const raw=await smokePrivateRead(ref.path,MAX);need(sha(raw)===ref.sha256,'CiLocalReplayHash');return parse(raw);
 };
 const done=await read(completionRef);
 exact(done,['version','claimRef','allocationRef','allocationId','sourceReceiptRef','bundleRef','sourceReceiptHash','bundleHash','observedWireBytes','localUsed','originalPrepaidBudget','ownerRefund','authority']);
 need(done.version===1&&done.authority===false&&done.ownerRefund===0&&hex(done.allocationId)&&integer(done.observedWireBytes),'CiLocalReplayReceipt');
 same(done.bundleRef,bundleRef,'CiLocalReplayBundle');
 const [claim,source,bundle,allocation]=await Promise.all([read(done.claimRef),read(done.sourceReceiptRef),read(bundleRef),read(done.allocationRef)]);
 exact(claim,['version','kind','scope','configHash','sourceReceiptRef','openedMs','expiresMs','ownerRefund']);
 need(claim.version===1&&claim.kind==='ci-prepaid-slot-claim'&&claim.ownerRefund===0&&integer(claim.openedMs)&&integer(claim.expiresMs),'CiLocalReplayClaim');
 same(claim.sourceReceiptRef,done.sourceReceiptRef,'CiLocalReplaySource');
 need(done.sourceReceiptHash===done.sourceReceiptRef.sha256&&done.bundleHash===bundleRef.sha256,'CiLocalReplayReceipt');
 const phase=bundle.phaseReceipt?.phase;
 need(bundle.kind==='image-security-nonroot-deployment-bundle'&&bundle.phase==='deployment'&&['preconfigure','presst'].includes(phase)&&claim.scope.phase===phase,'CiLocalReplayPhase');
 // These two fixed consumers are the separate configure process and SST.
 // Other protected operations cannot reuse their local allowance.
 const checkpoint=phase==='presst'?'deploy-prod/19':'deploy-prod/17';
 need(claim.scope.route==='deploy-prod'&&claim.scope.checkpoint===checkpoint,'CiLocalReplayCheckpoint');
 need(typeof env.MEM9_CI_ACQUISITION_CONFIG==='string'&&Buffer.byteLength(env.MEM9_CI_ACQUISITION_CONFIG)<=65536,'CiAcquisitionOwnerConfigRequired');
 const configRaw=env.MEM9_CI_ACQUISITION_CONFIG;need(sha(configRaw)===claim.configHash,'CiLocalReplayConfig');
 const seed=acquisitionSeedFromConfig(parse(configRaw),{env,scope:{route:'deploy-prod',phase,checkpoint},sourceReceipt:source});
 sameJob(seed.expected.scope,env,source);same(seed.expected.scope,claim.scope,'CiLocalReplayScope');
 const paid=verifyPrepaidAllocationDocument(allocation,seed.expected);
 need(paid.allocationId===done.allocationId,'CiLocalReplayAllocation');same(done.originalPrepaidBudget,paid.budget,'CiLocalReplayBudget');
 counter(done.localUsed);const used={...done.localUsed};
 for(const key of COUNTERS)need(used[key]<=paid.localBudget[key],'CiLocalReplayBudget');
 need(used.ecrRequests===0&&used.httpBodyBytes===0&&done.observedWireBytes<=paid.budget.httpBodyBytes,'CiLocalReplayBudget');
 const parameter=Object.fromEntries(['Name','Type','ARN','Version','Value'].map(key=>[key,knownParameter?.[key]]));
 same(bundle.parameter,parameter,'CiLocalReplayParameter');
 need(knownParameter.Name===PRODUCTION_DATA_RELEASE_PARAMETER&&knownParameter.Type==='SecureString'&&
  knownParameter.ARN===`arn:aws:ssm:${seed.expected.scope.region}:${seed.expected.scope.account}:parameter${PRODUCTION_DATA_RELEASE_PARAMETER}`&&
  knownParameter.Version===seed.parameterVersion&&hash(parse(knownParameter.Value))===seed.expected.scope.descriptorHash&&hash(bundle.proof)===seed.expected.scope.proofHash,'CiLocalReplayParameter');
 need(bundle.source?.checkout?.sha===env.GITHUB_SHA&&bundle.source.checkout.tree===source.checkout.tree&&
  bundle.phaseReceipt.sourceReceiptHash===done.sourceReceiptRef.sha256&&bundle.phaseReceipt.observedMs>=claim.openedMs&&bundle.phaseReceipt.observedMs<=Date.now(),'CiLocalReplayBundle');
 const dir=await directory(env),key=hash(Object.fromEntries(['repository','runId','runAttempt','jobKey','route','checkpoint'].map(k=>[k,claim.scope[k]]))),prefix='acquisition-'+key;
 for(const[ref,suffix]of [[completionRef,'complete'],[done.claimRef,'claim'],[done.allocationRef,'allocation']])need(ref.path===join(dir,prefix+'-'+suffix+'.json'),'CiLocalReplayOwnedPath');
 const refs=[completionRef,done.claimRef,done.allocationRef,done.sourceReceiptRef,bundleRef];
 const expiresMs=Math.min(seed.expiresMs,claim.expiresMs,source.expiresMs,bundle.phaseReceipt.expiresMs);
 need(integer(expiresMs)&&Date.now()<expiresMs,'CiLocalReplayExpired');
 const check=()=>{
  need(Date.now()<expiresMs&&sha(env.MEM9_CI_ACQUISITION_CONFIG)===claim.configHash,'CiLocalReplayExpired');
  for(const ref of refs)immutable(ref);
 };
 check();const localPrefix=prefix+'-local-'+(phase==='presst'?'sst':'configure');
 const claimRef=await save(dir,localPrefix+'-claim.json',{version:1,kind:'ci-prepaid-local-replay',allocationId:paid.allocationId,completionRef,bundleRef,scope:claim.scope,startedMs:Date.now(),expiresMs,startingLocalUsed:used,ownerRefund:0});
 let sealed=false;
 const current=()=>{need(!sealed,'CiLocalReplayClosed');check();};
 return Object.freeze({authority:false,expiresMs,
  reserveLocal(charge){
   try{current();counter(charge);need(charge.ecrRequests===0&&charge.httpBodyBytes===0,'CiLocalReplayNetworkForbidden');
    const next={};for(const key of COUNTERS){next[key]=used[key]+charge[key];need(next[key]<=paid.localBudget[key],'CiLocalReplayBudget');}Object.assign(used,next);return {...used};
   }catch(error){sealed=true;throw error;}
  },
  async finish(){current();sealed=true;return {authority:false,receiptRef:await save(dir,localPrefix+'-complete.json',{version:1,claimRef,allocationId:paid.allocationId,completionRef,bundleRef,startingLocalUsed:done.localUsed,localUsed:used,ownerRefund:0,completedMs:Date.now()})};},
  async hold(){sealed=true;try{await save(dir,localPrefix+'-held.json',{version:1,claimRef,ownerRefund:0});}catch(error){if(error.code!=='EEXIST')throw error;}},
 });
}
