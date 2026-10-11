import {beginCarrierLocalCleanup,drainCarrierLocalCounter,closeCarrierLocalCounter} from './ci-carrier-local-counter.mjs';
import {normalizeImageDigestResponse,imageResponseFromSdk} from './production-image-response.mjs';
/** The CI journal spends an already-paid R9 allocation. It never creates a
 * ledger, claim, credit, refund, replacement grant or extended deadline. */
import {mkdirSync,openSync,writeSync,fsyncSync,closeSync,fstatSync,lstatSync,realpathSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {consumeCarrierStartup,inspectCarrierWorkerConfig} from './ci-carrier-startup.mjs';
import {CARRIER_PROFILE_ACTIONS,carrierBlobDebit,verifyCarrierBeforeCopyGrant,carrierObjectKeys,carrierCheckpointSelection,carrierHash as hash} from './ci-carrier-before-copy.mjs';
import {makeCarrierBuildResult,inspectCarrierBuildResult} from './ci-carrier-result.mjs';
import {inspectCarrierOfflineBuild} from './production-nonroot-carrier-build.mjs';
import {IMAGE_MEDIA,decodeImageDescriptorData,imageDescriptorDataLocalBytes,imageGraphState} from './production-image-graph.mjs';
import {parseAcquisitionJson,sha,zero,need,exact,freeze,COUNTERS} from './ci-smoke-acquisition-format.mjs';
import {IMAGE_TRANSITION_LIMITS as L} from './production-image-transition.mjs';

const manifests=new Set([IMAGE_MEDIA.index,IMAGE_MEDIA.dockerIndex,IMAGE_MEDIA.manifest,IMAGE_MEDIA.dockerManifest]),indexes=new Set([IMAGE_MEDIA.index,IMAGE_MEDIA.dockerIndex]);
const handles=new WeakMap();
const normalized=q=>Object.fromEntries(Object.entries(q).map(([k,v])=>[k,k==='WebIdentityToken'?{sha256:sha(v)}:k==='Body'||k==='layerPartBlob'?{sha256:sha(v),bytesLength:Buffer.byteLength(v)}:v]));
const same=(a,b,c)=>need(hash(a)===hash(b),c);
export function openCarrierConsumer({startup,config:input,env}){
 const config=inspectCarrierWorkerConfig(input),admission=consumeCarrierStartup(startup,config),p=config.plan,t=p.template,keys=carrierObjectKeys(t);
 need(CARRIER_PROFILE_ACTIONS.scan[0]==='owner','CarrierScanActorRequired');
 const aggregate=admission.local;
 try{
 const root=env.RUNNER_TEMP;need(typeof root==='string'&&resolve(root)===root&&realpathSync(root)===root,'CarrierConsumerDirectory');
 const directory=join(root,'mem9-carrier-consumer-'+hash({grantHash:config.grantHash,binding:admission.binding,nonce:admission.receipt.nonce}));mkdirSync(directory,{mode:0o700});
 const path=join(directory,'journal.jsonl'),fd=openSync(path,'wx',0o600),identity=fstatSync(fd),local=zero(),used={},wire=zero(),events=[];
 const aggregate=admission.local;
 let closed=false,held=false,current,previous=null,phase='assume',confirmed=false,assumedArn,output,outputNodes,sqlAcceptance,sqlBuilt,missing=[],available=new Set(),availabilityOffset=0,uploaded=new Set(),published=new Set(),activeUpload,preparedResult;const uploadIds=new Set();
 const baseNodes=new Map([[t.base.rootDigest,{digest:t.base.rootDigest}]]),baseDone=new Set(),baseUrls=new Set();let blobUsage={requests:0,responseBytes:0,digests:[]};
 const checkJournal=()=>{need(!closed,'CarrierConsumerHeld');const current=fstatSync(fd),named=lstatSync(path);need(current.dev===identity.dev&&current.ino===identity.ino&&named.ino===identity.ino&&named.dev===identity.dev&&current.uid===process.getuid()&&(current.mode&511)===0o600&&current.nlink===1,'CarrierConsumerJournalChanged');};
 const check=()=>{aggregate?.checkNormal();need(!closed&&!held&&Date.now()>=p.issuedMs&&Date.now()<p.deadlineMs,'CarrierConsumerHeld');checkJournal();};
 const reserveLocal=charge=>{if(aggregate){checkJournal();aggregate.reserveLocal(charge);Object.assign(local,aggregate.snapshot().spent);return;}check();exact(charge,COUNTERS);need(charge.ecrRequests===0&&charge.httpBodyBytes===0,'CarrierConsumerLocal');for(const k of COUNTERS)need(Number.isSafeInteger(charge[k])&&charge[k]>=0&&local[k]+charge[k]<=t.fundedLocal.ci[k],'CarrierConsumerLocalLimit');for(const k of COUNTERS)local[k]+=charge[k];};
 const append=(type,data)=>{check();if(aggregate)reserveLocal({...zero(),logicalBytes:65536});const e={version:1,sequence:events.length+1,planHash:hash(p),previousHash:previous,type,data},raw=Buffer.from(JSON.stringify(e)+'\n');if(aggregate)need(raw.length<=16384,'CarrierConsumerRecordSize');else reserveLocal({...zero(),logicalBytes:raw.length});let at=0;while(at<raw.length){const n=writeSync(fd,raw,at,raw.length-at);need(n>0,'CarrierConsumerJournalWrite');at+=n;}fsyncSync(fd);events.push(freeze(e));previous=hash(e);return e;};
 append('start',{grantHash:config.grantHash,ledgerStartHash:config.ledgerStartHash,binding:admission.binding,startup:admission.receipt,allocation:p.budget.ci});
 const scope=(q,base=false)=>{need(q.registryId===t.scope.account&&q.repositoryName===(base?t.base.repositoryName:t.scope.repositoryName),'CarrierConsumerRepository');};
 const register=d=>{const cost=imageDescriptorDataLocalBytes(d);if(cost)reserveLocal({...zero(),logicalBytes:cost});const isManifest=manifests.has(d.mediaType),embedded=decodeImageDescriptorData(d,isManifest?'manifest':'blob');const old=baseNodes.get(d.digest);if(old?.size!==undefined)need(old.size===d.size&&old.mediaType===d.mediaType,'CarrierBaseDescriptorConflict');baseNodes.set(d.digest,{digest:d.digest,size:d.size,mediaType:d.mediaType});let bytes=0,nm=0,nb=0;for(const d of baseNodes.values()){bytes+=d.size??0;manifests.has(d.mediaType)||d.size===undefined?nm++:nb++;}need(bytes<=t.bounds.compressedBytes&&nm<=t.bounds.manifestNodes&&nb<=t.bounds.blobNodes,'CarrierBaseGraphBound');
  // This is reachable only while completing the actual authenticated parent
  // response. It records content coverage, never a fictitious blob request.
  if(embedded!==undefined&&!isManifest)baseDone.add(d.digest);
 };
 const manifestResponse=(q,r)=>{
  const wanted=q.imageIds[0].imageDigest,{image,raw:bytes}=normalizeImageDigestResponse(r,{registryId:q.registryId,repositoryName:q.repositoryName,imageDigest:wanted},n=>reserveLocal({...zero(),logicalBytes:n}));
  const d={digest:wanted,size:bytes.length,mediaType:image.imageManifestMediaType},doc=parseAcquisitionJson(bytes,L.maxManifestBytes);register(d);need(doc.schemaVersion===2&&doc.mediaType===d.mediaType,'CarrierBaseManifest');
  if(indexes.has(d.mediaType)){need(Array.isArray(doc.manifests)&&doc.manifests.length>0,'CarrierBaseManifest');for(const child of doc.manifests)register(child);if(wanted===t.base.rootDigest)need(doc.manifests.filter(d=>d.digest===t.base.arm64Digest&&d.platform?.os==='linux'&&d.platform.architecture==='arm64').length===1,'CarrierBaseArm64');}
  else{register(doc.config);need(Array.isArray(doc.layers),'CarrierBaseManifest');for(const child of doc.layers)register(child);if(wanted===t.base.arm64Digest)need(doc.config.digest===t.base.configDigest,'CarrierBaseConfig');}if(doc.subject)register(doc.subject);baseDone.add(wanted);
 };
 const validate=(purpose,action,q)=>{
  const profile=t.profiles[purpose];need(CARRIER_PROFILE_ACTIONS[purpose]?.[0]==='ci'&&CARRIER_PROFILE_ACTIONS[purpose]?.[1]===action,'CarrierConsumerPurpose');
  if(purpose==='assume'){need(phase==='assume','CarrierConsumerOrder');exact(q,['RoleArn','RoleSessionName','DurationSeconds','Policy']);need(q.RoleArn===t.scope.previewRoleArn&&q.DurationSeconds===2700&&/^carrier-[0-9]+-[0-9]+-[a-f0-9]{16}$/.test(q.RoleSessionName)&&typeof q.Policy==='string','CarrierConsumerAssume');}
  else if(purpose==='ciIdentity'){need(phase==='identity','CarrierConsumerOrder');exact(q,[]);}
  else if(purpose==='grantGet'||purpose==='contextGet'){need(purpose==='grantGet'?phase==='grant':phase==='context'&&confirmed,'CarrierConsumerOrder');exact(q,['Bucket','Key','ExpectedBucketOwner']);need(q.Bucket===t.scope.bucket&&q.Key===keys[purpose==='grantGet'?'grant':'context']&&q.ExpectedBucketOwner===t.scope.account,'CarrierConsumerObject');}
  else if(purpose==='fixtureGet'){need(phase==='base'&&confirmed&&!sqlAcceptance&&[...baseNodes.keys()].every(d=>baseDone.has(d)),'CarrierConsumerFixtureOrder');exact(q,['Bucket','Key','ExpectedBucketOwner']);need(q.Bucket===t.scope.bucket&&q.Key===keys.fixture&&q.ExpectedBucketOwner===t.scope.account,'CarrierConsumerFixtureScope');}
  else if(purpose==='baseManifest'){need(phase==='base'&&confirmed,'CarrierConsumerOrder');exact(q,['registryId','repositoryName','imageIds']);scope(q,true);need(q.imageIds?.length===1&&Object.keys(q.imageIds[0]).join()==='imageDigest'&&baseNodes.has(q.imageIds[0].imageDigest)&&!baseDone.has(q.imageIds[0].imageDigest),'CarrierConsumerBaseManifest');}
  else if(purpose==='baseUrl'){need(phase==='base','CarrierConsumerOrder');exact(q,['registryId','repositoryName','layerDigest']);scope(q,true);const d=baseNodes.get(q.layerDigest);need(d&&d.size!==undefined&&!manifests.has(d.mediaType)&&!baseUrls.has(d.digest)&&!baseDone.has(d.digest),'CarrierConsumerBaseBlob');}
  else if(purpose==='baseBlob'){need(phase==='base','CarrierConsumerOrder');exact(q,['repositoryName','layerDigest']);need(q.repositoryName===t.base.repositoryName&&baseUrls.has(q.layerDigest)&&!baseDone.has(q.layerDigest),'CarrierConsumerBaseBlob');const d=baseNodes.get(q.layerDigest),debit=carrierBlobDebit(p,'ci',blobUsage,d);return {caps:debit.caps,blobDebit:debit};}
  else if(purpose==='availability'){need(phase==='output','CarrierConsumerOrder');exact(q,['registryId','repositoryName','layerDigests']);scope(q);const want=outputNodes.filter(d=>!manifests.has(d.mediaType)).slice(availabilityOffset,availabilityOffset+100).map(d=>d.digest);need(want.length>0,'CarrierConsumerAvailability');same(q.layerDigests,want,'CarrierConsumerAvailability');}
  else if(purpose==='initiate'){need(phase==='upload'&&!activeUpload&&missing.length>0,'CarrierConsumerOrder');exact(q,['registryId','repositoryName']);scope(q);}
  else if(purpose==='part'){need(phase==='upload'&&activeUpload,'CarrierConsumerOrder');exact(q,['registryId','repositoryName','uploadId','partFirstByte','partLastByte','layerPartBlob']);scope(q);const u=activeUpload;need(q.uploadId===u.id&&q.layerPartBlob instanceof Uint8Array&&q.partFirstByte===u.offset&&q.layerPartBlob.length===Math.min(L.uploadPartBytes,u.descriptor.size-u.offset)&&q.partLastByte===q.partFirstByte+q.layerPartBlob.length-1,'CarrierConsumerUploadPart');}
  else if(purpose==='complete'){need(phase==='upload'&&activeUpload&&activeUpload.offset===activeUpload.descriptor.size,'CarrierConsumerOrder');exact(q,['registryId','repositoryName','uploadId','layerDigests']);scope(q);need(q.uploadId===activeUpload.id&&hash(q.layerDigests)===hash([activeUpload.descriptor.digest])&&'sha256:'+activeUpload.digest.digest('hex')===activeUpload.descriptor.digest,'CarrierConsumerUploadComplete');}
  else if(purpose==='manifestPut'){need(phase==='manifests','CarrierConsumerOrder');exact(q,['registryId','repositoryName','imageDigest','imageManifest','imageManifestMediaType']);scope(q);const d=outputNodes.find(d=>d.digest===q.imageDigest);need(d&&manifests.has(d.mediaType)&&!published.has(d.digest)&&q.imageManifestMediaType===d.mediaType&&typeof q.imageManifest==='string'&&Buffer.byteLength(q.imageManifest)===d.size&&'sha256:'+sha(q.imageManifest)===d.digest,'CarrierConsumerPutManifest');const doc=parseAcquisitionJson(Buffer.from(q.imageManifest),L.maxManifestBytes);for(const child of indexes.has(d.mediaType)?doc.manifests:[doc.config,...doc.layers])need(manifests.has(child.mediaType)?published.has(child.digest):available.has(child.digest)||uploaded.has(child.digest),'CarrierConsumerManifestOrder');}
  else if(purpose==='resultPut'){need(phase==='result'&&preparedResult,'CarrierConsumerOrder');exact(q,['Bucket','Key','ExpectedBucketOwner','Body','ContentLength','IfNoneMatch','ServerSideEncryption','SSEKMSKeyId','BucketKeyEnabled','ChecksumSHA256']);need(q.Bucket===t.scope.bucket&&q.Key===keys.result&&q.ExpectedBucketOwner===t.scope.account&&q.IfNoneMatch==='*'&&q.ServerSideEncryption==='aws:kms'&&q.SSEKMSKeyId===t.scope.kmsKeyArn&&q.BucketKeyEnabled===true&&q.ContentLength===preparedResult.length&&sha(q.Body)===sha(preparedResult)&&q.ChecksumSHA256===Buffer.from(sha(preparedResult),'hex').toString('base64'),'CarrierConsumerResult');}
  else throw Error('CarrierConsumerPurpose');
  return {caps:{requestBytes:profile.requestBytes,responseBytes:profile.responseBytes,overshootBytes:8388608}};
 };
 async function beforeRequest(purpose,action,request){
  check();need(!current,'CarrierConsumerSerial');if(aggregate){const profile=t.profiles[purpose];need(profile&&CARRIER_PROFILE_ACTIONS[purpose]?.[0]==='ci','CarrierConsumerPurpose');const requestBytes=profile.requestBytes??0,responseBytes=purpose==='baseBlob'?0:profile.responseBytes;reserveLocal({...zero(),logicalBytes:8*(requestBytes+responseBytes)});}
  const q=structuredClone(request),allocated=validate(purpose,action,q),profile=t.profiles[purpose],n=(used[purpose]??0)+1;need(n<=(profile.maxRequests??profile.count),'CarrierConsumerCalls');
  used[purpose]=n;if(allocated.blobDebit)blobUsage=allocated.blobDebit.usage;
  const b=allocated.blobDebit;
  const intent=append('request',{purpose,action,requestHash:hash(normalized(q)),caps:allocated.caps,attempt:n,...(b?{blobDebit:{descriptorSource:b.descriptorSource,descriptor:b.descriptor,requests:b.usage.requests,responseBytes:b.usage.responseBytes}}:{}),atMs:Date.now()});let charged=0,settled=false;current=intent.sequence;
  const guard=()=>{check();need(!settled&&current===intent.sequence,'CarrierConsumerReservation');};
  const unknown=async()=>{if(settled)return;try{append('unknown',{request:intent.sequence,chargedBytes:allocated.caps.requestBytes+allocated.caps.responseBytes+allocated.caps.overshootBytes,atMs:Date.now()});}finally{held=true;aggregate?.hold();settled=true;current=undefined;}};
  return {caps:allocated.caps,finalGuard:guard,charge(n){guard();need(Number.isSafeInteger(n)&&n>=0,'CarrierConsumerCharge');charged+=n;need(charged<=allocated.caps.requestBytes+allocated.caps.responseBytes,'CarrierConsumerWireLimit');},unknown,async complete(r,responseHash){
   guard();need(/^[a-f0-9]{64}$/.test(responseHash),'CarrierConsumerResponseHash');
   if(purpose==='assume'){assumedArn=r.AssumedRoleUser?.Arn;need(typeof assumedArn==='string'&&assumedArn==='arn:aws:sts::'+t.scope.account+':assumed-role/'+t.scope.previewRoleArn.split('/').at(-1)+'/'+q.RoleSessionName,'CarrierConsumerAssumedIdentity');phase='identity';}
   else if(purpose==='ciIdentity'){need(r.Account===t.scope.account&&r.Arn===assumedArn,'CarrierConsumerIdentity');phase='grant';}
   else if(purpose==='grantGet'||purpose==='contextGet'){need(r.ServerSideEncryption==='aws:kms'&&r.SSEKMSKeyId===t.scope.kmsKeyArn&&r.BucketKeyEnabled===true,'CarrierConsumerEncryption');if(purpose==='contextGet'){need(r.ContentLength===p.context.bytesLength&&responseHash===p.context.sha256,'CarrierConsumerContextHash');phase='base';}}
   else if(purpose==='fixtureGet'){need(r.ServerSideEncryption==='aws:kms'&&r.SSEKMSKeyId===t.scope.kmsKeyArn&&r.BucketKeyEnabled===true&&r.ContentLength===t.sqlFixture.archive.bytesLength&&responseHash===t.sqlFixture.archive.sha256,'CarrierConsumerFixtureResponse');}
   else if(purpose==='baseManifest')manifestResponse(q,r);
   else if(purpose==='baseUrl'){need(r.layerDigest===q.layerDigest,'CarrierConsumerUrlDigest');baseUrls.add(q.layerDigest);}
   else if(purpose==='baseBlob'){const d=baseNodes.get(q.layerDigest);same(r,{repositoryName:q.repositoryName,layerDigest:d.digest,size:d.size},'CarrierConsumerBlobResponse');need(responseHash===d.digest.slice(7),'CarrierConsumerBlobHash');baseDone.add(d.digest);}
   else if(purpose==='availability'){need(Array.isArray(r.layers)&&Array.isArray(r.failures)&&r.failures.length===0&&r.layers.length===q.layerDigests.length,'CarrierConsumerAvailabilityResponse');const seen=new Set();for(const row of r.layers){need(q.layerDigests.includes(row.layerDigest)&&!seen.has(row.layerDigest)&&['AVAILABLE','UNAVAILABLE'].includes(row.layerAvailability),'CarrierConsumerAvailabilityResponse');seen.add(row.layerDigest);const d=outputNodes.find(d=>d.digest===row.layerDigest);if(row.layerAvailability==='AVAILABLE'){need(row.layerSize===d.size,'CarrierConsumerLayerSize');available.add(d.digest);}else missing.push(d);}availabilityOffset+=r.layers.length;if(availabilityOffset===outputNodes.filter(d=>!manifests.has(d.mediaType)).length){missing.sort((a,b)=>a.digest.localeCompare(b.digest));phase=missing.length?'upload':'manifests';}}
   else if(purpose==='initiate'){need(r.repositoryName===q.repositoryName&&r.registryId===q.registryId&&/^[a-f0-9-]{36}$/i.test(r.uploadId??'')&&!uploadIds.has(r.uploadId.toLowerCase())&&Number.isSafeInteger(r.partSize)&&r.partSize>=L.uploadPartBytes,'CarrierConsumerInitiateResponse');uploadIds.add(r.uploadId.toLowerCase());activeUpload={id:r.uploadId,descriptor:missing[0],offset:0,digest:createHash('sha256')};}
   else if(purpose==='part'){need(r.repositoryName===q.repositoryName&&r.registryId===q.registryId&&r.uploadId===q.uploadId&&r.lastByteReceived===q.partLastByte,'CarrierConsumerPartResponse');activeUpload.digest.update(q.layerPartBlob);activeUpload.offset+=q.layerPartBlob.length;}
   else if(purpose==='complete'){need(r.repositoryName===q.repositoryName&&r.registryId===q.registryId&&r.uploadId===q.uploadId&&r.layerDigest===activeUpload.descriptor.digest,'CarrierConsumerCompleteResponse');uploaded.add(r.layerDigest);missing.shift();activeUpload=undefined;if(!missing.length)phase='manifests';}
   else if(purpose==='manifestPut'){need(r.image?.registryId===q.registryId&&r.image?.repositoryName===q.repositoryName&&r.image?.imageId?.imageDigest===q.imageDigest,'CarrierConsumerPutImageResponse');published.add(q.imageDigest);if(published.size===outputNodes.filter(d=>manifests.has(d.mediaType)).length)phase='result';}
   else if(purpose==='resultPut'){need(r.ServerSideEncryption==='aws:kms'&&r.SSEKMSKeyId===t.scope.kmsKeyArn&&r.BucketKeyEnabled===true,'CarrierConsumerEncryption');phase='published';}
   wire.httpBodyBytes+=charged;wire.logicalBytes+=charged;if(action!=='S3BlobGet'&&!['AssumeRoleWithWebIdentity','GetCallerIdentity','GetObject','PutObject'].includes(action))wire.ecrRequests++;
   append('complete',{request:intent.sequence,responseHash,chargedBytes:charged,atMs:Date.now()});settled=true;current=undefined;
  }};
 }
 const api={directory,admission,check,reserveLocal,beforeRequest,
  assertLocalStage(type,cost){check();if(!aggregate)return;need(['build','sql'].includes(type)&&Number.isSafeInteger(cost)&&cost>=0,'CarrierLocalStage');if(cost+aggregate.policy.recordChargeBytes>aggregate.snapshot().normalRemaining){aggregate.hold();throw Error('CarrierLocalStageUnavailable');}aggregate.record(type,{logicalBytes:cost});Object.assign(local,aggregate.snapshot().spent);},
  beginCleanup(){if(aggregate)beginCarrierLocalCleanup(admission.localCounter);},
  confirmGrant(grant){check();need(phase==='grant'&&!current&&!confirmed&&used.grantGet===1,'CarrierConsumerGrantOrder');const verified=verifyCarrierBeforeCopyGrant(grant,{...config,now:Date.now()});same(verified.plan,p,'CarrierConsumerGrantPlan');append('grant-verified',{grantHash:config.grantHash});confirmed=true;phase='context';},
  baseDescriptors(){check();return [...baseNodes.values()].map(d=>({...d}));},
  async bindSqlAcceptance(handle,built){check();need(phase==='base'&&!current&&!output&&!sqlAcceptance&&used.fixtureGet===1,'CarrierConsumerSqlOrder');
   const {inspectCompletedCarrierSqlAcceptance}=await import('./ci-carrier-sql-acceptance.mjs');check();
   const value=inspectCompletedCarrierSqlAcceptance(handle,{built,consumer:api});need(value.record.templateHash===p.templateHash&&value.record.contextHash===p.context.sha256,'CarrierConsumerSqlBinding');
   sqlAcceptance=value;sqlBuilt=built;append('sql-accepted',{acceptanceHash:hash(value),atMs:Date.now()});
  },
  bindBuilt(handle){check();need(phase==='base'&&!current&&!output&&[...baseNodes.keys()].every(d=>baseDone.has(d)),'CarrierConsumerBaseIncomplete');const built=inspectCarrierOfflineBuild(handle);need(built.record.templateHash===config.templateHash&&built.record.contextHash===p.context.sha256&&(!sqlAcceptance||sqlBuilt===handle),'CarrierConsumerBuildBinding');output=built;outputNodes=built.graph.inventory.nodes;append('built',{record:built.record});phase='output';},
  missing(){check();return missing.map(d=>({...d}));},
  prepareResult(){check();need(phase==='result'&&!current&&!preparedResult,'CarrierConsumerResultOrder');const {record,graph}=output;
   const claim=carrierCheckpointSelection(p,admission.binding,Object.fromEntries(['nonce','scopeHash','artifactId','artifactDigest'].map(k=>[k,admission.receipt[k]]))).claim;
   need(sqlAcceptance,'CarrierConsumerSqlRequired');if(aggregate)reserveLocal({...zero(),logicalBytes:8*t.bounds.resultBytes});const localEvidence=aggregate?.evidence();if(localEvidence)Object.assign(local,localEvidence.spent);const consumerPrefix={events:[...events],lastHash:previous,local:{...local},wire:{...wire},used:{...used},blobUsage,...(localEvidence?{ciLocal:localEvidence}:{})};
   const supplied={metadata:output.metadataRaw,buildEvidence:record,consumerPrefix,logBase64:output.log.toString('base64'),derivedMaterial:output.derivedRecord,...(sqlAcceptance?{sqlAcceptance}:{})};
   const result=makeCarrierBuildResult(p,admission.binding,claim,supplied);
   // The same owner codec must accept the complete envelope BEFORE the only
   // PutObject. An older build-only codec must hold instead of dropping the
   // actual journal or inventing a completed-job/security record.
   inspectCarrierBuildResult(result,{plan:p,binding:admission.binding,claim});
   preparedResult=Buffer.from(JSON.stringify(result));need(preparedResult.length<=t.bounds.resultBytes,'CarrierConsumerResultSize');if(!aggregate)reserveLocal({...zero(),logicalBytes:preparedResult.length});return Buffer.from(preparedResult);
  },
  async close({cleanupConfirmed=false}={}){if(closed)return;need(!current,'CarrierConsumerActive');try{if(aggregate){await drainCarrierLocalCounter(admission.localCounter);closeCarrierLocalCounter(admission.localCounter,{complete:cleanupConfirmed&&phase==='published'&&!held});}}finally{fsyncSync(fd);closeSync(fd);closed=true;}},
  inspect(){check();return freeze({phase,local:{...local},wire:{...wire},used:{...used},blobUsage:structuredClone(blobUsage),events:[...events]});},
 };
 handles.set(api,{check});return Object.freeze(api);
 }catch(e){if(aggregate)try{closeCarrierLocalCounter(admission.localCounter,{complete:false});}catch{}throw e;}
}
export function assertCarrierConsumer(value){const s=handles.get(value);need(s,'CarrierConsumerHandle');s.check();return value;}
