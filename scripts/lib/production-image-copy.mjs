import {createHash} from 'node:crypto';
import {setTimeout as sleep} from 'node:timers/promises';
import {IMAGE_TRANSITION_LIMITS as L,IMAGE_TRANSITION_LIMITS_HASH,IMAGE_TRANSITION_COMPONENTS} from './production-image-transition.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {imageGraphState,readImageGraph,verifyImageGraphCopies,inspectImageCopyVerification,imageFailure,imageDigest,assertImageBudget} from './production-image-graph.mjs';
import {inspectImageFilesystem,inspectImageFilesystemEvidence,imageFilesystemRequirements,assertImageFilesystemSource} from './production-image-filesystem.mjs';

const need=(v,code='ImageCopyInvalid')=>{if(!v)imageFailure(code);};
const sha=b=>createHash('sha256').update(b).digest('hex');
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join();
const asBytes=v=>{need(v instanceof Uint8Array&&v.length<=L.maxBufferPerStreamBytes,'ImageCopyBuffer');return Buffer.from(v.buffer,v.byteOffset,v.byteLength);};
const callOptions=budget=>({signal:budget.signal,timeoutMs:Math.min(L.maxRequestMs,budget.deadlineMs-budget.now()-L.cleanupReserveMs)});
async function stored(journal,name,value){await journal.once(name,value);need(hash(await journal.read(name))===hash(value),'ImageJournalReadback');}
function requestRecord(operation,input){
 const request={...input};if(request.layerPartBlob!==undefined){const bytes=asBytes(request.layerPartBlob);delete request.layerPartBlob;request.partSha256=sha(bytes);request.partBytes=bytes.length;}
 if(request.imageManifest!==undefined){request.manifestSha256=sha(request.imageManifest);request.manifestBytes=Buffer.byteLength(request.imageManifest);delete request.imageManifest;}
 return {operation,request};
}
function writes({api,journal,authorize,assertCurrent,budget,operation,graphHash}){
 need(typeof authorize==='function'&&typeof assertCurrent==='function'&&typeof journal?.once==='function'&&typeof journal.read==='function','ImageCopyAuthorityRequired');
 return async(name,input,objectDigest=null)=>{
  need(['InitiateLayerUpload','UploadLayerPart','CompleteLayerUpload','PutImage','StartImageScan'].includes(name)&&typeof api[name]==='function','ImageCopyOperation');
  const record={version:1,owner:operation.owner,planHash:operation.planHash,graphHash,limitsHash:IMAGE_TRANSITION_LIMITS_HASH,objectDigest,...requestRecord(name,input)},key='intent-'+hash(record)+'.json';
  need(await journal.read(key)===null,'ImageMutationObservationRequired');budget.check();need(await authorize(record)===undefined,'ImageAuthorityContract');
  await stored(journal,key,record);budget.check();need(await authorize(record)===undefined,'ImageAuthorityContract');need(assertCurrent(record)===undefined,'ImageAuthorityContract');budget.call();
  let response;try{response=await api[name](input,callOptions(budget));}catch(e){if(e?.code==='ECLEANUP'||e?.cleanupComplete===false)throw Object.assign(Error('ECLEANUP'),{code:'ECLEANUP',cleanupComplete:false,hold:true});imageFailure('ImageMutationOutcomeUnknown');}
  await stored(journal,'result-'+hash(record)+'.json',{version:1,intentHash:hash(record),response});return response;
 };
}
async function manifestBytes(state,d){const parts=[];let size=0;for await(const chunk of state.store.open(d)){size+=chunk.length;need(size<=L.maxManifestBytes,'ImageManifestLimit');parts.push(chunk);}const bytes=Buffer.concat(parts,size);need(size===d.size&&imageDigest(bytes)===d.digest,'ImageCacheChanged');return bytes;}
async function* parts(stream){
 let chunks=[],size=0;
 for await(const input of stream){let chunk=asBytes(input);while(chunk.length){const count=Math.min(L.uploadPartBytes-size,chunk.length);chunks.push(chunk.subarray(0,count));size+=count;chunk=chunk.subarray(count);if(size===L.uploadPartBytes){yield Buffer.concat(chunks,size);chunks=[];size=0;}}}
 if(size)yield Buffer.concat(chunks,size);
}
function closure(state,root,inventory){
 const nodes=new Set(),ordered=[];const visit=digest=>{if(nodes.has(digest))return;nodes.add(digest);for(const e of inventory.edges.filter(e=>e.component===root.component&&e.parent===digest))visit(e.child);if(state.manifests.has(digest))ordered.push(state.manifests.get(digest));};visit(root.root.digest);
 return {root,manifests:ordered,blobs:[...nodes].filter(d=>state.blobs.has(d)).map(d=>state.blobs.get(d))};
}

/** The caller provides typed native adapters and real authority checks. There is
 * no SDK default chain, shell/registry fallback, or JSON-selectable callback. */
export async function copyImageGraph(sourceGraph,{api,destination,store,budget,filesystems,filesystemRequirements,journal,operation,scope,authorize,assertCurrent,mode='copy'}={}){
 const state=imageGraphState(sourceGraph);need(state.side==='source'&&budget===state.budget,'ImageCopySource');assertImageBudget(budget);
 need(['copy','observe'].includes(mode)&&exact(operation,['owner','planHash'])&&/^[a-f0-9]{32}$/.test(operation.owner)&&/^[a-f0-9]{64}$/.test(operation.planHash),'ImageCopyOperation');
 need(exact(scope,['account','region'])&&/^\d{12}$/.test(scope.account)&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(scope.region),'ImageCopyScope');
 need(Array.isArray(filesystems)&&filesystems.length===3,'ImageFilesystemRequired');
 filesystems=[...filesystems];operation=Object.freeze(structuredClone(operation));scope=Object.freeze(structuredClone(scope));
 need(exact(filesystemRequirements,IMAGE_TRANSITION_COMPONENTS)&&Object.values(filesystemRequirements).every(v=>Array.isArray(v)&&v.length<=32)&&filesystemRequirements['mnemo-server'].length>0,'ImageFilesystemRequirementsRequired');
 const requirements=structuredClone(filesystemRequirements),requirementsHash=hash(requirements);
 const fsEvidence=filesystems.map(c=>{const e=inspectImageFilesystemEvidence(c);need(Object.hasOwn(requirements,e.component),'ImageFilesystemComponent');return assertImageFilesystemSource(c,sourceGraph,{requirementsHash:hash(requirements[e.component])});});
 need(new Set(fsEvidence.map(e=>e.component)).size===3&&fsEvidence.every(e=>e.graphHash===sourceGraph.inventoryHash&&e.limitsHash===IMAGE_TRANSITION_LIMITS_HASH),'ImageFilesystemBinding');
 const mutate=writes({api,journal,authorize,assertCurrent,budget,operation,graphHash:sourceGraph.inventoryHash});
 const header={version:1,owner:operation.owner,planHash:operation.planHash,inventoryHash:sourceGraph.inventoryHash,limitsHash:IMAGE_TRANSITION_LIMITS_HASH,requirementsHash,scope,startedMs:budget.startedMs};
 const prior=await journal.read('copy-operation.json');if(prior){need(hash(prior)===hash(header),'ImageCopyPlanChanged');need(mode==='observe','ImageCopyObservationRequired');}else need(mode==='copy','ImageCopyOperationMissing');
 const groups=state.roots.map(r=>closure(state,r,sourceGraph.inventory));
 let plannedBytes=0,plannedCalls=0;for(const group of groups){for(const d of group.blobs){plannedBytes+=d.size*2;plannedCalls+=2+Math.ceil(d.size/L.uploadPartBytes)+1;}for(const d of group.manifests){plannedBytes+=d.size*3;plannedCalls+=3;}plannedCalls+=Math.ceil(group.blobs.length/100)+3;plannedBytes+=L.maxManifestBytes*2;}
 budget.projected({transferBytes:plannedBytes,ecrCalls:plannedCalls});
 // Recheck every cached byte and every target tag before the first upload.
 for(const d of sourceGraph.inventory.nodes)for await(const _ of state.store.open(d)){}
 const tagMatches=new Map(),existingManifests=new Set();
 for(const root of state.roots){budget.call();budget.transfer(L.maxManifestBytes);const current=await api.readTag({repositoryName:root.destinationRepository,imageTag:root.targetTag},callOptions(budget));
  if(current!==null){const bytes=asBytes(current);need(bytes.length===root.root.size&&imageDigest(bytes)===root.root.digest,'ImageDestinationTagConflict');tagMatches.set(root.component,true);}
 }
 for(const group of groups)for(const d of group.manifests){budget.call();budget.transfer(d.size);const bytes=await api.readManifest({repositoryName:group.root.destinationRepository,descriptor:d},callOptions(budget));if(bytes!==null){const body=asBytes(bytes);need(body.length===d.size&&imageDigest(body)===d.digest,'ImageExistingManifestChanged');existingManifests.add(group.root.destinationRepository+'@'+d.digest);}}
 if(mode==='copy'){
  need(await authorize({version:1,phase:'before-copy',...header,filesystemEvidence:fsEvidence})===undefined,'ImageAuthorityContract');await stored(journal,'copy-operation.json',header);
  for(const group of groups){
   const repositoryName=group.root.destinationRepository,missing=new Set();
   for(let start=0;start<group.blobs.length;start+=100){const batch=group.blobs.slice(start,start+100),expected=new Map(batch.map(d=>[d.digest,d]));budget.call();const response=await api.BatchCheckLayerAvailability({repositoryName,layerDigests:[...expected.keys()]},callOptions(budget));need(response.repositoryName===repositoryName&&Array.isArray(response.layers)&&Array.isArray(response.failures),'ImageLayerAvailability');
    for(const row of response.layers){const d=expected.get(row.layerDigest);need(d&&['AVAILABLE','UNAVAILABLE'].includes(row.layerAvailability),'ImageLayerAvailability');expected.delete(row.layerDigest);if(row.layerAvailability==='UNAVAILABLE')missing.add(d.digest);else if(row.layerSize!==undefined)need(row.layerSize===d.size,'ImageLayerAvailability');}
    for(const row of response.failures){need(expected.has(row.layerDigest)&&row.failureCode==='LayerNotFound','ImageLayerAvailability');expected.delete(row.layerDigest);missing.add(row.layerDigest);}need(expected.size===0,'ImageLayerAvailabilityIncomplete');
   }
   for(const d of group.blobs.filter(d=>missing.has(d.digest))){
    const opened=await mutate('InitiateLayerUpload',{repositoryName},d.digest);need(opened.repositoryName===repositoryName&&typeof opened.uploadId==='string'&&opened.uploadId.length>0&&opened.uploadId.length<=4096,'ImageUploadIdentity');
    let offset=0;const streaming=state.store.open(d),digester=createHash('sha256');
    for await(const chunk of parts(streaming)){digester.update(chunk);budget.transfer(chunk.length);const last=offset+chunk.length-1;const response=await mutate('UploadLayerPart',{repositoryName,uploadId:opened.uploadId,partFirstByte:offset,partLastByte:last,layerPartBlob:chunk});need(response.repositoryName===repositoryName&&response.uploadId===opened.uploadId&&response.lastByteReceived===last,'ImageUploadPartReadback');offset=last+1;}
    need(offset===d.size&&'sha256:'+digester.digest('hex')===d.digest,'ImageUploadBytesChanged');const result=await mutate('CompleteLayerUpload',{repositoryName,uploadId:opened.uploadId,layerDigests:[d.digest]});need(result.repositoryName===repositoryName&&result.uploadId===opened.uploadId&&result.layerDigest===d.digest,'ImageUploadReadback');
   }
   for(const d of group.manifests){const isRoot=d.digest===group.root.root.digest;if(!isRoot&&existingManifests.has(repositoryName+'@'+d.digest))continue;
    if(isRoot){budget.call();budget.transfer(L.maxManifestBytes);const current=await api.readTag({repositoryName,imageTag:group.root.targetTag},callOptions(budget));if(current!==null){const b=asBytes(current);need(b.length===d.size&&imageDigest(b)===d.digest,'ImageDestinationTagConflict');continue;}}
    const bytes=await manifestBytes(state,d);budget.transfer(bytes.length);
    const response=await mutate('PutImage',{repositoryName,imageDigest:d.digest,imageManifest:bytes.toString('utf8'),imageManifestMediaType:d.mediaType,...(d.digest===group.root.root.digest?{imageTag:group.root.targetTag}:{})});
    need(response.image?.repositoryName===repositoryName&&response.image.imageId?.imageDigest===d.digest,'ImageManifestReadback');if(response.image.imageManifest!==undefined)need(Buffer.from(response.image.imageManifest).equals(bytes),'ImageManifestReadback');
   }
  }
 }
 const destinationGraph=await readImageGraph(state.roots,{...destination,store,budget,side:'destination'});
 const destinationFilesystems=[];
 for(const context of filesystems){const before=inspectImageFilesystemEvidence(context),after=await inspectImageFilesystem(destinationGraph,{component:before.component,requirements:imageFilesystemRequirements(context),budget});need(hash(after.evidence)===hash(before),'ImageDestinationFilesystemChanged');destinationFilesystems.push(after);}
 const verification=verifyImageGraphCopies(sourceGraph,destinationGraph,scope),proof=inspectImageCopyVerification(verification);
 await stored(journal,(mode==='copy'?'copy-verified-':'copy-observed-')+proof.graphHash+'.json',{version:1,owner:operation.owner,planHash:operation.planHash,summary:proof.summary,graphHash:proof.graphHash,inventory:proof.inventory,destinationReadback:proof.destinationReadback,filesystems:destinationFilesystems.map(inspectImageFilesystemEvidence)});
 return {phase:mode==='copy'?'copied':'observed',verification,destinationGraph,filesystems:destinationFilesystems};
}

/** Preserve raw complete pages. The mandatory normalize callback is wired to
 * the unchanged full-finding normalizer by the pinned private caller. */
export async function observeImageScans(copyContext,{api,journal,budget,operation,authorize,assertCurrent,normalize,mode='copy',pause=sleep}={}){
 const checked=inspectImageCopyVerification(copyContext),summary=checked.summary;assertImageBudget(budget);need(['copy','observe'].includes(mode)&&typeof normalize==='function','ImageScanNormalizerRequired');
 const mutate=writes({api,journal,budget,operation,authorize,assertCurrent,graphHash:checked.graphHash});const until=Math.min(budget.now()+L.maxScanObservationMs,budget.deadlineMs-L.cleanupReserveMs),pending=new Set(Object.keys(summary.images)),results={};
 const roots=new Map(checked.inventory.roots.map(r=>[r.component,r]));let round=0,mayStart=mode==='copy';
 for(const component of pending)if(await journal.read('scan-'+component+'-intent.json')!==null)mayStart=false;
 while(pending.size){budget.check();need(budget.now()<until,'ImageScanObservationExpired');
  for(const component of [...pending]){const root=roots.get(component),imageId={imageDigest:summary.images[component].arm64Digest},repositoryName=root.destinationRepository,input={repositoryName,imageId,maxResults:1000};let response,missing=false;
   try{budget.call();response=await api.DescribeImageScanFindings(input,callOptions(budget));}catch(e){if(e?.name==='ScanNotFoundException'&&e.$metadata?.httpStatusCode===400&&typeof e.$metadata.requestId==='string')missing=true;else throw e;}
   const identity=r=>need(r?.registryId===summary.account&&r.repositoryName===repositoryName&&r.imageId?.imageDigest===imageId.imageDigest,'ImageScanIdentity');
   if(!missing)identity(response);const status=response?.imageScanStatus?.status,completed=Date.parse(response?.imageScanFindings?.imageScanCompletedAt);let intent=await journal.read('scan-'+component+'-intent.json');
   if(!missing&&status==='COMPLETE'&&Number.isSafeInteger(completed)&&completed<=budget.now()&&budget.now()-completed<=86400000){
    const pages=[],tokens=new Set();let current=response;
    for(let page=0;page<L.maxScanPagesPerObservation;page++){identity(current);need(current.imageScanStatus?.status==='COMPLETE'&&Date.parse(current.imageScanFindings?.imageScanCompletedAt)===completed,'ImageScanChanged');pages.push(current);await stored(journal,'scan-'+component+'-'+round+'-'+page+'.json',current);if(!current.nextToken)break;need(typeof current.nextToken==='string'&&!tokens.has(current.nextToken),'ImageScanPagination');tokens.add(current.nextToken);budget.call();current=await api.DescribeImageScanFindings({...input,nextToken:current.nextToken},callOptions(budget));}
    need(!pages.at(-1)?.nextToken,'ImageScanPagination');const accepted=await journal.read('scan-'+component+'-accepted.json');if(accepted)need(intent&&accepted.intentHash===hash(intent),'ImageScanIntentChanged');
    results[component]={repositoryName,imageDigest:imageId.imageDigest,completedMs:completed,observedMs:budget.now(),pages,requestOutcome:accepted?'accepted':intent?'unknown':'not-requested'};pending.delete(component);continue;
   }
   if(!missing&&['PENDING','IN_PROGRESS'].includes(status))continue;
   const eligible=missing||status==='COMPLETE'&&Number.isSafeInteger(completed)&&completed<=budget.now()-86400000;
   need(eligible,'ImageScanUnavailable');
   if(!intent&&mayStart){
    intent={version:1,owner:operation.owner,graphHash:checked.graphHash,repositoryName,imageId,requestedMs:budget.now()};await stored(journal,'scan-'+component+'-intent.json',intent);
    try{const started=await mutate('StartImageScan',{repositoryName,imageId});identity(started);need(['PENDING','IN_PROGRESS','COMPLETE'].includes(started.imageScanStatus?.status),'ImageScanStartStatus');await stored(journal,'scan-'+component+'-accepted.json',{intentHash:hash(intent),response:started});}catch(e){if(e?.code!=='ImageMutationOutcomeUnknown')throw e;mayStart=false;await stored(journal,'scan-'+component+'-unknown.json',{intentHash:hash(intent)});}
   }
  }
  round++;if(pending.size)await pause(Math.min(L.scanPollMs,until-budget.now()),undefined,{signal:budget.signal});
 }
 const normalized=await normalize({summary,scans:results,observedMs:budget.now()});need(normalized&&normalized.scans&&hash(normalized.scans)===normalized.securityEvidenceHash,'ImageScanNormalization');
 for(const [component,r]of Object.entries(results)){const s=normalized.scans[component];need(s&&s.repositoryName===r.repositoryName&&s.imageDigest===r.imageDigest&&Array.isArray(s.findings)&&s.findings.length<=L.maxFindingsPerComponent,'ImageScanNormalization');r.findings=s.findings;r.findingsHash=hash(s.findings);}
 return {version:1,graphHash:checked.graphHash,limitsHash:IMAGE_TRANSITION_LIMITS_HASH,scans:results,normalized};
}
