import {normalizeImageDigestResponse,imageResponseFromSdk} from './production-image-response.mjs';
/** Materialize the published CONTROL image through the existing prepaid
 * readers, then reconstruct its graph and filesystem from owned local bytes. */
import {mkdtemp,mkdir,open,realpath,rm} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {IMAGE_MEDIA,decodeImageDescriptorData,imageDescriptorDataLocalBytes,createPrepaidControlCacheBudget,readCollectedControlImageCache} from './production-image-graph.mjs';
import {inspectImageFilesystem} from './production-image-filesystem.mjs';
import {IMAGE_TRANSITION_LIMITS as L} from './production-image-transition.mjs';
import {inspectNonrootRecord,parseNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {inspectAllocatedControlResources,registerControlCache} from './ci-smoke-control-resources.mjs';

const need=(ok,code='NonrootControlDownloadInvalid')=>{if(!ok)throw Error(code);};
const digest=raw=>'sha256:'+createHash('sha256').update(raw).digest('hex');
const indexes=new Set([IMAGE_MEDIA.index,IMAGE_MEDIA.dockerIndex]);
const manifests=new Set([...indexes,IMAGE_MEDIA.manifest,IMAGE_MEDIA.dockerManifest]);
const zero=()=>({ecrRequests:0,httpBodyBytes:0,logicalBytes:0,uncompressedBytes:0,processedEntries:0});

export async function collectNonrootControlImage({capture,contract:input,budgetedReads,metadataReads,tempRoot,resourceHandle,signal,clock=Date.now}){
 const contract=inspectNonrootRecord('ControlBuildContractV1',input),scope=contract.output;
 need(capture?.kind==='nonroot-control-build-action-capture'&&capture.contractHash===hash(contract)&&/^sha256:[a-f0-9]{64}$/.test(capture.outputDigest),'NonrootControlDownloadCapture');
 const metadata=parseNonrootJson(capture.metadata),configDigest=metadata['containerimage.config.digest'];
 need(metadata['containerimage.digest']===capture.outputDigest&&/^sha256:[a-f0-9]{64}$/.test(configDigest),'NonrootControlDownloadCapture');
 need(capture.source?.repository===contract.repository&&capture.source.checkout?.tree===contract.candidate.tree,'NonrootControlDownloadSource');
 need(typeof budgetedReads?.readJson==='function'&&typeof budgetedReads?.readBlob==='function'&&typeof metadataReads?.reserveLocal==='function','NonrootControlDownloadBudget');
 need(typeof tempRoot==='string'&&resolve(tempRoot)===tempRoot&&await realpath(tempRoot)===tempRoot,'NonrootControlDownloadDirectory');
 if(resourceHandle!==undefined){const owned=await inspectAllocatedControlResources(resourceHandle);need(owned.tempRoot===tempRoot&&owned.rootDigest===capture.outputDigest&&owned.configDigest===configDigest,'NonrootControlDownloadResource');}
 const startedMs=clock(),deadlineMs=startedMs+L.maxBlobTransferMs;
 const check=()=>{signal?.throwIfAborted();need(clock()>=startedMs&&clock()<deadlineMs-L.cleanupReserveMs,'NonrootControlDownloadExpired');metadataReads.reserveLocal(zero());};check();
 const directory=await mkdtemp(join(tempRoot,'mem9-control-download-')),cacheDirectory=join(directory,'blobs');
 try{await mkdir(cacheDirectory,{mode:0o700});}catch(error){await rm(directory,{recursive:true,force:true});throw error;}
 const nodes=new Map(),documents=new Map(),visiting=new Set(),complete=new Set();let total=0,manifestCount=0,blobCount=0,root,arm64Digest,verified,closed=false;
 const embeddedBlobs=new Map();
 const register=d=>{
  const cost=imageDescriptorDataLocalBytes(d);if(cost)metadataReads.reserveLocal({...zero(),logicalBytes:cost});
  const manifest=manifests.has(d.mediaType),embedded=decodeImageDescriptorData(d,manifest?'manifest':'blob');
  if(embedded!==undefined&&!manifest)embeddedBlobs.set(d.digest,embedded);
  const previous=nodes.get(d.digest);if(previous){need(previous.size===d.size&&previous.mediaType===d.mediaType,'NonrootControlDownloadDescriptor');return;}
  total+=d.size;if(manifest)manifestCount++;else blobCount++;
  need(total<=L.maxUniqueCompressedGraphBytes&&manifestCount<=L.maxManifestNodes&&blobCount<=L.maxBlobNodes,'NonrootControlDownloadLimit');nodes.set(d.digest,{digest:d.digest,size:d.size,mediaType:d.mediaType});
 };
 const write=async(d,consume)=>{
  check();metadataReads.reserveLocal({...zero(),logicalBytes:d.size});
  const file=await open(join(cacheDirectory,d.digest.slice(7)),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{await consume(file);check();await file.sync();}finally{await file.close();}
 };
 const visit=async(wanted,depth)=>{
  check();need(depth<=L.maxGraphDepth&&!visiting.has(wanted.digest),'NonrootControlDownloadCycle');if(complete.has(wanted.digest)){register(wanted);return;}
  if(wanted.size!==undefined)register(wanted);visiting.add(wanted.digest);
  const response=await budgetedReads.readJson('ecr','BatchGetImage',{registryId:scope.account,repositoryName:scope.repositoryName,imageIds:[{imageDigest:wanted.digest}]});check();
  const {image,raw}=normalizeImageDigestResponse(response,{registryId:scope.account,repositoryName:scope.repositoryName,imageDigest:wanted.digest},n=>metadataReads.reserveLocal({...zero(),logicalBytes:n}));
  const descriptor={digest:wanted.digest,size:raw.length,mediaType:image.imageManifestMediaType};register(descriptor);
  const value=parseNonrootJson(raw.toString('utf8'),{maxBytes:L.maxManifestBytes});
  need(value.schemaVersion===2&&value.mediaType===descriptor.mediaType,'NonrootControlDownloadManifest');
  const fields=indexes.has(descriptor.mediaType)?['schemaVersion','mediaType','manifests','annotations','subject','artifactType']:['schemaVersion','mediaType','config','layers','annotations','subject','artifactType'];
  need(Object.keys(value).every(k=>fields.includes(k)),'NonrootControlDownloadManifest');
  await write(descriptor,file=>file.writeFile(raw));documents.set(descriptor.digest,value);
  if(depth===0){
   need(indexes.has(descriptor.mediaType)&&Array.isArray(value.manifests),'NonrootControlDownloadRoot');root=descriptor;
   const arm=value.manifests.filter(d=>d.platform?.os==='linux'&&d.platform.architecture==='arm64');need(arm.length===1,'NonrootControlDownloadArm64');arm64Digest=arm[0].digest;
  }
  if(indexes.has(descriptor.mediaType)){
   need(Array.isArray(value.manifests)&&value.manifests.length>0&&value.manifests.length<=L.maxEdges&&new Set(value.manifests.map(d=>d.digest)).size===value.manifests.length,'NonrootControlDownloadManifest');
   for(const child of value.manifests)await visit(child,depth+1);
  }else{
   need(Array.isArray(value.layers)&&value.layers.length<=L.maxBlobNodes,'NonrootControlDownloadManifest');
   register(value.config);for(const layer of value.layers)register(layer);
  }
  if(value.subject){need(value.subject.digest===arm64Digest,'NonrootControlDownloadSubject');await visit(value.subject,depth+1);}
  visiting.delete(wanted.digest);complete.add(wanted.digest);
 };
 // A registered CI allocation retains bytes for separate-process LOCAL
 // consumers. Its explicit final cleanup owns deletion; close releases IO.
 const close=async()=>{if(closed)return;closed=true;try{await verified?.cache.close();}finally{if(resourceHandle===undefined)await rm(directory,{recursive:true,force:true});}};
 try{
  await visit({digest:capture.outputDigest},0);
  need(documents.get(arm64Digest)?.config?.digest===configDigest,'NonrootControlDownloadConfig');
  for(const node of nodes.values())if(!manifests.has(node.mediaType)){
   if(embeddedBlobs.has(node.digest)){const raw=embeddedBlobs.get(node.digest);await write(node,file=>file.writeFile(raw));embeddedBlobs.delete(node.digest);continue;}
   check();await budgetedReads.readJson('ecr','GetDownloadUrlForLayer',{registryId:scope.account,repositoryName:scope.repositoryName,layerDigest:node.digest});
   await write(node,file=>budgetedReads.readBlob({repositoryName:scope.repositoryName,layerDigest:node.digest},{account:scope.account,size:node.size,signal,consume:async stream=>{
    for await(const chunk of stream){check();let offset=0;while(offset<chunk.length){const {bytesWritten}=await file.write(chunk,offset,chunk.length-offset);need(bytesWritten>0,'NonrootControlDownloadWrite');offset+=bytesWritten;}}
   }}));
  }
  check();const binding={...scope,root,arm64Digest,configDigest},budget=createPrepaidControlCacheBudget({metadataReads,deadlineMs,now:clock,signal});
  verified=await readCollectedControlImageCache(binding,{directory:cacheDirectory,nodes:[...nodes.values()],budget,metadataReads});
  const filesystem=await inspectImageFilesystem(verified.graph,{component:'bootstrap'});await verified.cache.check();check();
  const completedMs=clock();
  if(resourceHandle!==undefined)await registerControlCache(resourceHandle,{graph:verified.graph,cacheDirectory,startedMs,completedMs});
  return Object.freeze({binding,cacheDirectory,graph:verified.graph,filesystem,inventory:verified.graph.inventory,startedMs,completedMs,close});
 }catch(error){try{await close();}catch{throw Object.assign(Error('ECLEANUP'),{code:'ECLEANUP',operationDirectory:directory});}throw error;}
}
