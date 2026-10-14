/** Fixed streaming OCI composition. No subprocess, installer, daemon, image
 * execution or registry fallback. Publication uses the separately funded
 * native transport after this producer returns its live output handle. */
import {createHash} from 'node:crypto';
import {mkdir,open,unlink,rmdir,lstat,realpath} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join} from 'node:path';
import {nonrootHash as hash,inspectNonrootRecord,copyNonrootJson} from './production-nonroot-contracts.mjs';
import {parseAcquisitionJson,freeze} from './ci-smoke-acquisition-format.mjs';
import {imageGraphState,controlImageGraphBinding,readCollectedControlImageCache,IMAGE_MEDIA as M} from './production-image-graph.mjs';
import {inspectImageFilesystem,inspectImageFilesystemEvidence,inspectImageFilesystemEntries,imageFilesystemVerificationKind} from './production-image-filesystem.mjs';
import {readControlSourceFile} from './production-control-source.mjs';
import {inspectProductionControlComposition,compositionUstarPath,compositionNeed as need,
 PRODUCTION_CONTROL_COMPOSITION_LIMITS as L,COMPOSITION_BUILDER_ID} from './production-control-composition.mjs';
import {describeProductionControlCopyManifest} from './production-control-composition-source.mjs';
import {productionControlCompositionStatement} from './production-control-composition-provenance.mjs';
import {requireProductionControlCompositionAllocation,requireProductionControlCompositionBudget,
 beginProductionControlCompositionStage,createProductionControlCompositionCacheBudget,holdProductionControlComposition,
 recordProductionControlComposition} from './production-control-composition-lifetime.mjs';

const outputs=new WeakMap();
const sha=b=>createHash('sha256').update(b).digest('hex');
const same=(a,b,code)=>need(hash(a)===hash(b),code);
function octal(buffer,value,at,width){
 const text=value.toString(8);need(text.length<width,'ControlCompositionUstarNumber');
 buffer.write(text.padStart(width-1,'0')+'\0',at,width,'ascii');
}
function header(row){
 const b=Buffer.alloc(512),path=compositionUstarPath(row.path);
 b.write(path.name,0,100,'utf8');b.write(path.prefix,345,155,'utf8');
 octal(b,row.mode,100,8);octal(b,row.uid,108,8);octal(b,row.gid,116,8);
 octal(b,row.type==='file'?row.bytesLength:0,124,12);octal(b,0,136,12);
 b.fill(32,148,156);b[156]=row.type==='file'?48:row.type==='directory'?53:50;
 if(row.type==='symlink')b.write(row.target,157,100,'utf8');
 b.write('ustar\0',257,6,'ascii');b.write('00',263,2,'ascii');
 let sum=0;for(const n of b)sum+=n;b.write(sum.toString(8).padStart(6,'0')+'\0 ',148,8,'ascii');return b;
}
function filesystemProjection(entries){
 return entries.map(e=>Object.fromEntries(Object.entries({
  path:e.path,type:e.type,mode:e.mode,uid:e.uid,gid:e.gid,implicit:e.implicit,
  target:e.link,sha256:e.content?.sha256,size:e.content?.size,
  attributes:Object.fromEntries(Object.entries(e.pax??{}).filter(([k])=>k.startsWith('SCHILY.xattr.'))),
 }).filter(([,v])=>v!==undefined)));
}
async function removeOutput(s){
 let problem;
 try{await s.cache?.cache.close();}catch(error){problem=error;}
 for(const path of [...s.files].reverse())try{await unlink(path);}catch(error){if(error.code!=='ENOENT')problem??=error;}
 for(const path of [...s.directories].reverse())try{await rmdir(path);}catch(error){if(error.code!=='ENOENT')problem??=error;}
 s.closed=true;if(problem)throw Object.assign(Error('ControlCompositionOutputCleanup'),{cause:problem});
}
export async function composeProductionControl({plan:rawPlan,baseGraph,baseFilesystem,sourceContext,actualMain,allocation,tempRoot,signal}){
 const plan=inspectProductionControlComposition(rawPlan),active=requireProductionControlCompositionAllocation(allocation);
 same(plan,active.plan,'ControlCompositionAllocationPlan');
 const nativeBase=imageGraphState(baseGraph);requireProductionControlCompositionBudget(allocation,nativeBase.budget);
 const {graphHash,...image}=controlImageGraphBinding(baseGraph);
 same(image,plan.input.base.image,'ControlCompositionBaseImage');same(baseGraph.inventory,plan.input.base.inventory,'ControlCompositionBaseInventory');
 need(imageFilesystemVerificationKind(baseFilesystem)==='live-filesystem-evidence','ControlCompositionLiveFilesystem');
 same(inspectImageFilesystemEvidence(baseFilesystem),plan.input.base.filesystem,'ControlCompositionBaseFilesystem');
 need(graphHash===plan.input.base.filesystem.graphHash&&sourceContext.tree===plan.input.source.candidateTree,'ControlCompositionSourceTree');
 const actual=inspectNonrootRecord('ActualMainV1',actualMain),binding=active.binding.source;
 for(const key of ['repository','candidateRevision','candidateTree','baseRevision','mainRevision','mainTree','parents','prNumber','workflowPath','workflowSha'])
  same(actual[key],binding[key],'ControlCompositionActualMain');
 need(actual.workflowRun===binding.runId&&actual.workflowAttempt===binding.runAttempt,'ControlCompositionActualMain');
 need(await realpath(tempRoot)===tempRoot&&(plan.version===2?active.directory===tempRoot:active.directory.startsWith(tempRoot+'/')),'ControlCompositionOutputRoot');
 const rootStat=await lstat(tempRoot);need(rootStat.isDirectory()&&(rootStat.mode&0o777)===0o700&&rootStat.uid===process.getuid(),'ControlCompositionOutputRoot');
 const startedMs=Date.now(),s={allocation,files:[],directories:[],cache:null,closed:false},directory=join(active.directory,'output');
 let stage;
 const check=()=>{signal?.throwIfAborted();requireProductionControlCompositionAllocation(allocation);};
 const mkdirOwned=async path=>{check();await mkdir(path,{mode:0o700});s.directories.push(path);};
 const syncWrite=async(fd,bytes)=>{let at=0;while(at<bytes.length){check();const r=await fd.write(bytes,at,bytes.length-at);need(r.bytesWritten>0,'ControlCompositionWrite');at+=r.bytesWritten;}};
 const store=new Map();
 async function writeBlob(descriptor,stream,{readCharged=false}={}){
  if(store.has(descriptor.digest)){same(store.get(descriptor.digest),descriptor,'ControlCompositionBlobConflict');return;}
  const path=join(directory,'blobs',descriptor.digest.slice(7)),fd=await open(path,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  s.files.push(path);const digest=createHash('sha256');let size=0;
  try{
   for await(const chunk of stream){
    check();need(chunk instanceof Uint8Array&&chunk.length<=L.streamBytes,'ControlCompositionChunk');
    need(size+chunk.length<=descriptor.size,'ControlCompositionBlobSize');stage.charge(chunk.length*(readCharged?2:3));
    size+=chunk.length;digest.update(chunk);await syncWrite(fd,chunk);
   }
   need(size===descriptor.size&&'sha256:'+digest.digest('hex')===descriptor.digest,'ControlCompositionBlobDigest');await fd.sync();
  }finally{await fd.close();}
  store.set(descriptor.digest,descriptor);
 }
 async function putJson(value,mediaType,maximum){
  // The complete encoding/copy reservation precedes serialization.
  stage.charge(4*maximum);const text=JSON.stringify(value);need(Buffer.byteLength(text)<=maximum,'ControlCompositionMetadataSize');
  const bytes=Buffer.from(text),d={mediaType,digest:'sha256:'+sha(bytes),size:bytes.length};
  await writeBlob(d,(async function*(){for(let at=0;at<bytes.length;at+=L.streamBytes)yield bytes.subarray(at,at+L.streamBytes);})());
  return d;
 }
 try{
  await mkdirOwned(directory);await mkdirOwned(join(directory,'blobs'));
  stage=beginProductionControlCompositionStage(allocation,'compose');
  const source=await describeProductionControlCopyManifest({sourceContext,baseFilesystem,charge:n=>stage.charge(n)});
  same(source.rows,plan.input.copyManifest,'ControlCompositionCopyChanged');
  const runtime=nativeBase.images.get('bootstrap'),configChunks=[];let configBytes=0;
  stage.charge(3*runtime.config.size);
  for await(const b of nativeBase.store.open(runtime.config)){check();need(configBytes+b.length<=runtime.config.size,'ControlCompositionConfigSize');configBytes+=b.length;configChunks.push(b);}
  need(configBytes===runtime.config.size,'ControlCompositionConfigSize');
  const raw=Buffer.concat(configChunks,configBytes);need('sha256:'+sha(raw)===image.configDigest,'ControlCompositionConfigHash');
  const original=parseAcquisitionJson(raw,L.configBytes);
  need(original.architecture==='arm64'&&original.os==='linux'&&original.rootfs?.type==='layers'&&
   hash(original.rootfs.diff_ids)===hash(runtime.diffIds)&&
   (original.config?.OnBuild===undefined||original.config.OnBuild===null||Array.isArray(original.config.OnBuild)&&original.config.OnBuild.length===0),'ControlCompositionInheritedTrigger');
  const layerPath=join(directory,'copy-layer.partial'),layerFd=await open(layerPath,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  s.files.push(layerPath);const layerDigest=createHash('sha256');let layerSize=0;
  async function emit(bytes){
   check();need(bytes.length<=L.streamBytes&&layerSize+bytes.length<=plan.tarBytes,'ControlCompositionTarSize');stage.charge(3*bytes.length);
   layerDigest.update(bytes);layerSize+=bytes.length;await syncWrite(layerFd,bytes);
  }
  try{
   for(const row of source.rows){
    await emit(header(row));
    if(row.type==='file'){
     stage.charge(row.bytesLength);
     const file=await readControlSourceFile(sourceContext,row.sourcePath);
     need(file.file.sha256===row.sha256&&file.bytes.length===row.bytesLength,'ControlCompositionSourceChanged');
     for(let at=0;at<file.bytes.length;at+=L.streamBytes)await emit(file.bytes.subarray(at,at+L.streamBytes));
     if(row.bytesLength%512)await emit(Buffer.alloc(512-row.bytesLength%512));
    }
   }
   await emit(Buffer.alloc(1024));need(layerSize===plan.tarBytes,'ControlCompositionTarSize');await layerFd.sync();
  }finally{await layerFd.close();}
  const layer={mediaType:M.tar,size:layerSize,digest:'sha256:'+layerDigest.digest('hex')};
  // Rename preserves the just-written owned inode; no link or duplicate data.
  const {rename}=await import('node:fs/promises');const finalLayerPath=join(directory,'blobs',layer.digest.slice(7));
  await rename(layerPath,finalLayerPath);s.files[s.files.indexOf(layerPath)]=finalLayerPath;store.set(layer.digest,layer);
  const config=structuredClone(original);config.created=new Date(startedMs).toISOString();config.rootfs.diff_ids=[...runtime.diffIds,layer.digest];
  if(original.history!==undefined){need(Array.isArray(original.history),'ControlCompositionHistory');config.history=[...original.history,{created:config.created,created_by:COMPOSITION_BUILDER_ID,comment:'plan:'+plan.planHash}];}
  const configDescriptor=await putJson(config,M.config,L.configBytes);
  const arm=await putJson({schemaVersion:2,mediaType:M.manifest,config:configDescriptor,layers:[...runtime.layers,layer]},M.manifest,L.manifestBytes);
  const serializedMs=Date.now(),statement=productionControlCompositionStatement({plan,actualMain:actual,arm64Digest:arm.digest,startedMs,completedMs:serializedMs});
  const payload=await putJson(statement,M.attestation,L.attestationBytes),empty=await putJson({},M.emptyConfig,2);
  const attestation=await putJson({schemaVersion:2,mediaType:M.manifest,artifactType:M.attestation,config:empty,layers:[payload],subject:arm},M.manifest,L.manifestBytes);
  const root=await putJson({schemaVersion:2,mediaType:M.index,manifests:[{...arm,platform:{os:'linux',architecture:'arm64'}},
   {...attestation,platform:{os:'unknown',architecture:'unknown'}}]},M.index,L.manifestBytes);
  const compositionUsage=stage.close();stage=null;
  stage=beginProductionControlCompositionStage(allocation,'outputStaging');
  for(const d of new Map(runtime.layers.map(d=>[d.digest,d])).values())await writeBlob({digest:d.digest,size:d.size,mediaType:d.mediaType},nativeBase.store.open(d),{readCharged:true});
  const stagingUsage=stage.close();stage=null;
  const outputImage={account:image.account,region:image.region,repositoryName:'mem9-on-aws/bootstrap',rootDigest:root.digest,arm64Digest:arm.digest,configDigest:configDescriptor.digest};
  const nodes=[...store.values()].sort((a,b)=>a.digest.localeCompare(b.digest));
  need(nodes.reduce((n,d)=>n+d.size,0)<=plan.bounds.graphBytes,'ControlCompositionGraphBound');
  stage=beginProductionControlCompositionStage(allocation,'verify');
  const parsing=createProductionControlCompositionCacheBudget(allocation);
  s.cache=await readCollectedControlImageCache({account:outputImage.account,region:outputImage.region,repositoryName:outputImage.repositoryName,root,arm64Digest:arm.digest,configDigest:configDescriptor.digest},
   {directory:join(directory,'blobs'),nodes,...parsing});
  const filesystem=await inspectImageFilesystem(s.cache.graph,{component:'bootstrap',budget:parsing.budget});
  same(filesystemProjection(inspectImageFilesystemEntries(filesystem)),filesystemProjection(inspectImageFilesystemEntries(baseFilesystem)),'ControlCompositionFilesystemEquivalent');
  const used=parsing.budget.usage();need(used.uncompressedBytes===plan.bounds.uncompressedBytes&&used.fsEntries===plan.bounds.processedEntries,'ControlCompositionFilesystemBound');
  await s.cache.cache.check();const verificationUsage=stage.close();stage=null;
  const completedMs=Date.now(),record={version:1,kind:'native-control-composition-output',authority:false,builder:COMPOSITION_BUILDER_ID,
   allocationId:active.id,planHash:plan.planHash,actualMain:actual,image:outputImage,rootDescriptor:root,graphHash:s.cache.graph.graphHash,filesystem:inspectImageFilesystemEvidence(filesystem),
   layer,statementHash:hash(statement),statement,startedMs,serializedMs,completedMs,tarBytes:layerSize,tarEntries:source.rows.length,
   usage:{composition:compositionUsage,staging:stagingUsage,verification:verificationUsage}};
  recordProductionControlComposition(allocation,'built',{planHash:plan.planHash,image:outputImage,graphHash:record.graphHash,statementHash:record.statementHash});
  const handle=Object.freeze({kind:'native-control-composition-output'});Object.assign(s,{record:freeze(copyNonrootJson(record)),graph:s.cache.graph,filesystem,store,directory});outputs.set(handle,s);return handle;
 }catch(error){
  try{stage?.close();}catch{}holdProductionControlComposition(allocation,error.message);
  try{await removeOutput(s);}catch(cleanup){throw Object.assign(cleanup,{cause:error});}throw error;
 }
}
export function inspectProductionControlCompositionOutput(handle){
 const s=outputs.get(handle);need(s&&!s.closed,'ControlCompositionNativeOutput');requireProductionControlCompositionAllocation(s.allocation);
 return Object.freeze({record:s.record,graph:s.graph,filesystem:s.filesystem,directory:s.directory});
}
export async function closeProductionControlCompositionOutput(handle){
 const s=outputs.get(handle);need(s&&!s.closed,'ControlCompositionNativeOutput');await removeOutput(s);
}
export function captureProductionControlComposition(handle,{run,job}){
 const {record:r}=inspectProductionControlCompositionOutput(handle),m=r.actualMain;
 need(run.id===m.workflowRun&&run.run_attempt===m.workflowAttempt&&run.head_sha===m.mainRevision&&run.event==='push'&&run.head_branch==='main'&&
  run.path===m.workflowPath&&run.repository?.full_name===m.repository&&run.status==='in_progress'&&run.conclusion===null,'ControlCompositionCaptureRun');
 need(Number.isSafeInteger(job.id)&&job.id>0&&job.run_id===m.workflowRun&&job.run_attempt===m.workflowAttempt&&job.head_sha===m.mainRevision&&
  job.name==='Build image transition control'&&job.status==='in_progress'&&job.conclusion===null,'ControlCompositionCaptureJob');
 const name='Build & push image transition bootstrap (arm64)',steps=job.steps?.filter(s=>s.name===name);
 need(steps?.length===1&&steps[0].status==='in_progress'&&steps[0].conclusion===null&&
  Number.isSafeInteger(Date.parse(steps[0].started_at))&&Date.parse(steps[0].started_at)<=r.startedMs,'ControlCompositionCaptureStep');
 return copyNonrootJson({version:1,kind:'native-control-composition-capture',builder:r.builder,planHash:r.planHash,actualMain:m,image:r.image,rootDescriptor:r.rootDescriptor,
  graphHash:r.graphHash,filesystem:r.filesystem,statementHash:r.statementHash,startedMs:r.startedMs,completedMs:r.completedMs,
  enclosing:{jobId:job.id,stepName:name,status:'in_progress'}});
}
