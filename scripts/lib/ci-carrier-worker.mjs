import {controlSourcePaths} from './production-control-source.mjs';
import {carrierPublicationAdmissionBytes,carrierSqlStageAdmissionBytes} from './ci-carrier-stage-admission.mjs';
import {normalizeImageDigestResponse,imageResponseFromSdk} from './production-image-response.mjs';
/** Actual carrier pipeline, separate from every production SOURCE/TARGET gate.
 * Defaults use the official artifact client, SDK HTTP and fixed native build. */
import {mkdir,mkdtemp,open,rm,readFile,lstat} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {openCarrierStartup,inspectCarrierWorkerConfig} from './ci-carrier-startup.mjs';
import {openCarrierConsumer} from './ci-carrier-consumer.mjs';
import {createCarrierTransport,carrierSessionPolicy} from './ci-carrier-transport.mjs';
import {materializeCarrierBuildContext,inspectMaterializedCarrierContext,closeCarrierBuildContext} from './ci-carrier-context.mjs';
import {buildCarrierOffline,inspectCarrierOfflineBuild,closeCarrierOfflineBuild} from './production-nonroot-carrier-build.mjs';
import {deriveCarrierRuntimeMaterial,closeCarrierRuntimeMaterial} from './ci-carrier-derived.mjs';
import {materializeCarrierSqlPackage,verifyCarrierSqlPackage,closeCarrierSqlPackage} from './ci-carrier-sql-package.mjs';
import {openCarrierSqlFixture,closeCarrierSqlFixture} from './ci-carrier-sql-fixture.mjs';
import {runCarrierSqlAcceptance,inspectCarrierSqlRuntimeBudget} from './ci-carrier-sql-acceptance.mjs';
import {carrierSqlRuntimeFixedBudget} from './ci-carrier-sql-runtime-budget.mjs';
import {assertCarrierSqlDatabasePin} from './ci-carrier-sql-acceptance-format.mjs';
import {IMAGE_MEDIA,decodeImageDescriptorData,imageDescriptorDataLocalBytes,createPrepaidControlCacheBudget,readCollectedControlImageCache,imageGraphState} from './production-image-graph.mjs';
import {inspectImageFilesystem} from './production-image-filesystem.mjs';
import {IMAGE_TRANSITION_LIMITS as L} from './production-image-transition.mjs';
import {CARRIER_PROFILE_ACTIONS,carrierSqlFixtureBudget,carrierHash as hash} from './ci-carrier-before-copy.mjs';
import {need,parseAcquisitionJson,sha,zero} from './ci-smoke-acquisition-format.mjs';

const indexes=new Set([IMAGE_MEDIA.index,IMAGE_MEDIA.dockerIndex]),manifests=new Set([...indexes,IMAGE_MEDIA.manifest,IMAGE_MEDIA.dockerManifest]);
export async function collectCarrierBase({consumer,transport,tempRoot}){
 const p=consumer.admission.config.plan,t=p.template,directory=await mkdtemp(join(tempRoot,'mem9-carrier-base-')),cache=join(directory,'blobs');await mkdir(cache,{mode:0o700});
 const nodes=new Map(),done=new Set(),visiting=new Set();let root,verified;
 const save=async(d,stream)=>{
  consumer.reserveLocal({...zero(),logicalBytes:d.size});const fd=await open(join(cache,d.digest.slice(7)),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600),digest=createHash('sha256');let count=0;
  try{for await(const b of stream){consumer.check();count+=b.length;need(count<=d.size,'CarrierBaseSize');digest.update(b);let at=0;while(at<b.length){const r=await fd.write(b,at,b.length-at);need(r.bytesWritten>0,'CarrierBaseWrite');at+=r.bytesWritten;}}need(count===d.size&&'sha256:'+digest.digest('hex')===d.digest,'CarrierBaseDigest');await fd.sync();}finally{await fd.close();}
 };
 const register=d=>{const cost=imageDescriptorDataLocalBytes(d);if(cost)consumer.reserveLocal({...zero(),logicalBytes:cost});const embedded=decodeImageDescriptorData(d,manifests.has(d.mediaType)?'manifest':'blob');const old=nodes.get(d.digest);if(old)need(old.size===d.size&&old.mediaType===d.mediaType,'CarrierBaseConflict');nodes.set(d.digest,{digest:d.digest,size:d.size,mediaType:d.mediaType});return embedded;};
 const visit=async wanted=>{
  consumer.check();if(done.has(wanted.digest))return;need(!visiting.has(wanted.digest)&&visiting.size<=L.maxGraphDepth,'CarrierBaseCycle');visiting.add(wanted.digest);
  const response=await transport.baseManifest(wanted),{image,raw}=normalizeImageDigestResponse(response,{registryId:t.base.account,repositoryName:t.base.repositoryName,imageDigest:wanted.digest},n=>consumer.reserveLocal({...zero(),logicalBytes:n})),d={digest:wanted.digest,size:raw.length,mediaType:image.imageManifestMediaType};register(d);if(!root)root=d;
  const doc=parseAcquisitionJson(raw,L.maxManifestBytes);await save(d,(async function*(){yield raw;})());
  if(indexes.has(d.mediaType)){for(const child of doc.manifests)await visit(child);}
  else{for(const child of [doc.config,...doc.layers]){const embedded=register(child);if(!done.has(child.digest)){if(embedded!==undefined)await save(child,(async function*(){yield embedded;})());else await transport.baseBlob(child,stream=>save(child,stream));done.add(child.digest);}}}
  if(doc.subject)await visit(doc.subject);visiting.delete(wanted.digest);done.add(wanted.digest);
 };
 try{
  await visit({digest:t.base.rootDigest});const binding={account:t.base.account,region:t.base.region,repositoryName:t.base.repositoryName,root,arm64Digest:t.base.arm64Digest,configDigest:t.base.configDigest};
  const budget=createPrepaidControlCacheBudget({uncompressedBytesLimit:t.bounds.uncompressedBytes,metadataReads:consumer,deadlineMs:Math.min(p.deadlineMs,Date.now()+L.maxBlobTransferMs)});verified=await readCollectedControlImageCache(binding,{directory:cache,nodes:[...nodes.values()],budget,metadataReads:consumer});
  const filesystem=await inspectImageFilesystem(verified.graph,{component:'bootstrap'});return {directory,cacheDirectory:cache,graph:verified.graph,filesystem,close:verified.cache.close};
 }catch(e){await verified?.cache.close();await rm(directory,{recursive:true,force:true});throw e;}
}
async function* parts(stream){let chunks=[],size=0;for await(const raw of stream){let at=0;while(at<raw.length){const n=Math.min(raw.length-at,L.uploadPartBytes-size);chunks.push(raw.subarray(at,at+n));size+=n;at+=n;if(size===L.uploadPartBytes){yield Buffer.concat(chunks,size);chunks=[];size=0;}}}if(size)yield Buffer.concat(chunks,size);}
async function publishBuilt({built,consumer,transport}){
 consumer.bindBuilt(built);const image=inspectCarrierOfflineBuild(built),state=imageGraphState(image.graph),nodes=image.graph.inventory.nodes,blobs=nodes.filter(d=>!manifests.has(d.mediaType));
 for(let at=0;at<blobs.length;at+=100)await transport.availability(blobs.slice(at,at+100).map(d=>d.digest));
 for(const d of consumer.missing()){
  const initiated=await transport.initiate();let offset=0;for await(const b of parts(state.store.open(d))){consumer.reserveLocal({...zero(),logicalBytes:b.length});await transport.part({uploadId:initiated.uploadId,partFirstByte:offset,partLastByte:offset+b.length-1,layerPartBlob:b});offset+=b.length;}
  need(offset===d.size,'CarrierUploadSize');await transport.complete({uploadId:initiated.uploadId,layerDigests:[d.digest]});
 }
 const done=new Set();
 const put=async d=>{
  if(done.has(d.digest))return;const raw=[];let bytes=0;for await(const b of state.store.open(d)){bytes+=b.length;need(bytes<=L.maxManifestBytes,'CarrierUploadManifest');raw.push(b);}const body=Buffer.concat(raw,bytes),doc=parseAcquisitionJson(body,L.maxManifestBytes);
  if(indexes.has(d.mediaType))for(const child of doc.manifests)await put(child);if(doc.subject)await put(doc.subject);
  consumer.reserveLocal({...zero(),logicalBytes:body.length});await transport.putManifest(d,body);done.add(d.digest);
 };
 await put(state.roots[0].root);need(done.size===nodes.filter(d=>manifests.has(d.mediaType)).length,'CarrierPublicationIncomplete');
 return image;
}

export async function runCarrierBeforeCopy(env=process.env,seams={}){
 need(process.platform==='linux'&&process.arch==='arm64','CarrierWorkerNativeArm64');
 need(Object.keys(seams).every(k=>['host','startup','transport'].includes(k)),'CarrierWorkerSeams');
 const config=inspectCarrierWorkerConfig(env.MEM9_CARRIER_WORKER_CONFIG);
 assertCarrierSqlDatabasePin(config.plan.template.sqlFixture);
 const pgLocal=carrierSqlFixtureBudget(config.plan.template).packageAndImportLocal.ci;
 for(const [key,value]of Object.entries(pgLocal))need(config.plan.template.fundedLocal.ci[key]>=value,'CarrierWorkerPgLocalBudget');
 const runtimeFixed=carrierSqlRuntimeFixedBudget().total;
 for(const key of Object.keys(pgLocal))need(config.plan.template.fundedLocal.ci[key]>=pgLocal[key]+runtimeFixed[key],'CarrierWorkerSqlRuntimeBudget');
 need(env.INPUT_GRANT_COMMITMENT===config.grantHash&&env.INPUT_CONTEXT_COMMITMENT===config.plan.context.sha256,'CarrierDispatchCommitments');
 need(CARRIER_PROFILE_ACTIONS.scan[0]==='owner','CarrierOwnerScanRequired');carrierSessionPolicy(config.plan); // fail policy shape/size before any acquisition
 let consumer,transport,context,base,derived,built,result,databasePackage,fixture,published=false,problem;
 try{
  const startup=await openCarrierStartup({config,env,...(seams.host?{host:seams.host}:{})},seams.startup);
  consumer=openCarrierConsumer({startup,config,env});transport=createCarrierTransport({consumer,env},seams.transport);
  await transport.assume();await transport.identity();consumer.confirmGrant(await transport.getGrant());
  context=await transport.getContext(stream=>materializeCarrierBuildContext({stream,plan:config.plan,tempRoot:env.RUNNER_TEMP,metadataReads:consumer}));
  base=await collectCarrierBase({consumer,transport,tempRoot:env.RUNNER_TEMP});
  if(inspectMaterializedCarrierContext(context).manifest.version===2)derived=await deriveCarrierRuntimeMaterial({context,baseGraph:base.graph,baseFilesystem:base.filesystem,baseCacheDirectory:base.cacheDirectory,sourceContext:consumer.admission.source.sourceContext,metadataReads:consumer,tempRoot:env.RUNNER_TEMP});
  built=await buildCarrierOffline({context,baseGraph:base.graph,baseFilesystem:base.filesystem,metadataReads:consumer,tempRoot:env.RUNNER_TEMP,...(derived?{derived}:{})});
  if(config.plan.template.ciLocalPolicy){const runtime=inspectCarrierSqlRuntimeBudget(built),image=inspectCarrierOfflineBuild(built);consumer.assertLocalStage('sql',carrierSqlStageAdmissionBytes({runtime:runtime.budget,packageLocal:pgLocal,counterRecordBytes:consumer.admission.local.snapshot().recordBytes,sourceReads:1+controlSourcePaths(consumer.admission.source.sourceContext).filter(p=>p.startsWith('docker/bootstrap/')&&(p.endsWith('.sql')||p==='docker/bootstrap/schema-digest.sh')).length,fixtureCaptureBytes:config.plan.template.profiles.fixtureGet.responseBytes,publicationBytes:carrierPublicationAdmissionBytes(config.plan.template,image.graph.inventory.nodes)}));}
  databasePackage=await transport.getFixture(stream=>materializeCarrierSqlPackage({stream,consumer,tempRoot:env.RUNNER_TEMP}));
  await verifyCarrierSqlPackage(databasePackage,{consumer});
  fixture=await openCarrierSqlFixture({databasePackage,tempRoot:env.RUNNER_TEMP,metadataReads:consumer,deadlineMs:config.plan.deadlineMs});
  const sql=await runCarrierSqlAcceptance({built,context,derived,consumer,sourceContext:consumer.admission.source.sourceContext,fixture,oldSource:config.plan.template.sqlFixture.oldSource});fixture=undefined;
  await consumer.bindSqlAcceptance(sql,built);
  result=await publishBuilt({built,consumer,transport});const raw=consumer.prepareResult();await transport.putResult(raw);published=true;
  return Object.freeze({kind:'carrier-build-published',grantHash:config.grantHash,bindingHash:hash(consumer.admission.binding),resultHash:sha(raw)});
 }catch(e){problem=e;throw e;}
 finally{
  let cleanupFailure=false;
  try{consumer?.beginCleanup();}catch{cleanupFailure=true;}
  try{if(fixture)await closeCarrierSqlFixture(fixture);}catch{cleanupFailure=true;}
  try{await transport?.close();}catch{cleanupFailure=true;}
  try{await base?.close();if(built)await closeCarrierOfflineBuild(built);}catch{cleanupFailure=true;}
  // Unknown native/import/transport states retain every owned artifact. The
  // completed run/job observed by the owner also proves this finalizer passed.
  if(published&&!problem&&!cleanupFailure){
   try{if(databasePackage)await closeCarrierSqlPackage(databasePackage,{consumer});}catch{cleanupFailure=true;}
   try{if(derived)await closeCarrierRuntimeMaterial(derived,{context,baseGraph:base.graph,baseFilesystem:base.filesystem,metadataReads:consumer});if(context)await closeCarrierBuildContext(context);if(base)await rm(base.directory,{recursive:true});if(result)await rm(result.directory,{recursive:true});}catch{cleanupFailure=true;}
  }
  try{await consumer?.close({cleanupConfirmed:published&&!problem&&!cleanupFailure});}catch{cleanupFailure=true;}
  if(cleanupFailure)throw Object.assign(Error('CarrierWorkerCleanupHeld'),{code:'ECLEANUP'});
 }
}
