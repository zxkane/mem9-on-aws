import {describe,it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {graphFixture} from './production-image.fixture.mjs';
import {readImageGraph,verifyImageGraphCopies,inspectImageCopyVerification,createImageBudget,IMAGE_MEDIA} from './lib/production-image-graph.mjs';
import {inspectImageFilesystem,inspectImageFilesystemEvidence} from './lib/production-image-filesystem.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {verifyNonrootArtifactCache,inspectNonrootArtifactCacheVerification} from './lib/production-nonroot-cache.mjs';

export async function cacheFixture(){
 const f=graphFixture({packageDatabaseText:'P:zlib\nV:1.3.2-r1\nA:aarch64\n\n'}),now=Date.now(),account='123456789012',region='us-west-2';
 for(const root of f.roots){root.sourceRepository='mem9-on-aws/preview/'+root.component;root.destinationRepository='mem9-on-aws/'+root.component;root.targetTag='mem9-example';}
 const source=await readImageGraph(f.roots,f),destination=await readImageGraph(f.roots,{...f,side:'destination'});
 const copied=inspectImageCopyVerification(verifyImageGraphCopies(source,destination,{account,region}));
 const filesystems={};for(const root of f.roots)filesystems[root.component]=inspectImageFilesystemEvidence(await inspectImageFilesystem(destination,{component:root.component}));
 const owner='a'.repeat(32),publication={version:1,mode:'digest-only',inventoryHash:hash(copied.inventory),roots:Object.fromEntries(f.roots.map(r=>[r.component,{repositoryName:r.destinationRepository,rootDigest:r.root.digest,arm64Digest:r.arm64Digest}])),sourceTags:Object.fromEntries(f.roots.map(r=>[r.component,'pr-example']))};
 const envelope=(r,d)=>({request:{registryId:account,repositoryName:r.destinationRepository,imageIds:[{imageDigest:d.digest}]},response:{failures:[],images:[{registryId:account,repositoryName:r.destinationRepository,imageId:{imageDigest:d.digest},imageManifest:f.data.get(d.digest).toString(),imageManifestMediaType:d.mediaType}]}});
 const copyRecords=new Map();
 const finalRootReadbacks=f.roots.map(r=>{const raw=Buffer.from(JSON.stringify({component:r.component,phase:'final-root',observedMs:copied.summary.completedMs,...envelope(r,r.root)}));const ref={path:'/synthetic/'+r.component+'.json',sha256:createHash('sha256').update(raw).digest('hex')};copyRecords.set(ref.path,raw);return ref;});
 const copyReceipt={version:2,kind:'digest-only-image-copy',owner,planHash:'b'.repeat(64),publication,publicationHash:hash(publication),summary:copied.summary,graphHash:copied.graphHash,inventory:copied.inventory,destinationReadback:copied.destinationReadback,filesystems:Object.values(filesystems),finalRootReadbacks};
 const freshDestinationMetadata={version:1,kind:'nonroot-destination-metadata',account,region,startedMs:now,completedMs:Date.now(),repositories:f.roots.map(r=>{
  const arm=copied.inventory.nodes.find(n=>n.digest===r.arm64Digest),config=JSON.parse(f.data.get(arm.digest)).config;
  const blobs=copied.destinationReadback.reads.filter(n=>n.repositoryName===r.destinationRepository&&!n.mediaType.includes('manifest')&&!n.mediaType.includes('index'));
  return {component:r.component,repositoryName:r.destinationRepository,root:envelope(r,r.root),arm64:envelope(r,arm),config:{digest:config.digest,bytesBase64:f.data.get(config.digest).toString('base64')},availability:[{request:{registryId:account,repositoryName:r.destinationRepository,layerDigests:blobs.map(n=>n.digest)},response:{failures:[],layers:blobs.map(n=>({layerDigest:n.digest,layerSize:n.size,layerAvailability:'AVAILABLE',mediaType:n.mediaType}))}}],retention:{repository:{registryId:account,repositoryName:r.destinationRepository,repositoryArn:`arn:aws:ecr:${region}:${account}:repository/${r.destinationRepository}`},policy:{operation:'GetLifecyclePolicy',registryId:account,repositoryName:r.destinationRepository,errorCode:'LifecyclePolicyNotFoundException',requestId:'synthetic-request'}}};
 })};
 const pinned=(path,value)=>{const raw=Buffer.from(JSON.stringify(value));copyRecords.set(path,raw);return {path,sha256:createHash('sha256').update(raw).digest('hex')};};
 const copyCheckpoint={binding:{owner,executionId:'c'.repeat(32),planHash:copyReceipt.planHash,publicationHash:copyReceipt.publicationHash},startingCounters:{ecrRequests:13,logicalBytes:4096,httpBodyBytes:2048,uncompressedBytes:8192,processedEntries:128},counters:{ecrRequests:13,logicalBytes:4096,httpBodyBytes:2048,uncompressedBytes:8192,processedEntries:128},remainingReservation:{ecrRequests:60,logicalBytes:1000000,httpBodyBytes:1000000,uncompressedBytes:1000000,processedEntries:1000},eventCount:1,lastEventHash:'e'.repeat(64),active:0,sealed:true};
 const cacheCustody={origin:'authenticated-completed-destination-cache',owner,executionId:'c'.repeat(32),copyReceiptRef:pinned('/synthetic/copy-receipt.json',copyReceipt),checkpointRef:pinned('/synthetic/checkpoint.json',copyCheckpoint)},verifierClosure={version:1,kind:'git-file-closure',tree:'d'.repeat(40),files:[],closureHash:hash([])};
 const input={copyReceipt,cacheCustody,verifierClosure,freshDestinationMetadata,requirements:Object.fromEntries(f.roots.map(r=>[r.component,[]]))};
 const expected={account,region,images:copied.summary.images,...Object.fromEntries(Object.entries(input).map(([k,v])=>[k+'Hash',hash(v)]))};
 const counts={manifest:0,blob:0,physical:0};
 const cache={roots:f.roots,inventoryHash:hash(copied.inventory),contentHash:copied.summary.contentHash,cacheCustody,
  async readManifest({repositoryName,descriptor}){counts.manifest++;if(!repositoryName.startsWith('mem9-on-aws/')||repositoryName.includes('/preview/'))throw Error('wrong repo');return f.data.get(descriptor.digest);},
  async *readBlob({descriptor}){counts.blob++;yield f.data.get(descriptor.digest);},
  store:{async put(_d,stream){for await(const _ of stream){}},async *open(d){counts.physical+=d.size;yield f.data.get(d.digest);}}
 };
 const budget=createImageBudget({credentialExpiresMs:Date.now()+3600000});
 return {f,input,expected,cache,budget,counts,copyRecords,pinned,copyCheckpoint,readCopyRecord:async ref=>copyRecords.get(ref.path),measureFilesystem:async(_component,_usage,run)=>run(),now:Date.now()};
}

describe('completed destination cache material verification',()=>{
 it('performs one actual destination graph and filesystem pass without making a live copy brand',async()=>{
  const f=await cacheFixture(),context=await verifyNonrootArtifactCache(f.input,{expected:f.expected,cache:f.cache,budget:f.budget,readCopyRecord:f.readCopyRecord,measureFilesystem:f.measureFilesystem,now:()=>Date.now()});
  const b=inspectNonrootArtifactCacheVerification(context);
  expect(b.kind).toBe('nonroot-cache-reverification');expect(b.authority).toBe(false);
  expect(b.inventory).toEqual(f.input.copyReceipt.inventory);expect(b.filesystem).toEqual(Object.fromEntries(f.input.copyReceipt.filesystems.map(e=>[e.component,e])));
  expect(f.counts.manifest+f.counts.blob).toBe(f.input.copyReceipt.destinationReadback.reads.length);
  expect(b.readUsage.logicalBytes).toBe(f.input.copyReceipt.destinationReadback.reads.reduce((n,r)=>n+r.size,0));
  expect(()=>inspectImageCopyVerification(context)).toThrow();
  expect(()=>inspectNonrootArtifactCacheVerification(structuredClone(context))).toThrow();
  await expect(verifyNonrootArtifactCache(f.input,{expected:f.expected,cache:f.cache,budget:f.budget,readCopyRecord:f.readCopyRecord,measureFilesystem:f.measureFilesystem})).rejects.toThrow('NonrootCacheAlreadyConsumed');
 });
 it.each(['copyReceipt','cacheCustody','verifierClosure','freshDestinationMetadata'])('requires the independently authenticated %s pin',async field=>{
  const f=await cacheFixture();f.expected[field+'Hash']='f'.repeat(64);
  await expect(verifyNonrootArtifactCache(f.input,{expected:f.expected,cache:f.cache,budget:f.budget,readCopyRecord:f.readCopyRecord,measureFilesystem:f.measureFilesystem})).rejects.toThrow('NonrootCacheIndependentBinding');
  expect(f.counts.manifest+f.counts.blob).toBe(0);
 });
 it.each(['legacy','tagged','missing-root','unavailable','retention','future','stale','config'])('rejects %s material even when outer pins match',async defect=>{
  const f=await cacheFixture(),m=f.input.freshDestinationMetadata;
  if(defect==='legacy')f.input.copyReceipt.version=1;
  if(defect==='tagged'){const ref=f.input.copyReceipt.finalRootReadbacks[0],row=JSON.parse(f.copyRecords.get(ref.path));row.request.imageIds[0].imageTag='untrusted';const raw=Buffer.from(JSON.stringify(row));ref.sha256=createHash('sha256').update(raw).digest('hex');f.copyRecords.set(ref.path,raw);}
  if(defect==='missing-root')m.repositories[0].root.response.images=[];
  if(defect==='unavailable')m.repositories[0].availability[0].response.layers[0].layerAvailability='UNAVAILABLE';
  if(defect==='retention')m.repositories[0].retention.policy.errorCode='AccessDeniedException';
  if(defect==='future')m.completedMs=Date.now()+60000;
  if(defect==='stale'){m.startedMs-=600000;m.completedMs-=600000;}
  if(defect==='config')m.repositories[0].config.bytesBase64=Buffer.from('{}').toString('base64');
  f.input.cacheCustody.copyReceiptRef=f.pinned('/synthetic/copy-receipt.json',f.input.copyReceipt);
  for(const [k,v]of Object.entries(f.input))f.expected[k+'Hash']=hash(v);
  await expect(verifyNonrootArtifactCache(f.input,{expected:f.expected,cache:f.cache,budget:f.budget,readCopyRecord:f.readCopyRecord,measureFilesystem:f.measureFilesystem})).rejects.toThrow();
 });
 it('rejects cached bytes changed after completed-copy metadata was pinned',async()=>{
  const f=await cacheFixture(),layer=f.input.copyReceipt.inventory.nodes.find(n=>n.mediaType===IMAGE_MEDIA.tar);
  f.f.data.set(layer.digest,Buffer.alloc(layer.size));
  await expect(verifyNonrootArtifactCache(f.input,{expected:f.expected,cache:f.cache,budget:f.budget,readCopyRecord:f.readCopyRecord,measureFilesystem:f.measureFilesystem})).rejects.toThrow('ImageBlobDigest');
 });
 it.each(['missing','skipped','duplicate'])('rejects %s actual filesystem accounting',async defect=>{
  const f=await cacheFixture();
  const measureFilesystem=defect==='missing'?undefined:defect==='skipped'?async()=>({}):async(_component,_usage,run)=>{await run();return run();};
  await expect(verifyNonrootArtifactCache(f.input,{expected:f.expected,cache:f.cache,budget:f.budget,readCopyRecord:f.readCopyRecord,measureFilesystem})).rejects.toThrow();
 });
});
