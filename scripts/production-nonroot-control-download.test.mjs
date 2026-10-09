import {digestAliases} from './production-image-response.fixture.mjs';
import {it,expect} from 'vitest';
import {mkdtemp,rm,readdir,lstat,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Readable} from 'node:stream';
import {graphFixture} from './production-image.fixture.mjs';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {collectNonrootControlImage} from './lib/production-nonroot-control-download.mjs';
import {createNonrootBudgetedReads} from './lib/production-nonroot-budget-transport.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {controlImageGraphBinding,IMAGE_MEDIA} from './lib/production-image-graph.mjs';
import {inspectImageFilesystemEntries} from './lib/production-image-filesystem.mjs';
import {verifyOwnedNonrootControlCache} from './lib/production-nonroot-control-cache.mjs';
import {controlResourceFixture} from './ci-smoke-control-resources.fixture.mjs';

async function fixture(use,{defect,inlineConfig,manifestAliases=false,aliasDefect}={}){
 const d=await nonrootDeploymentFixture(),f=graphFixture(),root=f.roots.find(r=>r.component==='mnemo-server'),image=JSON.parse(f.data.get(root.arm64Digest));
 if(inlineConfig){const index=JSON.parse(f.data.get(root.root.digest)),attestation=JSON.parse(f.data.get(index.manifests[1].digest)),empty=f.put({},IMAGE_MEDIA.emptyConfig);attestation.config={...empty,data:inlineConfig==='valid'?'e30=':inlineConfig};index.manifests[1]={...index.manifests[1],...f.put(attestation,IMAGE_MEDIA.manifest)};root.root=f.put(index,IMAGE_MEDIA.index);f.data.delete(empty.digest);}
 const directory=await mkdtemp(join(tmpdir(),'control-download-test-')),events=[],scope=d.contract.output;
 const capture={kind:'nonroot-control-build-action-capture',contractHash:hash(d.contract),outputDigest:root.root.digest,source:d.source,metadata:JSON.stringify({'containerimage.digest':root.root.digest,'containerimage.config.digest':defect==='config'?'sha256:'+'f'.repeat(64):image.config.digest})};
 const metadataReads={async beforeRead(action,request){events.push({action,request});return {caps:{requestBytes:16384,responseBytes:8388608},finalGuard(){},charge(){},async complete(){},async unknown(){events.push({unknown:true});}};},reserveLocal(charge){if(defect==='budget'&&charge.logicalBytes||defect==='inline-budget'&&charge.logicalBytes===8)throw Error('PrepaidLocalQuota');events.push({local:charge});},async finish(){throw Error('CallerOwnsFinish');}};
 const transport={async handle(request){
  if(request.hostname.startsWith('api.ecr.')){
   const q=JSON.parse(request.body),action=request.headers['x-amz-target'].split('.').at(-1);let result;
   if(action==='BatchGetImage'){
    const id=q.imageIds[0].imageDigest,raw=defect==='manifest'&&id===root.root.digest?Buffer.from('{}'):f.data.get(id);
    result={images:[{registryId:scope.account,repositoryName:scope.repositoryName,imageId:{imageDigest:id},imageManifest:raw.toString(),imageManifestMediaType:JSON.parse(raw).mediaType}],failures:[]};
   }else{
    expect(action).toBe('GetDownloadUrlForLayer');const date=new Date().toISOString().replace(/[-:]/g,'').replace(/\.\d{3}/,'');
    const url=new URL(`https://prod-${scope.region}-starport-layer-bucket.s3.${scope.region}.amazonaws.com/${q.layerDigest.slice(7)}`);
    for(const [k,v] of Object.entries({'X-Amz-Algorithm':'AWS4-HMAC-SHA256','X-Amz-Date':date,'X-Amz-Expires':'300','X-Amz-Credential':`synthetic/${date.slice(0,8)}/${scope.region}/s3/aws4_request`,'X-Amz-SignedHeaders':'host','X-Amz-Signature':'a'.repeat(64)}))url.searchParams.set(k,v);
    result={layerDigest:q.layerDigest,downloadUrl:url.href};
   }
   if(action==='BatchGetImage'&&manifestAliases)result=digestAliases(result,aliasDefect);
   return {response:{statusCode:200,headers:{},body:Readable.from([Buffer.from(JSON.stringify(result))])}};
  }
  const raw=f.data.get('sha256:'+request.path.slice(1));expect(raw).toBeDefined();
  return {response:{statusCode:200,headers:{'content-length':String(raw.length)},body:Readable.from([defect==='blob'?Buffer.alloc(raw.length,1):raw])}};
 },destroy(){}};
 const budgetedReads=createNonrootBudgetedReads({region:scope.region,env:{AWS_ACCESS_KEY_ID:'synthetic',AWS_SECRET_ACCESS_KEY:'synthetic',AWS_SESSION_TOKEN:'synthetic'},metadataReads,requestHandler:transport});
 try{await use({input:{capture,contract:d.contract,budgetedReads,metadataReads,tempRoot:directory},events,directory,root});}
 finally{budgetedReads.close();await rm(directory,{recursive:true,force:true});}
}
it('consumes authenticated inline bytes absent from registry, then detects tampering on separate LOCAL replay',()=>fixture(async({input,events})=>{
 const r=await collectNonrootControlImage(input);
 try{
  const d=r.inventory.nodes.find(d=>d.mediaType===IMAGE_MEDIA.emptyConfig);expect(d).toBeDefined();expect(await readFile(join(r.cacheDirectory,d.digest.slice(7)),'utf8')).toBe('{}');
  expect(r.inventory.attestations).toHaveLength(1);expect(events.some(e=>e.local?.logicalBytes===8)).toBe(true);
  expect(events.some(e=>e.request?.layerDigest===d.digest)).toBe(false);
  await writeFile(join(r.cacheDirectory,d.digest.slice(7)),'[]');
  await expect(verifyOwnedNonrootControlCache({directory:r.cacheDirectory,binding:r.binding,inventory:r.inventory,metadataReads:input.metadataReads})).rejects.toThrow();
 }finally{await r.close();}
},{inlineConfig:'valid'}));
it.each(['e30','e30=\n','e31=','W10='])('rejects invalid inline config %s and never falls back to remote bytes',inlineConfig=>fixture(async({input,events,directory})=>{
 await expect(collectNonrootControlImage(input)).rejects.toThrow('ImageEmbeddedDataInvalid');expect(events.some(e=>e.action==='GetDownloadUrlForLayer')).toBe(false);expect(await readdir(directory)).toEqual([]);
},{inlineConfig}));
it('reserves inline decoding before materialization and holds on exhausted LOCAL funds',()=>fixture(async({input,events,directory})=>{
 await expect(collectNonrootControlImage(input)).rejects.toThrow('PrepaidLocalQuota');expect(events.some(e=>e.action==='GetDownloadUrlForLayer')).toBe(false);expect(await readdir(directory)).toEqual([]);
},{inlineConfig:'valid',defect:'inline-budget'}));
it('downloads the full published CONTROL graph through metered SDK HTTP into a verified private cache',()=>fixture(async({input,events,directory,root})=>{
 const result=await collectNonrootControlImage(input);
 try{
  expect(controlImageGraphBinding(result.graph).rootDigest).toBe(root.root.digest);expect(result.inventory.attestations.length).toBeGreaterThan(0);expect(inspectImageFilesystemEntries(result.filesystem).length).toBeGreaterThan(0);
  expect((await readdir(result.cacheDirectory)).sort()).toEqual(result.inventory.nodes.map(n=>n.digest.slice(7)).sort());
  for(const node of result.inventory.nodes){const s=await lstat(join(result.cacheDirectory,node.digest.slice(7)));expect(s.mode&511).toBe(0o600);expect(s.nlink).toBe(1);expect(s.size).toBe(node.size);}
  expect(events.filter(e=>e.action==='S3BlobGet').length).toBeGreaterThan(0);expect(events.some(e=>e.local?.uncompressedBytes>0)).toBe(true);expect(events.some(e=>e.unknown)).toBe(false);
 }finally{await result.close();}
 expect(await readdir(directory)).toEqual([]);
}));
it.each(['manifest','config','blob','budget'])('holds %s corruption or exhausted funding and cleans its own cache',defect=>fixture(async({input,directory})=>{
 await expect(collectNonrootControlImage(input)).rejects.toThrow();expect(await readdir(directory)).toEqual([]);
},{defect}));
it('retains allocated cache bytes after closing live readers and reconstructs a separate local verification',()=>fixture(async({input,directory})=>{
 const resource=await controlResourceFixture(directory,{rootDigest:input.capture.outputDigest,configDigest:JSON.parse(input.capture.metadata)['containerimage.config.digest']});
 const result=await collectNonrootControlImage({...input,tempRoot:resource.allocation.tempRoot,resourceHandle:resource.allocation.handle});await result.close();
 expect((await readdir(result.cacheDirectory)).length).toBe(result.inventory.nodes.length);
 const cache=JSON.parse(await (await import('node:fs/promises')).readFile(join(resource.allocation.root,'cache.json'),'utf8'));expect(cache.directory).toBe(result.cacheDirectory);
 const replay=await verifyOwnedNonrootControlCache({directory:result.cacheDirectory,binding:result.binding,inventory:result.inventory,metadataReads:input.metadataReads});
 try{expect(controlImageGraphBinding(replay.graph).rootDigest).toBe(input.capture.outputDigest);}finally{await replay.close();}
}));
it('rejects a serialized allocation or a different subtree before any download',()=>fixture(async({input,directory,events})=>{
 const resource=await controlResourceFixture(directory,{rootDigest:input.capture.outputDigest,configDigest:JSON.parse(input.capture.metadata)['containerimage.config.digest']});
 await expect(collectNonrootControlImage({...input,tempRoot:resource.allocation.tempRoot,resourceHandle:{...resource.allocation.handle}})).rejects.toThrow('CiControlResourceHandle');
 await expect(collectNonrootControlImage({...input,resourceHandle:resource.allocation.handle})).rejects.toThrow('NonrootControlDownloadResource');expect(events).toEqual([]);
}));
it('actual SDK CONTROL download accepts all exact-digest aliases and still verifies the full inline graph',()=>fixture(async({input,events})=>{
 const r=await collectNonrootControlImage(input);try{expect(r.inventory.attestations).toHaveLength(1);expect(events.filter(e=>e.action==='BatchGetImage')).toHaveLength(3);}finally{await r.close();}
},{manifestAliases:true,inlineConfig:'valid'}));
it.each(['top','image','id','bytes','scope','media'])('actual SDK CONTROL download rejects alias %s and cleans up',aliasDefect=>fixture(async({input,events,directory})=>{
 await expect(collectNonrootControlImage(input)).rejects.toThrow();expect(events.filter(e=>e.action==='BatchGetImage')).toHaveLength(1);expect(await readdir(directory)).toEqual([]);
},{manifestAliases:true,aliasDefect}));
