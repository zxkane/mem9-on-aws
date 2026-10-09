import {it,expect,vi} from 'vitest';
import {mkdtemp,mkdir,writeFile,chmod,symlink,link,rm,open} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {graphFixture} from './production-image.fixture.mjs';
import {readControlImageGraph,readCollectedControlImageCache,createImageBudget,createPrepaidControlCacheBudget,controlImageGraphBinding} from './lib/production-image-graph.mjs';
import {inspectImageFilesystemEntries} from './lib/production-image-filesystem.mjs';
import {verifyOwnedNonrootControlCache} from './lib/production-nonroot-control-cache.mjs';

async function fixture(use){
 const directory=await mkdtemp(join(tmpdir(),'nonroot-owned-control-'));
 try{
  await chmod(directory,0o700);const cache=join(directory,'cache');await mkdir(cache,{mode:0o700});
  const f=graphFixture(),row=f.roots.find(r=>r.component==='mnemo-server'),config=JSON.parse(f.data.get(row.arm64Digest)).config;
  const binding={account:'123456789012',region:'ap-northeast-1',repositoryName:'mem9-on-aws/bootstrap',root:row.root,arm64Digest:row.arm64Digest,configDigest:config.digest};
  const original=await readControlImageGraph(binding,{source:f.source,store:f.store,budget:f.budget});
  for(const node of original.inventory.nodes)await writeFile(join(cache,node.digest.slice(7)),f.data.get(node.digest),{mode:0o600,flag:'wx'});
  const budget=createImageBudget({credentialExpiresMs:Date.now()+3600000});
  await use({directory,cache,binding,inventory:original.inventory,budget});
 }finally{await rm(directory,{recursive:true,force:true});}
}
it('reconstructs genuine CONTROL graph/FS brands from every cached byte with measured reads',()=>fixture(async f=>{
 const before=f.budget.usage(),result=await verifyOwnedNonrootControlCache({directory:f.cache,binding:f.binding,inventory:f.inventory,budget:f.budget});
 try{
  expect(controlImageGraphBinding(result.graph).rootDigest).toBe(f.binding.root.digest);
  expect(inspectImageFilesystemEntries(result.filesystem).length).toBeGreaterThan(0);
  const usage=result.usage();expect(usage.graphPasses).toBe(1);expect(usage.filesystemPasses).toBe(1);
  expect(usage.physicalCacheBytes).toBeGreaterThan(0);
  expect(usage.after.calls-before.calls).toBe(f.inventory.nodes.length);
  expect(usage.after.transferredBytes-before.transferredBytes).toBe(f.inventory.nodes.reduce((n,d)=>n+d.size,0));
 }finally{await result.close();}
}));
it.each(['bytes','symlink','hardlink','mode','extra','missing','wrong-root'])('rejects %s before returning live evidence',defect=>fixture(async f=>{
 const node=f.inventory.nodes.find(d=>d.size>2),path=join(f.cache,node.digest.slice(7));
 if(defect==='bytes')await writeFile(path,Buffer.alloc(node.size,1));
 if(defect==='symlink'){const elsewhere=join(f.directory,'outside');await writeFile(elsewhere,Buffer.alloc(node.size),{mode:0o600});await rm(path);await symlink(elsewhere,path);}
 if(defect==='hardlink')await link(path,join(f.directory,'alias'));
 if(defect==='mode')await chmod(path,0o644);
 if(defect==='extra')await writeFile(join(f.cache,'unrecorded'),'x',{mode:0o600});
 if(defect==='missing')await rm(path);
 if(defect==='wrong-root')f.binding={...f.binding,root:{...f.binding.root,digest:'sha256:'+'f'.repeat(64)}};
 await expect(verifyOwnedNonrootControlCache({directory:f.cache,binding:f.binding,inventory:f.inventory,budget:f.budget})).rejects.toThrow();
}));
it('rejects a serialized or absent budget rather than starting new counters',()=>fixture(async f=>{
 for(const budget of [undefined,JSON.parse(JSON.stringify({limitsHash:f.budget.limitsHash}))])
  await expect(verifyOwnedNonrootControlCache({directory:f.cache,binding:f.binding,inventory:f.inventory,budget})).rejects.toThrow('ImageBudgetRequired');
}));
it('defaults to prepaid LOCAL verification and charges real cache/FS work without ECR or HTTP debits',()=>fixture(async f=>{
 const spent={ecrRequests:5,httpBodyBytes:200,logicalBytes:100,uncompressedBytes:0,processedEntries:0},prior={...spent};let zeroChecks=0;
 const metadataReads={reserveLocal(charge){expect(charge.ecrRequests).toBe(0);expect(charge.httpBodyBytes).toBe(0);if(Object.values(charge).every(n=>n===0))zeroChecks++;for(const key of Object.keys(spent))spent[key]+=charge[key];return {...spent};}};
 const result=await verifyOwnedNonrootControlCache({directory:f.cache,binding:f.binding,inventory:f.inventory,metadataReads});
 try{
  expect(controlImageGraphBinding(result.graph).rootDigest).toBe(f.binding.root.digest);const usage=result.usage();
  expect(usage.after.calls).toBe(0);expect(usage.after.transferredBytes).toBe(0);expect(usage.after.logicalBytes).toBe(usage.physicalCacheBytes);
  expect(spent).toEqual({...prior,logicalBytes:prior.logicalBytes+usage.after.logicalBytes,uncompressedBytes:usage.after.uncompressedBytes,processedEntries:usage.after.fsEntries});
  expect(zeroChecks).toBeGreaterThan(f.inventory.nodes.length);
 }finally{await result.close();}
}));
it('rejects exhausted prepaid logical quota before opening or parsing corrupt image bytes',()=>fixture(async f=>{
 await writeFile(join(f.cache,f.binding.root.digest.slice(7)),Buffer.alloc(f.binding.root.size,1));
 const budget=createPrepaidControlCacheBudget({metadataReads:{reserveLocal(charge){if(charge.logicalBytes)throw Error('PrepaidLocalQuota');}}});
 const probe=await open(join(f.cache,f.binding.root.digest.slice(7)),'r'),read=vi.spyOn(Object.getPrototypeOf(probe),'read');
 try{
  await expect(verifyOwnedNonrootControlCache({directory:f.cache,binding:f.binding,inventory:f.inventory,budget})).rejects.toThrow('PrepaidLocalQuota');
  expect(read).not.toHaveBeenCalled();expect(budget.usage()).toMatchObject({logicalBytes:0,localReads:0,calls:0,transferredBytes:0});
 }finally{read.mockRestore();await probe.close();}
}));
it('does not silently ignore a different acquisition or reuse the same local graph budget',()=>fixture(async f=>{
 const metadataReads={reserveLocal(){}},budget=createPrepaidControlCacheBudget({metadataReads});
 await expect(verifyOwnedNonrootControlCache({directory:f.cache,binding:f.binding,inventory:f.inventory,budget,metadataReads:{reserveLocal(){}}})).rejects.toThrow('ControlCacheAcquisitionMismatch');
 const result=await verifyOwnedNonrootControlCache({directory:f.cache,binding:f.binding,inventory:f.inventory,budget,metadataReads});
 try{await expect(verifyOwnedNonrootControlCache({directory:f.cache,binding:f.binding,inventory:f.inventory,budget})).rejects.toThrow('ControlCacheBudgetConsumed');}
 finally{await result.close();}
}));
it('derives every graph edge and attestation from a freshly collected cache instead of an input receipt',()=>fixture(async f=>{
 const metadataReads={reserveLocal(){}},budget=createPrepaidControlCacheBudget({metadataReads});
 const result=await readCollectedControlImageCache(f.binding,{directory:f.cache,nodes:f.inventory.nodes,budget,metadataReads});
 try{expect(result.graph.inventory).toEqual(f.inventory);expect(controlImageGraphBinding(result.graph).rootDigest).toBe(f.binding.root.digest);}
 finally{await result.cache.close();}
}));
it('rejects unreferenced downloaded nodes even when they have valid hashes and file permissions',()=>fixture(async f=>{
 const {createHash}=await import('node:crypto'),bytes=Buffer.from('{"unused":true}'),node={digest:'sha256:'+createHash('sha256').update(bytes).digest('hex'),size:bytes.length,mediaType:'application/vnd.oci.image.config.v1+json'};
 expect(f.inventory.nodes.some(n=>n.digest===node.digest)).toBe(false);await writeFile(join(f.cache,node.digest.slice(7)),bytes,{mode:0o600});
 const metadataReads={reserveLocal(){}},budget=createPrepaidControlCacheBudget({metadataReads});
 await expect(readCollectedControlImageCache(f.binding,{directory:f.cache,nodes:[...f.inventory.nodes,node],budget,metadataReads})).rejects.toThrow('NonrootControlCacheGraphChanged');
}));
