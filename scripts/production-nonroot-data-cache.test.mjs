import {expect, it, vi} from 'vitest';
import {mkdtemp, writeFile, chmod, symlink, link, rename, rm, open} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {gzipSync} from 'node:zlib';
import {
  IMAGE_MEDIA, imageDigest, readImageGraph, imageGraphState,
  createPrepaidDataCacheBudget, createPrepaidControlCacheBudget,
  readOwnedDataImageCache, readOwnedControlImageCache, readCollectedControlImageCache,
  readArchivedControlImageGraph, controlImageGraphBinding, verifyImageGraphCopies,
} from './lib/production-image-graph.mjs';
import {
  inspectImageFilesystem, inspectImageFilesystemEvidence, inspectImageFilesystemEntries,
  readImageFilesystemFile, assertImageFilesystemSource,
} from './lib/production-image-filesystem.mjs';
import {copyImageGraph} from './lib/production-image-copy.mjs';
import {openOwnedNonrootControlCache} from './lib/production-nonroot-control-cache.mjs';
import {graphFixture, tar} from './production-image.fixture.mjs';

const zero=()=>({ecrRequests:0,logicalBytes:0,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0});
function payer(deny=()=>false) {
  const initial={ecrRequests:3,logicalBytes:17,httpBodyBytes:29,uncompressedBytes:31,processedEntries:5};
  const spent={...initial},charges=[];
  const metadataReads={reserveLocal(c) {
    expect(Object.keys(c).sort()).toEqual(Object.keys(zero()).sort());
    expect(c.ecrRequests).toBe(0);expect(c.httpBodyBytes).toBe(0);
    if(deny(c))throw Error('SyntheticOriginalQuota');
    charges.push({...c});for(const key of Object.keys(spent))spent[key]+=c[key];
    return {...spent};
  }};
  return {initial,spent,charges,metadataReads};
}

async function fixture(use,{extraLayers=0,gzip=false}={}) {
  const directory=await mkdtemp(join(tmpdir(),'owned-data-cache-'));
  const f=graphFixture();
  // Generate independent synthetic layer occurrences, keeping attestation
  // subjects and diff IDs bound to the changed ARM64 manifests.
  for(const root of f.roots) {
    const index=JSON.parse(f.data.get(root.root.digest)),arm=JSON.parse(f.data.get(root.arm64Digest));
    const config=JSON.parse(f.data.get(arm.config.digest));
    const rawLayers=[...arm.layers.map(d=>f.data.get(d.digest)),...Array.from({length:extraLayers},(_,i)=>tar([{path:'extra/'+root.component+'/'+i,body:'synthetic '+i}]))];
    arm.layers=rawLayers.map(raw=>f.put(gzip?gzipSync(raw):raw,gzip?IMAGE_MEDIA.gzip:IMAGE_MEDIA.tar));
    config.rootfs.diff_ids=rawLayers.map(imageDigest);arm.config=f.put(config,IMAGE_MEDIA.config);
    const manifest=f.put(arm,IMAGE_MEDIA.manifest),attestation=JSON.parse(f.data.get(index.manifests[1].digest));
    const payload=JSON.parse(f.data.get(attestation.layers[0].digest));payload.subject[0].digest.sha256=manifest.digest.slice(7);
    attestation.layers=[f.put(payload,IMAGE_MEDIA.attestation)];
    index.manifests=[{...manifest,platform:{os:'linux',architecture:'arm64'}},{...f.put(attestation,IMAGE_MEDIA.manifest),platform:{os:'unknown',architecture:'unknown'},annotations:{'vnd.docker.reference.type':'attestation-manifest','vnd.docker.reference.digest':manifest.digest}}];
    root.root=f.put(index,IMAGE_MEDIA.index);root.arm64Digest=manifest.digest;
  }
  const reference=await readImageGraph(f.roots,f),objects=[];
  try {
    for(const d of reference.inventory.nodes) {
      // Pinned DATA files need not have digest-derived basenames.
      const path=join(directory,'object-'+objects.length+'.bin');
      await writeFile(path,f.data.get(d.digest),{mode:0o600,flag:'wx'});
      objects.push({path,sha256:d.digest.slice(7),bytesLength:d.size});
    }
    const options={inventory:reference.inventory,objects};
    await use({...f,directory,reference,objects,options});
  } finally {await rm(directory,{recursive:true,force:true});}
}
async function local(f,p=payer(),options={}) {
  const budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads,...options});
  const opened=await readOwnedDataImageCache(f.roots,{...f.options,budget,metadataReads:p.metadataReads});
  return {...opened,budget,p};
}
async function fileProbe(f,use) {
  const probe=await open(f.objects[0].path,'r'),proto=Object.getPrototypeOf(probe);
  try {await use(proto);} finally {vi.restoreAllMocks();await probe.close();}
}

it('reconstructs all three images and the complete inventory with shared blobs and many layers',()=>fixture(async f=>{
  const p=payer(),result=await local(f,p);
  try {
    expect(result.graph.inventory).toEqual(f.reference.inventory);
    expect(result.graph.graphHash).toBe(f.reference.graphHash);
    expect(imageGraphState(result.graph).readbacks).toEqual(imageGraphState(f.reference).readbacks);
    expect(imageGraphState(result.graph).side).not.toBe('source');
    expect(imageGraphState(result.graph).side).not.toBe('destination');
    for(const root of f.roots) {
      const expected=await inspectImageFilesystem(f.reference,{component:root.component});
      const actual=await inspectImageFilesystem(result.graph,{component:root.component});
      expect(inspectImageFilesystemEvidence(actual)).toEqual(inspectImageFilesystemEvidence(expected));
      expect(inspectImageFilesystemEntries(actual)).toEqual(inspectImageFilesystemEntries(expected));
    }
    await result.cache.check();
    const usage=result.cache.usage();
    expect(p.spent.logicalBytes-p.initial.logicalBytes).toBe(4096*usage.cacheReads+3*usage.physicalCacheBytes);
    expect(p.spent.uncompressedBytes-p.initial.uncompressedBytes).toBe(result.budget.usage().uncompressedBytes);
    expect(p.spent.processedEntries-p.initial.processedEntries).toBe(result.budget.usage().fsEntries);
    expect(p.spent.ecrRequests).toBe(p.initial.ecrRequests);expect(p.spent.httpBodyBytes).toBe(p.initial.httpBodyBytes);
  } finally {await result.cache.close();await result.cache.close();}
},{extraLayers:13}));

it('keeps the lease alive and pays again for config, filesystem and later file rereads',()=>fixture(async f=>{
  const r=await local(f),component=f.roots[0].component;
  try {
    const fs=await inspectImageFilesystem(r.graph,{component}),before={...r.p.spent};
    expect((await readImageFilesystemFile(fs,'/app/'+component)).toString()).toBe('synthetic layer '+component);
    expect(r.p.spent.logicalBytes).toBeGreaterThan(before.logicalBytes);
    expect(r.p.spent.uncompressedBytes).toBeGreaterThan(before.uncompressedBytes);
    expect(r.p.spent.processedEntries).toBe(before.processedEntries);
    await r.cache.check();
  } finally {await r.cache.close();}
  await expect(r.cache.check()).rejects.toThrow();
}));

it.each(['digest','size','media','duplicate','missing','extra','extra-field'])('rejects %s object/inventory changes',defect=>fixture(async f=>{
  const inventory=structuredClone(f.options.inventory),objects=structuredClone(f.objects);
  if(defect==='digest')objects[0].sha256='f'.repeat(64);
  if(defect==='size')objects[0].bytesLength++;
  if(defect==='media')inventory.nodes[0].mediaType='application/not-an-image';
  if(defect==='duplicate')objects.push({...objects[0]});
  if(defect==='missing')objects.pop();
  if(defect==='extra')objects.push({path:join(f.directory,'unused'),sha256:'f'.repeat(64),bytesLength:1});
  if(defect==='extra-field')objects[0].url='https://example.com/object';
  const p=payer(),budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads});
  await fileProbe(f,async proto=>{
    const reads=vi.spyOn(proto,'read');
    await expect(readOwnedDataImageCache(f.roots,{inventory,objects,budget,metadataReads:p.metadataReads})).rejects.toThrow();
    expect(reads).not.toHaveBeenCalled();
  });
}));

it.each(['corrupt','symlink','hardlink','mode','path-alias'])('rejects %s file custody',defect=>fixture(async f=>{
  const objects=structuredClone(f.objects),target=objects.find(o=>o.bytesLength>2);
  if(defect==='corrupt')await writeFile(target.path,Buffer.alloc(target.bytesLength,1));
  if(defect==='mode')await chmod(target.path,0o644);
  if(defect==='hardlink')await link(target.path,join(f.directory,'alias'));
  if(defect==='symlink') {const saved=target.path+'.real';await rename(target.path,saved);await symlink(saved,target.path);}
  if(defect==='path-alias')target.path=f.directory+'/./'+target.path.slice(f.directory.length+1);
  const p=payer(),budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads});
  await expect(readOwnedDataImageCache(f.roots,{inventory:f.options.inventory,objects,budget,metadataReads:p.metadataReads})).rejects.toThrow();
}));

it('rejects inode replacement during a read and closes the actual opened descriptor',()=>fixture(async f=>{
  const target=f.objects.find(o=>o.sha256===f.roots[0].root.digest.slice(7)),saved=target.path+'.saved';
  const p=payer(),budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads});
  await fileProbe(f,async proto=>{
    const original=proto.read,opened=new Set();let replaced=false;
    vi.spyOn(proto,'read').mockImplementation(async function(...args){
      opened.add(this);
      const value=await original.apply(this,args);
      if(!replaced){replaced=true;await rename(target.path,saved);await writeFile(target.path,f.data.get('sha256:'+target.sha256),{mode:0o600});}
      return value;
    });
    await expect(readOwnedDataImageCache(f.roots,{...f.options,budget,metadataReads:p.metadataReads})).rejects.toThrow();
    expect(replaced).toBe(true);expect(opened.size).toBeGreaterThan(0);
    for(const handle of opened)expect(handle.fd).toBe(-1);
  });
}));

it('charges each bounded read before fd.read, and does not double-charge the graph',()=>fixture(async f=>{
  const p=payer();
  await fileProbe(f,async proto=>{
    const original=proto.read;let reads=0;
    vi.spyOn(proto,'read').mockImplementation(function(buffer,offset,length,position){
      const debit=p.charges.filter(c=>c.logicalBytes>0).at(-1);
      expect(length).toBeLessThanOrEqual(65536);expect(debit.logicalBytes).toBe(3*length);reads++;
      return original.call(this,buffer,offset,length,position);
    });
    const r=await local(f,p);
    try {expect(reads).toBeGreaterThan(0);const u=r.cache.usage();expect(p.spent.logicalBytes-p.initial.logicalBytes).toBe(4096*u.cacheReads+3*u.physicalCacheBytes);}
    finally {await r.cache.close();}
  });
}));

it.each(['open','chunk'])('stops denied %s work before any file read',kind=>fixture(async f=>{
  const p=payer(c=>kind==='open'?c.logicalBytes===4096:c.logicalBytes>0&&c.logicalBytes!==4096);
  const budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads});
  await fileProbe(f,async proto=>{
    const read=vi.spyOn(proto,'read'),alloc=vi.spyOn(Buffer,'alloc');
    await expect(readOwnedDataImageCache(f.roots,{...f.options,budget,metadataReads:p.metadataReads})).rejects.toThrow('SyntheticOriginalQuota');
    expect(read).not.toHaveBeenCalled();expect(alloc).not.toHaveBeenCalled();expect(()=>budget.check()).toThrow('DataCacheBudgetHeld');
  });
}));

it('stops cancellation after an actual read and still joins file closure',()=>fixture(async f=>{
  const p=payer(),abort=new AbortController(),budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads,signal:abort.signal});
  await fileProbe(f,async proto=>{
    const original=proto.read,opened=new Set();let count=0;
    vi.spyOn(proto,'read').mockImplementation(async function(...args){opened.add(this);const value=await original.apply(this,args);count++;abort.abort(Error('OwnerCancelled'));return value;});
    await expect(readOwnedDataImageCache(f.roots,{...f.options,budget,metadataReads:p.metadataReads})).rejects.toThrow('OwnerCancelled');
    expect(count).toBe(1);for(const handle of opened)expect(handle.fd).toBe(-1);expect(()=>budget.check()).toThrow('DataCacheBudgetHeld');
  });
}));

it('does not return a graph when physical close reports failure',()=>fixture(async f=>{
  const p=payer(),budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads});
  await fileProbe(f,async proto=>{
    const original=proto.stat;let once=false;
    vi.spyOn(proto,'stat').mockImplementation(async function(...args){
      const value=await original.apply(this,args);
      if(!once){once=true;const close=this.close.bind(this);vi.spyOn(this,'close').mockImplementation(async()=>{await close();throw Error('SyntheticCloseFailure');});}
      return value;
    });
    await expect(readOwnedDataImageCache(f.roots,{...f.options,budget,metadataReads:p.metadataReads})).rejects.toThrow();
    expect(once).toBe(true);expect(()=>budget.check()).toThrow('DataCacheBudgetHeld');
  });
}));

it.each(['uncompressedBytes','processedEntries'])('denies %s after bounded yield but before pass counter or parser admission',counter=>fixture(async f=>{
  let deny=false;const p=payer(c=>deny&&c[counter]>0),r=await local(f,p);
  try {
    deny=true;const before={...p.spent};
    await expect(inspectImageFilesystem(r.graph,{component:f.roots[0].component})).rejects.toThrow('SyntheticOriginalQuota');
    expect(p.spent[counter]).toBe(before[counter]);
    expect(r.budget.usage()[counter==='processedEntries'?'fsEntries':counter]).toBe(0);
    expect(()=>r.budget.check()).toThrow('DataCacheBudgetHeld');
  } finally {await r.cache.close();}
},{gzip:true}));

it('compares full reconstructed edges and attestations, not just supplied nodes',()=>fixture(async f=>{
  const p=payer(),budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads});
  const inventory=structuredClone(f.options.inventory);inventory.edges.pop();
  await expect(readOwnedDataImageCache(f.roots,{...f.options,inventory,budget,metadataReads:p.metadataReads})).rejects.toThrow();
  expect(()=>budget.check()).toThrow('DataCacheBudgetHeld');
}));

it('requires the same payer and permits only one graph opening attempt',()=>fixture(async f=>{
  const p=payer(),budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads});
  await expect(readOwnedDataImageCache(f.roots,{...f.options,budget,metadataReads:{reserveLocal:p.metadataReads.reserveLocal}})).rejects.toThrow('DataCache');
  const r=await local(f,p);
  try {await expect(readOwnedDataImageCache(f.roots,{...f.options,budget:r.budget,metadataReads:p.metadataReads})).rejects.toThrow('DataCacheBudgetConsumed');}
  finally {await r.cache.close();}
}));

it.each(['readManifest','readBlob','source','store','url'])('rejects the caller-supplied %s escape hatch before invoking it',key=>fixture(async f=>{
  const callback=vi.fn(),p=payer(),budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads});
  await expect(readOwnedDataImageCache(f.roots,{...f.options,budget,metadataReads:p.metadataReads,[key]:callback})).rejects.toThrow('DataCacheReadOptions');
  expect(callback).not.toHaveBeenCalled();
}));

it('rejects missing roots, CONTROL budgets, and DATA-to-CONTROL admission before IO',()=>fixture(async f=>{
  const p=payer();
  for(const roots of [f.roots.slice(0,2),[...f.roots,{...f.roots[0]}]]) {
    const budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads});
    await expect(readOwnedDataImageCache(roots,{...f.options,budget,metadataReads:p.metadataReads})).rejects.toThrow('ImageRoots');
  }
  await expect(readOwnedDataImageCache(f.roots,{...f.options,budget:createPrepaidControlCacheBudget({metadataReads:p.metadataReads}),metadataReads:p.metadataReads})).rejects.toThrow('DataCache');
  const root=f.roots[0],config=JSON.parse(f.data.get(root.arm64Digest)).config;
  const binding={account:'123456789012',region:'ap-northeast-1',repositoryName:'mem9-on-aws/bootstrap',root:root.root,arm64Digest:root.arm64Digest,configDigest:config.digest};
  for(const run of [readOwnedControlImageCache,readCollectedControlImageCache,readArchivedControlImageGraph]) {
    const budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads});
    await expect(run(binding,{directory:'/does-not-exist',inventory:f.options.inventory,nodes:f.options.inventory.nodes,budget,metadataReads:p.metadataReads})).rejects.toThrow();
  }
  await expect(openOwnedNonrootControlCache({directory:'/does-not-exist',binding,inventory:f.options.inventory,budget:createPrepaidDataCacheBudget({metadataReads:p.metadataReads})})).rejects.toThrow('DataCache');
}));

it('does not grant source-copy or CONTROL authority through a genuine DATA-local graph',()=>fixture(async f=>{
  const r=await local(f),api=vi.fn(),journal={once:vi.fn(),read:vi.fn()};
  try {
    const fs=await inspectImageFilesystem(r.graph,{component:f.roots[0].component});
    expect(()=>controlImageGraphBinding(r.graph)).toThrow('ControlImageContextRequired');
    expect(()=>verifyImageGraphCopies(r.graph,f.reference,{account:'123456789012',region:'ap-northeast-1'})).toThrow();
    expect(()=>assertImageFilesystemSource(fs,r.graph,{requirementsHash:inspectImageFilesystemEvidence(fs).requirementsHash})).toThrow('ImageFilesystemSourceRequired');
    await expect(copyImageGraph(r.graph,{budget:r.budget,api,journal})).rejects.toThrow('ImageCopySource');
    expect(api).not.toHaveBeenCalled();expect(journal.once).not.toHaveBeenCalled();expect(journal.read).not.toHaveBeenCalled();
  } finally {await r.cache.close();}
}));

it('cannot promote a copied DATA projection or replace the owned cache readers',()=>fixture(async f=>{
  const r=await local(f),replacement=vi.fn();
  try {
    const state=imageGraphState(r.graph);
    state.side='source';state.store={open:replacement};
    expect(imageGraphState(r.graph).side).toBe('local-data');
    expect(Reflect.set(r.cache.store,'open',replacement)).toBe(false);
    expect(Reflect.set(imageGraphState(r.graph).store,'open',replacement)).toBe(false);
    await expect(copyImageGraph(r.graph,{budget:r.budget,api:replacement})).rejects.toThrow('ImageCopySource');
    expect(replacement).not.toHaveBeenCalled();
  } finally {await r.cache.close();}
}));

it('rejects another uid before reading content and still closes the real file',()=>fixture(async f=>{
  const p=payer(),budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads});
  await fileProbe(f,async proto=>{
    const original=proto.stat,handles=new Set(),reads=vi.spyOn(proto,'read');
    vi.spyOn(proto,'stat').mockImplementation(async function(...args){
      handles.add(this);const value=await original.apply(this,args);
      return Object.assign(Object.create(Object.getPrototypeOf(value)),value,{uid:value.uid+1n});
    });
    await expect(readOwnedDataImageCache(f.roots,{...f.options,budget,metadataReads:p.metadataReads})).rejects.toThrow('NonrootDataCacheFile');
    expect(reads).not.toHaveBeenCalled();for(const handle of handles)expect(handle.fd).toBe(-1);
  });
}));

it('joins both open streams when one physical close fails',()=>fixture(async f=>{
  const r=await local(f);
  await fileProbe(f,async proto=>{
    const original=proto.stat,handles=[];
    vi.spyOn(proto,'stat').mockImplementation(async function(...args){
      const value=await original.apply(this,args);
      if(!handles.includes(this)){
        handles.push(this);
        if(handles.length===1){const close=this.close.bind(this);vi.spyOn(this,'close').mockImplementation(async()=>{await close();throw Error('OneCloseFailed');});}
      }
      return value;
    });
    const layers=f.roots.slice(0,2).map(root=>imageGraphState(r.graph).images.get(root.component).layers[0]);
    const streams=layers.map(layer=>r.cache.store.open(layer));
    for(const stream of streams)expect((await stream.next()).done).toBe(false);
    const closing=r.cache.close();expect(r.cache.close()).toBe(closing);
    await expect(closing).rejects.toMatchObject({cleanupComplete:false});
    expect(handles).toHaveLength(2);for(const handle of handles)expect(handle.fd).toBe(-1);
    expect(()=>r.budget.check()).toThrow('DataCacheBudgetHeld');
  });
}));
