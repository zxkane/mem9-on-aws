/** Local CONTROL cache reader; it never executes image code. Metadata is not evidence:
 * every referenced byte passes the original CONTROL graph and FS parsers.
 * The caller supplies the already reserved/seeded budget; this module cannot
 * start a new accounting lifetime or turn an archive receipt into a live brand. */
import {open,lstat,realpath,readdir} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {readOwnedControlImageCache,createPrepaidControlCacheBudget,assertImageBudget,validateImageDescriptor,IMAGE_MEDIA} from './production-image-graph.mjs';
import {inspectImageFilesystem} from './production-image-filesystem.mjs';
import {copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {IMAGE_TRANSITION_LIMITS as L} from './production-image-transition.mjs';

const need=(ok,code='NonrootControlCacheInvalid')=>{if(!ok)throw Error(code);};
const unchanged=(a,b,keys)=>keys.every(key=>a[key]===b[key]);
const fileKeys=['dev','ino','size','mtimeMs','ctimeMs','mode','uid','nlink'];
const manifests=new Set([IMAGE_MEDIA.index,IMAGE_MEDIA.dockerIndex,IMAGE_MEDIA.manifest,IMAGE_MEDIA.dockerManifest]);

/** Code-owned opener: callers can select only local paths/descriptors, never
 * replace these readers with network callbacks. Every descriptor is charged
 * before opening it, including config/FS/file-extraction rereads. */
export async function openOwnedNonrootControlCache({directory,binding,inventory,budget}){
 assertImageBudget(budget);binding=copyNonrootJson(binding);inventory=copyNonrootJson(inventory);
 need(typeof directory==='string'&&resolve(directory)===directory&&await realpath(directory)===directory,'NonrootControlCachePath');
 const initial=await lstat(directory);
 need(initial.isDirectory()&&initial.uid===process.getuid()&&(initial.mode&0o777)===0o700,'NonrootControlCacheDirectory');
 need(inventory.kind==='readonly-control-image-graph'&&inventory.roots?.length===1&&Array.isArray(inventory.nodes)&&inventory.nodes.length>0&&inventory.nodes.length<=L.maxManifestNodes+L.maxBlobNodes,'NonrootControlCacheInventory');
 const nodes=new Map();
 for(const node of inventory.nodes){
  need(!nodes.has(node.digest),'NonrootControlCacheInventory');validateImageDescriptor(node,manifests.has(node.mediaType)?'manifest':'blob');nodes.set(node.digest,node);
 }
 const names=[...nodes.keys()].map(d=>d.slice(7)).sort(),identities=new Map(),active=new Set();
 let closed=false,physicalCacheBytes=0,reads=0;
 const check=()=>{need(!closed,'NonrootControlCacheClosed');budget.check();};
 const directoryUnchanged=async()=>{
  check();const current=await lstat(directory);
  need(await realpath(directory)===directory&&unchanged(initial,current,['dev','ino','mode','uid'])&&hash((await readdir(directory)).sort())===hash(names),'NonrootControlCacheInventory');
 };
 await directoryUnchanged();
 async function* bytes(descriptor){
  check();const expected=nodes.get(descriptor.digest);
  need(expected&&expected.size===descriptor.size&&expected.mediaType===descriptor.mediaType,'NonrootControlCacheDescriptor');
  need(active.size<L.maxConcurrency,'NonrootControlCacheConcurrency');
  budget.cacheRead?.(descriptor.size);
  const path=join(directory,descriptor.digest.slice(7));need(await realpath(path)===path,'NonrootControlCacheAlias');
  const fd=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);active.add(fd);
  try{
   const before=await fd.stat();
   need(before.isFile()&&before.uid===process.getuid()&&(before.mode&0o777)===0o600&&before.nlink===1&&before.size===descriptor.size,'NonrootControlCacheFile');
   const prior=identities.get(descriptor.digest);if(prior)need(unchanged(prior,before,fileKeys),'NonrootControlCacheChanged');else identities.set(descriptor.digest,before);
   const digest=createHash('sha256'),buffer=Buffer.alloc(65536);let size=0;reads++;
   while(true){
    check();const {bytesRead}=await fd.read(buffer,0,buffer.length,null);if(!bytesRead)break;
    size+=bytesRead;physicalCacheBytes+=bytesRead;
    need(size<=descriptor.size&&Number.isSafeInteger(physicalCacheBytes),'NonrootControlCacheSize');
    const chunk=Buffer.from(buffer.subarray(0,bytesRead));digest.update(chunk);yield chunk;
   }
   const after=await fd.stat(),named=await lstat(path);
   need(size===descriptor.size&&'sha256:'+digest.digest('hex')===descriptor.digest,'NonrootControlCacheDigest');
   need(unchanged(before,after,fileKeys)&&unchanged(before,named,fileKeys),'NonrootControlCacheChanged');
  }finally{active.delete(fd);await fd.close();}
 }
 const reader=request=>{
  need(request.repositoryName===binding.repositoryName,'NonrootControlCacheRepository');return bytes(request.descriptor);
 };
 const store={open:bytes,async put(descriptor,stream){
  check();let size=0;const digest=createHash('sha256');
  for await(const chunk of stream){check();size+=chunk.length;need(size<=descriptor.size,'NonrootControlCacheSize');digest.update(chunk);}
  need(size===descriptor.size&&'sha256:'+digest.digest('hex')===descriptor.digest,'NonrootControlCacheDigest');
 }};
 const before=budget.usage();
 const close=async()=>{closed=true;const pending=[...active];await Promise.all(pending.map(fd=>fd.close()));need(pending.length===0,'NonrootControlCacheActive');};
 return Object.freeze({store,readBlob:reader,readManifest:async request=>{
  const chunks=[];let size=0;for await(const chunk of reader(request)){size+=chunk.length;need(size<=L.maxManifestBytes,'NonrootControlCacheManifest');chunks.push(chunk);}return Buffer.concat(chunks,size);
 },check:async()=>{await directoryUnchanged();need(active.size===0,'NonrootControlCacheActive');},close,
 usage:()=>copyNonrootJson({physicalCacheBytes,cacheReads:reads,before,after:budget.usage()})});
}

export async function verifyOwnedNonrootControlCache({directory,binding,inventory,budget,metadataReads,deadlineMs,now,signal}){
 if(budget===undefined&&metadataReads!==undefined)budget=createPrepaidControlCacheBudget({metadataReads,...(deadlineMs!==undefined?{deadlineMs}:{}),...(now!==undefined?{now}:{}),...(signal!==undefined?{signal}:{})});
 assertImageBudget(budget);
 const {graph,cache}=await readOwnedControlImageCache(binding,{directory,inventory,budget,...(metadataReads!==undefined?{metadataReads}:{})});
 try{
  const filesystem=await inspectImageFilesystem(graph,{component:'bootstrap'});
  await cache.check();
  return Object.freeze({graph,filesystem,close:cache.close,usage:()=>copyNonrootJson({graphPasses:1,filesystemPasses:1,...cache.usage()})});
 }catch(error){await cache.close();throw error;}
}
