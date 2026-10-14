/** Code-owned DATA cache IO. Pinned local files are parser input, not source,
 * copy, credential or publication authority. No network adapter is accepted. */
import {open,lstat,realpath} from 'node:fs/promises';
import {constants} from 'node:fs';
import {resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {assertImageBudget,validateImageDescriptor,IMAGE_MEDIA,DATA_CACHE_READ_CHUNK_BYTES} from './production-image-graph.mjs';
import {IMAGE_TRANSITION_LIMITS as L,IMAGE_TRANSITION_COMPONENTS} from './production-image-transition.mjs';
import {copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';

const need=(ok,code='NonrootDataCacheInvalid')=>{if(!ok)throw Error(code);};
const fields=['dev','ino','size','mode','uid','gid','nlink','mtimeNs','ctimeNs'];
const sameFile=(a,b)=>fields.every(k=>a[k]===b[k]);
const fileShape=(s,size)=>s.isFile()&&s.uid===BigInt(process.getuid())&&(s.mode&511n)===384n&&s.nlink===1n&&s.size===BigInt(size);

export async function openOwnedNonrootDataCache({roots,inventory,objects,budget}){
 const manifests=new Set([IMAGE_MEDIA.index,IMAGE_MEDIA.dockerIndex,IMAGE_MEDIA.manifest,IMAGE_MEDIA.dockerManifest]);
 assertImageBudget(budget);need(budget.kind==='prepaid-local-data-cache','DataCacheBudgetRequired');
 need(Array.isArray(inventory?.nodes)&&inventory.nodes.length>0&&inventory.nodes.length<=L.maxManifestNodes+L.maxBlobNodes&&
  Array.isArray(objects)&&objects.length===inventory.nodes.length,'NonrootDataCacheInventory');
 const bound=copyNonrootJson({roots,inventory,objects});({roots,inventory,objects}=bound);
 need(Array.isArray(roots)&&roots.length===L.rootCount&&hash(roots.map(r=>r.component).sort())===hash(IMAGE_TRANSITION_COMPONENTS)&&
  inventory.version===1&&inventory.kind===undefined&&hash(inventory.roots)===hash(roots),'NonrootDataCacheInventory');
 const nodes=new Map(),refs=new Map(),paths=new Set();
 for(const d of inventory.nodes){
  need(d&&Object.keys(d).sort().join()==='digest,mediaType,size'&&!nodes.has(d.digest),'NonrootDataCacheDescriptor');
  validateImageDescriptor(d,manifests.has(d.mediaType)?'manifest':'blob');nodes.set(d.digest,d);
 }
 for(const r of objects){
  need(r&&Object.keys(r).sort().join()==='bytesLength,path,sha256'&&typeof r.path==='string'&&resolve(r.path)===r.path&&
   Buffer.byteLength(r.path)<=L.maxPathBytes&&/^[a-f0-9]{64}$/.test(r.sha256)&&Number.isSafeInteger(r.bytesLength)&&r.bytesLength>=0,'NonrootDataCacheReference');
  const digest='sha256:'+r.sha256,d=nodes.get(digest);
  need(d&&d.size===r.bytesLength&&!refs.has(digest)&&!paths.has(r.path),'NonrootDataCacheInventory');refs.set(digest,r);paths.add(r.path);
 }
 const repositories=new Set(roots.map(r=>r.sourceRepository)),identities=new Map(),leases=new Set();
 let closed=false,closing,physicalCacheBytes=0,cacheReads=0;
 const check=()=>{need(!closed,'NonrootDataCacheClosed');budget.check();};
 // One promise owns each physical close, including its uncertainty. A failed
 // close is never retried or forgotten merely to make cleanup look successful.
 const closeFile=lease=>lease.closePromise??=(async()=>{if(lease.fd)await lease.fd.close();lease.closed=true;})();
 const bytes=descriptor=>{
  check();const d=nodes.get(descriptor?.digest),r=d&&refs.get(d.digest);
  need(d&&d.size===descriptor.size&&d.mediaType===descriptor.mediaType,'NonrootDataCacheDescriptor');
  need(leases.size<L.maxConcurrency,'NonrootDataCacheConcurrency');
  const lease={fd:null,closed:false,closePromise:null,iterator:null};
  lease.iterator=(async function*(){
   try{
    check();budget.cacheOpen();cacheReads++;
    need(await realpath(r.path)===r.path,'NonrootDataCacheAlias');check();
    lease.fd=await open(r.path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);check();
    const before=await lease.fd.stat({bigint:true});check();
    need(fileShape(before,r.bytesLength),'NonrootDataCacheFile');
    const prior=identities.get(d.digest);if(prior)need(sameFile(prior,before),'NonrootDataCacheChanged');else identities.set(d.digest,before);
    const digest=createHash('sha256');let count=0;
    while(count<r.bytesLength){
     check();const size=Math.min(DATA_CACHE_READ_CHUNK_BYTES,r.bytesLength-count);
     budget.cacheRead(size);const buffer=Buffer.alloc(size);
     const result=await lease.fd.read(buffer,0,size,count);check();
     need(result.bytesRead===size,'NonrootDataCacheShortRead');
     count+=size;physicalCacheBytes+=size;need(Number.isSafeInteger(physicalCacheBytes),'NonrootDataCacheSize');
     digest.update(buffer);yield buffer;
    }
    check();const after=await lease.fd.stat({bigint:true});check();const named=await lstat(r.path,{bigint:true});check();
    need(count===d.size&&'sha256:'+digest.digest('hex')===d.digest,'NonrootDataCacheDigest');
    need(sameFile(before,after)&&sameFile(before,named)&&await realpath(r.path)===r.path,'NonrootDataCacheChanged');check();
   }catch(error){budget.hold();throw error;}
   finally{
    try{await closeFile(lease);leases.delete(lease);}
    catch(error){budget.hold();throw Object.assign(error,{cleanupComplete:false,hold:true});}
   }
  })();
  leases.add(lease);return lease.iterator;
 };
 const read=request=>{check();need(repositories.has(request.repositoryName),'NonrootDataCacheRepository');return bytes(request.descriptor);};
 const store=Object.freeze({open:bytes,async put(d,stream){
  check();let size=0;
  for await(const chunk of stream){check();need(chunk instanceof Uint8Array,'NonrootDataCacheBytes');size+=chunk.length;need(size<=d.size,'NonrootDataCacheSize');}
  check();need(size===d.size,'NonrootDataCacheSize');
 }});
 const before=budget.usage();
 const close=()=>closing??=(async()=>{
  closed=true;const pending=[...leases];
  // A stream failure has its own caller; cleanup independently joins all
  // iterator returns and all physical closes even after the payer is held.
  await Promise.allSettled(pending.map(lease=>lease.iterator.return()));
  const results=await Promise.allSettled(pending.map(closeFile));
  if(results.some(r=>r.status==='rejected')||pending.some(lease=>!lease.closed)){
   budget.hold();throw Object.assign(Error('NonrootDataCacheCleanup'),{cleanupComplete:false,hold:true});
  }
  for(const lease of pending)leases.delete(lease);
 })();
 return Object.freeze({store,readBlob:read,readManifest:async request=>{
  const chunks=[];let size=0;
  for await(const chunk of read(request)){check();size+=chunk.length;need(size<=L.maxManifestBytes,'NonrootDataCacheManifest');chunks.push(chunk);}
  check();return Buffer.concat(chunks,size);
 },async check(){
  try{
   check();need(leases.size===0,'NonrootDataCacheActive');
   for(const [digest,prior]of identities){const r=refs.get(digest),named=await lstat(r.path,{bigint:true});check();need(sameFile(prior,named)&&await realpath(r.path)===r.path,'NonrootDataCacheChanged');check();}
  }catch(error){budget.hold();throw error;}
 },close,usage:()=>copyNonrootJson({physicalCacheBytes,cacheReads,before,after:budget.usage()})});
}
