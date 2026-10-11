/** Reacquire the complete immutable base in the original main child. The
 * owner's discovery cache is evidence only and is never borrowed here. */
import {mkdir,open,unlink,rmdir} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {readCollectedControlImageCache} from './production-image-graph.mjs';
import {inspectImageFilesystem,inspectImageFilesystemEvidence} from './production-image-filesystem.mjs';
import {requireProductionControlCompositionAllocation,createProductionControlCompositionCacheBudget,reserveProductionControlComposition,
 recordProductionControlComposition,holdProductionControlComposition} from './production-control-composition-lifetime.mjs';
import {requireProductionControlCompositionTransport} from './production-control-composition-transport.mjs';
import {compositionNeed as need,compositionCharge} from './production-control-composition.mjs';

const handles=new WeakMap(),used=new WeakSet(),metadata=d=>d.mediaType.includes('manifest')||d.mediaType.includes('image.index');
async function cleanup(s){
 let problem;try{await s.cache?.cache.close();}catch(e){problem=e;}
 for(const path of [...s.files].reverse())try{await unlink(path);}catch(e){if(e.code!=='ENOENT')problem??=e;}
 if(s.created)try{await rmdir(s.directory);}catch(e){if(e.code!=='ENOENT')problem??=e;}
 s.closed=true;if(problem)throw Object.assign(Error('ControlCompositionBaseCleanup'),{cause:problem});
}
export async function acquireProductionControlCompositionBase({allocation,transport}){
 const a=requireProductionControlCompositionAllocation(allocation);requireProductionControlCompositionTransport(transport,allocation);
 need(!used.has(allocation),'ControlCompositionBaseRepeated');used.add(allocation);
 const s={allocation,directory:join(a.directory,'acquired-base'),created:false,files:[],cache:null,closed:false};let staged=0;
 try{
  await mkdir(s.directory,{mode:0o700});s.created=true;
  for(const d of a.plan.input.base.inventory.nodes){
   const path=join(s.directory,d.digest.slice(7)),fd=await open(path,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW,0o600);s.files.push(path);
   const digest=createHash('sha256');let size=0;
   const consume=async bytes=>{
    for(let at=0;at<bytes.length;at+=65536){
     const b=bytes.subarray(at,at+65536);need(size+b.length<=d.size&&staged+2*b.length<=2*a.plan.base.graphBytes,'ControlCompositionBaseSize');
     reserveProductionControlComposition(allocation,compositionCharge({logicalBytes:2*b.length}));staged+=2*b.length;
     digest.update(b);size+=b.length;let written=0;
     while(written<b.length){requireProductionControlCompositionAllocation(allocation);const r=await fd.write(b,written,b.length-written);need(r.bytesWritten>0,'ControlCompositionBaseWrite');written+=r.bytesWritten;}
    }
   };
   try{
    if(metadata(d))await consume(await transport.manifest(d,{base:true}));else await transport.baseBlob(d,consume);
    need(size===d.size&&'sha256:'+digest.digest('hex')===d.digest,'ControlCompositionBaseDigest');await fd.sync();
   }finally{await fd.close();}
  }
  const p=a.plan.input.base,i=p.image,root=p.inventory.roots[0].root;
  const parsing=createProductionControlCompositionCacheBudget(allocation,{part:'base',alreadyCharged:staged});
  s.cache=await readCollectedControlImageCache({account:i.account,region:i.region,repositoryName:i.repositoryName,root,arm64Digest:i.arm64Digest,configDigest:i.configDigest},
   {directory:s.directory,nodes:p.inventory.nodes,budget:parsing.budget,metadataReads:parsing.metadataReads});
  need(hash(s.cache.graph.inventory)===hash(p.inventory),'ControlCompositionBaseInventory');
  s.filesystem=await inspectImageFilesystem(s.cache.graph,{component:'bootstrap',budget:parsing.budget});
  need(hash(inspectImageFilesystemEvidence(s.filesystem))===hash(p.filesystem),'ControlCompositionBaseFilesystem');
  const u=parsing.budget.usage();need(u.uncompressedBytes===p.uncompressedBytes&&u.fsEntries===p.processedEntries&&staged+u.logicalBytes<=a.plan.parts.base.logicalBytes,'ControlCompositionBaseGeometry');
  await s.cache.cache.check();const charged=parsing.completeAcquisition();
  recordProductionControlComposition(allocation,'base-acquired',{graphHash:s.cache.graph.graphHash,stagedBytes:staged,usage:u,charged});
  const h=Object.freeze({kind:'native-control-composition-base'});handles.set(h,s);return h;
 }catch(e){holdProductionControlComposition(allocation,e.message);try{await cleanup(s);}catch(c){throw Object.assign(c,{cause:e});}throw e;}
}
export function requireProductionControlCompositionBase(handle,allocation){
 const s=handles.get(handle);need(s&&!s.closed&&s.allocation===allocation,'ControlCompositionNativeBase');requireProductionControlCompositionAllocation(allocation);
 return Object.freeze({baseGraph:s.cache.graph,baseFilesystem:s.filesystem});
}
export async function closeProductionControlCompositionBase(handle){const s=handles.get(handle);need(s&&!s.closed,'ControlCompositionNativeBase');await cleanup(s);}
