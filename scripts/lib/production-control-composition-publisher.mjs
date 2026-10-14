/** Publish only the exact native output, in dependency order. Complete and
 * readback bind explicit registry/repository/digest; no second upload follows
 * an unknown outcome and no existing immutable object is overwritten. */
import {createHash} from 'node:crypto';
import {imageGraphState} from './production-image-graph.mjs';
import {inspectProductionControlCompositionOutput} from './production-control-composition-producer.mjs';
import {requireProductionControlCompositionTransport} from './production-control-composition-transport.mjs';
import {requireProductionControlCompositionAllocation,reserveProductionControlComposition,recordProductionControlComposition,holdProductionControlComposition} from './production-control-composition-lifetime.mjs';
import {compositionCharge,compositionNeed as need,PRODUCTION_CONTROL_COMPOSITION_LIMITS as L} from './production-control-composition.mjs';

const manifest=d=>d.mediaType.includes('manifest')||d.mediaType.includes('image.index');
export async function publishProductionControlComposition({output,allocation,transport}){
 const admitted=requireProductionControlCompositionAllocation(allocation);
 requireProductionControlCompositionTransport(transport,allocation);
 const built=inspectProductionControlCompositionOutput(output),state=imageGraphState(built.graph),nodes=built.graph.inventory.nodes;
 need(built.record.allocationId===admitted.id&&built.record.planHash===admitted.plan.planHash,'ControlCompositionPublicationBinding');
 let logical=0;
 const allocate=n=>{need(Number.isSafeInteger(n)&&n>=0&&logical+n<=admitted.plan.parts.publicationRead.logicalBytes,'ControlCompositionPublicationRead');
  reserveProductionControlComposition(allocation,compositionCharge({logicalBytes:n}));logical+=n;};
 async function readSmall(d){
  allocate(d.size);const chunks=[];let n=0;
  for await(const b of state.store.open(d)){need(n+b.length<=d.size,'ControlCompositionPublicationSize');chunks.push(b);n+=b.length;}
  need(n===d.size,'ControlCompositionPublicationSize');return Buffer.concat(chunks,n);
 }
 try{
  await transport.bindOutput(output);
  const blobs=nodes.filter(d=>!manifest(d)).sort((a,b)=>a.digest.localeCompare(b.digest));
  const availability=await transport.availability(blobs.map(d=>d.digest));
  const absent=new Set(availability.layers.filter(r=>r.layerAvailability==='UNAVAILABLE').map(r=>r.layerDigest));
  for(const d of blobs.filter(d=>absent.has(d.digest))){
   const started=await transport.initiate(),iterator=state.store.open(d)[Symbol.asyncIterator]();let pending=Buffer.alloc(0),at=0;
   const checksum=createHash('sha256');
   try{
    while(at<d.size){
     const size=Math.min(L.partBytes,d.size-at);allocate(size);const body=Buffer.alloc(size);let filled=0;
     while(filled<size){
      if(!pending.length){const next=await iterator.next();need(!next.done&&next.value instanceof Uint8Array,'ControlCompositionPublicationTruncated');pending=next.value;}
      const n=Math.min(size-filled,pending.length);body.set(pending.subarray(0,n),filled);pending=pending.subarray(n);filled+=n;
     }
     checksum.update(body);await transport.part(started.uploadId,at,body);at+=size;
    }
    need(!pending.length&&(await iterator.next()).done&&'sha256:'+checksum.digest('hex')===d.digest,'ControlCompositionPublicationDigest');
    await transport.complete(started.uploadId,d.digest);
   }finally{await iterator.return?.();}
  }
  const remaining=new Map(nodes.filter(manifest).map(d=>[d.digest,d])),published=new Set();
  while(remaining.size){
   let progress=false;
   for(const [digest,d]of [...remaining]){
    const document=state.manifests.get(digest).document;
    const dependencies=[...(document.manifests??[]),...(document.subject?[document.subject]:[])].filter(manifest);
    if(dependencies.some(child=>!published.has(child.digest)))continue;
    const bytes=await readSmall(d);await transport.putManifest(d,bytes,{root:digest===built.record.image.rootDigest});
    published.add(digest);remaining.delete(digest);progress=true;
   }
   need(progress,'ControlCompositionPublicationCycle');
  }
  for(const d of nodes.filter(manifest)){
   const bytes=await transport.manifest(d);need(bytes.length===d.size&&'sha256:'+createHash('sha256').update(bytes).digest('hex')===d.digest,'ControlCompositionPublicationReadback');
  }
  recordProductionControlComposition(allocation,'published',{image:built.record.image,rootDescriptor:built.record.rootDescriptor,graphHash:built.record.graphHash,
   rawReadbackManifests:published.size,observedMaterializationBytes:logical});
  return Object.freeze({version:1,kind:'native-control-composition-registry-publication',authority:false,planHash:admitted.plan.planHash,
   image:built.record.image,rootDescriptor:built.record.rootDescriptor,graphHash:built.record.graphHash});
 }catch(error){holdProductionControlComposition(allocation,error.message);throw error;}
}
