/** Archive-only original-data reader. PrivateRef.path remains inert evidence;
 * no filesystem, credential, command or provider interface is imported. */
import {nonrootArchiveBindings,nonrootArchiveInventory,forkNonrootArchive,nonrootArchiveResolvers} from './production-nonroot-archive.mjs';
import {need,exact,sha,hash,json} from './production-nonroot-engineering-json.mjs';
import {types} from 'node:util';

export const OBSERVER_REPLAY_CURRENT_LOCAL=32*4096;
export function bindObserverReplayWork(work){
 exact(work,['assertCurrent','chargeLocal']);
 const check=work.assertCurrent,charge=work.chargeLocal;
 need(typeof check==='function'&&!types.isAsyncFunction(check)&&typeof charge==='function'&&!types.isAsyncFunction(charge),'ObserverReplayOriginalWork');
 const sync=(fn,...args)=>{
  const value=fn(...args);
  if(value&&typeof value.then==='function'){Promise.resolve(value).catch(()=>{});need(false,'ObserverReplaySynchronousWork');}
  need(value===undefined,'ObserverReplaySynchronousWork');
 };
 const current=()=>{need(work.assertCurrent===check&&work.chargeLocal===charge,'ObserverReplayWorkChanged');sync(check);};
 const debit=n=>{current();need(Number.isSafeInteger(n)&&n>=0,'ObserverReplayWorkOverflow');sync(charge,n);current();};
 // Forward the complete work binding into every resumed consumer. A paid
 // callback may retire its owner; its successful return is not currentness.
 current();return Object.freeze({work,check:current,current,debit});
}

export function createNonrootObserverArchiveReader(archive,work,geometry){
 const paid=bindObserverReplayWork(work);paid.debit(32768);
 exact(geometry,['reads','bytes']);
 need(Number.isSafeInteger(geometry.reads)&&geometry.reads>0&&geometry.reads<=1000000&&Number.isSafeInteger(geometry.bytes)&&geometry.bytes>0,'ObserverReplayReadGeometry');
 const limits=Object.freeze({reads:geometry.reads,bytes:geometry.bytes});
 // The original archive factory/reader authenticates its exact inventory.
 // Original caller/context checks still bind this archive to live authority.
 const binding=nonrootArchiveBindings(archive),inventory=nonrootArchiveInventory(archive);
 const scope=forkNonrootArchive(archive,{assertCurrent:paid.check});
 let reads=0,bytes=0,failed=false;
 const current=()=>{need(!failed,'ObserverReplayReaderHeld');paid.current();};
 const take=async(reference,cap=67108864)=>{
  current();
  need(reference&&typeof reference==='object'&&!types.isProxy(reference),'ObserverReplayReference');
  const digest=reference.bytesHash??reference.sha256;
  need(/^[a-f0-9]{64}$/.test(digest)&&Number.isSafeInteger(cap)&&cap>0&&cap<=67108864,'ObserverReplayReference');
  paid.debit(2*1024*(inventory.files.length+1)+32*OBSERVER_REPLAY_CURRENT_LOCAL);
  const rows=inventory.files.filter(r=>(r.ref.bytesHash??r.ref.sha256)===digest);
  need(rows.length===1,'ObserverReplayArchiveReference');const row=rows[0];
  if(reference.bytesLength!==undefined)need(reference.bytesLength===row.ref.bytesLength,'ObserverReplayReferenceSize');
  if(reference.canonicalHash!==undefined)need(row.encoding==='json'&&reference.canonicalHash===row.ref.canonicalHash,'ObserverReplayReferenceCanonical');
  need(row.ref.bytesLength<=cap&&reads<limits.reads&&bytes+row.ref.bytesLength<=limits.bytes,'ObserverReplayReadBound');
  reads++;bytes+=row.ref.bytesLength;
  // Retain full payment when an original read or any later predicate fails.
  paid.debit(64*row.ref.bytesLength+16384+OBSERVER_REPLAY_CURRENT_LOCAL);
  try{
   // resolve-by-ref never interprets a historical path, URL or owner filename.
   const resolve=nonrootArchiveResolvers(scope);
   const raw=await (row.encoding==='bytes'?resolve.resolveBytes(row.ref):resolve.resolveJson(row.ref));current();
   need(raw instanceof Uint8Array&&raw.byteLength===row.ref.bytesLength&&sha(raw)===digest,'ObserverReplayArchiveBytes');
   return raw;
  }catch(error){failed=true;throw error;}
 };
 return Object.freeze({binding,archive,scope,work,paid,current,
  readBytes:take,
  async json(reference,cap=33554432){const raw=await take(reference,cap);current();return json(raw,cap);},
  inspect(){current();return Object.freeze({reads,bytes,manifestHash:binding.manifestHash});},
  assertBinding(candidate){current();need(candidate===archive&&hash(nonrootArchiveBindings(candidate))===hash(binding),'ObserverReplayArchiveChanged');},
 });
}
