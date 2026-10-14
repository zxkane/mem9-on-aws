/** Original read-only observer predicates; no owner/provider creation. */
/** Complete content-addressed index DATA. Each object's absolute path is
 * derived from one bound directory and its retained SHA256, never truncated. */
import {resolve,join} from 'node:path';
import {need,exact,hash} from './production-nonroot-engineering-json.mjs';
const integer=n=>Number.isSafeInteger(n)&&n>=0;
export function observerArchiveIndexWork(records){
 need(integer(records)&&records>0,'ObserverArchiveIndexRecords');
 // JSON row {bytesLength,sha256}: <=112 bytes including its delimiter.
 // 64KiB covers the exact header, even a maximally escaped4096-byte path.
 const bytes=65536+128*records,nodes=3*records+16;
 need(Number.isSafeInteger(bytes)&&bytes<=33554432&&nodes<=1000000,'ObserverArchiveIndexBound');
 return {bytes,nodes,localBytes:128*records+65536+32*nodes};
}
export function createObserverArchiveIndex({owner,operation,directory,objects,putRecords,putBytes}){
 need(/^[a-f0-9]{32}$/.test(owner)&&/^[a-f0-9]{32}$/.test(operation),'ObserverArchiveIdentity');
 need(typeof directory==='string'&&Buffer.byteLength(directory)<=4096&&resolve(directory)===directory,'ObserverArchiveDirectory');
 need(Array.isArray(objects)&&integer(putRecords)&&integer(putBytes)&&putRecords>=objects.length,'ObserverArchiveCounts');
 const seen=new Set(),rows=[];let uniqueBytes=0;
 for(const r of objects){
  exact(r,['sha256','path','bytesLength']);need(/^[a-f0-9]{64}$/.test(r.sha256)&&!seen.has(r.sha256)&&r.path===join(directory,r.sha256)&&integer(r.bytesLength)&&r.bytesLength<=33554432,'ObserverArchiveObject');
  seen.add(r.sha256);uniqueBytes+=r.bytesLength;need(Number.isSafeInteger(uniqueBytes),'ObserverArchiveCounts');rows.push({sha256:r.sha256,bytesLength:r.bytesLength});
 }
 need(uniqueBytes<=putBytes,'ObserverArchiveCounts');
 return {version:1,kind:'original-observer-archive-index',authority:false,owner,operation,directory,objects:rows,putRecords,putBytes,uniqueBytes};
}
export function inspectObserverArchiveIndex(value,{owner,operation,directory}){
 exact(value,['version','kind','authority','owner','operation','directory','objects','putRecords','putBytes','uniqueBytes']);
 need(value.version===1&&value.kind==='original-observer-archive-index'&&value.authority===false&&value.owner===owner&&value.operation===operation&&value.directory===directory,'ObserverArchiveBinding');
 need(Array.isArray(value.objects),'ObserverArchiveObjects');
 const objects=value.objects.map(r=>{exact(r,['sha256','bytesLength']);return {...r,path:join(directory,r.sha256)};});
 const checked=createObserverArchiveIndex({owner,operation,directory,objects,putRecords:value.putRecords,putBytes:value.putBytes});
 need(hash(checked)===hash(value),'ObserverArchiveBinding');return {authority:false,objects};
}

/** Re-read every retained object, including objects not selected by a later
 * verifier. The descriptor and index do not substitute for their raw bodies. */
export async function readNonrootObserverArchiveIndex(descriptor,{reader,maximumObjects}){
 reader.current();reader.paid.debit(65536);
 need(integer(maximumObjects)&&maximumObjects>0&&maximumObjects<=1000000&&descriptor.objects<=maximumObjects,'ObserverArchiveObjectBound');
 const value=await reader.json(descriptor.index,33554432);reader.current();
 need(Array.isArray(value.objects)&&value.objects.length===descriptor.objects,'ObserverArchiveObjectCount');
 reader.paid.debit(32*descriptor.index.bytesLength+4096*(value.objects.length+1));
 const checked=inspectObserverArchiveIndex(value,descriptor);
 need(value.putRecords===descriptor.putRecords&&value.putBytes===descriptor.putBytes,'ObserverArchiveDescriptorCounts');
 const objects=new Map();
 for(const object of checked.objects){
  reader.current();need(object.sha256!==descriptor.index.sha256,'ObserverArchiveSelfIndex');
  const raw=await reader.readBytes(object,33554432);reader.current();
  need(raw.length===object.bytesLength,'ObserverArchiveObjectBytes');
  objects.set(object.sha256,Object.freeze({...object}));
 }
 reader.current();return {index:value,objects};
}
