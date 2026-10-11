/** Optional synchronous processing on the original proof owner. These helpers
 * carry no provider, reservation, proof, or completion authority. Legacy calls
 * without work retain their original validators and encodings. */
import {types} from 'node:util';
import {X509Certificate} from 'node:crypto';
const need=(v,c='DescriptorProcessing')=>{if(!v)throw Error(c);};
const nat=n=>Number.isSafeInteger(n)&&n>=0;
const MAX=33554432,MAX_NODES=1000000;
export const DESCRIPTOR_CERTIFICATE_BYTES=16384;
export const DESCRIPTOR_CERTIFICATE_OPERATION_LOCAL=16*DESCRIPTOR_CERTIFICATE_BYTES+32*DESCRIPTOR_CERTIFICATE_BYTES;
const certCounts=Object.freeze({parse:1,selfIssued:1,selfVerify:2,subject:1,pem:1,raw:1,host:1,ip:1});
const exact=(v,keys)=>need(v&&Object.keys(v).sort().join()===keys.toSorted().join(),'DescriptorProcessingFields');
export function descriptorProcessingRow(v){
 let n;
 if(v.kind==='descriptor-sizing'){
  exact(v,['kind','visits','utf16Units']);need(nat(v.visits)&&nat(v.utf16Units));n=32*v.visits+8*v.utf16Units;
 }else if(v.kind==='descriptor-guard'){
  exact(v,['kind','bytesLength','nodes']);need(nat(v.bytesLength)&&v.bytesLength<=MAX&&nat(v.nodes)&&v.nodes<=MAX_NODES);n=16*v.bytesLength+32*v.nodes;
 }else if(v.kind==='descriptor-json'){
  exact(v,['kind','bytesLength','nodeLimit']);need(nat(v.bytesLength)&&v.bytesLength<=MAX&&[100000,250000,MAX].includes(v.nodeLimit));n=8*v.bytesLength+32*Math.min(v.nodeLimit,v.bytesLength);
 }else if(v.kind==='descriptor-bytes'){
  exact(v,['kind','bytesLength']);need(nat(v.bytesLength)&&v.bytesLength<=4*MAX);n=4*v.bytesLength;
 }else if(v.kind==='descriptor-path-scan'){
  exact(v,['kind','entries','pathUnits']);need(nat(v.entries)&&v.entries<=100000&&nat(v.pathUnits)&&v.pathUnits<=MAX);n=32*v.entries+8*v.entries*v.pathUnits;
 }else if(v.kind==='descriptor-split'){
  exact(v,['kind','utf16Units']);need(nat(v.utf16Units)&&v.utf16Units<=MAX);n=8*v.utf16Units+32*(v.utf16Units+1);
 }else if(v.kind==='descriptor-certificate'){
  exact(v,['kind','operation','certificateBytes']);need(Object.hasOwn(certCounts,v.operation)&&nat(v.certificateBytes)&&v.certificateBytes>0&&v.certificateBytes<=DESCRIPTOR_CERTIFICATE_BYTES);n=certCounts[v.operation]*DESCRIPTOR_CERTIFICATE_OPERATION_LOCAL;
 }else need(false,'DescriptorProcessingKind');
 need(nat(n),'DescriptorProcessingOverflow');return Object.freeze({...v,logicalBytes:n});
}
const owners=new WeakMap(),certificates=new WeakMap();
export function createDescriptorProcessing({check,charge}){
 need(typeof check==='function'&&typeof charge==='function','DescriptorOriginalProcessing');
 let failed=false;
 const current=()=>{need(!failed,'DescriptorProcessingHeld');const result=check();if(result&&typeof result.then==='function')Promise.resolve(result).catch(()=>{});need(result===undefined,'DescriptorSynchronousProcessing');};
 const pay=v=>{current();try{const result=charge(v);if(result&&typeof result.then==='function')Promise.resolve(result).catch(()=>{});need(result===undefined,'DescriptorSynchronousProcessing');current();}catch(error){failed=true;throw error;}};
 const size=value=>{
  current();let bytes=0,nodes=0;const active=new Set();
  const add=n=>{bytes+=n;need(nat(bytes)&&bytes<=MAX,'DescriptorJsonBound');};
  const string=s=>{
   pay({kind:'descriptor-sizing',visits:1,utf16Units:s.length});add(2);
   for(let i=0;i<s.length;i++){const c=s.charCodeAt(i);
    if(c===34||c===92||[8,9,10,12,13].includes(c))add(2);else if(c<32)add(6);else if(c<128)add(1);else if(c<2048)add(2);
    else if(c>=0xd800&&c<=0xdbff){const next=s.charCodeAt(i+1);if(next>=0xdc00&&next<=0xdfff){add(4);i++;}else add(6);}else if(c>=0xdc00&&c<=0xdfff)add(6);else add(3);
   }
  };
  const visit=v=>{
   pay({kind:'descriptor-sizing',visits:1,utf16Units:0});need(++nodes<=MAX_NODES,'DescriptorJsonBound');
   if(v===null){add(4);return;}if(typeof v==='boolean'){add(v?4:5);return;}if(typeof v==='string'){string(v);return;}
   if(typeof v==='number'){need(Number.isFinite(v),'DescriptorJsonValue');add(String(Object.is(v,-0)?0:v).length);return;}
   need(v&&typeof v==='object'&&!types.isProxy(v)&&!active.has(v),'DescriptorJsonValue');const array=Array.isArray(v),proto=Object.getPrototypeOf(v);need(array?proto===Array.prototype:proto===Object.prototype||proto===null,'DescriptorJsonValue');active.add(v);add(2);let count=0;
   if(array){for(let i=0;i<v.length;i++){pay({kind:'descriptor-sizing',visits:1,utf16Units:0});const d=Object.getOwnPropertyDescriptor(v,String(i));need(d&&Object.hasOwn(d,'value'),'DescriptorJsonValue');if(count++)add(1);visit(d.value);}}
   else for(const key in v){pay({kind:'descriptor-sizing',visits:1,utf16Units:key.length});if(!Object.hasOwn(v,key))continue;const d=Object.getOwnPropertyDescriptor(v,key);need(d?.enumerable&&Object.hasOwn(d,'value'),'DescriptorJsonValue');if(d.value===undefined)continue;if(count++)add(1);string(key);add(1);visit(d.value);}
   active.delete(v);
  };
  visit(value);current();return {bytesLength:bytes,nodes};
 };
 const byteLength=value=>{current();if(typeof value==='string'){pay({kind:'descriptor-sizing',visits:0,utf16Units:value.length});return Buffer.byteLength(value);}need(value instanceof Uint8Array,'DescriptorBytes');return value.byteLength;};
 const work=Object.freeze({
  check:current,
  fail(){failed=true;},
  guard(value){try{const g=size(value);pay({kind:'descriptor-guard',...g});}catch(error){failed=true;throw error;}},
  json(value,nodeLimit=MAX){const bytesLength=byteLength(value);pay({kind:'descriptor-json',bytesLength,nodeLimit});},
  bytes(value){pay({kind:'descriptor-bytes',bytesLength:byteLength(value)});},
  byteCount(bytesLength){pay({kind:'descriptor-bytes',bytesLength});},
  encode(value){const g=size(value);pay({kind:'descriptor-bytes',bytesLength:g.bytesLength});},
  pathScan(rows,path){current();need(Array.isArray(rows)&&typeof path==='string','DescriptorPathScan');pay({kind:'descriptor-path-scan',entries:rows.length,pathUnits:path.length});},
  split(value){current();need(typeof value==='string','DescriptorSplit');pay({kind:'descriptor-split',utf16Units:value.length});},
  certificate(operation,certificateBytes){pay({kind:'descriptor-certificate',operation,certificateBytes});},
 });owners.set(work,{current});return work;
}
export function requireDescriptorProcessing(work){need(owners.has(work),'DescriptorOriginalProcessing');work.check();return work;}
export function descriptorCheck(work){if(work!==undefined)requireDescriptorProcessing(work);}
export function descriptorGuard(work,...values){if(work===undefined)return;requireDescriptorProcessing(work);for(const value of values)if(value!==undefined){if(value instanceof Uint8Array)work.bytes(value);else work.guard(value);}}
export function descriptorResume(work,value){descriptorCheck(work);return value;}

/** Local lexical wrappers: actual original primitive functions are retained.
 * Every invocation is charged; no immutable-object memo or copied credit. */
export function descriptorOperations(work,base){
 if(work===undefined)return base;requireDescriptorProcessing(work);const out={...base};
 for(const key of ['hash','copyNonrootJson'])if(base[key])out[key]=value=>{work.guard(value);return base[key](value);};
 if(base.same)out.same=(a,b,...rest)=>{work.guard(a);work.guard(b);return base.same(a,b,...rest);};
 if(base.inspectNonrootRecord)out.inspectNonrootRecord=(type,value)=>{work.guard(value);if(typeof value==='string')work.json(value,MAX);return base.inspectNonrootRecord(type,value);};
 if(base.sha)out.sha=value=>{work.bytes(value);return base.sha(value);};
 // parseNonrootJson scans and JSON.parse runs before copyJson's 100000-node
 // check. Failed large inputs therefore retain the full byte-derived bound.
 if(base.parseNonrootJson)out.parseNonrootJson=(text,...rest)=>{work.json(text,MAX);return base.parseNonrootJson(text,...rest);};
 if(base.parseAcquisitionJson)out.parseAcquisitionJson=(bytes,...rest)=>{work.json(bytes,250000);return base.parseAcquisitionJson(bytes,...rest);};
 out.JSON={stringify(value,...rest){work.encode(value);return JSON.stringify(value,...rest);},parse(text,...rest){work.json(text,MAX);return JSON.parse(text,...rest);}};
 return out;
}
export function descriptorBufferFrom(work,value,encoding){
 if(work!==undefined){requireDescriptorProcessing(work);if(encoding==='base64'){need(typeof value==='string','DescriptorBase64');work.byteCount(3*Math.ceil(value.length/4));}else work.bytes(value);}
 return Buffer.from(value,encoding);
}
export function descriptorBufferByteLength(work,value,encoding){if(work!==undefined){requireDescriptorProcessing(work);work.bytes(value);}return Buffer.byteLength(value,encoding);}
export function descriptorBufferString(work,value,encoding){
 if(work!==undefined){requireDescriptorProcessing(work);need(value instanceof Uint8Array,'DescriptorBytes');work.byteCount(encoding==='base64'?4*Math.ceil(value.byteLength/3):value.byteLength);}
 return value.toString(encoding);
}
export function descriptorSplit(work,value,separator){if(work!==undefined){requireDescriptorProcessing(work);work.split(value);}return value.split(separator);}
export function descriptorPathFilter(work,rows,path){if(work!==undefined){requireDescriptorProcessing(work);work.pathScan(rows,path);}return rows.filter(row=>row.path===path);}
export function descriptorPathFind(work,rows,path){if(work!==undefined){requireDescriptorProcessing(work);work.pathScan(rows,path);}return rows.find(row=>row.path===path);}
export function descriptorCertificate(work,bytes){
 if(work!==undefined){requireDescriptorProcessing(work);need(bytes instanceof Uint8Array,'DescriptorCertificateBytes');work.certificate('parse',bytes.byteLength);}
 const result=new X509Certificate(bytes);certificates.set(result,{work,bytesLength:bytes.byteLength});return result;
}
export function descriptorCertificateOperation(work,certificate,operation,arg){
 if(work!==undefined){requireDescriptorProcessing(work);const state=certificates.get(certificate);need(state?.work===work,'DescriptorCertificateOwner');work.certificate(operation,state.bytesLength);if(arg!==undefined)work.guard(arg);}
 switch(operation){
  case 'selfIssued':return certificate.checkIssued(certificate);
  case 'selfVerify':return certificate.verify(certificate.publicKey);
  case 'subject':return certificate.subject;
  case 'pem':return certificate.toString();
  case 'raw':return certificate.raw;
  case 'host':return certificate.checkHost(arg);
  case 'ip':return certificate.checkIP(arg);
  default:throw Error('DescriptorCertificateOperation');
 }
}

/** All reads are started by this one source-owned scope, so failure still joins
 * every started promise before propagating its first error or owner closure. */
export async function descriptorJoin(work,values,read){
 descriptorGuard(work,values);let failed=false,firstError;
 const record=error=>{if(!failed){failed=true;firstError=error;}throw error;};
 const pending=values.map(value=>{try{return Promise.resolve(read(value)).catch(record);}catch(error){if(!failed){failed=true;firstError=error;}return Promise.reject(error);}});
 const settled=await Promise.allSettled(pending);
 // Inspect terminal statuses only after the whole started set joins. This is
 // cleanup of that earlier paid scope, including when its normal owner held.
 if(failed){work?.fail();throw firstError;}
 descriptorCheck(work);return settled.map(r=>r.value);
}
