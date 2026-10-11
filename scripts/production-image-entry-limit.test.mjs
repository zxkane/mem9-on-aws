import {test,onTestFinished} from 'vitest';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {gzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {IMAGE_MEDIA,createPrepaidControlCacheBudget,readCollectedControlImageCache} from './lib/production-image-graph.mjs';
import {inspectImageFilesystem,inspectImageFilesystemEntries,readImageFilesystemFile,assertImageFilesystemEntryLimit} from './lib/production-image-filesystem.mjs';
import {IMAGE_TRANSITION_LIMITS as L} from './lib/production-image-transition.mjs';
import {tar} from './production-image.fixture.mjs';
import {FUTURE_CONTROL_CAPACITY} from './lib/production-control-capacity.mjs';
const zero=()=>({ecrRequests:0,logicalBytes:0,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0});
const digest=b=>'sha256:'+createHash('sha256').update(b).digest('hex');
async function fixture({layers,limit,payerEntries=300000,priorEntries=7}){
 const directory=await mkdtemp(join(tmpdir(),'carrier-entry-bound-')),cacheDirectory=join(directory,'cache');await mkdir(cacheDirectory,{mode:0o700});
 let verified,closed=false;
 onTestFinished(async()=>{try{if(!closed)await verified?.cache.close();}finally{await rm(directory,{recursive:true,force:true});}});
 const data=new Map(),put=(bytes,mediaType)=>{bytes=Buffer.isBuffer(bytes)?bytes:Buffer.from(JSON.stringify(bytes));const d={mediaType,digest:digest(bytes),size:bytes.length};data.set(d.digest,{d,bytes});return d;};
 const encoded=layers.map(raw=>put(gzipSync(raw),IMAGE_MEDIA.gzip));
 const config=put({os:'linux',architecture:'arm64',rootfs:{type:'layers',diff_ids:layers.map(digest)}},IMAGE_MEDIA.config);
 const arm=put({schemaVersion:2,mediaType:IMAGE_MEDIA.manifest,config,layers:encoded},IMAGE_MEDIA.manifest);
 const root=put({schemaVersion:2,mediaType:IMAGE_MEDIA.index,manifests:[{...arm,platform:{os:'linux',architecture:'arm64'}}]},IMAGE_MEDIA.index);
 for(const {d,bytes}of data.values())await writeFile(join(cacheDirectory,d.digest.slice(7)),bytes,{mode:0o600});
 const spent={...zero(),processedEntries:priorEntries},charges=[];
 const metadataReads={reserveLocal(c){assert.equal(c.ecrRequests,0);assert.equal(c.httpBodyBytes,0);if(spent.processedEntries+c.processedEntries>payerEntries)throw Error('SyntheticOriginalPayerEntries');for(const key of Object.keys(spent)){assert(Number.isSafeInteger(c[key])&&c[key]>=0);spent[key]+=c[key];}if(c.processedEntries)charges.push(c);}};
 const budget=createPrepaidControlCacheBudget({metadataReads,uncompressedBytesLimit:1073741824,...(limit===undefined?{}:{processedEntriesLimit:limit})});
 const binding={account:'123456789012',region:'ap-northeast-1',repositoryName:'mem9-on-aws/preview/bootstrap',root,arm64Digest:arm.digest,configDigest:config.digest};
 verified=await readCollectedControlImageCache(binding,{directory:cacheDirectory,nodes:[...data.values()].map(r=>r.d),budget,metadataReads});
 return {...verified,directory,cacheDirectory,budget,spent,charges,priorEntries,close:async()=>{await verified.cache.close();closed=true;}};
}
const rejectAndClose=async(f,count,code='ImageFilesystemEntryLimit')=>{
 await assert.rejects(inspectImageFilesystem(f.graph,{component:'bootstrap'}),{message:code});
 assert.equal(f.budget.usage().fsEntries,count);assert.equal(f.spent.processedEntries,f.priorEntries+count);assert.equal(f.charges.length,count);
 await f.close();assert.equal(f.budget.usage().active,0);await rm(f.cacheDirectory,{recursive:true});assert.deepEqual(await readdir(f.directory),[]);
};
test('four actual headers reject at limit three while original payer still has capacity',async()=>{
 const f=await fixture({layers:[tar(['a','b','c','d'].map(path=>({path,body:''})))],limit:3});await rejectAndClose(f,3);
});
test('exact three-entry boundary succeeds; independent full recheck debits original counters again',async()=>{
 const raw=tar(['a','b','c'].map(path=>({path,body:'same'}))),f=await fixture({layers:[raw],limit:3});
 for(let i=0;i<2;i++){const fs=await inspectImageFilesystem(f.graph,{component:'bootstrap'});assert.equal(assertImageFilesystemEntryLimit(fs,3),3);assert.throws(()=>assertImageFilesystemEntryLimit(fs,2),/ImageFilesystemEntryLimit/);assert.equal(inspectImageFilesystemEntries(fs).length,3);}
 assert.equal(f.budget.usage().fsEntries,6);assert.equal(f.spent.processedEntries,f.priorEntries+6);await f.close();
});
test('original cumulative payer exhaustion is still authoritative before scoped counter advances',async()=>{
 const f=await fixture({layers:[tar(['a','b','c'].map(path=>({path,body:''})))],limit:10,payerEntries:9,priorEntries:7});await rejectAndClose(f,2,'SyntheticOriginalPayerEntries');assert.throws(()=>f.budget.entry(),/ControlCacheBudgetHeld/);
});
test('overwrites and repeated layer occurrences count even though final filesystem has one file',async()=>{
 const raw=tar([{path:'same',body:''}]),f=await fixture({layers:[raw,raw,raw],limit:2});await rejectAndClose(f,2);
 const g=await fixture({layers:[raw,raw],limit:2}),fs=await inspectImageFilesystem(g.graph,{component:'bootstrap'});assert.equal(inspectImageFilesystemEntries(fs).length,1);assert.equal(assertImageFilesystemEntryLimit(fs,2),2);await g.close();
});
test('implicit parent directories use the same entry guard before each map insertion',async()=>{
 const raw=tar([{path:'parent/child/file',body:'data'}]),f=await fixture({layers:[raw],limit:2});await rejectAndClose(f,2);
 const g=await fixture({layers:[raw],limit:3}),fs=await inspectImageFilesystem(g.graph,{component:'bootstrap'});assert.equal(assertImageFilesystemEntryLimit(fs,3),3);assert.equal(inspectImageFilesystemEntries(fs).length,3);await g.close();
});
function pax(key,value){let n=key.length+value.length+4;for(;;){const text=n+' '+key+'='+value+'\n';if(Buffer.byteLength(text)===n)return text;n=Buffer.byteLength(text);}}
test('PAX and GNU extension headers count without dropping metadata',async()=>{
 for(const [type,body]of [['x',pax('comment','preserved')],['L','long-name\0']]){
  const raw=tar([{path:'extension',type,body},{path:'file',body:'content'}]);
  const f=await fixture({layers:[raw],limit:1});await rejectAndClose(f,1);
  const g=await fixture({layers:[raw],limit:2}),fs=await inspectImageFilesystem(g.graph,{component:'bootstrap'}),rows=inspectImageFilesystemEntries(fs);
  assert.equal(assertImageFilesystemEntryLimit(fs,2),2);assert.equal(rows.length,1);if(type==='x')assert.equal(rows[0].pax.comment,'preserved');else assert.equal(rows[0].path,'long-name');await g.close();
 }
});
test('whiteouts count and deleted entries never refund the original payer',async()=>{
 const raw=tar([{path:'old',body:''},{path:'.wh.old',body:''},{path:'new',body:''}]),f=await fixture({layers:[raw],limit:2});await rejectAndClose(f,2);
});
test('the exact production-sized 50000 entry boundary rejects 50001 with tiny compressed data',async()=>{
 const one=tar([{path:'same',body:''}]).subarray(0,512),raw=Buffer.concat([...Array(50001).fill(one),Buffer.alloc(1024)]);
 const f=await fixture({layers:[raw],limit:50000});await rejectAndClose(f,50000);
},15000);
test('entry failure occurs before interpreting an excess malformed header',async()=>{
 const raw=tar([{path:'a',body:''},{path:'b',body:''}]);raw[512]=255;
 const f=await fixture({layers:[raw],limit:1});await rejectAndClose(f,1);
 const g=await fixture({layers:[raw],limit:2});await rejectAndClose(g,2,'ImageTarChecksum');
});
test('later file byte rereads remain paid and do not invent new tar entry admissions',async()=>{
 const raw=tar([{path:'file',body:'retained'}]),f=await fixture({layers:[raw],limit:1}),fs=await inspectImageFilesystem(f.graph,{component:'bootstrap'});
 const before=f.budget.usage();assert.equal((await readImageFilesystemFile(fs,'/file')).toString(),'retained');const after=f.budget.usage();
 assert.equal(after.fsEntries,before.fsEntries);assert.equal(after.uncompressedBytes,before.uncompressedBytes+raw.length);assert(after.logicalBytes>before.logicalBytes);assert.equal(assertImageFilesystemEntryLimit(fs,1),1);
 assert.throws(()=>assertImageFilesystemEntryLimit(JSON.parse(JSON.stringify(fs)),1),/ImageFilesystemContextRequired/);await f.close();
});
test('invalid bounds fail before debit; global cap remains the maximum',()=>{
 for(const processedEntriesLimit of [0,-1,1.5,null,'3',Infinity,NaN,Number.MAX_SAFE_INTEGER+1]){let calls=0;assert.throws(()=>createPrepaidControlCacheBudget({metadataReads:{reserveLocal(){calls++;}},processedEntriesLimit}),/ControlCacheProcessedEntriesLimit/);assert.equal(calls,0);}
 const budget=createPrepaidControlCacheBudget({metadataReads:{reserveLocal(){}},processedEntriesLimit:Number.MAX_SAFE_INTEGER});assert.equal(budget.processedEntriesLimit,L.maxFsEntries);
 const constrained=createPrepaidControlCacheBudget({metadataReads:{reserveLocal(){},controlCapacity:FUTURE_CONTROL_CAPACITY},processedEntriesLimit:Number.MAX_SAFE_INTEGER});assert.equal(constrained.processedEntriesLimit,Math.min(L.maxFsEntries,FUTURE_CONTROL_CAPACITY.processedEntries));
});
test('legacy omission preserves budget shape and existing cumulative charging',async()=>{
 const f=await fixture({layers:[tar(['a','b','c','d'].map(path=>({path,body:''})))]}),fs=await inspectImageFilesystem(f.graph,{component:'bootstrap'});
 assert.equal(Object.hasOwn(f.budget,'processedEntriesLimit'),false);assert.equal(f.budget.usage().fsEntries,4);assert.equal(f.spent.processedEntries,f.priorEntries+4);assert.equal(inspectImageFilesystemEntries(fs).length,4);await f.close();
});
