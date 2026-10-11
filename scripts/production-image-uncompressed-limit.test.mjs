import {test} from 'vitest';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {gzipSync,zstdCompressSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {IMAGE_MEDIA,createPrepaidControlCacheBudget,readCollectedControlImageCache} from './lib/production-image-graph.mjs';
import {inspectImageFilesystem,inspectImageFilesystemEntries,readImageFilesystemFile,assertImageFilesystemUncompressedLimit} from './lib/production-image-filesystem.mjs';
import {IMAGE_TRANSITION_LIMITS as L} from './lib/production-image-transition.mjs';
import {tar} from './production-image.fixture.mjs';
const zero=()=>({ecrRequests:0,logicalBytes:0,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0});
const digest=b=>'sha256:'+createHash('sha256').update(b).digest('hex');
async function fixture(t,{layers,encoding='tar',limit}){
 const directory=await mkdtemp(join(tmpdir(),'carrier-u-'));t.onTestFinished(()=>rm(directory,{force:true,recursive:true}));
 const cache=join(directory,'cache');await mkdir(cache,{mode:0o700});const data=new Map(),put=(bytes,mediaType)=>{bytes=Buffer.isBuffer(bytes)?bytes:Buffer.from(JSON.stringify(bytes));const d={mediaType,digest:digest(bytes),size:bytes.length};data.set(d.digest,{d,bytes});return d;};
 const media=IMAGE_MEDIA[encoding],encoded=layers.map(raw=>put(encoding==='gzip'?gzipSync(raw):encoding==='zstd'?zstdCompressSync(raw):raw,media));
 const config=put({os:'linux',architecture:'arm64',rootfs:{type:'layers',diff_ids:layers.map(digest)}},IMAGE_MEDIA.config);
 const arm=put({schemaVersion:2,mediaType:IMAGE_MEDIA.manifest,config,layers:encoded},IMAGE_MEDIA.manifest);
 const root=put({schemaVersion:2,mediaType:IMAGE_MEDIA.index,manifests:[{...arm,platform:{os:'linux',architecture:'arm64'}}]},IMAGE_MEDIA.index);
 for(const {d,bytes}of data.values())await writeFile(join(cache,d.digest.slice(7)),bytes,{mode:0o600});
 const spent=zero(),original={logicalBytes:173,uncompressedBytes:71,processedEntries:3};Object.assign(spent,original);
 const metadataReads={reserveLocal(c){for(const key of Object.keys(spent)){assert(Number.isSafeInteger(c[key])&&c[key]>=0);spent[key]+=c[key];}}};
 const budget=createPrepaidControlCacheBudget({metadataReads,...(limit===undefined?{}:{uncompressedBytesLimit:limit})});
 const binding={account:'123456789012',region:'ap-northeast-1',repositoryName:'mem9-on-aws/preview/bootstrap',root,arm64Digest:arm.digest,configDigest:config.digest};
 const verified=await readCollectedControlImageCache(binding,{directory:cache,nodes:[...data.values()].map(r=>r.d),budget,metadataReads});
 let closed=false;t.onTestFinished(async()=>{if(!closed)await verified.cache.close();});
 return {directory,cacheDirectory:cache,...verified,budget,spent,original,close:async()=>{await verified.cache.close();closed=true;},metadataReads};
}
for(const encoding of ['tar','gzip','zstd'])test(`${encoding}: actual oversized layer is rejected before an out-of-bound byte is charged or parsed; owned descriptors close`,async t=>{
 const raw=tar([{path:'too-large',body:Buffer.alloc(2*1024*1024,42)}]);const cap=65536;
 const f=await fixture(t,{layers:[raw],encoding,limit:cap});
 await assert.rejects(inspectImageFilesystem(f.graph,{component:'bootstrap'}),{message:'ImageUncompressedLimit'});
 assert(f.budget.usage().uncompressedBytes<=cap);assert.equal(f.spent.uncompressedBytes,f.original.uncompressedBytes+f.budget.usage().uncompressedBytes);
 assert(f.budget.usage().fsEntries<=1);await f.close();assert.equal(f.budget.usage().active,0);
 await rm(f.cacheDirectory,{recursive:true});assert.deepEqual(await readdir(f.directory),[]);
});
test('cumulative layers, repeated layer occurrences and tar trailing zeros all count against the one filesystem U',async t=>{
 const raw=tar([{path:'one',body:'one'}]);const f=await fixture(t,{layers:[raw,raw],encoding:'gzip',limit:raw.length});
 await assert.rejects(inspectImageFilesystem(f.graph,{component:'bootstrap'}),{message:'ImageUncompressedLimit'});await f.close();assert(f.budget.usage().uncompressedBytes<=raw.length);
 const padded=Buffer.concat([raw,Buffer.alloc(65536)]),g=await fixture(t,{layers:[padded],encoding:'gzip',limit:raw.length});
 await assert.rejects(inspectImageFilesystem(g.graph,{component:'bootstrap'}),{message:'ImageUncompressedLimit'});await g.close();
});
test('exact complete U succeeds and later file rereads remain charged to original cumulative counters',async t=>{
 const raw=tar([{path:'hello',body:'original'}]),f=await fixture(t,{layers:[raw],encoding:'gzip',limit:raw.length});
 const fs=await inspectImageFilesystem(f.graph,{component:'bootstrap'});assert.equal(inspectImageFilesystemEntries(fs).length,1);
 assert.throws(()=>assertImageFilesystemUncompressedLimit(fs,raw.length-1),/ImageUncompressedLimit/);
 assert.throws(()=>assertImageFilesystemUncompressedLimit(JSON.parse(JSON.stringify(fs)),raw.length),/ImageFilesystemContextRequired/);
 for(let i=0;i<2;i++)assert.equal((await readImageFilesystemFile(fs,'/hello')).toString(),'original');
 assert.equal(assertImageFilesystemUncompressedLimit(fs,raw.length),raw.length);
 assert.equal(f.budget.usage().uncompressedBytes,3*raw.length);assert.equal(f.spent.uncompressedBytes,f.original.uncompressedBytes+3*raw.length);await f.close();
});
test('invalid allocation limits fail before any local debit; a larger bound cannot increase the global ceiling',()=>{
 for(const uncompressedBytesLimit of [0,-1,1.5,Infinity,NaN,'1024',null,Number.MAX_SAFE_INTEGER+1]){
  let debits=0;assert.throws(()=>createPrepaidControlCacheBudget({metadataReads:{reserveLocal(){debits++;}},uncompressedBytesLimit}),/ControlCacheUncompressedLimit/);assert.equal(debits,0);
 }
 const budget=createPrepaidControlCacheBudget({metadataReads:{reserveLocal(){}},uncompressedBytesLimit:Number.MAX_SAFE_INTEGER});assert.equal(budget.uncompressedBytesLimit,L.maxUncompressedBytes);
});
test('legacy budget without the optional U retains ordinary full filesystem and reread accounting',async t=>{
 const raw=tar([{path:'hello',body:'legacy'}]),f=await fixture(t,{layers:[raw]});const fs=await inspectImageFilesystem(f.graph,{component:'bootstrap'});
 assert.equal((await readImageFilesystemFile(fs,'/hello')).toString(),'legacy');assert.equal(f.budget.uncompressedBytesLimit,undefined);assert.equal(f.budget.usage().uncompressedBytes,2*raw.length);await f.close();
});
