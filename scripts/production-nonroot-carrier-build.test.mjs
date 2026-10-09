import {describe,it,expect} from 'vitest';
import {readFile,mkdir,mkdtemp,writeFile,rm,readdir} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {buildCarrierOffline,inspectCarrierOfflineBuild,closeCarrierOfflineBuild,carrierBuildSourcePolicy} from './lib/production-nonroot-carrier-build.mjs';
import {materializeCarrierBuildContext} from './lib/ci-carrier-context.mjs';
import {IMAGE_MEDIA,createPrepaidControlCacheBudget,readCollectedControlImageCache} from './lib/production-image-graph.mjs';
import {inspectImageFilesystem,inspectImageFilesystemEntries} from './lib/production-image-filesystem.mjs';
import {carrierContextFixture,sha,zero} from './ci-carrier.fixture.mjs';

function nativeTar(entries){const blocks=[];for(const e of entries){const b=Buffer.from(e.body??''),h=Buffer.alloc(512),oct=(n,at,len)=>h.write(n.toString(8).padStart(len-1,'0')+'\0',at,len);h.write(e.path,0,100);oct(e.mode??0o555,100,8);oct(0,108,8);oct(0,116,8);oct(b.length,124,12);oct(0,136,12);h.fill(32,148,156);h[156]=(e.type??'0').charCodeAt(0);h.write(e.link??'',157,100);h.write('ustar\0',257,6);h.write('00',263,2);h.write([...h].reduce((a,b)=>a+b,0).toString(8).padStart(6,'0')+'\0 ',148,8);blocks.push(h,b,Buffer.alloc((512-b.length%512)%512));}blocks.push(Buffer.alloc(1024));return Buffer.concat(blocks);}
async function fixture(use){
 const tempRoot=await mkdtemp(join(tmpdir(),'carrier-build-test-')),cache=join(tempRoot,'cache'),spent=zero();await mkdir(cache,{mode:0o700});
 const metadataReads={reserveLocal(c){for(const k of Object.keys(spent)){expect(c[k]).toBeGreaterThanOrEqual(0);spent[k]+=c[k];}if(spent.logicalBytes>536870912)throw Error('SyntheticCarrierBudget');}};let base;
 try{
  const data=new Map(),put=(b,mediaType)=>{b=Buffer.isBuffer(b)?b:Buffer.from(JSON.stringify(b));const d={digest:'sha256:'+sha(b),size:b.length,mediaType};data.set(d.digest,{d,b});return d;},busybox=await readFile('/bin/busybox');
  const layer=put(nativeTar([
   ...['bin','usr','usr/local','usr/local/bin','bootstrap','bootstrap/operator','carrier'].map(path=>({path,type:'5'})),
   {path:'bin/busybox',body:busybox},...['sh','rm','chmod','find'].map(name=>({path:'bin/'+name,type:'2',link:'busybox',mode:0o777})),
   {path:'usr/local/bin/node',body:busybox},{path:'bin/setpriv',body:busybox},
   {path:'bootstrap/operator/SHOULD-BE-REMOVED',body:'stale new-image code',mode:0o444},{path:'carrier/SHOULD-BE-REMOVED',body:'stale guard',mode:0o444},
  ]),IMAGE_MEDIA.tar);
  const config=put({architecture:'arm64',os:'linux',config:{Env:['PATH=/usr/local/bin:/usr/bin:/bin']},rootfs:{type:'layers',diff_ids:[layer.digest]}},IMAGE_MEDIA.config);
  const arm=put({schemaVersion:2,mediaType:IMAGE_MEDIA.manifest,config,layers:[layer]},IMAGE_MEDIA.manifest),root=put({schemaVersion:2,mediaType:IMAGE_MEDIA.index,manifests:[{...arm,platform:{os:'linux',architecture:'arm64'}}]},IMAGE_MEDIA.index);
  for(const {d,b}of data.values())await writeFile(join(cache,d.digest.slice(7)),b,{mode:0o600});
  const binding={account:'123456789012',region:'ap-northeast-1',repositoryName:'mem9-on-aws/bootstrap',root,arm64Digest:arm.digest,configDigest:config.digest};
  const f=carrierContextFixture({baseImage:{account:binding.account,region:binding.region,repositoryName:binding.repositoryName,rootDigest:root.digest,arm64Digest:arm.digest,configDigest:config.digest},nativePins:{nodeSha256:sha(busybox),setprivSha256:sha(busybox)}});
  f.template.bounds.compressedBytes=16777216;f.template.bounds.uncompressedBytes=33554432;f.rebind();
  // Rebind the synthetic framing after changing its static test bounds.
  f.manifest.templateHash=f.plan.templateHash;const header=Buffer.from(JSON.stringify(f.manifest)),len=Buffer.alloc(4);len.writeUInt32BE(header.length);
  const bytes=Buffer.concat([Buffer.from('MEM9-CARRIER-CONTEXT-V1\n'),len,header,...f.manifest.files.map(r=>f.members.get(r.path))]);
  const {carrierHash}=await import('./lib/ci-carrier-before-copy.mjs');Object.assign(f.plan.context,{manifestHash:carrierHash(f.manifest),sha256:sha(bytes),bytesLength:bytes.length});
  const context=await materializeCarrierBuildContext({stream:(async function*(){yield bytes;})(),plan:f.plan,baseEvidence:f.baseEvidence,tempRoot,metadataReads});
  const budget=createPrepaidControlCacheBudget({metadataReads,deadlineMs:f.plan.deadlineMs});
  base=await readCollectedControlImageCache(binding,{directory:cache,nodes:[...data.values()].map(v=>v.d),budget,metadataReads});
  const filesystem=await inspectImageFilesystem(base.graph,{component:'bootstrap'});
  await use({context,baseGraph:base.graph,baseFilesystem:filesystem,metadataReads,tempRoot,spent,f});
 }finally{await base?.cache.close();await rm(tempRoot,{recursive:true,force:true});}
}
it('uses a default-deny source policy with no docker-image/http resolver',()=>{
 const f=carrierContextFixture(),p=carrierBuildSourcePolicy(f.template.base);
 expect(p.rules[0]).toEqual({action:'DENY',selector:{identifier:'*'}});
 expect(p.rules.slice(1).every(r=>r.action==='ALLOW'&&(r.selector.identifier.startsWith('local://')||r.selector.identifier.startsWith('oci-layout://')))).toBe(true);
});
it('rejects a deserialized context before inspecting Docker',async()=>{
 await expect(buildCarrierOffline({context:{kind:'carrier-materialized-context'}})).rejects.toThrow('CarrierContextHandle');
});
describe.skipIf(process.env.MEM9_CARRIER_NATIVE_TEST!=='1')('native ARM64 offline carrier build',()=>{
 it('builds from complete local OCI bytes, removes inherited carrier/operator leftovers and verifies the output graph',()=>fixture(async input=>{
  let result;try{result=await buildCarrierOffline(input);}catch(e){const m=e.operationDirectory?JSON.parse(await readFile(join(e.operationDirectory,'metadata.json'),'utf8').catch(()=>'{}')):{};const attestations=[];for(const name of await readdir(join(e.operationDirectory,'output/blobs/sha256')).catch(()=>[])){const b=await readFile(join(e.operationDirectory,'output/blobs/sha256',name));if(b.length<1048576&&b[0]===123){const doc=JSON.parse(b);if(doc.predicateType)attestations.push({_type:doc._type,subject:doc.subject});}}process.stderr.write('SYNTHETIC BUILD DIAGNOSTIC: '+JSON.stringify({stage:e.stage,code:e.failureCode,metadataKeys:Object.keys(m),root:m['containerimage.digest'],attestations,termination:e.termination})+'\n');throw e;}
  const built=inspectCarrierOfflineBuild(result);
  try{
   expect(built.record).toMatchObject({authority:false,processStopped:true,templateHash:input.f.plan.templateHash,contextHash:input.f.plan.context.sha256});
   expect(built.graph.inventory.attestations.length).toBeGreaterThan(0);
   expect(inspectImageFilesystemEntries(built.filesystem).some(e=>e.path.endsWith('SHOULD-BE-REMOVED'))).toBe(false);
   expect((await readdir(built.directory)).includes('image.tar')).toBe(false);
   expect(input.spent.ecrRequests).toBe(0);expect(input.spent.httpBodyBytes).toBe(0);
  }finally{await closeCarrierOfflineBuild(result);}
 }),180000);
});
