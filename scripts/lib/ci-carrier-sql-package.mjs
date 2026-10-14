/** The independently prepaid SQL fixture, never a base/output image grant.
 * Keep the upstream index intact and verify its complete selected ARM64 graph.
 * No host tar extraction, registry resolution, caller URL or cached-image trust. */
import {open,mkdtemp,lstat,realpath,rm} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {Readable} from 'node:stream';
import {createGunzip} from 'node:zlib';
import {assertCarrierConsumer} from './ci-carrier-consumer.mjs';
import {carrierSqlPackageReadBounds} from './ci-carrier-before-copy.mjs';
import {CARRIER_SQL_DATABASE_ROOT,carrierSqlDerivedProfile,assertCarrierSqlDatabasePin} from './ci-carrier-sql-acceptance-format.mjs';
import {IMAGE_MEDIA} from './production-image-graph.mjs';
import {need,sha,hash,zero,parseAcquisitionJson} from './ci-smoke-acquisition-format.mjs';

const handles=new WeakMap(),keys=['dev','ino','size','mtimeMs','ctimeMs','mode','uid','nlink'];
const unchanged=(a,b)=>keys.every(k=>a[k]===b[k]);
const text=b=>{const n=b.indexOf(0);return new TextDecoder('utf-8',{fatal:true}).decode(n<0?b:b.subarray(0,n));};
const number=b=>{const s=text(b).trim();need(/^[0-7]+$/.test(s),'CarrierPgTarNumber');const n=parseInt(s,8);need(Number.isSafeInteger(n)&&n>=0,'CarrierPgTarNumber');return n;};
const json=b=>parseAcquisitionJson(b,1048576),padded=n=>Math.ceil(n/512)*512;

// Inert framing only: no archive path is opened, no image/SQL is executed,
// and this index is unusable until the whole HTTP response is authenticated.
function archiveIndex(limit){
 const files=new Map(),names=new Set();let position=0,header=Buffer.alloc(0),remaining=0,padding=0,member,digest,zeros=0,ended=false;
 const complete=()=>{member.sha256=digest.digest('hex');if(member.name.startsWith('blobs/'))need(member.sha256===member.name.slice(13),'CarrierPgBlobHash');files.set(member.name,{offset:member.offset,size:member.size,sha256:member.sha256});member=undefined;};
 return {files,push(chunk){
  let at=0;while(at<chunk.length){
   if(ended){need(chunk.subarray(at).every(b=>b===0),'CarrierPgTarTrailing');zeros+=chunk.length-at;position+=chunk.length-at;break;}
   if(remaining){const n=Math.min(remaining,chunk.length-at);digest.update(chunk.subarray(at,at+n));at+=n;position+=n;remaining-=n;if(!remaining)complete();continue;}
   if(padding){const n=Math.min(padding,chunk.length-at);need(chunk.subarray(at,at+n).every(b=>b===0),'CarrierPgTarPadding');padding-=n;at+=n;position+=n;continue;}
   const n=Math.min(512-header.length,chunk.length-at);header=Buffer.concat([header,chunk.subarray(at,at+n)]);at+=n;position+=n;if(header.length!==512)continue;
   const h=header;header=Buffer.alloc(0);if(h.every(b=>b===0)){ended=true;continue;}
   let sum=0;for(let i=0;i<512;i++)sum+=i>=148&&i<156?32:h[i];need(sum===number(h.subarray(148,156)),'CarrierPgTarChecksum');
   const name=text(h.subarray(0,100)),size=number(h.subarray(124,136)),type=String.fromCharCode(h[156]||48);
   need(['ustar','ustar '].includes(text(h.subarray(257,263)))&&text(h.subarray(345,500))===''&&text(h.subarray(157,257))===''&&!names.has(name)&&names.size<128,'CarrierPgTarHeader');names.add(name);
   if(type==='5'){need(['blobs','blobs/','blobs/sha256','blobs/sha256/'].includes(name)&&size===0,'CarrierPgDirectoryEntry');continue;}
   need(type==='0'&&/^(?:blobs\/sha256\/[a-f0-9]{64}|index\.json|manifest\.json|oci-layout)$/.test(name)&&size>0&&position+padded(size)<=limit,'CarrierPgTarMember');
   member={name,size,offset:position};digest=createHash('sha256');remaining=size;padding=padded(size)-size;
  }
 },finish(){need(ended&&zeros>=512&&!remaining&&!padding&&header.length===0&&position===limit,'CarrierPgTarEnd');return files;}};
}

export async function materializeCarrierSqlPackage({stream,consumer,tempRoot}){
 assertCarrierConsumer(consumer);const f=consumer.admission.config.plan.template.sqlFixture;
 assertCarrierSqlDatabasePin(f);
 need(typeof tempRoot==='string'&&resolve(tempRoot)===tempRoot&&await realpath(tempRoot)===tempRoot,'CarrierPgDirectory');
 const directory=await mkdtemp(join(tempRoot,'mem9-carrier-sql-pg-')),path=join(directory,'fixture.oci.tar');
 const fd=await open(path,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600),digest=createHash('sha256'),index=archiveIndex(f.archive.bytesLength);let count=0;
 try{
  for await(const chunk of stream){consumer.check();need(chunk instanceof Uint8Array&&(count+=chunk.length)<=f.archive.bytesLength,'CarrierPgBytes');consumer.reserveLocal({...zero(),logicalBytes:chunk.length});digest.update(chunk);index.push(chunk);let at=0;while(at<chunk.length){const r=await fd.write(chunk,at,chunk.length-at);need(r.bytesWritten>0,'CarrierPgWrite');at+=r.bytesWritten;}}
  need(count===f.archive.bytesLength&&digest.digest('hex')===f.archive.sha256,'CarrierPgHash');index.finish();await fd.sync();
 }catch(error){await fd.close();await rm(directory,{recursive:true});throw error;}
 await fd.close();const identity=await lstat(path),handle=Object.freeze({kind:'carrier-sql-package'});
 handles.set(handle,{consumer,f,directory,path,identity,files:index.files,io:{archiveReceivedBytes:count,archiveWriteBytes:count,verificationReadBytes:0,decodedBytes:0},verified:false,consumed:false,closed:false});return handle;
}
function state(handle,consumer){const s=handles.get(handle);need(s&&!s.closed&&s.consumer===consumer,'CarrierPgHandle');assertCarrierConsumer(consumer);return s;}
async function current(s){s.consumer.check();need(await realpath(s.path)===s.path&&unchanged(s.identity,await lstat(s.path))&&s.identity.isFile()&&s.identity.uid===process.getuid()&&(s.identity.mode&511)===0o600&&s.identity.nlink===1,'CarrierPgChanged');}

export async function verifyCarrierSqlPackage(handle,{consumer}){
 const s=state(handle,consumer);need(!s.verified&&!s.consumed,'CarrierPgSpent');await current(s);
 // Download completion (including S3 custody and raw hash) precedes semantic
 // verification and any use of the index assembled during the download.
 need(consumer.inspect().used.fixtureGet===1&&consumer.inspect().events.at(-1)?.type==='complete','CarrierPgDownloadIncomplete');
 const fd=await open(s.path,constants.O_RDONLY|constants.O_NOFOLLOW),files=s.files,f=s.f,bounds=carrierSqlPackageReadBounds(f);let readBytes=0,layerReadBytes=0,metadataReadBytes=0;
 const read=async(at,n,layer=false)=>{need(Number.isSafeInteger(n)&&n>=0&&n<=1048576&&at+n<=f.archive.bytesLength,'CarrierPgRead');need(layer?layerReadBytes+n<=bounds.compressedLayerBytes:metadataReadBytes+n<=bounds.metadataReadBytes,'CarrierPgReadBudget');consumer.check();consumer.reserveLocal({...zero(),logicalBytes:n});readBytes+=n;if(layer)layerReadBytes+=n;else metadataReadBytes+=n;const b=Buffer.alloc(n);let p=0;while(p<n){const r=await fd.read(b,p,n-p,at+p);need(r.bytesRead>0,'CarrierPgTruncated');p+=r.bytesRead;}return b;};
 async function* bytes(row){let at=0;const digest=createHash('sha256');while(at<row.size){const b=await read(row.offset+at,Math.min(65536,row.size-at),true);at+=b.length;digest.update(b);yield b;}need(digest.digest('hex')===row.sha256,'CarrierPgStoredBlobHash');}
 const body=async name=>{const r=files.get(name);need(r&&r.size<=1048576,'CarrierPgMetadata');const bytes=await read(r.offset,r.size);need(sha(bytes)===r.sha256,'CarrierPgStoredMetadataHash');return bytes;};
 try{
  const layout=json(await body('oci-layout')),index=json(await body('index.json'));
  need(layout.imageLayoutVersion==='1.0.0'&&index.schemaVersion===2&&index.manifests?.length===1&&index.manifests[0].digest===f.rootDigest,'CarrierPgIndex');
  const root=json(await body('blobs/sha256/'+f.rootDigest.slice(7)));need(root.mediaType===IMAGE_MEDIA.index&&root.schemaVersion===2&&Array.isArray(root.manifests)&&root.manifests.length<=16,'CarrierPgIndex');
  const selected=root.manifests.filter(d=>d.platform?.os==='linux'&&d.platform.architecture==='arm64'),att=root.manifests.filter(d=>d.annotations?.['vnd.docker.reference.digest']===f.arm64Digest);
  need(selected.length===1&&selected[0].digest===f.arm64Digest&&att.length===1&&att[0].digest===f.attestationDigest&&att[0].annotations['vnd.docker.reference.type']==='attestation-manifest','CarrierPgSelection');
  const nodes=new Map(),manifests=new Map();
  const visit=async d=>{
   need(typeof d?.digest==='string'&&/^sha256:[a-f0-9]{64}$/.test(d.digest)&&Number.isSafeInteger(d.size)&&d.size>0,'CarrierPgDescriptor');const row=files.get('blobs/sha256/'+d.digest.slice(7));need(row?.size===d.size,'CarrierPgDescriptor');
   if(nodes.has(d.digest)){need(hash(nodes.get(d.digest))===hash(d),'CarrierPgDescriptor');return;}nodes.set(d.digest,d);
   if(d.mediaType===IMAGE_MEDIA.manifest){const m=json(await body('blobs/sha256/'+d.digest.slice(7)));need(m.schemaVersion===2&&m.mediaType===d.mediaType&&Array.isArray(m.layers)&&m.layers.length<=64,'CarrierPgManifest');manifests.set(d.digest,m);for(const child of [m.config,...m.layers])await visit(child);}
  };await visit(selected[0]);await visit(att[0]);
  // No unselected platform bytes or unexplained extra payloads are imported.
  const expected=new Set([...nodes.keys(),f.rootDigest].map(d=>'blobs/sha256/'+d.slice(7)));for(const name of files.keys())if(name.startsWith('blobs/'))need(expected.has(name),'CarrierPgExtraBlob');
  const main=manifests.get(f.arm64Digest),evidence=manifests.get(f.attestationDigest);need(main.config.digest===f.configDigest,'CarrierPgConfig');const config=json(await body('blobs/sha256/'+f.configDigest.slice(7)));
  need(config.os==='linux'&&config.architecture==='arm64'&&config.rootfs?.type==='layers'&&config.rootfs.diff_ids?.length===main.layers.length,'CarrierPgConfig');
  for(const d of evidence.layers){need(d.mediaType===IMAGE_MEDIA.attestation,'CarrierPgAttestation');const payload=json(await body('blobs/sha256/'+d.digest.slice(7)));need(['https://in-toto.io/Statement/v0.1','https://in-toto.io/Statement/v1'].includes(payload._type)&&payload.subject?.length>0&&payload.subject.every(v=>v.digest?.sha256===f.arm64Digest.slice(7)),'CarrierPgAttestation');
   const derived=carrierSqlDerivedProfile(f.rootDigest);if(derived)need(evidence.layers.length===1&&payload.predicateType===(derived.jit==='off'?'urn:mem9:carrier-sql:offline-prune-nojit:v1':'urn:mem9:carrier-sql:offline-prune:v1')&&hash(payload.predicate)===derived.provenanceHash&&payload.predicate.sourceRootDigest===CARRIER_SQL_DATABASE_ROOT&&payload.predicate.recipeSha256===derived.recipeHash,'CarrierPgDerivation');
  }
  const docker=json(await body('manifest.json'));need(docker.length===1&&docker[0].Config==='blobs/sha256/'+f.configDigest.slice(7)&&hash(docker[0].Layers)===hash(main.layers.map(d=>'blobs/sha256/'+d.digest.slice(7)))&&(!docker[0].RepoTags||docker[0].RepoTags.length===0),'CarrierPgDockerManifest');
  let unpacked=0,entries=0;
  for(const [i,d]of main.layers.entries()){
   need([IMAGE_MEDIA.gzip,IMAGE_MEDIA.dockerGzip,IMAGE_MEDIA.tar].includes(d.mediaType),'CarrierPgLayer');const input=Readable.from(bytes(files.get('blobs/sha256/'+d.digest.slice(7)))),output=d.mediaType===IMAGE_MEDIA.tar?input:createGunzip({chunkSize:65536}),digest=createHash('sha256');
   if(output!==input){input.on('error',e=>output.destroy(e));output.on('error',e=>input.destroy(e));input.pipe(output);}let header=Buffer.alloc(0),remaining=0;
   try{for await(const b of output){consumer.check();consumer.reserveLocal({...zero(),uncompressedBytes:b.length});unpacked+=b.length;need(unpacked<=f.uncompressedBytes,'CarrierPgUncompressed');digest.update(b);let at=0;
    while(at<b.length){if(remaining){const n=Math.min(remaining,b.length-at);remaining-=n;at+=n;continue;}const n=Math.min(512-header.length,b.length-at);header=Buffer.concat([header,b.subarray(at,at+n)]);at+=n;if(header.length===512){if(!header.every(v=>v===0)){need(++entries<=f.processedEntries,'CarrierPgEntries');consumer.reserveLocal({...zero(),processedEntries:1});remaining=padded(number(header.subarray(124,136)));}header=Buffer.alloc(0);}}
   }need(header.length===0&&remaining===0&&'sha256:'+digest.digest('hex')===config.rootfs.diff_ids[i],'CarrierPgDiffId');}finally{input.destroy();output.destroy();}
  }
  need(unpacked===f.uncompressedBytes,'CarrierPgUncompressed');await current(s);Object.assign(s.io,{verificationReadBytes:readBytes,layerReadBytes,metadataReadBytes,decodedBytes:unpacked});s.verified=true;s.diffIds=Object.freeze([...config.rootfs.diff_ids]);s.receipt=Object.freeze({archive:f.archive,rootDigest:f.rootDigest,arm64Digest:f.arm64Digest,configDigest:f.configDigest,attestationDigest:f.attestationDigest,uncompressedBytes:unpacked,processedEntries:entries});return s.receipt;
 }finally{await fd.close();}
}
export async function consumeCarrierSqlPackage(handle,{consumer}){const s=state(handle,consumer);need(s.verified&&!s.consumed,'CarrierPgNotVerified');await current(s);s.consumed=true;return Object.freeze({path:s.path,directory:s.directory,receipt:s.receipt,diffIds:s.diffIds,check:()=>current(s)});}
export function inspectCarrierSqlPackageIo(handle,{consumer}){const s=state(handle,consumer);need(s.verified,'CarrierPgNotVerified');return Object.freeze({...s.io});}
export async function closeCarrierSqlPackage(handle,{consumer}){const s=handles.get(handle);need(s&&s.consumer===consumer,'CarrierPgHandle');if(s.closed)return;s.closed=true;await rm(s.directory,{recursive:true});}
