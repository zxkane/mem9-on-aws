/** Immutable, complete packs. Archive member names are content-addressed;
 * original Git paths/ELF paths remain authenticated manifest data, never
 * extraction paths. No links, devices, extensions or second extraction. */
import {createHash} from 'node:crypto';
import {mkdir,open,lstat,unlink,rmdir,realpath} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join} from 'node:path';
import {nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {parseAcquisitionJson,freeze} from './ci-smoke-acquisition-format.mjs';
import {createControlSourceContext,controlSourceEntries,readControlSourceFile} from './production-control-source.mjs';
import {compositionNeed as need,compositionExact as exact,compositionCharge,encodeCompositionJson} from './production-control-composition.mjs';
import {requireProductionControlCompositionAllocation,reserveProductionControlComposition,recordProductionControlComposition,holdProductionControlComposition} from './production-control-composition-lifetime.mjs';
import {requireProductionControlCompositionTransport} from './production-control-composition-transport.mjs';

const handles=new WeakMap(),opened=new WeakSet(),STREAM=65536,MANIFEST=4194304;
const sha=b=>createHash('sha256').update(b).digest('hex');
const same=(a,b,code)=>need(hash(a)===hash(b),code);
const statKeys=['dev','ino','size','mode','ctimeMs','mtimeMs','nlink'];
function memberHeader(path,size){
 need(path==='manifest.json'||path==='blobs'||/^blobs\/[a-f0-9]{64}$/.test(path),'ControlCompositionPackPath');
 const b=Buffer.alloc(512),oct=(n,a,w)=>{const s=n.toString(8);need(s.length<w,'ControlCompositionPackNumber');b.write(s.padStart(w-1,'0')+'\0',a,w);};
 b.write(path);oct(path==='blobs'?0o700:0o600,100,8);oct(0,108,8);oct(0,116,8);oct(size,124,12);oct(0,136,12);
 b.fill(32,148,156);b[156]=path==='blobs'?53:48;b.write('ustar\0',257);b.write('00',263);
 b.write([...b].reduce((n,c)=>n+c,0).toString(8).padStart(6,'0')+'\0 ',148);return b;
}
function inspectManifest(value,name){
 exact(value,['version','kind','name','files',...(name==='source'?['source']:['nodeVersion','architecture'])]);
 need(value.version===1&&value.kind==='native-control-composition-pack'&&value.name===name,'ControlCompositionPackManifest');
 need(Array.isArray(value.files)&&value.files.length>0&&value.files.length<=20000,'ControlCompositionPackFiles');
 const paths=new Set(),blobs=new Map();
 for(const f of value.files){
  exact(f,['path','sha256','bytesLength',...(name==='source'?['gitMode','oid']:['mode','role'])]);
  need(typeof f.path==='string'&&Buffer.byteLength(f.path)<=4096&&!paths.has(f.path)&&/^[a-f0-9]{64}$/.test(f.sha256)&&
   Number.isSafeInteger(f.bytesLength)&&f.bytesLength>=0&&f.bytesLength<=(name==='source'?16777216:268435456),'ControlCompositionPackFile');
  if(name==='source')need(['100644','100755'].includes(f.gitMode)&&/^[a-f0-9]{40}$/.test(f.oid),'ControlCompositionPackGitFile');
  else need(['node','elf','source','data'].includes(f.role)&&[0o400,0o444,0o500,0o555,0o600,0o644,0o700,0o755].includes(f.mode)&&f.path.startsWith('/')&&!f.path.includes('\0'),'ControlCompositionPackTool');
  const prior=blobs.get(f.sha256);need(prior===undefined||prior===f.bytesLength,'ControlCompositionPackBlobConflict');
  blobs.set(f.sha256,f.bytesLength);paths.add(f.path);
 }
 same(value.files.map(f=>f.path),[...paths].sort(),'ControlCompositionPackOrder');
 if(name==='source'){
  // This reconstructs the complete Git tree, including every declared member.
  createControlSourceContext(value.source,()=>{throw Error('ControlCompositionPackNotMaterialized');});
  same(value.source.entries.map(e=>({path:e.path,gitMode:e.mode,oid:e.oid})).sort((a,b)=>a.path.localeCompare(b.path)),
   value.files.map(f=>({path:f.path,gitMode:f.gitMode,oid:f.oid})).sort((a,b)=>a.path.localeCompare(b.path)),'ControlCompositionPackCompleteTree');
 }else{
  need(/^24\.[0-9]+\.[0-9]+$/.test(value.nodeVersion)&&['x64','arm64'].includes(value.architecture)&&
   value.files.filter(f=>f.role==='node').length===1,'ControlCompositionPackNode');
 }
 return [...blobs].sort(([a],[b])=>a.localeCompare(b)).map(([sha256,bytesLength])=>({sha256,bytesLength}));
}
/** Data calculator; callers must fund bytes before invoking the encoder. */
export function describeProductionControlCompositionPack(manifest){
 const blobs=inspectManifest(manifest,manifest.name),bytes=encodeCompositionJson(manifest,MANIFEST);
 const rows=[{path:'manifest.json',bytesLength:bytes.length},{path:'blobs',bytesLength:0},...blobs.map(b=>({path:'blobs/'+b.sha256,bytesLength:b.bytesLength}))];
 const archiveBytes=1024+rows.reduce((n,r)=>n+512+Math.ceil(r.bytesLength/512)*512,0);
 return {manifest,manifestBytes:bytes,blobs,archiveBytes,uncompressedBytes:archiveBytes,processedEntries:rows.length};
}
/** Pure streaming encoder: it is deliberately not an admission or a receipt.
 * The owner adapter supplies original-paid reads and writes around iteration. */
export async function* encodeProductionControlCompositionPack(manifest,read){
 const p=describeProductionControlCompositionPack(manifest);
 yield memberHeader('manifest.json',p.manifestBytes.length);yield p.manifestBytes;
 if(p.manifestBytes.length%512)yield Buffer.alloc(512-p.manifestBytes.length%512);
 yield memberHeader('blobs',0);
 for(const d of p.blobs){
  yield memberHeader('blobs/'+d.sha256,d.bytesLength);const digest=createHash('sha256');let size=0;
  for await(const b of read(d)){
   need(b instanceof Uint8Array&&b.length<=STREAM&&size+b.length<=d.bytesLength,'ControlCompositionPackChunk');size+=b.length;digest.update(b);yield b;
  }
  need(size===d.bytesLength&&digest.digest('hex')===d.sha256,'ControlCompositionPackBlobDigest');
  if(size%512)yield Buffer.alloc(512-size%512);
 }
 yield Buffer.alloc(1024);
}
async function closeOwned(s){
 let problem;
 for(const p of [...s.files].reverse())try{await unlink(p);}catch(e){if(e.code!=='ENOENT')problem??=e;}
 for(const p of [...s.dirs].reverse())try{await rmdir(p);}catch(e){if(e.code!=='ENOENT')problem??=e;}
 s.closed=true;if(problem)throw Object.assign(Error('ControlCompositionPackCleanup'),{cause:problem});
}
export async function materializeProductionControlCompositionPacks({allocation,transport}){
 const a=requireProductionControlCompositionAllocation(allocation);requireProductionControlCompositionTransport(transport,allocation);
 need(!opened.has(allocation),'ControlCompositionPacksRepeated');opened.add(allocation);
 const s={allocation,files:[],dirs:[],closed:false,packs:{},used:compositionCharge()},limit=a.plan.parts.packingCi;
 const sourceStatOptions=a.plan.version===2?{bigint:true}:undefined,sourceStatKeys=a.plan.version===2?['dev','ino','size','mode','ctimeNs','mtimeNs','nlink']:statKeys;
 const charge=(logicalBytes,extra={})=>{
  requireProductionControlCompositionAllocation(allocation);const c=compositionCharge({logicalBytes,...extra});
  for(const k of Object.keys(s.used))need(s.used[k]+c[k]<=limit[k],'ControlCompositionPackCapacity');
  reserveProductionControlComposition(allocation,c);for(const k of Object.keys(s.used))s.used[k]+=c[k];
 };
 const write=async(fd,b)=>{let at=0;while(at<b.length){requireProductionControlCompositionAllocation(allocation);const r=await fd.write(b,at,b.length-at);need(r.bytesWritten>0,'ControlCompositionPackWrite');at+=r.bytesWritten;}};
 try{
  const root=join(a.directory,'packs');await mkdir(root,{mode:0o700});s.dirs.push(root);
  for(const name of a.plan.version===2?['source']:['tools','source']){
   const declared=a.plan.input.packs[name],path=join(root,name+'.tar');
   const fd=await open(path,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);s.files.push(path);
   let received=0;const digest=createHash('sha256');
   try{
    await transport[name==='tools'?'getTools':'getSource'](async raw=>{
     // Raw transport has its independent body bound. Split disk work into
     // fixed chunks and precharge each owned write/hash before copying it.
     for(let at=0;at<raw.length;at+=STREAM){
      const b=raw.subarray(at,at+STREAM);need(received+b.length<=declared.ref.bytesLength,'ControlCompositionPackSize');
      charge(2*b.length);digest.update(b);received+=b.length;await write(fd,b);
     }
    });
    need(received===declared.ref.bytesLength&&digest.digest('hex')===declared.ref.sha256,'ControlCompositionPackDigest');await fd.sync();
   }finally{await fd.close();}
   const dir=join(root,name);await mkdir(dir,{mode:0o700});s.dirs.push(dir);
   const input=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);let at=0,entries=0;
   const before=await input.stat();need(before.isFile()&&before.nlink===1&&before.size===declared.ref.bytesLength,'ControlCompositionPackFile');
   const read=async size=>{
    need(Number.isSafeInteger(size)&&size>=0&&size<=MANIFEST&&at+size<=declared.ref.bytesLength,'ControlCompositionPackRead');
    charge(size,{uncompressedBytes:size});const b=Buffer.alloc(size);let n=0;
    while(n<size){requireProductionControlCompositionAllocation(allocation);const r=await input.read(b,n,size-n,at+n);need(r.bytesRead>0,'ControlCompositionPackTruncated');n+=r.bytesRead;}
    at+=size;return b;
   };
   const padding=async size=>{if(size%512)need((await read(512-size%512)).every(v=>v===0),'ControlCompositionPackPadding');};
   const head=async(path,size)=>{charge(0,{processedEntries:1});entries++;need((await read(512)).equals(memberHeader(path,size)),'ControlCompositionPackHeader');};
   try{
    const h=await read(512);charge(0,{processedEntries:1});entries++;
    const rawSize=h.subarray(124,135).toString('ascii');need(/^[0-7]{11}$/.test(rawSize),'ControlCompositionPackSize');const size=parseInt(rawSize,8);
    need(size>0&&size<=MANIFEST&&h.equals(memberHeader('manifest.json',size)),'ControlCompositionPackHeader');
    const manifest=parseAcquisitionJson(await read(size),MANIFEST);await padding(size);
    const blobs=inspectManifest(manifest,name),calculated=describeProductionControlCompositionPack(manifest);
    need(calculated.archiveBytes===declared.ref.bytesLength&&calculated.uncompressedBytes===declared.uncompressedBytes&&calculated.processedEntries===declared.processedEntries,'ControlCompositionPackDeclaredGeometry');
    if(name==='source')need(manifest.source.tree===a.plan.input.source.candidateTree,'ControlCompositionPackSourceTree');
    await head('blobs',0);const members=new Map();
    for(const d of blobs){
     await head('blobs/'+d.sha256,d.bytesLength);const target=join(dir,d.sha256);
     const out=await open(target,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);s.files.push(target);
     const hash=createHash('sha256');let n=0;
     try{while(n<d.bytesLength){const size=Math.min(STREAM,d.bytesLength-n);charge(2*size);const b=await read(size);hash.update(b);await write(out,b);n+=size;}
      need(hash.digest('hex')===d.sha256,'ControlCompositionPackBlobDigest');await out.sync();
     }finally{await out.close();}
     await padding(n);members.set(d.sha256,{...d,path:target,stat:await lstat(target,sourceStatOptions)});
    }
    need((await read(1024)).every(v=>v===0)&&at===declared.ref.bytesLength&&entries===declared.processedEntries,'ControlCompositionPackTerminator');
    const after=await input.stat(),named=await lstat(path);need(statKeys.every(k=>before[k]===after[k]&&before[k]===named[k]),'ControlCompositionPackChanged');
    s.packs[name]={manifest:freeze(manifest),members};
   }finally{await input.close();}
  }
  const source=s.packs.source,byPath=new Map(source.manifest.files.map(f=>[f.path,f]));
  if(a.plan.version===2)need(source.manifest.files.length===a.plan.input.sourceFiles&&source.manifest.files.reduce((n,f)=>n+f.bytesLength,0)===a.plan.input.sourceBytes,'ControlCompositionSourceBytes');
  // Each consumer retains its original source-stage/read charge. This native
  // reader additionally preserves the materialized file's inode and hash.
  const readBlob=async(oid,path)=>{
   requireProductionControlCompositionAllocation(allocation);need(!s.closed,'ControlCompositionPacksClosed');
   const f=byPath.get(path);need(f?.oid===oid,'ControlCompositionPackSourceMember');const d=source.members.get(f.sha256);
   const fd=await open(d.path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
   try{
    const before=await fd.stat(sourceStatOptions);need(sourceStatKeys.every(k=>before[k]===d.stat[k]),'ControlCompositionPackChanged');
    const bytes=Buffer.alloc(f.bytesLength);let at=0;
    while(at<bytes.length){requireProductionControlCompositionAllocation(allocation);const r=await fd.read(bytes,at,bytes.length-at,at);need(r.bytesRead>0,'ControlCompositionPackTruncated');at+=r.bytesRead;}
    const after=await fd.stat(sourceStatOptions),named=await lstat(d.path,sourceStatOptions);need(sourceStatKeys.every(k=>before[k]===after[k]&&before[k]===named[k])&&sha(bytes)===f.sha256,'ControlCompositionPackChanged');return bytes;
   }finally{await fd.close();}
  };
  s.sourceContext=createControlSourceContext(source.manifest.source,readBlob);
  same(controlSourceEntries(s.sourceContext),source.manifest.source.entries,'ControlCompositionPackSourceEntries');
  recordProductionControlComposition(allocation,'packs-materialized',{refs:a.plan.input.packs,usage:s.used});
  const handle=Object.freeze({kind:'native-control-composition-packs'});handles.set(handle,s);return handle;
 }catch(error){holdProductionControlComposition(allocation,error.message);try{await closeOwned(s);}catch(cleanup){throw Object.assign(cleanup,{cause:error});}throw error;}
}
export function requireProductionControlCompositionPacks(handle,allocation){
 const s=handles.get(handle);need(s&&!s.closed&&s.allocation===allocation,'ControlCompositionNativePacks');requireProductionControlCompositionAllocation(allocation);
 return Object.freeze({sourceContext:s.sourceContext,...(s.packs.tools?{tools:s.packs.tools.manifest}:{}),usage:{...s.used}});
}
export async function closeProductionControlCompositionPacks(handle){const s=handles.get(handle);need(s&&!s.closed,'ControlCompositionNativePacks');await closeOwned(s);}

const PHASES=['packs','source','base','composed','published','captured'];
export async function verifyProductionControlCompositionSource(handle,allocation,phase){
 const s=handles.get(handle),a=requireProductionControlCompositionAllocation(allocation);need(s&&!s.closed&&s.allocation===allocation&&a.plan.version===2,'ControlCompositionNativePacks');
 const ordinal=s.sourcePass??0;need(PHASES[ordinal]===phase,'ControlCompositionSourceOrder');s.sourcePass=ordinal+1;
 try{
  reserveProductionControlComposition(allocation,compositionCharge({logicalBytes:a.plan.parts.source.logicalBytes/6,processedEntries:a.plan.input.sourceFiles}));
  for(const f of s.packs.source.manifest.files){const actual=await readControlSourceFile(s.sourceContext,f.path);need(actual.file.sha256===f.sha256&&actual.file.bytes===f.bytesLength,'ControlCompositionSourceChanged');}
  return Object.freeze({pass:ordinal+1,sourceBytes:a.plan.input.sourceBytes,sourceFiles:a.plan.input.sourceFiles});
 }catch(e){holdProductionControlComposition(allocation,e.message);throw e;}
}
/** Six genuine full source/tool checks in the same process. A pinned Node
 * version string is insufficient: all loaded ELF files and the executable
 * are compared to the original authenticated pack, before/after stat checks. */
export async function verifyProductionControlCompositionRuntime(handle,allocation,phase){
 const s=handles.get(handle),a=requireProductionControlCompositionAllocation(allocation);
 need(s&&!s.closed&&s.allocation===allocation,'ControlCompositionNativePacks');
 const step=s.runtimePass??0;need(PHASES[step]===phase,'ControlCompositionRuntimeOrder');s.runtimePass=step+1;
 try{
  const t=s.packs.tools.manifest,src=s.packs.source.manifest;
  const bytes=[...t.files,...src.files].reduce((n,f)=>n+f.bytesLength,0);
  need(Number.isSafeInteger(bytes)&&bytes===a.plan.input.sourceToolBytes,'ControlCompositionSourceToolBytes');
  // Logical work is consumed on failure; neither a snapshot nor another
  // phase name can repeat a successful/failed pass or recover its charge.
  reserveProductionControlComposition(allocation,compositionCharge({logicalBytes:bytes+4*65537}));
  need(process.platform==='linux'&&process.versions.node===t.nodeVersion&&process.arch===t.architecture&&
   !process.env.NODE_OPTIONS&&!process.env.LD_PRELOAD&&!process.env.LD_LIBRARY_PATH,'ControlCompositionNativeRuntime');
  const node=await realpath(process.execPath),expected=t.files.filter(f=>['node','elf'].includes(f.role));
  need(t.files.find(f=>f.role==='node').path===node,'ControlCompositionNativeNodePath');
  // The committed action is bundled with no non-builtin external imports.
  // Its executable entry bytes therefore cover the actual loaded JS/SDK code.
  const entry=await realpath(process.argv[1]);
  need(t.files.some(f=>f.role==='source'&&f.path===entry),'ControlCompositionNativeEntryPin');
  const maps=await open('/proc/self/maps',constants.O_RDONLY|constants.O_NOFOLLOW),raw=Buffer.alloc(65537);let size=0;
  try{while(size<raw.length){const r=await maps.read(raw,size,raw.length-size,null);if(!r.bytesRead)break;size+=r.bytesRead;}
   need(size<=65536,'ControlCompositionNativeMapBytes');
  }finally{await maps.close();}
  const paths=new Set([node]);
  for(const line of new TextDecoder('utf-8',{fatal:true}).decode(raw.subarray(0,size)).split('\n')){
   const m=/^[a-f0-9]+-[a-f0-9]+\s+\S+\s+\S+\s+\S+\s+\d+\s+(\/.*)$/.exec(line);if(!m)continue;
   need(!m[1].endsWith(' (deleted)'),'ControlCompositionDeletedTool');
   if(m[1]===process.execPath||/\.(?:so(?:\.[0-9.]+)?|node)$/.test(m[1]))paths.add(await realpath(m[1]));
  }
  need(paths.size<=128,'ControlCompositionNativeTools');same([...paths].sort(),expected.map(f=>f.path).sort(),'ControlCompositionNativeToolClosure');
  s.toolStats??=new Map();
  for(const f of t.files){
   requireProductionControlCompositionAllocation(allocation);need(await realpath(f.path)===f.path,'ControlCompositionToolPath');
   const fd=await open(f.path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
   try{
    const before=await fd.stat();need(before.isFile()&&before.nlink===1&&before.size===f.bytesLength&&(before.mode&0o7777)===f.mode,'ControlCompositionToolMetadata');
    const old=s.toolStats.get(f.path);if(old)need(statKeys.every(k=>old[k]===before[k]),'ControlCompositionToolChanged');
    const chunk=Buffer.alloc(Math.min(STREAM,Math.max(1,f.bytesLength))),digest=createHash('sha256');let at=0;
    while(at<f.bytesLength){requireProductionControlCompositionAllocation(allocation);const r=await fd.read(chunk,0,Math.min(chunk.length,f.bytesLength-at),at);
     need(r.bytesRead>0,'ControlCompositionToolTruncated');if(at===0&&['node','elf'].includes(f.role))need(r.bytesRead>=20&&chunk.subarray(0,4).equals(Buffer.from([127,69,76,70]))&&
      chunk[4]===2&&chunk[5]===1&&chunk.readUInt16LE(18)===(t.architecture==='arm64'?183:62),'ControlCompositionToolElf');
     digest.update(chunk.subarray(0,r.bytesRead));at+=r.bytesRead;
    }
    const after=await fd.stat(),named=await lstat(f.path);need(statKeys.every(k=>before[k]===after[k]&&before[k]===named[k])&&digest.digest('hex')===f.sha256,'ControlCompositionToolChanged');
    s.toolStats.set(f.path,before);
   }finally{await fd.close();}
  }
  for(const f of src.files){const checked=await readControlSourceFile(s.sourceContext,f.path);need(checked.file.sha256===f.sha256&&checked.file.bytes===f.bytesLength,'ControlCompositionSourceChanged');}
  recordProductionControlComposition(allocation,'runtime-checked',{phase,pass:step+1,sourceToolBytes:bytes,toolFiles:t.files.length,sourceFiles:src.files.length});
  return Object.freeze({pass:step+1,sourceToolBytes:bytes});
 }catch(e){holdProductionControlComposition(allocation,e.message);throw e;}
}
