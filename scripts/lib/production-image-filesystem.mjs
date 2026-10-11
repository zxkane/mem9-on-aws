import {createHash} from 'node:crypto';
import {Readable} from 'node:stream';
import {finished} from 'node:stream/promises';
import {createGunzip,createZstdDecompress} from 'node:zlib';
import {posix} from 'node:path';
import {IMAGE_TRANSITION_LIMITS as L,IMAGE_TRANSITION_LIMITS_HASH} from './production-image-transition.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {imageGraphState,assertImageBudget,inspectImageCopyVerification,IMAGE_MEDIA,imageFailure} from './production-image-graph.mjs';
import {inspectImageArchiveBinding} from './production-image-custody.mjs';

const verified=new WeakMap(),decoder=()=>new TextDecoder('utf-8',{fatal:true});
const need=(v,code='ImageFilesystemInvalid')=>{if(!v)imageFailure(code);};
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
const zero=b=>b.every(v=>v===0);
function text(b){const end=b.indexOf(0);return decoder().decode(end<0?b:b.subarray(0,end));}
function numeric(b,{negative=false}={}){
 let value;if(b[0]&0x80){let n=BigInt(b[0]&0x7f);for(const v of b.subarray(1))n=n*256n+BigInt(v);if(b[0]&0x40)n-=1n<<BigInt(b.length*8-1);value=Number(n);}
 else{const s=b.toString('ascii').replace(/\0.*$/s,'').trim();need(s===''||/^[0-7]+$/.test(s),'ImageTarNumber');value=s===''?0:parseInt(s,8);}
 need(Number.isSafeInteger(value)&&(negative||value>=0),'ImageTarNumber');return value;
}
function normalize(path,{link=false,base=''}={}){
 need(typeof path==='string'&&Buffer.byteLength(path)<=L.maxPathBytes&&!path.includes('\0')&&!path.includes('\\'),'ImageTarPath');
 need(link||!path.startsWith('/'),'ImageTarAbsolutePath');
 const parts=link&&!path.startsWith('/')?base.split('/').filter(Boolean):[];
 for(const part of path.split('/')){if(!part||part==='.')continue;if(part==='..'){need(link&&parts.length>0,'ImageTarEscape');parts.pop();}else parts.push(part);}
 return parts.join('/');
}
function uncompressedPass(budget){
 const limit=budget.uncompressedBytesLimit;
 return {limit,bytes:0,check(size){need(Number.isSafeInteger(size)&&size>=0&&(limit===undefined||size<=limit),'ImageUncompressedLimit');},
  add(size){this.check(this.bytes+size);budget.uncompressed(size);this.bytes+=size;}};
}
async function* unpacked(layer,diffId,readBlob,budget,pass=uncompressedPass(budget)){
 // Bound the input queue in bytes, including while a decoder is stopping.
 const source=Readable.from(readBlob(layer),{highWaterMark:65536,objectMode:false});let output=source;
 if(layer.mediaType===IMAGE_MEDIA.gzip||layer.mediaType===IMAGE_MEDIA.dockerGzip)output=createGunzip({chunkSize:65536});
 else if(layer.mediaType===IMAGE_MEDIA.zstd)output=createZstdDecompress({chunkSize:65536});
 else need(layer.mediaType===IMAGE_MEDIA.tar,'ImageFilesystemMedia');
 if(output!==source){source.on('error',e=>output.destroy(e));output.on('error',e=>source.destroy(e));source.pipe(output);}
 const sha=createHash('sha256');
 try{for await(const chunk of output){need(chunk.length<=L.maxBufferPerStreamBytes,'ImageFilesystemBuffer');pass.add(chunk.length);sha.update(chunk);yield chunk;}
  need('sha256:'+sha.digest('hex')===diffId,'ImageLayerDiffId');
 }finally{
  // Join teardown of asynchronous cache reads before the caller closes the
  // cache; destroy alone does not prove that its owned descriptors are closed.
  const stopped=[...new Set([output,source])].map(stream=>finished(stream,{cleanup:true}).catch(error=>{if(error?.code!=='ERR_STREAM_PREMATURE_CLOSE'&&error?.code!=='ABORT_ERR')throw error;}));
  output.destroy();source.destroy();await Promise.all(stopped);
 }
}
class Cursor{
 constructor(stream){this.iterator=stream[Symbol.asyncIterator]();this.buffer=Buffer.alloc(0);this.position=0;this.offset=0;this.done=false;}
 async available(){while(this.position===this.buffer.length&&!this.done){const next=await this.iterator.next();this.done=next.done;this.buffer=next.done?Buffer.alloc(0):next.value;this.position=0;}return this.buffer.length-this.position;}
 async *chunks(size){need(Number.isSafeInteger(size)&&size>=0);while(size){need(await this.available()>0,'ImageTarTruncated');const count=Math.min(size,this.buffer.length-this.position);const chunk=this.buffer.subarray(this.position,this.position+size);this.position+=count;this.offset+=count;size-=count;yield chunk;}}
 async read(size){need(size<=L.maxBufferPerStreamBytes,'ImageTarBuffer');const all=[];for await(const chunk of this.chunks(size))all.push(chunk);return Buffer.concat(all,size);}
 async skip(size){for await(const _ of this.chunks(size)){} }
 async drain({zeros=false}={}){while(await this.available()){const count=this.buffer.length-this.position;if(zeros)need(zero(this.buffer.subarray(this.position)),'ImageTarTrailingData');this.position+=count;this.offset+=count;}}
 async close(){await this.iterator.return?.();}
}
function pax(bytes){
 const result={};let at=0;
 while(at<bytes.length){const space=bytes.indexOf(32,at);need(space>at,'ImagePaxLength');const digits=bytes.subarray(at,space).toString('ascii');need(/^[1-9]\d*$/.test(digits),'ImagePaxLength');const n=Number(digits);need(Number.isSafeInteger(n)&&n>space-at+2&&at+n<=bytes.length&&bytes[at+n-1]===10,'ImagePaxLength');
  const record=decoder().decode(bytes.subarray(space+1,at+n-1)),equals=record.indexOf('=');need(equals>0,'ImagePaxRecord');const key=record.slice(0,equals),value=record.slice(equals+1);need(!Object.hasOwn(result,key),'ImagePaxDuplicate');
  need(['path','linkpath','size','mtime','atime','ctime','uid','gid','uname','gname','comment','charset'].includes(key)||/^SCHILY\.xattr\.[A-Za-z0-9_.-]+$/.test(key),'ImagePaxUnsupported');result[key]=value;at+=n;
 }return result;
}
function resolved(nodes,path,{parent=false,missing=true,onLink}={}){
 let rest=normalize(path).split('/').filter(Boolean),prefix=[],hops=0;
 while(rest.length){const part=rest.shift();prefix.push(part);const name=prefix.join('/'),node=nodes.get(name);
  if(node?.type==='symlink'&&(!parent||rest.length)){need(++hops<=L.maxVirtualLinkHops,'ImageVirtualLinkLoop');onLink?.(name,node);rest=[...normalize(node.link,{link:true,base:prefix.slice(0,-1).join('/')}).split('/').filter(Boolean),...rest];prefix=[];continue;}
  if(rest.length&&node)need(node.type==='directory','ImageVirtualParent');
  if(!node&&!missing)imageFailure('ImageVirtualLinkMissing');
 }return prefix.join('/');
}
function parents(nodes,path,layer,budget){
 const parts=path.split('/');parts.pop();let parent='';
 for(const part of parts){parent=parent?parent+'/'+part:part;const found=nodes.get(parent);if(found)need(found.type==='directory','ImageVirtualParent');else{budget.entry();nodes.set(parent,{type:'directory',layer,implicit:true});}}
}
function remove(nodes,path,{olderThan}={}){for(const [name,node]of nodes)if((name===path||name.startsWith(path+'/'))&&(olderThan===undefined||node.layer<olderThan))nodes.delete(name);}
async function applyLayer(nodes,layer,diffId,index,readBlob,budget,pass){
 const layerStart=pass.bytes,cursor=new Cursor(unpacked(layer,diffId,readBlob,budget,pass));let local={},global={},longPath,longLink;
 try{while(true){budget.check();const header=await cursor.read(512);if(zero(header)){need(zero(await cursor.read(512)),'ImageTarTerminator');need(!Object.keys(local).length&&longPath===undefined&&longLink===undefined,'ImageTarDanglingExtension');await cursor.drain({zeros:true});break;}
   budget.entry();let checksum=0;for(let i=0;i<512;i++)checksum+=i>=148&&i<156?32:header[i];need(checksum===numeric(header.subarray(148,156)),'ImageTarChecksum');
   const type=String.fromCharCode(header[156]||48),rawSize=numeric(header.subarray(124,136));need(rawSize<=L.maxUncompressedBytes,'ImageTarSize');
   const magic=text(header.subarray(257,263));need(magic===''||magic==='ustar'||magic==='ustar ','ImageTarFormat');
   if(['x','g','L','K'].includes(type)){
    pass.check(layerStart+cursor.offset+Math.ceil(rawSize/512)*512);
    need(rawSize<=L.maxBufferPerStreamBytes,'ImageTarExtensionSize');const bytes=await cursor.read(rawSize);await cursor.skip((512-rawSize%512)%512);
    if(type==='x'){need(!Object.keys(local).length,'ImagePaxDuplicateHeader');local=pax(bytes);}else if(type==='g'){const values=pax(bytes);need(!Object.hasOwn(values,'path')&&!Object.hasOwn(values,'linkpath')&&!Object.hasOwn(values,'size'),'ImagePaxGlobalPath');global={...global,...values};}
    else{const value=text(bytes);need(Buffer.byteLength(value)<=L.maxPathBytes);if(type==='L'){need(longPath===undefined);longPath=value;}else{need(longLink===undefined);longLink=value;}}continue;
   }
   const values={...global,...local};local={};const prefix=text(header.subarray(345,500));let path=values.path??longPath??(prefix?prefix+'/':'')+text(header.subarray(0,100)),link=values.linkpath??longLink??text(header.subarray(157,257));longPath=longLink=undefined;
   const size=values.size===undefined?rawSize:Number(values.size);need(Number.isSafeInteger(size)&&size>=0&&size<=L.maxUncompressedBytes&&size+budget.usage().uncompressedBytes<=L.maxUncompressedBytes,'ImageTarSize');
   // Reject an impossible advertised body before hashing or parsing it.
   pass.check(layerStart+cursor.offset+Math.ceil(size/512)*512);
   path=normalize(path);if(path===''){need(type==='5'&&size===0,'ImageTarRoot');continue;}
   path=resolved(nodes,path,{parent:true});parents(nodes,path,index,budget);
   const name=posix.basename(path),parent=posix.dirname(path)==='.'?'':posix.dirname(path);
   if(name.startsWith('.wh.')){
    need(type==='0'&&size===0,'ImageWhiteoutInvalid');if(name==='.wh..wh..opq')for(const [p,node]of nodes){if((parent===''||p.startsWith(parent+'/'))&&node.layer<index)nodes.delete(p);}
    else{const target=name.slice(4);need(target&&target!=='.'&&target!=='..','ImageWhiteoutInvalid');remove(nodes,parent?parent+'/'+target:target,{olderThan:index});}continue;
   }
   const metadata={layer:index,layerDigest:layer.digest,mode:numeric(header.subarray(100,108)),uid:numeric(header.subarray(108,116)),gid:numeric(header.subarray(116,124)),mtime:numeric(header.subarray(136,148),{negative:true}),pax:values};
   if(type==='0'){
    const offset=cursor.offset,sha=createHash('sha256');for await(const chunk of cursor.chunks(size))sha.update(chunk);await cursor.skip((512-size%512)%512);
    remove(nodes,path);nodes.set(path,{...metadata,type:'file',content:{layer: index,layerDigest:layer.digest,offset,size,sha256:sha.digest('hex')}});
   }else if(type==='5'){need(size===0,'ImageTarDirectorySize');if(nodes.get(path)?.type!=='directory')remove(nodes,path);nodes.set(path,{...metadata,type:'directory'});}
   else if(type==='2'){need(size===0&&link.length>0,'ImageTarLink');normalize(link,{link:true,base:parent});remove(nodes,path);nodes.set(path,{...metadata,type:'symlink',link});}
   else if(type==='1'){need(size===0&&link.length>0,'ImageTarLink');const target=nodes.get(resolved(nodes,normalize(link,{link:true}),{missing:false}));need(target&&['file','hardlink'].includes(target.type),'ImageHardlinkTarget');remove(nodes,path);nodes.set(path,{...metadata,type:'hardlink',link,content:target.content});}
   else imageFailure('ImageTarEntryUnsupported');
  }
 }finally{await cursor.close();}
}
async function packageDatabase(content,layers,diffIds,readBlob,budget,requirements){
 need(content.size<=L.maxPackageDatabaseBytes,'ImagePackageDatabaseLimit');const layer=layers[content.layer],cursor=new Cursor(unpacked(layer,diffIds[content.layer],readBlob,budget)),decode=decoder(),sha=createHash('sha256');
 const matches=new Map(requirements.map(r=>[r.name,[]]));let pending='',databaseText='',pkg={};
 const line=value=>{if(value===''){if(Object.keys(pkg).length){need(pkg.P&&pkg.V,'ImagePackageRecord');if(matches.has(pkg.P))matches.get(pkg.P).push(pkg.V);}pkg={};return;}
  if(value.startsWith('P:')||value.startsWith('V:')){need(!Object.hasOwn(pkg,value[0]),'ImagePackageDuplicateField');pkg[value[0]]=value.slice(2);}
 };
 try{await cursor.skip(content.offset);for await(const bytes of cursor.chunks(content.size)){sha.update(bytes);const decoded=decode.decode(bytes,{stream:true});databaseText+=decoded;pending+=decoded;need(Buffer.byteLength(pending)<=L.maxBufferPerStreamBytes,'ImagePackageLineLimit');const rows=pending.split('\n');pending=rows.pop();for(const row of rows)line(row);}
  const final=decode.decode();databaseText+=final;pending+=final;if(pending)line(pending);line('');await cursor.drain();need(sha.digest('hex')===content.sha256,'ImagePackageDatabaseChanged');
 }finally{await cursor.close();}
 return {databaseText,databaseHash:content.sha256,paths:requirements.map(r=>r.path),packages:requirements.map(r=>{const versions=matches.get(r.name);need(versions.length===1&&versions[0]===r.version,'ImagePackageVersion');return {path:r.path,manager:r.manager,name:r.name,version:versions[0],databaseSha256:content.sha256,databaseSize:content.size,layerDigest:content.layerDigest};})};
}

/** No filesystem or credential APIs are used. readBlob comes only from the
 * verified cache. A private caller must isolate this parser from credentials. */
export async function inspectImageFilesystem(graph,{component,requirements=[],budget}={}){
 const state=imageGraphState(graph);budget??=state.budget;need(budget===state.budget,'ImageFilesystemBudget');assertImageBudget(budget);const image=state.images.get(component);need(image,'ImageFilesystemComponent');
 need(Array.isArray(requirements)&&requirements.length<=32&&new Set(requirements.map(r=>r.path+'\0'+r.name)).size===requirements.length,'ImagePackageRequirements');
 for(const r of requirements)need(r&&Object.keys(r).sort().join()===['path','manager','name','version'].sort().join()&&r.manager==='apk'&&typeof r.path==='string'&&r.path.startsWith('/')&&typeof r.name==='string'&&/^[a-zA-Z0-9+_.-]{1,256}$/.test(r.name)&&typeof r.version==='string'&&/^[^\s\0]{1,512}$/.test(r.version),'ImagePackageRequirements');
 const nodes=new Map(),readBlob=d=>state.store.open(d),pass=uncompressedPass(budget);
 for(let i=0;i<image.layers.length;i++)await applyLayer(nodes,image.layers[i],image.diffIds[i],i,readBlob,budget,pass);
 // Dangling runtime symlinks remain inert metadata; required files and all
 // hardlinks must resolve. Cycles/escapes are rejected even for unused links.
 for(const [path,node]of nodes)if(node.type==='symlink')resolved(nodes,path);
 const groups=new Map();for(const r of requirements){const path=normalize(r.path,{link:true}),name=resolved(nodes,path,{missing:false}),node=nodes.get(name);need(node&&['file','hardlink'].includes(node.type),'ImagePackageDatabaseMissing');const key=node.content.layer+':'+node.content.offset;if(!groups.has(key))groups.set(key,{content:node.content,requirements:[]});groups.get(key).requirements.push(r);}
 const packages=[],databases=[];for(const group of groups.values()){const db=await packageDatabase(group.content,image.layers,image.diffIds,readBlob,budget,group.requirements);packages.push(...db.packages);databases.push(db);}
 const entries=[...nodes].sort(([a],[b])=>a.localeCompare(b)).map(([path,node])=>({path,...node}));
 const evidence=freeze({version:1,graphHash:graph.graphHash,limitsHash:IMAGE_TRANSITION_LIMITS_HASH,component,rootDigest:state.roots.find(r=>r.component===component).root.digest,arm64Digest:image.manifest.digest,entriesHash:hash(entries),entryCount:entries.length,requirementsHash:hash(requirements),packages});
 const context=Object.freeze({evidence});verified.set(context,{evidence,databases,uncompressedBytes:pass.bytes,entries:freeze(entries),side:state.side,graph,requirements:structuredClone(requirements)});return context;
}
/** A new copy requires this exact live source graph, not destination or archive
 * evidence with the same public hashes. The caller supplies policy-bound pins. */
export function assertImageFilesystemSource(context,graph,{requirementsHash}={}){
 const state=verified.get(context);need(state&&state.kind!=='archived-filesystem-evidence'&&state.side==='source'&&state.graph===graph,'ImageFilesystemSourceRequired');
 need(typeof requirementsHash==='string'&&/^[a-f0-9]{64}$/.test(requirementsHash)&&state.evidence.requirementsHash===requirementsHash&&hash(state.requirements)===requirementsHash,'ImageFilesystemRequirementsChanged');
 return structuredClone(state.evidence);
}
/** Native use binds actual complete geometry to its original allocation.
 * This value comes only from live parser state, not serialized evidence. */
export function assertImageFilesystemUncompressedLimit(context,limit){
 const state=verified.get(context);
 need(state&&state.kind!=='archived-filesystem-evidence'&&Number.isSafeInteger(state.uncompressedBytes),'ImageFilesystemContextRequired');
 need(Number.isSafeInteger(limit)&&limit>0,'ImageFilesystemUncompressedLimit');
 need(state.uncompressedBytes<=Math.min(limit,L.maxUncompressedBytes),'ImageUncompressedLimit');
 return state.uncompressedBytes;
}
export function inspectImageFilesystemEvidence(context){need(verified.has(context),'ImageFilesystemContextRequired');return structuredClone(verified.get(context).evidence);}
/** Read-only metadata from the actual verified virtual filesystem. This does
 * not create authority or expose a host filesystem path. Archive reconstruction
 * cannot claim a new live extraction through this accessor. */
export function inspectImageFilesystemEntries(context){
 const state=verified.get(context);need(state&&state.kind!=='archived-filesystem-evidence'&&state.entries,'ImageFilesystemContextRequired');
 need(hash(state.entries)===state.evidence.entriesHash,'ImageFilesystemEntriesChanged');return structuredClone(state.entries);
}
/** File facts come from the verified final overlay and actual layer bytes.
 * No host path is opened and no archived JSON object creates this handle. */
export function inspectImageFilesystemFile(context,path){
 const state=verified.get(context);need(state&&state.kind!=='archived-filesystem-evidence'&&state.entries,'ImageFilesystemContextRequired');
 need(typeof path==='string'&&path.startsWith('/')&&path!=='/'&&posix.normalize(path)===path&&!path.endsWith('/'),'ImageRuntimeFilePath');
 const nodes=new Map(state.entries.map(({path,...node})=>[path,node])),links=[];
 const effectiveId=(node,key)=>{
  const raw=node.pax?.[key];if(raw===undefined)return node[key];
  need(typeof raw==='string'&&/^(?:0|[1-9][0-9]*)$/.test(raw)&&Number.isSafeInteger(Number(raw)),'ImageRuntimeFileOwner');return Number(raw);
 };
 const metadata=(name,node)=>({path:'/'+name,type:node.type,...(node.implicit?{implicit:true}:{}),
  ...(node.mode===undefined?{}:{mode:node.mode}),...(effectiveId(node,'uid')===undefined?{}:{uid:effectiveId(node,'uid')}),
  ...(effectiveId(node,'gid')===undefined?{}:{gid:effectiveId(node,'gid')}),
  privilegeAttributes:Object.keys(node.pax??{}).filter(key=>key==='SCHILY.xattr.security.capability').sort(),
  ...(node.type==='symlink'?{link:node.link}:{})});
 const name=resolved(nodes,normalize(path,{link:true}),{missing:false,onLink:(name,node)=>links.push(metadata(name,node))}),node=nodes.get(name);
 // Runtime executable/CA proofs reject hardlink inode-metadata ambiguity.
 need(node?.type==='file'&&node.content,'ImageRuntimeFileRequired');
 const parentRecords=new Map();
 for(const start of [normalize(path,{link:true}),name,...links.map(link=>link.path.slice(1))]){
  let parent=posix.dirname(start);
  while(parent!=='.'&&parent!=='/'){
   const original=nodes.get(parent);
   if(original){need(['directory','symlink'].includes(original.type),'ImageVirtualParent');parentRecords.set(parent,metadata(parent,original));}
   else{const actual=resolved(nodes,parent,{missing:false}),entry=nodes.get(actual);need(entry?.type==='directory','ImageVirtualParent');parentRecords.set(actual,metadata(actual,entry));}
   parent=posix.dirname(parent);
  }
 }
 return freeze({...metadata(name,node),path,resolvedPath:'/'+name,sha256:node.content.sha256,size:node.content.size,
  layerDigest:node.content.layerDigest,symlinkChain:links,parents:[...parentRecords.values()].sort((a,b)=>a.path.localeCompare(b.path)),rootMetadata:'not-recorded'});
}

/** Bounded reads for source modules, passwd and loader metadata. Large
 * executables use their verified content hash, not an unbounded Buffer. */
export async function readImageFilesystemFile(context,path,{maxBytes=L.maxBufferPerStreamBytes}={}){
 need(Number.isSafeInteger(maxBytes)&&maxBytes>=0&&maxBytes<=L.maxBufferPerStreamBytes,'ImageRuntimeFileLimit');
 const fact=inspectImageFilesystemFile(context,path);need(fact.size<=maxBytes,'ImageRuntimeFileLimit');
 const state=verified.get(context),graph=imageGraphState(state.graph),image=graph.images.get(state.evidence.component),nodes=new Map(state.entries.map(({path,...node})=>[path,node]));
 const node=nodes.get(fact.resolvedPath.slice(1)),content=node.content,layer=image.layers[content.layer];
 const cursor=new Cursor(unpacked(layer,image.diffIds[content.layer],d=>graph.store.open(d),graph.budget));
 try{await cursor.skip(content.offset);const bytes=await cursor.read(content.size);await cursor.drain();
  need(createHash('sha256').update(bytes).digest('hex')===fact.sha256,'ImageRuntimeFileChanged');return bytes;
 }finally{await cursor.close();}
}
export function imageFilesystemRequirements(context){need(verified.has(context)&&verified.get(context).kind!=='archived-filesystem-evidence','ImageFilesystemContextRequired');return structuredClone(verified.get(context).requirements);}
export function imageFilesystemVerificationKind(context){need(verified.has(context),'ImageFilesystemContextRequired');return verified.get(context).kind??'live-filesystem-evidence';}
export function imageFilesystemVerificationBinding(context){need(verified.has(context),'ImageFilesystemContextRequired');const value=verified.get(context).archiveBinding;return value?structuredClone(value):null;}
export function imageFilesystemProof(context,copyContext,{path}={}){
 need(verified.has(context),'ImageFilesystemContextRequired');const state=verified.get(context),copy=inspectImageCopyVerification(copyContext);
 need(state.side==='destination'&&state.evidence.graphHash===copy.summary.inventoryHash,'ImageFilesystemCopyBinding');const matches=state.databases.filter(db=>db.paths.includes(path));need(matches.length===1,'ImagePackageDatabaseMissing');
 return {version:1,kind:'effective-apk-database',imageDigest:state.evidence.arm64Digest,graphHash:copy.graphHash,path,databaseText:matches[0].databaseText,databaseHash:matches[0].databaseHash};
}

/** Archive-only custody restores the previously committed package evidence.
 * It neither reads an image nor satisfies a new copy's filesystem preflight. */
export function restoreArchivedImageFilesystem(binding,value,copyContext){
 const anchor=inspectImageArchiveBinding(binding),copy=inspectImageCopyVerification(copyContext),proof=anchor.proof,e=proof.filesystemEvidence,f=proof.filesystem;
 need(copy.kind==='archived-copy-evidence'&&copy.archiveBinding.proofHash===anchor.proofHash&&copy.archiveBinding.dataHash===anchor.dataHash&&copy.archiveBinding.reviewHash===anchor.reviewHash,'ImageFilesystemArchiveBinding');
 need(value&&Object.keys(value).sort().join()===['version','filesystemHash','evidence','filesystem'].sort().join()&&value.version===1&&value.filesystemHash===hash(f)&&hash(value.evidence)===hash(e)&&hash(value.filesystem)===hash(f),'ImageFilesystemArchiveCommitment');
 need(e&&e.version===1&&e.limitsHash===IMAGE_TRANSITION_LIMITS_HASH&&e.graphHash===copy.summary.inventoryHash&&e.component==='mnemo-server'&&e.rootDigest===anchor.data.images['mnemo-server'].rootDigest&&e.arm64Digest===anchor.data.images['mnemo-server'].arm64Digest&&Number.isSafeInteger(e.entryCount)&&e.entryCount>=0&&e.entryCount<=L.maxFsEntries&&/^[a-f0-9]{64}$/.test(e.entriesHash),'ImageFilesystemArchiveEvidence');
 need(f&&f.version===1&&f.kind==='effective-apk-database'&&f.graphHash===copy.graphHash&&f.imageDigest===e.arm64Digest&&f.path==='/lib/apk/db/installed'&&typeof f.databaseText==='string'&&Buffer.byteLength(f.databaseText)<=L.maxPackageDatabaseBytes&&createHash('sha256').update(f.databaseText).digest('hex')===f.databaseHash,'ImageFilesystemArchiveDatabase');
 need(Array.isArray(e.packages)&&e.packages.length>0&&e.packages.length<=32,'ImageFilesystemArchivePackages');
 const requirements=[];
 for(const p of e.packages){
  need(p&&p.path===f.path&&p.manager==='apk'&&typeof p.name==='string'&&typeof p.version==='string'&&p.databaseSha256===f.databaseHash&&p.databaseSize===Buffer.byteLength(f.databaseText)&&copy.inventory.edges.some(x=>x.component===e.component&&x.parent===e.arm64Digest&&x.child===p.layerDigest&&x.kind==='layer'),'ImageFilesystemArchivePackages');
  requirements.push({path:p.path,manager:p.manager,name:p.name,version:p.version});
 }
 need(hash(requirements)===e.requirementsHash,'ImageFilesystemArchiveRequirements');
 const fixed=proof.policy.fixed,matching=e.packages.filter(p=>p.name===fixed.package&&p.version===fixed.targetVersion);
 need(matching.length===1&&fixed.component===e.component,'ImageFilesystemArchiveFixedPackage');
 const entries=f.databaseText.trim().split(/\n\s*\n/).map(s=>s.split('\n')),zlib=entries.filter(lines=>lines.includes('P:'+fixed.package));
 need(zlib.length===1&&zlib[0].filter(x=>x.startsWith('P:')).length===1&&zlib[0].filter(x=>x.startsWith('V:')).length===1&&zlib[0].includes('V:'+fixed.targetVersion),'ImageFilesystemArchiveVersion');
 const handle=Object.freeze({evidence:freeze(structuredClone(e))});
 verified.set(handle,{kind:'archived-filesystem-evidence',evidence:handle.evidence,side:'destination',requirements,databases:[{paths:[f.path],databaseText:f.databaseText,databaseHash:f.databaseHash}],archiveBinding:{proofHash:anchor.proofHash,dataHash:anchor.dataHash,reviewHash:anchor.reviewHash}});return handle;
}
