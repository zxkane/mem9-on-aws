/** Paid comparison DATA only. No image writer, publisher, host path or token. */
import {createHash} from 'node:crypto';
import {nonrootHash as hash,copyNonrootJson,NONROOT_LIMITS} from './production-nonroot-contracts.mjs';
import {imageGraphState,controlImageGraphBinding,IMAGE_MEDIA as M} from './production-image-graph.mjs';
import {inspectImageFilesystemEvidence,inspectImageFilesystemEntries,imageFilesystemVerificationKind} from './production-image-filesystem.mjs';
import {controlSourceEntries,createControlSourceContext,readControlSourceFile} from './production-control-source.mjs';
import {describeProductionControlCopyManifest} from './production-control-composition-source.mjs';
import {inspectProductionControlComposition,compositionUstarPath,encodeCompositionJson,COMPOSITION_BUILDER_ID,PRODUCTION_CONTROL_COMPOSITION_LIMITS as L} from './production-control-composition.mjs';
import {productionControlCompositionStatement,inspectProductionControlCompositionCapture} from './production-control-composition-provenance.mjs';
import {parseAcquisitionJson} from './ci-smoke-acquisition-format.mjs';

export const A_MAIN_BRIDGE_KIND='exact-A-base-to-main-composition-v1';
export const A_MAIN_BRIDGE_ENTRY_LOCAL=16*NONROOT_LIMITS.maxProofBytes;
const need=(ok,code)=>{if(!ok)throw Object.assign(Error(code),{code});};
const same=(a,b,code)=>need(hash(a)===hash(b),code);
const sha=b=>createHash('sha256').update(b).digest('hex');
const nat=n=>Number.isSafeInteger(n)&&n>=0;
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'RehearsalBridgeFields');
function sync(call){const v=call();if(v&&typeof v.then==='function'){Promise.resolve(v).catch(()=>{});throw Error('RehearsalBridgeSynchronousPayer');}return v;}
function current(work){need(work&&typeof work.assertCurrent==='function'&&typeof work.chargeLocal==='function','RehearsalBridgeOriginalPayer');need(sync(()=>work.assertCurrent())===undefined,'RehearsalBridgeOriginalPayer');}
function debit(work,n){current(work);need(nat(n),'RehearsalBridgeCharge');sync(()=>work.chargeLocal(n));current(work);}

/** Geometry is a declared bound, validated against native objects before use.
 * Returned prices are DATA; compareNonrootAtoMain always makes its own debit. */
export function describeNonrootAtoMainComparison(plan,geometry){
 exact(geometry,['sourceBytes','sourceFiles','baseFsBytes','baseFsNodes','mainFsBytes','mainFsNodes']);
 need(Object.values(geometry).every(n=>nat(n)&&n>0),'RehearsalBridgeGeometry');
 const p=inspectProductionControlComposition(plan),g=geometry;
 need(g.sourceFiles<=20000,'RehearsalBridgeSourceGeometry');
 const source=32*(g.sourceBytes+p.sourceBytes+2*L.sourceFileBytes)+4096*g.sourceFiles;
 const filesystem=32*(g.baseFsBytes+g.mainFsBytes)+128*(g.baseFsNodes+g.mainFsNodes);
 const metadata=16*L.metadataBytes,tar=4*p.tarBytes;
 const total=A_MAIN_BRIDGE_ENTRY_LOCAL+source+filesystem+metadata+tar;
 need([source,filesystem,metadata,tar,total].every(nat),'RehearsalBridgeCharge');
 return Object.freeze({authority:false,kind:'A-main-comparison-work',entry:A_MAIN_BRIDGE_ENTRY_LOCAL,source,filesystem,metadata,tar,logicalBytes:total});
}

// Exact original composition header (not the loader's outer OCI envelope).
export function encodeRehearsalComparisonHeader(row){
 const b=Buffer.alloc(512),path=compositionUstarPath(row.path);
 const octal=(value,at,width)=>{const s=value.toString(8);need(s.length<width,'ControlCompositionUstarNumber');b.write(s.padStart(width-1,'0')+'\0',at,width,'ascii');};
 b.write(path.name,0,100,'utf8');b.write(path.prefix,345,155,'utf8');
 octal(row.mode,100,8);octal(row.uid,108,8);octal(row.gid,116,8);
 octal(row.type==='file'?row.bytesLength:0,124,12);octal(0,136,12);
 b.fill(32,148,156);b[156]=row.type==='file'?48:row.type==='directory'?53:50;
 if(row.type==='symlink')b.write(row.target,157,100,'utf8');
 b.write('ustar\0',257,6,'ascii');b.write('00',263,2,'ascii');
 let sum=0;for(const n of b)sum+=n;b.write(sum.toString(8).padStart(6,'0')+'\0 ',148,8,'ascii');return b;
}

// Count before allocating a serialized native FS body. No new smaller cap.
function boundedGeometry(value,maxBytes,maxNodes,{beforeNode=()=>{},beforeString=()=>{}}={}){
 let bytes=0,nodes=0;
 const add=n=>{bytes+=n;need(Number.isSafeInteger(bytes)&&bytes<=maxBytes,'RehearsalBridgeFilesystemBytes');};
 const string=s=>{beforeString(s.length);add(2);for(let i=0;i<s.length;i++){
  const c=s.charCodeAt(i);if(c===34||c===92||[8,9,10,12,13].includes(c))add(2);
  else if(c<32)add(6);else if(c<128)add(1);else if(c<2048)add(2);
  else if(c>=0xd800&&c<=0xdbff&&s.charCodeAt(i+1)>=0xdc00&&s.charCodeAt(i+1)<=0xdfff){add(4);i++;}
  else if(c>=0xd800&&c<=0xdfff)add(6);else add(3);
 }};
 const visit=v=>{
  beforeNode();need(Number.isSafeInteger(++nodes)&&nodes<=maxNodes,'RehearsalBridgeFilesystemNodes');
  if(typeof v==='string')return string(v);
  if(v===null)return add(4);if(typeof v==='boolean')return add(v?4:5);
  if(typeof v==='number'){need(Number.isFinite(v),'RehearsalBridgeFilesystemValue');return add(String(v).length);}
  need(v&&typeof v==='object','RehearsalBridgeFilesystemValue');add(2);
  const array=Array.isArray(v),keys=Object.keys(v);if(array)need(keys.length===v.length,'RehearsalBridgeFilesystemValue');
  for(let i=0;i<keys.length;i++){if(i)add(1);const key=keys[i],d=Object.getOwnPropertyDescriptor(v,key);need(d&&Object.hasOwn(d,'value'),'RehearsalBridgeFilesystemValue');if(!array){string(key);add(1);}visit(d.value);}
 };visit(value);return {bytes,nodes};
}
function projection(entries){return entries.map(e=>Object.fromEntries(Object.entries({
 path:e.path,type:e.type,mode:e.mode,uid:e.uid,gid:e.gid,implicit:e.implicit,target:e.link,
 sha256:e.content?.sha256,size:e.content?.size,
 attributes:Object.fromEntries(Object.entries(e.pax??{}).filter(([k])=>k.startsWith('SCHILY.xattr.'))),
}).filter(([,v])=>v!==undefined)));}

/** Current native geometry, paid before any native membership copy/sizing.
 * Source forecasts may bound this operation; they are never execution facts. */
export function deriveNonrootRehearsalComparisonGeometry(input,{work}){
 debit(work,A_MAIN_BRIDGE_ENTRY_LOCAL);
 const {sourceContext,baseFilesystem,mainFilesystem}=input;
 const source=controlSourceEntries(sourceContext),sourceBytes=encodeCompositionJson(source,NONROOT_LIMITS.maxProofBytes).length;
 const filesystem=context=>{
  let geometry;
  inspectImageFilesystemEntries(context,{beforeRead(entries){
   current(work);
   // Native full-FS data has already passed its original graph/FS limits.
   // Count it without a proof-JSON byte/node cap or a serialized buffer.
   // Every counting node/string is prepaid before its processing; the native
   // accessor's subsequent full hash and clone are prepaid before return.
   geometry=boundedGeometry(entries,Number.MAX_SAFE_INTEGER,Number.MAX_SAFE_INTEGER,{
    beforeNode:()=>debit(work,32),beforeString:n=>debit(work,8*n+32),
   });
   debit(work,8*geometry.bytes+32*geometry.nodes);
  }});
  current(work);return geometry;
 };
 const base=filesystem(baseFilesystem),main=filesystem(mainFilesystem);
 current(work);return Object.freeze({sourceBytes,sourceFiles:source.length,baseFsBytes:base.bytes,baseFsNodes:base.nodes,mainFsBytes:main.bytes,mainFsNodes:main.nodes});
}

/** actualMain is the completed original composition record, not a supplied
 * verdict. The production caller must first run the unchanged main verifier. */
export async function compareNonrootAtoMain(input,{work}){
 debit(work,A_MAIN_BRIDGE_ENTRY_LOCAL);
 exact(input,['plan','actualMain','baseGraph','baseFilesystem','mainGraph','mainFilesystem','sourceContext','geometry']);
 const {baseGraph,baseFilesystem,mainGraph,mainFilesystem,sourceContext}=input;
 const plan=inspectProductionControlComposition(input.plan),q=describeNonrootAtoMainComparison(plan,input.geometry);
 debit(work,q.logicalBytes-q.entry);
 exact(input.actualMain,['capture','statement']);
 const actual=inspectProductionControlCompositionCapture(input.actualMain.capture),actualStatement=copyNonrootJson(input.actualMain.statement),g=input.geometry;
 need(actual.builder===COMPOSITION_BUILDER_ID&&actual.planHash===plan.planHash,'RehearsalBridgeMainRecord');
 const serializedMs=Date.parse(actualStatement?.predicate?.runDetails?.metadata?.finishedOn);
 need(nat(actual.startedMs)&&actual.startedMs>0&&nat(serializedMs)&&serializedMs>=actual.startedMs&&nat(actual.completedMs)&&actual.completedMs>=serializedMs,'RehearsalBridgeMainClock');
 const aBinding=controlImageGraphBinding(baseGraph),mBinding=controlImageGraphBinding(mainGraph);
 const {graphHash:aGraphHash,...aImage}=aBinding,{graphHash:mGraphHash,...mImage}=mBinding;
 same(aImage,plan.input.base.image,'RehearsalBridgeBaseImage');same(baseGraph.inventory,plan.input.base.inventory,'RehearsalBridgeBaseInventory');
 same(actual.image,mImage,'RehearsalBridgeMainImage');need(actual.graphHash===mGraphHash,'RehearsalBridgeMainGraph');
 need(aImage.account===mImage.account&&aImage.region===mImage.region&&aImage.repositoryName==='mem9-on-aws/preview/bootstrap'&&mImage.repositoryName==='mem9-on-aws/bootstrap','RehearsalBridgeImageScope');
 need(sourceContext.tree===plan.input.source.candidateTree,'RehearsalBridgeSource');
 for(const fs of [baseFilesystem,mainFilesystem])need(imageFilesystemVerificationKind(fs)==='live-filesystem-evidence','RehearsalBridgeLiveFilesystem');
 const af=inspectImageFilesystemEvidence(baseFilesystem),mf=inspectImageFilesystemEvidence(mainFilesystem);
 same(af,plan.input.base.filesystem,'RehearsalBridgeBaseFilesystem');same(mf,actual.filesystem,'RehearsalBridgeMainFilesystem');
 need(af.graphHash===aGraphHash&&mf.graphHash===mGraphHash,'RehearsalBridgeFilesystemGraph');
 const before=inspectImageFilesystemEntries(baseFilesystem,{beforeRead(entries){current(work);boundedGeometry(entries,g.baseFsBytes,g.baseFsNodes);}});
 const after=inspectImageFilesystemEntries(mainFilesystem,{beforeRead(entries){current(work);boundedGeometry(entries,g.mainFsBytes,g.mainFsNodes);}});
 same(projection(before),projection(after),'RehearsalBridgeFilesystemChanged');
 const originalEntries=controlSourceEntries(sourceContext);need(originalEntries.length<=g.sourceFiles,'RehearsalBridgeSourceFiles');
 need(Buffer.byteLength(JSON.stringify(originalEntries))<=g.sourceBytes,'RehearsalBridgeSourceBytes');
 // A paid read-only view forwards the ORIGINAL source reader and adds this
 // caller's lifetime check. It never substitutes blobs or transfers authority.
 const view=createControlSourceContext({tree:sourceContext.tree,entries:originalEntries},async(_oid,path)=>{
  current(work);const result=await readControlSourceFile(sourceContext,path);current(work);return result.bytes;
 },{assertCurrent:()=>current(work)});
 const rows=await describeProductionControlCopyManifest({sourceContext:view,baseFilesystem,charge:()=>current(work)});current(work);
 same(rows.rows,plan.input.copyManifest,'RehearsalBridgeCopyRows');need(rows.copyHash===plan.copyHash&&rows.tarBytes===plan.tarBytes,'RehearsalBridgeCopyPlan');
 const layerHash=createHash('sha256');let length=0;
 const emit=b=>{current(work);need(b.length<=L.streamBytes&&length+b.length<=plan.tarBytes,'RehearsalBridgeTarBound');layerHash.update(b);length+=b.length;};
 for(const row of rows.rows){
  emit(encodeRehearsalComparisonHeader(row));
  if(row.type==='file'){
   const file=await readControlSourceFile(view,row.sourcePath);current(work);
   need(file.file.sha256===row.sha256&&file.bytes.length===row.bytesLength,'RehearsalBridgeSourceBytes');
   for(let at=0;at<file.bytes.length;at+=L.streamBytes)emit(file.bytes.subarray(at,at+L.streamBytes));
   if(row.bytesLength%512)emit(Buffer.alloc(512-row.bytesLength%512));
  }
 }
 emit(Buffer.alloc(1024));need(length===plan.tarBytes,'RehearsalBridgeTarSize');
 const layer={mediaType:M.tar,size:length,digest:'sha256:'+layerHash.digest('hex')};
 const a=imageGraphState(baseGraph),m=imageGraphState(mainGraph),runtime=a.images.get('bootstrap'),mainRuntime=m.images.get('bootstrap');
 same(layer,mainRuntime.layers.at(-1),'RehearsalBridgeLayer');
 same(mainRuntime.layers,[...runtime.layers,layer],'RehearsalBridgeLayerOrder');
 same(mainRuntime.diffIds,[...runtime.diffIds,layer.digest],'RehearsalBridgeDiffIds');
 const expectedNodes=new Map(runtime.layers.map(d=>[d.digest,{digest:d.digest,mediaType:d.mediaType,size:d.size}]));expectedNodes.set(layer.digest,layer);
 async function read(state,d,max){
  current(work);need(d.size<=max,'RehearsalBridgeMetadataBound');
  const iterator=state.store.open(d)[Symbol.asyncIterator](),parts=[];let bytes=0,failed,ended=false;
  try{
   while(true){const next=await iterator.next();current(work);if(next.done){ended=true;break;}const b=next.value;need(b instanceof Uint8Array&&bytes+b.length<=d.size,'RehearsalBridgeMetadataSize');bytes+=b.length;parts.push(b);}
   need(bytes===d.size,'RehearsalBridgeMetadataSize');const raw=Buffer.concat(parts,bytes);need('sha256:'+sha(raw)===d.digest,'RehearsalBridgeMetadataHash');return raw;
  }catch(e){failed=e;throw e;}
  finally{try{
   need(ended||typeof iterator.return==='function','RehearsalBridgeReaderUnjoined');
   if(typeof iterator.return==='function'){const closed=await iterator.return();need(closed?.done===true,'RehearsalBridgeReaderUnjoined');}
  }catch(e){throw Object.assign(Error('RehearsalBridgeReaderCleanup'),{code:'ECLEANUP',cause:e,operationError:failed,cleanupComplete:false});}current(work);}
 }
 const baseRaw=await read(a,runtime.config,L.configBytes);current(work);const config=parseAcquisitionJson(baseRaw,L.configBytes);
 need(config.architecture==='arm64'&&config.os==='linux'&&config.rootfs?.type==='layers','RehearsalBridgeBaseConfig');
 need(config.config?.OnBuild===undefined||config.config.OnBuild===null||Array.isArray(config.config.OnBuild)&&config.config.OnBuild.length===0,'RehearsalBridgeOnBuild');
 same(config.rootfs.diff_ids,runtime.diffIds,'RehearsalBridgeBaseDiffIds');
 config.created=new Date(actual.startedMs).toISOString();config.rootfs.diff_ids=[...runtime.diffIds,layer.digest];
 if(config.history!==undefined){need(Array.isArray(config.history),'RehearsalBridgeHistory');config.history=[...config.history,{created:config.created,created_by:COMPOSITION_BUILDER_ID,comment:'plan:'+plan.planHash}];}
 async function metadata(value,mediaType,max){
  current(work);const bytes=encodeCompositionJson(value,max),d={mediaType,digest:'sha256:'+sha(bytes),size:bytes.length};
  const found=mainGraph.inventory.nodes.find(n=>n.digest===d.digest);need(found&&found.mediaType===mediaType&&found.size===bytes.length,'RehearsalBridgeMetadataDescriptor');
  const raw=await read(m,d,max);current(work);need(raw.equals(bytes),'RehearsalBridgeMetadataBytes');expectedNodes.set(d.digest,d);return d;
 }
 const configDescriptor=await metadata(config,M.config,L.configBytes);current(work);need(configDescriptor.digest===mImage.configDigest,'RehearsalBridgeConfigDigest');
 const arm=await metadata({schemaVersion:2,mediaType:M.manifest,config:configDescriptor,layers:[...runtime.layers,layer]},M.manifest,L.manifestBytes);current(work);need(arm.digest===mImage.arm64Digest,'RehearsalBridgeArmDigest');
 const statement=productionControlCompositionStatement({plan,actualMain:actual.actualMain,arm64Digest:arm.digest,startedMs:actual.startedMs,completedMs:serializedMs});
 same(statement,actualStatement,'RehearsalBridgeStatement');need(hash(statement)===actual.statementHash,'RehearsalBridgeStatementHash');
 const payload=await metadata(statement,M.attestation,L.attestationBytes);current(work);
 const empty=await metadata({},M.emptyConfig,2);current(work);
 const attestation=await metadata({schemaVersion:2,mediaType:M.manifest,artifactType:M.attestation,config:empty,layers:[payload],subject:arm},M.manifest,L.manifestBytes);current(work);
 const root=await metadata({schemaVersion:2,mediaType:M.index,manifests:[{...arm,platform:{os:'linux',architecture:'arm64'}},{...attestation,platform:{os:'unknown',architecture:'unknown'}}]},M.index,L.manifestBytes);current(work);
 need(root.digest===mImage.rootDigest,'RehearsalBridgeRootDigest');same(root,actual.rootDescriptor,'RehearsalBridgeRootDescriptor');
 same([...expectedNodes.values()].sort((x,y)=>x.digest.localeCompare(y.digest)),[...mainGraph.inventory.nodes].sort((x,y)=>x.digest.localeCompare(y.digest)),'RehearsalBridgeCompleteGraph');
 controlImageGraphBinding(baseGraph);controlImageGraphBinding(mainGraph);current(work);
 return Object.freeze({version:1,kind:A_MAIN_BRIDGE_KIND,authority:false,baseImage:Object.freeze(aImage),mainImage:Object.freeze(mImage),
  baseGraphHash:aGraphHash,mainGraphHash:mGraphHash,baseFilesystemHash:hash(af),mainFilesystemHash:hash(mf),
  source:Object.freeze(copyNonrootJson(plan.input.source)),planHash:plan.planHash,copyHash:plan.copyHash,
  mainRevision:actual.actualMain.mainRevision,mainTree:actual.actualMain.mainTree,layer:Object.freeze(layer),logicalBytes:q.logicalBytes});
}
