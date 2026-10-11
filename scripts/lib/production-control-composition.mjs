/** Prospective native CONTROL composition. Data and arithmetic only: neither
 * a plan nor its hash is a filesystem, source, funding or publication handle. */
import {copyNonrootJson, nonrootHash as hash, inspectNonrootRecord} from './production-nonroot-contracts.mjs';
import {IMAGE_MEDIA as M, validateImageDescriptor} from './production-image-graph.mjs';
import {IMAGE_TRANSITION_LIMITS as IMAGE, IMAGE_TRANSITION_LIMITS_HASH} from './production-image-transition.mjs';
import {NONROOT_REMAINING_WORK_CAPS_V2 as CAPS} from './production-nonroot-budget-revision.mjs';
import {CONTROL_COMPOSITION_MAIN_OUTPUT_CHARGE} from './production-control-composition-main-policy.mjs';
import {COMPOSITION_OWNER_SOURCE_LIMITS,describeCompositionOwnerWork} from './production-control-composition-owner.mjs';
import {PRODUCTION_CONTROL_COMPOSITION_RUNTIME_POLICY as RUNTIME,PRODUCTION_CONTROL_COMPOSITION_RUNTIME_POLICY_HASH as RH,
 CONTROL_COMPOSITION_RUNTIME_NORMAL_LOCAL,CONTROL_COMPOSITION_RUNTIME_CLEANUP_LOCAL,CONTROL_COMPOSITION_RUNTIME_VALIDATION_LOCAL,
 CONTROL_COMPOSITION_RUNTIME_ENTRY,CONTROL_COMPOSITION_RUNTIME_TOOLCHAIN} from './production-control-composition-runtime-policy.mjs';

const MiB=1048576;
export const PRODUCTION_CONTROL_COMPOSITION_LIMITS=Object.freeze({
 version:1, kind:'native-control-composition-limits', streamBytes:65536,
 manifestBytes:IMAGE.maxManifestBytes, configBytes:IMAGE.maxConfigBytes,
 attestationBytes:IMAGE.maxAttestationPayloadBytes,
 metadataBytes:3*IMAGE.maxManifestBytes+2*IMAGE.maxConfigBytes+IMAGE.maxAttestationPayloadBytes,
 graphBytes:660*MiB, uncompressedBytes:2*1024*MiB, processedEntries:50000,
 manifestNodes:3, configNodes:2, layerNodes:64, blobNodes:66,
 copyRows:20000, sourceFileBytes:16777216, recordBytes:65536,
 unknownBytes:8*MiB, partBytes:IMAGE.uploadPartBytes,
});
export const PRODUCTION_CONTROL_COMPOSITION_LIMITS_HASH=hash(PRODUCTION_CONTROL_COMPOSITION_LIMITS);
export const PRODUCTION_CONTROL_COMPOSITION_LIMITS_V2=Object.freeze({...PRODUCTION_CONTROL_COMPOSITION_LIMITS,version:2,runtimePolicyHash:RH});
export const PRODUCTION_CONTROL_COMPOSITION_LIMITS_V2_HASH=hash(PRODUCTION_CONTROL_COMPOSITION_LIMITS_V2);
export const COMPOSITION_BUILDER_ID='mem9-native-control-composition/v1';
const L=PRODUCTION_CONTROL_COMPOSITION_LIMITS;
const HEX=/^[a-f0-9]{64}$/, DIGEST=/^sha256:[a-f0-9]{64}$/;
const fields=['ecrRequests','logicalBytes','httpBodyBytes','uncompressedBytes','processedEntries'];
const manifests=new Set([M.index,M.dockerIndex,M.manifest,M.dockerManifest]);
const configs=new Set([M.config,M.dockerConfig,M.emptyConfig]);
const layers=new Set([M.tar,M.gzip,M.zstd,M.dockerGzip,M.attestation]);
export const compositionNeed=(ok,code='ControlCompositionInvalid')=>{if(!ok)throw Error(code);};
const need=compositionNeed;
export function compositionExact(value,keys,code='ControlCompositionFields'){
 need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.slice().sort().join(),code);
}
export function compositionNat(n,code='ControlCompositionInteger'){
 need(Number.isSafeInteger(n)&&n>=0,code);return n;
}
export function compositionSum(...values){
 let total=0;for(const value of values){compositionNat(value);total+=value;compositionNat(total,'ControlCompositionOverflow');}return total;
}
export function compositionCounter(value){
 compositionExact(value,fields);for(const key of fields)need(Number.isSafeInteger(value[key])&&value[key]>=0&&value[key]<=CAPS[key],'ControlCompositionGlobalCap');return value;
}
export function compositionCharge(value={}){
 return compositionCounter(Object.fromEntries(fields.map(key=>[key,value[key]??0])));
}
export function sumCompositionCharges(rows){
 return compositionCharge(Object.fromEntries(fields.map(key=>[key,compositionSum(...rows.map(row=>compositionCounter(row)[key]))])));
}
const freeze=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;};
const same=(a,b,code)=>need(hash(a)===hash(b),code);
const padded=n=>Math.ceil(n/512)*512;

/** USTAR has no path-extension escape hatch. Parent directories are emitted
 * explicitly, so the complete processed-entry count is known before writing. */
export function compositionUstarPath(path){
 need(typeof path==='string'&&/^[A-Za-z0-9_.\/-]+$/.test(path)&&!path.startsWith('/')&&!path.endsWith('/')&&
  path.split('/').every(part=>part&&part!=='.'&&part!=='..'&&!part.startsWith('.wh.')),'ControlCompositionPath');
 if(Buffer.byteLength(path)<=100)return {name:path,prefix:''};
 for(let at=path.lastIndexOf('/');at>0;at=path.lastIndexOf('/',at-1)){
  const prefix=path.slice(0,at),name=path.slice(at+1);
  if(Buffer.byteLength(prefix)<=155&&Buffer.byteLength(name)<=100)return {name,prefix};
 }
 throw Error('ControlCompositionUstarPath');
}
function linkTarget(target,path){
 need(typeof target==='string'&&target.length>0&&Buffer.byteLength(target)<=100&&!/[\x00-\x1f\x7f\\]/.test(target),'ControlCompositionLink');
 const parts=target.startsWith('/')?[]:path.split('/').slice(0,-1);
 for(const part of target.split('/')){if(part==='..'){need(parts.length>0,'ControlCompositionLinkEscape');parts.pop();}else if(part&&part!=='.')parts.push(part);}
 need(parts.length>0,'ControlCompositionLink');
}
export function inspectProductionControlCopyRows(value){
 const rows=copyNonrootJson(value);
 need(Array.isArray(rows)&&rows.length>0&&rows.length<=L.copyRows,'ControlCompositionCopyRows');
 const seen=new Map();let bytes=0,tarBytes=1024;
 for(const row of rows){
  need(['file','directory','symlink'].includes(row.type),'ControlCompositionMemberType');
  compositionExact(row,['path','type','mode','uid','gid',...(row.type==='file'?['sourcePath','sha256','bytesLength']:row.type==='symlink'?['target']:[])]);
  compositionUstarPath(row.path);need(!seen.has(row.path),'ControlCompositionDuplicatePath');
  need(Number.isSafeInteger(row.mode)&&row.mode>=0&&row.mode<=0o7777,'ControlCompositionMode');
  for(const key of ['uid','gid'])need(Number.isSafeInteger(row[key])&&row[key]>=0&&row[key]<=0o7777777,'ControlCompositionOwner');
  if(row.type==='file'){
   // Source paths retain the original Git reader's 4096-byte path limit;
   // only the destination must fit USTAR.
   need(typeof row.sourcePath==='string'&&Buffer.byteLength(row.sourcePath)<=4096&&/^[A-Za-z0-9_.\/-]+$/.test(row.sourcePath)&&
    !row.sourcePath.startsWith('/')&&row.sourcePath.split('/').every(p=>p&&p!=='.'&&p!=='..'),'ControlCompositionSourcePath');
   need(HEX.test(row.sha256)&&Number.isSafeInteger(row.bytesLength)&&row.bytesLength>=0&&row.bytesLength<=L.sourceFileBytes,'ControlCompositionSourceFile');
   bytes=compositionSum(bytes,row.bytesLength);
  }else if(row.type==='symlink')linkTarget(row.target,row.path);
  tarBytes=compositionSum(tarBytes,512,row.type==='file'?padded(row.bytesLength):0);seen.set(row.path,row);
 }
 for(const row of rows){
  const parts=row.path.split('/');parts.pop();
  while(parts.length){need(seen.get(parts.join('/'))?.type==='directory','ControlCompositionParent');parts.pop();}
 }
 const sorted=rows.slice().sort((a,b)=>Buffer.compare(Buffer.from(a.path),Buffer.from(b.path)));
 same(rows,sorted,'ControlCompositionOrder');
 return freeze({rows,tarBytes,tarEntries:rows.length,sourceBytes:bytes,copyHash:hash(rows)});
}

function source(value){
 compositionExact(value,['repository','prNumber','candidateRevision','candidateTree','baseRevision']);
 need(typeof value.repository==='string'&&/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value.repository)&&value.repository.length<=201&&
  Number.isSafeInteger(value.prNumber)&&value.prNumber>0&&['candidateRevision','candidateTree','baseRevision'].every(k=>/^[a-f0-9]{40}$/.test(value[k])),'ControlCompositionSource');
 return value;
}
function pack(value){
 compositionExact(value,['ref','uncompressedBytes','processedEntries']);inspectNonrootRecord('ByteRef',value.ref);
 need(value.ref.bytesLength>0,'ControlCompositionPack');compositionNat(value.uncompressedBytes);compositionNat(value.processedEntries);return value;
}
function base(value){
 compositionExact(value,['image','inventory','filesystem','uncompressedBytes','processedEntries']);
 inspectNonrootRecord('ControlImageBindingV1',value.image);
 compositionNat(value.uncompressedBytes);compositionNat(value.processedEntries);
 const inv=value.inventory;
 compositionExact(inv,['version','kind','limitsHash','roots','nodes','edges','attestations']);
 need(inv.version===1&&inv.kind==='readonly-control-image-graph'&&inv.limitsHash===IMAGE_TRANSITION_LIMITS_HASH&&
  Array.isArray(inv.roots)&&inv.roots.length===1&&Array.isArray(inv.nodes)&&inv.nodes.length>0&&inv.nodes.length<=69&&
  Array.isArray(inv.edges)&&inv.edges.length<=IMAGE.maxEdges&&Array.isArray(inv.attestations),'ControlCompositionInventory');
 const root=inv.roots[0];need(root.component==='bootstrap'&&root.repositoryName===value.image.repositoryName&&
  root.root?.digest===value.image.rootDigest&&root.arm64Digest===value.image.arm64Digest,'ControlCompositionBaseImage');
 const byDigest=new Map();let graphBytes=0,manifestNodes=0,configNodes=0,layerNodes=0;
 for(const d of inv.nodes){
  compositionExact(d,['digest','mediaType','size']);validateImageDescriptor(d,manifests.has(d.mediaType)?'manifest':'blob');
  need(manifests.has(d.mediaType)||configs.has(d.mediaType)||layers.has(d.mediaType),'ControlCompositionMedia');
  need(!byDigest.has(d.digest),'ControlCompositionDuplicateDescriptor');byDigest.set(d.digest,d);
  graphBytes=compositionSum(graphBytes,d.size);
  if(manifests.has(d.mediaType))manifestNodes++;else if(configs.has(d.mediaType))configNodes++;else layerNodes++;
 }
 need(byDigest.get(value.image.rootDigest)?.mediaType===root.root.mediaType&&byDigest.get(value.image.rootDigest)?.size===root.root.size&&
  manifests.has(byDigest.get(value.image.arm64Digest)?.mediaType)&&configs.has(byDigest.get(value.image.configDigest)?.mediaType),'ControlCompositionBaseDescriptors');
 const runtimeEdges=inv.edges.filter(e=>e.parent===value.image.arm64Digest&&e.kind==='layer').sort((a,b)=>a.index-b.index);
 const runtimeLayers=runtimeEdges.map((e,index)=>{
  need(e.index===index&&e.component==='bootstrap'&&byDigest.has(e.child),'ControlCompositionRuntimeEdge');
  const d=byDigest.get(e.child);need(layers.has(d.mediaType)&&d.mediaType!==M.attestation,'ControlCompositionRuntimeLayer');return d;
 });
 need(runtimeLayers.length>0,'ControlCompositionRuntimeLayers');
 const f=value.filesystem;
 compositionExact(f,['version','graphHash','limitsHash','component','rootDigest','arm64Digest','entriesHash','entryCount','requirementsHash','packages']);
 need(f.version===1&&f.component==='bootstrap'&&f.graphHash===hash(inv)&&f.limitsHash===IMAGE_TRANSITION_LIMITS_HASH&&
  f.rootDigest===value.image.rootDigest&&f.arm64Digest===value.image.arm64Digest&&HEX.test(f.entriesHash)&&HEX.test(f.requirementsHash)&&
  Number.isSafeInteger(f.entryCount)&&f.entryCount>=0&&f.entryCount<=value.processedEntries&&Array.isArray(f.packages),'ControlCompositionFilesystem');
 need(manifestNodes<=L.manifestNodes&&configNodes<=L.configNodes&&layerNodes<=L.layerNodes&&configNodes+layerNodes<=L.blobNodes,'ControlCompositionBaseCounts');
 return {graphBytes,manifestNodes,configNodes,layerNodes,runtimeLayers,
  blobNodes:configNodes+layerNodes,blobBytes:compositionSum(...inv.nodes.filter(n=>!manifests.has(n.mediaType)).map(n=>n.size)),
  rereadBytes:compositionSum(...inv.nodes.filter(n=>configs.has(n.mediaType)||n.mediaType===M.attestation).map(n=>n.size),...runtimeLayers.map(n=>n.size))};
}

export function describeProductionControlComposition(value){
 const input=copyNonrootJson(value);
 const native=input.version===2;
 compositionExact(input,['version','kind','base','source','copyManifest','packs',...(native?['sourceBytes','sourceFiles','runtime']:['sourceToolBytes'])]);
 need([1,2].includes(input.version)&&input.kind==='production-control-composition-input','ControlCompositionVersion');
 source(input.source);compositionExact(input.packs,native?['source']:['tools','source']);if(!native)pack(input.packs.tools);pack(input.packs.source);
 let runtime;
 if(native){
  need(Number.isSafeInteger(input.sourceBytes)&&input.sourceBytes>0&&Number.isSafeInteger(input.sourceFiles)&&input.sourceFiles>0&&input.sourceFiles<=20000,'ControlCompositionSourceBytes');
  compositionExact(input.runtime,['version','kind','policyHash','entry','toolchain']);
  need(input.runtime.version===1&&input.runtime.kind==='github-main-runtime-observation'&&input.runtime.policyHash===RH,'ControlCompositionRuntimePolicy');
  for(const [key,path]of [['entry',CONTROL_COMPOSITION_RUNTIME_ENTRY],['toolchain',CONTROL_COMPOSITION_RUNTIME_TOOLCHAIN]]){
   const file=inspectNonrootRecord('SourceFileV1',input.runtime[key]);need(file.path===path,'ControlCompositionRuntimeSource');
  }
  runtime={version:1,kind:'github-main-runtime-observation-plan',policyHash:RH,policy:RUNTIME,entry:input.runtime.entry,toolchain:input.runtime.toolchain,
   normalCharge:compositionCharge({logicalBytes:CONTROL_COMPOSITION_RUNTIME_NORMAL_LOCAL,processedEntries:1061}),
   physicalCleanupCharge:compositionCharge({logicalBytes:CONTROL_COMPOSITION_RUNTIME_CLEANUP_LOCAL,processedEntries:152}),additionalJournalRecords:2,validationLocalBytes:CONTROL_COMPOSITION_RUNTIME_VALIDATION_LOCAL};
 }else need(Number.isSafeInteger(input.sourceToolBytes)&&input.sourceToolBytes>0,'ControlCompositionSourceToolBytes');
 const b=base(input.base),copy=inspectProductionControlCopyRows(input.copyManifest);
 const bounds={graphBytes:compositionSum(b.graphBytes,copy.tarBytes,L.metadataBytes),
  uncompressedBytes:compositionSum(input.base.uncompressedBytes,copy.tarBytes),
  processedEntries:compositionSum(input.base.processedEntries,copy.tarEntries),
  manifestNodes:3,configNodes:2,layerNodes:b.runtimeLayers.length+2,blobNodes:b.runtimeLayers.length+4};
 for(const key of Object.keys(bounds))need(bounds[key]<=L[key],'ControlCompositionOutputBound');
 const selected=Object.values(input.packs),A=compositionSum(...selected.map(p=>p.ref.bytesLength));
 const E=compositionSum(...selected.map(p=>p.uncompressedBytes));
 const N=compositionSum(...selected.map(p=>p.processedEntries));
 // Declared source-owned input bound, not an observed input size. The
 // original owner checks its separately pinned actual input ref against it.
 const ownerWork=native?describeCompositionOwnerWork({sourcePack:input.packs.source,inputBytes:COMPOSITION_OWNER_SOURCE_LIMITS.inputBytes,runtimeObservationVersion:1}):null;
 // Metadata includes the complete output attestation/config/manifest closure.
 // Network/credential/publication catalogs are an additional named component;
 // the work reservation below is not advertised as their payment.
 const parts={
  actionOutput:CONTROL_COMPOSITION_MAIN_OUTPUT_CHARGE,
  ...(native?{allocationFilesystem:compositionCharge({logicalBytes:32768,processedEntries:2})}:{}),
  packingOwner:native?ownerWork.work:compositionCharge({logicalBytes:compositionSum(3*A,E)}),
  packingCi:compositionCharge({logicalBytes:compositionSum(3*A,2*E),uncompressedBytes:E,processedEntries:N}),
  source:native?compositionCharge({logicalBytes:compositionSum(42*input.sourceBytes,196608*input.sourceFiles),processedEntries:6*input.sourceFiles}):compositionCharge({logicalBytes:6*input.sourceToolBytes}),
  ...(native?{runtime:runtime.normalCharge}:{runtimeMaps:compositionCharge({logicalBytes:6*4*65537})}),
  base:compositionCharge({logicalBytes:compositionSum(3*b.graphBytes,b.rereadBytes),uncompressedBytes:input.base.uncompressedBytes,processedEntries:input.base.processedEntries}),
  compose:compositionCharge({logicalBytes:compositionSum(2*copy.sourceBytes,3*copy.tarBytes,8*L.metadataBytes)}),
  outputStaging:compositionCharge({logicalBytes:3*compositionSum(...[...new Map(b.runtimeLayers.map(d=>[d.digest,d])).values()].map(d=>d.size))}),
  publicationRead:compositionCharge({logicalBytes:2*bounds.graphBytes}),
  verify:compositionCharge({logicalBytes:compositionSum(bounds.graphBytes,b.rereadBytes,copy.tarBytes,L.metadataBytes),uncompressedBytes:bounds.uncompressedBytes,processedEntries:bounds.processedEntries}),
 };
 const result={version:input.version,kind:'production-control-composition-plan',authority:false,limitsHash:native?PRODUCTION_CONTROL_COMPOSITION_LIMITS_V2_HASH:PRODUCTION_CONTROL_COMPOSITION_LIMITS_HASH,
  builder:COMPOSITION_BUILDER_ID,input,copyHash:copy.copyHash,tarBytes:copy.tarBytes,tarEntries:copy.tarEntries,sourceBytes:copy.sourceBytes,
  base:b,bounds,...(native?{runtime}:{}),parts,workCharge:sumCompositionCharges(Object.values(parts))};
 return freeze({...result,planHash:hash(result)});
}
export function inspectProductionControlComposition(value){
 const original=copyNonrootJson(value),expected=describeProductionControlComposition(original.input);
 same(original,expected,'ControlCompositionPlanChanged');return expected;
}

/** Entire actor catalogs are required. A caller cannot substitute a work-only
 * quote for raw wire, journaling, unknown outcomes or cleanup. Native admission
 * additionally binds this exact catalog to the original funded consumer. */
export function describeProductionControlCompositionFunding({plan:rawPlan,catalog,cleanup,recordCounts}){
 const plan=inspectProductionControlComposition(rawPlan);
 compositionExact(catalog,['owner','ci']);compositionExact(cleanup,['owner','ci']);compositionExact(recordCounts,['owner','ci']);
 for(const actor of ['owner','ci']){
  compositionCounter(cleanup[actor]);compositionNat(recordCounts[actor]);
  need(cleanup[actor].logicalBytes>0&&recordCounts[actor]>0&&recordCounts[actor]<=4096,'ControlCompositionCleanupFunding');
 }
 const charges={},catalogs=copyNonrootJson(catalog);
 for(const actor of ['owner','ci']){
  const rows=catalogs[actor];need(Array.isArray(rows)&&rows.length>0&&rows.length<=256,'ControlCompositionCallCatalog');
  const ids=new Set();let wire=L.unknownBytes,calls=0,ecr=0;
  for(const row of rows){
   compositionExact(row,['id','service','action','count','requestBytes','responseBytes']);
   need(typeof row.id==='string'&&/^[a-z][a-z0-9-]{0,63}$/.test(row.id)&&!ids.has(row.id),'ControlCompositionCallId');ids.add(row.id);
   need(['s3','ssm','ecr','sts','github'].includes(row.service)&&typeof row.action==='string'&&/^[A-Za-z][A-Za-z0-9]+$/.test(row.action),'ControlCompositionCall');
   need(Number.isSafeInteger(row.count)&&row.count>0&&row.count<=20000,'ControlCompositionCallCount');
   compositionNat(row.requestBytes);compositionNat(row.responseBytes);need(row.responseBytes>0,'ControlCompositionCallBytes');
   wire=compositionSum(wire,row.count*compositionSum(row.requestBytes,row.responseBytes));calls=compositionSum(calls,row.count);if(row.service==='ecr')ecr+=row.count;
  }
  charges[actor]=compositionCharge({ecrRequests:ecr,httpBodyBytes:wire,logicalBytes:compositionSum(9*wire,8*L.recordBytes*calls)});
 }
 const journals=Object.fromEntries(['owner','ci'].map(actor=>[actor,compositionCharge({logicalBytes:4*L.recordBytes*recordCounts[actor]})]));
 if(plan.version===2){
  const q=describeCompositionOwnerWork({sourcePack:plan.input.packs.source,inputBytes:COMPOSITION_OWNER_SOURCE_LIMITS.inputBytes,runtimeObservationVersion:1});
  same(catalogs.owner,q.calls,'ControlCompositionOwnerCatalog');same(plan.parts.packingOwner,q.work,'ControlCompositionOwnerWork');
  same(charges.owner,q.rows.network,'ControlCompositionOwnerNetwork');same(journals.owner,q.rows.journals,'ControlCompositionOwnerJournal');
  same(cleanup.owner,q.rows.cleanup,'ControlCompositionOwnerCleanup');need(recordCounts.owner===COMPOSITION_OWNER_SOURCE_LIMITS.recordCount,'ControlCompositionOwnerJournal');
 }
 const ownerCharge=sumCompositionCharges([plan.parts.packingOwner,charges.owner,journals.owner,cleanup.owner]);
 const ciCharge=sumCompositionCharges([...Object.entries(plan.parts).filter(([key])=>key!=='packingOwner').map(([,v])=>v),charges.ci,journals.ci,cleanup.ci]);
 if(plan.version===2)need(recordCounts.ci===34,'ControlCompositionRuntimeJournal');
 const result={version:plan.version,kind:'production-control-composition-funding',authority:false,planHash:plan.planHash,catalog:catalogs,
  recordCounts:copyNonrootJson(recordCounts),parts:{...plan.parts,ownerNetwork:charges.owner,ciNetwork:charges.ci,ownerJournal:journals.owner,ciJournal:journals.ci,
   ownerCleanup:copyNonrootJson(cleanup.owner),ciCleanup:copyNonrootJson(cleanup.ci)},ownerCharge,ciCharge,charge:sumCompositionCharges([ownerCharge,ciCharge])};
 return freeze({...result,fundingHash:hash(result)});
}
export function inspectProductionControlCompositionFunding(value,plan){
 const v=copyNonrootJson(value);
 const checked=describeProductionControlCompositionFunding({plan,catalog:v.catalog,
  cleanup:{owner:v.parts?.ownerCleanup,ci:v.parts?.ciCleanup},recordCounts:v.recordCounts});
 same(v,checked,'ControlCompositionFundingChanged');return checked;
}

/** Call only after reserving the corresponding serialization/processing row.
 * Count escaped UTF-8 bytes and bounded nodes before allocating JSON output. */
export function encodeCompositionJson(value,maximum=33554432){
 let bytes=0,nodes=0;
 const add=n=>{bytes+=n;need(Number.isSafeInteger(bytes)&&bytes<=maximum,'ControlCompositionJsonBytes');};
 const string=s=>{add(2);for(let i=0;i<s.length;i++){
  const c=s.charCodeAt(i);
  if(c===34||c===92||[8,9,10,12,13].includes(c))add(2);
  else if(c<32)add(6);
  else if(c<128)add(1);
  else if(c<2048)add(2);
  else if(c>=0xd800&&c<=0xdbff&&s.charCodeAt(i+1)>=0xdc00&&s.charCodeAt(i+1)<=0xdfff){add(4);i++;}
  else if(c>=0xd800&&c<=0xdfff)add(6);else add(3);
 }};
 const visit=(v,depth)=>{
  need(depth<=64&&++nodes<=250000,'ControlCompositionJsonNodes');
  if(typeof v==='string')return string(v);
  if(v===null)return add(4);
  if(typeof v==='boolean')return add(v?4:5);
  if(typeof v==='number'){need(Number.isFinite(v),'ControlCompositionJsonNumber');return add(String(v).length);}
  need(v&&typeof v==='object'&&(Array.isArray(v)||Object.getPrototypeOf(v)===Object.prototype||Object.getPrototypeOf(v)===null),'ControlCompositionJsonValue');
  add(2);let first=true;
  for(const k of Object.keys(v)){
   if(!first)add(1);first=false;
   if(!Array.isArray(v)){string(k);add(1);}
   const d=Object.getOwnPropertyDescriptor(v,k);need(d&&Object.hasOwn(d,'value'),'ControlCompositionJsonAccessor');visit(d.value,depth+1);
  }
  if(Array.isArray(v))need(Object.keys(v).length===v.length,'ControlCompositionJsonArray');
 };
 visit(value,0);const encoded=Buffer.from(JSON.stringify(value));need(encoded.length===bytes,'ControlCompositionJsonEncoding');return encoded;
}
