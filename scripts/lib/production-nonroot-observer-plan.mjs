import {OBSERVER_ACCOUNTING_V3,OBSERVER_ACCOUNTING_LOCAL,OBSERVER_RESOURCE_READS,OBSERVER_RESOURCE_READ_LOCAL,observerAccountingJournalRecords,observerCaseVersion,inspectObserverAccounting,observerBackendAdmissionId,observerBackendAdmissionWork,observerVerificationCaptures} from './production-nonroot-observer-accounting.mjs';
/** Portable original observer plan and quote arithmetic. Every identity,
 * pathname and generated catalog arrives as authenticated caller DATA. This
 * module does not read paths, load source, create owners or dispatch providers.
 * Its returned quote is DATA; the source verifier must bind sourceModel first.
 */
import {types} from 'node:util';
import {need,exact,hash,ref,canonical,counter,zero,add,local,json} from './production-nonroot-engineering-json.mjs';
import {IMAGE_TRANSITION_LIMITS as IMAGE_LIMITS} from './production-image-transition.mjs';
import {bindObserverReplayWork} from './production-nonroot-observer-archive-reader.mjs';
const CAPS=Object.freeze({ecrRequests:IMAGE_LIMITS.maxEcrCalls,logicalBytes:IMAGE_LIMITS.maxTransferredBytes,httpBodyBytes:IMAGE_LIMITS.maxTransferredBytes,uncompressedBytes:IMAGE_LIMITS.maxUncompressedBytes,processedEntries:IMAGE_LIMITS.maxFsEntries});
export const OBSERVER_PLAN_RECOMPILE_ENTRY_LOCAL=16*4194304;
export const OBSERVER_PLAN_RECOMPILE_NODE_LOCAL=128;
export const OBSERVER_PLAN_RECOMPILE_ROW_LOCAL=4096;
const OBSERVER_TOOL_CHECK_LOCAL=32*4096,OBSERVER_TOOL_CHUNK_BYTES=65536;
function observerToolInitialLocal(bytes){
 need(Number.isSafeInteger(bytes)&&bytes>0,'ObserverToolBytes');
 // read + hash + buffer retirement + reserve for copies; one bounded buffer,
 // and 256 units per chunk for loop/owner/metadata bookkeeping.
 const n=4*bytes+4*OBSERVER_TOOL_CHUNK_BYTES+256*Math.ceil(bytes/OBSERVER_TOOL_CHUNK_BYTES);
 need(Number.isSafeInteger(n)&&n+OBSERVER_TOOL_CHECK_LOCAL<=CAPS.logicalBytes,'ObserverToolOriginalCapacity');
 return n;
}
/** Fixed work description for the original local CONTROL collector.
 * No Docker command, clock, source callback or authority is created here. */
const OBSERVER_CONTROL_RUNTIME_STAGES=Object.freeze(['inspect-root','inspect-platform','create','inspect-created','start','inspect-exited']);
const OBSERVER_CONTROL_RUNTIME_CLEANUP=Object.freeze(['remove','inspect-removed']);
const OBSERVER_CONTROL_RUNTIME_BOUNDS=Object.freeze({normalCommands:6,cleanupCommands:2,argumentBytes:131072,cleanupArgumentBytes:4096,outputBytes:1048576,probeBytes:65536,paths:512,pathBytes:4096,probeOutputBytes:262144,collectorMs:120000,cleanupReserveMs:25000});
const keys=['buildBytes','graphJsonBytes','graphNodes','entriesBytes','entryNodes','artifactLookups'];
function quoteObserverControlRuntimeWork(g){
 exact(g,keys);for(const k of keys)need(Number.isSafeInteger(g[k])&&g[k]>0,'ObserverControlRuntimeGeometry');
 need(g.buildBytes<=33554432&&g.entriesBytes<=33554432&&g.entryNodes<=1000000,'ObserverControlRuntimeGeometry');
 const b=OBSERVER_CONTROL_RUNTIME_BOUNDS,lookups=g.artifactLookups+4;
 // Preflight: build validation/copy, graph views, artifact file lookups,
 // filesystem hash/copy and path-plan construction. Physical config reads
 // and original proof-record reads still debit the existing cache/proof rows.
 const preflight=64*g.buildBytes+64*g.graphJsonBytes+1024*g.graphNodes+64*g.entriesBytes*lookups+128*g.entryNodes*lookups;
 const normal=preflight+b.normalCommands*(32*b.argumentBytes+64*b.outputBytes+65536)+64*b.probeBytes+32*b.probeOutputBytes+16*b.paths*b.pathBytes;
 const cleanup=b.cleanupCommands*(32*b.cleanupArgumentBytes+64*b.outputBytes+65536)+65536;
 need([preflight,normal,cleanup].every(n=>Number.isSafeInteger(n)&&n>0),'ObserverControlRuntimeWorkOverflow');
 return Object.freeze({authority:false,preflightLocal:preflight,normal:{...zero(),logicalBytes:normal},cleanup:{...zero(),logicalBytes:cleanup}});
}
const L=Object.freeze({headerBytes:33554432,recordBytes:65536,manifestBytes:16777216,recordCount:40000,cleanupRecords:64,materialFiles:8192,maxNodes:2176,graphBytes:536870912,inputBytes:67108864,metadataBytes:33554432});
function inspectAcquisitionReference(a){
 exact(a,['headerRef','terminalRef','manifestRef','recordCount','recordBytes','rawCount','rawBytes']);for(const k of ['headerRef','terminalRef','manifestRef'])ref(a[k]);
 need(a.headerRef.bytesLength>0&&a.headerRef.bytesLength<=L.headerBytes&&a.terminalRef.bytesLength>0&&a.terminalRef.bytesLength<=L.recordBytes&&a.manifestRef.bytesLength>0&&a.manifestRef.bytesLength<=L.manifestBytes,'AcquisitionReferenceBound');
 for(const k of ['recordCount','recordBytes','rawCount','rawBytes'])need(Number.isSafeInteger(a[k])&&a[k]>=0,'AcquisitionReferenceBound');
 need(a.recordCount>0&&a.recordCount<=L.recordCount+L.cleanupRecords&&a.recordBytes<=a.recordCount*L.recordBytes&&a.rawCount>0&&a.rawCount<=L.materialFiles+L.maxNodes+512&&a.rawBytes<=L.graphBytes+L.inputBytes+8*33554432+L.metadataBytes,'AcquisitionReferenceBound');return a;
}
const OFFLINE_RECIPE_LIMITS=Object.freeze({readsPerRef:64});
/** New D work only. Historical A/B quotes and spent rows are untouched. */

const REHEARSAL_CURRENT_LOCAL=32*4096;
function quoteObserverAcquisitionReplay(value){
 exact(value,['acquisition','expectedBytes','expectedHash']);
 const a=inspectAcquisitionReference(value.acquisition);
 need(Number.isSafeInteger(value.expectedBytes)&&value.expectedBytes>0&&value.expectedBytes<=8388608,'ObserverRehearsalExpectedBound');
 need(/^[a-f0-9]{64}$/.test(value.expectedHash),'ObserverRehearsalExpectedBinding');
 const auditBytes=a.headerRef.bytesLength+a.manifestRef.bytesLength+a.recordBytes+a.rawBytes;
 const files=a.recordCount+a.rawCount+2;
 // Original audit:20 passes/read bytes, independent body validation and the
 // original32-pass quote. Additional snapshot/check work is separately paid.
 // A short successful native read can return one byte: use the actual
 // source-bound worst case, not ceil(bytes/chunk) without a full-read rule.
 const currentChecks=4*auditBytes+64*files+128;
 const normalLocal=32*auditBytes+16384*(files+14)+16*value.expectedBytes+REHEARSAL_CURRENT_LOCAL*currentChecks;
 const cleanupLocal=REHEARSAL_CURRENT_LOCAL*files;
 need([auditBytes,currentChecks,normalLocal,cleanupLocal].every(Number.isSafeInteger),'ObserverRehearsalWorkOverflow');
 return Object.freeze({authority:false,auditBytes,files,currentChecks,normal:local(normalLocal),cleanup:local(cleanupLocal)});
}


/** The original replay multiplicity is retained. Full original raw bodies,
 * CI decoding and every source parse are separate from acquisition custody. */
const CAPTURE_REPLAY_LIMITS=Object.freeze({localBytes:1073741824,dockerbuildBytes:33554432,tarBytes:134217728,entries:256});
function quoteObserverRehearsalCiWork(g,version=3){
 need([1,2,3].includes(version),'ObserverRehearsalCiVersion');
 exact(g,['acquisition','envelopeBytes','sourceFiles','sourceBytes']);
 const a=inspectAcquisitionReference(g.acquisition),repeats=OFFLINE_RECIPE_LIMITS.readsPerRef;
 for(const k of ['envelopeBytes','sourceFiles','sourceBytes'])need(Number.isSafeInteger(g[k])&&g[k]>0,'ObserverRehearsalCiGeometry');
 need(g.envelopeBytes<=33554432&&g.sourceBytes<=33554432&&g.sourceFiles<=20000,'ObserverRehearsalCiGeometry');
 const reads=repeats*a.rawCount,readBytes=repeats*a.rawBytes,sourceCalls=repeats*g.sourceFiles,sourceReadBytes=repeats*g.sourceBytes;
 // Source parser tariff: three original (20B+69632) passes per source read.
 // Contexts and general envelope validation keep their full original bounds.
 const ciLocal=64*g.envelopeBytes+3*(8*33554432+32*1000000)+60*sourceReadBytes+3*69632*sourceCalls;
 // Legacy archive reconstruction retains its original formula and fields.
 if(version!==3){
  const currentChecks=4*readBytes+64*reads+8*sourceCalls+4096;
  const normalLocal=32*readBytes+16384*reads+ciLocal+134217728+REHEARSAL_CURRENT_LOCAL*currentChecks;
  const cleanupLocal=reads*REHEARSAL_CURRENT_LOCAL;
  need([reads,readBytes,sourceCalls,sourceReadBytes,ciLocal,currentChecks,normalLocal,cleanupLocal].every(Number.isSafeInteger),'ObserverRehearsalCiOverflow');
  return Object.freeze({authority:false,repeats,reads,readBytes,sourceCalls,sourceReadBytes,currentChecks,normal:local(normalLocal),cleanup:local(cleanupLocal)});
 }
 // One captured artifact decode: ZIP member plus every tar header. The
 // original three capture-time passes are not executed by this CI traversal.
 // Every replay body keeps the original 4B+4096 capture wrapper charge.
 // Reference indexing is paid before building maps from the authenticated A.
 const capture={referenceIndexLocal:32*a.manifestRef.bytesLength+65536,
  readLocal:4*readBytes+4096*reads,decoderLocal:CAPTURE_REPLAY_LIMITS.localBytes,
  uncompressedBytes:CAPTURE_REPLAY_LIMITS.dockerbuildBytes+CAPTURE_REPLAY_LIMITS.tarBytes,
  processedEntries:CAPTURE_REPLAY_LIMITS.entries+1};
 const captureCurrentChecks=16*reads+4*(CAPTURE_REPLAY_LIMITS.entries+32)+16;
 const currentChecks=4*readBytes+64*reads+8*sourceCalls+4096+captureCurrentChecks;
 const normalLocal=32*readBytes+16384*reads+ciLocal+134217728+capture.referenceIndexLocal+capture.readLocal+capture.decoderLocal+REHEARSAL_CURRENT_LOCAL*currentChecks;
 const cleanupLocal=reads*REHEARSAL_CURRENT_LOCAL;
 need([reads,readBytes,sourceCalls,sourceReadBytes,ciLocal,currentChecks,normalLocal,cleanupLocal].every(Number.isSafeInteger),'ObserverRehearsalCiOverflow');
 return Object.freeze({authority:false,repeats,reads,readBytes,sourceCalls,sourceReadBytes,currentChecks,capture:Object.freeze(capture),normal:{...local(normalLocal),uncompressedBytes:capture.uncompressedBytes,processedEntries:capture.processedEntries},cleanup:local(cleanupLocal)});
}


/** Complete conservative work for one loader, one prerequisites collector,
 * all five fixed guard cases and one path observation. No old work credit. */
function quoteObserverRehearsalNativeWork(g){
 exact(g,['rawBytes','nodes','uncompressedBytes','processedEntries','observation']);
 for(const k of ['rawBytes','nodes','uncompressedBytes','processedEntries'])need(Number.isSafeInteger(g[k])&&g[k]>0,'ObserverRehearsalNativeGeometry');
 const observation=quoteObserverControlRuntimeWork(g.observation);
 const framing=g.nodes*1536+32768,archiveBytes=g.rawBytes+framing;
 // Native read() may return short chunks. Retain a source-derived bound on
 // every consuming-frame check; never assume one read per64KiB request.
 const currentChecks=8*g.rawBytes+128*g.nodes+32*g.observation.artifactLookups+4096;
 const loader=16*g.rawBytes+8*archiveBytes+16*framing+3*(64*1048576+32*16384+65536)+2*g.uncompressedBytes;
 // Runtime and prerequisites each have six normal/two cleanup commands;
 // every guard case uses no more than that complete command/parse envelope.
 // Two eight-command collectors and five seven-command guard cases.
 // Raw command/body retention is new performed work; archive store I/O stays
 // separately priced by the original material rows, including empty stderr.
 const commandCount=2*8+5*7,retentionLocal=commandCount*(16*(1048576+131072)+16384);
 const normalLocal=loader+7*observation.normal.logicalBytes+currentChecks*REHEARSAL_CURRENT_LOCAL+retentionLocal;
 const cleanupLocal=7*observation.cleanup.logicalBytes+3*(64*1048576+32*16384+65536)+4096*REHEARSAL_CURRENT_LOCAL;
 need([archiveBytes,currentChecks,normalLocal,cleanupLocal].every(Number.isSafeInteger),'ObserverRehearsalNativeOverflow');
 return Object.freeze({authority:false,currentChecks,archiveBytes,commandCount,retentionLocal,
  normal:{...zero(),logicalBytes:normalLocal,uncompressedBytes:g.uncompressedBytes,processedEntries:g.processedEntries},
  cleanup:{...zero(),logicalBytes:cleanupLocal}});
}

function observerRunMaterialWork(geometry){
 need(Number.isSafeInteger(geometry.materialBytes)&&geometry.materialBytes>0,'ObserverRunMaterialGeometry');
 const logicalBytes=64*geometry.materialBytes+262144;
 need(Number.isSafeInteger(logicalBytes),'ObserverRunMaterialGeometry');return local(logicalBytes);
}

/** Case-scoped DATA. No clocks, authority, callbacks or provider operations. */
const OBSERVER_BACKEND_ROLES=Object.freeze(['llm-proxy','qwen3-embed','mnemo-server']);
function observerCaseRoles(c){return [...OBSERVER_BACKEND_ROLES,...c.runtimeRoles.filter(r=>['planner','executor'].includes(r))];}
function observerContractKey(caseName,role){return caseName+'/'+role;}
function observerCaseGeometry(p,caseName,role){
 const found=p.geometry.roles.filter(r=>r.role===role&&(p.version===1||r.caseName===caseName));
 need(found.length===1,'ObserverCaseRoleGeometry');return found[0];
}
function observerCompileId(p,r){return observerCaseVersion(p)?r.caseName+'/compile/'+r.role:'compile/'+r.role;}
function observerLaunchId(p,r,index){return observerCaseVersion(p)?r.caseName+'/launch/'+r.role+'/'+index:'launch/'+r.role+'/'+index;}
const {observerArchiveIndexWork}=(()=>{
const integer=n=>Number.isSafeInteger(n)&&n>=0;
function observerArchiveIndexWork(records){
 need(integer(records)&&records>0,'ObserverArchiveIndexRecords');
 // JSON row {bytesLength,sha256}: <=112 bytes including its delimiter.
 // 64KiB covers the exact header, even a maximally escaped4096-byte path.
 const bytes=65536+128*records,nodes=3*records+16;
 need(Number.isSafeInteger(bytes)&&bytes<=33554432&&nodes<=1000000,'ObserverArchiveIndexBound');
 return {bytes,nodes,localBytes:128*records+65536+32*nodes};
}

return {observerArchiveIndexWork};
})();
const {quoteObserverLogPages}=(()=>{
const positive=n=>Number.isSafeInteger(n)&&n>0;
function limits(g){
 exact(g,['rawPageBytes','logPolls','logPages','logEvents','maxMessageBytes','captures']);
 for(const n of Object.values(g))need(positive(n),'ObserverLogGeometry');
 need(g.rawPageBytes<=33554432&&g.logPolls<=1024&&g.logPages<=100&&g.logEvents<=1000000&&g.maxMessageBytes<=1048576&&g.captures<=1000,'ObserverLogGeometry');
 return g;
}
function quoteObserverLogPages(input){
 const g=limits(input),pages=g.logPolls*g.logPages,bytes=pages*g.rawPageBytes;
 // Page UTF8/duplicate-key parse/canonical walk, secret screening, event and
 // provenance hashing, original/normalized frame copies, decoder scan and
 // base64/hash work. Finish owns every full 1MiB capture allocation/hash,
 // 514 retained parts and worst-case capture ordering comparisons.
 const maxGuardCalls=3*pages+4,guardLocal=maxGuardCalls*16384;
 const logicalBytes=guardLocal+8192+128*bytes+g.logEvents*8192+g.captures*(16*1048576+514*4096)+g.captures*g.captures*256;
 need(Number.isSafeInteger(logicalBytes),'ObserverLogQuoteOverflow');
 return {logicalBytes,pages,rawBytes:bytes,captures:g.captures,maxGuardCalls,guardLocal};
}

return {quoteObserverLogPages};
})();
const {observerControlLogGeometry,quoteObserverControlLogs}=(()=>{
const CONTROL_OUTPUT_BYTES=65536;
function limits(g){
 exact(g,['rawPageBytes','logPages','logEvents','maxMessageBytes']);
 for(const k of Object.keys(g))need(Number.isSafeInteger(g[k])&&g[k]>0,'ObserverControlLogGeometry');
 need(g.rawPageBytes<=33554432&&g.logPages<=100&&g.logEvents<=1000000&&g.maxMessageBytes<=1048576,'ObserverControlLogGeometry');return g;
}
function observerControlLogGeometry(g){
 // The fixed CONTROL JSON output has a 64KiB source bound. The unrelated DATA frame
 // maximum (usually4096) must not truncate or reject the complete CONTROL record.
 return {rawPageBytes:g.rawPageBytes,logPages:g.control.logPages,logEvents:g.logEvents,maxMessageBytes:CONTROL_OUTPUT_BYTES};
}
function quoteObserverControlLogs(geometry){
 const g=limits(geometry),maxGuardCalls=2*g.logPages+4;
 // Complete raw-page parse, duplicate/event hashes and message copies;
 // full task descriptor, delivery schema/hash, 64KiB output and embedded
 // metadata/JWKS reconstruction, records/counters/protocol replay and copies.
 const logicalBytes=128*(g.rawPageBytes*(g.logPages+1)+262144+CONTROL_OUTPUT_BYTES)+g.logEvents*8192+21*65536+maxGuardCalls*16384;
 need(Number.isSafeInteger(logicalBytes),'ObserverControlLogQuote');return {logicalBytes,maxGuardCalls,rawBytes:g.rawPageBytes*g.logPages};
}

return {observerControlLogGeometry,quoteObserverControlLogs};
})();

function clonePaid(value,debit){
 let nodes=0;const active=new Set();
 const text=v=>{debit(8*v.length+32);need(v.isWellFormed(),'Utf8');return v;};
 const copy=(v,depth)=>{
  debit(OBSERVER_PLAN_RECOMPILE_NODE_LOCAL);need(++nodes<=1000000&&depth<=64,'DataBound');
  if(v===null||typeof v==='boolean')return v;
  if(typeof v==='number'){need(Number.isSafeInteger(v),'Integer');return v;}
  if(typeof v==='string')return text(v);
  need(v&&typeof v==='object'&&!types.isProxy(v)&&!active.has(v),'Data');active.add(v);
  const d=Object.getOwnPropertyDescriptors(v);let next;
  if(Array.isArray(v)){
   need(Object.getPrototypeOf(v)===Array.prototype&&Reflect.ownKeys(d).length===v.length+1,'Data');next=[];
   for(let i=0;i<v.length;i++){need(d[i]?.enumerable&&Object.hasOwn(d[i],'value'),'Data');next.push(copy(d[i].value,depth+1));}
  }else{
   exact(v,Object.keys(d));next={};
   for(const k of Object.keys(d)){text(k);Object.defineProperty(next,k,{value:copy(d[k].value,depth+1),enumerable:true,writable:true,configurable:true});}
  }
  active.delete(v);return next;
 };
 return copy(value,0);
}

function observerSourceArchiveWork(plan){
 const g=plan.geometry;
 need([g.materialBytes,g.materialRecords,g.sourcePassLocal].every(n=>Number.isSafeInteger(n)&&n>0),'ObserverSourceArchiveGeometry');
 const modelLocal=16*g.materialBytes+4096*g.materialRecords+262144;
 const originalReadLocal=16*g.materialBytes+4096*g.materialRecords;
 const logicalBytes=g.sourcePassLocal+modelLocal+originalReadLocal;
 need([modelLocal,originalReadLocal,logicalBytes].every(Number.isSafeInteger),'ObserverSourceArchiveWork');
 return {modelLocal,originalReadLocal,charge:local(logicalBytes)};
}


function compiler(sourceModel,debit){
 exact(sourceModel,['hostCatalogPath','packageCatalogJson','parserFiles','baseRoleArn']);
 need(typeof sourceModel.hostCatalogPath==='string'&&sourceModel.hostCatalogPath.startsWith('/')&&!sourceModel.hostCatalogPath.split('/').includes('..'),'ObserverHostCatalogRequired');
 need(typeof sourceModel.baseRoleArn==='string'&&/^arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9_+=,.@/-]+$/.test(sourceModel.baseRoleArn),'ObserverOriginalRole');
 const OBSERVER_PACKAGE_CATALOG_JSON=sourceModel.packageCatalogJson;
 need(typeof OBSERVER_PACKAGE_CATALOG_JSON==='string','ObserverPackageCatalogSize');
 const packageBytes=Buffer.byteLength(OBSERVER_PACKAGE_CATALOG_JSON);need(packageBytes>0&&packageBytes<=33554432,'ObserverPackageCatalogSize');
 debit(64*packageBytes+65536);const catalog=json(Buffer.from(OBSERVER_PACKAGE_CATALOG_JSON),33554432);
 need(catalog.version===1&&catalog.kind==='reviewed-host-package-subgraph'&&catalog.authority===false&&catalog.completeHostClosure===false,'ObserverPackageCatalog');
 for(const k of ['files','bindings','fileBindings','literalRequires','esmEdges'])need(Array.isArray(catalog[k]),'ObserverPackageCatalog');
 let fileBytes=0;for(const f of catalog.files){ref(f);need(f.bytesLength>0&&f.bytesLength<=33554432,'ObserverSourceReadBound');fileBytes+=f.bytesLength;}
 const OBSERVER_PACKAGE_CATALOG_LOCAL=16*packageBytes+8*fileBytes+1024*(catalog.literalRequires.length+catalog.esmEdges.length+catalog.fileBindings.length+catalog.bindings.length)+65536;
 need(Number.isSafeInteger(OBSERVER_PACKAGE_CATALOG_LOCAL),'ObserverPackageCatalogSize');
 need(Array.isArray(sourceModel.parserFiles)&&sourceModel.parserFiles.length>0,'ObserverHostParserBinding');
 let parserBytes=0;for(const p of sourceModel.parserFiles){exact(p,['path','sha256','bytes']);ref({path:p.path,sha256:p.sha256,bytesLength:p.bytes});parserBytes+=p.bytes+1;}
 const SOURCE_DEPENDENCY_PARSER_LOCAL=3*parserBytes;need(Number.isSafeInteger(SOURCE_DEPENDENCY_PARSER_LOCAL),'ObserverHostQuote');
 const OBSERVER_HOST_CATALOG=sourceModel.hostCatalogPath;
 const observerHostSyntaxLocal=bytes=>{need(Number.isSafeInteger(bytes)&&bytes>=0&&bytes<=33554432,'ObserverHostSourceBound');return 48*bytes+131072;};
 function describeObserverCompleteSourceRead(manifest){
  const rows=new Map(catalog.files.map(r=>[r.path,r]));
  for(const r of manifest.files){const prior=rows.get(r.path);need(!prior||prior.sha256===r.sha256&&prior.bytesLength===r.bytesLength,'ObserverPackageManifestMismatch');rows.set(r.path,r);}
  const files=[...rows.values()];let total=0;
  for(const r of files){need(Number.isSafeInteger(r.bytesLength)&&r.bytesLength>0&&r.bytesLength<=33554432,'ObserverSourceReadBound');total+=4*r.bytesLength+16*4096;}
  need(Number.isSafeInteger(total),'ObserverSourceReadQuote');return {files,logicalBytes:8*packageBytes+65536+total};
 }
function observerHostClosureQuote(manifest){
 const catalog=manifest.files.find(r=>r.path===OBSERVER_HOST_CATALOG);need(catalog,'ObserverHostCatalogRequired');
 const rows=manifest.files.filter(r=>r.path!==OBSERVER_HOST_CATALOG);
 const syntaxLocal=rows.reduce((n,r)=>n+observerHostSyntaxLocal(r.bytesLength),0);
 const bindingLocal=16*(catalog.bytesLength+Buffer.byteLength(OBSERVER_PACKAGE_CATALOG_JSON)+Buffer.byteLength(JSON.stringify(manifest)))+65536;
 const logicalBytes=syntaxLocal+SOURCE_DEPENDENCY_PARSER_LOCAL+bindingLocal;
 need(Number.isSafeInteger(logicalBytes),'ObserverHostQuote');return {authority:false,logicalBytes,syntaxLocal,bindingLocal,parserLocal:SOURCE_DEPENDENCY_PARSER_LOCAL,files:rows.length};
}

const OBSERVER_CASES=Object.freeze(['successful-handover','prefix-start-failure','sidecar-readiness-failure','post-liveness-regression','nonterminal-timeout']);
// The fixed known-refusal transport charges16*8192 before retaining a known refusal.
// It is additional to request/body/source work and conveys no auth success.
const OBSERVER_KNOWN_FAILURE_LOCAL=131072;
// Only a fresh explicit policy pays this incremental authorization work.
// Its exact three-field envelope occupies <=128 JSON bytes; changing the
// capacity can add <=16 decimal bytes. Eight bounded passes cover schema,
// five existing whole-plan hash/clone sites, limit binding, and retirement.
// Later prepayments use the already bound limits, without decoding policy.
const OBSERVER_PROCESSING_POLICY_LOCAL=16*(128+16)*8;
const roles=['llm-proxy','qwen3-embed','mnemo-server','planner','executor'];
const integer=(n,min=0,max=Number.MAX_SAFE_INTEGER)=>Number.isSafeInteger(n)&&n>=min&&n<=max;
const local=n=>({...zero(),logicalBytes:n});
const h=(s,n=64)=>typeof s==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(s);
const positive=(n,max=Number.MAX_SAFE_INTEGER)=>need(integer(n,1,max),'ObserverPlanBound');
function inspectObserverPlan(p){
 need(p&&typeof p==='object'&&!types.isProxy(p),'Fields');
 const fresh=Object.hasOwn(p,'processingPolicy');
 exact(p,['version','kind','owner','operation','ownerRef','inputsRef','startedMs','deadlineMs','cleanupReserveMs','capacity','source','geometry','scope','cases',...(p.version===3?['accounting']:[]),...(fresh?['processingPolicy']:[])]);
 need([1,2,3].includes(p.version)&&p.kind==='original-data-observer-operation'&&h(p.owner,32)&&h(p.operation,32),'ObserverPlanKind');inspectObserverAccounting(p);
 for(const r of [p.ownerRef,p.inputsRef]){ref(r);positive(r.bytesLength,33554432);}need(p.ownerRef.bytesLength<=65536,'ObserverOwnerBound');
 positive(p.startedMs);need(integer(p.deadlineMs,p.startedMs+1,p.startedMs+7200000)&&integer(p.cleanupReserveMs,1000,60000)&&p.deadlineMs-p.startedMs>p.cleanupReserveMs,'ObserverPlanClock');
 let processingLimit=CAPS.logicalBytes;
 if(fresh){
  need(observerCaseVersion(p),'ObserverProcessingPolicy');
  exact(p.processingPolicy,['version','kind','maximumLocal']);
  const policy=p.processingPolicy;
  need(policy.version===2&&policy.kind==='source-quoted-cumulative-processing'&&integer(policy.maximumLocal,1),'ObserverProcessingPolicy');
  processingLimit=policy.maximumLocal;
 }
 counter(p.capacity);need(Object.keys(CAPS).every(k=>p.capacity[k]<=(k==='logicalBytes'?processingLimit:CAPS[k])),'ObserverOriginalCapacity');
 exact(p.source,['files','roots','node','versions','env']);need(Array.isArray(p.source.files)&&p.source.files.length>0&&p.source.files.length<=20000&&new Set(p.source.files.map(r=>r.path)).size===p.source.files.length,'ObserverSourceManifest');
 for(const r of p.source.files){ref({path:r.path,sha256:r.sha256,bytesLength:r.bytesLength});positive(r.bytesLength,33554432);need(integer(r.mode,0,511)&&integer(r.uid),'ObserverSourceMetadata');}
 const node=p.source.node;ref({path:node.path,sha256:node.sha256,bytesLength:node.bytesLength});observerToolInitialLocal(node.bytesLength);need(integer(node.mode,0,511)&&integer(node.uid)&&!p.source.files.some(r=>r.path===node.path),'ObserverToolReference');
 need(Array.isArray(p.source.roots)&&p.source.roots.length>0&&p.source.roots.every(path=>p.source.files.some(f=>f.path===path)),'ObserverSourceRoots');
 exact(p.scope,['account','personalAccount','region','stsRegion','clusterArn','taskRoleArns','logGroupArns','rootParameterArn','discoveryServiceArns','sourceCredentialsRef','sourceExpiresMs','baseRoleArn']);
 need(/^\d{12}$/.test(p.scope.account)&&/^\d{12}$/.test(p.scope.personalAccount)&&p.scope.account!==p.scope.personalAccount,'ObserverAccountBoundary');
 for(const r of [p.scope.region,p.scope.stsRegion])need(/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(r),'ObserverRegion');
 need(p.scope.baseRoleArn===sourceModel.baseRoleArn&&p.scope.baseRoleArn.startsWith('arn:aws:iam::'+p.scope.account+':role/')&&p.scope.clusterArn.startsWith('arn:aws:ecs:'+p.scope.region+':'+p.scope.account+':cluster/'),'ObserverOriginalRole');
 ref(p.scope.sourceCredentialsRef);need(p.scope.sourceCredentialsRef.bytesLength<=65536&&p.scope.sourceExpiresMs>=p.deadlineMs,'ObserverSourceLifetime');
 for(const [name,service]of [['taskRoleArns','iam'],['logGroupArns','logs'],['discoveryServiceArns','servicediscovery']]){
  need(Array.isArray(p.scope[name])&&p.scope[name].length>0&&p.scope[name].length<=32&&new Set(p.scope[name]).size===p.scope[name].length,'ObserverScope');
  for(const arn of p.scope[name])need(typeof arn==='string'&&arn.startsWith('arn:aws:'+service+':')&&arn.includes(':'+p.scope.account+':')&&!/[?*]/.test(arn),'ObserverScope');
 }
 need(typeof p.scope.rootParameterArn==='string'&&p.scope.rootParameterArn.startsWith('arn:aws:ssm:'+p.scope.region+':'+p.scope.account+':parameter/')&&!/[?*]/.test(p.scope.rootParameterArn),'ObserverRootScope');
 exact(p.geometry,['sourcePassLocal','sourcePreparation','roles','cache','prerequisiteReplay','materialBytes','materialRecords','rawPageBytes','listPages','taskLimit','logPages','logPolls','logEvents','maxMessageBytes','issuerSourceBytes','contextSourceBytes',...(p.version===3?['admission','admissionCleanup']:[]),...(p.geometry.control?['control']:[])]);
 const g=p.geometry;if(p.version===3){counter(g.admission);counter(g.admissionCleanup);need(g.admission.logicalBytes>0&&g.admissionCleanup.logicalBytes>0,'ObserverResourceAdmissionQuote');}for(const k of ['sourcePassLocal','materialBytes','materialRecords','rawPageBytes','listPages','taskLimit','logPages','logPolls','logEvents','maxMessageBytes','issuerSourceBytes','contextSourceBytes'])positive(g[k]);
 need(g.rawPageBytes<=33554432&&g.listPages<=100&&g.taskLimit<=10000&&g.logPages<=100&&g.logPolls<=1024&&g.logEvents<=1000000&&g.maxMessageBytes<=1048576,'ObserverWireBounds');
 counter(g.sourcePreparation);counter(g.cache);counter(g.prerequisiteReplay);
 if(g.control){
  const rehearsalKeys=['rehearsalAcquisition','rehearsalCi','rehearsalNative'];
  exact(g.control,['source','cache','proof','runtime','rawDeliveryBytes','compressedDeliveryBytes','taskPolls','logPages',...(Object.hasOwn(g.control,'observation')?['observation']:[]),...rehearsalKeys.filter(k=>Object.hasOwn(g.control,k))]);
  if(Object.hasOwn(g.control,'observation'))quoteObserverControlRuntimeWork(g.control.observation);
  if(rehearsalKeys.some(k=>Object.hasOwn(g.control,k))){
   need(rehearsalKeys.every(k=>Object.hasOwn(g.control,k))&&g.control.observation,'ObserverRehearsalCompleteQuote');
   quoteObserverAcquisitionReplay(g.control.rehearsalAcquisition);quoteObserverRehearsalCiWork(g.control.rehearsalCi,p.version);quoteObserverRehearsalNativeWork(g.control.rehearsalNative);
   need(hash(g.control.rehearsalAcquisition.acquisition)===hash(g.control.rehearsalCi.acquisition)&&hash(g.control.observation)===hash(g.control.rehearsalNative.observation),'ObserverRehearsalQuoteBinding');
  }
  for(const k of ['source','cache','proof','runtime'])counter(g.control[k]);positive(g.control.rawDeliveryBytes,262144);positive(g.control.compressedDeliveryBytes,8192);positive(g.control.taskPolls,1024);positive(g.control.logPages,100);
 }
 need(Array.isArray(g.roles)&&(p.version===1?g.roles.length===5:g.roles.length>=17&&g.roles.length<=25)&&roles.every(role=>g.roles.some(r=>r.role===role)),'ObserverFiveRoles');
 for(const r of g.roles){
  const backend=['llm-proxy','qwen3-embed','mnemo-server'].includes(r.role),scoped=observerCaseVersion(p);
  const numeric=['inputBytes','compiledBytes','expandedBytes','compressedBytes','bootstrapBytes','files','fileBytes','episodes','snapshots','polls',...(p.version===3&&backend?[]:['executions']),...(scoped?['filesystemLookupLocal','targetContainerBytes']:[])];
  exact(r,['role',...numeric,...(scoped?['caseName','planHash','compiledHash']:[]),...(p.version===3?['executionScope']:[])]);
  for(const k of numeric)positive(r[k]);need(r.files<=256&&r.episodes<=1000&&(p.version===3&&backend||r.executions<=10000),'ObserverRoleGeometry');
  if(scoped)need(OBSERVER_CASES.includes(r.caseName)&&h(r.planHash)&&h(r.compiledHash),'ObserverCaseGeometryBinding');
  if(p.version===3)need(r.executionScope===(backend?'autonomous-service':'single-explicit-worker'),'ObserverRoleExecutionScope');
 }
 need(Array.isArray(p.cases)&&p.cases.length===5&&OBSERVER_CASES.every(name=>p.cases.some(c=>c.name===name)),'ObserverFiveCases');
 for(const c of p.cases){exact(c,['name','serviceName','family','startedMs','deadlineMs','sampleTimes','runtimeRoles','baselinePolls','cleanupPolls',...(g.control?['stage']:[]),...(observerCaseVersion(p)?['logPollTimes','definitionBytes']:[])]);
  if(g.control)need(/^pr-[1-9][0-9]*$/.test(c.stage),'ObserverCohortStage');
  need(c.serviceName==='mem9-observe-'+p.owner.slice(0,12)+'-'+(g.control?c.stage+'-':'')+c.name&&c.family===c.serviceName&&integer(c.startedMs,p.startedMs,p.deadlineMs-p.cleanupReserveMs)&&integer(c.deadlineMs,c.startedMs+1,p.deadlineMs-p.cleanupReserveMs),'ObserverCohortScope');
  need(Array.isArray(c.sampleTimes)&&c.sampleTimes.length>=2&&c.sampleTimes.length<=1024&&c.sampleTimes.every((t,i)=>integer(t,c.startedMs,c.deadlineMs)&&(!i||t>c.sampleTimes[i-1])),'ObserverSamples');
  need(Array.isArray(c.runtimeRoles)&&new Set(c.runtimeRoles).size===c.runtimeRoles.length&&c.runtimeRoles.every(r=>roles.includes(r)),'ObserverRuntimeRoles');
  positive(c.baselinePolls,1024);positive(c.cleanupPolls,1024);
 }
 if(observerCaseVersion(p)){
  need(g.control,'ObserverCompleteControlQuoteRequired');
  const keys=g.roles.map(r=>r.caseName+'/'+r.role),wanted=p.cases.flatMap(c=>observerCaseRoles(c).map(role=>c.name+'/'+role));
  need(keys.length===wanted.length&&new Set(keys).size===keys.length&&wanted.every(key=>keys.includes(key)),'ObserverCaseRoleCoverage');
  for(const [index,c]of p.cases.entries()){
   exact(c.definitionBytes,['baseline','control',...c.runtimeRoles.filter(r=>['planner','executor'].includes(r))]);for(const n of Object.values(c.definitionBytes))positive(n,33554432);
   need(index===0||c.startedMs>=p.cases[index-1].deadlineMs,'ObserverCaseScheduleOrder');
   need(Array.isArray(c.logPollTimes)&&c.logPollTimes.length===g.logPolls&&c.logPollTimes.every((t,i)=>integer(t,c.startedMs,c.deadlineMs)&&(!i||t>c.logPollTimes[i-1])),'ObserverCaseLogPollSchedule');
   if(['successful-handover','post-liveness-regression'].includes(c.name))need(['llm-proxy','qwen3-embed','mnemo-server'].every(r=>c.runtimeRoles.includes(r)),'ObserverRequiredCaseRuntime');
   for(const role of observerCaseRoles(c)){const r=observerCaseGeometry(p,c.name,role);need(['planner','executor'].includes(role)?r.executions===1:p.version===3?r.executionScope==='autonomous-service':r.executions>=g.taskLimit,'ObserverCaseExecutionCoverage');}
  }
 }
 const sourceRead=describeObserverCompleteSourceRead(p.source);
 const minimumSourcePass=sourceRead.logicalBytes+observerHostClosureQuote(p.source).logicalBytes+OBSERVER_TOOL_CHECK_LOCAL+OBSERVER_PACKAGE_CATALOG_LOCAL;
 need(g.sourcePassLocal>=minimumSourcePass,'ObserverSourceQuote');need(g.sourcePreparation.logicalBytes>=g.sourcePassLocal,'ObserverInitialSourceQuote');return p;
}

function quoteObserverOperation(input){return buildObserverOperation(input,false);}
/** Original owner preparation moves its existing single plan clone here.
 * Deep canonical validation precedes cloning, so no getter is invoked by
 * structuredClone. Rows are built once from that private snapshot; borrowed
 * counter references can no longer lead back to the caller's plan. */
function prepareObserverOwnerOperation(input){return buildObserverOperation(input,true);}
function buildObserverOperation(input,snapshot){
 let p=inspectObserverPlan(input);
 if(snapshot&&p.version===3)need(Object.hasOwn(p,'processingPolicy'),'ObserverAccountingProcessingPolicy');
 const planHash=hash(p);
 if(snapshot)p=structuredClone(p);
 const g=p.geometry,rows=[];
 const addRow=(id,charge,options={})=>{debit(OBSERVER_PLAN_RECOMPILE_ROW_LOCAL+128*(rows.length+1));counter(charge);need(!rows.some(r=>r.id===id),'ObserverDuplicateQuote');rows.push({id,charge,...options});};
 addRow('authorize',local(16*p.ownerRef.bytesLength+16*p.inputsRef.bytesLength+65536+(Object.hasOwn(p,'processingPolicy')?OBSERVER_PROCESSING_POLICY_LOCAL:0)+(p.version===3?OBSERVER_ACCOUNTING_LOCAL:0)));
 addRow('source-prepare',add(g.sourcePreparation,local(observerToolInitialLocal(p.source.node.bytesLength))));
 if(p.version===3){addRow('resource-admission',g.admission);addRow('resource-admission-cleanup',g.admissionCleanup,{cleanup:true});}
 addRow('cache',g.cache);
 addRow('prerequisite-replay',g.prerequisiteReplay);
 if(g.control){addRow('control-source',g.control.source);addRow('control-cache',g.control.cache);addRow('control-proof',g.control.proof);}
 if(g.control?.observation&&!g.control.rehearsalNative){const work=quoteObserverControlRuntimeWork(g.control.observation);addRow('control-observe',work.normal);addRow('control-observe-cleanup',work.cleanup,{cleanup:true});}
 if(g.control?.rehearsalAcquisition){
  const work=quoteObserverAcquisitionReplay(g.control.rehearsalAcquisition);
  addRow('control-A-authenticate',work.normal);addRow('control-A-authenticate-cleanup',work.cleanup,{cleanup:true});
  const ci=quoteObserverRehearsalCiWork(g.control.rehearsalCi,p.version),native=quoteObserverRehearsalNativeWork(g.control.rehearsalNative);
  addRow('control-A-ci',ci.normal);addRow('control-A-ci-cleanup',ci.cleanup,{cleanup:true});
  addRow('control-A-native',native.normal);addRow('control-A-native-cleanup',native.cleanup,{cleanup:true});
  addRow('run-material',observerRunMaterialWork(g));
  addRow('source-archive',observerSourceArchiveWork(p).charge);
 }
 for(const r of g.roles){
  // Enumerated buffers/passes: input inert copy+schema+normal+spec+hash,
  // fixed factory source assembly and compression, output/canonical binding.
  addRow(observerCompileId(p,r),local(8*r.inputBytes+8*r.expandedBytes+4*r.compressedBytes+8*r.compiledBytes+g.sourcePassLocal+(observerCaseVersion(p)?r.filesystemLookupLocal:0)));
  const loaderLocal=3*(8*r.bootstrapBytes+8*r.compressedBytes+12*r.expandedBytes);
  const gateLocal=3*(3*r.fileBytes+3*r.files+2*65537+262145);
  const rawLocal=r.episodes*268435456;
  const procCopies=r.snapshots*128*(2*4097+65537+2*16385+2*4097)*20;
  const polling=r.polls*(4097+128*(16385*8+4097))+r.snapshots*8192;
  const frames=r.episodes*(514*4096);
  // Node: one whole hash, disjoint per-part hash, and disjoint base64 input
  // reads. Buffer.subarray is a view, not 514 repeated whole-record scans.
  // Keep the existing wire/string/descriptor allowance and BusyBox's actual
  // repeated shell-string slicing. The full 1MiB record bound is unchanged.
  const framingLocal=16*frames+r.episodes*1048576*(r.role==='mnemo-server'?514:3);
  const busyboxGuard=r.role==='mnemo-server'?r.episodes*514*100*(4097+4096+256):0;
  if(p.version===3&&r.executionScope==='autonomous-service'){const work=observerBackendAdmissionWork(p,p.cases.find(c=>c.name===r.caseName));addRow(observerBackendAdmissionId(r),local(work.logicalBytes),{role:r.role,caseName:r.caseName,planHash:r.planHash,accounting:'host-observed-task-attribution'});}
  else for(let i=0;i<r.executions;i++)addRow(observerLaunchId(p,r,i),local(loaderLocal+gateLocal+rawLocal+procCopies+polling+framingLocal+busyboxGuard),{role:r.role,...(observerCaseVersion(p)?{caseName:r.caseName,planHash:r.planHash}: {})});
 }
 const sourcePass=g.sourcePassLocal;
 const call=(id,action,{cleanup=false,requestBytes=16384,responseBytes=g.rawPageBytes}={})=>{
  const serdeLocal=action==='Route'?0:32*responseBytes+65536;
  const resourceReadLocal=p.version===3&&Object.hasOwn(OBSERVER_RESOURCE_READS,id)?OBSERVER_RESOURCE_READ_LOCAL:0;
  addRow(id,{...zero(),httpBodyBytes:requestBytes+responseBytes,logicalBytes:sourcePass+8*requestBytes+32*responseBytes+serdeLocal+(action==='Route'?OBSERVER_KNOWN_FAILURE_LOCAL:0)+resourceReadLocal},{action,requestBytes,responseBytes,cleanup,...(serdeLocal?{serdeLocal}:{}),...(action==='Route'?{knownFailureLocal:OBSERVER_KNOWN_FAILURE_LOCAL}:{}),...(resourceReadLocal?{resourceReadLocal}:{})});
 };
 for(const purpose of ['read','setup','update','cleanup',...(g.control?['launch']:[])]){
  addRow('issuer-source/'+purpose,local(16*g.issuerSourceBytes+65536));
  for(const [index,action]of ['GetCallerIdentity','AssumeRole','GetCallerIdentity'].entries())call('issuer/'+purpose+'/'+index,action,{cleanup:purpose==='cleanup',requestBytes:65536,responseBytes:262144});
 }
 if(p.version===3)for(const [id,action]of Object.entries(OBSERVER_RESOURCE_READS))call(id,action,{requestBytes:16384,responseBytes:262144});
 let logReplayLocal=0;
 for(const c of p.cases){
  const key=c.name;
  const registration=(lane)=>observerCaseVersion(p)?{requestBytes:c.definitionBytes[lane]+4096+(lane==='baseline'?0:lane==='control'?0:observerCaseGeometry(p,key,lane).targetContainerBytes)}:{};
  call(key+'/register-baseline','RegisterTaskDefinition',registration('baseline'));
  call(key+'/register-target','RegisterTaskDefinition',observerCaseVersion(p)?{requestBytes:c.definitionBytes.baseline+4096+['llm-proxy','qwen3-embed','mnemo-server'].reduce((n,role)=>n+observerCaseGeometry(p,key,role).targetContainerBytes,0)}:{});call(key+'/create','CreateService');
  for(let i=0;i<c.baselinePolls;i++)call(key+'/baseline/'+i,'DescribeServices');
  call(key+'/baseline-definition','DescribeTaskDefinition');call(key+'/target-definition','DescribeTaskDefinition');call(key+'/discovery','GetService');call(key+'/update','UpdateService');
  if(g.control){
   call(key+'/register-control','RegisterTaskDefinition',registration('control'));call(key+'/control-definition','DescribeTaskDefinition');
   for(const role of c.runtimeRoles.filter(r=>['planner','executor'].includes(r))){
    call(key+'/register-'+role,'RegisterTaskDefinition',registration(role));call(key+'/'+role+'-definition','DescribeTaskDefinition');call(key+'/run-'+role,'RunTask');
    for(let i=0;i<g.control.taskPolls;i++)call(key+'/'+role+'-task/'+i,'DescribeTasks');
    call(key+'/stop-'+role,'StopTask',{cleanup:true});
   }
  }
  const samples=c.sampleTimes.length+1;
  for(let i=0;i<samples;i++){
   const prefix=key+'/sample/'+i;
   call(prefix+'/service','DescribeServices');call(prefix+'/root','GetParameter');
   for(const status of ['RUNNING','STOPPED'])for(let j=0;j<g.listPages;j++)call(prefix+'/list/'+status+'/'+j,'ListTasks');
   for(let j=0;j<Math.ceil(g.taskLimit/100);j++)call(prefix+'/tasks/'+j,'DescribeTasks');
   addRow(prefix+'/context',local(16*g.contextSourceBytes+32*65536+5*4096));
   if(g.control){
    addRow(key+'/control-prepare/'+i,local(g.sourcePassLocal+32*g.control.rawDeliveryBytes+16*g.control.compressedDeliveryBytes+262144));
    addRow(key+'/control-runtime/'+i,g.control.runtime);
    call(key+'/control-run/'+i,'RunTask',{requestBytes:65536});
    for(let poll=0;poll<g.control.taskPolls;poll++)call(key+'/control-task/'+i+'/'+poll,'DescribeTasks');
    for(let page=0;page<g.control.logPages;page++)call(key+'/control-log/'+i+'/'+page,'FilterLogEvents');
    call(key+'/control-stop/'+i,'StopTask',{cleanup:true});
   }else for(const route of ['private-unauth','private-auth','ingress-unauth','ingress-auth'])call(prefix+'/'+route,'Route',{requestBytes:65536,responseBytes:1048576});
  }
  if(key==='post-liveness-regression')call(key+'/fault-stop','StopTask');
  for(const role of c.runtimeRoles){
   const captures=observerCaseGeometry(p,c.name,role).episodes;
   const pageWork=quoteObserverLogPages({...Object.fromEntries(['rawPageBytes','logPolls','logPages','logEvents','maxMessageBytes'].map(k=>[k,g[k]])),captures});
   // Acquisition and independent proof replay each pay the complete parser
   // and decoder; provider raw-copy work is separate from both.
   addRow(key+'/log-work/'+role,local(pageWork.logicalBytes+8*pageWork.rawBytes));
   logReplayLocal+=pageWork.logicalBytes;
   for(let poll=0;poll<g.logPolls;poll++)for(let page=0;page<g.logPages;page++)call(key+'/log/'+role+'/'+poll+'/'+page,'FilterLogEvents');
  }
  call(key+'/delete-service','DeleteService',{cleanup:true});
  for(let i=0;i<c.cleanupPolls;i++){
   call(key+'/cleanup-service/'+i,'DescribeServices',{cleanup:true});
   for(const status of ['RUNNING','STOPPED'])for(let j=0;j<g.listPages;j++)call(key+'/cleanup-list/'+i+'/'+status+'/'+j,'ListTasks',{cleanup:true});
   for(let j=0;j<Math.ceil(g.taskLimit/100);j++)call(key+'/cleanup-tasks/'+i+'/'+j,'DescribeTasks',{cleanup:true});
  }
  for(const lane of ['baseline','target',...(g.control?['control',...c.runtimeRoles.filter(r=>['planner','executor'].includes(r))]:[])]){call(key+'/deregister/'+lane,'DeregisterTaskDefinition',{cleanup:true});call(key+'/delete-definition/'+lane,'DeleteTaskDefinitions',{cleanup:true});}
 }
 // Only this consumer's provider-copy calls belong to normal assembly.
 // Legacy Route uses its own request/context tickets, issuer uses issuer-source,
 // DATA log reads use log-work, and cleanup uses cleanup-assembly. Their API
 // rows remain in the quote; pricing them here again duplicated their work.
 const assemblyRows=rows.filter(r=>r.action&&!r.cleanup&&r.action!=='Route'&&!r.id.startsWith('issuer/')&&!r.id.includes('/log/'));
 const assemblyBytes=assemblyRows.reduce((n,r)=>n+r.requestBytes+r.responseBytes,0);
 const controlLogWork=g.control?p.cases.reduce((n,c)=>n+(c.sampleTimes.length+1)*quoteObserverControlLogs(observerControlLogGeometry(g)).logicalBytes,0):0;
 addRow('assembly',local(64*assemblyBytes+controlLogWork+g.sourcePassLocal+16*g.materialBytes));
 const cleanupBytes=rows.filter(r=>r.action&&r.cleanup&&!r.id.startsWith('issuer/')).reduce((n,r)=>n+r.requestBytes+r.responseBytes,0);
 addRow('cleanup-assembly',local(64*cleanupBytes+g.sourcePassLocal+16*g.materialBytes),{cleanup:true});
 addRow('archive',local(16*g.materialBytes+(4096+8*16384)*g.materialRecords+(observerCaseVersion(p)?observerArchiveIndexWork(g.materialRecords).localBytes:0)),{cleanup:true});
 // All raw page, exact stream/registration, frame, complete proc/file/source
 // and nested five-case replay is separate from capture and archive costs.
 const captures=observerVerificationCaptures(p);
 const decodeInput=p.cases.reduce((n,c)=>n+c.runtimeRoles.length,0)*g.logPolls*g.logPages*g.rawPageBytes;
 // CONTROL acquisition and archive replay each invoke the complete parser.
 // Provider response copying, archive IO and remote runtime slots remain separate.
 addRow('replay',local(logReplayLocal+controlLogWork+16*16384*g.materialRecords+32*g.materialBytes+32*decodeInput+64*captures*1048576+g.sourcePassLocal+g.roles.reduce((n,r)=>n+r.snapshots*128*(4*g.materialBytes+32768),0)));
 const journal={records:6*rows.length+64+observerAccountingJournalRecords(p,rows),recordBytes:65536};journal.charge=local(journal.records*(16*journal.recordBytes+4096));
 const total=add(journal.charge,...rows.map(r=>r.charge));
 if(Object.hasOwn(p,'processingPolicy'))need(total.logicalBytes===p.capacity.logicalBytes&&total.logicalBytes===p.processingPolicy.maximumLocal,'ObserverProcessingQuote');
 const quote={version:p.version===3?2:1,kind:p.version===3?'original-observer-host-verification-work':'original-observer-full-work',authority:false,...(p.version===3?{accounting:OBSERVER_ACCOUNTING_V3}:{}),planHash,rows,journal,total};
 return snapshot?{plan:p,quote}:quote;
}

return {inspectObserverPlan,quoteObserverOperation,prepareObserverOwnerOperation};
}

function invoke(mode,input,options){
 const paid=bindObserverReplayWork(options?.work),debit=n=>{paid.debit(n);paid.current();};
 debit(OBSERVER_PLAN_RECOMPILE_ENTRY_LOCAL);
 const plan=clonePaid(input,debit),sourceModel=clonePaid(options.sourceModel,debit);
 const api=compiler(sourceModel,debit),result=api[mode](plan);paid.current();
 return clonePaid(result,debit);
}
export const inspectNonrootObserverPlan=(plan,options)=>invoke('inspectObserverPlan',plan,options);
export const quoteNonrootObserverOperation=(plan,options)=>invoke('quoteObserverOperation',plan,options);
export const prepareNonrootObserverOperation=(plan,options)=>invoke('prepareObserverOwnerOperation',plan,options);
