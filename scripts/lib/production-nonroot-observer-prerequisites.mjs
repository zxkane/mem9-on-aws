/** Full original prerequisite replay over current authenticated DATA facts.
 * Entries remain complete archived metadata; no plain JSON becomes a live FS.
 * Every original raw/kernel/library/source check is repeated under this payer. */
import {resolve,dirname,posix} from 'node:path';
import {need,exact,same,hash,sha,immutable as freeze} from './production-nonroot-engineering-json.mjs';
import {inspectNonrootRecord,parseNonrootJson} from './production-nonroot-contracts.mjs';
import {parseImageTransitionJson} from './production-image-transition-proof.mjs';
import {compileDataProbePlan,inspectDataProbeOutput} from './production-nonroot-observer-primitives.mjs';
import {finalizationJsonSize} from './production-nonroot-observer-json-size.mjs';
import {scanArchivedObserverDependencies} from './production-nonroot-observer-source-syntax.mjs';
const SOURCE_DEPENDENCY_PARSER_LOCAL=3*(513214+1+1382+1);
function sourceDependencyQuote(rows,invocations=1){
 let inputBytes=0,parseCalls=0,processingLocalBytes=0;
 for(const row of rows)if(row.ref.path.endsWith('.mjs')){need(Number.isSafeInteger(row.bytes)&&row.bytes>=0&&row.bytes<=33554432,'SourceDependencyInputBound');inputBytes+=row.bytes;parseCalls++;processingLocalBytes+=20*row.bytes+69632;}
 const parserLocalBytes=parseCalls?SOURCE_DEPENDENCY_PARSER_LOCAL:0,logicalBytes=(processingLocalBytes+parserLocalBytes)*invocations;
 need(Number.isSafeInteger(logicalBytes),'SourceDependencyQuote');return freeze({version:1,authority:false,invocations,parseCalls,inputBytes,processingLocalBytes,parserLocalBytes,logicalBytes});
}
const names=['llm-proxy','mnemo-server','qwen3-embed'];
const counterKeys=['logicalBytes','ecrRequests','httpBodyBytes','uncompressedBytes','processedEntries'];
// The D owner's synchronous check includes named claim metadata reads. This
// retains the existing32*4096 metadata envelope per covered check; a cheaper
// C check retains its unused prepayment. It is not a zero-debit guard call.
export const DATA_PREREQUISITE_CALLER_CHECK_LOCAL=32*4096;
const refKey=ref=>hash(ref);
function originalCallerCheck(check){
 need(typeof check==='function','DataPrerequisiteOriginalCaller');
 return ()=>{const result=check();if(result&&typeof result.then==='function'){Promise.resolve(result).catch(()=>{});need(false,'DataPrerequisiteSynchronousCheck');}need(result===undefined,'DataPrerequisiteSynchronousCheck');};
}
function specification(value,roots){
 exact(value,['version','kind','authority','productionRuntimeObserved','inventoryHash','dataSourceTree','sourceClosure','originalResult','primitives','components','objects']);
 need(value.version===2&&value.kind==='original-data-prerequisite-source'&&value.authority===false&&value.productionRuntimeObserved===false,'DataPrerequisiteSourceKind');
 need(/^[a-f0-9]{64}$/.test(value.inventoryHash)&&/^[a-f0-9]{40}$/.test(value.dataSourceTree),'DataPrerequisiteSourceBinding');
 exact(value.sourceClosure,['version','kind','roots','files','closureHash']);
 need(value.sourceClosure.version===1&&value.sourceClosure.kind==='private-literal-source-closure','DataPrerequisiteSourceClosure');
 same(value.sourceClosure.roots,roots,'DataPrerequisiteSourceRoots');
 need(Array.isArray(value.sourceClosure.files)&&value.sourceClosure.files.length>0&&value.sourceClosure.files.length<=1024,'DataPrerequisiteSourceFiles');
 const paths=new Set();for(const f of value.sourceClosure.files){exact(f,['path','sha256','bytesLength','blob']);need(resolve(f.path)===f.path&&!paths.has(f.path),'DataPrerequisiteSourcePath');paths.add(f.path);inspectNonrootRecord('ByteRef',f.blob);need(f.sha256===f.blob.sha256&&f.bytesLength===f.blob.bytesLength,'DataPrerequisiteSourceFile');}
 same(value.sourceClosure.closureHash,hash(value.sourceClosure.files),'DataPrerequisiteSourceHash');
 need(roots.every(p=>paths.has(p)),'DataPrerequisiteSourceRoots');
 inspectNonrootRecord('JsonRef',value.primitives);
 inspectNonrootRecord('ByteRef',value.originalResult);need(value.originalResult.bytesLength<=4194304,'DataPrerequisiteOriginalResult');
 need(Array.isArray(value.components)&&value.components.length===3&&value.components.map(c=>c.component).sort().join()===names.join(),'DataPrerequisiteComponents');
 need(Array.isArray(value.objects)&&value.objects.length===21,'DataPrerequisiteOriginalObjects');
 const refs=new Set();for(const ref of [value.primitives,...value.objects]){inspectNonrootRecord(Object.hasOwn(ref,'canonicalHash')?'JsonRef':'ByteRef',ref);need(ref.bytesLength<=4194304,'DataPrerequisiteOriginalObjects');refs.add(refKey(ref));}
 for(const c of value.components){
  exact(c,['component','record','sourceClosure','requirementsHash','config','filesystem','raw']);
  inspectNonrootRecord('JsonRef',c.record);need(refs.has(refKey(c.record)),'DataPrerequisiteRecordMissing');
  inspectNonrootRecord('ByteRef',c.raw);need(refs.has(refKey(c.raw))&&c.raw.bytesLength<=1048576,'DataPrerequisiteRawRequired');
  inspectNonrootRecord('ByteRef',c.config);need(c.config.bytesLength<=8388608,'DataPrerequisiteConfigBound');
  inspectNonrootRecord('SourceClosureV1',c.sourceClosure);need(c.sourceClosure.tree===value.dataSourceTree&&/^[a-f0-9]{64}$/.test(c.requirementsHash),'DataPrerequisiteSourceBinding');
  const f=c.filesystem;exact(f,['entries','entryCount','entryNodes','evidenceBytes','evidenceNodes','fileLookups']);
  inspectNonrootRecord('ByteRef',f.entries);need(f.entries.bytesLength<=33554432,'DataPrerequisiteEntriesBound');
  for(const k of ['entryCount','entryNodes','evidenceBytes','evidenceNodes'])need(Number.isSafeInteger(f[k])&&f[k]>0&&f[k]<=1000000,'DataPrerequisiteGeometry');
  // Up to16 compiled paths plus at most one distinct requested alias per
  // byte of the three existing 64KiB decoded loader outputs; actual paths,
  // including aliases, are charged individually rather than truncated.
  need(Array.isArray(f.fileLookups)&&f.fileLookups.length>0&&f.fileLookups.length<=16+3*65536&&new Set(f.fileLookups).size===f.fileLookups.length,'DataPrerequisiteFileLookups');
  for(const path of f.fileLookups)need(typeof path==='string'&&/^\/[A-Za-z0-9_./+-]+$/.test(path)&&path.length<=4096&&posix.normalize(path)===path,'DataPrerequisiteFileLookups');
 }
 return value;
}

/** DATA declarations bound work, never authenticate a filesystem or payment.
 * All terms are prepaid once; every material accessor checks its matching
 * invocation/node bound before work. No COPY budget is consulted or reopened. */
export function describeArchivedDataPrerequisiteReplay(value,roots){
 const s=specification(value,roots),recordBytes=[s.originalResult,s.primitives,...s.objects].reduce((n,r)=>n+r.bytesLength,0),sourceBytes=s.sourceClosure.files.reduce((n,f)=>n+f.bytesLength,0);
 need(sourceBytes<=33554432,'DataPrerequisiteSourceBytes');
 const sourceProcessing=sourceDependencyQuote(s.sourceClosure.files.map(f=>({ref:{path:f.path,sha256:f.sha256},bytes:f.bytesLength})),1);
 const components=s.components.map(c=>{
  const f=c.filesystem,B=f.entries.bytesLength,N=f.entryNodes;
  // Entry read/copy/hash/UTF8/full duplicate-key parse/canonical binding: 8B.
  // Existing bounded sizing visits cost 32/node. Compile scan, candidate list,
  // arguments and result checks get four further full byte passes +32/node.
  // Each distinct original getFile rebuilds the complete map (including rest
  // object copies), resolves parents/links and freezes facts: 4B+32N. Memoizing
  // a fact within this single replay avoids repeating that same immutable work.
  // compileDataProbePlan enforces argumentBytes<=65536 before returning.
  const compileArgumentsLocal=4*65536;
  const entriesLocal=12*B+64*N+compileArgumentsLocal;
  const fileLookupLocal=f.fileLookups.length*(4*B+32*N);
  const evidenceLocal=4*f.evidenceBytes+32*f.evidenceNodes;
  const configLocal=8*c.config.bytesLength;
  // Entire original P/F/L/M/K wire is replayed; includes base64 decoding,
  // row/status/map parsing and canonical comparison to the original record.
  const probeLocal=16*c.raw.bytesLength;
  return {component:c.component,entriesLocal,compileArgumentsLocal,fileLookupLocal,evidenceLocal,configLocal,probeLocal,
   fileLookupCount:f.fileLookups.length,logicalBytes:entriesLocal+fileLookupLocal+evidenceLocal+configLocal+probeLocal};
 });
 // Each F+29 material reads has before/after and caller-resumption checks.
 // Each M source scans has two scanner checks plus caller-resumption. One
 // cold pinned-parser load has nine more; entry/payment/return contribute3.
 const callerChecks=3+3*(s.sourceClosure.files.length+29)+3*sourceProcessing.parseCalls+(sourceProcessing.parseCalls?9:0);
 const callerCheckLocal=callerChecks*DATA_PREREQUISITE_CALLER_CHECK_LOCAL;
 const recordLocal=16*recordBytes,sourceReadLocal=4*sourceBytes,logicalBytes=recordLocal+sourceReadLocal+sourceProcessing.logicalBytes+callerCheckLocal+components.reduce((n,c)=>n+c.logicalBytes,0);
 need(Number.isSafeInteger(logicalBytes),'DataPrerequisiteReplayQuote');
 return freeze({version:2,kind:'data-prerequisite-replay-quote',authority:false,recordCount:23,recordBytes,sourceBytes,recordLocal,sourceReadLocal,sourceProcessing,callerChecks,callerCheckLocal,components,
  charge:{logicalBytes,ecrRequests:0,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0},excludes:['input-source-document read','normal record-store puts/snapshot','original source graph/FS acquisition','historical local probe execution']});
}

export async function replayArchivedObserverPrerequisites({value,dataOrigin,dataClosure,requirements,inventoryHash,runtimePins,roots},{reader,file,evidence:filesystemEvidence,imageConfig,recordedMs}){
 const readBytes=ref=>reader.readBytes(ref,33554432),reserveLocal=n=>reader.paid.debit(n),check=()=>reader.current(),now=recordedMs;
 need(Number.isSafeInteger(now)&&now>0,'DataPrerequisiteRecordedTime');
 need(typeof readBytes==='function'&&typeof reserveLocal==='function','DataPrerequisiteOriginalCaller');
 const originalCurrent=originalCallerCheck(check);let checkLimit,checkCount=0;const current=()=>{checkCount++;need(checkLimit===undefined||checkCount<=checkLimit,'DataPrerequisiteCallerCheckBound');originalCurrent();};current();
 const s=specification(value,roots),quote=describeArchivedDataPrerequisiteReplay(s,roots);
 checkLimit=quote.callerChecks;
 same(s.inventoryHash,inventoryHash,'DataPrerequisiteInventory');need(s.dataSourceTree===dataOrigin.tree&&dataClosure.tree===dataOrigin.tree,'DataPrerequisiteDataSource');
 const pins=new Map(runtimePins.map(r=>[r.path,r.sha256]));
 for(const f of s.sourceClosure.files)need(pins.get(f.path)===f.sha256,'DataPrerequisiteRuntimeSource');
 // The original finalization caller pays the complete replay BEFORE the
 // first covered read/parser call. Unused warm-memo capacity is not refunded.
 const payment=reserveLocal(quote.charge.logicalBytes);if(payment&&typeof payment.then==='function'){Promise.resolve(payment).catch(()=>{});need(false,'DataPrerequisiteSynchronousPayment');}
 current();
 let used=quote.callerCheckLocal;const debit=n=>{need(Number.isSafeInteger(n)&&n>=0,'DataPrerequisiteReplayBound');used+=n;need(used<=quote.charge.logicalBytes,'DataPrerequisiteReplayBound');};
 const bytes=async(ref,rate)=>{current();inspectNonrootRecord(Object.hasOwn(ref,'canonicalHash')?'JsonRef':'ByteRef',ref);debit(rate*ref.bytesLength);const raw=await readBytes(ref);current();const b=Buffer.from(raw);need(b.length===ref.bytesLength&&sha(b)===(ref.bytesHash??ref.sha256),'DataPrerequisiteEvidenceBytes');return b;};
 const source=new Map();
 // The original full replay envelope is charged above. Static parser code is
 // current source; archived scanner/parser pins were verified by the model.
 debit(quote.sourceProcessing.logicalBytes);
 const scan=raw=>scanArchivedObserverDependencies(raw,{check:current});
 for(const f of s.sourceClosure.files){const b=await bytes(f.blob,4);current();source.set(f.path,b);}
 for(const [path,b]of source){if(!path.endsWith('.mjs'))continue;const names=await scan(b,{path,sha256:pins.get(path)});current();for(const name of names){if(name.startsWith('node:')||!name.startsWith('.')&&!name.startsWith('/'))continue;need(source.has(resolve(dirname(path),name)),'DataPrerequisiteIncompleteSourceClosure');}}
 const documents=new Map(),raws=new Map();for(const ref of [s.primitives,...s.objects]){const b=await bytes(ref,16);current();if(Object.hasOwn(ref,'canonicalHash')){const v=parseNonrootJson(b.toString('utf8'));same(hash(v),ref.canonicalHash,'DataPrerequisiteCanonicalBytes');documents.set(refKey(ref),v);}else raws.set(refKey(ref),b);}
 const originalBytes=await bytes(s.originalResult,16);current();const original=parseNonrootJson(originalBytes.toString('utf8'));need(original.kind==='actual-local-original-data-primitives'&&original.authority===false&&original.productionRuntimeObserved===false&&original.outputs?.length===3,'DataPrerequisiteOriginalResult');same(hash(original.originalInventory),inventoryHash,'DataPrerequisiteInventory');
 same(s.objects,original.outputs.flatMap(row=>row.objects.map(o=>o.ref)),'DataPrerequisiteOriginalMultiplicity');
 const json=ref=>{const v=documents.get(refKey(ref));need(v,'DataPrerequisiteUndeclaredObject');return v;},primitives=json(s.primitives);exact(primitives,names);
 for(const c of s.components){
  const r=json(c.record),p=inspectNonrootRecord('PrimitiveEvidenceV1',primitives[c.component]);
  const originalRow=original.outputs.filter(r=>r.component===c.component);need(originalRow.length===1,'DataPrerequisiteOriginalResult');same(originalRow[0].primitiveEvidence,p,'DataPrerequisiteOriginalPrimitive');same(originalRow[0].recordRef,c.record,'DataPrerequisiteOriginalRecord');
  exact(r,['version','kind','observationClass','productionRuntimeObserved','component','image','sourceTree','sourceClosureHash','graphHash','filesystemHash','startedMs','container','observed','work','completedMs','cleanupConfirmed','probeOutput']);
  need(r.version===2&&r.kind==='measured-data-prerequisites'&&r.observationClass==='local-original-image'&&r.productionRuntimeObserved===false&&r.cleanupConfirmed===true&&r.component===c.component,'DataPrerequisiteActualLocalSource');
  need(Number.isSafeInteger(r.startedMs)&&r.startedMs>0&&Number.isSafeInteger(r.completedMs)&&r.completedMs>=r.startedMs&&r.completedMs<=now&&r.completedMs-r.startedMs<=120000,'DataPrerequisiteObservationTime');
  same(r.image,dataOrigin.images[c.component],'DataPrerequisiteImage');same(p.image,r.image,'DataPrerequisiteImage');same(r.graphHash,inventoryHash,'DataPrerequisiteGraph');
  need(r.sourceTree===dataOrigin.tree&&r.sourceClosureHash===hash(c.sourceClosure),'DataPrerequisiteImageSource');
  for(const f of c.sourceClosure.files){const old=dataClosure.files.find(row=>row.path===f.path);need(old,'DataPrerequisiteImageSource');same(old,f,'DataPrerequisiteImageSource');}
  same(c.requirementsHash,hash(requirements[c.component]),'DataPrerequisiteRequirements');
  // A closed COPY supplies only immutable verified DATA. The original
  // finalization prepayment above pays ALL new parsing, sizing and accessors.
  const fullEvidence=filesystemEvidence(c.component);current();
  const f=c.filesystem,q=quote.components.find(row=>row.component===c.component);
  let evidenceNodes=0;const evidenceBytes=finalizationJsonSize(fullEvidence,f.evidenceBytes,n=>{need(++evidenceNodes<=f.evidenceNodes,'DataPrerequisiteEvidenceNodes');debit(n);});
  debit(4*f.evidenceBytes);const evidence=fullEvidence;
  need(evidenceBytes===f.evidenceBytes&&evidenceNodes===f.evidenceNodes,'DataPrerequisiteEvidenceGeometry');
  same(hash(evidence),r.filesystemHash,'DataPrerequisiteFilesystem');
  need(evidence.component===c.component&&evidence.graphHash===inventoryHash&&evidence.rootDigest===r.image.rootDigest&&evidence.arm64Digest===r.image.arm64Digest&&evidence.requirementsHash===c.requirementsHash,'DataPrerequisiteFilesystemBinding');
  const entryRaw=await bytes(f.entries,8);current();const entries=parseImageTransitionJson(new TextDecoder('utf-8',{fatal:true}).decode(entryRaw));
  let entryNodes=0;finalizationJsonSize(entries,f.entries.bytesLength,n=>{need(++entryNodes<=f.entryNodes,'DataPrerequisiteEntryNodes');debit(n);});
  need(Array.isArray(entries)&&entries.length===evidence.entryCount&&entries.length===f.entryCount&&entryNodes===f.entryNodes,'DataPrerequisiteEntryGeometry');
  same(hash(entries),evidence.entriesHash,'DataPrerequisiteEntriesHash');
  need(original.originalInventory.edges.some(e=>e.component===c.component&&e.parent===r.image.arm64Digest&&e.child===r.image.configDigest&&e.kind==='config'),'DataPrerequisiteConfigGraph');
  const configRaw=await bytes(c.config,8);current();need('sha256:'+c.config.sha256===r.image.configDigest,'DataPrerequisiteConfigDigest');
  const config=parseImageTransitionJson(new TextDecoder('utf-8',{fatal:true}).decode(configRaw));
  same(config,imageConfig(c.component),'DataPrerequisiteCurrentConfig');current();
  const allowed=new Set(f.fileLookups),facts=new Map();
  const getFile=path=>{need(allowed.has(path),'DataPrerequisiteUndeclaredFileLookup');if(!facts.has(path)){debit(4*f.entries.bytesLength+32*f.entryNodes);facts.set(path,file(c.component,path));current();}return facts.get(path);};
  debit(4*f.entries.bytesLength+32*f.entryNodes+q.compileArgumentsLocal);
  const plan=compileDataProbePlan({component:c.component,image:r.image,config,entries,getFile});
  same(c.raw,r.probeOutput,'DataPrerequisiteOriginalRaw');const raw=raws.get(refKey(c.raw));need(raw&&sha(raw)===r.observed.rawHash,'DataPrerequisiteRawHash');
  debit(q.probeLocal);const o=inspectDataProbeOutput(new TextDecoder('utf-8',{fatal:true}).decode(raw),plan,{getFile});
  same(o,r.observed,'DataPrerequisiteFullObservation');
  need(facts.size===allowed.size,'DataPrerequisiteUnusedFileLookup');
  const [before,parent,child]=o.processes;
  const feature=json(p.featureProbe),negative=json(p.inheritanceAndNegativeProbes),privilege=json(p.privilegeMetadata),libs=json(p.loaderAndLibraries);
  for(const [key,value]of Object.entries({invokedPath:plan.primitive.path,resolvedPath:plan.primitive.resolvedPath,fileSha256:plan.primitive.sha256,mode:plan.primitive.mode,uid:plan.primitive.uid,gid:plan.primitive.gid}))same(p[key],value,'DataPrerequisitePrimitiveFile');
  same(privilege.actualFile,plan.primitive,'DataPrerequisiteFullFileMetadata');
  same(json(p.symlinkChain),plan.primitive.symlinkChain.map(l=>({path:l.path,target:posix.resolve(posix.dirname(l.path),l.link)})),'DataPrerequisiteSymlinkChain');
  for(const doc of [feature,negative]){same(doc.image,r.image,'DataPrerequisitePrimitiveImage');need(doc.executableSha256===p.fileSha256&&doc.observationHash===hash(r),'DataPrerequisiteObservationBinding');}
  need(feature.noNewPrivs===1&&feature.exitCode===0&&negative.setuidBlocked===true&&negative.setgidBlocked===true&&negative.clearRejected===true,'DataPrerequisiteKernel');
  same(feature.identity,parent,'DataPrerequisiteFeatureIdentity');same(negative.parent,parent);same(negative.child,child);same(negative.nodeChild,o.processes.find(p=>p.phase==='node')??null,'DataPrerequisiteNodeChild');same(negative.kernelResults,o.kernel);same(negative.nativeProbeHash,o.nativeProbeHash);
  need(privilege.setuid===false&&privilege.setgid===false&&privilege.fileCapabilities===false&&privilege.actualFile.sha256===p.fileSha256&&privilege.actualFile.mode===p.mode&&privilege.actualFile.uid===p.uid&&privilege.actualFile.gid===p.gid,'DataPrerequisiteFilePrivilege');
  same(libs,o.libraries[p.invokedPath],'DataPrerequisiteLibraryBinding');need(libs.files.length>0,'DataPrerequisiteLibraries');json(p.symlinkChain);
  // r.work is a historical local engineering quote. It is deliberately
  // neither returned as credit nor deducted from this caller's payment.
  exact(r.work,counterKeys);same(r.work,plan.work,'DataPrerequisiteHistoricalWork');
 }
 current();return Object.freeze({authority:false,productionRuntimeObserved:false,primitives,quote,prepaidLocalBytes:quote.charge.logicalBytes,usedLocalBytes:used,originalRecordRefs:s.components.map(c=>c.record)});
}
