/** Read-only replay of original A from an authenticated archive. This module
 * has no host-path, credential, command, publisher or owner-creation API. */
import {need,exact,hash,same,immutable,json,canonical} from './production-nonroot-engineering-json.mjs';
import {createNonrootObserverArchiveReader} from './production-nonroot-observer-archive-reader.mjs';
import {replayArchivedAcquisitionChain} from './production-nonroot-acquisition-audit.mjs';
import {decodeCiSmokeEnvelope} from './ci-smoke-private-archive.mjs';
import {captureCiSmokeGithub} from './ci-smoke-github.mjs';
import {verifyDecoded} from './ci-smoke-archive-replay.mjs';
import {verifyControlCensusPreview} from './production-nonroot-buildkit-replay.mjs';
import {parseImageTransitionJson} from './production-image-transition-proof.mjs';
import {createControlSourceContext} from './production-control-source.mjs';
import {createPrepaidControlCacheBudget,readArchivedControlImageGraph,controlImageGraphBinding} from './production-image-graph.mjs';
import {inspectImageFilesystem,inspectImageFilesystemEvidence} from './production-image-filesystem.mjs';

const states=new WeakMap();
function sourceProcessing(reader){
 return {
  context(_value,ref){reader.current();reader.paid.debit(8*ref.bytesLength+32*Math.min(100000,ref.bytesLength));},
  source(ref,path){reader.current();need(typeof path==='string'&&path.length>0&&path.length<=4096&&Number.isSafeInteger(ref.bytesLength)&&ref.bytesLength<=16777216,'AcquisitionSourceRead');reader.paid.debit(3*(20*ref.bytesLength+69632));},
 };
}
function projectMeasurement(measurement){
 need(measurement?.version===1&&measurement.kind==='control-census-measurement'&&measurement.status==='COMPLETE'&&measurement.authority===false,'ControlCaptureCompositionMeasurement');
 const {binding,inventory,filesystem,usage}=measurement;
 need(inventory&&filesystem&&usage&&binding.graphHash===hash(inventory)&&filesystem.graphHash===binding.graphHash&&filesystem.rootDigest===binding.rootDigest,'ControlCaptureCompositionGraph');
 for(const key of ['uncompressedBytes','processedEntries'])need(Number.isSafeInteger(usage[key])&&usage[key]>=0,'ControlCaptureCompositionUsage');
 const image=Object.fromEntries(['account','region','repositoryName','rootDigest','arm64Digest','configDigest'].map(key=>[key,binding[key]]));
 need(Object.values(image).every(value=>typeof value==='string'),'ControlCaptureCompositionImage');
 return {image,inventory,filesystem,uncompressedBytes:usage.uncompressedBytes,processedEntries:usage.processedEntries};
}

export async function replayNonrootRehearsalAcquisition(input,{work,metadataReads}){
 exact(input,['archive','acquisitionRef','expectedSource','image','geometry']);
 need(metadataReads&&typeof metadataReads.reserveLocal==='function','AcquisitionOriginalGraphPayer');
 const {archive,geometry}=input;exact(geometry,['reads']);
 const reader=createNonrootObserverArchiveReader(archive,work,geometry.reads);
 reader.paid.debit(16*65536+32768);
 const fields={acquisitionRef:input.acquisitionRef,expectedSource:input.expectedSource,image:input.image};
 const snapshot=immutable(json(Buffer.from(canonical(fields)),65536)),{acquisitionRef,expectedSource,image}=snapshot;
 const acquisition=await reader.json(acquisitionRef,65536);reader.current();
 const audit=await replayArchivedAcquisitionChain(acquisition,{reader,expectedSource,image});reader.current();
 const {config:c,manifest:m}=audit,x=c.selection,p=c.provenance;
 const retained=new Map(m.inputs.map(r=>[r.original.path,r.retained])),raws=new Map(m.raws.map(r=>[r.path,r])),counts=new Map();
 const originalBytes=async ref=>{
  reader.current();const bound=retained.get(ref.path)??raws.get(ref.path);
  need(bound&&bound.sha256===ref.sha256&&(ref.bytesLength===undefined||bound.bytesLength===ref.bytesLength),'AcquisitionReadInput');
  const count=(counts.get(bound.path)??0)+1;need(count<=64,'AcquisitionReplayMultiplicity');counts.set(bound.path,count);
  const raw=await reader.readBytes(bound,33554432);reader.current();return raw;
 };
 const io={readBytes:originalBytes,json:async ref=>{const raw=await originalBytes(ref);reader.current();return parseImageTransitionJson(new TextDecoder('utf-8',{fatal:true}).decode(raw));}};
 const envelope=await originalBytes(m.envelopeRef);reader.current();reader.paid.debit(64*envelope.length);
 const decoded=decodeCiSmokeEnvelope(envelope,c.ci.commitment);
 const routes=new Map([
  ['actions/runs/'+x.runId+'/attempts/'+x.runAttempt,p.runRef],
  ['actions/runs/'+x.runId+'/attempts/'+x.runAttempt+'/jobs?per_page=100',p.jobsRef],
  ['git/commits/'+x.buildRevision,p.buildCommitRef],['git/commits/'+x.head,p.headCommitRef],
 ]);
 const provenance=await captureCiSmokeGithub({api:path=>{reader.current();need(routes.has(path),'OfflineGithubRoute');return io.json(routes.get(path));},
  readLog:async id=>{reader.current();need(id===c.ci.commitment.buildJobId,'OfflineGithubLog');const raw=await originalBytes(p.buildLogRef);reader.current();return Buffer.from(raw).toString('utf8');}},
  {repository:x.repository,runId:x.runId,runAttempt:x.runAttempt,sourceRevision:x.buildRevision,purpose:'consume',commitApi:'git-database',assertCurrent:reader.paid.check});
 reader.current();
 const processing=sourceProcessing(reader),checked=await verifyDecoded(decoded,provenance,audit.header.startedMs,{assertCurrent:reader.paid.check,processing});reader.current();
 const completion=await io.json(m.completionRef);reader.current();same(checked.completion,completion,'AcquisitionCompletionReconstruction');
 const origin=await io.json(p.originalOriginRef);reader.current();same(decoded.records.isolation.origin,origin,'OriginalIsolationOrigin');
 need(decoded.records.isolation.candidate.revision===x.head&&decoded.records.isolation.candidate.tree===x.tree,'CurrentIsolationCandidate');
 const measurement=await io.json(m.measurementRef);reader.current();reader.paid.debit(32*m.measurementRef.bytesLength+4096);
 const base=projectMeasurement(measurement),retainedBase=await io.json(m.baseRef);reader.current();same(base,retainedBase,'AcquisitionBase');same(base.image,image,'AcquisitionBaseImage');
 const censusInput=await io.json(p.censusInputRef);reader.current();same(censusInput.image,image,'CensusImage');
 let buildKitLocal=0;
 const preview=await verifyControlCensusPreview(censusInput,{io,expectedSource,assertCurrent:reader.paid.check,chargeLocal:n=>{
  reader.current();need(Number.isSafeInteger(n)&&n>=0&&buildKitLocal+n<=134217728,'ProvenanceLocal');buildKitLocal+=n;reader.paid.debit(n);
 }});reader.current();
 const sourceRef=decoded.records.source.material.candidate;
 reader.paid.debit(64*sourceRef.bytesLength+32768);
 const sourceRaw=decoded.readJson(sourceRef),source=json(sourceRaw,33554432);
 need(source.tree===x.tree&&Array.isArray(source.entries)&&source.blobs&&typeof source.blobs==='object','AcquisitionSourceContext');
 const sourceContext=createControlSourceContext({tree:source.tree,entries:source.entries},async oid=>{
  reader.current();const ref=source.blobs[oid];need(ref,'AcquisitionSourceBlob');processing.source(ref,oid);const raw=decoded.readBytes(ref);reader.current();return raw;
 },{assertCurrent:reader.paid.check});
 const originalReserve=metadataReads.reserveLocal;
 const reserve=charge=>{reader.current();need(metadataReads.reserveLocal===originalReserve,'AcquisitionGraphPayerChanged');const result=originalReserve.call(metadataReads,charge);if(result&&typeof result.then==='function'){Promise.resolve(result).catch(()=>{});need(false,'AcquisitionSynchronousGraphPayment');}};
 const graphReads=Object.freeze({reserveLocal:reserve}),budget=createPrepaidControlCacheBudget({metadataReads:graphReads});
 const graph=await readArchivedControlImageGraph({account:image.account,region:image.region,repositoryName:image.repositoryName,root:m.graph.root,arm64Digest:image.arm64Digest,configDigest:image.configDigest},
  {archive:reader.scope,inventory:base.inventory,budget,metadataReads:graphReads});
 reader.current();same(graph.inventory,base.inventory,'AcquisitionGraphInventory');
 const filesystem=await inspectImageFilesystem(graph,{component:'bootstrap',budget});reader.current();
 same(inspectImageFilesystemEvidence(filesystem),base.filesystem,'AcquisitionFilesystem');
 const handle=Object.freeze({kind:'verified-archived-A-replay'});
 const bindings=immutable({archiveHash:reader.binding.manifestHash,acquisitionHash:hash(acquisition),sourceHash:hash(expectedSource),imageHash:hash(image),graphHash:controlImageGraphBinding(graph).graphHash,owner:c.owner});
 states.set(handle,{reader,work,metadataReads,archive,acquisitionRef:immutable({...acquisitionRef}),expectedSource,image,bindings,
  origin:immutable({version:1,kind:'original-A-authenticated-custody',authority:false,acquisition,selection:c.selection,manifestHash:acquisition.manifestRef.sha256}),
  config:c,manifest:m,base,completion,sourceContext,graph,filesystem,preview,provenance});return handle;
}
export function requireNonrootRehearsalAcquisition(handle,{archive,acquisitionRef,expectedSource,image,work}){
 const s=states.get(handle);need(s&&s.archive===archive&&s.work===work,'AcquisitionReplayRequired');s.reader.current();s.reader.assertBinding(archive);
 same(s.acquisitionRef,acquisitionRef,'AcquisitionReplayBinding');same(s.expectedSource,expectedSource,'AcquisitionReplayBinding');same(s.image,image,'AcquisitionReplayBinding');
 controlImageGraphBinding(s.graph);
 return Object.freeze({origin:s.origin,config:s.config,manifest:s.manifest,base:s.base,completion:s.completion,sourceContext:s.sourceContext,graph:s.graph,filesystem:s.filesystem,bindings:s.bindings});
}
