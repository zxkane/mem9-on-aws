import {observerCaseVersion,inspectObserverAccounting,assertObserverAccountingBinding} from './production-nonroot-observer-accounting.mjs';
/** Current archive/source/DATA joins for the original observer. Public input
 * JSON has no filesystem, owner, provider or process-observation authority. */
import {dirname,posix} from 'node:path';
import {need,hash,sha,same,canonical,json,immutable} from './production-nonroot-engineering-json.mjs';
import {requireArchivedObserverSourceModel} from './production-nonroot-observer-source-model.mjs';
import {parseArchivedObserverSource,archivedObserverConstant} from './production-nonroot-observer-source-syntax.mjs';
import {replayArchivedObserverPrerequisites} from './production-nonroot-observer-prerequisites.mjs';
import {compileArchivedObserverRoles} from './production-nonroot-observer-source-compile.mjs';
import {buildObserverCohortModels,observerCohortTimeline} from './production-nonroot-observer-cohort-model.mjs';
import {requireNonrootRehearsalAcquisition} from './production-nonroot-rehearsal-acquisition.mjs';
import {readControlSourceFile,controlSourceEntries} from './production-control-source.mjs';
import {IMAGE_TRANSITION_LIMITS as IMAGE_LIMITS} from './production-image-transition.mjs';

const states=new WeakMap(),components=['llm-proxy','mnemo-server','qwen3-embed'];
const imageOnly=image=>Object.fromEntries(['rootDigest','arm64Digest','configDigest'].map(k=>[k,image[k]]));

export async function replayNonrootObserverInputs({plan,quote,input,preparation,rehearsal,rehearsalRef,sourceModel},{reader,dataFacts,metadataReads}){
 reader.current();
 const original=requireArchivedObserverSourceModel(sourceModel,{reader,plan,input});reader.current();
 // Use the detached, verified inputs throughout all awaits. Caller mutations
 // cannot change either the source selection or the compiler's model.
 plan=original.plan;input=original.input;
 reader.paid.debit(32*33554432);
 ({quote,preparation,rehearsalRef}=immutable(json(Buffer.from(canonical({quote,preparation,rehearsalRef})),33554432)));
 need(metadataReads&&typeof metadataReads.reserveLocal==='function','ObserverInputCounterPayer');
 const reserve=metadataReads.reserveLocal,current=()=>{reader.current();need(metadataReads.reserveLocal===reserve,'ObserverInputCounterPayerChanged');};
 const acquisition=requireNonrootRehearsalAcquisition(rehearsal,{archive:reader.archive,acquisitionRef:preparation.acquisition,expectedSource:preparation.source,image:preparation.controlImage,work:reader.work});current();
 assertObserverAccountingBinding(plan,input,preparation);need(observerCaseVersion(plan)&&plan.owner===preparation.owner&&input.owner===plan.owner&&input.operation===plan.operation,'ObserverOriginalInputs');
 const nodeCount=input.inventory.nodes.length;
 need(Number.isSafeInteger(nodeCount)&&nodeCount>0&&nodeCount<=IMAGE_LIMITS.maxManifestNodes+IMAGE_LIMITS.maxBlobNodes&&input.objects.length===nodeCount,'ObserverOriginalInventory');
 const descriptors=new Map(input.inventory.nodes.map(n=>[n.digest,n])),originals=new Map(input.objects.map(o=>['sha256:'+o.sha256,o]));
 need(descriptors.size===nodeCount&&originals.size===nodeCount,'ObserverOriginalInventory');
 for(const d of descriptors.values())need(originals.get(d.digest)?.bytesLength===d.size,'ObserverOriginalObject');
 const images=Object.fromEntries(components.map(c=>[c,imageOnly(input.dataOrigin.images[c])]));
 same(images,preparation.dataImages,'ObserverInputsDataImages');
 need(preparation.source.candidateTree===input.control.source.tree&&input.control.source.tree===acquisition.sourceContext.tree,'ObserverInputsControlSource');
 const binding=input.control.binding,image=acquisition.base.image;
 need(image.account===plan.scope.account&&image.region===plan.scope.region,'ObserverInputsControlScope');
 for(const k of ['account','region','repositoryName','arm64Digest','configDigest'])need(binding[k]===image[k],'ObserverInputsControlImage');
 same(binding.root,acquisition.manifest.graph.root,'ObserverInputsControlRoot');same(input.control.inventory,acquisition.base.inventory,'ObserverInputsControlInventory');
 same(input.control.filesystemEvidence,acquisition.base.filesystem,'ObserverInputsControlFilesystem');
 same(plan.geometry.control.rehearsalAcquisition.acquisition,acquisition.origin.acquisition,'ObserverInputsAcquisition');
 need(input.control.origin?.kind==='original-A-acquisition-input-v1','ObserverInputsAcquisition');
 const expected=input.control.origin.originals,g=plan.geometry.control.rehearsalAcquisition;
 same(expected.acquisition,acquisition.origin.acquisition,'ObserverInputsAcquisition');need(hash(expected)===g.expectedHash&&Buffer.byteLength(JSON.stringify(expected))<=g.expectedBytes,'ObserverInputsAcquisitionExpected');

 // Public source rows are bound to the full genuine A Git context. Package
 // bodies remain separately lock/catalog-bound, never imported from archive.
 const gitRows=new Map(controlSourceEntries(acquisition.sourceContext).map(r=>[r.path,r]));current();
 const publicPrefix=original.policy.publicRoot+'/',sourceObjects=new Map(input.control.sourceObjects.map(r=>[r.oid,r.ref]));
 need(sourceObjects.size===input.control.sourceObjects.length,'ObserverInputsControlObjects');
 same(input.control.source.entries,[...gitRows.values()],'ObserverInputsControlTree');
 for(const row of original.rows){
  current();if(!row.path.startsWith(publicPrefix))continue;const relative=row.path.slice(publicPrefix.length);
  if(relative.split('/').includes('node_modules'))continue;
  need(gitRows.has(relative),'ObserverInputsPublicSourceMissing');
  reader.paid.debit(16*row.bytesLength+65536);const read=await readControlSourceFile(acquisition.sourceContext,relative);current();
  need(read.file.sha256===row.sha256&&read.file.bytes===row.bytesLength,'ObserverInputsPublicSourceChanged');
 }
 for(const row of input.control.source.entries){
  current();if(row.type!=='blob'||!['100644','100755'].includes(row.mode))continue;
  const ref=sourceObjects.get(row.oid);need(ref,'ObserverInputsControlObjectMissing');
  const raw=await reader.readBytes(ref,16777216);current();
  reader.paid.debit(16*raw.length+65536);const read=await readControlSourceFile(acquisition.sourceContext,row.path);current();
  need(sha(raw)===read.file.sha256&&raw.length===read.file.bytes,'ObserverInputsControlObjectChanged');
 }

 // This is the fixed P WeakMap accessor, not a caller-supplied fact callback.
 const factsApi=await import('./production-nonroot-proof.mjs');current();
 const factBinding=factsApi.inspectNonrootDataFacts(dataFacts,{work:reader.work});current();
 need(['live-cache-data-facts','published-proof-data-facts'].includes(factBinding.kind)&&factBinding.authority===false&&factBinding.owner===plan.owner&&factBinding.sourceTree===input.control.source.tree&&factBinding.inventoryHash===hash(input.inventory),'ObserverInputsDataFactsBinding');
 // A live cache belongs to the original COPY archive. A restored proof's
 // facts must instead belong to this same authenticated full-proof archive.
 if(factBinding.kind==='published-proof-data-facts')need(factBinding.archiveManifestHash===reader.binding.manifestHash,'ObserverInputsPublishedArchive');
 same(factBinding.images,images,'ObserverInputsDataFactsImages');
 const assertFacts=()=>{current();factsApi.inspectNonrootDataFacts(dataFacts,{work:reader.work});current();};
 const file=(component,path)=>{current();const out=factsApi.readNonrootDataFileFact(dataFacts,{component,path,image:images[component]},{work:reader.work});current();return immutable(out);};
 const requireAbsent=(component,path)=>{
  current();const result=factsApi.assertNonrootDataPathAbsent(dataFacts,{component,path,image:images[component]},{work:reader.work});current();
  if(result&&typeof result.then==='function'){Promise.resolve(result).catch(()=>{});need(false,'ObserverDataAbsenceSynchronous');}
  need(result===undefined,'ObserverDataAbsenceSynchronous');
 };
 const imageConfig=component=>{current();const out=factsApi.readNonrootDataImageFact(dataFacts,{component,image:images[component]},{work:reader.work});current();return out.config;};
 const evidence=component=>{current();need(typeof factsApi.readNonrootDataFilesystemEvidence==='function','ObserverDataFullEvidenceAccessorRequired');const out=factsApi.readNonrootDataFilesystemEvidence(dataFacts,{component,image:images[component]},{work:reader.work});current();same(out,input.filesystems[component].evidence,'ObserverInputsFilesystemChanged');return out;};

 // The collector roots come from the authenticated original source literal.
 // Historical pathnames are keys; they never trigger host file reads.
 const prerequisitePath=posix.join(dirname(original.policy.parserSibling),'data-prerequisite-evidence.mjs');
 const prerequisiteCode=original.readSource(prerequisitePath),parsed=parseArchivedObserverSource(prerequisiteCode,prerequisitePath,{reader});
 const root=archivedObserverConstant(parsed.ast,'ROOT');need(root===dirname(prerequisitePath)+'/','ObserverPrerequisiteRoot');
 const roots=['data-prerequisites.mjs','data-probe.mjs','data-prerequisite-evidence.mjs'].map(p=>root+p);
 const prerequisite=await replayArchivedObserverPrerequisites({value:input.prerequisite,dataOrigin:input.dataOrigin,dataClosure:input.dataClosure,requirements:input.requirements,inventoryHash:hash(input.inventory),runtimePins:plan.source.files,roots},{reader,file,evidence,imageConfig,recordedMs:plan.startedMs});current();
 const {contracts}=compileArchivedObserverRoles({plan,input,images},{reader,file});current();
 // Fixed archive verifier replays recorded intrinsic/runtime/guard/scan DATA.
 // It never mints or revives a local Docker observation handle.
 const rehearsalApi=await import('./production-nonroot-rehearsal-control-replay.mjs');current();
 const control=await rehearsalApi.replayNonrootArchivedRehearsal({plan,input,preparation,rehearsalRef,acquisition},{reader,metadataReads});current();
 const models=buildObserverCohortModels({plan,input,contracts,rehearsalRef,controlBinding:control.binding},{reader,dataFacts:{requireAbsent}});current();
 assertFacts();
 const handle=Object.freeze({kind:'verified-archived-observer-inputs'});
 states.set(handle,{reader,current,assertFacts,plan,input,quote,prerequisite,contracts,models,file,requireAbsent,rehearsal:control});return handle;
}

export function requireNonrootObserverDataSources(handle,{reader}){
 assertNonrootObserverDataSources(handle,{reader});const s=states.get(handle);
 // Model maps are copied so a consumer cannot replace authenticated cases or
 // contracts retained by the source capability before a later replay.
 reader.paid.debit(64*s.plan.geometry.materialBytes+64*s.plan.geometry.roles.reduce((n,r)=>n+r.compiledBytes,0)+65536);
 return Object.freeze({plan:s.plan,input:s.input,quote:s.quote,contracts:structuredClone(s.contracts),models:structuredClone(s.models),file:s.file,requireAbsent:s.requireAbsent});
}
export function assertNonrootObserverDataSources(handle,{reader}){
 reader.current();const s=states.get(handle);need(s&&s.reader===reader,'ObserverDataSourcesRequired');s.current();s.assertFacts();
}
export function getObserverCohortModel(handle,caseName,{reader}){const s=requireNonrootObserverDataSources(handle,{reader});const model=s.models.get(caseName);need(model,'ObserverCohortModelRequired');return model;}
export function observerExpectedTimeline(handle,caseName,bindings,{reader}){const model=getObserverCohortModel(handle,caseName,{reader});reader.current();reader.paid.debit(16*4194304);return observerCohortTimeline(model,bindings);}
