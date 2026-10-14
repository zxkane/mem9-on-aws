/** Fixed joins into D's new archive replay capabilities. Only complete
 * current-payer handles qualify; no old runtime handle or JSON verdict does. */
import {inspectNonrootRecord,nonrootHash as hash,NONROOT_LIMITS,copyNonrootJson} from './production-nonroot-contracts.mjs';
import {nonrootArchiveResolvers,nonrootArchiveBindings} from './production-nonroot-archive.mjs';
import {readNonrootEvidence} from './production-nonroot-runtime.mjs';
import {parseAcquisitionJson} from './ci-smoke-acquisition-format.mjs';
import {inspectProductionControlComposition} from './production-control-composition.mjs';
import {requireNonrootRehearsalProfile} from './production-nonroot-overlap-preparation.mjs';
import {compareNonrootAtoMain,deriveNonrootRehearsalComparisonGeometry} from './production-nonroot-rehearsal-bridge.mjs';
import {describeNonrootRehearsalBinding} from './production-nonroot-rehearsal-binding.mjs';
import {openNonrootPublishedDataFacts} from './production-nonroot-proof.mjs';
const need=(v,c)=>{if(!v)throw Error(c);};
const same=(a,b,c)=>need(hash(a)===hash(b),c);
function sync(call){const v=call();if(v&&typeof v.then==='function'){Promise.resolve(v).catch(()=>{});throw Error('NonrootRehearsalSynchronousWork');}return v;}
const current=work=>{need(work&&typeof work.assertCurrent==='function'&&typeof work.chargeLocal==='function','NonrootRehearsalOriginalWork');need(sync(()=>work.assertCurrent())===undefined,'NonrootRehearsalSynchronousWork');};
function pay(work,n){current(work);sync(()=>work.chargeLocal(n));current(work);}
export const REHEARSAL_JOIN_ENTRY_LOCAL=16*NONROOT_LIMITS.maxProofBytes;

export function nativeNonrootRehearsalWork(metadataReads){
 need(metadataReads&&typeof metadataReads.assertCurrent==='function'&&typeof metadataReads.reserveLocal==='function','NonrootRehearsalOriginalPayer');
 return Object.freeze({assertCurrent(){need(sync(()=>metadataReads.assertCurrent())===undefined,'NonrootRehearsalSynchronousWork');},chargeLocal(n){need(Number.isSafeInteger(n)&&n>=0,'NonrootRehearsalCharge');sync(()=>metadataReads.reserveLocal({ecrRequests:0,httpBodyBytes:0,logicalBytes:n,uncompressedBytes:0,processedEntries:0}));}});
}
async function read(archive,ref,work,json=true){
 pay(work,32*ref.bytesLength);const raw=await readNonrootEvidence(ref,{...nonrootArchiveResolvers(archive),assertCurrent:()=>current(work)},json);current(work);return raw;
}

/** Rebuild from source/record commitments every native phase or restore.
 * Adapter fields carry native references only; D verifies the opaque handle. */
export async function createNonrootRehearsalVerification({archive,taskPlan,context,parameter},{work,metadataReads}){
 pay(work,REHEARSAL_JOIN_ENTRY_LOCAL);nonrootArchiveBindings(archive);
 const plan=inspectNonrootRecord('TaskPlanV2',taskPlan),contract=plan.deployedControlBuildContract;
 need(contract.version===2,'NonrootRehearsalCurrentProfile');
 const root=await read(archive,plan.overlap.rehearsal.evidence,work);current(work);
 need([1,2].includes(root.version)&&root.kind==='original-nonexec-five-case-rehearsal','NonrootRehearsalOriginalEvidence');
 inspectNonrootRecord('JsonRef',root.preparation);inspectNonrootRecord('JsonRef',root.runRef);
 const p=await read(archive,root.preparation,work);current(work);const preparation=requireNonrootRehearsalProfile(contract,p);
 need(root.version===preparation.version,'NonrootRehearsalAccountingVersion');
 if(root.version===2)same(root.accounting,preparation.accounting,'NonrootRehearsalAccounting');
 else need(!Object.hasOwn(root,'accounting'),'NonrootRehearsalAccounting');
 const dataFacts=openNonrootPublishedDataFacts(context,{archive,parameter,expected:{owner:preparation.owner,sourceTree:preparation.source.candidateTree,images:preparation.dataImages}},{work});current(work);
 const api=await import('./production-nonroot-observer-replay.mjs');current(work);
 const handle=await api.replayNonrootObserverRun({archive,runRef:root.runRef,preparation,geometry:root.replayGeometry},{work,metadataReads,dataFacts});current(work);
 const adapter=Object.freeze({handle,archive,runRef:root.runRef,preparation,work,metadataReads,dataFacts,replayGeometry:root.replayGeometry});
 const replay=sync(()=>api.requireNonrootObserverRunReplay(handle,{archive,runRef:root.runRef,preparation,work}));current(work);
 need(replay.bindings.runHash===root.runRef.canonicalHash,'NonrootRehearsalRunRef');
 need(hash(replay.record)===replay.bindings.runMaterialHash,'NonrootRehearsalRunMaterial');
 need(replay.owner===preparation.owner,'NonrootRehearsalOwner');same(replay.record.rehearsalRef,plan.overlap.rehearsal.controlBuild,'NonrootRehearsalOriginalControl');
 same(replay.caseResults,plan.overlap.rehearsal.cases,'NonrootRehearsalOriginalCases');
 need(replay.completedMs===plan.overlap.rehearsal.completedMs,'NonrootRehearsalOriginalTime');
 return adapter;
}

export async function verifyNonrootDeploymentRehearsal({record,taskPlan,contract,controlVerification,sourceContext,archive,proofArchive,rehearsalVerification,metadataReads}){
 const v=rehearsalVerification;need(v&&v.metadataReads===metadataReads,'NonrootRehearsalReplayRequired');
 const work=v.work;pay(work,REHEARSAL_JOIN_ENTRY_LOCAL);
 const original=nonrootArchiveBindings(proofArchive),replayed=nonrootArchiveBindings(v.archive);
 need(original.owner===replayed.owner&&original.manifestHash===replayed.manifestHash,'NonrootRehearsalProofArchive');
 const p=requireNonrootRehearsalProfile(contract,v.preparation);
 const d=await import('./production-nonroot-observer-replay.mjs');current(work);
 const replay=sync(()=>d.requireNonrootObserverRunReplay(v.handle,{archive:v.archive,runRef:v.runRef,preparation:p,work}));current(work);
 need(replay.bindings.runHash===v.runRef.canonicalHash,'NonrootRehearsalRunRef');
 need(hash(replay.record)===replay.bindings.runMaterialHash,'NonrootRehearsalRunMaterial');
 need(replay.owner===p.owner,'NonrootRehearsalOwner');same(replay.record.rehearsalRef,taskPlan.overlap.rehearsal.controlBuild,'NonrootRehearsalOriginalControl');
 same(replay.caseResults,taskPlan.overlap.rehearsal.cases,'NonrootRehearsalOriginalCases');need(replay.completedMs===taskPlan.overlap.rehearsal.completedMs,'NonrootRehearsalOriginalTime');
 const a=await import('./production-nonroot-rehearsal-acquisition.mjs');current(work);
 const base=sync(()=>a.requireNonrootRehearsalAcquisition(replay.rehearsal,{archive:v.archive,acquisitionRef:p.acquisition,expectedSource:p.source,image:p.controlImage,work}));current(work);
 const acquisition=await read(v.archive,p.acquisition,work);current(work);same(base.origin.acquisition,acquisition,'NonrootRehearsalAcquisition');
 need(base.sourceContext.tree===sourceContext.tree&&sourceContext.tree===p.source.candidateTree,'NonrootRehearsalSource');
 const invocation=await read(archive,record.deployedControlBuild.actualInvocation,work);current(work);
 inspectNonrootRecord('ByteRef',invocation.capture);
 const raw=await read(archive,invocation.capture,work,false);current(work);
 const envelope=parseAcquisitionJson(raw),plan=inspectProductionControlComposition(envelope.plan);
 need(plan.planHash===p.construction.planHash&&plan.copyHash===p.construction.copyHash,'NonrootRehearsalConstruction');
 const geometry=deriveNonrootRehearsalComparisonGeometry({sourceContext:base.sourceContext,baseFilesystem:base.filesystem,mainFilesystem:controlVerification.filesystem},{work});
 const comparison=await compareNonrootAtoMain({plan,actualMain:{capture:envelope.capture,statement:envelope.statement},baseGraph:base.graph,baseFilesystem:base.filesystem,mainGraph:controlVerification.graph,mainFilesystem:controlVerification.filesystem,sourceContext:base.sourceContext,geometry},{work});current(work);
 return {comparison,preparation:copyNonrootJson(p)};
}

export function finishNonrootRehearsalBinding(verified,{record,contract,taskPlan,registrations}){
 return describeNonrootRehearsalBinding({...verified,record,contract,taskPlan,registrations});
}
