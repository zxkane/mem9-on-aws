/** Explicit image-security successor; ordinary retained issuance stays separate.
 * One V1 lineage is extended by one typed V2 target. The original DB root and
 * cumulative allowance are unchanged. Full proof/archive authentication and
 * fresh root/permission snapshots remain mandatory at every write boundary.
 */
import {inspectDataRelease,requireActiveDataRelease} from './production-data-release.mjs';
import {assertImageTransitionDataRelease,imageTransitionContextBindings} from './production-image-transition-proof.mjs';
import {validateSupersessionLineage as validateLegacyLineage} from './production-data-supersession.mjs';
import {PRODUCTION_DATA_RELEASE_PARAMETER as parameterName} from './production-data-issuance.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';

const fail=code=>{throw Error(code);};
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join();
const hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
const fingerprints=['sourceEvidenceHash','materialHash','runtimeHash','buildInputsHash','securityEvidenceHash','freshBuildSecurityHash','policyHash','parentProofHash','rootHash','writerBoundaryHash','lineageHash','dataOriginSourceEvidenceHash','transitionProofHash'];
const unchanged=['stage','account','region','runtimeNonce','generation','targetsHash','parentProofHash','backendBindingHash','schemaDigest','operatorDigest'];
const normalized=v=>JSON.parse(JSON.stringify(v));
const immutable=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(immutable);Object.freeze(v);}return v;};
const parameterHash=v=>hash(normalized(v));
export const MAX_SUPERSESSION_LINEAGE=1000;
export const SUPERSESSION_ADMISSION_MAX_AGE_MS=300000;
export const SUPERSESSION_EVIDENCE_MAX_AGE_MS=300000;
export const SUPERSESSION_OPERATION_MAX_MS=1800000;

/** Derived only from existing immutable authorization/review fields. This is
 * an issuance bound, not a timeout for owned task or credential cleanup. */
export function supersessionOperationDeadline(times){
 if(!exact(times,['issuedMs','reviewedMs','expiresMs'])||Object.values(times).some(v=>!Number.isSafeInteger(v)||v<1)||
   times.expiresMs<=times.issuedMs||times.expiresMs<=times.reviewedMs)fail('DataReleaseSupersessionTimeInvalid');
 const deadline=Math.min(times.issuedMs,times.reviewedMs)+SUPERSESSION_OPERATION_MAX_MS;
 if(!Number.isSafeInteger(deadline))fail('DataReleaseSupersessionTimeInvalid');
 return Math.min(deadline,times.expiresMs);
}

export function assertSupersessionOperationWindow(times,now,{initial=false,historical=false}={}){
 const deadline=supersessionOperationDeadline(times);
 if(typeof initial!=='boolean'||typeof historical!=='boolean'||initial&&historical||!Number.isSafeInteger(now)||now<1||
   times.issuedMs>now||times.reviewedMs>now)fail('DataReleaseSupersessionTimeInvalid');
 if(historical)return deadline;
 if(initial&&(now-times.issuedMs>SUPERSESSION_ADMISSION_MAX_AGE_MS||now-times.reviewedMs>SUPERSESSION_ADMISSION_MAX_AGE_MS))fail('DataReleaseSupersessionEvidenceExpired');
 if(now>=deadline)fail('DataReleaseSupersessionOperationExpired');
 return deadline;
}

function inspectParameter(p,expected){
 if(!p||p.Name!==parameterName||p.Type!=='SecureString'||!Number.isSafeInteger(p.Version)||p.Version<1||
   p.ARN!==`arn:aws:ssm:${expected.region}:${expected.account}:parameter${parameterName}`||typeof p.Value!=='string')fail('DataReleasePredecessorInvalid');
 return inspectDataRelease(p.Value,{stage:'prod',account:expected.account,region:expected.region,controlSourceTree:JSON.parse(p.Value).controlSourceTree});
}

/** The private adapter authenticates these complete create-only archive records.
 * SSM history is not the full-lineage authority and may have a shorter window. */
export function validateImageTransitionPredecessorLineage(lineage,predecessor,nextId){
 return validateLegacyLineage(lineage,predecessor,nextId);
}

function validate(input,now,{initial=false,historical=false,transition}={}){
 if(!exact(input,['authorization','expected','predecessor','lineage']))fail('ImageReleaseInputInvalid');
 const {authorization,expected,predecessor,lineage}=input,data=authorization?.data;
 if(!exact(authorization,['data','hash','review'])||data?.version!==2)fail('ImageReleaseInputInvalid');
 assertSupersessionOperationWindow({issuedMs:data.issuedMs,reviewedMs:authorization.review?.reviewedMs,expiresMs:data.expiresMs},now,{initial,historical});
 if(!exact(expected,['account','region','controlRevision','controlSourceTree',...fingerprints,'parameterProtection','rootState'])||!hex(expected.controlRevision,40)||fingerprints.some(k=>!hex(expected[k])))fail('ImageReleaseContextInvalid');
 const protection=expected.parameterProtection,root=expected.rootState;
 if(!exact(protection,['KeyId','Tier','DataType'])||typeof protection.KeyId!=='string'||!protection.KeyId||protection.KeyId.length>2048||/[\0\r\n]/.test(protection.KeyId)||protection.Tier!=='Standard'||protection.DataType!=='text')fail('ImageReleaseProtectionInvalid');
 if(!exact(root,['generation','validationId','receipts','changedRows','conservationHash','cap'])||!hex(root.generation)||!hex(root.validationId,32)||!hex(root.conservationHash)||!Number.isSafeInteger(root.receipts)||root.receipts<0||!Number.isSafeInteger(root.changedRows)||root.changedRows<0||root.changedRows>=20||root.cap!==20)fail('ImageReleaseRootInvalid');
 const previous=inspectParameter(predecessor,expected),context={stage:'prod',account:expected.account,region:expected.region,controlSourceTree:expected.controlSourceTree};
 if(previous.data.version!==1)fail('ImageReleasePredecessorTypeInvalid');
 const next=historical?inspectDataRelease(data,context):requireActiveDataRelease(data,context,{now});
 if(next.hash!==authorization.hash||previous.data.expiresMs>now||previous.data.authorizationId===data.authorizationId||data.transition.predecessorHash!==hash(previous.data)||data.transition.proofHash!==expected.transitionProofHash)fail('ImageReleaseIdentityInvalid');
 for(const field of unchanged)if(hash(previous.data[field])!==hash(data[field]))fail('ImageReleaseRootBindingChanged');
 if(expected.lineageHash!==validateImageTransitionPredecessorLineage(lineage,predecessor,data.authorizationId))fail('ImageReleaseLineageChanged');
 const verified=imageTransitionContextBindings(transition),review=authorization.review;
 if(initial&&verified.evidenceKind!=='live-copy-evidence')fail('ImageReleaseLiveEvidenceRequired');
 if(verified.proofHash!==expected.transitionProofHash||verified.control.revision!==expected.controlRevision||verified.control.sourceTree!==expected.controlSourceTree||verified.control.sourceEvidenceHash!==expected.sourceEvidenceHash||verified.dataOrigin.sourceEvidenceHash!==expected.dataOriginSourceEvidenceHash||hash(verified.rootState)!==hash(root))fail('ImageReleaseProofContextInvalid');
 const reviewKeys=['version','kind','decision','controlSourceTree','sourceEvidenceHash','dataOriginSourceEvidenceHash','parentProofHash','buildInputsHash','securityEvidenceHash','freshBuildSecurityHash','policySourcesHash','artifactPolicyHash','imageTransitionProofHash','reviewedMs','expiresMs'];
 if(!exact(review,reviewKeys)||review.version!==1||review.kind!=='image-security-policy-review'||review.decision!=='within-existing-policy'||review.controlSourceTree!==data.controlSourceTree||review.reviewedMs!==data.issuedMs||review.expiresMs!==data.expiresMs||!hex(review.policySourcesHash)||review.artifactPolicyHash!==verified.artifactPolicyHash||review.imageTransitionProofHash!==verified.proofHash||hash(review)!==data.policyHash)fail('ImageReleasePolicyReviewInvalid');
 for(const field of ['sourceEvidenceHash','dataOriginSourceEvidenceHash','parentProofHash','buildInputsHash','securityEvidenceHash','freshBuildSecurityHash'])if(review[field]!==expected[field])fail('ImageReleasePolicyReviewInvalid');
 for(const field of ['parentProofHash','buildInputsHash','securityEvidenceHash','policyHash'])if(data[field]!==expected[field])fail('ImageReleaseContextInvalid');
 assertImageTransitionDataRelease(transition,{previous:previous.data,current:data,controlSourceTree:expected.controlSourceTree,now,mode:historical?'inspection':'admission',review});
 return {previous:previous.data,data};
}

function verifySnapshot(snapshot,input,now,{successor=false,fenced=false}={}){
 const {expected,predecessor,authorization}=input,owner=authorization.data.authorizationId;
 if(!snapshot||Object.keys(expected).some(k=>snapshot[k]===undefined||hash(snapshot[k])!==hash(expected[k])))fail('DataReleaseSnapshotChanged');
 if(snapshot.rootVerified!==true||snapshot.writersSerialized!==true||snapshot.executionEnabled!==false||snapshot.dispatcherEnabled!==false||
   ['enabledSchedules','activeWorkers','activeAdministration','activeContinuations','benchmarkRemaining'].some(k=>snapshot[k]!==0))fail('DataReleaseSupersessionNotPaused');
 if(!Number.isSafeInteger(now)||now<1||!Number.isSafeInteger(snapshot.observedMs)||snapshot.observedMs>now||now-snapshot.observedMs>SUPERSESSION_EVIDENCE_MAX_AGE_MS||fenced&&snapshot.fenceOwner!==owner)fail('DataReleaseSnapshotNotFresh');
 const p=snapshot.parameter;inspectParameter(p,expected);
 if(successor){if(p.Version!==predecessor.Version+1||p.Value!==JSON.stringify(authorization.data))fail('DataReleaseSupersessionReadbackUncertain');}
 else if(parameterHash(p)!==parameterHash(predecessor))fail('DataReleasePredecessorChanged');
}

function envelopeFor(input){
 const {authorization,expected,predecessor}=input;
 const commitment={version:1,kind:'image-security-transition',predecessorHash:parameterHash(predecessor),predecessorVersion:predecessor.Version,
  authorizationHash:authorization.hash,authorizationId:authorization.data.authorizationId,nextVersion:predecessor.Version+1};
 const operation={owner:authorization.data.authorizationId,expected:{revision:expected.controlRevision,newValue:JSON.stringify(commitment)},prior:{value:predecessor.Value}};
 return {version:1,kind:'image-security-transition',operation,predecessor:normalized(predecessor),authorization:normalized(authorization),expected:normalized(expected),lineage:normalized(input.lineage)};
}
async function verifyArchive(deps,envelope){
 const stored=await deps.readArchive(envelope.operation.owner);
 if(!stored||hash(stored)!==hash(envelope))fail('DataReleaseArchiveUnverified');
 const proof=await deps.readImageTransitionProof(envelope.operation.owner);
 if(!proof||hash(proof)!==envelope.authorization.data.transition.proofHash)fail('ImageReleaseProofArchiveUnverified');
}
function writeIntent(envelope){return {version:1,owner:envelope.operation.owner,parameter:parameterName,archiveHash:hash(envelope),nextVersion:envelope.predecessor.Version+1,authorizationHash:envelope.authorization.hash};}
function acquisitionIntent(envelope){return {version:1,owner:envelope.operation.owner,archiveHash:hash(envelope),kind:'acquire-image-transition-fences'};}
function noSendReceipt(envelope,intent,mutex,gate){
 return {version:1,owner:envelope.operation.owner,archiveHash:hash(envelope),predecessorHash:parameterHash(envelope.predecessor),
  intentHash:intent?hash(intent):null,mutexHash:mutex?hash(mutex):null,gateHash:gate?hash(gate):null,sent:false};
}
async function persistRecord(deps,writer,reader,value,code){
 await deps[writer](value);
 const stored=await deps[reader](value.owner);
 if(!stored||hash(stored)!==hash(value))fail(code);
}
async function persistAbort(deps,receipt){
 await persistRecord(deps,'recordAborted','readAborted',receipt,'DataReleaseAbortReceiptInvalid');
}
async function verifyUnsentPredecessor(deps,envelope,intent){
 if(parameterHash(await deps.readback())!==parameterHash(envelope.predecessor)||hash(await deps.readIntent(envelope.operation.owner))!==hash(intent))fail('DataReleasePredecessorChanged');
}

/** Released receipts change how ownership is checked, not whether a remaining
 * mutation needs current evidence. The adapter's guard is read-only and must
 * authenticate released resources as well as the still-owned mutex. */
async function finishRecoveryRelease(deps,envelope,input,fences,now,{successor}){
 const {mutex,gate,mutexReleased,gateReleased}=fences,owner=envelope.operation.owner;
 if(typeof deps.assertRemainingFenceOwnership!=='function')fail('DataReleaseRecoveryReleaseGuardRequired');
 await deps.assertRemainingFenceOwnership(gate,mutex,envelope.operation);
 const remaining=Boolean(mutex&&!mutexReleased||gate&&!gateReleased);
 let snapshot;
 if(remaining){
  snapshot=await deps.inspect({owner,remainingFences:true});
  await deps.assertRemainingFenceOwnership(gate,mutex,envelope.operation);
  verifySnapshot(snapshot,input,now(),{successor,fenced:true});
 }
 // When both receipts are authenticated these helper calls only verify the
 // released state. They must never reacquire or change released resources.
 if(gate)await deps.restoreGate(gate,envelope.operation,mutex);
 await deps.assertRecoveryOwner(envelope.operation);
 await deps.assertRemainingFenceOwnership(gate,mutex,envelope.operation);
 if(snapshot)verifySnapshot(snapshot,input,now(),{successor,fenced:true});
 if(mutex)await deps.releaseMutex(mutex,envelope.operation);
}

/** One protected overwrite. The adapter owns the existing non-expiring mutex,
 * authenticated fresh evidence and durable create-only archive implementation.
 * No post-write observation can cause a retry or corrective write. */
export async function supersedeProductionImageRelease(deps,input,{transition}={}){
 const now=deps.now??Date.now;validate(input,now(),{initial:true,transition});input=immutable(normalized(input));const envelope=immutable(envelopeFor(input)),owner=envelope.operation.owner;
 if(await deps.priorAttempt(owner)!==null||await deps.readArchive(owner)!==null)fail('DataReleaseReconciliationRequired');
 validate(input,now(),{transition});verifySnapshot(await deps.inspect(),input,now());validate(input,now(),{transition});await deps.archive(envelope);await verifyArchive(deps,envelope);
 const state={version:1,owner,authorizationHash:input.authorization.hash,predecessorVersion:input.predecessor.Version,phase:'inspecting',sent:false,verified:false};
 let mutex,gate,advancePending=false;
 try{
  // Durable, authenticated absence of this record after issuer termination
  // distinguishes an archive-only crash from an uncertain fence acquisition.
  validate(input,now(),{transition});advancePending=true;await persistRecord(deps,'recordAcquisitionIntent','readAcquisitionIntent',acquisitionIntent(envelope),'DataReleaseAcquisitionIntentUnverified');advancePending=false;
  validate(input,now(),{transition});advancePending=true;mutex=await deps.acquireMutex(envelope.operation);state.mutex=mutex;advancePending=false;
  validate(input,now(),{transition});advancePending=true;gate=await deps.acquireGate(envelope.operation,mutex);state.gate=gate;advancePending=false;
  validate(input,now(),{transition});const before=await deps.inspect({owner,fenced:true});verifySnapshot(before,input,now(),{fenced:true});validate(input,now(),{transition});
  await verifyArchive(deps,envelope);await deps.assertFence(gate,mutex);
  validate(input,now(),{transition});advancePending=true;await persistRecord(deps,'recordIntent','readIntent',writeIntent(envelope),'DataReleaseWriteIntentUnverified');advancePending=false;
  // Re-read the exact predecessor after all archive/inspection work. The
  // non-expiring owned mutex remains held across the single write and checks.
  if(parameterHash(await deps.readback())!==parameterHash(input.predecessor))fail('DataReleasePredecessorChanged');
  await deps.assertFence(gate,mutex);verifySnapshot(before,input,now(),{fenced:true});validate(input,now(),{transition});state.sent=true;state.phase='attempted';
  let response;try{response=await deps.putParameter({Name:parameterName,Type:'SecureString',Value:JSON.stringify(input.authorization.data),Overwrite:true,...input.expected.parameterProtection});}catch{state.transportUncertain=true;}
  if(response!==undefined&&response.Version!==input.predecessor.Version+1)fail('DataReleaseWriteVersionConflict');
  const parameter=await deps.readback();
  // Exact readback is necessary but not sufficient: repeat the entire live
  // audit. This is evidence/release gating, never permission for another Put.
  validate(input,now(),{transition});const after=await deps.inspect({owner,fenced:true});verifySnapshot(after,input,now(),{successor:true,fenced:true});
  if(parameterHash(parameter)!==parameterHash(after.parameter))fail('DataReleaseSupersessionReadbackUncertain');
  validate(input,now(),{transition});await deps.assertFence(gate,mutex);verifySnapshot(after,input,now(),{successor:true,fenced:true});validate(input,now(),{transition});state.verified=true;state.phase='issued';state.parameterVersion=parameter.Version;
  await persistRecord(deps,'recordVerified','readVerified',{...state,archiveHash:hash(envelope)},'DataReleaseVerificationReceiptUnverified');
  // Persistence can consume time or lose ownership. Do not release based on
  // the freshness/authority that existed before the durable receipt write.
  validate(input,now(),{transition});const releaseSnapshot=await deps.inspect({owner,fenced:true});
  await deps.assertFence(gate,mutex);verifySnapshot(releaseSnapshot,input,now(),{successor:true,fenced:true});validate(input,now(),{transition});
  await deps.restoreGate(gate,envelope.operation,mutex);state.gateRestored=true;
  verifySnapshot(releaseSnapshot,input,now(),{successor:true,fenced:true});validate(input,now(),{transition});await deps.releaseMutex(mutex,envelope.operation);state.mutexReleased=true;state.phase='complete';
 }catch(error){
  state.error=/^[A-Za-z0-9_.:-]{1,128}$/.test(error?.message??'')?error.message:'DataReleaseSupersessionFailed';
  if(!mutex&&error?.mutex){mutex=error.mutex;state.mutex=mutex;}
  // A deadline guard may carry hold:true from an adapter. It does not erase
  // this issuer's positive no-send knowledge, but it cannot excuse an unknown
  // acquisition/intent or unconfirmed child cleanup. All abort proof below is
  // still mandatory before any cleanup capability is used.
  const caughtAt=now(),deadlineOnly=!advancePending&&error?.code!=='ECLEANUP'&&error?.cleanupComplete!==false&&
   ['DataReleaseSupersessionOperationExpired','SupersessionAdmissionExpired'].includes(error?.message)&&Number.isSafeInteger(caughtAt)&&
   caughtAt>=supersessionOperationDeadline({issuedMs:input.authorization.data.issuedMs,reviewedMs:input.authorization.review.reviewedMs,expiresMs:input.authorization.data.expiresMs});
  if(state.sent||error?.hold&&!deadlineOnly)state.phase=state.gateRestored?'issued_cleanup_pending':'held';
  else try{
   await verifyArchive(deps,envelope);
   const intent=await deps.readIntent(owner);
   if(intent&&hash(intent)!==hash(writeIntent(envelope)))fail('DataReleaseReconciliationIntentInvalid');
   // The running issuer knows it has not crossed the Put boundary. Preserve
   // that positive evidence before releasing any resource, even with an intent.
   await verifyUnsentPredecessor(deps,envelope,intent);
   await persistAbort(deps,noSendReceipt(envelope,intent,mutex,gate));
   await verifyUnsentPredecessor(deps,envelope,intent);
   if(mutex){
    const releaseSnapshot=await deps.inspect({owner,fenced:true});
    await deps.assertFence(gate,mutex);verifySnapshot(releaseSnapshot,input,now(),{fenced:true});
   }
   if(gate)await deps.restoreGate(gate,envelope.operation,mutex);if(mutex)await deps.releaseMutex(mutex,envelope.operation);state.phase='rejected';
  }catch{state.phase='held';}
 }
 await deps.recordOutcome(state);return state;
}

/** Reconciliation has no Put/Delete callback use. An old or missing value is
 * always uncertain here; negative/terminal conclusions require independently
 * corroborated service/history evidence and are not inferred from stale reads. */
export async function reconcileProductionImageRelease(deps,envelope,{transition}={}){
 envelope=immutable(normalized(envelope));
 const input={authorization:envelope.authorization,expected:envelope.expected,predecessor:envelope.predecessor,lineage:envelope.lineage},now=deps.now??Date.now;
 validate(input,now(),{historical:true,transition});if(hash(envelopeFor(input))!==hash(envelope))fail('DataReleaseArchiveUnverified');
 await verifyArchive(deps,envelope);await deps.assertRecoveryOwner(envelope.operation);
 const intent=await deps.readIntent(envelope.operation.owner);
 if(intent&&hash(intent)!==hash(writeIntent(envelope)))fail('DataReleaseReconciliationIntentInvalid');
 const acquisition=await deps.readAcquisitionIntent(envelope.operation.owner);
 if(acquisition&&hash(acquisition)!==hash(acquisitionIntent(envelope))||intent&&!acquisition)fail('DataReleaseAcquisitionIntentInvalid');
 // These are authenticated acquisition descriptors, retained after release;
 // they are not a list of currently active resources. Release receipts must
 // authenticate the original descriptors and the helpers recheck their state.
 const fences=await deps.readFences(envelope.operation.owner),{mutex,gate}=fences;
 const state={version:1,owner:envelope.operation.owner,authorizationHash:input.authorization.hash,phase:'held',sent:true,verified:false,writeAttempted:false};
 try{
  if(mutex&&mutex.owner!==state.owner||gate&&gate.owner!==state.owner||fences.mutexReleased&&!mutex||fences.gateReleased&&!gate)fail('DataReleaseReconciliationFenceInvalid');
  const aborted=await deps.readAborted(state.owner);
  if(!intent||aborted){
   if(!gate&&fences.gateAttempt)fail('DataReleaseGateAcquisitionUncertain');
   const abortReceipt=noSendReceipt(envelope,intent,mutex,gate);
   if(aborted&&hash(aborted)!==hash(abortReceipt))fail('DataReleaseAbortReceiptInvalid');
   if(!mutex){
    if(gate||fences.mutexAttempt||!aborted&&(acquisition||intent))fail('DataReleaseAcquisitionUncertain');
    await verifyUnsentPredecessor(deps,envelope,intent);
    if(!aborted)await persistAbort(deps,abortReceipt);
    await deps.assertRecoveryOwner(envelope.operation);
    if(hash(await deps.readAcquisitionIntent(state.owner))!==hash(acquisition))fail('DataReleaseAcquisitionIntentChanged');
    await verifyUnsentPredecessor(deps,envelope,intent);
    state.sent=false;state.phase='aborted';await deps.recordOutcome(state);return state;
   }
   if(fences.gateReleased||fences.mutexReleased){
    if(!aborted||gate&&!fences.gateReleased||fences.gateReleased&&fences.gateReleased.owner!==state.owner||fences.mutexReleased&&fences.mutexReleased.owner!==state.owner)fail('DataReleaseAbortReceiptInvalid');
    await verifyUnsentPredecessor(deps,envelope,intent);
    await finishRecoveryRelease(deps,envelope,input,fences,now,{successor:false});
    state.sent=false;state.phase='aborted';await deps.recordOutcome(state);return state;
   }
   await deps.assertFence(gate,mutex);const before=await deps.inspect({owner:state.owner,fenced:true});verifySnapshot(before,input,now(),{fenced:true});
   await verifyUnsentPredecessor(deps,envelope,intent);
   if(!aborted)await persistAbort(deps,abortReceipt);
   const releaseSnapshot=await deps.inspect({owner:state.owner,fenced:true});
   await deps.assertFence(gate,mutex);verifySnapshot(releaseSnapshot,input,now(),{fenced:true});
   if(gate)await deps.restoreGate(gate,envelope.operation,mutex);await deps.releaseMutex(mutex,envelope.operation);
   state.sent=false;state.phase='aborted';await deps.recordOutcome(state);return state;
  }
  if(!mutex||!gate)fail('DataReleaseReconciliationFenceInvalid');
  const verified=await deps.readVerified(state.owner);
  if(verified&&(verified.owner!==state.owner||verified.verified!==true||verified.authorizationHash!==state.authorizationHash||verified.parameterVersion!==input.predecessor.Version+1||verified.archiveHash!==hash(envelope)))fail('DataReleaseVerificationReceiptInvalid');
  if(fences.gateReleased||fences.mutexReleased){
   if(!verified||!fences.gateReleased||fences.gateReleased.owner!==state.owner||fences.mutexReleased&&fences.mutexReleased.owner!==state.owner)fail('DataReleaseReleaseReceiptInvalid');
   const p=await deps.readback();inspectParameter(p,input.expected);
   if(p.Version!==input.predecessor.Version+1||p.Value!==JSON.stringify(input.authorization.data))fail('DataReleaseSupersessionReadbackUncertain');
   await finishRecoveryRelease(deps,envelope,input,fences,now,{successor:true});
   state.verified=true;state.parameterVersion=p.Version;state.expired=now()>=input.authorization.data.expiresMs;state.phase='complete';
   await deps.recordOutcome(state);return state;
  }
  await deps.assertFence(gate,mutex);const snapshot=await deps.inspect({owner:state.owner,fenced:true});
  await deps.assertFence(gate,mutex);verifySnapshot(snapshot,input,now(),{successor:true,fenced:true});
  state.parameterVersion=snapshot.parameter.Version;state.verified=true;
  // Expiry never creates authority for admission, but does not prevent proving
  // which single write landed and safely releasing its already-paused fences.
  state.expired=now()>=input.authorization.data.expiresMs;
  if(!verified)await persistRecord(deps,'recordVerified','readVerified',{...state,archiveHash:hash(envelope)},'DataReleaseVerificationReceiptUnverified');
  const releaseSnapshot=await deps.inspect({owner:state.owner,fenced:true});
  await deps.assertFence(gate,mutex);verifySnapshot(releaseSnapshot,input,now(),{successor:true,fenced:true});
  await deps.restoreGate(gate,envelope.operation,mutex);await deps.releaseMutex(mutex,envelope.operation);state.phase='complete';
 }catch(error){state.error=/^[A-Za-z0-9_.:-]{1,128}$/.test(error?.message??'')?error.message:'DataReleaseReconciliationUncertain';}
 await deps.recordOutcome(state);return state;
}
