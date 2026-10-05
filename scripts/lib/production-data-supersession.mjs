import {inspectDataRelease,requireActiveDataRelease} from './production-data-release.mjs';
import {PRODUCTION_DATA_RELEASE_PARAMETER as parameterName} from './production-data-issuance.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';

const fail=code=>{throw Error(code);};
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join();
const hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
const fingerprints=['sourceEvidenceHash','materialHash','runtimeHash','buildInputsHash','securityEvidenceHash','freshBuildSecurityHash','policyHash','parentProofHash','rootHash','writerBoundaryHash','lineageHash'];
const unchanged=['stage','account','region','dataRevision','dataSourceTree','dataSourceTag','images','runtimeNonce','generation','targetsHash','parentProofHash','backendBindingHash','schemaDigest','operatorDigest','buildInputsHash'];
const normalized=v=>JSON.parse(JSON.stringify(v));
const parameterHash=v=>hash(normalized(v));
export const MAX_SUPERSESSION_LINEAGE=1000;
export const SUPERSESSION_EVIDENCE_MAX_AGE_MS=300000;

function inspectParameter(p,expected){
 if(!p||p.Name!==parameterName||p.Type!=='SecureString'||!Number.isSafeInteger(p.Version)||p.Version<1||
   p.ARN!==`arn:aws:ssm:${expected.region}:${expected.account}:parameter${parameterName}`||typeof p.Value!=='string')fail('DataReleasePredecessorInvalid');
 return inspectDataRelease(p.Value,{stage:'prod',account:expected.account,region:expected.region,controlSourceTree:JSON.parse(p.Value).controlSourceTree});
}

/** The private adapter authenticates these complete create-only archive records.
 * SSM history is not the full-lineage authority and may have a shorter window. */
export function validateSupersessionLineage(lineage,predecessor,nextId){
 if(!Array.isArray(lineage)||!lineage.length||lineage.length>MAX_SUPERSESSION_LINEAGE||lineage.length!==predecessor.Version||!hex(nextId,32))fail('DataReleaseLineageInvalid');
 const anchor=JSON.parse(predecessor.Value),ids=new Set();let previous=null;
 for(const [index,row] of lineage.entries()){
  if(!exact(row,['parameterVersion','predecessorHash','authorization','authorizationHash'])||row.parameterVersion!==index+1||row.predecessorHash!==previous||
    !hex(row.authorizationHash)||row.authorizationHash!==hash(row.authorization)||!hex(row.authorization?.authorizationId,32)||ids.has(row.authorization.authorizationId))fail('DataReleaseLineageInvalid');
  inspectDataRelease(row.authorization,{stage:'prod',account:anchor.account,region:anchor.region,controlSourceTree:row.authorization.controlSourceTree});
  for(const field of unchanged)if(hash(row.authorization[field])!==hash(anchor[field]))fail('DataReleaseLineageBindingChanged');
  ids.add(row.authorization.authorizationId);previous=row.authorizationHash;
 }
 if(previous!==hash(JSON.parse(predecessor.Value))||ids.has(nextId))fail('DataReleaseAuthorizationIdReused');
 return hash(lineage);
}

function validate(input,now,{historical=false}={}){
 if(!exact(input,['authorization','expected','predecessor','lineage']))fail('DataReleaseSupersessionInputInvalid');
 const {authorization,expected,predecessor,lineage}=input,data=authorization?.data;
 if(!exact(expected,['account','region','controlRevision','controlSourceTree',...fingerprints])||!hex(expected.controlRevision,40)||fingerprints.some(k=>!hex(expected[k])))fail('DataReleaseSupersessionContextInvalid');
 const previous=inspectParameter(predecessor,expected),context={stage:'prod',account:expected.account,region:expected.region,controlSourceTree:expected.controlSourceTree};
 const next=historical?inspectDataRelease(data,context):requireActiveDataRelease(data,context,{now});
 if(next.hash!==authorization.hash||previous.data.expiresMs>now||previous.data.authorizationId===data.authorizationId)fail('DataReleaseSupersessionIdentityInvalid');
 for(const field of unchanged)if(hash(previous.data[field])!==hash(data[field]))fail('DataReleaseRetainedBindingChanged');
 if(expected.lineageHash!==validateSupersessionLineage(lineage,predecessor,data.authorizationId))fail('DataReleaseLineageChanged');
 const review=authorization.review;
 if(!review||review.version!==1||review.kind!=='retained-data-policy-review'||review.decision!=='within-existing-policy'||
    review.controlSourceTree!==data.controlSourceTree||review.expiresMs!==data.expiresMs||!hex(review.policySourcesHash)||hash(review)!==data.policyHash)fail('DataReleasePolicyReviewInvalid');
 for(const field of ['sourceEvidenceHash','parentProofHash','buildInputsHash','securityEvidenceHash','freshBuildSecurityHash'])if(review[field]!==expected[field])fail('DataReleasePolicyReviewInvalid');
 for(const field of ['parentProofHash','buildInputsHash','securityEvidenceHash','policyHash'])if(data[field]!==expected[field])fail('DataReleaseSupersessionContextInvalid');
 if(!historical&&(now-data.issuedMs>SUPERSESSION_EVIDENCE_MAX_AGE_MS||!Number.isSafeInteger(review.reviewedMs)||review.reviewedMs>now||now-review.reviewedMs>SUPERSESSION_EVIDENCE_MAX_AGE_MS))fail('DataReleaseSupersessionEvidenceExpired');
 return {previous:previous.data,data};
}

function verifySnapshot(snapshot,input,now,{successor=false,fenced=false}={}){
 const {expected,predecessor,authorization}=input,owner=authorization.data.authorizationId;
 if(!snapshot||Object.keys(expected).some(k=>snapshot[k]!==expected[k]))fail('DataReleaseSnapshotChanged');
 if(snapshot.rootVerified!==true||snapshot.writersSerialized!==true||snapshot.executionEnabled!==false||snapshot.dispatcherEnabled!==false||
   ['enabledSchedules','activeWorkers','activeAdministration','activeContinuations','benchmarkRemaining'].some(k=>snapshot[k]!==0))fail('DataReleaseSupersessionNotPaused');
 if(!Number.isSafeInteger(snapshot.observedMs)||snapshot.observedMs>now||now-snapshot.observedMs>SUPERSESSION_EVIDENCE_MAX_AGE_MS||fenced&&snapshot.fenceOwner!==owner)fail('DataReleaseSnapshotNotFresh');
 const p=snapshot.parameter;inspectParameter(p,expected);
 if(successor){if(p.Version!==predecessor.Version+1||p.Value!==JSON.stringify(authorization.data))fail('DataReleaseSupersessionReadbackUncertain');}
 else if(parameterHash(p)!==parameterHash(predecessor))fail('DataReleasePredecessorChanged');
}

function envelopeFor(input){
 const {authorization,expected,predecessor}=input;
 const commitment={version:1,kind:'retained-data-supersession',predecessorHash:parameterHash(predecessor),predecessorVersion:predecessor.Version,
  authorizationHash:authorization.hash,authorizationId:authorization.data.authorizationId,nextVersion:predecessor.Version+1};
 const operation={owner:authorization.data.authorizationId,expected:{revision:expected.controlRevision,newValue:JSON.stringify(commitment)},prior:{value:predecessor.Value}};
 return {version:1,kind:'retained-data-supersession',operation,predecessor:normalized(predecessor),authorization:normalized(authorization),expected:normalized(expected),lineage:normalized(input.lineage)};
}
async function verifyArchive(deps,envelope){
 const stored=await deps.readArchive(envelope.operation.owner);
 if(!stored||hash(stored)!==hash(envelope))fail('DataReleaseArchiveUnverified');
}
function writeIntent(envelope){return {version:1,owner:envelope.operation.owner,parameter:parameterName,archiveHash:hash(envelope),nextVersion:envelope.predecessor.Version+1,authorizationHash:envelope.authorization.hash};}
function acquisitionIntent(envelope){return {version:1,owner:envelope.operation.owner,archiveHash:hash(envelope),kind:'acquire-supersession-fences'};}
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

/** One protected overwrite. The adapter owns the existing non-expiring mutex,
 * authenticated fresh evidence and durable create-only archive implementation.
 * No post-write observation can cause a retry or corrective write. */
export async function supersedeProductionDataRelease(deps,input){
 const now=deps.now??Date.now;validate(input,now());const envelope=envelopeFor(input),owner=envelope.operation.owner;
 if(await deps.priorAttempt(owner)!==null||await deps.readArchive(owner)!==null)fail('DataReleaseReconciliationRequired');
 verifySnapshot(await deps.inspect(),input,now());await deps.archive(envelope);await verifyArchive(deps,envelope);
 const state={version:1,owner,authorizationHash:input.authorization.hash,predecessorVersion:input.predecessor.Version,phase:'inspecting',sent:false,verified:false};
 let mutex,gate;
 try{
  // Durable, authenticated absence of this record after issuer termination
  // distinguishes an archive-only crash from an uncertain fence acquisition.
  await persistRecord(deps,'recordAcquisitionIntent','readAcquisitionIntent',acquisitionIntent(envelope),'DataReleaseAcquisitionIntentUnverified');
  mutex=await deps.acquireMutex(envelope.operation);state.mutex=mutex;
  gate=await deps.acquireGate(envelope.operation,mutex);state.gate=gate;
  verifySnapshot(await deps.inspect({owner,fenced:true}),input,now(),{fenced:true});validate(input,now());
  await verifyArchive(deps,envelope);await deps.assertFence(gate,mutex);
  await persistRecord(deps,'recordIntent','readIntent',writeIntent(envelope),'DataReleaseWriteIntentUnverified');
  // Re-read the exact predecessor after all archive/inspection work. The
  // non-expiring owned mutex remains held across the single write and checks.
  if(parameterHash(await deps.readback())!==parameterHash(input.predecessor))fail('DataReleasePredecessorChanged');
  await deps.assertFence(gate,mutex);validate(input,now());state.sent=true;state.phase='attempted';
  let response;try{response=await deps.putParameter({Name:parameterName,Type:'SecureString',Value:JSON.stringify(input.authorization.data),Overwrite:true});}catch{state.transportUncertain=true;}
  if(response!==undefined&&response.Version!==input.predecessor.Version+1)fail('DataReleaseWriteVersionConflict');
  const parameter=await deps.readback();
  // Exact readback is necessary but not sufficient: repeat the entire live
  // audit. This is evidence/release gating, never permission for another Put.
  const after=await deps.inspect({owner,fenced:true});verifySnapshot(after,input,now(),{successor:true,fenced:true});
  if(parameterHash(parameter)!==parameterHash(after.parameter))fail('DataReleaseSupersessionReadbackUncertain');
  validate(input,now());await deps.assertFence(gate,mutex);state.verified=true;state.phase='issued';state.parameterVersion=parameter.Version;
  await persistRecord(deps,'recordVerified','readVerified',{...state,archiveHash:hash(envelope)},'DataReleaseVerificationReceiptUnverified');
  // Persistence can consume time or lose ownership. Do not release based on
  // the freshness/authority that existed before the durable receipt write.
  const releaseSnapshot=await deps.inspect({owner,fenced:true});
  await deps.assertFence(gate,mutex);verifySnapshot(releaseSnapshot,input,now(),{successor:true,fenced:true});validate(input,now());
  await deps.restoreGate(gate,envelope.operation,mutex);state.gateRestored=true;
  await deps.releaseMutex(mutex,envelope.operation);state.mutexReleased=true;state.phase='complete';
 }catch(error){
  state.error=/^[A-Za-z0-9_.:-]{1,128}$/.test(error?.message??'')?error.message:'DataReleaseSupersessionFailed';
  if(!mutex&&error?.mutex){mutex=error.mutex;state.mutex=mutex;}
  if(state.sent||error?.hold)state.phase=state.gateRestored?'issued_cleanup_pending':'held';
  else try{
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
export async function reconcileProductionDataSupersession(deps,envelope){
 const input={authorization:envelope.authorization,expected:envelope.expected,predecessor:envelope.predecessor,lineage:envelope.lineage},now=deps.now??Date.now;
 validate(input,now(),{historical:true});if(hash(envelopeFor(input))!==hash(envelope))fail('DataReleaseArchiveUnverified');
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
    if(gate)await deps.restoreGate(gate,envelope.operation,mutex);await deps.releaseMutex(mutex,envelope.operation);
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
   // Existing fence helpers re-read and authenticate released receipts. They
   // must not require an already-released gate to become active again.
   await deps.restoreGate(gate,envelope.operation,mutex);await deps.releaseMutex(mutex,envelope.operation);
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
