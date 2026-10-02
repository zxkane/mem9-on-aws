import {requireActiveDataRelease} from './production-data-release.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';

const fail=code=>{throw Error(code);};
const fingerprints=['sourceEvidenceHash','materialHash','runtimeHash','buildInputsHash','securityEvidenceHash','policyHash','parentProofHash'];
const safeError=e=>/^[A-Za-z0-9_.:-]{1,128}$/.test(e?.message??'')?e.message:'DataReleaseIssuanceFailed';
export const PRODUCTION_DATA_RELEASE_PARAMETER='/mem9-on-aws/prod/consolidation-runtime/data-release';

function verifySnapshot(actual,expected,authorization,{issued=false}={}){
  if(!actual||!expected||Object.keys(expected).sort().join()!==['account','region','controlRevision','controlSourceTree',...fingerprints].sort().join())fail('DataReleaseSnapshotInvalid');
  for(const key of Object.keys(expected))if(actual[key]!==expected[key])fail('DataReleaseSnapshotChanged');
  if(actual.executionEnabled!==false||actual.dispatcherEnabled!==false||actual.enabledSchedules!==0||
    actual.activeWorkers!==0||actual.activeAdministration!==0||actual.benchmarkRemaining!==0)fail('DataReleaseProductionNotPaused');
  const parameter=actual.parameter;
  if(!issued){if(parameter!==null)fail('DataReleaseAlreadyExists');return;}
  const data=authorization.data;
  if(parameter?.Name!==PRODUCTION_DATA_RELEASE_PARAMETER||parameter.Type!=='SecureString'||parameter.Version!==1||
    parameter.ARN!==`arn:aws:ssm:${data.region}:${data.account}:parameter${PRODUCTION_DATA_RELEASE_PARAMETER}`||
    parameter.Value!==JSON.stringify(data))fail('DataReleaseReadbackUncertain');
}

/** One protected creation, under the existing operator mutex/deployment fence.
 * The adapter independently obtains every snapshot from AWS/GitHub/database
 * evidence. A pre-existing intent is reconciliation-only, never another write.
 */
export async function issueProductionDataRelease(deps,{authorization,expected}){
  const now=deps.now??Date.now,data=authorization?.data;
  const active=()=>{
    const checked=requireActiveDataRelease(data,{stage:'prod',account:expected?.account,region:expected?.region,controlSourceTree:expected?.controlSourceTree},{now:now()});
    if(checked.hash!==authorization.hash||!/^([a-f0-9]{40})$/.test(expected.controlRevision??''))fail('DataReleaseIssuanceIdentity');
    for(const field of fingerprints){
      if(!/^[a-f0-9]{64}$/.test(expected[field]??''))fail('DataReleaseIssuanceIdentity');
      if(['buildInputsHash','securityEvidenceHash','policyHash','parentProofHash'].includes(field)&&expected[field]!==data[field])fail('DataReleaseIssuanceIdentity');
    }
  };
  active();
  const owner=data.authorizationId,operation={owner,expected:{...expected,newValue:JSON.stringify(data),revision:expected.controlRevision},prior:{value:'absent'}};
  const state={version:1,owner,authorizationHash:authorization.hash,phase:'inspecting',sent:false,verified:false};
  const prior=await deps.priorAttempt(owner);
  if(prior!==null)fail('DataReleaseReconciliationRequired');
  verifySnapshot(await deps.inspect(),expected,authorization);
  await deps.archive(operation,authorization);
  let mutex,gate;
  const record=async()=>{try{await deps.recordOutcome(state);}catch{}};
  try{
    mutex=await deps.acquireMutex(operation);state.mutex=mutex;
    gate=await deps.acquireGate(operation,mutex);state.gate=gate;
    const before=await deps.inspect();verifySnapshot(before,expected,authorization);active();
    await deps.assertFence(gate,mutex);
    await deps.recordIntent({owner,authorizationHash:authorization.hash,parameter:PRODUCTION_DATA_RELEASE_PARAMETER,at:now()});
    active();
    state.phase='attempted';state.sent=true;
    let response;
    try{
      response=await deps.putParameter({Name:PRODUCTION_DATA_RELEASE_PARAMETER,Type:'SecureString',Value:JSON.stringify(data),Overwrite:false});
    }catch(error){state.transportError=safeError(error);}
    if(response!==undefined&&response.Version!==1)fail('DataReleaseWriteVersionConflict');
    const parameter=await deps.readback();
    verifySnapshot({...before,parameter},expected,authorization,{issued:true});
    const after=await deps.inspect();verifySnapshot(after,expected,authorization,{issued:true});active();
    await deps.assertFence(gate,mutex);active();
    state.verified=true;state.phase='issued';state.parameterVersion=parameter.Version;
    await deps.recordVerified({...state,at:now()});
    await deps.restoreGate(gate,operation,mutex);state.gateRestored=true;
    await deps.releaseMutex(mutex,operation);state.mutexReleased=true;
    state.phase='complete';await record();return state;
  }catch(error){
    state.error=safeError(error);
    if(!mutex&&error?.mutex){mutex=error.mutex;state.mutex=mutex;}
    if(state.gateRestored){state.phase='issued_cleanup_pending';await record();return state;}
    if(state.sent||error?.hold){state.phase='held';await record();return state;}
    try{
      if(gate)await deps.restoreGate(gate,operation,mutex);
      if(mutex)await deps.releaseMutex(mutex,operation);
      state.phase='rejected';
    }catch(cleanupError){state.phase='held';state.cleanupError=safeError(cleanupError);}
    await record();return state;
  }
}
