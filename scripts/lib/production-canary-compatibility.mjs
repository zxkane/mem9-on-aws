import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {validateProductionBackendBinding} from './production-artifacts.mjs';

const fail=()=>{throw Error('CanaryCompatibilityInvalid');};
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const digest=v=>typeof v==='string'&&/^sha256:[a-f0-9]{64}$/.test(v);
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.sort().join();

export function canaryWitnessMatches(acceptance,certificateHash,parentProofHash){
  const witness=acceptance?.continuation,fixture=witness?.fixture;
  return !!(exact(witness,['version','parentProofHash','certificateHash','sourceTree','fixture'])&&witness.version===1&&
    witness.parentProofHash===parentProofHash&&witness.certificateHash===certificateHash&&witness.sourceTree===acceptance.sourceTree&&
    exact(fixture,['hash','runId','runAttempt'])&&hex(fixture.hash)&&/^[1-9][0-9]*$/.test(fixture.runId??'')&&
    Number.isSafeInteger(fixture.runAttempt)&&fixture.runAttempt>0);
}

// The host publisher resolves authenticated manifests and compares full
// material configurations. Its protected witness authorizes this exact compact
// certificate; the database operator additionally binds it to live root state.
export function validateCanaryCompatibility(certificate,parent,config,state){
  const inspected=inspectCanaryCompatibility(certificate,parent,config,state);
  if(!canaryWitnessMatches(config.acceptance,hash(certificate),certificate.parentProofHash))fail();
  if(certificate.version===2&&config.acceptance.dataReleaseHash!==certificate.dataReleaseHash)fail();
  return inspected;
}

// Structural inspection does not authorize an operator invocation. It is used
// by the independent read-only publisher before a new witness exists.
export function inspectCanaryCompatibility(certificate,parent,config,state){
  const retained=certificate?.version===2;
  if(!exact(certificate,['version','parentProofHash','generation','targetsHash','previous','current','images','material',...(retained?['dataReleaseHash']:[])])||![1,2].includes(certificate.version)||
    (retained?(!hex(certificate.dataReleaseHash)||config.dataRelease?.hash!==certificate.dataReleaseHash):config.dataRelease!==undefined)||
    certificate.parentProofHash!==hash(parent)||certificate.generation!==parent.generation||certificate.generation!==config.generation||
    certificate.targetsHash!==hash([...config.targets].sort())||hash(parent.targets)!==hash(config.targets)||
    !exact(certificate.previous,['release','backendBindingHash'])||!exact(certificate.current,['release','backendBinding'])||
    certificate.previous.backendBindingHash!==parent.backendBindingHash)fail();
  const releaseKeys=['sourceTree','coordinatorDigest','sourceTag','workerImage','schemaDigest','operatorDigest','runtimeNonce'];
  for(const release of [certificate.previous.release,certificate.current.release]){
    if(!exact(release,releaseKeys)||!/^[a-f0-9]{40}$/.test(release.sourceTree??'')||!hex(release.coordinatorDigest)||
      !/^mem9-[a-f0-9]{7}$/.test(release.sourceTag??'')||typeof release.workerImage!=='string'||!/@sha256:[a-f0-9]{64}$/.test(release.workerImage)||
      release.schemaDigest!==state.identity.schemaDigest||release.operatorDigest!==state.identity.operatorDigest||release.runtimeNonce!==state.operation_nonce)fail();
  }
  const previous=certificate.previous.release,next=certificate.current.release;
  if(hash(previous)!==parent.releaseHash||previous.workerImage!==parent.workerImage||previous.sourceTag!==parent.sourceTag||
    next.workerImage!==config.workerImage||next.sourceTag!==config.sourceTag||next.sourceTree!==config.acceptance.sourceTree||
    next.coordinatorDigest!==config.acceptance.coordinatorDigest)fail();
  const components=['worker','mnemo-server','qwen3-embed','llm-proxy'];
  if(!exact(certificate.images,components))fail();
  for(const image of Object.values(certificate.images)){
    if(!exact(image,['previousRoot','currentRoot','previousChild','currentChild'])||!Object.values(image).every(digest)||
      image.previousChild!==image.currentChild||image.previousRoot===image.previousChild||image.currentRoot===image.currentChild)fail();
  }
  if(!previous.workerImage.endsWith('@'+certificate.images.worker.previousRoot)||!next.workerImage.endsWith('@'+certificate.images.worker.currentRoot))fail();
  const kinds=['planner','executor','backend','network','authority','credentials'];
  if(!exact(certificate.material,kinds))fail();
  for(const material of Object.values(certificate.material))if(!exact(material,['previous','current'])||!hex(material.previous)||material.previous!==material.current)fail();
  const backendBinding=validateProductionBackendBinding(certificate.current.backendBinding,state.identity.clusterArn);
  for(const container of backendBinding.containers){
    const image=certificate.images[container.name];
    if(!image||![image.currentRoot,image.currentChild].includes(container.imageDigest))fail();
  }
  return {backendBinding,previousRelease:previous,release:next,certificateHash:hash(certificate)};
}
