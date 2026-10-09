import {IMAGE_TRANSITION_LIMITS as legacy, IMAGE_TRANSITION_LIMITS_HASH} from './production-image-transition.mjs';
import {nonrootHash as hash, copyNonrootJson} from './production-nonroot-contracts.mjs';

const need=(ok,code)=>{if(!ok)throw Error(code);};
const fields=['ecrRequests','logicalBytes','httpBodyBytes','uncompressedBytes','processedEntries'];
const revisionFields=['version','limitsHash','envelopeHash','historyHeadHash'];
const exact=(value,keys)=>need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.toSorted().join(),'NonrootBudgetRevisionFields');
const hex=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);

export const NONROOT_LEGACY_ACCOUNTING_CAPS=Object.freeze({
 ecrRequests:legacy.maxEcrCalls,logicalBytes:legacy.maxTransferredBytes,httpBodyBytes:legacy.maxTransferredBytes,
 uncompressedBytes:legacy.maxUncompressedBytes,processedEntries:legacy.maxFsEntries,
});
export const NONROOT_REMAINING_WORK_CAPS_V2=Object.freeze({
 ecrRequests:20000,logicalBytes:64*1024**3,httpBodyBytes:32*1024**3,
 uncompressedBytes:64*1024**3,processedEntries:1000000,
});
export const NONROOT_REMAINING_WORK_REVISION_V2=Object.freeze({
 version:2,kind:'remaining-work-cumulative-limits',caps:NONROOT_REMAINING_WORK_CAPS_V2,
 perOperationLimitsHash:IMAGE_TRANSITION_LIMITS_HASH,
});
export const NONROOT_REMAINING_WORK_LIMITS_HASH_V2=hash(NONROOT_REMAINING_WORK_REVISION_V2);

/** Arithmetic selection only. The caller obtains expectedRevision from its
 * independently verified, complete envelope. Neither a journal's declaration
 * nor this helper authenticates an envelope or authorizes an operation. */
export function nonrootAccountingPolicy(revision,expectedRevision,expectedCeiling){
 let version=1,caps=NONROOT_LEGACY_ACCOUNTING_CAPS,budgetRevision;
 if(revision===undefined){need(expectedRevision===undefined&&expectedCeiling===undefined,'NonrootBudgetRevisionMissing');}
 else{
  exact(revision,revisionFields);exact(expectedRevision,revisionFields);
  need(revision.version===2&&revision.limitsHash===NONROOT_REMAINING_WORK_LIMITS_HASH_V2&&
   hex(revision.envelopeHash)&&hex(revision.historyHeadHash),'NonrootBudgetRevisionBinding');
  need(hash(revision)===hash(expectedRevision),'NonrootBudgetRevisionMismatch');
  exact(expectedCeiling,fields);
  for(const key of fields)need(Number.isSafeInteger(expectedCeiling[key])&&expectedCeiling[key]>=0&&expectedCeiling[key]<=NONROOT_REMAINING_WORK_CAPS_V2[key],'NonrootBudgetCeiling');
  version=2;caps=Object.freeze(copyNonrootJson(expectedCeiling));budgetRevision=Object.freeze(copyNonrootJson(revision));
 }
 const counter=value=>{
  exact(value,fields);
  for(const key of fields)need(Number.isSafeInteger(value[key])&&value[key]>=0&&value[key]<=caps[key],'NonrootBudgetCounter');
  return value;
 };
 return Object.freeze({version,caps,counter,...(budgetRevision?{budgetRevision}:{})});
}

/** Read an envelope already committed by the independent protected-inputs
 * digest and original copy checkpoint. This checks its commitment and sums;
 * producer/source authentication remains the responsibility of admission. */
export function inspectCommittedNonrootBudgetEnvelope(value,{budgetRevision,owner}){
 const v=copyNonrootJson(value);
 exact(v,['version','kind','limitsHash','perOperationLimitsHash','inputBindingHash','history','bindings','components','parts','rootCatalogHash','rootMaximumCalls','knownRemaining','completionReserve','projected','authority','executionReady','designRefs','proposalHash','caps','headroom','complete','status','fits','overCap','unresolved','envelopeHash','budgetRevision']);
 const {envelopeHash,budgetRevision:declared,...body}=v;
 need(v.version===2&&v.kind==='remaining-work-budget-envelope'&&v.authority===false&&v.executionReady===false&&v.complete===true&&v.status==='BUDGET_FITS'&&v.fits===true&&Array.isArray(v.unresolved)&&v.unresolved.length===0&&Array.isArray(v.overCap)&&v.overCap.length===0,'NonrootBudgetEnvelopeIncomplete');
 need(hex(envelopeHash)&&hash(body)===envelopeHash&&envelopeHash===budgetRevision?.envelopeHash,'NonrootBudgetEnvelopeCommitment');
 need(v.limitsHash===NONROOT_REMAINING_WORK_LIMITS_HASH_V2&&v.perOperationLimitsHash===IMAGE_TRANSITION_LIMITS_HASH&&hash(v.caps)===hash(NONROOT_REMAINING_WORK_CAPS_V2),'NonrootBudgetEnvelopeLimits');
 const policy=nonrootAccountingPolicy(declared,budgetRevision,v.projected);
 need(typeof owner==='string'&&/^[a-f0-9]{32}$/.test(owner)&&v.history?.owner===owner&&v.history.headHash===declared.historyHeadHash,'NonrootBudgetEnvelopeOwner');
 exact(v.bindings,['source','sourceReview','policy','scopes','inventory','rootBinding','carrierTemplate','operationSet']);
 const bindings=Object.fromEntries(Object.entries(v.bindings).filter(([key])=>key!=='sourceReview'));
 need(hash({limitsHash:v.limitsHash,history:v.history,bindings})===v.inputBindingHash,'NonrootBudgetEnvelopeInput');
 const proposal={version:v.version,kind:'remaining-work-budget-proposal',limitsHash:v.limitsHash,perOperationLimitsHash:v.perOperationLimitsHash,inputBindingHash:v.inputBindingHash,history:v.history,bindings,components:v.components,parts:v.parts,rootCatalogHash:v.rootCatalogHash,rootMaximumCalls:v.rootMaximumCalls,knownRemaining:v.knownRemaining,completionReserve:v.completionReserve,projected:v.projected};
 need(hash(proposal)===v.proposalHash,'NonrootBudgetEnvelopeProposal');
 const ids=['remainingMetadata','originalIssuers','legacy','carrier','ciEnvelope','copy','futureNonroot','finalization','root:before-copy',...['9','17','19','21','23'].map(n=>'root:deploy-prod/'+n)];
 need(Array.isArray(v.parts)&&v.parts.length===ids.length&&new Set(v.parts.map(p=>p.id)).size===ids.length&&v.parts.every(p=>ids.includes(p.id)&&p.complete===true),'NonrootBudgetEnvelopeParts');
 const sums=Object.fromEntries(fields.map(key=>[key,0])),reserves={...sums};
 for(const part of v.parts){
  policy.counter(part.charge);policy.counter(part.completionReserve);
  for(const key of fields){need(part.completionReserve[key]<=part.charge[key],'NonrootBudgetEnvelopeReserve');sums[key]+=part.charge[key];reserves[key]+=part.completionReserve[key];}
 }
 policy.counter(sums);policy.counter(reserves);policy.counter(v.history.counters);
 need(hash(sums)===hash(v.knownRemaining)&&hash(reserves)===hash(v.completionReserve),'NonrootBudgetEnvelopeSum');
 for(const key of fields)need(v.projected[key]===v.history.counters[key]+sums[key]&&v.headroom[key]===v.caps[key]-v.projected[key],'NonrootBudgetEnvelopeProjection');
 return Object.freeze({budgetRevision:policy.budgetRevision,compiledCeiling:policy.caps});
}
