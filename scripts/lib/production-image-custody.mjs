import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {inspectDataRelease} from './production-data-release.mjs';
const bindings=new WeakMap(),fail=()=>{throw Error('ImageArchiveBindingInvalid');};
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join();
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
/** Expected commitments come from authenticated protected descriptor/operation
 * reads, not from fields copied out of the untrusted archive body. This binding
 * can restore archived evidence only; it cannot construct live copy evidence.
 */
export function authenticateImageArchiveBinding({proof,data,review},expected){
 if(!exact(expected,['expectedProofHash','expectedReviewHash','expectedDataHash','expectedScope'])||!['expectedProofHash','expectedReviewHash','expectedDataHash'].every(k=>hex(expected[k]))||!exact(expected.expectedScope,['account','region','runtimeNonce','authorizationId']))fail();
 const scope=expected.expectedScope,selected=inspectDataRelease(data,{stage:'prod',account:scope.account,region:scope.region,controlSourceTree:data?.controlSourceTree});
 if(data.version!==2||scope.runtimeNonce!==data.runtimeNonce||scope.authorizationId!==data.authorizationId||hash(data)!==expected.expectedDataHash||hash(proof)!==expected.expectedProofHash||data.transition.proofHash!==expected.expectedProofHash||hash(review)!==expected.expectedReviewHash||data.policyHash!==expected.expectedReviewHash||review.imageTransitionProofHash!==expected.expectedProofHash||selected.hash!==expected.expectedDataHash)fail();
 const handle=Object.freeze({kind:'authenticated-image-archive-binding',proofHash:expected.expectedProofHash,dataHash:expected.expectedDataHash,reviewHash:expected.expectedReviewHash});
 bindings.set(handle,{proof:structuredClone(proof),data:structuredClone(data),review:structuredClone(review),scope:structuredClone(scope)});return handle;
}
export function inspectImageArchiveBinding(handle){const value=bindings.get(handle);if(!value)fail();return {proofHash:handle.proofHash,dataHash:handle.dataHash,reviewHash:handle.reviewHash,...structuredClone(value)};}
