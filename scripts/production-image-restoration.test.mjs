import {it,expect} from 'vitest';
import {imageTransitionFixture,imageTransitionServingFixture} from './production-image-transition.fixture.mjs';
import {buildImageTransitionProof,verifyImageTransitionProof,imageTransitionProofExpected,bindImageTransitionAuthorization,assertImageTransitionDataRelease} from './lib/production-image-transition-proof.mjs';
import {restoreImageVerificationEvidence} from './lib/production-image-restoration.mjs';
import {inspectImageCopyVerification,imageGraphState} from './lib/production-image-graph.mjs';
import {inspectImageFilesystemEvidence,imageFilesystemRequirements} from './lib/production-image-filesystem.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
async function fixture(){
 const f=await imageTransitionFixture(),b=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,b),proof=b.proof;
 const input={proof,data:s.data,review:s.review,graphEvidence:{version:1,graphHash:hash(proof.graph),summary:proof.graph,inventory:proof.graphInventory,destinationReadback:proof.destinationReadback},filesystemEvidence:{version:1,filesystemHash:hash(proof.filesystem),evidence:proof.filesystemEvidence,filesystem:proof.filesystem}};
 const expected={expectedProofHash:b.proofHash,expectedDataHash:hash(s.data),expectedReviewHash:hash(s.review),expectedScope:{account:s.data.account,region:s.data.region,runtimeNonce:s.data.runtimeNonce,authorizationId:s.data.authorizationId}};
 return {f,b,s,input,expected};
}
it('restores only committed archive custody without making a live-copy handle',async()=>{
 const f=await fixture(),restored=restoreImageVerificationEvidence(f.input,f.expected),copy=inspectImageCopyVerification(restored.graphVerification);
 expect(copy.kind).toBe('archived-copy-evidence');expect(copy.archiveBinding.dataHash).toBe(f.expected.expectedDataHash);
 expect(inspectImageFilesystemEvidence(restored.filesystemVerification)).toEqual(f.b.proof.filesystemEvidence);
 expect(()=>imageGraphState(restored.graphVerification)).toThrow();expect(()=>imageFilesystemRequirements(restored.filesystemVerification)).toThrow();
});
it.each(['proof','data','review','scope','graph','filesystem'])('rejects altered %s under unchanged protected commitments',async kind=>{
 const f=await fixture(),input=structuredClone(f.input),expected=structuredClone(f.expected);
 if(kind==='proof')input.proof.observedMs++;if(kind==='data')input.data.authorizationId='0'.repeat(32);if(kind==='review')input.review.reviewedMs++;
 if(kind==='scope')expected.expectedScope.account='0'.repeat(12);if(kind==='graph')input.graphEvidence.inventory.nodes.pop();if(kind==='filesystem')input.filesystemEvidence.filesystem.databaseText+='changed';
 expect(()=>restoreImageVerificationEvidence(input,expected)).toThrow();
});
it('does not accept archive custody for first proof construction',async()=>{
 const f=await fixture(),restored=restoreImageVerificationEvidence(f.input,f.expected);
 await expect(buildImageTransitionProof(f.f.input,{...f.f,...restored})).rejects.toThrow();
});
it('can verify an existing committed proof and bind its original final review',async()=>{
 const f=await fixture(),restored=restoreImageVerificationEvidence(f.input,f.expected),expected=imageTransitionProofExpected(f.b.proof,{proofHash:f.b.proofHash});
 const context=await verifyImageTransitionProof(f.b.proof,{...restored,proofHash:f.b.proofHash,expected,now:f.f.now,current:f.s.data,review:f.s.review,targetObservation:{observedMs:f.f.now,artifacts:f.f.input.artifacts}});
 const authorized=bindImageTransitionAuthorization(context,{review:f.s.review,now:f.f.now});
 expect(()=>assertImageTransitionDataRelease(authorized,{current:f.s.data,controlSourceTree:f.s.data.controlSourceTree,now:f.f.now})).not.toThrow();
 const changed={...f.s.data,authorizationId:'0'.repeat(32)};expect(()=>assertImageTransitionDataRelease(authorized,{current:changed,controlSourceTree:changed.controlSourceTree,now:f.f.now})).toThrow();
});
