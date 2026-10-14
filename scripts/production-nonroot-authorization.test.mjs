import {describe,it,expect} from 'vitest';
import {completeNonrootProofFixture,nonrootAuthorizationValues} from './production-nonroot.fixture.mjs';
import {buildNonrootImageTransitionProof,verifyNonrootImageTransitionProof,nonrootProofExpected,nonrootTransitionContextBindings,bindNonrootTransitionAuthorization,assertNonrootDataRelease,nonrootAuthorizationBindings,nonrootAdmissionDeadline} from './lib/production-nonroot-proof.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';

async function fixture(){
 const f=await completeNonrootProofFixture(),expected=nonrootProofExpected(f.input,{proofHash:hash(f.input)});
 const built=await buildNonrootImageTransitionProof(f.input,{expected,evidence:f.evidence,now:f.now});
 return {...f,expected,built,...nonrootAuthorizationValues(f,built,nonrootTransitionContextBindings(built.context))};
}
describe('nonroot proof to final review and descriptor',()=>{
 it('binds the actual full proof to the final review hash while preserving the original root anchor',async()=>{
  const f=await fixture(),context=bindNonrootTransitionAuthorization(f.built.context,{review:f.review,now:f.now});
  const result=assertNonrootDataRelease(context,{previous:f.f.predecessor,current:f.current,controlSourceTree:f.deploymentControl.tree,now:f.now});
  expect(result.descriptorHash).toBe(hash(f.current));expect(result.reviewHash).toBe(hash(f.review));
  expect(f.current.backendBindingHash).toBe(f.f.predecessor.backendBindingHash);
  expect(nonrootAuthorizationBindings(context).proofHash).toBe(f.built.proofHash);
  expect(nonrootAuthorizationBindings(context)).not.toHaveProperty('fundingPlanHashes');
  expect(nonrootAdmissionDeadline(context)).toBe(f.prerequisite.expiresMs);
 });
 it.each(['sourceEvidenceHash','dataOriginSourceEvidenceHash','artifactReverificationHash','predecessorHash'])('rejects final review %s mismatch',async field=>{
  const f=await fixture();f.review[field]='f'.repeat(64);
  expect(()=>bindNonrootTransitionAuthorization(f.built.context,{review:f.review,now:f.now})).toThrow('NonrootReviewBinding');
 });
 it('rejects a future review without replacing its observation time',async()=>{
  const f=await fixture();f.review.reviewedMs=f.now+1;
  expect(()=>bindNonrootTransitionAuthorization(f.built.context,{review:f.review,now:f.now})).toThrow('NonrootReviewClock');
 });
 it('rejects serialization of an authentic authorization context',async()=>{
  const f=await fixture(),context=bindNonrootTransitionAuthorization(f.built.context,{review:f.review,now:f.now});
  expect(()=>assertNonrootDataRelease(structuredClone(context),{current:f.current,controlSourceTree:f.deploymentControl.tree,now:f.now})).toThrow('NonrootProofContextRequired');
 });
 it.each(['backendBindingHash','images','policyHash','authorizationId'])('rejects descriptor %s drift',async field=>{
  const f=await fixture(),context=bindNonrootTransitionAuthorization(f.built.context,{review:f.review,now:f.now});
  if(field==='images')f.current.images['mnemo-server'].rootDigest='sha256:'+'f'.repeat(64);
  else f.current[field]='f'.repeat(field==='authorizationId'?32:64);
  expect(()=>assertNonrootDataRelease(context,{current:f.current,controlSourceTree:f.deploymentControl.tree,now:f.now})).toThrow();
 });
 it('keeps historical verification non-admitting even with a matching final review',async()=>{
  const f=await fixture(),proof=await verifyNonrootImageTransitionProof(f.built.proof,{proofHash:f.built.proofHash,expected:f.expected,evidence:f.evidence,now:f.now,mode:'inspection'});
  const historical=bindNonrootTransitionAuthorization(proof,{review:f.review,now:f.now,mode:'inspection'});
  expect(assertNonrootDataRelease(historical,{current:f.current,controlSourceTree:f.deploymentControl.tree,now:f.now,mode:'inspection'}).descriptorHash).toBe(hash(f.current));
  expect(()=>assertNonrootDataRelease(historical,{current:f.current,controlSourceTree:f.deploymentControl.tree,now:f.now,mode:'admission'})).toThrow();
 });
});
