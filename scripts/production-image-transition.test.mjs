import {describe,it,expect} from 'vitest';
import {IMAGE_TRANSITION_LIMITS,IMAGE_TRANSITION_LIMITS_HASH,inspectImageTransitionDescriptorCommitment} from './lib/production-image-transition.mjs';
import {canaryEvidenceHash} from './lib/production-canary-verification.mjs';

const commitment=()=>({version:1,kind:'image-security-upgrade',proofHash:'a'.repeat(64),predecessorHash:'b'.repeat(64),limitsHash:IMAGE_TRANSITION_LIMITS_HASH});
describe('pure image transition commitments',()=>{
 it('pins the complete reviewed limits, not a caller override',()=>{
  expect(canaryEvidenceHash(IMAGE_TRANSITION_LIMITS)).toBe(IMAGE_TRANSITION_LIMITS_HASH);
  expect(IMAGE_TRANSITION_LIMITS_HASH).toBe('59a5bf6d08f4e1a787d1f016a320c625fd43bb973bb924d6999427dfcfe71ced');
  expect(Object.isFrozen(IMAGE_TRANSITION_LIMITS)).toBe(true);
 });
 it('returns commitments only without authority or a mutable input alias',()=>{
  const t=commitment(),r=inspectImageTransitionDescriptorCommitment(t);
  expect(r).toEqual({proofHash:t.proofHash,predecessorHash:t.predecessorHash,limitsHash:t.limitsHash});expect(Object.isFrozen(r)).toBe(true);
  t.proofHash='c'.repeat(64);expect(r.proofHash).toBe('a'.repeat(64));
 });
 it.each(['limits','version','kind','extra','missing','getter','prototype'])('rejects %s',kind=>{
  const t=commitment();if(kind==='limits')t.limitsHash='d'.repeat(64);if(kind==='version')t.version=2;if(kind==='kind')t.kind='bootstrap-boundary-tightening';if(kind==='extra')t.approved=true;if(kind==='missing')delete t.predecessorHash;
  if(kind==='getter')Object.defineProperty(t,'proofHash',{get(){throw Error('getter must not run');},enumerable:true});if(kind==='prototype')Object.setPrototypeOf(t,{extra:true});
  expect(()=>inspectImageTransitionDescriptorCommitment(t)).toThrow('ImageTransition');
 });
});
