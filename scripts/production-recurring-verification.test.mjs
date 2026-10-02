import {it,expect} from 'vitest';
import {verifyProductionRecurringDelivery,verifyProductionRecurringProof} from './lib/production-recurring-verification.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {productionRecurringFixture as fixture} from './test-fixtures/production-recurring.mjs';
const account='123456789012',now=1800000000000;

it('accepts a genuine empty periodic cycle with authenticated role and redacted CloudTrail environment',()=>{
  const f=fixture(),proof=verifyProductionRecurringDelivery(f.input,f.target,f.options);expect(proof.kind).toBe('planner');expect(proof.evidenceHash).toMatch(/^[a-f0-9]{64}$/);
});
it('requires one successful slice even when no memories need changing',()=>{
  const f=fixture(),valid=verifyProductionRecurringDelivery(f.input,f.target,f.options);
  f.input.record.slices=0;expect(()=>verifyProductionRecurringDelivery(f.input,f.target,f.options)).toThrow('ProductionRecurringDeliveryUnverified');
  const {evidenceHash,...payload}=valid;payload.slices=0;
  expect(()=>verifyProductionRecurringProof({...payload,evidenceHash:hash(payload)},{kind:f.target.kind,generation:f.target.generation,admission:f.options.admission,image:f.target.image})).toThrow('ProductionRecurringDeliveryUnverified');
});
it('rejects a manual caller even if its user agent claims to be Scheduler',()=>{
  const f=fixture();f.input.event.userAgent='AmazonEventBridgeScheduler';f.input.event.userIdentity.sessionContext.sessionIssuer.arn=`arn:aws:iam::${account}:role/manual`;
  expect(()=>verifyProductionRecurringDelivery(f.input,f.target,f.options)).toThrow('ProductionRecurringDeliveryUnverified');
});
it('rejects altered trust, task identity, context, execution settings and report failure',()=>{
  for(const change of [f=>{f.input.role.AssumeRolePolicyDocument.Statement[0].Principal={AWS:'*'};},f=>{f.input.event.responseElements.tasks[0].taskArn+='wrong';},
    f=>{f.input.task.overrides.containerOverrides[0].environment[2].value+='wrong';},f=>{f.input.task.overrides.containerOverrides[0].command=['unapproved'];},
    f=>{f.input.record.failedSlices=1;},f=>{f.options.afterMs=now-30000;}]){
    const f=fixture();change(f);expect(()=>verifyProductionRecurringDelivery(f.input,f.target,f.options)).toThrow();
  }
});
