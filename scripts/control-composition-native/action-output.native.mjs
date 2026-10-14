import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture} from './fixture.mjs';
import {CONTROL_COMPOSITION_MAIN_OUTPUT_CHARGE as fee} from '../lib/production-control-composition-main-policy.mjs';
import {sumCompositionCharges} from '../lib/production-control-composition.mjs';
test('action output is exactly one CI-only prospective row and does not alter the owner term',async()=>{
 const f=await fixture();try{
  assert.equal(fee.logicalBytes,163840);assert.equal(JSON.stringify(f.plan.parts.actionOutput),JSON.stringify(fee));
  assert.deepEqual(f.funding.ownerCharge,sumCompositionCharges(['packingOwner','ownerNetwork','ownerJournal','ownerCleanup'].map(k=>f.funding.parts[k])));
  assert.deepEqual(f.funding.ciCharge,sumCompositionCharges([...Object.entries(f.plan.parts).filter(([k])=>k!=='packingOwner').map(([,v])=>v),
   f.funding.parts.ciNetwork,f.funding.parts.ciJournal,f.funding.parts.ciCleanup]));
 }finally{await f.remove();}
});
