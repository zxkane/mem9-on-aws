import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {verifyCiSmokeRecoveryPin} from './lib/ci-smoke-isolation.mjs';
import {CI_SMOKE_POLICY} from './lib/ci-smoke-policy.mjs';

const row=CI_SMOKE_POLICY.rows.find(row=>row.route==='deploy-prod'&&row.callPath==='deploy-prod/25');
const expected=row.rule.entryFiles.find(pin=>pin.path==='scripts/lib/production-image-deployment-bundle.mjs');
const raw=readFileSync(new URL('../'+expected.path,import.meta.url));
const actual={...expected,bytes:raw.length,sha256:createHash('sha256').update(raw).digest('hex')};

describe('reviewed recovery source revisions',()=>{
 it('preserves the exact historical policy pin',()=>{
  expect(expected.sha256).toBe('ad7ab7b53ab30429b09dd46b203f8ed6e649e61d06946220c8707183d56fa125');
  expect(()=>verifyCiSmokeRecoveryPin(row,expected,expected)).not.toThrow();
 });
 it('accepts the exact reviewed successor from the checkout',()=>{
  expect(actual.sha256).toBe('661b7ebffc9d3e99f1ff56a5906eb807d8360ff2502fdd342505ba6564e25e27');
  expect(()=>verifyCiSmokeRecoveryPin(row,expected,actual)).not.toThrow();
 });
 it.each([
  {sha256:'0'.repeat(64)},{bytes:actual.bytes+1},{gitMode:'100755'},
  {path:'scripts/lib/unreviewed.mjs'},{additional:true},
 ])('rejects a successor with changed metadata %j',change=>{
  expect(()=>verifyCiSmokeRecoveryPin(row,expected,{...actual,...change})).toThrow('CiSmokeFileChanged');
 });
 it.each([
  {...row,route:'deploy-preview'},
  {...row,callPath:'deploy-prod/26'},
  {...row,rule:{...row.rule,contractId:'different-contract'}},
  {...row,rule:{...row.rule,kind:'unreviewed'}},
 ])('does not apply the successor outside its recovery contract',other=>{
  expect(()=>verifyCiSmokeRecoveryPin(other,expected,actual)).toThrow('CiSmokeFileChanged');
 });
 it('rejects a changed predecessor and preserves other exact file checks',()=>{
  expect(()=>verifyCiSmokeRecoveryPin(row,{...expected,bytes:expected.bytes+1},actual)).toThrow('CiSmokeFileChanged');
  const other=row.rule.entryFiles.find(pin=>pin.path!==expected.path);
  expect(()=>verifyCiSmokeRecoveryPin(row,other,other)).not.toThrow();
  expect(()=>verifyCiSmokeRecoveryPin(row,other,{...other,sha256:actual.sha256})).toThrow('CiSmokeFileChanged');
 });
});
