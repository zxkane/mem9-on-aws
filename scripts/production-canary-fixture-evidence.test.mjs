import {it,expect} from 'vitest';
import {verifyCanaryFixtureEvidence,canaryFixtureChecks} from './lib/production-canary-fixture-evidence.mjs';
const expected={stage:'pr-7',runId:'12345',runAttempt:1,commit:'a'.repeat(40),sourceTree:'b'.repeat(40),
  coordinatorDigest:'c'.repeat(64),schemaDigest:'d'.repeat(64),operatorDigest:'e'.repeat(64)};
const now=1800000000000;
const fixture=()=>({version:1,kind:'synthetic-canary-continuation',...expected,nonce:'f'.repeat(32),databaseHash:'1'.repeat(64),
  completedMs:now-1000,checks:Object.fromEntries(canaryFixtureChecks.map(k=>[k,true]))});
it('accepts a complete marked fixture only for the exact release and workflow attempt',()=>{
 expect(verifyCanaryFixtureEvidence(fixture(),expected,{now})).toMatchObject({runId:expected.runId,runAttempt:1});
});
it('rejects missing, stale, unmarked, incomplete and mismatched fixture evidence',()=>{
 for(const change of [f=>{f.stage='prod';},f=>{f.runAttempt=2;},f=>{f.sourceTree='9'.repeat(40);},f=>{f.completedMs=now-86400001;},
  f=>{f.completedMs=now+1;},f=>{f.kind='production-canary';},f=>{f.checks.cleanup=false;},f=>{delete f.checks.budgetCap;},f=>{f.extra=true;}]){
  const f=fixture();change(f);expect(()=>verifyCanaryFixtureEvidence(f,expected,{now})).toThrow('CanaryFixtureEvidenceInvalid');
 }
});
