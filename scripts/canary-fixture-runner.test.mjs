import {it,expect} from 'vitest';
import {fixtureCaseNames,fixtureChecksFromReport,parseCanaryFixtureIdentity} from './canary-fixture-runner.mjs';
const report=()=>({success:true,numTotalTests:fixtureCaseNames.length,numPassedTests:fixtureCaseNames.length,numFailedTests:0,numPendingTests:0,
  testResults:[{status:'passed',assertionResults:fixtureCaseNames.map(title=>({title,status:'passed'}))}]});
it('requires every named canonical case and never derives cleanup from a test count',()=>{
 const checks=fixtureChecksFromReport(report());expect(Object.keys(checks)).toHaveLength(8);expect(Object.values(checks).every(Boolean)).toBe(true);
 expect(checks.cleanup).toBeUndefined();
});
it('rejects skipped, incomplete, duplicate, renamed or failed fixture results',()=>{
 for(const change of [r=>{r.success=false;},r=>{r.numPendingTests=1;},r=>{r.testResults[0].assertionResults.pop();},
  r=>{r.testResults[0].assertionResults[0].status='skipped';},r=>{r.testResults[0].assertionResults[0].title='unrelated';},
  r=>{r.testResults[0].assertionResults[0]=r.testResults[0].assertionResults[1];}]){
  const r=report();change(r);expect(()=>fixtureChecksFromReport(r)).toThrow('CanaryFixtureTestsIncomplete');
 }
});
it('accepts only explicit preview metadata with no additional execution inputs',()=>{
 const value={stage:'pr-7',runId:'12345',runAttempt:1,commit:'a'.repeat(40),sourceTree:'b'.repeat(40),coordinatorDigest:'c'.repeat(64),
  schemaDigest:'d'.repeat(64),operatorDigest:'e'.repeat(64),nonce:'f'.repeat(32),deadlineMs:1800000000000};
 expect(parseCanaryFixtureIdentity(JSON.stringify(value))).toEqual(value);
 for(const patch of [{stage:'prod'},{runAttempt:0},{nonce:'invalid'},{command:'untrusted'},{deadlineMs:0}]){
  expect(()=>parseCanaryFixtureIdentity(JSON.stringify({...value,...patch}))).toThrow('CanaryFixtureIdentityInvalid');
 }
});
