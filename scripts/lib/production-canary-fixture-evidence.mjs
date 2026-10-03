import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
export const canaryFixtureChecks=Object.freeze(['frozenParent','continuation','budgetCap','receiptAdmission','parentPreservation','readOnlyAudit','commitWindow','steadyState','cleanup']);
const fail=()=>{throw Error('CanaryFixtureEvidenceInvalid');};
export function verifyCanaryFixtureEvidence(evidence,expected,{now=Date.now()}={}){
  const identity=['stage','runId','runAttempt','commit','sourceTree','coordinatorDigest','schemaDigest','operatorDigest'];
  const keys=['version','kind',...identity,'nonce','databaseHash','completedMs','checks'];
  if(!evidence||typeof evidence!=='object'||Array.isArray(evidence)||Object.keys(evidence).sort().join()!==keys.sort().join()||
    evidence.version!==1||evidence.kind!=='synthetic-canary-continuation'||!/^pr-[1-9][0-9]*$/.test(evidence.stage??'')||
    !/^[1-9][0-9]*$/.test(evidence.runId??'')||!Number.isSafeInteger(evidence.runAttempt)||evidence.runAttempt<1||
    !Number.isSafeInteger(now)||!Number.isSafeInteger(evidence.completedMs)||evidence.completedMs<1||evidence.completedMs>now||now-evidence.completedMs>86400000||
    !/^[a-f0-9]{32}$/.test(evidence.nonce??''))fail();
  for(const key of ['commit','sourceTree'])if(!/^[a-f0-9]{40}$/.test(evidence[key]??''))fail();
  for(const key of ['coordinatorDigest','schemaDigest','operatorDigest','databaseHash'])if(!/^[a-f0-9]{64}$/.test(evidence[key]??''))fail();
  if(!evidence.checks||Object.keys(evidence.checks).sort().join()!==[...canaryFixtureChecks].sort().join()||canaryFixtureChecks.some(k=>evidence.checks[k]!==true))fail();
  for(const key of identity)if(evidence[key]!==expected?.[key])fail();
  return {hash:hash(evidence),runId:evidence.runId,runAttempt:evidence.runAttempt};
}
