import {createHash} from 'node:crypto';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {PLANNER_PROMPT} from './consolidation-model.mjs';

// A planner model may only classify production neighborhoods after the exact
// request contract has passed the synthetic evaluation. A false MERGE joins
// unrelated or conflicting records, so the gate admits none. A missed MERGE is
// only a deferred consolidation, so recall has a lower, explicit floor.
export const PLANNER_CERTIFICATE_POLICY=Object.freeze({maxFalseMerges:0,maxErrors:0,minMergeRecall:0.5,maxAgeMs:7*86400000});
const CONTRACT_KEYS=['adapter','model','region','project','max_input_tokens','max_output_tokens','reasoning','input_bound','output_bound'];
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===[...keys].sort().join();
const fail=()=>{throw Error('PlannerModelCertificateInvalid');};
export const plannerPromptHash=()=>createHash('sha256').update(PLANNER_PROMPT).digest('hex');

export function validatePlannerEvaluation(fixture){
  if(fixture?.version!==1||!Array.isArray(fixture.cases)||fixture.cases.length<20||fixture.cases.length>200||
    new Set(fixture.cases.map(c=>c.id)).size!==fixture.cases.length||
    fixture.cases.some(c=>!['MERGE','NOT_MERGE'].includes(c.expect)||!Array.isArray(c.members)||c.members.length<2||c.members.length>10||
      c.members.some(m=>typeof m?.memory?.content!=='string'||!m.memory.content))||
    ['MERGE','NOT_MERGE'].some(kind=>fixture.cases.filter(c=>c.expect===kind).length<10))fail();
  return fixture;
}

/** One model call per case through the production planner request path. */
export async function evaluatePlannerModel({fixture,contract,infer,timeoutMs=110000}){
  validatePlannerEvaluation(fixture);
  const verdicts=[];
  for(const item of fixture.cases){
    let verdict;
    try{
      const response=await infer({members:item.members},{contract:{...contract,proof:'0'.repeat(64)}},timeoutMs);
      const value=JSON.parse(response.text);
      verdict=['MERGE','KEEP','REVIEW'].includes(value?.result)&&Object.keys(value).length===1?value.result:'ERROR';
    }catch{verdict='ERROR';}
    verdicts.push({id:item.id,expect:item.expect,verdict});
  }
  return verdicts;
}

export function buildPlannerCertificate({fixture,contract,verdicts,evaluatedMs}){
  validatePlannerEvaluation(fixture);
  if(!exact(contract,CONTRACT_KEYS)||!Number.isSafeInteger(evaluatedMs)||!Array.isArray(verdicts)||verdicts.length!==fixture.cases.length||
    verdicts.some((v,i)=>v.id!==fixture.cases[i].id||v.expect!==fixture.cases[i].expect||!['MERGE','KEEP','REVIEW','ERROR'].includes(v.verdict)))fail();
  const merges=verdicts.filter(v=>v.expect==='MERGE');
  const results={cases:verdicts.length,expectedMerges:merges.length,observedMerges:merges.filter(v=>v.verdict==='MERGE').length,
    falseMerges:verdicts.filter(v=>v.expect==='NOT_MERGE'&&v.verdict==='MERGE').length,errors:verdicts.filter(v=>v.verdict==='ERROR').length,
    verdictsHash:hash(verdicts)};
  const policy=PLANNER_CERTIFICATE_POLICY;
  const passed=results.falseMerges<=policy.maxFalseMerges&&results.errors<=policy.maxErrors&&
    results.observedMerges>=Math.ceil(results.expectedMerges*policy.minMergeRecall);
  return {version:1,contract,promptHash:plannerPromptHash(),fixtureHash:hash(fixture),policy:{...policy},results,passed,evaluatedMs};
}

/**
 * Recompute the certificate's outcome and bind it to the current prompt and
 * fixture. The returned contract carries the certificate hash as its proof.
 */
export function certifiedPlannerContract(certificate,{fixture,now=Date.now()}){
  if(certificate?.version!==1||!exact(certificate,['version','contract','promptHash','fixtureHash','policy','results','passed','evaluatedMs']))fail();
  validatePlannerEvaluation(fixture);
  if(!exact(certificate.contract,CONTRACT_KEYS)||hash(fixture)!==certificate.fixtureHash||certificate.promptHash!==plannerPromptHash()||hash(certificate.policy)!==hash({...PLANNER_CERTIFICATE_POLICY})||
    certificate.passed!==true||certificate.evaluatedMs>now||now-certificate.evaluatedMs>PLANNER_CERTIFICATE_POLICY.maxAgeMs)fail();
  const r=certificate.results,policy=PLANNER_CERTIFICATE_POLICY;
  if(r?.cases!==fixture.cases.length||r.expectedMerges!==fixture.cases.filter(c=>c.expect==='MERGE').length||
    !Number.isSafeInteger(r.observedMerges)||r.falseMerges>policy.maxFalseMerges||r.errors>policy.maxErrors||
    r.observedMerges<Math.ceil(r.expectedMerges*policy.minMergeRecall))fail();
  return {...certificate.contract,proof:hash(certificate)};
}
