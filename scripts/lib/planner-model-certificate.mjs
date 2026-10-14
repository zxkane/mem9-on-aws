import {createHash} from 'node:crypto';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {PLANNER_PROMPT} from './consolidation-model.mjs';

// A planner model may only classify production neighborhoods after the exact
// request contract has passed the synthetic evaluation in every one of several
// independent runs, because a model can answer the same case differently.
// A false MERGE bundles an unresolved contradiction, a different subject or an
// injected instruction, so the gate admits none. A missed MERGE only defers
// consolidation, so recall has a lower, explicit floor. EITHER cases are
// jointly true records (a context-specific exception or an explicitly resolved
// change) that lossless composition preserves, so both answers are acceptable.
export const PLANNER_CERTIFICATE_POLICY=Object.freeze({runs:3,maxFalseMerges:0,maxErrors:0,minMergeRecall:0.5,maxAgeMs:7*86400000});
const EXPECTATIONS=['MERGE','NOT_MERGE','EITHER'];
const CONTRACT_KEYS=['adapter','model','region','project','max_input_tokens','max_output_tokens','reasoning','input_bound','output_bound'];
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===[...keys].sort().join();
const fail=()=>{throw Error('PlannerModelCertificateInvalid');};
export const plannerPromptHash=()=>createHash('sha256').update(PLANNER_PROMPT).digest('hex');

export function validatePlannerEvaluation(fixture){
  if(fixture?.version!==1||!Array.isArray(fixture.cases)||fixture.cases.length<20||fixture.cases.length>200||
    new Set(fixture.cases.map(c=>c.id)).size!==fixture.cases.length||
    fixture.cases.some(c=>!EXPECTATIONS.includes(c.expect)||!Array.isArray(c.members)||c.members.length<2||c.members.length>10||
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

function scoreRun(fixture,verdicts){
  if(!Array.isArray(verdicts)||verdicts.length!==fixture.cases.length||
    verdicts.some((v,i)=>!exact(v,['id','expect','verdict'])||v.id!==fixture.cases[i].id||v.expect!==fixture.cases[i].expect||
      !['MERGE','KEEP','REVIEW','ERROR'].includes(v.verdict)))fail();
  const merges=verdicts.filter(v=>v.expect==='MERGE'),policy=PLANNER_CERTIFICATE_POLICY;
  const result={expectedMerges:merges.length,observedMerges:merges.filter(v=>v.verdict==='MERGE').length,
    falseMerges:verdicts.filter(v=>v.expect==='NOT_MERGE'&&v.verdict==='MERGE').length,errors:verdicts.filter(v=>v.verdict==='ERROR').length};
  return {...result,passed:result.falseMerges<=policy.maxFalseMerges&&result.errors<=policy.maxErrors&&
    result.observedMerges>=Math.ceil(result.expectedMerges*policy.minMergeRecall)};
}

export function buildPlannerCertificate({fixture,contract,runs,evaluatedMs}){
  validatePlannerEvaluation(fixture);
  if(!exact(contract,CONTRACT_KEYS)||!Number.isSafeInteger(evaluatedMs)||!Array.isArray(runs)||runs.length!==PLANNER_CERTIFICATE_POLICY.runs)fail();
  const scored=runs.map(verdicts=>scoreRun(fixture,verdicts));
  const results={cases:fixture.cases.length,runs:scored.map(({passed,...result})=>result),verdictsHash:hash(runs)};
  return {version:1,contract,promptHash:plannerPromptHash(),fixtureHash:hash(fixture),policy:{...PLANNER_CERTIFICATE_POLICY},
    runs,results,passed:scored.every(run=>run.passed),evaluatedMs};
}

/**
 * Recompute the certificate's outcome from its recorded verdicts and bind it
 * to the current prompt and fixture. The returned contract carries the
 * certificate hash as its proof. Verdicts name synthetic cases only.
 */
export function certifiedPlannerContract(certificate,{fixture,now=Date.now()}){
  if(certificate?.version!==1||!exact(certificate,['version','contract','promptHash','fixtureHash','policy','runs','results','passed','evaluatedMs'])||
    !Number.isSafeInteger(certificate.evaluatedMs)||certificate.evaluatedMs>now||now-certificate.evaluatedMs>PLANNER_CERTIFICATE_POLICY.maxAgeMs)fail();
  const expected=buildPlannerCertificate({fixture,contract:certificate.contract,runs:certificate.runs,evaluatedMs:certificate.evaluatedMs});
  if(hash(expected)!==hash(certificate)||expected.passed!==true)fail();
  return {...certificate.contract,proof:hash(certificate)};
}
