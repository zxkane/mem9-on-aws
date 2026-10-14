import {describe,it,expect} from 'vitest';
import {readFile,mkdtemp,writeFile,rm,chmod} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {buildPlannerCertificate,certifiedPlannerContract,evaluatePlannerModel,validatePlannerEvaluation,PLANNER_CERTIFICATE_POLICY} from './lib/planner-model-certificate.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {plannerEvaluationContract,PLANNER_EVALUATION_FIXTURE} from './evaluate-planner-model.mjs';
import {plannerModelRequest} from './run-production-consolidation.mjs';
import {parseProductionConsolidationRequest} from './production-consolidation-operator.mjs';

const fixture=JSON.parse(await readFile(PLANNER_EVALUATION_FIXTURE,'utf8'));
const env={MEM9_LLM_MODEL:'openai.gpt-example',AWS_REGION:'ap-northeast-1',MEM9_LLM_RESPONSES_REGION:'us-west-2',
  MEM9_BEDROCK_PROJECT:'proj_app',MEM9_BEDROCK_PROJECT_OPENAI:'proj_responses'};
const contract=plannerEvaluationContract(env,{adapter:'mantle-responses-total-v1'});
const perfect=fixture.cases.map(c=>({id:c.id,expect:c.expect,verdict:c.expect==='MERGE'?'MERGE':'REVIEW'}));
const now=1800000000000;

describe('planner model certification',()=>{
  it('ships a balanced synthetic fixture and routes the evaluation contract like the planner',()=>{
    expect(validatePlannerEvaluation(fixture).cases.length).toBeGreaterThanOrEqual(30);
    expect(contract).toMatchObject({model:'openai.gpt-example',region:'us-west-2',project:'proj_responses',max_input_tokens:32768});
    expect(plannerEvaluationContract(env,{adapter:'mantle-chat-total-v1'})).toMatchObject({region:'ap-northeast-1',project:'proj_app'});
    expect(()=>plannerEvaluationContract(env,{adapter:'other'})).toThrow('InvalidPlannerAdapter');
  });
  it('certifies only zero false merges, zero errors and the recall floor',()=>{
    const passed=buildPlannerCertificate({fixture,contract,verdicts:perfect,evaluatedMs:now});
    expect(passed.passed).toBe(true);
    expect(certifiedPlannerContract(passed,{fixture,now})).toEqual({...contract,proof:hash(passed)});
    const falseMerge=perfect.map(v=>v.expect==='NOT_MERGE'&&v.id===perfect.find(x=>x.expect==='NOT_MERGE').id?{...v,verdict:'MERGE'}:v);
    expect(buildPlannerCertificate({fixture,contract,verdicts:falseMerge,evaluatedMs:now}).passed).toBe(false);
    expect(buildPlannerCertificate({fixture,contract,verdicts:perfect.map((v,i)=>i?v:{...v,verdict:'ERROR'}),evaluatedMs:now}).passed).toBe(false);
    const merges=perfect.filter(v=>v.expect==='MERGE').length,floor=Math.ceil(merges*PLANNER_CERTIFICATE_POLICY.minMergeRecall);
    let kept=0;const sparse=perfect.map(v=>v.expect!=='MERGE'?v:kept++<floor?v:{...v,verdict:'REVIEW'});
    expect(buildPlannerCertificate({fixture,contract,verdicts:sparse,evaluatedMs:now}).passed).toBe(true);
    let fewer=0;const below=perfect.map(v=>v.expect!=='MERGE'?v:fewer++<floor-1?v:{...v,verdict:'KEEP'});
    expect(buildPlannerCertificate({fixture,contract,verdicts:below,evaluatedMs:now}).passed).toBe(false);
  });
  it('rejects stale, tampered or differently bound certificates',()=>{
    const certificate=buildPlannerCertificate({fixture,contract,verdicts:perfect,evaluatedMs:now});
    for(const [value,options] of [
      [{...certificate,passed:false},{}],
      [{...certificate,promptHash:'0'.repeat(64)},{}],
      [{...certificate,results:{...certificate.results,falseMerges:1}},{}],
      [{...certificate,results:{...certificate.results,falseMerges:Number.NaN}},{}],
      [{...certificate,verdicts:certificate.verdicts.map(v=>v.id===certificate.verdicts.find(x=>x.expect==='NOT_MERGE').id?{...v,verdict:'MERGE'}:v)},{}],
      [{...certificate,verdicts:certificate.verdicts.slice(1)},{}],
      [{...certificate,policy:{...certificate.policy,maxFalseMerges:1}},{}],
      [{...certificate,contract:{...contract,extra:1}},{}],
      [certificate,{now:now+PLANNER_CERTIFICATE_POLICY.maxAgeMs+1}],
      [certificate,{now:now-1}],
      [certificate,{fixture:{...fixture,cases:fixture.cases.slice(1)}}],
    ])expect(()=>certifiedPlannerContract(value,{fixture,now,...options})).toThrow('PlannerModelCertificateInvalid');
  });
  it('evaluates through the planner request path and treats malformed answers as errors',async()=>{
    const calls=[];
    const infer=async(work,admission)=>{calls.push(admission.contract);
      const merge=fixture.cases.find(c=>c.members===work.members).expect==='MERGE';
      return {text:calls.length===1?'not json':JSON.stringify({result:merge?'MERGE':'KEEP'})};};
    const verdicts=await evaluatePlannerModel({fixture,contract,infer});
    expect(calls).toHaveLength(fixture.cases.length);expect(calls[0].proof).toMatch(/^0{64}$/);
    expect(verdicts[0].verdict).toBe('ERROR');expect(verdicts.slice(1).every(v=>(v.verdict==='MERGE')===(v.expect==='MERGE'))).toBe(true);
  });
  it('builds a validated configure-model request from an owner-held certificate',async()=>{
    const directory=await mkdtemp(join(tmpdir(),'planner-certificate-'));
    try{
      const certificate=buildPlannerCertificate({fixture,contract,verdicts:perfect,evaluatedMs:now}),file=join(directory,'certificate.json');
      await writeFile(file,JSON.stringify(certificate),{mode:0o644});
      await expect(plannerModelRequest({MEM9_PLANNER_CERTIFICATE:file},{now})).rejects.toThrow('PlannerModelCertificateExposed');
      await chmod(file,0o600);
      const model=await plannerModelRequest({MEM9_PLANNER_CERTIFICATE:file,MEM9_PLANNER_DAILY_REQUESTS:'100'},{now});
      expect(model.contract.proof).toBe(hash(certificate));
      expect(model.stage).toEqual({limits:{requests:100,input:100*32768,output:100*2048},slots:2,unknown:1});
      const request=parseProductionConsolidationRequest(JSON.stringify({operation:'configure-model',invocation:'a'.repeat(32),deadline:Date.now()+60000,plannerModel:model}));
      expect(request.plannerModel).toEqual(model);
      await expect(plannerModelRequest({},{now})).rejects.toThrow('PlannerModelCertificateRequired');
      await expect(plannerModelRequest({MEM9_PLANNER_CERTIFICATE:file,MEM9_PLANNER_DAILY_REQUESTS:'0'},{now})).rejects.toThrow('InvalidPlannerModelBudget');
      for(const plannerModel of [undefined,{...model,similarity:0.1},{...model,stage:{...model.stage,slots:5}},{...model,contract:{...model.contract,proof:'x'}}])
        expect(()=>parseProductionConsolidationRequest(JSON.stringify({operation:'configure-model',invocation:'a'.repeat(32),deadline:Date.now()+60000,plannerModel}))).toThrow('InvalidPlannerModel');
      expect(()=>parseProductionConsolidationRequest(JSON.stringify({operation:'status',invocation:'a'.repeat(32),deadline:Date.now()+60000,plannerModel:model}))).toThrow('UnexpectedPlannerModel');
    }finally{await rm(directory,{recursive:true,force:true});}
  });
});
