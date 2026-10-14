import {readFile,writeFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {createPlannerModelClient} from './lib/consolidation-model.mjs';
import {evaluatePlannerModel,buildPlannerCertificate,PLANNER_CERTIFICATE_POLICY} from './lib/planner-model-certificate.mjs';

export const PLANNER_EVALUATION_FIXTURE=new URL('./test-fixtures/planner-model-evaluation.json',import.meta.url);

/** The contract uses the same route settings the deployed planner reads. */
export function plannerEvaluationContract(env,{adapter,reasoning='low',maxInputTokens=32768,maxOutputTokens=2048}){
  const responses=adapter==='mantle-responses-total-v1';
  if(!responses&&adapter!=='mantle-chat-total-v1')throw Error('InvalidPlannerAdapter');
  return {adapter,model:env.MEM9_LLM_MODEL,region:responses?env.MEM9_LLM_RESPONSES_REGION:env.AWS_REGION,
    project:responses?env.MEM9_BEDROCK_PROJECT_OPENAI:env.MEM9_BEDROCK_PROJECT,max_input_tokens:maxInputTokens,
    max_output_tokens:maxOutputTokens,reasoning,input_bound:'context_limit',output_bound:'total_tokens'};
}

async function main(){
  const [adapter,output]=process.argv.slice(2);
  if(!output)throw Error('usage: evaluate-planner-model.mjs <adapter> <certificate-output-path>');
  const fixture=JSON.parse(await readFile(PLANNER_EVALUATION_FIXTURE,'utf8'));
  const contract=plannerEvaluationContract(process.env,{adapter,reasoning:process.env.MEM9_PLANNER_REASONING||'low',
    maxOutputTokens:Number(process.env.MEM9_PLANNER_MAX_OUTPUT_TOKENS||2048)});
  const mintToken=async region=>{
    const [{getToken},{fromNodeProviderChain}]=await Promise.all([import('@aws/bedrock-token-generator'),import('@aws-sdk/credential-providers')]);
    return getToken({credentials:await fromNodeProviderChain()(),region,expiresInSeconds:3600});
  };
  const infer=createPlannerModelClient({mintToken,dispatch:async()=>{},env:process.env});
  const runs=[];
  for(let run=0;run<PLANNER_CERTIFICATE_POLICY.runs;run++)runs.push(await evaluatePlannerModel({fixture,contract,infer}));
  const certificate=buildPlannerCertificate({fixture,contract,runs,evaluatedMs:Date.now()});
  // Synthetic case IDs and verdicts only; no memory content leaves this process.
  await writeFile(output,JSON.stringify(certificate),{mode:0o600,flag:'wx'});
  process.stdout.write(JSON.stringify({event:'planner_model_evaluation',passed:certificate.passed,...certificate.results,
    misses:runs.map(verdicts=>verdicts.filter(v=>v.expect!=='EITHER'&&(v.expect==='MERGE')!==(v.verdict==='MERGE')).map(v=>[v.id,v.verdict]))})+'\n');
  if(!certificate.passed)process.exitCode=1;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(error=>{
  process.stdout.write(JSON.stringify({event:'planner_model_evaluation',outcome:'failed',errorClass:/^[A-Za-z]{1,64}$/.test(error?.message??'')?error.message:'PlannerEvaluationFailed'})+'\n');
  process.exitCode=1;
});
