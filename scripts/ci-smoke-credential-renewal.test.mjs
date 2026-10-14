import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {parseExpression} from '@babel/parser';
import {parse as parseYaml} from 'yaml';
import {buildCiSmokePromotionRoutes,verifyCiSmokePromotionRoutes,describeCiSmokePromotionPins,CI_SMOKE_GATE_ENTRY_PATH} from './lib/ci-smoke-isolation.mjs';

const baseline=()=>JSON.parse(readFileSync(new URL('./fixtures/ci-smoke-baseline.json',import.meta.url),'utf8'));
const normal=[16,17,18,19,20,21,22,23,24,26],sites=[...normal,25];
const build=()=>buildCiSmokePromotionRoutes(baseline());
const find=(job,id)=>{const step=job.steps.find(s=>s.id===id);expect(step,'missing '+id).toBeDefined();return step;};
// Evaluate only this workflow's boolean condition syntax; never execute a
// workflow expression as JavaScript or shell code.
function enabled(expression,context){
 const source=expression.replace(/\bsteps(?:\.[A-Za-z0-9_-]+)+/g,path=>JSON.stringify(path.split('.').reduce((v,k)=>v?.[k],context)??''));
 const evaluate=node=>{
  if(node.type==='BooleanLiteral'||node.type==='StringLiteral')return node.value;
  if(node.type==='LogicalExpression'&&node.operator==='&&')return evaluate(node.left)&&evaluate(node.right);
  if(node.type==='LogicalExpression'&&node.operator==='||')return evaluate(node.left)||evaluate(node.right);
  if(node.type==='BinaryExpression'&&node.operator==='==')return evaluate(node.left)===evaluate(node.right);
  if(node.type==='BinaryExpression'&&node.operator==='!=')return evaluate(node.left)!==evaluate(node.right);
  if(node.type==='CallExpression'&&node.callee.type==='Identifier'&&node.arguments.length===0){
   if(node.callee.name==='always')return true;
   if(node.callee.name==='success')return !context.failed&&!context.cancelled;
   if(node.callee.name==='failure')return context.failed;
   if(node.callee.name==='cancelled')return context.cancelled;
  }
  throw Error('Unsupported renewal condition');
 };
 if(!/\b(?:always|success|failure|cancelled)\s*\(/.test(expression)&&(context.failed||context.cancelled))return false;
 return Boolean(evaluate(parseExpression(source)));
}
const context=(recovery=false)=>({failed:recovery,cancelled:false,steps:{ci_smoke_source:{outcome:'success'},gate:{outputs:{skip:'false'}},deploy:{outputs:{stage:'pr-123'}}}});
const environment=()=>({PATH:'/usr/bin:/bin',AWS_ACCESS_KEY_ID:'synthetic-ambient-key',AWS_SECRET_ACCESS_KEY:'synthetic-ambient-secret',AWS_SESSION_TOKEN:'synthetic-ambient-session',ACTIONS_ID_TOKEN_REQUEST_URL:'https://example.com/native-oidc',ACTIONS_ID_TOKEN_REQUEST_TOKEN:'synthetic-native-token'});

describe('bounded preview credential renewal',()=>{
 it.each(sites)('prechecks native OIDC immediately before the fixed renewal at %s',index=>{
  const job=build().jobs['deploy-preview'],check=find(job,'ci_smoke_oidc_check_'+index),renew=find(job,'ci_smoke_credentials_'+index);
  expect(job.steps.indexOf(renew)).toBe(job.steps.indexOf(check)+1);
  expect(renew.if).toBe('('+check.if+") && steps."+check.id+".outcome == 'success'");
  expect(check.shell).toBe('bash');expect(check['continue-on-error']).toBe(false);
  expect(renew).toMatchObject({uses:'aws-actions/configure-aws-credentials@e1253824e5c10ff9df46874f81ed3ec929e19cfd','continue-on-error':false,
   with:{'role-to-assume':'${{ secrets.AWS_PREVIEW_ROLE_ARN }}','aws-region':'${{ env.AWS_REGION }}','mask-aws-account-id':true,'translate-env-variables':false,'unset-current-credentials':true,'role-duration-seconds':3600,'action-timeout-s':120}});
  expect(Object.keys(renew.with).sort()).toEqual(['action-timeout-s','aws-region','mask-aws-account-id','role-duration-seconds','role-to-assume','translate-env-variables','unset-current-credentials']);
  if(index!==25)expect(job.steps[job.steps.indexOf(renew)+1].env.MEM9_CI_SMOKE_CHECKPOINT).toBe('deploy-preview/'+index);
  else{const cancel=job.steps[job.steps.indexOf(renew)+1];expect(cancel.name).toBe('Cancel outstanding runtime bootstrap invocations');expect(cancel.if).toContain("steps.ci_smoke_credentials_25.outcome == 'success'");}
 });
 it.each([false,true])('missing native context cannot reach providers with usable ambient credentials, recovery=%s',recovery=>{
  const index=recovery?25:24,job=build().jobs['deploy-preview'],check=find(job,'ci_smoke_oidc_check_'+index),renew=find(job,'ci_smoke_credentials_'+index);
  for(const missing of [['ACTIONS_ID_TOKEN_REQUEST_URL'],['ACTIONS_ID_TOKEN_REQUEST_TOKEN'],['ACTIONS_ID_TOKEN_REQUEST_URL','ACTIONS_ID_TOKEN_REQUEST_TOKEN']]){
   const env=environment(),state=context(recovery);for(const key of missing)delete env[key];
   expect(enabled(check.if,state)).toBe(true);
   const result=spawnSync('/usr/bin/bash',['--noprofile','--norc','-e','-o','pipefail','-c',check.run],{env,encoding:'utf8',timeout:1000});
   expect(result.status).toBe(1);expect(result.stdout+result.stderr).toBe('::error::Native GitHub OIDC context unavailable\n');
   for(const value of Object.values(env))expect(result.stdout+result.stderr).not.toContain(value);
   state.steps[check.id]={outcome:'failure'};state.failed=true;let providerCalls=0,cleanupCalls=0;
   if(enabled(renew.if,state))providerCalls++;
   state.steps[renew.id]={outcome:'skipped'};
   if(enabled(job.steps.find(s=>s.name==='Cancel outstanding runtime bootstrap invocations').if,state))cleanupCalls++;
   expect({providerCalls,cleanupCalls}).toEqual({providerCalls:0,cleanupCalls:0});
  }
 });
 it.each(['failure','skipped','cancelled'])('a %s precheck cannot renew during cancellation',outcome=>{
  const job=build().jobs['deploy-preview'],renew=find(job,'ci_smoke_credentials_25'),state=context();state.cancelled=true;state.steps.ci_smoke_oidc_check_25={outcome};
  expect(enabled(renew.if,state)).toBe(false);
 });
 it('fresh native context admits renewal, while failed renewal prevents all cleanup dispatch',()=>{
  const job=build().jobs['deploy-preview'],check=find(job,'ci_smoke_oidc_check_25'),renew=find(job,'ci_smoke_credentials_25'),cancel=job.steps.find(s=>s.name==='Cancel outstanding runtime bootstrap invocations');
  const result=spawnSync('/usr/bin/bash',['--noprofile','--norc','-e','-o','pipefail','-c',check.run],{env:environment(),encoding:'utf8',timeout:1000});expect(result.status).toBe(0);expect(result.stdout+result.stderr).toBe('');
  for(const cancelled of [false,true]){
   const state=context(!cancelled);state.cancelled=cancelled;state.steps[check.id]={outcome:'success'};
   expect(enabled(check.if,state)).toBe(true);expect(enabled(renew.if,state)).toBe(true);
   for(const outcome of ['failure','skipped','cancelled']){state.steps[renew.id]={outcome};expect(enabled(cancel.if,state)).toBe(false);}
   state.steps[renew.id]={outcome:'success'};expect(enabled(cancel.if,state)).toBe(true);
  }
 });
 it.each(['source-failed','gate-skipped','stage-missing'])('renewal stays held when %s',fault=>{
  const job=build().jobs['deploy-preview'];
  for(const index of sites){const state=context(index===25);if(fault==='source-failed')state.steps.ci_smoke_source.outcome='failure';if(fault==='gate-skipped')state.steps.gate.outputs.skip='true';if(fault==='stage-missing')state.steps.deploy.outputs.stage='';
   state.steps['ci_smoke_oidc_check_'+index]={outcome:'success'};expect(enabled(find(job,'ci_smoke_oidc_check_'+index).if,state)).toBe(false);expect(enabled(find(job,'ci_smoke_credentials_'+index).if,state)).toBe(false);}
 });
 it.each(['failed','cancelled'])('does not renew ordinary acceptance credentials after the job is %s',status=>{
  const job=build().jobs['deploy-preview'],state=context();state[status]=true;
  for(const index of normal){state.steps['ci_smoke_oidc_check_'+index]={outcome:'success'};expect(enabled(find(job,'ci_smoke_oidc_check_'+index).if,state)).toBe(false);expect(enabled(find(job,'ci_smoke_credentials_'+index).if,state)).toBe(false);}
 });
 it('preserves clocks, original commands and every other route',()=>{
  const candidate=build(),original=parseYaml(readFileSync(new URL('../.github/workflows/infra-ci.yml',import.meta.url),'utf8'));
  expect(candidate.jobs['deploy-preview']['timeout-minutes']).toBe(90);
  for(const route of ['deploy-prod','runtime-cutover-prod','runtime-cutover-preview'])expect(candidate.jobs[route]).toEqual(original.jobs[route]);
  for(const name of ['Human namespace OAuth E2E (preview, hard)','Cancel outstanding runtime bootstrap invocations'])expect(candidate.jobs['deploy-preview'].steps.find(s=>s.name===name).run).toBe(original.jobs['deploy-preview'].steps.find(s=>s.name===name).run);
 });
 it('maps all eleven renewals as actual credential steps with their source prechecks pinned',()=>{
  const candidate=build(),paths=['.github/workflows/infra-ci.yml',...Object.keys(candidate.actions),CI_SMOKE_GATE_ENTRY_PATH],pins=Object.fromEntries(paths.map(path=>[path,{path,gitMode:'100644',sha256:'a'.repeat(64),bytes:1}]));
  const route=describeCiSmokePromotionPins({jobs:candidate.jobs},candidate.actions,pins).find(r=>r.job==='deploy-preview');
  expect(route.credentialSteps).toHaveLength(12);
  expect(route.credentialSteps.filter(s=>s.id?.startsWith('ci_smoke_credentials_')).map(s=>s.id).sort()).toEqual(sites.map(n=>'ci_smoke_credentials_'+n).sort());
  expect(route.protectedSteps.filter(s=>s.id?.startsWith('ci_smoke_oidc_check_'))).toHaveLength(11);
 });
 it.each([
  job=>{job.steps=job.steps.filter(s=>s.id!=='ci_smoke_oidc_check_24');},
  job=>{find(job,'ci_smoke_credentials_25').if='always()';},
  job=>{find(job,'ci_smoke_credentials_25').if=find(job,'ci_smoke_credentials_25').if.replace('check_25','check_24');},
  job=>{find(job,'ci_smoke_credentials_24').with['translate-env-variables']=true;},
  job=>{find(job,'ci_smoke_credentials_24').with['unset-current-credentials']=false;},
  job=>{find(job,'ci_smoke_credentials_24').with['role-to-assume']='${{ secrets.AWS_PROD_ROLE_ARN }}';},
  job=>{find(job,'ci_smoke_credentials_24').with['aws-region']='us-west-2';},
  job=>{find(job,'ci_smoke_credentials_24').with['role-duration-seconds']=7200;},
  job=>{find(job,'ci_smoke_credentials_24').with['use-existing-credentials']='true';},
  job=>{find(job,'ci_smoke_credentials_24').with['role-chaining']=true;},
  job=>{find(job,'ci_smoke_oidc_check_24').run='true';},
  job=>{const index=job.steps.findIndex(s=>s.id==='ci_smoke_oidc_check_24');[job.steps[index],job.steps[index+1]]=[job.steps[index+1],job.steps[index]];},
 ])('rejects changed renewal source or credential selection',mutate=>{
  const candidate=build();mutate(candidate.jobs['deploy-preview']);expect(()=>verifyCiSmokePromotionRoutes(baseline(),candidate)).toThrow('CiSmokePromotionSourceChanged');
 });
});
