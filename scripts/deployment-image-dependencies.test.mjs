import {readFileSync} from 'node:fs';
import {parse as parseYaml} from 'yaml';
import {parseExpression} from '@babel/parser';
import {describe,it,expect} from 'vitest';
import {classifyChangedPaths} from './classify-infra-changes.mjs';

const workflow=parseYaml(readFileSync(new URL('../.github/workflows/infra-ci.yml',import.meta.url),'utf8'));
// Interpret only the boolean expression subset used by these actual job
// conditions. Workflow text is never executed as JavaScript or shell code.
function enabled(expression,context){
 const source=expression.replace(/\b(?:needs|github|inputs)(?:\.[A-Za-z0-9_-]+)+/g,path=>JSON.stringify(path.split('.').reduce((value,key)=>value&&Object.hasOwn(value,key)?value[key]:undefined,context)??''));
 const evaluate=node=>{
  if(node.type==='BooleanLiteral'||node.type==='StringLiteral')return node.value;
  if(node.type==='UnaryExpression'&&node.operator==='!')return !evaluate(node.argument);
  if(node.type==='LogicalExpression'&&node.operator==='&&')return evaluate(node.left)&&evaluate(node.right);
  if(node.type==='LogicalExpression'&&node.operator==='||')return evaluate(node.left)||evaluate(node.right);
  if(node.type==='BinaryExpression'&&node.operator==='==')return evaluate(node.left)===evaluate(node.right);
  if(node.type==='BinaryExpression'&&node.operator==='!=')return evaluate(node.left)!==evaluate(node.right);
  if(node.type==='CallExpression'&&node.callee.type==='Identifier'&&node.callee.name==='always'&&node.arguments.length===0)return true;
  if(node.type==='CallExpression'&&node.callee.type==='Identifier'&&node.callee.name==='cancelled'&&node.arguments.length===0)return context.workflowCancelled===true;
  throw Error('Unsupported deployment condition: '+node.type);
 };
 return Boolean(evaluate(parseExpression(source)));
}
// GitHub's default success() includes the dependency chain, even when an
// immediate dependency ran successfully after an intentionally skipped job.
function scheduled(jobKey,context){
 const job=workflow.jobs[jobKey],ancestors=new Set();
 const visit=key=>{for(const parent of workflow.jobs[key].needs??[]){if(ancestors.has(parent))continue;ancestors.add(parent);visit(parent);}};
 visit(jobKey);
 if(!/\b(?:always|cancelled|failure|success)\s*\(/.test(job.if)){
  for(const parent of ancestors){
   if(!context.needs[parent])throw Error('Unmodeled dependency: '+parent);
   if(context.needs[parent].result!=='success')return false;
  }
 }
 return enabled(job.if,context);
}
function scenario(path,event='push',transition=false){
 const classification=classifyChangedPaths([path]);
 return {inputs:{runtime_cutover:false},github:{repository:'example/repository',event_name:event,event:{action:'synchronize',pull_request:{base:{ref:'main'},head:{repo:{full_name:'example/repository'}}}}},needs:{
  changes:{result:'success',outputs:{workload_changed:String(classification.workloadChanged),aws_mutation_required:String(classification.awsMutationRequired)}},
  'application-region':{result:'success'},typecheck:{result:'success'},
  'verify-production-image-transition':{result:event==='pull_request'?'skipped':'success',outputs:{image_transition:String(transition)}},
  'build-and-push-image':{result:'skipped'},'build-image-transition-control':{result:transition?'success':'skipped'},
  'build-human-acceptance-image':{result:'success'},'mnemo-nonroot-smoke':{result:'skipped'},
 }};
}
describe('deployment image dependency graph',()=>{
 it('PR smoke runs after successful prerequisites with a skipped production ancestor',()=>{
  const context=scenario('docker/mnemo-server/Dockerfile','pull_request');
  context.needs['build-and-push-image']={result:'success',outputs:{mnemo_digest:'sha256:'+'a'.repeat(64)}};
  expect(context.needs['verify-production-image-transition'].result).toBe('skipped');
  expect(scheduled('build-and-push-image',context)).toBe(true);
  expect(scheduled('mnemo-nonroot-smoke',context)).toBe(true);
  context.needs['mnemo-nonroot-smoke'].result='success';
  expect(scheduled('deploy-preview',context)).toBe(true);
 });
 it.each(['application-region','build-and-push-image'].flatMap(job=>['failure','cancelled','skipped'].map(result=>[job,result])))('smoke requires successful %s when its result is %s',(job,result)=>{
  const context=scenario('docker/mnemo-server/Dockerfile','pull_request');
  context.needs['build-and-push-image']={result:'success',outputs:{mnemo_digest:'sha256:'+'a'.repeat(64)}};
  context.needs[job].result=result;
  expect(scheduled('mnemo-nonroot-smoke',context)).toBe(false);
 });
 it.each(['cancelled','missing-digest','fork'])('smoke rejects %s',mode=>{
  const context=scenario('docker/mnemo-server/Dockerfile','pull_request');
  context.needs['build-and-push-image']={result:'success',outputs:{mnemo_digest:'sha256:'+'a'.repeat(64)}};
  if(mode==='cancelled')context.workflowCancelled=true;
  if(mode==='missing-digest')context.needs['build-and-push-image'].outputs.mnemo_digest='';
  if(mode==='fork')context.github.event.pull_request.head.repo.full_name='untrusted/fork';
  expect(scheduled('mnemo-nonroot-smoke',context)).toBe(false);
 });
 for(const path of ['infra/ecs.ts','infra/bootstrap.ts'])for(const event of ['push','pull_request'])it(`${path} on ${event} reaches build, smoke and deployment`,()=>{
  const context=scenario(path,event);
  expect(context.needs.changes.outputs.workload_changed).toBe('false');
  expect(enabled(workflow.jobs['build-and-push-image'].if,context)).toBe(true);
  context.needs['build-and-push-image']={result:'success',outputs:{mnemo_digest:'sha256:'+'a'.repeat(64)}};
  // The smoke job consumes exactly the build whose completion gates deploy.
  expect(workflow.jobs['mnemo-nonroot-smoke'].needs).toContain('build-and-push-image');
  expect(enabled(workflow.jobs['mnemo-nonroot-smoke'].if,context)).toBe(true);
  context.needs['mnemo-nonroot-smoke'].result='success';
  expect(enabled(workflow.jobs[event==='push'?'deploy-prod':'deploy-preview'].if,context)).toBe(true);
  context.needs['mnemo-nonroot-smoke'].result='failure';
  expect(enabled(workflow.jobs[event==='push'?'deploy-prod':'deploy-preview'].if,context)).toBe(false);
 });
 it('documentation and ownership-stack-only changes do not build or deploy workloads',()=>{
  for(const path of ['README.md','infra/cloudformation/github-actions-role.yaml']){
   const context=scenario(path);expect(enabled(workflow.jobs['build-and-push-image'].if,context)).toBe(false);expect(enabled(workflow.jobs['deploy-prod'].if,context)).toBe(false);
  }
 });
 it('a protected security transition still selects the separate control build',()=>{
  const context=scenario('infra/bootstrap.ts','push',true);
  expect(enabled(workflow.jobs['build-and-push-image'].if,context)).toBe(false);
  expect(enabled(workflow.jobs['deploy-prod'].if,context)).toBe(true);
  context.needs['build-image-transition-control'].result='failure';
  expect(enabled(workflow.jobs['deploy-prod'].if,context)).toBe(false);
 });
 it('an ordinary deploy cannot substitute a skipped build even with an unrelated smoke result',()=>{
  for(const event of ['push','pull_request']){
   const context=scenario('infra/ecs.ts',event);context.needs['mnemo-nonroot-smoke'].result='success';
   expect(enabled(workflow.jobs[event==='push'?'deploy-prod':'deploy-preview'].if,context)).toBe(false);
  }
 });
});
