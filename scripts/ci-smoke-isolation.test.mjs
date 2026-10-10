import {describe,it,expect,afterEach} from 'vitest';
import {execFileSync} from 'node:child_process';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {parse} from 'yaml';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {CI_SMOKE_POLICY} from './lib/ci-smoke-policy.mjs';
import {isolateDataRecipe,verifyIsolatedDataRecipe,buildCiSmokePromotionRoutes,buildCiSmokeImageJob,buildCiSmokeSourceJobs,verifyCiSmokePromotionRoutes,describeCiSmokePromotionPins,ciSmokeSourceClosure} from './lib/ci-smoke-isolation.mjs';
import {createControlSourceContext} from './lib/production-control-source.mjs';

const recipe=()=>({version:1,preparation:{steps:[
 {name:'Build & push mnemo-server (arm64)',uses:'docker/build-push-action@'+'a'.repeat(40)},
 {name:'Smoke test mnemo-server EMF framing (non-TTY)',if:"steps.gate.outputs.skip != 'true'",run:'bash scripts/run-mnemo-emf-smoke.sh'},
],scripts:[{path:'scripts/run-mnemo-health-smoke.sh',sha256:'a'.repeat(64)}]},components:{server:{source:'retained'}}});
// Keep the reviewed product workflow fixture independent of checkout depth,
// test commit and live repository/provider state.
const baseline=()=>JSON.parse(readFileSync(new URL('./fixtures/ci-smoke-baseline.json',import.meta.url),'utf8'));
describe('closed DATA smoke recipe amendment',()=>{
 it('admits only the literal disabled legacy step and new build action id',()=>{
  const origin=recipe(),candidate=isolateDataRecipe(origin);
  expect(candidate.preparation.steps[0].id).toBe('mnemo');expect(candidate.preparation.steps[1].if).toBe(false);
  expect(origin.preparation.steps[0]).not.toHaveProperty('id');
  expect(verifyIsolatedDataRecipe(origin,candidate,{originHash:hash(origin),candidateHash:hash(candidate)})).toEqual({originHash:hash(origin),candidateHash:hash(candidate)});
 });
 it.each([
  c=>{c.preparation.steps[1].if='false';},c=>{c.preparation.steps[1].if='${{ false }}';},
  c=>{delete c.preparation.steps[0].id;},c=>{c.preparation.steps[1].run='true';},
  c=>{c.preparation.scripts[0].sha256='b'.repeat(64);},c=>{c.components.server.source='changed';},
  c=>{c.preparation.steps.push({name:'extra preparation',run:'true'});},
 ])('rejects every additional source or execution delta',mutate=>{
  const o=recipe(),c=isolateDataRecipe(o);mutate(c);expect(()=>verifyIsolatedDataRecipe(o,c,{originHash:hash(o),candidateHash:hash(c)})).toThrow();
 });
 it('rejects duplicate step identities, conflicting ids and a relabelled origin hash',()=>{
  for(const mutate of [o=>o.preparation.steps.push({...o.preparation.steps[0]}),o=>{o.preparation.steps[0].id='mnemo';},o=>o.preparation.steps.push({id:'mnemo'})]){
   const o=recipe();mutate(o);expect(()=>isolateDataRecipe(o)).toThrow();
  }
  const o=recipe(),c=isolateDataRecipe(o);expect(()=>verifyIsolatedDataRecipe(o,c,{originHash:hash(c),candidateHash:hash(c)})).toThrow();
 });
});

describe('all four promotion routes and shared composite',()=>{
 it('acquires a fresh checkpoint before every ordinary-preview prereadiness guard',()=>{
  const b=baseline(),candidate=buildCiSmokePromotionRoutes(b),job=candidate.jobs['deploy-preview'];
  const rows=CI_SMOKE_POLICY.rows.filter(r=>r.route==='deploy-preview'&&r.rule.kind==='protected'&&r.rule.phase==='prereadiness');
  expect(rows.map(r=>r.callPath)).toEqual([16,17,18,19,20,21,22,23,24,26].map(i=>'deploy-preview/'+i));
  const checkpoints=job.steps.filter(s=>s.with?.mode==='target'&&s.with.phase==='prereadiness');
  expect(checkpoints.map(s=>s.env.MEM9_CI_SMOKE_CHECKPOINT)).toEqual(rows.map(r=>r.callPath));
  for(const row of rows){
   const guard=job.steps.findIndex(s=>s.id===row.rule.gateId),target=job.steps[guard-1],protectedStep=job.steps[guard+1];
   const original=b.workflow.jobs['deploy-preview'].steps[Number(row.callPath.split('/')[1])];
   expect(target).toMatchObject({name:'Acquire smoke target receipt: '+row.name,uses:'./.github/actions/ci-smoke-gate',with:{mode:'target',phase:'prereadiness'},'continue-on-error':false});
   expect(target.env).toEqual({GH_TOKEN:'${{ github.token }}',MEM9_DEPLOY_ROLE_ARN:'${{ secrets.AWS_PREVIEW_ROLE_ARN }}',STAGE:"${{ format('pr-{0}', github.event.pull_request.number) }}",MEM9_CI_SMOKE_CHECKPOINT:row.callPath});
   expect(target.if).toBe('success() && ('+(original.if??'true')+')');
   expect(protectedStep).toEqual({...original,if:row.rule.requiredCondition,'continue-on-error':false});
  }
 });
 it.each([16,17,18,19,20,21,22,23,24,26])('rejects deleting the fresh prereadiness checkpoint at deploy-preview/%s',index=>{
  const b=baseline(),candidate=buildCiSmokePromotionRoutes(b);
  candidate.jobs['deploy-preview'].steps=candidate.jobs['deploy-preview'].steps.filter(s=>s.env?.MEM9_CI_SMOKE_CHECKPOINT!=='deploy-preview/'+index);
  expect(()=>verifyCiSmokePromotionRoutes(b,candidate)).toThrow('CiSmokePromotionSourceChanged');
 });
 it('keeps production, retained-runtime, and shared-composite routes unchanged by preview refreshes',()=>{
  const b=baseline(),candidate=buildCiSmokePromotionRoutes(b),workflow=parse(readFileSync(new URL('../.github/workflows/infra-ci.yml',import.meta.url),'utf8'));
  for(const route of ['deploy-prod','runtime-cutover-prod','runtime-cutover-preview'])expect(candidate.jobs[route]).toEqual(workflow.jobs[route]);
  for(const [path,action]of Object.entries(candidate.actions))expect(action).toEqual(parse(readFileSync(new URL('../'+path,import.meta.url),'utf8')));
 });
 it('provides the owner acquisition configuration to every production source reader',()=>{
  const workflow=parse(readFileSync(new URL('../.github/workflows/infra-ci.yml',import.meta.url),'utf8'));
  for(const name of ['verify-production-image-transition','build-image-transition-control','deploy-prod','runtime-cutover-prod']){
   const job=workflow.jobs[name];expect(job.steps.some(step=>step.id==='ci_smoke_source')).toBe(true);
   expect(job.env.MEM9_CI_ACQUISITION_CONFIG,name).toBe('${{ secrets.MEM9_CI_PROD_ACQUISITION_CONFIG }}');
  }
 });
 it('reconstructs the actual checked-in workflow and action callsites from the unchanged baseline',()=>{
  const b=baseline(),workflow=parse(readFileSync(new URL('../.github/workflows/infra-ci.yml',import.meta.url),'utf8'));
  const paths=[...Object.keys(b.actions),'.github/actions/ci-smoke-gate/action.yml'];
  const actions=Object.fromEntries(paths.map(path=>[path,parse(readFileSync(new URL('../'+path,import.meta.url),'utf8'))]));
  expect(()=>verifyCiSmokePromotionRoutes(b,{jobs:Object.fromEntries(CI_SMOKE_POLICY.routes.map(({route})=>[route,workflow.jobs[route]])),actions})).not.toThrow();
  expect(Object.fromEntries(Object.keys(CI_SMOKE_POLICY.sourceJobs).map(name=>[name,workflow.jobs[name]]))).toEqual(buildCiSmokeSourceJobs(b.workflow));
  expect(workflow.jobs['build-and-push-image']).toEqual(buildCiSmokeImageJob(b.workflow));
 });
 it('rejects restoring a skipped build or mutable preview tag after reconstruction',()=>{
  const b=baseline(),candidate=buildCiSmokePromotionRoutes(b);
  for(const mutate of [
   c=>{c.jobs['deploy-preview'].if=c.jobs['deploy-preview'].if.replace("needs.build-and-push-image.result == 'success'","(needs.build-and-push-image.result == 'success' || needs.build-and-push-image.result == 'skipped')");},
   c=>{c.jobs['deploy-preview'].steps.find(s=>s.name==='Deploy PR stage').env.MEM9_IMAGE_TAG='latest';},
   c=>{c.jobs['deploy-preview'].steps.find(s=>s.name==='Deploy PR namespace enforcement').env.MEM9_ECR_NAMESPACE='mem9-on-aws';},
  ]){const changed=structuredClone(candidate);mutate(changed);expect(()=>verifyCiSmokePromotionRoutes(b,changed)).toThrow('CiSmokePromotionSourceChanged');}
 });
 it('rejects a same-named baseline operation with different bytes',()=>{
  const b=baseline();b.workflow.jobs['deploy-prod'].steps.find(s=>s.name==='Deploy prod stage').run='echo unrelated';
  expect(()=>buildCiSmokePromotionRoutes(b)).toThrow('CiSmokeBaselineJobChanged');
 });
 it('builds one shared action and all reviewed invocation bindings',()=>{
  const b=baseline(),candidate=buildCiSmokePromotionRoutes(b);
  expect(()=>verifyCiSmokePromotionRoutes(b,candidate)).not.toThrow();
  const shared=candidate.actions['.github/actions/runtime-cutover/action.yml'];
  expect(shared.runs.steps.filter(s=>s.id?.startsWith('ci_smoke_child_guard_'))).toHaveLength(6);
  for(const route of CI_SMOKE_POLICY.routes){
   expect(candidate.jobs[route.route].steps.filter(s=>s.id==='ci_smoke_source')).toHaveLength(1);
  }
  for(const call of CI_SMOKE_POLICY.shared.parentCalls){
   const step=candidate.jobs[call.route].steps.find(s=>s.name===call.name);
   expect(step.with['ci-smoke-route']).toBe(call.route);expect(step.with['ci-smoke-call-path']).toBe(call.route+'/'+call.baselineIndex);
  }
 });
 it('reconstructs only the fixed Node 24 gate for source and target calls',()=>{
  const b=baseline(),candidate=buildCiSmokePromotionRoutes(b),path='.github/actions/ci-smoke-gate/action.yml';
  expect(candidate.actions[path]?.runs).toEqual({using:'node24',main:'index.mjs'});
  expect(Object.keys(candidate.actions[path].inputs).sort()).toEqual(['mode','phase']);
  const gates=[...Object.values(candidate.jobs).flatMap(job=>job.steps),...candidate.actions['.github/actions/runtime-cutover/action.yml'].runs.steps]
   .filter(step=>step.id==='ci_smoke_source'||step.env?.MEM9_CI_SMOKE_CHECKPOINT);
  expect(gates.length).toBeGreaterThan(10);
  for(const step of gates){
   expect(step.uses).toBe('./.github/actions/ci-smoke-gate');
   expect(step).not.toHaveProperty('run');expect(step).not.toHaveProperty('shell');
   expect(Object.keys(step.with).sort()).toEqual(step.with.mode==='source'?['mode']:['mode','phase']);
  }
  for(const mutate of [
   value=>{value.actions[path].runs.main='other.mjs';},
   value=>{value.actions[path].runs.pre='index.mjs';},
   value=>{value.actions[path].runs.using='node20';},
   value=>{value.actions[path].inputs.route={required:true};},
   value=>{value.jobs['deploy-prod'].steps.find(s=>s.id==='ci_smoke_source').with.route='deploy-preview';},
   value=>{value.jobs['deploy-prod'].steps.find(s=>s.id==='ci_smoke_source').uses='./.github/actions/unknown-node';},
  ]){const changed=structuredClone(candidate);mutate(changed);expect(()=>verifyCiSmokePromotionRoutes(b,changed)).toThrow();}
 });
 it.each(CI_SMOKE_POLICY.rows.filter(r=>r.rule.kind==='protected'&&!r.callPath.includes('/.github/')))('cannot omit the guard for $callPath',row=>{
  const b=baseline(),candidate=buildCiSmokePromotionRoutes(b);
  candidate.jobs[row.route].steps=candidate.jobs[row.route].steps.filter(s=>s.id!==row.rule.gateId);
  expect(()=>verifyCiSmokePromotionRoutes(b,candidate)).toThrow();
 });
 it.each(['Run guarded runtime cutover','Prepare guarded runtime cutover','Finish guarded runtime cutover'])('rejects swapped caller inputs for %s',name=>{
  const b=baseline(),c=buildCiSmokePromotionRoutes(b);const call=CI_SMOKE_POLICY.shared.parentCalls.find(v=>v.name===name);
  c.jobs[call.route].steps.find(s=>s.name===name).with['ci-smoke-call-path']='runtime-cutover-preview/99';
  expect(()=>verifyCiSmokePromotionRoutes(b,c)).toThrow();
 });
 it('retains recovery eligibility while rejecting unknown postcredential operations',()=>{
  const b=baseline(),c=buildCiSmokePromotionRoutes(b);
  for(const row of CI_SMOKE_POLICY.rows.filter(r=>r.rule.kind==='safe-recovery'&&!r.callPath.includes('/.github/'))){
   const original=b.workflow.jobs[row.route].steps[Number(row.callPath.split('/')[1])];
   expect(c.jobs[row.route].steps.find(s=>s.name===row.name)).toEqual(original);
  }
  c.jobs['deploy-prod'].steps.push({name:'hidden launch',run:'aws ecs run-task'});
  expect(()=>verifyCiSmokePromotionRoutes(b,c)).toThrow();
 });
 it('requires an entry-source pin and never treats an unknown Node action as an opaque leaf',()=>{
  const c=buildCiSmokePromotionRoutes(baseline()),entry='.github/actions/ci-smoke-gate/index.mjs';
  const paths=['.github/workflows/infra-ci.yml',...Object.keys(c.actions),entry];
  const pins=Object.fromEntries(paths.map(path=>[path,{path,gitMode:'100644',sha256:'a'.repeat(64),bytes:1}]));
  const workflow={jobs:c.jobs};
  expect(describeCiSmokePromotionPins(workflow,c.actions,pins).every(route=>route.localActions.some(pin=>pin.path===entry))).toBe(true);
  const missing={...pins};delete missing[entry];
  expect(()=>describeCiSmokePromotionPins(workflow,c.actions,missing)).toThrow('CiSmokeNodeActionSource');
  for(const using of ['node24','composite']){
   const foreign=structuredClone(workflow),path='.github/actions/unknown/action.yml';
   foreign.jobs['deploy-prod'].steps.push({uses:'./.github/actions/unknown'});
   const actions={...c.actions,[path]:{runs:using==='node24'?{using,main:'index.mjs'}:{using,steps:[{run:'echo unknown'}]}}};
   expect(()=>describeCiSmokePromotionPins(foreign,actions,{...pins,[path]:{...pins[entry],path}})).toThrow('CiSmokeUnclassifiedLocalAction');
  }
 });
});

describe('complete smoke source closure',()=>{
 const directories=[];afterEach(()=>{for(const d of directories.splice(0))rmSync(d,{recursive:true,force:true});});
 function source(files){
  const directory=mkdtempSync(join(tmpdir(),'ci-smoke-source-'));directories.push(directory);
  const git=args=>execFileSync('git',args,{cwd:directory,encoding:'utf8'});
  git(['init','--quiet']);
  for(const[path,content]of Object.entries(files)){const target=join(directory,path);mkdirSync(dirname(target),{recursive:true});writeFileSync(target,content);}
  git(['add','.']);const tree=git(['write-tree']).trim();
  const entries=git(['ls-tree','-r','-z',tree]).split('\0').filter(Boolean).map(row=>{const m=/^(\d+) (\w+) ([a-f0-9]{40})\t(.+)$/.exec(row);return{mode:m[1],type:m[2],oid:m[3],path:m[4]};});
  return createControlSourceContext({tree,entries},async oid=>Buffer.from(execFileSync('git',['cat-file','blob',oid],{cwd:directory})));
 }
 it('includes literal imports, re-exports and CommonJS references',async()=>{
  const context=source({'scripts/entry.mjs':"import './a.mjs'; export * from './b.mjs'; require('./c.mjs');",'scripts/a.mjs':'export const a=1;','scripts/b.mjs':'export const b=1;','scripts/c.mjs':'export const c=1;'});
  expect((await ciSmokeSourceClosure(context,['scripts/entry.mjs'])).map(f=>f.path)).toEqual(['scripts/a.mjs','scripts/b.mjs','scripts/c.mjs','scripts/entry.mjs']);
 });
 it('rejects an unsupported aliased createRequire loader',async()=>{
  const context=source({'scripts/entry.mjs':"import {createRequire as loader} from 'node:module'; const r=loader(import.meta.url); r('./hidden.mjs');",'scripts/hidden.mjs':'export const hidden=1;'});
  await expect(ciSmokeSourceClosure(context,['scripts/entry.mjs'])).rejects.toThrow('CiSmokeUnsupportedModuleLoader');
 });
 it('rejects a missing shell-script reference instead of silently dropping it',async()=>{
  const context=source({'scripts/entry.sh':'node scripts/absent.mjs\n'});
  await expect(ciSmokeSourceClosure(context,['scripts/entry.sh'])).rejects.toThrow('CiSmokeClosureMissing');
 });
});
