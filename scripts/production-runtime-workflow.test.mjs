import {readFileSync} from 'node:fs';
import {describe,it,expect} from 'vitest';
import {parse} from 'yaml';
import {cutoverDeploymentEnvironment} from './run-production-runtime.mjs';

const recovery=parse(readFileSync(new URL('../.github/workflows/runtime-recovery.yml',import.meta.url),'utf8'));
const cutover=parse(readFileSync(new URL('../.github/actions/runtime-cutover/action.yml',import.meta.url),'utf8'));
const ci=parse(readFileSync(new URL('../.github/workflows/infra-ci.yml',import.meta.url),'utf8'));
const AsyncFunction=Object.getPrototypeOf(async()=>{}).constructor;
const guard=new AsyncFunction('context','github','core',recovery.jobs.source.steps[0].with.script);
async function classify({branch='main',event='workflow_dispatch',jobs,path='.github/workflows/infra-ci.yml'}={}){
  const outputs={};
  await guard({repo:{owner:'example',repo:'example'},payload:{workflow_run:{id:7,event,path,head_branch:branch,head_sha:'a'.repeat(40)}}},
    {paginate:async()=>jobs,rest:{actions:{listJobsForWorkflowRun(){}}}},
    {setOutput:(name,value)=>{outputs[name]=value;}});
  return outputs;
}
describe('independent cutover cancellation recovery',()=>{
  it('rehearses the ordinary production bootstrap launcher after preview cutover completion',()=>{
    const steps=cutover.runs.steps;
    const at=steps.findIndex(s=>s.name==='Verify ordinary deployment bootstrap invocation');
    expect(at).toBeGreaterThan(steps.findIndex(s=>s.name==='Converge infrastructure and verify retirement'));
    expect(at).toBeLessThan(steps.findIndex(s=>s.name==='Verify preview extension upgrade and administrator backup recovery'));
    expect(steps[at]).toMatchObject({if:"success() && steps.ci_smoke_child_guard_08.outcome == 'success' && (inputs.cleanup-preview == 'true' && inputs.phase != 'prepare')",shell:'bash',run:'bash scripts/run-bootstrap-task.sh'});
    expect(steps[at-1].id).toBe('ci_smoke_child_guard_08');
    expect(steps[at]['continue-on-error']).not.toBe(true);
  });
  it('keeps preview rehearsal scheduling aligned with normal preview instead of the production opt-in',async()=>{
    const preview=ci.jobs['runtime-cutover-preview'];
    expect(preview.env.MEM9_CONSOLIDATION_SCHEDULE_ENABLED).toBe('0');
    expect(ci.jobs['deploy-preview'].env?.MEM9_CONSOLIDATION_SCHEDULE_ENABLED??'0').toBe('0');
    expect(ci.jobs['runtime-cutover-prod'].env.MEM9_CONSOLIDATION_SCHEDULE_ENABLED).toContain('vars.MEM9_NAMESPACE_CONSOLIDATION_SCHEDULE_ENABLED');
    const clients={ssm:{send:async command=>({Parameters:[{Name:command.input.Names[0],Value:'[]'}]})}};
    const env=await cutoverDeploymentEnvironment(clients,'pr-7',preview.env);
    expect(env.SST_SECRET_MaintenanceNamespaceIds).toBe('[]');
  });
  it('runs independently after source completion with literal protected environments and shared serialization',()=>{
    expect(recovery.on.workflow_run).toEqual({workflows:['Infra CI'],types:['completed']});
    expect(recovery.jobs.source.if).toContain('head_repository.full_name == github.repository');
    expect(recovery.jobs.source.permissions['id-token']).toBeUndefined();
    for(const job of Object.values(recovery.jobs))expect(job['runs-on']).toBe("${{ vars.RUNNER_LABEL && fromJSON(vars.RUNNER_LABEL) || 'ubuntu-latest' }}");
    expect(recovery.jobs.production.environment).toBe('prod');
    expect(recovery.jobs.preview.environment).toBe('preview-ci');
    expect(recovery.jobs.production.concurrency).toEqual({group:'infra-deploy-prod','cancel-in-progress':false,queue:'max'});
    expect(ci.concurrency.queue).toBe('max');expect(recovery.jobs.preview.concurrency.queue).toBe('max');
    for(const kind of ['production','preview']){
      const job=recovery.jobs[kind],checkout=job.steps.find(s=>s.uses?.startsWith('actions/checkout@'));
      expect(checkout.with).toMatchObject({ref:'${{ needs.source.outputs.sha }}','persist-credentials':false});
      expect(job.env.MEM9_RUNTIME_RECOVERY_RUN_ID).toBe('${{ needs.source.outputs.run-id }}');
      expect(job.steps.at(-1).run).toContain('2700 node scripts/run-production-runtime.mjs recover');
    }
    expect(cutover.runs.steps.some(s=>/\bmjs (recover|cleanup-preview)\b/.test(s.run??''))).toBe(false);
    const preview=ci.jobs['runtime-cutover-preview'];
    expect(preview.steps.find(s=>s.name==='Arm preview cancellation rehearsal')?.id).toBe('cancel_arm');
    for(const name of ['Restore interrupted preview runtime','Remove disposable rehearsal']){
      const step=preview.steps.find(s=>s.name===name);
      expect(step?.uses).toMatch(/^\.\/\.github\/actions\/runtime-(recovery|cleanup)$/);
      expect(step?.if).toContain("!(cancelled() && steps.cancel_arm.outputs.armed == 'true')");
    }
    expect(preview.steps.find(s=>s.name==='Remove disposable rehearsal').if).toContain("inputs.runtime_cancellation_mode != 'resume' || success()");
    expect(ci.jobs['runtime-cutover-prod'].steps.find(s=>s.name==='Restore interrupted production runtime').if).toBe('failure() || cancelled()');
  });
  it('accepts a cancelled production cutover but rejects a different branch or ordinary deployment failure',async()=>{
    const jobs=[{name:ci.jobs['runtime-cutover-prod'].name,conclusion:'cancelled'}];
    expect(await classify({jobs})).toEqual({stage:'prod',sha:'a'.repeat(40),'run-id':'7'});
    await expect(classify({branch:'feature/unreviewed',jobs})).rejects.toThrow('UntrustedProductionRecoverySource');
    expect(await classify({jobs:[{name:'Deploy prod',conclusion:'failure'}]})).toEqual({});
    expect(await classify({event:'pull_request',jobs})).toEqual({});
    expect(await classify({path:'unrelated.yml',jobs})).toEqual({});
  });
  it('binds preview cleanup/recovery to one validated numeric stage and ignores skipped cutovers',async()=>{
    expect(await classify({branch:'feat/test',jobs:[{name:'Preview runtime credential rehearsal (pr-7)',conclusion:'failure'}]})).toMatchObject({stage:'pr-7'});
    for(const name of ['Preview runtime credential rehearsal (prod)','Preview runtime credential rehearsal (pr-7; unsafe)'])
      expect(await classify({jobs:[{name,conclusion:'failure'}]})).toEqual({});
    expect(await classify({jobs:[{name:'Production runtime credential cutover',conclusion:'skipped'}]})).toEqual({});
  });
});
