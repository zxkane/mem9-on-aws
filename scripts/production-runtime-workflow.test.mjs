import {readFileSync} from 'node:fs';
import {describe,it,expect} from 'vitest';
import {parse} from 'yaml';

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
    const repair=cutover.runs.steps.filter(s=>/recovery credentials|failed cutover/.test(s.name??''));
    expect(repair).toHaveLength(2);expect(repair.every(s=>s.if==='failure() || cancelled()')).toBe(true);
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
