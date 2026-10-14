import {it,expect} from 'vitest';
import {readFile,mkdtemp,copyFile,rm} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {parse} from 'yaml';
import {CARRIER_CI_JOB} from './lib/ci-carrier-before-copy.mjs';
const workflow=()=>readFile(new URL('../.github/workflows/infra-ci.yml',import.meta.url),'utf8').then(parse);

it('uses the fixed preview job, secret, opaque dispatch commitments and bundled Node24 action',async()=>{
 const w=await workflow(),j=w.jobs[CARRIER_CI_JOB.jobKey],a=parse(await readFile(new URL('../.github/actions/ci-carrier-before-copy/action.yml',import.meta.url),'utf8'));
 expect(j.name).toBe(CARRIER_CI_JOB.jobName);expect(j.environment).toBe('preview-ci');expect(j.if).toBe("github.event_name == 'workflow_dispatch' && inputs.carrier_before_copy && !inputs.runtime_cutover");
 expect(j.env.MEM9_CARRIER_WORKER_CONFIG).toBe('${{ secrets.MEM9_CARRIER_WORKER_CONFIG }}');expect(j.env.AWS_PREVIEW_ROLE_ARN).toBe('${{ secrets.AWS_PREVIEW_ROLE_ARN }}');
 expect(j.permissions).toEqual({contents:'read',actions:'read',statuses:'read','id-token':'write'});
 expect(j.steps).toHaveLength(2);expect(j.steps[0].with['persist-credentials']).toBe(false);
 expect(j.steps[1]).toMatchObject({uses:'./.github/actions/ci-carrier-before-copy',with:{grant_commitment:'${{ inputs.carrier_grant }}',context_commitment:'${{ inputs.carrier_context }}'}});
 expect(a.runs).toEqual({using:'node24',main:'dist/index.mjs'});expect(j.env).not.toHaveProperty('MEM9_CI_ACQUISITION_CONFIG');
});
it('carrier dispatch closes every ordinary root and the always-running prod failure reporter',async()=>{
 const w=await workflow();for(const k of ['application-region','changes','typecheck','report-prod-failure'])expect(w.jobs[k].if).toContain('!inputs.carrier_before_copy');
 for(const k of ['runtime-cutover-prod','runtime-cutover-preview']){expect(w.jobs[k].needs).toContain('application-region');expect(w.jobs[k].needs).toContain('typecheck');expect(w.jobs[k].if).not.toContain('always()');}
 for(const k of ['deploy-prod','build-and-push-image']){expect(w.jobs[k].if).toContain("needs.application-region.result == 'success'");expect(w.jobs[k].if).toContain("needs.typecheck.result == 'success'");}
 expect(w.concurrency.group).toContain('inputs.carrier_before_copy');expect(w.concurrency['cancel-in-progress']).toBe(false);
});
it('bundled action holds cleanly in an isolated directory without installed packages or credentials',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'carrier-packed-test-')),file=join(dir,'index.mjs');
 try{await copyFile(new URL('../.github/actions/ci-carrier-before-copy/dist/index.mjs',import.meta.url),file);
  const result=await promisify(execFile)(process.execPath,[file],{cwd:dir,env:{PATH:'/usr/bin:/bin'},timeout:5000}).then(()=>null,e=>e);
  expect(result.code).toBe(1);expect(result.stdout).toBe('');expect(result.stderr).toBe('{"kind":"carrier-build-held","code":"CarrierActionFailed"}\n');
 }finally{await rm(dir,{recursive:true,force:true});}
});
