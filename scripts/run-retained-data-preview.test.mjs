import {it,expect} from 'vitest';
import {retainedPreviewBuildDigests,runRetainedDataPreview} from './run-retained-data-preview.mjs';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {parse} from 'yaml';
const names=['llm-proxy','mnemo-server','qwen3-embed','bootstrap'];
const log=()=>names.map((name,i)=>`#1 pushing manifest for masked.example.com/mem9-on-aws/preview/${name}:pr-aaaaaaa@sha256:${String(i+1).repeat(64)} done`).join('\n');
it('extracts one complete same-tag preview build and ignores independent fixture tags',()=>{
  const value=retainedPreviewBuildDigests(log()+'\n#2 pushing manifest for masked.example.com/mem9-on-aws/preview/bootstrap:pr-aaaaaaa-canary-db@sha256:'+'f'.repeat(64)+' done');
  expect(value.tag).toBe('pr-aaaaaaa');expect(Object.keys(value.images).sort()).toEqual([...names].sort());
});
it('rejects missing, mixed and ambiguous data artifacts',()=>{
  for(const value of [log().split('\n').slice(1).join('\n'),log().replace('pr-aaaaaaa','pr-bbbbbbb'),log()+'\n'+log().replaceAll('sha256:','sha256:0')]){
    expect(()=>retainedPreviewBuildDigests(value)).toThrow('RetainedPreviewUnverified');
  }
  expect(()=>retainedPreviewBuildDigests(log()+'\n'+log().replaceAll('1'.repeat(64),'f'.repeat(64)))).toThrow('RetainedPreviewUnverified');
});
it('cannot run against production or outside its actual workflow context',async()=>{
  await expect(runRetainedDataPreview({STAGE:'prod'})).rejects.toThrow('RetainedPreviewUnverified');
  await expect(runRetainedDataPreview({STAGE:'pr-7',GITHUB_EVENT_NAME:'pull_request'})).rejects.toThrow('RetainedPreviewUnverified');
});
it('gates the manual input before AWS work and runs the combination between finalization and cleanup',()=>{
  const workflow=parse(readFileSync('.github/workflows/infra-ci.yml','utf8'));
  const validation=workflow.jobs['application-region'].steps.find(s=>s.name==='Validate retained preview request');
  for(const [stage,cutover,runId,ok]of [['pr-7','true','42',true],['prod','true','42',false],['pr-7','false','42',false],['pr-7','true','bad',false],['prod','false','',true]]){
    const result=spawnSync('bash',['-c',validation.run],{env:{...process.env,RUNTIME_STAGE:stage,RUNTIME_CUTOVER:cutover,RETAINED_DATA_RUN_ID:runId},encoding:'utf8'});
    expect(result.status===0).toBe(ok);
  }
  const steps=workflow.jobs['runtime-cutover-preview'].steps,index=steps.findIndex(s=>s.name==='Retained data and current control acceptance (preview, hard)');
  expect(index).toBeGreaterThan(steps.findIndex(s=>s.name==='Finish guarded runtime cutover'));
  expect(index).toBeLessThan(steps.findIndex(s=>s.name==='Remove disposable rehearsal'));
  expect(steps[index].run).toBe('node scripts/run-retained-data-preview.mjs');
});
