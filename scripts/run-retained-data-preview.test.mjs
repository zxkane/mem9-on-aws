import {it,expect} from 'vitest';
import {retainedPreviewBuildDigests,runRetainedDataPreview,postRuntimePreviewEnvironment,assertRetainedPreviewQuiet,retainedPreviewStep} from './run-retained-data-preview.mjs';
import {previewGeneration} from './lib/consolidation-preview-config.mjs';
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
it('derives the post-runtime generation only from a completed matching preview',()=>{
  const env={STAGE:'pr-7',MEM9_DEPLOY_COMMIT:'a'.repeat(40),GITHUB_RUN_ID:'42',GITHUB_RUN_ATTEMPT:'1'};
  const marker={stage:'pr-7',phase:'complete',status:'running',nonce:'b'.repeat(32)};
  const next=postRuntimePreviewEnvironment(env,marker);
  expect(next.MEM9_PREVIEW_RUNTIME_NONCE).toBe(marker.nonce);expect(next.MEM9_PRODUCTION_RUNTIME_MODE).toBe('active');
  expect(previewGeneration('pr-7',next)).not.toBe(previewGeneration('pr-7',env));
  expect(env.MEM9_PREVIEW_RUNTIME_NONCE).toBeUndefined();
  for(const value of [{...marker,phase:'retired'},{...marker,stage:'prod'},{...marker,nonce:'invalid'}])expect(()=>postRuntimePreviewEnvironment(env,value)).toThrow();
});
it('requires empty old journals, disabled exact schedules and no running workers before changing context',async()=>{
  const stage='pr-7',region='ap-northeast-1',account='123456789012',clusterArn=`arn:aws:ecs:${region}:${account}:cluster/mem9-on-aws-pr-7-example`;
  const manifest={stage,generation:'a'.repeat(64),clusterArn,groupName:'mem9-on-aws-pr-7-consolidation-example',roleArn:`arn:aws:iam::${account}:role/mem9-on-aws-pr-7-Mem9ConsolidationSchedulerRole-role`,
    workers:['planner','executor'].map(kind=>({kind,containerName:'Mem9Consolidation'+(kind==='planner'?'Planner':'Executor'),taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/mem9-on-aws-pr-7-${kind}:1`,scheduleName:`mem9-on-aws-pr-7-${kind}-example`,logGroupName:'/sst/example'}))};
  for(const unsafe of [null,'journal','schedule','task','stopping','stopped','missing']){
    const calls=[],client={send:async command=>{
      const name=command.constructor.name;calls.push(name);
      if(name==='GetParametersCommand')return {Parameters:[{Name:command.input.Names[0],Value:JSON.stringify(manifest)}]};
      if(name==='GetParametersByPathCommand')return {Parameters:unsafe==='journal'?[{Name:'owned-pending'}]:[]};
      if(name==='ListSchedulesCommand')return {Schedules:manifest.workers.map(w=>({Name:w.scheduleName,GroupName:manifest.groupName,
        Arn:`arn:aws:scheduler:${region}:${account}:schedule/${manifest.groupName}/${w.scheduleName}`,State:unsafe==='schedule'?'ENABLED':'DISABLED'}))};
      if(name==='ListTasksCommand')return {taskArns:(unsafe==='task'&&command.input.desiredStatus==='RUNNING'||['stopping','stopped','missing'].includes(unsafe)&&command.input.desiredStatus==='STOPPED')?['known-task']:[]};
      if(name==='DescribeTasksCommand')return unsafe==='missing'?{}:{tasks:[{taskArn:'known-task',clusterArn,taskDefinitionArn:manifest.workers[0].taskDefinitionArn,lastStatus:unsafe==='stopped'?'STOPPED':unsafe==='stopping'?'STOPPING':'RUNNING'}]};
      throw Error('UnexpectedMutation');
    }};
    const operation=assertRetainedPreviewQuiet({ssm:client,ecs:client,scheduler:client},{stage,region,account,clusterArn});
    if(unsafe&&unsafe!=='stopped')await expect(operation).rejects.toThrow();else await expect(operation).resolves.toBeUndefined();
    expect(calls.every(c=>/^(Get|List|Describe)/.test(c))).toBe(true);
  }
});
it('emits only fixed stage diagnostics without child errors or secret output',async()=>{
  const events=[];
  await expect(retainedPreviewStep('scheduler',async()=>{throw Object.assign(Error('PRIVATE_SECRET'),{stdout:'PRIVATE_SECRET',stderr:'PRIVATE_SECRET'});},e=>events.push(e))).rejects.toMatchObject({step:'scheduler'});
  expect(JSON.stringify(events)).not.toContain('PRIVATE_SECRET');expect(events.at(-1)).toMatchObject({step:'scheduler',phase:'failed'});
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
