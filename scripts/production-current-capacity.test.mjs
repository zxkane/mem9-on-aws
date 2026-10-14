import {it,expect} from 'vitest';
import {captureCurrentCanaryCapacity,verifyCurrentCanaryCapacity} from './lib/production-current-capacity.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {normalizeCanaryTask} from './lib/production-canary-material.mjs';

function fixture(){
 const h=c=>c.repeat(64),now=1800000000000,account='123456789012',region='ap-northeast-1',dataRevision='a'.repeat(40),attemptId='b'.repeat(32),invocation='c'.repeat(32);
 const root='sha256:'+h('d'),child='sha256:'+h('e'),image=`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/llm-proxy@${root}`;
 const cluster=`arn:aws:ecs:${region}:${account}:cluster/mem9-on-aws-prod-Test`,taskArn=`arn:aws:ecs:${region}:${account}:task/mem9-on-aws-prod-Test/`+'f'.repeat(32);
 const definition={taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/mem9-on-aws-prod-Test-Executor:2`,family:'mem9-on-aws-prod-Test-Executor',revision:2,
  networkMode:'awsvpc',runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},requiresCompatibilities:['FARGATE'],cpu:'512',memory:'1024',
  taskRoleArn:`arn:aws:iam::${account}:role/task`,executionRoleArn:`arn:aws:iam::${account}:role/execution`,containerDefinitions:[{name:'Mem9ConsolidationExecutor',image,environment:[],secrets:[]}]};
 const delivery={kind:'executor',wave:'apply',invocation,taskArn,taskDefinitionArn:definition.taskDefinitionArn,startedMs:now-90000,stoppedMs:now-10000,exitCode:0,image,imageDigest:child};
 delivery.record={kind:'executor',stage:'prod',invocation,outcome:'complete',failedSlices:0,slices:1,changedRows:4,startedMs:delivery.startedMs,finishedMs:delivery.stoppedMs};
 const task={taskArn,clusterArn:cluster,taskDefinitionArn:definition.taskDefinitionArn,lastStatus:'STOPPED',launchType:'FARGATE',cpu:'512',memory:'1024',enableExecuteCommand:false,
  startedAt:new Date(now-91000).toISOString(),stoppedAt:new Date(now-9000).toISOString(),attributes:[{name:'ecs.cpu-architecture',value:'arm64'}],containers:[{name:'Mem9ConsolidationExecutor',image,imageDigest:child,exitCode:0}],
  overrides:{containerOverrides:[{name:'Mem9ConsolidationExecutor',environment:[{name:'MEM9_WORKER_GENERATION',value:h('a')},{name:'MEM9_WORKER_INVOCATION',value:invocation},{name:'MEM9_WORKER_ADMISSION',value:'b'.repeat(32)}]}]}};
 const catalog=new Map([[image,{registryId:account,repositoryName:'mem9-on-aws/llm-proxy',rootDigest:root,arm64Digest:child}]]);
 const compatibility={version:4,dataReleaseHash:h('c'),generation:h('a'),current:{release:{sourceTag:'mem9-'+dataRevision.slice(0,7),workerImage:image}},images:{worker:{currentRoot:root,currentChild:child}},material:{executor:{current:hash(normalizeCanaryTask(definition,{account,region,images:catalog}))}}};
 const calls=[],clients={ecs:{send:async(command,options)=>{calls.push({name:command.constructor.name,input:command.input,signal:options.abortSignal});
  return command.constructor.name==='DescribeTasksCommand'?{tasks:[structuredClone(task)],failures:[]}:{taskDefinition:structuredClone(definition)};}}};
 const launch={version:1,stage:'prod',region,account,cluster:'mem9-on-aws-prod-Test',clusterArn:cluster,generation:compatibility.generation,nonce:invocation,wave:'apply',when:now-100000,deadline:now,
  taskDefinitionArn:definition.taskDefinitionArn,containerName:'Mem9ConsolidationExecutor',taskRoleArn:definition.taskRoleArn,executionRoleArn:definition.executionRoleArn,targetHash:h('f'),overridesHash:hash({containerOverrides:task.overrides.containerOverrides})};
 const options={delivery,launch,attemptId,dataRevision,compatibility,now:()=>now};
 return {options,clients,calls,task,definition,now,cluster};
}
it('collects only the exact current apply task and definition with bounded read signals',async()=>{
 const f=fixture(),result=await captureCurrentCanaryCapacity(f.clients,f.options);
 expect(f.calls.map(c=>c.name)).toEqual(['DescribeTasksCommand','DescribeTaskDefinitionCommand']);
 expect(f.calls[0].input).toEqual({cluster:f.cluster,tasks:[f.task.taskArn]});expect(f.calls[1].input).toEqual({taskDefinition:f.definition.taskDefinitionArn});
 expect(f.calls.every(c=>c.signal instanceof AbortSignal)).toBe(true);expect(result.kind).toBe('current-apply-capacity');expect(result.observedMs).toBe(f.now);
 expect(verifyCurrentCanaryCapacity(result,{...f.options,now:f.now}).delivery).toEqual(f.options.delivery);
});
it('rejects replay, unknown certificate version, wrong source and aborted reads before any API',async()=>{
 for(const defect of ['replay','version','source','launch','abort']){
  const f=fixture();if(defect==='replay')f.options.delivery.wave='repeat-a';if(defect==='version')f.options.compatibility.version=3;
  if(defect==='source')f.options.dataRevision='f'.repeat(40);if(defect==='abort')f.options.signal=AbortSignal.abort();
  if(defect==='launch')f.options.launch.nonce='0'.repeat(32);
  await expect(captureCurrentCanaryCapacity(f.clients,f.options)).rejects.toThrow();expect(f.calls).toHaveLength(0);
 }
});
it('rejects unconfirmed task exit, returned identities, image and execution configuration drift',async()=>{
 for(const defect of ['running','task','definition','image','cpu','override','extra-task']){
  const f=fixture();if(defect==='running')f.task.lastStatus='RUNNING';if(defect==='task')f.task.taskArn+='foreign';if(defect==='definition')f.definition.taskDefinitionArn+='3';
  if(defect==='image')f.task.containers[0].imageDigest='sha256:'+'0'.repeat(64);if(defect==='cpu')f.definition.cpu='1024';if(defect==='override')f.task.overrides.taskRoleArn=f.definition.executionRoleArn;
  if(defect==='extra-task')f.clients.ecs.send=async()=>({tasks:[f.task,f.task],failures:[]});
  await expect(captureCurrentCanaryCapacity(f.clients,f.options)).rejects.toThrow();
 }
});
it('rejects future/stale observations and replacing the complete delivered apply record',async()=>{
 const f=fixture(),value=await captureCurrentCanaryCapacity(f.clients,f.options);
 for(const change of [v=>{v.observedMs=f.now+1;},v=>{v.observedMs=f.now-300001;},v=>{v.delivery.record.changedRows=2;},v=>{v.dataRevision='b'.repeat(40);},v=>{v.attemptId='0'.repeat(32);}]){
  const bad=structuredClone(value);change(bad);expect(()=>verifyCurrentCanaryCapacity(bad,{...f.options,now:f.now})).toThrow();
 }
});
