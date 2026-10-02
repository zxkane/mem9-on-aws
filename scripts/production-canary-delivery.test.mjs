import {describe,it,expect} from 'vitest';
import {productionCanarySchedule,ownsCanaryTask,quiesceProductionWorkers,runProductionCanaryWake} from './lib/production-canary-delivery.mjs';
import {canaryEvidenceHash} from './lib/production-canary-verification.mjs';

const namespace='60000000-0000-4000-8000-000000000001',id='a'.repeat(64);
function fixture(wave='repeat-a'){
  const target={clusterArn:'arn:aws:ecs:ap-northeast-1:123456789012:cluster/mem9-on-aws-prod-Fixture',cluster:'mem9-on-aws-prod-Fixture',
    region:'ap-northeast-1',account:'123456789012',groupName:'mem9-on-aws-prod-consolidation-example',generation:'b'.repeat(64),
    roleArn:'arn:aws:iam::123456789012:role/mem9-on-aws-prod-Mem9ConsolidationSchedulerRole-role',
    containerName:'Mem9ConsolidationExecutor',taskDefinitionArn:'arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-on-aws-prod-Fixture-Mem9ConsolidationExecutor:1',
    taskRoleArn:'task-role',executionRoleArn:'execution-role',subnets:['subnet-abcd'],securityGroup:'sg-abcd'};
  const template={State:'ENABLED',GroupName:target.groupName,Target:{Arn:target.clusterArn,RoleArn:target.roleArn,
    EcsParameters:{TaskDefinitionArn:target.taskDefinitionArn,LaunchType:'FARGATE',TaskCount:1,NetworkConfiguration:{awsvpcConfiguration:{AssignPublicIp:'DISABLED',Subnets:['subnet-abcd'],SecurityGroups:['sg-abcd']}}},
    Input:JSON.stringify({containerOverrides:[{name:target.containerName,environment:[{name:'MEM9_WORKER_GENERATION',value:target.generation}]}]})}};
  const request=productionCanarySchedule(template,target,{wave,nonce:'c'.repeat(32),when:Date.now()+60000,
    actions:[{id,namespace,result:{action_id:id,status:'applied',changed_rows:2}}]});
  const journal={...target,nonce:'c'.repeat(32),overridesHash:canaryEvidenceHash(JSON.parse(request.Target.Input))};
  const task={taskArn:`arn:aws:ecs:${target.region}:${target.account}:task/${target.cluster}/${'d'.repeat(32)}`,clusterArn:target.clusterArn,
    taskDefinitionArn:target.taskDefinitionArn,overrides:JSON.parse(request.Target.Input)};
  return {target,template,request,journal,task};
}
describe('bounded production Scheduler deliveries',()=>{
  it('persists the exact launch identity before any AWS write and honors cancellation without retiming',async()=>{
    const f=fixture(),calls=[],target={...f.target,kind:'executor',template:f.template},abort=new AbortController();
    const clients={ssm:{send:async()=>calls.push('put')},scheduler:{send:async()=>calls.push('schedule')}};
    await expect(runProductionCanaryWake(clients,target,{wave:'apply',admission:'a'.repeat(32),onIntent:async journal=>{
      expect(journal.stage).toBe('prod');expect(journal.wave).toBe('apply');expect(journal.nonce).toMatch(/^[a-f0-9]{32}$/);expect(calls).toEqual([]);abort.abort();
    }},{signal:abort.signal})).rejects.toThrow();expect(calls).toEqual([]);
    let clock=100000;
    await expect(runProductionCanaryWake(clients,target,{wave:'apply',admission:'a'.repeat(32),onIntent:async()=>{clock+=60001;}},{now:()=>clock})).rejects.toThrow('ProductionCanaryDeliveryFailed');
    expect(calls).toEqual([]);
  });
  it('stops older revisions of approved worker families and leaves unrelated tasks alone',async()=>{
    const f=fixture(),stopped=[];let now=Date.now();
    const target={...f.target,taskDefinitionArn:f.target.taskDefinitionArn.replace(/:1$/,':2')};
    const tasks=[{...f.task,lastStatus:'RUNNING'},
      {...f.task,taskArn:f.task.taskArn.replace(/d{32}$/,'e'.repeat(32)),taskDefinitionArn:f.task.taskDefinitionArn.replace('Mem9ConsolidationExecutor','Mem9Server'),lastStatus:'RUNNING'}];
    const ecs={send:async command=>{
      if(command.constructor.name==='ListTasksCommand')return {taskArns:tasks.filter(task=>(task.lastStatus==='STOPPED')===(command.input.desiredStatus==='STOPPED')).map(task=>task.taskArn)};
      if(command.constructor.name==='DescribeTasksCommand')return {tasks:tasks.filter(task=>command.input.tasks.includes(task.taskArn))};
      if(command.constructor.name==='StopTaskCommand'){stopped.push(command.input.task);tasks.find(task=>task.taskArn===command.input.task).lastStatus='STOPPED';return {};}
      throw Error('UnexpectedCommand');
    }};
    await quiesceProductionWorkers({ecs},[target],{now:()=>now,sleep:async ms=>{now+=ms;}});
    expect(stopped).toEqual([f.task.taskArn]);expect(tasks[1].lastStatus).toBe('RUNNING');
  });
  it('creates one-shot cached-receipt replay with no delivery retries and exact worker identity',()=>{
    const f=fixture(),input=JSON.parse(f.request.Target.Input).containerOverrides[0];
    expect(f.request).toMatchObject({ActionAfterCompletion:'DELETE',State:'ENABLED',FlexibleTimeWindow:{Mode:'OFF'}});
    expect(f.request.Target.RetryPolicy).toEqual({MaximumEventAgeInSeconds:60,MaximumRetryAttempts:0});
    expect(input.command).toEqual(['/app/scripts/consolidation-canary-replay.mjs']);
    expect(ownsCanaryTask(f.task,f.journal)).toBe(true);
  });
  it('rejects changed targets and unexpected task overrides',()=>{
    const f=fixture();
    expect(()=>productionCanarySchedule({...f.template,Target:{...f.template.Target,Arn:'foreign'}},f.target,{wave:'repeat-a',nonce:'c'.repeat(32),when:Date.now()+60000,actions:[]})).toThrow();
    for(const patch of [{executionRoleArn:'foreign'},{containerOverrides:[{name:f.target.containerName,command:['unsafe']}]}]){
      expect(ownsCanaryTask({...f.task,overrides:{...f.task.overrides,...patch}},f.journal)).toBe(false);
    }
  });
  it.each(['public','subnet','security-group'])('rejects %s network drift before delivery',kind=>{
    const f=fixture(),template=structuredClone(f.template),network=template.Target.EcsParameters.NetworkConfiguration.awsvpcConfiguration;
    if(kind==='public')network.AssignPublicIp='ENABLED';
    if(kind==='subnet')network.Subnets=['subnet-ffff'];
    if(kind==='security-group')network.SecurityGroups=['sg-ffff'];
    expect(()=>productionCanarySchedule(template,f.target,{wave:'apply',nonce:'c'.repeat(32),when:Date.now()+60000})).toThrow('ProductionCanaryDeliveryFailed');
  });
});
