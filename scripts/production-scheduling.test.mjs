import {describe,it,expect} from 'vitest';
import {activateProductionScheduling,verifyProductionScheduling,disableProductionScheduling,enableProductionScheduling,captureProductionBackend} from './lib/production-scheduling.mjs';
import {productionArtifactAdmission,bindProductionBackend,validateProductionBackendBinding} from './lib/production-artifacts.mjs';

const revision='a'.repeat(40),admission='b'.repeat(64),account='123456789012',region='ap-northeast-1';
function deployment(){
  const cluster='mem9-on-aws-prod-Fixture',clusterArn=`arn:aws:ecs:${region}:${account}:cluster/${cluster}`,calls=[];
  const targets=['planner','executor'].map(kind=>{
    const containerName='Mem9Consolidation'+(kind==='planner'?'Planner':'Executor');
    const target={cluster,clusterArn,account,region,kind,revision,containerName,generation:'c'.repeat(64),groupName:'mem9-on-aws-prod-consolidation-test',
      sourceTag:'mem9-aaaaaaa',image:`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/llm-proxy@sha256:${'d'.repeat(64)}`,
      roleArn:`arn:aws:iam::${account}:role/mem9-on-aws-prod-Mem9ConsolidationSchedulerRole-role`,
      taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/${cluster}-${containerName}:2`,subnets:['subnet-abcd'],securityGroup:'sg-abcd'};
    target.template={Name:kind,GroupName:target.groupName,State:'DISABLED',ScheduleExpression:`rate(${kind==='planner'?15:5} minutes)`,FlexibleTimeWindow:{Mode:'OFF'},
      Target:{Arn:clusterArn,RoleArn:target.roleArn,RetryPolicy:{MaximumEventAgeInSeconds:60,MaximumRetryAttempts:0},
        Input:JSON.stringify({containerOverrides:[{name:containerName,environment:[{name:'MEM9_WORKER_GENERATION',value:target.generation},{name:'MEM9_WORKER_ADMISSION',value:admission}]}]}),
        EcsParameters:{LaunchType:'FARGATE',TaskCount:1,TaskDefinitionArn:target.taskDefinitionArn,
          NetworkConfiguration:{awsvpcConfiguration:{AssignPublicIp:'DISABLED',Subnets:target.subnets,SecurityGroups:[target.securityGroup]}}}}};
    return target;
  });
  const server={name:'mnemo-server',image:`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/mnemo-server:mem9-${revision.slice(0,7)}`,
    environment:[{name:'MNEMO_CONSOLIDATION_EXECUTION_ENABLED',value:'true'}]};
  const send=async command=>{
    calls.push(command);
    if(command.constructor.name==='GetScheduleCommand')return targets.find(target=>target.template.Name===command.input.Name).template;
    if(command.constructor.name==='UpdateScheduleCommand')return {};
    if(command.constructor.name==='DescribeServicesCommand')return {services:[{runningCount:1,pendingCount:0,desiredCount:1,taskDefinition:'server',deployments:[{rolloutState:'COMPLETED'}]}]};
    if(command.constructor.name==='DescribeTaskDefinitionCommand')return {taskDefinition:{containerDefinitions:[server]}};
    if(command.constructor.name==='ListTasksCommand')return {taskArns:[clusterArn.replace(':cluster/',':task/')+'/'+'a'.repeat(32)]};
    if(command.constructor.name==='DescribeTasksCommand')return {tasks:[{taskArn:clusterArn.replace(':cluster/',':task/')+'/'+'a'.repeat(32),
      taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/${cluster}-Mem9RuntimeServer:1`,clusterArn,lastStatus:'RUNNING',
      containers:['mnemo-server','qwen3-embed','llm-proxy'].map(name=>({name,imageDigest:'sha256:'+'e'.repeat(64)}))}]};
    throw Error('UnexpectedCommand');
  };
  return {targets,calls,server,clients:{ecs:{send},scheduler:{send}}};
}
describe('production scheduling admission and deployment',()=>{
  it('checks retained data roots independently of the current control revision',async()=>{
    const f=deployment(),selected=`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/mnemo-server@sha256:${'e'.repeat(64)}`;
    for(const target of f.targets)target.dataRelease={images:{'mnemo-server':selected}};
    f.server.image=selected;expect((await verifyProductionScheduling(f.clients,f.targets,{enabled:false})).enabled).toBe(false);
    f.server.image=selected.replace(/e{64}$/,'f'.repeat(64));await expect(verifyProductionScheduling(f.clients,f.targets,{enabled:false})).rejects.toThrow();
  });
  it('TC-CONS-WORKER-014 accepts the deployed runtime family and rejects legacy or foreign families',()=>{
    const f=deployment(),target=f.targets[0];
    const binding={taskArn:target.clusterArn.replace(':cluster/',':task/')+'/'+'a'.repeat(32),
      taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/${target.cluster}-Mem9RuntimeServer:2`,
      containers:['mnemo-server','qwen3-embed','llm-proxy'].map(name=>({name,imageDigest:'sha256:'+'e'.repeat(64)}))};
    expect(validateProductionBackendBinding(binding,target.clusterArn).taskDefinitionArn).toBe(binding.taskDefinitionArn);
    for(const taskDefinitionArn of [binding.taskDefinitionArn.replace('Mem9RuntimeServer','Mem9Server'),
      binding.taskDefinitionArn.replace('Mem9RuntimeServer','Mem9RuntimeServerExtra'),
      binding.taskDefinitionArn.replace(target.cluster,target.cluster+'-foreign'),binding.taskDefinitionArn.replace(':2',':0')]){
      expect(()=>validateProductionBackendBinding({...binding,taskDefinitionArn},target.clusterArn)).toThrow('InvalidProductionBackendBinding');
    }
  });
  it('requires HTTP capability but disabled recurrence during the canary',async()=>{
    const f=deployment();expect((await verifyProductionScheduling(f.clients,f.targets,{enabled:false})).enabled).toBe(false);
    f.server.environment[0].value='false';await expect(verifyProductionScheduling(f.clients,f.targets,{enabled:false})).rejects.toThrow();
  });
  it('rejects old tokens, wrong backend revisions and altered scheduled commands',async()=>{
    const f=deployment();f.targets.forEach(target=>target.template.State='ENABLED');
    await expect(verifyProductionScheduling(f.clients,f.targets,{enabled:true,admission:'d'.repeat(64)})).rejects.toThrow();
    expect((await verifyProductionScheduling(f.clients,f.targets,{enabled:true,admission})).enabled).toBe(true);
    f.server.image+='stale';await expect(verifyProductionScheduling(f.clients,f.targets,{enabled:true,admission})).rejects.toThrow();
    f.server.image=f.server.image.slice(0,-5);
    const input=JSON.parse(f.targets[0].template.Target.Input);input.containerOverrides[0].command=['unapproved'];f.targets[0].template.Target.Input=JSON.stringify(input);
    await expect(verifyProductionScheduling(f.clients,f.targets,{enabled:true,admission})).rejects.toThrow();
  });
  it('disables only validated recurring schedules while preserving their options',async()=>{
    const f=deployment();await disableProductionScheduling(f.clients,f.targets);
    expect(f.calls.filter(c=>c.constructor.name==='UpdateScheduleCommand').map(c=>c.input.State)).toEqual(['DISABLED','DISABLED']);
  });
  it('binds activation to exact main and updates only the verified schedules',async()=>{
    const activationSeed='f'.repeat(64),calls=[],deps={currentMain:async()=>revision,setSecret:async name=>calls.push(name),
      enable:async()=>calls.push('enable'),verify:async()=>{calls.push('verify');return {enabled:true};}};
    expect(await activateProductionScheduling(deps,{revision,admission,activationSeed})).toEqual({revision,enabled:true});
    expect(calls).toEqual(['ProductionConsolidationAdmission','ProductionConsolidationEnabled','enable','verify']);
    calls.length=0;
    await expect(activateProductionScheduling({...deps,currentMain:async()=>'f'.repeat(40)},{revision,admission,activationSeed})).rejects.toThrow();expect(calls).toEqual([]);
    await expect(activateProductionScheduling({...deps,enable:async()=>{throw Error('FailedUpdate');}},{revision,admission,activationSeed})).rejects.toThrow('FailedUpdate');
  });
  it('preserves pinned targets and separates index identity from running platform digests',async()=>{
    const f=deployment(),activationSeed='f'.repeat(64),target=f.targets[0];
    const token=productionArtifactAdmission(activationSeed,target.sourceTag,target.image);
    await enableProductionScheduling(f.clients,f.targets,{admission:token,activationSeed,assertRelease:async()=>{}});
    const updates=f.calls.filter(c=>c.constructor.name==='UpdateScheduleCommand');
    expect(updates).toHaveLength(2);
    expect(updates.map(c=>c.input.Target.EcsParameters.TaskDefinitionArn)).toEqual(f.targets.map(t=>t.taskDefinitionArn));
    expect(JSON.parse(updates[0].input.Target.Input).containerOverrides[0].environment[1].value).toBe(token);
    expect(productionArtifactAdmission(activationSeed,'mem9-bbbbbbb',target.image)).not.toBe(token);
    expect(productionArtifactAdmission(activationSeed,target.sourceTag,target.image.replace(/d{64}$/,'c'.repeat(64)))).not.toBe(token);
    const backend=await captureProductionBackend(f.clients,target);
    expect(backend.containers).toHaveLength(3);expect(backend.containers[0].imageDigest).toBe('sha256:'+'e'.repeat(64));
    const persisted=JSON.parse(JSON.stringify(backend));
    expect(bindProductionBackend(persisted,backend,target.clusterArn)).toEqual(backend);
    expect(()=>bindProductionBackend(undefined,backend,target.clusterArn)).toThrow('ProductionBackendBindingMissing');
    expect(()=>bindProductionBackend(persisted,{...backend,taskArn:backend.taskArn.replace(/a{32}$/,'b'.repeat(32))},target.clusterArn)).toThrow('ProductionBackendArtifactChanged');
  });
});
