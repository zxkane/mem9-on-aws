import {DescribeServicesCommand,DescribeTaskDefinitionCommand,ListTasksCommand,DescribeTasksCommand} from '@aws-sdk/client-ecs';
import {GetScheduleCommand,UpdateScheduleCommand} from '@aws-sdk/client-scheduler';
import {productionCanarySchedule} from './production-canary-delivery.mjs';
import {canaryEvidenceHash} from './production-canary-verification.mjs';
import {productionArtifactAdmission,validateProductionBackendBinding} from './production-artifacts.mjs';
import {productionRecurringEnvironment,SCHEDULER_CONTEXT_ENVIRONMENT} from './production-scheduler-context.mjs';
import {sendMaintenanceCommand,dispatchMaintenanceAction,maintenanceWorkerTarget} from './production-maintenance-admission.mjs';

const fail=()=>{throw Error('ProductionSchedulingNotVerified');};
const send=(client,command)=>client.send(command,{abortSignal:AbortSignal.timeout(30000)});

export async function captureProductionBackend(clients,target){
  const listed=await send(clients.ecs,new ListTasksCommand({cluster:target.clusterArn,serviceName:'Mem9Server',desiredStatus:'RUNNING',maxResults:100}));
  if(listed.nextToken||listed.taskArns?.length!==1)fail();
  const described=await send(clients.ecs,new DescribeTasksCommand({cluster:target.clusterArn,tasks:listed.taskArns})),task=described.tasks?.[0];
  if(described.failures?.length||described.tasks?.length!==1||task.lastStatus!=='RUNNING'||task.taskArn!==listed.taskArns[0]||task.clusterArn!==target.clusterArn||
    task.containers?.length!==3||task.containers.some(container=>!/^sha256:[a-f0-9]{64}$/.test(container.imageDigest??''))||
    [...task.containers.map(container=>container.name)].sort().join()!==['mnemo-server','qwen3-embed','llm-proxy'].sort().join())fail();
  return validateProductionBackendBinding({taskArn:task.taskArn,taskDefinitionArn:task.taskDefinitionArn,
    containers:task.containers.map(({name,imageDigest})=>({name,imageDigest}))},target.clusterArn);
}

export async function enableProductionScheduling(clients,targets,{admission,activationSeed,assertRelease}){
  for(const target of targets){
    if(productionArtifactAdmission(activationSeed,target.sourceTag,target.image)!==admission)fail();
    await assertRelease();
    const current=await send(clients.scheduler,new GetScheduleCommand({Name:target.template.Name,GroupName:target.groupName}));
    if(canaryEvidenceHash(current.Target)!==canaryEvidenceHash(target.template.Target)||current.State!=='DISABLED')fail();
    productionCanarySchedule(current,target,{wave:'apply',nonce:'0'.repeat(32),admission:'0'.repeat(32),when:Date.now()+60000});
    const input={containerOverrides:[{name:target.containerName,environment:productionRecurringEnvironment(target.generation,admission)}]};
    await sendMaintenanceCommand(clients,'scheduler',new UpdateScheduleCommand({Name:current.Name,GroupName:current.GroupName,State:'ENABLED',
      ...Object.fromEntries(['Description','StartDate','EndDate','KmsKeyArn','ActionAfterCompletion'].filter(key=>current[key]!==undefined).map(key=>[key,current[key]])),
      ScheduleExpression:current.ScheduleExpression,ScheduleExpressionTimezone:current.ScheduleExpressionTimezone,
      FlexibleTimeWindow:current.FlexibleTimeWindow,Target:{...current.Target,Input:JSON.stringify(input)}}),{kind:'activate',operation:'enable-schedule',target:maintenanceWorkerTarget(target)});
  }
}

export async function verifyProductionScheduling(clients,targets,{enabled,admission}={}){
  if(targets.length!==2||new Set(targets.map(target=>target.kind)).size!==2)fail();
  for(const target of targets){
    const current=await send(clients.scheduler,new GetScheduleCommand({Name:target.template.Name,GroupName:target.groupName}));
    productionCanarySchedule(current,target,{wave:'apply',nonce:'0'.repeat(32),admission:'0'.repeat(32),when:Date.now()+60000});
    const input=JSON.parse(current.Target.Input),override=input.containerOverrides[0];
    const metadata=enabled||override.environment?.length===6;
    const allowed=['MEM9_WORKER_GENERATION','MEM9_WORKER_ADMISSION',...(metadata?SCHEDULER_CONTEXT_ENVIRONMENT.map(e=>e.name):[])];
    if(current.State!==(enabled?'ENABLED':'DISABLED')||current.ScheduleExpression!==(target.kind==='planner'?'rate(15 minutes)':'rate(5 minutes)')||
      current.Target.RetryPolicy?.MaximumRetryAttempts!==0||current.Target.RetryPolicy?.MaximumEventAgeInSeconds!==60||
      current.FlexibleTimeWindow?.Mode!=='OFF'||Object.keys(input).join()!=='containerOverrides'||
      Object.keys(override).sort().join()!==['name','environment'].sort().join()||
      override.environment.length!==allowed.length||new Set(override.environment.map(item=>item.name)).size!==allowed.length||
      override.environment.some(item=>!allowed.includes(item.name))||
      metadata&&SCHEDULER_CONTEXT_ENVIRONMENT.some(e=>override.environment.find(item=>item.name===e.name)?.value!==e.value)||
      (enabled&&override.environment.find(item=>item.name==='MEM9_WORKER_ADMISSION')?.value!==admission))fail();
  }
  const services=await send(clients.ecs,new DescribeServicesCommand({cluster:targets[0].clusterArn,services:['Mem9Server']}));
  const service=services.services?.[0];
  if(services.failures?.length||services.services?.length!==1||service.runningCount!==1||service.pendingCount||service.desiredCount!==1||
    service.deployments?.length!==1||service.deployments[0].rolloutState!=='COMPLETED')fail();
  const definition=(await send(clients.ecs,new DescribeTaskDefinitionCommand({taskDefinition:service.taskDefinition}))).taskDefinition;
  const server=definition?.containerDefinitions?.find(container=>container.name==='mnemo-server');
  const target=targets[0];
  const expectedServer=target.dataRelease?.images['mnemo-server']??`${target.account}.dkr.ecr.${target.region}.amazonaws.com/mem9-on-aws/mnemo-server:mem9-${target.revision.slice(0,7)}`;
  if(!/^[a-f0-9]{40}$/.test(target.revision??'')||server?.image!==expectedServer||
    server.environment?.find(item=>item.name==='MNEMO_CONSOLIDATION_EXECUTION_ENABLED')?.value!=='true')fail();
  return {enabled,taskDefinitions:targets.map(target=>target.taskDefinitionArn)};
}

/** SQL must already be paused; disable only the two previously validated schedules. */
export async function disableProductionScheduling(clients,targets){
  for(const target of targets){
    const current=await send(clients.scheduler,new GetScheduleCommand({Name:target.template.Name,GroupName:target.groupName}));
    productionCanarySchedule(current,target,{wave:'apply',nonce:'0'.repeat(32),admission:'0'.repeat(32),when:Date.now()+60000});
    await send(clients.scheduler,new UpdateScheduleCommand({Name:current.Name,GroupName:current.GroupName,State:'DISABLED',
      ...Object.fromEntries(['Description','StartDate','EndDate','KmsKeyArn','ActionAfterCompletion'].filter(key=>current[key]!==undefined).map(key=>[key,current[key]])),
      ScheduleExpression:current.ScheduleExpression,ScheduleExpressionTimezone:current.ScheduleExpressionTimezone,
      FlexibleTimeWindow:current.FlexibleTimeWindow,Target:current.Target}));
  }
}

export async function activateProductionScheduling(deps,{revision,admission,activationSeed}){
  if(!/^[a-f0-9]{40}$/.test(revision??'')||!/^[a-f0-9]{64}$/.test(admission??'')||!/^[a-f0-9]{64}$/.test(activationSeed??''))fail();
  const sameRelease=async()=>{if(await deps.currentMain()!==revision)fail();};
  const setting=(name,value)=>dispatchMaintenanceAction(deps.clients,{kind:'activate',operation:'set-setting',revision},{name,value},input=>deps.setSecret(input.name,input.value));
  await sameRelease();await setting('ProductionConsolidationAdmission',activationSeed);
  await sameRelease();await setting('ProductionConsolidationEnabled','1');
  await sameRelease();await deps.enable({admission,activationSeed,assertRelease:sameRelease});
  await sameRelease();const verified=await deps.verify({enabled:true,admission});return {revision,...verified};
}
