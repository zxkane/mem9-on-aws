import {randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {GetParametersCommand,GetParametersByPathCommand,PutParameterCommand,DeleteParameterCommand} from '@aws-sdk/client-ssm';
import {GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {DescribeTaskDefinitionCommand,ListTasksCommand,DescribeTasksCommand,StopTaskCommand} from '@aws-sdk/client-ecs';
import {GetScheduleCommand,CreateScheduleCommand,DeleteScheduleCommand} from '@aws-sdk/client-scheduler';
import {FilterLogEventsCommand} from '@aws-sdk/client-cloudwatch-logs';
import {verifyProductionTaskRoles,validateProductionWorkerTarget} from '../run-production-consolidation.mjs';
import {canaryEvidenceHash} from './production-canary-verification.mjs';
import {requireNamespaceId} from './maintenance-scope.mjs';
import {discoverSchedulerTasks} from '../consolidation-scheduler-e2e.mjs';
import {loadWorkerDataRelease} from './production-data-release-loader.mjs';
import {productionSourceTree} from '../run-production-runtime.mjs';
import {sendMaintenanceCommand,maintenanceWorkerTarget} from './production-maintenance-admission.mjs';

const send=(client,command)=>client.send(command,{abortSignal:AbortSignal.timeout(30000)});
const fail=()=>{throw Error('ProductionCanaryDeliveryFailed');};
const env=container=>Object.fromEntries((container?.environment??[]).map(item=>[item.name,item.value]));

export function productionCanarySchedule(template,target,{wave,nonce,when,actions,admission}){
  if(!['plan','apply','repeat-a','repeat-b'].includes(wave)||!/^[a-f0-9]{32}$/.test(nonce??'')||!Number.isSafeInteger(when)||
    !['ENABLED','DISABLED'].includes(template?.State)||template.GroupName!==target.groupName||template.Target?.Arn!==target.clusterArn||
    template.Target.RoleArn!==target.roleArn||template.Target.EcsParameters?.TaskDefinitionArn!==target.taskDefinitionArn||
    template.Target.EcsParameters.LaunchType!=='FARGATE'||template.Target.EcsParameters.TaskCount!==1)fail();
  const network=template.Target.EcsParameters.NetworkConfiguration?.awsvpcConfiguration;
  if(network?.AssignPublicIp!=='DISABLED'||!Array.isArray(network.Subnets)||!Array.isArray(network.SecurityGroups)||
    canaryEvidenceHash([...network.Subnets].sort())!==canaryEvidenceHash([...target.subnets].sort())||
    canaryEvidenceHash([...network.SecurityGroups].sort())!==canaryEvidenceHash([target.securityGroup]))fail();
  const original=JSON.parse(template.Target.Input??'{}');
  if(original.containerOverrides?.length!==1||original.containerOverrides[0].name!==target.containerName||
    env(original.containerOverrides[0]).MEM9_WORKER_GENERATION!==target.generation)fail();
  const replay=wave.startsWith('repeat');
  if(!replay&&!/^[a-f0-9]{32}$/.test(admission??''))fail();
  const environment=[{name:'MEM9_WORKER_GENERATION',value:target.generation},{name:'MEM9_WORKER_INVOCATION',value:nonce}];
  if(!replay)environment.push({name:'MEM9_WORKER_ADMISSION',value:admission});
  if(replay){
    if(target.containerName!=='Mem9ConsolidationExecutor'||!Array.isArray(actions)||!actions.length||actions.length>20||
      new Set(actions.map(action=>action.namespace+'/'+action.id)).size!==actions.length)fail();
    for(const action of actions){requireNamespaceId(action.namespace);if(!/^[a-f0-9]{64}$/.test(action.id??'')||action.result?.status!=='applied'||action.result.action_id!==action.id)fail();}
    const value=JSON.stringify(actions);if(Buffer.byteLength(value)>6500)fail();
    environment.push({name:'MEM9_CANARY_INVOCATION',value:nonce},{name:'MEM9_CANARY_ACTIONS',value});
  }
  const input={containerOverrides:[{name:target.containerName,environment,...(replay?{command:['/app/scripts/consolidation-canary-replay.mjs']}:{})}]};
  if(Buffer.byteLength(JSON.stringify(input))>8192)fail();
  const ecs={...template.Target.EcsParameters};delete ecs.Tags;delete ecs.PropagateTags;delete ecs.EnableECSManagedTags;
  return {Name:`m9-prod-canary-${wave}-${nonce.slice(0,16)}`,GroupName:target.groupName,ClientToken:nonce,
    ScheduleExpression:`at(${new Date(when).toISOString().slice(0,19)})`,ScheduleExpressionTimezone:'UTC',
    FlexibleTimeWindow:{Mode:'OFF'},State:'ENABLED',ActionAfterCompletion:'DELETE',Target:{Arn:target.clusterArn,RoleArn:target.roleArn,
      EcsParameters:ecs,RetryPolicy:{MaximumEventAgeInSeconds:60,MaximumRetryAttempts:0},Input:JSON.stringify(input)}};
}

export function ownsCanaryTask(task,journal){
  const prefix=`arn:aws:ecs:${journal.region}:${journal.account}:task/${journal.cluster}/`;
  const overrides=task?.overrides,container=overrides?.containerOverrides?.[0];
  return task?.taskArn?.startsWith(prefix)&&/^[a-f0-9]{32}$/.test(task.taskArn.slice(prefix.length))&&
    task.clusterArn===journal.clusterArn&&task.taskDefinitionArn===journal.taskDefinitionArn&&
    overrides.containerOverrides?.length===1&&container.name===journal.containerName&&!container.environmentFiles?.length&&
    env(container).MEM9_WORKER_INVOCATION===journal.nonce&&
    (!overrides.taskRoleArn||overrides.taskRoleArn===journal.taskRoleArn)&&(!overrides.executionRoleArn||overrides.executionRoleArn===journal.executionRoleArn)&&
    canaryEvidenceHash({containerOverrides:overrides.containerOverrides})===journal.overridesHash;
}

export async function loadProductionCanaryWorker(clients,{region,kind,revision,controlSourceTree}){
  if(!['planner','executor'].includes(kind)||!/^[a-f0-9]{40}$/.test(revision??''))fail();
  const account=(await send(clients.sts,new GetCallerIdentityCommand({}))).Account;
  const name='/mem9-on-aws/prod/consolidation-runtime/manifest',operatorName='/mem9-on-aws/prod/consolidation-runtime/operator-manifest';
  const result=await send(clients.ssm,new GetParametersCommand({Names:[name,operatorName],WithDecryption:true}));
  if(result.InvalidParameters?.length||result.Parameters?.length!==2)fail();
  const parameters=new Map(result.Parameters.map(parameter=>[parameter.Name,JSON.parse(parameter.Value)]));
  const approved=validateProductionWorkerTarget(parameters.get(operatorName),{region,account});
  const dataRelease=await loadWorkerDataRelease(clients,approved,{controlRevision:revision,
    controlSourceTree:approved.version>=2?(controlSourceTree??await productionSourceTree()):undefined});
  const manifest=parameters.get(name),prefix=`arn:aws:ecs:${region}:${account}:cluster/`;
  if(manifest.version!==(approved.version===3?2:1)||manifest.stage!=='prod'||!/^[a-f0-9]{64}$/.test(manifest.generation??'')||
    !manifest.clusterArn?.startsWith(prefix+'mem9-on-aws-prod-')||!/^mem9-on-aws-prod-consolidation-[A-Za-z0-9-]+$/.test(manifest.groupName??'')||
    manifest.roleArn!==`arn:aws:iam::${account}:role/mem9-on-aws-prod-Mem9ConsolidationSchedulerRole-role`||
    !Array.isArray(manifest.workers)||manifest.workers.length!==2||new Set(manifest.workers.map(worker=>worker.kind)).size!==2||
    manifest.clusterArn!==approved.clusterArn||manifest.generation!==approved.generation)fail();
  if(approved.version===3&&(manifest.dataReleaseHash!==approved.dataReleaseHash||manifest.dataReleaseParameterVersion!==approved.dataReleaseParameterVersion)||
    approved.version!==3&&(manifest.dataReleaseHash!==undefined||manifest.dataReleaseParameterVersion!==undefined))fail();
  const worker=manifest.workers.find(worker=>worker.kind===kind),cluster=manifest.clusterArn.slice(prefix.length);
  const containerName=`Mem9Consolidation${kind==='planner'?'Planner':'Executor'}`;
  if(worker?.containerName!==containerName||worker.sourceTag!==approved.sourceTag||worker.image!==approved.workerImage||
    !worker.taskDefinitionArn?.startsWith(`arn:aws:ecs:${region}:${account}:task-definition/${cluster}-${containerName}:`)||
    !/^[1-9][0-9]*$/.test(worker.taskDefinitionArn.split(':').at(-1)))fail();
  const definition=(await send(clients.ecs,new DescribeTaskDefinitionCommand({taskDefinition:worker.taskDefinitionArn}))).taskDefinition;
  const container=definition?.containerDefinitions?.[0],values=env(container),parameter=`arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/prod/`;
  const secrets={MEM9_WORKER_TARGETS:parameter+'maintenance/targets',[kind==='planner'?'MEM9_PLANNER_DB_SECRET':'MEM9_EXECUTOR_DB_SECRET']:parameter+`consolidation-runtime/${kind}-credential`,
    ...(kind==='executor'?{MEM9_TENANT_ID:parameter+'consolidation-runtime/tenant',MEM9_SERVICE_TRANSPORT_SIGNING_KEYS:parameter+'namespace/service-consolidation-signing-keys'}:{})};
  const actual=Object.fromEntries((container?.secrets??[]).map(secret=>[secret.name,secret.valueFrom]));
  if(definition?.taskDefinitionArn!==worker.taskDefinitionArn||definition.containerDefinitions?.length!==1||container.name!==containerName||
    definition.networkMode!=='awsvpc'||definition.runtimePlatform?.cpuArchitecture!=='ARM64'||container.environmentFiles?.length||
    container.entryPoint?.join()!=='node'||container.command?.join()!=='/app/scripts/consolidation-worker.mjs'||
    container.image!==worker.image||
    values.MEM9_STAGE!=='prod'||values.MEM9_WORKER_KIND!==kind||values.MEM9_WORKER_GENERATION!==manifest.generation||
    values.MEM9_DB_HOST!==approved.host||values.MEM9_DB_NAME!==approved.database||values.MEM9_DB_PORT!==String(approved.port)||
    values.MEM9_BASE_URL!=='http://mnemo.mem9-prod.local:8080'||
    canaryEvidenceHash(actual)!==canaryEvidenceHash(secrets)||container.secrets.length!==Object.keys(secrets).length)fail();
  const meta={...manifest,region,account,cluster,kind,revision,controlSourceTag:approved.controlSourceTag??approved.sourceTag,dataRelease,
    image:worker.image,sourceTag:worker.sourceTag,containerName,taskDefinitionArn:worker.taskDefinitionArn,subnets:approved.subnets,securityGroup:approved.securityGroup,
    taskRoleArn:definition.taskRoleArn,executionRoleArn:definition.executionRoleArn};
  await verifyProductionTaskRoles(clients,meta,definition,containerName,secrets,'WorkerParameters');
  const template=await send(clients.scheduler,new GetScheduleCommand({Name:worker.scheduleName,GroupName:manifest.groupName}));
  return {...meta,template,logOptions:container.logConfiguration?.options};
}

async function matchingTasks(clients,target,journal){
  return discoverSchedulerTasks(clients.ecs,target.clusterArn,task=>ownsCanaryTask(task,journal));
}

export async function quiesceProductionWorkers(clients,targets,{now=Date.now,sleep=delay}={}){
  if(!targets.length||targets.some(target=>target.clusterArn!==targets[0].clusterArn))fail();
  const families=new Set(targets.map(target=>target.taskDefinitionArn.replace(/:[1-9][0-9]*$/,'')));
  const clusterArn=targets[0].clusterArn,until=now()+180000;let quiet=0;
  while(now()<until){
    const tasks=await discoverSchedulerTasks(clients.ecs,clusterArn,task=>/:[1-9][0-9]*$/.test(task.taskDefinitionArn??'')&&
      families.has(task.taskDefinitionArn.replace(/:[1-9][0-9]*$/,'')),{sleep,now});
    const active=tasks.filter(task=>task.lastStatus!=='STOPPED');
    for(const task of active)await send(clients.ecs,new StopTaskCommand({cluster:clusterArn,task:task.taskArn,reason:'Pause production canary workers before verification'}));
    quiet=active.length?0:quiet+1;if(quiet>=3)return;await sleep(5000);
  }
  fail();
}

/** Call only after database execution and dispatch have been paused. */
export async function recoverProductionCanaryDeliveries(clients,targets,{now=Date.now,sleep=delay}={}){
  const path='/mem9-on-aws/prod/consolidation-runtime/canary-deliveries/',pending=[];let NextToken;
  for(let page=0;page<100;page++){
    const response=await send(clients.ssm,new GetParametersByPathCommand({Path:path,Recursive:false,WithDecryption:true,MaxResults:10,NextToken}));
    for(const parameter of response.Parameters??[]){
      const journal=JSON.parse(parameter.Value),target=targets.find(target=>target.containerName===journal.containerName);
      if(!target||journal.version!==1||journal.stage!=='prod'||journal.region!==target.region||journal.account!==target.account||
        journal.cluster!==target.cluster||journal.clusterArn!==target.clusterArn||journal.groupName!==target.groupName||
        !/^[a-f0-9]{32}$/.test(journal.nonce??'')||parameter.Name!==path+journal.nonce||
        !['plan','apply','repeat-a','repeat-b'].includes(journal.wave)||journal.name!==`m9-prod-canary-${journal.wave}-${journal.nonce.slice(0,16)}`||
        !/^[a-f0-9]{64}$/.test(journal.generation??'')||!/^[a-f0-9]{64}$/.test(journal.overridesHash??'')||!/^[a-f0-9]{64}$/.test(journal.targetHash??'')||
        !Number.isSafeInteger(journal.when)||!Number.isSafeInteger(journal.deadline)||journal.deadline<journal.when||journal.deadline>now()+20*60000||
        !journal.taskDefinitionArn?.startsWith(`arn:aws:ecs:${target.region}:${target.account}:task-definition/${target.cluster}-${target.containerName}:`))fail();
      pending.push({journal,target,path:parameter.Name});
    }
    if(!response.NextToken)break;if(response.NextToken===NextToken||page===99)fail();NextToken=response.NextToken;
  }
  for(const item of pending){
    const {journal,target}=item;
    try{
      const current=await send(clients.scheduler,new GetScheduleCommand({Name:journal.name,GroupName:journal.groupName}));
      if(canaryEvidenceHash(current.Target)!==journal.targetHash)fail();
      await send(clients.scheduler,new DeleteScheduleCommand({Name:journal.name,GroupName:journal.groupName}));
    }catch(error){if(error.name!=='ResourceNotFoundException')throw error;}
    const until=Math.max(now()+60000,journal.deadline+60000);let quiet=0;
    while(now()<until){
      const tasks=await matchingTasks(clients,target,journal);
      for(const task of tasks)if(task.lastStatus!=='STOPPED')await send(clients.ecs,new StopTaskCommand({cluster:target.clusterArn,task:task.taskArn,reason:'Reconcile prior production canary delivery'}));
      if(tasks.every(task=>task.lastStatus==='STOPPED')&&now()>=journal.when+120000)quiet++;else quiet=0;
      if(quiet>=3)break;await sleep(5000);
    }
    if(quiet<3)fail();
    await send(clients.ssm,new DeleteParameterCommand({Name:item.path}));
  }
  return {reconciled:pending.length};
}

export async function runProductionCanaryWake(clients,target,{wave,actions,onIntent=async()=>{},admission,onRunning=async()=>{}},{now=Date.now,sleep=delay,signal}={}){
  signal?.throwIfAborted();
  const nonce=randomUUID().replaceAll('-',''),when=now()+60000,deadline=when+(target.kind==='planner'?18:8)*60000;
  const request=productionCanarySchedule(target.template,target,{wave,nonce,when,actions,admission});
  const journal={version:1,stage:'prod',region:target.region,account:target.account,cluster:target.cluster,clusterArn:target.clusterArn,
    generation:target.generation,nonce,wave,when,deadline,groupName:request.GroupName,name:request.Name,
    taskDefinitionArn:target.taskDefinitionArn,containerName:target.containerName,taskRoleArn:target.taskRoleArn,executionRoleArn:target.executionRoleArn,
    overridesHash:canaryEvidenceHash(JSON.parse(request.Target.Input)),targetHash:canaryEvidenceHash(request.Target)};
  const journalPath='/mem9-on-aws/prod/consolidation-runtime/canary-deliveries/'+nonce;
  await onIntent(structuredClone(journal));signal?.throwIfAborted();if(now()>=when)fail();
  const dispatch={kind:'wake',operation:wave,target:maintenanceWorkerTarget(target)};
  await sendMaintenanceCommand(clients,'ssm',new PutParameterCommand({Name:journalPath,Type:'SecureString',Value:JSON.stringify(journal),Overwrite:false}),dispatch,{...(signal?{abortSignal:signal}:{})});
  signal?.throwIfAborted();if(now()>=when)fail();
  await sendMaintenanceCommand(clients,'scheduler',new CreateScheduleCommand(request),dispatch,{...(signal?{abortSignal:signal}:{})});
  let terminal,started=false;
  while(now()<deadline){
    signal?.throwIfAborted();
    const matches=await matchingTasks(clients,target,journal);if(matches.length>1)fail();
    if(matches.length){
      const task=matches[0];
      if(!started&&task.lastStatus==='RUNNING'){started=true;await onRunning({taskArn:task.taskArn,startedMs:new Date(task.startedAt).getTime()});}
      if(task.lastStatus==='STOPPED'){terminal=task;break;}
    }
    await sleep(5000);
  }
  if(!terminal){for(const task of await matchingTasks(clients,target,journal))if(task.lastStatus!=='STOPPED')await send(clients.ecs,new StopTaskCommand({cluster:target.clusterArn,task:task.taskArn,reason:'Bounded production canary delivery'}));fail();}
  if(terminal.containers?.length!==1||terminal.containers[0].exitCode!==0)fail();
  if(!/^sha256:[a-f0-9]{64}$/.test(terminal.containers[0].imageDigest??''))fail();
  const log=target.logOptions;if(!log?.['awslogs-group']||!log['awslogs-stream-prefix'])fail();
  const event=wave.startsWith('repeat')?'consolidation_canary_replay':'consolidation_worker';let record;
  for(let attempt=0;attempt<12&&!record;attempt++){
    signal?.throwIfAborted();
    const records=[],seen=new Set();let nextToken;
    for(let page=0;page<30;page++){
      const response=await send(clients.logs,new FilterLogEventsCommand({logGroupName:log['awslogs-group'],
        logStreamNames:[log['awslogs-stream-prefix']+'/'+target.containerName+'/'+terminal.taskArn.split('/').at(-1)],nextToken}));
      for(const row of response.events??[]){
        if(row.eventId&&seen.has(row.eventId))continue;if(row.eventId)seen.add(row.eventId);
        try{const value=JSON.parse(row.message);if(value.event===event)records.push(value);}catch{}
      }
      if(!response.nextToken||response.nextToken===nextToken)break;if(page===29)fail();nextToken=response.nextToken;
    }
    if(records.length>1)fail();record=records[0];if(!record)await sleep(5000);
  }
  if(record?.invocation!==nonce||!Number.isSafeInteger(record.startedMs)||!Number.isSafeInteger(record.finishedMs)||record.finishedMs<record.startedMs)fail();
  if(wave.startsWith('repeat')){
    if(record.matched!==actions.length||record.resultHash!==canaryEvidenceHash(actions.map(action=>[action.namespace,action.id,action.result])))fail();
  }else if(record.stage!=='prod'||record.kind!==target.kind||record.failedSlices||!['complete','deadline'].includes(record.outcome))fail();
  try{
    const current=await send(clients.scheduler,new GetScheduleCommand({Name:request.Name,GroupName:request.GroupName}));
    if(canaryEvidenceHash(current.Target)!==journal.targetHash)fail();
    await send(clients.scheduler,new DeleteScheduleCommand({Name:request.Name,GroupName:request.GroupName}));
  }catch(error){if(error.name!=='ResourceNotFoundException')throw error;}
  await send(clients.ssm,new DeleteParameterCommand({Name:journalPath}));
  return {wave,kind:target.kind,invocation:nonce,taskArn:terminal.taskArn,taskDefinitionArn:target.taskDefinitionArn,
    startedMs:record.startedMs,stoppedMs:record.finishedMs,exitCode:0,image:target.image,imageDigest:terminal.containers[0].imageDigest,record};
}
