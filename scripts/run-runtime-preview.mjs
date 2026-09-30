import {randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {pathToFileURL} from 'node:url';
import {SSMClient,GetParametersCommand,GetParametersByPathCommand,PutParameterCommand,DeleteParameterCommand} from '@aws-sdk/client-ssm';
import {ECSClient,DescribeTaskDefinitionCommand,DescribeServicesCommand,ListTasksCommand,DescribeTasksCommand,StopTaskCommand,RunTaskCommand} from '@aws-sdk/client-ecs';
import {CloudWatchLogsClient,FilterLogEventsCommand} from '@aws-sdk/client-cloudwatch-logs';
import {IAMClient} from '@aws-sdk/client-iam';
import {runtimeServerContract,verifyRuntimeRoles} from './lib/runtime-live-verification.mjs';
import {runtimeStage} from './lib/runtime-credentials.mjs';
import {resolveApplicationRegion} from './lib/application-region.mjs';

const fail=message=>{throw Error(message);};
const emit=phase=>process.stdout.write(JSON.stringify({event:'runtime_preview',phase})+'\n');
const environment=container=>Object.fromEntries((container?.environment??[]).map(e=>[e.name,e.value]));

export function validateRuntimeMetadata(meta,stage,region){
  if(!runtimeStage(stage)||!new RegExp(`^mem9-on-aws-${stage}-[A-Za-z0-9-]+$`).test(meta.cluster??''))fail('InvalidRuntimeMetadata');
  const arn=meta.taskDefinition?.match(/^arn:aws:ecs:([a-z0-9-]+):([0-9]{12}):task-definition\/(.+):([1-9][0-9]*)$/);
  if(!arn||arn[1]!==region||arn[3]!==meta.cluster+'-Mem9Bootstrap'||meta.service!=='Mem9Server'||
    !/^sg-[a-f0-9]+$/.test(meta.securityGroup??'')||!Array.isArray(meta.subnets)||!meta.subnets.length||meta.subnets.length>16||
    meta.subnets.some(s=>!/^subnet-[a-f0-9]+$/.test(s)))fail('InvalidRuntimeMetadata');
  return {...meta,stage,region,account:arn[2],family:arn[3],clusterArn:`arn:aws:ecs:${region}:${arn[2]}:cluster/${meta.cluster}`};
}

export function validateRuntimeJournal(journal,meta,path,now=Date.now()){
  if(journal?.version!==1||journal.stage!==meta.stage||!/^[a-f0-9]{32}$/.test(journal.nonce??'')||
    !['bootstrap','verify'].includes(journal.operation)||!Number.isSafeInteger(journal.deadline)||!Number.isSafeInteger(journal.createdAt)||
    journal.createdAt>now+30000||journal.deadline!==journal.createdAt+900000||
    path!==`/mem9-on-aws/${meta.stage}/runtime/invocations/${journal.nonce}`||
    !journal.taskDefinition?.startsWith(`arn:aws:ecs:${meta.region}:${meta.account}:task-definition/${meta.family}:`)||
    !/:[1-9][0-9]*$/.test(journal.taskDefinition))fail('InvalidRuntimeJournal');
  return journal;
}

export function ownsRuntimeTask(task,meta,journal){
  const env=environment(task.overrides?.containerOverrides?.find(c=>c.name==='Mem9Bootstrap'));
  return task.clusterArn===meta.clusterArn&&task.taskDefinitionArn===journal.taskDefinition&&
    task.taskArn?.startsWith(`arn:aws:ecs:${meta.region}:${meta.account}:task/${meta.cluster}/`)&&
    env.MEM9_RUNTIME_INVOCATION===journal.nonce&&env.MEM9_RUNTIME_BOOTSTRAP_DEADLINE===String(journal.deadline)&&
    env.MEM9_BOOTSTRAP_OPERATION===`runtime-${journal.operation}`;
}

export async function runRuntimePreview({clients,stage,region,operation,now=Date.now,sleep=delay,progress=emit}){
  if(!runtimeStage(stage)||!['drain','bootstrap','verify','cancel'].includes(operation))fail('InvalidRuntimeOperation');
  const {ssm,ecs,logs}=clients;
  const send=(client,command)=>client.send(command,{abortSignal:AbortSignal.timeout(30000)});
  const prefix=`/mem9-on-aws/${stage}`;
  const names=['bootstrap/cluster-name','bootstrap/task-def-arn','bootstrap/task-sg-id','bootstrap/subnet-ids','ecs/service-name','ecs/task-definition'].map(k=>prefix+'/'+k);
  const response=await send(ssm,new GetParametersCommand({Names:names,WithDecryption:false}));
  if(response.InvalidParameters?.length||response.Parameters?.length!==names.length)fail('RuntimeMetadataMissing');
  const values=new Map(response.Parameters.map(p=>[p.Name,p.Value]));
  const meta=validateRuntimeMetadata({cluster:values.get(names[0]),taskDefinition:values.get(names[1]),securityGroup:values.get(names[2]),
    subnets:values.get(names[3])?.split(','),service:values.get(names[4]),serverTaskDefinition:values.get(names[5])},stage,region);

  const list=async filter=>{
    const arns=new Set();
    // RUNNING is desired status: it includes lastStatus=PENDING. STOPPED also
    // includes tasks still shutting down, which must be observed until terminal.
    for(const desiredStatus of ['RUNNING','STOPPED']){
      let nextToken;
      for(let page=0;page<100;page++){
        const r=await send(ecs,new ListTasksCommand({cluster:meta.clusterArn,...filter,desiredStatus,maxResults:100,nextToken}));
        for(const arn of r.taskArns??[])arns.add(arn);
        if(!r.nextToken)break;
        if(r.nextToken===nextToken||page===99)fail('RuntimeTaskInventoryIncomplete');nextToken=r.nextToken;
      }
    }
    const tasks=[];const all=[...arns];
    for(let offset=0;offset<all.length;offset+=100){
      const r=await send(ecs,new DescribeTasksCommand({cluster:meta.clusterArn,tasks:all.slice(offset,offset+100)}));
      if(r.failures?.length||r.tasks?.length!==Math.min(100,all.length-offset))fail('RuntimeTaskObservationFailed');
      tasks.push(...r.tasks);
    }
    return tasks;
  };
  const stop=async task=>{
    if(task.clusterArn!==meta.clusterArn||!task.taskArn?.startsWith(`arn:aws:ecs:${region}:${meta.account}:task/${meta.cluster}/`))fail('RuntimeTaskOwnershipMismatch');
    if(task.lastStatus!=='STOPPED')await send(ecs,new StopTaskCommand({cluster:meta.clusterArn,task:task.taskArn,reason:'Preview runtime credential preparation'}));
  };
  const journals=async()=>{
    const result=[];let NextToken;
    for(let page=0;page<100;page++){
      const r=await send(ssm,new GetParametersByPathCommand({Path:prefix+'/runtime/invocations/',Recursive:false,WithDecryption:false,NextToken,MaxResults:10}));
      for(const p of r.Parameters??[])result.push({path:p.Name,journal:validateRuntimeJournal(JSON.parse(p.Value),meta,p.Name,now())});
      if(!r.NextToken)break;
      if(NextToken===r.NextToken||page===99)fail('RuntimeJournalInventoryIncomplete');NextToken=r.NextToken;
    }
    return result;
  };
  const cancel=async()=>{
    const pending=await journals();
    for(const {path,journal} of pending){
      const until=Math.max(now()+90000,journal.deadline+90000);
      let complete=false;
      while(now()<until){
        const tasks=(await list({family:meta.family})).filter(t=>ownsRuntimeTask(t,meta,journal));
        for(const task of tasks)await stop(task);
        if(tasks.length&&tasks.every(t=>t.lastStatus==='STOPPED')){complete=true;break;}
        // An ambiguous RunTask may appear late. Do not discard its durable
        // record until its in-container deadline plus observation grace elapsed.
        if(!tasks.length&&now()>=journal.deadline+60000){complete=true;break;}
        await sleep(5000);
      }
      if(!complete)fail('RuntimeCancellationIncomplete');
      await send(ssm,new DeleteParameterCommand({Name:path}));
    }
  };
  if(operation==='cancel'){await cancel();progress('cancelled');return;}
  if(operation==='drain'){
    await cancel();
    const deadline=now()+600000;let empty=0;
    while(now()<deadline){
      const r=await send(ecs,new DescribeServicesCommand({cluster:meta.clusterArn,services:[meta.service]}));
      if(r.failures?.length||r.services?.length!==1||r.services[0].desiredCount!==0)fail('RuntimeServiceNotStopped');
      const serviceTasks=await list({serviceName:meta.service});
      const bootTasks=await list({family:meta.family});
      for(const task of bootTasks){
        if(task.taskDefinitionArn?.split(':').slice(0,-1).join(':')!==meta.taskDefinition.split(':').slice(0,-1).join(':'))fail('RuntimeBootstrapFamilyMismatch');
        await stop(task);
      }
      if(![...serviceTasks,...bootTasks].some(t=>t.lastStatus!=='STOPPED')&&r.services[0].runningCount===0&&r.services[0].pendingCount===0)empty++;else empty=0;
      if(empty>=3){progress('drained');return;}
      await sleep(5000);
    }
    fail('RuntimeDrainDeadline');
  }
  const def=(await send(ecs,new DescribeTaskDefinitionCommand({taskDefinition:meta.taskDefinition}))).taskDefinition;
  const container=def?.containerDefinitions?.find(c=>c.name==='Mem9Bootstrap'),env=environment(container);
  if(def?.family!==meta.family||env.MEM9_RUNTIME_BOOTSTRAP_VERSION!=='1'||env.MEM9_STAGE!==stage||
    container?.secrets?.find(s=>s.name==='MEM9_RUNTIME_DB_SECRET')?.valueFrom!==`arn:aws:ssm:${region}:${meta.account}:parameter${prefix}/runtime/database-credential`)fail('RuntimeBootstrapRevisionMismatch');
  if(operation==='bootstrap'){
    const r=await send(ecs,new DescribeServicesCommand({cluster:meta.clusterArn,services:[meta.service]}));
    if(r.failures?.length||r.services?.length!==1||r.services[0].desiredCount!==0||r.services[0].runningCount||r.services[0].pendingCount)fail('RuntimeServiceNotStopped');
    if((await list({family:meta.family})).some(t=>t.lastStatus!=='STOPPED'))fail('RuntimeBootstrapStillRunning');
  }
  const verifyLiveServer=async()=>{
    const r=await send(ecs,new DescribeServicesCommand({cluster:meta.clusterArn,services:[meta.service]})),service=r.services?.[0];
    if(r.failures?.length||r.services?.length!==1||service.desiredCount!==1||service.runningCount!==1||service.pendingCount!==0||
      service.taskDefinition!==meta.serverTaskDefinition||service.deployments?.length!==1||service.deployments[0].rolloutState!=='COMPLETED')fail('RuntimeServerNotStable');
    const tasks=(await list({serviceName:meta.service})).filter(t=>t.lastStatus!=='STOPPED');
    if(tasks.length!==1||tasks.some(t=>t.lastStatus!=='RUNNING'||t.taskDefinitionArn!==meta.serverTaskDefinition))fail('RuntimeServerRevisionMismatch');
    const definition=(await send(ecs,new DescribeTaskDefinitionCommand({taskDefinition:meta.serverTaskDefinition}))).taskDefinition;
    const contract=runtimeServerContract(definition,meta,container.secrets?.find(s=>s.name==='MEM9_TENANT_ID')?.valueFrom);
    for(const task of tasks){
      if(task.overrides?.containerOverrides?.some(c=>c.environment?.length||c.environmentFiles?.length||c.command?.length)||
        ['taskRoleArn','executionRoleArn'].some(k=>task.overrides?.[k]&&task.overrides[k]!==definition[k]))fail('RuntimeServerOverrideMismatch');
    }
    await verifyRuntimeRoles({iam:clients.iam,definition,meta,contract});
  };
  if(operation==='verify')await verifyLiveServer();
  const createdAt=now(),nonce=randomUUID().replaceAll('-','');
  const journal={version:1,stage,operation,nonce,createdAt,deadline:createdAt+900000,taskDefinition:meta.taskDefinition};
  const path=prefix+'/runtime/invocations/'+nonce;
  // Persist before invoking ECS. No credential value is retrieved by the runner.
  await send(ssm,new PutParameterCommand({Name:path,Type:'String',Value:JSON.stringify(journal),Overwrite:false}));
  try{
    const r=await send(ecs,new RunTaskCommand({cluster:meta.clusterArn,taskDefinition:meta.taskDefinition,launchType:'FARGATE',count:1,clientToken:nonce,
      propagateTags:'TASK_DEFINITION',enableECSManagedTags:true,
      networkConfiguration:{awsvpcConfiguration:{subnets:meta.subnets,securityGroups:[meta.securityGroup],assignPublicIp:'DISABLED'}},
      overrides:{containerOverrides:[{name:'Mem9Bootstrap',environment:[{name:'MEM9_BOOTSTRAP_OPERATION',value:'runtime-'+operation},
        {name:'MEM9_RUNTIME_INVOCATION',value:nonce},{name:'MEM9_RUNTIME_BOOTSTRAP_DEADLINE',value:String(journal.deadline)}]}]}}));
    if(r.failures?.length||r.tasks?.length!==1)fail('RuntimeLaunchFailed');
    let stopped;
    while(now()<journal.deadline+60000){
      const status=await send(ecs,new DescribeTasksCommand({cluster:meta.clusterArn,tasks:[r.tasks[0].taskArn]}));
      const task=status.tasks?.[0];
      if(task&&!ownsRuntimeTask(task,meta,journal))fail('RuntimeTaskOwnershipMismatch');
      if(task?.lastStatus==='STOPPED'){stopped=task;break;}
      await sleep(5000);
    }
    if(!stopped)fail('RuntimeInvocationDeadline');
    const cfg=container.logConfiguration?.options;
    if(!cfg?.['awslogs-group']||!cfg['awslogs-stream-prefix'])fail('RuntimeLogConfigurationMissing');
    const event=operation==='verify'?'runtime_verify':'runtime_bootstrap';
    let terminal=[];
    for(let attempt=0;attempt<12&&!terminal.length;attempt++){
      let nextToken;const observed=new Set();
      for(let page=0;page<20;page++){
        const r=await send(logs,new FilterLogEventsCommand({logGroupName:cfg['awslogs-group'],nextToken,
          logStreamNames:[cfg['awslogs-stream-prefix']+'/Mem9Bootstrap/'+stopped.taskArn.split('/').at(-1)],limit:1000}));
        for(const row of r.events??[]){
          if(row.eventId&&observed.has(row.eventId))continue;
          observed.add(row.eventId);
          try{const value=JSON.parse(row.message);if([event,'runtime_bootstrap_failed'].includes(value.event))terminal.push(value);}catch{/* structural events only */}
        }
        if(!r.nextToken||r.nextToken===nextToken)break;
        if(page===19)fail('RuntimeLogCoverageIncomplete');nextToken=r.nextToken;
      }
      if(!terminal.length)await sleep(5000);
    }
    if(stopped.containers?.find(c=>c.name==='Mem9Bootstrap')?.exitCode!==0||terminal.length!==1||terminal[0].event!==event||terminal[0].outcome!=='ready'){
      const error=terminal.find(v=>v.event==='runtime_bootstrap_failed')?.errorClass;
      fail(/^[A-Z][A-Za-z]{1,70}$/.test(error??'')?error:'RuntimeInvocationFailed');
    }
    if(operation==='verify')await verifyLiveServer();
    await send(ssm,new DeleteParameterCommand({Name:path}));progress(operation+'-ready');
  }catch(error){
    try{await cancel();}catch{progress('cancellation-pending');}
    throw error;
  }
}

async function main(){
  const region=process.env.AWS_REGION||await resolveApplicationRegion(),stage=process.env.STAGE;
  const clients={ssm:new SSMClient({region,maxAttempts:3}),ecs:new ECSClient({region,maxAttempts:3}),logs:new CloudWatchLogsClient({region,maxAttempts:3}),iam:new IAMClient({region,maxAttempts:3})};
  try{await runRuntimePreview({clients,region,stage,operation:process.argv[2]});}
  finally{for(const client of Object.values(clients))client.destroy();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(error=>{
  process.stdout.write(JSON.stringify({event:'runtime_preview_failed',errorClass:/^[A-Z][A-Za-z]{1,70}$/.test(error.message)?error.message:'RuntimePreviewError'})+'\n');process.exitCode=1;
});
