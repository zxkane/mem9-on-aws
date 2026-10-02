import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {setTimeout as delay} from 'node:timers/promises';
import {ListTasksCommand,DescribeTasksCommand,DescribeTaskDefinitionCommand} from '@aws-sdk/client-ecs';
import {GetRoleCommand} from '@aws-sdk/client-iam';
import {FilterLogEventsCommand} from '@aws-sdk/client-cloudwatch-logs';
import {ListSchedulesCommand} from '@aws-sdk/client-scheduler';
import {verifyProductionRecurringDelivery,verifyProductionSchedulerIdentity} from './production-recurring-verification.mjs';
import {verifyProductionScheduling} from './production-scheduling.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';

const execute=promisify(execFile),fail=code=>{throw Error(code);};
const send=(client,command,deadline)=>client.send(command,{abortSignal:AbortSignal.timeout(Math.max(1,Math.min(30000,deadline-Date.now())))});

export async function readRecurringLaunchEvents({region,startMs,endMs,profile=process.env.AWS_PROFILE,deadlineMs=endMs+60000}){
  if(!/^[a-z0-9-]+$/.test(region??'')||!Number.isSafeInteger(startMs)||startMs<1||!Number.isSafeInteger(endMs)||endMs<startMs||endMs-startMs>3600000)fail('RecurringEventWindowInvalid');
  const events=[],tokens=new Set();let token;
  for(let page=0;page<100;page++){
    if(Date.now()>=deadlineMs)fail('RecurringObservationDeadline');
    const args=['cloudtrail','lookup-events','--region',region,'--lookup-attributes','AttributeKey=EventName,AttributeValue=RunTask',
      '--start-time',new Date(startMs).toISOString(),'--end-time',new Date(endMs).toISOString(),'--max-results','50','--no-paginate','--output','json',
      ...(profile?['--profile',profile]:[]),...(token?['--next-token',token]:[])];
    let response;try{response=JSON.parse((await execute('aws',args,{timeout:Math.max(1,Math.min(30000,deadlineMs-Date.now())),maxBuffer:8*1024*1024})).stdout);}catch{fail('RecurringEventReadFailed');}
    if(!Array.isArray(response.Events)||response.Events.length>50)fail('RecurringEventInventoryInvalid');
    for(const row of response.Events){
      if(typeof row.CloudTrailEvent!=='string'||Buffer.byteLength(row.CloudTrailEvent)>1048576)fail('RecurringEventInventoryInvalid');
      const event=JSON.parse(row.CloudTrailEvent);if(event.eventID!==row.EventId||event.eventName!=='RunTask')fail('RecurringEventInventoryInvalid');events.push(event);
    }
    if(!response.NextToken)return events;
    if(tokens.has(response.NextToken))fail('RecurringEventInventoryInvalid');tokens.add(response.NextToken);token=response.NextToken;
    await delay(550);
  }
  fail('RecurringEventInventoryIncomplete');
}

export async function observeProductionRecurringDeliveries(clients,targets,{admission,artifacts,afterMs,deadlineMs,guard,persist=async()=>{},
  now=Date.now,sleep=delay,readEvents=readRecurringLaunchEvents}={}){
  if(!Array.isArray(targets)||targets.length!==2||targets.map(t=>t.kind).sort().join()!=='executor,planner'||
    targets[0].clusterArn!==targets[1].clusterArn||targets[0].groupName!==targets[1].groupName||targets[0].roleArn!==targets[1].roleArn||
    targets[0].generation!==targets[1].generation||!/^[a-f0-9]{64}$/.test(admission??'')||typeof guard!=='function'||
    !Number.isSafeInteger(afterMs)||afterMs<1||afterMs>now()||!Number.isSafeInteger(deadlineMs)||deadlineMs<=now()||deadlineMs>afterMs+2700000)fail('RecurringObservationConfigurationInvalid');
  const roleName=targets[0].roleArn.split('/').at(-1),definitions={},proofs={},events=new Map();
  await guard();await verifyProductionScheduling(clients,targets,{enabled:true,admission});
  const role=(await send(clients.iam,new GetRoleCommand({RoleName:roleName}),deadlineMs)).Role;
  const identity=verifyProductionSchedulerIdentity(role,targets[0]);
  for(const target of targets){
    definitions[target.kind]=(await send(clients.ecs,new DescribeTaskDefinitionCommand({taskDefinition:target.taskDefinitionArn}),deadlineMs)).taskDefinition;
    if(!artifacts?.[target.kind])fail('RecurringArtifactEvidenceMissing');
    const log=definitions[target.kind]?.containerDefinitions?.[0]?.logConfiguration;
    if(log?.logDriver!=='awslogs'||log.options?.['awslogs-region']!==target.region||
      log.options?.['awslogs-group']!==target.logOptions?.['awslogs-group']||log.options?.['awslogs-stream-prefix']!==target.logOptions?.['awslogs-stream-prefix'])fail('RecurringLogMetadataMissing');
  }
  const inventory=async()=>{
    const result=[],seen=new Set();let token;
    for(let page=0;page<100;page++){
      const r=await send(clients.scheduler,new ListSchedulesCommand({GroupName:targets[0].groupName,MaxResults:100,NextToken:token}),deadlineMs);
      result.push(...(r.Schedules??[]));if(!r.NextToken)break;
      if(seen.has(r.NextToken)||page===99)fail('RecurringScheduleInventoryIncomplete');seen.add(r.NextToken);token=r.NextToken;
    }
    if(result.length!==2||result.some(s=>s.State!=='ENABLED')||hash(result.map(s=>s.Name).sort())!==hash(targets.map(t=>t.template.Name).sort()))fail('UnexpectedProductionSchedule');
  };
  while(now()<deadlineMs){
    await guard();await inventory();let waitingForEvent=false;
    for(const target of targets){
      if(proofs[target.kind])continue;
      const ids=new Set(),tokens=new Set();let token;
      for(let page=0;page<100;page++){
        const response=await send(clients.ecs,new ListTasksCommand({cluster:target.clusterArn,family:target.taskDefinitionArn.split('/').at(-1).replace(/:[0-9]+$/,''),
          desiredStatus:'STOPPED',maxResults:100,nextToken:token}),deadlineMs);
        for(const arn of response.taskArns??[])ids.add(arn);
        if(!response.nextToken)break;if(tokens.has(response.nextToken)||page===99)fail('RecurringTaskInventoryIncomplete');tokens.add(response.nextToken);token=response.nextToken;
      }
      const arns=[...ids];
      for(let offset=0;offset<arns.length;offset+=100){
        const requested=arns.slice(offset,offset+100),r=await send(clients.ecs,new DescribeTasksCommand({cluster:target.clusterArn,tasks:requested}),deadlineMs);
        if(r.failures?.length||!Array.isArray(r.tasks)||hash(r.tasks.map(t=>t.taskArn).sort())!==hash([...requested].sort()))fail('RecurringTaskCoverageIncomplete');
        for(const task of r.tasks){
          if(task.taskDefinitionArn!==target.taskDefinitionArn||new Date(task.startedAt).getTime()<afterMs)continue;
          if(task.clusterArn!==target.clusterArn||task.lastStatus!=='STOPPED'||task.containers?.length!==1||task.containers[0].exitCode!==0)fail('ProductionRecurringTaskFailed');
          const options=target.logOptions,group=options?.['awslogs-group'],prefix=options?.['awslogs-stream-prefix'];
          if(!group||!prefix)fail('RecurringLogMetadataMissing');
          const records=[],logIds=new Set(),logTokens=new Set();let nextToken;
          for(let page=0;page<100;page++){
            const logs=await send(clients.logs,new FilterLogEventsCommand({logGroupName:group,logStreamNames:[prefix+'/'+target.containerName+'/'+task.taskArn.split('/').at(-1)],nextToken}),deadlineMs);
            for(const row of logs.events??[]){
              if(row.eventId&&logIds.has(row.eventId))continue;if(row.eventId)logIds.add(row.eventId);
              let record;try{record=JSON.parse(row.message);}catch{continue;}if(record.event==='consolidation_worker')records.push(record);
            }
            if(!logs.nextToken||logs.nextToken===nextToken)break;
            if(logTokens.has(logs.nextToken)||page===99)fail('RecurringLogInventoryIncomplete');logTokens.add(logs.nextToken);nextToken=logs.nextToken;
          }
          if(records.length>1)fail('RecurringWorkerReportAmbiguous');if(!records.length)continue;
          const launches=events.get(task.taskArn);if(!launches?.size){waitingForEvent=true;continue;}
          // SDK retries may return the same idempotent task in several genuine
          // RunTask events. Use its earliest authenticated successful launch.
          let proof;
          for(const event of [...launches.values()].sort((a,b)=>Date.parse(a.eventTime)-Date.parse(b.eventTime))){
            try{proof=verifyProductionRecurringDelivery({task,definition:definitions[target.kind],record:records[0],event,role},target,
              {admission,artifact:artifacts[target.kind],afterMs,now:now()});break;}catch{}
          }
          if(!proof)fail('ProductionRecurringDeliveryUnverified');proofs[target.kind]=proof;
          await persist({version:1,phase:'observing-recurring',admission,generation:target.generation,...proofs});
        }
      }
    }
    if(proofs.planner&&proofs.executor){
      await guard();await inventory();await verifyProductionScheduling(clients,targets,{enabled:true,admission});
      const latest=(await send(clients.iam,new GetRoleCommand({RoleName:roleName}),deadlineMs)).Role;
      if(hash(verifyProductionSchedulerIdentity(latest,targets[0]))!==hash(identity))fail('RecurringSchedulerIdentityChanged');
      return {version:1,admission,generation:targets[0].generation,...proofs,verifiedMs:now()};
    }
    if(waitingForEvent){
      for(const event of await readEvents({region:targets[0].region,startMs:Math.max(1,afterMs-5000),endMs:now(),deadlineMs})){
        if(event.userIdentity?.sessionContext?.sessionIssuer?.arn!==targets[0].roleArn)continue;
        for(const task of event.responseElements?.tasks??[]){
          if(task.clusterArn!==targets[0].clusterArn||!targets.some(t=>t.taskDefinitionArn===task.taskDefinitionArn))continue;
          if(!events.has(task.taskArn))events.set(task.taskArn,new Map());
          const launches=events.get(task.taskArn),prior=launches.get(event.eventID);
          if(prior&&hash(prior)!==hash(event)||launches.size>=20)fail('RecurringLaunchAmbiguous');launches.set(event.eventID,event);
        }
      }
    }
    await sleep(Math.min(10000,Math.max(1,deadlineMs-now())));
  }
  fail('RecurringObservationDeadline');
}
