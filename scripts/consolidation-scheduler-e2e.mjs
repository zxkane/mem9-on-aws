import {randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {pathToFileURL} from 'node:url';
import {SSMClient,GetParametersCommand,GetParametersByPathCommand,PutParameterCommand,DeleteParameterCommand} from '@aws-sdk/client-ssm';
import {ECSClient,DescribeTaskDefinitionCommand,RunTaskCommand,ListTasksCommand,DescribeTasksCommand,StopTaskCommand,TagResourceCommand} from '@aws-sdk/client-ecs';
import {SchedulerClient,GetScheduleCommand,CreateScheduleCommand,DeleteScheduleCommand} from '@aws-sdk/client-scheduler';
import {CloudWatchLogsClient,FilterLogEventsCommand} from '@aws-sdk/client-cloudwatch-logs';
import {RDSClient,DescribeDBClustersCommand,DescribeDBInstancesCommand,ListTagsForResourceCommand,DescribeDBLogFilesCommand,DownloadDBLogFilePortionCommand} from '@aws-sdk/client-rds';
import {previewGeneration,isConsolidationPreview} from './lib/consolidation-preview-config.mjs';
import {assertStructuralDatabaseLog} from './lib/consolidation-preview-secrets.mjs';
import {resolveApplicationRegion} from './lib/application-region.mjs';

const fail=message=>{throw Error(message);};
const emit=(phase,values={})=>process.stdout.write(JSON.stringify({event:'consolidation_scheduler_acceptance',phase,...values})+'\n');
export function taskDefinitionMatches(arn,manifest,containerName){
  const prefix=`arn:aws:ecs:${manifest.region}:${manifest.account}:task-definition/${manifest.clusterName}-${containerName}:`;
  return typeof arn==='string'&&arn.startsWith(prefix)&&/^[1-9][0-9]*$/.test(arn.slice(prefix.length));
}
export function validateManifest(value,stage,generation,region){
  if(!isConsolidationPreview(stage)||value?.stage!==stage||value.generation!==generation)fail('GenerationDeployMismatch');
  const cluster=value.clusterArn?.match(/^arn:aws:ecs:([a-z0-9-]+):([0-9]{12}):cluster\/(.+)$/);
  if(!cluster||cluster[1]!==region||!cluster[3].startsWith(`mem9-on-aws-${stage}-`)||
    !new RegExp(`^mem9-on-aws-${stage}-consolidation-[a-zA-Z0-9-]+$`).test(value.groupName)||
    value.roleArn!==`arn:aws:iam::${cluster[2]}:role/mem9-on-aws-${stage}-Mem9ConsolidationSchedulerRole-role`||
    !Array.isArray(value.workers)||value.workers.length!==2||new Set(value.workers.map(w=>w.kind)).size!==2)fail('InvalidAcceptanceManifest');
  for(const w of value.workers){
    if(!['planner','executor'].includes(w.kind)||w.containerName!==`Mem9Consolidation${w.kind==='planner'?'Planner':'Executor'}`||
      !w.taskDefinitionArn?.startsWith(`arn:aws:ecs:${region}:${cluster[2]}:task-definition/mem9-on-aws-${stage}-`)||
      !/:\d+$/.test(w.taskDefinitionArn)||!w.scheduleName?.startsWith(`mem9-on-aws-${stage}-${w.kind}-`)||
      !w.logGroupName?.startsWith('/sst/'))fail('InvalidAcceptanceWorker');
  }
  return {...value,account:cluster[2],clusterName:cluster[3],region};
}
export function scheduleJournal(manifest,worker,wave,when,nonce=randomUUID().replaceAll('-','')){
  if(!['plan','apply','repeat-a','repeat-b'].includes(wave))fail('InvalidAcceptanceWave');
  if(!/^[a-f0-9]{32}$/.test(nonce))fail('InvalidAcceptanceNonce');
  const name=`m9-${manifest.stage}-${manifest.generation.slice(0,12)}-${wave}-${worker.kind}-${nonce.slice(0,8)}`;
  return {version:1,stage:manifest.stage,generation:manifest.generation,kind:worker.kind,wave,
    name,group:manifest.groupName,when,taskDefinitionArn:worker.taskDefinitionArn,containerName:worker.containerName,
    nonce};
}
export function validateJournal(journal,manifest,path,now=Date.now()){
  const worker=manifest.workers.find(w=>w.kind===journal?.kind);
  if(!worker||!/^[0-9a-f]{64}$/.test(journal.generation||'')||journal.stage!==manifest.stage||journal.group!==manifest.groupName||
    journal.containerName!==worker.containerName||journal.taskDefinitionArn?.split(':').slice(0,-1).join(':')!==worker.taskDefinitionArn.split(':').slice(0,-1).join(':')||
    !/:\d+$/.test(journal.taskDefinitionArn)||!Number.isSafeInteger(journal.when)||journal.when>now+10*60_000)fail('InvalidAcceptanceJournal');
  const expected=scheduleJournal({...manifest,generation:journal.generation},{...worker,taskDefinitionArn:journal.taskDefinitionArn},journal.wave,journal.when,journal.nonce);
  if(journal.name!==expected.name||journal.nonce!==expected.nonce||path!==`/mem9-on-aws/${manifest.stage}/consolidation-preview/schedules/${journal.generation}/${journal.wave}-${journal.kind}`)fail('InvalidAcceptanceJournal');
  return journal;
}
export function ownsTask(task,manifest,journal){
  const prefix=`arn:aws:ecs:${manifest.region}:${manifest.account}:task/${manifest.clusterName}/`;
  if(!task.taskArn?.startsWith(prefix)||!/^[-a-zA-Z0-9]+$/.test(task.taskArn.slice(prefix.length))||task.clusterArn!==manifest.clusterArn||task.taskDefinitionArn!==journal.taskDefinitionArn)return false;
  const override=task.overrides?.containerOverrides?.find(c=>c.name===journal.containerName);
  const env=Object.fromEntries((override?.environment??[]).map(v=>[v.name,v.value]));
  return env.MEM9_WORKER_GENERATION===journal.generation&&env.MEM9_WORKER_INVOCATION===journal.nonce;
}
export function ownsOperatorTask(task,manifest,journal){
  const prefix=`arn:aws:ecs:${manifest.region}:${manifest.account}:task/${manifest.clusterName}/`;
  if(!task.taskArn?.startsWith(prefix)||task.clusterArn!==manifest.clusterArn||task.taskDefinitionArn!==journal.taskDefinitionArn)return false;
  const env=Object.fromEntries((task.overrides?.containerOverrides?.find(c=>c.name==='Mem9Bootstrap')?.environment??[]).map(e=>[e.name,e.value]));
  return env.MEM9_BOOTSTRAP_OPERATION==='consolidation-preview-setup'&&env.MEM9_PREVIEW_EXPECTED_GENERATION===journal.generation&&
    env.MEM9_PREVIEW_OPERATOR_NONCE===journal.nonce&&env.MEM9_PREVIEW_OPERATOR_DEADLINE===String(journal.deadline);
}
export function oneShotInput(template,manifest,worker,journal){
  if(template.State!=='DISABLED'||template.GroupName!==manifest.groupName||template.Target?.RoleArn!==manifest.roleArn||
    template.Target?.Arn!==manifest.clusterArn||template.Target?.EcsParameters?.TaskDefinitionArn!==worker.taskDefinitionArn)fail('InvalidDisabledSchedule');
  const input=JSON.parse(template.Target.Input||'{}');
  if(input.containerOverrides?.length!==1||input.containerOverrides[0].name!==worker.containerName||
    input.containerOverrides[0].environment?.find(e=>e.name==='MEM9_WORKER_GENERATION')?.value!==manifest.generation)fail('ScheduleGenerationMismatch');
  const ecs={...template.Target.EcsParameters};
  delete ecs.PropagateTags;delete ecs.Tags;delete ecs.EnableECSManagedTags;
  return {Name:journal.name,GroupName:journal.group,ScheduleExpression:`at(${new Date(journal.when).toISOString().slice(0,19)})`,
    ScheduleExpressionTimezone:'UTC',FlexibleTimeWindow:{Mode:'OFF'},State:'ENABLED',ActionAfterCompletion:'DELETE',
    ClientToken:journal.nonce,Target:{Arn:manifest.clusterArn,RoleArn:manifest.roleArn,EcsParameters:ecs,
      RetryPolicy:{MaximumEventAgeInSeconds:60,MaximumRetryAttempts:0},
      Input:JSON.stringify({containerOverrides:[{name:worker.containerName,environment:[
        {name:'MEM9_WORKER_GENERATION',value:journal.generation},{name:'MEM9_WORKER_INVOCATION',value:journal.nonce}]}]})}};
}

export async function runSchedulerAcceptance({clients,stage,generation,region,now=Date.now,sleep=delay,progress=emit}){
  const {ssm,ecs,scheduler,logs,rds}=clients;
  const send=(client,command)=>client.send(command,{abortSignal:AbortSignal.timeout(30000)});
  const prefix=`/mem9-on-aws/${stage}`;
  const parameters=async names=>{
    const r=await send(ssm,new GetParametersCommand({Names:names,WithDecryption:false}));
    if(r.InvalidParameters?.length||r.Parameters?.length!==names.length)fail('AcceptanceMetadataMissing');
    return new Map(r.Parameters.map(p=>[p.Name,p.Value]));
  };
  const manifestName=prefix+'/consolidation-preview/manifest';
  const manifest=validateManifest(JSON.parse((await parameters([manifestName])).get(manifestName)),stage,generation,region);
  const started=now();
  const bootstrapKeys=['task-def-arn','subnet-ids','task-sg-id'].map(key=>prefix+'/bootstrap/'+key);
  const bootstrap=await parameters(bootstrapKeys);
  const bootArn=bootstrap.get(bootstrapKeys[0]);
  if(!taskDefinitionMatches(bootArn,manifest,'Mem9Bootstrap'))fail('InvalidBootstrapMetadata');
  const bootDef=(await send(ecs,new DescribeTaskDefinitionCommand({taskDefinition:bootArn}))).taskDefinition;
  const boot=bootDef?.containerDefinitions?.find(c=>c.name==='Mem9Bootstrap');
  const bootEnv=Object.fromEntries((boot?.environment??[]).map(e=>[e.name,e.value]));
  if(bootEnv.MEM9_PREVIEW_GENERATION!==generation)fail('GenerationDeployMismatch');
  const defs=new Map([[bootArn,bootDef]]);
  for(const worker of manifest.workers){
    const def=(await send(ecs,new DescribeTaskDefinitionCommand({taskDefinition:worker.taskDefinitionArn}))).taskDefinition;
    if(def?.containerDefinitions?.find(c=>c.name===worker.containerName)?.environment?.find(e=>e.name==='MEM9_WORKER_GENERATION')?.value!==generation)fail('GenerationDeployMismatch');
    defs.set(worker.taskDefinitionArn,def);
  }
  const records=async(task,containerName,event)=>{
    const def=defs.get(task.taskDefinitionArn);
    const cfg=def?.containerDefinitions?.find(c=>c.name===containerName)?.logConfiguration?.options;
    if(!cfg?.['awslogs-group']||!cfg['awslogs-stream-prefix'])fail('MissingTaskLogConfiguration');
    const stream=cfg['awslogs-stream-prefix']+'/'+containerName+'/'+task.taskArn.split('/').at(-1);
    for(let attempt=0;attempt<8;attempt++){
      let token;const parsed=[];
      for(let page=0;page<20;page++){
        const r=await send(logs,new FilterLogEventsCommand({logGroupName:cfg['awslogs-group'],logStreamNames:[stream],nextToken:token,limit:1000}));
        for(const row of r.events??[]){let value;try{value=JSON.parse(row.message);}catch{continue;}
          if(value.event===event||value.event===event+'_failed')parsed.push(value);}
        if(!r.nextToken||r.nextToken===token)break;token=r.nextToken;if(page===19)fail('TaskLogCoverageIncomplete');
      }
      if(parsed.length)return parsed;
      await sleep(5000);
    }
    fail('TaskTerminalRecordMissing');
  };
  const waitTask=async(arn,deadline)=>{
    while(now()<deadline){
      const r=await send(ecs,new DescribeTasksCommand({cluster:manifest.clusterArn,tasks:[arn]}));
      if(r.failures?.length||r.tasks?.length!==1)fail('TaskObservationFailed');
      if(r.tasks[0].lastStatus==='STOPPED')return r.tasks[0];
      await sleep(5000);
    }
    fail('AcceptanceTaskDeadline');
  };
  let operatorTask;
  const operator=async(operation,crossings=0)=>{
    progress('operator-'+operation);
    const nonce=randomUUID().replaceAll('-',''),deadline=now()+600000;
    const journal={operator:true,stage,generation,nonce,deadline,taskDefinitionArn:bootArn};
    const journalPath=prefix+'/consolidation-preview/operators/'+nonce;
    if(operation==='setup'){
      await send(ssm,new PutParameterCommand({Name:journalPath,Type:'String',Value:JSON.stringify(journal),Overwrite:false}));
      const saved=JSON.parse((await parameters([journalPath])).get(journalPath));
      if(JSON.stringify(saved)!==JSON.stringify(journal))fail('OperatorJournalMismatch');
    }
    const r=await send(ecs,new RunTaskCommand({cluster:manifest.clusterArn,taskDefinition:bootArn,launchType:'FARGATE',count:1,clientToken:nonce,
      propagateTags:'TASK_DEFINITION',enableECSManagedTags:true,
      networkConfiguration:{awsvpcConfiguration:{subnets:bootstrap.get(bootstrapKeys[1]).split(','),securityGroups:[bootstrap.get(bootstrapKeys[2])],assignPublicIp:'DISABLED'}},
      overrides:{containerOverrides:[{name:'Mem9Bootstrap',environment:[
        {name:'MEM9_BOOTSTRAP_OPERATION',value:'consolidation-preview-'+operation},
        {name:'MEM9_PREVIEW_EXPECTED_GENERATION',value:generation},
        {name:'MEM9_PREVIEW_OPERATOR_NONCE',value:nonce},
        {name:'MEM9_PREVIEW_OPERATOR_DEADLINE',value:String(deadline)},
        {name:'MEM9_PREVIEW_BATCH_BOUNDARY_CROSSINGS',value:String(crossings)}]}]}}));
    if(r.failures?.length||r.tasks?.length!==1)fail('OperatorLaunchFailed');
    operatorTask=r.tasks[0].taskArn;
    const task=await waitTask(operatorTask,now()+600000);
    const terminal=await records(task,'Mem9Bootstrap','consolidation_preview');
    operatorTask=undefined;
    const bad=terminal.find(r=>r.event.endsWith('_failed'));
    if(bad)fail(/^[A-Za-z]{1,80}$/.test(bad.errorClass)?bad.errorClass:'OperatorFailed');
    if(task.containers?.find(c=>c.name==='Mem9Bootstrap')?.exitCode!==0||terminal.length!==1)fail('OperatorFailed');
    return terminal[0];
  };
  const journals=async()=>{
    const result=[];let NextToken;
    for(let page=0;page<100;page++){
      const r=await send(ssm,new GetParametersByPathCommand({Path:prefix+'/consolidation-preview/schedules/',Recursive:true,WithDecryption:false,NextToken}));
      for(const p of r.Parameters??[])result.push({path:p.Name,journal:validateJournal(JSON.parse(p.Value),manifest,p.Name,now())});
      if(!r.NextToken)return result;NextToken=r.NextToken;
    }
    fail('AcceptanceJournalLimit');
  };
  const discover=async journal=>{
    const arns=new Set();
    for(const desiredStatus of ['RUNNING','STOPPED']){
      let nextToken;
      for(let page=0;page<30;page++){
        const r=await send(ecs,new ListTasksCommand({cluster:manifest.clusterArn,desiredStatus,nextToken,maxResults:100}));
        for(const arn of r.taskArns??[])arns.add(arn);
        if(!r.nextToken)break;nextToken=r.nextToken;if(page===29)fail('TaskDiscoveryIncomplete');
      }
    }
    const owned=[];const list=[...arns];
    for(let i=0;i<list.length;i+=100){
      const r=await send(ecs,new DescribeTasksCommand({cluster:manifest.clusterArn,tasks:list.slice(i,i+100)}));
      if(r.failures?.length)fail('TaskDiscoveryIncomplete');
      for(const task of r.tasks??[])if(journal.operator?ownsOperatorTask(task,manifest,journal):ownsTask(task,manifest,journal))owned.push(task);
    }
    return owned;
  };
  const quiesceOperators=async()=>{
    let NextToken;const saved=[];const errors=[];
    for(let page=0;page<100;page++){
      const r=await send(ssm,new GetParametersByPathCommand({Path:prefix+'/consolidation-preview/operators/',Recursive:true,WithDecryption:false,NextToken}));
      for(const p of r.Parameters??[]){
        let j;try{j=JSON.parse(p.Value);}catch{fail('InvalidOperatorJournal');}
        if(j.operator!==true||j.stage!==stage||!/^[a-f0-9]{64}$/.test(j.generation||'')||!/^[a-f0-9]{32}$/.test(j.nonce||'')||
          p.Name!==prefix+'/consolidation-preview/operators/'+j.nonce||!Number.isSafeInteger(j.deadline)||j.deadline>now()+600000||
          j.taskDefinitionArn?.split(':').slice(0,-1).join(':')!==bootArn.split(':').slice(0,-1).join(':')||!/:\d+$/.test(j.taskDefinitionArn))fail('InvalidOperatorJournal');
        saved.push({path:p.Name,journal:j});
      }
      if(!r.NextToken)break;NextToken=r.NextToken;if(page===99)fail('OperatorJournalLimit');
    }
    for(const {path,journal} of saved){
      let complete=false;
      // Unknown RunTask outcomes stay recoverable. Delayed setup cannot activate
      // after its absolute deadline; final pause follows this quiescence step.
      while(!complete){
        try{
          const tasks=await discover(journal);
          if(tasks.length){
            for(const task of tasks)if(task.lastStatus!=='STOPPED'){
              await send(ecs,new StopTaskCommand({cluster:manifest.clusterArn,task:task.taskArn,reason:'Synthetic setup recovery'}));
              const stopped=await waitTask(task.taskArn,Math.max(now()+30000,journal.deadline+90000));
              if(!ownsOperatorTask(stopped,manifest,journal))fail('OperatorOwnershipChanged');
            }
            complete=true;
          }else if(now()>=journal.deadline+90000)complete=true;
        }catch{if(now()>=journal.deadline+90000){errors.push(path);break;}}
        if(!complete)await sleep(Math.min(10000,Math.max(1,journal.deadline+90000-now())));
      }
      if(complete)try{await send(ssm,new DeleteParameterCommand({Name:path}));}catch{errors.push(path);}
    }
    if(errors.length)fail('OperatorCleanupIncomplete');
  };
  const cleanup=async()=>{
    const saved=await journals();
    const failed=new Set();
    for(const {journal} of saved){
      try{await send(scheduler,new DeleteScheduleCommand({Name:journal.name,GroupName:journal.group}));}
      catch(error){if(error.name!=='ResourceNotFoundException')failed.add(journal.name);}
    }
    // Deletion cannot cancel an in-flight delivery. Paused DB modes and pinned
    // generations are authoritative; the quiet interval bounds final discovery.
    const until=Math.max(now(),...saved.map(r=>r.journal.when+60000));
    while(now()<until)await sleep(Math.min(10000,until-now()));
    for(const {path,journal} of saved){
      try{
        for(const task of await discover(journal))if(task.lastStatus!=='STOPPED'){
          try{
            await send(ecs,new StopTaskCommand({cluster:manifest.clusterArn,task:task.taskArn,reason:'Synthetic consolidation acceptance cleanup'}));
            await waitTask(task.taskArn,now()+180000);
          }catch{failed.add(journal.name);}
        }
        if(!failed.has(journal.name))await send(ssm,new DeleteParameterCommand({Name:path}));
      }catch{failed.add(journal.name);}
    }
    if(failed.size)fail('ScheduleCleanupIncomplete');
  };
  const createWake=async(kind,wave)=>{
    const worker=manifest.workers.find(w=>w.kind===kind);
    const template=await send(scheduler,new GetScheduleCommand({Name:worker.scheduleName,GroupName:manifest.groupName}));
    const journal=scheduleJournal(manifest,worker,wave,Math.ceil((now()+125000)/1000)*1000);
    const path=prefix+'/consolidation-preview/schedules/'+generation+'/'+wave+'-'+kind;
    await send(ssm,new PutParameterCommand({Name:path,Type:'String',Value:JSON.stringify(journal),Overwrite:false}));
    validateJournal(JSON.parse((await parameters([path])).get(path)),manifest,path,now());
    await send(scheduler,new CreateScheduleCommand(oneShotInput(template,manifest,worker,journal)));
    progress('scheduled-'+wave);
    return journal;
  };
  const observeWake=async journal=>{
    const deadline=journal.when+(journal.kind==='planner'?3300000:900000);
    while(now()<deadline){
      const tasks=await discover(journal);
      if(tasks.length){
        const reports=[];
        for(const initial of tasks){
          // Best-effort inventory tags never confer ownership or gate cleanup.
          await send(ecs,new TagResourceCommand({resourceArn:initial.taskArn,tags:[{key:'Project',value:'mem9-on-aws'},{key:'Stage',value:stage}]})).catch(()=>{});
          const task=await waitTask(initial.taskArn,deadline);
          if(!ownsTask(task,manifest,journal))fail('TaskOwnershipChanged');
          const found=await records(task,journal.containerName,'consolidation_worker');
          if(task.containers?.find(c=>c.name===journal.containerName)?.exitCode!==0||found.length!==1||
            found[0].event!=='consolidation_worker'||!['complete','busy','disabled'].includes(found[0].outcome))fail('ScheduledWorkerFailed');
          const record=found[0];
          if(record.kind!==journal.kind||record.stage!==stage||!Number.isSafeInteger(record.changedRows)||
            !Number.isSafeInteger(record.batchBoundaryCrossings))fail('InvalidWorkerEvidence');
          reports.push(record);
        }
        return reports;
      }
      await sleep(10000);
    }
    fail('SchedulerDeliveryNotObserved');
  };
  let activated=false;
  try{
    activated=true;
    await quiesceOperators();
    await operator('pause');
    await cleanup();
    const seeded=await operator('setup');
    if(seeded.outcome==='reused_proven')fail('GenerationAlreadyProvenRedeployForFreshAcceptance');
    const planned=await createWake('planner','plan');await observeWake(planned);
    await operator('verify-planned');
    const executed=await createWake('executor','apply');const results=await observeWake(executed);
    const crossings=results.reduce((n,r)=>n+r.batchBoundaryCrossings,0);
    await operator('verify-executed',crossings);
    const repeatedA=await createWake('executor','repeat-a');const repeatedB=await createWake('executor','repeat-b');
    const repeated=await Promise.all([observeWake(repeatedA),observeWake(repeatedB)]);
    if(repeated.flat().some(r=>r.changedRows!==0))fail('RepeatedWakeChangedRows');
    await operator('verify-repeated');
    await quiesceOperators();
    await operator('pause');activated=false;
    await cleanup();
    await sleep(30000);
    await scanDatabaseLogs({send,rds,manifest,host:bootEnv.MEM9_DB_HOST,since:started});
    for(const worker of manifest.workers){const schedule=await send(scheduler,new GetScheduleCommand({Name:worker.scheduleName,GroupName:manifest.groupName}));if(schedule.State!=='DISABLED')fail('RecurringScheduleEnabled');}
    progress('passed',{synthetic:true,changedRows:150,batchBoundaryCrossings:crossings});
    return {synthetic:true,changedRows:150,batchBoundaryCrossings:crossings};
  }finally{
    const failures=[];
    if(operatorTask)try{
      await send(ecs,new StopTaskCommand({cluster:manifest.clusterArn,task:operatorTask,reason:'Acceptance operator cleanup'}));
      await waitTask(operatorTask,now()+180000);
    }catch{failures.push('operator-stop');}
    try{await quiesceOperators();}catch{failures.push('operator-recovery');}
    try{if(activated)await operator('pause');}catch{failures.push('pause');}
    try{await cleanup();}catch{failures.push('schedules');}
    if(failures.length)fail('AcceptanceCleanupIncomplete');
  }
}

async function scanDatabaseLogs({send,rds,manifest,host,since}){
  let Marker;let cluster;
  for(let page=0;page<100;page++){
    const r=await send(rds,new DescribeDBClustersCommand({Marker}));
    cluster=r.DBClusters?.find(c=>c.Endpoint===host)??cluster;
    if(!r.Marker)break;Marker=r.Marker;if(page===99)fail('DatabaseLogCoverageIncomplete');
  }
  if(!cluster?.DBClusterIdentifier?.startsWith(`mem9-on-aws-${manifest.stage}-`))fail('DatabaseLogOwnerMismatch');
  const tags=(await send(rds,new ListTagsForResourceCommand({ResourceName:cluster.DBClusterArn}))).TagList??[];
  if(!tags.some(t=>t.Key==='Stage'&&t.Value===manifest.stage)||!tags.some(t=>t.Key==='Project'&&t.Value==='mem9-on-aws'))fail('DatabaseLogOwnerMismatch');
  let files=0,bytes=0;
  for(const member of cluster.DBClusterMembers??[]){
    const instance=(await send(rds,new DescribeDBInstancesCommand({DBInstanceIdentifier:member.DBInstanceIdentifier}))).DBInstances?.[0];
    if(!instance?.DBInstanceIdentifier?.startsWith(`mem9-on-aws-${manifest.stage}-`)||instance.DBClusterIdentifier!==cluster.DBClusterIdentifier)fail('DatabaseLogOwnerMismatch');
    let Marker;
    for(let page=0;page<100;page++){
      const r=await send(rds,new DescribeDBLogFilesCommand({DBInstanceIdentifier:instance.DBInstanceIdentifier,FileLastWritten:since,Marker}));
      for(const file of r.DescribeDBLogFiles??[]){
        if(!file.LogFileName?.startsWith('error/postgresql'))continue;
        let cursor='0',tail='';
        for(let part=0;part<1000;part++){
          const data=await send(rds,new DownloadDBLogFilePortionCommand({DBInstanceIdentifier:instance.DBInstanceIdentifier,LogFileName:file.LogFileName,Marker:cursor,NumberOfLines:1000}));
          const raw=data.LogFileData??'';bytes+=Buffer.byteLength(raw);if(bytes>50*1024*1024)fail('DatabaseLogCoverageIncomplete');
          assertStructuralDatabaseLog(tail+raw);tail=raw.slice(-4096);
          if(!data.AdditionalDataPending)break;
          if(!data.Marker||data.Marker===cursor||part===999)fail('DatabaseLogCoverageIncomplete');cursor=data.Marker;
        }
        files++;
      }
      if(!r.Marker)break;Marker=r.Marker;if(page===99)fail('DatabaseLogCoverageIncomplete');
    }
  }
  if(!files)fail('DatabaseLogCoverageIncomplete');
  emit('StructuralDbLogCheckPassed',{files,bytes});
}

async function main(){
  const stage=process.env.STAGE;const generation=previewGeneration(stage);
  const region=process.env.AWS_REGION||await resolveApplicationRegion();
  const cfg={region,maxAttempts:3};
  const clients={ssm:new SSMClient(cfg),ecs:new ECSClient(cfg),scheduler:new SchedulerClient(cfg),logs:new CloudWatchLogsClient(cfg),rds:new RDSClient(cfg)};
  try{await runSchedulerAcceptance({clients,stage,generation,region});}finally{for(const client of Object.values(clients))client.destroy();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(error=>{
  emit('failed',{errorClass:/^[A-Za-z]{1,80}$/.test(error.message)?error.message:'AcceptanceError'});process.exitCode=1;
});
