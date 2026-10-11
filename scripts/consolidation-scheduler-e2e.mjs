import {randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {pathToFileURL} from 'node:url';
import {SSMClient,GetParametersCommand,GetParametersByPathCommand,PutParameterCommand,DeleteParameterCommand} from '@aws-sdk/client-ssm';
import {ECSClient,DescribeTaskDefinitionCommand,RunTaskCommand,ListTasksCommand,DescribeTasksCommand,StopTaskCommand,TagResourceCommand} from '@aws-sdk/client-ecs';
import {SchedulerClient,GetScheduleCommand,CreateScheduleCommand,DeleteScheduleCommand} from '@aws-sdk/client-scheduler';
import {CloudWatchLogsClient,FilterLogEventsCommand} from '@aws-sdk/client-cloudwatch-logs';
import {RDSClient,DescribeDBClustersCommand,DescribeDBInstancesCommand,ListTagsForResourceCommand,DescribeDBLogFilesCommand,DownloadDBLogFilePortionCommand} from '@aws-sdk/client-rds';
import {IAMClient} from '@aws-sdk/client-iam';
import {STSClient} from '@aws-sdk/client-sts';
import {previewGeneration,isConsolidationPreview,previewAcceptanceContext} from './lib/consolidation-preview-config.mjs';
import {loadPostRuntimeOperator,revalidatePostRuntimeOperator,loadNonrootPreviewBootstrap,revalidateNonrootPreviewBootstrap,nonrootPreviewSourceTree,nonrootPreviewObservation} from './lib/post-runtime-preview-aws.mjs';
import {previewBootstrapPurposeForOperation,validateNonrootPreviewOverrides} from './lib/nonroot-preview-source.mjs';
import {dataLaunchPolicy} from './lib/production-nonroot-launch.mjs';
import {POST_RUNTIME_PURPOSES,inspectPostRuntimeRoute,validatePostRuntimeDefinition} from './lib/post-runtime-preview-route.mjs';
import {canaryEvidenceHash as evidenceHash} from './lib/production-canary-verification.mjs';
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
  const name=journal.route?.containerName??'Mem9Bootstrap';
  const env=Object.fromEntries((task.overrides?.containerOverrides?.find(c=>c.name===name)?.environment??[]).map(e=>[e.name,e.value]));
  return env.MEM9_BOOTSTRAP_OPERATION==='consolidation-preview-'+(journal.operation??'setup')&&env.MEM9_PREVIEW_EXPECTED_GENERATION===journal.generation&&
    env.MEM9_PREVIEW_OPERATOR_NONCE===journal.nonce&&env.MEM9_PREVIEW_OPERATOR_DEADLINE===String(journal.deadline);
}
export function verifyPostRuntimeTask(task,manifest,binding,journal){
  const {route,image}=binding,override=task?.overrides?.containerOverrides;
  if(!ownsOperatorTask(task,manifest,journal)||task.lastStatus!=='STOPPED'||task.containers?.length!==1||override?.length!==1||
    override[0].name!==route.containerName||override[0].command?.length||override[0].environmentFiles?.length||
    task.overrides.taskRoleArn&&task.overrides.taskRoleArn!==route.taskRoleArn||
    task.overrides.executionRoleArn&&task.overrides.executionRoleArn!==route.executionRoleArn)fail('PostRuntimeTaskMismatch');
  const c=task.containers[0],env=Object.fromEntries((override[0].environment??[]).map(e=>[e.name,e.value]));
  const expected={MEM9_BOOTSTRAP_OPERATION:'consolidation-preview-'+journal.operation,MEM9_PREVIEW_EXPECTED_GENERATION:journal.generation,
    MEM9_PREVIEW_OPERATOR_NONCE:journal.nonce,MEM9_PREVIEW_OPERATOR_DEADLINE:String(journal.deadline),MEM9_PREVIEW_BATCH_BOUNDARY_CROSSINGS:String(journal.batchBoundaryCrossings)};
  if(c.name!==route.containerName||c.image!==route.image||![image.rootDigest,image.arm64Digest].includes(c.imageDigest)||c.exitCode!==0||
    override[0].environment?.length!==5||Object.keys(env).length!==5||Object.keys(expected).some(k=>env[k]!==expected[k]))fail('PostRuntimeTaskMismatch');
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

export async function discoverSchedulerTasks(ecs,clusterArn,accept,{sleep=delay,now=Date.now,deadlineMs=now()+120000}={}){
  const request=command=>{
    const remaining=deadlineMs-now();if(remaining<=0)fail('TaskDiscoveryIncomplete');
    return ecs.send(command,{abortSignal:AbortSignal.timeout(Math.min(30000,remaining))});
  };
  for(let attempt=0;attempt<4;attempt++){
    const arns=new Set();
    for(const desiredStatus of ['RUNNING','STOPPED']){
      let nextToken;
      for(let page=0;page<30;page++){
        const result=await request(new ListTasksCommand({cluster:clusterArn,desiredStatus,nextToken,maxResults:100}));
        if(!Array.isArray(result.taskArns))fail('TaskDiscoveryIncomplete');
        for(const arn of result.taskArns)arns.add(arn);
        if(!result.nextToken)break;
        if(result.nextToken===nextToken||page===29)fail('TaskDiscoveryIncomplete');nextToken=result.nextToken;
      }
    }
    const owned=[],all=[...arns];let missing=false;
    for(let index=0;index<all.length;index+=100){
      const batch=all.slice(index,index+100),expected=new Set(batch),seen=new Set();
      const result=await request(new DescribeTasksCommand({cluster:clusterArn,tasks:batch}));
      for(const failure of result.failures??[]){
        if(failure.reason!=='MISSING'||!expected.has(failure.arn)||seen.has(failure.arn))fail('TaskDiscoveryIncomplete');
        seen.add(failure.arn);missing=true;
      }
      for(const task of result.tasks??[]){
        if(!task?.taskArn||!expected.has(task.taskArn)||seen.has(task.taskArn)||task.clusterArn!==clusterArn)fail('TaskDiscoveryIncomplete');
        seen.add(task.taskArn);if(accept(task))owned.push(task);
      }
      if(seen.size!==expected.size)fail('TaskDiscoveryIncomplete');
    }
    if(!missing)return owned;
    // Never turn an unaccounted task into a successful partial inventory.
    // Refresh both views so expired stopped entries can disappear naturally.
    if(attempt===3)fail('TaskDiscoveryIncomplete');
    await sleep(Math.min([1000,3000,10000][attempt],Math.max(1,deadlineMs-now())));
  }
  fail('TaskDiscoveryIncomplete');
}

export async function runSchedulerAcceptance({clients,stage,generation,region,postRuntime,controlSourceTree,postRuntimeChecks,now=Date.now,sleep=delay,progress=emit}){
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
  const postOptions={stage,generation,region,context:postRuntime,controlSourceTree};
  let binding=postRuntime?await loadPostRuntimeOperator(clients,postOptions,postRuntimeChecks):undefined;
  const postParameters=binding?.parameters;
  let bootArn,bootDef,bootName,operatorSubnets,operatorSecurityGroup,bootstrapBinding;
  if(binding){
    if(binding.route.version!==2)fail('NonrootPreviewVersionRequired');
    if(!Array.isArray(binding.purposeBindings)||evidenceHash(binding.purposeBindings.map(b=>b.purpose).sort())!==evidenceHash([...POST_RUNTIME_PURPOSES].sort()))fail('NonrootPreviewPurposeUnavailable');
    const r=binding.route;bootArn=r.taskDefinitionArn;bootDef=binding.definition;bootName=r.containerName;operatorSubnets=r.subnets;operatorSecurityGroup=r.securityGroup;
  }else{
    const names=['production-plan','production-manifest','production-state'].map(name=>prefix+'/runtime/'+name);
    const lifecycle=await send(ssm,new GetParametersCommand({Names:names,WithDecryption:false}));
    if(lifecycle.Parameters?.length)fail('PostRuntimeContextRequired');
    if(!Array.isArray(lifecycle.InvalidParameters)||lifecycle.InvalidParameters.length!==names.length||
      new Set(lifecycle.InvalidParameters).size!==names.length||lifecycle.InvalidParameters.some(name=>!names.includes(name)))fail('AcceptanceMetadataMissing');
    bootstrapBinding=await loadNonrootPreviewBootstrap(clients,{stage,region,sourceTree:controlSourceTree,purpose:'preview-fixture-pause'});
    if(bootstrapBinding.clusterArn!==manifest.clusterArn)fail('InvalidBootstrapMetadata');
    bootArn=bootstrapBinding.binding.taskDefinitionArn;bootDef=bootstrapBinding.observation.taskDefinition;bootName='Mem9Bootstrap';
    operatorSubnets=bootstrapBinding.subnets;operatorSecurityGroup=bootstrapBinding.securityGroup;
  }
  const boot=bootDef?.containerDefinitions?.find(c=>c.name===bootName);
  const bootEnv=Object.fromEntries((boot?.environment??[]).map(e=>[e.name,e.value]));
  if(bootEnv.MEM9_PREVIEW_GENERATION!==generation)fail('GenerationDeployMismatch');
  const defs=new Map([[bootArn,bootDef]]);
  const workerReadbacks=new Map();
  for(const worker of manifest.workers){
    const observed=nonrootPreviewObservation(await send(ecs,new DescribeTaskDefinitionCommand({taskDefinition:worker.taskDefinitionArn,include:['TAGS']}))),def=observed.taskDefinition;
    if(def.taskDefinitionArn!==worker.taskDefinitionArn||!Array.isArray(observed.tags))fail('NonrootPreviewWorkerReadback');
    const container=def?.containerDefinitions?.find(c=>c.name===worker.containerName);
    if(container?.environment?.find(e=>e.name==='MEM9_WORKER_GENERATION')?.value!==generation)fail('GenerationDeployMismatch');
    const launch=dataLaunchPolicy(worker.kind,container);
    for(const field of ['user','entryPoint','command'])if(evidenceHash(container[field]??null)!==evidenceHash(launch[field]))fail('NonrootPreviewWorkerLaunch');
    if(evidenceHash(container.linuxParameters?.capabilities?.drop??null)!==evidenceHash(['ALL']))fail('NonrootPreviewWorkerLaunch');
    workerReadbacks.set(worker.taskDefinitionArn,observed);
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
  let operatorTask,operatorJournal;
  const operator=async(operation,crossings=0)=>{
    progress('operator-'+operation);
    const purpose=previewBootstrapPurposeForOperation('consolidation-preview-'+operation);
    let selected;
    if(bootstrapBinding){
      selected=await loadNonrootPreviewBootstrap(clients,{...bootstrapBinding.scope,purpose});
      if(evidenceHash(selected.parameters)!==evidenceHash(bootstrapBinding.parameters))fail('NonrootPreviewBindingsChanged');
      bootArn=selected.binding.taskDefinitionArn;defs.set(bootArn,selected.observation.taskDefinition);
      if(selected.observation.taskDefinition.containerDefinitions[0].environment.find(e=>e.name==='MEM9_PREVIEW_GENERATION')?.value!==generation)fail('GenerationDeployMismatch');
    }else{
      binding=await loadPostRuntimeOperator(clients,{...postOptions,purpose},postRuntimeChecks);
      if(evidenceHash(binding.parameters)!==evidenceHash(postParameters))fail('PostRuntimeRouteChanged');
      bootArn=binding.route.taskDefinitionArn;defs.set(bootArn,binding.definition);
      if(binding.definition.containerDefinitions[0].environment.find(e=>e.name==='MEM9_BOOTSTRAP_OPERATION')?.value!=='consolidation-preview-'+operation)fail('NonrootPreviewPurposeUnavailable');
    }
    if(binding)await revalidatePostRuntimeOperator(clients,binding,postOptions,postRuntimeChecks);
    const nonce=randomUUID().replaceAll('-',''),deadline=now()+600000;
    const journal={operator:true,stage,generation,nonce,deadline,taskDefinitionArn:bootArn,
      ...(binding?{version:2,operation,createdAt:now(),batchBoundaryCrossings:crossings,route:binding.route,routeHash:evidenceHash(binding.route)}:{})};
    const journalPath=prefix+'/consolidation-preview/operators/'+nonce;
    if(operation==='setup'||binding){
      await send(ssm,new PutParameterCommand({Name:journalPath,Type:'String',Value:JSON.stringify(journal),Overwrite:false}));
      const saved=JSON.parse((await parameters([journalPath])).get(journalPath));
      if(JSON.stringify(saved)!==JSON.stringify(journal))fail('OperatorJournalMismatch');
    }
    if(binding)await revalidatePostRuntimeOperator(clients,binding,postOptions,postRuntimeChecks);
    if(selected)await revalidateNonrootPreviewBootstrap(clients,selected);
    const overrides={containerOverrides:[{name:bootName,environment:[
      {name:'MEM9_BOOTSTRAP_OPERATION',value:'consolidation-preview-'+operation},
      {name:'MEM9_PREVIEW_EXPECTED_GENERATION',value:generation},
      {name:'MEM9_PREVIEW_OPERATOR_NONCE',value:nonce},
      {name:'MEM9_PREVIEW_OPERATOR_DEADLINE',value:String(deadline)},
      {name:'MEM9_PREVIEW_BATCH_BOUNDARY_CROSSINGS',value:String(crossings)}]}]};
    validateNonrootPreviewOverrides(purpose,overrides,{now:now(),containerName:bootName});
    const r=await send(ecs,new RunTaskCommand({cluster:manifest.clusterArn,taskDefinition:bootArn,launchType:'FARGATE',count:1,clientToken:nonce,
      enableExecuteCommand:false,
      propagateTags:'TASK_DEFINITION',enableECSManagedTags:true,
      networkConfiguration:{awsvpcConfiguration:{subnets:operatorSubnets,securityGroups:[operatorSecurityGroup],assignPublicIp:'DISABLED'}},
      overrides}));
    if(r.failures?.length||r.tasks?.length!==1)fail('OperatorLaunchFailed');
    if(!r.tasks[0].taskArn?.startsWith(manifest.clusterArn.replace(':cluster/',':task/')+'/')||
      r.tasks[0].clusterArn!==manifest.clusterArn||r.tasks[0].taskDefinitionArn!==bootArn)fail('OperatorLaunchIdentityMismatch');
    operatorTask=r.tasks[0].taskArn;
    operatorJournal=journal;
    if(binding){
      const prior=JSON.parse((await parameters([journalPath])).get(journalPath));if(evidenceHash(prior)!==evidenceHash(journal))fail('OperatorJournalMismatch');
      journal.taskArn=operatorTask;
      await send(ssm,new PutParameterCommand({Name:journalPath,Type:'String',Value:JSON.stringify(journal),Overwrite:true}));
      if(evidenceHash(JSON.parse((await parameters([journalPath])).get(journalPath)))!==evidenceHash(journal))fail('OperatorJournalMismatch');
    }
    const task=await waitTask(operatorTask,now()+600000);
    if(binding)verifyPostRuntimeTask(task,manifest,binding,journal);
    const terminal=await records(task,bootName,'consolidation_preview');
    operatorTask=undefined;
    const bad=terminal.find(r=>r.event.endsWith('_failed'));
    if(bad)fail(/^[A-Za-z]{1,80}$/.test(bad.errorClass)?bad.errorClass:'OperatorFailed');
    if(task.containers?.find(c=>c.name===bootName)?.exitCode!==0||terminal.length!==1)fail('OperatorFailed');
    if(binding){
      const proof=terminal[0].authority;
      if(proof?.stage!==stage||proof.generation!==generation||proof.contextHash!==evidenceHash(postRuntime)||!Number.isSafeInteger(proof.administratorOid)||
        !/^[a-f0-9]{64}$/.test(proof.runtimeStateHash??'')||!/^[a-f0-9]{64}$/.test(proof.runtimeRowsHash??''))fail('PostRuntimeOperatorEvidenceMissing');
    }
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
  const discover=journal=>discoverSchedulerTasks(ecs,manifest.clusterArn,
    task=>journal.operator?ownsOperatorTask(task,manifest,journal):ownsTask(task,manifest,journal),{sleep,now});
  const quiesceOperators=async()=>{
    let NextToken;const saved=[];const errors=[];
    for(let page=0;page<100;page++){
      const r=await send(ssm,new GetParametersByPathCommand({Path:prefix+'/consolidation-preview/operators/',Recursive:true,WithDecryption:false,NextToken}));
      for(const p of r.Parameters??[]){
        let j;try{j=JSON.parse(p.Value);}catch{fail('InvalidOperatorJournal');}
        if(j.operator!==true||j.stage!==stage||!/^[a-f0-9]{64}$/.test(j.generation||'')||!/^[a-f0-9]{32}$/.test(j.nonce||'')||
          p.Name!==prefix+'/consolidation-preview/operators/'+j.nonce||!Number.isSafeInteger(j.deadline)||j.deadline>now()+600000||!/:\d+$/.test(j.taskDefinitionArn))fail('InvalidOperatorJournal');
        if(j.version===2){
          const route=inspectPostRuntimeRoute(j.route,{stage,account:manifest.account,region});
          if(evidenceHash(route)!==j.routeHash||route.generation!==j.generation||route.taskDefinitionArn!==j.taskDefinitionArn||
            !['setup','pause','verify-planned','verify-executed','verify-repeated'].includes(j.operation)||!Number.isSafeInteger(j.createdAt)||j.createdAt<1||
            j.createdAt>j.deadline||j.deadline-j.createdAt>600000||!Number.isSafeInteger(j.batchBoundaryCrossings)||j.batchBoundaryCrossings<0||j.batchBoundaryCrossings>10000)fail('InvalidOperatorJournal');
          const observed=nonrootPreviewObservation(await send(ecs,new DescribeTaskDefinitionCommand({taskDefinition:j.taskDefinitionArn,include:['TAGS']})));
          validatePostRuntimeDefinition(observed.taskDefinition,route,observed);
        }else if(j.version!==undefined||!taskDefinitionMatches(j.taskDefinitionArn,manifest,'Mem9Bootstrap'))fail('InvalidOperatorJournal');
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
          if(journal.taskArn&&!tasks.some(task=>task.taskArn===journal.taskArn)){
            if(!journal.taskArn.startsWith(manifest.clusterArn.replace(':cluster/',':task/')+'/'))fail('OperatorOwnershipChanged');
            const known=await send(ecs,new DescribeTasksCommand({cluster:manifest.clusterArn,tasks:[journal.taskArn]}));
            if(known.failures?.length||known.tasks?.length!==1||!ownsOperatorTask(known.tasks[0],manifest,journal))fail('OperatorOwnershipChanged');
            tasks.push(known.tasks[0]);
          }
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
    const readback=nonrootPreviewObservation(await send(ecs,new DescribeTaskDefinitionCommand({taskDefinition:worker.taskDefinitionArn,include:['TAGS']})));
    if(evidenceHash(readback)!==evidenceHash(workerReadbacks.get(worker.taskDefinitionArn)))fail('NonrootPreviewWorkerReadbackChanged');
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
    const logCoverage=await captureDatabaseLogCoverage({send,rds,manifest,host:bootEnv.MEM9_DB_HOST});
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
    await scanDatabaseLogs({send,rds,manifest,host:bootEnv.MEM9_DB_HOST,coverage:logCoverage,progress});
    for(const worker of manifest.workers){const schedule=await send(scheduler,new GetScheduleCommand({Name:worker.scheduleName,GroupName:manifest.groupName}));if(schedule.State!=='DISABLED')fail('RecurringScheduleEnabled');}
    progress('passed',{synthetic:true,changedRows:150,batchBoundaryCrossings:crossings});
    return {synthetic:true,changedRows:150,batchBoundaryCrossings:crossings};
  }finally{
    const failures=[];
    if(operatorTask)try{
      if(binding){
        const known=await send(ecs,new DescribeTasksCommand({cluster:manifest.clusterArn,tasks:[operatorTask]}));
        if(known.failures?.length||known.tasks?.length!==1||!ownsOperatorTask(known.tasks[0],manifest,operatorJournal))fail('OperatorOwnershipChanged');
      }
      await send(ecs,new StopTaskCommand({cluster:manifest.clusterArn,task:operatorTask,reason:'Acceptance operator cleanup'}));
      await waitTask(operatorTask,now()+180000);
    }catch{failures.push('operator-stop');}
    try{await quiesceOperators();}catch{failures.push('operator-recovery');}
    try{if(activated)await operator('pause');}catch{failures.push('pause');}
    if(binding)try{await quiesceOperators();}catch{failures.push('final-operator-recovery');}
    try{await cleanup();}catch{failures.push('schedules');}
    if(failures.length)fail('AcceptanceCleanupIncomplete');
  }
}

async function databaseLogInventory({send,rds,manifest,host}){
  let Marker;let cluster;
  for(let page=0;page<100;page++){
    const r=await send(rds,new DescribeDBClustersCommand({Marker}));
    cluster=r.DBClusters?.find(c=>c.Endpoint===host)??cluster;
    if(!r.Marker)break;Marker=r.Marker;if(page===99)fail('DatabaseLogCoverageIncomplete');
  }
  if(!cluster?.DBClusterIdentifier?.startsWith(`mem9-on-aws-${manifest.stage}-`))fail('DatabaseLogOwnerMismatch');
  const tags=(await send(rds,new ListTagsForResourceCommand({ResourceName:cluster.DBClusterArn}))).TagList??[];
  if(!tags.some(t=>t.Key==='Stage'&&t.Value===manifest.stage)||!tags.some(t=>t.Key==='Project'&&t.Value==='mem9-on-aws'))fail('DatabaseLogOwnerMismatch');
  const inventory=[];
  for(const member of cluster.DBClusterMembers??[]){
    const instance=(await send(rds,new DescribeDBInstancesCommand({DBInstanceIdentifier:member.DBInstanceIdentifier}))).DBInstances?.[0];
    if(!instance?.DBInstanceIdentifier?.startsWith(`mem9-on-aws-${manifest.stage}-`)||instance.DBClusterIdentifier!==cluster.DBClusterIdentifier)fail('DatabaseLogOwnerMismatch');
    let Marker;const files=[];
    for(let page=0;page<100;page++){
      // LastWritten is not an interval-coverage filter: an active log can stay
      // unchanged throughout a quiet, successful acceptance run.
      const r=await send(rds,new DescribeDBLogFilesCommand({DBInstanceIdentifier:instance.DBInstanceIdentifier,Marker}));
      for(const file of r.DescribeDBLogFiles??[]){
        if(!file.LogFileName?.startsWith('error/postgresql'))continue;
        if(!Number.isSafeInteger(file.Size)||file.Size<0||!Number.isSafeInteger(file.LastWritten))fail('InvalidDatabaseLogMetadata');
        files.push(file);
      }
      if(!r.Marker)break;
      if(r.Marker===Marker||page===99)fail('DatabaseLogCoverageIncomplete');Marker=r.Marker;
    }
    if(!files.length||new Set(files.map(f=>f.LogFileName)).size!==files.length)fail('DatabaseLogCoverageIncomplete');
    inventory.push({instance:instance.DBInstanceIdentifier,files});
  }
  if(!inventory.length)fail('DatabaseLogCoverageIncomplete');
  return inventory;
}

export async function captureDatabaseLogCoverage(options){
  const inventory=await databaseLogInventory(options);
  return inventory.map(({instance,files})=>{
    const anchor=[...files].sort((a,b)=>b.LastWritten-a.LastWritten||b.LogFileName.localeCompare(a.LogFileName))[0];
    return {instance,anchor:anchor.LogFileName,minimumBytes:anchor.Size};
  });
}

export async function scanDatabaseLogs({coverage,progress=emit,...options}){
  const {send,rds}=options;
  const inventory=await databaseLogInventory(options);
  if(!Array.isArray(coverage)||coverage.length!==inventory.length)fail('DatabaseLogCoverageChanged');
  let files=0,bytes=0;
  for(const entry of inventory){
    const expected=coverage.find(c=>c.instance===entry.instance);
    const anchor=entry.files.find(f=>f.LogFileName===expected?.anchor);
    if(!anchor||anchor.Size<expected.minimumBytes)fail('DatabaseLogAnchorMissing');
    // Read all retained PostgreSQL files, including the pre-run anchor and any
    // rotations. No raw pages or credential values leave this scanner.
    for(const file of entry.files){
      let cursor='0',tail='',fileBytes=0;
      for(let part=0;part<1000;part++){
        const data=await send(rds,new DownloadDBLogFilePortionCommand({DBInstanceIdentifier:entry.instance,LogFileName:file.LogFileName,Marker:cursor,NumberOfLines:1000}));
        const raw=data.LogFileData??'';const length=Buffer.byteLength(raw);
        bytes+=length;fileBytes+=length;if(bytes>50*1024*1024)fail('DatabaseLogCoverageIncomplete');
        assertStructuralDatabaseLog(tail+raw);tail=raw.slice(-4096);
        if(!data.AdditionalDataPending)break;
        if(!data.Marker||data.Marker===cursor||part===999)fail('DatabaseLogCoverageIncomplete');cursor=data.Marker;
      }
      if(fileBytes<file.Size)fail('DatabaseLogReadIncomplete');
      files++;
    }
  }
  progress('StructuralDbLogCheckPassed',{files,bytes});
  return {files,bytes};
}

async function main(){
  const stage=process.env.STAGE;const generation=previewGeneration(stage);
  const postRuntime=previewAcceptanceContext(stage),controlSourceTree=await nonrootPreviewSourceTree();
  const region=process.env.AWS_REGION||await resolveApplicationRegion();
  const cfg={region,maxAttempts:3};
  const clients={ssm:new SSMClient(cfg),ecs:new ECSClient(cfg),scheduler:new SchedulerClient(cfg),logs:new CloudWatchLogsClient(cfg),rds:new RDSClient(cfg),
    sts:new STSClient(cfg),...(postRuntime?{iam:new IAMClient({...cfg,region:'us-east-1'})}:{})};
  try{await runSchedulerAcceptance({clients,stage,generation,region,postRuntime,controlSourceTree});}finally{for(const client of Object.values(clients))client.destroy();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(error=>{
  emit('failed',{errorClass:/^[A-Za-z]{1,80}$/.test(error.message)?error.message:'AcceptanceError'});process.exitCode=1;
});
