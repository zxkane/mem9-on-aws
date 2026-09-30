import {randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {GetParametersCommand,PutParameterCommand,GetParametersByPathCommand,DeleteParameterCommand} from '@aws-sdk/client-ssm';
import {DescribeTaskDefinitionCommand,RunTaskCommand,DescribeTasksCommand,ListTasksCommand,StopTaskCommand} from '@aws-sdk/client-ecs';
import {FilterLogEventsCommand} from '@aws-sdk/client-cloudwatch-logs';
import {GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {rolloutStage,validateRolloutIdentity} from './production-runtime-config.mjs';
import {validateExtensionCatalog} from './runtime-extension-catalog.mjs';

const fail=code=>{throw Error(code);};
const send=(client,command)=>client.send(command,{abortSignal:AbortSignal.timeout(30000)});
const environment=container=>Object.fromEntries((container?.environment??[]).map(e=>[e.name,e.value]));
const same=(a,b)=>JSON.stringify(Object.entries(a).sort())===JSON.stringify(Object.entries(b).sort());

export async function loadLegacyCatalogTarget(clients,{stage,region}){
  if(!rolloutStage(stage))fail('InvalidRolloutStage');
  const prefix=`/mem9-on-aws/${stage}/`,keys=['bootstrap/cluster-name','bootstrap/task-def-arn','bootstrap/subnet-ids','bootstrap/task-sg-id','db/host','db/port','db/name','db/secret-arn'];
  const result=await send(clients.ssm,new GetParametersCommand({Names:keys.map(k=>prefix+k),WithDecryption:false}));
  if(result.InvalidParameters?.length||result.Parameters?.length!==keys.length)fail('CatalogTargetMissing');
  const values=new Map(result.Parameters.map(p=>[p.Name.slice(prefix.length),p.Value]));
  const account=(await send(clients.sts,new GetCallerIdentityCommand({}))).Account;
  const cluster=values.get('bootstrap/cluster-name'),host=values.get('db/host'),database=values.get('db/name');
  const task=values.get('bootstrap/task-def-arn'),secret=values.get('db/secret-arn'),port=Number(values.get('db/port'));
  if(!cluster?.startsWith(`mem9-on-aws-${stage}-`)||!/^[A-Za-z0-9-]+$/.test(cluster)||
    !task?.startsWith(`arn:aws:ecs:${region}:${account}:task-definition/${cluster}-Mem9Bootstrap:`)||!/[1-9][0-9]*$/.test(task)||
    !host?.startsWith(`mem9-on-aws-${stage}-`)||!host.endsWith(`.${region}.rds.amazonaws.com`)||
    !secret?.startsWith(`arn:aws:secretsmanager:${region}:${account}:secret:mem9-on-aws-${stage}-`)||
    !/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(database??'')||!Number.isInteger(port)||port<1||port>65535)fail('CatalogTargetMismatch');
  const subnets=values.get('bootstrap/subnet-ids').split(','),securityGroup=values.get('bootstrap/task-sg-id');
  if(!subnets.length||subnets.length>16||subnets.some(s=>!/^subnet-[a-f0-9]+$/.test(s))||!/^sg-[a-f0-9]+$/.test(securityGroup))fail('CatalogNetworkMismatch');
  return {mode:'catalog',stage,region,account,cluster,clusterArn:`arn:aws:ecs:${region}:${account}:cluster/${cluster}`,
    bootstrapTaskDefinition:task,host,port,database,originalOwnerSecret:secret,subnets,securityGroup};
}

export async function loadProductionManifest(clients,{stage,region}){
  if(!rolloutStage(stage))fail('InvalidRolloutStage');
  const prefix=`/mem9-on-aws/${stage}`;
  const names=[prefix+'/runtime/production-manifest',prefix+'/bootstrap/task-def-arn'];
  const result=await send(clients.ssm,new GetParametersCommand({Names:names,WithDecryption:true}));
  if(result.InvalidParameters?.length||result.Parameters?.length!==2)fail('ProductionManifestMissing');
  const values=new Map(result.Parameters.map(p=>[p.Name,p.Value]));
  let meta;try{meta=JSON.parse(values.get(names[0]));}catch{fail('InvalidProductionManifest');}
  const account=(await send(clients.sts,new GetCallerIdentityCommand({}))).Account;
  if(meta?.version!==1||meta.stage!==stage||meta.region!==region||meta.account!==account||
    !['prepare','paused','ready','active'].includes(meta.mode)||!meta.cluster?.startsWith(`mem9-on-aws-${stage}-`)||
    !/^[A-Za-z0-9-]+$/.test(meta.cluster)||meta.clusterArn!==`arn:aws:ecs:${region}:${account}:cluster/${meta.cluster}`||
    meta.service!=='Mem9Server'||!meta.host?.startsWith(`mem9-on-aws-${stage}-`)||!meta.host.endsWith(`.${region}.rds.amazonaws.com`)||
    !Number.isInteger(meta.port)||meta.port<1||meta.port>65535||!/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(meta.database??'')||
    !Array.isArray(meta.subnets)||!meta.subnets.length||meta.subnets.length>16||meta.subnets.some(s=>!/^subnet-[a-f0-9]+$/.test(s))||
    !/^sg-[a-f0-9]+$/.test(meta.securityGroup??''))fail('InvalidProductionManifest');
  const arn=`arn:aws:ssm:${region}:${account}:parameter${prefix}/runtime/`;
  for(const [key,suffix] of Object.entries({administratorCredential:'schema-administrator-credential',administratorBackup:'schema-administrator-backup',
    transitionCredential:'transition-credential',runtimeCredential:'database-credential'}))if(meta[key]!==arn+suffix)fail('ProductionCredentialReferenceMismatch');
  for(const key of ['originalOwnerSecret','tenantSecret'])if(!meta[key]?.startsWith(`arn:aws:secretsmanager:${region}:${account}:secret:mem9-on-aws-${stage}-`))fail('ProductionCredentialReferenceMismatch');
  const task=(value,family)=>typeof value==='string'&&value.startsWith(`arn:aws:ecs:${region}:${account}:task-definition/${meta.cluster}-${family}:`)&&/^[1-9][0-9]*$/.test(value.split(':').at(-1));
  if(!task(meta.transitionTaskDefinition,'TransitionMem9Bootstrap')||!task(meta.fallbackTaskDefinition,'Mem9RuntimeServer')||
    !task(values.get(names[1]),'Mem9Bootstrap')||meta.transitionContainer!=='TransitionMem9Bootstrap'||
    !meta.fallbackImage?.startsWith(`${account}.dkr.ecr.${region}.amazonaws.com/`)||!/@sha256:[a-f0-9]{64}$/.test(meta.fallbackImage))fail('ProductionTaskReferenceMismatch');
  return {...meta,bootstrapTaskDefinition:values.get(names[1])};
}

export function ownsProductionInvocation(task,meta,journal){
  const overrides=task.overrides?.containerOverrides,container=overrides?.find(c=>c.name===journal.container),env=environment(container);
  const expected={MEM9_RUNTIME_INVOCATION:journal.invocation,MEM9_PRODUCTION_RUNTIME_REQUEST:JSON.stringify(journal.request),MEM9_BOOTSTRAP_OPERATION:'production-runtime'};
  return task.clusterArn===meta.clusterArn&&task.taskDefinitionArn===journal.taskDefinition&&
    task.taskArn?.startsWith(`arn:aws:ecs:${meta.region}:${meta.account}:task/${meta.cluster}/`)&&
    overrides?.length===1&&container.environment?.length===3&&!container.command?.length&&!container.environmentFiles?.length&&same(env,expected)&&
    (!task.overrides.taskRoleArn||task.overrides.taskRoleArn===journal.taskRoleArn)&&
    (!task.overrides.executionRoleArn||task.overrides.executionRoleArn===journal.executionRoleArn);
}

async function observeInvocation(clients,meta,journal,{sleep=delay,now=Date.now}={}){
  let stopped;
  while(now()<journal.request.deadline+60000){
    if(journal.taskArn){
      const response=await send(clients.ecs,new DescribeTasksCommand({cluster:meta.clusterArn,tasks:[journal.taskArn]}));
      if(response.failures?.length)fail('ProductionTaskObservationFailed');
      const task=response.tasks?.[0];
      if(task&&!ownsProductionInvocation(task,meta,journal))fail('ProductionTaskOwnershipMismatch');
      if(task?.lastStatus==='STOPPED'){stopped=task;break;}
    }
    await sleep(5000);
  }
  if(!stopped)fail('ProductionInvocationTimeout');
  return stopped;
}

export async function invokeProductionTask(clients,meta,{operation,nonce,epoch,target,verification_hash,task_definition},
  {now=Date.now,sleep=delay,progress=()=>{},deadlineMs=Infinity}={}){
  const catalog=meta.mode==='catalog';
  if(catalog&&operation!=='extension-catalog')fail('CatalogOnlyTarget');
  const main=meta.mode==='active'||catalog;
  const taskDefinition=main?meta.bootstrapTaskDefinition:meta.transitionTaskDefinition;
  const containerName=main?'Mem9Bootstrap':meta.transitionContainer;
  const definition=(await send(clients.ecs,new DescribeTaskDefinitionCommand({taskDefinition}))).taskDefinition;
  const container=definition?.containerDefinitions?.find(c=>c.name===containerName),env=environment(container);
  const expected=main?{MEM9_DB_SECRET:meta.administratorCredential,MEM9_RUNTIME_DB_SECRET:meta.runtimeCredential,MEM9_TENANT_ID:meta.tenantSecret}:
    {MEM9_DB_SECRET:meta.originalOwnerSecret,MEM9_SCHEMA_ADMIN_CREDENTIAL:meta.administratorCredential,MEM9_RUNTIME_DB_SECRET:meta.runtimeCredential,
      MEM9_TRANSITION_CREDENTIAL:meta.transitionCredential,MEM9_TENANT_ID:meta.tenantSecret};
  const legacySecretsValid=catalog&&container?.secrets?.find(s=>s.name==='MEM9_DB_SECRET')?.valueFrom===meta.originalOwnerSecret&&
    container.secrets.every(s=>s.valueFrom.startsWith(`arn:aws:ssm:${meta.region}:${meta.account}:parameter/mem9-on-aws/${meta.stage}/`)||
      s.valueFrom.startsWith(`arn:aws:secretsmanager:${meta.region}:${meta.account}:secret:mem9-on-aws-${meta.stage}-`));
  if(definition?.taskDefinitionArn!==taskDefinition||definition.containerDefinitions?.length!==1||container.environmentFiles?.length||
    (!catalog&&container.secrets?.length!==Object.keys(expected).length)||env.MEM9_STAGE!==meta.stage||env.MEM9_DB_HOST!==meta.host||
    env.MEM9_DB_NAME!==meta.database||env.MEM9_DB_PORT!==String(meta.port)||definition.networkMode!=='awsvpc'||
    definition.runtimePlatform?.cpuArchitecture!=='ARM64'||(catalog?!legacySecretsValid:!same(Object.fromEntries((container?.secrets??[]).map(s=>[s.name,s.valueFrom])),expected))||
    (main&&!catalog&&definition.executionRoleArn!==meta.bootstrapExecutionRole)||
    (!main&&(container.entryPoint?.join()!=='node'||container.command?.join()!=='/bootstrap/operator/scripts/production-runtime-operator.mjs')))
    fail('ProductionTaskDefinitionMismatch');
  const createdAt=now(),request={operation,nonce,epoch,deadline:Math.min(createdAt+900000,deadlineMs),
    ...(target?{target}:{}),...(verification_hash?{verification_hash}:{}),...(task_definition?{task_definition}:{})};
  if(!/^[a-f0-9]{32}$/.test(nonce??'')||!Number.isSafeInteger(epoch)||epoch<1||request.deadline<=createdAt+30000)fail('InvalidProductionInvocation');
  const invocation=randomUUID().replaceAll('-',''),path=`/mem9-on-aws/${meta.stage}/runtime/production-invocations/${invocation}`;
  const journal={version:1,stage:meta.stage,invocation,createdAt,taskDefinition,container:containerName,request,
    taskRoleArn:definition.taskRoleArn,executionRoleArn:definition.executionRoleArn};
  await send(clients.ssm,new PutParameterCommand({Name:path,Type:'SecureString',Value:JSON.stringify(journal),Overwrite:false}));
  const launched=await send(clients.ecs,new RunTaskCommand({cluster:meta.clusterArn,taskDefinition,launchType:'FARGATE',count:1,clientToken:invocation,
    networkConfiguration:{awsvpcConfiguration:{subnets:meta.subnets,securityGroups:[meta.securityGroup],assignPublicIp:'DISABLED'}},
    overrides:{containerOverrides:[{name:containerName,environment:[{name:'MEM9_BOOTSTRAP_OPERATION',value:'production-runtime'},
      {name:'MEM9_RUNTIME_INVOCATION',value:invocation},{name:'MEM9_PRODUCTION_RUNTIME_REQUEST',value:JSON.stringify(request)}]}]}}));
  if(launched.failures?.length||launched.tasks?.length!==1)fail('ProductionInvocationRejected');
  journal.taskArn=launched.tasks[0].taskArn;
  await send(clients.ssm,new PutParameterCommand({Name:path,Type:'SecureString',Value:JSON.stringify(journal),Overwrite:true}));
  const stopped=await observeInvocation(clients,meta,journal,{sleep,now});
  if(stopped.stopCode==='TaskFailedToStart'&&/^ResourceInitializationError/i.test(stopped.stoppedReason??'')&&
    /secret|ssm|parameter/i.test(stopped.stoppedReason))fail('ProductionSecretInjectionFailed');
  const opts=container.logConfiguration?.options;
  if(!opts?.['awslogs-group']||!opts['awslogs-stream-prefix'])fail('ProductionLogConfigurationMissing');
  let terminal;
  for(let attempt=0;attempt<12&&!terminal;attempt++){
    let nextToken;const results=[],seen=new Set();
    for(let page=0;page<30;page++){
      const log=await send(clients.logs,new FilterLogEventsCommand({logGroupName:opts['awslogs-group'],
        logStreamNames:[opts['awslogs-stream-prefix']+'/'+containerName+'/'+journal.taskArn.split('/').at(-1)],limit:1000,nextToken}));
      for(const row of log.events??[]){
        if(row.eventId&&seen.has(row.eventId))continue;if(row.eventId)seen.add(row.eventId);
        try{const value=JSON.parse(row.message);if(value.event==='production_runtime')results.push(value);}catch{}
      }
      if(!log.nextToken||log.nextToken===nextToken)break;
      if(page===29)fail('ProductionLogCoverageIncomplete');nextToken=log.nextToken;
    }
    if(results.length>1)fail('ProductionResultAmbiguous');terminal=results[0];if(!terminal)await sleep(5000);
  }
  if(stopped.containers?.find(c=>c.name===containerName)?.exitCode!==0||terminal?.outcome!=='complete'||terminal.nonce!==nonce||terminal.operation!==operation)
    fail(terminal?.sqlState==='42501'?'ProductionDatabasePermissionDenied':'ProductionOperationFailed');
  if(operation==='extension-catalog'){
    if(terminal.target?.stage!==meta.stage||terminal.target.host!==meta.host||terminal.target.database!==meta.database)fail('ExtensionCatalogTargetMismatch');
    validateExtensionCatalog(terminal.catalog);
    await send(clients.ssm,new DeleteParameterCommand({Name:path}));
    return terminal.catalog;
  }
  const state=terminal.state;
  if(operation==='inspect-preparation'&&state===null){
    await send(clients.ssm,new DeleteParameterCommand({Name:path}));return null;
  }
  validateRolloutIdentity(state?.identity);
  if(state.operation_nonce!==nonce||state.identity.stage!==meta.stage||state.identity.database!==meta.database||state.identity.clusterArn!==meta.clusterArn||state.identity.runtimeCredentialArn!==meta.runtimeCredential)
    fail('ProductionResultTargetMismatch');
  await send(clients.ssm,new DeleteParameterCommand({Name:path}));
  progress({operation,phase:state.phase,status:state.status,epoch:state.epoch});return state;
}

export async function cancelProductionInvocations(clients,meta,{now=Date.now,sleep=delay,deadlineMs=Infinity}={}){
  const journals=[];let NextToken;
  for(let page=0;page<100;page++){
    const response=await send(clients.ssm,new GetParametersByPathCommand({Path:`/mem9-on-aws/${meta.stage}/runtime/production-invocations/`,
      Recursive:false,WithDecryption:true,MaxResults:10,NextToken}));
    for(const parameter of response.Parameters??[]){
      let j;try{j=JSON.parse(parameter.Value);}catch{fail('InvalidProductionJournal');}
      if(j.version!==1||j.stage!==meta.stage||!/^[a-f0-9]{32}$/.test(j.invocation??'')||
        !Number.isSafeInteger(j.request?.deadline)||j.request.deadline<=j.createdAt||j.request.deadline>j.createdAt+900000||
        !Number.isSafeInteger(j.createdAt)||j.createdAt>now()+30000||
        parameter.Name!==`/mem9-on-aws/${meta.stage}/runtime/production-invocations/${j.invocation}`||
        !j.taskDefinition?.startsWith(`arn:aws:ecs:${meta.region}:${meta.account}:task-definition/${meta.cluster}-`)||
        !['Mem9Bootstrap','TransitionMem9Bootstrap'].includes(j.container))fail('InvalidProductionJournal');
      journals.push({path:parameter.Name,journal:j});
    }
    if(!response.NextToken)break;
    if(response.NextToken===NextToken||page===99)fail('ProductionJournalInventoryIncomplete');NextToken=response.NextToken;
  }
  for(const {path,journal} of journals){
    const until=Math.min(deadlineMs,Math.max(now()+60000,journal.request.deadline+60000));let terminal=false;
    while(now()<until){
      const arns=new Set();
      for(const desiredStatus of ['RUNNING','STOPPED']){
        let nextToken;
        for(let page=0;page<100;page++){
          const r=await send(clients.ecs,new ListTasksCommand({cluster:meta.clusterArn,desiredStatus,maxResults:100,nextToken}));
          for(const arn of r.taskArns??[])arns.add(arn);
          if(!r.nextToken)break;if(r.nextToken===nextToken||page===99)fail('ProductionTaskInventoryIncomplete');nextToken=r.nextToken;
        }
      }
      const tasks=[];const ids=[...arns];
      for(let i=0;i<ids.length;i+=100){const r=await send(clients.ecs,new DescribeTasksCommand({cluster:meta.clusterArn,tasks:ids.slice(i,i+100)}));
        if(r.failures?.length)fail('ProductionTaskObservationFailed');tasks.push(...(r.tasks??[]));}
      const owned=tasks.filter(t=>ownsProductionInvocation(t,meta,journal));
      for(const t of owned)if(t.lastStatus!=='STOPPED')await send(clients.ecs,new StopTaskCommand({cluster:meta.clusterArn,task:t.taskArn,reason:'Production runtime invocation recovery'}));
      if(owned.length&&owned.every(t=>t.lastStatus==='STOPPED')){terminal=true;break;}
      if(!owned.length&&now()>=journal.request.deadline+30000){terminal=true;break;}
      await sleep(5000);
    }
    if(!terminal)fail('ProductionInvocationCancellationIncomplete');
  }
  // Task termination alone is not database reconciliation. The coordinator
  // acknowledges these only after cancelling the recorded backend and committing
  // a recovery epoch (or proving a pre-ledger preparation has stopped).
  return journals;
}

export async function acknowledgeProductionCancellation(clients,journals){
  for(const {path} of journals)await send(clients.ssm,new DeleteParameterCommand({Name:path}));
}
