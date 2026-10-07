import {randomUUID,createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import {SSMClient,GetParametersCommand,GetParametersByPathCommand,PutParameterCommand,DeleteParameterCommand} from '@aws-sdk/client-ssm';
import {ECSClient,DescribeTaskDefinitionCommand,RunTaskCommand,DescribeTasksCommand,StopTaskCommand,ListTasksCommand} from '@aws-sdk/client-ecs';
import {CloudWatchLogsClient,FilterLogEventsCommand} from '@aws-sdk/client-cloudwatch-logs';
import {STSClient,GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {IAMClient,GetRoleCommand,GetRolePolicyCommand,ListRolePoliciesCommand,ListAttachedRolePoliciesCommand} from '@aws-sdk/client-iam';
import {resolveApplicationRegion} from './lib/application-region.mjs';
import {parseProductionConsolidationRequest} from './production-consolidation-operator.mjs';
import {productionCoordinatorDigest,productionSourceTree} from './run-production-runtime.mjs';
import {execFileSync} from 'node:child_process';
import {canaryReportDigest,canaryReportFragments} from './lib/production-canary-report.mjs';
import {loadWorkerDataRelease} from './lib/production-data-release-loader.mjs';
import {assertMaintenanceDispatch,sendMaintenanceCommand} from './lib/production-maintenance-admission.mjs';

const send=(client,command)=>client.send(command,{abortSignal:AbortSignal.timeout(30000)});
const fail=code=>{throw Error(code);};
const environment=container=>Object.fromEntries((container.environment??[]).map(e=>[e.name,e.value]));
const decode=value=>typeof value==='object'?value:JSON.parse(decodeURIComponent(value));
function canonical(value,key=''){
  if(['Action','Resource','Statement'].includes(key)&&!Array.isArray(value))value=[value];
  if(Array.isArray(value))return value.map(canonical).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
  if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).filter(k=>k!=='Sid').sort().map(k=>[k,canonical(value[k],k)]));
  return value;
}
const same=(a,b)=>JSON.stringify(canonical(a))===JSON.stringify(canonical(b));
const requestHash=value=>createHash('sha256').update(value).digest('hex');
export function productionConsolidationOverrides(name,request){
  if(!['ProdMem9Bootstrap','ControlMem9Bootstrap','PromoteMem9Bootstrap'].includes(name))fail('ProductionWorkerOperatorDefinitionMismatch');
  const encoded=JSON.stringify(request);parseProductionConsolidationRequest(encoded);
  const overrides={containerOverrides:[{name,environment:[{name:'MEM9_PRODUCTION_CONSOLIDATION_REQUEST',value:encoded},{name:'MEM9_OPERATOR_INVOCATION',value:request.invocation}]}]};
  if(Buffer.byteLength(JSON.stringify(overrides))>8192)fail('ProductionWorkerRequestTooLarge');
  return overrides;
}

export async function stopPreviousProductionAdministration(clients,meta,{now=Date.now,sleep=delay}={}){
  const path='/mem9-on-aws/prod/consolidation-runtime/invocations/',journals=[];let NextToken;
  for(let page=0;page<100;page++){
    const response=await send(clients.ssm,new GetParametersByPathCommand({Path:path,Recursive:false,WithDecryption:true,MaxResults:10,NextToken}));
    for(const parameter of response.Parameters??[]){
      let journal;try{journal=JSON.parse(parameter.Value);}catch{fail('InvalidProductionWorkerJournal');}
      if(journal.version!==1||journal.stage!=='prod'||journal.cluster!==meta.clusterArn||!/^[a-f0-9]{32}$/.test(journal.invocation??'')||
        parameter.Name!==path+journal.invocation||journal.request?.invocation!==journal.invocation||
        !/^[a-f0-9]{64}$/.test(journal.requestHash??'')||
        !Number.isSafeInteger(journal.request.deadline)||journal.request.deadline>now()+15*60000||
        !['ProdMem9Bootstrap','ControlMem9Bootstrap','PromoteMem9Bootstrap'].includes(journal.container)||
        !journal.taskDefinition?.startsWith(`arn:aws:ecs:${meta.region}:${meta.account}:task-definition/${meta.cluster}-${journal.container}:`))fail('InvalidProductionWorkerJournal');
      journals.push({name:parameter.Name,journal});
    }
    if(!response.NextToken)break;if(response.NextToken===NextToken||page===99)fail('ProductionWorkerJournalInventoryIncomplete');NextToken=response.NextToken;
  }
  for(const {name,journal} of journals){
    const until=Math.max(now()+60000,journal.request.deadline+60000);let done=false;
    while(now()<until){
      const ids=new Set(journal.taskArn?[journal.taskArn]:[]);
      for(const desiredStatus of ['RUNNING','STOPPED']){
        let nextToken;
        for(let page=0;page<100;page++){
          const result=await send(clients.ecs,new ListTasksCommand({cluster:meta.clusterArn,desiredStatus,maxResults:100,nextToken}));
          for(const arn of result.taskArns??[])ids.add(arn);
          if(!result.nextToken)break;if(result.nextToken===nextToken||page===99)fail('ProductionWorkerTaskInventoryIncomplete');nextToken=result.nextToken;
        }
      }
      const matches=[];const all=[...ids];
      for(let i=0;i<all.length;i+=100){
        const result=await send(clients.ecs,new DescribeTasksCommand({cluster:meta.clusterArn,tasks:all.slice(i,i+100)}));
        if(result.failures?.length)fail('ProductionWorkerTaskObservationFailed');
        for(const task of result.tasks??[]){
          const overrides=task.overrides?.containerOverrides,container=overrides?.[0];
          if(task.clusterArn===meta.clusterArn&&task.taskDefinitionArn===journal.taskDefinition&&overrides?.length===1&&container.name===journal.container&&
            !container.command?.length&&!container.environmentFiles?.length&&container.environment?.length===2&&
            environment(container).MEM9_OPERATOR_INVOCATION===journal.invocation&&
            typeof environment(container).MEM9_PRODUCTION_CONSOLIDATION_REQUEST==='string'&&requestHash(environment(container).MEM9_PRODUCTION_CONSOLIDATION_REQUEST)===journal.requestHash&&
            (!task.overrides.taskRoleArn||task.overrides.taskRoleArn===journal.taskRoleArn)&&
            (!task.overrides.executionRoleArn||task.overrides.executionRoleArn===journal.executionRoleArn))matches.push(task);
        }
      }
      for(const task of matches)if(task.lastStatus!=='STOPPED')await send(clients.ecs,new StopTaskCommand({cluster:meta.clusterArn,task:task.taskArn,reason:'Recover prior production administration'}));
      if(matches.length&&matches.every(task=>task.lastStatus==='STOPPED')){done=true;break;}
      if(!matches.length&&now()>=journal.request.deadline+30000){done=true;break;}
      await sleep(5000);
    }
    if(!done)fail('ProductionWorkerCancellationIncomplete');
    await send(clients.ssm,new DeleteParameterCommand({Name:name}));
  }
}
async function verifyOperatorRole(clients,meta,definition,name,secrets,kind,executionPolicyName='ProductionWorkerOperator'){
  const roleArn=definition[kind+'RoleArn'],scope=`arn:aws:iam::${meta.account}:role/`;
  const suffix=name+(kind==='execution'?'Execution':'Task')+'Role-';
  if(!roleArn?.startsWith(scope)||!/^mem9-on-a(?:ws|w)?-prod-/.test(roleArn.slice(scope.length))||!roleArn.includes('-'+suffix))fail('ProductionOperatorRoleScope');
  const RoleName=roleArn.split('/').at(-1),role=(await send(clients.iam,new GetRoleCommand({RoleName}))).Role;
  if(role?.Arn!==roleArn||role.PermissionsBoundary?.PermissionsBoundaryArn!==`arn:aws:iam::${meta.account}:policy/mem9-on-aws-workload-boundary`)fail('ProductionOperatorBoundaryMismatch');
  const trust={Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'sts:AssumeRole',Principal:{Service:'ecs-tasks.amazonaws.com'},Condition:{
    StringEquals:{'aws:SourceAccount':meta.account},ArnLike:{'aws:SourceArn':`arn:aws:ecs:${meta.region}:${meta.account}:*`}}}]};
  if(!same(decode(role.AssumeRolePolicyDocument),trust))fail('ProductionOperatorTrustMismatch');
  const inline=await send(clients.iam,new ListRolePoliciesCommand({RoleName}));
  const attached=await send(clients.iam,new ListAttachedRolePoliciesCommand({RoleName}));
  const policyName=kind==='execution'?executionPolicyName:'inline';
  const managed=kind==='execution'?['arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy']:[];
  if(inline.IsTruncated||attached.IsTruncated||!same(inline.PolicyNames,[policyName])||
    !same(attached.AttachedPolicies?.map(p=>p.PolicyArn),managed))fail('ProductionOperatorPolicyMismatch');
  const actual=decode((await send(clients.iam,new GetRolePolicyCommand({RoleName,PolicyName:policyName}))).PolicyDocument);
  const references=Object.values(secrets),expected={Version:'2012-10-17',Statement:kind==='execution'?[
    {Effect:'Allow',Action:['ssm:GetParameters'],Resource:references},
    {Effect:'Allow',Action:['kms:Decrypt'],Resource:'*',Condition:{StringEquals:{'kms:ViaService':`ssm.${meta.region}.amazonaws.com`,'kms:EncryptionContext:PARAMETER_ARN':references}}},
  ]:[{Effect:'Allow',Action:['ssmmessages:CreateControlChannel','ssmmessages:CreateDataChannel','ssmmessages:OpenControlChannel','ssmmessages:OpenDataChannel'],Resource:'*'}]};
  if(!same(actual,expected))fail('ProductionOperatorPolicyMismatch');
}

export async function verifyProductionTaskRoles(clients,meta,definition,name,secrets,executionPolicyName='ProductionWorkerOperator'){
  for(const kind of ['task','execution'])await verifyOperatorRole(clients,meta,definition,name,secrets,kind,executionPolicyName);
}

export function validateProductionWorkerTarget(meta,{region,account}){
  if(![1,2,3].includes(meta?.version)||meta.stage!=='prod'||meta.region!==region||meta.account!==account||
    !meta.cluster?.startsWith('mem9-on-aws-prod-')||!/^[A-Za-z0-9-]+$/.test(meta.cluster)||meta.clusterArn!==`arn:aws:ecs:${region}:${account}:cluster/${meta.cluster}`||
    !meta.host?.startsWith('mem9-on-aws-prod-')||!meta.host.endsWith(`.${region}.rds.amazonaws.com`)||
    !/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(meta.database??'')||!/^[a-f0-9]{64}$/.test(meta.generation??'')||
    !Number.isInteger(meta.port)||meta.port<1||meta.port>65535||!Array.isArray(meta.subnets)||!meta.subnets.length||meta.subnets.length>16||
    meta.subnets.some(s=>!/^subnet-[a-f0-9]+$/.test(s))||!/^sg-[a-f0-9]+$/.test(meta.securityGroup??'')||
    !/^mem9-[a-f0-9]{7}$/.test(meta.sourceTag??'')||
    !meta.workerImage?.startsWith(`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/llm-proxy@sha256:`)||!/@sha256:[a-f0-9]{64}$/.test(meta.workerImage))fail('InvalidProductionWorkerManifest');
  const arn=`arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/prod/`;
  for(const [key,path] of Object.entries({administratorCredential:'runtime/schema-administrator-credential',plannerCredential:'consolidation-runtime/planner-credential',
    executorCredential:'consolidation-runtime/executor-credential',targetsParameter:'maintenance/targets'}))if(meta[key]!==arn+path)fail('ProductionWorkerCredentialReferenceMismatch');
  if(meta.version>=2){
    if(!/^mem9-[a-f0-9]{7}$/.test(meta.controlSourceTag??'')||!/^[a-f0-9]{64}$/.test(meta.dataReleaseHash??'')||
      meta.dataReleaseParameter!=='/mem9-on-aws/prod/consolidation-runtime/data-release')fail('InvalidProductionDataReleaseManifest');
    if(meta.version===3&&(!Number.isSafeInteger(meta.dataReleaseParameterVersion)||meta.dataReleaseParameterVersion<1)||meta.version===2&&meta.dataReleaseParameterVersion!==undefined)fail('InvalidProductionDataReleaseManifest');
  }else if(meta.dataReleaseHash!==undefined||meta.dataReleaseParameter!==undefined||meta.dataReleaseParameterVersion!==undefined||meta.controlSourceTag!==undefined&&meta.controlSourceTag!==meta.sourceTag)fail('InvalidProductionDataReleaseManifest');
  return meta;
}

export async function runProductionConsolidationTask(clients,{region,operation,dailyRows,basisPoints,canaryReport,benchmarkRefs,backendBinding,attemptId,parentProofHash,compatibility},{now=Date.now,sleep=delay}={}){
  const account=(await send(clients.sts,new GetCallerIdentityCommand({}))).Account;
  const prefix='/mem9-on-aws/prod/',manifestName=prefix+'consolidation-runtime/operator-manifest';
  const response=await send(clients.ssm,new GetParametersCommand({Names:[manifestName],WithDecryption:true}));
  if(response.InvalidParameters?.length||response.Parameters?.length!==1)fail('ProductionWorkerManifestMissing');
  let meta;try{meta=JSON.parse(response.Parameters[0].Value);}catch{fail('InvalidProductionWorkerManifest');}
  validateProductionWorkerTarget(meta,{region,account});
  const kind=operation==='prepare'?'provision':operation==='promote'?'promotion':'control',
    name=kind==='provision'?'ProdMem9Bootstrap':kind==='promotion'?'PromoteMem9Bootstrap':'ControlMem9Bootstrap',target=meta.operators?.[kind];
  if(target?.containerName!==name||!target.taskDefinition?.startsWith(`arn:aws:ecs:${region}:${account}:task-definition/${meta.cluster}-${name}:`)||
    !/^[1-9][0-9]*$/.test(target.taskDefinition.split(':').at(-1))||
    !target.image?.startsWith(`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/bootstrap@sha256:`)||!/@sha256:[a-f0-9]{64}$/.test(target.image))fail('ProductionWorkerOperatorMismatch');
  const definition=(await send(clients.ecs,new DescribeTaskDefinitionCommand({taskDefinition:target.taskDefinition}))).taskDefinition;
  const container=definition?.containerDefinitions?.[0],env=container?environment(container):{};
  const secrets={MEM9_DB_SECRET:meta.administratorCredential,...(kind==='provision'?{MEM9_PLANNER_DB_SECRET:meta.plannerCredential,MEM9_EXECUTOR_DB_SECRET:meta.executorCredential,MEM9_WORKER_TARGETS:meta.targetsParameter}:
    kind==='promotion'?Object.fromEntries(Array.from({length:4},(_,index)=>['MEM9_CANARY_REPORT_'+index,`arn:aws:ssm:${region}:${account}:parameter${prefix}consolidation-runtime/canary-report-${index}`])):{})};
  const actual=Object.fromEntries((container?.secrets??[]).map(s=>[s.name,s.valueFrom]));
  if(definition?.taskDefinitionArn!==target.taskDefinition||definition.containerDefinitions?.length!==1||container.name!==name||
    definition.networkMode!=='awsvpc'||definition.runtimePlatform?.cpuArchitecture!=='ARM64'||
    container.entryPoint?.join()!=='node'||container.command?.join()!=='/bootstrap/operator/scripts/production-consolidation-operator.mjs'||container.environmentFiles?.length||
    container.image!==target.image||env.MEM9_WORKER_IMAGE!==meta.workerImage||env.MEM9_WORKER_SOURCE_TAG!==meta.sourceTag||
    (meta.controlSourceTag!==undefined&&env.MEM9_CONTROL_SOURCE_TAG!==meta.controlSourceTag)||
    (meta.version>=2&&env.MEM9_RETAINED_DATA_RELEASE_HASH!==meta.dataReleaseHash)||
    (meta.version===3&&env.MEM9_RETAINED_DATA_RELEASE_VERSION!==String(meta.dataReleaseParameterVersion))||
    env.MEM9_STAGE!=='prod'||env.MEM9_DB_HOST!==meta.host||env.MEM9_DB_NAME!==meta.database||env.MEM9_WORKER_GENERATION!==meta.generation||
    env.MEM9_DB_PORT!==String(meta.port)||env.MEM9_PRODUCTION_WORKER_OPERATOR!==kind||Object.keys(actual).length!==Object.keys(secrets).length||
    Object.entries(secrets).some(([key,value])=>actual[key]!==value))fail('ProductionWorkerOperatorDefinitionMismatch');
  await verifyProductionTaskRoles(clients,meta,definition,name,secrets);
  let acceptance;
  if(!['pause','status'].includes(operation)){
    const proof=await send(clients.ssm,new GetParametersCommand({Names:[prefix+'runtime/rehearsal-acceptance'],WithDecryption:true}));
    if(proof.InvalidParameters?.length||proof.Parameters?.length!==1)fail('ProductionWorkerRehearsalRequired');
    try{acceptance=JSON.parse(proof.Parameters[0].Value);}catch{fail('ProductionWorkerRehearsalRequired');}
    if(acceptance.sourceTree!==await productionSourceTree()||acceptance.coordinatorDigest!==await productionCoordinatorDigest())fail('ProductionWorkerReleaseEvidenceMismatch');
    const revision=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8',timeout:10000}).trim();
    if(!/^[a-f0-9]{40}$/.test(revision)||(meta.controlSourceTag??meta.sourceTag)!==`mem9-${revision.slice(0,7)}`)fail('ProductionWorkerImageRevisionMismatch');
    const mode=['prepare','plan','baseline','begin-continuation','resume-plan','canary','promote'].includes(operation)?'admission':'inspection';
    const data=await loadWorkerDataRelease(clients,meta,{controlRevision:revision,controlSourceTree:acceptance.sourceTree,mode,now:now()});
    if(data&&(acceptance.dataReleaseHash!==data.hash||env.MEM9_RETAINED_DATA_RELEASE_EXPIRES_MS!==String(data.data.expiresMs)||
      data.data.parentProofHash!==acceptance.continuation?.parentProofHash))fail('ProductionDataReleaseEvidenceMismatch');
  }
  const admission={kind:['status','inspect-canary'].includes(operation)?'target-verify':operation==='pause'?'owned-cleanup':'admin',operation,transitionRequired:compatibility?.version===3,target:{account,region,image:target.image,taskDefinitionArn:target.taskDefinition,taskRoleArn:definition.taskRoleArn,executionRoleArn:definition.executionRoleArn,
    sourceTree:acceptance?.sourceTree??null,dataReleaseHash:meta.dataReleaseHash??null,dataReleaseParameterVersion:meta.dataReleaseParameterVersion??null}};
  await assertMaintenanceDispatch(clients,{...admission,service:'ecs',api:'InspectTarget',input:{taskDefinition:target.taskDefinition}});
  if(operation!=='status')await stopPreviousProductionAdministration(clients,meta,{now,sleep});
  const invocation=randomUUID().replaceAll('-','');
  const request={operation,invocation,deadline:now()+15*60000,...(operation==='promote'?{dailyRows,basisPoints,canaryReportHash:canaryReportDigest(canaryReport)}:{}),
    ...(operation==='cleanup-benchmark'?{benchmarkRefs}:{}),...(operation==='baseline'?{backendBinding}:{}),...(acceptance?{acceptance}:{}),
    ...(attemptId!==undefined?{attemptId}:{}),...(parentProofHash!==undefined?{parentProofHash}:{}),...(compatibility!==undefined?{compatibility}:{})};
  const encoded=JSON.stringify(request),overrides=productionConsolidationOverrides(name,request);
  if(operation==='promote')for(const [index,value] of canaryReportFragments(canaryReport).entries()){
    await sendMaintenanceCommand(clients,'ssm',new PutParameterCommand({Name:prefix+`consolidation-runtime/canary-report-${index}`,Type:'SecureString',Value:value,Overwrite:true}),admission);
  }
  const journalName=prefix+'consolidation-runtime/invocations/'+invocation;
  const journal={version:1,stage:'prod',cluster:meta.clusterArn,taskDefinition:target.taskDefinition,container:name,invocation,
    request:{operation,invocation,deadline:request.deadline},requestHash:requestHash(encoded),
    taskRoleArn:definition.taskRoleArn,executionRoleArn:definition.executionRoleArn};
  if(Buffer.byteLength(JSON.stringify(journal))>3500)fail('ProductionWorkerJournalTooLarge');
  await sendMaintenanceCommand(clients,'ssm',new PutParameterCommand({Name:journalName,Type:'SecureString',Value:JSON.stringify(journal),Overwrite:false}),admission);
  const run=await sendMaintenanceCommand(clients,'ecs',new RunTaskCommand({cluster:meta.clusterArn,taskDefinition:target.taskDefinition,launchType:'FARGATE',count:1,clientToken:invocation,
    networkConfiguration:{awsvpcConfiguration:{subnets:meta.subnets,securityGroups:[meta.securityGroup],assignPublicIp:'DISABLED'}},
    overrides}),admission);
  if(run.failures?.length||run.tasks?.length!==1)fail('ProductionWorkerOperatorLaunchFailed');
  const taskArn=run.tasks[0].taskArn;
  await send(clients.ssm,new PutParameterCommand({Name:journalName,Type:'SecureString',Value:JSON.stringify({...journal,taskArn}),Overwrite:true}));
  let stopped;
  while(now()<request.deadline+60000){
    const result=await send(clients.ecs,new DescribeTasksCommand({cluster:meta.clusterArn,tasks:[taskArn]}));
    const task=result.tasks?.[0];
    const overrides=task?.overrides?.containerOverrides,override=overrides?.[0];
    if(result.failures?.length||task?.taskDefinitionArn!==target.taskDefinition||task.clusterArn!==meta.clusterArn||
      overrides?.length!==1||override.name!==name||override.command?.length||override.environmentFiles?.length||override.environment?.length!==2||
      environment(override).MEM9_OPERATOR_INVOCATION!==invocation||environment(override).MEM9_PRODUCTION_CONSOLIDATION_REQUEST!==JSON.stringify(request)||
      (task.overrides.taskRoleArn&&task.overrides.taskRoleArn!==definition.taskRoleArn)||
      (task.overrides.executionRoleArn&&task.overrides.executionRoleArn!==definition.executionRoleArn))fail('ProductionWorkerOperatorObservationFailed');
    if(task.lastStatus==='STOPPED'){stopped=task;break;}await sleep(5000);
  }
  if(!stopped){await send(clients.ecs,new StopTaskCommand({cluster:meta.clusterArn,task:taskArn,reason:'Bounded production worker administration'}));fail('ProductionWorkerOperatorDeadline');}
  const opts=container.logConfiguration?.options;let result;
  for(let attempt=0;attempt<12&&!result;attempt++){
    let nextToken;const records=[],seen=new Set();
    for(let page=0;page<30;page++){
      const logs=await send(clients.logs,new FilterLogEventsCommand({logGroupName:opts['awslogs-group'],logStreamNames:[opts['awslogs-stream-prefix']+'/'+name+'/'+taskArn.split('/').at(-1)],nextToken}));
      for(const row of logs.events??[]){
        if(row.eventId&&seen.has(row.eventId))continue;if(row.eventId)seen.add(row.eventId);
        try{const parsed=JSON.parse(row.message);if(parsed.event==='production_consolidation_operator')records.push(parsed);}catch{}
      }
      if(!logs.nextToken||logs.nextToken===nextToken)break;if(page===29)fail('ProductionWorkerLogCoverageIncomplete');nextToken=logs.nextToken;
    }
    if(records.length>1)fail('ProductionWorkerResultAmbiguous');result=records[0];
    if(!result)await sleep(5000);
  }
  if(stopped.containers?.[0]?.exitCode!==0||result?.outcome!=='complete'||result.phase!==operation||result.invocation!==invocation)fail('ProductionWorkerOperatorFailed');
  await send(clients.ssm,new DeleteParameterCommand({Name:journalName}));return result;
}

async function main(){
  const region=process.env.AWS_REGION||await resolveApplicationRegion();
  const clients={ssm:new SSMClient({region}),ecs:new ECSClient({region}),logs:new CloudWatchLogsClient({region}),sts:new STSClient({region}),iam:new IAMClient({region})};
  try{const result=await runProductionConsolidationTask(clients,{region,operation:process.argv[2],dailyRows:Number(process.argv[3]),basisPoints:Number(process.argv[4])});process.stdout.write(JSON.stringify(result)+'\n');}
  finally{Object.values(clients).forEach(client=>client.destroy());}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(()=>{
  process.stdout.write(JSON.stringify({event:'production_consolidation_operator',outcome:'failed',errorClass:'ProductionWorkerAdministrationFailed'})+'\n');process.exitCode=1;
});
