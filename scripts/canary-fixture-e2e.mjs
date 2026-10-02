import {execFile,execFileSync} from 'node:child_process';
import {promisify} from 'node:util';
import {randomUUID} from 'node:crypto';
import {mkdtemp,open,rename,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import {ECSClient,DescribeTaskDefinitionCommand,DescribeTasksCommand,RegisterTaskDefinitionCommand,DeregisterTaskDefinitionCommand,ListTaskDefinitionsCommand,RunTaskCommand,StopTaskCommand} from '@aws-sdk/client-ecs';
import {SSMClient,GetParametersCommand,PutParameterCommand} from '@aws-sdk/client-ssm';
import {STSClient,GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {IAMClient,GetRoleCommand} from '@aws-sdk/client-iam';
import {CloudWatchLogsClient,FilterLogEventsCommand} from '@aws-sdk/client-cloudwatch-logs';
import {resolveApplicationRegion} from './lib/application-region.mjs';
import {productionCoordinatorDigest,productionSourceTree} from './run-production-runtime.mjs';
import {productionOperatorDigest} from './production-runtime-operator.mjs';
import {runtimeSchemaDigest} from './lib/runtime-credentials.mjs';
import {parseCanaryFixtureIdentity} from './canary-fixture-runner.mjs';
import {verifyCanaryFixtureImageIndex} from './lib/production-canary-material.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {createCanaryFixtureDefinition,verifyCanaryFixtureDefinition,verifyCanaryFixtureTask,ownsCanaryFixtureTask,fixtureEvidenceFromRecord} from './lib/canary-fixture-task.mjs';
import {discoverSchedulerTasks} from './consolidation-scheduler-e2e.mjs';

const execute=promisify(execFile),fail=code=>{throw Error(code);};
const send=(client,command)=>client.send(command,{abortSignal:AbortSignal.timeout(30000)});
const emit=value=>process.stdout.write(JSON.stringify({event:'canary_continuation_fixture',...value})+'\n');
const decode=value=>typeof value==='string'?JSON.parse(decodeURIComponent(value)):value;

export function createCanaryFixtureJournal(clients,{meta,identity}){
  parseCanaryFixtureIdentity(JSON.stringify(identity));
  if(meta.stage!==identity.stage)fail('CanaryFixtureJournalScope');
  const path=`/mem9-on-aws/${meta.stage}/canary-fixture/invocations/${identity.nonce}`;let previous;
  const read=async()=>{
    const result=await send(clients.ssm,new GetParametersCommand({Names:[path],WithDecryption:true}));
    const p=result.Parameters?.[0];
    if(result.InvalidParameters?.length||result.Parameters?.length!==1||p.Name!==path||p.Type!=='SecureString'||!Number.isSafeInteger(p.Version)||p.Version<1)fail('CanaryFixtureJournalUncertain');
    return p;
  };
  return {path,persist:async state=>{
    if(state.stage!==identity.stage||state.nonce!==identity.nonce||state.deadlineMs!==identity.deadlineMs)fail('CanaryFixtureJournalScope');
    const value=JSON.stringify({version:1,stage:meta.stage,region:meta.region,account:meta.account,nonce:identity.nonce,deadlineMs:identity.deadlineMs,clusterArn:meta.clusterArn,
      sourceCommit:identity.commit,sourceTree:identity.sourceTree,runId:identity.runId,runAttempt:identity.runAttempt,
      family:state.definition.family,definitionHash:hash(state.definition),runRequestHash:state.runRequest?hash(state.runRequest):undefined,
      taskDefinitionArn:state.taskDefinitionArn,taskArn:state.taskArn,knownTaskArns:state.knownTaskArns??[],phase:state.phase,
      definitionStatus:state.definitionStatus,physicalDeletionPending:state.physicalDeletionPending===true});
    if(Buffer.byteLength(value)>3500)fail('CanaryFixtureJournalTooLarge');
    if(previous){const actual=await read();if(actual.Value!==previous.value||actual.Version!==previous.version)fail('CanaryFixtureJournalChanged');}
    let response;
    try{response=await send(clients.ssmWrite,new PutParameterCommand({Name:path,Type:'SecureString',Value:value,Overwrite:!!previous}));}
    catch(error){if(error.name==='ParameterAlreadyExists')fail('CanaryFixtureJournalAlreadyExists');}
    const actual=await read(),version=previous?previous.version+1:1;
    if(actual.Value!==value||actual.Version!==version||response&&response.Version!==version)fail('CanaryFixtureJournalUncertain');
    previous={value,version};
  }};
}

export async function runCanaryFixtureTask(clients,{meta,images,identity},{persist,verifyDeployment,progress=emit,now=Date.now,sleep=delay}={}){
  if(typeof persist!=='function'||typeof verifyDeployment!=='function'||identity.deadlineMs<=now()||identity.deadlineMs>now()+720000)fail('CanaryFixtureHostConfiguration');
  const expected=createCanaryFixtureDefinition(meta,images,identity),state={version:1,stage:meta.stage,nonce:identity.nonce,deadlineMs:identity.deadlineMs,definition:expected,phase:'prepared'};
  let definition,task,record,launchUnknown=false,launchAttempted=false,primaryFailure;
  const knownTasks=new Set();
  const readDefinition=async arn=>{
    const result=await send(clients.ecs,new DescribeTaskDefinitionCommand({taskDefinition:arn,include:['TAGS']}));
    verifyCanaryFixtureDefinition(result.taskDefinition,expected,meta);
    if(hash([...(result.tags??[])].sort((a,b)=>a.key.localeCompare(b.key)))!==hash([...expected.tags].sort((a,b)=>a.key.localeCompare(b.key))))fail('CanaryFixtureTagsChanged');
    return result.taskDefinition;
  };
  const inventory=()=>discoverSchedulerTasks(clients.ecs,meta.clusterArn,t=>t.taskDefinitionArn?.startsWith(
    `arn:aws:ecs:${meta.region}:${meta.account}:task-definition/${expected.family}:`),{now,sleep});
  const findDefinition=async()=>{
    const arns=new Set();
    for(const status of ['ACTIVE','INACTIVE']){
      let nextToken;
      for(let page=0;page<30;page++){
        const r=await send(clients.ecs,new ListTaskDefinitionsCommand({familyPrefix:expected.family,status,maxResults:100,nextToken}));
        for(const arn of r.taskDefinitionArns??[])if(arn.split('/').at(-1).split(':')[0]===expected.family)arns.add(arn);
        if(!r.nextToken)break;if(r.nextToken===nextToken||page===29)fail('CanaryFixtureDefinitionInventoryIncomplete');nextToken=r.nextToken;
      }
    }
    if(arns.size!==1)fail('CanaryFixtureRegistrationUnresolved');return readDefinition([...arns][0]);
  };
  const drain=async()=>{
    const until=Math.max(now()+120000,launchUnknown?identity.deadlineMs+60000:0);let quiet=0;
    while(now()<until){
      const direct=knownTasks.size?await send(clients.ecs,new DescribeTasksCommand({cluster:meta.clusterArn,tasks:[...knownTasks]})):{tasks:[]};
      if(direct.failures?.some(f=>f.reason!=='MISSING'||!knownTasks.has(f.arn)))fail('CanaryFixtureKnownTaskUnresolved');
      const directTasks=direct.tasks??[];
      if(new Set(directTasks.map(t=>t.taskArn)).size!==directTasks.length||directTasks.some(t=>!knownTasks.has(t.taskArn)||!ownsCanaryFixtureTask(t,definition.taskDefinitionArn,meta)))fail('CanaryFixtureKnownTaskUnresolved');
      for(const current of directTasks)if(current.lastStatus!=='STOPPED')await send(clients.ecsWrite,new StopTaskCommand({cluster:meta.clusterArn,task:current.taskArn,reason:'Stop acknowledged synthetic canary fixture'}));
      const found=await inventory();
      for(const current of found){
        if(!ownsCanaryFixtureTask(current,definition.taskDefinitionArn,meta))fail('CanaryFixtureOwnershipChanged');
        knownTasks.add(current.taskArn);
        if(current.lastStatus!=='STOPPED')await send(clients.ecsWrite,new StopTaskCommand({cluster:meta.clusterArn,task:current.taskArn,reason:'Stop owned synthetic canary fixture'}));
      }
      state.knownTaskArns=[...knownTasks];
      if(knownTasks.size>1)primaryFailure??=Error('CanaryFixtureDuplicateTask');
      quiet=direct.failures?.length||directTasks.length!==knownTasks.size||directTasks.some(t=>t.lastStatus!=='STOPPED')||found.some(t=>t.lastStatus!=='STOPPED')?0:quiet+1;
      if(quiet>=3&&(!launchUnknown||now()>=identity.deadlineMs+30000))return;
      await sleep(2000);
    }
    fail('CanaryFixtureDrainUnproven');
  };
  try{
    await verifyDeployment();await persist(state);
    progress({phase:'fixture-intent',stage:meta.stage,nonce:identity.nonce,family:expected.family,deadlineMs:identity.deadlineMs});
    state.phase='registering';await persist(state);
    const registered=await send(clients.ecsWrite,new RegisterTaskDefinitionCommand(expected));
    definition=await readDefinition(registered.taskDefinition?.taskDefinitionArn);
    state.taskDefinitionArn=definition.taskDefinitionArn;state.phase='registered';await persist(state);
    progress({phase:'fixture-resource',stage:meta.stage,nonce:identity.nonce,family:expected.family,revision:definition.revision});
    await verifyDeployment();
    const request={cluster:meta.clusterArn,taskDefinition:definition.taskDefinitionArn,launchType:'FARGATE',platformVersion:'LATEST',count:1,
      clientToken:identity.nonce,startedBy:'canary-'+identity.nonce.slice(0,28),enableExecuteCommand:false,
      overrides:{containerOverrides:expected.containerDefinitions.map(c=>({name:c.name}))},
      networkConfiguration:{awsvpcConfiguration:{subnets:meta.subnets,securityGroups:[meta.securityGroup],assignPublicIp:'DISABLED'}}};
    state.runRequest=request;state.phase='launch-intent';await persist(state);
    if(now()>=identity.deadlineMs)fail('CanaryFixtureExpired');launchAttempted=true;launchUnknown=true;
    const response=await send(clients.ecsWrite,new RunTaskCommand(request));
    for(const candidate of response.tasks??[])if(ownsCanaryFixtureTask(candidate,definition.taskDefinitionArn,meta))knownTasks.add(candidate.taskArn);
    if(response.failures?.length||response.tasks?.length!==1||!ownsCanaryFixtureTask(response.tasks[0],definition.taskDefinitionArn,meta))fail('CanaryFixtureLaunchUnresolved');
    state.taskArn=response.tasks[0].taskArn;state.phase='running';launchUnknown=false;await persist(state);
    while(now()<identity.deadlineMs+60000){
      const found=await inventory();
      for(const observed of found)if(ownsCanaryFixtureTask(observed,definition.taskDefinitionArn,meta))knownTasks.add(observed.taskArn);
      state.knownTaskArns=[...knownTasks];
      if(found.some(t=>!ownsCanaryFixtureTask(t,definition.taskDefinitionArn,meta)))fail('CanaryFixtureOwnershipChanged');
      if(found.length>1)fail('CanaryFixtureDuplicateTask');
      if(found.length){
        if(found[0].taskArn!==state.taskArn)fail('CanaryFixtureTaskChanged');
        if(found[0].lastStatus==='STOPPED'){task=verifyCanaryFixtureTask(found[0],definition,expected,meta,images);break;}
      }
      await sleep(5000);
    }
    if(!task)fail('CanaryFixtureDeadline');
    const stream='canary-fixture-'+identity.nonce+'/Mem9CanaryFixture/'+task.taskArn.split('/').at(-1);
    for(let attempt=0;attempt<12&&!record;attempt++){
      const records=[],events=new Set();let nextToken;
      for(let page=0;page<30;page++){
        const r=await send(clients.logs,new FilterLogEventsCommand({logGroupName:meta.logGroup,logStreamNames:[stream],nextToken}));
        for(const e of r.events??[]){
          if(e.eventId&&events.has(e.eventId))continue;if(e.eventId)events.add(e.eventId);
          try{const value=JSON.parse(e.message);if(value.event==='canary_fixture_database'&&value.phase==='complete')records.push(value);}catch{}
        }
        if(!r.nextToken||r.nextToken===nextToken)break;if(page===29)fail('CanaryFixtureLogInventoryIncomplete');nextToken=r.nextToken;
      }
      if(records.length>1)fail('CanaryFixtureEvidenceAmbiguous');record=records[0];if(!record)await sleep(5000);
    }
    fixtureEvidenceFromRecord(record,identity,task,now());await verifyDeployment();state.phase='verified';await persist(state);
  }catch(error){primaryFailure=error;}
  try{
    if(state.phase!=='prepared'){
      definition??=await findDefinition();
      state.taskDefinitionArn=definition.taskDefinitionArn;state.knownTaskArns=[...knownTasks];
      if(launchAttempted)await drain();
      if((await readDefinition(definition.taskDefinitionArn)).status==='ACTIVE')await send(clients.ecsWrite,new DeregisterTaskDefinitionCommand({taskDefinition:definition.taskDefinitionArn}));
      if((await readDefinition(definition.taskDefinitionArn)).status!=='INACTIVE')fail('CanaryFixtureDeregistrationUnproven');
      state.definitionStatus='INACTIVE';state.physicalDeletionPending=true;state.phase='cleaned';await persist(state);
      progress({phase:'fixture-cleanup',stage:meta.stage,nonce:identity.nonce,family:expected.family,revision:definition.revision,
        definitionStatus:'INACTIVE',physicalDeletionPending:true,journalParameter:state.journalParameter});
    }
  }catch(error){state.phase='cleanup-pending';await persist(state);throw Error('CanaryFixtureCleanupPending',{cause:error});}
  if(primaryFailure)throw primaryFailure;
  return {evidence:fixtureEvidenceFromRecord(record,identity,task,now()),resources:{family:expected.family,revision:definition.revision,
    nonce:identity.nonce,definitionStatus:'INACTIVE',physicalDeletionPending:true}};
}

async function main(){
  const env=process.env,stage=env.STAGE,commit=env.MEM9_FIXTURE_SOURCE_COMMIT;
  if(env.GITHUB_EVENT_NAME!=='pull_request'||env.GITHUB_REPOSITORY!=='zxkane/mem9-on-aws'||!/^pr-[1-9][0-9]*$/.test(stage??'')||
    !/^[a-f0-9]{40}$/.test(commit??'')||!/^pr-[a-f0-9]{7}$/.test(env.EXPECTED_IMAGE_TAG??''))fail('CanaryFixturePreviewRequired');
  const region=await resolveApplicationRegion();if(env.AWS_REGION&&env.AWS_REGION!==region)fail('CanaryFixtureRegionMismatch');
  const sourceTree=await productionSourceTree();
  if(execFileSync('git',['rev-parse',commit+'^{tree}'],{encoding:'utf8',timeout:10000}).trim()!==sourceTree||
    execFileSync('git',['status','--porcelain','--untracked-files=no'],{encoding:'utf8',timeout:10000}).trim())fail('CanaryFixtureSourceMismatch');
  const identity=parseCanaryFixtureIdentity(JSON.stringify({stage,commit,sourceTree,runId:env.GITHUB_RUN_ID,runAttempt:Number(env.GITHUB_RUN_ATTEMPT),
    coordinatorDigest:await productionCoordinatorDigest(),operatorDigest:await productionOperatorDigest(),schemaDigest:await runtimeSchemaDigest('docker/bootstrap'),
    nonce:randomUUID().replaceAll('-',''),deadlineMs:Date.now()+720000}));
  const clients={ecs:new ECSClient({region,maxAttempts:3}),ecsWrite:new ECSClient({region,maxAttempts:1}),ssm:new SSMClient({region}),ssmWrite:new SSMClient({region,maxAttempts:1}),
    sts:new STSClient({region}),iam:new IAMClient({region:'us-east-1'}),logs:new CloudWatchLogsClient({region})};
  const directory=await mkdtemp(join(tmpdir(),'mem9-canary-fixture-host-'));
  try{
    const account=(await send(clients.sts,new GetCallerIdentityCommand({}))).Account;
    if(!/^\d{12}$/.test(account??''))fail('CanaryFixtureAccountInvalid');
    const prefix=`/mem9-on-aws/${stage}/bootstrap/`,names=['cluster-name','task-def-arn','task-sg-id','subnet-ids'].map(k=>prefix+k);
    const metadata=async()=>{
      const r=await send(clients.ssm,new GetParametersCommand({Names:names}));
      if(r.InvalidParameters?.length||r.Parameters?.length!==names.length||new Set(r.Parameters.map(p=>p.Name)).size!==names.length||
        r.Parameters.some(p=>!names.includes(p.Name)||typeof p.Value!=='string'||!Number.isSafeInteger(p.Version)||p.Version<1))fail('CanaryFixtureMetadataMissing');
      return r.Parameters.map(({Name,Value,Version})=>({Name,Value,Version})).sort((a,b)=>a.Name.localeCompare(b.Name));
    };
    const initial=await metadata(),values=Object.fromEntries(initial.map(p=>[p.Name.slice(prefix.length),p.Value])),cluster=values['cluster-name'];
    const base=(await send(clients.ecs,new DescribeTaskDefinitionCommand({taskDefinition:values['task-def-arn']}))).taskDefinition;
    const container=base?.containerDefinitions?.[0],baseArn=`arn:aws:ecs:${region}:${account}:task-definition/${cluster}-Mem9Bootstrap:`;
    if(!base?.taskDefinitionArn?.startsWith(baseArn)||base.status!=='ACTIVE'||base.containerDefinitions?.length!==1||container.name!=='Mem9Bootstrap'||
      container.environment?.filter(e=>e.name==='MEM9_STAGE'&&e.value===stage).length!==1||!/^sg-[a-f0-9]+$/.test(values['task-sg-id']??''))fail('CanaryFixtureBootstrapMismatch');
    const repo=`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/preview/bootstrap`,roots={bootstrap:env.EXPECTED_BOOTSTRAP_DIGEST,runner:env.EXPECTED_FIXTURE_RUNNER_DIGEST,database:env.EXPECTED_FIXTURE_DATABASE_DIGEST};
    if(Object.values(roots).some(d=>!/^sha256:[a-f0-9]{64}$/.test(d??''))||new Set(Object.values(roots)).size!==3||
      ![repo+':'+env.EXPECTED_IMAGE_TAG,repo+'@'+roots.bootstrap].includes(container.image))fail('CanaryFixtureImageMismatch');
    const batch=async selector=>JSON.parse((await execute('aws',['ecr','batch-get-image','--region',region,'--registry-id',account,'--repository-name','mem9-on-aws/preview/bootstrap',
      '--image-ids',selector,'--output','json'],{timeout:30000,maxBuffer:4194304})).stdout);
    verifyCanaryFixtureImageIndex(await batch('imageTag='+env.EXPECTED_IMAGE_TAG),{account,repositoryName:'mem9-on-aws/preview/bootstrap',rootDigest:roots.bootstrap});
    const images={};for(const kind of ['runner','database']){
      const image=verifyCanaryFixtureImageIndex(await batch('imageDigest='+roots[kind]),{account,repositoryName:'mem9-on-aws/preview/bootstrap',rootDigest:roots[kind]});
      images[kind]={...image,image:repo+'@'+roots[kind]};
    }
    const meta={account,region,stage,cluster,clusterArn:`arn:aws:ecs:${region}:${account}:cluster/${cluster}`,executionRoleArn:base.executionRoleArn,
      logGroup:container.logConfiguration?.options?.['awslogs-group'],subnets:values['subnet-ids'].split(','),securityGroup:values['task-sg-id']};
    if(!meta.subnets.length||meta.subnets.length>16||new Set(meta.subnets).size!==meta.subnets.length||meta.subnets.some(s=>!/^subnet-[a-f0-9]+$/.test(s)))fail('CanaryFixtureNetworkMismatch');
    createCanaryFixtureDefinition(meta,images,identity);
    const role=(await send(clients.iam,new GetRoleCommand({RoleName:meta.executionRoleArn.split('/').at(-1)}))).Role;
    if(role?.Arn!==meta.executionRoleArn||role.PermissionsBoundary?.PermissionsBoundaryArn!==`arn:aws:iam::${account}:policy/mem9-on-aws-workload-boundary`)fail('CanaryFixtureExecutionRoleMismatch');
    const trust=decode(role.AssumeRolePolicyDocument),statement=trust?.Statement;
    if(trust.Version!=='2012-10-17'||!Array.isArray(statement)||statement.length!==1||statement[0].Effect!=='Allow'||
      statement[0].Action!=='sts:AssumeRole'||hash(statement[0].Principal)!==hash({Service:'ecs-tasks.amazonaws.com'})||
      Object.keys(statement[0]).some(k=>!['Sid','Effect','Action','Principal','Condition'].includes(k))||
      statement[0].Condition&&hash(statement[0].Condition)!==hash({StringEquals:{'aws:SourceAccount':account},ArnLike:{'aws:SourceArn':`arn:aws:ecs:${region}:${account}:*`}}))fail('CanaryFixtureTrustMismatch');
    const journal=createCanaryFixtureJournal(clients,{meta,identity});
    const persist=async state=>{
      state.journalParameter=journal.path;
      const file=await open(join(directory,'state.tmp'),'w',0o600);
      try{await file.writeFile(JSON.stringify(state));await file.sync();}finally{await file.close();}
      await rename(join(directory,'state.tmp'),join(directory,'state.local.json'));
      const dir=await open(directory,'r');try{await dir.sync();}finally{await dir.close();}
      await journal.persist(state);
    };
    const result=await runCanaryFixtureTask(clients,{meta,images,identity},{persist,verifyDeployment:async()=>{if(hash(await metadata())!==hash(initial))fail('CanaryFixtureDeploymentChanged');}});
    emit({phase:'complete',...result});await rm(directory,{recursive:true,force:true});
  }finally{Object.values(clients).forEach(client=>client.destroy());}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(error=>{
  emit({phase:'failed',errorClass:/^CanaryFixture[A-Za-z]+$/.test(error.message??'')?error.message:'CanaryFixtureFailed'});process.exitCode=1;
});
