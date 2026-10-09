import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {parseCanaryFixtureIdentity,fixtureCaseNames} from '../canary-fixture-runner.mjs';
import {verifyCanaryFixtureEvidence} from './production-canary-fixture-evidence.mjs';
import {controlLaunchPolicy} from './production-nonroot-launch.mjs';
const fail=()=>{throw Error('CanaryFixtureTaskInvalid');};
const digest=value=>/^sha256:[a-f0-9]{64}$/.test(value??'');
const names=['CanaryPostgres','Mem9CanaryFixture'];
const same=(a,b)=>hash(a)===hash(b);

export function createCanaryFixtureDefinition(meta,images,identity){
  parseCanaryFixtureIdentity(JSON.stringify(identity));
  if(!/^pr-[1-9][0-9]*$/.test(meta.stage??'')||identity.stage!==meta.stage||!/^\d{12}$/.test(meta.account??'')||
    !/^[a-z0-9-]+$/.test(meta.region??'')||!meta.cluster?.startsWith('mem9-on-aws-'+meta.stage+'-')||!/^[-a-zA-Z0-9]+$/.test(meta.cluster)||
    meta.clusterArn!==`arn:aws:ecs:${meta.region}:${meta.account}:cluster/${meta.cluster}`||
    !meta.executionRoleArn?.startsWith(`arn:aws:iam::${meta.account}:role/`)||
    !new RegExp(`^mem9-on-a(?:ws|w)?-${meta.stage}-.*Mem9BootstrapExecutionRole-[a-zA-Z0-9-]+$`).test(meta.executionRoleArn.split('/').at(-1))||
    !meta.logGroup?.startsWith('/sst/')||!meta.logGroup.includes('/'+meta.cluster+'/'))fail();
  const prefix=`${meta.account}.dkr.ecr.${meta.region}.amazonaws.com/mem9-on-aws/preview/bootstrap@`;
  for(const image of [images.runner,images.database])if(!image||!digest(image.rootDigest)||!digest(image.arm64Digest)||image.rootDigest===image.arm64Digest||image.image!==prefix+image.rootDigest)fail();
  if(images.runner.rootDigest===images.database.rootDigest)fail();
  const common={essential:true,readonlyRootFilesystem:false,stopTimeout:30,linuxParameters:{capabilities:{drop:['ALL']}},
    portMappings:[],mountPoints:[],volumesFrom:[],secrets:[],systemControls:[],
    logConfiguration:{logDriver:'awslogs',options:{'awslogs-region':meta.region,'awslogs-group':meta.logGroup,
      'awslogs-stream-prefix':'canary-fixture-'+identity.nonce,mode:'blocking'}}};
  return {family:meta.cluster+'-CanaryFixture-'+identity.nonce,networkMode:'awsvpc',requiresCompatibilities:['FARGATE'],
    runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},executionRoleArn:meta.executionRoleArn,cpu:'1024',memory:'2048',volumes:[],
    containerDefinitions:[
      controlLaunchPolicy('canary-fixture',{...structuredClone(common),name:'Mem9CanaryFixture',image:images.runner.image,user:'1000:1000',cpu:768,memory:1024,
        entryPoint:['node'],command:['/bootstrap/operator/scripts/canary-fixture-runner.mjs'],
        environment:[{name:'MEM9_STAGE',value:meta.stage},{name:'MEM9_CANARY_FIXTURE_IDENTITY',value:JSON.stringify(identity)}],
        dependsOn:[{containerName:'CanaryPostgres',condition:'HEALTHY'}]}),
      {...structuredClone(common),name:'CanaryPostgres',image:images.database.image,user:'999:999',cpu:256,memory:1024,
        entryPoint:['docker-entrypoint.sh'],command:['postgres','-c','listen_addresses=127.0.0.1','-c','hba_file=/fixture-pg-hba.conf','-c','log_min_error_statement=panic','-c','log_error_verbosity=terse'],environment:[],
        healthCheck:{command:['CMD','pg_isready','-h','127.0.0.1','-U','postgres','-d','runtime_credentials_test'],interval:5,timeout:5,retries:3,startPeriod:30}},
    ],tags:[{key:'Project',value:'mem9-on-aws'},{key:'Stage',value:meta.stage},{key:'Purpose',value:'canary-continuation-fixture'},{key:'Operation',value:identity.nonce}]};
}

function normalizedDefinition(value){
  const copy=structuredClone(value);
  for(const key of ['taskDefinitionArn','revision','status','registeredAt','registeredBy','deregisteredAt','compatibilities','requiresAttributes','tags'])delete copy[key];
  if(copy.taskRoleArn==='')delete copy.taskRoleArn;
  if(copy.enableFaultInjection===false)delete copy.enableFaultInjection;
  if(copy.placementConstraints?.length===0)delete copy.placementConstraints;
  copy.containerDefinitions=copy.containerDefinitions.map(c=>{
    if(Array.isArray(c.linuxParameters?.capabilities?.add)&&c.linuxParameters.capabilities.add.length===0)delete c.linuxParameters.capabilities.add;
    for(const key of ['environmentFiles','dependsOn','resourceRequirements','ulimits'])if(c[key]?.length===0)delete c[key];
    for(const key of ['privileged','interactive','pseudoTerminal'])if(c[key]===false)delete c[key];
    c.environment?.sort((a,b)=>a.name.localeCompare(b.name));return c;
  }).sort((a,b)=>a.name.localeCompare(b.name));
  return copy;
}
export function verifyCanaryFixtureDefinition(actual,expected,meta){
  if(!actual||!Number.isSafeInteger(actual.revision)||actual.revision<1||!['ACTIVE','INACTIVE'].includes(actual.status)||
    actual.taskDefinitionArn!==`arn:aws:ecs:${meta.region}:${meta.account}:task-definition/${expected.family}:${actual.revision}`||
    !same(normalizedDefinition(actual),normalizedDefinition(expected)))fail();
  return actual.taskDefinitionArn;
}
export function ownsCanaryFixtureTask(task,definitionArn,meta){
  const prefix=`arn:aws:ecs:${meta.region}:${meta.account}:task/${meta.cluster}/`;
  return task?.clusterArn===meta.clusterArn&&task.taskDefinitionArn===definitionArn&&task.taskArn?.startsWith(prefix)&&/^[a-f0-9]{32}$/.test(task.taskArn.slice(prefix.length));
}
export function verifyCanaryFixtureTask(task,definition,expected,meta,images){
  verifyCanaryFixtureDefinition(definition,expected,meta);
  const override=task?.overrides??{},cpu=task?.attributes?.filter(a=>a.name==='ecs.cpu-architecture');
  if(override.inferenceAcceleratorOverrides!==undefined&&(!Array.isArray(override.inferenceAcceleratorOverrides)||override.inferenceAcceleratorOverrides.length!==0))fail();
  if(!ownsCanaryFixtureTask(task,definition.taskDefinitionArn,meta)||task.lastStatus!=='STOPPED'||task.launchType!=='FARGATE'||
    task.cpu!==expected.cpu||task.memory!==expected.memory||task.enableExecuteCommand===true||task.stopCode!=='EssentialContainerExited'||
    cpu?.length!==1||cpu[0].value!=='arm64'||Object.keys(override).some(k=>!['containerOverrides','executionRoleArn','taskRoleArn','inferenceAcceleratorOverrides'].includes(k))||
    override.taskRoleArn||override.executionRoleArn&&override.executionRoleArn!==expected.executionRoleArn||
    !Array.isArray(override.containerOverrides)||
    !same([...override.containerOverrides].sort((a,b)=>String(a?.name).localeCompare(String(b?.name))),expected.containerDefinitions.map(c=>({name:c.name})).sort((a,b)=>a.name.localeCompare(b.name)))||
    !Array.isArray(task.containers)||!same(task.containers.map(c=>c.name).sort(),names))fail();
  for(const c of task.containers){
    const image=c.name==='Mem9CanaryFixture'?images.runner:images.database;
    if(c.lastStatus!=='STOPPED'||c.exitCode!==0||c.image!==image.image||![image.rootDigest,image.arm64Digest].includes(c.imageDigest))fail();
  }
  const start=new Date(task.startedAt).getTime(),end=new Date(task.stoppedAt).getTime();
  if(!Number.isSafeInteger(start)||start<1||!Number.isSafeInteger(end)||end<start)fail();
  return task;
}
export function fixtureEvidenceFromRecord(record,identity,task,now=Date.now()){
  if(record?.event!=='canary_fixture_database'||record.phase!=='complete'||record.cases!==fixtureCaseNames.length||!same(record.identity,identity)||
    !Number.isSafeInteger(record.completedMs)||record.completedMs>identity.deadlineMs||record.completedMs<new Date(task.startedAt).getTime()-5000||
    record.completedMs>new Date(task.stoppedAt).getTime()+5000)fail();
  const {deadlineMs,...source}=identity;
  const evidence={version:1,kind:'synthetic-canary-continuation',...source,databaseHash:record.databaseHash,checks:record.checks,completedMs:record.completedMs};
  verifyCanaryFixtureEvidence(evidence,source,{now});return evidence;
}
