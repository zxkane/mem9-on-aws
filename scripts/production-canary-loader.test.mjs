import {describe,it,expect} from 'vitest';
import {loadProductionCanaryWorker} from './lib/production-canary-delivery.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {NONROOT_LIMITS_HASH} from './lib/production-nonroot-contracts.mjs';
import {dataLaunchPolicy} from './lib/production-nonroot-launch.mjs';

function fixture(drift,kind='executor'){
  const account='123456789012',region='ap-northeast-1',revision='a'.repeat(40),generation='b'.repeat(64),cluster='mem9-on-aws-prod-Fixture';
  const clusterArn=`arn:aws:ecs:${region}:${account}:cluster/${cluster}`,prefix=`arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/prod/`;
  const containerName='Mem9Consolidation'+(kind==='planner'?'Planner':'Executor'),taskDefinitionArn=`arn:aws:ecs:${region}:${account}:task-definition/${cluster}-${containerName}:1`;
  const operator={version:1,stage:'prod',region,account,cluster,clusterArn,generation,host:'mem9-on-aws-prod-fixture.cluster-example.ap-northeast-1.'+['rds','amazonaws','com'].join('.'),
    sourceTag:'mem9-aaaaaaa',workerImage:`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/llm-proxy@sha256:${'d'.repeat(64)}`,
    database:'mem9',port:5432,subnets:['subnet-abcd'],securityGroup:'sg-abcd',administratorCredential:prefix+'runtime/schema-administrator-credential',
    plannerCredential:prefix+'consolidation-runtime/planner-credential',executorCredential:prefix+'consolidation-runtime/executor-credential',targetsParameter:prefix+'maintenance/targets'};
  const manifest={version:1,stage:'prod',generation,clusterArn,groupName:'mem9-on-aws-prod-consolidation-fixture',
    roleArn:`arn:aws:iam::${account}:role/mem9-on-aws-prod-Mem9ConsolidationSchedulerRole-role`,
    workers:[{kind:kind==='planner'?'executor':'planner'},{kind,containerName,taskDefinitionArn,scheduleName:kind+'-schedule',sourceTag:operator.sourceTag,image:operator.workerImage}]};
  const secrets={MEM9_WORKER_TARGETS:operator.targetsParameter,[kind==='planner'?'MEM9_PLANNER_DB_SECRET':'MEM9_EXECUTOR_DB_SECRET']:operator[kind+'Credential'],
    ...(kind==='executor'?{MEM9_TENANT_ID:prefix+'consolidation-runtime/tenant',MEM9_SERVICE_TRANSPORT_SIGNING_KEYS:prefix+'namespace/service-consolidation-signing-keys'}:{})};
  const role=kind=>`arn:aws:iam::${account}:role/mem9-on-aws-prod-${containerName}${kind==='task'?'Task':'Execution'}Role-fixture`;
  const values={MEM9_STAGE:'prod',MEM9_WORKER_KIND:kind,MEM9_WORKER_GENERATION:generation,MEM9_DB_HOST:operator.host,MEM9_DB_NAME:operator.database,
    MEM9_DB_PORT:String(operator.port),MEM9_BASE_URL:'http://mnemo.mem9-prod.local:8080'};
  if(drift==='host')values.MEM9_DB_HOST='foreign.example.com';
  if(drift==='database')values.MEM9_DB_NAME='unrelated';
  if(drift==='port')values.MEM9_DB_PORT='5433';
  const calls=[],state={dataParameter:null};
  const send=async command=>{
    const name=command.constructor.name,input=command.input;calls.push(name);
    if(name==='GetCallerIdentityCommand')return {Account:account};
    if(name==='GetParametersCommand')return {Parameters:input.Names.map(Name=>Name.endsWith('/data-release')?state.dataParameter:{Name,Value:JSON.stringify(Name.endsWith('/operator-manifest')?operator:manifest)})};
    if(name==='DescribeTaskDefinitionCommand'){
      const taskDefinition={taskDefinitionArn,taskRoleArn:role('task'),executionRoleArn:role('execution'),networkMode:'awsvpc',runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},
      containerDefinitions:[{name:containerName,image:operator.workerImage,
        entryPoint:['node'],command:['/app/scripts/consolidation-worker.mjs'],environment:Object.entries(values).map(([name,value])=>({name,value})),
        secrets:Object.entries(secrets).map(([name,valueFrom])=>({name,valueFrom})),logConfiguration:{options:{'awslogs-group':'/synthetic','awslogs-stream-prefix':'worker'}}}]};
      state.changeDefinition?.(taskDefinition);return {taskDefinition};
    }
    const execution=input.RoleName?.includes('ExecutionRole');
    if(name==='GetRoleCommand')return {Role:{Arn:role(execution?'execution':'task'),PermissionsBoundary:{PermissionsBoundaryArn:`arn:aws:iam::${account}:policy/mem9-on-aws-workload-boundary`},
      AssumeRolePolicyDocument:{Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'sts:AssumeRole',Principal:{Service:'ecs-tasks.amazonaws.com'},Condition:{
        StringEquals:{'aws:SourceAccount':account},ArnLike:{'aws:SourceArn':`arn:aws:ecs:${region}:${account}:*`}}}]}}};
    if(name==='ListRolePoliciesCommand')return {PolicyNames:[execution?'WorkerParameters':'inline']};
    if(name==='ListAttachedRolePoliciesCommand')return {AttachedPolicies:execution?[{PolicyArn:'arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'}]:[]};
    if(name==='GetRolePolicyCommand')return {PolicyDocument:{Version:'2012-10-17',Statement:execution?[
      {Effect:'Allow',Action:['ssm:GetParameters'],Resource:Object.values(secrets)},
      {Effect:'Allow',Action:['kms:Decrypt'],Resource:'*',Condition:{StringEquals:{'kms:ViaService':`ssm.${region}.amazonaws.com`,'kms:EncryptionContext:PARAMETER_ARN':Object.values(secrets)}}},
    ]:[{Effect:'Allow',Action:['ssmmessages:CreateControlChannel','ssmmessages:CreateDataChannel','ssmmessages:OpenControlChannel','ssmmessages:OpenDataChannel'],Resource:'*'}]}};
    if(name==='GetScheduleCommand')return {};
    throw Error('UnexpectedCommand');
  };
  return {clients:{ssm:{send},sts:{send},ecs:{send},iam:{send},scheduler:{send}},options:{region,kind,revision},calls,operator,manifest,state};
}
function retainedFixture(kind='executor'){
 const f=fixture(undefined,kind),o=f.operator,now=Date.now(),h='e'.repeat(64);
 const data={version:1,stage:'prod',account:o.account,region:o.region,controlSourceTree:'a'.repeat(40),dataRevision:'a'.repeat(40),dataSourceTree:'b'.repeat(40),dataSourceTag:o.sourceTag,
  images:Object.fromEntries(['llm-proxy','mnemo-server','qwen3-embed'].map(name=>[name,{rootDigest:'sha256:'+'d'.repeat(64),arm64Digest:'sha256:'+h}])),
  runtimeNonce:'c'.repeat(32),authorizationId:'d'.repeat(32),issuedMs:now-1000,expiresMs:now+3600000,
  ...Object.fromEntries(['parentProofHash','backendBindingHash','targetsHash','schemaDigest','operatorDigest','buildInputsHash','securityEvidenceHash','policyHash'].map(k=>[k,h])),generation:o.generation};
 Object.assign(o,{version:3,controlSourceTag:o.sourceTag,dataReleaseHash:hash(data),dataReleaseParameter:'/mem9-on-aws/prod/consolidation-runtime/data-release',dataReleaseParameterVersion:2});
 Object.assign(f.manifest,{version:2,dataReleaseHash:o.dataReleaseHash,dataReleaseParameterVersion:2});f.options.controlSourceTree=data.controlSourceTree;
 f.state.dataParameter={Name:o.dataReleaseParameter,Type:'SecureString',Version:2,Value:JSON.stringify(data)};return f;
}
function nonrootFixture(kind='executor',mutate=()=>{}){
 const f=retainedFixture(kind),data=JSON.parse(f.state.dataParameter.Value);
 data.version=3;data.transition={version:2,kind:'image-security-nonroot-upgrade',proofHash:'f'.repeat(64),predecessorHash:'c'.repeat(64),limitsHash:NONROOT_LIMITS_HASH};
 f.state.dataParameter.Value=JSON.stringify(data);f.operator.dataReleaseHash=hash(data);f.manifest.dataReleaseHash=hash(data);
 f.state.changeDefinition=definition=>{definition.containerDefinitions[0]=structuredClone(dataLaunchPolicy(kind,definition.containerDefinitions[0]));mutate(definition.containerDefinitions[0],definition);};
 return f;
}
describe('production canary worker target loading',()=>{
  it('binds approved DB and private network to a verified task and both IAM roles',async()=>{
    const f=fixture(),target=await loadProductionCanaryWorker(f.clients,f.options);
    expect(target.subnets).toEqual(['subnet-abcd']);expect(target.securityGroup).toBe('sg-abcd');
    expect(f.calls.filter(name=>name==='GetRoleCommand')).toHaveLength(2);
  });
  it.each(['host','database','port'])('rejects %s drift before schedule creation',async drift=>{
    const f=fixture(drift);await expect(loadProductionCanaryWorker(f.clients,f.options)).rejects.toThrow('ProductionCanaryDeliveryFailed');
    expect(f.calls).not.toContain('GetScheduleCommand');expect(f.calls).not.toContain('CreateScheduleCommand');
  });
  it('binds both retained manifests to the same exact protected version',async()=>{
    const f=retainedFixture(),target=await loadProductionCanaryWorker(f.clients,f.options);expect(target.dataRelease.parameterVersion).toBe(2);
  });
  it.each(['planner','executor'])('loads the fixed nonroot %s through both role checks and schedule discovery',async kind=>{
    const f=nonrootFixture(kind),target=await loadProductionCanaryWorker(f.clients,f.options);
    expect(target.kind).toBe(kind);expect(target.dataRelease.data.version).toBe(3);
    expect(f.calls.filter(name=>name==='GetRoleCommand')).toHaveLength(2);expect(f.calls.at(-1)).toBe('GetScheduleCommand');
  });
  it.each([
    ['legacy entrypoint',c=>{c.entryPoint=['node'];}],
    ['stripped guards',c=>{c.entryPoint=['node'];delete c.user;delete c.linuxParameters;}],
    ['root user',c=>{c.user='0:0';}],
    ['missing capability drop',c=>{delete c.linuxParameters.capabilities;}],
    ['added capability',c=>{c.linuxParameters.capabilities.add=['SYS_ADMIN'];}],
    ['privileged container',c=>{c.privileged=true;}],
    ['alternate executable',c=>{c.entryPoint[3]='/bin/sh';}],
    ['replay command',c=>{c.command=['/app/scripts/consolidation-canary-replay.mjs'];}],
    ['missing Linux platform',(_c,d)=>{delete d.runtimePlatform.operatingSystemFamily;}],
    ['runtime injection',c=>{c.environment.push({name:'NODE_OPTIONS',value:'--require=/tmp/injected.mjs'});}],
    ['loader injection',c=>{c.environment.push({name:'LD_PRELOAD',value:'/tmp/injected.so'});}],
    ['duplicate environment',c=>{c.environment.push({...c.environment[0]});}],
    ['duplicate secret name',c=>{c.environment.push({name:c.secrets[0].name,value:'override'});}],
  ])('rejects nonroot %s before role or schedule discovery',async(_label,mutate)=>{
    const f=nonrootFixture('executor',mutate);await expect(loadProductionCanaryWorker(f.clients,f.options)).rejects.toThrow('ProductionCanaryDeliveryFailed');
    expect(f.calls).not.toContain('GetRoleCommand');expect(f.calls).not.toContain('GetScheduleCommand');
  });
  it.each([undefined,1,3])('rejects worker-manifest version binding %s before worker discovery',async version=>{
    const f=retainedFixture();f.manifest.dataReleaseParameterVersion=version;await expect(loadProductionCanaryWorker(f.clients,f.options)).rejects.toThrow();expect(f.calls).not.toContain('DescribeTaskDefinitionCommand');
  });
  it('rejects a later same-byte protected parameter rewrite before worker discovery',async()=>{
    const f=retainedFixture();f.state.dataParameter.Version=3;await expect(loadProductionCanaryWorker(f.clients,f.options)).rejects.toThrow('VersionMismatch');expect(f.calls).not.toContain('DescribeTaskDefinitionCommand');
  });
});
