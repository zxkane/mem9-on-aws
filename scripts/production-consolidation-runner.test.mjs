import {describe,it,expect} from 'vitest';
import {runProductionConsolidationTask,stopPreviousProductionAdministration} from './run-production-consolidation.mjs';
import {productionSourceTree,productionCoordinatorDigest} from './run-production-runtime.mjs';
import {execFileSync} from 'node:child_process';

const account='123456789012',region='ap-northeast-1',cluster='mem9-on-aws-prod-Fixture',name='ControlMem9Bootstrap';
const prefix=`arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/prod/`;
const taskDefinition=`arn:aws:ecs:${region}:${account}:task-definition/${cluster}-${name}:1`;
function fixture({drift=false,loseReply=false,wrongNonce=false,taskDrift,acceptance,sourceTag='mem9-aaaaaaa'}={}){
  const calls=[],journals=new Map();let task,time=Date.now();
  const meta={version:1,stage:'prod',region,account,cluster,clusterArn:`arn:aws:ecs:${region}:${account}:cluster/${cluster}`,
    sourceTag,workerImage:`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/llm-proxy@sha256:${'d'.repeat(64)}`,
    host:'mem9-on-aws-prod-fixture.cluster-example.ap-northeast-1.'+['rds','amazonaws','com'].join('.'),port:5432,database:'mem9',generation:'a'.repeat(64),
    subnets:['subnet-abcd'],securityGroup:'sg-abcd',administratorCredential:prefix+'runtime/schema-administrator-credential',
    plannerCredential:prefix+'consolidation-runtime/planner-credential',executorCredential:prefix+'consolidation-runtime/executor-credential',targetsParameter:prefix+'maintenance/targets',
    operators:{control:{containerName:name,taskDefinition,image:`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/bootstrap@sha256:${'e'.repeat(64)}`}}};
  const executionRole=`arn:aws:iam::${account}:role/mem9-on-aws-prod-${name}ExecutionRole-synthetic`;
  const taskRole=`arn:aws:iam::${account}:role/mem9-on-aws-${taskDrift==='scope'?'pr-7':'prod'}-${name}TaskRole-synthetic`;
  const trust={Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'sts:AssumeRole',Principal:{Service:'ecs-tasks.amazonaws.com'},Condition:{
    StringEquals:{'aws:SourceAccount':account},ArnLike:{'aws:SourceArn':`arn:aws:ecs:${region}:${account}:*`}}}]};
  const injected=[{name:'MEM9_DB_SECRET',valueFrom:meta.administratorCredential}];
  const references=injected.map(secret=>secret.valueFrom);
  const policy={Version:'2012-10-17',Statement:[{Effect:'Allow',Action:['ssm:GetParameters'],Resource:references},
    {Effect:'Allow',Action:['kms:Decrypt'],Resource:'*',Condition:{StringEquals:{'kms:ViaService':`ssm.${region}.amazonaws.com`,'kms:EncryptionContext:PARAMETER_ARN':references}}}]};
  const send=async command=>{
    const type=command.constructor.name,input=command.input;calls.push({type,input});
    if(type==='GetCallerIdentityCommand')return {Account:account};
    if(type==='GetParametersCommand')return {Parameters:[{Value:JSON.stringify(input.Names[0].includes('rehearsal-acceptance')?acceptance:meta)}]};
    if(type==='GetParametersByPathCommand')return {Parameters:[...journals].map(([Name,Value])=>({Name,Value}))};
    if(type==='DescribeTaskDefinitionCommand')return {taskDefinition:{taskDefinitionArn:taskDefinition,executionRoleArn:executionRole,taskRoleArn:taskRole,networkMode:'awsvpc',runtimePlatform:{cpuArchitecture:'ARM64'},
      containerDefinitions:[{name,image:meta.operators.control.image,entryPoint:['node'],command:['/bootstrap/operator/scripts/production-consolidation-operator.mjs'],
        environment:Object.entries({MEM9_STAGE:'prod',MEM9_DB_HOST:meta.host,MEM9_DB_NAME:'mem9',MEM9_DB_PORT:'5432',MEM9_WORKER_GENERATION:meta.generation,MEM9_PRODUCTION_WORKER_OPERATOR:'control',MEM9_WORKER_IMAGE:meta.workerImage,MEM9_WORKER_SOURCE_TAG:meta.sourceTag}).map(([name,value])=>({name,value})),
        secrets:injected,logConfiguration:{options:{'awslogs-group':'/synthetic','awslogs-stream-prefix':'operator'}}}]}};
    const taskIdentity=input.RoleName===taskRole.split('/').at(-1);
    if(type==='GetRoleCommand')return {Role:{Arn:taskIdentity?taskRole:executionRole,
      AssumeRolePolicyDocument:taskIdentity&&taskDrift==='trust'?{Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'sts:AssumeRole',Principal:{AWS:'*'}}]}:trust,
      PermissionsBoundary:taskIdentity&&taskDrift==='boundary'?undefined:{PermissionsBoundaryArn:`arn:aws:iam::${account}:policy/mem9-on-aws-workload-boundary`}}};
    if(type==='ListRolePoliciesCommand')return {PolicyNames:taskIdentity?['inline']:['ProductionWorkerOperator']};
    if(type==='ListAttachedRolePoliciesCommand')return {AttachedPolicies:taskIdentity&&taskDrift!=='attachment'?[]:[{PolicyArn:'arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'}]};
    if(type==='GetRolePolicyCommand')return {PolicyDocument:drift||(taskIdentity&&taskDrift==='policy')?{Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'ssm:*',Resource:'*'}]}:
      taskIdentity?{Version:'2012-10-17',Statement:[{Effect:'Allow',Action:['ssmmessages:CreateControlChannel','ssmmessages:CreateDataChannel','ssmmessages:OpenControlChannel','ssmmessages:OpenDataChannel'],Resource:'*'}]}:policy};
    if(type==='PutParameterCommand'){journals.set(input.Name,input.Value);return {};}
    if(type==='DeleteParameterCommand'){journals.delete(input.Name);return {};}
    if(type==='RunTaskCommand'){
      task={taskArn:`arn:aws:ecs:${region}:${account}:task/${cluster}/synthetic`,clusterArn:meta.clusterArn,taskDefinitionArn:taskDefinition,overrides:input.overrides,lastStatus:'STOPPED',containers:[{name,exitCode:0}]};
      if(loseReply)throw Error('SyntheticLostReply');return {tasks:[task]};
    }
    if(type==='DescribeTasksCommand')return {tasks:[task]};
    if(type==='ListTasksCommand')return {taskArns:task?[task.taskArn]:[]};
    if(type==='StopTaskCommand'){task.lastStatus='STOPPED';return {};}
    if(type==='FilterLogEventsCommand'){
      const request=JSON.parse(task.overrides.containerOverrides[0].environment.find(e=>e.name==='MEM9_PRODUCTION_CONSOLIDATION_REQUEST').value);
      return {events:[{eventId:'result',message:JSON.stringify({event:'production_consolidation_operator',phase:request.operation,outcome:'complete',invocation:wrongNonce?'wrong':request.invocation})}]};
    }
    throw Error('UnexpectedCommand');
  };
  return {meta,clients:{ssm:{send},ecs:{send},logs:{send},sts:{send},iam:{send}},calls,journals,options:{now:()=>time,sleep:async ms=>{time+=ms;}}};
}
describe('production worker administrative task invocation',()=>{
  it('serializes continuation fields into the bounded owned task request without silently dropping them',async()=>{
    const revision=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
    const acceptance={sourceTree:await productionSourceTree(),coordinatorDigest:await productionCoordinatorDigest()};
    const f=fixture({acceptance,sourceTag:'mem9-'+revision.slice(0,7)});
    const data={attemptId:'b'.repeat(32),parentProofHash:'c'.repeat(64),compatibility:{version:1}};
    await runProductionConsolidationTask(f.clients,{region,operation:'begin-continuation',...data},f.options);
    const launch=f.calls.find(c=>c.type==='RunTaskCommand');
    const request=JSON.parse(launch.input.overrides.containerOverrides[0].environment.find(e=>e.name==='MEM9_PRODUCTION_CONSOLIDATION_REQUEST').value);
    expect(request).toMatchObject({operation:'begin-continuation',...data});expect(f.journals.size).toBe(0);
    const rejected=fixture();
    await expect(runProductionConsolidationTask(rejected.clients,{region,operation:'status',...data},rejected.options)).rejects.toThrow();
    expect(rejected.calls.some(c=>c.type==='RunTaskCommand')).toBe(false);
  });
  it('validates the control credential and exact IAM policy, then matches the terminal nonce',async()=>{
    const f=fixture();expect((await runProductionConsolidationTask(f.clients,{region,operation:'status'},f.options)).outcome).toBe('complete');
    expect(f.journals.size).toBe(0);
    expect(f.calls.filter(c=>c.type==='RunTaskCommand')).toHaveLength(1);
    expect(f.calls.some(c=>c.type==='GetParametersCommand'&&c.input.Names[0].includes('rehearsal-acceptance'))).toBe(false);
  });
  it('rejects widened credential readers before launching',async()=>{
    const f=fixture({drift:true});await expect(runProductionConsolidationTask(f.clients,{region,operation:'status'},f.options)).rejects.toThrow('ProductionOperatorPolicyMismatch');
    expect(f.calls.some(c=>c.type==='RunTaskCommand')).toBe(false);
  });
  it.each(['scope','trust','boundary','policy','attachment'])('rejects administrator task-role %s drift before launching',async taskDrift=>{
    const f=fixture({taskDrift});
    await expect(runProductionConsolidationTask(f.clients,{region,operation:'status'},f.options)).rejects.toThrow();
    expect(f.calls.some(c=>c.type==='RunTaskCommand')).toBe(false);
  });
  it.each([{loseReply:true},{wrongNonce:true}])('retains recovery state after ambiguous or mismatched completion %o',async options=>{
    const f=fixture(options);await expect(runProductionConsolidationTask(f.clients,{region,operation:'status'},f.options)).rejects.toThrow();
    expect(f.journals.size).toBe(1);
  });
  it('reconciles an accepted task whose launch response was lost before another mutation',async()=>{
    const f=fixture({loseReply:true});
    await expect(runProductionConsolidationTask(f.clients,{region,operation:'status'},f.options)).rejects.toThrow('SyntheticLostReply');
    await stopPreviousProductionAdministration(f.clients,f.meta,f.options);
    expect(f.journals.size).toBe(0);
    expect(f.calls.some(c=>c.type==='ListTasksCommand')).toBe(true);
  });
});
