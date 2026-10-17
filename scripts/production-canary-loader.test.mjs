import {describe,it,expect} from 'vitest';
import {loadProductionCanaryWorker,plannerModelStatements} from './lib/production-canary-delivery.mjs';
import {plannerContractMatchesRoute} from './run-production-canary.mjs';

function fixture(drift){
  const account='123456789012',region='ap-northeast-1',revision='a'.repeat(40),generation='b'.repeat(64),cluster='mem9-on-aws-prod-Fixture';
  const clusterArn=`arn:aws:ecs:${region}:${account}:cluster/${cluster}`,prefix=`arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/prod/`;
  const planner=drift==='planner',containerName=planner?'Mem9ConsolidationPlanner':'Mem9ConsolidationExecutor',taskDefinitionArn=`arn:aws:ecs:${region}:${account}:task-definition/${cluster}-${containerName}:1`;
  const operator={version:1,stage:'prod',region,account,cluster,clusterArn,generation,host:'mem9-on-aws-prod-fixture.cluster-example.ap-northeast-1.'+['rds','amazonaws','com'].join('.'),
    sourceTag:'mem9-aaaaaaa',workerImage:`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/llm-proxy@sha256:${'d'.repeat(64)}`,
    database:'mem9',port:5432,subnets:['subnet-abcd'],securityGroup:'sg-abcd',administratorCredential:prefix+'runtime/schema-administrator-credential',
    plannerCredential:prefix+'consolidation-runtime/planner-credential',executorCredential:prefix+'consolidation-runtime/executor-credential',targetsParameter:prefix+'maintenance/targets'};
  const manifest={version:1,stage:'prod',generation,clusterArn,groupName:'mem9-on-aws-prod-consolidation-fixture',
    roleArn:`arn:aws:iam::${account}:role/mem9-on-aws-prod-Mem9ConsolidationSchedulerRole-role`,
    workers:[{kind:planner?'executor':'planner'},{kind:planner?'planner':'executor',containerName,taskDefinitionArn,scheduleName:'worker-schedule',sourceTag:operator.sourceTag,image:operator.workerImage}]};
  const secrets=planner?{MEM9_WORKER_TARGETS:operator.targetsParameter,MEM9_PLANNER_DB_SECRET:operator.plannerCredential}:
    {MEM9_WORKER_TARGETS:operator.targetsParameter,MEM9_EXECUTOR_DB_SECRET:operator.executorCredential,
    MEM9_TENANT_ID:prefix+'consolidation-runtime/tenant',MEM9_SERVICE_TRANSPORT_SIGNING_KEYS:prefix+'namespace/service-consolidation-signing-keys'};
  const role=kind=>`arn:aws:iam::${account}:role/mem9-on-aws-prod-${containerName}${kind==='task'?'Task':'Execution'}Role-fixture`;
  const values={MEM9_STAGE:'prod',MEM9_WORKER_KIND:planner?'planner':'executor',MEM9_WORKER_GENERATION:generation,MEM9_DB_HOST:operator.host,MEM9_DB_NAME:operator.database,
    MEM9_DB_PORT:String(operator.port),MEM9_BASE_URL:'http://mnemo.mem9-prod.local:8080',
    ...(planner?{MEM9_LLM_MODEL:'openai.gpt-example',AWS_REGION:region,MEM9_BEDROCK_PROJECT:'proj_app',MEM9_LLM_RESPONSES_REGION:'us-east-1',MEM9_BEDROCK_PROJECT_OPENAI:'proj_responses'}:{})};
  if(drift==='host')values.MEM9_DB_HOST='foreign.example.com';
  if(drift==='database')values.MEM9_DB_NAME='unrelated';
  if(drift==='port')values.MEM9_DB_PORT='5433';
  const calls=[];
  const send=async command=>{
    const name=command.constructor.name,input=command.input;calls.push(name);
    if(name==='GetCallerIdentityCommand')return {Account:account};
    if(name==='GetParametersCommand')return {Parameters:input.Names.map(Name=>({Name,Value:JSON.stringify(Name.endsWith('/operator-manifest')?operator:manifest)}))};
    if(name==='DescribeTaskDefinitionCommand')return {taskDefinition:{taskDefinitionArn,taskRoleArn:role('task'),executionRoleArn:role('execution'),networkMode:'awsvpc',runtimePlatform:{cpuArchitecture:'ARM64'},
      containerDefinitions:[{name:containerName,image:operator.workerImage,
        entryPoint:['node'],command:['/app/scripts/consolidation-worker.mjs'],environment:Object.entries(values).map(([name,value])=>({name,value})),
        secrets:Object.entries(secrets).map(([name,valueFrom])=>({name,valueFrom})),logConfiguration:{options:{'awslogs-group':'/synthetic','awslogs-stream-prefix':'worker'}}}]}};
    const execution=input.RoleName?.includes('ExecutionRole');
    if(name==='GetRoleCommand')return {Role:{Arn:role(execution?'execution':'task'),PermissionsBoundary:{PermissionsBoundaryArn:`arn:aws:iam::${account}:policy/mem9-on-aws-workload-boundary`},
      AssumeRolePolicyDocument:{Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'sts:AssumeRole',Principal:{Service:'ecs-tasks.amazonaws.com'},Condition:{
        StringEquals:{'aws:SourceAccount':account},ArnLike:{'aws:SourceArn':`arn:aws:ecs:${region}:${account}:*`}}}]}}};
    if(name==='ListRolePoliciesCommand')return {PolicyNames:[execution?'WorkerParameters':'inline']};
    if(name==='ListAttachedRolePoliciesCommand')return {AttachedPolicies:execution?[{PolicyArn:'arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'}]:[]};
    if(name==='GetRolePolicyCommand')return {PolicyDocument:{Version:'2012-10-17',Statement:execution?[
      {Effect:'Allow',Action:['ssm:GetParameters'],Resource:Object.values(secrets)},
      {Effect:'Allow',Action:['kms:Decrypt'],Resource:'*',Condition:{StringEquals:{'kms:ViaService':`ssm.${region}.amazonaws.com`,'kms:EncryptionContext:PARAMETER_ARN':Object.values(secrets)}}},
    ]:[{Effect:'Allow',Action:['ssmmessages:CreateControlChannel','ssmmessages:CreateDataChannel','ssmmessages:OpenControlChannel','ssmmessages:OpenDataChannel'],Resource:'*'},
      ...(planner?plannerModelStatements({kind:'planner',region,account,values}):[])]}};
    if(name==='GetScheduleCommand')return {};
    throw Error('UnexpectedCommand');
  };
  return {clients:{ssm:{send},sts:{send},ecs:{send},iam:{send},scheduler:{send}},options:{region,kind:'executor',revision},calls};
}
describe('production canary worker target loading',()=>{
  it('binds approved DB and private network to a verified task and both IAM roles',async()=>{
    const f=fixture(),target=await loadProductionCanaryWorker(f.clients,f.options);
    expect(target.subnets).toEqual(['subnet-abcd']);expect(target.securityGroup).toBe('sg-abcd');
    expect(f.calls.filter(name=>name==='GetRoleCommand')).toHaveLength(2);
    expect(target.plannerRoute).toBeUndefined();
  });
  it('exposes the deployed route settings for the planner only',async()=>{
    const f=fixture('planner'),target=await loadProductionCanaryWorker(f.clients,{...f.options,kind:'planner'});
    expect(target.plannerRoute).toEqual({model:'openai.gpt-example',region:'ap-northeast-1',project:'proj_app',responsesRegion:'us-east-1',openaiProject:'proj_responses'});
  });
  it.each(['host','database','port'])('rejects %s drift before schedule creation',async drift=>{
    const f=fixture(drift);await expect(loadProductionCanaryWorker(f.clients,f.options)).rejects.toThrow('ProductionCanaryDeliveryFailed');
    expect(f.calls).not.toContain('GetScheduleCommand');expect(f.calls).not.toContain('CreateScheduleCommand');
  });
});
describe('planner model grant verification',()=>{
  const context={region:'ap-northeast-1',account:'123456789012'};
  const values={MEM9_LLM_MODEL:'openai.gpt-example',MEM9_BEDROCK_PROJECT:'proj_app',MEM9_BEDROCK_PROJECT_OPENAI:'proj_responses',
    MEM9_LLM_RESPONSES_REGION:'us-west-2',AWS_REGION:'ap-northeast-1'};
  it('expects exactly the planner route projects and the bearer-token call',()=>{
    expect(plannerModelStatements({...context,kind:'planner',values})).toEqual([
      {Effect:'Allow',Action:['bedrock-mantle:CreateInference'],Resource:['arn:aws:bedrock-mantle:ap-northeast-1:123456789012:project/proj_app',
        'arn:aws:bedrock-mantle:us-west-2:123456789012:project/proj_responses']},
      {Effect:'Allow',Action:['bedrock-mantle:CallWithBearerToken'],Resource:'*'}]);
    expect(plannerModelStatements({...context,kind:'planner',values:{...values,MEM9_BEDROCK_PROJECT:'',MEM9_BEDROCK_PROJECT_OPENAI:''}})).toEqual([]);
  });
  it('rejects model settings on the executor and malformed planner routes',()=>{
    expect(plannerModelStatements({...context,kind:'executor',values:{}})).toEqual([]);
    expect(()=>plannerModelStatements({...context,kind:'executor',values})).toThrow();
    for(const drift of [{MEM9_BEDROCK_PROJECT:'proj_*'},{MEM9_LLM_RESPONSES_REGION:'*'},{AWS_REGION:'us-east-1'}])
      expect(()=>plannerModelStatements({...context,kind:'planner',values:{...values,...drift}})).toThrow();
  });
});
describe('planner model switch route',()=>{
  const route={model:'openai.gpt-example',region:'ap-northeast-1',project:'proj_app',responsesRegion:'us-east-1',openaiProject:'proj_responses'};
  const contract={adapter:'mantle-responses-total-v1',model:'openai.gpt-example',region:'us-east-1',project:'proj_responses'};
  it('accepts only the deployed planner model, region and project',()=>{
    expect(plannerContractMatchesRoute(contract,route)).toBe(true);
    expect(plannerContractMatchesRoute({...contract,adapter:'mantle-chat-total-v1',region:'ap-northeast-1',project:'proj_app'},route)).toBe(true);
    for(const drift of [{model:'openai.other'},{region:'us-west-2'},{project:'proj_app'},{adapter:'mantle-chat-total-v1'}])
      expect(plannerContractMatchesRoute({...contract,...drift},route)).toBe(false);
    expect(plannerContractMatchesRoute(contract,undefined)).toBe(false);
  });
});
