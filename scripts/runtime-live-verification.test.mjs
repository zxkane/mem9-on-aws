import {describe,it,expect} from 'vitest';
import {runtimeServerContract,verifyRuntimeRoles} from './lib/runtime-live-verification.mjs';

function fixture(){
  const meta={stage:'prod',region:'ap-northeast-1',account:'123456789012',productionRuntime:true};
  const prefix=`arn:aws:iam::${meta.account}:role/mem9-on-aws-prod-`;
  const definition={taskRoleArn:prefix+'Mem9ServerTaskRole-example',executionRoleArn:prefix+'RuntimeMem9ServerExecutionRole-example'};
  const contract={task:{Version:'2012-10-17',Statement:[]},execution:{Version:'2012-10-17',Statement:[]},
    fence:{Version:'2012-10-17',Statement:[{Effect:'Deny',Action:'ssm:GetParameters',Resource:'*'}]}};
  const roles=Object.fromEntries(['task','execution'].map(kind=>[kind,{Arn:definition[kind+'RoleArn'],
    PermissionsBoundary:{PermissionsBoundaryArn:`arn:aws:iam::${meta.account}:policy/mem9-on-aws-workload-boundary`},
    AssumeRolePolicyDocument:{Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'sts:AssumeRole',Principal:{Service:'ecs-tasks.amazonaws.com'},
      ...(kind==='execution'?{Condition:{StringEquals:{'aws:SourceAccount':meta.account},ArnLike:{'aws:SourceArn':`arn:aws:ecs:${meta.region}:${meta.account}:*`}}}:{})}]},
  }]));
  const iam={send:async command=>{
    const kind=command.input.RoleName.includes('ExecutionRole')?'execution':'task';
    switch(command.constructor.name){
      case 'GetRoleCommand':return {Role:roles[kind]};
      case 'ListRolePoliciesCommand':return {PolicyNames:kind==='task'?['inline','ProductionCredentialFence']:['RuntimeSecrets']};
      case 'ListAttachedRolePoliciesCommand':return {AttachedPolicies:kind==='task'?[]:[{PolicyArn:'arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'}]};
      case 'GetRolePolicyCommand':return {PolicyDocument:contract[command.input.PolicyName==='ProductionCredentialFence'?'fence':kind]};
      default:throw Error('UnexpectedCommand');
    }
  }};
  return {meta,definition,contract,roles,iam};
}
describe('production runtime role trust',()=>{
  it('accepts inherited ECS task trust and requires scoped replacement execution trust',async()=>{
    await expect(verifyRuntimeRoles(fixture())).resolves.toBeUndefined();
  });
  it('rejects missing or foreign-account conditions on the replacement execution role',async()=>{
    for(const condition of [undefined,{StringEquals:{'aws:SourceAccount':'foreign'},ArnLike:{'aws:SourceArn':'*'}}]){
      const f=fixture();f.roles.execution.AssumeRolePolicyDocument.Statement[0].Condition=condition;
      await expect(verifyRuntimeRoles(f)).rejects.toThrow('RuntimeRoleTrustMismatch');
    }
  });
  it.each(['task','execution'])('rejects an additional AWS principal on %s trust',async kind=>{
    const f=fixture();f.roles[kind].AssumeRolePolicyDocument.Statement[0].Principal.AWS='*';
    await expect(verifyRuntimeRoles(f)).rejects.toThrow('RuntimeRoleTrustMismatch');
  });
  it('still rejects missing credential fencing on the inherited task role',async()=>{
    const f=fixture(),send=f.iam.send;
    f.iam.send=async command=>command.constructor.name==='GetRolePolicyCommand'&&command.input.PolicyName==='ProductionCredentialFence'
      ?{PolicyDocument:{Version:'2012-10-17',Statement:[]}}:send(command);
    await expect(verifyRuntimeRoles(f)).rejects.toThrow('RuntimeRolePolicyMismatch');
  });
});

// The Responses route's temporary second project (region migration). The live
// verifiers derive the expected task-role policy from the task definition, so
// the extra grant is accepted only when the definition records both markers.
describe('Responses-route migration grant',()=>{
  const stage='pr-7',region='ap-northeast-1',account='123456789012';
  const cluster='mem9-on-aws-pr-7-Mem9Cluster-abc',serverTaskDefinition=`arn:aws:ecs:${region}:${account}:task-definition/${cluster}-Mem9Server:9`;
  const tenantSecret=`arn:aws:secretsmanager:${region}:${account}:secret:mem9-on-aws-pr-7-tenant-api-key-abc`;
  const base=`arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/${stage}`;
  const meta={stage,region,account,cluster,serverTaskDefinition};
  const definition=proxyEnvironment=>({taskDefinitionArn:serverTaskDefinition,family:cluster+'-Mem9Server',
    containerDefinitions:[{name:'mnemo-server',environment:[{name:'MEM9_STAGE',value:stage},{name:'MNEMO_SCHEMA_MODE',value:'verify'},{name:'MNEMO_NAMESPACE_REQUIRED',value:'1'}],
      secrets:Object.entries({MEM9_DB_SECRET:base+'/runtime/database-credential',MEM9_TENANT_ID:tenantSecret,
        MNEMO_TRANSPORT_SIGNING_KEYS:base+'/namespace/transport-signing-keys',MNEMO_SERVICE_TRANSPORT_SIGNING_KEYS:base+'/namespace/service-transport-signing-keys'}).map(([name,valueFrom])=>({name,valueFrom}))},
      {name:'llm-proxy',environment:Object.entries(proxyEnvironment).map(([name,value])=>({name,value}))}]});
  const project=(projectRegion,id)=>`arn:aws:bedrock-mantle:${projectRegion}:${account}:project/${id}`;
  const current={LLM_PROXY_OPENAI_PROJECT:'proj_app',LLM_PROXY_RESPONSES_REGION:'us-east-1',LLM_PROXY_RESPONSES_OPENAI_PROJECT:'proj_new'};
  const migrating={...current,LLM_PROXY_RESPONSES_NEXT_REGION:'us-west-2',LLM_PROXY_RESPONSES_NEXT_OPENAI_PROJECT:'proj_old'};
  const inference=contract=>contract.task.Statement.find(s=>s.Action.includes('bedrock-mantle:CreateInference')).Resource;

  it('TC-IAM-BOUNDARY-112 expects exactly the recorded projects in each shape',()=>{
    expect(inference(runtimeServerContract(definition(current),meta,tenantSecret)))
      .toEqual([project(region,'proj_app'),project('us-east-1','proj_new')]);
    expect(inference(runtimeServerContract(definition(migrating),meta,tenantSecret)))
      .toEqual([project(region,'proj_app'),project('us-east-1','proj_new'),project('us-west-2','proj_old')]);
  });

  it.each([
    ['a region without a project',{...current,LLM_PROXY_RESPONSES_NEXT_REGION:'us-west-2'}],
    ['a project without a region',{...current,LLM_PROXY_RESPONSES_NEXT_OPENAI_PROJECT:'proj_old'}],
    ['a malformed project id',{...migrating,LLM_PROXY_RESPONSES_NEXT_OPENAI_PROJECT:'proj_*'}],
    ['the current Responses region',{...migrating,LLM_PROXY_RESPONSES_NEXT_REGION:'us-east-1'}],
    ['the application region',{...migrating,LLM_PROXY_RESPONSES_NEXT_REGION:region}],
  ])('TC-IAM-BOUNDARY-112 rejects a migration marker with %s',(_name,proxyEnvironment)=>{
    expect(()=>runtimeServerContract(definition(proxyEnvironment),meta,tenantSecret)).toThrow('RuntimeResponsesMigrationMismatch');
  });

  it('TC-IAM-BOUNDARY-112 rejects a live extra grant the task definition does not record',async()=>{
    const f=fixture(),recorded=runtimeServerContract(definition(current),meta,tenantSecret);
    const live=runtimeServerContract(definition(migrating),meta,tenantSecret);
    f.contract.task=live.task;
    await expect(verifyRuntimeRoles(f)).resolves.toBeUndefined();
    await expect(verifyRuntimeRoles({...f,contract:{...f.contract,task:recorded.task}})).rejects.toThrow('RuntimeRolePolicyMismatch');
  });
});
