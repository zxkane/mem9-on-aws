import {describe,it,expect} from 'vitest';
import {verifyRuntimeRoles} from './lib/runtime-live-verification.mjs';

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
