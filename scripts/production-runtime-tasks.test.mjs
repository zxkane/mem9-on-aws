import {describe,it,expect} from 'vitest';
import {invokeProductionTask,ownsProductionInvocation,cancelProductionInvocations} from './lib/production-runtime-tasks.mjs';

const account='123456789012',region='ap-northeast-1',stage='prod',cluster='mem9-on-aws-prod-Fixture';
const arn=`arn:aws:ecs:${region}:${account}`,prefix=`arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/prod/runtime/`;
const meta={stage,region,account,cluster,clusterArn:arn+':cluster/'+cluster,mode:'prepare',database:'mem9',port:5432,
  host:'mem9-on-aws-prod-fixture.cluster-example.ap-northeast-1.'+['rds','amazonaws','com'].join('.'),
  transitionTaskDefinition:arn+':task-definition/'+cluster+'-TransitionMem9Bootstrap:1',transitionContainer:'TransitionMem9Bootstrap',
  runtimeCredential:prefix+'database-credential',administratorCredential:prefix+'schema-administrator-credential',
  transitionCredential:prefix+'transition-credential',originalOwnerSecret:`arn:aws:secretsmanager:${region}:${account}:secret:mem9-on-aws-prod-owner`,
  tenantSecret:`arn:aws:secretsmanager:${region}:${account}:secret:mem9-on-aws-prod-tenant`,subnets:['subnet-abcd'],securityGroup:'sg-abcd'};

function fixture({loseReply=false}={}){
  let time=Date.now();const journals=new Map(),tasks=[],calls=[];
  const send=async command=>{
    const name=command.constructor.name,input=command.input;calls.push({name,input});
    if(name==='DescribeTaskDefinitionCommand')return {taskDefinition:{taskDefinitionArn:meta.transitionTaskDefinition,networkMode:'awsvpc',runtimePlatform:{cpuArchitecture:'ARM64'},
      taskRoleArn:'task-role',executionRoleArn:'execution-role',containerDefinitions:[{name:meta.transitionContainer,entryPoint:['node'],command:['/bootstrap/operator/scripts/production-runtime-operator.mjs'],
        environment:Object.entries({MEM9_STAGE:stage,MEM9_DB_HOST:meta.host,MEM9_DB_PORT:'5432',MEM9_DB_NAME:'mem9'}).map(([name,value])=>({name,value})),
        secrets:Object.entries({MEM9_DB_SECRET:meta.originalOwnerSecret,MEM9_SCHEMA_ADMIN_CREDENTIAL:meta.administratorCredential,
          MEM9_RUNTIME_DB_SECRET:meta.runtimeCredential,MEM9_TRANSITION_CREDENTIAL:meta.transitionCredential,MEM9_TENANT_ID:meta.tenantSecret}).map(([name,valueFrom])=>({name,valueFrom})),
        logConfiguration:{options:{'awslogs-group':'/synthetic','awslogs-stream-prefix':'operator'}}}]}};
    if(name==='PutParameterCommand'){journals.set(input.Name,input.Value);return {};}
    if(name==='GetParametersByPathCommand')return {Parameters:[...journals].map(([Name,Value])=>({Name,Value}))};
    if(name==='DeleteParameterCommand'){journals.delete(input.Name);return {};}
    if(name==='RunTaskCommand'){
      tasks.push({taskArn:arn+':task/'+cluster+'/invocation',clusterArn:meta.clusterArn,taskDefinitionArn:input.taskDefinition,
        overrides:input.overrides,lastStatus:'RUNNING',containers:[{name:meta.transitionContainer,exitCode:0}]});
      if(loseReply)throw Error('SyntheticLostReply');return {tasks:[tasks[0]]};
    }
    if(name==='ListTasksCommand')return {taskArns:input.desiredStatus==='RUNNING'?tasks.map(t=>t.taskArn):[]};
    if(name==='DescribeTasksCommand')return {tasks};
    if(name==='StopTaskCommand'){tasks[0].lastStatus='STOPPED';return {};}
    throw Error('UnexpectedCommand');
  };
  return {clients:{ecs:{send},ssm:{send},logs:{send}},journals,tasks,calls,now:()=>time,sleep:async ms=>{time+=ms;}};
}

describe('production invocation recovery',()=>{
  it('cannot use a catalog-only target for a mutating operation',async()=>{
    const f=fixture();await expect(invokeProductionTask(f.clients,{...meta,mode:'catalog'},
      {operation:'prepare',nonce:'a'.repeat(32),epoch:1},{now:f.now,sleep:f.sleep})).rejects.toThrow('CatalogOnlyTarget');
    expect(f.calls).toEqual([]);
  });
  it('preserves the pre-launch journal after an accepted request loses its response',async()=>{
    const f=fixture({loseReply:true});
    await expect(invokeProductionTask(f.clients,meta,{operation:'status',nonce:'a'.repeat(32),epoch:1},{now:f.now,sleep:f.sleep})).rejects.toThrow('SyntheticLostReply');
    expect(f.journals.size).toBe(1);expect(f.calls.filter(c=>c.name==='RunTaskCommand')).toHaveLength(1);
    const stopped=await cancelProductionInvocations(f.clients,meta,{now:f.now,sleep:f.sleep});
    expect(stopped).toHaveLength(1);expect(f.tasks[0].lastStatus).toBe('STOPPED');
    expect(f.journals.size).toBe(1); // DB recovery must acknowledge it separately.
  });
  it.each([{operation:'resume',expected_hash:'c'.repeat(64)},{operation:'rehearsal-preservation',checkpoint_sequence:8}])('forwards the complete cancellation protocol through the real task adapter: %o',async fields=>{
    const f=fixture({loseReply:true});
    await expect(invokeProductionTask(f.clients,meta,{...fields,nonce:'a'.repeat(32),epoch:3},{now:f.now,sleep:f.sleep})).rejects.toThrow('SyntheticLostReply');
    const value=f.tasks[0].overrides.containerOverrides[0].environment.find(entry=>entry.name==='MEM9_PRODUCTION_RUNTIME_REQUEST').value;
    expect(JSON.parse(value)).toMatchObject(fields);
    expect(JSON.parse([...f.journals.values()][0]).request).toMatchObject(fields);
  });
  it.each([{operation:'status',expected_hash:'c'.repeat(64)},{operation:'resume',expected_hash:'bad'},
    {operation:'rehearsal-preservation',checkpoint_sequence:0},{operation:'status',checkpoint_sequence:8}])('rejects invalid cancellation protocol before launch: %o',async fields=>{
    const f=fixture({loseReply:true});
    await expect(invokeProductionTask(f.clients,meta,{...fields,nonce:'a'.repeat(32),epoch:3},{now:f.now,sleep:f.sleep})).rejects.toThrow('InvalidProductionInvocation');
    expect(f.calls.some(call=>call.name==='RunTaskCommand')).toBe(false);
  });
  it('rejects command, environment and role override drift',()=>{
    const request={operation:'status',nonce:'a'.repeat(32),epoch:1,deadline:Date.now()+60000};
    const journal={invocation:'b'.repeat(32),request,taskDefinition:meta.transitionTaskDefinition,container:meta.transitionContainer,taskRoleArn:'task-role',executionRoleArn:'execution-role'};
    const task={clusterArn:meta.clusterArn,taskDefinitionArn:meta.transitionTaskDefinition,taskArn:arn+':task/'+cluster+'/test',
      overrides:{containerOverrides:[{name:meta.transitionContainer,environment:[{name:'MEM9_RUNTIME_INVOCATION',value:journal.invocation},
        {name:'MEM9_BOOTSTRAP_OPERATION',value:'production-runtime'},{name:'MEM9_PRODUCTION_RUNTIME_REQUEST',value:JSON.stringify(request)}]}]}};
    expect(ownsProductionInvocation(task,meta,journal)).toBe(true);
    const changed=structuredClone(task);changed.overrides.containerOverrides[0].command=['unsafe'];
    expect(ownsProductionInvocation(changed,meta,journal)).toBe(false);
    changed.overrides.containerOverrides[0].command=[];changed.overrides.executionRoleArn='other-role';
    expect(ownsProductionInvocation(changed,meta,journal)).toBe(false);
  });
});
