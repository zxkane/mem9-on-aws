import {describe,it,expect} from 'vitest';
import {runRuntimePreview,validateRuntimeMetadata,validateRuntimeJournal} from './run-runtime-preview.mjs';
import {runtimeServerContract} from './lib/runtime-live-verification.mjs';

const stage='pr-7',region='ap-northeast-1',account='123456789012';
const cluster='mem9-on-aws-pr-7-Mem9Cluster-abc',clusterArn=`arn:aws:ecs:${region}:${account}:cluster/${cluster}`;
const family=cluster+'-Mem9Bootstrap',taskDefinition=`arn:aws:ecs:${region}:${account}:task-definition/${family}:8`;
const prefix='/mem9-on-aws/pr-7';
const serverTaskDefinition=`arn:aws:ecs:${region}:${account}:task-definition/${cluster}-Mem9Server:9`;
const tenantSecret=`arn:aws:secretsmanager:${region}:${account}:secret:mem9-on-aws-pr-7-tenant-api-key-abc`;
const shape={cluster,taskDefinition,securityGroup:'sg-abc',subnets:['subnet-abc'],service:'mem9-on-aws-pr-7-Mem9Server-abc'};
function harness(){
  let time=1000000,sequence=0;const calls=[],journals=new Map(),tasks=[];
  const state={desiredCount:0,runningCount:0,pendingCount:0,loseRunResponse:false,wrongRevision:false};
  const serverDefinition={taskDefinitionArn:serverTaskDefinition,family:cluster+'-Mem9Server',
    taskRoleArn:`arn:aws:iam::${account}:role/mem9-on-aws-pr-7-Mem9ServerTaskRole-role`,
    executionRoleArn:`arn:aws:iam::${account}:role/mem9-on-aws-pr-7-Mem9ServerExecutionRole-role`,
    containerDefinitions:[{name:'mnemo-server',environment:[{name:'MEM9_STAGE',value:stage},{name:'MNEMO_SCHEMA_MODE',value:'verify'},{name:'MNEMO_NAMESPACE_REQUIRED',value:'1'}],
      secrets:Object.entries({MEM9_DB_SECRET:`arn:aws:ssm:${region}:${account}:parameter${prefix}/runtime/database-credential`,MEM9_TENANT_ID:tenantSecret,
        MNEMO_TRANSPORT_SIGNING_KEYS:`arn:aws:ssm:${region}:${account}:parameter${prefix}/namespace/transport-signing-keys`,
        MNEMO_SERVICE_TRANSPORT_SIGNING_KEYS:`arn:aws:ssm:${region}:${account}:parameter${prefix}/namespace/service-transport-signing-keys`}).map(([name,valueFrom])=>({name,valueFrom}))},
      {name:'llm-proxy',environment:[]},{name:'qwen3-embed'}]};
  const contract=runtimeServerContract(serverDefinition,{...shape,stage,region,account,serverTaskDefinition},tenantSecret);
  const ready=()=>{
    Object.assign(state,{desiredCount:1,runningCount:1,taskDefinition:serverTaskDefinition,deployments:[{rolloutState:'COMPLETED'}]});
    tasks.push({taskArn:`arn:aws:ecs:${region}:${account}:task/${cluster}/server`,clusterArn,taskDefinitionArn:serverTaskDefinition,lastStatus:'RUNNING',group:'service:'+shape.service});
  };
  const send=async command=>{
    const name=command.constructor.name,input=command.input;calls.push({name,input});
    switch(name){
      case 'GetParametersCommand':return {Parameters:input.Names.map(Name=>({Name,Value:{
        'bootstrap/cluster-name':cluster,'bootstrap/task-def-arn':taskDefinition,'bootstrap/task-sg-id':shape.securityGroup,
        'bootstrap/subnet-ids':shape.subnets.join(','),'ecs/service-name':shape.service,'ecs/task-definition':serverTaskDefinition}[Name.slice(prefix.length+1)]}))};
      case 'GetParametersByPathCommand':return {Parameters:[...journals].map(([Name,Value])=>({Name,Value}))};
      case 'PutParameterCommand':journals.set(input.Name,input.Value);return {};
      case 'DeleteParameterCommand':journals.delete(input.Name);return {};
      case 'DescribeServicesCommand':return {services:[state]};
      case 'ListTasksCommand':return {taskArns:tasks.filter(t=>(input.family?t.taskDefinitionArn.includes('/'+input.family+':'):t.group==='service:'+shape.service)
        &&(t.desiredStatus??'RUNNING')===input.desiredStatus).map(t=>t.taskArn)};
      case 'DescribeTasksCommand':return {tasks:tasks.filter(t=>input.tasks.includes(t.taskArn)).map(t=>{
        if(t.automatic)t.lastStatus='STOPPED';return {...t};
      })};
      case 'StopTaskCommand':tasks.find(t=>t.taskArn===input.task).lastStatus='STOPPED';return {};
      case 'DescribeTaskDefinitionCommand':if(input.taskDefinition===serverTaskDefinition)return {taskDefinition:serverDefinition};return {taskDefinition:{family,containerDefinitions:[{name:'Mem9Bootstrap',environment:[
        {name:'MEM9_STAGE',value:stage},{name:'MEM9_RUNTIME_BOOTSTRAP_VERSION',value:state.wrongRevision?'0':'1'}],
        secrets:[{name:'MEM9_RUNTIME_DB_SECRET',valueFrom:`arn:aws:ssm:${region}:${account}:parameter${prefix}/runtime/database-credential`},{name:'MEM9_TENANT_ID',valueFrom:tenantSecret}],
        logConfiguration:{options:{'awslogs-group':'/sst/synthetic','awslogs-stream-prefix':'bootstrap'}}}]}};
      case 'RunTaskCommand':{
        const task={taskArn:`arn:aws:ecs:${region}:${account}:task/${cluster}/task-${++sequence}`,clusterArn,taskDefinitionArn:taskDefinition,
          overrides:input.overrides,lastStatus:'PENDING',automatic:!state.loseRunResponse,containers:[{name:'Mem9Bootstrap',exitCode:0}]};
        tasks.push(task);if(state.loseRunResponse)throw Error('SyntheticLostResponse');return {tasks:[task]};
      }
      case 'FilterLogEventsCommand':{
        const run=calls.findLast(c=>c.name==='RunTaskCommand');
        const operation=run.input.overrides.containerOverrides[0].environment.find(e=>e.name==='MEM9_BOOTSTRAP_OPERATION').value;
        return {events:[{message:JSON.stringify({event:operation==='runtime-verify'?'runtime_verify':'runtime_bootstrap',outcome:'ready'})}]};
      }
      case 'GetRoleCommand':return {Role:{Arn:`arn:aws:iam::${account}:role/${input.RoleName}`,PermissionsBoundary:{PermissionsBoundaryArn:`arn:aws:iam::${account}:policy/mem9-on-aws-workload-boundary`},
        AssumeRolePolicyDocument:encodeURIComponent(JSON.stringify({Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'sts:AssumeRole',Principal:{Service:'ecs-tasks.amazonaws.com'}}]}))}};
      case 'ListRolePoliciesCommand':return {PolicyNames:[input.RoleName.includes('ExecutionRole')?'RuntimeSecrets':'inline']};
      case 'ListAttachedRolePoliciesCommand':return {AttachedPolicies:input.RoleName.includes('ExecutionRole')?[{PolicyArn:'arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'}]:[]};
      case 'GetRolePolicyCommand':return {PolicyDocument:encodeURIComponent(JSON.stringify(contract[input.RoleName.includes('ExecutionRole')?'execution':'task']))};
      default:throw Error('UnexpectedCommand '+name);
    }
  };
  return {state,calls,journals,tasks,ready,serverDefinition,contract,now:()=>time,run:operation=>runRuntimePreview({clients:{ssm:{send},ecs:{send},logs:{send},iam:{send}},stage,region,operation,
    now:()=>time,sleep:async ms=>{time+=ms;},progress:()=>{}})};
}
describe('preview runtime deployment orchestration',()=>{
  it('RUNTIME-001/009: rejects other stages, foreign families and malformed journals before mutation',async()=>{
    for(const invalid of ['prod','dev','pr-0'])expect(()=>validateRuntimeMetadata(shape,invalid,region)).toThrow();
    expect(()=>validateRuntimeMetadata({...shape,taskDefinition:taskDefinition.replace('pr-7','pr-8')},stage,region)).toThrow();
    const meta=validateRuntimeMetadata(shape,stage,region);
    expect(()=>validateRuntimeJournal({version:1,stage,nonce:'a'.repeat(32),createdAt:0,deadline:900000,operation:'bootstrap',taskDefinition},meta,prefix+'/runtime/invocations/wrong',1000000)).toThrow();
    const f=harness();f.state.desiredCount=1;
    await expect(f.run('bootstrap')).rejects.toThrow('RuntimeServiceNotStopped');
    expect(f.calls.some(c=>c.name==='RunTaskCommand')).toBe(false);
  });
  it('RUNTIME-009: drains pending and stopping tasks across all bootstrap revisions',async()=>{
    const f=harness();
    for(const [i,desiredStatus] of ['RUNNING','STOPPED'].entries())f.tasks.push({taskArn:`arn:aws:ecs:${region}:${account}:task/${cluster}/old-${i}`,
      clusterArn,taskDefinitionArn:taskDefinition.replace(':8',':2'),lastStatus:'PENDING',desiredStatus});
    await f.run('drain');
    expect(f.calls.filter(c=>c.name==='StopTaskCommand')).toHaveLength(2);
    expect(f.tasks.every(t=>t.lastStatus==='STOPPED')).toBe(true);
    expect(f.calls.filter(c=>c.name==='ListTasksCommand').some(c=>c.input.desiredStatus==='PENDING')).toBe(false);
  });
  it.each(['bootstrap','verify'])('RUNTIME-009/010: journals %s before exactly one idempotent launch and removes it after success',async operation=>{
    const f=harness();if(operation==='verify')f.ready();await f.run(operation);
    const launch=f.calls.find(c=>c.name==='RunTaskCommand');
    expect(f.calls.filter(c=>c.name==='RunTaskCommand')).toHaveLength(1);
    expect(f.calls.findIndex(c=>c.name==='PutParameterCommand')).toBeLessThan(f.calls.indexOf(launch));
    expect(launch.input.clientToken).toMatch(/^[a-f0-9]{32}$/);
    expect(launch.input.networkConfiguration.awsvpcConfiguration.assignPublicIp).toBe('DISABLED');
    expect(f.journals.size).toBe(0);
    expect(JSON.stringify(launch)).not.toContain('MEM9_DB_SECRET');
    expect(f.calls.filter(c=>c.name==='GetParametersCommand').every(c=>c.input.WithDecryption===false)).toBe(true);
  });
  it('RUNTIME-009: recovers an accepted RunTask whose response was lost without launching again',async()=>{
    const f=harness();f.state.loseRunResponse=true;
    await expect(f.run('bootstrap')).rejects.toThrow('SyntheticLostResponse');
    expect(f.calls.filter(c=>c.name==='RunTaskCommand')).toHaveLength(1);
    expect(f.tasks[0].lastStatus).toBe('STOPPED');expect(f.journals.size).toBe(0);
  });
  it('RUNTIME-009: retains an ambiguous invocation until its task deadline has expired',async()=>{
    const f=harness(),nonce='a'.repeat(32),start=f.now();
    f.journals.set(prefix+'/runtime/invocations/'+nonce,JSON.stringify({version:1,stage,nonce,createdAt:start,deadline:start+900000,operation:'bootstrap',taskDefinition}));
    await f.run('cancel');
    expect(f.now()).toBeGreaterThanOrEqual(start+960000);
    expect(f.journals.size).toBe(0);expect(f.calls.some(c=>c.name==='RunTaskCommand')).toBe(false);
  });
  it('RUNTIME-009: never launches a cached owner bootstrap lacking the runtime marker',async()=>{
    const f=harness();f.state.wrongRevision=true;
    await expect(f.run('bootstrap')).rejects.toThrow('RuntimeBootstrapRevisionMismatch');
    expect(f.calls.some(c=>c.name==='RunTaskCommand')).toBe(false);
  });
  it.each(['owner-reference','old-revision','extra-execution-policy','extra-task-policy','injected-environment'])('RUNTIME-010: rejects live server drift: %s',async scenario=>{
    const f=harness();f.ready();
    if(scenario==='owner-reference')f.serverDefinition.containerDefinitions[0].secrets[0].valueFrom=`arn:aws:secretsmanager:${region}:${account}:secret:mem9-on-aws-pr-7-Mem9DbSecret-abc`;
    if(scenario==='old-revision')f.tasks[0].taskDefinitionArn=serverTaskDefinition.replace(':9',':8');
    if(scenario==='extra-execution-policy')f.contract.execution.Statement.push({Effect:'Allow',Action:'secretsmanager:GetSecretValue',Resource:'*'});
    if(scenario==='extra-task-policy')f.contract.task.Statement.push({Effect:'Allow',Action:'*',Resource:'*'});
    if(scenario==='injected-environment')f.tasks[0].overrides={containerOverrides:[{name:'mnemo-server',environment:[{name:'MNEMO_SCHEMA_MODE',value:'apply'}]}]};
    await expect(f.run('verify')).rejects.toThrow(/Runtime/);
    expect(f.calls.some(c=>c.name==='RunTaskCommand')).toBe(false);
  });
});
