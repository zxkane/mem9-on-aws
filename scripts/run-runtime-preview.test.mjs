import {describe,it,expect} from 'vitest';
import {runRuntimePreview,validateRuntimeMetadata,validateRuntimeJournal} from './run-runtime-preview.mjs';
import {runtimeServerContract} from './lib/runtime-live-verification.mjs';
import {createServer} from 'node:http';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
import {nonrootPreviewFixture} from './nonroot-preview.fixture.mjs';

const stage='pr-7',region='ap-northeast-1',account='123456789012';
const cluster='mem9-on-aws-pr-7-Mem9Cluster-abc',clusterArn=`arn:aws:ecs:${region}:${account}:cluster/${cluster}`;
const family=cluster+'-Mem9Bootstrap',taskDefinition=`arn:aws:ecs:${region}:${account}:task-definition/${family}:8`;
const prefix='/mem9-on-aws/pr-7';
const serverTaskDefinition=`arn:aws:ecs:${region}:${account}:task-definition/${cluster}-Mem9Server:9`;
const tenantSecret=`arn:aws:secretsmanager:${region}:${account}:secret:mem9-on-aws-pr-7-tenant-api-key-abc`;
const shape={cluster,taskDefinition,securityGroup:'sg-0123456789abcdef0',subnets:['subnet-0123456789abcdef0'],service:'Mem9Server'};
function harness(){
  let time=1000000,sequence=0;const calls=[],journals=new Map(),tasks=[];
  const state={desiredCount:0,runningCount:0,pendingCount:0,loseRunResponse:false,wrongRevision:false};
  const guarded=nonrootPreviewFixture({stage,region,account,cluster,secrets:[
    {name:'MEM9_RUNTIME_DB_SECRET',valueFrom:`arn:aws:ssm:${region}:${account}:parameter${prefix}/runtime/database-credential`},
    {name:'MEM9_PROBE_ADMIN_CREDENTIAL',valueFrom:`arn:aws:ssm:${region}:${account}:parameter${prefix}/runtime/admin-probe-credential`},
    {name:'MEM9_TENANT_ID',valueFrom:tenantSecret}]});
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
      case 'GetCallerIdentityCommand':return {Account:account};
      case 'GetParametersCommand':if(input.Names[0].endsWith('/purpose-bindings'))return {Parameters:input.Names.map(Name=>{
        const p=structuredClone(guarded.parameters.get(Name));if(state.changedMapAfterJournal&&journals.size&&Name.endsWith('/purpose-bindings'))p.Version++;return p;
      }),...(state.missingMap?{InvalidParameters:[input.Names[0]]}:{})};
      return {Parameters:input.Names.map(Name=>({Name,Value:{
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
      case 'DescribeTaskDefinitionCommand':{
        if(input.taskDefinition===serverTaskDefinition)return {taskDefinition:serverDefinition};
        const observed=structuredClone(guarded.definitions.get(input.taskDefinition));
        if(state.wrongRevision)observed.taskDefinition.containerDefinitions[0].environment.find(e=>e.name==='MEM9_RUNTIME_BOOTSTRAP_VERSION').value='0';
        if(state.wrongProbeReference)observed.taskDefinition.containerDefinitions[0].secrets.find(e=>e.name==='MEM9_PROBE_ADMIN_CREDENTIAL').valueFrom+='-wrong';
        return observed;
      }
      case 'RunTaskCommand':{
        const task={taskArn:`arn:aws:ecs:${region}:${account}:task/${cluster}/task-${++sequence}`,clusterArn,taskDefinitionArn:input.taskDefinition,
          overrides:input.overrides,lastStatus:'PENDING',automatic:!state.loseRunResponse,containers:[{name:'Mem9Bootstrap',exitCode:0}]};
        tasks.push(task);if(state.loseRunResponse)throw Error('SyntheticLostResponse');return {tasks:[task]};
      }
      case 'FilterLogEventsCommand':{
        const run=calls.findLast(c=>c.name==='RunTaskCommand');
        const operation=run.input.overrides.containerOverrides[0].environment.find(e=>e.name==='MEM9_BOOTSTRAP_OPERATION').value;
        if(operation==='runtime-admin-probe-cleanup'&&state.failCleanup)return {events:[{message:JSON.stringify({event:'runtime_bootstrap_failed',errorClass:'AdminProbeCleanupFailed'})}]};
        return {events:[{message:JSON.stringify({event:operation==='runtime-verify'?'runtime_verify':operation==='runtime-admin-probe'?'runtime_admin_probe':
          operation==='runtime-admin-probe-cleanup'?'runtime_admin_probe_cleanup':'runtime_bootstrap',outcome:'ready',
          ...(operation==='runtime-admin-probe-cleanup'?{roleRemoved:true}:{})})}]};
      }
      case 'GetRoleCommand':return {Role:{Arn:`arn:aws:iam::${account}:role/${input.RoleName}`,PermissionsBoundary:{PermissionsBoundaryArn:`arn:aws:iam::${account}:policy/mem9-on-aws-workload-boundary`},
        AssumeRolePolicyDocument:encodeURIComponent(JSON.stringify({Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'sts:AssumeRole',Principal:{Service:'ecs-tasks.amazonaws.com'}}]}))}};
      case 'ListRolePoliciesCommand':return {PolicyNames:[input.RoleName.includes('ExecutionRole')?'RuntimeSecrets':'inline']};
      case 'ListAttachedRolePoliciesCommand':return {AttachedPolicies:input.RoleName.includes('ExecutionRole')?[{PolicyArn:'arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'}]:[]};
      case 'GetRolePolicyCommand':return {PolicyDocument:encodeURIComponent(JSON.stringify(contract[input.RoleName.includes('ExecutionRole')?'execution':'task']))};
      default:throw Error('UnexpectedCommand '+name);
    }
  };
  return {state,calls,journals,tasks,ready,serverDefinition,contract,guarded,now:()=>time,run:operation=>runRuntimePreview({clients:{ssm:{send},ecs:{send},logs:{send},iam:{send},sts:{send}},stage,region,operation,sourceTree:guarded.scope.sourceTree,
    now:()=>time,sleep:async ms=>{time+=ms;},progress:()=>{}})};
}
describe('preview runtime deployment orchestration',()=>{
  it('RUNTIME-008: the actual CLI resolves the project region when AWS_REGION is absent',async()=>{
    const requests=[];
    const server=createServer((req,res)=>{
      let body='';req.on('data',chunk=>{body+=chunk;});req.on('end',()=>{
        const target=req.headers['x-amz-target']?.split('.').at(-1);requests.push(target);
        const input=JSON.parse(body);
        const response=target==='GetParameters'?{Parameters:input.Names.map(Name=>({Name,Value:{
          'bootstrap/cluster-name':cluster,'bootstrap/task-def-arn':taskDefinition,'bootstrap/task-sg-id':shape.securityGroup,
          'bootstrap/subnet-ids':shape.subnets.join(','),'ecs/service-name':shape.service,'ecs/task-definition':serverTaskDefinition}[Name.slice(prefix.length+1)]}))}:
          {Parameters:[]};
        res.writeHead(200,{'content-type':'application/x-amz-json-1.1'});res.end(JSON.stringify(response));
      });
    });
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    try{
      const endpoint=`http://127.0.0.1:${server.address().port}`;
      const {stdout}=await promisify(execFile)(process.execPath,[fileURLToPath(new URL('./run-runtime-preview.mjs',import.meta.url)),'cancel'],{
        timeout:20000,env:{PATH:process.env.PATH,STAGE:stage,AWS_ACCESS_KEY_ID:'synthetic-test-access',AWS_SECRET_ACCESS_KEY:'synthetic-test-secret',
          AWS_EC2_METADATA_DISABLED:'true',AWS_ENDPOINT_URL:endpoint}});
      expect(JSON.parse(stdout)).toEqual({event:'runtime_preview',phase:'cancelled'});
      expect(requests).toEqual(['GetParameters','GetParametersByPath']);
    }finally{await new Promise(resolve=>server.close(resolve));}
  });
  it('RUNTIME-001/009: rejects other stages, foreign families and malformed journals before mutation',async()=>{
    for(const invalid of ['prod','dev','pr-0'])expect(()=>validateRuntimeMetadata(shape,invalid,region)).toThrow();
    expect(()=>validateRuntimeMetadata({...shape,taskDefinition:taskDefinition.replace('pr-7','pr-8')},stage,region)).toThrow();
    expect(()=>validateRuntimeMetadata({...shape,service:'OtherService'},stage,region)).toThrow();
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
  it.each(['bootstrap','verify','admin-probe','admin-probe-cleanup'])('RUNTIME-009/010: journals %s before exactly one idempotent launch and removes it after success',async operation=>{
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
    await expect(f.run('bootstrap')).rejects.toThrow('NonrootPreviewReadbackChanged');
    expect(f.calls.some(c=>c.name==='RunTaskCommand')).toBe(false);
  });
  it('refuses an administrator probe with a foreign credential reference before launch',async()=>{
    const f=harness();f.state.wrongProbeReference=true;
    await expect(f.run('admin-probe')).rejects.toThrow('NonrootPreviewReadbackChanged');
    expect(f.calls.some(c=>c.name==='RunTaskCommand')).toBe(false);
  });
  it('requires the purpose map and rechecks its version after journal writes without a legacy launch fallback',async()=>{
    for(const key of ['missingMap','changedMapAfterJournal']){
      const f=harness();f.state[key]=true;await expect(f.run('bootstrap')).rejects.toThrow(/NonrootPreviewBindings/);
      expect(f.calls.some(c=>c.name==='RunTaskCommand')).toBe(false);
    }
  });
  it('selects different exact revisions for bootstrap and administrator cleanup',async()=>{
    const f=harness();await f.run('bootstrap');await f.run('admin-probe-cleanup');
    const runs=f.calls.filter(c=>c.name==='RunTaskCommand');expect(runs).toHaveLength(2);
    expect(runs[0].input.taskDefinition).toBe(f.guarded.map.bindings.find(b=>b.purpose==='bootstrap-runtime-bootstrap').taskDefinitionArn);
    expect(runs[1].input.taskDefinition).toBe(f.guarded.map.bindings.find(b=>b.purpose==='bootstrap-admin-probe-cleanup').taskDefinitionArn);
    expect(runs.every(r=>r.input.enableExecuteCommand===false&&!Object.hasOwn(r.input.overrides.containerOverrides[0],'command'))).toBe(true);
  });
  it.each([false,true])('retains interrupted probe tracking until role cleanup is proven (failure=%s)',async failCleanup=>{
    const f=harness(),nonce='a'.repeat(32),path=prefix+'/runtime/invocations/'+nonce,start=f.now();
    f.state.failCleanup=failCleanup;
    f.journals.set(path,JSON.stringify({version:1,stage,nonce,createdAt:start,deadline:start+900000,operation:'admin-probe',taskDefinition}));
    if(failCleanup){
      await expect(f.run('cancel')).rejects.toThrow('AdminProbeCleanupFailed');
      expect(f.journals.has(path)).toBe(true);expect(f.journals.size).toBe(2);
    }else{await f.run('cancel');expect(f.journals.size).toBe(0);}
    const launch=f.calls.find(c=>c.name==='RunTaskCommand');
    expect(launch.input.overrides.containerOverrides[0].environment).toContainEqual({name:'MEM9_BOOTSTRAP_OPERATION',value:'runtime-admin-probe-cleanup'});
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
