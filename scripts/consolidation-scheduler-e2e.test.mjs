import {describe,it,expect} from 'vitest';
import {validateManifest,scheduleJournal,validateJournal,ownsTask,oneShotInput,runSchedulerAcceptance,taskDefinitionMatches,discoverSchedulerTasks,verifyPostRuntimeTask} from './consolidation-scheduler-e2e.mjs';

const stage='pr-7',generation='a'.repeat(64),region='ap-northeast-1',account='123456789012';
const clusterName=`mem9-on-aws-${stage}-Cluster-example`;
const raw={version:1,stage,generation,groupName:`mem9-on-aws-${stage}-consolidation-example`,
  roleArn:`arn:aws:iam::${account}:role/mem9-on-aws-${stage}-Mem9ConsolidationSchedulerRole-role`,
  clusterArn:`arn:aws:ecs:${region}:${account}:cluster/${clusterName}`,
  workers:['planner','executor'].map(kind=>({kind,containerName:`Mem9Consolidation${kind==='planner'?'Planner':'Executor'}`,
    taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/mem9-on-aws-${stage}-Mem9Consolidation${kind}:7`,
    scheduleName:`mem9-on-aws-${stage}-${kind}-example`,logGroupName:'/sst/synthetic'}))};
const manifest=validateManifest(raw,stage,generation,region),worker=manifest.workers[0];
const when=Date.now()+125000,journal=scheduleJournal(manifest,worker,'plan',when);
const path=`/mem9-on-aws/${stage}/consolidation-preview/schedules/${generation}/plan-planner`;
const template={State:'DISABLED',GroupName:manifest.groupName,Target:{Arn:manifest.clusterArn,RoleArn:manifest.roleArn,
  Input:JSON.stringify({containerOverrides:[{name:worker.containerName,environment:[{name:'MEM9_WORKER_GENERATION',value:generation}]}]}),
  EcsParameters:{TaskDefinitionArn:worker.taskDefinitionArn,LaunchType:'FARGATE',PropagateTags:'TASK_DEFINITION'}}};
describe('real Scheduler acceptance ownership and cleanup',()=>{
  it('requires actual post-runtime task images and overrides, not requested values substituted as evidence',()=>{
    const route={containerName:'Mem9PostFixture',taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/${clusterName}-Mem9PostFixture:7`,image:`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/preview/bootstrap@sha256:${'b'.repeat(64)}`,taskRoleArn:'task-role',executionRoleArn:'execution-role'};
    const j={operator:true,stage,generation,nonce:'c'.repeat(32),deadline:Date.now()+60000,operation:'setup',batchBoundaryCrossings:0,taskDefinitionArn:route.taskDefinitionArn,route};
    const task={taskArn:manifest.clusterArn.replace(':cluster/',':task/')+'/'+'d'.repeat(32),clusterArn:manifest.clusterArn,taskDefinitionArn:route.taskDefinitionArn,lastStatus:'STOPPED',
      containers:[{name:route.containerName,image:route.image,imageDigest:'sha256:'+'e'.repeat(64),exitCode:0}],
      overrides:{containerOverrides:[{name:route.containerName,environment:Object.entries({MEM9_BOOTSTRAP_OPERATION:'consolidation-preview-setup',MEM9_PREVIEW_EXPECTED_GENERATION:generation,MEM9_PREVIEW_OPERATOR_NONCE:j.nonce,MEM9_PREVIEW_OPERATOR_DEADLINE:String(j.deadline),MEM9_PREVIEW_BATCH_BOUNDARY_CROSSINGS:'0'}).map(([name,value])=>({name,value}))}]}};
    const binding={route,image:{rootDigest:'sha256:'+'b'.repeat(64),arm64Digest:'sha256:'+'e'.repeat(64)}};
    expect(()=>verifyPostRuntimeTask(task,manifest,binding,j)).not.toThrow();
    for(const mutate of [t=>{delete t.overrides;},t=>{t.containers[0].imageDigest='sha256:'+'f'.repeat(64);},t=>{t.overrides.executionRoleArn='foreign';},t=>{t.overrides.containerOverrides[0].command=['foreign'];}]){
      const bad=structuredClone(task);mutate(bad);expect(()=>verifyPostRuntimeTask(bad,manifest,binding,j)).toThrow('PostRuntimeTaskMismatch');
    }
  });
  it('re-reads task inventory when a listed task briefly has no description',async()=>{
    const arn=manifest.clusterArn.replace(':cluster/',':task/')+'/fresh',waits=[];let attempt=0;
    const ecs={send:async command=>{
      if(command.constructor.name==='ListTasksCommand')return {taskArns:command.input.desiredStatus==='RUNNING'?[arn]:[]};
      attempt++;return attempt===1?{failures:[{arn,reason:'MISSING'}]}:{tasks:[{taskArn:arn,clusterArn:manifest.clusterArn}]};
    }};
    expect(await discoverSchedulerTasks(ecs,manifest.clusterArn,()=>true,{sleep:async ms=>waits.push(ms)})).toHaveLength(1);
    expect(attempt).toBe(2);expect(waits).toEqual([1000]);
  });
  it('accepts a fresh complete inventory after an expired stopped entry disappears',async()=>{
    const arn=manifest.clusterArn.replace(':cluster/',':task/')+'/expired';let lists=0;
    const ecs={send:async command=>command.constructor.name==='ListTasksCommand'
      ?{taskArns:++lists<=2&&command.input.desiredStatus==='STOPPED'?[arn]:[]}
      :{failures:[{arn,reason:'MISSING'}]}};
    expect(await discoverSchedulerTasks(ecs,manifest.clusterArn,()=>true,{sleep:async()=>{}})).toEqual([]);
    expect(lists).toBe(4);
  });
  it.each(['MISSING','ACCESS_DENIED','unaccounted'])('keeps unresolved or unauthorized %s descriptions fail-closed',async reason=>{
    const arn=manifest.clusterArn.replace(':cluster/',':task/')+'/test';let reads=0;
    const ecs={send:async command=>{
      if(command.constructor.name==='ListTasksCommand')return {taskArns:command.input.desiredStatus==='RUNNING'?[arn]:[]};
      reads++;return reason==='unaccounted'?{tasks:[]}:{failures:[{arn,reason}]};
    }};
    await expect(discoverSchedulerTasks(ecs,manifest.clusterArn,()=>true,{sleep:async()=>{}})).rejects.toThrow('TaskDiscoveryIncomplete');
    expect(reads).toBe(reason==='MISSING'?4:1);
  });
  it('accepts the actual SST cluster-prefixed bootstrap family and rejects other families',()=>{
    const arn=`arn:aws:ecs:${region}:${account}:task-definition/${clusterName}-Mem9Bootstrap:7`;
    expect(taskDefinitionMatches(arn,manifest,'Mem9Bootstrap')).toBe(true);
    for(const other of [arn.replace('-Mem9Bootstrap:','-Mem9BootstrapOther:'),arn.replace(clusterName,'mem9-on-aws-pr-8-Cluster-example'),
      arn.replace(':7',':0'),arn.replace(`${clusterName}-Mem9Bootstrap`,`mem9-on-aws-${stage}-Mem9Bootstrap`)])
      expect(taskDefinitionMatches(other,manifest,'Mem9Bootstrap')).toBe(false);
  });
  it('rejects stale deployment, wrong account and wrong stage',()=>{
    expect(()=>validateManifest(raw,stage,'b'.repeat(64),region)).toThrow('GenerationDeployMismatch');
    expect(()=>validateManifest({...raw,roleArn:raw.roleArn.replace(account,'<other-account-id>')},stage,generation,region)).toThrow();
    expect(()=>validateManifest(raw,'prod',generation,region)).toThrow();
  });
  it('accepts only the journal-owned schedule in the exact stage and group',()=>{
    expect(validateJournal(journal,manifest,path)).toEqual(journal);
    for(const mutation of [{group:'unrelated'},{name:'unrelated'},{generation:'b'.repeat(64)},{nonce:'b'.repeat(64)},
      {taskDefinitionArn:worker.taskDefinitionArn.replace(stage,'prod')}])expect(()=>validateJournal({...journal,...mutation},manifest,path)).toThrow();
    expect(()=>validateJournal(journal,manifest,path.replace(stage,'pr-8'))).toThrow();
  });
  it('requires exact long task ARN, revision, generation and nonce',()=>{
    const task={taskArn:`arn:aws:ecs:${region}:${account}:task/${clusterName}/synthetic-task`,clusterArn:manifest.clusterArn,
      taskDefinitionArn:worker.taskDefinitionArn,overrides:{containerOverrides:[{name:worker.containerName,environment:[
        {name:'MEM9_WORKER_GENERATION',value:generation},{name:'MEM9_WORKER_INVOCATION',value:journal.nonce}]}]}};
    expect(ownsTask(task,manifest,journal)).toBe(true);
    for(const changed of [{taskArn:`arn:aws:ecs:${region}:${account}:task/short-id`},{taskDefinitionArn:worker.taskDefinitionArn.replace(':7',':6')},
      {clusterArn:manifest.clusterArn.replace(stage,'prod')},{overrides:{}}])expect(ownsTask({...task,...changed},manifest,journal)).toBe(false);
    expect(ownsTask(task,manifest,{...journal,generation:'b'.repeat(64)})).toBe(false);
    const replay=scheduleJournal(manifest,worker,'plan',when+60000);
    expect(replay.nonce).not.toBe(journal.nonce);expect(replay.name).not.toBe(journal.name);
    const oldStopped={...task,lastStatus:'STOPPED'};
    const current={...task,taskArn:task.taskArn+'-new',overrides:{containerOverrides:[{name:worker.containerName,environment:[
      {name:'MEM9_WORKER_GENERATION',value:generation},{name:'MEM9_WORKER_INVOCATION',value:replay.nonce}]}]}};
    expect([oldStopped,current].filter(candidate=>ownsTask(candidate,manifest,replay))).toEqual([current]);
  });
  it('clones a disabled target with no retries, no tag propagation and pinned generation',()=>{
    const result=oneShotInput(template,manifest,worker,journal);
    expect(result.Target.RetryPolicy).toEqual({MaximumEventAgeInSeconds:60,MaximumRetryAttempts:0});
    expect(result.Target.EcsParameters.PropagateTags).toBeUndefined();
    expect(result.ActionAfterCompletion).toBe('DELETE');expect(result.ScheduleExpression).toMatch(/^at\(/);
    expect(()=>oneShotInput({...template,State:'ENABLED'},manifest,worker,journal)).toThrow();
  });
  it('does not mutate anything when the expected generation differs',async()=>{
    const calls=[];
    const client={send:async command=>{calls.push(command.constructor.name);return {Parameters:[{Name:'/mem9-on-aws/pr-7/consolidation-preview/manifest',Value:JSON.stringify(raw)}]};}};
    await expect(runSchedulerAcceptance({clients:{ssm:client},stage,generation:'b'.repeat(64),region,progress:()=>{}})).rejects.toThrow('GenerationDeployMismatch');
    expect(calls).toEqual(['GetParametersCommand']);
  });
  it('holds the legacy route once runtime preparation exists even if its fixture generation still matches',async()=>{
    const bootArn=`arn:aws:ecs:${region}:${account}:task-definition/${clusterName}-Mem9Bootstrap:7`,calls=[];
    const client={send:async command=>{
      calls.push(command.constructor.name);
      if(command.constructor.name==='DescribeTaskDefinitionCommand')return {taskDefinition:{containerDefinitions:[{name:'Mem9Bootstrap',environment:[{name:'MEM9_PREVIEW_GENERATION',value:generation}]}]}};
      const names=command.input.Names;
      if(names[0].endsWith('/manifest'))return {Parameters:[{Name:names[0],Value:JSON.stringify(raw)}]};
      if(names[0].endsWith('/production-plan'))return {Parameters:[{Name:names[0],Value:'existing-lifecycle'}]};
      return {Parameters:names.map((Name,i)=>({Name,Value:[bootArn,'subnet-test','sg-test'][i]}))};
    }};
    await expect(runSchedulerAcceptance({clients:{ssm:client,ecs:client},stage,generation,region,progress:()=>{}})).rejects.toThrow('PostRuntimeContextRequired');
    expect(calls.every(name=>/^(Get|Describe)/.test(name))).toBe(true);
  });
  it.each(['schedule-response-loss','setup-response-loss','stop-failure'])('journals and continues cleanup after %s',async scenario=>{
    let now=Date.now(),taskSequence=0;const calls=[],store=new Map(),tasks=new Map();
    const bootArn=`arn:aws:ecs:${region}:${account}:task-definition/${clusterName}-Mem9Bootstrap:7`;
    store.set(`/mem9-on-aws/${stage}/consolidation-preview/manifest`,JSON.stringify(raw));
    for(const [k,v] of Object.entries({'task-def-arn':bootArn,'subnet-ids':'subnet-test','task-sg-id':'sg-test'}))store.set(`/mem9-on-aws/${stage}/bootstrap/${k}`,v);
    const client={send:async command=>{
      const kind=command.constructor.name,input=command.input;calls.push({kind,input});
      if(kind==='GetParametersCommand')return {Parameters:input.Names.filter(Name=>store.has(Name)).map(Name=>({Name,Value:store.get(Name)})),InvalidParameters:input.Names.filter(Name=>!store.has(Name))};
      if(kind==='PutParameterCommand'){store.set(input.Name,input.Value);return {};}
      if(kind==='DeleteParameterCommand'){store.delete(input.Name);return {};}
      if(kind==='GetParametersByPathCommand')return {Parameters:[...store].filter(([key])=>key.startsWith(input.Path)).map(([Name,Value])=>({Name,Value}))};
      if(kind==='DescribeTaskDefinitionCommand'){
        const w=manifest.workers.find(w=>w.taskDefinitionArn===input.taskDefinition),name=w?.containerName??'Mem9Bootstrap';
        return {taskDefinition:{containerDefinitions:[{name,environment:[{name:w?'MEM9_WORKER_GENERATION':'MEM9_PREVIEW_GENERATION',value:generation},{name:'MEM9_DB_HOST',value:'writer.example.com'}],
          logConfiguration:{options:{'awslogs-group':'/sst/synthetic','awslogs-stream-prefix':'ecs'}}}]}};
      }
      if(kind==='DescribeDBClustersCommand')return {DBClusters:[{Endpoint:'writer.example.com',DBClusterIdentifier:'mem9-on-aws-pr-7-db',DBClusterArn:'synthetic-db-arn',DBClusterMembers:[{DBInstanceIdentifier:'mem9-on-aws-pr-7-instance'}]}]};
      if(kind==='ListTagsForResourceCommand')return {TagList:[{Key:'Project',Value:'mem9-on-aws'},{Key:'Stage',Value:stage}]};
      if(kind==='DescribeDBInstancesCommand')return {DBInstances:[{DBInstanceIdentifier:'mem9-on-aws-pr-7-instance',DBClusterIdentifier:'mem9-on-aws-pr-7-db'}]};
      if(kind==='DescribeDBLogFilesCommand')return {DescribeDBLogFiles:[{LogFileName:'error/postgresql.log.2026-09-29-1805',Size:10,LastWritten:now-60000}]};
      if(kind==='RunTaskCommand'){
        const taskArn=`arn:aws:ecs:${region}:${account}:task/${clusterName}/task-${++taskSequence}`;
        const setup=input.overrides.containerOverrides[0].environment[0].value==='consolidation-preview-setup';
        tasks.set(taskArn,{taskArn,clusterArn:manifest.clusterArn,taskDefinitionArn:bootArn,overrides:input.overrides,
          lastStatus:setup&&scenario!=='schedule-response-loss'?'RUNNING':'STOPPED',containers:[{name:'Mem9Bootstrap',exitCode:0}]});
        if(setup&&scenario==='setup-response-loss')throw Error('SyntheticSetupResponseLost');
        return {tasks:[{taskArn}]};
      }
      if(kind==='DescribeTasksCommand'){
        if(scenario==='stop-failure'&&input.tasks.some(arn=>tasks.get(arn)?.lastStatus==='RUNNING'))throw Error('SyntheticObservationFailure');
        return {tasks:input.tasks.map(arn=>tasks.get(arn))};
      }
      if(kind==='StopTaskCommand'){
        if(scenario==='stop-failure')throw Error('SyntheticStopFailure');
        tasks.get(input.task).lastStatus='STOPPED';return {};
      }
      if(kind==='FilterLogEventsCommand')return {events:[{message:JSON.stringify({event:'consolidation_preview',outcome:'seeded'})}]};
      if(kind==='GetScheduleCommand')return template;
      if(kind==='CreateScheduleCommand')throw Error('SyntheticResponseLost');
      if(kind==='DeleteScheduleCommand')return {};
      if(kind==='ListTasksCommand')return {taskArns:[...tasks].filter(([,task])=>task.lastStatus===input.desiredStatus).map(([arn])=>arn)};
      throw Error('UnexpectedCommand');
    }};
    await expect(runSchedulerAcceptance({clients:{ssm:client,ecs:client,scheduler:client,logs:client,rds:client},stage,generation,region,
      now:()=>now,sleep:async ms=>{now+=ms;},progress:()=>{}})).rejects.toThrow(scenario==='schedule-response-loss'?'SyntheticResponseLost':scenario==='setup-response-loss'?'SyntheticSetupResponseLost':'AcceptanceCleanupIncomplete');
    const setup=calls.findIndex(c=>c.kind==='RunTaskCommand'&&c.input.overrides.containerOverrides[0].environment[0].value==='consolidation-preview-setup');
    expect(calls[setup-1].kind).toBe('GetParametersCommand');
    expect(calls[setup-2].kind).toBe('PutParameterCommand');
    const finalPause=calls.findLastIndex(c=>c.kind==='RunTaskCommand'&&c.input.overrides.containerOverrides[0].environment[0].value==='consolidation-preview-pause');
    expect(finalPause).toBeGreaterThan(setup);
    if(scenario==='setup-response-loss')expect(calls.findIndex(c=>c.kind==='StopTaskCommand')).toBeLessThan(finalPause);
    if(scenario==='stop-failure'){
      expect([...store.keys()].some(key=>key.includes('/operators/'))).toBe(true);
      expect(calls.slice(finalPause).some(c=>c.kind==='GetParametersByPathCommand'&&c.input.Path.endsWith('/schedules/'))).toBe(true);
      return;
    }
    expect([...store.keys()].some(key=>key.includes('/operators/'))).toBe(false);
    if(scenario==='setup-response-loss')return;
    const create=calls.findIndex(c=>c.kind==='CreateScheduleCommand');
    expect(calls.slice(0,create).some(c=>c.kind==='PutParameterCommand')).toBe(true);
    expect(calls[create-1].kind).toBe('GetParametersCommand');
    const later=calls.slice(create+1);
    expect(later.find(c=>c.kind==='RunTaskCommand').input.overrides.containerOverrides[0].environment[0].value).toBe('consolidation-preview-pause');
    expect(later.some(c=>c.kind==='DeleteScheduleCommand')).toBe(true);
    expect([...store.keys()].some(key=>key.includes('/schedules/'))).toBe(false);
  });
});
