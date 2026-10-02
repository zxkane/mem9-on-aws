import {it,expect} from 'vitest';
import {runCanaryFixtureTask,createCanaryFixtureJournal} from './canary-fixture-e2e.mjs';
import {createCanaryFixtureDefinition} from './lib/canary-fixture-task.mjs';
import {canaryFixtureChecks} from './lib/production-canary-fixture-evidence.mjs';
function fixture(options={}){
  const account='123456789012',region='ap-northeast-1',stage='pr-7',cluster='mem9-on-aws-pr-7-Fixture',start=1800000000000;
  const meta={account,region,stage,cluster,clusterArn:`arn:aws:ecs:${region}:${account}:cluster/${cluster}`,subnets:['subnet-abcd'],securityGroup:'sg-abcd',
    executionRoleArn:`arn:aws:iam::${account}:role/mem9-on-aws-pr-7-Mem9BootstrapExecutionRole-test`,logGroup:'/sst/cluster/'+cluster+'/Mem9Bootstrap/Mem9Bootstrap'};
  const identity={stage,runId:'12345',runAttempt:1,commit:'a'.repeat(40),sourceTree:'b'.repeat(40),coordinatorDigest:'c'.repeat(64),schemaDigest:'d'.repeat(64),operatorDigest:'e'.repeat(64),nonce:'f'.repeat(32),deadlineMs:start+10000};
  const digest=n=>'sha256:'+n.repeat(64),image=(root,child)=>({rootDigest:digest(root),arm64Digest:digest(child),image:`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/preview/bootstrap@${digest(root)}`});
  const images={runner:image('1','2'),database:image('3','4')},definition=createCanaryFixtureDefinition(meta,images,identity),arn=`arn:aws:ecs:${region}:${account}:task-definition/${definition.family}:1`;
  const task={taskArn:`arn:aws:ecs:${region}:${account}:task/${cluster}/${'9'.repeat(32)}`,clusterArn:meta.clusterArn,taskDefinitionArn:arn,lastStatus:'STOPPED',
    launchType:'FARGATE',cpu:'1024',memory:'2048',stopCode:'EssentialContainerExited',attributes:[{name:'ecs.cpu-architecture',value:'arm64'}],
    startedAt:new Date(start-2000),stoppedAt:new Date(start-1000),overrides:{containerOverrides:definition.containerDefinitions.map(c=>({name:c.name}))},
    containers:definition.containerDefinitions.map(c=>({name:c.name,image:c.image,imageDigest:c.name==='Mem9CanaryFixture'?images.runner.arm64Digest:images.database.arm64Digest,lastStatus:'STOPPED',exitCode:0}))};
  const extra=structuredClone(task);extra.taskArn=task.taskArn.replace(/9{32}$/,'8'.repeat(32));extra.lastStatus='RUNNING';
  let now=start,registered=false,launched=false,status='ACTIVE',discoveryAt=start,deployChecks=0,inventoryRound=0;
  const calls=[],states=[],events=[],stopped=[];
  const record={event:'canary_fixture_database',phase:'complete',identity,cases:17,completedMs:start-1200,databaseHash:'8'.repeat(64),checks:Object.fromEntries(canaryFixtureChecks.map(k=>[k,true]))};
  const send=async command=>{
    const name=command.constructor.name,input=command.input;calls.push(name);
    if(name==='RegisterTaskDefinitionCommand'){registered=true;return {taskDefinition:{taskDefinitionArn:arn}};}
    if(name==='DescribeTaskDefinitionCommand')return {taskDefinition:{...definition,taskDefinitionArn:arn,revision:1,status,tags:undefined},tags:options.badTags?[]:definition.tags};
    if(name==='ListTaskDefinitionsCommand')return {taskDefinitionArns:registered&&input.status===status?[arn]:[]};
    if(name==='RunTaskCommand'){
      launched=true;
      if(options.lostRun){task.lastStatus='RUNNING';discoveryAt=now+4000;throw Error('TransportLost');}
      if(options.persistFailure)task.lastStatus='RUNNING';
      if(options.failedTask)task.containers[0].exitCode=1;
      return {tasks:[task]};
    }
    if(name==='ListTasksCommand'){
      if(input.desiredStatus==='RUNNING')inventoryRound++;
      if(options.duplicateThenOmitted)return {taskArns:launched&&inventoryRound===1?[input.desiredStatus==='RUNNING'?extra.taskArn:task.taskArn]:[]};
      return {taskArns:!options.emptyInventory&&launched&&now>=discoveryAt&&input.desiredStatus===(task.lastStatus==='STOPPED'?'STOPPED':'RUNNING')?[task.taskArn]:[]};
    }
    if(name==='DescribeTasksCommand')return options.missingKnown?{tasks:[],failures:input.tasks.map(arn=>({arn,reason:'MISSING'}))}:
      {tasks:input.tasks.map(arn=>arn===task.taskArn?task:extra)};
    if(name==='StopTaskCommand'){if(options.stopFailure)throw Error('StopUncertain');const current=input.task===task.taskArn?task:extra;current.lastStatus='STOPPED';stopped.push(input.task);return {task:current};}
    if(name==='DeregisterTaskDefinitionCommand'){if(!options.deregisterFailure)status='INACTIVE';return {};}
    if(name==='FilterLogEventsCommand')return {events:[{eventId:'one',message:JSON.stringify(record)},...(options.duplicateRecord?[{eventId:'two',message:JSON.stringify(record)}]:[])]};
    throw Error('UnexpectedCommand:'+name);
  };
  const deps={now:()=>now,sleep:async ms=>{now+=ms;},persist:async s=>{states.push(structuredClone(s));if(options.persistFailure&&s.phase==='running')throw Error('JournalWriteFailed');},progress:e=>events.push(e),verifyDeployment:async()=>{
    deployChecks++;if(options.expireBeforeRun&&deployChecks===2)now=identity.deadlineMs+1;
  }};
  return {clients:{ecs:{send},ecsWrite:{send},logs:{send}},input:{meta,images,identity},deps,calls,states,events,stopped,extra,get now(){return now;}};
}
it('verifies the real task result and drains before recording pending physical deletion',async()=>{
  const f=fixture(),result=await runCanaryFixtureTask(f.clients,f.input,f.deps);
  expect(result.evidence.checks.cleanup).toBe(true);expect(result.evidence.completedMs).toBe(1800000000000-1200);
  expect(result.resources).toMatchObject({definitionStatus:'INACTIVE',physicalDeletionPending:true});
  expect(f.calls.filter(c=>c==='RunTaskCommand')).toHaveLength(1);
  expect(f.states.findIndex(s=>s.phase==='launch-intent')).toBeLessThan(f.states.findIndex(s=>s.phase==='running'));
  expect(f.events.at(-1).phase).toBe('fixture-cleanup');
});
it('reconciles a late task after a lost launch response without another RunTask',async()=>{
  const f=fixture({lostRun:true});await expect(runCanaryFixtureTask(f.clients,f.input,f.deps)).rejects.toThrow('TransportLost');
  expect(f.calls.filter(c=>c==='RunTaskCommand')).toHaveLength(1);expect(f.calls).toContain('StopTaskCommand');
  expect(f.now).toBeGreaterThanOrEqual(f.input.identity.deadlineMs+30000);expect(f.states.at(-1).phase).toBe('cleaned');
});
it.each(['failedTask','duplicateRecord'])('rejects %s and still cleans the owned definition',async kind=>{
  const f=fixture({[kind]:true});await expect(runCanaryFixtureTask(f.clients,f.input,f.deps)).rejects.toThrow();
  expect(f.states.at(-1).phase).toBe('cleaned');
});
it.each([{lostRun:true,stopFailure:true},{deregisterFailure:true},{badTags:true}])('retains unresolved cleanup evidence',async options=>{
  const f=fixture(options);await expect(runCanaryFixtureTask(f.clients,f.input,f.deps)).rejects.toThrow('CanaryFixtureCleanupPending');
  expect(f.states.at(-1).phase).toBe('cleanup-pending');
});
it('does not launch after the immutable deadline expires during preparation',async()=>{
  const f=fixture({expireBeforeRun:true});await expect(runCanaryFixtureTask(f.clients,f.input,f.deps)).rejects.toThrow('CanaryFixtureExpired');
  expect(f.calls).not.toContain('RunTaskCommand');expect(f.states.at(-1).phase).toBe('cleaned');
});
it('stops an acknowledged task even when ListTasks omits it after journal failure',async()=>{
  const f=fixture({persistFailure:true,emptyInventory:true});await expect(runCanaryFixtureTask(f.clients,f.input,f.deps)).rejects.toThrow('JournalWriteFailed');
  expect(f.calls).toContain('StopTaskCommand');expect(f.states.at(-1).phase).toBe('cleaned');
});
it('retains cleanup pending when a known task cannot be directly reconciled',async()=>{
  const f=fixture({persistFailure:true,emptyInventory:true,missingKnown:true});
  await expect(runCanaryFixtureTask(f.clients,f.input,f.deps)).rejects.toThrow('CanaryFixtureCleanupPending');
  expect(f.states.at(-1).phase).toBe('cleanup-pending');expect(f.calls).not.toContain('DeregisterTaskDefinitionCommand');
});
it('retains and stops an observed duplicate even when later inventories omit it',async()=>{
  const f=fixture({duplicateThenOmitted:true});await expect(runCanaryFixtureTask(f.clients,f.input,f.deps)).rejects.toThrow('CanaryFixtureDuplicateTask');
  expect(f.stopped).toContain(f.extra.taskArn);expect(f.states.at(-1).knownTaskArns).toHaveLength(2);expect(f.states.at(-1).phase).toBe('cleaned');
});
it('persists exact private ownership and reconciles a lost journal-write response once',async()=>{
  const f=fixture(),{meta,identity}=f.input;let parameter,writes=0;
  const send=async command=>{
    if(command.constructor.name==='GetParametersCommand')return {Parameters:parameter?[parameter]:[]};
    writes++;parameter={Name:command.input.Name,Type:command.input.Type,Value:command.input.Value,Version:writes};
    if(writes===2)throw Error('TransportLost');return {Version:writes};
  };
  const journal=createCanaryFixtureJournal({ssm:{send},ssmWrite:{send}},f.input);
  const state={version:1,stage:meta.stage,nonce:identity.nonce,deadlineMs:identity.deadlineMs,
    definition:createCanaryFixtureDefinition(meta,f.input.images,identity),phase:'prepared'};
  await journal.persist(state);state.phase='launch-intent';state.runRequest={clientToken:identity.nonce};await journal.persist(state);
  state.taskArn=meta.clusterArn.replace(':cluster/',':task/')+'/'+'9'.repeat(32);state.phase='cleaned';state.physicalDeletionPending=true;
  await journal.persist(state);expect(writes).toBe(3);
  expect(JSON.parse(parameter.Value)).toMatchObject({taskArn:state.taskArn,phase:'cleaned',physicalDeletionPending:true,runId:identity.runId});
  parameter.Value='foreign';await expect(journal.persist(state)).rejects.toThrow('CanaryFixtureJournalChanged');expect(writes).toBe(3);
});
