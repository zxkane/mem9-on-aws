import {it,expect} from 'vitest';
import {createCanaryFixtureDefinition,verifyCanaryFixtureDefinition,verifyCanaryFixtureTask,fixtureEvidenceFromRecord} from './lib/canary-fixture-task.mjs';
import {canaryFixtureChecks} from './lib/production-canary-fixture-evidence.mjs';
const region='ap-northeast-1',account='123456789012',stage='pr-7',cluster='mem9-on-aws-pr-7-Fixture';
const digest=n=>'sha256:'+n.repeat(64),repo=`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/preview/bootstrap`;
function fixture(){
 const identity={stage,runId:'12345',runAttempt:1,commit:'a'.repeat(40),sourceTree:'b'.repeat(40),coordinatorDigest:'c'.repeat(64),
  schemaDigest:'d'.repeat(64),operatorDigest:'e'.repeat(64),nonce:'f'.repeat(32),deadlineMs:1800000600000};
 const meta={account,region,stage,cluster,clusterArn:`arn:aws:ecs:${region}:${account}:cluster/${cluster}`,subnets:['subnet-abcd'],securityGroup:'sg-abcd',
  executionRoleArn:`arn:aws:iam::${account}:role/mem9-on-aws-pr-7-Mem9BootstrapExecutionRole-test`,logGroup:`/sst/cluster/${cluster}/Mem9Bootstrap/Mem9Bootstrap`};
 const images={runner:{image:repo+'@'+digest('1'),rootDigest:digest('1'),arm64Digest:digest('2')},database:{image:repo+'@'+digest('3'),rootDigest:digest('3'),arm64Digest:digest('4')}};
 const expected=createCanaryFixtureDefinition(meta,images,identity),arn=`arn:aws:ecs:${region}:${account}:task-definition/${expected.family}:1`;
 const definition={...structuredClone(expected),taskDefinitionArn:arn,revision:1,status:'ACTIVE'};delete definition.tags;
 const task={taskArn:`arn:aws:ecs:${region}:${account}:task/${cluster}/${'9'.repeat(32)}`,clusterArn:meta.clusterArn,taskDefinitionArn:arn,lastStatus:'STOPPED',
  launchType:'FARGATE',cpu:'1024',memory:'2048',attributes:[{name:'ecs.cpu-architecture',value:'arm64'}],stopCode:'EssentialContainerExited',startedAt:new Date(1800000000000),stoppedAt:new Date(1800000500000),
  overrides:{containerOverrides:expected.containerDefinitions.map(c=>({name:c.name}))},containers:expected.containerDefinitions.map(c=>({name:c.name,image:c.image,
    imageDigest:c.name==='Mem9CanaryFixture'?images.runner.arm64Digest:images.database.arm64Digest,lastStatus:'STOPPED',exitCode:0}))};
 return {identity,meta,images,expected,definition,task};
}
it('creates a bounded preview fixture with no application AWS role, secrets or exposed ports',()=>{
 const f=fixture();expect(f.expected.taskRoleArn).toBeUndefined();
 expect(f.expected.containerDefinitions.every(c=>c.secrets.length===0&&c.portMappings.length===0&&c.user!=='root')).toBe(true);
 expect(f.expected.containerDefinitions[0].dependsOn).toEqual([{containerName:'CanaryPostgres',condition:'HEALTHY'}]);
 expect(()=>verifyCanaryFixtureDefinition(f.definition,f.expected,f.meta)).not.toThrow();
  expect(()=>verifyCanaryFixtureTask(f.task,f.definition,f.expected,f.meta,f.images)).not.toThrow();
  for(const container of f.definition.containerDefinitions)container.linuxParameters.capabilities.add=[];
  expect(()=>verifyCanaryFixtureDefinition(f.definition,f.expected,f.meta)).not.toThrow();
  f.definition.containerDefinitions[0].linuxParameters.capabilities.add=['SYS_PTRACE'];
  expect(()=>verifyCanaryFixtureDefinition(f.definition,f.expected,f.meta)).toThrow();
  f.definition.containerDefinitions[0].linuxParameters.capabilities.add=[];
  f.task.overrides.inferenceAcceleratorOverrides=[];
  f.task.overrides.containerOverrides.reverse();
  expect(()=>verifyCanaryFixtureTask(f.task,f.definition,f.expected,f.meta,f.images)).not.toThrow();
  for(const value of [null,{},[{deviceName:'unexpected'}]]){
    f.task.overrides.inferenceAcceleratorOverrides=value;
    expect(()=>verifyCanaryFixtureTask(f.task,f.definition,f.expected,f.meta,f.images)).toThrow();
  }
});
it('preserves the image guard with fixed absolute Node and leaves PostgreSQL on its separate UID 999 contract',()=>{
 const f=fixture(),runner=f.expected.containerDefinitions.find(c=>c.name==='Mem9CanaryFixture'),db=f.expected.containerDefinitions.find(c=>c.name==='CanaryPostgres');
 expect(runner.entryPoint).toEqual(['/bin/setpriv','--no-new-privs','--','/usr/local/bin/node','/bootstrap/nonroot-dispatch.mjs','canary-fixture']);
 expect(runner.command).toEqual([]);expect(runner.user).toBe('1000:1000');expect(runner.linuxParameters.capabilities).toEqual({drop:['ALL']});
 expect(db.user).toBe('999:999');expect(db.entryPoint).toEqual(['docker-entrypoint.sh']);expect(db.command[0]).toBe('postgres');
 expect(db.healthCheck.command).toEqual(['CMD','pg_isready','-h','127.0.0.1','-U','postgres','-d','runtime_credentials_test']);
 for(const patch of [{entryPoint:['node']},{entryPoint:runner.entryPoint.map(v=>v==='/usr/local/bin/node'?'node':v)},{command:['/bootstrap/operator/scripts/canary-fixture-runner.mjs']},{user:'root'}]){
  const actual=structuredClone(f.definition);Object.assign(actual.containerDefinitions[0],patch);expect(()=>verifyCanaryFixtureDefinition(actual,f.expected,f.meta)).toThrow();
 }
});
it('rejects credential injection, different code, overrides and foreign or unfinished tasks',()=>{
 for(const mutate of [f=>{f.definition.taskRoleArn=f.meta.executionRoleArn;},f=>{f.definition.containerDefinitions[0].secrets=[{name:'DB',valueFrom:'foreign'}];},
  f=>{f.definition.containerDefinitions[0].environment.push({name:'UNEXPECTED',value:'x'});},f=>{f.definition.containerDefinitions[0].privileged=true;},
  f=>{f.task.containers[0].imageDigest=digest('8');},f=>{f.task.overrides.taskRoleArn=f.meta.executionRoleArn;},
  f=>{f.task.overrides.containerOverrides[0].command=['unexpected'];},f=>{f.task.containers[0].lastStatus='RUNNING';},
  f=>{f.task.clusterArn+='foreign';},f=>{f.task.containers[0].exitCode=1;}]){
  const f=fixture();mutate(f);expect(()=>{verifyCanaryFixtureDefinition(f.definition,f.expected,f.meta);verifyCanaryFixtureTask(f.task,f.definition,f.expected,f.meta,f.images);}).toThrow();
 }
});
it('requires matching complete database evidence within the immutable task deadline',()=>{
 const f=fixture(),record={event:'canary_fixture_database',phase:'complete',identity:f.identity,cases:17,databaseHash:'8'.repeat(64),completedMs:1800000400000,
  checks:Object.fromEntries(canaryFixtureChecks.map(k=>[k,true]))};
 expect(fixtureEvidenceFromRecord(record,f.identity,f.task,1800000500001)).toMatchObject({kind:'synthetic-canary-continuation',stage});
 for(const patch of [{cases:16},{completedMs:f.identity.deadlineMs+1},{identity:{...f.identity,nonce:'a'.repeat(32)}},{checks:{...record.checks,cleanup:false}}]){
  expect(()=>fixtureEvidenceFromRecord({...record,...patch},f.identity,f.task,1800000500001)).toThrow();
 }
});
it('refuses production and other-account execution/image configuration',()=>{
 const f=fixture();
 for(const patch of [{stage:'prod'},{executionRoleArn:f.meta.executionRoleArn.replace(account,'0'.repeat(12))},{logGroup:'/unrelated'}]){
  expect(()=>createCanaryFixtureDefinition({...f.meta,...patch},f.images,f.identity)).toThrow();
 }
});
