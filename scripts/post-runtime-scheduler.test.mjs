import {describe,it,expect,vi} from 'vitest';
import {runSchedulerAcceptance} from './consolidation-scheduler-e2e.mjs';
import {POST_RUNTIME_OPERATOR,postRuntimeCredentialReferences,postRuntimeOperatorEnvironment} from './lib/post-runtime-preview-route.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {dataLaunchPolicy} from './lib/production-nonroot-launch.mjs';
import {nonrootPostRuntimeFixture} from './nonroot-preview.fixture.mjs';
const deps=vi.hoisted(()=>({binding:null,bindings:null,checks:0}));
vi.mock('./lib/post-runtime-preview-aws.mjs',async original=>({...await original(),loadPostRuntimeOperator:async(_clients,options)=>deps.bindings?.get(options.purpose??'preview-fixture-pause')??deps.binding,revalidatePostRuntimeOperator:async()=>{deps.checks++;}}));
describe('dedicated post-runtime scheduler recovery',()=>{
  it.each([1,2])('holds legacy routes or recovers a lost setup through its exact guarded revision (version %s)',async version=>{
    const stage='pr-7',region='ap-northeast-1',account='123456789012',generation='a'.repeat(64),context={kind:'post-runtime',runtimeNonce:'b'.repeat(32)},tree='c'.repeat(40);
    const clusterName='mem9-on-aws-pr-7-Cluster-example',clusterArn=`arn:aws:ecs:${region}:${account}:cluster/${clusterName}`;
    const manifest={stage,generation,clusterArn,groupName:'mem9-on-aws-pr-7-consolidation-example',roleArn:`arn:aws:iam::${account}:role/mem9-on-aws-pr-7-Mem9ConsolidationSchedulerRole-role`,
      workers:['planner','executor'].map(kind=>({kind,containerName:'Mem9Consolidation'+(kind==='planner'?'Planner':'Executor'),taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/${clusterName}-Mem9Consolidation${kind}:1`,scheduleName:`mem9-on-aws-pr-7-${kind}-test`,logGroupName:'/sst/test'}))};
    const route={version:1,kind:'post-runtime-preview-operator',stage,region,account,generation,context,controlSourceTree:tree,clusterArn,
      taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/${clusterName}-${POST_RUNTIME_OPERATOR}:1`,containerName:POST_RUNTIME_OPERATOR,
      image:`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/preview/bootstrap@sha256:${'d'.repeat(64)}`,
      taskRoleArn:`arn:aws:iam::${account}:role/mem9-on-aws-pr-7-${POST_RUNTIME_OPERATOR}TaskRole-role-test`,
      executionRoleArn:`arn:aws:iam::${account}:role/mem9-on-aws-pr-7-${POST_RUNTIME_OPERATOR}ExecutionRole-role-test`,
      subnets:['subnet-aaaabbbb'],securityGroup:'sg-aaaabbbb',host:'writer.example.com',port:5432,database:'mem9',
      kmsKeyArn:`arn:aws:kms:${region}:${account}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`,credentials:postRuntimeCredentialReferences(stage,account,region)};
    const def={taskDefinitionArn:route.taskDefinitionArn,taskRoleArn:route.taskRoleArn,executionRoleArn:route.executionRoleArn,networkMode:'awsvpc',cpu:'256',memory:'512',requiresCompatibilities:['FARGATE'],runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},
      containerDefinitions:[{name:POST_RUNTIME_OPERATOR,image:route.image,entryPoint:['node'],command:['/bootstrap/operator/scripts/consolidation-preview-fixture.mjs'],user:'node',readonlyRootFilesystem:true,linuxParameters:{capabilities:{drop:['ALL']}},
        environment:Object.entries(postRuntimeOperatorEnvironment(route)).map(([name,value])=>({name,value})),secrets:Object.entries(route.credentials).map(([name,valueFrom])=>({name,valueFrom})),
        logConfiguration:{logDriver:'awslogs',options:{'awslogs-group':'/sst/mem9-on-aws/pr-7/operator','awslogs-region':region,'awslogs-stream-prefix':'ecs'}}}]};
    const guarded=nonrootPostRuntimeFixture(route),image={rootDigest:'sha256:'+'d'.repeat(64),arm64Digest:'sha256:'+'e'.repeat(64)};
    deps.binding={route,definition:def,observation:{taskDefinition:def,tags:[]},image};deps.checks=0;
    deps.bindings=version===2?new Map(guarded.records.map(r=>[r.purpose,{route:guarded.routes.get(r.purpose),purpose:r.purpose,purposeBindings:guarded.map.bindings,
      definition:r.observation.taskDefinition,observation:r.observation,image,parameters:[]}])):null;
    let now=Date.now(),sequence=0;const store=new Map([['/mem9-on-aws/pr-7/consolidation-preview/manifest',JSON.stringify(manifest)]]),tasks=new Map(),calls=[];
    const client={send:async command=>{
      const kind=command.constructor.name,input=command.input;calls.push({kind,input});
      if(kind==='GetParametersCommand')return {Parameters:input.Names.filter(n=>store.has(n)).map(Name=>({Name,Value:store.get(Name)})),InvalidParameters:input.Names.filter(n=>!store.has(n))};
      if(kind==='PutParameterCommand'){store.set(input.Name,input.Value);return {};}
      if(kind==='DeleteParameterCommand'){store.delete(input.Name);return {};}
      if(kind==='GetParametersByPathCommand')return {Parameters:[...store].filter(([n])=>n.startsWith(input.Path)).map(([Name,Value])=>({Name,Value}))};
      if(kind==='DescribeTaskDefinitionCommand'){
        if(guarded.definitions.has(input.taskDefinition))return guarded.definitions.get(input.taskDefinition);
        const worker=manifest.workers.find(w=>w.taskDefinitionArn===input.taskDefinition);
        return {taskDefinition:{taskDefinitionArn:input.taskDefinition,containerDefinitions:[dataLaunchPolicy(worker.kind,{name:worker.containerName,entryPoint:['node'],command:['/app/scripts/consolidation-worker.mjs'],environment:[{name:'MEM9_WORKER_GENERATION',value:generation}]})]},tags:[]};
      }
      if(kind==='DescribeDBClustersCommand')return {DBClusters:[{Endpoint:route.host,DBClusterIdentifier:'mem9-on-aws-pr-7-db',DBClusterArn:'db-arn',DBClusterMembers:[{DBInstanceIdentifier:'mem9-on-aws-pr-7-instance'}]}]};
      if(kind==='ListTagsForResourceCommand')return {TagList:[{Key:'Project',Value:'mem9-on-aws'},{Key:'Stage',Value:stage}]};
      if(kind==='DescribeDBInstancesCommand')return {DBInstances:[{DBInstanceIdentifier:'mem9-on-aws-pr-7-instance',DBClusterIdentifier:'mem9-on-aws-pr-7-db'}]};
      if(kind==='DescribeDBLogFilesCommand')return {DescribeDBLogFiles:[{LogFileName:'error/postgresql.log.2026-10-03-0000',Size:0,LastWritten:now-1000}]};
      if(kind==='RunTaskCommand'){
        const taskArn=clusterArn.replace(':cluster/',':task/')+'/'+(++sequence).toString(16).padStart(32,'0');
        const operation=input.overrides.containerOverrides[0].environment.find(e=>e.name==='MEM9_BOOTSTRAP_OPERATION').value;
        const task={taskArn,clusterArn,taskDefinitionArn:input.taskDefinition,overrides:input.overrides,lastStatus:operation.endsWith('-setup')?'RUNNING':'STOPPED',
          containers:[{name:POST_RUNTIME_OPERATOR,image:route.image,imageDigest:image.arm64Digest,exitCode:0}]};tasks.set(taskArn,task);
        if(operation.endsWith('-setup'))throw Error('PostSetupResponseLost');
        return {tasks:[task]};
      }
      if(kind==='DescribeTasksCommand')return {tasks:input.tasks.map(n=>tasks.get(n))};
      if(kind==='ListTasksCommand')return {taskArns:[...tasks.values()].filter(t=>t.lastStatus===input.desiredStatus).map(t=>t.taskArn)};
      if(kind==='StopTaskCommand'){tasks.get(input.task).lastStatus='STOPPED';return {};}
      if(kind==='FilterLogEventsCommand')return {events:[{message:JSON.stringify({event:'consolidation_preview',outcome:'paused',authority:{stage,generation,contextHash:hash(context),administratorOid:41,runtimeStateHash:'f'.repeat(64),runtimeRowsHash:'f'.repeat(64)}})}]};
      throw Error('UnexpectedOperation');
    }};
    await expect(runSchedulerAcceptance({clients:{ssm:client,ecs:client,scheduler:client,logs:client,rds:client},stage,region,generation,postRuntime:context,controlSourceTree:tree,
      now:()=>now,sleep:async ms=>{now+=ms;},progress:()=>{}})).rejects.toThrow(version===1?'NonrootPreviewVersionRequired':'PostSetupResponseLost');
    const launches=calls.filter(c=>c.kind==='RunTaskCommand');
    expect(launches.filter(c=>c.input.overrides.containerOverrides[0].environment[0].value.endsWith('-setup'))).toHaveLength(version===1?0:1);
    expect(launches.every(c=>guarded.definitions.has(c.input.taskDefinition)&&c.input.overrides.containerOverrides[0].name===POST_RUNTIME_OPERATOR)).toBe(true);
    expect([...store.keys()].filter(n=>n.includes('/operators/'))).toEqual([]);
    if(version===1)expect(launches).toHaveLength(0);else{
      expect(new Set(launches.map(c=>c.input.taskDefinition)).size).toBe(2);
      expect(calls.some(c=>c.kind==='StopTaskCommand')).toBe(true);expect(deps.checks).toBeGreaterThanOrEqual(6);
    }
  });
});
