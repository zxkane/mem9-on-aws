import {describe,it,expect} from 'vitest';
import {runProductionConsolidationTask,stopPreviousProductionAdministration} from './run-production-consolidation.mjs';
import {productionSourceTree,productionCoordinatorDigest} from './run-production-runtime.mjs';
import {execFileSync} from 'node:child_process';
import {controlLaunchPolicy} from './lib/production-nonroot-launch.mjs';
import {installImageAuthorization} from './lib/production-image-admission.mjs';
import {completeNonrootProofFixture,nonrootAuthorizationValues} from './production-nonroot.fixture.mjs';
import {buildNonrootImageTransitionProof,nonrootProofExpected,nonrootTransitionContextBindings,bindNonrootTransitionAuthorization} from './lib/production-nonroot-proof.mjs';
import {nonrootHash} from './lib/production-nonroot-contracts.mjs';
import {installMaintenanceAdmission,requireMaintenanceAdmission,assertMaintenancePhase} from './lib/production-maintenance-admission.mjs';

const account='123456789012',region='ap-northeast-1',cluster='mem9-on-aws-prod-Fixture',name='ControlMem9Bootstrap';
const prefix=`arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/prod/`;
const taskDefinition=`arn:aws:ecs:${region}:${account}:task-definition/${cluster}-${name}:1`;
function fixture({drift=false,loseReply=false,wrongNonce=false,taskDrift,acceptance,sourceTag='mem9-aaaaaaa',phase='ready',guard=true,nonroot=false,definitionDrift,operatorKind='control'}={}){
  const name=operatorKind==='promotion'?'PromoteMem9Bootstrap':operatorKind==='provision'?'ProdMem9Bootstrap':'ControlMem9Bootstrap';
  const taskDefinition=`arn:aws:ecs:${region}:${account}:task-definition/${cluster}-${name}:1`;
  const calls=[],journals=new Map();let task,time=Date.now();
  const meta={version:1,stage:'prod',region,account,cluster,clusterArn:`arn:aws:ecs:${region}:${account}:cluster/${cluster}`,
    sourceTag,workerImage:`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/llm-proxy@sha256:${'d'.repeat(64)}`,
    host:'mem9-on-aws-prod-fixture.cluster-example.ap-northeast-1.'+['rds','amazonaws','com'].join('.'),port:5432,database:'mem9',generation:'a'.repeat(64),
    subnets:['subnet-abcd'],securityGroup:'sg-abcd',administratorCredential:prefix+'runtime/schema-administrator-credential',
    plannerCredential:prefix+'consolidation-runtime/planner-credential',executorCredential:prefix+'consolidation-runtime/executor-credential',targetsParameter:prefix+'maintenance/targets',
    operators:{[operatorKind]:{containerName:name,taskDefinition,image:`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/bootstrap@sha256:${'e'.repeat(64)}`}}};
  const executionRole=`arn:aws:iam::${account}:role/mem9-on-aws-prod-${name}ExecutionRole-synthetic`;
  const taskRole=`arn:aws:iam::${account}:role/mem9-on-aws-${taskDrift==='scope'?'pr-7':'prod'}-${name}TaskRole-synthetic`;
  const trust={Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'sts:AssumeRole',Principal:{Service:'ecs-tasks.amazonaws.com'},Condition:{
    StringEquals:{'aws:SourceAccount':account},ArnLike:{'aws:SourceArn':`arn:aws:ecs:${region}:${account}:*`}}}]};
  const injected=[{name:'MEM9_DB_SECRET',valueFrom:meta.administratorCredential}];
  if(operatorKind==='promotion')for(let i=0;i<4;i++)injected.push({name:`MEM9_CANARY_REPORT_${i}`,valueFrom:prefix+`consolidation-runtime/canary-report-${i}`});
  if(operatorKind==='provision')injected.push({name:'MEM9_PLANNER_DB_SECRET',valueFrom:meta.plannerCredential},{name:'MEM9_EXECUTOR_DB_SECRET',valueFrom:meta.executorCredential},{name:'MEM9_WORKER_TARGETS',valueFrom:meta.targetsParameter});
  const references=injected.map(secret=>secret.valueFrom);
  const policy={Version:'2012-10-17',Statement:[{Effect:'Allow',Action:['ssm:GetParameters'],Resource:references},
    {Effect:'Allow',Action:['kms:Decrypt'],Resource:'*',Condition:{StringEquals:{'kms:ViaService':`ssm.${region}.amazonaws.com`,'kms:EncryptionContext:PARAMETER_ARN':references}}}]};
  const send=async command=>{
    const type=command.constructor.name,input=command.input;calls.push({type,input});
    if(type==='GetCallerIdentityCommand')return {Account:account};
    if(type==='GetParametersCommand')return {Parameters:[{Value:JSON.stringify(input.Names[0].includes('rehearsal-acceptance')?acceptance:meta)}]};
    if(type==='GetParametersByPathCommand')return {Parameters:[...journals].map(([Name,Value])=>({Name,Value}))};
    if(type==='DescribeTaskDefinitionCommand'){const definition={taskDefinitionArn:taskDefinition,executionRoleArn:executionRole,taskRoleArn:taskRole,networkMode:'awsvpc',runtimePlatform:{cpuArchitecture:'ARM64'},
      containerDefinitions:[{name,image:meta.operators[operatorKind].image,entryPoint:['node'],command:['/bootstrap/operator/scripts/production-consolidation-operator.mjs'],
        environment:Object.entries({MEM9_STAGE:'prod',MEM9_DB_HOST:meta.host,MEM9_DB_NAME:'mem9',MEM9_DB_PORT:'5432',MEM9_WORKER_GENERATION:meta.generation,MEM9_PRODUCTION_WORKER_OPERATOR:operatorKind,MEM9_WORKER_IMAGE:meta.workerImage,MEM9_WORKER_SOURCE_TAG:meta.sourceTag}).map(([name,value])=>({name,value})),
        secrets:injected,logConfiguration:{options:{'awslogs-group':'/synthetic','awslogs-stream-prefix':'operator'}}}]};
      if(nonroot){definition.runtimePlatform.operatingSystemFamily='LINUX';definition.containerDefinitions=[structuredClone(controlLaunchPolicy({control:'consolidation-control',promotion:'consolidation-promote',provision:'denied-provision'}[operatorKind],definition.containerDefinitions[0]))];}
      definitionDrift?.(definition);return {taskDefinition:definition};
    }
    const taskIdentity=input.RoleName===taskRole.split('/').at(-1);
    if(type==='GetRoleCommand')return {Role:{Arn:taskIdentity?taskRole:executionRole,
      AssumeRolePolicyDocument:taskIdentity&&taskDrift==='trust'?{Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'sts:AssumeRole',Principal:{AWS:'*'}}]}:trust,
      PermissionsBoundary:taskIdentity&&taskDrift==='boundary'?undefined:{PermissionsBoundaryArn:`arn:aws:iam::${account}:policy/mem9-on-aws-workload-boundary`}}};
    if(type==='ListRolePoliciesCommand')return {PolicyNames:taskIdentity?['inline']:['ProductionWorkerOperator']};
    if(type==='ListAttachedRolePoliciesCommand')return {AttachedPolicies:taskIdentity&&taskDrift!=='attachment'?[]:[{PolicyArn:'arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'}]};
    if(type==='GetRolePolicyCommand')return {PolicyDocument:drift||(taskIdentity&&taskDrift==='policy')?{Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'ssm:*',Resource:'*'}]}:
      taskIdentity?{Version:'2012-10-17',Statement:[{Effect:'Allow',Action:['ssmmessages:CreateControlChannel','ssmmessages:CreateDataChannel','ssmmessages:OpenControlChannel','ssmmessages:OpenDataChannel'],Resource:'*'}]}:policy};
    if(type==='PutParameterCommand'){journals.set(input.Name,input.Value);return {};}
    if(type==='DeleteParameterCommand'){journals.delete(input.Name);return {};}
    if(type==='RunTaskCommand'){
      task={taskArn:`arn:aws:ecs:${region}:${account}:task/${cluster}/synthetic`,clusterArn:meta.clusterArn,taskDefinitionArn:taskDefinition,overrides:input.overrides,lastStatus:'STOPPED',containers:[{name,exitCode:0}]};
      if(loseReply)throw Error('SyntheticLostReply');return {tasks:[task]};
    }
    if(type==='DescribeTasksCommand')return {tasks:[task]};
    if(type==='ListTasksCommand')return {taskArns:task?[task.taskArn]:[]};
    if(type==='StopTaskCommand'){task.lastStatus='STOPPED';return {};}
    if(type==='FilterLogEventsCommand'){
      const request=JSON.parse(task.overrides.containerOverrides[0].environment.find(e=>e.name==='MEM9_PRODUCTION_CONSOLIDATION_REQUEST').value);
      return {events:[{eventId:'result',message:JSON.stringify({event:'production_consolidation_operator',phase:request.operation,outcome:'complete',invocation:wrongNonce?'wrong':request.invocation})}]};
    }
    throw Error('UnexpectedCommand');
  };
  const clients={ssm:{send},ecs:{send},logs:{send},sts:{send},iam:{send}};
  if(guard){const binding={owner:'a'.repeat(32),operationHash:'b'.repeat(64),fenceHash:'c'.repeat(64),sourceTree:'d'.repeat(40)};let mint;mint=installMaintenanceAdmission(clients,{binding,assertCurrent:()=>{},verify:async event=>{assertMaintenancePhase(phase,event.kind);expect(event.target.image).toBe(meta.operators[operatorKind].image);expect(event.target.taskDefinitionArn).toBe(taskDefinition);const at=Date.now();return mint(event,{...binding,phase,observedMs:at,expiresMs:at+300000});}});}
  return {meta,clients,calls,journals,options:{now:()=>time,sleep:async ms=>{time+=ms;}}};
}
describe('production worker administrative task invocation',()=>{
  it('serializes continuation fields into the bounded owned task request without silently dropping them',async()=>{
    const revision=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
    const acceptance={sourceTree:await productionSourceTree(),coordinatorDigest:await productionCoordinatorDigest()};
    const f=fixture({acceptance,sourceTag:'mem9-'+revision.slice(0,7)});
    const data={attemptId:'b'.repeat(32),parentProofHash:'c'.repeat(64),compatibility:{version:1}};
    await runProductionConsolidationTask(f.clients,{region,operation:'begin-continuation',...data},f.options);
    const launch=f.calls.find(c=>c.type==='RunTaskCommand');
    const request=JSON.parse(launch.input.overrides.containerOverrides[0].environment.find(e=>e.name==='MEM9_PRODUCTION_CONSOLIDATION_REQUEST').value);
    expect(request).toMatchObject({operation:'begin-continuation',...data});expect(f.journals.size).toBe(0);
    const rejected=fixture();
    await expect(runProductionConsolidationTask(rejected.clients,{region,operation:'status',...data},rejected.options)).rejects.toThrow();
    expect(rejected.calls.some(c=>c.type==='RunTaskCommand')).toBe(false);
  });
  it('validates the control credential and exact IAM policy, then matches the terminal nonce',async()=>{
    const f=fixture();expect((await runProductionConsolidationTask(f.clients,{region,operation:'status'},f.options)).outcome).toBe('complete');
    expect(f.journals.size).toBe(0);
    expect(f.calls.filter(c=>c.type==='RunTaskCommand')).toHaveLength(1);
    expect(f.calls.some(c=>c.type==='GetParametersCommand'&&c.input.Names[0].includes('rehearsal-acceptance'))).toBe(false);
  });
  it('rejects widened credential readers before launching',async()=>{
    const f=fixture({drift:true});await expect(runProductionConsolidationTask(f.clients,{region,operation:'status'},f.options)).rejects.toThrow('ProductionOperatorPolicyMismatch');
    expect(f.calls.some(c=>c.type==='RunTaskCommand')).toBe(false);
  });
  it.each(['scope','trust','boundary','policy','attachment'])('rejects administrator task-role %s drift before launching',async taskDrift=>{
    const f=fixture({taskDrift});
    await expect(runProductionConsolidationTask(f.clients,{region,operation:'status'},f.options)).rejects.toThrow();
    expect(f.calls.some(c=>c.type==='RunTaskCommand')).toBe(false);
  });
  it.each([{loseReply:true},{wrongNonce:true}])('retains recovery state after ambiguous or mismatched completion %o',async options=>{
    const f=fixture(options);await expect(runProductionConsolidationTask(f.clients,{region,operation:'status'},f.options)).rejects.toThrow();
    expect(f.journals.size).toBe(1);
  });
  it('reconciles an accepted task whose launch response was lost before another mutation',async()=>{
    const f=fixture({loseReply:true});
    await expect(runProductionConsolidationTask(f.clients,{region,operation:'status'},f.options)).rejects.toThrow('SyntheticLostReply');
    await stopPreviousProductionAdministration(f.clients,f.meta,f.options);
    expect(f.journals.size).toBe(0);
    expect(f.calls.some(c=>c.type==='ListTasksCommand')).toBe(true);
  });
});
it('before deployment a general status task is not the fixed legacy root-audit exception',async()=>{
 const f=fixture({phase:'before-deployment'});await expect(runProductionConsolidationTask(f.clients,{region,operation:'status'},f.options)).rejects.toThrow('MaintenancePhaseDenied');expect(f.calls.some(c=>['PutParameterCommand','RunTaskCommand'].includes(c.type))).toBe(false);
});
it('before witness the host may explicitly verify its authenticated target with status',async()=>{
 const f=fixture({phase:'before-witness'});expect((await runProductionConsolidationTask(f.clients,{region,operation:'status'},f.options)).phase).toBe('status');
 expect(f.calls.filter(c=>c.type==='RunTaskCommand')).toHaveLength(1);
});
it('actual admin dispatch fails closed without a verified host registration',async()=>{
 const f=fixture({guard:false});requireMaintenanceAdmission(f.clients);await expect(runProductionConsolidationTask(f.clients,{region,operation:'status'},f.options)).rejects.toThrow('MaintenanceAdmissionRequired');expect(f.journals.size).toBe(0);
});

describe('guarded production administration',()=>{
  it('accepts the actual controlLaunchPolicy definition while keeping command overrides absent',async()=>{
    const f=fixture({nonroot:true});expect((await runProductionConsolidationTask(f.clients,{region,operation:'status'},f.options)).outcome).toBe('complete');
    const launches=f.calls.filter(c=>c.type==='RunTaskCommand');expect(launches).toHaveLength(1);
    expect(launches[0].input.networkConfiguration).toEqual({awsvpcConfiguration:{subnets:f.meta.subnets,securityGroups:[f.meta.securityGroup],assignPublicIp:'DISABLED'}});
    expect(Object.keys(launches[0].input.overrides.containerOverrides[0]).sort()).toEqual(['environment','name']);expect(f.journals.size).toBe(0);
  });
  const defects={
    'root-user':d=>d.containerDefinitions[0].user='0:0',
    'named-user':d=>d.containerDefinitions[0].user='node',
    'privileged':d=>d.containerDefinitions[0].privileged=true,
    'added-capability':d=>d.containerDefinitions[0].linuxParameters.capabilities.add=['SYS_ADMIN'],
    'missing-drop-all':d=>d.containerDefinitions[0].linuxParameters.capabilities.drop=[],
    'missing-nnp':d=>d.containerDefinitions[0].entryPoint.splice(1,1),
    'wrong-argv-order':d=>d.containerDefinitions[0].entryPoint.reverse(),
    'wrong-purpose':d=>d.containerDefinitions[0].entryPoint[5]='consolidation-promote',
    'inspection-purpose':d=>d.containerDefinitions[0].entryPoint[5]='continuation-inspection',
    'relative-node':d=>d.containerDefinitions[0].entryPoint[3]='node',
    'wrong-dispatcher':d=>d.containerDefinitions[0].entryPoint[4]='/bootstrap/other.mjs',
    'extra-command':d=>d.containerDefinitions[0].command=['--extra'],
    'raw-node-e':d=>{d.containerDefinitions[0].entryPoint=['node'];d.containerDefinitions[0].command=['-e','process.exit(0)'];},
    'guard-downgrade':d=>{d.containerDefinitions[0].entryPoint=['node'];d.containerDefinitions[0].command=['/bootstrap/operator/scripts/production-consolidation-operator.mjs'];},
    'wrong-network':d=>d.networkMode='host',
    'wrong-platform':d=>d.runtimePlatform.operatingSystemFamily='WINDOWS_SERVER_2022_CORE',
    'wrong-secret':d=>d.containerDefinitions[0].secrets[0].valueFrom+='-other',
    'duplicate-secret':d=>d.containerDefinitions[0].secrets.push({...d.containerDefinitions[0].secrets[0]}),
    'plaintext-secret':d=>d.containerDefinitions[0].environment.push({name:'MEM9_DB_SECRET',value:'synthetic-not-a-secret'}),
    'loader-environment':d=>d.containerDefinitions[0].environment.push({name:'NODE_OPTIONS',value:'--import=/tmp/other.mjs'}),
    'preload-environment':d=>d.containerDefinitions[0].environment.push({name:'LD_PRELOAD',value:'/tmp/other.so'}),
    'duplicate-environment':d=>d.containerDefinitions[0].environment.push({...d.containerDefinitions[0].environment[0]}),
  };
  it.each(Object.entries(defects))('rejects %s before any journal write or launch',async(_name,definitionDrift)=>{
    const f=fixture({nonroot:true,definitionDrift});await expect(runProductionConsolidationTask(f.clients,{region,operation:'status'},f.options)).rejects.toThrow('ProductionWorkerOperatorDefinitionMismatch');
    expect(f.calls.some(c=>['PutParameterCommand','DeleteParameterCommand','RunTaskCommand'].includes(c.type))).toBe(false);
  });
  it.each(['scope','trust','boundary','policy','attachment'])('retains exact IAM %s checks for guarded launches',async taskDrift=>{
    const f=fixture({nonroot:true,taskDrift});await expect(runProductionConsolidationTask(f.clients,{region,operation:'status'},f.options)).rejects.toThrow();expect(f.calls.some(c=>['PutParameterCommand','RunTaskCommand'].includes(c.type))).toBe(false);
  });
  it('still requires the original host maintenance admission for a guarded launch',async()=>{
    const f=fixture({nonroot:true,guard:false});requireMaintenanceAdmission(f.clients);await expect(runProductionConsolidationTask(f.clients,{region,operation:'status'},f.options)).rejects.toThrow('MaintenanceAdmissionRequired');expect(f.journals.size).toBe(0);
  });
  it('accepts the guarded promotion definition and exact report-secret roles but still requires rehearsal evidence',async()=>{
    const f=fixture({nonroot:true,operatorKind:'promotion'});
    await expect(runProductionConsolidationTask(f.clients,{region,operation:'promote'},f.options)).rejects.toThrow('ProductionWorkerRehearsalRequired');
    expect(f.calls.filter(c=>c.type==='GetRoleCommand')).toHaveLength(2);
    expect(f.calls.some(c=>['PutParameterCommand','RunTaskCommand'].includes(c.type))).toBe(false);
  });
  it('does not turn the explicitly denied nonroot provision purpose into an admin launch',async()=>{
    const f=fixture({nonroot:true,operatorKind:'provision'});
    await expect(runProductionConsolidationTask(f.clients,{region,operation:'prepare'},f.options)).rejects.toThrow('ProductionWorkerOperatorDefinitionMismatch');
    expect(f.calls.some(c=>['GetRoleCommand','PutParameterCommand','RunTaskCommand'].includes(c.type))).toBe(false);
  });
  it.each(['status','pause'])('%s cannot strip every guard and select the legacy launch after native nonroot authorization is installed',async operation=>{
    const p=await completeNonrootProofFixture(),built=await buildNonrootImageTransitionProof(p.input,{expected:nonrootProofExpected(p.input,{proofHash:nonrootHash(p.input)}),evidence:p.evidence,now:p.now});
    const {review,current:data}=nonrootAuthorizationValues(p,built,nonrootTransitionContextBindings(built.context));
    const context=bindNonrootTransitionAuthorization(built.context,{review,now:p.now}),f=fixture();
    installImageAuthorization(f.clients,context,{data,controlSourceTree:data.controlSourceTree,now:p.now});
    await expect(runProductionConsolidationTask(f.clients,{region,operation},f.options)).rejects.toThrow('ProductionWorkerOperatorDefinitionMismatch');
    expect(f.calls.some(c=>['PutParameterCommand','RunTaskCommand'].includes(c.type))).toBe(false);
  });
  it.each(['status','pause'])('%s accepts the exact guarded launch with native nonroot authorization',async operation=>{
    const p=await completeNonrootProofFixture(),built=await buildNonrootImageTransitionProof(p.input,{expected:nonrootProofExpected(p.input,{proofHash:nonrootHash(p.input)}),evidence:p.evidence,now:p.now});
    const {review,current:data}=nonrootAuthorizationValues(p,built,nonrootTransitionContextBindings(built.context));
    const context=bindNonrootTransitionAuthorization(built.context,{review,now:p.now}),f=fixture({nonroot:true});
    installImageAuthorization(f.clients,context,{data,controlSourceTree:data.controlSourceTree,now:p.now});
    expect((await runProductionConsolidationTask(f.clients,{region,operation},f.options)).outcome).toBe('complete');
    expect(f.calls.filter(c=>c.type==='RunTaskCommand')).toHaveLength(1);expect(f.journals.size).toBe(0);
  });
});
