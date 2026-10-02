import {readProductionSchedulerContext} from './production-scheduler-context.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';

const fail=()=>{throw Error('ProductionRecurringDeliveryUnverified');};
const millis=v=>v instanceof Date?v.getTime():typeof v==='string'?Date.parse(v):NaN;
const number=(v,min=0)=>Number.isSafeInteger(v)&&v>=min;
const shape=(value,key='')=>{
  if(['Statement','Action'].includes(key)&&!Array.isArray(value))value=[value];
  if(Array.isArray(value))return value.map(v=>shape(v)).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return value&&typeof value==='object'?Object.fromEntries(Object.keys(value).filter(k=>k!=='Sid').sort().map(k=>[k,shape(value[k],k)])):value;
};

export function verifyProductionSchedulerIdentity(role,target){
  const arn=`arn:aws:iam::${target.account}:role/mem9-on-aws-prod-Mem9ConsolidationSchedulerRole-role`;
  if(target.roleArn!==arn||role?.Arn!==arn||!/^[A-Z0-9]{16,128}$/.test(role.RoleId??'')||
    role.PermissionsBoundary?.PermissionsBoundaryArn!==`arn:aws:iam::${target.account}:policy/mem9-on-aws-workload-boundary`)fail();
  let policy;try{policy=typeof role.AssumeRolePolicyDocument==='string'?JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument)):role.AssumeRolePolicyDocument;}catch{fail();}
  const expected={Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'sts:AssumeRole',Principal:{Service:'scheduler.amazonaws.com'},
    Condition:{StringEquals:{'aws:SourceAccount':target.account,'aws:SourceArn':`arn:aws:scheduler:${target.region}:${target.account}:schedule-group/${target.groupName}`}}}]};
  if(hash(shape(policy))!==hash(shape(expected)))fail();return {arn,roleId:role.RoleId,trustHash:hash(shape(policy))};
}

/** CloudTrail supplies authenticated identity; ECS supplies unredacted immutable
 * task overrides. CloudTrail redacts environment values and does not necessarily
 * include invokedBy. User-agent strings are never an authentication condition.
 */
export function verifyProductionRecurringDelivery({task,definition,record,event,role},target,{admission,artifact,afterMs,now=Date.now()}){
  if(!['planner','executor'].includes(target?.kind)||!/^\d{12}$/.test(target.account??'')||!/^[a-z0-9-]+$/.test(target.region??'')||
    !target.clusterArn?.startsWith(`arn:aws:ecs:${target.region}:${target.account}:cluster/mem9-on-aws-prod-`)||
    !target.template?.Name?.startsWith('mem9-on-aws-prod-'+target.kind+'-')||!number(afterMs,1)||!number(now,afterMs))fail();
  const identity=verifyProductionSchedulerIdentity(role,target),scheduleArn=`arn:aws:scheduler:${target.region}:${target.account}:schedule/${target.groupName}/${target.template.Name}`;
  const container=task?.containers?.[0],configured=definition?.containerDefinitions?.[0],override=task?.overrides?.containerOverrides?.[0];
  if(task?.taskDefinitionArn!==target.taskDefinitionArn||definition?.taskDefinitionArn!==target.taskDefinitionArn||task.clusterArn!==target.clusterArn||
    task.lastStatus!=='STOPPED'||task.launchType!=='FARGATE'||task.containers?.length!==1||definition.containerDefinitions?.length!==1||
    definition.networkMode!=='awsvpc'||definition.runtimePlatform?.cpuArchitecture!=='ARM64'||definition.runtimePlatform.operatingSystemFamily!=='LINUX'||
    container.name!==target.containerName||container.exitCode!==0||container.image!==target.image||configured.image!==target.image||configured.name!==target.containerName||
    definition.taskRoleArn!==target.taskRoleArn||definition.executionRoleArn!==target.executionRoleArn||
    task.overrides?.containerOverrides?.length!==1||override.name!==target.containerName||
    Object.keys(override).some(k=>!['name','environment','cpu','memory','memoryReservation','command','environmentFiles','resourceRequirements'].includes(k))||
    ['command','environmentFiles','resourceRequirements'].some(k=>override[k]!==undefined&&(!Array.isArray(override[k])||override[k].length))||
    ['cpu','memory','memoryReservation'].some(k=>override[k]!==undefined&&override[k]!==configured[k]&&!(override[k]===0&&configured[k]===undefined))||
    Object.keys(task.overrides).some(k=>!['containerOverrides','cpu','memory','taskRoleArn','executionRoleArn','inferenceAcceleratorOverrides','ephemeralStorage'].includes(k))||
    ['taskRoleArn','executionRoleArn','cpu','memory'].some(k=>task.overrides[k]!==undefined&&String(task.overrides[k])!==String(definition[k]))||
    task.overrides.inferenceAcceleratorOverrides?.length||task.overrides.ephemeralStorage&&hash(task.overrides.ephemeralStorage)!==hash(definition.ephemeralStorage??{sizeInGiB:20}))fail();
  const cpu=task.attributes?.filter(a=>a.name==='ecs.cpu-architecture');
  if(cpu?.length!==1||cpu[0].value!=='arm64'||!/^sha256:[a-f0-9]{64}$/.test(artifact?.rootDigest??'')||
    !/^sha256:[a-f0-9]{64}$/.test(artifact?.arm64Digest??'')||artifact.rootDigest===artifact.arm64Digest||
    !target.image.endsWith('@'+artifact.rootDigest)||![artifact.rootDigest,artifact.arm64Digest].includes(container.imageDigest))fail();
  const context=readProductionSchedulerContext(override.environment,{scheduleArn,generation:target.generation,admission});
  const start=millis(task.startedAt),stop=millis(task.stoppedAt),eventTime=millis(event?.eventTime);
  if(!number(start,1)||!number(stop,start)||stop>now+5000||context.scheduledMs<afterMs||context.scheduledMs>start+5000||
    !number(eventTime,1)||eventTime<context.scheduledMs-1000||eventTime-context.scheduledMs>65000||eventTime>start+5000)fail();
  const user=event.userIdentity,issuer=user?.sessionContext?.sessionIssuer,request=event.requestParameters,response=event.responseElements;
  if(event.eventSource!=='ecs.amazonaws.com'||event.eventName!=='RunTask'||event.eventType!=='AwsApiCall'||event.awsRegion!==target.region||
    event.recipientAccountId!==target.account||event.errorCode||event.errorMessage||!/^[a-f0-9-]{36}$/.test(event.eventID??'')||
    user?.type!=='AssumedRole'||user.accountId!==target.account||issuer?.arn!==identity.arn||issuer.principalId!==identity.roleId||
    !user.principalId?.startsWith(identity.roleId+':')||!user.arn?.startsWith(`arn:aws:sts::${target.account}:assumed-role/${identity.arn.split('/').at(-1)}/`)||
    ![target.clusterArn,target.clusterArn.split('/').at(-1)].includes(request?.cluster)||
    ![target.taskDefinitionArn,target.taskDefinitionArn.split('/').at(-1)].includes(request?.taskDefinition)||request.count!==1||request.launchType!=='FARGATE'||
    request.enableExecuteCommand===true||response?.failures?.length||response?.tasks?.length!==1||response.tasks[0].taskArn!==task.taskArn||
    response.tasks[0].clusterArn!==target.clusterArn||response.tasks[0].taskDefinitionArn!==target.taskDefinitionArn||
    request.startedBy!==task.startedBy)fail();
  const network=request.networkConfiguration?.awsvpcConfiguration;
  if(network?.assignPublicIp!=='DISABLED'||!Array.isArray(network.subnets)||!Array.isArray(network.securityGroups)||
    hash([...network.subnets].sort())!==hash([...target.subnets].sort())||hash([...network.securityGroups].sort())!==hash([target.securityGroup]))fail();
  if(record?.event!=='consolidation_worker'||record.stage!=='prod'||record.kind!==target.kind||!['complete','deadline'].includes(record.outcome)||
    record.invocation!==undefined||!['slices','classified','changedRows','failedSlices'].every(k=>number(record[k]))||record.slices<1||record.failedSlices!==0||
    !number(record.startedMs,start-5000)||!number(record.finishedMs,record.startedMs)||record.finishedMs>stop+5000)fail();
  const proof={version:1,kind:target.kind,generation:target.generation,admission,...context,taskArn:task.taskArn,taskDefinitionArn:task.taskDefinitionArn,
    image:container.image,imageDigest:container.imageDigest,exitCode:0,startedMs:record.startedMs,stoppedMs:record.finishedMs,
    slices:record.slices,failedSlices:record.failedSlices,classified:record.classified,changedRows:record.changedRows,
    recordHash:hash(record),overridesHash:hash(task.overrides),launchEventId:event.eventID,launchEventHash:hash(event),schedulerIdentity:identity};
  return {...proof,evidenceHash:hash(proof)};
}

export function verifyProductionRecurringProof(value,{kind,generation,admission,image}){
  if(!value||typeof value!=='object'||Array.isArray(value))fail();
  const {evidenceHash,...proof}=value;
  if(evidenceHash!==hash(proof)||proof.version!==1||proof.kind!==kind||proof.generation!==generation||proof.admission!==admission||
    proof.image!==image||proof.exitCode!==0||!number(proof.slices,1)||proof.failedSlices!==0||!number(proof.classified)||!number(proof.changedRows)||
    !number(proof.scheduledMs,1)||!number(proof.startedMs,proof.scheduledMs)||!number(proof.stoppedMs,proof.startedMs)||
    typeof proof.taskArn!=='string'||!proof.taskArn||typeof proof.taskDefinitionArn!=='string'||!proof.taskDefinitionArn||
    !['recordHash','overridesHash','launchEventHash'].every(k=>/^[a-f0-9]{64}$/.test(proof[k]??''))||
    !/^[a-f0-9-]{36}$/.test(proof.launchEventId??'')||!proof.schedulerIdentity?.arn||!proof.schedulerIdentity?.roleId)fail();
  return value;
}
