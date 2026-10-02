import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
import {ECSClient,DescribeTaskDefinitionCommand,DescribeTasksCommand,DescribeServicesCommand} from '@aws-sdk/client-ecs';
import {SSMClient,GetParametersCommand} from '@aws-sdk/client-ssm';
import {STSClient,GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {IAMClient,ListAccountAliasesCommand,GetRoleCommand,ListRolePoliciesCommand,GetRolePolicyCommand,ListAttachedRolePoliciesCommand,GetPolicyCommand,GetPolicyVersionCommand} from '@aws-sdk/client-iam';
import {SecretsManagerClient,GetSecretValueCommand} from '@aws-sdk/client-secrets-manager';
import {SchedulerClient,ListSchedulesCommand} from '@aws-sdk/client-scheduler';
import {fromIni} from '@aws-sdk/credential-providers';
import {loadProductionCanaryWorker} from './production-canary-delivery.mjs';
import {verifyProductionScheduling,captureProductionBackend} from './production-scheduling.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {verifyCanaryImageIndex,normalizeCanaryTask} from './production-canary-material.mjs';
import {loadProductionManifest} from './production-runtime-tasks.mjs';
import {runtimeServerContract,verifyRuntimeRoles} from './runtime-live-verification.mjs';
import {validateProductionBackendBinding} from './production-artifacts.mjs';

const execute=promisify(execFile),fail=()=>{throw Error('CanaryMaterialCaptureFailed');};
const send=(client,command)=>client.send(command,{abortSignal:AbortSignal.timeout(30000)});
const decode=value=>typeof value==='string'?JSON.parse(decodeURIComponent(value)):value;
const semanticPolicy=value=>Array.isArray(value)?value.map(semanticPolicy).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b))):
  value&&typeof value==='object'?Object.fromEntries(Object.keys(value).filter(k=>k!=='Sid').sort().map(k=>[k,semanticPolicy(value[k])])):value;
const policyShape=(value,key='')=>{
  if(['Action','Resource','Statement'].includes(key)&&!Array.isArray(value))value=[value];
  if(Array.isArray(value))return value.map(v=>policyShape(v)).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return value&&typeof value==='object'?Object.fromEntries(Object.keys(value).filter(k=>k!=='Sid').sort().map(k=>[k,policyShape(value[k],k)])):value;
};

export function normalizeCanaryAuthority(snapshot){
  const {account,region,definitions,scheduler,authority:roles,network}=snapshot;
  if(scheduler?.roleArn!==`arn:aws:iam::${account}:role/mem9-on-aws-prod-Mem9ConsolidationSchedulerRole-role`||
    !/^mem9-on-aws-prod-consolidation-[A-Za-z0-9-]+$/.test(scheduler.groupName??''))fail();
  const role=roles?.find(r=>r.arn===scheduler.roleArn),workers=[definitions.planner,definitions.executor];
  const revisions=workers.map(d=>d.taskDefinitionArn),families=revisions.map(arn=>arn.replace(/:[1-9][0-9]*$/,''));
  const cluster=network?.cluster,clusterPrefix=`arn:aws:ecs:${region}:${account}:cluster/`;
  if(!cluster?.startsWith(clusterPrefix+'mem9-on-aws-prod-')||new Set(families).size!==2||
    role?.boundary?.arn!==`arn:aws:iam::${account}:policy/mem9-on-aws-workload-boundary`||
    !role.roleId||role.inlinePolicies?.length!==1||role.attachedPolicies?.length!==0)fail();
  const expectedTrust={Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'sts:AssumeRole',Principal:{Service:'scheduler.amazonaws.com'},
    Condition:{StringEquals:{'aws:SourceAccount':account,'aws:SourceArn':`arn:aws:scheduler:${region}:${account}:schedule-group/${scheduler.groupName}`}}}]};
  const expectedPolicy={Version:'2012-10-17',Statement:[
    {Effect:'Deny',Action:'ecs:RunTask',Resource:`arn:aws:ecs:${region}:${account}:task-definition/${cluster.slice(clusterPrefix.length)}-Mem9Consolidation:*`},
    {Effect:'Allow',Action:'ecs:RunTask',Resource:revisions,Condition:{ArnEquals:{'ecs:cluster':cluster}}},
    {Effect:'Allow',Action:'iam:PassRole',Resource:workers.flatMap(d=>[d.taskRoleArn,d.executionRoleArn]),Condition:{StringEquals:{'iam:PassedToService':'ecs-tasks.amazonaws.com'}}},
  ]};
  if(hash(policyShape(role.trust))!==hash(policyShape(expectedTrust))||hash(policyShape(role.inlinePolicies[0].document))!==hash(policyShape(expectedPolicy)))fail();
  const normalized=structuredClone(roles),copy=normalized.find(r=>r.arn===role.arn);
  const document=policyShape(copy.inlinePolicies[0].document);
  // Exact current-revision permission was verified above. Substitute only its
  // two RunTask resources for comparison, never for a deployed IAM document.
  document.Statement.find(s=>s.Effect==='Allow'&&s.Action.join()==='ecs:RunTask').Resource=families.map(f=>'canary-worker-family:'+f).sort();
  copy.inlinePolicies[0].document=document;
  return normalized;
}

export function createCanaryMaterialClients({region,profile=process.env.AWS_PROFILE||'default'}){
  const credentials=fromIni({profile});
  const clients={ecs:new ECSClient({region,credentials}),ssm:new SSMClient({region,credentials}),sts:new STSClient({region,credentials}),
    iam:new IAMClient({region:'us-east-1',credentials}),secrets:new SecretsManagerClient({region,credentials}),scheduler:new SchedulerClient({region,credentials})};
  const batchGetImage=async input=>JSON.parse((await execute('aws',['ecr','batch-get-image','--profile',profile,'--region',region,
    '--registry-id',input.registryId,'--repository-name',input.repositoryName,'--image-ids','imageDigest='+input.imageIds[0].imageDigest,'--output','json'],
  {timeout:30000,maxBuffer:4194304})).stdout);
  return {clients,batchGetImage,destroy:()=>Object.values(clients).forEach(c=>c.destroy())};
}

async function authority(clients,arns,account){
  const result=[];
  const policy=async arn=>{
    if(!arn.startsWith(`arn:aws:iam::${account}:policy/`)&&!arn.startsWith('arn:aws:iam::aws:policy/'))fail();
    const p=(await send(clients.iam,new GetPolicyCommand({PolicyArn:arn}))).Policy;
    if(p?.Arn!==arn||!p.DefaultVersionId)fail();
    const version=(await send(clients.iam,new GetPolicyVersionCommand({PolicyArn:arn,VersionId:p.DefaultVersionId}))).PolicyVersion;
    if(version?.VersionId!==p.DefaultVersionId)fail();
    return {arn,document:semanticPolicy(decode(version.Document))};
  };
  for(const arn of [...new Set(arns)].sort()){
    if(!arn.startsWith(`arn:aws:iam::${account}:role/`))fail();
    const RoleName=arn.split('/').at(-1),r=(await send(clients.iam,new GetRoleCommand({RoleName}))).Role;
    if(r?.Arn!==arn||!r.RoleId||!r.PermissionsBoundary?.PermissionsBoundaryArn)fail();
    const inline=await send(clients.iam,new ListRolePoliciesCommand({RoleName})),attached=await send(clients.iam,new ListAttachedRolePoliciesCommand({RoleName}));
    if(inline.IsTruncated||attached.IsTruncated)fail();
    const inlinePolicies=[];
    for(const PolicyName of [...(inline.PolicyNames??[])].sort()){
      const p=await send(clients.iam,new GetRolePolicyCommand({RoleName,PolicyName}));
      if(p.RoleName!==RoleName||p.PolicyName!==PolicyName)fail();
      inlinePolicies.push({name:PolicyName,document:semanticPolicy(decode(p.PolicyDocument))});
    }
    const attachedPolicies=[];
    for(const p of [...(attached.AttachedPolicies??[])].sort((a,b)=>a.PolicyArn.localeCompare(b.PolicyArn)))attachedPolicies.push(await policy(p.PolicyArn));
    result.push({arn,roleId:r.RoleId,path:r.Path,maxSessionDuration:r.MaxSessionDuration,trust:semanticPolicy(decode(r.AssumeRolePolicyDocument)),
      tags:[...(r.Tags??[])].sort((a,b)=>a.Key.localeCompare(b.Key)),inlinePolicies,attachedPolicies,boundary:await policy(r.PermissionsBoundary.PermissionsBoundaryArn)});
  }
  return result;
}

async function credentialFingerprints(clients,references,{account,region}){
  const result=[];
  for(const reference of [...new Set(references)].sort()){
    const prefix='arn:aws:',parts=reference.split(':');
    if(!reference.startsWith(prefix)||parts[3]!==region||parts[4]!==account)fail();
    if(parts[2]==='ssm'&&parts.length===6&&parts[5].startsWith('parameter/mem9-on-aws/prod/')){
      const r=await send(clients.ssm,new GetParametersCommand({Names:[reference],WithDecryption:true}));
      const p=r.Parameters?.[0];
      if(r.InvalidParameters?.length||r.Parameters?.length!==1||p.ARN!==reference||!Number.isSafeInteger(p.Version)||p.Version<1||typeof p.Value!=='string')fail();
      result.push({reference,version:String(p.Version),type:p.Type,valueHash:createHash('sha256').update(p.Value).digest('hex')});
    }else if(parts[2]==='secretsmanager'&&parts.length===7&&parts[5]==='secret'&&parts[6].startsWith('mem9-on-aws-prod-')){
      const p=await send(clients.secrets,new GetSecretValueCommand({SecretId:reference,VersionStage:'AWSCURRENT'}));
      if(p.ARN!==reference||!p.VersionId||!p.VersionStages?.includes('AWSCURRENT'))fail();
      const bytes=typeof p.SecretString==='string'?Buffer.from(p.SecretString):p.SecretBinary;
      if(!bytes)fail();result.push({reference,version:p.VersionId,type:typeof p.SecretString==='string'?'SecretString':'SecretBinary',valueHash:createHash('sha256').update(bytes).digest('hex')});
    }else fail();
  }
  return result;
}

/** `release` must be produced by the authenticated release-evidence verifier. */
export async function captureCanaryMaterial(clients,{account,region,release,batchGetImage,expectedAccountAlias}){
  if(!/^[0-9]{12}$/.test(account??'')||!/^[a-f0-9]{40}$/.test(release?.revision??'')||!/^[a-f0-9]{40}$/.test(release.sourceTree??'')||
    !/^[a-f0-9]{64}$/.test(release.coordinatorDigest??'')||typeof expectedAccountAlias!=='string'||!expectedAccountAlias.trim()||expectedAccountAlias.length>128)fail();
  if((await send(clients.sts,new GetCallerIdentityCommand({}))).Account!==account)fail();
  const aliases=await send(clients.iam,new ListAccountAliasesCommand({}));
  if(aliases.IsTruncated||aliases.AccountAliases?.length!==1||aliases.AccountAliases[0]!==expectedAccountAlias)fail();
  const targets=[];for(const kind of ['planner','executor'])targets.push(await loadProductionCanaryWorker(clients,{region,kind,revision:release.revision}));
  await verifyProductionScheduling(clients,targets,{enabled:false});
  const scheduler={roleArn:targets[0].roleArn,groupName:targets[0].groupName};
  if(targets.some(t=>t.roleArn!==scheduler.roleArn||t.groupName!==scheduler.groupName))fail();
  const schedules=[];let NextToken;
  for(let page=0;page<100;page++){
    const result=await send(clients.scheduler,new ListSchedulesCommand({GroupName:scheduler.groupName,MaxResults:100,NextToken}));
    schedules.push(...(result.Schedules??[]));if(!result.NextToken)break;
    if(result.NextToken===NextToken||page===99)fail();NextToken=result.NextToken;
  }
  if(hash(schedules.map(s=>s.Name).sort())!==hash(targets.map(t=>t.template.Name).sort())||schedules.some(s=>s.State!=='DISABLED'))fail();
  const backend=await captureProductionBackend(clients,targets[0]);
  const definitions={};
  for(const [kind,arn]of [['backend',backend.taskDefinitionArn],...targets.map(t=>[t.kind,t.taskDefinitionArn])]){
    const definition=(await send(clients.ecs,new DescribeTaskDefinitionCommand({taskDefinition:arn}))).taskDefinition;
    if(definition?.taskDefinitionArn!==arn||definition.status!=='ACTIVE')fail();definitions[kind]=definition;
  }
  const running=(await send(clients.ecs,new DescribeTasksCommand({cluster:targets[0].clusterArn,tasks:[backend.taskArn]})));
  if(running.failures?.length||running.tasks?.length!==1)fail();
  const task=running.tasks[0],cpu=task.attributes?.filter(a=>a.name==='ecs.cpu-architecture');
  if(task.taskArn!==backend.taskArn||task.taskDefinitionArn!==backend.taskDefinitionArn||task.lastStatus!=='RUNNING'||task.healthStatus!=='HEALTHY'||
    task.launchType!=='FARGATE'||cpu?.length!==1||cpu[0].value!=='arm64'||task.containers?.some(c=>c.healthStatus!=='HEALTHY'))fail();
  const runtimeManifest=await loadProductionManifest(clients,{stage:'prod',region});
  if(runtimeManifest.mode!=='active')fail();
  const runtimeMeta={...runtimeManifest,serverTaskDefinition:backend.taskDefinitionArn,productionRuntime:true};
  const contract=runtimeServerContract(definitions.backend,runtimeMeta,runtimeManifest.tenantSecret);
  await verifyRuntimeRoles({iam:clients.iam,definition:definitions.backend,meta:runtimeMeta,contract});
  const services=await send(clients.ecs,new DescribeServicesCommand({cluster:targets[0].clusterArn,services:['Mem9Server']}));
  if(services.failures?.length||services.services?.length!==1||services.services[0].taskDefinition!==backend.taskDefinitionArn)fail();
  const backendNetwork=structuredClone(services.services[0].networkConfiguration);
  const vpc=backendNetwork?.awsvpcConfiguration;
  if(vpc?.assignPublicIp!=='DISABLED'||!Array.isArray(vpc.subnets)||!vpc.subnets.length||!Array.isArray(vpc.securityGroups)||!vpc.securityGroups.length||
    new Set(vpc.subnets).size!==vpc.subnets.length||new Set(vpc.securityGroups).size!==vpc.securityGroups.length)fail();
  vpc.subnets.sort();vpc.securityGroups.sort();
  const catalog=new Map(),components={};
  for(const [component,reference,repository]of [
    ['worker',targets[0].image,'llm-proxy'],...definitions.backend.containerDefinitions.map(c=>[c.name,c.image,c.name]),
  ]){
    const repositoryName='mem9-on-aws/'+repository,rootDigest=release.imageDigests?.[repository];
    const image=verifyCanaryImageIndex(await batchGetImage({registryId:account,repositoryName,imageIds:[{imageDigest:rootDigest}]}),{account,repositoryName,rootDigest});
    catalog.set(reference,image);components[component]=image;
  }
  for(const c of backend.containers){const image=components[c.name];if(!image||![image.rootDigest,image.arm64Digest].includes(c.imageDigest))fail();}
  const normalized={};for(const [kind,d]of Object.entries(definitions))normalized[kind]=normalizeCanaryTask(d,{account,region,images:catalog});
  const roles=[scheduler.roleArn,...Object.values(definitions).flatMap(d=>[d.taskRoleArn,d.executionRoleArn])];
  const references=Object.values(definitions).flatMap(d=>d.containerDefinitions.flatMap(c=>(c.secrets??[]).map(s=>s.valueFrom)));
  const runtimeName='/mem9-on-aws/prod/runtime/production-state';
  const runtimeResult=await send(clients.ssm,new GetParametersCommand({Names:[runtimeName],WithDecryption:true}));
  if(runtimeResult.InvalidParameters?.length||runtimeResult.Parameters?.length!==1||runtimeResult.Parameters[0].Name!==runtimeName)fail();
  const runtime=JSON.parse(runtimeResult.Parameters[0].Value);
  if(runtime.stage!=='prod'||runtime.phase!=='complete'||runtime.status!=='running')fail();
  const auth=await authority(clients,roles,account),credentials=await credentialFingerprints(clients,references,{account,region});
  const network={cluster:targets[0].clusterArn,backend:backendNetwork,workers:targets.map(t=>({kind:t.kind,subnets:[...t.subnets].sort(),securityGroup:t.securityGroup,assignPublicIp:'DISABLED'}))};
  if(hash(await captureProductionBackend(clients,targets[0]))!==hash(backend))fail();
  return {version:2,observedAt:new Date().toISOString(),account,region,revision:release.revision,sourceTree:release.sourceTree,coordinatorDigest:release.coordinatorDigest,
    generation:targets[0].generation,sourceTag:'mem9-'+release.revision.slice(0,7),workerImage:targets[0].image,backendBinding:backend,
    runtime:{schemaDigest:runtime.schemaDigest,operatorDigest:runtime.operatorDigest,runtimeNonce:runtime.nonce},
    components,definitions,backendTask:task,authority:auth,credentials,network,scheduler,
    material:{planner:hash(normalized.planner),executor:hash(normalized.executor),backend:hash(normalized.backend),network:hash(network),
      authority:hash(normalizeCanaryAuthority({account,region,definitions,scheduler,authority:auth,network})),credentials:hash(credentials)}};
}

function materialHashes(snapshot){
  const binding=validateProductionBackendBinding(snapshot.backendBinding,snapshot.network?.cluster),task=snapshot.backendTask;
  const names=['llm-proxy','mnemo-server','qwen3-embed'];
  if(!snapshot.network?.cluster||snapshot.definitions?.backend?.taskDefinitionArn!==binding.taskDefinitionArn||
    task?.taskArn!==binding.taskArn||task.taskDefinitionArn!==binding.taskDefinitionArn||task.clusterArn!==snapshot.network.cluster||task.lastStatus!=='RUNNING')fail();
  for(const containers of [binding.containers,task.containers,snapshot.definitions.backend.containerDefinitions]){
    if(!Array.isArray(containers)||hash(containers.map(c=>c?.name).sort())!==hash(names))fail();
  }
  for(const bound of binding.containers){
    const image=snapshot.components[bound.name],actual=task.containers.find(c=>c.name===bound.name),configured=snapshot.definitions.backend.containerDefinitions.find(c=>c.name===bound.name);
    if(!image||![image.rootDigest,image.arm64Digest].includes(bound.imageDigest)||actual.imageDigest!==bound.imageDigest||actual.image!==configured.image)fail();
  }
  const images=new Map([[snapshot.workerImage,snapshot.components.worker]]);
  for(const c of snapshot.definitions.backend.containerDefinitions)images.set(c.image,snapshot.components[c.name]);
  const context={account:snapshot.account,region:snapshot.region,images},material={};
  const roleArns=[...new Set([snapshot.scheduler?.roleArn,...Object.values(snapshot.definitions).flatMap(d=>[d.taskRoleArn,d.executionRoleArn])])].sort();
  const references=[...new Set(Object.values(snapshot.definitions).flatMap(d=>d.containerDefinitions.flatMap(c=>(c.secrets??[]).map(s=>s.valueFrom))))].sort();
  if(!Array.isArray(snapshot.authority)||hash(snapshot.authority.map(r=>r.arn).sort())!==hash(roleArns)||
    !Array.isArray(snapshot.credentials)||hash(snapshot.credentials.map(c=>c.reference).sort())!==hash(references)||
    snapshot.credentials.some(c=>typeof c.version!=='string'||!c.version||!/^[a-f0-9]{64}$/.test(c.valueHash??'')))fail();
  for(const kind of ['planner','executor','backend'])material[kind]=hash(normalizeCanaryTask(snapshot.definitions[kind],context));
  for(const kind of ['network','credentials'])material[kind]=hash(snapshot[kind]);
  material.authority=hash(normalizeCanaryAuthority(snapshot));
  if(hash(material)!==hash(snapshot.material))fail();
  return material;
}

export function buildCanaryCompatibility(previous,current,parent){
  if(previous?.version!==2||current?.version!==2||previous.account!==current.account||previous.region!==current.region||previous.generation!==current.generation||
    hash(previous.runtime)!==hash(current.runtime)||previous.workerImage!==parent.workerImage||previous.sourceTag!==parent.sourceTag||
    hash(previous.backendBinding)!==parent.backendBindingHash||previous.generation!==parent.generation)fail();
  const release=s=>({sourceTree:s.sourceTree,coordinatorDigest:s.coordinatorDigest,sourceTag:s.sourceTag,workerImage:s.workerImage,...s.runtime});
  if(hash(release(previous))!==parent.releaseHash)fail();
  const images={},material={};
  const oldMaterial=materialHashes(previous),newMaterial=materialHashes(current);
  for(const name of ['worker','mnemo-server','qwen3-embed','llm-proxy']){
    const old=previous.components[name],next=current.components[name];if(!old||!next||old.arm64Digest!==next.arm64Digest)fail();
    images[name]={previousRoot:old.rootDigest,currentRoot:next.rootDigest,previousChild:old.arm64Digest,currentChild:next.arm64Digest};
  }
  for(const name of ['planner','executor','backend','network','authority','credentials']){
    if(!oldMaterial[name]||oldMaterial[name]!==newMaterial[name])fail();material[name]={previous:oldMaterial[name],current:newMaterial[name]};
  }
  return {version:1,parentProofHash:hash(parent),generation:parent.generation,targetsHash:hash([...parent.targets].sort()),
    previous:{release:release(previous),backendBindingHash:parent.backendBindingHash},current:{release:release(current),backendBinding:current.backendBinding},images,material};
}
