import {dataLaunchPolicy} from './lib/production-nonroot-launch.mjs';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {createControlSourceContext} from './lib/production-control-source.mjs';
import {PREVIEW_SOURCE_PLAN_FILES} from './lib/production-nonroot-preview-provider.mjs';
import {nonrootPostRuntimeFixture} from './nonroot-preview.fixture.mjs';
import {postRuntimeCredentialReferences,postRuntimeTaskTrust,postRuntimeExecutionPolicy} from './lib/post-runtime-preview-route.mjs';

/** Synthetic checkout built with real Git object hashing. No cloud observation
 * or execution authority is produced by this source fixture. */
export function previewProviderSourceFixture(){
 const directory=mkdtempSync(join(tmpdir(),'nonroot-preview-source-'));
 try{
  const git=(args,input)=>execFileSync('git',args,{cwd:directory,input,encoding:'utf8',stdio:['pipe','pipe','pipe']}).trim();
  git(['init','--quiet']);const entries=[],blobs=new Map();
  for(const path of PREVIEW_SOURCE_PLAN_FILES){
   const raw=readFileSync(new URL('../'+path,import.meta.url)),oid=git(['hash-object','-w','--stdin'],raw);
   const target=join(directory,path);mkdirSync(dirname(target),{recursive:true});writeFileSync(target,raw);
   git(['update-index','--add','--cacheinfo','100644',oid,path]);entries.push({path,mode:'100644',type:'blob',oid});blobs.set(oid,raw);
  }
  const tree=git(['write-tree']),context=createControlSourceContext({tree,entries},async oid=>blobs.get(oid));return {tree,context};
 }finally{rmSync(directory,{recursive:true,force:true});}
}

export function previewWorkloadFixture(scopeOverride){
 const scope=scopeOverride??{stage:'pr-7',account:'123456789012',region:'ap-northeast-1',sourceTree:'a'.repeat(40)},sourceRevision='b'.repeat(40),prefix=`/mem9-on-aws/${scope.stage}/`,cluster='mem9-on-aws-pr-7-Cluster-example',serviceName='mem9-on-aws-pr-7-Mem9Server-example';
 const arn=`arn:aws:ecs:${scope.region}:${scope.account}:`,definitionArn=arn+'task-definition/'+cluster+'-Mem9Server:2',taskArn=arn+'task/'+cluster+'/'+'c'.repeat(32);
 const images=Object.fromEntries(['llm-proxy','mnemo-server','qwen3-embed'].map(name=>[name,`${scope.account}.dkr.ecr.${scope.region}.amazonaws.com/mem9-on-aws/preview/${name}:pr-${sourceRevision.slice(0,7)}`]));
 const definition={family:cluster+'-Mem9Server',taskDefinitionArn:definitionArn,revision:2,status:'ACTIVE',networkMode:'awsvpc',requiresCompatibilities:['FARGATE'],runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},
  containerDefinitions:Object.entries(images).map(([name,image])=>dataLaunchPolicy(name,{name,image,environment:[]}))};
 const task={taskArn,clusterArn:arn+'cluster/'+cluster,taskDefinitionArn:definitionArn,lastStatus:'RUNNING',desiredStatus:'RUNNING',launchType:'FARGATE',
  containers:Object.entries(images).map(([name,image],i)=>({name,image,imageDigest:'sha256:'+String(i+1).repeat(64),lastStatus:'RUNNING',healthStatus:'HEALTHY'}))};
 const service={serviceName,clusterArn:task.clusterArn,taskDefinition:definitionArn,desiredCount:1,runningCount:1,pendingCount:0,
  deployments:[{status:'PRIMARY',taskDefinition:definitionArn,rolloutState:'COMPLETED',desiredCount:1,runningCount:1,pendingCount:0}]};
 const parameters=new Map(Object.entries({'ecs/cluster-name':cluster,'ecs/service-name':serviceName,'ecs/task-definition':definitionArn,
  'ecs/image-selection':JSON.stringify({version:1,mode:'tag',controlTag:'pr-'+sourceRevision.slice(0,7),dataTag:'pr-'+sourceRevision.slice(0,7),images})}).map(([name,Value])=>[prefix+name,{Name:prefix+name,Value,Version:1}]));
 const calls=[],send=async(serviceName,command)=>{
  calls.push({service:serviceName,api:command.constructor.name,input:command.input});
  if(command.constructor.name==='DescribeTaskDefinitionCommand')return {taskDefinition:definition,tags:[]};
  if(command.constructor.name==='DescribeServicesCommand')return {services:[service],failures:[]};
  if(command.constructor.name==='ListTasksCommand')return {taskArns:[taskArn]};
  if(command.constructor.name==='DescribeTasksCommand')return {tasks:[task],failures:[]};
  throw Error('Unexpected read');
 };
 return {scope,sourceRevision,definition,task,service,parameters,calls,send};
}

export function previewPostRuntimeFixture(scope){
 const {stage,account,region,sourceTree}=scope,cluster=`mem9-on-aws-${stage}-Cluster-example`,prefix=`/mem9-on-aws/${stage}`,ecs=`arn:aws:ecs:${region}:${account}:`;
 const route={version:1,kind:'post-runtime-preview-operator',stage,account,region,generation:'d'.repeat(64),context:{kind:'post-runtime',runtimeNonce:'e'.repeat(32)},controlSourceTree:sourceTree,
  clusterArn:ecs+'cluster/'+cluster,taskDefinitionArn:ecs+'task-definition/'+cluster+'-Mem9PostFixture:7',containerName:'Mem9PostFixture',
  image:`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/preview/bootstrap@sha256:${'f'.repeat(64)}`,
  taskRoleArn:`arn:aws:iam::${account}:role/mem9-on-aws-${stage}-Mem9PostFixtureTaskRole-synthetic`,executionRoleArn:`arn:aws:iam::${account}:role/mem9-on-aws-${stage}-Mem9PostFixtureExecutionRole-synthetic`,
  subnets:['subnet-aaaabbbb'],securityGroup:'sg-aaaabbbb',host:'writer.example.com',port:5432,database:'mem9',
  kmsKeyArn:`arn:aws:kms:${region}:${account}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`,credentials:postRuntimeCredentialReferences(stage,account,region)};
 const guarded=nonrootPostRuntimeFixture(route),runtime={stage,nonce:route.context.runtimeNonce,phase:'complete',status:'running'},
  manifest={stage,mode:'active',account,region,clusterArn:route.clusterArn,subnets:route.subnets,securityGroup:route.securityGroup,host:route.host,port:route.port,database:route.database,administratorCredential:route.credentials.MEM9_DB_SECRET};
 const values=new Map([[prefix+'/consolidation-preview/operator',guarded.map],[prefix+'/runtime/production-state',runtime],[prefix+'/runtime/production-manifest',manifest]]);
 const parameters=new Map([...values].map(([Name,value])=>[Name,{Name,Value:JSON.stringify(value),ARN:`arn:aws:ssm:${region}:${account}:parameter${Name}`,Version:1,Type:Name.endsWith('/operator')?'String':'SecureString'}]));
 const calls=[];
 const send=async(service,command)=>{
  const api=command.constructor.name,input=command.input;calls.push({service,api,input});
  if(api==='GetCallerIdentityCommand')return {Account:account};
  if(api==='DescribeTaskDefinitionCommand')return guarded.definitions.get(input.taskDefinition);
  const execution=input.RoleName===route.executionRoleArn.split('/').at(-1);
  if(api==='GetRoleCommand')return {Role:{Arn:execution?route.executionRoleArn:route.taskRoleArn,RoleId:'synthetic-role',
   AssumeRolePolicyDocument:encodeURIComponent(JSON.stringify(postRuntimeTaskTrust(account,region))),PermissionsBoundary:{PermissionsBoundaryArn:`arn:aws:iam::${account}:policy/mem9-on-aws-workload-boundary`}}};
  if(api==='ListRolePoliciesCommand')return {PolicyNames:execution?['PostRuntimePreviewSecrets']:[],IsTruncated:false};
  if(api==='ListAttachedRolePoliciesCommand')return {AttachedPolicies:execution?[{PolicyArn:'arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'}]:[],IsTruncated:false};
  if(api==='GetRolePolicyCommand')return {PolicyDocument:JSON.stringify(postRuntimeExecutionPolicy(Object.values(route.credentials),route.kmsKeyArn,region))};
  throw Error('Unexpected synthetic read');
 };
 const metadataReads={artifact:async selected=>({rootDigest:selected.image.split('@')[1],arm64Digest:'sha256:'+'a'.repeat(64)}),key:async selected=>selected.kmsKeyArn};
 return {scope,route,guarded,parameters,send,calls,metadataReads};
}
