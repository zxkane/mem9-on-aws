import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {readFile} from 'node:fs/promises';
import {GetParametersCommand} from '@aws-sdk/client-ssm';
import {DescribeTaskDefinitionCommand} from '@aws-sdk/client-ecs';
import {GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {GetRoleCommand,ListRolePoliciesCommand,ListAttachedRolePoliciesCommand,GetRolePolicyCommand} from '@aws-sdk/client-iam';
import {inspectPostRuntimePurposeMap,selectGuardedPostRuntimeRoute,validatePostRuntimeDefinition,postRuntimeTaskTrust,postRuntimeExecutionPolicy} from './post-runtime-preview-route.mjs';
import {inspectNonrootPreviewPurposeMap,selectNonrootPreviewPurpose,verifyNonrootPreviewPurposeReadback,validateNonrootPreviewOverrides} from './nonroot-preview-source.mjs';
import {parseNonrootJson,copyNonrootJson} from './production-nonroot-contracts.mjs';
import {verifyCanaryFixtureImageIndex} from './production-canary-material.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';

const execute=promisify(execFile),send=(client,command)=>client.send(command,{abortSignal:AbortSignal.timeout(30000)});
const fail=code=>{throw Error(code);};
export async function nonrootPreviewSourceTree(){
  const cwd=fileURLToPath(new URL('../../',import.meta.url)),options={cwd,encoding:'utf8',timeout:10000};
  await execute('git',['ls-files','--error-unmatch','scripts/lib/nonroot-preview-source.mjs'],options);
  await execute('git',['diff','--quiet'],options);await execute('git',['diff','--cached','--quiet'],options);
  const tree=(await execute('git',['rev-parse','HEAD^{tree}'],options)).stdout.trim();
  if(!/^[a-f0-9]{40}$/.test(tree))fail('NonrootPreviewSource');return tree;
}
/** Canonicalize only the SDK/CLI representation of the service timestamp.
 * Every task field and tag remains part of the authenticated observation. */
export function nonrootPreviewObservation(response){
  const taskDefinition={...response.taskDefinition};
  if(taskDefinition.registeredAt!==undefined)taskDefinition.registeredAt=new Date(taskDefinition.registeredAt).toISOString();
  return copyNonrootJson(JSON.parse(JSON.stringify({taskDefinition,tags:response.tags})));
}
export async function loadNonrootPreviewBootstrap(clients,{stage,region,purpose,sourceTree}){
  if(!/^pr-[1-9][0-9]*$/.test(stage??'')||!/^[a-z]{2}(?:-[a-z]+)+-\d$/.test(region??''))fail('NonrootPreviewScope');
  const account=(await send(clients.sts,new GetCallerIdentityCommand({}))).Account;
  const scope={stage,region,account,sourceTree:sourceTree??await nonrootPreviewSourceTree()};
  const prefix=`/mem9-on-aws/${stage}/bootstrap/`,names=['purpose-bindings','cluster-name','subnet-ids','task-sg-id'].map(n=>prefix+n);
  const result=await send(clients.ssm,new GetParametersCommand({Names:names,WithDecryption:false}));
  if(result.InvalidParameters?.length||result.Parameters?.length!==names.length)fail('NonrootPreviewBindingsMissing');
  const values=new Map();
  for(const p of result.Parameters){
    if(!names.includes(p.Name)||values.has(p.Name)||p.ARN!==`arn:aws:ssm:${region}:${account}:parameter${p.Name}`||
      !Number.isSafeInteger(p.Version)||p.Version<1||p.Type!==(p.Name===names[2]?'StringList':'String')||typeof p.Value!=='string')fail('NonrootPreviewBindingsMissing');
    values.set(p.Name,p);
  }
  const map=inspectNonrootPreviewPurposeMap(values.get(names[0]).Value,scope),selected=purpose??map.defaultPurpose;
  const binding=selectNonrootPreviewPurpose(map,selected,scope),cluster=values.get(names[1]).Value;
  const subnets=values.get(names[2]).Value.split(','),securityGroup=values.get(names[3]).Value;
  if(map.family!==cluster+'-Mem9Bootstrap'||!new RegExp('^mem9-on-aws-'+stage+'-[A-Za-z0-9_-]+$').test(cluster)||
    subnets.length<1||subnets.length>16||new Set(subnets).size!==subnets.length||subnets.some(s=>!/^subnet-(?:[a-f0-9]{8}|[a-f0-9]{17})$/.test(s))||
    !/^sg-(?:[a-f0-9]{8}|[a-f0-9]{17})$/.test(securityGroup))fail('NonrootPreviewNetwork');
  const observation=nonrootPreviewObservation(await send(clients.ecs,new DescribeTaskDefinitionCommand({taskDefinition:binding.taskDefinitionArn,include:['TAGS']})));
  verifyNonrootPreviewPurposeReadback(map,selected,observation,scope);
  const parameters=names.map(name=>({name,version:values.get(name).Version,valueHash:hash(values.get(name).Value)}));
  const resultBinding={scope,purpose:selected,binding,map,observation,cluster,clusterArn:`arn:aws:ecs:${region}:${account}:cluster/${cluster}`,subnets,securityGroup,parameters};
  return copyNonrootJson({...resultBinding,snapshotHash:hash(resultBinding)});
}
export async function revalidateNonrootPreviewBootstrap(clients,binding){
  const current=await loadNonrootPreviewBootstrap(clients,{...binding.scope,purpose:binding.purpose});
  if(current.snapshotHash!==binding.snapshotHash)fail('NonrootPreviewBindingsChanged');return current;
}
function document(value){
  if(value&&typeof value==='object'&&!Array.isArray(value))return value;
  try{return JSON.parse(String(value).trim().startsWith('{')?value:decodeURIComponent(value));}catch{fail('PostRuntimeRoleMismatch');}
}
async function cli(args){
  try{return JSON.parse((await execute('aws',[...args,'--output','json'],{encoding:'utf8',timeout:30000,maxBuffer:8*1024*1024})).stdout);}
  catch{fail('PostRuntimeArtifactUnavailable');}
}
async function controlArtifact(route){
  const repositoryName='mem9-on-aws/preview/bootstrap',rootDigest=route.image.split('@')[1];
  const response=await cli(['ecr','batch-get-image','--region',route.region,'--registry-id',route.account,'--repository-name',repositoryName,'--image-ids','imageDigest='+rootDigest]);
  return verifyCanaryFixtureImageIndex(response,{account:route.account,repositoryName,rootDigest});
}
async function parameterKey(route){
  const key=(await cli(['kms','describe-key','--region',route.region,'--key-id','alias/aws/ssm'])).KeyMetadata;
  if(key?.Arn!==route.kmsKeyArn||key.AWSAccountId!==route.account||key.Enabled!==true||key.KeyState!=='Enabled'||key.KeyManager!=='AWS')fail('PostRuntimeKeyMismatch');
  return key.Arn;
}
async function roleMaterial(iam,route,arn,execution){
  const RoleName=arn.split('/').at(-1),role=(await send(iam,new GetRoleCommand({RoleName}))).Role;
  const trust=document(role?.AssumeRolePolicyDocument),boundary=`arn:aws:iam::${route.account}:policy/mem9-on-aws-workload-boundary`;
  if(role?.Arn!==arn||role.PermissionsBoundary?.PermissionsBoundaryArn!==boundary||hash(trust)!==hash(postRuntimeTaskTrust(route.account,route.region)))fail('PostRuntimeRoleMismatch');
  const inline=await send(iam,new ListRolePoliciesCommand({RoleName,MaxItems:100}));
  const attached=await send(iam,new ListAttachedRolePoliciesCommand({RoleName,MaxItems:100}));
  if(inline.IsTruncated||attached.IsTruncated||!Array.isArray(inline.PolicyNames)||!Array.isArray(attached.AttachedPolicies))fail('PostRuntimeRoleMismatch');
  let policy;
  if(execution){
    if(inline.PolicyNames.join()!=='PostRuntimePreviewSecrets'||attached.AttachedPolicies.length!==1||
      attached.AttachedPolicies[0].PolicyArn!=='arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy')fail('PostRuntimeRoleMismatch');
    policy=document((await send(iam,new GetRolePolicyCommand({RoleName,PolicyName:'PostRuntimePreviewSecrets'}))).PolicyDocument);
    if(hash(policy)!==hash(postRuntimeExecutionPolicy(Object.values(route.credentials),route.kmsKeyArn,route.region)))fail('PostRuntimeRoleMismatch');
  }else if(inline.PolicyNames.length||attached.AttachedPolicies.length)fail('PostRuntimeRoleMismatch');
  return {arn,roleId:role.RoleId??null,createdAt:role.CreateDate?new Date(role.CreateDate).toISOString():null,trust,boundary,policy:policy??null};
}

/** Reads only. No fixture mutation is admitted until this complete observation passes. */
export async function loadPostRuntimeOperator(clients,options,{artifact=controlArtifact,key=parameterKey}={}){
  const account=(await send(clients.sts,new GetCallerIdentityCommand({}))).Account;
  const prefix='/mem9-on-aws/'+options.stage,names=[prefix+'/consolidation-preview/operator',prefix+'/runtime/production-state',prefix+'/runtime/production-manifest'];
  const response=await send(clients.ssm,new GetParametersCommand({Names:names,WithDecryption:true}));
  if(response.InvalidParameters?.length||response.Parameters?.length!==3)fail('PostRuntimeRouteMissing');
  const values=new Map();
  for(const p of response.Parameters){
    if(!names.includes(p.Name)||values.has(p.Name)||p.ARN!==`arn:aws:ssm:${options.region}:${account}:parameter${p.Name}`||
      !Number.isSafeInteger(p.Version)||p.Version<1||p.Type!==(p.Name===names[0]?'String':'SecureString')||typeof p.Value!=='string')fail('PostRuntimeRouteMissing');
    let value;try{value=JSON.parse(p.Value);}catch{fail('PostRuntimeRouteMissing');}values.set(p.Name,{parameter:p,value});
  }
  const map=inspectPostRuntimePurposeMap(values.get(names[0]).value,{...options,account}),purpose=options.purpose??'preview-fixture-pause';
  const route=selectGuardedPostRuntimeRoute(map,{...options,account,runtime:values.get(names[1]).value,manifest:values.get(names[2]).value},purpose);
  const observation=nonrootPreviewObservation(await send(clients.ecs,new DescribeTaskDefinitionCommand({taskDefinition:route.taskDefinitionArn,include:['TAGS']})));
  const definition=observation.taskDefinition;validatePostRuntimeDefinition(definition,route,observation);
  const roles=[await roleMaterial(clients.iam,route,route.taskRoleArn,false),await roleMaterial(clients.iam,route,route.executionRoleArn,true)];
  const image=await artifact(route);
  if(image.rootDigest!==route.image.split('@')[1]||!/^sha256:[a-f0-9]{64}$/.test(image.arm64Digest??'')||image.arm64Digest===image.rootDigest||await key(route)!==route.kmsKeyArn)fail('PostRuntimeArtifactMismatch');
  const parameters=names.map(name=>{const p=values.get(name).parameter;return {name,version:p.Version,valueHash:hash(p.Value)};});
  const snapshotHash=hash({route,observation,roles,parameters,image});
  return {route,purpose,purposeBindings:map.bindings,definition,observation,image,snapshotHash,parameters};
}

export async function revalidatePostRuntimeOperator(clients,binding,options,checks){
  const current=await loadPostRuntimeOperator(clients,{...options,purpose:binding.purpose},checks);
  if(current.snapshotHash!==binding.snapshotHash)fail('PostRuntimeRouteChanged');
}

// Read-only CLI bridge for the existing Bash runner, using its AWS CLI/profile.
// The operation catalog is fixed; stdin never supplies arbitrary CLI arguments.
async function bootstrapCli(){
  const region=process.env.AWS_REGION,stage=process.env.STAGE,mode=process.argv[2];
  if(!['bootstrap-load','bootstrap-recheck'].includes(mode))fail('NonrootPreviewCommand');
  const clients={
    sts:{send:()=>cli(['sts','get-caller-identity','--region',region])},
    ssm:{send:c=>cli(['ssm','get-parameters','--names',...c.input.Names,'--region',region])},
    ecs:{send:c=>cli(['ecs','describe-task-definition','--task-definition',c.input.taskDefinition,'--include','TAGS','--region',region])},
  };
  const sourceTree=await nonrootPreviewSourceTree();
  if(mode==='bootstrap-load'){
    process.stdout.write(JSON.stringify(await loadNonrootPreviewBootstrap(clients,{stage,region,sourceTree})));return;
  }
  const input=parseNonrootJson(await readFile('/dev/stdin','utf8'));
  if(!input||Object.keys(input).sort().join()!=='binding,overrides'||input.binding.scope.stage!==stage||input.binding.scope.region!==region||input.binding.scope.sourceTree!==sourceTree)fail('NonrootPreviewScope');
  await revalidateNonrootPreviewBootstrap(clients,input.binding);
  validateNonrootPreviewOverrides(input.binding.purpose,input.overrides);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)bootstrapCli().catch(()=>{process.stderr.write('NonrootPreviewRejected\n');process.exitCode=1;});
