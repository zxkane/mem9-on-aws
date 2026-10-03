import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {GetParametersCommand} from '@aws-sdk/client-ssm';
import {DescribeTaskDefinitionCommand} from '@aws-sdk/client-ecs';
import {GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {GetRoleCommand,ListRolePoliciesCommand,ListAttachedRolePoliciesCommand,GetRolePolicyCommand} from '@aws-sdk/client-iam';
import {validatePostRuntimeRoute,validatePostRuntimeDefinition,postRuntimeTaskTrust,postRuntimeExecutionPolicy} from './post-runtime-preview-route.mjs';
import {verifyCanaryFixtureImageIndex} from './production-canary-material.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';

const execute=promisify(execFile),send=(client,command)=>client.send(command,{abortSignal:AbortSignal.timeout(30000)});
const fail=code=>{throw Error(code);};
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
  const route=validatePostRuntimeRoute(values.get(names[0]).value,{...options,account,runtime:values.get(names[1]).value,manifest:values.get(names[2]).value});
  const definition=(await send(clients.ecs,new DescribeTaskDefinitionCommand({taskDefinition:route.taskDefinitionArn}))).taskDefinition;
  validatePostRuntimeDefinition(definition,route);
  const roles=[await roleMaterial(clients.iam,route,route.taskRoleArn,false),await roleMaterial(clients.iam,route,route.executionRoleArn,true)];
  const image=await artifact(route);
  if(image.rootDigest!==route.image.split('@')[1]||!/^sha256:[a-f0-9]{64}$/.test(image.arm64Digest??'')||image.arm64Digest===image.rootDigest||await key(route)!==route.kmsKeyArn)fail('PostRuntimeArtifactMismatch');
  const parameters=names.map(name=>{const p=values.get(name).parameter;return {name,version:p.Version,valueHash:hash(p.Value)};});
  const snapshotHash=hash({route,definition:JSON.parse(JSON.stringify(definition)),roles,parameters,image});
  return {route,definition,image,snapshotHash,parameters};
}

export async function revalidatePostRuntimeOperator(clients,binding,options,checks){
  const current=await loadPostRuntimeOperator(clients,options,checks);
  if(current.snapshotHash!==binding.snapshotHash)fail('PostRuntimeRouteChanged');
}
