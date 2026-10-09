import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {parse} from 'yaml';
import {expectedGatewayBoundaryPolicyDocument as render,gatewayBoundaryProbeCases,gatewayRoleStage,gatewayBoundaryArn} from './lib/gateway-workload-boundary.mjs';
import {verifyGatewayBoundaryPolicyDocument,expectedRoleBoundaryArn,expectedBoundaryPolicyDocument} from './lib/workload-permissions-boundary.mjs';
const contract={partition:'aws',accountId:'123456789012',applicationRegion:'ap-northeast-1',policyRevision:'r1'};
const policy=render(contract),list=v=>v===undefined?[]:Array.isArray(v)?v:[v];
function expand(value,context){let absent=false;const result=value.replace(/\$\{([^}]+)\}/g,(_,key)=>{if(context[key]===undefined){absent=true;return '';}return context[key];});return absent?undefined:result;}
function glob(pattern,value){if(pattern===undefined||value===undefined)return false;return new RegExp('^'+pattern.split('*').map(v=>v.split('?').map(v=>v.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')).join('.')).join('.*')+'$').test(value);}
function condition(spec,context){return Object.entries(spec??{}).every(([op,fields])=>Object.entries(fields).every(([key,wanted])=>{
 if(op==='Null')return (context[key]===undefined)===(wanted==='true');
 if(op.endsWith('IfExists')&&context[key]===undefined)return true;
 const negative=op.includes('Not'),like=op.includes('Like')||op.startsWith('Arn');
 if(!['StringEquals','StringNotEquals','StringLike','StringNotLike','StringNotLikeIfExists','StringNotEqualsIfExists','ArnLike','ArnNotLike','ArnEquals','ArnNotEquals'].includes(op))throw Error('unsupported test operator '+op);
 const matched=list(wanted).some(v=>{const pattern=expand(v,context);return pattern!==undefined&&context[key]!==undefined&&(like?glob(pattern,context[key]):pattern===context[key]);});
 return negative?!matched:matched;
}));}
function decision(document,action,resource,context,sessionGrant=false){let allowed=sessionGrant;for(const statement of document.Statement){
 const actions=statement.Action?list(statement.Action).some(v=>glob(v.toLowerCase(),action.toLowerCase())):!list(statement.NotAction).some(v=>glob(v.toLowerCase(),action.toLowerCase()));
 const resources=statement.Resource?list(statement.Resource).some(v=>glob(expand(v,context),resource)):!list(statement.NotResource).some(v=>glob(expand(v,context),resource));
 if(actions&&resources&&condition(statement.Condition,context)){if(statement.Effect==='Deny')return 'explicitDeny';allowed=true;}
}return allowed?'allowed':'implicitDeny';}
const scope=(stage='prod',token='Mem9ProxyFnRole')=>({'aws:PrincipalArn':`arn:aws:iam::123456789012:role/mem9-on-aws-${stage}-${token}-fixture`,'aws:PrincipalTag/Stage':stage,'aws:PrincipalTag/Project':'mem9-on-aws'});
const secret=(stage,kind)=>`arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:mem9-on-aws-${stage}-${kind}-fixture`;

describe('closed Gateway permissions boundary',()=>{
 for(const row of gatewayBoundaryProbeCases(contract))it(row.name,()=>{
  const context=Object.fromEntries(row.context.map(value=>{const key=/ContextKeyName=([^,]+)/.exec(value)[1],v=/ContextKeyValues=(.*)$/.exec(value)[1];return[key,v];}));
  expect(decision(policy,'kms:Decrypt',row.resource,context,true)).toBe(row.expected);
 });
 it('retains only the two known role families and the exact operator-owned ARN mapping',()=>{
  for(const prefix of ['mem9-on-aws','mem9-on-aw','mem9-on-a'])for(const type of ['Mem9ProxyFnRole','Mem9IdentityInterceptorFnRole']){
   const name=`${prefix}-pr-7-${type}-fixture`;expect(gatewayRoleStage(name)).toBe('pr-7');expect(expectedRoleBoundaryArn(name,contract)).toBe(gatewayBoundaryArn(contract));
  }
  for(const name of ['mem9-on-aws-prod-Mem9ServerExecutionRole-fixture','foreign-prod-Mem9ProxyFnRole-fixture','mem9-on-aws-prod-Mem9ProxyFnRole'])expect(expectedRoleBoundaryArn(name,contract)).toBe('arn:aws:iam::123456789012:policy/mem9-on-aws-workload-boundary');
 });
 it('rejects the independently reviewed stage-prefix collision and incomplete-ARN regression',()=>{
  const context={...scope(),'aws:PrincipalArn':'arn:aws:iam::123456789012:role/mem9-on-aws-pr-prod-Mem9ProxyFnRole-x','secretsmanager:ResourceTag/Stage':'prod'};
  expect(decision(policy,'secretsmanager:GetSecretValue',secret('prod','tenant-api-key'),context,true)).toBe('explicitDeny');
  expect(decision(policy,'ec2:CreateNetworkInterface','*',scope())).toBe('allowed');
  expect(decision(policy,'ec2:CreateNetworkInterface','*',scope('prod','Mem9IdentityInterceptorFnRole'))).toBe('explicitDeny');
  expect(decision(policy,'ec2:CreateNetworkInterface','*',{...scope(),'lambda:SourceFunctionArn':'some-function'})).toBe('explicitDeny');
  for(const statement of policy.Statement)for(const [op,values]of Object.entries(statement.Condition??{}))if(op.startsWith('Arn'))for(const value of list(values['aws:PrincipalArn']))expect(value.startsWith('arn:')).toBe(true);
 });
 it('enforces actual secret/parameter API scope and explicit denies despite session grants',()=>{
  for(const stage of ['prod','pr-7']){
   const c={...scope(stage),'secretsmanager:ResourceTag/Stage':stage,'ssm:resourceTag/Stage':stage};
   for(const kind of ['identity-signing-keys','tenant-api-key'])expect(decision(policy,'secretsmanager:GetSecretValue',secret(stage,kind),c)).toBe('allowed');
   expect(decision(policy,'secretsmanager:GetSecretValue',secret(stage,'tenant-api-key'),{...c,...scope(stage,'Mem9IdentityInterceptorFnRole')},true)).toBe('explicitDeny');
   expect(decision(policy,'secretsmanager:GetSecretValue',secret(stage==='prod'?'pr-7':'prod','tenant-api-key'),c,true)).toBe('explicitDeny');
   expect(decision(policy,'secretsmanager:GetSecretValue',secret(stage,'tenant-api-key'),{...c,'secretsmanager:ResourceTag/Stage':'different'},true)).toBe('explicitDeny');
   const parameter=`arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/${stage}/namespace/transport-signing-keys`;
   expect(decision(policy,'ssm:GetParameters',parameter,c)).toBe('allowed');
   expect(decision(policy,'ssm:GetParameters',parameter,{...c,...scope(stage,'Mem9IdentityInterceptorFnRole')},true)).toBe('explicitDeny');
   const log=`arn:aws:logs:ap-northeast-1:123456789012:log-group:/aws/lambda/mem9-on-aws-${stage}-Mem9ProxyFnFunction-fixture:log-stream:stream`;
   for(const action of ['logs:CreateLogGroup','logs:CreateLogStream','logs:PutLogEvents'])expect(decision(policy,action,log,c)).toBe('allowed');
   expect(decision(policy,'logs:PutLogEvents',log.replace('mem9-on-aws-'+stage,'mem9-on-aws-pr-'+stage),c,true)).toBe('explicitDeny');
  }
  for(const action of ['iam:PassRole','iam:CreatePolicy','sts:AssumeRole','ecs:RunTask','s3:GetObject','s3:PutObject','secretsmanager:PutSecretValue','ssm:PutParameter','kms:GenerateDataKey','kms:Encrypt','ecr:GetAuthorizationToken'])expect(decision(policy,action,'*',scope(),true)).toBe('explicitDeny');
 });
 it('deploy role admits exactly the fixed family/boundary pairs and Lambda-only passing',()=>{
  const customTags=[...['!Sub','!Ref','!GetAtt'].map(tag=>({tag,resolve:value=>value})),...['!If','!Not','!Equals'].map(tag=>({tag,collection:'seq',resolve:value=>value}))];
  const template=parse(readFileSync(new URL('../infra/cloudformation/github-actions-role.yaml',import.meta.url),'utf8'),{customTags});
  const selected=new Set(['EcsTaskRoleCreateWithBoundary','EcsTaskRolePolicyWritesWithBoundary','DenyUnboundedProjectRoleCreation','DenyUnboundedProjectRolePolicyWrites','DenyGatewayBoundaryOnOtherRoles','DenyGatewayRolesWrongBoundary','PassRoleConstrained','DenyLambdaRolePassToOtherServices']);
  const raw=Object.values(template.Resources).filter(r=>r.Type==='AWS::IAM::ManagedPolicy').flatMap(r=>r.Properties.PolicyDocument.Statement).filter(s=>selected.has(s.Sid));
  const rendered=JSON.parse(JSON.stringify(raw).replaceAll('${AWS::Partition}','aws').replaceAll('${AWS::AccountId}',contract.accountId).replaceAll('${ProjectName}','mem9-on-aws'));
  const deployed={Statement:rendered};expect(rendered).toHaveLength(selected.size);
  const old='arn:aws:iam::123456789012:policy/mem9-on-aws-workload-boundary',gateway=gatewayBoundaryArn(contract);
  for(const prefix of ['mem9-on-aws','mem9-on-aw','mem9-on-a'])for(const stage of ['prod','pr-7']){
   for(const token of ['Mem9ProxyFnRole','Mem9IdentityInterceptorFnRole','Mem9ServerExecutionRole']){
    const resource=`arn:aws:iam::123456789012:role/${prefix}-${stage}-${token}-fixture`,isGateway=token!=='Mem9ServerExecutionRole';
    for(const action of ['iam:CreateRole','iam:PutRolePermissionsBoundary','iam:PutRolePolicy','iam:AttachRolePolicy']){
     expect(decision(deployed,action,resource,{'iam:PermissionsBoundary':isGateway?gateway:old})).toBe('allowed');
     for(const wrong of [isGateway?old:gateway,'arn:aws:iam::123456789012:policy/arbitrary',undefined])expect(decision(deployed,action,resource,{'iam:PermissionsBoundary':wrong},true)).toBe('explicitDeny');
    }
    if(isGateway){
     expect(decision(deployed,'iam:PassRole',resource,{'iam:PassedToService':'lambda.amazonaws.com'})).toBe('allowed');
     expect(decision(deployed,'iam:PassRole',resource,{'iam:PassedToService':'ecs-tasks.amazonaws.com'},true)).toBe('explicitDeny');
    }
   }
  }
 });
 it('keeps both template and native renderer identical, without changing the original boundary',()=>{
  const customTags=[...['!Sub','!Ref','!GetAtt'].map(tag=>({tag,resolve:value=>value})),...['!If','!Not','!Equals'].map(tag=>({tag,collection:'seq',resolve:value=>value}))];
  const template=parse(readFileSync(new URL('../infra/cloudformation/workload-permissions-boundary.yaml',import.meta.url),'utf8'),{customTags});
  const replace=v=>Array.isArray(v)?v.map(replace):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).map(([k,x])=>[k,replace(x)])):typeof v==='string'?v.replaceAll('${AWS::Partition}','aws').replaceAll('${AWS::AccountId}','123456789012').replaceAll('${ApplicationRegion}',contract.applicationRegion).replaceAll('${AWS::URLSuffix}','amazonaws.com').replaceAll('${PolicyRevision}','r1').replaceAll('${!aws:PrincipalTag/Stage}','${aws:PrincipalTag/Stage}'):v;
  expect(replace(template.Resources.GatewayPermissionsBoundary.Properties.PolicyDocument)).toEqual(policy);
  expect(verifyGatewayBoundaryPolicyDocument(policy,contract)).toBe(true);
  const changed=structuredClone(policy);changed.Statement.pop();expect(verifyGatewayBoundaryPolicyDocument(changed,contract)).toBe(false);
  const old=expectedBoundaryPolicyDocument({...contract,bedrockProjectArn:'arn:aws:bedrock-mantle:ap-northeast-1:123456789012:project/proj_test'});
  expect(JSON.stringify(old)).not.toContain('identity-signing-keys');
 });
 it('fits every bounded contract, including longest region/partition/revision inputs',()=>{
  expect(JSON.stringify(render({...contract,partition:'x'.repeat(16),applicationRegion:'aa-'+'b'.repeat(19)+'-1',policyRevision:'r'+'9'.repeat(20)})).length).toBeLessThanOrEqual(6144);
  expect(()=>render({...contract,applicationRegion:'aa-'+'b'.repeat(20)+'-1'})).toThrow();
 });
});
