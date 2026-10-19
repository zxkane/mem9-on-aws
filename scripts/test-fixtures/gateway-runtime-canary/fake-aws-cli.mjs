// Synthetic AWS CLI for broker tests. It speaks the fixed --cli-input-json
// request shape, keeps one canary's state in a private JSON file, and enforces
// each scoped lane's session policy at action level. It is not AWS provenance:
// the adapter it serves is real, the services are not.
import {readFileSync,writeFileSync,appendFileSync,existsSync,chmodSync,mkdirSync} from 'node:fs';
import {join} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {codeZip} from '../../gateway-runtime-canary.fixture.mjs';
import {GATEWAY_CANARY_OPERATOR_ROLE_NAME,GATEWAY_CANARY_OPERATOR_POLICY_NAME,gatewayCanaryOperatorPolicy,gatewayCanaryOperatorTrustPolicy} from '../../lib/gateway-canary-operator-role.mjs';

const KEY_ID='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
export const FAKE_OWNER_ROLE='synthetic-scoped-owner';

/** Write the fake `aws` executable and its configuration into directory. */
export function installFakeAwsCli({directory,accountId='123456789012',region='ap-northeast-1',vpcId='vpc-12345678',liveBoundaryPath,liveVersion='v1',faults={}}){
  const bin=join(directory,'bin');mkdirSync(bin,{recursive:true,mode:0o700});
  const configPath=join(directory,'fake-aws.json'),statePath=join(directory,'fake-aws-state.json'),callsPath=join(directory,'fake-aws-calls.jsonl');
  writeFileSync(configPath,JSON.stringify({accountId,region,vpcId,liveBoundaryPath,liveVersion,statePath,callsPath,faults}));
  writeFileSync(statePath,JSON.stringify({sessionPolicies:{},sessionRestrictions:{}}));
  const awsExecutable=join(bin,'aws');
  writeFileSync(awsExecutable,`#!/bin/sh\nexec "${process.execPath}" "${fileURLToPath(import.meta.url)}" "${configPath}" "$@"\n`);chmodSync(awsExecutable,0o700);
  return {awsExecutable,bin,statePath,configPath,
    ownerRoleArn:`arn:aws:iam::${accountId}:role/operators/${FAKE_OWNER_ROLE}`,
    calls:()=>existsSync(callsPath)?readFileSync(callsPath,'utf8').trim().split('\n').filter(Boolean).map(l=>JSON.parse(l)):[],
    state:()=>JSON.parse(readFileSync(statePath,'utf8')),
    setFaults(next){const c=JSON.parse(readFileSync(configPath,'utf8'));c.faults={...c.faults,...next};writeFileSync(configPath,JSON.stringify(c));},
    setLiveVersion(liveVersion){const c=JSON.parse(readFileSync(configPath,'utf8'));writeFileSync(configPath,JSON.stringify({...c,liveVersion}));}};
}

export const fakeCanaryKeyArn=(accountId,region)=>`arn:aws:kms:${region}:${accountId}:key/${KEY_ID}`;
export function codeSha256(zip){return createHash('sha256').update(zip).digest('base64');}

function main([configPath,...args]){
  const config=JSON.parse(readFileSync(configPath,'utf8')),state=JSON.parse(readFileSync(config.statePath,'utf8'));
  const {accountId,region,faults}=config,at=args.indexOf('--cli-read-timeout');
  const service=args[at+2],action=args[at+3],inputAt=args.indexOf('--cli-input-json');
  const request=inputAt>0?JSON.parse(readFileSync(args[inputAt+1].slice(7),'utf8')):{};
  const pascal=action.split('-').map(w=>w[0].toUpperCase()+w.slice(1)).join('');
  const lane=laneOf(process.env);
  const log=extra=>appendFileSync(config.callsPath,JSON.stringify({service,action,lane,region:args[args.indexOf('--region')+1],request:redact(request),...extra})+'\n');
  const fail=(code,message=`synthetic ${code}`)=>{log({error:code});process.stderr.write(`\naws: [ERROR]: An error occurred (${code}) when calling the ${pascal} operation: ${message}\n`);process.exit(254);};
  // Like IAM and KMS, return policy documents in a key order of the service's
  // own (here reversed), not the order in which they were written.
  const serviceOrder=v=>Array.isArray(v)?v.map(serviceOrder):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).reverse().map(([k,x])=>[k,serviceOrder(x)])):v;
  const documents=v=>Array.isArray(v)?v.map(documents):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).map(([k,x])=>
    [k,['Document','PolicyDocument','AssumeRolePolicyDocument'].includes(k)&&x&&typeof x==='object'?serviceOrder(x):documents(x)])):v;
  const reply=value=>{log({});writeFileSync(config.statePath,JSON.stringify(state));process.stdout.write(JSON.stringify(documents(value)));process.exit(0);};
  if(faults.delayIdentityMs&&action==='get-caller-identity')Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,faults.delayIdentityMs);
  // A lane may act only where both its session policy and the operator role allow.
  if(lane&&!(laneAllows(state,lane,`${service}:${pascal}`)&&allows(gatewayCanaryOperatorPolicy({accountId,applicationRegion:region}),`${service}:${pascal}`)))fail('AccessDenied','synthetic lane policy denies '+pascal);
  const iamArn=`arn:aws:iam::${accountId}:`,ownerArn=`${iamArn}role/operators/${FAKE_OWNER_ROLE}`,operatorArn=`${iamArn}role/${GATEWAY_CANARY_OPERATOR_ROLE_NAME}`;
  // The deployed operator role: trust names the owner (or a fault's other
  // principal), with the session tags when the trust requires them.
  const operatorTrust=()=>gatewayCanaryOperatorTrustPolicy({ownerRoleArn:faults.operatorTrustOwner??ownerArn,tags:faults.requireSessionTags??null});
  const operatorPolicy=()=>{const p=structuredClone(gatewayCanaryOperatorPolicy({accountId,applicationRegion:region}));if(faults.operatorPolicyDrift)p.Statement.push({Effect:'Allow',Action:'iam:PassRole',Resource:'*'});return p;};
  // The owner role's own identity documents: AdministratorAccess plus an
  // explicit-deny guard. faults.ownerDenies adds denied actions to the guard,
  // ownerNarrow replaces the administrator grant, ownerBoundary sets a boundary,
  // ownerExtraPolicies attaches more, ownerListTruncated truncates the list.
  const isOwner=name=>name===FAKE_OWNER_ROLE||name===faults.callerRole;
  // ownerTagDeny denies CreateStack to principals tagged team=restricted, and tags the owner so.
  const ownerTags=()=>faults.ownerTagDeny?[{Key:'team',Value:'restricted'}]:[{Key:'Project',Value:'mem9-on-aws'}];
  const ownerDocuments=()=>({
    inline:{'blast-radius-guard':{Version:'2012-10-17',Statement:[{Sid:'BlastRadiusGuard',Effect:'Deny',Action:['organizations:LeaveOrganization',...(faults.ownerDenies??[])],Resource:'*'},
      ...(faults.ownerTagDeny?[{Effect:'Deny',Action:'cloudformation:CreateStack',Resource:'*',Condition:{StringEquals:{'aws:PrincipalTag/team':'restricted'}}}]:[])]}},
    attached:[{arn:'arn:aws:iam::aws:policy/AdministratorAccess',document:{Version:'2012-10-17',Statement:[faults.ownerNarrow
      ?{Effect:'Allow',Action:['cloudformation:*','iam:Get*','iam:List*','kms:*','lambda:*','logs:*'],Resource:'*'}:{Effect:'Allow',Action:'*',Resource:'*'}]}},
      ...Array.from({length:faults.ownerExtraPolicies??0},(_,i)=>({arn:`${iamArn}policy/synthetic-extra-${i}`,document:{Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'s3:ListAllMyBuckets',Resource:'*'}]}}))],
    boundary:faults.ownerBoundary?{arn:`${iamArn}policy/synthetic-owner-boundary`,document:faults.ownerBoundary}:null});
  const ownerManaged=arn=>{const d=ownerDocuments();return d.attached.find(a=>a.arn===arn)??(d.boundary?.arn===arn?d.boundary:null);};
  const live=()=>({document:JSON.parse(readFileSync(config.liveBoundaryPath,'utf8')),versionId:state.deleted&&faults.liveVersionAfterCanary?faults.liveVersionAfterCanary:config.liveVersion});
  const t=state.template,r=t?.Resources,exists=Boolean(t)&&!state.deleted;
  const names=t&&{role:r.CanaryRole.Properties.RoleName,fn:r.CanaryFunction.Properties.FunctionName,comparison:r.ComparisonBoundary.Properties.ManagedPolicyName,stack:state.stackName};
  const roleArn=t&&`${iamArn}role/${names.role}`,keyArn=fakeCanaryKeyArn(accountId,region),comparisonArn=t&&`${iamArn}policy/${names.comparison}`;
  const resolve=v=>Array.isArray(v)?v.map(resolve):v&&typeof v==='object'?v['Fn::GetAtt']?v['Fn::GetAtt'][0]==='SyntheticKey'?keyArn:roleArn
    :v.Ref==='ComparisonBoundary'?comparisonArn:Object.fromEntries(Object.entries(v).map(([k,x])=>[k,resolve(x)])):v;
  const fnConfig=()=>({FunctionName:names.fn,FunctionArn:`arn:aws:lambda:${region}:${accountId}:function:${names.fn}`,Runtime:'nodejs24.x',Architectures:['arm64'],Handler:'index.handler',Role:roleArn,
    CodeSha256:state.codeSha256,State:'Active',LastUpdateStatus:'Successful',Environment:{Variables:resolve(r.CanaryFunction.Properties.Environment.Variables)},RevisionId:'synthetic-code-revision'});
  const key=()=>state.deleted?{Arn:keyArn,KeyId:KEY_ID,Enabled:false,KeyState:'PendingDeletion',KeyManager:'CUSTOMER',KeyUsage:'ENCRYPT_DECRYPT',KeySpec:'SYMMETRIC_DEFAULT',MultiRegion:false,DeletionDate:state.deletionDate}
    :{Arn:keyArn,KeyId:KEY_ID,Enabled:true,KeyState:'Enabled',KeyManager:'CUSTOMER',KeyUsage:'ENCRYPT_DECRYPT',KeySpec:'SYMMETRIC_DEFAULT',MultiRegion:false};
  const sessionPolicy=arn=>state.sessionPolicies[arn];
  switch(`${service} ${action}`){
    case 'sts get-caller-identity':return reply({UserId:'AROASYNTHETICOWNER01:owner-session',Account:accountId,Arn:faults.callerArn??`arn:aws:sts::${accountId}:assumed-role/${FAKE_OWNER_ROLE}/owner-session`});
    case 'sts assume-role':{
      const m=/^mem9-gateway-(observe|bootstrap|provision)-[a-f0-9]{12}$/.exec(request.RoleSessionName??'');
      if(request.RoleArn!==operatorArn||!m||faults.trustDenied)fail('AccessDenied');
      // STS session tags, as in role chaining: the calling session's transitive
      // tags (faults.callerTransitiveTags) are forwarded automatically, and
      // setting one of those keys again is an InvalidParameterValue conflict.
      // The deployed operator trust is then evaluated on the effective tags.
      const transitive=lane===null?faults.callerTransitiveTags??[]:[],explicit=request.Tags??[];
      if(explicit.some(t=>transitive.some(x=>x.Key.toLowerCase()===t.Key.toLowerCase())))
        fail('InvalidParameterValue',"One of the specified transitive tag keys can't be set because it conflicts with a transitive tag key from the calling session");
      const effective=[...transitive,...explicit],trust=operatorTrust().Statement[0];
      if(effective.length&&![trust.Action].flat().includes('sts:TagSession'))fail('AccessDenied','not authorized to perform: sts:TagSession');
      if(trust.Condition){
        const value=key=>effective.find(t=>t.Key===key)?.Value,allowedKeys=trust.Condition['ForAllValues:StringEquals']['aws:TagKeys'];
        const matches=Object.entries(trust.Condition.StringEquals).every(([k,v])=>value(k.slice('aws:RequestTag/'.length))===v)&&effective.every(t=>allowedKeys.includes(t.Key));
        if(!matches)fail('AccessDenied','not authorized to perform: sts:AssumeRole');
      }
      if(request.PolicyArns&&!sessionPolicy(request.PolicyArns[0]?.arn))fail('MalformedPolicyDocument');
      state.sessionRestrictions[m[1]]=request.Policy?{policy:JSON.parse(request.Policy)}:{policyArn:request.PolicyArns[0].arn};
      return reply({Credentials:{AccessKeyId:'ASIA'+m[1].toUpperCase().padEnd(16,'0'),SecretAccessKey:'s'.repeat(40),SessionToken:'synthetic-session-token-'+m[1],Expiration:new Date(Date.now()+3600_000).toISOString()},
        AssumedRoleUser:{AssumedRoleId:'AROASYNTHETICOPERATOR:'+request.RoleSessionName,Arn:`arn:aws:sts::${accountId}:assumed-role/${GATEWAY_CANARY_OPERATOR_ROLE_NAME}/${request.RoleSessionName}`}});
    }
    case 'iam simulate-custom-policy':{
      // faults.operatorSimulationDeny: the simulator newly denies that action to the operator's policy alone.
      const result=simulateCustomPolicy(request),operator=request.PolicyInputList.length===1&&request.PolicyInputList[0]===JSON.stringify(gatewayCanaryOperatorPolicy({accountId,applicationRegion:region}));
      if(operator&&faults.operatorSimulationDeny)for(const r of result.EvaluationResults)if(r.EvalActionName===faults.operatorSimulationDeny)r.EvalDecision='implicitDeny';
      return reply(result);
    }
    // Organizations: account -> (optional OU) -> root, FullAWSAccess SCP and RCP at the root.
    // orgNotInUse, orgUnreadable, orgRcpDisabled and orgPrincipalScoped vary it.
    case 'organizations list-parents':{
      if(faults.orgNotInUse)fail('AWSOrganizationsNotInUseException');if(faults.orgUnreadable)fail('AccessDeniedException');
      if(request.ChildId===accountId)return reply({Parents:[faults.orgOu?{Id:'ou-abcd-11111111',Type:'ORGANIZATIONAL_UNIT'}:{Id:'r-abcd',Type:'ROOT'}]});
      if(request.ChildId==='ou-abcd-11111111')return reply({Parents:[{Id:'r-abcd',Type:'ROOT'}]});
      return fail('ChildNotFoundException');
    }
    case 'organizations list-policies-for-target':{
      if(request.Filter==='RESOURCE_CONTROL_POLICY'&&faults.orgRcpDisabled)fail('PolicyTypeNotEnabledException');
      const scp=request.Filter==='SERVICE_CONTROL_POLICY',root=request.TargetId==='r-abcd';
      const scoped=faults.orgPrincipalScoped&&(faults.orgPrincipalScoped.filter===request.Filter)&&request.TargetId===(faults.orgOu?'ou-abcd-11111111':accountId);
      return reply({Policies:[...(root?[{Id:scp?'p-FullAWSAccess':'p-RCPFullAWSAccess',Name:'FullAWSAccess'}]:[]),...(scoped?[{Id:'p-principalscoped',Name:'Narrowing'}]:[])]});
    }
    case 'organizations describe-policy':{
      const full=id=>JSON.stringify({Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'*',Resource:'*'}]});
      if(request.PolicyId==='p-principalscoped')return reply({Policy:{PolicySummary:{Id:request.PolicyId},Content:JSON.stringify(faults.orgPrincipalScoped.content)}});
      if(['p-FullAWSAccess','p-RCPFullAWSAccess'].includes(request.PolicyId))return reply({Policy:{PolicySummary:{Id:request.PolicyId},Content:full()}});
      return fail('PolicyNotFoundException');
    }
    case 'ec2 describe-vpcs':return reply({Vpcs:[{VpcId:config.vpcId,IsDefault:true}]});
    case 'iam get-role':
      if(request.RoleName===FAKE_OWNER_ROLE||request.RoleName===faults.callerRole){const path=faults.callerRole===request.RoleName&&faults.callerPath||'operators';
        const boundary=ownerDocuments().boundary;
        return reply({Role:{RoleName:request.RoleName,Arn:`${iamArn}role/${path}/${request.RoleName}`,Path:`/${path}/`,Tags:ownerTags(),...(boundary?{PermissionsBoundary:{PermissionsBoundaryType:'Policy',PermissionsBoundaryArn:boundary.arn}}:{})}});}
      if(request.RoleName===GATEWAY_CANARY_OPERATOR_ROLE_NAME){if(faults.operatorMissing)fail('NoSuchEntity');return reply({Role:{RoleName:request.RoleName,Arn:operatorArn,Path:'/',MaxSessionDuration:3600,AssumeRolePolicyDocument:operatorTrust()}});}
      if(!exists||request.RoleName!==names.role)fail('NoSuchEntity');
      return reply({Role:{RoleName:names.role,Arn:roleArn,RoleId:'AROASYNTHETIC0000001',AssumeRolePolicyDocument:r.CanaryRole.Properties.AssumeRolePolicyDocument,Tags:r.CanaryRole.Properties.Tags,
        PermissionsBoundary:{PermissionsBoundaryType:'Policy',PermissionsBoundaryArn:state.mode==='original'?`${iamArn}policy/mem9-on-aws-gateway-boundary`:comparisonArn}}});
    case 'iam get-policy':
      if(request.PolicyArn===`${iamArn}policy/mem9-on-aws-gateway-boundary`)return reply({Policy:{Arn:request.PolicyArn,DefaultVersionId:live().versionId}});
      if(exists&&request.PolicyArn===comparisonArn)return reply({Policy:{Arn:comparisonArn,DefaultVersionId:'v1'}});
      if(sessionPolicy(request.PolicyArn)){const p=sessionPolicy(request.PolicyArn);return reply({Policy:{Arn:request.PolicyArn,PolicyName:p.name,PolicyId:p.id,DefaultVersionId:'v1',AttachmentCount:0,PermissionsBoundaryUsageCount:0}});}
      if(ownerManaged(request.PolicyArn))return reply({Policy:{Arn:request.PolicyArn,DefaultVersionId:'v3'}});
      return fail('NoSuchEntity');
    case 'iam get-policy-version':
      if(request.PolicyArn===`${iamArn}policy/mem9-on-aws-gateway-boundary`){const l=live();if(request.VersionId!==l.versionId)fail('NoSuchEntity');return reply({PolicyVersion:{VersionId:l.versionId,IsDefaultVersion:true,Document:l.document}});}
      if(exists&&request.PolicyArn===comparisonArn)return reply({PolicyVersion:{VersionId:'v1',IsDefaultVersion:true,Document:r.ComparisonBoundary.Properties.PolicyDocument}});
      if(sessionPolicy(request.PolicyArn))return reply({PolicyVersion:{VersionId:'v1',IsDefaultVersion:true,Document:sessionPolicy(request.PolicyArn).document}});
      if(ownerManaged(request.PolicyArn)&&request.VersionId==='v3')return reply({PolicyVersion:{VersionId:'v3',IsDefaultVersion:true,Document:ownerManaged(request.PolicyArn).document}});
      return fail('NoSuchEntity');
    case 'iam create-policy':{
      const arn=`${iamArn}policy${request.Path??'/'}${request.PolicyName}`;if(sessionPolicy(arn))fail('EntityAlreadyExists');
      state.sessionPolicies[arn]={name:request.PolicyName,id:'ANPASYNTHETIC0000000001',document:JSON.parse(request.PolicyDocument),tags:request.Tags};
      return reply({Policy:{PolicyName:request.PolicyName,PolicyId:'ANPASYNTHETIC0000000001',Arn:arn,DefaultVersionId:'v1'}});
    }
    case 'iam list-policy-versions':return sessionPolicy(request.PolicyArn)?reply({Versions:[{VersionId:'v1',IsDefaultVersion:true}],IsTruncated:false}):fail('NoSuchEntity');
    case 'iam list-policy-tags':return sessionPolicy(request.PolicyArn)?reply({Tags:sessionPolicy(request.PolicyArn).tags,IsTruncated:false}):fail('NoSuchEntity');
    case 'iam list-entities-for-policy':return sessionPolicy(request.PolicyArn)?reply({PolicyGroups:[],PolicyUsers:[],PolicyRoles:[],IsTruncated:false}):fail('NoSuchEntity');
    case 'iam delete-policy':if(faults.deletePolicyDenied)fail('AccessDenied');if(!sessionPolicy(request.PolicyArn))fail('NoSuchEntity');delete state.sessionPolicies[request.PolicyArn];return reply({});
    case 'iam list-role-policies':
      if(isOwner(request.RoleName))return reply({PolicyNames:Object.keys(ownerDocuments().inline),IsTruncated:faults.ownerListTruncated===true,...(faults.ownerListTruncated?{Marker:'synthetic'}:{})});
      return reply({PolicyNames:[request.RoleName===GATEWAY_CANARY_OPERATOR_ROLE_NAME?GATEWAY_CANARY_OPERATOR_POLICY_NAME:'synthetic-verification'],IsTruncated:false});
    case 'iam get-role-policy':
      if(isOwner(request.RoleName)){const document=ownerDocuments().inline[request.PolicyName];if(!document)fail('NoSuchEntity');return reply({RoleName:request.RoleName,PolicyName:request.PolicyName,PolicyDocument:document});}
      if(request.RoleName===GATEWAY_CANARY_OPERATOR_ROLE_NAME)return reply({RoleName:request.RoleName,PolicyName:GATEWAY_CANARY_OPERATOR_POLICY_NAME,PolicyDocument:operatorPolicy()});
      return reply({RoleName:names.role,PolicyName:'synthetic-verification',PolicyDocument:resolve(r.CanaryIdentityPolicy.Properties.PolicyDocument)});
    case 'iam list-attached-role-policies':
      if(isOwner(request.RoleName))return reply({AttachedPolicies:ownerDocuments().attached.map(a=>({PolicyArn:a.arn,PolicyName:a.arn.split('/').at(-1)})),IsTruncated:false});
      return reply({AttachedPolicies:[],IsTruncated:false});
    case 'cloudformation create-stack':
      // Each canary is a fresh stack; an earlier one in this state file is gone.
      state.template=JSON.parse(request.TemplateBody);state.stackName=request.StackName;state.mode='comparison';state.deleted=false;delete state.deletionDate;state.polls=0;
      state.stackId=`arn:aws:cloudformation:${region}:${accountId}:stack/${request.StackName}/${randomUUID()}`;
      state.codeSha256=codeSha256(codeZip(state.template.Resources.CanaryFunction.Properties.Code.ZipFile));
      return reply({StackId:state.stackId});
    case 'cloudformation update-stack':state.mode=request.Parameters[0].ParameterValue;return reply({StackId:state.stackId});
    case 'cloudformation delete-stack':if(faults.deleteStackDenied)fail('AccessDenied');state.deleted=true;state.deletionDate=new Date(Date.now()+7*86400_000).toISOString();return reply({});
    case 'cloudformation describe-stacks':
      if(!exists)fail('ValidationError',`Stack with id ${request.StackName} does not exist`);
      // faults.createInProgressPolls holds the lifecycle in its poll wait, outside any CLI call.
      if((state.polls=(state.polls??0)+1)<=(faults.createInProgressPolls??0)){log({status:'CREATE_IN_PROGRESS'});writeFileSync(config.statePath,JSON.stringify(state));
        process.stdout.write(JSON.stringify({Stacks:[{StackName:state.stackName,StackId:state.stackId,StackStatus:'CREATE_IN_PROGRESS'}]}));process.exit(0);}
      return reply({Stacks:[{StackName:state.stackName,StackId:state.stackId,StackStatus:'UPDATE_COMPLETE'}]});
    case 'cloudformation get-template':return reply({TemplateBody:t});
    case 'cloudformation list-stack-resources':
      return reply({StackResourceSummaries:Object.entries(r).map(([LogicalResourceId,x])=>({LogicalResourceId,ResourceType:x.Type,PhysicalResourceId:LogicalResourceId==='SyntheticKey'?KEY_ID:'synthetic'}))});
    case 'lambda get-function-configuration':if(!exists)fail('ResourceNotFoundException');return reply(fnConfig());
    case 'lambda get-function':if(!exists)fail('ResourceNotFoundException');
      return reply({Configuration:fnConfig(),Code:{RepositoryType:'S3',Location:`https://awslambda-synthetic.s3.${region}.amazonaws.com/snapshots/code?X-Amz-Signature=synthetic`}});
    case 'logs describe-log-groups':return reply({logGroups:exists?[{logGroupName:'/aws/lambda/'+names.fn}]:[]});
    case 'kms describe-key':return reply({KeyMetadata:key()});
    case 'kms get-key-policy':return reply({PolicyName:'default',Policy:JSON.stringify(serviceOrder(resolve(r.SyntheticKey.Properties.KeyPolicy)))});
    case 'kms list-grants':return reply({Grants:[],Truncated:false});
    case 'kms list-resource-tags':return reply({Tags:r.SyntheticKey.Properties.Tags.map(x=>({TagKey:x.Key,TagValue:x.Value})),Truncated:false});
    case 'kms encrypt':return reply({KeyId:keyArn,EncryptionAlgorithm:'SYMMETRIC_DEFAULT',CiphertextBlob:Buffer.from('synthetic encrypted bytes for '+request.EncryptionContext['aws:lambda:FunctionArn']).toString('base64')});
  }
  fail('UnsupportedSyntheticOperation');
}
function laneOf(env){
  if(!env.AWS_SHARED_CREDENTIALS_FILE)return null;
  const id=/aws_access_key_id = ASIA([A-Z]+)0*\n/.exec(readFileSync(env.AWS_SHARED_CREDENTIALS_FILE,'utf8'))?.[1];
  return id?id.toLowerCase():'unknown';
}
/** A small IAM evaluator for iam:SimulateCustomPolicy over the supplied
 * documents: explicit deny wins, then an allow that the boundary (if any) also
 * allows. Action, NotAction, Resource, NotResource and the String/Arn
 * Equals/Like operators (and their Not forms) are supported; anything else throws.
 * Like the real simulator, it applies every action to every resource and
 * returns implicitDeny, matching nothing, for an IAM action on a resource of
 * the other type and for logs:GetLogEvents on a log-stream ARN. */
function simulatorImplicitDeny(action,resource){
  const a=action.toLowerCase();
  if(a.startsWith('iam:'))return resource.includes(':policy/')&&a.includes('role')||resource.includes(':role/')&&!a.includes('role');
  return a==='logs:getlogevents'&&resource.includes(':log-stream:');
}
const wildcard=(pattern,value,flags='')=>new RegExp('^'+String(pattern).split(/([*?])/).map(p=>p==='*'?'.*':p==='?'?'.':RegExp.escape(p)).join('')+'$',flags).test(value);
function statementMatches(statement,action,resource,context){
  const any=(list,value,flags)=>[list].flat().some(p=>wildcard(p,value,flags));
  if(statement.Action!==undefined?!any(statement.Action,action,'i'):statement.NotAction===undefined||any(statement.NotAction,action,'i'))return false;
  if(statement.Resource!==undefined?!any(statement.Resource,resource):statement.NotResource===undefined||any(statement.NotResource,resource))return false;
  for(const [operator,entries] of Object.entries(statement.Condition??{})){
    if(!/^(String|Arn)(Not)?(Equals|Like)$/.test(operator))throw Error('synthetic simulator: unsupported '+operator);
    for(const [key,expected] of Object.entries(entries)){
      const values=context.get(key.toLowerCase()),like=operator.endsWith('Like');
      const hit=values!==undefined&&values.some(v=>[expected].flat().some(e=>like?wildcard(e,v):e===v));
      if(operator.includes('Not')?hit:!hit)return false;
    }
  }
  return true;
}
export function simulateCustomPolicy(request){
  const parse=list=>(list??[]).map(p=>[JSON.parse(p).Statement].flat());
  const policies=parse(request.PolicyInputList),boundary=parse(request.PermissionsBoundaryPolicyInputList);
  const context=new Map((request.ContextEntries??[]).map(e=>[e.ContextKeyName.toLowerCase(),e.ContextKeyValues]));
  const some=(documents,effect,action,resource)=>documents.some(statements=>statements.some(s=>s.Effect===effect&&statementMatches(s,action,resource,context)));
  return {IsTruncated:false,EvaluationResults:request.ActionNames.flatMap(action=>(request.ResourceArns??['*']).map(resource=>({EvalActionName:action,EvalResourceName:resource,
    EvalDecision:simulatorImplicitDeny(action,resource)?'implicitDeny':some([...policies,...boundary],'Deny',action,resource)?'explicitDeny'
      :some(policies,'Allow',action,resource)&&(boundary.length===0||some(boundary,'Allow',action,resource))?'allowed':'implicitDeny'})))};
}
const allows=(policy,action)=>Boolean(policy)&&policy.Statement.some(s=>s.Effect==='Allow'&&[s.Action].flat().includes(action));
function laneAllows(state,lane,action){
  const restriction=state.sessionRestrictions[lane];
  return allows(restriction?.policy??state.sessionPolicies[restriction?.policyArn]?.document,action);
}
const redact=v=>v&&typeof v==='object'?Object.fromEntries(Object.entries(v).map(([k,x])=>[k,k==='TemplateBody'||k==='Policy'||k==='PolicyDocument'?'<'+k+'>':x])):v;
if(process.argv[1]===fileURLToPath(import.meta.url))main(process.argv.slice(2));
