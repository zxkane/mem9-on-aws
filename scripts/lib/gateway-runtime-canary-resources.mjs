import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {expectedGatewayBoundaryPolicyDocument} from './gateway-workload-boundary.mjs';

const check=(ok,reason)=>{if(!ok)throw new Error('GatewayRuntimeCanary'+reason);};
const exact=(v,keys)=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&
  Object.keys(v).sort().join()===keys.slice().sort().join();
const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'
  ?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
export const gatewayCanaryDocumentHash=v=>createHash('sha256').update(JSON.stringify(canonical(v))).digest('hex');
const bytesHash=v=>createHash('sha256').update(v).digest('hex');
const freeze=v=>{if(v&&typeof v==='object'){for(const x of Object.values(v))freeze(x);Object.freeze(v);}return v;};
const TEMPLATE=new URL('../test-fixtures/gateway-runtime-canary/template.json',import.meta.url);
export const GATEWAY_CANARY_LIMITS=Object.freeze({operationMs:20*60_000,cleanupMs:5*60_000,
  propagationAttempts:6,propagationDelayMs:5000,invokeTimeoutMs:45_000,
  maximumTemplateBytes:51200,maximumHandlerBytes:24000,maximumPolicyBytes:6144,
  stackPolls:60,stackPollDelayMs:5000,maximumResponseBytes:1024*1024});

/** A resource scope, not an execution capability. All names are derived; callers
 * cannot select another canary role family, stage or boundary. ownerRoleArn
 * must come from the native issuer's authenticated same-account identity; a
 * policy document or this pure compiler cannot establish that authority. */
export function compileGatewayRuntimeCanaryScope(input){
  check(exact(input,['accountId','applicationRegion','verificationId','vpcId','ownerRoleArn']),'Scope');
  const {accountId,applicationRegion,verificationId,vpcId,ownerRoleArn}=input;
  check(typeof accountId==='string'&&/^\d{12}$/.test(accountId),'Account');
  check(typeof applicationRegion==='string'&&/^[a-z]{2}-[a-z]+-\d$/.test(applicationRegion)&&applicationRegion.length<=24,'Region');
  check(typeof verificationId==='string'&&/^[a-f0-9]{12}$/.test(verificationId),'VerificationId');
  check(typeof vpcId==='string'&&/^vpc-(?:[a-f0-9]{8}|[a-f0-9]{17})$/.test(vpcId),'Vpc');
  check(typeof ownerRoleArn==='string'&&ownerRoleArn.startsWith(`arn:aws:iam::${accountId}:role/`)&&
    /^[A-Za-z0-9_+=,.@/-]{1,576}$/.test(ownerRoleArn.slice(`arn:aws:iam::${accountId}:role/`.length)),'OwnerRole');
  const stage='runtime-check',prefix=`mem9-on-aws-${stage}`;
  const roleName=`${prefix}-Mem9ProxyFnRole-${verificationId}`;
  const functionName=`${prefix}-Mem9ProxyFnFunction-${verificationId}`;
  const stackName=`mem9-on-aws-gateway-check-${verificationId}`;
  const comparisonName=`mem9-on-aws-gateway-comparison-${verificationId}`;
  const iam=`arn:aws:iam::${accountId}:`,regional=(service,suffix)=>`arn:aws:${service}:${applicationRegion}:${accountId}:${suffix}`;
  return freeze({...input,partition:'aws',stage,roleName,functionName,stackName,comparisonName,
    roleArn:iam+'role/'+roleName,
    originalBoundaryArn:iam+'policy/mem9-on-aws-gateway-boundary',comparisonArn:iam+'policy/'+comparisonName,
    functionArn:regional('lambda','function:'+functionName),stackArnPattern:regional('cloudformation','stack/'+stackName+'/*'),
    keyArnPattern:regional('kms','key/*'),logGroupName:'/aws/lambda/'+functionName,
    logGroupArn:regional('logs','log-group:/aws/lambda/'+functionName),
    temporaryPolicyArn:iam+'policy/mem9-on-aws-gateway-check-session-'+verificationId});
}
function validateScope(s){
  check(s&&typeof s==='object','Scope');
  const fresh=compileGatewayRuntimeCanaryScope(Object.fromEntries(['accountId','applicationRegion','verificationId','vpcId','ownerRoleArn'].map(k=>[k,s[k]])));
  check(isDeepStrictEqual(s,fresh),'Scope');return fresh;
}

/** Verify the whole authenticated original before removing two exact clauses.
 * Hashes commit canonical JSON documents, not a claimed raw AWS response. */
export function deriveGatewayComparisonBoundary(original,contract){
  const expected=expectedGatewayBoundaryPolicyDocument(contract);
  check(isDeepStrictEqual(original,expected),'OriginalPolicy');
  const removed=original.Statement.filter(s=>s.Condition?.Null?.['lambda:SourceFunctionArn']==='false');
  check(removed.length===2&&removed[0].Action==='kms:Decrypt'&&removed[1].Action==='ec2:*','SourceStatements');
  const document=structuredClone({...original,Statement:original.Statement.filter(s=>!removed.includes(s))});
  return freeze({document,removedStatements:structuredClone(removed),originalHash:gatewayCanaryDocumentHash(original),comparisonHash:gatewayCanaryDocumentHash(document)});
}
function boundaryContract(policy,scope){
  const revisions=policy?.Statement?.filter(s=>typeof s.Sid==='string'&&/^Gr[0-9]{1,20}$/.test(s.Sid));
  check(revisions?.length===1,'PolicyRevision');
  return {partition:'aws',accountId:scope.accountId,applicationRegion:scope.applicationRegion,policyRevision:revisions[0].Sid.slice(1)};
}
const allow=(Action,Resource,Condition)=>({Effect:'Allow',Action,Resource,...(Condition?{Condition}:{})});

/** The caller must authenticate handlerSource against its reviewed checkout;
 * this compiler generates no authority or PASS. The native owner retains that
 * source/code binding through provisioning and each real invocation. */
export function renderGatewayRuntimeCanaryTemplate(input){
  check(exact(input,['scope','originalBoundary','handlerSource']),'TemplateInput');
  const scope=validateScope(input.scope),{originalBoundary,handlerSource}=input;
  check(typeof handlerSource==='string'&&handlerSource.isWellFormed()&&handlerSource.length>0&&
    Buffer.byteLength(handlerSource)<=GATEWAY_CANARY_LIMITS.maximumHandlerBytes,'Handler');
  const comparison=deriveGatewayComparisonBoundary(originalBoundary,boundaryContract(originalBoundary,scope));
  const template=JSON.parse(readFileSync(TEMPLATE,'utf8')),r=template.Resources;
  const tags=[{Key:'Project',Value:'mem9-on-aws'},{Key:'Stage',Value:scope.stage},{Key:'VerificationId',Value:scope.verificationId}];
  const context={StringEquals:{'kms:EncryptionContext:aws:lambda:FunctionArn':scope.functionArn}};
  template.Metadata.OriginalBoundaryHash=comparison.originalHash;
  template.Metadata.ComparisonBoundaryHash=comparison.comparisonHash;
  template.Metadata.HandlerHash=bytesHash(handlerSource);
  r.ComparisonBoundary.Properties={ManagedPolicyName:scope.comparisonName,Description:'Synthetic source-condition comparison; delete after verification.',PolicyDocument:comparison.document};
  Object.assign(r.CanaryRole.Properties,{RoleName:scope.roleName,Tags:tags,
    PermissionsBoundary:{'Fn::If':['UseOriginalBoundary',scope.originalBoundaryArn,{Ref:'ComparisonBoundary'}]}});
  Object.assign(r.SyntheticKey.Properties,{Description:'Synthetic Gateway source-condition verification only.',Tags:tags,
    KeyPolicy:{Version:'2012-10-17',Statement:[
      {Sid:'OwnedKeyAdministration',...allow(['kms:DescribeKey','kms:GetKeyPolicy','kms:PutKeyPolicy','kms:ListGrants','kms:ListResourceTags','kms:TagResource','kms:UntagResource','kms:ScheduleKeyDeletion'],'*'),Principal:{AWS:scope.ownerRoleArn}},
      {Sid:'SyntheticEncrypt',...allow('kms:Encrypt','*',context),Principal:{AWS:scope.ownerRoleArn}},
      {Sid:'SyntheticDecrypt',...allow('kms:Decrypt','*',context),Principal:{AWS:{'Fn::GetAtt':['CanaryRole','Arn']}}},
    ]}});
  r.CanaryIdentityPolicy.Properties={PolicyName:'synthetic-verification',Roles:[{Ref:'CanaryRole'}],PolicyDocument:{Version:'2012-10-17',Statement:[
    allow('kms:Decrypt',{'Fn::GetAtt':['SyntheticKey','Arn']},context),
    // DescribeSubnets has no VPC resource authorization. The fixed handler uses
    // DryRun=true and its committed VPC filter; the IAM scope is regional.
    allow('ec2:DescribeSubnets','*',{StringEquals:{'aws:RequestedRegion':scope.applicationRegion}}),
    allow(['logs:CreateLogStream','logs:PutLogEvents'],scope.logGroupArn+':log-stream:*'),
  ]}};
  Object.assign(r.CanaryLogGroup.Properties,{LogGroupName:scope.logGroupName,Tags:tags});
  Object.assign(r.CanaryFunction.Properties,{FunctionName:scope.functionName,Role:{'Fn::GetAtt':['CanaryRole','Arn']},
    Code:{ZipFile:handlerSource},Tags:tags,LoggingConfig:{LogFormat:'JSON',LogGroup:{Ref:'CanaryLogGroup'}},
    Environment:{Variables:{CANARY_KEY_ARN:{'Fn::GetAtt':['SyntheticKey','Arn']},CANARY_VPC_ID:scope.vpcId}}});
  const templateBody=JSON.stringify(template);check(Buffer.byteLength(templateBody)<=GATEWAY_CANARY_LIMITS.maximumTemplateBytes,'TemplateTooLarge');
  return freeze({version:1,scope,template,templateBody,templateHash:bytesHash(templateBody),handlerHash:bytesHash(handlerSource),comparison});
}

/** Recompute the closed template, not just a caller-rehashable body checksum.
 * Authentication of the selected original policy and handler remains with the
 * native owner/source gate; this check cannot mint that authentication. */
export function verifyGatewayRuntimeCanaryPlan(plan){
  check(plan&&typeof plan==='object','Plan');
  const scope=validateScope(plan.scope),contract=boundaryContract(plan.comparison?.document,scope);
  const expected=renderGatewayRuntimeCanaryTemplate({scope,originalBoundary:expectedGatewayBoundaryPolicyDocument(contract),handlerSource:plan.template?.Resources?.CanaryFunction?.Properties?.Code?.ZipFile});
  check(isDeepStrictEqual(plan,expected),'PlanChanged');return expected;
}

/** Fixed finite lifecycle permissions. Metadata that CloudFormation itself
 * needs remains in provision; independent inventory/invoke/encrypt is separate.
 * The full provision document is measured before requesting any session. */
export function buildGatewayCanaryOperatorPolicies(input){
  const s=validateScope(input),via={StringEquals:{'aws:CalledViaLast':'cloudformation.amazonaws.com'}};
  const keyTags={'aws:ResourceTag/Project':'mem9-on-aws','aws:ResourceTag/Stage':s.stage,'aws:ResourceTag/VerificationId':s.verificationId};
  const keyCondition={StringEquals:{...keyTags,'aws:CalledViaLast':'cloudformation.amazonaws.com'}};
  const provision={Version:'2012-10-17',Statement:[
    allow(['cloudformation:CreateStack','cloudformation:UpdateStack','cloudformation:DeleteStack','cloudformation:DescribeStacks','cloudformation:DescribeEvents','cloudformation:ListStackResources','cloudformation:GetTemplate'],s.stackArnPattern),
    allow('iam:CreateRole',s.roleArn,{StringEquals:{'aws:CalledViaLast':'cloudformation.amazonaws.com'},ArnEquals:{'iam:PermissionsBoundary':s.comparisonArn}}),
    allow('iam:PutRolePermissionsBoundary',s.roleArn,{StringEquals:{'aws:CalledViaLast':'cloudformation.amazonaws.com'},ArnEquals:{'iam:PermissionsBoundary':[s.comparisonArn,s.originalBoundaryArn]}}),
    allow(['iam:GetRole','iam:DeleteRole','iam:TagRole','iam:UntagRole','iam:ListRolePolicies','iam:ListAttachedRolePolicies','iam:PutRolePolicy','iam:GetRolePolicy','iam:DeleteRolePolicy'],s.roleArn,via),
    allow(['iam:CreatePolicy','iam:GetPolicy','iam:GetPolicyVersion','iam:ListPolicyVersions','iam:ListEntitiesForPolicy','iam:DeletePolicy'],s.comparisonArn,via),
    allow('iam:PassRole',s.roleArn,{StringEquals:{'iam:PassedToService':'lambda.amazonaws.com'}}),
    allow(['lambda:CreateFunction','lambda:GetFunction','lambda:GetFunctionConfiguration','lambda:DeleteFunction','lambda:TagResource','lambda:UntagResource','lambda:PutFunctionConcurrency','lambda:DeleteFunctionConcurrency'],s.functionArn,via),
    allow(['logs:CreateLogGroup','logs:DeleteLogGroup','logs:PutRetentionPolicy','logs:ListTagsForResource','logs:TagResource','logs:UntagResource'],[s.logGroupArn,s.logGroupArn+':*'],via),
    allow('logs:DescribeLogGroups','*',{StringEquals:{'aws:RequestedRegion':s.applicationRegion,'aws:CalledViaLast':'cloudformation.amazonaws.com'}}),
    allow('kms:CreateKey','*',{StringEquals:{'aws:CalledViaLast':'cloudformation.amazonaws.com','aws:RequestTag/Project':'mem9-on-aws','aws:RequestTag/Stage':s.stage,'aws:RequestTag/VerificationId':s.verificationId,'kms:KeySpec':'SYMMETRIC_DEFAULT','kms:KeyUsage':'ENCRYPT_DECRYPT'}}),
    // CreateKey with Tags separately authorizes TagResource before resource
    // tags exist. Keep that dependency in the one account/region, with the
    // fixed request tags and CloudFormation chain, rather than ResourceTag.
    allow('kms:TagResource',s.keyArnPattern,{StringEquals:{'aws:CalledViaLast':'cloudformation.amazonaws.com','aws:RequestTag/Project':'mem9-on-aws','aws:RequestTag/Stage':s.stage,'aws:RequestTag/VerificationId':s.verificationId}}),
    allow(['kms:DescribeKey','kms:GetKeyPolicy','kms:PutKeyPolicy','kms:ListGrants','kms:ListResourceTags','kms:TagResource','kms:UntagResource','kms:ScheduleKeyDeletion'],s.keyArnPattern,keyCondition),
  ]};
  const observe={Version:'2012-10-17',Statement:[
    // GetCallerIdentity still runs in the issuer; STS requires no IAM allow.
    allow('logs:DescribeLogGroups','*',{StringEquals:{'aws:RequestedRegion':s.applicationRegion}}),
    allow(['cloudformation:DescribeStacks','cloudformation:ListStackResources','cloudformation:GetTemplate'],s.stackArnPattern),
    // IAM role operations require a role ARN; policy operations require a
    // policy ARN. Grouping their exact resources adds no effective permission.
    allow(['iam:GetRole','iam:GetRolePolicy','iam:ListRolePolicies','iam:ListAttachedRolePolicies','iam:GetPolicy','iam:GetPolicyVersion','iam:ListPolicyVersions','iam:ListEntitiesForPolicy'],[s.roleArn,s.comparisonArn,s.originalBoundaryArn]),
    allow(['lambda:GetFunction','lambda:GetFunctionConfiguration','lambda:InvokeFunction'],s.functionArn),
    allow(['kms:DescribeKey','kms:GetKeyPolicy','kms:ListGrants','kms:ListResourceTags'],s.keyArnPattern,{StringEquals:keyTags}),
    allow('kms:Encrypt',s.keyArnPattern,{StringEquals:{...keyTags,'kms:EncryptionContext:aws:lambda:FunctionArn':s.functionArn}}),
    allow('logs:GetLogEvents',s.logGroupArn+':log-stream:*'),
  ]};
  const bytes={provision:Buffer.byteLength(JSON.stringify(provision)),observe:Buffer.byteLength(JSON.stringify(observe))};
  check(bytes.provision<=GATEWAY_CANARY_LIMITS.maximumPolicyBytes&&bytes.observe<=2048,'OperatorPolicyTooLarge');
  return freeze({provision,observe,bytes,requiresManagedProvisionPolicy:bytes.provision>2048,
    provisionHash:gatewayCanaryDocumentHash(provision),observeHash:gatewayCanaryDocumentHash(observe)});
}

/** Only for the measured >2048-byte provisioning document. The extra policy is
 * never attached to an IAM identity, has one version, and is used only as the
 * session PolicyArns restriction on the existing same-account owner role. */
export function buildGatewayCanarySessionPolicyBootstrap(input){
  const s=validateScope(input),compiled=buildGatewayCanaryOperatorPolicies(s);
  check(compiled.requiresManagedProvisionPolicy,'ManagedPolicyUnnecessary');
  const policy={Version:'2012-10-17',Statement:[
    allow(['iam:CreatePolicy','iam:TagPolicy'],s.temporaryPolicyArn,{StringEquals:{'aws:RequestTag/Project':'mem9-on-aws','aws:RequestTag/Stage':s.stage,'aws:RequestTag/VerificationId':s.verificationId}}),
    allow(['iam:GetPolicy','iam:GetPolicyVersion','iam:ListPolicyVersions','iam:ListEntitiesForPolicy','iam:ListPolicyTags','iam:DeletePolicy'],s.temporaryPolicyArn),
  ]};
  const policyJson=JSON.stringify(policy);check(Buffer.byteLength(policyJson)<=2048,'BootstrapPolicyTooLarge');
  return freeze({policy,policyJson,policyHash:gatewayCanaryDocumentHash(policy),durationSeconds:3600,
    temporaryPolicyArn:s.temporaryPolicyArn,provisionHash:compiled.provisionHash});
}
