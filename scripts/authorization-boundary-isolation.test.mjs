import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parseDocument } from 'yaml';
import * as boundary from './lib/workload-permissions-boundary.mjs';

const accountId = '123456789012';
const base = { partition:'aws', accountId, applicationRegion:'ap-northeast-1',
  bedrockProjectArn:`arn:aws:bedrock-mantle:ap-northeast-1:${accountId}:project/proj_test` };
const maximum = { ...base, decisionArtifactBucketName:'a'.repeat(33), policyRevision:'r'+'9'.repeat(20),
  bedrockProjectArn:`arn:aws:bedrock-mantle:ap-northeast-1:${accountId}:project/proj_${'z'.repeat(20)}`,
  openAiBedrockProjectArn:`arn:aws:bedrock-mantle:us-west-2:${accountId}:project/proj_${'z'.repeat(20)}` };
const list = value => Array.isArray(value) ? value : [value];
const bucket = contract => contract.decisionArtifactBucketName ?? `mem9-audit-${contract.accountId}`;
const maintenanceDeny = contract => ({Effect:'Deny',Action:['s3:PutObject','iam:PassRole'],
  Resource:[`arn:${contract.partition}:s3:::${bucket(contract)}/data-authorizations/*`,
    `arn:${contract.partition}:iam::${contract.accountId}:role/mem9-on-aws-namespace-operator`,
    `arn:${contract.partition}:iam::${contract.accountId}:role/mem9-on-aws-preview-human-acceptance`]});
const build = contract => boundary.expectedBoundaryPolicyDocument(contract);
const verify = (document, contract=base) => boundary.verifyBoundaryPolicyDocument(document, contract);
const compare = (document, expected) => boundary.compareBoundaryPolicyDocuments(document, expected);
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value==='object' ?
  Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])])) : value;
const fingerprint = value => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
const withoutSids = document => document.Statement.map(({Sid,...statement})=>statement);
const isMaintenanceDeny = (statement, contract=base) => fingerprint(statement)===fingerprint(maintenanceDeny(contract));
const resourceCeiling = document => document.Statement.find(s=>s.Effect==='Deny' && list(s.Action).some(a=>a==='s3:GetObject'||a==='s3:*') && s.NotResource);
const originalResourceActions = ['bedrock-mantle:CreateInference','bedrock-mantle:GetProject','bedrock-mantle:ListProjects','bedrock-mantle:ListTagsForResource',
  'ecr:BatchCheckLayerAvailability','ecr:BatchGetImage','ecr:GetDownloadUrlForLayer','lambda:InvokeFunction','logs:CreateLogGroup','logs:CreateLogStream',
  'logs:PutLogEvents','secretsmanager:GetSecretValue','sns:Publish','sqs:SendMessage','ssm:GetParameters','ssm:PutParameter','s3:GetObject','s3:PutObject'];
const originalCeiling = [...originalResourceActions,'ecs:RunTask','ec2:AssignPrivateIpAddresses','ec2:CreateNetworkInterface','ec2:DeleteNetworkInterface',
  'ec2:DescribeNetworkInterfaces','ec2:DescribeSubnets','ec2:UnassignPrivateIpAddresses','ecr:GetAuthorizationToken','iam:PassRole',
  'ssmmessages:CreateControlChannel','ssmmessages:CreateDataChannel','ssmmessages:OpenControlChannel','ssmmessages:OpenDataChannel',
  'kms:Decrypt','kms:GenerateDataKey','bedrock-mantle:CallWithBearerToken'];
function previousBoundary(document, contract=base){
  const previous=structuredClone(document);
  previous.Statement=previous.Statement.filter(s=>!isMaintenanceDeny(s,contract));
  resourceCeiling(previous).Action=[...originalResourceActions];
  return previous;
}


it('the executable verifier rejects duplicate raw JSON instead of losing it during pre-parsing', () => {
  const invoke = input => spawnSync(process.execPath, [fileURLToPath(new URL('./verify-workload-permissions-boundary.mjs', import.meta.url))], {
    input, encoding: 'utf8', timeout: 5000,
    env: {...process.env, WORKLOAD_BOUNDARY_ACCOUNT_ID: base.accountId,
      WORKLOAD_BOUNDARY_APPLICATION_REGION: base.applicationRegion,
      WORKLOAD_BOUNDARY_BEDROCK_PROJECT_ARN: base.bedrockProjectArn,
      WORKLOAD_BOUNDARY_DECISION_ARTIFACT_BUCKET: bucket(base),
      WORKLOAD_BOUNDARY_PARTITION: base.partition, WORKLOAD_BOUNDARY_POLICY_REVISION: 'r1',
      WORKLOAD_BOUNDARY_OPENAI_BEDROCK_PROJECT_ARN: ''},
  });
  const raw = JSON.stringify(build(base));
  expect(invoke(raw).status).toBe(0);
  const duplicate = raw.replace('"Effect":"Allow"', '"Effect":"Deny","Effect":"Allow"');
  expect(duplicate).not.toBe(raw);
  const rejected = invoke(duplicate);
  expect(rejected.status).toBe(1);
  expect(rejected.stderr).toContain('policy read-back mismatch');
  expect(rejected.stderr).not.toContain(base.accountId);
});

const templateSource=readFileSync(new URL('../infra/cloudformation/workload-permissions-boundary.yaml',import.meta.url),'utf8');
function renderTemplate(contract) {
  const document=parseDocument(templateSource,{uniqueKeys:true,prettyErrors:false,customTags:[
    {tag:'!Ref',resolve:value=>({Ref:value})}, {tag:'!Sub',resolve:value=>({'Fn::Sub':value})},
    ...['If','Equals','Not'].map(name=>({tag:'!'+name,collection:'seq',resolve:value=>({['Fn::'+name]:value.toJSON()})})),
  ]});
  expect(document.errors).toEqual([]);
  const template=document.toJS(),noValue=Symbol('NoValue');
  const values={'AWS::Partition':contract.partition,'AWS::AccountId':contract.accountId,
    'AWS::URLSuffix':contract.partition==='aws-cn'?'amazonaws.com.cn':'amazonaws.com',
    ApplicationRegion:contract.applicationRegion,DecisionArtifactBucketName:bucket(contract),
    BedrockProjectArn:contract.bedrockProjectArn,OpenAiBedrockProjectArn:contract.openAiBedrockProjectArn??'',
    PolicyRevision:contract.policyRevision??'r1','AWS::NoValue':noValue};
  const resolve=value=>{
    if(Array.isArray(value))return value.map(resolve).filter(v=>v!==noValue);
    if(value&&typeof value==='object'){
      if(Object.hasOwn(value,'Ref')){expect(Object.hasOwn(values,value.Ref)).toBe(true);return values[value.Ref];}
      if(Object.hasOwn(value,'Fn::Sub'))return value['Fn::Sub'].replace(/\$\{([^}]+)\}/gu,(_,key)=>{
        expect(Object.hasOwn(values,key)).toBe(true);return values[key];
      });
      if(Object.hasOwn(value,'Fn::If')){
        const [condition,yes,no]=value['Fn::If'];expect(condition).toBe('HasOpenAiBedrockProject');
        return resolve(contract.openAiBedrockProjectArn?yes:no);
      }
      return Object.fromEntries(Object.entries(value).map(([key,child])=>[key,resolve(child)]));
    }
    return value;
  };
  return {template,document:resolve(template.Resources.WorkloadPermissionsBoundary.Properties.PolicyDocument)};
}

const fixtures=[];
for(const bucketName of [undefined,'abc','example-decisions','a'.repeat(33)])
  for(const primary of [base.bedrockProjectArn,maximum.bedrockProjectArn])
    for(const secondary of ['',`arn:aws:bedrock-mantle:us-west-2:${accountId}:project/default`,maximum.openAiBedrockProjectArn])
      for(const revision of ['r1',maximum.policyRevision])fixtures.push({name:`fixture-${fixtures.length+1}`,
        contract:{...base,decisionArtifactBucketName:bucketName,bedrockProjectArn:primary,openAiBedrockProjectArn:secondary,policyRevision:revision}});

describe('authorization archive workload boundary',()=>{
  it.each(fixtures)('TC096/097: full rendered parity, uniqueness and quota for $name',({contract})=>{
    const {template,document}=renderTemplate(contract),expected=build(contract);
    expect(template.Parameters.DecisionArtifactBucketName.MaxLength).toBe(33);
    expect(document.Statement).toHaveLength(16);
    expect(document.Statement.filter(s=>Object.hasOwn(s,'Sid')).map(s=>s.Sid)).toEqual(['C'+contract.policyRevision]);
    expect(document.Statement.filter(s=>isMaintenanceDeny(s,contract))).toHaveLength(1);
    expect(verify(document,contract)).toBe(true);
    expect(compare(document,expected)).toBe(true);
    expect(JSON.stringify(document).length).toBeLessThanOrEqual(6144);
  });

  it('TC096/110: the complete maximum fixture is 6069 characters; longer bucket names reject',()=>{
    expect(JSON.stringify(renderTemplate(maximum).document).length).toBe(6069);
    for(const length of [34,63])expect(()=>build({...base,decisionArtifactBucketName:'a'.repeat(length)})).toThrow(/invalid decision-artifact bucket name/u);
  });

  it.each([
    ['default',base,'107ce6149ee5e34bb9cc12912f32b1e34566bc4e59a1ace7ae0650576ceccbce'],
    ['maximum',maximum,'1ae6c364ada0618b9f3a6afaf38055b9d8c7d71c8f2d09f46a6a177358506535'],
  ])('TC099: %s preserves every pre-change semantic field',(_name,contract,pinnedHash)=>{
    // Restore only the separately proven resource-action compaction and remove
    // the two new maintenance exclusions; every older field remains pinned.
    const document=build(contract);
    expect(document.Statement.filter(s=>isMaintenanceDeny(s,contract))).toHaveLength(1);
    const previous=previousBoundary(document,contract);
    expect(fingerprint(withoutSids(previous))).toBe(pinnedHash);
  });

  it('TC097: accepts ordering and scalar/list variants only at the existing four fields',()=>{
    const document=build(base);document.Statement.reverse();
    for(const statement of document.Statement){
      for(const key of ['Action','NotAction','Resource','NotResource'])if(Object.hasOwn(statement,key)){
        statement[key]=list(statement[key]).slice().reverse();
      }
      if(statement.Condition)for(const entries of Object.values(statement.Condition))for(const [key,value] of Object.entries(entries))
        if(Array.isArray(value))entries[key]=value.slice().reverse();
    }
    expect(verify(document)).toBe(true);
    expect(verify(JSON.stringify(document))).toBe(true);
    expect(verify(encodeURIComponent(JSON.stringify(document)))).toBe(true);
    const altered=build(base).Statement.find(s=>s.Action==='kms:GenerateDataKey');
    const conditionKey='kms:EncryptionContext:aws:s3:arn';
    altered.Condition.StringNotLikeIfExists[conditionKey]=[altered.Condition.StringNotLikeIfExists[conditionKey]];
    const mismatch=build(base);mismatch.Statement[mismatch.Statement.findIndex(s=>s.Action==='kms:GenerateDataKey')]=altered;
    expect(verify(mismatch)).toBe(false);
  });

  it.each([
    ['duplicate statement',d=>d.Statement.push(structuredClone(d.Statement[0]))],
    ['missing statement',d=>d.Statement.pop()],
    ['same-count duplicate and omission',d=>d.Statement[2]=structuredClone(d.Statement[0])],
    ['rogue statement',d=>d.Statement.push({Effect:'Allow',Action:'s3:*',Resource:'*'})],
    ['duplicate Action',d=>{const s=resourceCeiling(d);s.Action.push(s.Action[0]);}],
    ['duplicate NotAction',d=>{const s=d.Statement.find(s=>s.NotAction);s.NotAction.push(s.NotAction[0]);}],
    ['duplicate Resource',d=>d.Statement[0].Resource=['*','*']],
    ['duplicate NotResource',d=>{const s=resourceCeiling(d);s.NotResource.push(s.NotResource[0]);}],
    ['effect',d=>d.Statement[0].Effect='Deny'],
    ['extra field',d=>d.Statement[0].Principal='*'],
    ['extra undefined field',d=>d.Statement[0].Principal=undefined],
    ['action',d=>d.Statement.at(-1).Action='s3:GetObject'],
    ['resource',d=>d.Statement.at(-1).Resource='*'],
    ['condition',d=>{const s=d.Statement.find(s=>s.Action==='bedrock-mantle:CallWithBearerToken');s.Condition.StringNotEqualsIfExists['bedrock-mantle:BearerTokenType']='LONG_TERM';}],
    ['missing revision',d=>delete d.Statement.find(s=>s.Sid).Sid],
    ['changed revision',d=>d.Statement.find(s=>s.Sid).Sid='Cr2'],
    ['extra Sid',d=>d.Statement[0].Sid='Unexpected'],
    ['document version',d=>d.Version='2008-10-17'],
    ['document extra field',d=>d.Id='unexpected'],
  ])('TC098: rejects %s',(_name,mutate)=>{
    const document=build(base);mutate(document);expect(verify(document)).toBe(false);
  });

  it('TC098: rejects canonical expected collisions after Sid removal, including a same-count rogue actual',()=>{
    const differingSids=[{Sid:'First',Effect:'Deny',Action:'s3:PutObject',Resource:'*'},
      {Sid:'Second',Effect:'Deny',Action:['s3:PutObject'],Resource:['*']}];
    const expected={Version:'2012-10-17',Statement:withoutSids({Statement:differingSids})};
    expect(compare(expected,expected)).toBe(false);
    const rogue={...expected,Statement:[expected.Statement[0],{Effect:'Allow',Action:'*',Resource:'*'}]};
    expect(compare(rogue,expected)).toBe(false);
    const duplicate=build(base);duplicate.Statement[2]=structuredClone(duplicate.Statement[0]);
    const actual=structuredClone(duplicate);actual.Statement[2]={Effect:'Allow',Action:'s3:*',Resource:'*'};
    expect(compare(actual,duplicate)).toBe(false);
    const duplicateValue=build(base);resourceCeiling(duplicateValue).Action.push(resourceCeiling(duplicateValue).Action[0]);
    expect(compare(duplicateValue,duplicateValue)).toBe(false);
  });

  it('TC098: rejects duplicate JSON members and non-JSON ambiguity instead of discarding it',()=>{
    const raw=JSON.stringify(build(base));
    for(const member of ['"Effect"','"\\u0045ffect"']){
      const duplicate=raw.replace('"Effect":"Allow"','"Effect":"Deny",'+member+':"Allow"');
      expect(verify(duplicate)).toBe(false);expect(verify(encodeURIComponent(duplicate))).toBe(false);
    }
    for(const document of [null,[],{},'not-json','%zz',{Version:'2012-10-17',Statement:null}])expect(verify(document)).toBe(false);
  });

  it('TC098: anonymous condition drift and duplicates have bounded content-free diagnostics',()=>{
    const document=build(base),s=document.Statement.find(s=>s.Action==='kms:GenerateDataKey');
    s.Condition.StringNotLikeIfExists['kms:EncryptionContext:aws:s3:arn']=`arn:aws:s3:::synthetic-private-${accountId}`;
    document.Statement.push({Sid:'synthetic-private-token',Effect:'Allow',Action:'other:SyntheticPrivateAction',Resource:'*'});
    const diagnostic=boundary.boundaryPolicyDriftDiagnostic(document,base);
    expect(diagnostic).toContain('added statements: <redacted>');
    expect(diagnostic).toContain('removed statements: statement-12');
    for(const secret of ['synthetic-private',accountId,'arn:aws:'])expect(diagnostic).not.toContain(secret);
    const duplicate=build(base);duplicate.Statement[2]=structuredClone(duplicate.Statement[0]);
    expect(boundary.boundaryPolicyDriftDiagnostic(duplicate,base)).toContain('duplicate statements: 1');
    expect(boundary.boundaryPolicyDriftDiagnostic(build(base),base)).toContain('removed statements: (none)');
  });
});

// This models only this boundary's explicit-deny ceiling, with an independent
// identity Allow assumed. It is a synthetic differential check, not live IAM.
const matches=(pattern,value)=>typeof value==='string'&&new RegExp('^'+pattern.split(/([*?])/u)
  .map(p=>p==='*'?'.*':p==='?'?'.':RegExp.escape(p)).join('')+'$','u').test(value);
function permits(document,{action,resource,context={}}){
  const conditionMatches=condition=>Object.entries(condition??{}).every(([operator,entries])=>Object.entries(entries).every(([key,expected])=>{
    const actual=context[key];
    if(operator==='Null')return String(actual===undefined)===expected;
    expect(['StringNotLikeIfExists','StringNotEqualsIfExists','ArnNotLike']).toContain(operator);
    return actual===undefined||!list(expected).some(value=>operator==='StringNotEqualsIfExists'?actual===value:matches(value,actual));
  }));
  return !document.Statement.some(s=>s.Effect==='Deny'&&
    (s.Action?list(s.Action).some(a=>matches(a,action)):!list(s.NotAction).some(a=>matches(a,action)))&&
    (s.Resource?list(s.Resource).some(r=>matches(r,resource)):!list(s.NotResource).some(r=>matches(r,resource)))&&conditionMatches(s.Condition));
}

it('TC093/094/099/108: only archive Put and operator PassRole change across the synthetic request matrix',()=>{
  const document=build(base),before=previousBoundary(document);
  expect(fingerprint(withoutSids(before))).toBe('107ce6149ee5e34bb9cc12912f32b1e34566bc4e59a1ace7ae0650576ceccbce');
  const arn=`arn:aws:s3:::${bucket(base)}`,parameter=`arn:aws:ssm:${base.applicationRegion}:${accountId}:parameter/mem9-on-aws/prod/`;
  const key=`arn:aws:kms:${base.applicationRegion}:${accountId}:key/synthetic`,fn=`arn:aws:lambda:${base.applicationRegion}:${accountId}:function:mem9-on-aws-prod-proxy`;
  const proxy=`arn:aws:iam::${accountId}:role/mem9-on-aws-prod-Mem9ProxyFnRole-synthetic`;
  const secret=`arn:aws:secretsmanager:${base.applicationRegion}:${accountId}:secret:mem9-on-aws-prod-Mem9DbSecret-synthetic`;
  const executionRole=`arn:aws:iam::${accountId}:role/mem9-on-aws-prod-Mem9ServerExecutionRole-synthetic`;
  const ssmVia='ssm.'+base.applicationRegion+'.amazonaws.com',secretVia='secretsmanager.'+base.applicationRegion+'.amazonaws.com';
  const cases=[];
  for(const prefix of ['data-authorizations/op/','decisions/prod/','decisions/pr-1/','consolidation-digests/prod/','runtime-publication-locks/prod/'])
    for(const action of ['s3:GetObject','s3:PutObject','s3:DeleteObject','s3:PutObjectTagging'])cases.push({action,resource:arn+'/'+prefix+'record.json',
      allowed:['s3:GetObject','s3:PutObject'].includes(action),after:action==='s3:PutObject'&&prefix.startsWith('data-authorizations/')?false:undefined});
  for(const resource of [`arn:aws:s3:${base.applicationRegion}:${accountId}:accesspoint/example/object/data-authorizations/x`,
    `arn:aws:s3::${accountId}:accesspoint/example.mrap/object/data-authorizations/x`,
    `arn:aws:s3:${base.applicationRegion}:${'9'.repeat(12)}:accesspoint/example/object/decisions/prod/x`])
    for(const action of ['s3:GetObject','s3:PutObject'])cases.push({action,resource,allowed:false});
  cases.push({action:'s3:PutObject',resource:`arn:aws:s3:::foreign-${accountId}/decisions/prod/x`,allowed:false},
    {action:'ssm:PutParameter',resource:parameter+'approvals/synthetic',allowed:true},
    {action:'ssm:PutParameter',resource:parameter+'consolidation-runtime/data-release',allowed:false},
    {action:'ssm:GetParameters',resource:parameter+'consolidation-runtime/data-release',allowed:true},
    {action:'iam:PassRole',resource:proxy,context:{'iam:PassedToService':'lambda.amazonaws.com'},allowed:true});
  for(const action of ['kms:Decrypt','kms:GenerateDataKey'])for(const [context,allowed] of [
    [{},false], [{ 'kms:EncryptionContext:aws:s3:arn':arn,'kms:ViaService':'s3.'+base.applicationRegion+'.amazonaws.com'},true],
    [{ 'kms:EncryptionContext:aws:s3:arn':arn+'/decisions/prod/x','kms:ViaService':'s3.'+base.applicationRegion+'.amazonaws.com'},false],
  ])cases.push({action,resource:key,context,allowed});
  cases.push({action:'kms:Decrypt',resource:key,context:{'kms:EncryptionContext:PARAMETER_ARN':parameter+'secret','kms:ViaService':'ssm.'+base.applicationRegion+'.amazonaws.com'},allowed:true},
    {action:'kms:Decrypt',resource:key,context:{'kms:EncryptionContext:PARAMETER_ARN':parameter+'secret','kms:ViaService':secretVia},allowed:false},
    {action:'kms:GenerateDataKey',resource:key,context:{'kms:EncryptionContext:PARAMETER_ARN':parameter+'secret','kms:ViaService':ssmVia},allowed:false},
    {action:'kms:Decrypt',resource:key,context:{'kms:EncryptionContext:SecretARN':secret,'kms:ViaService':secretVia,'aws:PrincipalArn':executionRole},allowed:true},
    {action:'kms:Decrypt',resource:key,context:{'kms:EncryptionContext:SecretARN':secret,'kms:ViaService':secretVia,'aws:PrincipalArn':proxy},allowed:false},
    {action:'kms:Decrypt',resource:key,context:{'kms:EncryptionContext:SecretARN':secret,'kms:ViaService':ssmVia,'aws:PrincipalArn':executionRole},allowed:false},
    {action:'kms:Decrypt',resource:key,context:{'kms:EncryptionContext:aws:lambda:FunctionArn':fn,'aws:PrincipalArn':proxy},allowed:true},
    {action:'kms:Decrypt',resource:key,context:{'kms:EncryptionContext:aws:lambda:FunctionArn':fn,'aws:PrincipalArn':executionRole},allowed:false},
    {action:'kms:Decrypt',resource:key,context:{'kms:EncryptionContext:aws:lambda:FunctionArn':fn,'aws:PrincipalArn':proxy,'lambda:SourceFunctionArn':fn},allowed:false},
    {action:'bedrock-mantle:CallWithBearerToken',resource:'*',context:{'bedrock-mantle:BearerTokenType':'SHORT_TERM'},allowed:true},
    {action:'bedrock-mantle:CallWithBearerToken',resource:'*',context:{'bedrock-mantle:BearerTokenType':'LONG_TERM'},allowed:false},
    {action:'ec2:CreateNetworkInterface',resource:'*',context:{'aws:PrincipalArn':proxy},allowed:true},
    {action:'ec2:CreateNetworkInterface',resource:'*',context:{'aws:PrincipalArn':proxy,'lambda:SourceFunctionArn':fn},allowed:false},
    {action:'ec2:CreateNetworkInterface',resource:'*',context:{'aws:PrincipalArn':proxy.replace('Mem9ProxyFnRole','UnreviewedRole')},allowed:false});
  for(const name of ['mem9-on-aws-namespace-operator','mem9-on-aws-preview-human-acceptance'])
    cases.push({action:'iam:PassRole',resource:`arn:aws:iam::${accountId}:role/${name}`,context:{'iam:PassedToService':'ecs-tasks.amazonaws.com'},allowed:true,after:false});
  for(const request of cases){
    expect(permits(before,request),JSON.stringify(request)).toBe(request.allowed);
    expect(permits(document,request),JSON.stringify(request)).toBe(request.after??request.allowed);
  }
  expect(list(resourceCeiling(document).NotResource).some(r=>r.includes(':accesspoint/'))).toBe(false);
});

it('TC109: exact 34-action ceiling proves the resource-action compaction intersection',()=>{
  for(const {contract} of fixtures){
    const document=build(contract),ceiling=document.Statement.find(s=>s.NotAction).NotAction;
    expect(ceiling).toEqual(originalCeiling);expect(ceiling).toHaveLength(34);
    expect(new Set(ceiling).size).toBe(34);expect(ceiling.every(a=>!/[?*]/u.test(a))).toBe(true);
    const compact=list(resourceCeiling(document).Action);
    for(const action of ceiling)expect(compact.some(p=>matches(p,action)),action).toBe(originalResourceActions.some(p=>matches(p,action)));
    for(const action of ['s3:FutureMutation','ecr:BatchFutureMutation','lambda:FutureMutation']){
      expect(ceiling.includes(action)).toBe(false);
      expect(permits(document,{action,resource:'*'})).toBe(false);
    }
  }
});
