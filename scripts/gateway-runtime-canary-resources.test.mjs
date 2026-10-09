import {describe,it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {classifyChangedPaths} from './classify-infra-changes.mjs';
import {expectedGatewayBoundaryPolicyDocument} from './lib/gateway-workload-boundary.mjs';
import {compileGatewayRuntimeCanaryScope,deriveGatewayComparisonBoundary,
  renderGatewayRuntimeCanaryTemplate,buildGatewayCanaryOperatorPolicies} from './lib/gateway-runtime-canary-resources.mjs';

const input={accountId:'123456789012',applicationRegion:'ap-northeast-1',verificationId:'abcdef012345',vpcId:'vpc-0123456789abcdef0',ownerRoleArn:'arn:aws:iam::123456789012:role/example-runtime-operator'};
const scope=()=>compileGatewayRuntimeCanaryScope(input);
const contract={partition:'aws',accountId:input.accountId,applicationRegion:input.applicationRegion,policyRevision:'r1234'};
const original=()=>expectedGatewayBoundaryPolicyDocument(contract);
const hash=value=>createHash('sha256').update(value).digest('hex');
const code='exports.handler=async()=>{throw new Error("synthetic test only")};\n';
const render=()=>renderGatewayRuntimeCanaryTemplate({scope:scope(),originalBoundary:original(),handlerSource:code});
const list=v=>Array.isArray(v)?v:[v];
const match=(pattern,value)=>new RegExp('^'+RegExp.escape(pattern).replaceAll('\\*','.*').replaceAll('\\?','.')+'$').test(value);
const allowed=(policy,action,resource,context={})=>policy.Statement.some(s=>s.Effect==='Allow'&&
  list(s.Action).some(a=>match(a,action))&&list(s.Resource).some(r=>match(r,resource))&&
  Object.entries(s.Condition??{}).every(([op,terms])=>['StringEquals','ArnEquals'].includes(op)&&
    Object.entries(terms).every(([key,value])=>context[key]!==undefined&&list(value).includes(context[key]))));

describe('operator-only Gateway runtime canary resource contract',()=>{
  it('has exactly one isolated Proxy identity, function and same-account owner',()=>{
    const s=scope();
    expect(s.roleName).toBe('mem9-on-aws-runtime-check-Mem9ProxyFnRole-abcdef012345');
    expect(s.functionName).toBe('mem9-on-aws-runtime-check-Mem9ProxyFnFunction-abcdef012345');
    expect(s.roleName.length).toBeLessThanOrEqual(64);
    expect(s.functionName.length).toBeLessThanOrEqual(64);
    expect(s.ownerRoleArn).toBe(input.ownerRoleArn);
    expect(s.stage).toBe('runtime-check');
    expect(Object.isFrozen(s)).toBe(true);
  });
  it.each([
    {verificationId:'latest'}, {applicationRegion:'*'}, {vpcId:'vpc-*'},
    {accountId:'12345678901'}, {ownerRoleArn:`arn:aws:iam::${'9'.repeat(12)}:role/example-runtime-operator`},
    {stage:'prod'}, {originalBoundaryArn:'arbitrary'},
  ])('rejects caller-selected scope or identities %j',delta=>{
    expect(()=>compileGatewayRuntimeCanaryScope({...input,...delta})).toThrow();
  });
  it('removes exactly the two complete source statements without changing original data',()=>{
    const policy=original(),before=JSON.stringify(policy),result=deriveGatewayComparisonBoundary(policy,contract);
    expect(JSON.stringify(policy)).toBe(before);
    const removed=policy.Statement.filter(s=>s.Condition?.Null?.['lambda:SourceFunctionArn']==='false');
    expect(removed).toHaveLength(2);
    expect(result.document).toEqual({...policy,Statement:policy.Statement.filter(s=>!removed.includes(s))});
    expect(result.removedStatements).toEqual(removed);
    expect(result.originalHash).not.toBe(result.comparisonHash);
    expect(Object.isFrozen(result.document.Statement)).toBe(true);
  });
  it.each(['missing','duplicate','changed-predicate','unrelated-allow','wrong-account'])('rejects unreviewed boundary changes: %s',kind=>{
    const p=original(),i=p.Statement.findIndex(s=>s.Condition?.Null?.['lambda:SourceFunctionArn']);
    if(kind==='missing')p.Statement.splice(i,1);
    if(kind==='duplicate')p.Statement.push(structuredClone(p.Statement[i]));
    if(kind==='changed-predicate')p.Statement[i].Condition.Null['lambda:SourceFunctionArn']='true';
    if(kind==='unrelated-allow')p.Statement[0].Action=['kms:*'];
    if(kind==='wrong-account')p.Statement[2].Condition.ArnNotLike['aws:PrincipalArn'][0]=p.Statement[2].Condition.ArnNotLike['aws:PrincipalArn'][0].replace(input.accountId,'9'.repeat(12));
    expect(()=>deriveGatewayComparisonBoundary(p,contract)).toThrow();
  });
  it('does not deploy the app in the real change classifier',()=>{
    expect(classifyChangedPaths(['scripts/test-fixtures/gateway-runtime-canary/template.json',
      'scripts/lib/gateway-runtime-canary-resources.mjs','scripts/lib/gateway-runtime-canary-lifecycle.mjs',
      'scripts/gateway-runtime-canary-resources.test.mjs','scripts/gateway-runtime-canary-lifecycle.test.mjs'])).toEqual({
      workloadChanged:false,applicationInfrastructureChanged:false,awsMutationRequired:false,
    });
  });
  it('renders six exact owned resources without VPC, URLs, CMK environment encryption or production secrets',()=>{
    const plan=render(),t=plan.template;
    expect(Object.keys(t.Resources).sort()).toEqual(['CanaryFunction','CanaryIdentityPolicy','CanaryLogGroup','CanaryRole','ComparisonBoundary','SyntheticKey']);
    const fn=t.Resources.CanaryFunction.Properties;
    expect(fn.Runtime).toBe('nodejs24.x');expect(fn.Architectures).toEqual(['arm64']);
    expect(fn.VpcConfig).toBeUndefined();expect(fn.KmsKeyArn).toBeUndefined();
    expect(fn.ReservedConcurrentExecutions).toBe(1);expect(fn.Timeout).toBe(30);
    expect(fn.Code.ZipFile).toBe(code);expect(plan.handlerHash).toBe(hash(code));
    expect(t.Resources.SyntheticKey.Properties.PendingWindowInDays).toBe(7);
    expect(t.Resources.SyntheticKey.Properties.BypassPolicyLockoutSafetyCheck).toBe(false);
    expect(t.Resources.SyntheticKey.DeletionPolicy).toBe('Delete');
    const executionResources=structuredClone(t.Resources);delete executionResources.ComparisonBoundary;
    // The comparison must retain the original policy's entire non-source
    // deny vocabulary. Check granted runtime permissions separately.
    expect(JSON.stringify(executionResources)).not.toMatch(/FunctionUrl|secretsmanager:GetSecretValue|ec2:CreateNetworkInterface|iam:CreateRole|AWS_ACCESS_KEY/);
    expect(Buffer.byteLength(plan.templateBody)).toBeLessThanOrEqual(51200);
    expect(t.Resources.ComparisonBoundary.Properties.PolicyDocument).toEqual(plan.comparison.document);
  });
  it('identity grants only exact synthetic decrypt/context, scoped logs and regional subnet authorization probe',()=>{
    const statements=render().template.Resources.CanaryIdentityPolicy.Properties.PolicyDocument.Statement;
    expect(statements.flatMap(s=>[].concat(s.Action)).sort()).toEqual(['ec2:DescribeSubnets','kms:Decrypt','logs:CreateLogStream','logs:PutLogEvents'].sort());
    const kms=statements.find(s=>s.Action==='kms:Decrypt');
    expect(kms.Resource).toEqual({'Fn::GetAtt':['SyntheticKey','Arn']});
    expect(kms.Condition.StringEquals['kms:EncryptionContext:aws:lambda:FunctionArn']).toBe(scope().functionArn);
    const ec2=statements.find(s=>s.Action==='ec2:DescribeSubnets');
    expect(ec2.Resource).toBe('*');expect(ec2.Condition).toEqual({StringEquals:{'aws:RequestedRegion':input.applicationRegion}});
    expect(JSON.stringify(statements)).not.toContain('ec2:Vpc');
  });
  it('keeps runtime policy switching entirely on the one test role',()=>{
    const t=render().template;
    expect(t.Parameters.BoundaryMode.AllowedValues).toEqual(['comparison','original']);
    expect(t.Resources.CanaryRole.Properties.PermissionsBoundary).toEqual({'Fn::If':['UseOriginalBoundary',scope().originalBoundaryArn,{Ref:'ComparisonBoundary'}]});
    expect(t.Resources.CanaryRole.Properties.Tags).toEqual(expect.arrayContaining([{Key:'Project',Value:'mem9-on-aws'},{Key:'Stage',Value:'runtime-check'}]));
    expect(t.Resources.CanaryRole.Properties.AssumeRolePolicyDocument.Statement).toEqual([{Effect:'Allow',Principal:{Service:'lambda.amazonaws.com'},Action:'sts:AssumeRole'}]);
  });
  it('renders auditable finite operator grants with no IAM wildcard or production resources',()=>{
    const p=buildGatewayCanaryOperatorPolicies(scope());
    expect(p).toHaveProperty('provision');expect(p).toHaveProperty('observe');
    for(const policy of [p.provision,p.observe])for(const statement of policy.Statement){
      expect([].concat(statement.Action)).not.toContain('iam:*');
      expect(JSON.stringify(statement)).not.toContain('role/github-actions');
    }
    const pass=p.provision.Statement.find(s=>[].concat(s.Action).includes('iam:PassRole'));
    expect(pass.Resource).toBe(scope().roleArn);
    expect(pass.Condition.StringEquals['iam:PassedToService']).toBe('lambda.amazonaws.com');
    const encrypt=p.observe.Statement.find(s=>[].concat(s.Action).includes('kms:Encrypt'));
    expect(encrypt.Condition.StringEquals['aws:ResourceTag/VerificationId']).toBe(input.verificationId);
    expect(encrypt.Condition.StringEquals['kms:EncryptionContext:aws:lambda:FunctionArn']).toBe(scope().functionArn);
    expect(p.bytes.provision).toBe(Buffer.byteLength(JSON.stringify(p.provision)));
    expect(p.requiresManagedProvisionPolicy).toBe(p.bytes.provision>2048);
    expect(p.provision.Statement.flatMap(s=>[].concat(s.Action))).toContain('cloudformation:DescribeEvents');
    expect(p.provision.Statement.flatMap(s=>[].concat(s.Action))).not.toContain('cloudformation:DescribeStackEvents');
    const logs=p.observe.Statement.find(s=>s.Action==='logs:DescribeLogGroups');
    expect(logs).toEqual({Effect:'Allow',Action:'logs:DescribeLogGroups',Resource:'*',Condition:{StringEquals:{'aws:RequestedRegion':input.applicationRegion}}});
    expect(p.bytes.observe).toBeLessThanOrEqual(2048);
  });
  it('requires CloudFormation, the exact canary role and approved boundary for creation/updates',()=>{
    const s=scope(),p=buildGatewayCanaryOperatorPolicies(s).provision;
    const context={'aws:CalledViaLast':'cloudformation.amazonaws.com','iam:PermissionsBoundary':s.comparisonArn};
    expect(allowed(p,'iam:CreateRole',s.roleArn,context)).toBe(true);
    for(const delta of [{'aws:CalledViaLast':undefined},{'aws:CalledViaLast':'lambda.amazonaws.com'},{'iam:PermissionsBoundary':s.originalBoundaryArn},{'iam:PermissionsBoundary':undefined}])expect(allowed(p,'iam:CreateRole',s.roleArn,{...context,...delta})).toBe(false);
    for(const boundary of [s.comparisonArn,s.originalBoundaryArn])expect(allowed(p,'iam:PutRolePermissionsBoundary',s.roleArn,{...context,'iam:PermissionsBoundary':boundary})).toBe(true);
    for(const role of [s.roleArn.replace('runtime-check','prod'),s.roleArn.replace(input.accountId,'9'.repeat(12)),s.roleArn+'other'])expect(allowed(p,'iam:PutRolePermissionsBoundary',role,context)).toBe(false);
    expect(allowed(p,'iam:PassRole',s.roleArn,{'iam:PassedToService':'lambda.amazonaws.com'})).toBe(true);
    expect(allowed(p,'iam:PassRole',s.roleArn,{'iam:PassedToService':'ecs-tasks.amazonaws.com'})).toBe(false);
  });
  it('cannot encrypt outside its exact synthetic key tags/context or inspect logs outside the region',()=>{
    const s=scope(),p=buildGatewayCanaryOperatorPolicies(s).observe,key=s.keyArnPattern.replace('*','a'.repeat(36));
    const context={'aws:ResourceTag/Project':'mem9-on-aws','aws:ResourceTag/Stage':s.stage,'aws:ResourceTag/VerificationId':s.verificationId,'kms:EncryptionContext:aws:lambda:FunctionArn':s.functionArn};
    expect(allowed(p,'kms:Encrypt',key,context)).toBe(true);
    for(const keyName of Object.keys(context))expect(allowed(p,'kms:Encrypt',key,{...context,[keyName]:'different'})).toBe(false);
    expect(allowed(p,'kms:Encrypt',key.replace(input.accountId,'9'.repeat(12)),context)).toBe(false);
    expect(allowed(p,'kms:Decrypt',key,context)).toBe(false);
    expect(allowed(p,'lambda:InvokeFunction',s.functionArn)).toBe(true);
    expect(allowed(p,'lambda:InvokeFunction',s.functionArn.replace('runtime-check','prod'))).toBe(false);
    expect(allowed(p,'logs:DescribeLogGroups','*',{'aws:RequestedRegion':input.applicationRegion})).toBe(true);
    expect(allowed(p,'logs:DescribeLogGroups','*',{'aws:RequestedRegion':'us-west-2'})).toBe(false);
  });
  it('permits creation-time key tagging without existing tags, only with the fixed request tags and CFN chain',()=>{
    const s=scope(),p=buildGatewayCanaryOperatorPolicies(s).provision,key=s.keyArnPattern.replace('*','synthetic-key');
    const context={'aws:CalledViaLast':'cloudformation.amazonaws.com','aws:RequestTag/Project':'mem9-on-aws','aws:RequestTag/Stage':s.stage,'aws:RequestTag/VerificationId':s.verificationId};
    expect(allowed(p,'kms:TagResource',key,context)).toBe(true);
    for(const k of Object.keys(context))expect(allowed(p,'kms:TagResource',key,{...context,[k]:undefined})).toBe(false);
    expect(allowed(p,'kms:TagResource',key.replace(input.accountId,'9'.repeat(12)),context)).toBe(false);
    expect(allowed(p,'kms:TagResource',key.replace(input.applicationRegion,'us-west-2'),context)).toBe(false);
  });
  it('has an acyclic dependency graph and no broad key-policy principal',()=>{
    const t=render().template,edges=new Map(Object.keys(t.Resources).map(k=>[k,new Set()]));
    const refs=(v,out)=>{if(Array.isArray(v))v.forEach(x=>refs(x,out));else if(v&&typeof v==='object'){
      if(v.Ref&&edges.has(v.Ref))out.add(v.Ref);if(v['Fn::GetAtt'])out.add(v['Fn::GetAtt'][0]);Object.values(v).forEach(x=>refs(x,out));
    }};
    for(const [name,r]of Object.entries(t.Resources)){refs(r,edges.get(name));for(const dependency of list(r.DependsOn??[]))edges.get(name).add(dependency);}
    const complete=new Set(),active=new Set();const visit=name=>{expect(active.has(name)).toBe(false);if(complete.has(name))return;active.add(name);for(const dep of edges.get(name))visit(dep);active.delete(name);complete.add(name);};
    for(const name of edges.keys())visit(name);expect(complete.size).toBe(6);
    const key=t.Resources.SyntheticKey.Properties.KeyPolicy;
    expect(key.Statement.map(s=>s.Principal)).toEqual([{AWS:input.ownerRoleArn},{AWS:input.ownerRoleArn},{AWS:{'Fn::GetAtt':['CanaryRole','Arn']}}]);
    expect(JSON.stringify(key)).not.toContain('kms:*');
  });
});
