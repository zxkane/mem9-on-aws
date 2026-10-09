import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseDocument } from 'yaml';

const root = resolve(import.meta.dirname, '..');
const accountId = '123456789012';
const foreignId = '9'.repeat(12);
const context = { partition: 'aws', accountId, applicationRegion: 'ap-northeast-1',
  decisionArtifactBucketName: `mem9-audit-${accountId}`, projectName: 'mem9-on-aws', githubRepo: 'mem9-on-aws' };
const roleName = 'github-actions-mem9-on-aws';
const artifactName = 'decision-artifact-bucket-mem9-on-aws';
const boundaryName = 'workload-permissions-boundary-mem9-on-aws';
const sids = ['DenyProductionDataReleaseMutation', 'DenyAuthorizationArchiveMutation', 'DenyS3AccessPointMutation'];
const dataActions = ['ssm:PutParameter', 'ssm:DeleteParameter', 'ssm:DeleteParameters',
  'ssm:AddTagsToResource', 'ssm:RemoveTagsFromResource', 'ssm:LabelParameterVersion', 'ssm:UnlabelParameterVersion'];
const apActions = ['s3:CreateAccessPoint', 's3:DeleteAccessPoint', 's3:CreateMultiRegionAccessPoint',
  's3:DeleteMultiRegionAccessPoint', 's3:PutAccessPointPolicy', 's3:DeleteAccessPointPolicy',
  's3:PutMultiRegionAccessPointPolicy', 's3:SubmitMultiRegionAccessPointRoutes'];
const list = value => Array.isArray(value) ? value : [value];
const source = readFileSync(join(root, 'infra/cloudformation/github-actions-role.yaml'), 'utf8');
function render(contract = context, legacy = 'false') {
  const doc = parseDocument(source, { uniqueKeys: true, customTags: [
    ...['Ref', 'Sub', 'GetAtt'].map(name => ({ tag: '!' + name, resolve: value => ({ [name]: value }) })),
    ...['If', 'Equals', 'Not'].map(name => ({ tag: '!' + name, collection: 'seq', resolve: value => ({ [name]: value.toJSON() }) })),
  ] });
  expect(doc.errors).toEqual([]);
  const template = doc.toJS();
  const vars = Object.fromEntries(Object.entries(template.Parameters).map(([key, value]) => [key, value.Default]));
  Object.assign(vars, { 'AWS::Partition': contract.partition, 'AWS::AccountId': contract.accountId,
    'AWS::Region': 'us-west-2', 'AWS::URLSuffix': 'amazonaws.com', 'AWS::StackName': roleName,
    ApplicationRegion: contract.applicationRegion, DecisionArtifactBucketName: contract.decisionArtifactBucketName,
    ProjectName: contract.projectName, GitHubRepo: contract.githubRepo, LegacyRoleEnabled: legacy,
    ApplicationVpcArn: `arn:aws:ec2:${contract.applicationRegion}:${accountId}:vpc/vpc-1234567890abcdef0`,
    ApplicationPrivateSubnetArns: ['a', 'b', 'c'].map(c => `arn:aws:ec2:${contract.applicationRegion}:${accountId}:subnet/subnet-${c.repeat(17)}`),
    ProductionHostedZoneArn: `arn:aws:route53:::hostedzone/Z${'X'.repeat(20)}` });
  const visit = value => {
    if (Array.isArray(value)) return value.map(visit);
    if (!value || typeof value !== 'object') return value;
    if ('Ref' in value) { expect(vars[value.Ref], value.Ref).toBeDefined(); return vars[value.Ref]; }
    if ('Sub' in value) return value.Sub.replace(/\$\{([^}]+)\}/gu, (_, key) => {
      expect(vars[key], key).toBeDefined(); return vars[key];
    });
    if ('If' in value) { const [name, yes, no] = value.If; return visit(visit(template.Conditions[name]) ? yes : no); }
    if ('Equals' in value) return visit(value.Equals[0]) === visit(value.Equals[1]);
    if ('Not' in value) return !visit(value.Not[0]);
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, visit(child)]));
  };
  const policies = Object.fromEntries(Object.entries(template.Resources).filter(([, r]) => r.Type === 'AWS::IAM::ManagedPolicy')
    .map(([key, r]) => [key, visit(r.Properties.PolicyDocument)]));
  return { template, policies, vars, statements: Object.values(policies).flatMap(p => p.Statement) };
}
const matches = (pattern, value) => new RegExp('^' + pattern.replace(/[.+?^${}()|[\]\\]/gu, '\\$&').replaceAll('*', '.*') + '$', 'iu').test(value);
const denies = (statements, action, resource) => statements.some(s => s.Effect === 'Deny' && !s.Condition &&
  (s.NotAction ? !list(s.NotAction).some(a => matches(a, action)) : list(s.Action).some(a => matches(a, action))) &&
  list(s.Resource).some(r => matches(r, resource)));
const helper = () => import('./lib/authorization-maintenance-isolation.mjs');

describe('deployment authorization maintenance exclusions', () => {
  it('TC091/092/094: exact unconditional statements and artifact owner protection', async () => {
    const { statements, policies } = render();
    for (const sid of sids) expect(statements.filter(s => s.Sid === sid)).toHaveLength(1);
    const expected = (await helper()).expectedAuthorizationMaintenanceStatements(context);
    expect(expected.map(s => s.Sid).sort()).toEqual([...sids, 'DenyOperatorOwnedStackMutation'].sort());
    expect((await helper()).verifyAuthorizationMaintenanceIsolation(Object.values(policies), context)).toBe(true);
    expect(statements.find(s => s.Sid === sids[0])).toEqual({ Sid: sids[0], Effect: 'Deny', Action: dataActions,
      Resource: `arn:aws:ssm:${context.applicationRegion}:${accountId}:parameter/mem9-on-aws/prod/consolidation-runtime/data-release` });
    expect(statements.find(s => s.Sid === sids[1])).toEqual({ Sid: sids[1], Effect: 'Deny', NotAction: ['s3:Get*', 's3:List*'],
      Resource: [`arn:aws:s3:::${context.decisionArtifactBucketName}`, `arn:aws:s3:::${context.decisionArtifactBucketName}/data-authorizations/*`, 'arn:aws:s3:*:*:accesspoint/*'] });
    expect(statements.find(s => s.Sid === sids[2])).toEqual({ Sid: sids[2], Effect: 'Deny', Action: apActions, Resource: '*' });
  });

  it('TC091/092: synthetic denied writes and unaffected read/preview/lock prefixes', () => {
    const { statements } = render();
    const parameter = `arn:aws:ssm:${context.applicationRegion}:${accountId}:parameter/mem9-on-aws/prod/consolidation-runtime/data-release`;
    for (const action of dataActions) {
      expect(denies(statements, action, parameter), action).toBe(true);
      expect(denies(statements, action, parameter.replace('/prod/', '/pr-123/'))).toBe(false);
    }
    expect(denies(statements, 'ssm:GetParameter', parameter)).toBe(false);
    const bucket = `arn:aws:s3:::${context.decisionArtifactBucketName}`;
    const archive = `${bucket}/data-authorizations/example.json`;
    for (const action of ['s3:PutObject', 's3:DeleteObject', 's3:DeleteObjectVersion', 's3:PutObjectAcl',
      's3:PutObjectVersionAcl', 's3:PutObjectTagging', 's3:DeleteObjectTagging', 's3:ReplicateObject', 's3:ReplicateDelete', 's3:RestoreObject']) {
      expect(denies(statements, action, archive), action).toBe(true);
      for (const prefix of ['decisions', 'digests', 'deployment-locks', 'publication-locks'])
        expect(denies(statements, action, `${bucket}/${prefix}/example.json`)).toBe(false);
    }
    for (const action of ['s3:PutBucketPolicy', 's3:DeleteBucketPolicy', 's3:PutLifecycleConfiguration', 's3:PutBucketVersioning', 's3:DeleteBucket'])
      expect(denies(statements, action, bucket), action).toBe(true);
    for (const resource of [bucket, archive, 'arn:aws:s3:us-west-2:123456789012:accesspoint/example/object/key',
      'arn:aws:s3::123456789012:accesspoint/example.mrap/object/key', `arn:aws:s3:us-west-2:${foreignId}:accesspoint/example/object/key`]) {
      expect(denies(statements, 's3:GetObject', resource)).toBe(false);
      expect(denies(statements, 's3:ListBucket', resource)).toBe(false);
      expect(denies(statements, 's3:PutObject', resource)).toBe(true);
    }
    for (const action of apActions) expect(denies(statements, action, '*')).toBe(true);
  });

  it('all three deploy roles retain identities, attachments and outputs even with disabled legacy trust', () => {
    const { template, policies } = render();
    for (const [role, suffix, output] of [['GitHubPreviewActionsRole', '-preview', 'PreviewRoleArn'],
      ['GitHubProductionActionsRole', '-prod', 'ProductionRoleArn'], ['GitHubActionsRole', '', 'LegacyRoleArn']]) {
      const resource = template.Resources[role];
      expect(resource.Condition).toBeUndefined();
      expect(resource.Properties.RoleName).toEqual({ Sub: `github-actions-\${GitHubRepo}${suffix}` });
      const attached = resource.Properties.ManagedPolicyArns.map(p => p.Ref).flatMap(p => policies[p].Statement);
      for (const sid of sids) expect(attached.filter(s => s.Sid === sid)).toHaveLength(1);
      expect(template.Outputs[output].Value).toEqual({ GetAtt: `${role}.Arn` });
    }
    expect(template.Outputs.RoleArn.Value).toEqual(template.Outputs.LegacyRoleArn.Value);
  });

  it.each(['abc', 'example-artifact', 'a'.repeat(33)])('TC095/096: bucket %s and full rendered managed-policy quota', name => {
    const { template, policies } = render({ ...context, decisionArtifactBucketName: name });
    expect(template.Parameters.DecisionArtifactBucketName).toMatchObject({ Type: 'String', MinLength: 3, MaxLength: 33 });
    expect(template.Parameters.DecisionArtifactBucketName.Default).toBeUndefined();
    for (const [logicalId, policy] of Object.entries(policies)) expect(JSON.stringify(policy).length, logicalId).toBeLessThanOrEqual(6144);
  });

  it('preserves the prior template apart from approved isolation additions', () => {
    const { template } = render();
    for (const [logical, role] of [['LegacyRetainedOperatorProtection','GitHubActionsRole'],
      ['PreviewRetainedOperatorProtection','GitHubPreviewActionsRole'],['ProductionRetainedOperatorProtection','GitHubProductionActionsRole']]) {
      expect(template.Resources[logical]).toMatchObject({Type:'AWS::IAM::Policy',Properties:{Roles:[{Ref:role}]}});
      delete template.Resources[logical];
    }
    delete template.Parameters.DecisionArtifactBucketName;
    const statements = template.Resources.DenyPolicy.Properties.PolicyDocument.Statement;
    template.Resources.DenyPolicy.Properties.PolicyDocument.Statement = statements.filter(s => !sids.includes(s.Sid));
    const owner = statements.find(s => s.Sid === 'DenyOperatorOwnedStackMutation');
    expect(owner.Resource.pop()).toEqual({ Sub: 'arn:${AWS::Partition}:cloudformation:*:${AWS::AccountId}:stack/decision-artifact-bucket-${ProjectName}/*' });
    // Reviewed Gateway/endpoint delta, with all trusts and unrelated statements
    // included. Reverse only that explicit delta to retain the original proof.
    expect(createHash('sha256').update(JSON.stringify(template)).digest('hex'))
      .toBe('e8431ed654f49a5971baefb61456bc016583f01a511d00cd903723d93f9eb354');
    const deny = template.Resources.DenyPolicy.Properties.PolicyDocument.Statement;
    const scaffold = template.Resources.ScaffoldPolicy.Properties.PolicyDocument.Statement;
    const accountDeny = scaffold.find(s => s.Sid === 'DenyAccountLevel');
    deny.splice(deny.findIndex(s => s.Sid === 'DenyIAMUserAndProvider') + 1, 0, accountDeny);
    const added = ['DenyAccountLevel','GatewaySecretEndpointRead','GatewaySecretEndpointNetwork',
      'GatewaySecretEndpointCreate','GatewaySecretEndpointLifecycle','DenyGatewayBoundaryOnOtherRoles','DenyGatewayRolesWrongBoundary'];
    template.Resources.ScaffoldPolicy.Properties.PolicyDocument.Statement = scaffold.filter(s => !added.includes(s.Sid));
    const oldArn={Sub:'arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/${ProjectName}-workload-boundary'};
    const gatewayArn={Sub:'arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/${ProjectName}-gateway-boundary'};
    for(const [policy,sid,key] of [
      ['DenyPolicy','DenyOperatorOwnedIamMutation','Resource'],
      ['ComputePolicy','WorkloadBoundaryRead','Resource'],
      ['DenyPolicy','DenyUnboundedProjectRoleCreation','ArnNotEquals'],
      ['DenyPolicy','DenyUnboundedProjectRolePolicyWrites','ArnNotEquals'],
      ['ComputePolicy','EcsTaskRoleCreateWithBoundary','ArnEquals'],
      ['ComputePolicy','EcsTaskRolePolicyWritesWithBoundary','ArnEquals'],
    ]) {
      const statement=template.Resources[policy].Properties.PolicyDocument.Statement.find(s=>s.Sid===sid);
      const target=key==='Resource'?statement:statement.Condition[key];
      const field=key==='Resource'?'Resource':'iam:PermissionsBoundary';
      expect(target[field]).toEqual([oldArn,gatewayArn]);target[field]=oldArn;
    }
    expect(createHash('sha256').update(JSON.stringify(template)).digest('hex'))
      .toBe('7b95c6db189cbcc2f300cd16e4bf632e5ffae5eb8677665a6eab370c02a93aa1');
  });

  it('deployment preflight measures every full policy with the actual parameters', async () => {
    const { verifyAuthorizationDeploymentTemplate: verify } = await helper();
    const { policies, vars } = render({ ...context, decisionArtifactBucketName: 'a'.repeat(33) });
    const measured = await verify(source, vars);
    expect(measured).toEqual(Object.fromEntries(Object.entries(policies).map(([key, policy]) => [key, JSON.stringify(policy).length])));
    expect(measured.DenyPolicy).toBe(6053);
    await expect(verify(source.replace('DenyIAMUserAndProvider', 'a'.repeat(6500)), vars)).rejects.toThrow(/quota/u);
    await expect(verify(source.replace('!Sub arn:', '!Unsupported arn:'), vars)).rejects.toThrow(/invalid deployment template/u);
    await expect(verify(source, { ...vars, DecisionArtifactBucketName: 'a'.repeat(34) })).rejects.toThrow(/bucket name/u);
  });

  it('strict required-statement comparison accepts only set/order/scalar equivalence', async () => {
    const { expectedAuthorizationMaintenanceStatements: build, verifyAuthorizationMaintenanceIsolation: verify } = await helper();
    const expected = build(context);
    const policy = { Version: '2012-10-17', Statement: expected };
    expect(verify([policy], context)).toBe(true);
    const reordered = structuredClone(policy);
    reordered.Statement.reverse();
    for (const s of reordered.Statement) for (const key of ['Action', 'NotAction', 'Resource'])
      if (key in s) s[key] = list(s[key]).reverse();
    expect(verify([reordered], context)).toBe(true);
    for (const mutate of [p => p.Statement.pop(), p => p.Statement.push(structuredClone(p.Statement[0])),
      p => p.Statement[0].Action.push(p.Statement[0].Action[0]), p => p.Statement[0].Condition = {},
      p => p.Statement[0].Resource += '*', p => p.Statement[0].Effect = 'Allow',
      p => p.Statement[0].Principal = '*', p => p.Statement[1].NotAction.push('s3:Put*'),
      p => p.Statement[3].Resource.pop()]) {
      const changed = structuredClone(policy); mutate(changed);
      expect(() => verify([changed], context)).toThrow();
    }
  });
});

function stack(name, region, parameters) {
  return { StackName: name, StackId: `arn:aws:cloudformation:${region}:${accountId}:stack/${name}/example-id`,
    StackStatus: 'UPDATE_COMPLETE', Parameters: Object.entries(parameters).map(([ParameterKey, ParameterValue]) => ({ ParameterKey, ParameterValue })) };
}
function fixture() {
  return { account: { Account: accountId, Arn: `arn:aws:sts::${accountId}:assumed-role/operator/example`, UserId: 'example' },
    stacks: {
      [roleName]: stack(roleName, 'us-west-2', { ApplicationRegion: context.applicationRegion, LegacyRoleEnabled: 'false' }),
      [artifactName]: stack(artifactName, context.applicationRegion, { DecisionArtifactBucketName: context.decisionArtifactBucketName }),
      [boundaryName]: stack(boundaryName, 'us-west-2', { ApplicationRegion: context.applicationRegion, DecisionArtifactBucketName: context.decisionArtifactBucketName }),
    }, bucket: context.decisionArtifactBucketName };
}
function runBootstrap({ data = fixture(), args = [], bucket } = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'authorization-deploy-test-'));
  try {
    writeFileSync(join(directory, 'fixture.json'), JSON.stringify(data));
    writeFileSync(join(directory, 'aws'), `#!${process.execPath}
import {readFileSync,appendFileSync} from 'node:fs';
const args=process.argv.slice(2), d=JSON.parse(readFileSync(process.env.ISOLATION_FIXTURE,'utf8'));
appendFileSync(process.env.ISOLATION_LOG,JSON.stringify(args)+'\\n');
const calls=readFileSync(process.env.ISOLATION_LOG,'utf8').trim().split('\\n').map(JSON.parse);
const phase=calls.filter(c=>c[0]==='sts').length;
if(d.drift && phase >= (d.drift==='before-upload'?2:3)) d.stacks['${boundaryName}'].Parameters.find(p=>p.ParameterKey==='DecisionArtifactBucketName').ParameterValue='changed-bucket';
const arg=k=>args[args.indexOf(k)+1], op=args.slice(0,2).join(' ');
const send=x=>console.log(typeof x==='string'?x:JSON.stringify(x));
if(op==='sts get-caller-identity') send(d.rawIdentityOutput??(args.includes('--query')?d.account[arg('--query')]:d.account));
else if(op==='cloudformation describe-stacks') {
 const name=arg('--stack-name');
 if(args.includes('--query') && arg('--query').includes('Outputs')){send('arn:aws:iam::123456789012:role/example');process.exit(0);}
 if(d.errors?.[name]){console.error(d.errors[name]);process.exit(1);}
 if(!d.stacks[name]){console.error('An error occurred (ValidationError) when calling the DescribeStacks operation: Stack with id '+name+' does not exist');process.exit(254);}
 const s=d.stacks[name];
 if(args.includes('--query')){
  const q=arg('--query');
  if(q.includes('Outputs'))send('arn:aws:iam::123456789012:role/example');
  else {const key=q.match(/ParameterKey=='([^']+)'/)[1];send(s.Parameters.find(p=>p.ParameterKey===key)?.ParameterValue??'None');}
 }else send(d.malformed?{}:{Stacks:[s]});
}else if(op==='cloudformation describe-stack-resource') send({StackResourceDetail:{StackId:d.stacks['${artifactName}']?.StackId,LogicalResourceId:'DecisionArtifactBucket',ResourceType:'AWS::S3::Bucket',PhysicalResourceId:d.bucket,ResourceStatus:'CREATE_COMPLETE',...d.resourceOverrides}});
else if(op==='cloudformation describe-stack-resources') send({StackResources:[{StackId:d.stacks['${artifactName}']?.StackId,LogicalResourceId:'DecisionArtifactBucket',ResourceType:'AWS::S3::Bucket',PhysicalResourceId:d.bucket,ResourceStatus:'CREATE_COMPLETE'}]});
else if(op==='iam list-open-id-connect-providers') send('arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com');
else if(op==='ec2 describe-vpcs') send('vpc-1234567890abcdef0');
else if(op==='ec2 describe-subnets') send(d.subnets??'subnet-1234567890abcdef0');
else if(op==='servicediscovery list-namespaces') send([]);
else if(op==='s3api get-bucket-location') send('us-west-2');
else if(['s3 cp','cloudformation create-stack','cloudformation update-stack','cloudformation wait'].includes(op)) send({});
else {console.error('Unexpected synthetic AWS call '+args.join(' '));process.exit(1);}
`, { mode: 0o755 });
    const env = { ...process.env, PATH: directory + ':' + process.env.PATH, WORKLOAD_BOUNDARY_SKIP_DOTENV: 'true',
      STACK_NAME: roleName, MEM9_TEMPLATE_BUCKET: 'example-template-bucket', MEM9_VPC_ID: '',
      ISOLATION_FIXTURE: join(directory, 'fixture.json'), ISOLATION_LOG: join(directory, 'calls.jsonl') };
    delete env.MEM9_DECISION_ARTIFACT_BUCKET;
    if (bucket !== undefined) env.MEM9_DECISION_ARTIFACT_BUCKET = bucket;
    const result = spawnSync('bash', ['scripts/deploy-github-role.sh', ...args], { cwd: root, env, encoding: 'utf8', timeout: 30000 });
    let calls = [];
    try { calls = readFileSync(env.ISOLATION_LOG, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse); } catch {}
    return { ...result, calls, writes: calls.filter(c => ['s3 cp', 'cloudformation create-stack', 'cloudformation update-stack'].includes(c.slice(0, 2).join(' '))) };
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

describe('deployment bootstrap identity checks before mutation', () => {
  it.each(['provider stderr', 'malformed provider JSON'])('withholds untrusted CLI diagnostics from %s', scenario => {
    const data = fixture();
    const marker = 'synthetic-private-diagnostic';
    if (scenario === 'provider stderr') data.errors = { [roleName]: `AccessDenied: ${marker}` };
    else data.rawIdentityOutput = `${marker} is not JSON`;
    const result = runBootstrap({ data });
    expect(result.status).not.toBe(0);
    expect(result.writes).toEqual([]);
    expect(result.stderr).toBe('Authorization isolation check failed; details withheld.\n');
    expect(result.stdout + result.stderr).not.toContain(marker);
  });
  it.each(['UPPER', 'a'.repeat(34), 'a'.repeat(63), 'ab', 'abc-s3alias', 'xn--example', 'with.dot'])('rejects invalid override %s before any AWS command', bucket => {
    const result = runBootstrap({ bucket });
    expect(result.status).not.toBe(0); expect(result.calls).toEqual([]);
  });
  it.each(['role bucket', 'artifact parameter', 'artifact physical', 'boundary bucket', 'boundary region', 'role region', 'stack account',
    'access denied', 'network', 'malformed', 'wrong absence', 'duplicate parameter', 'caller mismatch', 'missing region',
    'wrong project', 'resource stack', 'resource type', 'resource status', 'artifact unreadable'])('rejects %s without upload or update', scenario => {
    const data = fixture();
    const add = (name, key, value) => { const p = data.stacks[name].Parameters.find(p => p.ParameterKey === key);
      if (p) p.ParameterValue = value; else data.stacks[name].Parameters.push({ ParameterKey: key, ParameterValue: value }); };
    if (scenario === 'role bucket') add(roleName, 'DecisionArtifactBucketName', 'wrong-bucket');
    if (scenario === 'artifact parameter') add(artifactName, 'DecisionArtifactBucketName', 'wrong-bucket');
    if (scenario === 'artifact physical') data.bucket = 'wrong-bucket';
    if (scenario === 'boundary bucket') add(boundaryName, 'DecisionArtifactBucketName', 'wrong-bucket');
    if (scenario === 'boundary region') add(boundaryName, 'ApplicationRegion', 'us-east-1');
    if (scenario === 'role region') add(roleName, 'ApplicationRegion', 'us-east-1');
    if (scenario === 'stack account') data.stacks[artifactName].StackId = data.stacks[artifactName].StackId.replace(accountId, foreignId);
    if (scenario === 'access denied') data.errors = { [roleName]: 'AccessDenied: not authorized' };
    if (scenario === 'network') data.errors = { [boundaryName]: 'Connection timed out' };
    if (scenario === 'malformed') data.malformed = true;
    if (scenario === 'wrong absence') data.errors = { [roleName]: 'An error occurred (ValidationError) when calling the DescribeStacks operation: Stack with id unrelated does not exist' };
    if (scenario === 'duplicate parameter') data.stacks[artifactName].Parameters.push(data.stacks[artifactName].Parameters[0]);
    if (scenario === 'caller mismatch') data.account.Account = foreignId;
    if (scenario === 'missing region') data.stacks[roleName].Parameters = data.stacks[roleName].Parameters.filter(p => p.ParameterKey !== 'ApplicationRegion');
    if (scenario === 'wrong project') add(roleName, 'ProjectName', 'another-project');
    if (scenario === 'resource stack') data.resourceOverrides = { StackId: data.stacks[boundaryName].StackId };
    if (scenario === 'resource type') data.resourceOverrides = { ResourceType: 'AWS::S3::BucketPolicy' };
    if (scenario === 'resource status') data.resourceOverrides = { ResourceStatus: 'DELETE_IN_PROGRESS' };
    if (scenario === 'artifact unreadable') data.errors = { [artifactName]: 'AccessDenied: not authorized' };
    const result = runBootstrap({ data });
    expect(result.status, result.stderr).not.toBe(0); expect(result.writes, result.stdout).toEqual([]);
  });
  it('upgrades the old role parameter set only after matching owner/boundary readback and preserves false legacy trust', () => {
    const result = runBootstrap();
    expect(result.status, result.stderr).toBe(0);
    const update = result.calls.find(c => c[1] === 'update-stack');
    const params = JSON.parse(update[update.indexOf('--parameters') + 1]);
    expect(params).toContainEqual({ ParameterKey: 'DecisionArtifactBucketName', ParameterValue: context.decisionArtifactBucketName });
    expect(params).toContainEqual({ ParameterKey: 'LegacyRoleEnabled', ParameterValue: 'false' });
    const upload = result.calls.findIndex(c => c[0] === 's3' && c[1] === 'cp');
    for (const name of [roleName, artifactName, boundaryName])
      expect(result.calls.slice(0, upload).some(c => c[1] === 'describe-stacks' && c.includes(name))).toBe(true);
  });
  it('supports authenticated fresh absence but refuses an explicit mode inconsistent with existence', () => {
    const data = fixture(); data.stacks = {};
    const fresh = runBootstrap({ data });
    expect(fresh.status, fresh.stderr).toBe(0);
    expect(fresh.calls.filter(c => c[1] === 'create-stack')).toHaveLength(1);
    for (const options of [{ data, args: ['--update'] }, { args: ['--create'] }, { args: ['--create', '--update'] }]) {
      const result = runBootstrap(options); expect(result.status).not.toBe(0); expect(result.writes).toEqual([]);
    }
  });

  it('threads a matching custom bucket into the exact template parameter', () => {
    const data = fixture(); const bucket = 'example-custom-artifact'; data.bucket = bucket;
    for (const name of [artifactName, boundaryName])
      data.stacks[name].Parameters.find(p => p.ParameterKey === 'DecisionArtifactBucketName').ParameterValue = bucket;
    const result = runBootstrap({ data, bucket });
    expect(result.status, result.stderr).toBe(0);
    const update = result.calls.find(c => c[1] === 'update-stack');
    expect(JSON.parse(update[update.indexOf('--parameters') + 1]))
      .toContainEqual({ ParameterKey: 'DecisionArtifactBucketName', ParameterValue: bucket });
  });

  it.each(['before-upload', 'before-update'])('rechecks binding drift %s at the mutation boundary', drift => {
    const data = fixture(); data.drift = drift;
    const result = runBootstrap({ data });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('boundary bucket binding mismatch');
    expect(result.writes.map(c => c.slice(0, 2).join(' '))).toEqual(drift === 'before-upload' ? [] : ['s3 cp']);
  });

  it('rejects an oversized full rendered policy before uploading', () => {
    const data = fixture();
    data.subnets = Array.from({ length: 100 }, (_, i) => `subnet-${i.toString(16).padStart(17, '0')}`).join(' ');
    const result = runBootstrap({ data });
    expect(result.status).not.toBe(0); expect(result.stderr).toContain('quota'); expect(result.writes).toEqual([]);
  });
});
