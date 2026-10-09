import { describe, expect, it } from 'vitest';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { stringify } from 'yaml';
import { createRetainedOperatorFixture as fixture } from './test-fixtures/retained-operator.mjs';
import { expectedRolePatterns, matchingRoleNames } from './lib/workload-permissions-boundary.mjs';
const accountId = '123456789012';
const identity = { partition: 'aws', accountId };
const applicationRegion = 'ap-northeast-1';
const otherRegion = 'us-east-1';
const namespaceStack = 'memory-namespace-operator-mem9-on-aws';
const deploymentStack = 'github-actions-mem9-on-aws';
const namespaceRole = 'mem9-on-aws-namespace-operator';
const humanRole = 'mem9-on-aws-preview-human-acceptance';
const retained = [namespaceRole, humanRole].sort();
const indirectTypes = ['AWS::CloudFormation::Stack', 'AWS::CloudFormation::StackSet', 'Custom::RoleInstaller', 'AWS::Lambda::Function'];
async function create(f) {
  const module = await import('./lib/retained-operator-inventory.mjs');
  return { ...module, inventory: module.createRetainedOperatorInventory({ invokeAws: f.invokeAws, identity, applicationRegion }) };
}

describe('retained operator ownership inventory', () => {
  it('accepts a completed deployment-stack rollback as input and preserves ownership across the next update', async () => {
    const f = fixture(); const { inventory } = await create(f);
    f.stacks[deploymentStack].StackStatus = 'UPDATE_ROLLBACK_COMPLETE';
    expect(await inventory.verify()).toEqual(retained);
    await expect(inventory.verifyDeploymentRoleCatalog()).resolves.toBeUndefined();
    f.stacks[deploymentStack].StackStatus = 'UPDATE_COMPLETE';
    expect(await inventory.verify()).toEqual(retained);
    await expect(inventory.verifyDeploymentRoleCatalog()).resolves.toBeUndefined();
    f.roles[humanRole].RoleId += 'REPLACED';
    await expect(inventory.verify()).rejects.toThrow();
  });

  it.each(['UPDATE_ROLLBACK_FAILED', 'UPDATE_ROLLBACK_IN_PROGRESS', 'UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS', 'UPDATE_IN_PROGRESS', 'UPDATE_FAILED', 'ROLLBACK_COMPLETE'])('refuses deployment-stack %s as recovery input', async status => {
    const f = fixture(); const { inventory } = await create(f);
    f.stacks[deploymentStack].StackStatus = status;
    await expect(inventory.verify()).rejects.toThrow();
    await expect(inventory.verifyDeploymentRoleCatalog()).rejects.toThrow();
  });

  it('does not extend completed-rollback input acceptance to the namespace owner', async () => {
    const f = fixture(); const { inventory } = await create(f);
    f.stacks[namespaceStack].StackStatus = 'UPDATE_ROLLBACK_COMPLETE';
    await expect(inventory.verify()).rejects.toThrow();
  });

  it('still rejects altered retained policy in a completed deployment-stack rollback', async () => {
    const f = fixture(); const { inventory } = await create(f);
    f.stacks[deploymentStack].StackStatus = 'UPDATE_ROLLBACK_COMPLETE';
    const policy = Object.values(f.inline[humanRole])[0];
    policy.Statement[0].Resource = '*';
    await expect(inventory.verify()).rejects.toThrow();
  });

  it('rejects unknown configuration fields before invoking a provider', async () => {
    const f = fixture(); const { createRetainedOperatorInventory } = await create(f);
    for (const extra of [{ roleNames: retained }, { sourceTemplates: {} }])
      expect(() => createRetainedOperatorInventory({ invokeAws: f.invokeAws, identity, applicationRegion, ...extra })).toThrow();
    expect(f.calls).toEqual([]);
  });

  it.each(['', `${applicationRegion}_Example`])('verifies exact owners and conditional namespace policy for pool %s', async pool => {
    const f = fixture({ pool, paginate: true }); const { inventory, RETAINED_OPERATOR_ROLE_NAMES } = await create(f);
    expect(RETAINED_OPERATOR_ROLE_NAMES).toEqual(retained); expect(Object.isFrozen(RETAINED_OPERATOR_ROLE_NAMES)).toBe(true);
    expect(await inventory.verify()).toEqual(retained);
    expect(await inventory.verify()).toEqual(retained);
    await expect(inventory.verifyDeploymentRoleCatalog()).resolves.toBeUndefined();
    expect(f.calls.some(a => a.includes('--next-token'))).toBe(true);
  });

  it.each([namespaceStack, deploymentStack])('accepts a flow-style YAML owner template from %s', async stack => {
    const f = fixture(); const { inventory } = await create(f);
    const raw = stringify(f.templates[stack], { collectionStyle: 'flow', lineWidth: 0 });
    expect(raw.trimStart().startsWith('{')).toBe(true);
    expect(() => JSON.parse(raw)).toThrow();
    f.state.rawTemplate[stack] = raw;
    expect(await inventory.verify()).toEqual(retained);
    expect(await inventory.verify()).toEqual(retained);
    await expect(inventory.verifyDeploymentRoleCatalog()).resolves.toBeUndefined();
  });

  it.each(['duplicate key', 'changed role'])('rejects an invalid flow-style YAML owner template: %s', async scenario => {
    const f = fixture(); const { inventory } = await create(f);
    if (scenario === 'changed role') f.templates[namespaceStack].Resources.MemoryNamespaceOperatorRole.Properties.RoleName = humanRole;
    let raw = stringify(f.templates[namespaceStack], { collectionStyle: 'flow', lineWidth: 0 });
    if (scenario === 'duplicate key') {
      expect(raw).toContain('Resources:'); raw = raw.replace('Resources:', 'Resources: {}, Resources:');
    }
    f.state.rawTemplate[namespaceStack] = raw;
    await expect(inventory.verify()).rejects.toThrow();
    expect(() => inventory.filterRoles(Object.values(f.roles))).toThrow();
  });

  it.each(['owner account', 'owner region', 'owner status', 'nested owner', 'service role', 'stage', 'pool region', 'duplicate parameter',
    'resource type', 'resource name', 'resource missing', 'resource duplicate', 'template role', 'template condition', 'boundary', 'empty boundary',
    'managed attachment', 'extra inline', 'missing inline', 'extra role field', 'trust', 'policy', 'duplicate actions', 'encoded duplicate JSON'])('rejects %s before exemption', async scenario => {
    const f = fixture(); const { inventory } = await create(f);
    const owner = f.stacks[namespaceStack], role = f.roles[namespaceRole], policy = f.inline[namespaceRole]['mem9-memory-namespace-operator'];
    if (scenario === 'owner account') owner.StackId = owner.StackId.replace(accountId, '9'.repeat(12));
    if (scenario === 'owner region') owner.Parameters[0].ParameterValue = 'us-east-1';
    if (scenario === 'owner status') owner.StackStatus = 'UPDATE_IN_PROGRESS';
    if (scenario === 'nested owner') owner.ParentId = 'parent';
    if (scenario === 'service role') owner.RoleARN = `arn:aws:iam::${accountId}:role/service`;
    if (scenario === 'stage') owner.Parameters.find(p => p.ParameterKey === 'Stage').ParameterValue = 'pr-1';
    if (scenario === 'pool region') owner.Parameters.find(p => p.ParameterKey === 'CognitoUserPoolId').ParameterValue = `${otherRegion}_Example`;
    if (scenario === 'duplicate parameter') owner.Parameters.push(owner.Parameters[0]);
    if (scenario === 'resource type') f.resources[namespaceStack][0].ResourceType = 'AWS::IAM::User';
    if (scenario === 'resource name') f.resources[namespaceStack][0].PhysicalResourceId = humanRole;
    if (scenario === 'resource missing') f.resources[namespaceStack] = f.state.resources[namespaceStack] = [];
    if (scenario === 'resource duplicate') f.resources[namespaceStack].push(f.resources[namespaceStack][0]);
    if (scenario === 'template role') f.templates[namespaceStack].Resources.MemoryNamespaceOperatorRole.Properties.RoleName = humanRole;
    if (scenario === 'template condition') f.templates[namespaceStack].Conditions.HasManagedPool = { 'Fn::Equals': ['same', 'same'] };
    if (scenario === 'boundary') role.PermissionsBoundary = { PermissionsBoundaryArn: `arn:aws:iam::${accountId}:policy/boundary`, PermissionsBoundaryType: 'Policy' };
    if (scenario === 'empty boundary') role.PermissionsBoundary = null;
    if (scenario === 'managed attachment') f.managed[namespaceRole].push({ PolicyName: 'extra', PolicyArn: `arn:aws:iam::${accountId}:policy/extra` });
    if (scenario === 'extra inline') f.inline[namespaceRole].extra = policy;
    if (scenario === 'missing inline') delete f.inline[namespaceRole]['mem9-memory-namespace-operator'];
    if (scenario === 'extra role field') role.Unknown = true;
    if (scenario === 'trust') role.AssumeRolePolicyDocument = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: '*' }] };
    if (scenario === 'policy') policy.Statement[0].Resource = '*';
    if (scenario === 'duplicate actions') policy.Statement[0].Action = ['ssm:GetParameters', 'ssm:GetParameters'];
    if (scenario === 'encoded duplicate JSON') role.AssumeRolePolicyDocument = encodeURIComponent('{"Version":"2012-10-17","Version":"2012-10-17","Statement":[]}');
    await expect(inventory.verify()).rejects.toThrow();
    expect(() => inventory.filterRoles(Object.values(f.roles))).toThrow();
  });

  it('freezes RoleId, policy, parameters and exact absence; rejects restored-name recreation', async () => {
    const f = fixture(); const { inventory } = await create(f); await inventory.verify();
    f.roles[namespaceRole].RoleId = 'AROA' + '9'.repeat(17);
    await expect(inventory.verify()).rejects.toThrow();
    expect(() => inventory.filterRoles([f.roles[namespaceRole]])).toThrow();
  });

  it('does not adopt a different otherwise valid managed-pool binding after freezing', async () => {
    const f = fixture(); const { inventory } = await create(f); await inventory.verify();
    const changed = fixture({ pool: `${applicationRegion}_Replacement` });
    f.stacks[namespaceStack].Parameters = changed.stacks[namespaceStack].Parameters;
    f.inline[namespaceRole] = changed.inline[namespaceRole];
    await expect(inventory.verify()).rejects.toThrow();
  });

  it.each(['template', 'policy'])('rejects duplicate decoded JSON members in a %s', async kind => {
    const f = fixture(); const { inventory } = await create(f);
    if (kind === 'template') f.state.rawTemplate[namespaceStack] = JSON.stringify(f.templates[namespaceStack])
      .replace('"Resources":', '"Resources":{},"Resour\\u0063es":');
    else f.inline[namespaceRole]['mem9-memory-namespace-operator'] =
      '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ssm:GetParameters","Resource":"*","Resour\\u0063e":"*"}]}';
    await expect(inventory.verify()).rejects.toThrow();
  });

  const sourceCases = [{ scenario: 'extra local role', stack: deploymentStack }, { scenario: 'changed pinned bytes', stack: deploymentStack },
    ...indirectTypes.flatMap(scenario => [namespaceStack, deploymentStack].map(stack => ({ scenario, stack })))];
  it.each(sourceCases)('uses pinned import-relative source: $scenario in $stack', async ({ scenario, stack }) => {
    const root = resolve(import.meta.dirname, '..'), directory = mkdtempSync(join(tmpdir(), 'retained-source-test-'));
    try {
      mkdirSync(join(directory, 'scripts/lib'), { recursive: true });
      mkdirSync(join(directory, 'infra/cloudformation'), { recursive: true });
      symlinkSync(join(root, 'node_modules'), join(directory, 'node_modules'), 'dir');
      for (const name of ['retained-operator-inventory.mjs', 'authorization-archive-policy.mjs'])
        copyFileSync(join(root, 'scripts/lib', name), join(directory, 'scripts/lib', name));
      for (const name of ['memory-namespace-operator-role.yaml', 'github-actions-role.yaml'])
        copyFileSync(join(root, 'infra/cloudformation', name), join(directory, 'infra/cloudformation', name));
      const target = join(directory, 'infra/cloudformation', stack === namespaceStack ? 'memory-namespace-operator-role.yaml' : 'github-actions-role.yaml');
      const f = fixture();
      if (scenario !== 'changed pinned bytes') {
        const source = structuredClone(f.templates[stack]);
        source.Resources.Extra = scenario === 'extra local role' ? structuredClone(source.Resources.GitHubActionsRole) : { Type: scenario, Properties: {} };
        writeFileSync(target, JSON.stringify(source));
      }
      const { createRetainedOperatorInventory } = await import(pathToFileURL(join(directory, 'scripts/lib/retained-operator-inventory.mjs')).href);
      const build = () => createRetainedOperatorInventory({ invokeAws: f.invokeAws, identity, applicationRegion });
      if (scenario !== 'changed pinned bytes') { expect(build).toThrow(); expect(f.calls).toEqual([]); }
      else {
        const inventory = build(); await inventory.verify();
        writeFileSync(target, readFileSync(target, 'utf8') + '\n# changed during attempt\n');
        await expect(inventory.verify()).rejects.toThrow();
        expect(() => inventory.filterRoles([])).toThrow();
      }
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });

  it.each(['operators', 'catalog'])('rejects owner changes during the %s read', async kind => {
    const f = fixture(); const { inventory } = await create(f);
    f.state.mutate = args => {
      if (args[0] !== 'iam' || args[1] !== 'get-role') return;
      const stack = kind === 'operators' ? namespaceStack : deploymentStack;
      f.stacks[stack].StackStatus = 'UPDATE_IN_PROGRESS';
    };
    await expect(kind === 'operators' ? inventory.verify() : inventory.verifyDeploymentRoleCatalog()).rejects.toThrow();
  });

  it('filters only exact authenticated names and validates every raw page member', async () => {
    const f = fixture(); const { inventory } = await create(f);
    expect(() => inventory.filterRoles([])).toThrow(); await inventory.verify();
    const ordinary = { ...f.roles[namespaceRole], RoleName: 'mem9-on-aws-prod-workload', Arn: `arn:aws:iam::${accountId}:role/mem9-on-aws-prod-workload`, RoleId: 'AROA' + '8'.repeat(17) };
    expect(inventory.filterRoles([ordinary, f.roles[humanRole], f.roles[namespaceRole]]).map(r => r.RoleName)).toEqual([ordinary.RoleName]);
    for (const page of [[ordinary, null], [ordinary, ordinary], [{ ...f.roles[humanRole], Arn: ordinary.Arn }], [{ ...ordinary, Arn: ordinary.Arn.replace(accountId, '9'.repeat(12)) }]])
      expect(() => inventory.filterRoles(page)).toThrow();
  });

  it.each(['Id', 'legacy version', 'implicit version', 'scalar statement'])('preserves unrelated valid IAM trust with %s', async form => {
    const f = fixture(); const { inventory } = await create(f); await inventory.verify();
    const ordinary = { ...f.roles[namespaceRole], RoleName: 'other-service', Arn: `arn:aws:iam::${accountId}:role/other-service`, RoleId: 'AROA' + '6'.repeat(17) };
    const trust = JSON.parse(decodeURIComponent(ordinary.AssumeRolePolicyDocument));
    if (form === 'Id') trust.Id = 'unrelated-trust';
    if (form === 'legacy version') trust.Version = '2008-10-17';
    if (form === 'implicit version') delete trust.Version;
    if (form === 'scalar statement') trust.Statement = trust.Statement[0];
    ordinary.AssumeRolePolicyDocument = encodeURIComponent(JSON.stringify(trust));
    expect(inventory.filterRoles([ordinary])).toEqual([ordinary]);
  });

  it.each(['object', 'JSON', 'encoded JSON'])('preserves unrelated duplicate Sids, empty conditions and extensions: %s', async encoding => {
    const f = fixture(); const { inventory } = await create(f); await inventory.verify();
    const statement = { Sid: 'Repeated', Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { AWS: `arn:aws:iam::${accountId}:root` }, Condition: {} };
    const trust = { Version: '2012-10-17', Statement: [statement, structuredClone(statement)], Extension: { evidence: 'opaque' } };
    const value = encoding === 'object' ? trust : encoding === 'JSON' ? JSON.stringify(trust) : encodeURIComponent(JSON.stringify(trust));
    const ordinary = { ...f.roles[namespaceRole], RoleName: 'other-role', Arn: `arn:aws:iam::${accountId}:role/other-role`, AssumeRolePolicyDocument: value };
    const result = inventory.filterRoles([ordinary]);
    expect(result).toEqual([ordinary]); expect(result[0]).toBe(ordinary); expect(result[0].AssumeRolePolicyDocument).toBe(value);
  });

  it('CI catalog freezes the entire decoded trust without approving its semantics', async () => {
    const f = fixture(); const { inventory } = await create(f);
    const trust = JSON.parse(decodeURIComponent(f.roles[deploymentStack].AssumeRolePolicyDocument));
    trust.Extension = { marker: 'original' }; f.roles[deploymentStack].AssumeRolePolicyDocument = trust;
    await inventory.verifyDeploymentRoleCatalog();
    f.roles[deploymentStack].AssumeRolePolicyDocument.Extension.marker = 'changed';
    await expect(inventory.verifyDeploymentRoleCatalog()).rejects.toThrow();
  });

  it('leaves project Lambda root-trust rejection to the original matching-role verifier', async () => {
    const f = fixture(); const { inventory } = await create(f); await inventory.verify();
    const name = 'mem9-on-aws-prod-Mem9ProxyFnRole-fixture';
    const role = { ...f.roles[namespaceRole], RoleName: name, Arn: `arn:aws:iam::${accountId}:role/${name}`,
      AssumeRolePolicyDocument: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { AWS: `arn:aws:iam::${accountId}:root` } }] } };
    const page = inventory.filterRoles([role]); expect(page).toEqual([role]);
    expect(() => matchingRoleNames(page.map(r => ({ name: r.RoleName, arn: r.Arn, assumeRolePolicyDocument: r.AssumeRolePolicyDocument })), expectedRolePatterns(identity)))
      .toThrow(/Lambda-only/u);
  });

  it.each(['listing subset', 'missing optional trust', 'source role template', 'underscore RoleId', 'repeated action', 'repeated statement', 'empty condition'])('accepts documented unrelated Role shape: %s', async form => {
    const f = fixture(); const { inventory } = await create(f); await inventory.verify();
    const ordinary = { ...f.roles[namespaceRole], RoleName: 'OtherServiceRole', Path: '/aws-service-role/service.example/',
      Arn: `arn:aws:iam::${accountId}:role/aws-service-role/service.example/OtherServiceRole`, RoleId: 'AROA' + '6'.repeat(17) };
    const trust = JSON.parse(decodeURIComponent(ordinary.AssumeRolePolicyDocument));
    if (form === 'listing subset') { delete ordinary.Tags; delete ordinary.MaxSessionDuration; }
    if (form === 'missing optional trust') delete ordinary.AssumeRolePolicyDocument;
    if (form === 'source role template') ordinary.SourceRoleTemplate = { TemplateArn: `arn:aws:iam::${accountId}:role-template/example`, TemplateMinorVersion: 1 };
    if (form === 'underscore RoleId') ordinary.RoleId = 'AROA_ROLE_ID_EXAMPLE';
    if (form === 'repeated action') { trust.Statement[0].Action = ['sts:AssumeRole', 'sts:AssumeRole']; ordinary.AssumeRolePolicyDocument = trust; }
    if (form === 'repeated statement') { trust.Statement.push(structuredClone(trust.Statement[0])); ordinary.AssumeRolePolicyDocument = trust; }
    if (form === 'empty condition') { trust.Statement[0].Condition = {}; ordinary.AssumeRolePolicyDocument = trust; }
    expect(inventory.filterRoles([ordinary])).toEqual([ordinary]);
  });

  it.each(['missing trust', 'source role template', 'repeated action', 'empty condition', 'duplicate Sid', 'extension'])('retained roles still reject %s', async form => {
    const f = fixture(); const { inventory } = await create(f); await inventory.verify();
    const role = f.roles[namespaceRole];
    if (form === 'missing trust') delete role.AssumeRolePolicyDocument;
    if (form === 'source role template') role.SourceRoleTemplate = { TemplateArn: `arn:aws:iam::${accountId}:role-template/example`, TemplateMinorVersion: 1 };
    if (form === 'repeated action') {
      const trust = JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument)); trust.Statement[0].Action = ['sts:AssumeRole', 'sts:AssumeRole']; role.AssumeRolePolicyDocument = trust;
    }
    if (form === 'empty condition') {
      const trust = JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument)); trust.Statement[0].Condition = {}; role.AssumeRolePolicyDocument = trust;
    }
    if (form === 'duplicate Sid' || form === 'extension') {
      const trust = JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument));
      if (form === 'duplicate Sid') { trust.Statement[0].Sid = 'Repeated'; trust.Statement.push(structuredClone(trust.Statement[0])); }
      else trust.Extension = { marker: 'extra' };
      role.AssumeRolePolicyDocument = trust;
    }
    expect(() => inventory.filterRoles([role])).toThrow();
    await expect(inventory.verify()).rejects.toThrow();
  });

  it.each(['null', '[]', '42', '"scalar"'])('rejects non-object JSON trust %s on unrelated roles', async value => {
    const f = fixture(); const { inventory } = await create(f); await inventory.verify();
    const role = { ...f.roles[namespaceRole], RoleName: 'other', Arn: `arn:aws:iam::${accountId}:role/other`, AssumeRolePolicyDocument: value };
    expect(() => inventory.filterRoles([role])).toThrow();
  });

  it.each(['short RoleId', 'bad path', 'bad template', 'unknown template field', 'bad last-used metadata', 'duplicate JSON key'])('rejects malformed unrelated Role: %s', async form => {
    const f = fixture(); const { inventory } = await create(f); await inventory.verify();
    const role = { ...f.roles[namespaceRole], RoleName: 'other', Arn: `arn:aws:iam::${accountId}:role/other` };
    if (form === 'short RoleId') role.RoleId = 'x';
    if (form === 'bad path') { role.Path = '/bad path/'; role.Arn = `arn:aws:iam::${accountId}:role/bad path/other`; }
    if (form === 'bad template') role.SourceRoleTemplate = { TemplateArn: 'bad', TemplateMinorVersion: '1' };
    if (form === 'unknown template field') role.SourceRoleTemplate = { TemplateArn: `arn:aws:iam::${accountId}:role-template/example`, TemplateMinorVersion: 1, Unknown: true };
    if (form === 'bad last-used metadata') role.RoleLastUsed = 'not an object';
    if (form === 'duplicate JSON key') role.AssumeRolePolicyDocument = '{"Version":"2012-10-17","Version":"2008-10-17","Statement":[]}';
    expect(() => inventory.filterRoles([role])).toThrow();
  });

  it('does not discard unexpected Id or version fields on a retained operator', async () => {
    for (const change of [d => d.Id = 'extra', d => d.Version = '2008-10-17', d => delete d.Version]) {
      const f = fixture(); const { inventory } = await create(f);
      const trust = JSON.parse(decodeURIComponent(f.roles[namespaceRole].AssumeRolePolicyDocument)); change(trust);
      f.roles[namespaceRole].AssumeRolePolicyDocument = trust;
      await expect(inventory.verify()).rejects.toThrow();
    }
  });

  it.each(['extra source role', 'missing role', 'swapped physical', 'changed output', 'duplicate role'])('closed catalog rejects %s', async scenario => {
    const f = fixture(); const { inventory } = await create(f);
    if (scenario === 'extra source role') f.templates[deploymentStack].Resources.AnotherCiRole = structuredClone(f.templates[deploymentStack].Resources.GitHubActionsRole);
    if (scenario === 'missing role') delete f.templates[deploymentStack].Resources.GitHubActionsRole;
    if (scenario === 'swapped physical') f.resources[deploymentStack].find(r => r.LogicalResourceId === 'GitHubActionsRole').PhysicalResourceId = humanRole;
    if (scenario === 'changed output') f.stacks[deploymentStack].Outputs[0].OutputValue += '-other';
    if (scenario === 'duplicate role') f.resources[deploymentStack].push(f.resources[deploymentStack].find(r => r.LogicalResourceId === 'GitHubActionsRole'));
    await expect(inventory.verifyDeploymentRoleCatalog()).rejects.toThrow();
  });

  const indirectCases = indirectTypes.flatMap(type => [namespaceStack, deploymentStack].flatMap(stack =>
    ['template', 'summary'].flatMap(surface => [false, true].map(frozen => ({ type, stack, surface, frozen })))));
  it.each(indirectCases)('rejects $type in $stack $surface (frozen=$frozen)', async ({ type, stack, surface, frozen }) => {
    const f = fixture(); const { inventory } = await create(f);
    if (frozen) { await inventory.verify(); await inventory.verifyDeploymentRoleCatalog(); }
    if (surface === 'template') f.templates[stack].Resources.HiddenAuthority = { Type: type, Properties: {} };
    else f.resources[stack].push({ LogicalResourceId: 'HiddenAuthority', PhysicalResourceId: 'hidden-authority', ResourceType: type, ResourceStatus: 'CREATE_COMPLETE' });
    await expect(inventory.verify()).rejects.toThrow();
    if (stack === deploymentStack) await expect(inventory.verifyDeploymentRoleCatalog()).rejects.toThrow();
    expect(() => inventory.filterRoles(Object.values(f.roles))).toThrow();
  });

  it('catalog freezes identities but permits unrelated managed-policy and quarantine-era source-owned resource updates', async () => {
    const f = fixture(); const { inventory } = await create(f); await inventory.verify(); await inventory.verifyDeploymentRoleCatalog();
    f.templates[deploymentStack].Resources.DenyPolicy.Properties.PolicyDocument.Statement.push({ Effect: 'Deny', Action: 'example:Write', Resource: '*' });
    f.resources[deploymentStack].push({ LogicalResourceId: 'AdditionalProtection', PhysicalResourceId: 'protection', ResourceType: 'AWS::IAM::Policy', ResourceStatus: 'CREATE_COMPLETE' });
    f.templates[deploymentStack].Resources.AdditionalProtection = { Type: 'AWS::IAM::Policy', Properties: { PolicyName: 'example-protection',
      Roles: [{ Ref: 'GitHubActionsRole' }], PolicyDocument: { Version: '2012-10-17', Statement: [{ Effect: 'Deny', Action: 'iam:DeleteRole', Resource: '*' }] } } };
    await expect(inventory.verify()).resolves.toEqual(retained); await expect(inventory.verifyDeploymentRoleCatalog()).resolves.toBeUndefined();
    f.roles[deploymentStack].RoleId = 'AROA' + '7'.repeat(17);
    await expect(inventory.verifyDeploymentRoleCatalog()).rejects.toThrow();
  });

  it.each(['false truncation', 'cycle', 'late attachment', 'extra response field'])('fails closed on %s', async scenario => {
    const f = fixture(); const { inventory } = await create(f);
    f.state.responseOverride = (args, response) => {
      if (args[1] !== 'list-attached-role-policies') return response;
      if (scenario === 'false truncation') return { ...response, Marker: 'hidden' };
      if (scenario === 'cycle') return { ...response, IsTruncated: true, Marker: 'same' };
      if (scenario === 'extra response field') return { ...response, Unknown: true };
      return args.includes('--marker') ? { AttachedPolicies: [{ PolicyName: 'extra', PolicyArn: `arn:aws:iam::${accountId}:policy/extra` }], IsTruncated: false } :
        { AttachedPolicies: [], IsTruncated: true, Marker: 'next' };
    };
    await expect(inventory.verify()).rejects.toThrow();
  });
});
