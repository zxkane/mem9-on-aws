import { readFileSync } from 'node:fs';
import { strict as assert } from 'node:assert';
import { parseDocument } from 'yaml';

const accountId = '123456789012';
const identity = { partition: 'aws', accountId };
const applicationRegion = 'ap-northeast-1';
const namespaceStack = 'memory-namespace-operator-mem9-on-aws';
const deploymentStack = 'github-actions-mem9-on-aws';
const namespaceRole = 'mem9-on-aws-namespace-operator';
const humanRole = 'mem9-on-aws-preview-human-acceptance';
const retained = [namespaceRole, humanRole].sort();
const roleMap = { MemoryNamespaceOperatorRole: namespaceRole,
  PreviewHumanAcceptanceRole: humanRole, GitHubActionsRole: deploymentStack,
  GitHubPreviewActionsRole: `${deploymentStack}-preview`, GitHubProductionActionsRole: `${deploymentStack}-prod` };
const sources = Object.fromEntries([[namespaceStack, 'memory-namespace-operator-role.yaml'], [deploymentStack, 'github-actions-role.yaml']]
  .map(([name, file]) => [name, readFileSync(new URL(`../../infra/cloudformation/${file}`, import.meta.url), 'utf8')]));
function parse(source) {
  const document = parseDocument(source, { uniqueKeys: true, customTags: [
    ...['Ref', 'Sub', 'GetAtt'].map(name => ({ tag: '!' + name, resolve: value => ({ [name === 'Ref' ? name : 'Fn::' + name]: value }) })),
    ...['If', 'Equals', 'Not'].map(name => ({ tag: '!' + name, collection: 'seq', resolve: value => ({ ['Fn::' + name]: value.toJSON() }) })),
  ] });
  assert.deepEqual(document.errors, []);
  return document.toJS();
}
export function createRetainedOperatorFixture({ pool = '', legacy = 'false', paginate = false } = {}) {
  const calls = [];
  const templates = Object.fromEntries(Object.entries(sources).map(([name, source]) => [name, parse(source)]));
  const stackId = name => `arn:aws:cloudformation:us-west-2:${accountId}:stack/${name}/fixture-id`;
  const parameters = {
    [namespaceStack]: { ApplicationRegion: applicationRegion, Stage: 'prod', CognitoUserPoolId: pool },
    [deploymentStack]: { ProjectName: 'mem9-on-aws', GitHubOrg: 'zxkane', GitHubRepo: 'mem9-on-aws', ApplicationRegion: applicationRegion,
      LegacyRoleEnabled: legacy, OIDCProviderArn: `arn:aws:iam::${accountId}:oidc-provider/token.actions.githubusercontent.com` },
  };
  const noValue = Symbol('NoValue');
  const render = (value, stack) => {
    const values = { ...parameters[stack], 'AWS::AccountId': accountId, 'AWS::Partition': 'aws', 'AWS::Region': 'us-west-2', 'AWS::NoValue': noValue };
    if (Array.isArray(value)) return value.map(v => render(v, stack)).filter(v => v !== noValue);
    if (!value || typeof value !== 'object') return value;
    if ('Ref' in value) { assert.notEqual(values[value.Ref], undefined, value.Ref); return values[value.Ref]; }
    if ('Fn::Sub' in value) return value['Fn::Sub'].replace(/\$\{([^}]+)\}/gu, (_, key) => { assert.notEqual(values[key], undefined, key); return values[key]; });
    if ('Fn::If' in value) { const [key, yes, no] = value['Fn::If']; return render(render(templates[stack].Conditions[key], stack) ? yes : no, stack); }
    if ('Fn::Equals' in value) return render(value['Fn::Equals'][0], stack) === render(value['Fn::Equals'][1], stack);
    if ('Fn::Not' in value) return !render(value['Fn::Not'][0], stack);
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, render(v, stack)]));
  };
  const stacks = {}, resources = {}, roles = {}, inline = {}, managed = {};
  for (const [stack, template] of Object.entries(templates)) {
    stacks[stack] = { StackName: stack, StackId: stackId(stack), StackStatus: 'UPDATE_COMPLETE', CreationTime: '2026-01-01T00:00:00Z',
      Parameters: Object.entries(parameters[stack]).map(([ParameterKey, ParameterValue]) => ({ ParameterKey, ParameterValue })),
      Outputs: stack === namespaceStack ? [{ OutputKey: 'RoleArn', OutputValue: `arn:aws:iam::${accountId}:role/${namespaceRole}` }] :
        [['RoleArn', deploymentStack], ['LegacyRoleArn', deploymentStack], ['PreviewRoleArn', `${deploymentStack}-preview`], ['ProductionRoleArn', `${deploymentStack}-prod`]]
          .map(([OutputKey, name]) => ({ OutputKey, OutputValue: `arn:aws:iam::${accountId}:role/${name}` })) };
    resources[stack] = Object.entries(template.Resources).map(([LogicalResourceId, r]) => ({ LogicalResourceId, ResourceType: r.Type,
      PhysicalResourceId: roleMap[LogicalResourceId] ?? LogicalResourceId, ResourceStatus: 'CREATE_COMPLETE', LastUpdatedTimestamp: '2026-01-01T00:00:00Z' }));
    for (const [logical, role] of Object.entries(roleMap)) {
      if (!template.Resources[logical]) continue;
      const p = template.Resources[logical].Properties;
      roles[role] = { RoleName: role, RoleId: `AROA${Object.keys(roles).length.toString().padStart(17, '0')}`, Path: '/',
        Arn: `arn:aws:iam::${accountId}:role/${role}`, CreateDate: '2026-01-01T00:00:00Z', MaxSessionDuration: 3600,
        AssumeRolePolicyDocument: encodeURIComponent(JSON.stringify(render(p.AssumeRolePolicyDocument, stack))), Tags: render(p.Tags, stack) };
      inline[role] = retained.includes(role) ? Object.fromEntries(render(p.Policies, stack).map(p => [p.PolicyName, p.PolicyDocument])) : {};
      managed[role] = [];
    }
  }
  const state = { stacks, resources, roles, inline, managed, templates, calls, paginate, mutate: undefined, rawTemplate: {}, responseOverride: undefined };
  const invokeAws = async args => {
    calls.push([...args]);
    await state.mutate?.(args, state);
    const op = args.slice(0, 2).join(' '), get = key => args[args.indexOf(key) + 1];
    let response;
    if (args[0] === 'cloudformation') {
      assert.equal(get('--region'), 'us-west-2');
      const name = Object.keys(stacks).find(name => get('--stack-name') === name || get('--stack-name') === stacks[name].StackId);
      if (!name) throw Error('missing synthetic owner');
      if (op === 'cloudformation describe-stacks') response = { Stacks: [stacks[name]] };
      else if (op === 'cloudformation get-template') {
        assert.equal(get('--template-stage'), 'Original');
        response = { TemplateBody: state.rawTemplate[name] ?? JSON.stringify(templates[name]), StagesAvailable: ['Original'] };
      } else if (op === 'cloudformation list-stack-resources') {
        const start = args.includes('--next-token') ? Number(get('--next-token')) : 0;
        const size = state.paginate ? 2 : resources[name].length;
        response = { StackResourceSummaries: resources[name].slice(start, start + size) };
        if (start + size < resources[name].length) response.NextToken = String(start + size);
      } else throw Error('unexpected synthetic CF operation');
    } else if (args[0] === 'iam') {
      assert.equal(get('--region'), 'us-east-1');
      const name = get('--role-name');
      if (op === 'iam get-role') response = { Role: roles[name] };
      else if (op === 'iam list-role-policies') response = { PolicyNames: Object.keys(inline[name]), IsTruncated: false };
      else if (op === 'iam list-attached-role-policies') response = { AttachedPolicies: managed[name], IsTruncated: false };
      else if (op === 'iam get-role-policy') response = { RoleName: name, PolicyName: get('--policy-name'), PolicyDocument: inline[name][get('--policy-name')] };
      else throw Error('unexpected synthetic IAM operation');
    } else throw Error('mutating or unexpected service call');
    response = structuredClone(response);
    return state.responseOverride?.(args, response) ?? response;
  };
  return { ...state, state, invokeAws };
}
