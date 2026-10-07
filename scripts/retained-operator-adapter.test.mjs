import { expect, it } from 'vitest';
import { createAwsCliAdapter } from './lib/workload-permissions-boundary-aws.mjs';
import { createRetainedOperatorFixture } from './test-fixtures/retained-operator.mjs';

const accountId = '123456789012';
const identity = { accountId, partition: 'aws' };
const retainedNames = ['mem9-on-aws-namespace-operator', 'mem9-on-aws-preview-human-acceptance'];
const workloadName = 'mem9-on-aws-prod-task-role';
const workload = { RoleName: workloadName, RoleId: 'AROASYNTHETICWORKLOAD',
  Arn: `arn:aws:iam::${accountId}:role/${workloadName}`, Path: '/', CreateDate: '2026-01-01T00:00:00Z',
  AssumeRolePolicyDocument: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { Service: 'ecs-tasks.amazonaws.com' } }] } };

function create(mutatePage = () => {}) {
  const f = createRetainedOperatorFixture();
  const calls = [];
  const adapter = createAwsCliAdapter({ identity, applicationRegion: 'ap-northeast-1', consistencyAttempts: 1,
    invokeAws: async args => {
      calls.push(args);
      if (args.slice(0, 2).join(' ') === 'iam list-roles') {
        const response = { Roles: [...Object.values(f.roles), workload].map(r => structuredClone(r)), IsTruncated: false };
        mutatePage(response, f, args);
        return response;
      }
      return f.invokeAws(args);
    }, sleep: async () => {},
  });
  return { f, calls, adapter };
}

it('TC104: real adapter excludes only verified exact operators and keeps ordinary roles', async () => {
  const { adapter } = create();
  await expect(adapter.verifyRetainedOperators()).resolves.toBe(true);
  const page = await adapter.listRoles({});
  expect(page.roles.map(r => r.name)).toContain(workloadName);
  for (const name of retainedNames) expect(page.roles.map(r => r.name)).not.toContain(name);
  expect(page.roles.filter(r => r.name.startsWith('github-actions-'))).toHaveLength(3);
});

it('TC118: requests large service pages and still follows markers on short pages', async () => {
  const { adapter, calls } = create((response, _fixture, args) => {
    const next = args.includes('--marker');
    response.Roles = next ? response.Roles.slice(3) : response.Roles.slice(0, 3);
    response.IsTruncated = !next;
    if (!next) response.Marker = 'next-page';
  });
  const first = await adapter.listRoles({});
  expect(first.marker).toBe('next-page');
  const second = await adapter.listRoles({ marker: first.marker });
  expect(second.marker).toBeUndefined();
  const requests = calls.filter(args => args[1] === 'list-roles');
  expect(requests).toHaveLength(2);
  for (const args of requests) {
    expect(args).toContain('--no-paginate');
    expect(JSON.parse(args[args.indexOf('--cli-input-json') + 1])).toEqual({ MaxItems: 1000 });
    expect(args).not.toContain('--max-items');
  }
  expect(requests[1][requests[1].indexOf('--marker') + 1]).toBe('next-page');
  expect([...first.roles, ...second.roles].map(role => role.name)).toContain(workloadName);
  expect(calls.filter(args => args[1] === 'get-template')).toHaveLength(8);
});

it.each(['Arn', 'RoleId'])('TC105: filtering cannot hide a retained role with a changed %s', async field => {
  const { adapter } = create(response => {
    const role = response.Roles.find(r => r.RoleName === retainedNames[0]);
    role[field] += 'changed';
  });
  await expect(adapter.listRoles({})).rejects.toThrow();
});

it.each(retainedNames)('TC104: attachment rejects %s even without any prior verification', async roleName => {
  const { adapter, calls } = create();
  await expect(adapter.putRoleBoundary({ roleName, permissionsBoundary: `arn:aws:iam::${accountId}:policy/mem9-on-aws-workload-boundary` }))
    .rejects.toThrow(/retained operator/u);
  expect(calls).toEqual([]);
});

it('TC112: deployment catalog is closed before accepting CI identities', async () => {
  const { f, adapter } = create();
  await expect(adapter.resolveDeploymentRoles()).resolves.toEqual(
    ['github-actions-mem9-on-aws', 'github-actions-mem9-on-aws-preview', 'github-actions-mem9-on-aws-prod'].sort());
  f.templates['github-actions-mem9-on-aws'].Resources.UnreviewedRole = {
    Type: 'AWS::IAM::Role', Properties: { RoleName: 'unreviewed-role' },
  };
  await expect(adapter.resolveDeploymentRoles()).rejects.toThrow();
});

it('TC112: operator state stays bound to the original attempt across list calls', async () => {
  const { f, adapter } = create();
  await adapter.listRoles({});
  f.roles[retainedNames[0]].RoleId += 'recreated';
  await expect(adapter.listRoles({})).rejects.toThrow();
});
