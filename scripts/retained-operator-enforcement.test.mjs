import { describe, expect, it } from 'vitest';
import { verifyRetainedOperatorEnforcement } from './lib/retained-operator-enforcement.mjs';
import { expectedRetainedOperatorProtectionPolicy, retainedOperatorProtectionPolicyName } from './lib/retained-operator-protection.mjs';
import { quarantinePolicyDocument, QUARANTINE_POLICY_NAME } from './lib/workload-permissions-boundary.mjs';

const identity = { partition: 'aws', accountId: '123456789012' };
const roleNames = ['github-actions-mem9-on-aws', 'github-actions-mem9-on-aws-preview', 'github-actions-mem9-on-aws-prod'].sort();
const roleArn = name => `arn:aws:iam::${identity.accountId}:role/${name}`;
const managedArn = `arn:aws:iam::${identity.accountId}:policy/retained-operator-test`;
const argument = (args, key) => args[args.indexOf(key) + 1];

function fixture(mutate = () => {}) {
  const calls = [];
  const reads = new Map();
  const policies = new Map(roleNames.map(roleName => [roleName, {
    [retainedOperatorProtectionPolicyName(roleName)]: expectedRetainedOperatorProtectionPolicy({ ...identity, roleName }),
    [QUARANTINE_POLICY_NAME]: quarantinePolicyDocument(),
    Runtime: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'iam:PassRole',
      Resource: roleArn('mem9-on-aws-preview-human-acceptance'),
      Condition: { StringEquals: { 'iam:PassedToService': 'ecs-tasks.amazonaws.com' } } }] },
  }]));
  const invokeAws = async args => {
    calls.push(args);
    const command = args.slice(0, 2).join(' ');
    const name = argument(args, '--role-name');
    const policyName = argument(args, '--policy-name');
    const key = `${command}:${name}:${policyName}`;
    reads.set(key, (reads.get(key) ?? 0) + 1);
    let response;
    switch (command) {
      case 'iam get-role': response = { Role: { RoleName: name, Arn: roleArn(name), RoleId: 'AROASYNTHETIC' + roleNames.indexOf(name) } }; break;
      case 'iam list-role-policies': response = { PolicyNames: Object.keys(policies.get(name)), IsTruncated: false }; break;
      case 'iam get-role-policy': response = { RoleName: name, PolicyName: policyName, PolicyDocument: structuredClone(policies.get(name)[policyName]) }; break;
      case 'iam list-attached-role-policies': response = { AttachedPolicies: [{ PolicyArn: managedArn }], IsTruncated: false }; break;
      case 'iam get-policy': response = { Policy: { Arn: argument(args, '--policy-arn'), DefaultVersionId: 'v1' } }; break;
      case 'iam get-policy-version': response = { PolicyVersion: { VersionId: argument(args, '--version-id'), IsDefaultVersion: true,
        Document: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'logs:DescribeLogGroups', Resource: '*' }] } } }; break;
      case 'iam simulate-custom-policy': {
        const policy = JSON.parse(argument(args, '--policy-input-list'));
        expect(policy.Statement.some(s => s.Sid === 'QuarantineAllDeployRoleActions')).toBe(false);
        expect(policy.Statement.some(s => s.Effect === 'Deny' && s.Action === '*' && s.Resource === '*')).toBe(false);
        const action = argument(args, '--action-names');
        const resource = argument(args, '--resource-arns');
        const allowed = action === 'iam:PassRole' && resource.endsWith('/mem9-on-aws-preview-human-acceptance') &&
          args.some(value => value.includes('ContextKeyValues=ecs-tasks.amazonaws.com')) &&
          !policy.Statement.some(s => s.Effect === 'Deny' && !s.Condition &&
            [].concat(s.Action ?? []).includes('iam:PassRole') && [].concat(s.Resource ?? []).includes(resource));
        response = { EvaluationResults: [{ EvalActionName: action, EvalResourceName: resource,
          EvalDecision: allowed ? 'allowed' : 'explicitDeny', MatchedStatements: [{ SourcePolicyId: 'PolicyInputList.1' }] }], IsTruncated: false };
        break;
      }
      default: throw new Error(`unexpected command: ${command}`);
    }
    mutate({ args, command, name, policyName, response, read: reads.get(key), policies });
    return response;
  };
  return { invokeAws, calls };
}

describe('live retained operator enforcement', () => {
  it('TC111/115: verifies each current inline attachment independently of quarantine', async () => {
    const f = fixture();
    await expect(verifyRetainedOperatorEnforcement({ ...f, identity, roleNames })).resolves.toBe(true);
    for (const name of roleNames) expect(f.calls.filter(args => args[1] === 'get-role-policy' &&
      argument(args, '--role-name') === name && argument(args, '--policy-name') === retainedOperatorProtectionPolicyName(name)).length).toBeGreaterThanOrEqual(2);
    expect(f.calls.every(args => ['get-role', 'list-role-policies', 'get-role-policy', 'list-attached-role-policies', 'get-policy', 'get-policy-version', 'simulate-custom-policy'].includes(args[1]))).toBe(true);
  });

  it.each(roleNames)('TC111: a missing permanent policy on %s cannot be covered by peers/quarantine', async name => {
    const f = fixture(({ command, name: current, response }) => {
      if (command === 'iam list-role-policies' && current === name) response.PolicyNames = response.PolicyNames.filter(n => n !== retainedOperatorProtectionPolicyName(name));
    });
    await expect(verifyRetainedOperatorEnforcement({ ...f, identity, roleNames })).rejects.toThrow(/retained operator/u);
  });

  it.each(['role', 'policy', 'quarantine'])('TC112: late %s drift holds the result', async kind => {
    const f = fixture(({ command, name, policyName, response, read }) => {
      if (name !== roleNames[0] || read < 2) return;
      if (kind === 'role' && command === 'iam get-role') response.Role.RoleId += 'RECREATED';
      if (kind === 'policy' && command === 'iam get-role-policy' && policyName === retainedOperatorProtectionPolicyName(name)) response.PolicyDocument.Statement.pop();
      if (kind === 'quarantine' && command === 'iam list-role-policies') response.PolicyNames = response.PolicyNames.filter(n => n !== QUARANTINE_POLICY_NAME);
    });
    await expect(verifyRetainedOperatorEnforcement({ ...f, identity, roleNames })).rejects.toThrow(/retained operator/u);
  });

  it('TC110: counts all inline policies including quarantine before simulation', async () => {
    const f = fixture(({ command, policyName, response }) => {
      if (command === 'iam get-role-policy' && policyName === 'Runtime') response.PolicyDocument.Statement[0].Sid = 'a'.repeat(10240);
    });
    await expect(verifyRetainedOperatorEnforcement({ ...f, identity, roleNames })).rejects.toThrow(/quota/u);
    expect(f.calls.some(args => args[1] === 'simulate-custom-policy')).toBe(false);
  });

  it.each(['attachment', 'version', 'content'])('TC112: catches managed policy %s drift after simulation', async kind => {
    let simulated = false;
    const f = fixture(({ command, response }) => {
      if (command === 'iam simulate-custom-policy') simulated = true;
      if (!simulated) return;
      if (kind === 'attachment' && command === 'iam list-attached-role-policies') response.AttachedPolicies = [];
      if (kind === 'version' && command === 'iam get-policy') response.Policy.DefaultVersionId = 'v2';
      if (kind === 'content' && command === 'iam get-policy-version') response.PolicyVersion.Document.Statement[0].Action = 'logs:DescribeLogStreams';
    });
    await expect(verifyRetainedOperatorEnforcement({ ...f, identity, roleNames })).rejects.toThrow(/changed/u);
  });

  it('TC111: rejects duplicate keys in raw policy JSON', async () => {
    const f = fixture(({ command, response, policyName }) => {
      if (command === 'iam get-role-policy' && policyName === 'Runtime') response.PolicyDocument = JSON.stringify(response.PolicyDocument)
        .replace('"Effect":"Allow"', '"Effect":"Deny","Effect":"Allow"');
    });
    await expect(verifyRetainedOperatorEnforcement({ ...f, identity, roleNames })).rejects.toThrow(/encoding/u);
  });

  it.each(['allowed', 'implicitDeny'])('TC106: incorrect negative simulation %s fails', async decision => {
    const f = fixture(({ command, response }) => {
      if (command === 'iam simulate-custom-policy') response.EvaluationResults[0].EvalDecision = decision;
    });
    await expect(verifyRetainedOperatorEnforcement({ ...f, identity, roleNames })).rejects.toThrow(/simulation/u);
  });

  it('TC116: rejects live CI self-policy-write grants even with permanent denies present', async () => {
    const f = fixture(({ command, policyName, response }) => {
      if (command === 'iam get-role-policy' && policyName === 'Runtime') response.PolicyDocument.Statement.push({ Effect: 'Allow', Action: 'iam:DeleteRolePolicy', Resource: roleArn(roleNames[0]) });
    });
    await expect(verifyRetainedOperatorEnforcement({ ...f, identity, roleNames })).rejects.toThrow();
    expect(f.calls.some(args => args[1] === 'simulate-custom-policy')).toBe(false);
  });

  it('TC107: unrelated stage conditions are checked for drift but excluded from the isolated protection probe', async () => {
    const f = fixture(({ command, policyName, args, response }) => {
      if (command === 'iam get-role-policy' && policyName === 'Runtime') response.PolicyDocument.Statement.push({
        Sid: 'DenyTaggedProductionResources', Effect: 'Deny', Action: '*', Resource: '*',
        Condition: { StringEquals: { 'aws:ResourceTag/sst:stage': 'prod' } },
      });
      if (command === 'iam simulate-custom-policy') expect(argument(args, '--policy-input-list')).not.toContain('aws:ResourceTag/sst:stage');
    });
    await expect(verifyRetainedOperatorEnforcement({ ...f, identity, roleNames })).resolves.toBe(true);
  });

  it.each(['duplicate', 'truncated', 'malformed', 'missing completion flag'])('TC111: rejects %s inline inventory', async fault => {
    const f = fixture(({ command, response }) => {
      if (command !== 'iam list-role-policies') return;
      if (fault === 'duplicate') response.PolicyNames.push(response.PolicyNames[0]);
      if (fault === 'truncated') response.IsTruncated = true;
      if (fault === 'malformed') delete response.PolicyNames;
      if (fault === 'missing completion flag') delete response.IsTruncated;
    });
    await expect(verifyRetainedOperatorEnforcement({ ...f, identity, roleNames })).rejects.toThrow(/retained operator/u);
  });

  it.each(['missing completion', 'repeated marker'])('TC111: rejects managed listing with %s', async fault => {
    const f = fixture(({ command, response }) => {
      if (command !== 'iam list-attached-role-policies') return;
      if (fault === 'missing completion') delete response.IsTruncated;
      else { response.IsTruncated = true; response.Marker = 'same-marker'; }
    });
    await expect(verifyRetainedOperatorEnforcement({ ...f, identity, roleNames })).rejects.toThrow(/retained operator/u);
  });

  it('TC111: reads every inline and managed policy page', async () => {
    const f = fixture(({ command, args, response }) => {
      if (!['iam list-role-policies', 'iam list-attached-role-policies'].includes(command)) return;
      const field = command === 'iam list-role-policies' ? 'PolicyNames' : 'AttachedPolicies';
      if (field === 'AttachedPolicies') response[field].push({ PolicyArn: managedArn + '-second' });
      if (args.includes('--marker')) response[field] = response[field].slice(1);
      else { response[field] = response[field].slice(0, 1); response.IsTruncated = true; response.Marker = 'second-page'; }
    });
    await expect(verifyRetainedOperatorEnforcement({ ...f, identity, roleNames })).resolves.toBe(true);
    expect(f.calls.some(args => args[1] === 'get-policy-version' && argument(args, '--policy-arn') === managedArn + '-second')).toBe(true);
  });

  it('TC107: absence-context denial remains valid, but positive probes require complete context', async () => {
    const negative = fixture(({ command, response }) => {
      if (command === 'iam simulate-custom-policy' && response.EvaluationResults[0].EvalDecision === 'explicitDeny')
        response.EvaluationResults[0].MissingContextValues = ['iam:PassedToService'];
    });
    await expect(verifyRetainedOperatorEnforcement({ ...negative, identity, roleNames })).resolves.toBe(true);
    const positive = fixture(({ command, response }) => {
      if (command === 'iam simulate-custom-policy' && response.EvaluationResults[0].EvalDecision === 'allowed')
        response.EvaluationResults[0].MissingContextValues = ['iam:PassedToService'];
    });
    await expect(verifyRetainedOperatorEnforcement({ ...positive, identity, roleNames })).rejects.toThrow(/simulation/u);
  });
});
