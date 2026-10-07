import { isDeepStrictEqual } from 'node:util';
import { parseStrictJson } from './authorization-archive-policy.mjs';
import {
  expectedRetainedOperatorProtectionPolicy,
  retainedOperatorProtectionPolicyName,
  retainedOperatorProtectionProbes,
  verifyRetainedOperatorProtectionDocuments,
} from './retained-operator-protection.mjs';
import { QUARANTINE_POLICY_NAME, verifyQuarantinePolicy } from './workload-permissions-boundary.mjs';

const deploymentRoles = ['github-actions-mem9-on-aws', 'github-actions-mem9-on-aws-preview', 'github-actions-mem9-on-aws-prod'].sort();
const requireValue = (condition, detail) => {
  if (!condition) throw new Error(`retained operator enforcement ${detail}`);
};
const canonical = value => Array.isArray(value) ? value.map(canonical)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;

function policyDocument(value) {
  try {
    if (typeof value === 'string') value = parseStrictJson(value.trimStart().startsWith('{') ? value : decodeURIComponent(value));
  } catch { throw new Error('retained operator enforcement policy encoding is malformed'); }
  requireValue(value?.Version === '2012-10-17' && Array.isArray(value.Statement) && value.Statement.length > 0,
    'policy document is malformed');
  return value;
}

// Every page is bounded and must use an unambiguous completion marker. Duplicate
// names/ARNs are rejected after collection instead of silently deduplicated.
async function pages(invokeAws, args, field, key = value => value) {
  const result = [];
  const markers = new Set();
  let marker;
  for (let page = 0; page < 100; page++) {
    const response = await invokeAws([...args, '--no-paginate', ...(marker ? ['--marker', marker] : []), '--region', 'us-east-1']);
    requireValue(Array.isArray(response?.[field]) && typeof response.IsTruncated === 'boolean', 'policy inventory is malformed');
    result.push(...response[field]);
    requireValue(result.length <= 10000, 'policy inventory exceeded limit');
    if (response.IsTruncated !== true) {
      requireValue(!Object.hasOwn(response, 'Marker'), 'policy inventory has an unexpected marker');
      const keys = result.map(key);
      requireValue(keys.every(value => typeof value === 'string' && value.length > 0) && new Set(keys).size === keys.length,
        'policy inventory has duplicate or malformed entries');
      return result.sort((a, b) => key(a).localeCompare(key(b)));
    }
    marker = response.Marker;
    requireValue(typeof marker === 'string' && marker.length > 0 && marker.length <= 2048 && !markers.has(marker),
      'policy inventory is incomplete');
    markers.add(marker);
  }
  throw new Error('retained operator enforcement policy inventory exceeded page limit');
}

async function readRole(invokeAws, context) {
  const { roleName, accountId, partition } = context;
  const { Role: role } = await invokeAws(['iam', 'get-role', '--role-name', roleName, '--region', 'us-east-1']);
  requireValue(role?.RoleName === roleName && role.Arn === `arn:${partition}:iam::${accountId}:role/${roleName}` &&
    typeof role.RoleId === 'string' && role.RoleId.length > 0 && role.RoleId.length <= 128, 'role identity is malformed');
  const inlineNames = await pages(invokeAws, ['iam', 'list-role-policies', '--role-name', roleName], 'PolicyNames');
  const inline = [];
  for (const name of inlineNames) {
    const response = await invokeAws(['iam', 'get-role-policy', '--role-name', roleName, '--policy-name', name, '--region', 'us-east-1']);
    requireValue(response.RoleName === roleName && response.PolicyName === name, 'inline attachment identity is malformed');
    inline.push({ name, document: policyDocument(response.PolicyDocument) });
  }
  requireValue(inline.reduce((size, policy) => size + JSON.stringify(policy.document).length, 0) <= 10240,
    'inline policy quota exceeded');
  const quarantine = inline.find(policy => policy.name === QUARANTINE_POLICY_NAME);
  requireValue(quarantine && verifyQuarantinePolicy(quarantine.document), 'quarantine is missing or malformed');
  const permanent = inline.find(policy => policy.name === retainedOperatorProtectionPolicyName(roleName));
  requireValue(permanent && isDeepStrictEqual(canonical(permanent.document),
    canonical(expectedRetainedOperatorProtectionPolicy(context))), 'permanent inline policy is missing or changed');
  const attached = await pages(invokeAws, ['iam', 'list-attached-role-policies', '--role-name', roleName],
    'AttachedPolicies', value => value?.PolicyArn);
  const managed = [];
  for (const { PolicyArn: arn } of attached) {
    requireValue(new RegExp(`^arn:${RegExp.escape(partition)}:iam::(?:${accountId}|aws):policy/[A-Za-z0-9+=,.@_/-]+$`, 'u').test(arn),
      'managed policy ARN is malformed');
    const { Policy: metadata } = await invokeAws(['iam', 'get-policy', '--policy-arn', arn, '--region', 'us-east-1']);
    requireValue(metadata?.Arn === arn && /^v[1-9][0-9]*$/u.test(metadata.DefaultVersionId), 'managed policy metadata is malformed');
    const { PolicyVersion: version } = await invokeAws(['iam', 'get-policy-version', '--policy-arn', arn,
      '--version-id', metadata.DefaultVersionId, '--region', 'us-east-1']);
    requireValue(version?.VersionId === metadata.DefaultVersionId && version.IsDefaultVersion === true,
      'managed policy version is mismatched');
    managed.push({ arn, versionId: metadata.DefaultVersionId, document: policyDocument(version.Document) });
  }
  const documents = [...managed, ...inline.filter(policy => policy !== quarantine)].map(policy => policy.document);
  verifyRetainedOperatorProtectionDocuments(documents, context);
  const { RoleLastUsed, ...stableRole } = role;
  return { role: stableRole, inline, managed, documents };
}

// This is an independent attachment/readback gate. Simulations exercise the
// verified protection against an explicit grant for each probe. All live policies
// remain subject to coverage and drift checks; effective runner access is proved
// separately by preview E2E, not by this isolated protection-policy simulation.
export async function verifyRetainedOperatorEnforcement({ invokeAws, identity, roleNames }) {
  requireValue(typeof invokeAws === 'function' && /^[0-9]{12}$/u.test(identity?.accountId) &&
    /^aws(?:-us-gov|-cn)?$/u.test(identity?.partition), 'identity configuration is malformed');
  requireValue(isDeepStrictEqual(roleNames, deploymentRoles), 'deployment role catalog is incomplete');
  const before = new Map();
  for (const roleName of roleNames) before.set(roleName, await readRole(invokeAws, { ...identity, roleName }));
  for (const roleName of roleNames) {
    const context = { ...identity, roleName };
    const permanent = before.get(roleName).inline.find(policy => policy.name === retainedOperatorProtectionPolicyName(roleName)).document;
    for (const probe of retainedOperatorProtectionProbes(context)) {
      const serialized = JSON.stringify({ Version: '2012-10-17', Statement: [
        ...permanent.Statement,
        { Effect: 'Allow', Action: probe.action, Resource: probe.resource },
      ] });
      requireValue(serialized.length <= 131072, 'simulation input exceeded limit');
      const entries = Object.entries(probe.context ?? {}).map(([key, value]) =>
        `ContextKeyName=${key},ContextKeyValues=${value},ContextKeyType=string`);
      const response = await invokeAws(['iam', 'simulate-custom-policy', '--policy-input-list', serialized,
        '--action-names', probe.action, '--resource-arns', probe.resource,
        ...(entries.length ? ['--context-entries', ...entries] : []), '--region', 'us-east-1']);
      requireValue((response?.IsTruncated === undefined || response.IsTruncated === false) && !Object.hasOwn(response, 'Marker') &&
        Array.isArray(response.EvaluationResults) && response.EvaluationResults.length === 1, 'simulation response is incomplete');
      const result = response.EvaluationResults[0];
      requireValue(result.EvalActionName === probe.action && result.EvalResourceName === probe.resource &&
        result.EvalDecision === probe.decision && Array.isArray(result.MatchedStatements) && result.MatchedStatements.length > 0 &&
        (probe.decision !== 'allowed' || !result.MissingContextValues || result.MissingContextValues.length === 0),
      'simulation decision is mismatched');
    }
  }
  // Re-read every peer after all simulations, including attachment inventories,
  // default versions, inline documents and identity, before quarantine release.
  for (const roleName of roleNames) {
    const after = await readRole(invokeAws, { ...identity, roleName });
    requireValue(isDeepStrictEqual(canonical(before.get(roleName)), canonical(after)), 'role or policy changed during verification');
  }
  return true;
}
