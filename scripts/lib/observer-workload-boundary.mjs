import { isDeepStrictEqual } from 'node:util';

/** Canonical operator-owned ceiling; it grants no credentials or role authority. */
export const OBSERVER_BOUNDARY_POLICY_NAME = 'mem9-on-aws-observer-boundary';
export const OBSERVER_ROLE_TOKEN = 'ObserverControlTaskRole';
export const OBSERVER_POLICY_TAGS = Object.freeze([
  'Project', 'Stage', 'ObserverTenantSuffix', 'NamespaceIdentitySuffix',
  'ObserverSsmKeyId', 'ObserverSecretKeyId',
]);
const actions = ['ssm:GetParameter', 'secretsmanager:GetSecretValue', 'kms:Decrypt'];
const sourceNames = ['clientId', 'clientSecret', 'transportSigningKeys', 'tenantKey', 'identitySigningKeys'];
const parameterPaths = ['cognito/client-id', 'cognito/client-secret', 'namespace/transport-signing-keys'];
const secretFamilies = ['tenant-api-key', 'identity-signing-keys'];
const keyIdPattern = /^(?:[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}|mrk-[a-f0-9]{32})$/u;
const variable = key => '${aws:PrincipalTag/' + key + '}';
function requireValue(ok) { if (!ok) throw new Error('Observer role binding is invalid'); }

function identity({ partition, accountId, applicationRegion }) {
  requireValue(['aws', 'aws-cn', 'aws-us-gov'].includes(partition) && /^\d{12}$/u.test(accountId ?? ''));
  if (applicationRegion !== undefined) requireValue(
    /^[a-z]{2}(?:-[a-z]+)+-\d+$/u.test(applicationRegion) && applicationRegion.length <= 24);
  return { partition, accountId, applicationRegion, suffix: partition === 'aws-cn' ? 'amazonaws.com.cn' : 'amazonaws.com' };
}

/** IAM globs cannot validate numeric stages. Reserve malformed names as errors. */
export function observerRoleStage(name) {
  if (typeof name !== 'string' || !name.includes(OBSERVER_ROLE_TOKEN)) return undefined;
  const match = /^mem9-on-aws-(pr-[1-9][0-9]*)-ObserverControlTaskRole-([a-f0-9]{12})$/u.exec(name);
  requireValue(match && name.length <= 64);
  return match[1];
}
export function observerBoundaryArn(contract) {
  const { partition, accountId } = identity(contract);
  return `arn:${partition}:iam::${accountId}:policy/${OBSERVER_BOUNDARY_POLICY_NAME}`;
}
export function observerRoleArnPattern(contract, stage = '*') {
  const { partition, accountId } = identity(contract);
  return `arn:${partition}:iam::${accountId}:role/mem9-on-aws-${stage === '*' ? 'pr-*' : stage}-${OBSERVER_ROLE_TOKEN}-????????????`;
}
export function observerReservedRoleArnPattern(contract) {
  const { partition, accountId } = identity(contract);
  return `arn:${partition}:iam::${accountId}:role/mem9-on-aws-*-${OBSERVER_ROLE_TOKEN}-*`;
}

function resources(contract, tags) {
  const { partition, accountId, applicationRegion: region, suffix } = identity(contract);
  requireValue(region !== undefined);
  const arn = service => `arn:${partition}:${service}:${region}:${accountId}:`;
  return {
    parameters: parameterPaths.map(path => `${arn('ssm')}parameter/mem9-on-aws/${tags.Stage}/${path}`),
    secrets: secretFamilies.map((family, i) => `${arn('secretsmanager')}secret:mem9-on-aws-${tags.Stage}-${family}-${tags[OBSERVER_POLICY_TAGS[i + 2]]}`),
    keys: OBSERVER_POLICY_TAGS.slice(4).map(key => `${arn('kms')}key/${tags[key]}`),
    via: ['ssm', 'secretsmanager'].map(service => `${service}.${region}.${suffix}`),
  };
}

export function expectedObserverBoundaryPolicyDocument(contract) {
  const { applicationRegion } = identity(contract);
  const revision = contract.policyRevision ?? 'r1';
  requireValue(/^r[0-9]{1,20}$/u.test(revision));
  const { parameters, secrets, keys, via } = resources(contract, Object.fromEntries(OBSERVER_POLICY_TAGS.map(k => [k, variable(k)])));
  const deny = (Sid, Action, Condition, scope = { Resource: '*' }) => ({ Sid, Effect: 'Deny', Action, ...scope, ...(Condition ? { Condition } : {}) });
  const document = { Version: '2012-10-17', Statement: [
    // Preserve the frozen r1 document; the original owner's force-revision
    // mechanism must also reconcile later drift of this managed policy.
    { Sid: revision === 'r1' ? 'ReadOnlyCeiling' : `ReadOnlyCeiling${revision}`, Effect: 'Allow', Action: [...actions], Resource: '*' },
    { Sid: 'NoOtherAction', Effect: 'Deny', NotAction: [...actions], Resource: '*' },
    deny('RoleBinding', '*', { ArnNotLike: { 'aws:PrincipalArn': observerRoleArnPattern(contract, variable('Stage')) } }),
    deny('ProjectBinding', '*', { StringNotEquals: { 'aws:PrincipalTag/Project': 'mem9-on-aws' } }),
    deny('PreviewOnly', '*', { StringNotLike: { 'aws:PrincipalTag/Stage': 'pr-?*' } }),
    deny('RegionBinding', '*', { StringNotEquals: { 'aws:RequestedRegion': applicationRegion } }),
    ...OBSERVER_POLICY_TAGS.slice(2).map(key => deny('Missing' + key, '*', { Null: { ['aws:PrincipalTag/' + key]: 'true' } })),
    deny('OtherParameters', 'ssm:GetParameter', undefined, { NotResource: parameters }),
    deny('OtherSecrets', 'secretsmanager:GetSecretValue', undefined, { NotResource: secrets }),
    deny('OtherKeys', 'kms:Decrypt', undefined, { NotResource: keys }),
    // Negated IfExists in these Deny statements rejects missing service/context.
    deny('SsmKeyService', 'kms:Decrypt', { StringNotEqualsIfExists: { 'kms:ViaService': via[0] } }, { Resource: keys[0] }),
    deny('SsmKeyContext', 'kms:Decrypt', { StringNotEqualsIfExists: { 'kms:EncryptionContext:PARAMETER_ARN': parameters.slice(1) } }, { Resource: keys[0] }),
    deny('SecretKeyService', 'kms:Decrypt', { StringNotEqualsIfExists: { 'kms:ViaService': via[1] } }, { Resource: keys[1] }),
    deny('SecretKeyContext', 'kms:Decrypt', { StringNotEqualsIfExists: { 'kms:EncryptionContext:SecretARN': secrets } }, { Resource: keys[1] }),
  ] };
  requireValue(JSON.stringify(document).length <= 6144);
  return document;
}

export function assertObserverRoleTags(roleName, tags) {
  const stage = observerRoleStage(roleName);
  requireValue(stage !== undefined && tags && tags.Project === 'mem9-on-aws' && tags.Stage === stage);
  for (const key of OBSERVER_POLICY_TAGS.slice(2, 4)) requireValue(/^[A-Za-z0-9_+=.@-]{1,128}$/u.test(tags[key] ?? ''));
  for (const key of OBSERVER_POLICY_TAGS.slice(4)) requireValue(keyIdPattern.test(tags[key] ?? ''));
  requireValue(tags.ObserverSsmKeyId !== tags.ObserverSecretKeyId);
  return Object.fromEntries(OBSERVER_POLICY_TAGS.map(key => [key, tags[key]]));
}

/** Derive policy tags from retained, verified source references, never tag input. */
export function observerRoleTags({ roleName, credentialBindings }, contract) {
  const stage = observerRoleStage(roleName);
  requireValue(stage !== undefined && credentialBindings && isDeepStrictEqual(Object.keys(credentialBindings).sort(), [...sourceNames].sort()));
  const { partition, accountId, applicationRegion: region, suffix } = identity(contract);
  const tags = { Project: 'mem9-on-aws', Stage: stage };
  for (const [i, name] of sourceNames.entries()) {
    const ref = credentialBindings[name], store = i < 3 ? 'ssm' : 'secretsmanager';
    requireValue(ref && ref.store === store && ref.region === region &&
      ref.endpoint === `https://${store}.${region}.${suffix}` &&
      ref.valueType === (i === 0 ? 'String' : i < 3 ? 'SecureString' : 'SecretString') &&
      /^[a-f0-9]{64}$/u.test(ref.sha256 ?? '') && Number.isSafeInteger(ref.bytesLength) && ref.bytesLength > 0);
    requireValue(i < 3 ? Number.isSafeInteger(ref.version) && ref.version > 0 : /^[A-Za-z0-9_-]{32,64}$/u.test(ref.version ?? ''));
    const prefix = i < 3 ? `arn:${partition}:ssm:${region}:${accountId}:parameter/mem9-on-aws/${stage}/${parameterPaths[i]}`
      : `arn:${partition}:secretsmanager:${region}:${accountId}:secret:mem9-on-aws-${stage}-${secretFamilies[i - 3]}-`;
    if (i < 3) requireValue(ref.arn === prefix);
    else {
      requireValue(typeof ref.arn === 'string' && ref.arn.startsWith(prefix));
      tags[OBSERVER_POLICY_TAGS[i - 1]] = ref.arn.slice(prefix.length);
    }
    if (i === 0) { requireValue(ref.kms === null); continue; }
    const via = `${store}.${region}.${suffix}`, keyPrefix = `arn:${partition}:kms:${region}:${accountId}:key/`;
    requireValue(ref.kms && typeof ref.kms.keyArn === 'string' && ref.kms.keyArn.startsWith(keyPrefix) &&
      ref.kms.viaService === via && ref.kms.contextKey === (i < 3 ? 'PARAMETER_ARN' : 'SecretARN') && ref.kms.contextValue === ref.arn);
    const key = i < 3 ? 'ObserverSsmKeyId' : 'ObserverSecretKeyId', value = ref.kms.keyArn.slice(keyPrefix.length);
    requireValue(tags[key] === undefined || tags[key] === value);
    tags[key] = value;
  }
  return assertObserverRoleTags(roleName, tags);
}

function literalCutoff(cutoff) {
  requireValue(typeof cutoff === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/u.test(cutoff) &&
    Number.isFinite(Date.parse(cutoff)) && new Date(cutoff).toISOString() === cutoff);
  return cutoff;
}
function roleDocuments(roleName, tags, cutoff, contract) {
  literalCutoff(cutoff);
  tags = assertObserverRoleTags(roleName, tags);
  const { partition, accountId, applicationRegion } = identity(contract);
  const { parameters, secrets, keys, via } = resources(contract, tags);
  return { tags, permissionsBoundaryArn: observerBoundaryArn(contract),
    assumeRolePolicyDocument: { Version: '2012-10-17', Statement: [{ Effect: 'Allow',
      Principal: { Service: 'ecs-tasks.amazonaws.com' }, Action: 'sts:AssumeRole',
      Condition: { StringEquals: { 'aws:SourceAccount': accountId },
        ArnLike: { 'aws:SourceArn': `arn:${partition}:ecs:${applicationRegion}:${accountId}:*` },
        DateLessThan: { 'aws:CurrentTime': cutoff } } }] },
    policyDocument: { Version: '2012-10-17', Statement: [
      { Effect: 'Allow', Action: 'ssm:GetParameter', Resource: parameters },
      { Effect: 'Allow', Action: 'secretsmanager:GetSecretValue', Resource: secrets },
      ...keys.map((key, i) => ({ Effect: 'Allow', Action: 'kms:Decrypt', Resource: key,
        Condition: { StringEquals: { 'kms:ViaService': via[i],
          ['kms:EncryptionContext:' + (i === 0 ? 'PARAMETER_ARN' : 'SecretARN')]: i === 0 ? parameters.slice(1) : secrets } } })),
      { Sid: 'Expired', Effect: 'Deny', Action: '*', Resource: '*',
        Condition: { DateGreaterThanEquals: { 'aws:CurrentTime': cutoff } } },
    ] },
  };
}
export function observerRoleDocuments(selection, contract) {
  return roleDocuments(selection.roleName, observerRoleTags(selection, contract), selection.cutoff, contract);
}

function document(value) {
  if (typeof value === 'string') value = JSON.parse(value.trimStart().startsWith('{') ? value : decodeURIComponent(value));
  requireValue(value && typeof value === 'object');
  return value;
}

/** Inventory permits expired roles for cleanup, but never changes their cutoff.
 * The issuer supplies expected source refs; owner inventory independently checks
 * structure and pins its first complete read for the remaining rollout. */
export function assertObserverRole(roleName, role, contract, expected) {
  if (observerRoleStage(roleName) === undefined) return undefined;
  const { partition, accountId } = identity(contract);
  requireValue(role?.arn === `arn:${partition}:iam::${accountId}:role/${roleName}` &&
    role.permissionsBoundaryArn === observerBoundaryArn(contract) && Array.isArray(role.tags) &&
    role.tags.every(t => t && typeof t.Key === 'string' && typeof t.Value === 'string') &&
    new Set(role.tags.map(t => t.Key.toLowerCase())).size === role.tags.length &&
    Array.isArray(role.attachedPolicyArns) && role.attachedPolicyArns.length === 0 &&
    Array.isArray(role.inlinePolicies) && role.inlinePolicies.length === 1 && role.inlinePolicies[0].name === 'ObserverReadOnly');
  const tags = assertObserverRoleTags(roleName, Object.fromEntries(role.tags.map(t => [t.Key, t.Value])));
  const trust = document(role.assumeRolePolicyDocument);
  const cutoff = literalCutoff(trust.Statement?.[0]?.Condition?.DateLessThan?.['aws:CurrentTime']);
  const docs = roleDocuments(roleName, tags, cutoff, contract);
  requireValue(isDeepStrictEqual(trust, docs.assumeRolePolicyDocument) &&
    isDeepStrictEqual(document(role.inlinePolicies[0].document), docs.policyDocument));
  if (expected !== undefined) {
    requireValue(expected.roleName === roleName && isDeepStrictEqual(docs, observerRoleDocuments(expected, contract)));
  }
  return docs;
}

/** Fixed synthetic probes for the original owner verifier; never workload data. */
export function observerBoundaryProbeCases(contract) {
  expectedObserverBoundaryPolicyDocument(contract);
  const tags = { Project: 'mem9-on-aws', Stage: 'pr-7', ObserverTenantSuffix: 'fixture-A1b2c3',
    NamespaceIdentitySuffix: 'fixture-D4e5f6', ObserverSsmKeyId: '00000000-0000-0000-0000-aaaaaaaaaaaa',
    ObserverSecretKeyId: '00000000-0000-0000-0000-bbbbbbbbbbbb' };
  const { partition, accountId, applicationRegion } = identity(contract);
  const { parameters, secrets, keys, via } = resources(contract, tags);
  const base = { ...Object.fromEntries(Object.entries(tags).map(([key, value]) => ['aws:PrincipalTag/' + key, value])),
    'aws:PrincipalArn': `arn:${partition}:iam::${accountId}:role/mem9-on-aws-pr-7-ObserverControlTaskRole-012345abcdef`,
    'aws:RequestedRegion': applicationRegion };
  const probes = [];
  const add = (name, expected, action, resource, context = base) => probes.push({ name, expected, action, resource, context });
  const sources = [...parameters, ...secrets];
  for (const [i, resource] of sources.entries()) add('allow-' + sourceNames[i], 'allowed', i < 3 ? actions[0] : actions[1], resource);
  for (const i of [1, 2, 3, 4]) {
    const group = i < 3 ? 0 : 1, key = keys[group], field = sourceNames[i];
    const contextKey = 'kms:EncryptionContext:' + (group === 0 ? 'PARAMETER_ARN' : 'SecretARN');
    const context = { ...base, 'kms:ViaService': via[group], [contextKey]: sources[i] };
    add('allow-kms-' + field, 'allowed', actions[2], key, context);
    for (const [label, absent] of [['direct-kms', 'kms:ViaService'], ['missing-context', contextKey]]) {
      const missing = { ...context }; delete missing[absent];
      add('deny-' + label + '-' + field, 'explicitDeny', actions[2], key, missing);
    }
    add('deny-viaservice-' + field, 'explicitDeny', actions[2], key, { ...context, 'kms:ViaService': via[1 - group] });
    add('deny-context-' + field, 'explicitDeny', actions[2], key, { ...context, [contextKey]: sources[i] + '-other' });
  }
  for (const action of ['iam:TagRole','sts:AssumeRole','sts:TagSession','ecs:DescribeTasks','ssmmessages:OpenDataChannel',
    'ssm:GetParameters','ssm:GetParametersByPath','ssm:PutParameter','secretsmanager:PutSecretValue','kms:GenerateDataKey','s3:GetObject']) {
    add('deny-action-' + action, 'explicitDeny', action, '*');
  }
  for (const tag of OBSERVER_POLICY_TAGS) {
    const context = { ...base }; delete context['aws:PrincipalTag/' + tag];
    add('deny-missing-tag-' + tag, 'explicitDeny', actions[0], parameters[0], context);
  }
  for (const [name, key, value] of [
    ['project', 'aws:PrincipalTag/Project', 'other'], ['stage', 'aws:PrincipalTag/Stage', 'pr-8'],
    ['prod', 'aws:PrincipalTag/Stage', 'prod'], ['region', 'aws:RequestedRegion', 'us-west-2'],
    ['role', 'aws:PrincipalArn', base['aws:PrincipalArn'].replace('ObserverControlTaskRole','Mem9BootstrapTaskRole')],
    ['account', 'aws:PrincipalArn', base['aws:PrincipalArn'].replace(accountId,'9'.repeat(12))],
  ]) add('deny-' + name, 'explicitDeny', actions[0], parameters[0], { ...base, [key]: value });
  for (const i of [0, 3, 4]) {
    const action = i === 0 ? actions[0] : actions[1];
    add('deny-other-stage-' + sourceNames[i], 'explicitDeny', action, sources[i].replace('pr-7','prod'));
    add('deny-other-resource-' + sourceNames[i], 'explicitDeny', action, sources[i] + '-other');
  }
  add('deny-other-key', 'explicitDeny', actions[2], keys[0].slice(0,-1) + '0',
    { ...base, 'kms:ViaService': via[0], 'kms:EncryptionContext:PARAMETER_ARN': parameters[1] });
  return probes;
}
