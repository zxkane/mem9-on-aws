import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { parseDocument } from 'yaml';
import { parseStrictJson } from './authorization-archive-policy.mjs';

export const RETAINED_OPERATOR_ROLE_NAMES = Object.freeze([
  'mem9-on-aws-namespace-operator', 'mem9-on-aws-preview-human-acceptance',
]);
const NAMESPACE = 'memory-namespace-operator-mem9-on-aws';
const DEPLOYMENT = 'github-actions-mem9-on-aws';
const OWNER_RESOURCE_TYPES = {
  [NAMESPACE]: ['AWS::IAM::Role'],
  [DEPLOYMENT]: ['AWS::IAM::Role', 'AWS::IAM::ManagedPolicy', 'AWS::IAM::Policy', 'AWS::IAM::OIDCProvider'],
};
const ROLE_NAMES = Object.freeze({
  MemoryNamespaceOperatorRole: RETAINED_OPERATOR_ROLE_NAMES[0],
  PreviewHumanAcceptanceRole: RETAINED_OPERATOR_ROLE_NAMES[1],
  GitHubActionsRole: DEPLOYMENT,
  GitHubPreviewActionsRole: `${DEPLOYMENT}-preview`,
  GitHubProductionActionsRole: `${DEPLOYMENT}-prod`,
});
const FILES = {
  [NAMESPACE]: new URL('../../infra/cloudformation/memory-namespace-operator-role.yaml', import.meta.url),
  [DEPLOYMENT]: new URL('../../infra/cloudformation/github-actions-role.yaml', import.meta.url),
};
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v) &&
  [Object.prototype, null].includes(Object.getPrototypeOf(v));
const fail = () => { throw new Error('Retained operator ownership or catalog verification failed'); };
const requireValue = value => { if (!value) fail(); };
function fields(value, required, optional = []) {
  requireValue(object(value) && required.every(k => Object.hasOwn(value, k)) &&
    Object.keys(value).every(k => required.includes(k) || optional.includes(k)));
}
const text = v => typeof v === 'string' && v.length > 0 && v.length <= 2048;
const canonical = v => Array.isArray(v) ? v.map(canonical) : object(v)
  ? Object.fromEntries(Object.keys(v).sort().map(k => [k, canonical(v[k])])) : v;
const key = v => JSON.stringify(canonical(v));
const equal = (a, b) => requireValue(isDeepStrictEqual(a, b));
function unique(values) {
  requireValue(Array.isArray(values) && new Set(values.map(key)).size === values.length);
  return values;
}
function values(value) {
  const result = Array.isArray(value) ? value : [value];
  requireValue(result.length > 0 && result.every(v => typeof v === 'string' || typeof v === 'boolean' || (typeof v === 'number' && Number.isFinite(v))));
  unique(result);
  return result.slice().sort((a, b) => key(a).localeCompare(key(b)));
}
function json(value) {
  if (typeof value === 'string') {
    try { value = parseStrictJson(value.trimStart().startsWith('{') ? value : decodeURIComponent(value)); }
    catch { fail(); }
  }
  requireValue(object(value));
  return value;
}
function policy(value, kind) {
  const document = json(value);
  fields(document, ['Statement'], ['Version', 'Id']);
  if ('Version' in document) requireValue(['2008-10-17', '2012-10-17'].includes(document.Version));
  if ('Id' in document) requireValue(typeof document.Id === 'string');
  const statements = Array.isArray(document.Statement) ? document.Statement : [document.Statement];
  requireValue(statements.length > 0);
  const normalized = statements.map(statement => {
    fields(statement, ['Effect'], ['Sid', 'Action', 'NotAction', 'Resource', 'NotResource', 'Principal', 'NotPrincipal', 'Condition']);
    requireValue(['Allow', 'Deny'].includes(statement.Effect) &&
      Object.hasOwn(statement, 'Action') !== Object.hasOwn(statement, 'NotAction'));
    requireValue(kind === 'trust'
      ? (Object.hasOwn(statement, 'Principal') !== Object.hasOwn(statement, 'NotPrincipal')) && !('Resource' in statement) && !('NotResource' in statement)
      : (Object.hasOwn(statement, 'Resource') !== Object.hasOwn(statement, 'NotResource')) && !('Principal' in statement) && !('NotPrincipal' in statement));
    const result = { ...statement };
    if ('Sid' in result) requireValue(typeof result.Sid === 'string');
    for (const field of ['Action', 'NotAction', 'Resource', 'NotResource']) if (field in result) {
      result[field] = values(result[field]); requireValue(result[field].every(text));
    }
    for (const field of ['Principal', 'NotPrincipal']) if (field in result) {
      if (typeof result[field] === 'string') { requireValue(result[field] === '*'); continue; }
      const principal = result[field]; fields(principal, [], ['AWS', 'Service', 'Federated', 'CanonicalUser']);
      requireValue(Object.keys(principal).length > 0);
      result[field] = Object.fromEntries(Object.entries(principal).map(([k, v]) => { const entries = values(v); requireValue(entries.every(text)); return [k, entries]; }));
    }
    if ('Condition' in result) {
      requireValue(object(result.Condition) && Object.keys(result.Condition).length > 0);
      result.Condition = Object.fromEntries(Object.entries(result.Condition).map(([operator, conditions]) => {
        requireValue(text(operator) && object(conditions) && Object.keys(conditions).length > 0);
        return [operator, Object.fromEntries(Object.entries(conditions).map(([name, v]) => { requireValue(text(name)); return [name, values(v)]; }))];
      }));
    }
    return canonical(result);
  });
  unique(normalized);
  unique(normalized.filter(s => 'Sid' in s).map(s => s.Sid));
  // Preserve envelope fields so retained-policy comparison detects additions.
  return { ...document, Statement: normalized.sort((a, b) => key(a).localeCompare(key(b))) };
}
function template(value) {
  if (typeof value === 'string') {
    requireValue(Buffer.byteLength(value) <= 1024 * 1024);
    // JSON and YAML flow mappings can both start with "{". The YAML parser
    // accepts both formats while retaining duplicate-key and intrinsic checks.
    try {
      const document = parseDocument(value, { uniqueKeys: true, prettyErrors: false, customTags: [
        ...['Ref', 'Sub', 'GetAtt'].map(name => ({ tag: '!' + name, resolve: v => ({ [name === 'Ref' ? name : 'Fn::' + name]: v }) })),
        ...['If', 'Equals', 'Not'].map(name => ({ tag: '!' + name, collection: 'seq', resolve: v => ({ ['Fn::' + name]: v.toJSON() }) })),
      ] });
      requireValue(!document.errors.length && !document.warnings.length);
      value = document.toJS({ maxAliasCount: 0 });
    } catch { fail(); }
  }
  fields(value, ['Resources'], ['AWSTemplateFormatVersion', 'Description', 'Parameters', 'Conditions', 'Outputs', 'Metadata', 'Mappings']);
  requireValue(object(value.Resources) && object(value.Parameters) && object(value.Outputs));
  return value;
}
function pairs(rows, name, value, optional = []) {
  requireValue(Array.isArray(rows));
  const result = {};
  for (const row of rows) {
    fields(row, [name, value], optional);
    requireValue(text(row[name]) && typeof row[value] === 'string' && !Object.hasOwn(result, row[name]));
    Object.defineProperty(result, row[name], { value: row[value], enumerable: true });
  }
  return result;
}

/** Read-only. The guarded wrapper pins this module and its adjacent source.
 * No input role-name prefix or caller-provided allowlist establishes ownership. */
export function createRetainedOperatorInventory(options) {
  fields(options, ['invokeAws', 'identity', 'applicationRegion']);
  const { invokeAws, identity, applicationRegion } = options;
  fields(identity, ['partition', 'accountId']);
  const { partition, accountId } = identity;
  requireValue(typeof invokeAws === 'function' && typeof partition === 'string' && /^aws(?:-cn|-us-gov)?$/u.test(partition) &&
    typeof accountId === 'string' && /^\d{12}$/u.test(accountId) && typeof applicationRegion === 'string' && /^[a-z]{2}(?:-[a-z0-9]+)+-\d+$/u.test(applicationRegion));
  const sourceBytes = Object.fromEntries(Object.entries(FILES).map(([name, file]) => [name, readFileSync(file, 'utf8')]));
  const sources = Object.fromEntries(Object.entries(sourceBytes).map(([name, raw]) => [name, template(raw)]));
  const arn = name => `arn:${partition}:iam::${accountId}:role/${name}`;
  const expectedIds = stack => stack === NAMESPACE ? ['MemoryNamespaceOperatorRole'] : Object.keys(ROLE_NAMES).filter(k => k !== 'MemoryNamespaceOperatorRole').sort();
  function declaredRoles(document, stack) {
    for (const resource of Object.values(document.Resources))
      requireValue(object(resource) && OWNER_RESOURCE_TYPES[stack].includes(resource.Type));
    const ids = Object.keys(document.Resources).filter(k => document.Resources[k].Type === 'AWS::IAM::Role').sort();
    equal(ids, expectedIds(stack));
    for (const id of ids) requireValue(!Object.hasOwn(document.Resources[id], 'Condition') && object(document.Resources[id].Properties));
    return ids;
  }
  for (const [name, source] of Object.entries(sources)) declaredRoles(source, name);
  const checkSource = () => { for (const [name, path] of Object.entries(FILES)) equal(readFileSync(path, 'utf8'), sourceBytes[name]); };
  async function read(args) {
    let result;
    try { result = await invokeAws(args); } catch { throw new Error('Retained operator metadata read failed'); }
    return typeof result === 'string' ? json(result) : result;
  }
  const cf = (operation, stack, ...args) => read(['cloudformation', operation, '--stack-name', stack, '--region', 'us-west-2', ...args]);
  const iam = (operation, role, ...args) => read(['iam', operation, '--role-name', role, '--region', 'us-east-1', ...args]);
  async function pages(fetch, field, iamPages = false) {
    const rows = [], tokens = new Set(); let token;
    for (let page = 0; page < 100; page++) {
      const response = await fetch(token);
      fields(response, [field, ...(iamPages ? ['IsTruncated'] : [])], [iamPages ? 'Marker' : 'NextToken']);
      requireValue(Array.isArray(response[field])); rows.push(...response[field]); requireValue(rows.length <= 10000);
      if (iamPages) requireValue(typeof response.IsTruncated === 'boolean');
      const next = iamPages ? response.Marker : response.NextToken;
      if (iamPages ? !response.IsTruncated : next === undefined) {
        requireValue(next === undefined); return rows;
      }
      requireValue(text(next) && !tokens.has(next)); tokens.add(next); token = next;
    }
    fail();
  }
  function render(value, document, parameters, depth = 0) {
    requireValue(depth < 100);
    const noValue = undefined;
    if (Array.isArray(value)) return value.map(v => render(v, document, parameters, depth + 1)).filter(v => v !== noValue);
    if (!object(value)) return value;
    if ('Ref' in value) {
      fields(value, ['Ref']); if (value.Ref === 'AWS::NoValue') return noValue;
      requireValue(Object.hasOwn(parameters, value.Ref)); return parameters[value.Ref];
    }
    if ('Fn::Sub' in value) {
      fields(value, ['Fn::Sub']); requireValue(typeof value['Fn::Sub'] === 'string');
      return value['Fn::Sub'].replace(/\$\{([^}]+)\}/gu, (_, name) => { requireValue(typeof parameters[name] === 'string'); return parameters[name]; });
    }
    if ('Fn::If' in value) {
      fields(value, ['Fn::If']); const expression = value['Fn::If']; requireValue(Array.isArray(expression) && expression.length === 3);
      const [name, yes, no] = expression; requireValue(Object.hasOwn(document.Conditions ?? {}, name));
      const condition = render(document.Conditions[name], document, parameters, depth + 1); requireValue(typeof condition === 'boolean');
      return render(condition ? yes : no, document, parameters, depth + 1);
    }
    if ('Fn::Equals' in value) {
      fields(value, ['Fn::Equals']); requireValue(Array.isArray(value['Fn::Equals']) && value['Fn::Equals'].length === 2);
      return isDeepStrictEqual(...value['Fn::Equals'].map(v => render(v, document, parameters, depth + 1)));
    }
    if ('Fn::Not' in value) {
      fields(value, ['Fn::Not']); requireValue(Array.isArray(value['Fn::Not']) && value['Fn::Not'].length === 1);
      const condition = render(value['Fn::Not'][0], document, parameters, depth + 1); requireValue(typeof condition === 'boolean'); return !condition;
    }
    requireValue(!Object.keys(value).some(k => k.startsWith('Fn::')));
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, render(v, document, parameters, depth + 1)]).filter(([, v]) => v !== noValue));
  }
  async function owner(name) {
    const response = await cf('describe-stacks', name); fields(response, ['Stacks'], ['NextToken']);
    requireValue(response.NextToken === undefined && Array.isArray(response.Stacks) && response.Stacks.length === 1);
    const stack = response.Stacks[0];
    fields(stack, ['StackName', 'StackId', 'StackStatus', 'Parameters', 'Outputs'], ['CreationTime', 'LastUpdatedTime', 'Description', 'ChangeSetId',
      'DeletionTime', 'RollbackConfiguration', 'StackStatusReason', 'DisableRollback', 'NotificationARNs', 'TimeoutInMinutes', 'Capabilities', 'Tags',
      'EnableTerminationProtection', 'DriftInformation', 'RetainExceptOnCreate', 'DeletionMode', 'LastOperations', 'DetailedStatus']);
    const prefix = `arn:${partition}:cloudformation:us-west-2:${accountId}:stack/${name}/`;
    requireValue(stack.StackName === name && typeof stack.StackId === 'string' && stack.StackId.startsWith(prefix) && /^[A-Za-z0-9-]+$/u.test(stack.StackId.slice(prefix.length)) &&
      ['CREATE_COMPLETE', 'UPDATE_COMPLETE'].includes(stack.StackStatus));
    const parameters = pairs(stack.Parameters, 'ParameterKey', 'ParameterValue', ['UsePreviousValue', 'ResolvedValue']);
    const source = sources[name];
    requireValue(Object.keys(parameters).every(k => Object.hasOwn(source.Parameters, k)) && parameters.ApplicationRegion === applicationRegion);
    if (name === NAMESPACE) {
      requireValue(parameters.Stage === 'prod' && typeof parameters.CognitoUserPoolId === 'string' &&
        (parameters.CognitoUserPoolId === '' || (parameters.CognitoUserPoolId.startsWith(applicationRegion + '_') && /^[a-z0-9-]+_[A-Za-z0-9]+$/u.test(parameters.CognitoUserPoolId))));
    } else requireValue(parameters.ProjectName === 'mem9-on-aws' && parameters.GitHubRepo === 'mem9-on-aws' && ['true', 'false'].includes(parameters.LegacyRoleEnabled));
    const summaries = await pages(token => cf('list-stack-resources', stack.StackId, '--no-paginate', ...(token ? ['--next-token', token] : [])), 'StackResourceSummaries');
    const logical = new Map();
    for (const item of summaries) {
      fields(item, ['LogicalResourceId', 'PhysicalResourceId', 'ResourceType', 'ResourceStatus'], ['LastUpdatedTimestamp', 'ResourceStatusReason', 'DriftInformation', 'ModuleInfo']);
      requireValue(text(item.LogicalResourceId) && text(item.PhysicalResourceId) && OWNER_RESOURCE_TYPES[name].includes(item.ResourceType) && !logical.has(item.LogicalResourceId)); logical.set(item.LogicalResourceId, item);
    }
    const fetched = await cf('get-template', stack.StackId, '--template-stage', 'Original'); fields(fetched, ['TemplateBody'], ['StagesAvailable']);
    if ('StagesAvailable' in fetched) requireValue(Array.isArray(fetched.StagesAvailable) && unique(fetched.StagesAvailable).every(v => ['Original', 'Processed'].includes(v)));
    const live = template(fetched.TemplateBody), ids = declaredRoles(live, name);
    equal(summaries.filter(s => s.ResourceType === 'AWS::IAM::Role').map(s => s.LogicalResourceId).sort(), ids);
    // Only role declarations and their conditions are frozen. The intended
    // managed-policy and independent CI inline-policy updates remain possible.
    for (const id of ids) {
      equal(live.Resources[id], source.Resources[id]);
      const actual = logical.get(id); requireValue(actual && actual.PhysicalResourceId === ROLE_NAMES[id] && ['CREATE_COMPLETE', 'UPDATE_COMPLETE', 'IMPORT_COMPLETE'].includes(actual.ResourceStatus));
      equal(render(source.Resources[id].Properties.RoleName, source, parameters), ROLE_NAMES[id]);
    }
    equal(live.Conditions ?? {}, source.Conditions ?? {});
    const output = pairs(stack.Outputs, 'OutputKey', 'OutputValue', ['Description', 'ExportName']);
    const outputs = name === NAMESPACE ? { RoleArn: 'MemoryNamespaceOperatorRole' } :
      { RoleArn: 'GitHubActionsRole', LegacyRoleArn: 'GitHubActionsRole', PreviewRoleArn: 'GitHubPreviewActionsRole', ProductionRoleArn: 'GitHubProductionActionsRole' };
    equal(Object.keys(output).sort(), Object.keys(outputs).sort());
    for (const [label, id] of Object.entries(outputs)) {
      equal(source.Outputs[label]?.Value, { 'Fn::GetAtt': `${id}.Arn` }); equal(live.Outputs[label]?.Value, source.Outputs[label].Value); equal(output[label], arn(ROLE_NAMES[id]));
    }
    return { stackId: stack.StackId, source, parameters, ids,
      renderParameters: { ...parameters, 'AWS::Partition': partition, 'AWS::AccountId': accountId, 'AWS::Region': 'us-west-2' } };
  }
  function roleIdentity(role) {
    fields(role, ['RoleName', 'RoleId', 'Arn', 'Path', 'CreateDate'], ['AssumeRolePolicyDocument', 'Description', 'MaxSessionDuration', 'PermissionsBoundary', 'Tags', 'RoleLastUsed', 'SourceRoleTemplate']);
    requireValue(typeof role.RoleName === 'string' && /^[\w+=,.@-]{1,64}$/u.test(role.RoleName) && typeof role.RoleId === 'string' && /^\w{16,128}$/u.test(role.RoleId) &&
      typeof role.Path === 'string' && role.Path.length <= 512 && /^(?:\/|\/[\x21-\x7e]+\/)$/u.test(role.Path) &&
      role.Arn === `arn:${partition}:iam::${accountId}:role${role.Path}${role.RoleName}` && typeof role.CreateDate === 'string' && Number.isFinite(Date.parse(role.CreateDate)));
    if ('MaxSessionDuration' in role) requireValue(Number.isInteger(role.MaxSessionDuration) && role.MaxSessionDuration >= 3600 && role.MaxSessionDuration <= 43200);
    if ('Description' in role) requireValue(typeof role.Description === 'string');
    if ('PermissionsBoundary' in role) {
      fields(role.PermissionsBoundary, ['PermissionsBoundaryType', 'PermissionsBoundaryArn']); requireValue(role.PermissionsBoundary.PermissionsBoundaryType === 'Policy' && text(role.PermissionsBoundary.PermissionsBoundaryArn));
    }
    if ('RoleLastUsed' in role) {
      fields(role.RoleLastUsed, [], ['LastUsedDate', 'Region']);
      if ('LastUsedDate' in role.RoleLastUsed) requireValue(role.RoleLastUsed.LastUsedDate === null ||
        (typeof role.RoleLastUsed.LastUsedDate === 'string' && Number.isFinite(Date.parse(role.RoleLastUsed.LastUsedDate))));
      if ('Region' in role.RoleLastUsed) requireValue(text(role.RoleLastUsed.Region));
    }
    if ('SourceRoleTemplate' in role) {
      fields(role.SourceRoleTemplate, ['TemplateArn', 'TemplateMinorVersion']);
      requireValue(text(role.SourceRoleTemplate.TemplateArn) && role.SourceRoleTemplate.TemplateArn.length >= 20 &&
        /^arn:[^:]+:[^:]+:[^:]*:[^:]*:.+$/u.test(role.SourceRoleTemplate.TemplateArn) && Number.isInteger(role.SourceRoleTemplate.TemplateMinorVersion));
    }
    const retained = RETAINED_OPERATOR_ROLE_NAMES.includes(role.RoleName);
    requireValue(!retained || (Object.hasOwn(role, 'AssumeRolePolicyDocument') && !Object.hasOwn(role, 'SourceRoleTemplate')));
    const tags = 'Tags' in role ? pairs(role.Tags, 'Key', 'Value') : {};
    return { name: role.RoleName, arn: role.Arn, id: role.RoleId, path: role.Path, created: role.CreateDate,
      // Only the two retained operators use this module's policy contract.
      // Other trust documents are decoded losslessly for identity snapshots;
      // the existing project Lambda verifier and governance checks own their
      // semantics. filterRoles returns the original AWS records unchanged.
      trust: Object.hasOwn(role, 'AssumeRolePolicyDocument')
        ? retained ? policy(role.AssumeRolePolicyDocument, 'trust') : json(role.AssumeRolePolicyDocument)
        : null,
      tags, maximumSession: role.MaxSessionDuration ?? null,
      boundary: 'PermissionsBoundary' in role ? role.PermissionsBoundary : null };
  }
  async function getRole(name) {
    const response = await iam('get-role', name); fields(response, ['Role']);
    requireValue(object(response.Role) && Object.hasOwn(response.Role, 'AssumeRolePolicyDocument') && !Object.hasOwn(response.Role, 'SourceRoleTemplate'));
    const record = roleIdentity(response.Role); requireValue(record.name === name && record.arn === arn(name) && record.path === '/');
    return { raw: response.Role, record };
  }
  async function names(name) {
    const result = await pages(token => iam('list-role-policies', name, '--no-paginate', ...(token ? ['--marker', token] : [])), 'PolicyNames', true);
    requireValue(result.every(text)); return unique(result).sort();
  }
  async function noManaged(name) {
    const result = await pages(token => iam('list-attached-role-policies', name, '--no-paginate', ...(token ? ['--marker', token] : [])), 'AttachedPolicies', true);
    requireValue(result.length === 0);
  }
  async function retainedRole(ownership, id) {
    const name = ROLE_NAMES[id], resource = ownership.source.Resources[id];
    fields(resource, ['Type', 'DeletionPolicy', 'UpdateReplacePolicy', 'Properties']);
    requireValue(resource.DeletionPolicy === 'Retain' && resource.UpdateReplacePolicy === 'Retain');
    const expected = render(resource.Properties, ownership.source, ownership.renderParameters);
    fields(expected, ['RoleName', 'Description', 'AssumeRolePolicyDocument', 'Policies', 'Tags'], ['MaxSessionDuration', 'Path']);
    const before = await getRole(name); requireValue(!Object.hasOwn(before.raw, 'PermissionsBoundary'));
    equal(before.record.trust, policy(expected.AssumeRolePolicyDocument, 'trust'));
    equal(before.record.maximumSession, expected.MaxSessionDuration ?? 3600);
    const tags = pairs(expected.Tags, 'Key', 'Value'); for (const [k, v] of Object.entries(tags)) equal(before.record.tags[k], v);
    requireValue(Array.isArray(expected.Policies));
    const expectedPolicies = {};
    for (const entry of expected.Policies) { fields(entry, ['PolicyName', 'PolicyDocument']); requireValue(text(entry.PolicyName) && !Object.hasOwn(expectedPolicies, entry.PolicyName)); expectedPolicies[entry.PolicyName] = policy(entry.PolicyDocument, 'inline'); }
    const inlineNames = await names(name); equal(inlineNames, Object.keys(expectedPolicies).sort()); await noManaged(name);
    const actualPolicies = {};
    for (const policyName of inlineNames) {
      const response = await iam('get-role-policy', name, '--policy-name', policyName); fields(response, ['RoleName', 'PolicyName', 'PolicyDocument']);
      requireValue(response.RoleName === name && response.PolicyName === policyName); actualPolicies[policyName] = policy(response.PolicyDocument, 'inline');
    }
    equal(actualPolicies, expectedPolicies); equal(await names(name), inlineNames); await noManaged(name);
    const after = await getRole(name); requireValue(!Object.hasOwn(after.raw, 'PermissionsBoundary')); equal(before.record, after.record);
    return { owner: ownership.stackId, logicalId: id, parameters: ownership.parameters, role: before.record, policies: actualPolicies };
  }
  async function recheckOwner(name, before) {
    const after = await owner(name);
    equal(after.stackId, before.stackId); equal(after.parameters, before.parameters);
  }
  let frozen, catalog, usable = false, queue = Promise.resolve();
  const serialized = task => {
    const result = queue.then(async () => { checkSource(); try { return await task(); } catch (error) { usable = false; throw error; } });
    queue = result.catch(() => {}); return result;
  };
  return Object.freeze({
    verify: () => serialized(async () => {
      usable = false;
      const namespace = await owner(NAMESPACE), deployment = await owner(DEPLOYMENT);
      const current = [await retainedRole(namespace, 'MemoryNamespaceOperatorRole'), await retainedRole(deployment, 'PreviewHumanAcceptanceRole')];
      await recheckOwner(NAMESPACE, namespace); await recheckOwner(DEPLOYMENT, deployment);
      // The new bucket parameter is unrelated to retained-operator authority.
      current[1].parameters = Object.fromEntries(['ApplicationRegion', 'ProjectName', 'GitHubRepo', 'LegacyRoleEnabled'].map(k => [k, deployment.parameters[k]]));
      checkSource(); if (frozen) equal(current, frozen); else frozen = current;
      usable = true; return [...RETAINED_OPERATOR_ROLE_NAMES];
    }),
    verifyDeploymentRoleCatalog: () => serialized(async () => {
      const ownership = await owner(DEPLOYMENT), roles = [];
      for (const id of ownership.ids) { const role = await getRole(ROLE_NAMES[id]); roles.push({ logicalId: id, ...role.record }); }
      await recheckOwner(DEPLOYMENT, ownership);
      const parameters = Object.fromEntries(Object.entries(ownership.parameters).filter(([k]) => k !== 'DecisionArtifactBucketName'));
      const current = { owner: ownership.stackId, roles, parameters };
      checkSource(); if (catalog) equal(current, catalog); else catalog = current;
    }),
    filterRoles(rawAwsRoles) {
      checkSource(); requireValue(usable && frozen && Array.isArray(rawAwsRoles));
      const records = rawAwsRoles.map(roleIdentity);
      for (const field of ['name', 'arn', 'id']) unique(records.map(r => r[field]));
      records.forEach(record => {
        if (!RETAINED_OPERATOR_ROLE_NAMES.includes(record.name)) return;
        const original = frozen.find(v => v.role.name === record.name).role;
        requireValue(record.arn === original.arn && record.id === original.id && record.path === '/');
        equal(record.trust, original.trust); requireValue(record.boundary === null);
      });
      return rawAwsRoles.filter(role => !RETAINED_OPERATOR_ROLE_NAMES.includes(role.RoleName));
    },
  });
}
