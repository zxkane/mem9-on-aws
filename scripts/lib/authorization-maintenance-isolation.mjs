import { isDeepStrictEqual, promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

class IsolationValidationError extends Error {}

function requireValue(condition, message) {
  if (!condition) throw new IsolationValidationError(message);
}

export function validateDecisionArtifactBucketName(name) {
  requireValue(typeof name === 'string' && /^[a-z0-9][a-z0-9-]{1,31}[a-z0-9]$/u.test(name) &&
    !/^(?:xn--|sthree-|amzn-s3-demo-)/u.test(name) && !/(?:-s3alias|--ol-s3|--x-s3|--table-s3|-an)$/u.test(name),
  'invalid decision-artifact bucket name (expected 3-33 characters)');
  return name;
}

function contract({ partition = 'aws', accountId, applicationRegion,
  decisionArtifactBucketName = `mem9-audit-${accountId}`, projectName = 'mem9-on-aws', githubRepo = 'mem9-on-aws' }) {
  requireValue(typeof partition === 'string' && /^aws(?:-us-gov|-cn)?$/u.test(partition), 'invalid AWS partition');
  requireValue(typeof accountId === 'string' && /^[0-9]{12}$/u.test(accountId), 'invalid AWS account id');
  requireValue(typeof applicationRegion === 'string' && /^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$/u.test(applicationRegion), 'invalid application region');
  for (const name of [projectName, githubRepo])
    requireValue(typeof name === 'string' && /^[a-zA-Z][a-zA-Z0-9-]{0,63}$/u.test(name), 'invalid project/repository name');
  validateDecisionArtifactBucketName(decisionArtifactBucketName);
  return { partition, accountId, applicationRegion, decisionArtifactBucketName, projectName, githubRepo };
}

// Deployment Sids remain public verifier contracts; boundary Sid compaction is
// independent. Return fresh values so a caller cannot mutate a later check.
export function expectedAuthorizationMaintenanceStatements(context) {
  const { partition, accountId, applicationRegion, decisionArtifactBucketName, projectName, githubRepo } = contract(context);
  const bucket = `arn:${partition}:s3:::${decisionArtifactBucketName}`;
  return [
    { Sid: 'DenyProductionDataReleaseMutation', Effect: 'Deny',
      Action: ['ssm:PutParameter', 'ssm:DeleteParameter', 'ssm:DeleteParameters', 'ssm:AddTagsToResource',
        'ssm:RemoveTagsFromResource', 'ssm:LabelParameterVersion', 'ssm:UnlabelParameterVersion'],
      Resource: `arn:${partition}:ssm:${applicationRegion}:${accountId}:parameter/${projectName}/prod/consolidation-runtime/data-release` },
    { Sid: 'DenyAuthorizationArchiveMutation', Effect: 'Deny', NotAction: ['s3:Get*', 's3:List*'],
      Resource: [bucket, `${bucket}/data-authorizations/*`, `arn:${partition}:s3:*:*:accesspoint/*`] },
    { Sid: 'DenyS3AccessPointMutation', Effect: 'Deny',
      Action: ['s3:CreateAccessPoint', 's3:DeleteAccessPoint', 's3:CreateMultiRegionAccessPoint', 's3:DeleteMultiRegionAccessPoint',
        's3:PutAccessPointPolicy', 's3:DeleteAccessPointPolicy',
        's3:PutMultiRegionAccessPointPolicy', 's3:SubmitMultiRegionAccessPointRoutes'], Resource: '*' },
    { Sid: 'DenyOperatorOwnedStackMutation', Effect: 'Deny',
      Action: ['cloudformation:CancelUpdateStack', 'cloudformation:ContinueUpdateRollback', 'cloudformation:CreateChangeSet',
        'cloudformation:CreateStack', 'cloudformation:CreateStackRefactor', 'cloudformation:DeleteChangeSet',
        'cloudformation:DeleteStack', 'cloudformation:ExecuteChangeSet', 'cloudformation:ExecuteStackRefactor',
        'cloudformation:RecordHandlerProgress', 'cloudformation:RollbackStack', 'cloudformation:SetStackPolicy',
        'cloudformation:SignalResource', 'cloudformation:TagResource', 'cloudformation:UntagResource',
        'cloudformation:UpdateStack', 'cloudformation:UpdateTerminationProtection'],
      Resource: [`workload-permissions-boundary-${projectName}`, `github-actions-${githubRepo}`,
        `memory-namespace-operator-${projectName}`, `decision-artifact-bucket-${projectName}`]
        .map(name => `arn:${partition}:cloudformation:*:${accountId}:stack/${name}/*`) },
  ];
}

function canonicalStatement(statement) {
  requireValue(statement && typeof statement === 'object' && !Array.isArray(statement), 'invalid isolation statement');
  return Object.fromEntries(Object.entries(statement).map(([key, value]) => {
    if (!['Action', 'NotAction', 'Resource'].includes(key)) return [key, value];
    const values = Array.isArray(value) ? value : [value];
    requireValue(values.length > 0 && values.every(v => typeof v === 'string' && v.length > 0) &&
      new Set(values).size === values.length, `invalid or duplicate ${key} values`);
    return [key, [...values].sort()];
  }));
}

// Input is parsed identity policy documents, not AWS attachment wrappers. Other
// statements are left to the existing full deployment contract verifier.
export function verifyAuthorizationMaintenanceIsolation(policyDocuments, context) {
  requireValue(Array.isArray(policyDocuments) && policyDocuments.length > 0, 'missing deployment policy documents');
  const statements = policyDocuments.flatMap(document => {
    requireValue(document?.Version === '2012-10-17' && document.Statement && typeof document.Statement === 'object',
      'invalid deployment policy document');
    const rows = Array.isArray(document.Statement) ? document.Statement : [document.Statement];
    requireValue(rows.length > 0 && rows.every(s => s && typeof s === 'object' && !Array.isArray(s)), 'invalid deployment statements');
    return rows;
  });
  for (const expected of expectedAuthorizationMaintenanceStatements(context)) {
    const actual = statements.filter(s => s.Sid === expected.Sid);
    requireValue(actual.length === 1, `missing or duplicate ${expected.Sid}`);
    requireValue(isDeepStrictEqual(canonicalStatement(actual[0]), canonicalStatement(expected)), `changed ${expected.Sid}`);
  }
  return true;
}

function parameters(stack) {
  requireValue(Array.isArray(stack.Parameters), 'missing stack parameters');
  const result = new Map();
  for (const p of stack.Parameters) {
    requireValue(p && typeof p.ParameterKey === 'string' && typeof p.ParameterValue === 'string' && !result.has(p.ParameterKey),
      'invalid or duplicate stack parameter');
    result.set(p.ParameterKey, p.ParameterValue);
  }
  return result;
}

// Only authenticated metadata reads. Genuine DescribeStacks absence supports
// bootstrap ordering; a read failure or an empty success is never absence.
export async function inspectAuthorizationDeploymentBindings({ run, applicationRegion,
  decisionArtifactBucketName, stackName = 'github-actions-mem9-on-aws', mode = '' }) {
  requireValue(typeof run === 'function', 'metadata reader is required');
  requireValue(['', 'create', 'update'].includes(mode), 'invalid deployment mode');
  requireValue(stackName === 'github-actions-mem9-on-aws', 'stack name differs from source ownership contract');
  requireValue(typeof applicationRegion === 'string' && /^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$/u.test(applicationRegion), 'invalid application region');
  if (decisionArtifactBucketName !== undefined) validateDecisionArtifactBucketName(decisionArtifactBucketName);
  const identity = await run(['sts', 'get-caller-identity', '--output', 'json']);
  const match = typeof identity?.Arn === 'string' && /^arn:(aws(?:-us-gov|-cn)?):(?:iam|sts)::([0-9]{12}):\S+$/u.exec(identity.Arn);
  requireValue(match && match[2] === identity.Account, 'caller account/ARN mismatch');
  const binding = contract({ partition: match[1], accountId: identity.Account, applicationRegion, decisionArtifactBucketName });
  const readStack = async (name, region) => {
    let response;
    try { response = await run(['cloudformation', 'describe-stacks', '--stack-name', name, '--region', region, '--output', 'json']); }
    catch (error) {
      const absent = `An error occurred (ValidationError) when calling the DescribeStacks operation: Stack with id ${name} does not exist`;
      if (typeof error?.stderr === 'string' && error.stderr.trim() === absent) return null;
      throw error;
    }
    requireValue(response && !response.NextToken && Array.isArray(response.Stacks) && response.Stacks.length === 1, `incomplete stack read: ${name}`);
    const stack = response.Stacks[0];
    const prefix = `arn:${binding.partition}:cloudformation:${region}:${binding.accountId}:stack/${name}/`;
    requireValue(stack.StackName === name && typeof stack.StackId === 'string' && stack.StackId.startsWith(prefix) &&
      /^[a-zA-Z0-9-]+$/u.test(stack.StackId.slice(prefix.length)), `stack identity mismatch: ${name}`);
    requireValue(['CREATE_COMPLETE', 'UPDATE_COMPLETE', 'UPDATE_ROLLBACK_COMPLETE', 'IMPORT_COMPLETE', 'IMPORT_ROLLBACK_COMPLETE'].includes(stack.StackStatus),
      `stack is not stable: ${name}`);
    return { stackId: stack.StackId, values: parameters(stack) };
  };
  const role = await readStack(stackName, 'us-west-2');
  const actualMode = role ? 'update' : 'create';
  requireValue(!mode || mode === actualMode, 'requested mode differs from stack existence');
  if (role) {
    requireValue(role.values.get('ApplicationRegion') === applicationRegion, 'Existing GitHub Actions role belongs to another application region');
    for (const [key, expected] of [['DecisionArtifactBucketName', binding.decisionArtifactBucketName],
      ['ProjectName', binding.projectName], ['GitHubRepo', binding.githubRepo]])
      requireValue(!role.values.has(key) || role.values.get(key) === expected, `existing role ${key} binding mismatch`);
  }
  const legacyRoleEnabled = role?.values.get('LegacyRoleEnabled') ?? 'true';
  requireValue(['true', 'false'].includes(legacyRoleEnabled), 'invalid existing LegacyRoleEnabled');
  const artifactName = `decision-artifact-bucket-${binding.projectName}`;
  const artifact = await readStack(artifactName, applicationRegion);
  if (artifact) {
    requireValue(artifact.values.get('DecisionArtifactBucketName') === binding.decisionArtifactBucketName, 'artifact owner bucket binding mismatch');
    const response = await run(['cloudformation', 'describe-stack-resource', '--stack-name', artifact.stackId,
      '--logical-resource-id', 'DecisionArtifactBucket', '--region', applicationRegion, '--output', 'json']);
    const resource = response?.StackResourceDetail;
    requireValue(resource?.StackId === artifact.stackId && resource.LogicalResourceId === 'DecisionArtifactBucket' &&
      resource.ResourceType === 'AWS::S3::Bucket' && resource.PhysicalResourceId === binding.decisionArtifactBucketName &&
      ['CREATE_COMPLETE', 'UPDATE_COMPLETE', 'IMPORT_COMPLETE'].includes(resource.ResourceStatus), 'artifact owner physical bucket mismatch');
  }
  const boundary = await readStack(`workload-permissions-boundary-${binding.projectName}`, 'us-west-2');
  if (boundary) {
    requireValue(boundary.values.get('ApplicationRegion') === applicationRegion, 'boundary application region mismatch');
    requireValue(boundary.values.get('DecisionArtifactBucketName') === binding.decisionArtifactBucketName, 'boundary bucket binding mismatch');
  }
  return { ...binding, mode: actualMode, legacyRoleEnabled,
    roleStackId: role?.stackId ?? null, artifactStackId: artifact?.stackId ?? null, boundaryStackId: boundary?.stackId ?? null };
}

// Render complete managed policy documents with the actual deployment values,
// including conditions and subnet lists, before the template is uploaded.
export async function verifyAuthorizationDeploymentTemplate(templateSource, parameterValues) {
  const { parseDocument } = await import('yaml');
  const document = parseDocument(templateSource, { uniqueKeys: true, customTags: [
    ...['Ref', 'Sub', 'GetAtt'].map(name => ({ tag: '!' + name, resolve: value => ({ [name]: value }) })),
    ...['If', 'Equals', 'Not'].map(name => ({ tag: '!' + name, collection: 'seq', resolve: value => ({ [name]: value.toJSON() }) })),
  ] });
  requireValue(document.errors.length === 0 && document.warnings.length === 0, 'invalid deployment template');
  const template = document.toJS();
  const values = Object.fromEntries(Object.entries(template.Parameters).map(([key, value]) => [key, value.Default]));
  Object.assign(values, parameterValues);
  for (const [key, parameter] of Object.entries(template.Parameters)) {
    if (parameter.Type === 'CommaDelimitedList' && typeof values[key] === 'string') values[key] = values[key].split(',');
  }
  const resolve = value => {
    if (Array.isArray(value)) return value.map(resolve);
    if (!value || typeof value !== 'object') return value;
    if ('Ref' in value) { requireValue(values[value.Ref] !== undefined, `unresolved ${value.Ref}`); return values[value.Ref]; }
    if ('Sub' in value) return value.Sub.replace(/\$\{([^}]+)\}/gu, (_, key) => {
      requireValue(typeof values[key] === 'string', `unresolved ${key}`); return values[key];
    });
    if ('If' in value) { const [condition, yes, no] = value.If; requireValue(template.Conditions[condition], 'unknown template condition');
      return resolve(resolve(template.Conditions[condition]) ? yes : no); }
    if ('Equals' in value) return resolve(value.Equals[0]) === resolve(value.Equals[1]);
    if ('Not' in value) return !resolve(value.Not[0]);
    requireValue(!('GetAtt' in value) && !Object.keys(value).some(key => key.startsWith('Fn::')), 'unresolved policy intrinsic');
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, resolve(child)]));
  };
  const policies = Object.fromEntries(Object.entries(template.Resources).filter(([, r]) => r.Type === 'AWS::IAM::ManagedPolicy')
    .map(([key, r]) => [key, resolve(r.Properties.PolicyDocument)]));
  const sizes = Object.fromEntries(Object.entries(policies).map(([key, policy]) => [key, JSON.stringify(policy).length]));
  requireValue(Object.keys(sizes).length > 0, 'missing deployment managed policies');
  for (const [key, size] of Object.entries(sizes)) requireValue(size <= 6144, `${key} exceeds managed policy quota: ${size}`);
  const context = { partition: values['AWS::Partition'], accountId: values['AWS::AccountId'], applicationRegion: values.ApplicationRegion,
    decisionArtifactBucketName: values.DecisionArtifactBucketName, projectName: values.ProjectName, githubRepo: values.GitHubRepo };
  for (const role of ['GitHubPreviewActionsRole', 'GitHubProductionActionsRole', 'GitHubActionsRole']) {
    const resource = template.Resources[role];
    requireValue(resource && !resource.Condition, `missing or conditional deploy role: ${role}`);
    const attached = resource.Properties.ManagedPolicyArns.map(p => policies[p.Ref]).filter(Boolean);
    verifyAuthorizationMaintenanceIsolation(attached, context);
  }
  return sizes;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [operation, ...args] = process.argv.slice(2);
    if (operation === 'inspect' && args.length === 4) {
      const [applicationRegion, stackName, bucket, mode] = args;
      const run = async arguments_ => {
        const { stdout } = await promisify(execFile)('aws', arguments_, { encoding: 'utf8', timeout: 30000, maxBuffer: 4 * 1024 * 1024,
          env: { ...process.env, AWS_PAGER: '', AWS_CLI_AUTO_PROMPT: 'off' } });
        return JSON.parse(stdout);
      };
      console.log(JSON.stringify(await inspectAuthorizationDeploymentBindings({ run, applicationRegion, stackName, mode,
        decisionArtifactBucketName: bucket || undefined })));
    } else if (operation === 'template' && args.length === 1) {
      let input = ''; for await (const chunk of process.stdin) input += chunk;
      console.log(JSON.stringify(await verifyAuthorizationDeploymentTemplate(await readFile(args[0], 'utf8'), JSON.parse(input))));
    } else throw new Error('invalid authorization isolation helper arguments');
  } catch (error) {
    // Subprocess errors embed stderr/argv; parser errors can quote response
    // bytes. Keep these private while retaining local contract diagnostics.
    console.error(error instanceof IsolationValidationError
      ? error.message : 'Authorization isolation check failed; details withheld.');
    process.exitCode = 1;
  }
}
