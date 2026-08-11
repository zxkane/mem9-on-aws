import { readFileSync } from "node:fs";

const rolloutContract = JSON.parse(
  readFileSync(
    new URL("../workload-permissions-boundary-contract.json", import.meta.url),
    "utf8",
  ),
);
export const QUARANTINE_POLICY_NAME =
  rolloutContract.identifiers.quarantinePolicyName;
export const WORKLOAD_BOUNDARY_POLICY_NAME =
  rolloutContract.identifiers.boundaryPolicyName;
export const WORKLOAD_BOUNDARY_STACK_NAME =
  rolloutContract.identifiers.boundaryStackName;
export const DENY_DANGEROUS_POLICY_NAME =
  rolloutContract.identifiers.denyDangerousPolicyName;
export const DEPLOY_ROLE_NAME = rolloutContract.identifiers.deployRoleName;
export const ROLLOUT_RESUME_COMMAND =
  "WORKLOAD_BOUNDARY_MAINTENANCE_ACK=true " +
  "WORKLOAD_BOUNDARY_SKIP_DOTENV=false " +
  "WORKLOAD_BOUNDARY_ENV_FILE=.env.workload-boundary-resume " +
  "scripts/rollout-workload-permissions-boundary.sh";
if (
  !Number.isSafeInteger(rolloutContract.rolloutTimeoutMs) ||
  rolloutContract.rolloutTimeoutMs <= 0 ||
  !Number.isSafeInteger(rolloutContract.shutdownGraceMs) ||
  rolloutContract.shutdownGraceMs <= 0 ||
  rolloutContract.shutdownGraceMs >= rolloutContract.rolloutTimeoutMs
) {
  throw new Error("workload permissions-boundary rollout timeout is invalid");
}
export const ROLLOUT_TIMEOUT_MS = rolloutContract.rolloutTimeoutMs;
export const ROLLOUT_SHUTDOWN_GRACE_MS = rolloutContract.shutdownGraceMs;

const ROLE_PREFIXES = ["mem9-on-aws-", "mem9-on-aw-", "mem9-on-a-"];
const LAMBDA_EXECUTION_ROLE_TYPES = [
  {
    functionToken: "Mem9AlertRouter",
    roleToken: "Mem9AlertRouterRole-",
    isVpcProxy: false,
  },
  {
    functionToken: "Mem9OauthFacadeAllowAll",
    roleToken: "Mem9OauthFacadeAllowAllRole",
    isVpcProxy: false,
    optional: true,
    stableName: true,
  },
  {
    functionToken: "Mem9OauthFacadeFn",
    roleToken: "Mem9OauthFacadeFnRole-",
    isVpcProxy: false,
  },
  {
    functionToken: "Mem9ProxyFn",
    roleToken: "Mem9ProxyFnRole-",
    isVpcProxy: true,
  },
];

function lambdaExecutionRoleArnPatterns({ partition, accountId }) {
  return LAMBDA_EXECUTION_ROLE_TYPES.map(
    ({ roleToken, stableName }) =>
      `arn:${partition}:iam::${accountId}:role/` +
      `mem9-on-a*-*${roleToken}${stableName ? "" : "*"}`,
  );
}

function matchesProductionLambdaFunctionName(functionName, type) {
  return (
    typeof functionName === "string" &&
    (type.stableName
      ? functionName === `mem9-on-aws-prod-${type.functionToken}`
      : functionName.includes(type.functionToken))
  );
}

function matchesProductionLambdaRoleName(roleName, type) {
  return type.stableName
    ? roleName === `mem9-on-aws-prod-${type.roleToken}`
    : roleName.includes(type.roleToken);
}

function matchesProjectLambdaRoleName(roleName, type) {
  return type.stableName
    ? roleName.endsWith(`-${type.roleToken}`)
    : roleName.includes(type.roleToken);
}

// Every ECS execution role that fetches a Secrets Manager secret for `valueFrom`
// injection has to be listed here, because
// DenySecretContextDecryptFromNonEcsExecutionRoles is an ArnNotLike deny: an
// omitted role is denied, not merely ungranted. Measured against the live policy
// rather than reasoned about — the default `aws/secretsmanager` key needs no
// identity ALLOW, which makes it tempting to conclude the deny never fires, but a
// simulation of each role shows listed ones allowed and unlisted ones
// explicitDeny. A missing token costs a task death in the ECS agent's
// secret-fetch phase, before the entrypoint runs.
const ECS_EXECUTION_ROLE_TOKENS = [
  "Mem9ServerExecutionRole-",
  "Mem9BootstrapExecutionRole-",
  "Mem9ConsolidationExecutionRole-",
  "Mem9CleanupExecutionRole-",
];
const ALLOWED_PASS_SERVICES = new Set([
  "bedrock-agentcore.amazonaws.com",
  "ecs-tasks.amazonaws.com",
  "lambda.amazonaws.com",
  "scheduler.amazonaws.com",
]);
const PROJECT_RESOURCE_RUNTIME_ACTIONS = [
  "bedrock-mantle:CreateInference",
  "bedrock-mantle:GetProject",
  "bedrock-mantle:ListProjects",
  "bedrock-mantle:ListTagsForResource",
  "ecr:BatchCheckLayerAvailability",
  "ecr:BatchGetImage",
  "ecr:GetDownloadUrlForLayer",
  "lambda:InvokeFunction",
  "logs:CreateLogGroup",
  "logs:CreateLogStream",
  "logs:PutLogEvents",
  "secretsmanager:GetSecretValue",
  "sns:Publish",
  "sqs:SendMessage",
  "ssm:GetParameters",
  // The Slack approval record (#123 — the writer does not exist yet; this
  // prerequisite lands first because the rollout can only apply main's
  // template). Listed here rather than in GLOBAL_RUNTIME_ACTIONS because this
  // list feeds BOTH the action ceiling and DenyProjectRuntimeOutsideResources,
  // and the project SSM prefix is the only place this write belongs.
  // GLOBAL_RUNTIME_ACTIONS entries are admitted account-wide, which is why
  // ecs:RunTask and iam:PassRole live there and are constrained by identity
  // policy and out-of-band review instead.
  "ssm:PutParameter",
];
const MANTLE_BEARER_ACTION = "bedrock-mantle:CallWithBearerToken";
const GLOBAL_RUNTIME_ACTIONS = [
  "ecs:RunTask",
  "ec2:AssignPrivateIpAddresses",
  "ec2:CreateNetworkInterface",
  "ec2:DeleteNetworkInterface",
  "ec2:DescribeNetworkInterfaces",
  "ec2:DescribeSubnets",
  "ec2:UnassignPrivateIpAddresses",
  "ecr:GetAuthorizationToken",
  "iam:PassRole",
  "ssmmessages:CreateControlChannel",
  "ssmmessages:CreateDataChannel",
  "ssmmessages:OpenControlChannel",
  "ssmmessages:OpenDataChannel",
];
const CONDITIONED_RUNTIME_ACTIONS = ["kms:Decrypt"];
const RUNTIME_ACTION_CEILING = [
  ...PROJECT_RESOURCE_RUNTIME_ACTIONS,
  ...GLOBAL_RUNTIME_ACTIONS,
  ...CONDITIONED_RUNTIME_ACTIONS,
  MANTLE_BEARER_ACTION,
];
const NETWORK_INTERFACE_DENY_ACTIONS = [
  "ec2:*NetworkInterface*",
  "ec2:AssignPrivateIpAddresses",
  "ec2:DescribeSubnets",
  "ec2:UnassignPrivateIpAddresses",
];
const MAX_IAM_PAGES = 100;
const MAX_IAM_ITEMS = 10_000;
// An AWS region, as a bare regex source (embeddable in a larger ARN pattern)
// and as an anchored matcher for validating a region on its own.
const ANY_REGION_SOURCE = "[a-z]{2}(?:-gov)?-[a-z]+-[0-9]";
const REGION_PATTERN = new RegExp(`^${ANY_REGION_SOURCE}$`, "u");

function list(value) {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

function assertIdentity({ partition, accountId }) {
  if (!/^[a-z0-9-]+$/u.test(partition ?? "")) {
    throw new Error("invalid AWS partition");
  }
  if (!/^[0-9]{12}$/u.test(accountId ?? "")) {
    throw new Error("invalid AWS account id");
  }
}

export function expectedRolePatterns(identity) {
  assertIdentity(identity);
  return ROLE_PREFIXES.map(
    (prefix) =>
      `arn:${identity.partition}:iam::${identity.accountId}:role/${prefix}*`,
  );
}

function consolidationSchedulerRoleArnPattern({ partition, accountId }) {
  return (
    `arn:${partition}:iam::${accountId}:role/` +
    "mem9-on-a*-*Mem9ConsolidationSchedulerRole-*"
  );
}

function globMatches(pattern, value) {
  const source = String(pattern)
    .split(/([*?])/u)
    .map((part) => {
      if (part === "*") return ".*";
      if (part === "?") return ".";
      return RegExp.escape(part);
    })
    .join("");
  return new RegExp(`^${source}$`, "iu").test(value);
}

function statementCanAllowPassRole(statement) {
  if (statement?.Effect !== "Allow") return false;
  if (statement.NotAction !== undefined) {
    return !list(statement.NotAction).some((action) =>
      globMatches(action, "iam:PassRole"),
    );
  }
  return list(statement.Action).some((action) =>
    globMatches(action, "iam:PassRole"),
  );
}

function decodePolicyDocument(document) {
  if (document && typeof document === "object") return document;
  if (typeof document !== "string") {
    throw new Error("IAM policy document is missing or malformed");
  }
  let source = document;
  if (!source.trimStart().startsWith("{")) {
    try {
      source = decodeURIComponent(source);
    } catch {
      throw new Error("IAM policy document is not valid URL encoding");
    }
  }
  try {
    return JSON.parse(source);
  } catch {
    throw new Error("IAM policy document is not valid JSON");
  }
}

export function quarantinePolicyDocument() {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "QuarantineAllDeployRoleActions",
        Effect: "Deny",
        Action: "*",
        Resource: "*",
      },
    ],
  };
}

// A same-account Mantle project ARN. `regionSource` is a regex fragment: the
// exact application region for the primary project, ANY_REGION_SOURCE for the
// optional Responses-route project, which is regional and by definition lives
// outside the application region.
function mantleProjectArnPattern({ partition, accountId, regionSource }) {
  return new RegExp(
    `^arn:${RegExp.escape(partition)}:bedrock-mantle:` +
      `${regionSource}:${RegExp.escape(accountId)}:` +
      "project/[A-Za-z0-9_-]+$",
    "u",
  );
}

function boundaryContract({
  partition,
  accountId,
  applicationRegion,
  bedrockProjectArn,
  openAiBedrockProjectArn = "",
  policyRevision = "r1",
}) {
  assertIdentity({ partition, accountId });
  if (!REGION_PATTERN.test(applicationRegion ?? "")) {
    throw new Error("invalid application region");
  }
  const projectArnPattern = mantleProjectArnPattern({
    partition,
    accountId,
    regionSource: RegExp.escape(applicationRegion),
  });
  if (!projectArnPattern.test(bedrockProjectArn ?? "")) {
    throw new Error("invalid Bedrock Mantle project ARN");
  }
  // Optional second project for the llm-proxy Responses route. Empty = feature
  // not enabled; the boundary document then matches the historic shape.
  if (
    openAiBedrockProjectArn &&
    !mantleProjectArnPattern({
      partition,
      accountId,
      regionSource: ANY_REGION_SOURCE,
    }).test(openAiBedrockProjectArn)
  ) {
    throw new Error("invalid OpenAI Bedrock Mantle project ARN");
  }
  if (!/^r[0-9]{1,20}$/u.test(policyRevision)) {
    throw new Error("invalid boundary policy revision");
  }

  return {
    accountId,
    partition,
    policyRevision,
    kmsViaServices: ["ssm", "secretsmanager"].map(
      (service) =>
        `${service}.${applicationRegion}.${
          partition === "aws-cn" ? "amazonaws.com.cn" : "amazonaws.com"
        }`,
    ),
    secretArns: [
      "Mem9DbProxySecret-*",
      "Mem9DbSecret-*",
      "tenant-api-key-*",
    ].map(
      (secretToken) =>
        `arn:${partition}:secretsmanager:${applicationRegion}:${accountId}:` +
        `secret:mem9-on-aws-*-${secretToken}`,
    ),
    ecsExecutionRoleArns: ECS_EXECUTION_ROLE_TOKENS.map(
      (roleToken) =>
        `arn:${partition}:iam::${accountId}:role/` +
        `mem9-on-a*-*${roleToken}*`,
    ),
    lambdaFunctionArn:
      `arn:${partition}:lambda:${applicationRegion}:${accountId}:` +
      "function:mem9-on-aws-*",
    lambdaExecutionRoleArns: lambdaExecutionRoleArnPatterns({
      partition,
      accountId,
    }),
    ssmParameterArn:
      `arn:${partition}:ssm:${applicationRegion}:${accountId}:` +
      "parameter/mem9-on-aws/*",
    // The approval-record write (#123) is scoped tighter than the project
    // prefix. See DenyPutParameterOutsideApprovalRecords for why the broader
    // project scope is not sufficient for a WRITE.
    ssmApprovalParameterArn:
      `arn:${partition}:ssm:${applicationRegion}:${accountId}:` +
      "parameter/mem9-on-aws/*/approvals/*",
    projectResources: [
      bedrockProjectArn,
      ...(openAiBedrockProjectArn ? [openAiBedrockProjectArn] : []),
      `arn:${partition}:ecr:${applicationRegion}:${accountId}:repository/mem9-on-aws/*`,
      `arn:${partition}:lambda:${applicationRegion}:${accountId}:function:mem9-on-aws-*`,
      `arn:${partition}:logs:${applicationRegion}:${accountId}:log-group:/sst/*`,
      `arn:${partition}:logs:${applicationRegion}:${accountId}:log-group:/aws/lambda/mem9-on-aws-*`,
      `arn:${partition}:secretsmanager:${applicationRegion}:${accountId}:secret:mem9-on-aws-*`,
      `arn:${partition}:sqs:${applicationRegion}:${accountId}:AlertTransportFailureQueue-*`,
      `arn:${partition}:sqs:${applicationRegion}:${accountId}:AlertExecutionFailureQueue-*`,
      `arn:${partition}:sns:${applicationRegion}:${accountId}:mem9-on-aws-*-alerts`,
      `arn:${partition}:ssm:${applicationRegion}:${accountId}:parameter/mem9-on-aws/*`,
    ],
  };
}

export function expectedBoundaryPolicyDocument(contract) {
  const {
    accountId,
    ecsExecutionRoleArns,
    kmsViaServices,
    lambdaExecutionRoleArns,
    lambdaFunctionArn,
    partition,
    policyRevision,
    projectResources,
    secretArns,
    ssmApprovalParameterArn,
    ssmParameterArn,
  } = boundaryContract(contract);
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "AllowRuntimeIdentityPermissions",
        Effect: "Allow",
        Action: "*",
        Resource: "*",
      },
      {
        Sid: `DenyOutsideRuntimeActionCeiling${policyRevision}`,
        Effect: "Deny",
        NotAction: [...RUNTIME_ACTION_CEILING],
        Resource: "*",
      },
      {
        Sid: "DenyProjectRuntimeOutsideResources",
        Effect: "Deny",
        Action: [...PROJECT_RESOURCE_RUNTIME_ACTIONS],
        NotResource: projectResources,
      },
      // The statement above scopes the write to the PROJECT prefix — every
      // stage's whole SSM tree — which is too wide for a WRITE. This ceiling is
      // the only control on it: identity policies are PR-authored, and the
      // deploy role's DenyUnboundedProjectRolePolicyWrites only requires that
      // the boundary be ATTACHED, never constrains its content. Preview roles
      // are bounded too, so without this a PR could grant one of its own preview
      // Lambdas ssm:PutParameter on /mem9-on-aws/prod/* and overwrite prod's
      // plain-String parameters. SecureStrings are already unreachable (that
      // write needs kms:Encrypt or kms:GenerateDataKey; the ceiling admits
      // neither), so the plain-String ones are exactly the exposure this closes.
      {
        Sid: "DenyPutParameterOutsideApprovalRecords",
        Effect: "Deny",
        Action: ["ssm:PutParameter"],
        NotResource: [ssmApprovalParameterArn],
      },
      {
        Sid: "DenyKmsDecryptOutsideReviewedContexts",
        Effect: "Deny",
        Action: [...CONDITIONED_RUNTIME_ACTIONS],
        Resource: "*",
        Condition: {
          StringNotLikeIfExists: {
            "kms:EncryptionContext:PARAMETER_ARN": ssmParameterArn,
            "kms:EncryptionContext:aws:lambda:FunctionArn":
              lambdaFunctionArn,
            "kms:EncryptionContext:SecretARN": secretArns,
          },
        },
      },
      {
        Sid: "DenyKmsDecryptOutsideReviewedViaServices",
        Effect: "Deny",
        Action: [...CONDITIONED_RUNTIME_ACTIONS],
        Resource: "*",
        Condition: {
          StringNotEqualsIfExists: {
            "kms:ViaService": kmsViaServices,
          },
          StringNotLikeIfExists: {
            "kms:EncryptionContext:aws:lambda:FunctionArn":
              lambdaFunctionArn,
          },
        },
      },
      {
        Sid: "DenyParameterContextDecryptOutsideSsm",
        Effect: "Deny",
        Action: [...CONDITIONED_RUNTIME_ACTIONS],
        Resource: "*",
        Condition: {
          Null: {
            "kms:EncryptionContext:PARAMETER_ARN": "false",
          },
          StringNotEqualsIfExists: {
            "kms:ViaService": kmsViaServices[0],
          },
        },
      },
      {
        Sid: "DenySecretContextDecryptOutsideSecretsManager",
        Effect: "Deny",
        Action: [...CONDITIONED_RUNTIME_ACTIONS],
        Resource: "*",
        Condition: {
          Null: {
            "kms:EncryptionContext:SecretARN": "false",
          },
          StringNotEqualsIfExists: {
            "kms:ViaService": kmsViaServices[1],
          },
        },
      },
      {
        Sid: "DenySecretContextDecryptFromNonEcsExecutionRoles",
        Effect: "Deny",
        Action: [...CONDITIONED_RUNTIME_ACTIONS],
        Resource: "*",
        Condition: {
          Null: {
            "kms:EncryptionContext:SecretARN": "false",
          },
          ArnNotLike: {
            "aws:PrincipalArn": ecsExecutionRoleArns,
          },
        },
      },
      {
        Sid: "DenyLambdaContextDecryptFromNonLambdaRoles",
        Effect: "Deny",
        Action: [...CONDITIONED_RUNTIME_ACTIONS],
        Resource: "*",
        Condition: {
          Null: {
            "kms:EncryptionContext:aws:lambda:FunctionArn": "false",
          },
          ArnNotLike: {
            "aws:PrincipalArn": lambdaExecutionRoleArns,
          },
        },
      },
      {
        Sid: "DenyDirectKmsDecryptFromFunctionCode",
        Effect: "Deny",
        Action: [...CONDITIONED_RUNTIME_ACTIONS],
        Resource: "*",
        Condition: {
          Null: {
            "lambda:SourceFunctionArn": "false",
          },
          StringNotEqualsIfExists: {
            "kms:ViaService": kmsViaServices[0],
          },
        },
      },
      {
        Sid: "DenyNonShortTermMantleBearer",
        Effect: "Deny",
        Action: [MANTLE_BEARER_ACTION],
        Resource: "*",
        Condition: {
          StringNotEqualsIfExists: {
            "bedrock-mantle:BearerTokenType": "SHORT_TERM",
          },
        },
      },
      {
        Sid: "DenyEniFromNonVpcLambdaRoles",
        Effect: "Deny",
        Action: [...NETWORK_INTERFACE_DENY_ACTIONS],
        Resource: "*",
        Condition: {
          ArnNotLike: {
            "aws:PrincipalArn":
              `arn:${partition}:iam::${accountId}:role/` +
              "mem9-on-a*-*Mem9ProxyFnRole-*",
          },
        },
      },
      {
        Sid: "DenyEniFromFunctionCode",
        Effect: "Deny",
        Action: [...NETWORK_INTERFACE_DENY_ACTIONS],
        Resource: "*",
        Condition: {
          Null: {
            "lambda:SourceFunctionArn": "false",
          },
        },
      },
    ],
  };
}

function sortedStrings(value, label) {
  const values = list(value);
  if (values.some((item) => typeof item !== "string")) {
    throw new Error(`${label} is malformed`);
  }
  return [...values].sort();
}

function sameStringSet(left, right) {
  const normalizedLeft = sortedStrings(left, "policy value");
  const normalizedRight = sortedStrings(right, "expected policy value");
  return (
    normalizedLeft.length === normalizedRight.length &&
    normalizedLeft.every((value, index) => value === normalizedRight[index])
  );
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return value
      .map(canonicalJson)
      .sort((left, right) =>
        JSON.stringify(left).localeCompare(JSON.stringify(right)),
      );
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalJson(value[key])]),
    );
  }
  return value;
}

export function verifyBoundaryPolicyDocument(document, contract) {
  const decoded = decodePolicyDocument(document);
  if (
    decoded.Version !== "2012-10-17" ||
    Object.keys(decoded).some((key) => key !== "Version" && key !== "Statement")
  ) {
    return false;
  }
  const actual = list(decoded.Statement);
  const expected = expectedBoundaryPolicyDocument(contract).Statement;
  if (actual.length !== expected.length) return false;

  for (const expectedStatement of expected) {
    const matches = actual.filter(
      (statement) => statement?.Sid === expectedStatement.Sid,
    );
    if (matches.length !== 1) return false;
    const statement = matches[0];
    const expectedKeys = Object.keys(expectedStatement).sort();
    if (!sameStringSet(Object.keys(statement), expectedKeys)) return false;
    for (const key of ["Action", "NotAction", "Resource", "NotResource"]) {
      if (
        expectedStatement[key] !== undefined &&
        !sameStringSet(statement[key], expectedStatement[key])
      ) {
        return false;
      }
    }
    if (statement.Effect !== expectedStatement.Effect) return false;
    if (
      expectedStatement.Condition !== undefined &&
      JSON.stringify(canonicalJson(statement.Condition)) !==
        JSON.stringify(canonicalJson(expectedStatement.Condition))
    ) {
      return false;
    }
  }
  return true;
}

export function verifyQuarantinePolicy(document) {
  const decoded = decodePolicyDocument(document);
  if (
    decoded.Version !== "2012-10-17" ||
    !sameStringSet(Object.keys(decoded), ["Version", "Statement"])
  ) {
    return false;
  }
  const statements = list(decoded.Statement);
  if (statements.length !== 1) return false;
  const statement = statements[0];
  return (
    statement?.Sid === "QuarantineAllDeployRoleActions" &&
    statement.Effect === "Deny" &&
    sameStringSet(Object.keys(statement), [
      "Sid",
      "Effect",
      "Action",
      "Resource",
    ]) &&
    sameStringSet(statement.Action, ["*"]) &&
    sameStringSet(statement.Resource, ["*"]) &&
    statement.NotAction === undefined &&
    statement.NotResource === undefined &&
    statement.Condition === undefined
  );
}

function validatePassServices(statement) {
  const condition = statement.Condition;
  if (!condition || typeof condition !== "object") {
    throw new Error("iam:PassRole requires iam:PassedToService");
  }
  const values = condition.StringEquals?.["iam:PassedToService"];
  const services = list(values);
  if (
    services.length === 0 ||
    services.some(
      (service) =>
        typeof service !== "string" || !ALLOWED_PASS_SERVICES.has(service),
    )
  ) {
    throw new Error(
      "iam:PassRole has an unsupported iam:PassedToService scope",
    );
  }
  return services;
}

export function extractPassRoleScope(policyDocuments, identity) {
  const expected = expectedRolePatterns(identity);
  const expectedSet = new Set(expected);
  const schedulerRolePattern =
    consolidationSchedulerRoleArnPattern(identity);
  const resources = new Set();

  for (const rawDocument of policyDocuments) {
    const document = decodePolicyDocument(rawDocument);
    for (const statement of list(document.Statement)) {
      if (!statementCanAllowPassRole(statement)) continue;
      if (statement.NotAction !== undefined) {
        throw new Error("PassRole scope cannot be proven from NotAction");
      }

      const matchingActions = list(statement.Action).filter((action) =>
        globMatches(action, "iam:PassRole"),
      );
      if (
        matchingActions.length !== 1 ||
        String(matchingActions[0]).toLowerCase() !== "iam:passrole"
      ) {
        throw new Error("PassRole wildcard actions are unsupported");
      }
      if (statement.NotResource !== undefined) {
        throw new Error("PassRole NotResource is unsupported");
      }

      const services = validatePassServices(statement);
      const statementResources = list(statement.Resource);
      if (statementResources.length === 0) {
        throw new Error("PassRole statement has no resource scope");
      }
      if (services.includes("scheduler.amazonaws.com")) {
        if (
          services.length !== 1 ||
          statementResources.length !== 1 ||
          statementResources[0] !== schedulerRolePattern
        ) {
          throw new Error(
            "Scheduler PassRole scope does not match the consolidation role",
          );
        }
        continue;
      }
      for (const resource of statementResources) {
        if (
          typeof resource !== "string" ||
          !expectedSet.has(resource) ||
          !resource.endsWith("*") ||
          resource.slice(0, -1).includes("*") ||
          resource.includes("?")
        ) {
          throw new Error("PassRole resource scope is unsupported");
        }
        resources.add(resource);
      }
    }
  }

  const normalized = [...resources].sort();
  if (
    normalized.length !== expected.length ||
    expected.some((resource) => !resources.has(resource))
  ) {
    throw new Error(
      "PassRole scope does not match supported project role patterns",
    );
  }
  return expected;
}

async function collectPages(
  fetchPage,
  field,
  { maxPages = MAX_IAM_PAGES, maxItems = MAX_IAM_ITEMS } = {},
) {
  const values = [];
  const seenMarkers = new Set();
  let marker;
  let pageCount = 0;
  do {
    pageCount += 1;
    if (pageCount > maxPages) {
      throw new Error("IAM pagination exceeded the page limit");
    }
    const page = await fetchPage(marker);
    if (!page || !Array.isArray(page[field])) {
      throw new Error(`IAM pagination response is missing ${field}`);
    }
    values.push(...page[field]);
    if (values.length > maxItems) {
      throw new Error("IAM pagination exceeded the item limit");
    }
    marker = page.marker;
    if (marker !== undefined) {
      if (typeof marker !== "string" || marker.length === 0) {
        throw new Error("IAM pagination returned an invalid marker");
      }
      if (seenMarkers.has(marker)) {
        throw new Error("IAM pagination repeated a marker");
      }
      seenMarkers.add(marker);
    }
  } while (marker !== undefined);
  return values;
}

export async function loadRolePolicyDocuments(adapter, roleName) {
  const attached = await collectPages(
    (marker) => adapter.listAttachedPolicies({ roleName, marker }),
    "policies",
  );
  const inlineNames = await collectPages(
    (marker) => adapter.listInlinePolicies({ roleName, marker }),
    "policyNames",
  );
  const documents = [];

  for (const policy of attached) {
    if (!policy || typeof policy.arn !== "string") {
      throw new Error("attached IAM policy response is malformed");
    }
    const metadata = await adapter.getManagedPolicy({
      policyArn: policy.arn,
    });
    if (!metadata || typeof metadata.defaultVersionId !== "string") {
      throw new Error("managed IAM policy has no default version");
    }
    const version = await adapter.getManagedPolicyVersion({
      policyArn: policy.arn,
      versionId: metadata.defaultVersionId,
    });
    documents.push(version?.document);
  }

  for (const policyName of inlineNames) {
    if (typeof policyName !== "string" || policyName.length === 0) {
      throw new Error("inline IAM policy name is malformed");
    }
    const policy = await adapter.getInlinePolicy({ roleName, policyName });
    documents.push(policy?.document);
  }

  return documents;
}

export async function discoverPassRoleScope(
  adapter,
  { roleName, partition, accountId },
) {
  const documents = await loadRolePolicyDocuments(adapter, roleName);
  return extractPassRoleScope(documents, { partition, accountId });
}

const STACK_MUTATION_ACTIONS = [
  "cloudformation:CancelUpdateStack",
  "cloudformation:ContinueUpdateRollback",
  "cloudformation:CreateChangeSet",
  "cloudformation:CreateStack",
  "cloudformation:CreateStackRefactor",
  "cloudformation:DeleteChangeSet",
  "cloudformation:DeleteStack",
  "cloudformation:ExecuteChangeSet",
  "cloudformation:ExecuteStackRefactor",
  "cloudformation:RecordHandlerProgress",
  "cloudformation:RollbackStack",
  "cloudformation:SetStackPolicy",
  "cloudformation:SignalResource",
  "cloudformation:TagResource",
  "cloudformation:UntagResource",
  "cloudformation:UpdateStack",
  "cloudformation:UpdateTerminationProtection",
];

function statementBySid(documents, sid) {
  const matches = documents
    .map(decodePolicyDocument)
    .flatMap((document) => list(document.Statement))
    .filter((statement) => statement?.Sid === sid);
  if (matches.length !== 1) {
    throw new Error(
      `permanent enforcement statement ${sid} is missing or duplicated`,
    );
  }
  return matches[0];
}

function requireStatement(
  documents,
  {
    sid,
    effect,
    actions,
    resources,
    conditionOperator,
    conditionKey,
    conditionValue,
  },
) {
  const statement = statementBySid(documents, sid);
  if (
    statement.Effect !== effect ||
    !sameStringSet(statement.Action, actions) ||
    !sameStringSet(statement.Resource, resources) ||
    statement.NotAction !== undefined ||
    statement.NotResource !== undefined ||
    statement.Principal !== undefined ||
    statement.NotPrincipal !== undefined
  ) {
    throw new Error(`permanent enforcement statement ${sid} is malformed`);
  }

  if (conditionOperator === undefined) {
    if (statement.Condition !== undefined) {
      throw new Error(`permanent enforcement statement ${sid} has a condition`);
    }
    return;
  }
  const condition = statement.Condition;
  if (
    !condition ||
    Object.keys(condition).length !== 1 ||
    !condition[conditionOperator] ||
    Object.keys(condition[conditionOperator]).length !== 1 ||
    !sameStringSet(
      condition[conditionOperator][conditionKey],
      list(conditionValue),
    )
  ) {
    throw new Error(`permanent enforcement condition ${sid} is malformed`);
  }
}

export function verifyPermanentEnforcementDocuments(
  documents,
  { partition, accountId, boundaryArn },
) {
  assertIdentity({ partition, accountId });
  const expectedBoundaryArn =
    `arn:${partition}:iam::${accountId}:policy/` +
    WORKLOAD_BOUNDARY_POLICY_NAME;
  if (boundaryArn !== expectedBoundaryArn) {
    throw new Error("permanent enforcement boundary ARN is unexpected");
  }
  const rolePatterns = expectedRolePatterns({ partition, accountId });
  const stackPrefix = `arn:${partition}:cloudformation:*:${accountId}:stack`;

  for (const effect of ["Allow", "Deny"]) {
    requireStatement(documents, {
      sid:
        effect === "Allow"
          ? "EcsTaskRoleCreateWithBoundary"
          : "DenyUnboundedProjectRoleCreation",
      effect,
      actions: ["iam:CreateRole", "iam:PutRolePermissionsBoundary"],
      resources: rolePatterns,
      conditionOperator: effect === "Allow" ? "ArnEquals" : "ArnNotEquals",
      conditionKey: "iam:PermissionsBoundary",
      conditionValue: boundaryArn,
    });
    requireStatement(documents, {
      sid:
        effect === "Allow"
          ? "EcsTaskRolePolicyWritesWithBoundary"
          : "DenyUnboundedProjectRolePolicyWrites",
      effect,
      actions: ["iam:AttachRolePolicy", "iam:PutRolePolicy"],
      resources: rolePatterns,
      conditionOperator: effect === "Allow" ? "ArnEquals" : "ArnNotEquals",
      conditionKey: "iam:PermissionsBoundary",
      conditionValue: boundaryArn,
    });
  }

  requireStatement(documents, {
    sid: "DenyWorkloadBoundaryRemoval",
    effect: "Deny",
    actions: ["iam:DeleteRolePermissionsBoundary"],
    resources: rolePatterns,
  });
  requireStatement(documents, {
    sid: "EcsTaskRoleLifecycle",
    effect: "Allow",
    actions: [
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:DetachRolePolicy",
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListInstanceProfilesForRole",
      "iam:ListRolePolicies",
      "iam:ListRoleTags",
      "iam:TagRole",
      "iam:UntagRole",
    ],
    resources: rolePatterns,
  });
  requireStatement(documents, {
    sid: "DenyLambdaRolePassToOtherServices",
    effect: "Deny",
    actions: ["iam:PassRole"],
    resources: lambdaExecutionRoleArnPatterns({ partition, accountId }),
    conditionOperator: "StringNotEquals",
    conditionKey: "iam:PassedToService",
    conditionValue: "lambda.amazonaws.com",
  });
  requireStatement(documents, {
    sid: "DenyEcsExecutionRolePassToOtherServices",
    effect: "Deny",
    actions: ["iam:PassRole"],
    resources: ECS_EXECUTION_ROLE_TOKENS.map(
      (roleToken) =>
        `arn:${partition}:iam::${accountId}:role/` +
        `mem9-on-a*-*${roleToken}*`,
    ),
    conditionOperator: "StringNotEquals",
    conditionKey: "iam:PassedToService",
    conditionValue: "ecs-tasks.amazonaws.com",
  });
  requireStatement(documents, {
    sid: "DenyConsolidationSchedulerRolePassToOtherServices",
    effect: "Deny",
    actions: ["iam:PassRole"],
    resources: [
      consolidationSchedulerRoleArnPattern({ partition, accountId }),
    ],
    conditionOperator: "StringNotEquals",
    conditionKey: "iam:PassedToService",
    conditionValue: "scheduler.amazonaws.com",
  });
  requireStatement(documents, {
    sid: "DenyOperatorOwnedIamMutation",
    effect: "Deny",
    actions: [
      "iam:CreatePolicy",
      "iam:CreatePolicyVersion",
      "iam:DeletePolicy",
      "iam:DeletePolicyVersion",
      "iam:SetDefaultPolicyVersion",
      "iam:TagPolicy",
      "iam:UntagPolicy",
    ],
    resources: [boundaryArn],
  });
  requireStatement(documents, {
    sid: "DenyOperatorOwnedStackMutation",
    effect: "Deny",
    actions: STACK_MUTATION_ACTIONS,
    resources: [
      `${stackPrefix}/github-actions-mem9-on-aws/*`,
      `${stackPrefix}/workload-permissions-boundary-mem9-on-aws/*`,
    ],
  });
  requireStatement(documents, {
    sid: "DenyEcrRegistryScanningOwnershipStackMutation",
    effect: "Deny",
    actions: STACK_MUTATION_ACTIONS,
    resources: [`${stackPrefix}/ecr-registry-scanning-mem9-on-aws/*`],
  });
  return true;
}

const REQUIRED_TASK_SECRET_NAMES = ["MEM9_DB_SECRET", "MEM9_TENANT_ID"];

function taskDefinitionArnPattern({ partition, accountId, applicationRegion }) {
  return new RegExp(
    `^arn:${RegExp.escape(partition)}:ecs:` +
      `${RegExp.escape(applicationRegion)}:${RegExp.escape(accountId)}:` +
      "task-definition/[A-Za-z0-9_-]+:[1-9][0-9]*$",
    "u",
  );
}

function projectSecretArnPattern({ partition, accountId, applicationRegion }) {
  return new RegExp(
    `^arn:${RegExp.escape(partition)}:secretsmanager:` +
      `${RegExp.escape(applicationRegion)}:${RegExp.escape(accountId)}:` +
      "secret:mem9-on-aws-[A-Za-z0-9/_+=.@-]+(?::[^:]*){0,3}$",
    "u",
  );
}

export function validateProductionTaskDefinitionSecrets({
  partition,
  accountId,
  applicationRegion,
  bootstrapTaskDefinitionArn,
  serviceTaskDefinitionArns,
  taskDefinitions,
}) {
  assertIdentity({ partition, accountId });
  if (!REGION_PATTERN.test(applicationRegion ?? "")) {
    throw new Error("production task definition region is invalid");
  }
  const taskArnPattern = taskDefinitionArnPattern({
    partition,
    accountId,
    applicationRegion,
  });
  if (!taskArnPattern.test(bootstrapTaskDefinitionArn ?? "")) {
    throw new Error("production bootstrap task definition ARN is malformed");
  }
  if (
    !Array.isArray(serviceTaskDefinitionArns) ||
    serviceTaskDefinitionArns.length === 0 ||
    serviceTaskDefinitionArns.some(
      (arn) => typeof arn !== "string" || !taskArnPattern.test(arn),
    )
  ) {
    throw new Error("production service task definition set is malformed");
  }

  const expectedArns = new Set([
    bootstrapTaskDefinitionArn,
    ...serviceTaskDefinitionArns,
  ]);
  if (
    expectedArns.size !== serviceTaskDefinitionArns.length + 1 ||
    !Array.isArray(taskDefinitions) ||
    taskDefinitions.length !== expectedArns.size
  ) {
    throw new Error("production task definition inventory is incomplete");
  }

  const secretArnPattern = projectSecretArnPattern({
    partition,
    accountId,
    applicationRegion,
  });
  const seenArns = new Set();
  for (const taskDefinition of taskDefinitions) {
    const taskDefinitionArn = taskDefinition?.taskDefinitionArn;
    if (
      typeof taskDefinitionArn !== "string" ||
      !expectedArns.has(taskDefinitionArn) ||
      seenArns.has(taskDefinitionArn) ||
      !Array.isArray(taskDefinition.containerDefinitions) ||
      taskDefinition.containerDefinitions.length === 0
    ) {
      throw new Error("production task definition response is malformed");
    }
    seenArns.add(taskDefinitionArn);

    const secretNames = new Map();
    for (const container of taskDefinition.containerDefinitions) {
      if (
        !container ||
        typeof container.name !== "string" ||
        container.name.length === 0 ||
        (container.secrets !== undefined && !Array.isArray(container.secrets))
      ) {
        throw new Error("production task definition container is malformed");
      }
      for (const secret of container.secrets ?? []) {
        if (
          !secret ||
          typeof secret.name !== "string" ||
          secret.name.length === 0 ||
          typeof secret.valueFrom !== "string" ||
          !secretArnPattern.test(secret.valueFrom) ||
          secretNames.has(secret.name)
        ) {
          throw new Error(
            "production task definition secret reference is malformed",
          );
        }
        secretNames.set(secret.name, secret.valueFrom);
      }
    }
    if (
      REQUIRED_TASK_SECRET_NAMES.some(
        (secretName) => !secretNames.has(secretName),
      )
    ) {
      throw new Error(
        "production task definition is missing a required secret reference",
      );
    }
  }
  if (seenArns.size !== expectedArns.size) {
    throw new Error("production task definition inventory is incomplete");
  }
  return true;
}

function productionRoleName(roleArn, { partition, accountId }) {
  const prefix = `arn:${partition}:iam::${accountId}:role/`;
  if (
    typeof roleArn !== "string" ||
    !roleArn.startsWith(prefix) ||
    roleArn.length === prefix.length ||
    roleArn.slice(prefix.length).includes("/")
  ) {
    throw new Error("production runtime role ARN is malformed");
  }
  return roleArn.slice(prefix.length);
}

export function validateProductionRuntimeBindings({
  partition,
  accountId,
  applicationRegion,
  bedrockProjectArn,
  bootstrapTaskDefinitionArn,
  serviceTaskDefinitionArns,
  taskDefinitions,
  lambdaFunctions,
  gateway,
  gatewayId,
}) {
  validateProductionTaskDefinitionSecrets({
    partition,
    accountId,
    applicationRegion,
    bootstrapTaskDefinitionArn,
    serviceTaskDefinitionArns,
    taskDefinitions,
  });

  const projectArnPattern = new RegExp(
    `^arn:${RegExp.escape(partition)}:bedrock-mantle:` +
      `${RegExp.escape(applicationRegion)}:${RegExp.escape(accountId)}:` +
      "project/([A-Za-z0-9_-]+)$",
    "u",
  );
  const projectId = projectArnPattern.exec(bedrockProjectArn ?? "")?.[1];
  if (!projectId) {
    throw new Error("production Bedrock Mantle project ARN is malformed");
  }
  const serviceTaskDefinitionSet = new Set(serviceTaskDefinitionArns);
  for (const taskDefinition of taskDefinitions) {
    if (!serviceTaskDefinitionSet.has(taskDefinition.taskDefinitionArn)) {
      continue;
    }
    const proxyContainers = taskDefinition.containerDefinitions.filter(
      ({ name }) => name === "llm-proxy",
    );
    if (proxyContainers.length !== 1) {
      throw new Error(
        "production task definition llm-proxy inventory is malformed",
      );
    }
    const environment = proxyContainers[0].environment;
    if (!Array.isArray(environment)) {
      throw new Error(
        "production task definition Bedrock project is malformed",
      );
    }
    const projectVariables = environment.filter(
      (variable) => variable?.name === "LLM_PROXY_OPENAI_PROJECT",
    );
    if (
      projectVariables.length !== 1 ||
      projectVariables[0]?.value !== projectId
    ) {
      throw new Error(
        "production task definition Bedrock project does not match the boundary",
      );
    }
  }

  const roleNames = new Set();
  for (const taskDefinition of taskDefinitions) {
    for (const field of ["taskRoleArn", "executionRoleArn"]) {
      roleNames.add(
        requireNonProxyBinding(
          productionRoleName(taskDefinition?.[field], {
            partition,
            accountId,
          }),
          "ECS",
        ),
      );
    }
  }

  if (!Array.isArray(lambdaFunctions)) {
    throw new Error("production Lambda inventory is incomplete");
  }
  for (const type of LAMBDA_EXECUTION_ROLE_TYPES) {
    const count = lambdaFunctions.filter(({ FunctionName }) =>
      matchesProductionLambdaFunctionName(FunctionName, type),
    ).length;
    if (type.optional ? count > 1 : count !== 1) {
      throw new Error("production Lambda inventory is incomplete");
    }
  }
  const functionArnPrefix = `arn:${partition}:lambda:${applicationRegion}:${accountId}:function:`;
  const seenFunctions = new Set();
  for (const fn of lambdaFunctions) {
    if (
      !fn ||
      typeof fn.FunctionName !== "string" ||
      !fn.FunctionName.startsWith("mem9-on-aws-prod-") ||
      seenFunctions.has(fn.FunctionName) ||
      fn.FunctionArn !== `${functionArnPrefix}${fn.FunctionName}`
    ) {
      throw new Error("production Lambda inventory is malformed");
    }
    seenFunctions.add(fn.FunctionName);
    const matchingFunctionTypes = LAMBDA_EXECUTION_ROLE_TYPES.filter(
      (type) => matchesProductionLambdaFunctionName(fn.FunctionName, type),
    );
    if (matchingFunctionTypes.length !== 1) {
      throw new Error("production Lambda inventory is incomplete");
    }
    const roleName = productionRoleName(fn.Role, { partition, accountId });
    if (!matchesProductionLambdaRoleName(roleName, matchingFunctionTypes[0])) {
      throw new Error("production Lambda role binding is malformed");
    }
    if (isVpcProxyRoleName(roleName) !== matchingFunctionTypes[0].isVpcProxy) {
      throw new Error("production Lambda proxy role binding is malformed");
    }
    roleNames.add(roleName);
  }

  if (
    typeof gatewayId !== "string" ||
    gatewayId.length === 0 ||
    !gateway ||
    gateway.gatewayId !== gatewayId ||
    typeof gateway.gatewayArn !== "string" ||
    !gateway.gatewayArn.startsWith(
      `arn:${partition}:bedrock-agentcore:${applicationRegion}:${accountId}:gateway/`,
    )
  ) {
    throw new Error("production AgentCore Gateway response is malformed");
  }
  roleNames.add(
    requireNonProxyBinding(
      productionRoleName(gateway.roleArn, { partition, accountId }),
      "AgentCore Gateway",
    ),
  );

  return [...roleNames].sort();
}

function analyzeMatchingRoles(
  roles,
  rolePatterns,
  { repairableLegacyTrustIdentity } = {},
) {
  for (const pattern of rolePatterns) {
    const marker = ":role/";
    const offset = pattern.indexOf(marker);
    if (
      offset < 0 ||
      !pattern.endsWith("*") ||
      pattern.slice(0, -1).includes("*") ||
      pattern.includes("?")
    ) {
      throw new Error("unsupported role ARN pattern");
    }
  }
  if (repairableLegacyTrustIdentity !== undefined) {
    assertIdentity(repairableLegacyTrustIdentity);
  }

  const matches = new Set();
  const repairableLegacyLambdaRoles = new Set();
  for (const role of roles) {
    if (
      !role ||
      typeof role.name !== "string" ||
      role.name.length === 0 ||
      typeof role.arn !== "string" ||
      !role.arn.endsWith(`/${role.name}`)
    ) {
      throw new Error("IAM role inventory is malformed");
    }
    const matchesPattern = rolePatterns.some((pattern) =>
      globMatches(pattern, role.arn),
    );
    if (isProjectLambdaExecutionRoleName(role.name)) {
      if (verifyLambdaExecutionRoleTrustPolicy(role.assumeRolePolicyDocument)) {
        // Already safe. A resumed rollout must not rewrite it.
      } else if (
        matchesPattern &&
        repairableLegacyTrustIdentity !== undefined &&
        isExactLegacyLambdaTrustPolicy(
          role.assumeRolePolicyDocument,
          repairableLegacyTrustIdentity,
        )
      ) {
        repairableLegacyLambdaRoles.add(role.name);
      } else {
        throw new Error(
          "project Lambda execution role trust policy is not Lambda-only",
        );
      }
    }
    if (matchesPattern) {
      matches.add(role.name);
    }
  }
  return {
    repairableLegacyLambdaRoles: [...repairableLegacyLambdaRoles].sort(),
    roleNames: [...matches].sort(),
  };
}

export function matchingRoleNames(roles, rolePatterns) {
  return analyzeMatchingRoles(roles, rolePatterns).roleNames;
}

async function discoverMatchingRoles(adapter, rolePatterns) {
  const roles = await collectPages(
    (marker) => adapter.listRoles({ marker }),
    "roles",
  );
  return matchingRoleNames(roles, rolePatterns);
}

async function discoverAndRepairMatchingRoles(adapter, rolePatterns, identity) {
  const roles = await collectPages(
    (marker) => adapter.listRoles({ marker }),
    "roles",
  );
  const analysis = analyzeMatchingRoles(roles, rolePatterns, {
    repairableLegacyTrustIdentity: identity,
  });
  if (
    analysis.repairableLegacyLambdaRoles.length > 0 &&
    typeof adapter.updateAssumeRolePolicy !== "function"
  ) {
    throw new Error("Lambda trust repair adapter is not configured");
  }

  for (const roleName of analysis.repairableLegacyLambdaRoles) {
    const before = await adapter.getRole({ roleName });
    if (
      verifyLambdaExecutionRoleTrustPolicy(before?.assumeRolePolicyDocument)
    ) {
      continue;
    }
    if (
      !isExactLegacyLambdaTrustPolicy(
        before?.assumeRolePolicyDocument,
        identity,
      )
    ) {
      throw new Error(
        "project Lambda execution role trust changed before repair",
      );
    }
    await adapter.updateAssumeRolePolicy({
      policyDocument: lambdaExecutionRoleTrustPolicy(),
      roleName,
    });
    const after = await adapter.getRole({ roleName });
    if (
      !verifyLambdaExecutionRoleTrustPolicy(after?.assumeRolePolicyDocument)
    ) {
      throw new Error(
        "project Lambda execution role trust repair read-back mismatch",
      );
    }
  }
  return analysis.roleNames;
}

function sameList(left, right) {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function requireLiveRoleCoverage(liveRoleNames, inventoryRoleNames) {
  const inventoryRoleNameSet = new Set(inventoryRoleNames);
  if (
    !Array.isArray(liveRoleNames) ||
    liveRoleNames.length === 0 ||
    !sameList(liveRoleNames, [...new Set(liveRoleNames)].sort()) ||
    liveRoleNames.some((roleName) => !inventoryRoleNameSet.has(roleName))
  ) {
    throw new Error(
      "production runtime role bindings are outside the migration inventory",
    );
  }
}

function isProjectLambdaExecutionRoleName(roleName) {
  return (
    typeof roleName === "string" &&
    ROLE_PREFIXES.some((prefix) => roleName.startsWith(prefix)) &&
    LAMBDA_EXECUTION_ROLE_TYPES.some((type) =>
      matchesProjectLambdaRoleName(roleName, type),
    )
  );
}

function isVpcProxyRoleName(roleName) {
  return (
    isProjectLambdaExecutionRoleName(roleName) &&
    LAMBDA_EXECUTION_ROLE_TYPES.some(
      (type) =>
        type.isVpcProxy && matchesProjectLambdaRoleName(roleName, type),
    )
  );
}

export function lambdaExecutionRoleTrustPolicy() {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: "sts:AssumeRole",
        Principal: { Service: "lambda.amazonaws.com" },
      },
    ],
  };
}

function exactAssumeRolePrincipal(document) {
  let decoded;
  try {
    decoded = decodePolicyDocument(document);
  } catch {
    return false;
  }
  if (
    decoded.Version !== "2012-10-17" ||
    !sameStringSet(Object.keys(decoded), ["Version", "Statement"])
  ) {
    return false;
  }
  const statements = list(decoded.Statement);
  if (statements.length !== 1) return undefined;
  const statement = statements[0];
  if (
    statement?.Effect !== "Allow" ||
    !sameStringSet(Object.keys(statement), ["Action", "Effect", "Principal"]) ||
    !sameStringSet(statement.Action, ["sts:AssumeRole"]) ||
    !statement.Principal
  ) {
    return undefined;
  }
  return statement.Principal;
}

export function verifyLambdaExecutionRoleTrustPolicy(document) {
  const principal = exactAssumeRolePrincipal(document);
  return Boolean(
    principal &&
      sameStringSet(Object.keys(principal), ["Service"]) &&
      sameStringSet(principal.Service, ["lambda.amazonaws.com"]),
  );
}

function isExactLegacyLambdaTrustPolicy(document, { partition, accountId }) {
  try {
    assertIdentity({ partition, accountId });
  } catch {
    return false;
  }
  const principal = exactAssumeRolePrincipal(document);
  return Boolean(
    principal &&
      sameStringSet(Object.keys(principal), ["AWS", "Service"]) &&
      sameStringSet(principal.Service, ["lambda.amazonaws.com"]) &&
      sameStringSet(principal.AWS, [
        `arn:${partition}:iam::${accountId}:root`,
      ]),
  );
}

function requireNonProxyBinding(roleName, bindingType) {
  if (isVpcProxyRoleName(roleName)) {
    throw new Error(`VPC proxy role is bound to production ${bindingType}`);
  }
  return roleName;
}

function createDeadlineAdapter(adapter, deadlineAt) {
  if (!Number.isFinite(deadlineAt) || deadlineAt <= Date.now()) {
    throw new Error("workload boundary rollout deadline is invalid or expired");
  }
  return new Proxy(adapter, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if (typeof value !== "function") return value;
      return (...args) => {
        const remaining = deadlineAt - Date.now();
        if (remaining <= 0) {
          throw new Error("workload boundary rollout deadline exceeded");
        }
        let timer;
        return Promise.race([
          Promise.resolve(value.apply(target, args)),
          new Promise((_, reject) => {
            timer = setTimeout(
              () =>
                reject(
                  new Error("workload boundary rollout deadline exceeded"),
                ),
              remaining,
            );
            timer.unref?.();
          }),
        ])
          .then((result) => {
            if (Date.now() > deadlineAt) {
              throw new Error("workload boundary rollout deadline exceeded");
            }
            return result;
          })
          .finally(() => clearTimeout(timer));
      };
    },
  });
}

async function requireBoundary(adapter, roleName, boundaryArn) {
  const role = await adapter.getRole({ roleName });
  if (role?.permissionsBoundaryArn !== boundaryArn) {
    throw new Error("workload role boundary read-back mismatch");
  }
}

export async function runBoundaryRollout(
  adapter,
  {
    deployRoleName,
    boundaryArn,
    partition,
    accountId,
    resumeCommand,
    reviewedCommit,
    deadlineAt = Date.now() + ROLLOUT_TIMEOUT_MS,
  },
) {
  if (
    typeof reviewedCommit !== "string" ||
    !/^[0-9a-f]{40}$/u.test(reviewedCommit) ||
    typeof adapter.verifyFinalGithubInterlock !== "function"
  ) {
    throw new Error("final GitHub interlock configuration is invalid");
  }
  if (typeof adapter.verifyBoundaryRegion !== "function") {
    throw new Error("boundary region preflight configuration is invalid");
  }
  const boundedAdapter = createDeadlineAdapter(adapter, deadlineAt);
  let quarantineAttempted = false;
  let quarantineRemoved = false;
  try {
    // Catch a retained stack from another application region before quarantine
    // or any other IAM mutation. The full runtime binding read still runs below,
    // immediately before boundary attachment.
    await boundedAdapter.verifyBoundaryRegion();
    quarantineAttempted = true;
    await boundedAdapter.putQuarantine({
      roleName: deployRoleName,
      policyName: QUARANTINE_POLICY_NAME,
      policyDocument: quarantinePolicyDocument(),
    });
    if (!(await boundedAdapter.verifyQuarantine())) {
      throw new Error("deploy-role quarantine verification failed");
    }
    await boundedAdapter.deployBoundary();

    const discovery = { roleName: deployRoleName, partition, accountId };
    const scopeBefore = await discoverPassRoleScope(boundedAdapter, discovery);
    const rolesBefore = await discoverAndRepairMatchingRoles(
      boundedAdapter,
      scopeBefore,
      { partition, accountId },
    );
    if (rolesBefore.length === 0) {
      throw new Error("no workload roles matched the deployed PassRole scope");
    }
    const liveRolesBefore =
      await boundedAdapter.verifyProductionRuntimeBindings();
    requireLiveRoleCoverage(liveRolesBefore, rolesBefore);

    for (const roleName of rolesBefore) {
      const current = await boundedAdapter.getRole({ roleName });
      const currentBoundary = current?.permissionsBoundaryArn;
      if (currentBoundary === boundaryArn) continue;
      if (currentBoundary) {
        throw new Error("workload role has an unexpected permissions boundary");
      }
      await boundedAdapter.putRoleBoundary({
        roleName,
        permissionsBoundary: boundaryArn,
      });
      await requireBoundary(boundedAdapter, roleName, boundaryArn);
    }
    for (const roleName of rolesBefore) {
      await requireBoundary(boundedAdapter, roleName, boundaryArn);
    }

    const scopeBeforeEnforcement = await discoverPassRoleScope(
      boundedAdapter,
      discovery,
    );
    const rolesBeforeEnforcement = await discoverMatchingRoles(
      boundedAdapter,
      scopeBeforeEnforcement,
    );
    if (
      !sameList(scopeBefore, scopeBeforeEnforcement) ||
      !sameList(rolesBefore, rolesBeforeEnforcement)
    ) {
      throw new Error("PassRole scope or workload role inventory changed");
    }

    await boundedAdapter.deployPermanentEnforcement();
    if (!(await boundedAdapter.verifyQuarantine())) {
      throw new Error("deploy-role quarantine disappeared during enforcement");
    }

    const verifyFrozenState = async () => {
      const policyDocuments = await loadRolePolicyDocuments(
        boundedAdapter,
        deployRoleName,
      );
      const scope = extractPassRoleScope(policyDocuments, {
        partition,
        accountId,
      });
      const roles = await discoverMatchingRoles(boundedAdapter, scope);
      if (!sameList(scopeBefore, scope) || !sameList(rolesBefore, roles)) {
        throw new Error("PassRole scope changed during permanent enforcement");
      }
      const liveRoles = await boundedAdapter.verifyProductionRuntimeBindings();
      requireLiveRoleCoverage(liveRoles, roles);
      if (!sameList(liveRolesBefore, liveRoles)) {
        throw new Error(
          "production runtime role bindings changed during rollout",
        );
      }
      for (const roleName of roles) {
        await requireBoundary(boundedAdapter, roleName, boundaryArn);
      }
      if (
        !(await boundedAdapter.verifyPermanentEnforcement({
          boundaryArn,
        }))
      ) {
        throw new Error(
          "permanent permissions-boundary enforcement is incomplete",
        );
      }
      return roles;
    };
    const rolesAfter = await verifyFrozenState();
    // Re-read the operator-owned policy at the last possible point before prod
    // activation. The guarded deploy command verifies exact content and stack
    // state, and repairs direct drift while quarantine is still installed.
    await boundedAdapter.deployBoundary();
    await boundedAdapter.activateProductionBoundary();
    if (!(await boundedAdapter.verifyQuarantine())) {
      throw new Error("deploy-role quarantine failed final verification");
    }
    await boundedAdapter.verifyFinalGithubInterlock({ reviewedCommit });
    await verifyFrozenState();
    if (!(await boundedAdapter.verifyQuarantine())) {
      throw new Error("deploy-role quarantine failed final verification");
    }

    // Deletion owns a separate recovery budget so an interrupted or timed-out
    // response can reinstall and verify quarantine before the process exits.
    await adapter.deleteQuarantine({
      roleName: deployRoleName,
      policyName: QUARANTINE_POLICY_NAME,
    });
    quarantineRemoved = true;
    await boundedAdapter.resumeDeployments();
    return { verifiedRoleCount: rolesAfter.length, status: "complete" };
  } catch (error) {
    if (error && typeof error === "object") {
      error.quarantineAttempted = quarantineAttempted;
      error.quarantineRemoved = quarantineRemoved;
      error.resumeCommand = resumeCommand;
    }
    throw error;
  }
}

export function redactedRolloutFailure(error) {
  const attempted =
    error && typeof error === "object" && error.quarantineAttempted === true;
  const removed =
    error && typeof error === "object" && error.quarantineRemoved === true;
  const pauseRestored =
    error && typeof error === "object"
      ? error.deploymentPauseRestored
      : undefined;
  const workflowsRestored =
    error && typeof error === "object"
      ? error.deploymentWorkflowsRestored
      : undefined;
  const resumeCommand =
    error &&
    typeof error === "object" &&
    typeof error.resumeCommand === "string"
      ? error.resumeCommand
      : ROLLOUT_RESUME_COMMAND;
  return [
    "Workload permissions-boundary rollout failed.",
    removed
      ? "Permanent enforcement remains active; quarantine was removed after verification."
      : attempted
        ? "Quarantine was attempted and must be treated as installed; do not remove it manually."
        : "No quarantine write was attempted.",
    ...(removed
      ? pauseRestored === true && workflowsRestored === false
        ? [
            "The deployment pause was restored, but workflow rollback failed; verify and disable every deployment workflow before retrying.",
          ]
        : pauseRestored === true
          ? [
              "The deployment pause was restored after resume failed; re-run the guarded command.",
            ]
          : pauseRestored === false && workflowsRestored === false
            ? [
                "Deployment resume, maintenance-pause restoration, and workflow rollback failed; restore the pause and disable every deployment workflow before retrying.",
              ]
            : pauseRestored === false
              ? [
                  "Deployment resume and maintenance-pause restoration both failed; treat deployments as unpaused and restore the pause before retrying.",
                ]
              : [
                  "Deployment resume failed after quarantine removal; verify and restore the maintenance pause before retrying.",
                ]
      : []),
    `Resume: ${resumeCommand}`,
  ].join("\n");
}
