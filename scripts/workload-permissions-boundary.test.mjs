import { spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { parse } from "yaml";
import {
  DENY_DANGEROUS_POLICY_NAME,
  DEPLOY_ROLE_NAME,
  QUARANTINE_POLICY_NAME,
  ROLLOUT_RESUME_COMMAND,
  WORKLOAD_BOUNDARY_POLICY_NAME,
  WORKLOAD_BOUNDARY_STACK_NAME,
  discoverPassRoleScope,
  expectedBoundaryPolicyDocument,
  expectedRolePatterns,
  extractPassRoleScope,
  lambdaExecutionRoleTrustPolicy,
  matchingRoleNames,
  quarantinePolicyDocument,
  redactedRolloutFailure,
  runBoundaryRollout,
  validateProductionRuntimeBindings,
  validateProductionTaskDefinitionSecrets,
  verifyBoundaryPolicyDocument,
  verifyLambdaExecutionRoleTrustPolicy,
  verifyPermanentEnforcementDocuments,
  verifyQuarantinePolicy,
} from "./lib/workload-permissions-boundary.mjs";
import {
  AWS_CLI_TIMEOUT_MS,
  DEPLOY_COMMAND_TIMEOUT_MS,
  QUARANTINE_PROBE_ACTIONS,
  createAwsCliAdapter,
  invokeAwsCli,
  resolveAwsIdentity,
} from "./lib/workload-permissions-boundary-aws.mjs";
import {
  remainingCommandTimeout,
  runBoundedCommand,
} from "./lib/bounded-subprocess.mjs";
import {
  DEPLOYMENT_WORKFLOWS,
  NONTERMINAL_WORKFLOW_STATUSES,
  ROLLOUT_SHUTDOWN_GRACE_MS,
  ROLLOUT_TIMEOUT_MS,
  createGithubMaintenanceController,
  executeBoundaryRollout,
  parseRolloutArguments,
  runBoundaryRolloutCli,
} from "./rollout-workload-permissions-boundary.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const boundaryTemplatePath = resolve(
  root,
  "infra/cloudformation/workload-permissions-boundary.yaml",
);
const deployRoleTemplatePath = resolve(
  root,
  "infra/cloudformation/github-actions-role.yaml",
);
const workflowPath = resolve(root, ".github/workflows/infra-ci.yml");
const documentationSecurityWorkflowPath = resolve(
  root,
  ".github/workflows/docs-security.yml",
);
const reconciliationWorkflowPath = resolve(
  root,
  ".github/workflows/reconcile-previews.yml",
);
const rolloutWrapperPath = resolve(
  root,
  "scripts/rollout-workload-permissions-boundary.sh",
);
const boundaryDeployPath = resolve(
  root,
  "scripts/deploy-workload-permissions-boundary.sh",
);
const rolloutModulePath = resolve(
  root,
  "scripts/rollout-workload-permissions-boundary.mjs",
);
const rolloutCliPath = resolve(
  root,
  "scripts/run-workload-permissions-boundary-rollout.mjs",
);
const rolloutContractPath = resolve(
  root,
  "scripts/workload-permissions-boundary-contract.json",
);
const rolloutContract = JSON.parse(readFileSync(rolloutContractPath, "utf8"));
const reviewedWorkflowBlobs = new Map(
  rolloutContract.deploymentWorkflows.map(({ id, reviewedBlob }) => [
    id,
    reviewedBlob,
  ]),
);

const partition = "aws";
const accountId = "123456789012";
const reviewedCommit = "34adad58d807052f85bbee59dc8bcaa78366f379";
const boundaryArn =
  "arn:aws:iam::123456789012:policy/mem9-on-aws-workload-boundary";
const boundaryContract = {
  accountId,
  applicationRegion: "ap-northeast-1",
  bedrockProjectArn:
    "arn:aws:bedrock-mantle:ap-northeast-1:123456789012:project/proj_test",
  partition,
};
const patterns = expectedRolePatterns({ partition, accountId });
const consolidationSchedulerRolePattern =
  `arn:${partition}:iam::${accountId}:role/` +
  "mem9-on-a*-*Mem9ConsolidationSchedulerRole-*";
const denyPolicyId = DENY_DANGEROUS_POLICY_NAME;
const denyPolicyArn = `arn:${partition}:iam::${accountId}:policy/${denyPolicyId}`;
const independentRuntimeActions = [
  // AWSLambdaBasicExecutionRole v1.
  "logs:CreateLogGroup",
  "logs:CreateLogStream",
  "logs:PutLogEvents",
  // AWSLambdaVPCAccessExecutionRole v3 additions.
  "ec2:AssignPrivateIpAddresses",
  "ec2:CreateNetworkInterface",
  "ec2:DeleteNetworkInterface",
  "ec2:DescribeNetworkInterfaces",
  "ec2:DescribeSubnets",
  "ec2:UnassignPrivateIpAddresses",
  // AmazonECSTaskExecutionRolePolicy v1 additions.
  "ecr:BatchCheckLayerAvailability",
  "ecr:BatchGetImage",
  "ecr:GetAuthorizationToken",
  "ecr:GetDownloadUrlForLayer",
  // Current project runtime calls.
  "bedrock-mantle:CallWithBearerToken",
  "bedrock-mantle:CreateInference",
  "bedrock-mantle:GetProject",
  "bedrock-mantle:ListProjects",
  "bedrock-mantle:ListTagsForResource",
  "ecs:RunTask",
  "iam:PassRole",
  "kms:Decrypt",
  "lambda:InvokeFunction",
  "secretsmanager:GetSecretValue",
  "sns:Publish",
  "sqs:SendMessage",
  "ssm:GetParameters",
  "ssm:PutParameter",
  // SST Service/Task ECS Exec channels.
  "ssmmessages:CreateControlChannel",
  "ssmmessages:CreateDataChannel",
  "ssmmessages:OpenControlChannel",
  "ssmmessages:OpenDataChannel",
].sort();

const productionTaskDefinitions = {
  bootstrap:
    "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-on-aws-prod-Mem9Bootstrap:5",
  primary:
    "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-on-aws-prod-Mem9Server:42",
  replacement:
    "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-on-aws-prod-Mem9Server:43",
};
const productionSecretArns = {
  database:
    "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:mem9-on-aws-prod-Mem9Db-secret",
  tenant:
    "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:mem9-on-aws-prod-tenant-api-key-secret",
};
const productionRoleNames = {
  alertRouter: "mem9-on-aws-prod-Mem9AlertRouterRole-fixture",
  bootstrapExecution: "mem9-on-aws-prod-Mem9BootstrapExecutionRole-fixture",
  bootstrapTask: "mem9-on-aws-prod-Mem9BootstrapTaskRole-fixture",
  gateway: "mem9-on-aws-prod-Mem9GatewayServiceRole-fixture",
  oauthFacade: "mem9-on-aws-prod-Mem9OauthFacadeFnRole-fixture",
  proxy: "mem9-on-aws-prod-Mem9ProxyFnRole-fixture",
  serviceExecution: "mem9-on-aws-prod-Mem9ServerExecutionRole-fixture",
  serviceTask: "mem9-on-aws-prod-Mem9ServerTaskRole-fixture",
};
const productionRoleArns = Object.fromEntries(
  Object.entries(productionRoleNames).map(([key, name]) => [
    key,
    `arn:aws:iam::${accountId}:role/${name}`,
  ]),
);
const facadeAuthorizerRoleName =
  "mem9-on-aws-prod-Mem9OauthFacadeAllowAllRole";
const facadeAuthorizerRoleArn =
  `arn:aws:iam::${accountId}:role/${facadeAuthorizerRoleName}`;
const facadeAuthorizerFunctionName =
  "mem9-on-aws-prod-Mem9OauthFacadeAllowAll";
const expectedProductionRoleNames = Object.values(productionRoleNames).sort();

function taskDefinition(arn, family) {
  const bootstrap = family.includes("Bootstrap");
  return {
    taskDefinitionArn: arn,
    family,
    taskRoleArn: bootstrap
      ? productionRoleArns.bootstrapTask
      : productionRoleArns.serviceTask,
    executionRoleArn: bootstrap
      ? productionRoleArns.bootstrapExecution
      : productionRoleArns.serviceExecution,
    containerDefinitions: [
      {
        name: family.includes("Bootstrap") ? "bootstrap" : "mnemo-server",
        secrets: [
          {
            name: "MEM9_DB_SECRET",
            valueFrom: productionSecretArns.database,
          },
          {
            name: "MEM9_TENANT_ID",
            valueFrom: productionSecretArns.tenant,
          },
        ],
      },
      ...(!bootstrap
        ? [
            {
              environment: [
                {
                  name: "LLM_PROXY_OPENAI_PROJECT",
                  value: "proj_test",
                },
              ],
              name: "llm-proxy",
            },
          ]
        : []),
    ],
  };
}

function productionPreflightAws(args, override = {}) {
  const command = args.slice(0, 2).join(" ");
  if (Object.hasOwn(override, command)) return override[command];
  switch (command) {
    case "cloudformation describe-stacks":
      return {
        Stacks: [
          {
            Parameters: [
              {
                ParameterKey: "ApplicationRegion",
                ParameterValue: boundaryContract.applicationRegion,
              },
              {
                ParameterKey: "BedrockProjectArn",
                ParameterValue: boundaryContract.bedrockProjectArn,
              },
              {
                ParameterKey: "PolicyRevision",
                ParameterValue: "r1",
              },
            ],
            StackStatus: "UPDATE_COMPLETE",
          },
        ],
      };
    case "ssm get-parameters":
      return {
        InvalidParameters: [],
        Parameters: [
          {
            Name: "/mem9-on-aws/prod/ecs/cluster-name",
            Value: "mem9-prod-cluster",
          },
          {
            Name: "/mem9-on-aws/prod/ecs/service-name",
            Value: "mem9-prod-service",
          },
          {
            Name: "/mem9-on-aws/prod/bootstrap/task-def-arn",
            Value: productionTaskDefinitions.bootstrap,
          },
          {
            Name: "/mem9-on-aws/prod/gateway/id",
            Value: "gateway-prod-123",
          },
        ],
      };
    case "ecs describe-services":
      return {
        failures: [],
        services: [
          {
            deployments: [
              {
                status: "PRIMARY",
                taskDefinition: productionTaskDefinitions.primary,
              },
              {
                status: "ACTIVE",
                taskDefinition: productionTaskDefinitions.replacement,
              },
            ],
            serviceName: "mem9-prod-service",
            taskDefinition: productionTaskDefinitions.primary,
          },
        ],
      };
    case "ecs list-tasks":
      return {
        taskArns:
          argument(args, "--desired-status") === "RUNNING"
            ? ["arn:aws:ecs:ap-northeast-1:123456789012:task/running"]
            : ["arn:aws:ecs:ap-northeast-1:123456789012:task/pending"],
      };
    case "ecs describe-tasks":
      return {
        failures: [],
        tasks: [
          {
            taskArn: "arn:aws:ecs:ap-northeast-1:123456789012:task/running",
            taskDefinitionArn: productionTaskDefinitions.primary,
          },
          {
            taskArn: "arn:aws:ecs:ap-northeast-1:123456789012:task/pending",
            taskDefinitionArn: productionTaskDefinitions.replacement,
          },
        ],
      };
    case "ecs describe-task-definition": {
      const taskDefinitionArn = argument(args, "--task-definition");
      return {
        taskDefinition: taskDefinition(
          taskDefinitionArn,
          taskDefinitionArn?.includes("Mem9Bootstrap")
            ? "mem9-on-aws-prod-Mem9Bootstrap"
            : "mem9-on-aws-prod-Mem9Server",
        ),
      };
    }
    case "lambda list-functions":
      return {
        Functions: [
          ["Mem9AlertRouter", productionRoleArns.alertRouter],
          ["Mem9OauthFacadeFn", productionRoleArns.oauthFacade],
          ["Mem9ProxyFn", productionRoleArns.proxy],
        ].map(([logicalName, roleArn]) => {
          const FunctionName = `mem9-on-aws-prod-${logicalName}-fixture`;
          return {
            FunctionArn:
              `arn:aws:lambda:ap-northeast-1:${accountId}:function:` +
              FunctionName,
            FunctionName,
            Role: roleArn,
          };
        }),
      };
    case "bedrock-agentcore-control get-gateway":
      return {
        gatewayArn:
          `arn:aws:bedrock-agentcore:ap-northeast-1:${accountId}:` +
          "gateway/gateway-prod-123",
        gatewayId: "gateway-prod-123",
        roleArn: productionRoleArns.gateway,
      };
    default:
      throw new Error(`unexpected preflight AWS command: ${command}`);
  }
}

const expectedLambdaOnlyTrustPolicy = {
  Version: "2012-10-17",
  Statement: [
    {
      Effect: "Allow",
      Action: "sts:AssumeRole",
      Principal: { Service: "lambda.amazonaws.com" },
    },
  ],
};
const lambdaOnlyTrustPolicy = lambdaExecutionRoleTrustPolicy();
const legacyLambdaTrustPolicy = {
  Version: "2012-10-17",
  Statement: [
    {
      Effect: "Allow",
      Action: "sts:AssumeRole",
      Principal: {
        AWS: `arn:${partition}:iam::${accountId}:root`,
        Service: "lambda.amazonaws.com",
      },
    },
  ],
};

function isFixtureLambdaRoleName(name) {
  return [
    "Mem9AlertRouterRole-",
    "Mem9OauthFacadeAllowAllRole",
    "Mem9OauthFacadeFnRole-",
    "Mem9ProxyFnRole-",
  ].some((token) => name.includes(token));
}

function role(
  name,
  path = "",
  assumeRolePolicyDocument = isFixtureLambdaRoleName(name)
    ? lambdaOnlyTrustPolicy
    : undefined,
) {
  return {
    arn: `arn:${partition}:iam::${accountId}:role/${path}${name}`,
    assumeRolePolicyDocument,
    name,
  };
}

const cloudFormationTags = [
  ...["!Ref", "!Sub", "!GetAtt"].map((tag) => ({
    tag,
    resolve: (value) => value,
  })),
  ...["!If", "!Equals", "!Not"].map((tag) => ({
    tag,
    collection: "seq",
    resolve: (value) => value,
  })),
];

function parseCloudFormation(path) {
  return parse(readFileSync(path, "utf8"), { customTags: cloudFormationTags });
}

function gitBlobHash(path) {
  const contents = readFileSync(path);
  return createHash("sha1")
    .update(`blob ${contents.length}\0`)
    .update(contents)
    .digest("hex");
}

async function withMutatedRolloutModule(mutate, callback) {
  const sourcePath = resolve(
    root,
    "scripts/lib/workload-permissions-boundary.mjs",
  );
  const temporaryPath = resolve(
    root,
    "scripts/lib",
    `.workload-permissions-boundary.local.mutant-${randomUUID()}.mjs`,
  );
  const source = readFileSync(sourcePath, "utf8");
  const mutated = mutate(source);
  if (mutated === source) {
    throw new Error("workload boundary mutation did not change the module");
  }
  await writeFile(temporaryPath, mutated, { mode: 0o600 });
  try {
    const module = await import(
      /* @vite-ignore */ `${pathToFileURL(temporaryPath).href}?v=${randomUUID()}`
    );
    return await callback(module);
  } finally {
    await rm(temporaryPath, { force: true });
  }
}

// Sentinel for a collapsed Fn::If whose condition is false with template
// defaults (AWS::NoValue removes the entry from the surrounding list).
const NO_VALUE = Symbol("AWS::NoValue");

function resolveTemplateValue(value) {
  if (Array.isArray(value)) {
    // A parsed `!If [HasOpenAiBedrockProject, ...]` node: the parameter
    // defaults to "" so the condition is false → the else branch is
    // AWS::NoValue → the entry vanishes from the parent list.
    if (value.length === 3 && value[0] === "HasOpenAiBedrockProject") {
      return NO_VALUE;
    }
    return value.map(resolveTemplateValue).filter((item) => item !== NO_VALUE);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [
        key,
        resolveTemplateValue(child),
      ]),
    );
  }
  if (typeof value !== "string") return value;
  if (value === "BedrockProjectArn") return boundaryContract.bedrockProjectArn;
  return value
    .replaceAll("${AWS::Partition}", partition)
    .replaceAll("${AWS::AccountId}", accountId)
    .replaceAll("${AWS::URLSuffix}", "amazonaws.com")
    .replaceAll("${ApplicationRegion}", boundaryContract.applicationRegion)
    .replaceAll("${PolicyRevision}", "r1")
    .replaceAll("${ProjectName}", "mem9-on-aws")
    .replaceAll("${GitHubRepo}", "mem9-on-aws");
}

function deployedManagedPolicyDocuments() {
  return deployedManagedPolicyFixtures().map(({ document }) => document);
}

function deployedManagedPolicyFixtures() {
  const template = parseCloudFormation(deployRoleTemplatePath);
  return Object.entries(template.Resources)
    .filter(([, resource]) => resource.Type === "AWS::IAM::ManagedPolicy")
    .map(([logicalId, resource]) => ({
      arn:
        logicalId === "DenyPolicy"
          ? denyPolicyArn
          : `arn:${partition}:iam::${accountId}:policy/test-${logicalId}`,
      document: resolveTemplateValue(resource.Properties.PolicyDocument),
      logicalId,
    }));
}

function deployedDenyPolicyDocument() {
  return deployedManagedPolicyFixtures().find(
    ({ logicalId }) => logicalId === "DenyPolicy",
  ).document;
}

function passRolePolicy(resources = patterns) {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: "iam:PassRole",
        Resource: resources,
        Condition: {
          StringEquals: {
            "iam:PassedToService": [
              "lambda.amazonaws.com",
              "ecs-tasks.amazonaws.com",
              "bedrock-agentcore.amazonaws.com",
            ],
          },
        },
      },
    ],
  };
}

function consolidationSchedulerPassRolePolicy({
  resources = [consolidationSchedulerRolePattern],
  services = ["scheduler.amazonaws.com"],
} = {}) {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: "iam:PassRole",
        Resource: resources,
        Condition: {
          StringEquals: {
            "iam:PassedToService": services,
          },
        },
      },
    ],
  };
}

function argument(args, name) {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
}

function optionValues(args, name) {
  const start = args.indexOf(name);
  if (start === -1) return [];
  const values = [];
  for (const value of args.slice(start + 1)) {
    if (value.startsWith("--")) break;
    values.push(value);
  }
  return values;
}

async function runBoundaryDeployMock({
  boundarySimulationBadProbe = "",
  boundarySimulationMalformedProbe = "",
  defaultVersionDriftsAfterSimulation = false,
  guarded = false,
  matching = false,
  postMutationDrift = false,
  quarantineLostAfterSimulation = false,
  quarantine = true,
  quarantineSimulation,
  simulationCommandFails = false,
  stackExists = true,
  stackStatus = "UPDATE_COMPLETE",
  verifyOnly = false,
} = {}) {
  const directory = await mkdtemp(join(tmpdir(), "mem9-boundary-deploy-"));
  const awsPath = join(directory, "aws");
  const callsPath = join(directory, "calls");
  const createdPath = join(directory, "created");
  const updatedPath = join(directory, "updated");
  const expectedPath = join(directory, "expected.json");
  const boundarySimulationsPath = join(
    directory,
    "boundary-simulations.json",
  );
  const quarantinePath = join(directory, "quarantine.json");
  const simulationPath = join(directory, "simulation.json");
  const simulationCompletePath = join(directory, "simulation-complete");
  const expectedBoundaryPolicy =
    expectedBoundaryPolicyDocument(boundaryContract);
  await writeFile(
    expectedPath,
    JSON.stringify(expectedBoundaryPolicy),
  );
  const lambdaContext =
    "ContextKeyName=kms:EncryptionContext:aws:lambda:FunctionArn," +
    "ContextKeyValues=arn:aws:lambda:ap-northeast-1:123456789012:" +
    "function:mem9-on-aws-regression-probe,ContextKeyType=string";
  const lambdaPrincipalContext =
    "ContextKeyName=aws:PrincipalArn," +
    "ContextKeyValues=arn:aws:iam::123456789012:role/" +
    "mem9-on-aws-prod-Mem9OauthFacadeFnRole-regression-probe," +
    "ContextKeyType=string";
  const facadeAuthorizerPrincipalContext =
    "ContextKeyName=aws:PrincipalArn," +
    "ContextKeyValues=arn:aws:iam::123456789012:role/" +
    "mem9-on-aws-prod-Mem9OauthFacadeAllowAllRole," +
    "ContextKeyType=string";
  const nonLambdaPrincipalContext =
    "ContextKeyName=aws:PrincipalArn," +
    "ContextKeyValues=arn:aws:iam::123456789012:role/" +
    "mem9-on-aws-prod-Mem9ServerTaskRole-regression-probe," +
    "ContextKeyType=string";
  const outsideLambdaContext =
    "ContextKeyName=kms:EncryptionContext:aws:lambda:FunctionArn," +
    "ContextKeyValues=arn:aws:lambda:ap-northeast-1:123456789012:" +
    "function:outside-project-regression-probe,ContextKeyType=string";
  const sourceFunctionContext =
    "ContextKeyName=lambda:SourceFunctionArn," +
    "ContextKeyValues=arn:aws:lambda:ap-northeast-1:123456789012:" +
    "function:mem9-on-aws-regression-probe,ContextKeyType=string";
  const ssmContext =
    "ContextKeyName=kms:EncryptionContext:PARAMETER_ARN," +
    "ContextKeyValues=arn:aws:ssm:ap-northeast-1:123456789012:" +
    "parameter/mem9-on-aws/regression-probe,ContextKeyType=string";
  const ssmViaContext =
    "ContextKeyName=kms:ViaService," +
    "ContextKeyValues=ssm.ap-northeast-1.amazonaws.com," +
    "ContextKeyType=string";
  const secretContext =
    "ContextKeyName=kms:EncryptionContext:SecretARN," +
    "ContextKeyValues=arn:aws:secretsmanager:ap-northeast-1:123456789012:" +
    "secret:mem9-on-aws-prod-Mem9DbSecret-regression," +
    "ContextKeyType=string";
  const tenantSecretContext =
    "ContextKeyName=kms:EncryptionContext:SecretARN," +
    "ContextKeyValues=arn:aws:secretsmanager:ap-northeast-1:123456789012:" +
    "secret:mem9-on-aws-prod-tenant-api-key-regression," +
    "ContextKeyType=string";
  const outsideSecretContext =
    "ContextKeyName=kms:EncryptionContext:SecretARN," +
    "ContextKeyValues=arn:aws:secretsmanager:ap-northeast-1:123456789012:" +
    "secret:outside-project-regression,ContextKeyType=string";
  const secretVersionContext =
    "ContextKeyName=kms:EncryptionContext:SecretVersionId," +
    "ContextKeyValues=regression-version,ContextKeyType=string";
  const secretViaContext =
    "ContextKeyName=kms:ViaService," +
    "ContextKeyValues=secretsmanager.ap-northeast-1.amazonaws.com," +
    "ContextKeyType=string";
  const crossRegionSecretViaContext =
    "ContextKeyName=kms:ViaService," +
    "ContextKeyValues=secretsmanager.us-west-2.amazonaws.com," +
    "ContextKeyType=string";
  const serverExecutionPrincipalContext =
    "ContextKeyName=aws:PrincipalArn," +
    "ContextKeyValues=arn:aws:iam::123456789012:role/" +
    "mem9-on-aws-prod-Mem9ServerExecutionRole-regression-probe," +
    "ContextKeyType=string";
  const bootstrapExecutionPrincipalContext =
    "ContextKeyName=aws:PrincipalArn," +
    "ContextKeyValues=arn:aws:iam::123456789012:role/" +
    "mem9-on-aws-prod-Mem9BootstrapExecutionRole-regression-probe," +
    "ContextKeyType=string";
  await writeFile(
    boundarySimulationsPath,
    JSON.stringify({
      policyInputList: [
        JSON.stringify({
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Action: "kms:Decrypt",
              Resource: "*",
            },
          ],
        }),
      ],
      permissionsBoundaryPolicyInputList: [
        JSON.stringify(expectedBoundaryPolicy),
      ],
      actionNames: ["kms:Decrypt"],
      resourceArns: ["*"],
      output: ["json"],
      probes: [
        {
          name: "project-lambda",
          decision: "allowed",
          contextEntries: [lambdaContext, lambdaPrincipalContext],
        },
        {
          name: "facade-authorizer-lambda",
          decision: "allowed",
          contextEntries: [lambdaContext, facadeAuthorizerPrincipalContext],
        },
        {
          name: "project-ssm",
          decision: "allowed",
          contextEntries: [
            ssmContext,
            ssmViaContext,
            sourceFunctionContext,
          ],
        },
        {
          name: "server-secret",
          decision: "allowed",
          contextEntries: [
            secretContext,
            secretVersionContext,
            secretViaContext,
            serverExecutionPrincipalContext,
          ],
        },
        {
          name: "bootstrap-secret",
          decision: "allowed",
          contextEntries: [
            tenantSecretContext,
            secretVersionContext,
            secretViaContext,
            bootstrapExecutionPrincipalContext,
          ],
        },
        {
          name: "direct-ssm",
          decision: "explicitDeny",
          contextEntries: [ssmContext],
        },
        {
          name: "direct-secret",
          decision: "explicitDeny",
          contextEntries: [
            secretContext,
            secretVersionContext,
            serverExecutionPrincipalContext,
          ],
        },
        {
          name: "outside-secret",
          decision: "explicitDeny",
          contextEntries: [
            outsideSecretContext,
            secretVersionContext,
            secretViaContext,
            serverExecutionPrincipalContext,
          ],
        },
        {
          name: "task-role-secret",
          decision: "explicitDeny",
          contextEntries: [
            secretContext,
            secretVersionContext,
            secretViaContext,
            nonLambdaPrincipalContext,
          ],
        },
        {
          name: "lambda-role-secret",
          decision: "explicitDeny",
          contextEntries: [
            secretContext,
            secretVersionContext,
            secretViaContext,
            lambdaPrincipalContext,
          ],
        },
        {
          name: "cross-region-secret",
          decision: "explicitDeny",
          contextEntries: [
            secretContext,
            secretVersionContext,
            crossRegionSecretViaContext,
            serverExecutionPrincipalContext,
          ],
        },
        {
          name: "secret-via-ssm",
          decision: "explicitDeny",
          contextEntries: [
            secretContext,
            secretVersionContext,
            ssmViaContext,
            serverExecutionPrincipalContext,
          ],
        },
        {
          name: "parameter-via-secretsmanager",
          decision: "explicitDeny",
          contextEntries: [
            ssmContext,
            secretViaContext,
            serverExecutionPrincipalContext,
          ],
        },
        {
          name: "direct-function",
          decision: "explicitDeny",
          contextEntries: [
            lambdaContext,
            lambdaPrincipalContext,
            sourceFunctionContext,
          ],
        },
        {
          name: "nonlambda-forged-lambda",
          decision: "explicitDeny",
          contextEntries: [lambdaContext, nonLambdaPrincipalContext],
        },
        {
          name: "outside-lambda",
          decision: "explicitDeny",
          contextEntries: [
            outsideLambdaContext,
            lambdaPrincipalContext,
          ],
        },
        {
          name: "missing-context",
          decision: "explicitDeny",
          contextEntries: [],
        },
      ],
    }),
  );
  await writeFile(quarantinePath, JSON.stringify(quarantinePolicyDocument()));
  await writeFile(
    simulationPath,
    JSON.stringify(
      quarantineSimulation ?? {
        EvaluationResults: QUARANTINE_PROBE_ACTIONS.map((action) => ({
          EvalActionName: action,
          EvalDecision: "explicitDeny",
        })),
      },
    ),
  );
  await writeFile(
    awsPath,
    `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$MOCK_CALLS"
arg() {
  local needle="$1"
  shift
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "$needle" ]]; then printf '%s' "\${2:-}"; return; fi
    shift
  done
}
option_json() {
  local needle="$1"
  shift
  local found=false
  local -a values=()
  while [[ $# -gt 0 ]]; do
    if [[ "$found" == "true" ]]; then
      if [[ "$1" == --* ]]; then break; fi
      values+=("$1")
    elif [[ "$1" == "$needle" ]]; then
      found=true
    fi
    shift
  done
  jq -cn --args '$ARGS.positional' "\${values[@]}"
}
command="\${1:-} \${2:-}"
case "$command" in
  "sts get-caller-identity")
    printf '%s\\n' '{"Account":"123456789012","Arn":"arn:aws:sts::123456789012:assumed-role/operator/session"}'
    ;;
  "cloudformation validate-template"|"cloudformation wait")
    printf '%s\\n' '{}'
    ;;
  "cloudformation describe-stacks")
    stack="$(arg --stack-name "$@")"
    query="$(arg --query "$@")"
    if [[ "$stack" == "bedrock-mantle-project-mem9-on-aws" ]]; then
      # Regional: the primary project exists in the application region; the
      # optional Responses-route project stack is absent (feature off).
      project_region="$(arg --region "$@")"
      if [[ "$project_region" != "ap-northeast-1" ]]; then
        printf '%s\\n' 'ValidationError: Stack with id bedrock-mantle-project-mem9-on-aws does not exist' >&2
        exit 255
      fi
      printf '%s\\n' 'arn:aws:bedrock-mantle:ap-northeast-1:123456789012:project/proj_test'
    elif [[ "$MOCK_STACK_EXISTS" != "true" && ! -f "$MOCK_CREATED" ]]; then
      printf '%s\\n' 'ValidationError: Stack does not exist' >&2
      exit 255
    elif [[ "$query" == "Stacks[0].StackStatus" ]]; then
      if [[ -f "$MOCK_UPDATED" ]]; then
        printf '%s\\n' 'UPDATE_COMPLETE'
      else
        printf '%s\\n' "$MOCK_STACK_STATUS"
      fi
    elif [[ "$query" == "Stacks[0].Parameters[?ParameterKey=='PolicyRevision'].ParameterValue | [0]" ]]; then
      printf '%s\\n' 'r1'
    else
      printf '{"Stacks":[{"StackStatus":"%s"}]}\\n' "$MOCK_STACK_STATUS"
    fi
    ;;
  "cloudformation describe-stack-resources")
    query="$(arg --query "$@")"
    if [[ "$query" == "StackResources[0].PhysicalResourceId" ]]; then
      printf '%s\\n' 'arn:aws:iam::123456789012:policy/mem9-on-aws-workload-boundary'
    else
      printf '%s\\n' '1'
    fi
    ;;
  "cloudformation update-stack")
    : > "$MOCK_UPDATED"
    printf '%s\\n' '{}'
    ;;
  "cloudformation create-stack")
    : > "$MOCK_CREATED"
    printf '%s\\n' '{}'
    ;;
  "iam get-policy")
    if [[ "$MOCK_DEFAULT_VERSION_DRIFTS_AFTER_SIMULATION" == "true" &&
          -f "$MOCK_SIMULATION_COMPLETE" ]]; then
      printf '%s\\n' 'v2'
    else
      printf '%s\\n' 'v1'
    fi
    ;;
  "iam get-policy-version")
    if [[ "$MOCK_POST_MUTATION_DRIFT" != "true" &&
          ( -f "$MOCK_UPDATED" || -f "$MOCK_CREATED" || "$MOCK_MATCHING" == "true" ) ]]; then
      cat "$MOCK_EXPECTED"
    else
      printf '%s\\n' '{"Version":"2012-10-17","Statement":[]}'
    fi
    ;;
  "iam get-role-policy")
    if [[ "$MOCK_QUARANTINE" != "true" ||
          ( "$MOCK_QUARANTINE_LOST_AFTER_SIMULATION" == "true" &&
            -f "$MOCK_SIMULATION_COMPLETE" ) ]]; then
      exit 1
    fi
    cat "$MOCK_QUARANTINE_DOC"
    ;;
  "iam simulate-custom-policy")
    if [[ "$MOCK_SIMULATION_COMMAND_FAILS" == "true" ]]; then exit 1; fi
    : > "$MOCK_SIMULATION_COMPLETE"
    if [[ "$*" == *"--permissions-boundary-policy-input-list"* ]]; then
      policy_inputs="$(option_json --policy-input-list "$@")"
      boundary_inputs="$(
        option_json --permissions-boundary-policy-input-list "$@"
      )"
      action_names="$(option_json --action-names "$@")"
      resource_arns="$(option_json --resource-arns "$@")"
      output_values="$(option_json --output "$@")"
      context_entries="$(option_json --context-entries "$@")"
      probe_data="$(jq -er \
        --argjson policy_inputs "$policy_inputs" \
        --argjson boundary_inputs "$boundary_inputs" \
        --argjson action_names "$action_names" \
        --argjson resource_arns "$resource_arns" \
        --argjson output_values "$output_values" \
        --argjson context_entries "$context_entries" '
          select(
            .policyInputList == $policy_inputs and
            .permissionsBoundaryPolicyInputList == $boundary_inputs and
            .actionNames == $action_names and
            .resourceArns == $resource_arns and
            .output == $output_values
          )
          | .probes[]
          | select(.contextEntries == $context_entries)
          | [.name, .decision]
          | @tsv
        ' "$MOCK_BOUNDARY_SIMULATIONS")" || exit 1
      IFS=$'\\t' read -r probe decision <<<"$probe_data"
      if [[ "$MOCK_BOUNDARY_SIMULATION_MALFORMED_PROBE" == "$probe" ]]; then
        printf '%s\\n' '{"EvaluationResults":[{}]}'
        exit 0
      fi
      if [[ "$MOCK_BOUNDARY_SIMULATION_BAD_PROBE" == "$probe" ]]; then
        if [[ "$decision" == "allowed" ]]; then
          decision="explicitDeny"
        else
          decision="allowed"
        fi
      fi
      if [[ "$decision" == "explicitDeny" ]]; then
        matched='[{"SourcePolicyId":"Permissions Boundary Policy"}]'
      else
        matched='[]'
      fi
      printf '{"EvaluationResults":[{"EvalActionName":"kms:Decrypt","EvalResourceName":"*","EvalDecision":"%s","MatchedStatements":%s}]}\\n' "$decision" "$matched"
    else
      cat "$MOCK_SIMULATION"
    fi
    ;;
  *)
    printf 'unexpected mock command: %s\\n' "$*" >&2
    exit 1
    ;;
esac
`,
  );
  await chmod(awsPath, 0o755);

  try {
    const result = spawnSync(
      "bash",
      [
        boundaryDeployPath,
        ...(guarded
          ? ["--guarded-update"]
          : verifyOnly
            ? ["--verify-only"]
            : []),
      ],
      {
        cwd: root,
        encoding: "utf8",
        env: {
          ...process.env,
          AWS_PROFILE: "mock",
          MOCK_BOUNDARY_SIMULATION_BAD_PROBE: boundarySimulationBadProbe,
          MOCK_BOUNDARY_SIMULATION_MALFORMED_PROBE:
            boundarySimulationMalformedProbe,
          MOCK_BOUNDARY_SIMULATIONS: boundarySimulationsPath,
          MOCK_CALLS: callsPath,
          MOCK_CREATED: createdPath,
          MOCK_DEFAULT_VERSION_DRIFTS_AFTER_SIMULATION: String(
            defaultVersionDriftsAfterSimulation,
          ),
          MOCK_EXPECTED: expectedPath,
          MOCK_MATCHING: String(matching),
          MOCK_POST_MUTATION_DRIFT: String(postMutationDrift),
          MOCK_QUARANTINE: String(quarantine),
          MOCK_QUARANTINE_DOC: quarantinePath,
          MOCK_QUARANTINE_LOST_AFTER_SIMULATION: String(
            quarantineLostAfterSimulation,
          ),
          MOCK_SIMULATION: simulationPath,
          MOCK_SIMULATION_COMPLETE: simulationCompletePath,
          MOCK_SIMULATION_COMMAND_FAILS: String(simulationCommandFails),
          MOCK_STACK_EXISTS: String(stackExists),
          MOCK_STACK_STATUS: stackStatus,
          MOCK_UPDATED: updatedPath,
          PATH: `${directory}:${dirname(process.execPath)}:${process.env.PATH}`,
          WORKLOAD_BOUNDARY_MAINTENANCE_ACK: guarded ? "true" : "",
          WORKLOAD_BOUNDARY_SKIP_DOTENV: "true",
        },
      },
    );
    return {
      calls: readFileSync(callsPath, "utf8").trim().split("\n"),
      result,
    };
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
}

async function runRolloutGateMock({
  activeWorkflow = "",
  activeWorkflowAfterFirstDrain = "",
  ambientProfile,
  callerAccount = accountId,
  callerPartition = partition,
  dirtyIndex = false,
  dirtyWorktree = false,
  dotenvAck,
  dotenvApplicationRegion,
  dotenvProfile,
  dotenvProjectRegion,
  dotenvTemplateBucket,
  dotenvVpcId,
  expectedAccount,
  expectedPartition,
  gateRevision = true,
  headCiSucceeded = true,
  headMatches = true,
  headRunCompleted = true,
  hangAfterWorkflowDisable = false,
  originMatches = true,
  pauseCommandFails = false,
  pauseValue = "true",
  retainedResumeState,
  repositoryOverride,
  interruptSignal,
  timeout = "30s",
  clockStepMs = 0,
  nodeExit = 0,
} = {}) {
  const directory = await mkdtemp(join(tmpdir(), "mem9-boundary-pause-"));
  const awsPath = join(directory, "aws");
  const callsPath = join(directory, "calls");
  const ghPath = join(directory, "gh");
  const gitPath = join(directory, "git");
  const nodePath = join(directory, "node");
  const datePath = join(directory, "date");
  const clockPath = join(directory, "clock");
  const envPath = join(directory, ".env");
  const resumeStatePath = resolve(root, ".env.workload-boundary-resume");
  await writeFile(callsPath, "");
  if (
    dotenvAck !== undefined ||
    dotenvApplicationRegion !== undefined ||
    dotenvProfile !== undefined ||
    dotenvProjectRegion !== undefined ||
    dotenvTemplateBucket !== undefined ||
    dotenvVpcId !== undefined ||
    expectedAccount !== undefined ||
    expectedPartition !== undefined
  ) {
    await writeFile(
      envPath,
      [
        ...(dotenvAck === undefined
          ? []
          : [`WORKLOAD_BOUNDARY_MAINTENANCE_ACK=${dotenvAck}`]),
        ...(dotenvProfile === undefined
          ? []
          : [`AWS_PROFILE=${dotenvProfile}`]),
        ...(dotenvApplicationRegion === undefined
          ? []
          : [
              `WORKLOAD_BOUNDARY_APPLICATION_REGION=${dotenvApplicationRegion}`,
            ]),
        ...(dotenvProjectRegion === undefined
          ? []
          : [`PROJECT_REGION=${dotenvProjectRegion}`]),
        ...(dotenvTemplateBucket === undefined
          ? []
          : [`MEM9_TEMPLATE_BUCKET=${dotenvTemplateBucket}`]),
        ...(dotenvVpcId === undefined ? [] : [`MEM9_VPC_ID=${dotenvVpcId}`]),
        ...(expectedAccount === undefined
          ? []
          : [`WORKLOAD_BOUNDARY_EXPECTED_ACCOUNT_ID=${expectedAccount}`]),
        ...(expectedPartition === undefined
          ? []
          : [`WORKLOAD_BOUNDARY_EXPECTED_PARTITION=${expectedPartition}`]),
        "",
      ].join("\n"),
    );
  }
  await writeFile(
    awsPath,
    `#!/usr/bin/env bash
set -euo pipefail
printf 'aws %s\\n' "$*" >> "$MOCK_CALLS"
if [[ "\${1:-} \${2:-}" == "sts get-caller-identity" ]]; then
  printf '{"Account":"%s","Arn":"arn:%s:sts::%s:assumed-role/operator/session"}\\n' \
    "$MOCK_CALLER_ACCOUNT" "$MOCK_CALLER_PARTITION" "$MOCK_CALLER_ACCOUNT"
else
  exit 2
fi
`,
  );
  await writeFile(
    ghPath,
    `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$MOCK_CALLS"
case "\${1:-} \${2:-}" in
  "repo view")
    printf 'main\\n'
    ;;
  "api repos/zxkane/mem9-on-aws/commits/main")
    if [[ "$MOCK_HEAD_MATCHES" == "true" ]]; then
      printf '%s\\n' '34adad58d807052f85bbee59dc8bcaa78366f379'
    else
      printf '%s\\n' '0000000000000000000000000000000000000000'
    fi
    ;;
  "api --method")
    if [[ "$*" == *"infra-ci.yml"* ]]; then
      [[ "$MOCK_GATE_REVISION" == "true" ]] &&
        printf '%s\\n' '${reviewedWorkflowBlobs.get("infra-ci.yml")}' ||
        printf '%s\\n' '0000000000000000000000000000000000000000'
    else
      printf '%s\\n' '${reviewedWorkflowBlobs.get("reconcile-previews.yml")}'
    fi
    ;;
  "api repos/zxkane/mem9-on-aws/actions/workflows/infra-ci.yml"|"api repos/zxkane/mem9-on-aws/actions/workflows/reconcile-previews.yml")
    workflow="\${2##*/}"
    if [[ -f "$MOCK_DISABLED_DIR/$workflow" ]]; then
      printf '%s\\n' 'disabled_manually'
    else
      printf '%s\\n' 'active'
    fi
    ;;
  "variable get")
    if [[ "$MOCK_PAUSE_COMMAND_FAILS" == "true" ]]; then exit 1; fi
    printf '%s\\n' "$MOCK_PAUSE_VALUE"
    ;;
  "run list")
    all_args="$*"
    workflow=""
    status=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --workflow) workflow="\${2:-}"; shift 2 ;;
        --status) status="\${2:-}"; shift 2 ;;
        *) shift ;;
      esac
    done
    if [[ "$all_args" == *"--commit"* ]]; then
      if [[ "$MOCK_HEAD_RUN_COMPLETED" == "true" ]]; then
        printf '30247378152\\n'
      fi
    elif [[ -n "$MOCK_ACTIVE_WORKFLOW" &&
          "$workflow" == "$MOCK_ACTIVE_WORKFLOW" &&
          "$status" == "queued" ]]; then
      printf '1\\n'
    elif [[ -n "$MOCK_ACTIVE_WORKFLOW_AFTER_FIRST_DRAIN" &&
          "$workflow" == "$MOCK_ACTIVE_WORKFLOW_AFTER_FIRST_DRAIN" &&
          "$status" == "queued" &&
          "$(grep -c '^run list .*--status' "$MOCK_CALLS")" -gt 10 ]]; then
      printf '1\\n'
    else
      printf '0\\n'
    fi
    ;;
  "run view")
    [[ "$MOCK_HEAD_CI_SUCCEEDED" == "true" ]] && printf '1\\n' || printf '0\\n'
    ;;
  "workflow disable")
    : > "$MOCK_DISABLED_DIR/\${3:-}"
    if [[ "$MOCK_HANG_AFTER_WORKFLOW_DISABLE" == "true" ]]; then
      sleep 5
    fi
    ;;
  *)
    exit 2
    ;;
esac
`,
  );
  await writeFile(
    gitPath,
    `#!/usr/bin/env bash
set -euo pipefail
printf 'git %s\\n' "$*" >> "$MOCK_CALLS"
case "\${1:-} \${2:-}" in
  "-C ${root}")
    shift 2
    case "\${1:-}" in
      rev-parse)
        printf '%s\\n' '34adad58d807052f85bbee59dc8bcaa78366f379'
        ;;
      remote)
        if [[ "$MOCK_ORIGIN_MATCHES" == "true" ]]; then
          printf '%s\\n' 'git@github.com:zxkane/mem9-on-aws.git'
        else
          printf '%s\\n' 'git@github.com:other/repository.git'
        fi
        ;;
      diff)
        if [[ "\${2:-}" == "--cached" && "$MOCK_DIRTY_INDEX" == "true" ]]; then
          exit 1
        fi
        if [[ "\${2:-}" != "--cached" && "$MOCK_DIRTY_WORKTREE" == "true" ]]; then
          exit 1
        fi
        exit 0
        ;;
      hash-object)
        if [[ "\${2:-}" == *"infra-ci.yml" ]]; then
          printf '%s\\n' '${reviewedWorkflowBlobs.get("infra-ci.yml")}'
        else
          printf '%s\\n' '${reviewedWorkflowBlobs.get("reconcile-previews.yml")}'
        fi
        ;;
      *)
        exit 2
        ;;
    esac
    ;;
  *)
    exit 2
    ;;
esac
`,
  );
  await writeFile(
    nodePath,
    `#!/usr/bin/env bash
set -euo pipefail
if [[ "\${1:-}" == "-p" ]]; then
  printf '24\\n'
else
  printf 'node invoked profile=%s region=%s project_region=%s vpc=%s bucket=%s %s\\n' \
    "\${AWS_PROFILE-}" \
    "\${WORKLOAD_BOUNDARY_APPLICATION_REGION-}" \
    "\${PROJECT_REGION-}" \
    "\${MEM9_VPC_ID-}" \
    "\${MEM9_TEMPLATE_BUCKET-}" \
    "$*" >> "$MOCK_CALLS"
  if [[ "$MOCK_NODE_WAIT_SIGNAL" == "true" ]]; then
    trap 'printf "node received SIGINT\\n" >> "$MOCK_CALLS"; exit 130' INT
    trap 'printf "node received SIGTERM\\n" >> "$MOCK_CALLS"; exit 143' TERM
    while true; do
      sleep 1 &
      wait "$!"
    done
  fi
  exit "$MOCK_NODE_EXIT"
fi
`,
  );
  if (clockStepMs > 0) {
    await writeFile(clockPath, "1000000000000\n");
    await writeFile(
      datePath,
      `#!/usr/bin/env bash
set -euo pipefail
now="$(cat "$MOCK_CLOCK")"
printf '%s\\n' "$now"
printf '%s\\n' "$((now + MOCK_CLOCK_STEP_MS * 1000000))" > "$MOCK_CLOCK"
`,
    );
  }
  await Promise.all([
    chmod(awsPath, 0o700),
    chmod(ghPath, 0o700),
    chmod(gitPath, 0o700),
    chmod(nodePath, 0o700),
    ...(clockStepMs > 0 ? [chmod(datePath, 0o700)] : []),
  ]);

  const childEnv = {
    ...process.env,
    MOCK_CALLER_ACCOUNT: callerAccount,
    MOCK_CALLER_PARTITION: callerPartition,
    MOCK_NODE_EXIT: String(nodeExit),
    MOCK_NODE_WAIT_SIGNAL: String(interruptSignal !== undefined),
    MOCK_ACTIVE_WORKFLOW: activeWorkflow,
    MOCK_ACTIVE_WORKFLOW_AFTER_FIRST_DRAIN: activeWorkflowAfterFirstDrain,
    MOCK_CALLS: callsPath,
    MOCK_CLOCK: clockPath,
    MOCK_CLOCK_STEP_MS: String(clockStepMs),
    MOCK_DIRTY_INDEX: String(dirtyIndex),
    MOCK_DIRTY_WORKTREE: String(dirtyWorktree),
    MOCK_DISABLED_DIR: directory,
    MOCK_GATE_REVISION: String(gateRevision),
    MOCK_HEAD_CI_SUCCEEDED: String(headCiSucceeded),
    MOCK_HEAD_MATCHES: String(headMatches),
    MOCK_HEAD_RUN_COMPLETED: String(headRunCompleted),
    MOCK_HANG_AFTER_WORKFLOW_DISABLE: String(hangAfterWorkflowDisable),
    MOCK_PAUSE_COMMAND_FAILS: String(pauseCommandFails),
    MOCK_PAUSE_VALUE: pauseValue,
    MOCK_ORIGIN_MATCHES: String(originMatches),
    PATH: `${directory}:/usr/bin:/bin`,
    WORKLOAD_BOUNDARY_ENV_FILE: envPath,
    WORKLOAD_BOUNDARY_GH_TIMEOUT: timeout,
    WORKLOAD_BOUNDARY_MAINTENANCE_ACK: "true",
    WORKLOAD_BOUNDARY_SKIP_DOTENV:
      dotenvAck === undefined && dotenvProfile === undefined ? "true" : "false",
    ...(repositoryOverride === undefined
      ? {}
      : { GITHUB_REPOSITORY: repositoryOverride }),
  };
  for (const name of [
    "AWS_PROFILE",
    "MEM9_TEMPLATE_BUCKET",
    "MEM9_VPC_ID",
    "PROJECT_REGION",
    "WORKLOAD_BOUNDARY_APPLICATION_REGION",
  ]) {
    delete childEnv[name];
  }
  if (ambientProfile !== undefined) childEnv.AWS_PROFILE = ambientProfile;

  await rm(resumeStatePath, { force: true });
  if (retainedResumeState !== undefined) {
    await writeFile(resumeStatePath, retainedResumeState, { mode: 0o600 });
  }
  let result;
  if (interruptSignal === undefined) {
    result = spawnSync("bash", [rolloutWrapperPath], {
      cwd: root,
      encoding: "utf8",
      env: childEnv,
    });
  } else {
    const child = spawn("bash", [rolloutWrapperPath], {
      cwd: root,
      env: childEnv,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    const startedAt = Date.now();
    while (!readFileSync(callsPath, "utf8").includes("node invoked")) {
      if (Date.now() - startedAt > 15_000) {
        child.kill("SIGKILL");
        throw new Error("mock rollout did not reach the Node process");
      }
      await new Promise((resolvePromise) => {
        setTimeout(resolvePromise, 25);
      });
    }
    child.kill(interruptSignal);
    const close = await new Promise((resolvePromise, rejectPromise) => {
      const killTimer = setTimeout(() => {
        child.kill("SIGKILL");
        rejectPromise(new Error("mock rollout did not exit after signal"));
      }, 10_000);
      child.once("close", (status, signal) => {
        clearTimeout(killTimer);
        resolvePromise({ signal, status });
      });
    });
    result = { ...close, stderr, stdout };
  }
  const calls = readFileSync(callsPath, "utf8");
  let resumeState = "";
  try {
    resumeState = readFileSync(resumeStatePath, "utf8");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  await rm(resumeStatePath, { force: true });
  await rm(directory, { force: true, recursive: true });
  return { calls, result, resumeState };
}

function makeAdapter(options = {}) {
  const calls = [];
  const state = { quarantineInstalled: false };
  const roleBoundaries = new Map(
    Object.entries(options.initialBoundaries ?? {}),
  );
  const roleTrustPolicies = new Map(
    Object.entries(options.initialRoleTrustPolicies ?? {}),
  );
  const inventoryRole = (value) => {
    const fixture = typeof value === "string" ? role(value) : value;
    if (!roleTrustPolicies.has(fixture.name)) return fixture;
    return {
      ...fixture,
      assumeRolePolicyDocument: roleTrustPolicies.get(fixture.name),
    };
  };
  let scopeRead = 0;
  let roleInventoryRead = 0;
  let quarantineChecks = 0;
  let boundaryDeployments = 0;
  const scopePolicies = options.scopePolicies ?? [
    passRolePolicy(),
    passRolePolicy(),
    passRolePolicy(),
  ];

  const adapter = {
    calls,
    state,
    async putQuarantine({ roleName, policyName, policyDocument }) {
      calls.push(`quarantine:${roleName}:${policyName}`);
      if (options.failQuarantine) throw new Error("quarantine failed");
      if (!verifyQuarantinePolicy(policyDocument)) {
        throw new Error("invalid quarantine policy");
      }
      state.quarantineInstalled = true;
    },
    async verifyQuarantine() {
      quarantineChecks += 1;
      calls.push(`verify-quarantine:${quarantineChecks}`);
      return (
        state.quarantineInstalled &&
        options.failQuarantineVerificationAt !== quarantineChecks
      );
    },
    async deployBoundary() {
      calls.push("deploy-boundary");
      boundaryDeployments += 1;
      if (
        options.failBoundaryDeployment ||
        options.failBoundaryDeploymentAt === boundaryDeployments
      ) {
        throw new Error("boundary deployment failed");
      }
    },
    async verifyProductionRuntimeBindings() {
      calls.push("verify-prod-bindings");
      if (options.failProductionSecretPreflight) {
        throw new Error("production secret preflight failed");
      }
      return options.liveRoleNames ?? ["mem9-on-aws-prod-task-role"];
    },
    async listAttachedPolicies({ marker }) {
      calls.push(`list-attached:${marker ?? ""}`);
      if (options.repeatAttachedMarker && marker) {
        return {
          policies: [{ arn: "arn:managed:b" }],
          marker: "attached-2",
        };
      }
      return marker
        ? { policies: [{ arn: "arn:managed:b" }] }
        : { policies: [{ arn: "arn:managed:a" }], marker: "attached-2" };
    },
    async getManagedPolicy({ policyArn }) {
      calls.push(`get-policy:${policyArn}`);
      if (options.failPolicyRead) throw new Error("managed policy read failed");
      return { defaultVersionId: "v1" };
    },
    async getManagedPolicyVersion({ policyArn, versionId }) {
      calls.push(`get-policy-version:${policyArn}:${versionId}`);
      const policy =
        scopePolicies[Math.min(scopeRead, scopePolicies.length - 1)];
      if (policyArn.endsWith(":b")) scopeRead += 1;
      return { document: policy };
    },
    async listInlinePolicies({ marker }) {
      calls.push(`list-inline:${marker ?? ""}`);
      return marker
        ? { policyNames: ["inline-b"] }
        : { policyNames: ["inline-a"], marker: "inline-2" };
    },
    async getInlinePolicy({ policyName }) {
      calls.push(`get-inline:${policyName}`);
      return { document: { Version: "2012-10-17", Statement: [] } };
    },
    async listRoles({ marker }) {
      calls.push(`list-roles:${marker ?? ""}`);
      if (options.roleInventories !== undefined) {
        const inventory =
          options.roleInventories[
            Math.min(roleInventoryRead, options.roleInventories.length - 1)
          ];
        if (marker) {
          roleInventoryRead += 1;
          return { roles: inventory.slice(2).map(inventoryRole) };
        }
        return {
          roles: inventory.slice(0, 2).map(inventoryRole),
          marker: "roles-2",
        };
      }
      if (options.roles !== undefined) {
        return { roles: options.roles.map(inventoryRole) };
      }
      return marker
        ? {
            roles: [
              role("mem9-on-aw-pr-70-short-role"),
              role("unrelated-role"),
            ],
          }
        : {
            roles: [
              role("mem9-on-aws-prod-task-role"),
              role("mem9-on-a-pr-70-shortest-role"),
            ],
            marker: "roles-2",
          };
    },
    async putRoleBoundary({ roleName, permissionsBoundary }) {
      calls.push(`put-boundary:${roleName}`);
      if (options.failRole === roleName)
        throw new Error("boundary write failed");
      if (!options.dropBoundaryWrites) {
        roleBoundaries.set(roleName, permissionsBoundary);
      }
    },
    async getRole({ roleName }) {
      calls.push(`get-role:${roleName}`);
      const value =
        options.mismatchedRole === roleName
          ? "arn:aws:iam::123456789012:policy/wrong"
          : roleBoundaries.get(roleName);
      return {
        assumeRolePolicyDocument: roleTrustPolicies.has(roleName)
          ? roleTrustPolicies.get(roleName)
          : role(roleName).assumeRolePolicyDocument,
        permissionsBoundaryArn: value,
      };
    },
    async updateAssumeRolePolicy({ roleName, policyDocument }) {
      calls.push(`update-trust:${roleName}`);
      if (!verifyLambdaExecutionRoleTrustPolicy(policyDocument)) {
        throw new Error("invalid Lambda trust repair");
      }
      if (options.failTrustRole === roleName) {
        throw new Error("Lambda trust repair failed");
      }
      if (!options.dropTrustWrites) {
        roleTrustPolicies.set(roleName, policyDocument);
      }
    },
    async deployPermanentEnforcement() {
      calls.push("deploy-enforcement");
      if (options.failEnforcement) throw new Error("enforcement failed");
    },
    async verifyPermanentEnforcement(request) {
      calls.push("verify-enforcement");
      if (
        options.rejectStalePolicyDocuments &&
        Object.hasOwn(request, "policyDocuments")
      ) {
        throw new Error("stale policy documents were passed to verification");
      }
      if (options.failVerification) throw new Error("verification failed");
      if (options.falseVerification) return false;
      return true;
    },
    async activateProductionBoundary() {
      calls.push("activate-prod-boundary");
      if (options.failProductionActivation) {
        throw new Error("production activation failed");
      }
      if (options.removeBoundaryDuringProductionActivation) {
        roleBoundaries.delete("mem9-on-aws-prod-task-role");
      }
    },
    async verifyFinalGithubInterlock({
      reviewedCommit: receivedReviewedCommit,
    }) {
      calls.push(`verify-final-github:${receivedReviewedCommit}`);
      if (options.failFinalGithubInterlock) {
        throw new Error("final GitHub interlock failed");
      }
      if (receivedReviewedCommit !== reviewedCommit) {
        throw new Error("reviewed commit mismatch");
      }
      if (options.driftTrustDuringFinalGithub) {
        roleTrustPolicies.set(
          productionRoleNames.proxy,
          legacyLambdaTrustPolicy,
        );
      }
    },
    async deleteQuarantine({ roleName, policyName }) {
      calls.push(`unquarantine:${roleName}:${policyName}`);
      state.quarantineInstalled = false;
    },
    async resumeDeployments() {
      calls.push("resume-deployments");
      if (options.failDeploymentResume) {
        throw new Error("deployment resume failed");
      }
    },
  };
  return adapter;
}

describe("deployed PassRole scope", () => {
  it("builds and verifies the exact Lambda-only execution-role trust", () => {
    expect(lambdaOnlyTrustPolicy).toEqual(expectedLambdaOnlyTrustPolicy);
    expect(
      verifyLambdaExecutionRoleTrustPolicy(expectedLambdaOnlyTrustPolicy),
    ).toBe(true);
    expect(
      verifyLambdaExecutionRoleTrustPolicy(
        encodeURIComponent(JSON.stringify(expectedLambdaOnlyTrustPolicy)),
      ),
    ).toBe(true);
  });

  it.each([
    ["legacy account principal", legacyLambdaTrustPolicy],
    [
      "extra condition",
      {
        ...expectedLambdaOnlyTrustPolicy,
        Statement: [
          {
            ...expectedLambdaOnlyTrustPolicy.Statement[0],
            Condition: { StringEquals: { "aws:SourceAccount": accountId } },
          },
        ],
      },
    ],
    [
      "extra statement",
      {
        ...expectedLambdaOnlyTrustPolicy,
        Statement: [
          ...expectedLambdaOnlyTrustPolicy.Statement,
          expectedLambdaOnlyTrustPolicy.Statement[0],
        ],
      },
    ],
    [
      "wrong action",
      {
        ...expectedLambdaOnlyTrustPolicy,
        Statement: [
          {
            ...expectedLambdaOnlyTrustPolicy.Statement[0],
            Action: "sts:AssumeRoleWithWebIdentity",
          },
        ],
      },
    ],
    ["malformed", { Version: "2012-10-17" }],
  ])("rejects %s as Lambda-only trust", (_name, policy) => {
    expect(verifyLambdaExecutionRoleTrustPolicy(policy)).toBe(false);
  });

  it("normalizes the exact supported resource set", () => {
    expect(
      extractPassRoleScope([passRolePolicy([...patterns].reverse())], {
        partition,
        accountId,
      }),
    ).toEqual(patterns);
  });

  it("accepts the exact consolidation Scheduler role separately", () => {
    expect(
      extractPassRoleScope(
        [
          passRolePolicy([...patterns].reverse()),
          consolidationSchedulerPassRolePolicy(),
        ],
        { partition, accountId },
      ),
    ).toEqual(patterns);
  });

  it.each([
    [
      "generic project roles",
      consolidationSchedulerPassRolePolicy({ resources: patterns }),
    ],
    [
      "additional service",
      consolidationSchedulerPassRolePolicy({
        services: ["scheduler.amazonaws.com", "ecs-tasks.amazonaws.com"],
      }),
    ],
    [
      "foreign scheduler role",
      consolidationSchedulerPassRolePolicy({
        resources: [
          `arn:${partition}:iam::${accountId}:role/other-scheduler-role-*`,
        ],
      }),
    ],
  ])("rejects Scheduler PassRole for %s", (_name, policy) => {
    expect(() =>
      extractPassRoleScope([passRolePolicy(), policy], {
        partition,
        accountId,
      }),
    ).toThrow(/PassRole/u);
  });

  it.each([
    ["global resource", ["*"]],
    ["interior wildcard", ["arn:aws:iam::123456789012:role/mem9-*-on-aws"]],
    ["foreign prefix", ["arn:aws:iam::123456789012:role/other-*"]],
    [
      "question-mark wildcard",
      ["arn:aws:iam::123456789012:role/mem9-on-aws-?-role"],
    ],
  ])("fails closed for %s", (_name, resources) => {
    expect(() =>
      extractPassRoleScope([passRolePolicy(resources)], {
        partition,
        accountId,
      }),
    ).toThrow(/PassRole/u);
  });

  it.each([
    { Effect: "Allow", Action: "*", Resource: patterns },
    { Effect: "Allow", Action: "iam:*", Resource: patterns },
    { Effect: "Allow", NotAction: "iam:DeleteRole", Resource: patterns },
    {
      Effect: "Allow",
      Action: "iam:PassRole",
      Resource: patterns,
    },
    {
      Effect: "Allow",
      Action: "iam:PassRole",
      Resource: patterns,
      Condition: {
        StringEquals: { "iam:PassedToService": "ec2.amazonaws.com" },
      },
    },
    {
      Effect: "Allow",
      Action: "iam:PassRole",
      NotResource: patterns,
      Condition: {
        StringEquals: { "iam:PassedToService": "ecs-tasks.amazonaws.com" },
      },
    },
  ])("rejects an unsafe action or service shape", (statement) => {
    expect(() =>
      extractPassRoleScope(
        [{ Version: "2012-10-17", Statement: [statement] }],
        { partition, accountId },
      ),
    ).toThrow();
  });

  it("reads every managed/inline policy page and returns the exact scope", async () => {
    const adapter = makeAdapter();
    await expect(
      discoverPassRoleScope(adapter, {
        roleName: "github-actions-mem9-on-aws",
        partition,
        accountId,
      }),
    ).resolves.toEqual(patterns);
    expect(adapter.calls).toEqual(
      expect.arrayContaining([
        "list-attached:",
        "list-attached:attached-2",
        "get-policy:arn:managed:a",
        "get-policy:arn:managed:b",
        "list-inline:",
        "list-inline:inline-2",
        "get-inline:inline-a",
        "get-inline:inline-b",
      ]),
    );
  });

  it("fails closed on a repeated IAM pagination marker", async () => {
    const adapter = makeAdapter({ repeatAttachedMarker: true });
    await expect(
      discoverPassRoleScope(adapter, {
        roleName: "github-actions-mem9-on-aws",
        partition,
        accountId,
      }),
    ).rejects.toThrow(/repeated a marker/u);
  });

  it.each([
    [
      "page",
      async () => {
        let page = 0;
        const adapter = makeAdapter();
        adapter.listAttachedPolicies = async () => {
          page += 1;
          return { policies: [], marker: `marker-${page}` };
        };
        return discoverPassRoleScope(adapter, {
          roleName: "github-actions-mem9-on-aws",
          partition,
          accountId,
        });
      },
    ],
    [
      "item",
      async () => {
        const adapter = makeAdapter();
        adapter.listAttachedPolicies = async () => ({
          policies: Array.from({ length: 10_001 }, (_, index) => ({
            arn: `arn:managed:${index}`,
          })),
        });
        return discoverPassRoleScope(adapter, {
          roleName: "github-actions-mem9-on-aws",
          partition,
          accountId,
        });
      },
    ],
  ])(
    "fails closed when IAM pagination exceeds the %s limit",
    async (_name, run) => {
      await expect(run()).rejects.toThrow(/exceeded the (?:page|item) limit/u);
    },
  );

  it.each([
    ["attached policies array", "listAttachedPolicies", { IsTruncated: false }],
    ["inline policy names array", "listInlinePolicies", { IsTruncated: false }],
    ["role inventory array", "listRoles", { IsTruncated: false }],
    ["pagination completion flag", "listRoles", { Roles: [] }],
    ["truncated-page marker", "listRoles", { Roles: [], IsTruncated: true }],
  ])("fails closed on a malformed IAM %s", async (_name, method, response) => {
    const adapter = createAwsCliAdapter({
      identity: { accountId, partition },
      invokeAws: () => response,
    });
    await expect(adapter[method]({})).rejects.toThrow(/pagination|response/u);
  });

  it("reads role trust and updates it only with the exact Lambda policy", async () => {
    const calls = [];
    const adapter = createAwsCliAdapter({
      identity: { accountId, partition },
      invokeAws: (args) => {
        calls.push(args);
        if (args.slice(0, 2).join(" ") === "iam get-role") {
          return {
            Role: {
              AssumeRolePolicyDocument: legacyLambdaTrustPolicy,
              PermissionsBoundary: {
                PermissionsBoundaryArn: boundaryArn,
              },
            },
          };
        }
        if (args.slice(0, 2).join(" ") === "iam update-assume-role-policy") {
          return {};
        }
        throw new Error("unexpected IAM adapter command");
      },
    });
    await expect(
      adapter.getRole({ roleName: productionRoleNames.proxy }),
    ).resolves.toEqual({
      assumeRolePolicyDocument: legacyLambdaTrustPolicy,
      permissionsBoundaryArn: boundaryArn,
    });
    await adapter.updateAssumeRolePolicy({
      policyDocument: lambdaOnlyTrustPolicy,
      roleName: productionRoleNames.proxy,
    });
    expect(calls[1]).toEqual([
      "iam",
      "update-assume-role-policy",
      "--role-name",
      productionRoleNames.proxy,
      "--policy-document",
      JSON.stringify(lambdaOnlyTrustPolicy),
    ]);
    await expect(
      adapter.updateAssumeRolePolicy({
        policyDocument: legacyLambdaTrustPolicy,
        roleName: productionRoleNames.proxy,
      }),
    ).rejects.toThrow(/refusing malformed Lambda trust repair/u);
    expect(calls).toHaveLength(2);
  });

  it("matches only deployed role prefixes", () => {
    expect(
      matchingRoleNames(
        [
          role("mem9-on-aws-prod-task-role"),
          role("mem9-on-aw-pr-70-role"),
          role("mem9-on-a-pr-70-role"),
          role("mem9-on-aws"),
          role("mem9-on-aws-other"),
          role("mem9-on-aws-path-role", "service/"),
          role("unrelated-role"),
        ],
        patterns,
      ),
    ).toEqual([
      "mem9-on-a-pr-70-role",
      "mem9-on-aw-pr-70-role",
      "mem9-on-aws-other",
      "mem9-on-aws-prod-task-role",
    ]);
  });

  it.each([
    ["ECS", { Service: "ecs-tasks.amazonaws.com" }],
    ["AgentCore", { Service: "bedrock-agentcore.amazonaws.com" }],
    [
      "mixed Lambda and ECS",
      { Service: ["lambda.amazonaws.com", "ecs-tasks.amazonaws.com"] },
    ],
  ])("rejects a proxy-pattern role with %s trust", (_name, Principal) => {
    const unsafeTrust = {
      Version: "2012-10-17",
      Statement: [{ Effect: "Allow", Action: "sts:AssumeRole", Principal }],
    };
    expect(() =>
      matchingRoleNames(
        [role(productionRoleNames.proxy, "", unsafeTrust)],
        patterns,
      ),
    ).toThrow(/trust policy is not Lambda-only/u);
  });

  it.each([
    productionRoleNames.alertRouter,
    facadeAuthorizerRoleName,
    productionRoleNames.oauthFacade,
    productionRoleNames.proxy,
  ])("rejects legacy trust outside initial repair for %s", (roleName) => {
    expect(() =>
      matchingRoleNames(
        [role(roleName, "", legacyLambdaTrustPolicy)],
        patterns,
      ),
    ).toThrow(/trust policy is not Lambda-only/u);
  });
});

describe("production task-definition secret preflight", () => {
  const validInput = () => ({
    accountId,
    applicationRegion: "ap-northeast-1",
    bootstrapTaskDefinitionArn: productionTaskDefinitions.bootstrap,
    partition,
    serviceTaskDefinitionArns: [
      productionTaskDefinitions.primary,
      productionTaskDefinitions.replacement,
    ],
    taskDefinitions: [
      taskDefinition(
        productionTaskDefinitions.primary,
        "mem9-on-aws-prod-Mem9Server",
      ),
      taskDefinition(
        productionTaskDefinitions.replacement,
        "mem9-on-aws-prod-Mem9Server",
      ),
      taskDefinition(
        productionTaskDefinitions.bootstrap,
        "mem9-on-aws-prod-Mem9Bootstrap",
      ),
    ],
  });
  const validRuntimeInput = () => ({
    ...validInput(),
    bedrockProjectArn: boundaryContract.bedrockProjectArn,
    gateway: productionPreflightAws([
      "bedrock-agentcore-control",
      "get-gateway",
    ]),
    gatewayId: "gateway-prod-123",
    lambdaFunctions: productionPreflightAws(["lambda", "list-functions"])
      .Functions,
  });

  it("accepts every service and bootstrap secret only under the project prefix", () => {
    expect(validateProductionTaskDefinitionSecrets(validInput())).toBe(true);
  });

  it("returns every role bound to production ECS, Lambda, and AgentCore", () => {
    expect(validateProductionRuntimeBindings(validRuntimeInput())).toEqual(
      expectedProductionRoleNames,
    );
  });

  it("TC-FACADEAUTH-005: accepts the optional facade authorizer Lambda binding", () => {
    const input = validRuntimeInput();
    input.lambdaFunctions.push({
      FunctionArn:
        `arn:aws:lambda:ap-northeast-1:${accountId}:function:` +
        facadeAuthorizerFunctionName,
      FunctionName: facadeAuthorizerFunctionName,
      Role: facadeAuthorizerRoleArn,
    });
    expect(validateProductionRuntimeBindings(input)).toEqual(
      [...expectedProductionRoleNames, facadeAuthorizerRoleName].sort(),
    );
  });

  it.each([
    [
      "prefixed token",
      "mem9-on-aws-prod-XMem9OauthFacadeAllowAll",
    ],
    ["suffixed token", `${facadeAuthorizerFunctionName}Suffix`],
  ])(
    "rejects a non-exact optional facade authorizer Function name: %s",
    (_name, FunctionName) => {
      const input = validRuntimeInput();
      input.lambdaFunctions.push({
        FunctionArn:
          `arn:aws:lambda:ap-northeast-1:${accountId}:function:` +
          FunctionName,
        FunctionName,
        Role: facadeAuthorizerRoleArn,
      });
      expect(() => validateProductionRuntimeBindings(input)).toThrow(
        /Lambda inventory is incomplete/u,
      );
    },
  );

  it.each([
    [
      "prefixed token",
      "mem9-on-aws-prod-XMem9OauthFacadeAllowAllRole",
    ],
    ["suffixed token", `${facadeAuthorizerRoleName}Suffix`],
  ])(
    "rejects a non-exact optional facade authorizer role name: %s",
    (_name, roleName) => {
      const input = validRuntimeInput();
      input.lambdaFunctions.push({
        FunctionArn:
          `arn:aws:lambda:ap-northeast-1:${accountId}:function:` +
          facadeAuthorizerFunctionName,
        FunctionName: facadeAuthorizerFunctionName,
        Role: `arn:aws:iam::${accountId}:role/${roleName}`,
      });
      expect(() => validateProductionRuntimeBindings(input)).toThrow(
        /Lambda role binding is malformed/u,
      );
    },
  );

  it("rejects an additional production Lambda outside the reviewed graph", () => {
    const input = validRuntimeInput();
    const extraName = "mem9-on-aws-prod-UnreviewedFn-fixture";
    input.lambdaFunctions.push({
      FunctionArn:
        `arn:aws:lambda:ap-northeast-1:${accountId}:function:` + extraName,
      FunctionName: extraName,
      Role: productionRoleArns.oauthFacade,
    });
    expect(() => validateProductionRuntimeBindings(input)).toThrow(
      /Lambda inventory is incomplete/u,
    );
  });

  it.each([
    ["alert-router", 0, productionRoleArns.oauthFacade],
    ["OAuth facade", 1, productionRoleArns.alertRouter],
  ])("rejects a %s Function bound to another Lambda role type", (_name, index, roleArn) => {
    const input = validRuntimeInput();
    input.lambdaFunctions[index].Role = roleArn;
    expect(() => validateProductionRuntimeBindings(input)).toThrow(
      /Lambda role binding is malformed/u,
    );
  });

  it.each([
    [
      "missing llm-proxy",
      (input) => {
        input.taskDefinitions[0].containerDefinitions.pop();
      },
    ],
    [
      "missing project variable",
      (input) => {
        input.taskDefinitions[0].containerDefinitions[1].environment = [];
      },
    ],
    [
      "malformed project variable",
      (input) => {
        input.taskDefinitions[0].containerDefinitions[1].environment = [null];
      },
    ],
    [
      "different project",
      (input) => {
        input.taskDefinitions[0].containerDefinitions[1].environment[0].value =
          "proj_other";
      },
    ],
    [
      "different boundary project ARN",
      (input) => {
        input.bedrockProjectArn =
          "arn:aws:bedrock-mantle:ap-northeast-1:123456789012:project/proj_other";
      },
    ],
  ])("rejects a %s Bedrock project binding", (_name, mutate) => {
    const input = validRuntimeInput();
    mutate(input);
    expect(() => validateProductionRuntimeBindings(input)).toThrow(
      /Bedrock project|llm-proxy/u,
    );
  });

  it.each([
    [
      "ECS task",
      (input) => {
        input.taskDefinitions[0].taskRoleArn = productionRoleArns.proxy;
      },
    ],
    [
      "AgentCore Gateway",
      (input) => {
        input.gateway.roleArn = productionRoleArns.proxy;
      },
    ],
  ])("rejects a proxy-pattern role bound to %s", (_name, mutate) => {
    const input = validRuntimeInput();
    mutate(input);
    expect(() => validateProductionRuntimeBindings(input)).toThrow(
      /VPC proxy role is bound/u,
    );
  });

  it.each([
    [
      "secret",
      (input, foreignAccount) => {
        input.taskDefinitions[0].containerDefinitions[0].secrets[0].valueFrom =
          input.taskDefinitions[0].containerDefinitions[0].secrets[0].valueFrom.replace(
            accountId,
            foreignAccount,
          );
      },
    ],
    [
      "ECS role",
      (input, foreignAccount) => {
        input.taskDefinitions[0].taskRoleArn =
          input.taskDefinitions[0].taskRoleArn.replace(
            accountId,
            foreignAccount,
          );
      },
    ],
    [
      "Lambda role",
      (input, foreignAccount) => {
        input.lambdaFunctions[0].Role = input.lambdaFunctions[0].Role.replace(
          accountId,
          foreignAccount,
        );
      },
    ],
    [
      "AgentCore Gateway role",
      (input, foreignAccount) => {
        input.gateway.roleArn = input.gateway.roleArn.replace(
          accountId,
          foreignAccount,
        );
      },
    ],
  ])("rejects a cross-account production %s ARN", (_name, mutate) => {
    const input = validRuntimeInput();
    mutate(input, "9".repeat(12));
    expect(() => validateProductionRuntimeBindings(input)).toThrow(
      /secret|role ARN/u,
    );
  });

  it.each([
    [
      "foreign secret",
      (input) => {
        input.taskDefinitions[0].containerDefinitions[0].secrets[0].valueFrom =
          "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:other-project";
      },
    ],
    [
      "wrong region",
      (input) => {
        input.taskDefinitions[0].containerDefinitions[0].secrets[0].valueFrom =
          "arn:aws:secretsmanager:us-east-1:123456789012:secret:mem9-on-aws-prod-db";
      },
    ],
    [
      "missing tenant reference",
      (input) => {
        input.taskDefinitions[1].containerDefinitions[0].secrets.pop();
      },
    ],
    [
      "undescribed deployment definition",
      (input) => {
        input.taskDefinitions = input.taskDefinitions.filter(
          ({ taskDefinitionArn }) =>
            taskDefinitionArn !== productionTaskDefinitions.replacement,
        );
      },
    ],
    [
      "unrequested task definition",
      (input) => {
        input.taskDefinitions.push(
          taskDefinition(
            "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/unexpected:1",
            "unexpected",
          ),
        );
      },
    ],
    [
      "malformed containers",
      (input) => {
        input.taskDefinitions[0].containerDefinitions = undefined;
      },
    ],
  ])("fails closed for a %s", (_name, mutate) => {
    const input = validInput();
    mutate(input);
    expect(() => validateProductionTaskDefinitionSecrets(input)).toThrow(
      /task definition|secret/u,
    );
  });

  it("discovers deployments plus running/pending tasks and describes each definition once", async () => {
    const calls = [];
    const adapter = createAwsCliAdapter({
      consistencyAttempts: 1,
      identity: { accountId, partition },
      invokeAws: (args) => {
        calls.push(args);
        return productionPreflightAws(args);
      },
      sleep: async () => {},
    });
    await expect(adapter.verifyProductionRuntimeBindings()).resolves.toEqual(
      expectedProductionRoleNames,
    );
    expect(
      calls
        .filter((args) => args.slice(0, 2).join(" ") === "ecs list-tasks")
        .map((args) => argument(args, "--desired-status")),
    ).toEqual(["RUNNING", "PENDING"]);
    expect(
      calls
        .filter(
          (args) =>
            args.slice(0, 2).join(" ") === "ecs describe-task-definition",
        )
        .map((args) => argument(args, "--task-definition"))
        .sort(),
    ).toEqual(Object.values(productionTaskDefinitions).sort());
  });

  it.each([
    ["boundary stack read", "cloudformation describe-stacks", { Stacks: [] }],
    ["parameter read", "ssm get-parameters", { Parameters: [] }],
    ["service read", "ecs describe-services", { failures: [], services: [] }],
    ["task listing", "ecs list-tasks", {}],
    [
      "task read",
      "ecs describe-tasks",
      { failures: [{ reason: "missing" }], tasks: [] },
    ],
    ["task definition read", "ecs describe-task-definition", {}],
    ["Lambda listing", "lambda list-functions", {}],
    ["Gateway read", "bedrock-agentcore-control get-gateway", {}],
  ])(
    "fails closed on a malformed %s response",
    async (_name, command, response) => {
      const adapter = createAwsCliAdapter({
        consistencyAttempts: 1,
        identity: { accountId, partition },
        invokeAws: (args) =>
          productionPreflightAws(args, { [command]: response }),
        sleep: async () => {},
      });
      await expect(adapter.verifyProductionRuntimeBindings()).rejects.toThrow(
        /production|task|parameter|service|boundary stack/u,
      );
    },
  );
});

describe("guarded rollout", () => {
  const options = {
    deployRoleName: "github-actions-mem9-on-aws",
    boundaryArn,
    partition,
    accountId,
    reviewedCommit,
    resumeCommand: "scripts/rollout-workload-permissions-boundary.sh",
  };
  const migrationLambdaRoleNames = [
    productionRoleNames.alertRouter,
    productionRoleNames.oauthFacade,
    productionRoleNames.proxy,
  ];
  const migrationRoles = [
    role("mem9-on-aws-prod-task-role"),
    ...migrationLambdaRoleNames.map((roleName) => role(roleName)),
  ];
  const legacyMigrationTrust = Object.fromEntries(
    migrationLambdaRoleNames.map((roleName) => [
      roleName,
      legacyLambdaTrustPolicy,
    ]),
  );

  it("runs quarantine first and removes it only after complete verification", async () => {
    const adapter = makeAdapter();
    const result = await runBoundaryRollout(adapter, options);

    expect(result).toEqual({ verifiedRoleCount: 3, status: "complete" });
    expect(adapter.calls[0]).toBe(
      `quarantine:${options.deployRoleName}:${QUARANTINE_POLICY_NAME}`,
    );
    expect(adapter.calls.indexOf("deploy-boundary")).toBeGreaterThan(
      adapter.calls.indexOf("verify-quarantine:1"),
    );
    expect(adapter.calls.indexOf("deploy-boundary")).toBeLessThan(
      adapter.calls.indexOf("list-attached:"),
    );
    expect(
      adapter.calls.filter((call) => call === "deploy-boundary"),
    ).toHaveLength(2);
    expect(adapter.calls.lastIndexOf("deploy-boundary")).toBeGreaterThan(
      adapter.calls.indexOf("verify-enforcement"),
    );
    expect(adapter.calls.lastIndexOf("deploy-boundary")).toBeLessThan(
      adapter.calls.indexOf("activate-prod-boundary"),
    );
    expect(adapter.calls.indexOf("verify-prod-bindings")).toBeGreaterThan(
      adapter.calls.indexOf("list-roles:roles-2"),
    );
    expect(adapter.calls.indexOf("verify-prod-bindings")).toBeLessThan(
      adapter.calls.findIndex((call) => call.startsWith("put-boundary:")),
    );
    expect(
      adapter.calls.filter((call) => call.startsWith("verify-quarantine:")),
    ).toEqual([
      "verify-quarantine:1",
      "verify-quarantine:2",
      "verify-quarantine:3",
      "verify-quarantine:4",
    ]);
    expect(adapter.calls.at(-2)).toBe(
      `unquarantine:${options.deployRoleName}:${QUARANTINE_POLICY_NAME}`,
    );
    expect(adapter.calls.at(-1)).toBe("resume-deployments");
    expect(adapter.calls.indexOf("deploy-enforcement")).toBeGreaterThan(
      adapter.calls.lastIndexOf("put-boundary:mem9-on-aws-prod-task-role"),
    );
    expect(adapter.calls.indexOf("verify-enforcement")).toBeGreaterThan(
      adapter.calls.indexOf("deploy-enforcement"),
    );
    expect(adapter.calls.indexOf("activate-prod-boundary")).toBeGreaterThan(
      adapter.calls.indexOf("verify-enforcement"),
    );
    expect(adapter.calls.indexOf("activate-prod-boundary")).toBeLessThan(
      adapter.calls.indexOf("verify-quarantine:3"),
    );
    expect(adapter.calls.lastIndexOf("verify-enforcement")).toBeGreaterThan(
      adapter.calls.indexOf(`verify-final-github:${reviewedCommit}`),
    );
    expect(adapter.calls.lastIndexOf("verify-enforcement")).toBeLessThan(
      adapter.calls.indexOf("verify-quarantine:4"),
    );
    expect(
      adapter.calls.indexOf(`verify-final-github:${reviewedCommit}`),
    ).toBeLessThan(adapter.calls.indexOf("verify-quarantine:4"));
    expect(adapter.calls.indexOf("verify-quarantine:4")).toBeLessThan(
      adapter.calls.indexOf(
        `unquarantine:${options.deployRoleName}:${QUARANTINE_POLICY_NAME}`,
      ),
    );
  });

  it("repairs every exact legacy Lambda trust before boundary attachment", async () => {
    const adapter = makeAdapter({
      initialRoleTrustPolicies: legacyMigrationTrust,
      roles: migrationRoles,
    });

    await expect(runBoundaryRollout(adapter, options)).resolves.toEqual({
      status: "complete",
      verifiedRoleCount: migrationRoles.length,
    });
    expect(
      adapter.calls.filter((call) => call.startsWith("update-trust:")),
    ).toEqual(
      migrationLambdaRoleNames
        .map((roleName) => `update-trust:${roleName}`)
        .sort(),
    );
    const firstBoundaryWrite = adapter.calls.findIndex((call) =>
      call.startsWith("put-boundary:"),
    );
    expect(firstBoundaryWrite).toBeGreaterThan(-1);
    for (const roleName of migrationLambdaRoleNames) {
      const update = adapter.calls.indexOf(`update-trust:${roleName}`);
      expect(update).toBeGreaterThan(
        adapter.calls.indexOf(`get-role:${roleName}`),
      );
      expect(update).toBeLessThan(firstBoundaryWrite);
      expect(adapter.calls.slice(update + 1, firstBoundaryWrite)).toContain(
        `get-role:${roleName}`,
      );
    }
  });

  it("does not rewrite Lambda roles that already have exact trust", async () => {
    const adapter = makeAdapter({ roles: migrationRoles });

    await runBoundaryRollout(adapter, options);
    expect(adapter.calls.some((call) => call.startsWith("update-trust:"))).toBe(
      false,
    );
  });

  it.each([
    [
      "foreign root",
      {
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Action: "sts:AssumeRole",
            Principal: {
              AWS: `arn:${partition}:iam::${"9".repeat(12)}:root`,
              Service: "lambda.amazonaws.com",
            },
          },
        ],
      },
    ],
    [
      "unknown service",
      {
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Action: "sts:AssumeRole",
            Principal: {
              Service: ["lambda.amazonaws.com", "ecs-tasks.amazonaws.com"],
            },
          },
        ],
      },
    ],
    [
      "extra condition",
      {
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Action: "sts:AssumeRole",
            Principal: {
              AWS: `arn:${partition}:iam::${accountId}:root`,
              Service: "lambda.amazonaws.com",
            },
            Condition: { StringEquals: { "aws:SourceAccount": accountId } },
          },
        ],
      },
    ],
  ])(
    "rejects %s trust before repairing any role",
    async (_name, unsafeTrust) => {
      const adapter = makeAdapter({
        initialRoleTrustPolicies: {
          ...legacyMigrationTrust,
          [productionRoleNames.oauthFacade]: unsafeTrust,
        },
        roles: migrationRoles,
      });

      await expect(runBoundaryRollout(adapter, options)).rejects.toThrow(
        /trust policy is not Lambda-only/u,
      );
      expect(
        adapter.calls.some((call) => call.startsWith("update-trust:")),
      ).toBe(false);
      expect(
        adapter.calls.some((call) => call.startsWith("put-boundary:")),
      ).toBe(false);
      expect(adapter.state.quarantineInstalled).toBe(true);
      expect(
        adapter.calls.some((call) => call.startsWith("unquarantine:")),
      ).toBe(false);
    },
  );

  it("re-reads exact legacy trust immediately before mutation", async () => {
    const adapter = makeAdapter({
      initialRoleTrustPolicies: {
        [productionRoleNames.proxy]: legacyLambdaTrustPolicy,
      },
      roles: [
        role("mem9-on-aws-prod-task-role"),
        role(productionRoleNames.proxy),
      ],
    });
    const getRole = adapter.getRole.bind(adapter);
    adapter.getRole = async ({ roleName }) => {
      const result = await getRole({ roleName });
      if (roleName !== productionRoleNames.proxy) return result;
      return {
        ...result,
        assumeRolePolicyDocument: {
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Action: "sts:AssumeRole",
              Principal: { Service: "ecs-tasks.amazonaws.com" },
            },
          ],
        },
      };
    };

    await expect(runBoundaryRollout(adapter, options)).rejects.toThrow(
      /trust changed before repair/u,
    );
    expect(adapter.calls).not.toContain(
      `update-trust:${productionRoleNames.proxy}`,
    );
    expect(adapter.state.quarantineInstalled).toBe(true);
    expect(
      adapter.calls.some((call) => call.startsWith("unquarantine:")),
    ).toBe(false);
  });

  it("fails closed when repaired trust cannot be read back", async () => {
    const adapter = makeAdapter({
      dropTrustWrites: true,
      initialRoleTrustPolicies: {
        [productionRoleNames.proxy]: legacyLambdaTrustPolicy,
      },
      roles: [
        role("mem9-on-aws-prod-task-role"),
        role(productionRoleNames.proxy),
      ],
    });

    await expect(runBoundaryRollout(adapter, options)).rejects.toThrow(
      /trust repair read-back mismatch/u,
    );
    expect(adapter.calls).toContain(
      `update-trust:${productionRoleNames.proxy}`,
    );
    expect(adapter.calls.some((call) => call.startsWith("put-boundary:"))).toBe(
      false,
    );
    expect(adapter.state.quarantineInstalled).toBe(true);
    expect(
      adapter.calls.some((call) => call.startsWith("unquarantine:")),
    ).toBe(false);
  });

  it("resumes after a partial Lambda trust repair", async () => {
    const mutableOptions = {
      failTrustRole: productionRoleNames.oauthFacade,
      initialRoleTrustPolicies: legacyMigrationTrust,
      roles: migrationRoles,
    };
    const adapter = makeAdapter(mutableOptions);

    await expect(runBoundaryRollout(adapter, options)).rejects.toThrow(
      /Lambda trust repair failed/u,
    );
    expect(adapter.state.quarantineInstalled).toBe(true);
    delete mutableOptions.failTrustRole;
    await expect(runBoundaryRollout(adapter, options)).resolves.toEqual({
      status: "complete",
      verifiedRoleCount: migrationRoles.length,
    });
    expect(
      adapter.calls.filter(
        (call) => call === `update-trust:${productionRoleNames.alertRouter}`,
      ),
    ).toHaveLength(1);
    expect(
      adapter.calls.filter(
        (call) => call === `update-trust:${productionRoleNames.oauthFacade}`,
      ),
    ).toHaveLength(2);
    expect(
      adapter.calls.filter(
        (call) => call === `update-trust:${productionRoleNames.proxy}`,
      ),
    ).toHaveLength(1);
  });

  it("never repairs trust during frozen-state verification", async () => {
    const adapter = makeAdapter({
      roles: [
        role("mem9-on-aws-prod-task-role"),
        role(productionRoleNames.proxy),
      ],
    });
    const listRoles = adapter.listRoles.bind(adapter);
    let inventoryReads = 0;
    adapter.listRoles = async (request) => {
      inventoryReads += 1;
      const page = await listRoles(request);
      if (inventoryReads === 1) return page;
      return {
        ...page,
        roles: page.roles.map((fixture) =>
          fixture.name === productionRoleNames.proxy
            ? {
                ...fixture,
                assumeRolePolicyDocument: legacyLambdaTrustPolicy,
              }
            : fixture,
        ),
      };
    };

    await expect(runBoundaryRollout(adapter, options)).rejects.toThrow(
      /trust policy is not Lambda-only/u,
    );
    expect(adapter.calls.some((call) => call.startsWith("update-trust:"))).toBe(
      false,
    );
    expect(adapter.state.quarantineInstalled).toBe(true);
    expect(
      adapter.calls.some((call) => call.startsWith("unquarantine:")),
    ).toBe(false);
  });

  it("fails the quarantine-order invariant against a real module mutation", async () => {
    const requireQuarantineFirst = async (rollout) => {
      const adapter = makeAdapter();
      await rollout(adapter, options);
      const quarantineIndex = adapter.calls.findIndex((call) =>
        call.startsWith("quarantine:"),
      );
      const discoveryIndex = adapter.calls.findIndex((call) =>
        call.startsWith("list-attached:"),
      );
      if (
        quarantineIndex !== 0 ||
        discoveryIndex < 0 ||
        quarantineIndex >= discoveryIndex
      ) {
        throw new Error("quarantine did not precede role discovery");
      }
    };
    await requireQuarantineFirst(runBoundaryRollout);

    await withMutatedRolloutModule(
      (source) => {
        const start = source.indexOf("    quarantineAttempted = true;");
        const endMarker = "    await boundedAdapter.deployBoundary();\n";
        const end = source.indexOf(endMarker, start) + endMarker.length;
        const insertion = source.indexOf(
          "    if (rolesBefore.length === 0) {",
          end,
        );
        if (start < 0 || end < endMarker.length || insertion < 0) return source;
        const quarantineBlock = source.slice(start, end);
        return (
          source.slice(0, start) +
          source.slice(end, insertion) +
          quarantineBlock +
          source.slice(insertion)
        );
      },
      async ({ runBoundaryRollout: mutatedRollout }) => {
        await expect(requireQuarantineFirst(mutatedRollout)).rejects.toThrow(
          /quarantine did not precede role discovery/u,
        );
      },
    );
  });

  it("fails the boundary-coverage invariant against a real module mutation", async () => {
    const requireMissingBoundaryRejected = async (rollout) => {
      const adapter = makeAdapter({ dropBoundaryWrites: true });
      try {
        await rollout(adapter, options);
      } catch (error) {
        if (/workload role boundary read-back mismatch/u.test(error.message)) {
          return;
        }
        throw error;
      }
      throw new Error("rollout accepted a missing workload boundary");
    };
    await requireMissingBoundaryRejected(runBoundaryRollout);

    await withMutatedRolloutModule(
      (source) =>
        source.replace(
          "if (role?.permissionsBoundaryArn !== boundaryArn) {",
          "if (role?.permissionsBoundaryArn && role.permissionsBoundaryArn !== boundaryArn) {",
        ),
      async ({ runBoundaryRollout: mutatedRollout }) => {
        await expect(
          requireMissingBoundaryRejected(mutatedRollout),
        ).rejects.toThrow(/accepted a missing workload boundary/u);
      },
    );
  });

  it("stops at the overall rollout deadline", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-27T00:00:00Z"));
    try {
      const adapter = makeAdapter();
      adapter.putQuarantine = async () => new Promise(() => {});
      const rollout = runBoundaryRollout(adapter, {
        ...options,
        deadlineAt: Date.now() + 20,
      });
      const rejected = expect(rollout).rejects.toThrow(/deadline exceeded/u);
      await vi.advanceTimersByTimeAsync(21);
      await rejected;
      expect(adapter.calls).not.toContain("deploy-boundary");
    } finally {
      vi.useRealTimers();
    }
  });

  it("requires the final GitHub interlock before attempting quarantine", async () => {
    const adapter = makeAdapter();
    delete adapter.verifyFinalGithubInterlock;
    await expect(runBoundaryRollout(adapter, options)).rejects.toThrow(
      /final GitHub interlock configuration/u,
    );
    expect(adapter.calls).toEqual([]);
  });

  it("does nothing after a quarantine installation failure", async () => {
    const adapter = makeAdapter({ failQuarantine: true });
    await expect(runBoundaryRollout(adapter, options)).rejects.toThrow(
      /quarantine failed/u,
    );
    expect(adapter.calls).toHaveLength(1);
  });

  it("fails closed before enforcement when no workload role is discovered", async () => {
    const adapter = makeAdapter({ roles: [] });
    await expect(runBoundaryRollout(adapter, options)).rejects.toThrow(
      /no workload roles/u,
    );
    expect(adapter.state.quarantineInstalled).toBe(true);
    expect(adapter.calls).not.toContain("verify-prod-bindings");
    expect(adapter.calls).not.toContain("deploy-enforcement");
    expect(adapter.calls).not.toContain("activate-prod-boundary");
    expect(adapter.calls.some((call) => call.startsWith("unquarantine:"))).toBe(
      false,
    );
  });

  it.each([
    {
      name: "guarded boundary deployment failure",
      adapter: () => makeAdapter({ failBoundaryDeployment: true }),
    },
    {
      name: "initial quarantine verification false",
      adapter: () => makeAdapter({ failQuarantineVerificationAt: 1 }),
    },
    {
      name: "partial boundary write",
      adapter: () => makeAdapter({ failRole: "mem9-on-aw-pr-70-short-role" }),
    },
    {
      name: "production secret preflight failure",
      adapter: () => makeAdapter({ failProductionSecretPreflight: true }),
    },
    {
      name: "boundary read-back mismatch",
      adapter: () =>
        makeAdapter({ mismatchedRole: "mem9-on-a-pr-70-shortest-role" }),
    },
    {
      name: "changing PassRole scope",
      adapter: () =>
        makeAdapter({
          scopePolicies: [
            passRolePolicy(),
            passRolePolicy(patterns.slice(0, 2)),
          ],
        }),
    },
    {
      name: "deployed policy read failure",
      adapter: () => makeAdapter({ failPolicyRead: true }),
    },
    {
      name: "permanent enforcement failure",
      adapter: () => makeAdapter({ failEnforcement: true }),
    },
    {
      name: "quarantine loss during permanent enforcement",
      adapter: () => makeAdapter({ failQuarantineVerificationAt: 2 }),
    },
    {
      name: "permanent verification failure",
      adapter: () => makeAdapter({ failVerification: true }),
    },
    {
      name: "permanent verification false",
      adapter: () => makeAdapter({ falseVerification: true }),
    },
    {
      name: "final boundary policy verification failure",
      adapter: () => makeAdapter({ failBoundaryDeploymentAt: 2 }),
    },
    {
      name: "production boundary activation failure",
      adapter: () => makeAdapter({ failProductionActivation: true }),
    },
    {
      name: "quarantine loss after production activation",
      adapter: () => makeAdapter({ failQuarantineVerificationAt: 3 }),
    },
    {
      name: "boundary drift during production activation",
      adapter: () =>
        makeAdapter({ removeBoundaryDuringProductionActivation: true }),
    },
    {
      name: "final GitHub interlock failure",
      adapter: () => makeAdapter({ failFinalGithubInterlock: true }),
    },
    {
      name: "Lambda trust drift during final GitHub interlock",
      adapter: () =>
        makeAdapter({
          driftTrustDuringFinalGithub: true,
          liveRoleNames: [
            "mem9-on-aws-prod-task-role",
            productionRoleNames.proxy,
          ],
          roles: [
            role("mem9-on-aws-prod-task-role"),
            role(productionRoleNames.proxy),
          ],
        }),
    },
    {
      name: "quarantine loss after final GitHub interlock",
      adapter: () => makeAdapter({ failQuarantineVerificationAt: 4 }),
    },
  ])(
    "leaves quarantine installed after $name",
    async ({ adapter: factory }) => {
      const adapter = factory();
      await expect(runBoundaryRollout(adapter, options)).rejects.toThrow();
      expect(
        adapter.calls.some((call) => call.startsWith("unquarantine:")),
      ).toBe(false);
      expect(adapter.calls).not.toContain("resume-deployments");
    },
  );

  it("blocks a workload role inventory change after permanent enforcement", async () => {
    const stableInventory = [
      "mem9-on-aws-prod-task-role",
      "mem9-on-a-pr-70-shortest-role",
      "mem9-on-aw-pr-70-short-role",
      "unrelated-role",
    ];
    const adapter = makeAdapter({
      roleInventories: [
        stableInventory,
        stableInventory,
        [
          ...stableInventory.slice(0, 2),
          "mem9-on-aw-pr-70-new-role",
          "unrelated-role",
        ],
      ],
    });

    await expect(runBoundaryRollout(adapter, options)).rejects.toThrow(
      /role inventory changed|PassRole scope changed/u,
    );
    expect(adapter.calls).toContain("deploy-enforcement");
    expect(adapter.calls).not.toContain("activate-prod-boundary");
    expect(adapter.calls.some((call) => call.startsWith("unquarantine:"))).toBe(
      false,
    );
    expect(adapter.calls).not.toContain("resume-deployments");
  });

  it("blocks a PassRole scope change after permanent enforcement", async () => {
    const adapter = makeAdapter({
      scopePolicies: [
        passRolePolicy(),
        passRolePolicy(),
        passRolePolicy(patterns.slice(0, 2)),
      ],
    });

    await expect(runBoundaryRollout(adapter, options)).rejects.toThrow(
      /PassRole scope (?:changed|does not match)/u,
    );
    expect(adapter.calls).toContain("deploy-enforcement");
    expect(adapter.calls).not.toContain("activate-prod-boundary");
    expect(adapter.calls.some((call) => call.startsWith("unquarantine:"))).toBe(
      false,
    );
    expect(adapter.calls).not.toContain("resume-deployments");
  });

  it("lets permanent verification load its own live policy state", async () => {
    const adapter = makeAdapter({ rejectStalePolicyDocuments: true });
    await expect(runBoundaryRollout(adapter, options)).resolves.toEqual({
      verifiedRoleCount: 3,
      status: "complete",
    });
    expect(
      adapter.calls.filter((call) => call === "verify-enforcement"),
    ).toHaveLength(2);
  });

  it("does not attach any boundary when production secret preflight fails", async () => {
    const adapter = makeAdapter({ failProductionSecretPreflight: true });
    await expect(runBoundaryRollout(adapter, options)).rejects.toThrow(
      /secret preflight/u,
    );
    expect(adapter.calls).toContain("verify-prod-bindings");
    expect(adapter.calls.some((call) => call.startsWith("put-boundary:"))).toBe(
      false,
    );
  });

  it("rejects a production role binding outside the migration inventory", async () => {
    const adapter = makeAdapter({
      liveRoleNames: ["mem9-on-aws-prod-unmatched-live-role"],
    });
    await expect(runBoundaryRollout(adapter, options)).rejects.toThrow(
      /outside the migration inventory/u,
    );
    expect(adapter.calls).not.toContain("deploy-enforcement");
    expect(adapter.calls.some((call) => call.startsWith("put-boundary:"))).toBe(
      false,
    );
  });

  it("rejects a production role binding change during frozen-state verification", async () => {
    const adapter = makeAdapter();
    let reads = 0;
    adapter.verifyProductionRuntimeBindings = async () => {
      reads += 1;
      adapter.calls.push("verify-prod-bindings");
      return reads === 1
        ? ["mem9-on-aws-prod-task-role"]
        : ["mem9-on-aw-pr-70-short-role"];
    };
    await expect(runBoundaryRollout(adapter, options)).rejects.toThrow(
      /bindings changed during rollout/u,
    );
    expect(adapter.calls).not.toContain(
      `unquarantine:${options.deployRoleName}:${QUARANTINE_POLICY_NAME}`,
    );
  });

  it("keeps permanent enforcement and the deployment pause after resume fails", async () => {
    const adapter = makeAdapter({ failDeploymentResume: true });
    let failure;
    try {
      await runBoundaryRollout(adapter, options);
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(Error);
    expect(failure.message).toMatch(/deployment resume/u);
    expect(adapter.calls).toContain("verify-enforcement");
    expect(adapter.calls).toContain("resume-deployments");
    expect(adapter.calls.indexOf("resume-deployments")).toBeGreaterThan(
      adapter.calls.indexOf(
        `unquarantine:${options.deployRoleName}:${QUARANTINE_POLICY_NAME}`,
      ),
    );
    expect(adapter.state.quarantineInstalled).toBe(false);
    const output = redactedRolloutFailure(failure);
    expect(output).toContain("Permanent enforcement remains active");
    expect(output).toContain("verify and restore the maintenance pause");
    expect(output).not.toContain("pause was restored");
    expect(output).not.toContain("must be treated as installed");
  });

  it("resumes idempotently when one role already has the boundary", async () => {
    const adapter = makeAdapter({
      initialBoundaries: {
        "mem9-on-aws-prod-task-role": boundaryArn,
      },
    });
    await runBoundaryRollout(adapter, options);
    expect(
      adapter.calls.filter(
        (call) => call === "put-boundary:mem9-on-aws-prod-task-role",
      ),
    ).toHaveLength(0);
    expect(adapter.calls).toContain("get-role:mem9-on-aws-prod-task-role");
  });

  it("resumes on the same retained state after a partial migration failure", async () => {
    const mutableOptions = {
      failRole: "mem9-on-aw-pr-70-short-role",
    };
    const adapter = makeAdapter(mutableOptions);

    await expect(runBoundaryRollout(adapter, options)).rejects.toThrow(
      /boundary write failed/u,
    );
    expect(adapter.state.quarantineInstalled).toBe(true);
    expect(adapter.calls).not.toContain(
      `unquarantine:${options.deployRoleName}:${QUARANTINE_POLICY_NAME}`,
    );

    delete mutableOptions.failRole;
    await expect(runBoundaryRollout(adapter, options)).resolves.toEqual({
      verifiedRoleCount: 3,
      status: "complete",
    });
    expect(adapter.state.quarantineInstalled).toBe(false);
    expect(
      adapter.calls.filter(
        (call) => call === "put-boundary:mem9-on-a-pr-70-shortest-role",
      ),
    ).toHaveLength(1);
  });

  it.each(
    ["SIGINT", "SIGTERM"].flatMap((signalName) =>
      [
        ["quarantine installation", "putQuarantine", 1],
        ["initial boundary deployment", "deployBoundary", 1],
        ["role boundary attachment", "putRoleBoundary", 1],
        ["permanent enforcement", "deployPermanentEnforcement", 1],
        ["final boundary deployment", "deployBoundary", 2],
        ["production activation", "activateProductionBoundary", 1],
      ].map(([phase, method, occurrence]) => ({
        method,
        occurrence,
        phase,
        signalName,
      })),
    ),
  )(
    "resumes retained state after $signalName interrupts $phase",
    async ({ method, occurrence, signalName }) => {
      const adapter = makeAdapter();
      const original = adapter[method].bind(adapter);
      let invocation = 0;
      let interrupted = false;
      adapter[method] = async (...args) => {
        const result = await original(...args);
        invocation += 1;
        if (!interrupted && invocation === occurrence) {
          interrupted = true;
          const error = new Error(`${signalName} interrupted mutation`);
          error.code = "EINTR";
          throw error;
        }
        return result;
      };

      await expect(runBoundaryRollout(adapter, options)).rejects.toThrow(
        /interrupted mutation/u,
      );
      expect(adapter.state.quarantineInstalled).toBe(true);
      await expect(adapter.verifyQuarantine()).resolves.toBe(true);
      expect(
        adapter.calls.some((call) => call.startsWith("unquarantine:")),
      ).toBe(false);

      await expect(runBoundaryRollout(adapter, options)).resolves.toEqual({
        verifiedRoleCount: 3,
        status: "complete",
      });
      expect(adapter.state.quarantineInstalled).toBe(false);
      expect(adapter.calls.at(-1)).toBe("resume-deployments");
    },
  );

  it("emits only a redacted recovery command after a partial failure", async () => {
    const adapter = makeAdapter({
      failRole: "mem9-on-aw-pr-70-short-role",
    });
    let failure;
    try {
      await runBoundaryRollout(adapter, options);
    } catch (error) {
      failure = error;
    }
    const output = redactedRolloutFailure(failure);
    expect(output).toContain(options.resumeCommand);
    expect(output).toContain("must be treated as installed");
    expect(output).not.toMatch(/[0-9]{12}/u);
    expect(output).not.toContain("mem9-on-aw-pr-70-short-role");
    expect(output).not.toContain(boundaryArn);
  });
});

describe("quarantine and permanent policy verification", () => {
  it("accepts the exact quarantine document", () => {
    const document = quarantinePolicyDocument();
    expect(verifyQuarantinePolicy(document)).toBe(true);
    expect(document.Statement).toEqual([
      {
        Sid: "QuarantineAllDeployRoleActions",
        Effect: "Deny",
        Action: "*",
        Resource: "*",
      },
    ]);
  });

  it.each([
    [
      "effect",
      (document) => {
        document.Statement[0].Effect = "Allow";
      },
    ],
    [
      "action",
      (document) => {
        document.Statement[0].Action = "iam:PassRole";
      },
    ],
    [
      "resource",
      (document) => {
        document.Statement[0].Resource = boundaryArn;
      },
    ],
    [
      "condition",
      (document) => {
        document.Statement[0].Condition = {};
      },
    ],
    [
      "duplicate Sid",
      (document) => {
        document.Statement.push({ ...document.Statement[0] });
      },
    ],
    [
      "extra key",
      (document) => {
        document.Statement[0].Principal = "*";
      },
    ],
  ])("rejects a quarantine %s mutation", (_name, mutate) => {
    const document = quarantinePolicyDocument();
    mutate(document);
    expect(verifyQuarantinePolicy(document)).toBe(false);
  });

  it("accepts the exact workload boundary document", () => {
    expect(
      verifyBoundaryPolicyDocument(
        expectedBoundaryPolicyDocument(boundaryContract),
        boundaryContract,
      ),
    ).toBe(true);
  });

  it("TC-MMROUTE-061: accepts the optional cross-region OpenAI project ARN in NotResource", () => {
    const contract = {
      ...boundaryContract,
      openAiBedrockProjectArn:
        "arn:aws:bedrock-mantle:us-west-2:123456789012:project/proj_openai",
    };
    const document = expectedBoundaryPolicyDocument(contract);
    const projectStatement = document.Statement.find(
      ({ Sid }) => Sid === "DenyProjectRuntimeOutsideResources",
    );
    expect(projectStatement.NotResource).toContain(
      "arn:aws:bedrock-mantle:us-west-2:123456789012:project/proj_openai",
    );
    expect(verifyBoundaryPolicyDocument(document, contract)).toBe(true);
    // A document WITH the extra ARN must not verify against a contract WITHOUT
    // it (and vice versa) — the boundary shape is exact either way.
    expect(verifyBoundaryPolicyDocument(document, boundaryContract)).toBe(false);
    expect(
      verifyBoundaryPolicyDocument(
        expectedBoundaryPolicyDocument(boundaryContract),
        contract,
      ),
    ).toBe(false);
  });

  it("TC-MMROUTE-061: rejects a malformed or foreign-account OpenAI project ARN", () => {
    // Built programmatically: the public-artifact scan only allowlists the
    // canonical test account id, so no other 12-digit literal may appear.
    const foreignAccount = "9".repeat(12);
    for (const bad of [
      `arn:aws:bedrock-mantle:us-west-2:${foreignAccount}:project/p`, // foreign account
      `arn:aws:bedrock:us-west-2:${accountId}:project/p`, // wrong service
      "not-an-arn",
    ]) {
      expect(() =>
        expectedBoundaryPolicyDocument({
          ...boundaryContract,
          openAiBedrockProjectArn: bad,
        }),
      ).toThrow(/OpenAI Bedrock Mantle project ARN/);
    }
  });

  it("accepts semantically equivalent reordered action and resource lists", () => {
    const document = expectedBoundaryPolicyDocument(boundaryContract);
    document.Statement.find(({ Sid }) =>
      Sid.startsWith("DenyOutsideRuntimeActionCeiling"),
    ).NotAction.reverse();
    document.Statement.find(
      ({ Sid }) => Sid === "DenyProjectRuntimeOutsideResources",
    ).NotResource.reverse();
    expect(verifyBoundaryPolicyDocument(document, boundaryContract)).toBe(true);
  });

  it.each([
    [
      "effect",
      (document) => {
        document.Statement[0].Effect = "Deny";
      },
    ],
    [
      "action",
      (document) => {
        document.Statement.find(({ Sid }) =>
          Sid.startsWith("DenyOutsideRuntimeActionCeiling"),
        ).NotAction.push("s3:GetObject");
      },
    ],
    [
      "resource",
      (document) => {
        document.Statement.find(
          ({ Sid }) => Sid === "DenyProjectRuntimeOutsideResources",
        ).NotResource[0] =
          "arn:aws:bedrock-mantle:ap-northeast-1:123456789012:project/wrong";
      },
    ],
    [
      "condition",
      (document) => {
        document.Statement.find(
          ({ Sid }) => Sid === "DenyNonShortTermMantleBearer",
        ).Condition.StringNotEqualsIfExists["bedrock-mantle:BearerTokenType"] =
          "LONG_TERM";
      },
    ],
    [
      "duplicate Sid",
      (document) => {
        document.Statement[1].Sid = document.Statement[0].Sid;
      },
    ],
    [
      "extra key",
      (document) => {
        document.Statement[0].Principal = "*";
      },
    ],
  ])("rejects a workload boundary %s mutation", (_name, mutate) => {
    const document = expectedBoundaryPolicyDocument(boundaryContract);
    mutate(document);
    expect(verifyBoundaryPolicyDocument(document, boundaryContract)).toBe(
      false,
    );
  });

  it.each([
    ["missing statement", () => [passRolePolicy()]],
    [
      "effect",
      () => {
        const documents = structuredClone(deployedManagedPolicyDocuments());
        documents
          .flatMap(({ Statement }) => Statement)
          .find(({ Sid }) => Sid === "DenyWorkloadBoundaryRemoval").Effect =
          "Allow";
        return documents;
      },
    ],
    [
      "extra lifecycle action",
      () => {
        const documents = structuredClone(deployedManagedPolicyDocuments());
        documents
          .flatMap(({ Statement }) => Statement)
          .find(({ Sid }) => Sid === "EcsTaskRoleLifecycle")
          .Action.push("iam:UpdateAssumeRolePolicy");
        return documents;
      },
    ],
    [
      "widened lifecycle resource",
      () => {
        const documents = structuredClone(deployedManagedPolicyDocuments());
        documents
          .flatMap(({ Statement }) => Statement)
          .find(({ Sid }) => Sid === "EcsTaskRoleLifecycle").Resource = "*";
        return documents;
      },
    ],
    [
      "action",
      () => {
        const documents = structuredClone(deployedManagedPolicyDocuments());
        documents
          .flatMap(({ Statement }) => Statement)
          .find(({ Sid }) => Sid === "EcsTaskRoleCreateWithBoundary")
          .Action.push("iam:UpdateRole");
        return documents;
      },
    ],
    [
      "resource",
      () => {
        const documents = structuredClone(deployedManagedPolicyDocuments());
        documents
          .flatMap(({ Statement }) => Statement)
          .find(({ Sid }) => Sid === "DenyOperatorOwnedIamMutation").Resource =
          "arn:aws:iam::123456789012:policy/wrong";
        return documents;
      },
    ],
    [
      "condition",
      () => {
        const documents = structuredClone(deployedManagedPolicyDocuments());
        documents
          .flatMap(({ Statement }) => Statement)
          .find(
            ({ Sid }) => Sid === "EcsTaskRoleCreateWithBoundary",
          ).Condition.ArnEquals["iam:PermissionsBoundary"] =
          "arn:aws:iam::123456789012:policy/wrong";
        return documents;
      },
    ],
    [
      "duplicate Sid",
      () => {
        const documents = structuredClone(deployedManagedPolicyDocuments());
        const statement = documents
          .flatMap(({ Statement }) => Statement)
          .find(({ Sid }) => Sid === "DenyWorkloadBoundaryRemoval");
        documents[0].Statement.push(structuredClone(statement));
        return documents;
      },
    ],
    [
      "extra principal",
      () => {
        const documents = structuredClone(deployedManagedPolicyDocuments());
        documents
          .flatMap(({ Statement }) => Statement)
          .find(({ Sid }) => Sid === "DenyWorkloadBoundaryRemoval").Principal =
          "*";
        return documents;
      },
    ],
    [
      "missing ECR ownership-stack deny",
      () => {
        const documents = structuredClone(deployedManagedPolicyDocuments());
        for (const document of documents) {
          document.Statement = document.Statement.filter(
            ({ Sid }) =>
              Sid !== "DenyEcrRegistryScanningOwnershipStackMutation",
          );
        }
        return documents;
      },
    ],
    [
      "missing Lambda role PassRole deny",
      () => {
        const documents = structuredClone(deployedManagedPolicyDocuments());
        for (const document of documents) {
          document.Statement = document.Statement.filter(
            ({ Sid }) => Sid !== "DenyLambdaRolePassToOtherServices",
          );
        }
        return documents;
      },
    ],
    [
      "missing ECS execution role PassRole deny",
      () => {
        const documents = structuredClone(deployedManagedPolicyDocuments());
        for (const document of documents) {
          document.Statement = document.Statement.filter(
            ({ Sid }) => Sid !== "DenyEcsExecutionRolePassToOtherServices",
          );
        }
        return documents;
      },
    ],
    [
      "missing consolidation Scheduler role PassRole deny",
      () => {
        const documents = structuredClone(deployedManagedPolicyDocuments());
        for (const document of documents) {
          document.Statement = document.Statement.filter(
            ({ Sid }) =>
              Sid !== "DenyConsolidationSchedulerRolePassToOtherServices",
          );
        }
        return documents;
      },
    ],
  ])("rejects permanent enforcement with a %s mutation", (_name, documents) => {
    expect(() =>
      verifyPermanentEnforcementDocuments(documents(), {
        accountId,
        boundaryArn,
        partition,
      }),
    ).toThrow(/permanent enforcement/u);
  });
});

describe("stateful AWS CLI adapter", () => {
  function simulationMatrix(
    args,
    sourcePolicyId = denyPolicyId,
    sourcePolicyType = "IAM Policy",
  ) {
    const actions = optionValues(args, "--action-names");
    const configuredResources = optionValues(args, "--resource-arns");
    const resources =
      configuredResources.length === 0 ? ["*"] : configuredResources;
    return actions.flatMap((action) =>
      resources.map((resource) => ({
        EvalActionName: action,
        EvalDecision: "explicitDeny",
        EvalResourceName: resource,
        MatchedStatements: [
          {
            SourcePolicyId: sourcePolicyId,
            SourcePolicyType: sourcePolicyType,
          },
        ],
      })),
    );
  }

  it("custom-simulates the exact read-back quarantine on the default resource", async () => {
    const calls = [];
    const policy = quarantinePolicyDocument();
    const adapter = createAwsCliAdapter({
      consistencyAttempts: 1,
      identity: { accountId, partition },
      invokeAws: (args) => {
        calls.push(args);
        const command = args.slice(0, 2).join(" ");
        if (command === "iam get-role-policy") {
          return { PolicyDocument: policy };
        }
        if (command === "iam simulate-custom-policy") {
          expect(argument(args, "--policy-input-list")).toBe(
            JSON.stringify(policy),
          );
          expect(args).not.toContain("--policy-source-arn");
          expect(args).not.toContain("--resource-arns");
          return { EvaluationResults: simulationMatrix(args) };
        }
        throw new Error(`unexpected mocked command: ${args.join(" ")}`);
      },
      sleep: async () => {},
    });

    await expect(adapter.verifyQuarantine()).resolves.toBe(true);
    expect(calls.map((args) => args.slice(0, 2).join(" "))).toEqual([
      "iam get-role-policy",
      "iam simulate-custom-policy",
      "iam get-role-policy",
    ]);
  });

  it("retries when quarantine changes between simulation and post-read", async () => {
    const exactPolicy = quarantinePolicyDocument();
    const malformedPolicy = {
      ...exactPolicy,
      Statement: [],
    };
    let policyReads = 0;
    const adapter = createAwsCliAdapter({
      consistencyAttempts: 2,
      identity: { accountId, partition },
      invokeAws: (args) => {
        const command = args.slice(0, 2).join(" ");
        if (command === "iam get-role-policy") {
          policyReads += 1;
          return {
            PolicyDocument: policyReads === 2 ? malformedPolicy : exactPolicy,
          };
        }
        if (command === "iam simulate-custom-policy") {
          return { EvaluationResults: simulationMatrix(args) };
        }
        throw new Error(`unexpected mocked command: ${args.join(" ")}`);
      },
      sleep: async () => {},
    });

    await expect(adapter.verifyQuarantine()).resolves.toBe(true);
    expect(policyReads).toBe(4);
  });

  it("accepts an RFC3986-encoded exact quarantine document", async () => {
    const encoded = encodeURIComponent(
      JSON.stringify(quarantinePolicyDocument()),
    );
    const adapter = createAwsCliAdapter({
      consistencyAttempts: 1,
      identity: { accountId, partition },
      invokeAws: (args) => {
        const command = args.slice(0, 2).join(" ");
        if (command === "iam get-role-policy") {
          return { PolicyDocument: encoded };
        }
        if (command === "iam simulate-custom-policy") {
          expect(argument(args, "--policy-input-list")).toBe(
            JSON.stringify(quarantinePolicyDocument()),
          );
          return { EvaluationResults: simulationMatrix(args) };
        }
        throw new Error(`unexpected mocked command: ${args.join(" ")}`);
      },
      sleep: async () => {},
    });

    await expect(adapter.verifyQuarantine()).resolves.toBe(true);
  });

  function permanentVerificationAdapter(
    mutateSimulation = (results) => results,
    consistencyAttempts = 1,
    observeSimulation = () => {},
    mutateSimulationResponse = (response) => response,
  ) {
    const policies = deployedManagedPolicyFixtures();
    const documentsByArn = new Map(
      policies.map(({ arn, document }) => [arn, document]),
    );
    return createAwsCliAdapter({
      consistencyAttempts,
      identity: { accountId, partition },
      invokeAws: (args) => {
        switch (args.slice(0, 2).join(" ")) {
          case "iam list-attached-role-policies":
            return {
              AttachedPolicies: policies.map(({ arn }) => ({
                PolicyArn: arn,
              })),
              IsTruncated: false,
            };
          case "iam get-policy":
            return { Policy: { DefaultVersionId: "v1" } };
          case "iam get-policy-version":
            return {
              PolicyVersion: {
                Document: documentsByArn.get(argument(args, "--policy-arn")),
              },
            };
          case "iam list-role-policies":
            return { PolicyNames: [], IsTruncated: false };
          case "iam simulate-custom-policy": {
            observeSimulation(args);
            return mutateSimulationResponse(
              {
                EvaluationResults: mutateSimulation(
                  simulationMatrix(args),
                  args,
                ),
                IsTruncated: false,
              },
              args,
            );
          }
          default:
            throw new Error(`unexpected mocked command: ${args.join(" ")}`);
        }
      },
      sleep: async () => {},
    });
  }

  it("custom-simulates only the real deployed deny policy", async () => {
    const simulationCalls = [];
    const adapter = permanentVerificationAdapter(
      (results) => results,
      1,
      (args) => {
        simulationCalls.push(args);
      },
    );

    await expect(
      adapter.verifyPermanentEnforcement({ boundaryArn }),
    ).resolves.toBe(true);
    expect(simulationCalls).toHaveLength(7);
    for (const args of simulationCalls) {
      expect(JSON.parse(argument(args, "--policy-input-list"))).toEqual(
        deployedDenyPolicyDocument(),
      );
      expect(optionValues(args, "--action-names")).toHaveLength(1);
      expect(optionValues(args, "--resource-arns")).toHaveLength(1);
    }
    expect(
      simulationCalls.map((args) => [
        optionValues(args, "--action-names")[0],
        optionValues(args, "--resource-arns")[0],
      ]),
    ).toEqual([
      ["iam:CreatePolicyVersion", boundaryArn],
      [
        "cloudformation:UpdateStack",
        `arn:aws:cloudformation:us-west-2:${accountId}:stack/${WORKLOAD_BOUNDARY_STACK_NAME}/propagation-probe`,
      ],
      [
        "cloudformation:UpdateStack",
        `arn:aws:cloudformation:us-west-2:${accountId}:stack/ecr-registry-scanning-mem9-on-aws/propagation-probe`,
      ],
      [
        "iam:CreateRole",
        `arn:aws:iam::${accountId}:role/mem9-on-aws-quarantine-probe`,
      ],
      [
        "iam:PutRolePolicy",
        `arn:aws:iam::${accountId}:role/mem9-on-aws-quarantine-probe`,
      ],
      [
        "iam:DeleteRolePermissionsBoundary",
        `arn:aws:iam::${accountId}:role/mem9-on-aws-quarantine-probe`,
      ],
      [
        "iam:PassRole",
        `arn:aws:iam::${accountId}:role/mem9-on-aws-prod-Mem9ProxyFnRole-propagation-probe`,
      ],
    ]);
  });

  it("avoids generalized resource results from batched simulations", async () => {
    let simulationCalls = 0;
    const adapter = permanentVerificationAdapter((results, args) => {
      simulationCalls += 1;
      if (
        optionValues(args, "--action-names").length > 1 ||
        optionValues(args, "--resource-arns").length > 1
      ) {
        return results.map((result) => ({
          ...result,
          EvalResourceName: "*",
        }));
      }
      return results;
    });

    await expect(
      adapter.verifyPermanentEnforcement({ boundaryArn }),
    ).resolves.toBe(true);
    expect(simulationCalls).toBe(7);
  });

  it("accepts an RFC3986-encoded permanent deny policy document", async () => {
    const adapter = permanentVerificationAdapter(
      (results) => results,
      1,
      (args) => {
        expect(argument(args, "--policy-input-list")).toBe(
          JSON.stringify(deployedDenyPolicyDocument()),
        );
      },
    );
    const originalVersion = adapter.getManagedPolicyVersion;
    adapter.getManagedPolicyVersion = async (request) => {
      const version = await originalVersion(request);
      if (request.policyArn !== denyPolicyArn) return version;
      return {
        document: encodeURIComponent(JSON.stringify(version.document)),
      };
    };

    await expect(
      adapter.verifyPermanentEnforcement({ boundaryArn }),
    ).resolves.toBe(true);
  });

  it.each([
    [
      "implicit deny",
      (results) => {
        results[0].EvalDecision = "implicitDeny";
        return results;
      },
    ],
    ["missing result", (results) => results.slice(1)],
    ["malformed result set", () => "malformed"],
  ])("rejects a quarantine simulation with %s", async (_name, mutate) => {
    const adapter = createAwsCliAdapter({
      consistencyAttempts: 1,
      identity: { accountId, partition },
      invokeAws: (args) => {
        if (args.slice(0, 2).join(" ") === "iam get-role-policy") {
          return { PolicyDocument: quarantinePolicyDocument() };
        }
        if (args.slice(0, 2).join(" ") === "iam simulate-custom-policy") {
          return { EvaluationResults: mutate(simulationMatrix(args)) };
        }
        throw new Error(`unexpected mocked command: ${args.join(" ")}`);
      },
      sleep: async () => {},
    });
    await expect(adapter.verifyQuarantine()).resolves.toBe(false);
  });

  it("rejects duplicate and unexpected quarantine simulation actions", async () => {
    const adapter = createAwsCliAdapter({
      consistencyAttempts: 1,
      identity: { accountId, partition },
      invokeAws: (args) => {
        if (args.slice(0, 2).join(" ") === "iam get-role-policy") {
          return { PolicyDocument: quarantinePolicyDocument() };
        }
        if (args.slice(0, 2).join(" ") === "iam simulate-custom-policy") {
          const results = simulationMatrix(args);
          results[1] = {
            ...results[0],
            EvalActionName: "iam:DeleteUser",
          };
          return { EvaluationResults: results };
        }
        throw new Error(`unexpected mocked command: ${args.join(" ")}`);
      },
      sleep: async () => {},
    });
    await expect(adapter.verifyQuarantine()).resolves.toBe(false);
  });

  it.each([100, 101])(
    "describes every production task across the %i-task batch boundary",
    async (taskCount) => {
      const calls = [];
      const allTasks = Array.from({ length: taskCount }, (_, index) => ({
        taskArn:
          `arn:aws:ecs:ap-northeast-1:${accountId}:task/` +
          `production-${index + 1}`,
        taskDefinitionArn:
          index === taskCount - 1
            ? productionTaskDefinitions.replacement
            : productionTaskDefinitions.primary,
      }));
      const invokeAws = (args) => {
        calls.push(args);
        const command = args.slice(0, 2).join(" ");
        if (command === "ecs list-tasks") {
          const desiredStatus = argument(args, "--desired-status");
          const token = argument(args, "--next-token");
          if (desiredStatus === "RUNNING") {
            if (token === undefined && taskCount === 101) {
              return {
                taskArns: allTasks.slice(0, 60).map(({ taskArn }) => taskArn),
                nextToken: "running-2",
              };
            }
            if (token === "running-2") {
              return {
                taskArns: allTasks.slice(60, 100).map(({ taskArn }) => taskArn),
              };
            }
            return {
              taskArns: allTasks.slice(0, 100).map(({ taskArn }) => taskArn),
            };
          }
          if (taskCount === 101 && token === undefined) {
            return {
              taskArns: [allTasks[100].taskArn],
              nextToken: "pending-2",
            };
          }
          if (token === "pending-2" || taskCount === 100) {
            return { taskArns: [] };
          }
        }
        if (command === "ecs describe-tasks") {
          const batch = args.slice(args.indexOf("--tasks") + 1);
          return {
            failures: [],
            tasks: batch.map((taskArn) =>
              allTasks.find((task) => task.taskArn === taskArn),
            ),
          };
        }
        return productionPreflightAws(args);
      };
      const adapter = createAwsCliAdapter({
        consistencyAttempts: 1,
        identity: { accountId, partition },
        invokeAws,
        sleep: async () => {},
      });

      await expect(adapter.verifyProductionRuntimeBindings()).resolves.toEqual(
        expectedProductionRoleNames,
      );
      const describeCalls = calls.filter(
        (args) => args.slice(0, 2).join(" ") === "ecs describe-tasks",
      );
      expect(describeCalls).toHaveLength(taskCount === 101 ? 2 : 1);
      expect(
        describeCalls.map((args) => args.length - args.indexOf("--tasks") - 1),
      ).toEqual(taskCount === 101 ? [100, 1] : [100]);
      expect(
        calls.filter(
          (args) =>
            args.slice(0, 2).join(" ") === "ecs list-tasks" &&
            argument(args, "--desired-status") === "RUNNING",
        ),
      ).toHaveLength(taskCount === 101 ? 2 : 1);
      expect(
        calls.filter(
          (args) =>
            args.slice(0, 2).join(" ") === "ecs list-tasks" &&
            argument(args, "--desired-status") === "PENDING",
        ),
      ).toHaveLength(taskCount === 101 ? 2 : 1);
    },
  );

  it("rejects a repeated production task pagination token", async () => {
    const invokeAws = (args) => {
      if (args.slice(0, 2).join(" ") === "ecs list-tasks") {
        return {
          taskArns: [
            `arn:aws:ecs:ap-northeast-1:${accountId}:task/repeated-token`,
          ],
          nextToken: "repeated",
        };
      }
      return productionPreflightAws(args);
    };
    const adapter = createAwsCliAdapter({
      consistencyAttempts: 1,
      identity: { accountId, partition },
      invokeAws,
      sleep: async () => {},
    });
    await expect(adapter.verifyProductionRuntimeBindings()).rejects.toThrow(
      /pagination is malformed/u,
    );
  });

  it("rejects a repeated production Lambda pagination marker", async () => {
    const adapter = createAwsCliAdapter({
      consistencyAttempts: 1,
      identity: { accountId, partition },
      invokeAws: (args) => {
        if (args.slice(0, 2).join(" ") === "lambda list-functions") {
          return { Functions: [], NextMarker: "repeated" };
        }
        return productionPreflightAws(args);
      },
      sleep: async () => {},
    });
    await expect(adapter.verifyProductionRuntimeBindings()).rejects.toThrow(
      /Lambda listing pagination is malformed/u,
    );
  });

  it.each([100, 101])(
    "enforces the %i-page production ECS listing boundary",
    async (pageCount) => {
      const taskArn = `arn:aws:ecs:ap-northeast-1:${accountId}:task/page-limit`;
      let runningPages = 0;
      const adapter = createAwsCliAdapter({
        consistencyAttempts: 1,
        identity: { accountId, partition },
        invokeAws: (args) => {
          const command = args.slice(0, 2).join(" ");
          if (command === "ecs list-tasks") {
            if (argument(args, "--desired-status") === "PENDING") {
              return { taskArns: [] };
            }
            runningPages += 1;
            return {
              taskArns: [taskArn],
              ...(runningPages < pageCount
                ? { nextToken: `running-${runningPages + 1}` }
                : {}),
            };
          }
          if (command === "ecs describe-tasks") {
            return {
              failures: [],
              tasks: [
                {
                  taskArn,
                  taskDefinitionArn: productionTaskDefinitions.primary,
                },
              ],
            };
          }
          return productionPreflightAws(args);
        },
        sleep: async () => {},
      });

      if (pageCount === 100) {
        await expect(
          adapter.verifyProductionRuntimeBindings(),
        ).resolves.toEqual(expectedProductionRoleNames);
      } else {
        await expect(adapter.verifyProductionRuntimeBindings()).rejects.toThrow(
          /ECS task listing exceeded the page limit/u,
        );
      }
      expect(runningPages).toBe(100);
    },
  );

  it.each([10_000, 10_001])(
    "enforces the %i-item production ECS listing boundary",
    async (itemCount) => {
      const taskArn = `arn:aws:ecs:ap-northeast-1:${accountId}:task/item-limit`;
      const adapter = createAwsCliAdapter({
        consistencyAttempts: 1,
        identity: { accountId, partition },
        invokeAws: (args) => {
          const command = args.slice(0, 2).join(" ");
          if (command === "ecs list-tasks") {
            return {
              taskArns:
                argument(args, "--desired-status") === "RUNNING"
                  ? Array.from({ length: itemCount }, () => taskArn)
                  : [],
            };
          }
          if (command === "ecs describe-tasks") {
            return {
              failures: [],
              tasks: [
                {
                  taskArn,
                  taskDefinitionArn: productionTaskDefinitions.primary,
                },
              ],
            };
          }
          return productionPreflightAws(args);
        },
        sleep: async () => {},
      });

      if (itemCount === 10_000) {
        await expect(
          adapter.verifyProductionRuntimeBindings(),
        ).resolves.toEqual(expectedProductionRoleNames);
      } else {
        await expect(adapter.verifyProductionRuntimeBindings()).rejects.toThrow(
          /ECS task listing exceeded the item limit/u,
        );
      }
    },
  );

  it.each([100, 101])(
    "enforces the %i-page production Lambda listing boundary",
    async (pageCount) => {
      let lambdaPages = 0;
      const adapter = createAwsCliAdapter({
        consistencyAttempts: 1,
        identity: { accountId, partition },
        invokeAws: (args) => {
          if (args.slice(0, 2).join(" ") === "lambda list-functions") {
            lambdaPages += 1;
            return {
              Functions:
                lambdaPages === 1 ? productionPreflightAws(args).Functions : [],
              ...(lambdaPages < pageCount
                ? { NextMarker: `lambda-${lambdaPages + 1}` }
                : {}),
            };
          }
          return productionPreflightAws(args);
        },
        sleep: async () => {},
      });

      if (pageCount === 100) {
        await expect(
          adapter.verifyProductionRuntimeBindings(),
        ).resolves.toEqual(expectedProductionRoleNames);
      } else {
        await expect(adapter.verifyProductionRuntimeBindings()).rejects.toThrow(
          /Lambda listing exceeded the page limit/u,
        );
      }
      expect(lambdaPages).toBe(100);
    },
  );

  it.each([10_000, 10_001])(
    "enforces the %i-item production Lambda listing boundary",
    async (itemCount) => {
      const productionFunctions = productionPreflightAws([
        "lambda",
        "list-functions",
      ]).Functions;
      const adapter = createAwsCliAdapter({
        consistencyAttempts: 1,
        identity: { accountId, partition },
        invokeAws: (args) => {
          if (args.slice(0, 2).join(" ") === "lambda list-functions") {
            return {
              Functions: [
                ...productionFunctions,
                ...Array.from(
                  { length: itemCount - productionFunctions.length },
                  (_, index) => ({
                    FunctionName: `unrelated-${index}`,
                  }),
                ),
              ],
            };
          }
          return productionPreflightAws(args);
        },
        sleep: async () => {},
      });

      if (itemCount === 10_000) {
        await expect(
          adapter.verifyProductionRuntimeBindings(),
        ).resolves.toEqual(expectedProductionRoleNames);
      } else {
        await expect(adapter.verifyProductionRuntimeBindings()).rejects.toThrow(
          /Lambda listing exceeded the item limit/u,
        );
      }
    },
  );

  function quarantineRemovalHarness({ itemCount = 0, pageCount = 1 }) {
    const calls = [];
    let quarantine;
    const adapter = createAwsCliAdapter({
      consistencyAttempts: 1,
      identity: { accountId, partition },
      invokeAws: (args) => {
        const command = args.slice(0, 2).join(" ");
        calls.push(args);
        if (command === "iam delete-role-policy") {
          quarantine = undefined;
          return {};
        }
        if (command === "iam list-role-policies") {
          const marker = argument(args, "--marker");
          const currentPage =
            marker === undefined ? 1 : Number(marker.replace("page-", ""));
          return {
            IsTruncated: currentPage < pageCount,
            ...(currentPage < pageCount
              ? { Marker: `page-${currentPage + 1}` }
              : {}),
            PolicyNames: Array.from(
              {
                length: pageCount === 1 ? itemCount : currentPage === 1 ? 1 : 0,
              },
              () => "unrelated-inline-policy",
            ),
          };
        }
        if (command === "iam put-role-policy") {
          quarantine = JSON.parse(argument(args, "--policy-document"));
          return {};
        }
        if (command === "iam get-role-policy") {
          return { PolicyDocument: quarantine };
        }
        if (command === "iam simulate-custom-policy") {
          return { EvaluationResults: simulationMatrix(args) };
        }
        throw new Error(`unexpected AWS command: ${command}`);
      },
      sleep: async () => {},
    });
    return { adapter, calls, quarantine: () => quarantine };
  }

  it.each([100, 101])(
    "enforces the %i-page quarantine deletion listing boundary",
    async (pageCount) => {
      const harness = quarantineRemovalHarness({ pageCount });
      const deletion = harness.adapter.deleteQuarantine({
        policyName: QUARANTINE_POLICY_NAME,
        roleName: DEPLOY_ROLE_NAME,
      });
      if (pageCount === 100) {
        await expect(deletion).resolves.toBeUndefined();
      } else {
        await expect(deletion).rejects.toThrow(/removal was not observed/u);
        expect(verifyQuarantinePolicy(harness.quarantine())).toBe(true);
      }
      expect(
        harness.calls.filter(
          (args) => args.slice(0, 2).join(" ") === "iam list-role-policies",
        ),
      ).toHaveLength(100);
    },
  );

  it.each([10_000, 10_001])(
    "enforces the %i-item quarantine deletion listing boundary",
    async (itemCount) => {
      const harness = quarantineRemovalHarness({ itemCount });
      const deletion = harness.adapter.deleteQuarantine({
        policyName: QUARANTINE_POLICY_NAME,
        roleName: DEPLOY_ROLE_NAME,
      });
      if (itemCount === 10_000) {
        await expect(deletion).resolves.toBeUndefined();
      } else {
        await expect(deletion).rejects.toThrow(/removal was not observed/u);
        expect(verifyQuarantinePolicy(harness.quarantine())).toBe(true);
      }
    },
  );

  it("retries a transient quarantine read and succeeds", async () => {
    let policyReads = 0;
    const sleeps = [];
    const adapter = createAwsCliAdapter({
      consistencyAttempts: 3,
      identity: { accountId, partition },
      invokeAws: (args) => {
        const command = args.slice(0, 2).join(" ");
        if (command === "iam get-role-policy") {
          policyReads += 1;
          if (policyReads === 1) throw new Error("transient");
          return { PolicyDocument: quarantinePolicyDocument() };
        }
        if (command === "iam simulate-custom-policy") {
          return { EvaluationResults: simulationMatrix(args) };
        }
        throw new Error(`unexpected command: ${command}`);
      },
      sleep: async (milliseconds) => sleeps.push(milliseconds),
    });
    await expect(adapter.verifyQuarantine()).resolves.toBe(true);
    expect(policyReads).toBe(3);
    expect(sleeps).toEqual([2_000]);
  });

  it("stops retrying after the configured quarantine attempts", async () => {
    let policyReads = 0;
    const adapter = createAwsCliAdapter({
      consistencyAttempts: 3,
      identity: { accountId, partition },
      invokeAws: () => {
        policyReads += 1;
        throw new Error("persistent");
      },
      sleep: async () => {},
    });
    await expect(adapter.verifyQuarantine()).resolves.toBe(false);
    expect(policyReads).toBe(3);
  });

  it.each([
    [
      "implicit deny",
      (results) => {
        results[0].EvalDecision = "implicitDeny";
        return results;
      },
    ],
    ["missing result", (results) => results.slice(1)],
    ["malformed result set", () => "malformed"],
    ["duplicate result", (results) => [...results, structuredClone(results[0])]],
    [
      "mismatched action",
      (results) =>
        results.map((result) => ({
          ...result,
          EvalActionName: "iam:DeleteUser",
        })),
    ],
    [
      "generalized resource",
      (results) =>
        results.map((result) => ({
          ...result,
          EvalResourceName: "*",
        })),
    ],
    [
      "missing matched statement",
      (results) =>
        results.map((result) => ({
          ...result,
          MatchedStatements: [],
        })),
    ],
  ])("rejects permanent simulation with %s", async (_name, mutate) => {
    const adapter = permanentVerificationAdapter(mutate);
    await expect(
      adapter.verifyPermanentEnforcement({ boundaryArn }),
    ).resolves.toBe(false);
  });

  it("rejects a truncated permanent simulation result", async () => {
    const adapter = permanentVerificationAdapter(
      (results) => results,
      1,
      () => {},
      (response) => ({ ...response, IsTruncated: true }),
    );
    await expect(
      adapter.verifyPermanentEnforcement({ boundaryArn }),
    ).resolves.toBe(false);
  });

  it.each([
    ["malformed truncation flag", { IsTruncated: "false" }],
    ["unexpected pagination marker", { IsTruncated: false, Marker: "next" }],
  ])("rejects permanent simulation with %s", async (_name, metadata) => {
    const adapter = permanentVerificationAdapter(
      (results) => results,
      1,
      () => {},
      (response) => ({ ...response, ...metadata }),
    );
    await expect(
      adapter.verifyPermanentEnforcement({ boundaryArn }),
    ).resolves.toBe(false);
  });

  it("rejects a failed final permanent-enforcement probe", async () => {
    const simulatedActions = [];
    const adapter = permanentVerificationAdapter(
      (results, args) => {
        const [action] = optionValues(args, "--action-names");
        simulatedActions.push(action);
        if (action !== "iam:PassRole") return results;
        return results.map((result) => ({
          ...result,
          EvalDecision: "implicitDeny",
        }));
      },
      1,
    );

    await expect(
      adapter.verifyPermanentEnforcement({ boundaryArn }),
    ).resolves.toBe(false);
    expect(simulatedActions).toEqual([
      "iam:CreatePolicyVersion",
      "cloudformation:UpdateStack",
      "cloudformation:UpdateStack",
      "iam:CreateRole",
      "iam:PutRolePolicy",
      "iam:DeleteRolePermissionsBoundary",
      "iam:PassRole",
    ]);
  });

  it("restarts every probe with fresh policy state after a transient final-probe failure", async () => {
    const simulatedActions = [];
    let passRoleAttempts = 0;
    let denyPolicyDocumentReads = 0;
    const adapter = permanentVerificationAdapter(
      (results, args) => {
        const [action] = optionValues(args, "--action-names");
        simulatedActions.push(action);
        if (action !== "iam:PassRole" || passRoleAttempts++ > 0) return results;
        return results.map((result) => ({
          ...result,
          EvalDecision: "implicitDeny",
        }));
      },
      2,
    );
    const originalGetManagedPolicyVersion = adapter.getManagedPolicyVersion;
    adapter.getManagedPolicyVersion = async (request) => {
      if (request.policyArn === denyPolicyArn) {
        denyPolicyDocumentReads += 1;
      }
      return originalGetManagedPolicyVersion(request);
    };

    await expect(
      adapter.verifyPermanentEnforcement({ boundaryArn }),
    ).resolves.toBe(true);
    expect(simulatedActions).toEqual([
      "iam:CreatePolicyVersion",
      "cloudformation:UpdateStack",
      "cloudformation:UpdateStack",
      "iam:CreateRole",
      "iam:PutRolePolicy",
      "iam:DeleteRolePermissionsBoundary",
      "iam:PassRole",
      "iam:CreatePolicyVersion",
      "cloudformation:UpdateStack",
      "cloudformation:UpdateStack",
      "iam:CreateRole",
      "iam:PutRolePolicy",
      "iam:DeleteRolePermissionsBoundary",
      "iam:PassRole",
    ]);
    expect(denyPolicyDocumentReads).toBe(5);
  });

  it("rejects permanent verification without the exact attached deny policy", async () => {
    const adapter = permanentVerificationAdapter();
    const originalList = adapter.listAttachedPolicies;
    adapter.listAttachedPolicies = async (request) => {
      const page = await originalList(request);
      return {
        ...page,
        policies: page.policies.map(() => ({
          arn: "arn:aws:iam::123456789012:policy/wrong-policy",
        })),
      };
    };
    await expect(
      adapter.verifyPermanentEnforcement({ boundaryArn }),
    ).resolves.toBe(false);
  });

  it("retries until the exact permanent deny attachment is visible", async () => {
    let attachmentReads = 0;
    const adapter = permanentVerificationAdapter(
      (results) => results,
      2,
    );
    const originalList = adapter.listAttachedPolicies;
    adapter.listAttachedPolicies = async (request) => {
      attachmentReads += 1;
      if (attachmentReads === 2) {
        return {
          marker: undefined,
          policies: [
            { arn: "arn:aws:iam::123456789012:policy/wrong-policy" },
          ],
        };
      }
      return originalList(request);
    };

    await expect(
      adapter.verifyPermanentEnforcement({ boundaryArn }),
    ).resolves.toBe(true);
    expect(attachmentReads).toBeGreaterThanOrEqual(3);
  });

  it("retries a stale complete-policy read inside permanent verification", async () => {
    let versionReads = 0;
    const adapter = permanentVerificationAdapter(
      (results) => results,
      2,
    );
    const originalVersion = adapter.getManagedPolicyVersion;
    adapter.getManagedPolicyVersion = async (request) => {
      versionReads += 1;
      if (versionReads === 1) {
        return {
          document: { Version: "2012-10-17", Statement: [] },
        };
      }
      return originalVersion(request);
    };

    await expect(
      adapter.verifyPermanentEnforcement({ boundaryArn }),
    ).resolves.toBe(true);
    expect(versionReads).toBeGreaterThan(
      deployedManagedPolicyFixtures().length,
    );
  });

  it("rejects a deny-policy mutation after permanent simulation", async () => {
    let simulated = false;
    const adapter = permanentVerificationAdapter(
      (results) => {
        simulated = true;
        return results;
      },
      1,
    );
    const originalList = adapter.listAttachedPolicies;
    adapter.listAttachedPolicies = async (request) => {
      if (simulated) {
        return {
          marker: undefined,
          policies: [{ arn: "arn:aws:iam::123456789012:policy/wrong-policy" }],
        };
      }
      return originalList(request);
    };

    await expect(
      adapter.verifyPermanentEnforcement({ boundaryArn }),
    ).resolves.toBe(false);
  });

  it("rejects a default-version mutation after permanent simulation", async () => {
    let simulated = false;
    const adapter = permanentVerificationAdapter(
      (results) => {
        simulated = true;
        return results;
      },
      1,
    );
    const originalMetadata = adapter.getManagedPolicy;
    adapter.getManagedPolicy = async (request) => {
      if (simulated && request.policyArn === denyPolicyArn) {
        return { defaultVersionId: "v2" };
      }
      return originalMetadata(request);
    };

    await expect(
      adapter.verifyPermanentEnforcement({ boundaryArn }),
    ).resolves.toBe(false);
  });

  it("rejects aggregate policy drift after permanent simulation", async () => {
    let simulated = false;
    const adapter = permanentVerificationAdapter(
      (results) => {
        simulated = true;
        return results;
      },
      1,
    );
    const originalVersion = adapter.getManagedPolicyVersion;
    adapter.getManagedPolicyVersion = async (request) => {
      if (simulated && request.policyArn !== denyPolicyArn) {
        return {
          document: { Version: "2012-10-17", Statement: [] },
        };
      }
      return originalVersion(request);
    };

    await expect(
      adapter.verifyPermanentEnforcement({ boundaryArn }),
    ).resolves.toBe(false);
  });

  it("keeps rollout quarantine when the real permanent adapter rejects a probe", async () => {
    const rolloutAdapter = makeAdapter();
    const policyDocuments = deployedManagedPolicyDocuments();
    const policyArns = policyDocuments.map(
      (_document, index) => `arn:managed:permanent-${index}`,
    );
    rolloutAdapter.listAttachedPolicies = async () => ({
      policies: policyArns.map((arn) => ({ arn })),
    });
    rolloutAdapter.getManagedPolicy = async () => ({
      defaultVersionId: "v1",
    });
    rolloutAdapter.getManagedPolicyVersion = async ({ policyArn }) => ({
      document: policyDocuments[policyArns.indexOf(policyArn)],
    });
    rolloutAdapter.listInlinePolicies = async () => ({ policyNames: [] });
    rolloutAdapter.verifyPermanentEnforcement = permanentVerificationAdapter(
      (results) =>
        results.map((result) => ({
          ...result,
          MatchedStatements: [],
        })),
    ).verifyPermanentEnforcement;
    await expect(
      runBoundaryRollout(rolloutAdapter, {
        accountId,
        boundaryArn,
        deployRoleName: "github-actions-mem9-on-aws",
        partition,
        reviewedCommit,
        resumeCommand: "safe-resume-command",
      }),
    ).rejects.toThrow(/permanent permissions-boundary enforcement/u);
    expect(rolloutAdapter.state.quarantineInstalled).toBe(true);
  });

  it("runs the complete paginated migration and removes quarantine last", async () => {
    const calls = [];
    const boundaries = new Map();
    const state = {
      boundaryDeployed: false,
      deploymentPaused: true,
      enforced: false,
      productionBoundaryEnabled: false,
      quarantine: undefined,
      workflowsEnabled: false,
    };
    const permanentPolicies = deployedManagedPolicyFixtures();
    const permanentDocumentsByArn = new Map(
      permanentPolicies.map(({ arn, document }) => [arn, document]),
    );

    const invokeAws = (args) => {
      calls.push(args);
      const command = args.slice(0, 2).join(" ");
      const marker = argument(args, "--marker");
      const roleName = argument(args, "--role-name");
      const policyArn = argument(args, "--policy-arn");

      switch (command) {
        case "sts get-caller-identity":
          return {
            Account: accountId,
            Arn: `arn:${partition}:sts::${accountId}:assumed-role/operator/session`,
          };
        case "cloudformation describe-stacks":
          return productionPreflightAws(args);
        case "iam put-role-policy":
          state.quarantine = JSON.parse(argument(args, "--policy-document"));
          return {};
        case "iam get-role-policy":
          if (
            argument(args, "--policy-name") === QUARANTINE_POLICY_NAME &&
            state.quarantine
          ) {
            return { PolicyDocument: state.quarantine };
          }
          throw new Error("inline policy not found");
        case "iam simulate-custom-policy": {
          const actions = optionValues(args, "--action-names");
          const configuredResources = optionValues(args, "--resource-arns");
          const resources =
            configuredResources.length === 0 ? ["*"] : configuredResources;
          return {
            EvaluationResults: actions.flatMap((action) =>
              resources.map((resource) => {
                const permanentProbe =
                  resource === boundaryArn ||
                  resource.includes(
                    ":stack/workload-permissions-boundary-mem9-on-aws/",
                  ) ||
                  resource.includes(
                    ":stack/ecr-registry-scanning-mem9-on-aws/",
                  ) ||
                  resource.endsWith("/mem9-on-aws-quarantine-probe") ||
                  resource.includes("Mem9AlertRouterRole") ||
                  resource.includes("Mem9OauthFacadeAllowAllRole") ||
                  resource.includes("Mem9OauthFacadeFnRole") ||
                  resource.includes("Mem9ProxyFnRole");
                return {
                  EvalActionName: action,
                  EvalDecision:
                    state.quarantine || (permanentProbe && state.enforced)
                      ? "explicitDeny"
                      : "implicitDeny",
                  EvalResourceName: resource,
                  MatchedStatements:
                    permanentProbe && state.enforced
                      ? [
                          {
                            SourcePolicyId: denyPolicyId,
                            SourcePolicyType: "IAM Policy",
                          },
                        ]
                      : [],
                };
              }),
            ),
          };
        }
        case "iam list-attached-role-policies":
          return marker === "attached-2"
            ? {
                AttachedPolicies: permanentPolicies.slice(2).map(({ arn }) => ({
                  PolicyArn: arn,
                })),
                IsTruncated: false,
              }
            : {
                AttachedPolicies: permanentPolicies
                  .slice(0, 2)
                  .map(({ arn }) => ({ PolicyArn: arn })),
                IsTruncated: true,
                Marker: "attached-2",
              };
        case "iam get-policy":
          return {
            Policy: {
              DefaultVersionId: state.enforced ? "v2" : "v1",
            },
          };
        case "iam get-policy-version":
          return {
            PolicyVersion: {
              Document:
                policyArn === denyPolicyArn && !state.enforced
                  ? { Version: "2012-10-17", Statement: [] }
                  : permanentDocumentsByArn.get(policyArn),
            },
          };
        case "iam list-role-policies":
          if (marker === "inline-2") {
            return { PolicyNames: [], IsTruncated: false };
          }
          return {
            PolicyNames: state.quarantine ? [QUARANTINE_POLICY_NAME] : [],
            IsTruncated: true,
            Marker: "inline-2",
          };
        case "ssm get-parameters":
          return {
            InvalidParameters: [],
            Parameters: [
              {
                Name: "/mem9-on-aws/prod/ecs/cluster-name",
                Value: "mem9-prod-cluster",
              },
              {
                Name: "/mem9-on-aws/prod/ecs/service-name",
                Value: "mem9-prod-service",
              },
              {
                Name: "/mem9-on-aws/prod/bootstrap/task-def-arn",
                Value: productionTaskDefinitions.bootstrap,
              },
              {
                Name: "/mem9-on-aws/prod/gateway/id",
                Value: "gateway-prod-123",
              },
            ],
          };
        case "ecs describe-services":
          return {
            failures: [],
            services: [
              {
                deployments: [
                  {
                    status: "PRIMARY",
                    taskDefinition: productionTaskDefinitions.primary,
                  },
                  {
                    status: "ACTIVE",
                    taskDefinition: productionTaskDefinitions.replacement,
                  },
                ],
                serviceName: "mem9-prod-service",
                taskDefinition: productionTaskDefinitions.primary,
              },
            ],
          };
        case "ecs list-tasks":
          return argument(args, "--desired-status") === "RUNNING"
            ? {
                taskArns: [
                  "arn:aws:ecs:ap-northeast-1:123456789012:task/running",
                ],
              }
            : {
                taskArns: [
                  "arn:aws:ecs:ap-northeast-1:123456789012:task/pending",
                ],
              };
        case "ecs describe-tasks":
          return {
            failures: [],
            tasks: [
              {
                taskArn: "arn:aws:ecs:ap-northeast-1:123456789012:task/running",
                taskDefinitionArn: productionTaskDefinitions.primary,
              },
              {
                taskArn: "arn:aws:ecs:ap-northeast-1:123456789012:task/pending",
                taskDefinitionArn: productionTaskDefinitions.replacement,
              },
            ],
          };
        case "ecs describe-task-definition": {
          const taskDefinitionArn = argument(args, "--task-definition");
          const family = taskDefinitionArn?.includes("Mem9Bootstrap")
            ? "mem9-on-aws-prod-Mem9Bootstrap"
            : "mem9-on-aws-prod-Mem9Server";
          return {
            taskDefinition: taskDefinition(taskDefinitionArn, family),
          };
        }
        case "lambda list-functions":
        case "bedrock-agentcore-control get-gateway":
          return productionPreflightAws(args);
        case "iam list-roles":
          return marker === "roles-2"
            ? {
                Roles: [
                  {
                    Arn: role("mem9-on-aw-pr-70-short-role").arn,
                    AssumeRolePolicyDocument: undefined,
                    RoleName: "mem9-on-aw-pr-70-short-role",
                  },
                  {
                    Arn: role("mem9-on-a-pr-70-shortest-role").arn,
                    AssumeRolePolicyDocument: undefined,
                    RoleName: "mem9-on-a-pr-70-shortest-role",
                  },
                ],
                IsTruncated: false,
              }
            : {
                Roles: [
                  ...expectedProductionRoleNames.map((name) => ({
                    Arn: role(name).arn,
                    AssumeRolePolicyDocument:
                      role(name).assumeRolePolicyDocument,
                    RoleName: name,
                  })),
                  {
                    Arn: role("unrelated-role").arn,
                    AssumeRolePolicyDocument: undefined,
                    RoleName: "unrelated-role",
                  },
                ],
                IsTruncated: true,
                Marker: "roles-2",
              };
        case "iam put-role-permissions-boundary":
          boundaries.set(roleName, argument(args, "--permissions-boundary"));
          return {};
        case "iam get-role":
          return {
            Role: {
              PermissionsBoundary: boundaries.has(roleName)
                ? { PermissionsBoundaryArn: boundaries.get(roleName) }
                : undefined,
            },
          };
        case "iam delete-role-policy":
          state.quarantine = undefined;
          return {};
        default:
          throw new Error(`unexpected mocked command: ${command}`);
      }
    };

    const identity = await resolveAwsIdentity(invokeAws);
    const adapter = createAwsCliAdapter({
      consistencyAttempts: 1,
      deployBoundary: () => {
        calls.push(["deploy-boundary"]);
        state.boundaryDeployed = true;
      },
      deployEnforcement: () => {
        calls.push(["deploy-enforcement"]);
        state.enforced = true;
      },
      activateProductionBoundary: () => {
        calls.push(["activate-prod-boundary"]);
        state.productionBoundaryEnabled = true;
      },
      verifyFinalGithubInterlock: ({
        reviewedCommit: receivedReviewedCommit,
      }) => {
        calls.push(["verify-final-github", receivedReviewedCommit]);
        expect(receivedReviewedCommit).toBe(reviewedCommit);
      },
      identity,
      invokeAws,
      resumeDeployments: () => {
        calls.push(["resume-deployments"]);
        state.deploymentPaused = false;
        state.workflowsEnabled = true;
      },
      sleep: async () => {},
    });
    const result = await runBoundaryRollout(adapter, {
      accountId,
      boundaryArn,
      deployRoleName: "github-actions-mem9-on-aws",
      partition,
      reviewedCommit,
      resumeCommand: "safe-resume-command",
    });

    expect(result).toEqual({ verifiedRoleCount: 10, status: "complete" });
    expect(state).toEqual({
      boundaryDeployed: true,
      deploymentPaused: false,
      enforced: true,
      productionBoundaryEnabled: true,
      quarantine: undefined,
      workflowsEnabled: true,
    });
    expect([...boundaries.values()]).toEqual(
      Array.from({ length: 10 }, () => boundaryArn),
    );
    expect(
      calls.findIndex(
        (args) => args.slice(0, 2).join(" ") === "iam put-role-policy",
      ),
    ).toBeLessThan(
      calls.findIndex(
        (args) => args.slice(0, 2).join(" ") === "iam list-roles",
      ),
    );
    expect(
      calls.findIndex((args) => args[0] === "deploy-boundary"),
    ).toBeGreaterThan(
      calls.findIndex(
        (args) =>
          args.slice(0, 2).join(" ") === "iam simulate-custom-policy",
      ),
    );
    expect(
      calls.findIndex((args) => args[0] === "deploy-boundary"),
    ).toBeLessThan(
      calls.findIndex(
        (args) =>
          args.slice(0, 2).join(" ") === "iam list-attached-role-policies",
      ),
    );
    const boundaryDeploys = calls
      .map((args, index) => (args[0] === "deploy-boundary" ? index : -1))
      .filter((index) => index >= 0);
    expect(boundaryDeploys).toHaveLength(2);
    expect(boundaryDeploys[1]).toBeLessThan(
      calls.findIndex((args) => args[0] === "activate-prod-boundary"),
    );
    expect(
      calls.some(
        (args) =>
          args.slice(0, 2).join(" ") === "iam simulate-custom-policy" &&
          args.includes("lambda:UpdateFunctionCode"),
      ),
    ).toBe(true);
    for (const action of [
      "iam:CreateRole",
      "iam:PutRolePolicy",
      "iam:DeleteRolePermissionsBoundary",
      "iam:PassRole",
    ]) {
      expect(
        calls.some(
          (args) =>
            args.slice(0, 2).join(" ") === "iam simulate-custom-policy" &&
            args.includes(action),
        ),
      ).toBe(true);
    }
    expect(
      calls.some((args) => argument(args, "--marker") === "attached-2"),
    ).toBe(true);
    expect(calls.some((args) => argument(args, "--marker") === "roles-2")).toBe(
      true,
    );
    expect(
      calls.some(
        (args) =>
          args.slice(0, 2).join(" ") === "iam simulate-custom-policy" &&
          args.includes("iam:CreatePolicyVersion"),
      ),
    ).toBe(true);
    expect(
      calls.some(
        (args) =>
          args.slice(0, 2).join(" ") === "iam simulate-custom-policy" &&
          args.includes("cloudformation:UpdateStack") &&
          args.some((value) =>
            value.includes("stack/ecr-registry-scanning-mem9-on-aws/"),
          ),
      ),
    ).toBe(true);
    expect(
      calls.some(
        (args) =>
          args.slice(0, 2).join(" ") === "iam simulate-custom-policy" &&
          args.includes(
            "ContextKeyName=iam:PassedToService," +
              "ContextKeyValues=ecs-tasks.amazonaws.com," +
              "ContextKeyType=string",
          ),
      ),
    ).toBe(true);
    expect(calls.at(-1)).toEqual(["resume-deployments"]);
    const describedTaskDefinitions = calls
      .filter(
        (args) => args.slice(0, 2).join(" ") === "ecs describe-task-definition",
      )
      .map((args) => argument(args, "--task-definition"))
      .sort();
    expect([...new Set(describedTaskDefinitions)]).toEqual(
      Object.values(productionTaskDefinitions).sort(),
    );
    expect(describedTaskDefinitions).toHaveLength(9);
    const productionPreflightCalls = calls.filter((args) =>
      ["ssm", "ecs"].includes(args[0]),
    );
    expect(productionPreflightCalls.length).toBeGreaterThan(0);
    for (const args of productionPreflightCalls) {
      expect(argument(args, "--region")).toBe("ap-northeast-1");
    }
  });

  it("reinstalls quarantine when deletion read-back cannot be verified", async () => {
    const calls = [];
    const state = { quarantine: quarantinePolicyDocument() };
    const invokeAws = (args) => {
      calls.push(args);
      switch (args.slice(0, 2).join(" ")) {
        case "iam delete-role-policy":
          state.quarantine = undefined;
          return {};
        case "iam list-role-policies":
          throw new Error("transient read failure");
        case "iam put-role-policy":
          state.quarantine = JSON.parse(argument(args, "--policy-document"));
          return {};
        case "iam get-role-policy":
          return { PolicyDocument: state.quarantine };
        case "iam simulate-custom-policy":
          return {
            EvaluationResults: optionValues(args, "--action-names").map(
              (action) => ({
                EvalActionName: action,
                EvalDecision: "explicitDeny",
              }),
            ),
          };
        default:
          throw new Error("unexpected AWS command");
      }
    };
    const adapter = createAwsCliAdapter({
      consistencyAttempts: 1,
      identity: { accountId, partition },
      invokeAws,
      sleep: async () => {},
    });

    await expect(
      adapter.deleteQuarantine({
        roleName: "github-actions-mem9-on-aws",
        policyName: QUARANTINE_POLICY_NAME,
      }),
    ).rejects.toThrow(/removal was not observed/u);
    expect(verifyQuarantinePolicy(state.quarantine)).toBe(true);
    expect(
      calls.findIndex(
        (args) => args.slice(0, 2).join(" ") === "iam put-role-policy",
      ),
    ).toBeGreaterThan(
      calls.findIndex(
        (args) => args.slice(0, 2).join(" ") === "iam delete-role-policy",
      ),
    );
    expect(
      calls.some(
        (args) => args.slice(0, 2).join(" ") === "iam get-role-policy",
      ),
    ).toBe(true);
    expect(
      calls.some(
        (args) =>
          args.slice(0, 2).join(" ") === "iam simulate-custom-policy",
      ),
    ).toBe(true);
  });

  it("reinstalls quarantine after a lost successful delete response", async () => {
    const calls = [];
    const state = { quarantine: quarantinePolicyDocument() };
    const invokeAws = (args) => {
      calls.push(args);
      switch (args.slice(0, 2).join(" ")) {
        case "iam delete-role-policy":
          state.quarantine = undefined;
          throw new Error("delete response was lost");
        case "iam list-role-policies":
          return {
            IsTruncated: false,
            PolicyNames: state.quarantine ? [QUARANTINE_POLICY_NAME] : [],
          };
        case "iam put-role-policy":
          state.quarantine = JSON.parse(argument(args, "--policy-document"));
          return {};
        case "iam get-role-policy":
          return { PolicyDocument: state.quarantine };
        case "iam simulate-custom-policy":
          return {
            EvaluationResults: optionValues(args, "--action-names").map(
              (action) => ({
                EvalActionName: action,
                EvalDecision: "explicitDeny",
              }),
            ),
          };
        default:
          throw new Error("unexpected AWS command");
      }
    };
    const adapter = createAwsCliAdapter({
      consistencyAttempts: 1,
      identity: { accountId, partition },
      invokeAws,
      sleep: async () => {},
    });

    await expect(
      adapter.deleteQuarantine({
        roleName: "github-actions-mem9-on-aws",
        policyName: QUARANTINE_POLICY_NAME,
      }),
    ).rejects.toThrow(/removal was not observed/u);
    expect(verifyQuarantinePolicy(state.quarantine)).toBe(true);
    expect(calls.map((args) => args.slice(0, 2).join(" "))).toEqual(
      expect.arrayContaining([
        "iam delete-role-policy",
        "iam put-role-policy",
        "iam get-role-policy",
        "iam simulate-custom-policy",
      ]),
    );
    expect(
      calls.some(
        (args) => args.slice(0, 2).join(" ") === "iam list-role-policies",
      ),
    ).toBe(false);
  });

  it("skips stale absence retries after an interrupted quarantine delete", async () => {
    const controller = new AbortController();
    const calls = [];
    const sleeps = [];
    let quarantine = quarantinePolicyDocument();
    const invokeAws = (args, options) => {
      const command = args.slice(0, 2).join(" ");
      calls.push({ command, signal: options.signal });
      switch (command) {
        case "iam delete-role-policy": {
          quarantine = undefined;
          const error = new Error("rollout interrupted by SIGTERM");
          error.code = "EINTR";
          controller.abort(error);
          throw error;
        }
        case "iam put-role-policy":
          quarantine = JSON.parse(argument(args, "--policy-document"));
          return {};
        case "iam get-role-policy":
          return { PolicyDocument: quarantine };
        case "iam simulate-custom-policy":
          return {
            EvaluationResults: QUARANTINE_PROBE_ACTIONS.map((action) => ({
              EvalActionName: action,
              EvalDecision: "explicitDeny",
            })),
          };
        default:
          throw new Error("unexpected AWS command");
      }
    };
    const adapter = createAwsCliAdapter({
      consistencyAttempts: 10,
      deadlineAt: Date.now() + 30_000,
      identity: { accountId, partition },
      invokeAws,
      signal: controller.signal,
      sleep: async (milliseconds) => sleeps.push(milliseconds),
    });

    await expect(
      adapter.deleteQuarantine({
        roleName: DEPLOY_ROLE_NAME,
        policyName: QUARANTINE_POLICY_NAME,
      }),
    ).rejects.toThrow(/removal was not observed/u);
    expect(sleeps).toEqual([]);
    expect(verifyQuarantinePolicy(quarantine)).toBe(true);
    expect(calls.map(({ command }) => command)).toEqual([
      "iam delete-role-policy",
      "iam put-role-policy",
      "iam get-role-policy",
      "iam simulate-custom-policy",
      "iam get-role-policy",
    ]);
    for (const call of calls.slice(1)) {
      expect(call.signal).not.toBe(controller.signal);
      expect(call.signal.aborted).toBe(false);
    }
  });

  it("recovers quarantine after the operational deadline expires during delete", async () => {
    const calls = [];
    const mainSignal = new AbortController().signal;
    const deadlineAt = Date.now() + 500;
    let quarantine = quarantinePolicyDocument();
    const invokeAws = async (args, options) => {
      const command = args.slice(0, 2).join(" ");
      calls.push({ command, options, timestamp: Date.now() });
      switch (command) {
        case "iam delete-role-policy":
          quarantine = undefined;
          await new Promise((resolvePromise) =>
            setTimeout(resolvePromise, 600),
          );
          throw new Error("delete response was lost");
        case "iam list-role-policies":
          return {
            IsTruncated: false,
            PolicyNames: quarantine ? [QUARANTINE_POLICY_NAME] : [],
          };
        case "iam put-role-policy":
          quarantine = JSON.parse(argument(args, "--policy-document"));
          return {};
        case "iam get-role-policy":
          return { PolicyDocument: quarantine };
        case "iam simulate-custom-policy":
          return {
            EvaluationResults: QUARANTINE_PROBE_ACTIONS.map((action) => ({
              EvalActionName: action,
              EvalDecision: "explicitDeny",
            })),
          };
        default:
          throw new Error("unexpected AWS command");
      }
    };
    const adapter = createAwsCliAdapter({
      consistencyAttempts: 1,
      deadlineAt,
      identity: { accountId, partition },
      invokeAws,
      signal: mainSignal,
      sleep: async () => {},
    });

    await expect(
      adapter.deleteQuarantine({
        roleName: DEPLOY_ROLE_NAME,
        policyName: QUARANTINE_POLICY_NAME,
      }),
    ).rejects.toThrow(/removal was not observed/u);
    expect(Date.now()).toBeGreaterThan(deadlineAt);
    expect(verifyQuarantinePolicy(quarantine)).toBe(true);
    const recoveryCalls = calls.filter(({ command }) =>
      [
        "iam put-role-policy",
        "iam get-role-policy",
        "iam simulate-custom-policy",
      ].includes(command),
    );
    expect(recoveryCalls).toHaveLength(4);
    for (const call of recoveryCalls) {
      expect(call.timestamp).toBeGreaterThan(deadlineAt);
      expect(call.options.signal).not.toBe(mainSignal);
      expect(call.options.signal.aborted).toBe(false);
      expect(call.options.timeoutMs).toBeLessThanOrEqual(5_000);
    }
  });

  it("clamps AWS and deploy commands to the shared rollout deadline", async () => {
    const commandTimeouts = [];
    const deployTimeouts = [];
    const deadlineAt = Date.now() + 5_000;
    const adapter = createAwsCliAdapter({
      consistencyAttempts: 1,
      deadlineAt,
      deployBoundary: (options) => {
        deployTimeouts.push(options.timeoutMs);
      },
      deployEnforcement: (options) => {
        deployTimeouts.push(options.timeoutMs);
      },
      identity: { accountId, partition },
      invokeAws: (args, options) => {
        commandTimeouts.push(options.timeoutMs);
        if (args.slice(0, 2).join(" ") === "iam get-role") {
          return { Role: {} };
        }
        throw new Error(`unexpected AWS command: ${args.join(" ")}`);
      },
      sleep: async () => {},
    });

    await adapter.getRole({ roleName: "mem9-on-aws-prod-role" });
    await adapter.deployBoundary();
    await adapter.deployPermanentEnforcement();

    expect(commandTimeouts).toHaveLength(1);
    expect(deployTimeouts).toHaveLength(2);
    for (const timeoutMs of [...commandTimeouts, ...deployTimeouts]) {
      expect(timeoutMs).toBeGreaterThan(0);
      expect(timeoutMs).toBeLessThanOrEqual(5_000);
    }
  });
});

describe("AWS CLI process boundary", () => {
  async function withMockAws(source, callback) {
    const directory = await mkdtemp(join(tmpdir(), "mem9-boundary-aws-cli-"));
    const awsPath = join(directory, "aws");
    const previousPath = process.env.PATH;
    await writeFile(awsPath, `#!/bin/bash\n${source}\n`);
    await chmod(awsPath, 0o700);
    process.env.PATH = `${directory}:/usr/bin:/bin`;
    try {
      return await callback();
    } finally {
      process.env.PATH = previousPath;
      await rm(directory, { force: true, recursive: true });
    }
  }

  it("parses valid JSON and accepts an empty successful response", async () => {
    await withMockAws("printf '%s\\n' '{\"ok\":true}'", async () => {
      await expect(
        invokeAwsCli(["sts", "get-caller-identity"]),
      ).resolves.toEqual({
        ok: true,
      });
    });
    await withMockAws("exit 0", async () => {
      await expect(
        invokeAwsCli(["iam", "delete-role-policy"]),
      ).resolves.toEqual({});
    });
  });

  it("reserves both termination grace periods before the deadline", () => {
    expect(
      remainingCommandTimeout({
        deadlineAt: 1_000,
        killGraceMs: 100,
        maximumMs: 5_000,
        now: () => 0,
      }),
    ).toBe(800);
  });

  it("terminates an AWS CLI process that exceeds its timeout", async () => {
    await withMockAws("sleep 1", async () => {
      await expect(
        invokeAwsCli(["sts", "get-caller-identity"], { timeoutMs: 20 }),
      ).rejects.toThrow(/subprocess exceeded/u);
    });
  });

  it("terminates descendants in the timed-out subprocess group", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mem9-boundary-process-"));
    const pidPath = join(directory, "descendant.pid");
    let descendantPid;
    try {
      await expect(
        runBoundedCommand(
          "bash",
          ["-c", 'sleep 30 & printf "%s" "$!" > "$DESCENDANT_PID_PATH"; wait'],
          {
            env: {
              ...process.env,
              DESCENDANT_PID_PATH: pidPath,
            },
            killGraceMs: 100,
            timeoutMs: 500,
          },
        ),
      ).rejects.toThrow(/subprocess exceeded/u);
      descendantPid = Number(readFileSync(pidPath, "utf8"));
      expect(Number.isInteger(descendantPid)).toBe(true);

      let alive = true;
      for (let attempt = 0; attempt < 40 && alive; attempt += 1) {
        try {
          process.kill(descendantPid, 0);
          await new Promise((resolvePromise) => setTimeout(resolvePromise, 25));
        } catch (error) {
          if (error?.code !== "ESRCH") throw error;
          alive = false;
        }
      }
      expect(alive).toBe(false);
    } finally {
      if (Number.isInteger(descendantPid)) {
        try {
          process.kill(descendantPid, "SIGKILL");
        } catch (error) {
          if (error?.code !== "ESRCH") throw error;
        }
      }
      await rm(directory, { force: true, recursive: true });
    }
  });

  it("force-kills a TERM-resistant descendant after its leader exits", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mem9-boundary-orphan-"));
    const pidPath = join(directory, "descendant.pid");
    let descendantPid;
    try {
      const source = [
        'const { spawn } = require("node:child_process");',
        'const { writeFileSync } = require("node:fs");',
        'process.on("SIGTERM", () => process.exit(0));',
        'const child = spawn("bash",',
        '  ["-c", "trap \\"\\" TERM; exec sleep 30"],',
        '  { stdio: "ignore" });',
        "writeFileSync(process.env.DESCENDANT_PID_PATH, String(child.pid));",
        "setInterval(() => {}, 1000);",
      ].join("\n");
      await expect(
        runBoundedCommand(process.execPath, ["-e", source], {
          env: {
            ...process.env,
            DESCENDANT_PID_PATH: pidPath,
          },
          killGraceMs: 100,
          timeoutMs: 500,
        }),
      ).rejects.toThrow(/subprocess exceeded/u);
      descendantPid = Number(readFileSync(pidPath, "utf8"));
      expect(Number.isInteger(descendantPid)).toBe(true);

      let alive = true;
      for (let attempt = 0; attempt < 40 && alive; attempt += 1) {
        try {
          process.kill(descendantPid, 0);
          await new Promise((resolvePromise) => setTimeout(resolvePromise, 25));
        } catch (error) {
          if (error?.code !== "ESRCH") throw error;
          alive = false;
        }
      }
      expect(alive).toBe(false);
    } finally {
      if (Number.isInteger(descendantPid)) {
        try {
          process.kill(descendantPid, "SIGKILL");
        } catch (error) {
          if (error?.code !== "ESRCH") throw error;
        }
      }
      await rm(directory, { force: true, recursive: true });
    }
  });

  it("terminates descendants when combined output exceeds its limit", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mem9-boundary-output-"));
    const pidPath = join(directory, "descendant.pid");
    let descendantPid;
    try {
      const source = [
        'const { spawn } = require("node:child_process");',
        'const { writeFileSync } = require("node:fs");',
        "const child = spawn(process.execPath,",
        '  ["-e", "setInterval(() => {}, 1000)"],',
        '  { stdio: "ignore" });',
        "writeFileSync(process.env.DESCENDANT_PID_PATH, String(child.pid));",
        'process.stdout.write("x".repeat(64 * 1024));',
        "setInterval(() => {}, 1000);",
      ].join("\n");
      const promise = runBoundedCommand(process.execPath, ["-e", source], {
        env: {
          ...process.env,
          DESCENDANT_PID_PATH: pidPath,
        },
        killGraceMs: 100,
        maxBufferBytes: 32,
        timeoutMs: 5_000,
      });
      await expect(promise).rejects.toMatchObject({ code: "ENOBUFS" });
      descendantPid = Number(readFileSync(pidPath, "utf8"));
      expect(Number.isInteger(descendantPid)).toBe(true);

      let alive = true;
      for (let attempt = 0; attempt < 40 && alive; attempt += 1) {
        try {
          process.kill(descendantPid, 0);
          await new Promise((resolvePromise) => setTimeout(resolvePromise, 25));
        } catch (error) {
          if (error?.code !== "ESRCH") throw error;
          alive = false;
        }
      }
      expect(alive).toBe(false);
    } finally {
      if (Number.isInteger(descendantPid)) {
        try {
          process.kill(descendantPid, "SIGKILL");
        } catch (error) {
          if (error?.code !== "ESRCH") throw error;
        }
      }
      await rm(directory, { force: true, recursive: true });
    }
  });

  it.each([
    ["SIGINT", 130],
    ["SIGTERM", 143],
  ])(
    "awaits descendant shutdown when the CLI receives %s",
    async (signalName, expectedExitCode) => {
      const directory = await mkdtemp(join(tmpdir(), "mem9-boundary-signal-"));
      const childPath = join(directory, "signal-cli.mjs");
      const cleanupPath = join(directory, "cleanup");
      const pidPath = join(directory, "descendant.pid");
      const boundedModuleUrl = pathToFileURL(
        resolve(root, "scripts/lib/bounded-subprocess.mjs"),
      ).href;
      let child;
      let descendantPid;
      try {
        await writeFile(
          childPath,
          `
import { writeFileSync } from "node:fs";
import {
  installSubprocessSignalHandlers,
  runBoundedCommand,
} from ${JSON.stringify(boundedModuleUrl)};

const shutdown = installSubprocessSignalHandlers();
try {
  await runBoundedCommand(
    "bash",
    ["-c", 'sleep 30 & printf "%s" "$!" > "$DESCENDANT_PID_PATH"; wait'],
    {
      env: process.env,
      killGraceMs: 100,
      signal: shutdown.signal,
      timeoutMs: 30_000,
    },
  );
} catch (error) {
  if (error?.code !== "EINTR") throw error;
} finally {
  shutdown.dispose();
  writeFileSync(process.env.CLEANUP_PATH, "complete");
  process.exitCode = shutdown.exitCode ?? 1;
}
`,
          { mode: 0o600 },
        );
        child = spawn(process.execPath, [childPath], {
          env: {
            ...process.env,
            CLEANUP_PATH: cleanupPath,
            DESCENDANT_PID_PATH: pidPath,
          },
          stdio: ["ignore", "ignore", "pipe"],
        });
        let stderr = "";
        child.stderr.on("data", (chunk) => {
          stderr += chunk;
        });
        for (let attempt = 0; attempt < 100; attempt += 1) {
          try {
            descendantPid = Number(readFileSync(pidPath, "utf8"));
            break;
          } catch {
            await new Promise((resolvePromise) =>
              setTimeout(resolvePromise, 20),
            );
          }
        }
        expect(Number.isInteger(descendantPid)).toBe(true);
        child.kill(signalName);
        const result = await new Promise((resolvePromise, rejectPromise) => {
          const timer = setTimeout(
            () => rejectPromise(new Error("signal-aware CLI did not exit")),
            5_000,
          );
          child.once("error", rejectPromise);
          child.once("close", (status, signal) => {
            clearTimeout(timer);
            resolvePromise({ signal, status });
          });
        });
        expect(result, stderr).toEqual({
          signal: null,
          status: expectedExitCode,
        });
        expect(readFileSync(cleanupPath, "utf8")).toBe("complete");

        let alive = true;
        for (let attempt = 0; attempt < 40 && alive; attempt += 1) {
          try {
            process.kill(descendantPid, 0);
            await new Promise((resolvePromise) =>
              setTimeout(resolvePromise, 25),
            );
          } catch (error) {
            if (error?.code !== "ESRCH") throw error;
            alive = false;
          }
        }
        expect(alive).toBe(false);
      } finally {
        if (child?.exitCode === null && child.signalCode === null) {
          child.kill("SIGKILL");
        }
        if (Number.isInteger(descendantPid)) {
          try {
            process.kill(descendantPid, "SIGKILL");
          } catch (error) {
            if (error?.code !== "ESRCH") throw error;
          }
        }
        await rm(directory, { force: true, recursive: true });
      }
    },
  );

  it.each([
    ["SIGINT", 130],
    ["SIGTERM", 143],
  ])(
    "restores quarantine with a fresh command context after %s",
    async (signalName, expectedExitCode) => {
      const directory = await mkdtemp(
        join(tmpdir(), "mem9-boundary-recovery-"),
      );
      const awsPath = join(directory, "aws");
      const callsPath = join(directory, "calls");
      const childPath = join(directory, "signal-recovery.mjs");
      const deleteStartedPath = join(directory, "delete-started");
      const resultPath = join(directory, "result");
      const statePath = join(directory, "quarantine.json");
      const awsModuleUrl = pathToFileURL(
        resolve(root, "scripts/lib/workload-permissions-boundary-aws.mjs"),
      ).href;
      const boundaryModuleUrl = pathToFileURL(
        resolve(root, "scripts/lib/workload-permissions-boundary.mjs"),
      ).href;
      const boundedModuleUrl = pathToFileURL(
        resolve(root, "scripts/lib/bounded-subprocess.mjs"),
      ).href;
      let child;
      try {
        await writeFile(
          awsPath,
          `#!/usr/bin/env bash
set -euo pipefail

command_name="$1 $2"
printf '%s\\n' "$command_name" >> "$MOCK_CALLS_PATH"
shift 2

case "$command_name" in
  "iam delete-role-policy")
    rm -f "$MOCK_STATE_PATH"
    : > "$MOCK_DELETE_STARTED_PATH"
    trap 'exit 143' TERM
    sleep 30
    printf '{}\\n'
    ;;
  "iam list-role-policies")
    if [[ -f "$MOCK_STATE_PATH" ]]; then
      printf '{"IsTruncated":false,"PolicyNames":["%s"]}\\n' "$MOCK_POLICY_NAME"
    else
      printf '{"IsTruncated":false,"PolicyNames":[]}\\n'
    fi
    ;;
  "iam put-role-policy")
    policy_document=""
    while (($# > 0)); do
      if [[ "$1" == "--policy-document" ]]; then
        policy_document="$2"
        break
      fi
      shift
    done
    [[ -n "$policy_document" ]]
    printf '%s' "$policy_document" > "$MOCK_STATE_PATH"
    printf '{}\\n'
    ;;
  "iam get-role-policy")
    printf '{"PolicyDocument":'
    cat "$MOCK_STATE_PATH"
    printf '}\\n'
    ;;
  "iam simulate-custom-policy")
    actions=()
    reading_actions=false
    for argument in "$@"; do
      if [[ "$argument" == "--action-names" ]]; then
        reading_actions=true
      elif [[ "$reading_actions" == true && "$argument" == --* ]]; then
        break
      elif [[ "$reading_actions" == true ]]; then
        actions+=("$argument")
      fi
    done
    printf '{"EvaluationResults":['
    separator=""
    for action in "\${actions[@]}"; do
      printf '%s{"EvalActionName":"%s","EvalDecision":"explicitDeny"}' \
        "$separator" "$action"
      separator=","
    done
    printf ']}\\n'
    ;;
  *)
    exit 64
    ;;
esac
`,
          { mode: 0o700 },
        );
        await writeFile(callsPath, "");
        await writeFile(statePath, JSON.stringify(quarantinePolicyDocument()), {
          mode: 0o600,
        });
        await writeFile(
          childPath,
          `
import { writeFileSync } from "node:fs";
import {
  createAwsCliAdapter,
  invokeAwsCli,
} from ${JSON.stringify(awsModuleUrl)};
import {
  DEPLOY_ROLE_NAME,
  QUARANTINE_POLICY_NAME,
} from ${JSON.stringify(boundaryModuleUrl)};
import {
  installSubprocessSignalHandlers,
} from ${JSON.stringify(boundedModuleUrl)};

const shutdown = installSubprocessSignalHandlers();
let outcome = "unexpected success";
try {
  const adapter = createAwsCliAdapter({
    consistencyAttempts: 10,
    deadlineAt: Date.now() + 60_000,
    identity: { accountId: "123456789012", partition: "aws" },
    invokeAws: invokeAwsCli,
    signal: shutdown.signal,
  });
  await adapter.deleteQuarantine({
    roleName: DEPLOY_ROLE_NAME,
    policyName: QUARANTINE_POLICY_NAME,
  });
} catch (error) {
  outcome = error?.message ?? "unknown failure";
} finally {
  shutdown.dispose();
  writeFileSync(process.env.MOCK_RESULT_PATH, outcome);
  process.exitCode = shutdown.exitCode ?? 1;
}
`,
          { mode: 0o600 },
        );
        child = spawn(process.execPath, [childPath], {
          env: {
            ...process.env,
            MOCK_CALLS_PATH: callsPath,
            MOCK_DELETE_STARTED_PATH: deleteStartedPath,
            MOCK_POLICY_NAME: QUARANTINE_POLICY_NAME,
            MOCK_RESULT_PATH: resultPath,
            MOCK_STATE_PATH: statePath,
            PATH: `${directory}:${process.env.PATH}`,
          },
          stdio: ["ignore", "ignore", "pipe"],
        });
        let stderr = "";
        child.stderr.on("data", (chunk) => {
          stderr += chunk;
        });
        let deleteStarted = false;
        for (let attempt = 0; attempt < 100; attempt += 1) {
          try {
            readFileSync(deleteStartedPath);
            deleteStarted = true;
            break;
          } catch {
            await new Promise((resolvePromise) =>
              setTimeout(resolvePromise, 20),
            );
          }
        }
        expect(deleteStarted).toBe(true);
        child.kill(signalName);
        const result = await new Promise((resolvePromise, rejectPromise) => {
          const timer = setTimeout(
            () => rejectPromise(new Error("signal recovery CLI did not exit")),
            10_000,
          );
          child.once("error", rejectPromise);
          child.once("close", (status, signal) => {
            clearTimeout(timer);
            resolvePromise({ signal, status });
          });
        });
        expect(result, stderr).toEqual({
          signal: null,
          status: expectedExitCode,
        });
        expect(readFileSync(resultPath, "utf8")).toMatch(
          /removal was not observed/u,
        );
        expect(
          verifyQuarantinePolicy(JSON.parse(readFileSync(statePath, "utf8"))),
        ).toBe(true);
        expect(readFileSync(callsPath, "utf8").trim().split("\n")).toEqual([
          "iam delete-role-policy",
          "iam put-role-policy",
          "iam get-role-policy",
          "iam simulate-custom-policy",
          "iam get-role-policy",
        ]);
      } finally {
        if (child?.exitCode === null && child.signalCode === null) {
          child.kill("SIGKILL");
        }
        await rm(directory, { force: true, recursive: true });
      }
    },
  );

  it.each([
    ["nonzero exit", "exit 7", /AWS command failed/u],
    ["invalid JSON", "printf 'not-json'", /returned invalid JSON/u],
  ])("rejects a mocked AWS CLI %s", async (_name, source, expected) => {
    await withMockAws(source, async () => {
      await expect(invokeAwsCli(["iam", "get-role"])).rejects.toThrow(expected);
    });
  });

  it("rejects a missing AWS executable", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mem9-boundary-no-aws-"));
    const previousPath = process.env.PATH;
    process.env.PATH = directory;
    try {
      await expect(
        invokeAwsCli(["sts", "get-caller-identity"]),
      ).rejects.toThrow();
    } finally {
      process.env.PATH = previousPath;
      await rm(directory, { force: true, recursive: true });
    }
  });
});

describe("GitHub maintenance state transitions", () => {
  function maintenanceHarness({
    abortController,
    deadlineAt,
    defaultBranch = "main",
    defaultHead = reviewedCommit,
    failDisable,
    failEnable,
    failUnpauseAfterWrite = false,
    failPauseRestore = false,
    nonterminalRuns = {},
    observedCommandOptions = [],
    readbackOverrides = {},
    signal,
    workflowBlobs = Object.fromEntries(reviewedWorkflowBlobs),
    workflowStates = {
      "infra-ci.yml": "disabled_manually",
      "reconcile-previews.yml": "disabled_manually",
    },
  } = {}) {
    const calls = [];
    const variables = new Map([
      ["DEPLOYMENT_MAINTENANCE_PAUSED", "true"],
      ["WORKLOAD_BOUNDARY_PROD_ENABLED", "false"],
    ]);
    const states = new Map(Object.entries(workflowStates));
    const queuedReadbacks = new Map(
      Object.entries(readbackOverrides).map(([name, values]) => [
        name,
        [...values],
      ]),
    );
    const runGh = (args, _label, commandOptions) => {
      calls.push([...args]);
      observedCommandOptions.push(commandOptions);
      if (args[0] === "variable" && args[1] === "set") {
        if (
          failPauseRestore &&
          args[2] === "DEPLOYMENT_MAINTENANCE_PAUSED" &&
          argument(args, "--body") === "true"
        ) {
          throw new Error("deployment maintenance pause restore failed");
        }
        variables.set(args[2], argument(args, "--body"));
        if (
          failUnpauseAfterWrite &&
          args[2] === "DEPLOYMENT_MAINTENANCE_PAUSED" &&
          argument(args, "--body") === "false"
        ) {
          abortController?.abort();
          throw new Error("deployment maintenance resume interrupted");
        }
        return "";
      }
      if (args[0] === "variable" && args[1] === "get") {
        const overrides = queuedReadbacks.get(args[2]);
        if (overrides?.length > 0) return overrides.shift();
        return variables.get(args[2]) ?? "";
      }
      if (args[0] === "api") {
        if (args[1] === `repos/zxkane/mem9-on-aws`) {
          return defaultBranch;
        }
        if (args[1] === `repos/zxkane/mem9-on-aws/commits/${defaultBranch}`) {
          return defaultHead;
        }
        if (args[1] === "--method") {
          const workflow = args[3].split("/").at(-1);
          return workflowBlobs[workflow];
        }
        const workflow = args[1].split("/").at(-1);
        return states.get(workflow);
      }
      if (args[0] === "run" && args[1] === "list") {
        const key = `${argument(args, "--workflow")}:${argument(args, "--status")}`;
        return String(nonterminalRuns[key] ?? 0);
      }
      if (args[0] === "workflow" && args[1] === "enable") {
        const workflow = args[2];
        if (workflow === failEnable) {
          throw new Error("deployment workflow enable failed");
        }
        states.set(workflow, "active");
        return "";
      }
      if (args[0] === "workflow" && args[1] === "disable") {
        if (args[2] === failDisable) {
          throw new Error("deployment workflow disable rollback failed");
        }
        states.set(args[2], "disabled_manually");
        return "";
      }
      throw new Error(`unexpected gh command: ${args.join(" ")}`);
    };
    return {
      calls,
      controller: createGithubMaintenanceController({
        deadlineAt,
        runGh,
        signal,
      }),
      states,
      variables,
    };
  }

  it("activates the prod boundary while workflows remain paused and disabled", async () => {
    const harness = maintenanceHarness();
    await harness.controller.activateProductionBoundary();
    expect(harness.variables.get("WORKLOAD_BOUNDARY_PROD_ENABLED")).toBe(
      "true",
    );
    expect(harness.variables.get("DEPLOYMENT_MAINTENANCE_PAUSED")).toBe("true");
    expect([...harness.states.values()]).toEqual([
      "disabled_manually",
      "disabled_manually",
    ]);
    expect(
      harness.calls.some(
        (args) => args[0] === "workflow" && args[1] === "enable",
      ),
    ).toBe(false);
  });

  it("clamps GitHub commands to the shared rollout deadline", async () => {
    const timeouts = [];
    const signal = new AbortController().signal;
    const controller = createGithubMaintenanceController({
      deadlineAt: Date.now() + 5_000,
      runGh: (args, _label, options) => {
        expect(options.signal).toBe(signal);
        timeouts.push(options.timeoutMs);
        return args[0] === "variable" && args[1] === "get" ? "true" : "";
      },
      signal,
    });

    await controller.activateProductionBoundary();

    expect(timeouts).toHaveLength(2);
    for (const timeoutMs of timeouts) {
      expect(timeoutMs).toBeGreaterThan(0);
      expect(timeoutMs).toBeLessThanOrEqual(5_000);
    }
  });

  it("revalidates every GitHub maintenance interlock", async () => {
    const harness = maintenanceHarness();
    await harness.controller.verifyFinalInterlock({ reviewedCommit });
    const runReads = harness.calls.filter(
      (args) => args[0] === "run" && args[1] === "list",
    );
    expect(runReads).toHaveLength(
      DEPLOYMENT_WORKFLOWS.length * NONTERMINAL_WORKFLOW_STATUSES.length,
    );
    for (const workflow of DEPLOYMENT_WORKFLOWS) {
      for (const status of NONTERMINAL_WORKFLOW_STATUSES) {
        expect(runReads).toContainEqual(
          expect.arrayContaining([
            "--workflow",
            workflow,
            "--status",
            status,
            "--all",
          ]),
        );
      }
    }
  });

  it("rejects a changed default-branch head during final revalidation", async () => {
    const harness = maintenanceHarness({
      defaultHead: "0000000000000000000000000000000000000000",
    });
    await expect(
      harness.controller.verifyFinalInterlock({ reviewedCommit }),
    ).rejects.toThrow(/default branch changed/u);
  });

  it.each(DEPLOYMENT_WORKFLOWS)(
    "rejects a changed reviewed blob for %s during final revalidation",
    async (workflow) => {
      const harness = maintenanceHarness({
        workflowBlobs: {
          ...Object.fromEntries(reviewedWorkflowBlobs),
          [workflow]: "0000000000000000000000000000000000000000",
        },
      });
      await expect(
        harness.controller.verifyFinalInterlock({ reviewedCommit }),
      ).rejects.toThrow(/reviewed workflow changed/u);
    },
  );

  it("rejects a cleared maintenance pause during final revalidation", async () => {
    const harness = maintenanceHarness();
    harness.variables.set("DEPLOYMENT_MAINTENANCE_PAUSED", "false");
    await expect(
      harness.controller.verifyFinalInterlock({ reviewedCommit }),
    ).rejects.toThrow(/maintenance pause changed/u);
  });

  it.each(DEPLOYMENT_WORKFLOWS)(
    "rejects %s unless it remains manually disabled",
    async (workflow) => {
      const harness = maintenanceHarness({
        workflowStates: Object.fromEntries(
          DEPLOYMENT_WORKFLOWS.map((candidate) => [
            candidate,
            candidate === workflow ? "active" : "disabled_manually",
          ]),
        ),
      });
      await expect(
        harness.controller.verifyFinalInterlock({ reviewedCommit }),
      ).rejects.toThrow(/not manually disabled/u);
    },
  );

  it.each(NONTERMINAL_WORKFLOW_STATUSES)(
    "rejects a final %s deployment run",
    async (status) => {
      const workflow = DEPLOYMENT_WORKFLOWS[0];
      const harness = maintenanceHarness({
        nonterminalRuns: { [`${workflow}:${status}`]: 1 },
      });
      await expect(
        harness.controller.verifyFinalInterlock({ reviewedCommit }),
      ).rejects.toThrow(/became nonterminal/u);
    },
  );

  it("unpauses only after quarantine removal and verifies both workflows", async () => {
    const harness = maintenanceHarness();
    await harness.controller.resumeDeployments();
    expect(harness.variables.get("DEPLOYMENT_MAINTENANCE_PAUSED")).toBe(
      "false",
    );
    expect([...harness.states.values()]).toEqual(["active", "active"]);
    const unpause = harness.calls.findIndex(
      (args) =>
        args[0] === "variable" &&
        args[1] === "set" &&
        args[2] === "DEPLOYMENT_MAINTENANCE_PAUSED" &&
        argument(args, "--body") === "false",
    );
    const firstEnable = harness.calls.findIndex(
      (args) => args[0] === "workflow" && args[1] === "enable",
    );
    expect(unpause).toBeGreaterThanOrEqual(0);
    expect(unpause).toBeGreaterThan(firstEnable);
  });

  it("restores and verifies the deployment pause after a partial resume failure", async () => {
    const harness = maintenanceHarness({
      failEnable: "reconcile-previews.yml",
    });
    await expect(harness.controller.resumeDeployments()).rejects.toThrow(
      /workflow enable/u,
    );
    expect(harness.variables.get("DEPLOYMENT_MAINTENANCE_PAUSED")).toBe("true");
    expect([...harness.states.values()]).toEqual([
      "disabled_manually",
      "disabled_manually",
    ]);
    const pauseWrites = harness.calls.filter(
      (args) =>
        args[0] === "variable" &&
        args[1] === "set" &&
        args[2] === "DEPLOYMENT_MAINTENANCE_PAUSED",
    );
    expect(pauseWrites.map((args) => argument(args, "--body"))).toEqual([
      "true",
    ]);
  });

  it("uses a fresh recovery signal after the operational signal is aborted", async () => {
    const abortController = new AbortController();
    const observedCommandOptions = [];
    const harness = maintenanceHarness({
      abortController,
      deadlineAt: Date.now() + 5_000,
      failUnpauseAfterWrite: true,
      observedCommandOptions,
      signal: abortController.signal,
    });

    let failure;
    try {
      await harness.controller.resumeDeployments();
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(Error);
    expect(failure.deploymentPauseRestored).toBe(true);
    expect(failure.deploymentWorkflowsRestored).toBe(true);
    expect(harness.variables.get("DEPLOYMENT_MAINTENANCE_PAUSED")).toBe("true");
    expect([...harness.states.values()]).toEqual([
      "disabled_manually",
      "disabled_manually",
    ]);
    const recoveryOptions = observedCommandOptions.filter(
      ({ signal: commandSignal }) => commandSignal !== abortController.signal,
    );
    expect(recoveryOptions.length).toBeGreaterThan(0);
    for (const options of recoveryOptions) {
      expect(options.signal.aborted).toBe(false);
      expect(options.timeoutMs).toBeGreaterThan(0);
      expect(options.timeoutMs).toBeLessThanOrEqual(5_000);
    }
  });

  it("uses the hard-deadline reserve after the operational deadline expires", async () => {
    const observedCommandOptions = [];
    const harness = maintenanceHarness({
      deadlineAt: Date.now() - 1,
      observedCommandOptions,
    });

    let failure;
    try {
      await harness.controller.resumeDeployments();
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(Error);
    expect(failure.deploymentPauseRestored).toBe(true);
    expect(failure.deploymentWorkflowsRestored).toBe(true);
    expect(harness.variables.get("DEPLOYMENT_MAINTENANCE_PAUSED")).toBe("true");
    expect(observedCommandOptions).toHaveLength(2);
    for (const options of observedCommandOptions) {
      expect(options.signal.aborted).toBe(false);
      expect(options.timeoutMs).toBeGreaterThan(0);
      expect(options.timeoutMs).toBeLessThanOrEqual(5_000);
    }
  });

  it("rejects a stale production-activation read-back", async () => {
    const harness = maintenanceHarness({
      readbackOverrides: {
        WORKLOAD_BOUNDARY_PROD_ENABLED: ["false"],
      },
    });
    await expect(
      harness.controller.activateProductionBoundary(),
    ).rejects.toThrow(/activation read-back/u);
  });

  it("restores pause and workflow state after a stale unpause read-back", async () => {
    const harness = maintenanceHarness({
      readbackOverrides: {
        DEPLOYMENT_MAINTENANCE_PAUSED: ["true", "true"],
      },
    });
    let failure;
    try {
      await harness.controller.resumeDeployments();
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(Error);
    expect(failure.deploymentPauseRestored).toBe(true);
    expect(failure.deploymentWorkflowsRestored).toBe(true);
    expect(harness.variables.get("DEPLOYMENT_MAINTENANCE_PAUSED")).toBe("true");
    expect([...harness.states.values()]).toEqual([
      "disabled_manually",
      "disabled_manually",
    ]);
  });

  it("marks a stale maintenance-pause restoration read-back unsafe", async () => {
    const harness = maintenanceHarness({
      failEnable: "reconcile-previews.yml",
      readbackOverrides: {
        DEPLOYMENT_MAINTENANCE_PAUSED: ["false"],
      },
    });
    let failure;
    try {
      await harness.controller.resumeDeployments();
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(AggregateError);
    expect(failure.deploymentPauseRestored).toBe(false);
    expect([...harness.states.values()]).toEqual([
      "disabled_manually",
      "disabled_manually",
    ]);
  });

  it("marks a failed maintenance-pause restoration without claiming success", async () => {
    const harness = maintenanceHarness({
      failEnable: "reconcile-previews.yml",
      failPauseRestore: true,
    });
    let failure;
    try {
      await harness.controller.resumeDeployments();
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(AggregateError);
    expect(failure.deploymentPauseRestored).toBe(false);
    failure.quarantineRemoved = true;
    const output = redactedRolloutFailure(failure);
    expect(output).toContain("pause restoration both failed");
    expect(output).not.toContain("pause was restored");
  });

  it("reports a failed workflow rollback independently from pause restoration", async () => {
    const harness = maintenanceHarness({
      failDisable: "infra-ci.yml",
      failEnable: "reconcile-previews.yml",
    });
    let failure;
    try {
      await harness.controller.resumeDeployments();
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(AggregateError);
    expect(failure.deploymentPauseRestored).toBe(true);
    expect(failure.deploymentWorkflowsRestored).toBe(false);
    expect(harness.variables.get("DEPLOYMENT_MAINTENANCE_PAUSED")).toBe("true");
    expect([...harness.states.values()]).toEqual([
      "active",
      "disabled_manually",
    ]);
    failure.quarantineRemoved = true;
    const output = redactedRolloutFailure(failure);
    expect(output).toContain("workflow rollback failed");
    expect(output).toContain("disable every deployment workflow");
    expect(output).not.toContain("after resume failed; re-run");
  });

  it("is idempotent when the variables and workflows already have final values", async () => {
    const harness = maintenanceHarness({
      workflowStates: {
        "infra-ci.yml": "active",
        "reconcile-previews.yml": "active",
      },
    });
    harness.variables.set("WORKLOAD_BOUNDARY_PROD_ENABLED", "true");
    harness.variables.set("DEPLOYMENT_MAINTENANCE_PAUSED", "false");
    await harness.controller.activateProductionBoundary();
    await harness.controller.resumeDeployments();
    expect([...harness.states.values()]).toEqual(["active", "active"]);
    expect(
      harness.calls.some(
        (args) => args[0] === "workflow" && args[1] === "enable",
      ),
    ).toBe(false);
  });
});

describe("operator entry point", () => {
  it("wires resolved identity and injected adapters through executeBoundaryRollout", async () => {
    const calls = [];
    const adapter = { name: "injected-adapter" };
    const deadlineAt = Date.now() + 60_000;
    const signal = new AbortController().signal;
    const result = await executeBoundaryRollout({
      activateProduction: () => calls.push("activate"),
      consistencyAttempts: 3,
      createAdapter: (options) => {
        calls.push(["create-adapter", options]);
        return adapter;
      },
      deployBoundary: () => calls.push("deploy-boundary"),
      deployEnforcement: () => calls.push("deploy-enforcement"),
      deadlineAt,
      invokeAws: (args, options) => {
        expect(args).toEqual(["sts", "get-caller-identity"]);
        expect(options.timeoutMs).toBeGreaterThan(0);
        expect(options.timeoutMs).toBeLessThanOrEqual(60_000);
        expect(options.signal).toBe(signal);
        return {
          Account: accountId,
          Arn: `arn:${partition}:sts::${accountId}:assumed-role/operator/session`,
        };
      },
      reviewedCommit,
      resumeDeploymentWorkflows: () => calls.push("resume"),
      signal,
      rollout: (receivedAdapter, options) => {
        calls.push(["rollout", receivedAdapter, options]);
        return { status: "complete", verifiedRoleCount: 3 };
      },
      sleep: async () => {},
      verifyFinalGithubInterlock: () => calls.push("final-github"),
    });
    expect(result).toEqual({ status: "complete", verifiedRoleCount: 3 });
    const createOptions = calls.find(
      ([label]) => label === "create-adapter",
    )[1];
    expect(createOptions).toMatchObject({
      consistencyAttempts: 3,
      identity: { accountId, partition },
      signal,
    });
    expect(createOptions.deployBoundary).toBeTypeOf("function");
    expect(createOptions.deployEnforcement).toBeTypeOf("function");
    expect(createOptions.activateProductionBoundary).toBeTypeOf("function");
    expect(createOptions.verifyFinalGithubInterlock).toBeTypeOf("function");
    expect(createOptions.resumeDeployments).toBeTypeOf("function");
    expect(calls.find(([label]) => label === "rollout")).toEqual([
      "rollout",
      adapter,
      {
        accountId,
        boundaryArn,
        deployRoleName: "github-actions-mem9-on-aws",
        partition,
        reviewedCommit,
        resumeCommand: ROLLOUT_RESUME_COMMAND,
        deadlineAt,
      },
    ]);
  });

  it("parses one reviewed commit and the wrapper's remaining deadline", () => {
    const operationalDeadline = ROLLOUT_TIMEOUT_MS - ROLLOUT_SHUTDOWN_GRACE_MS;
    expect(
      parseRolloutArguments(
        [
          "--reviewed-commit",
          reviewedCommit,
          "--deadline-at",
          String(operationalDeadline),
        ],
        1,
      ),
    ).toEqual({ deadlineAt: operationalDeadline, reviewedCommit });
  });

  it.each([
    ["missing deadline", ["--reviewed-commit", reviewedCommit]],
    [
      "expired deadline",
      ["--reviewed-commit", reviewedCommit, "--deadline-at", "1000"],
    ],
    [
      "reset deadline",
      [
        "--reviewed-commit",
        reviewedCommit,
        "--deadline-at",
        String(ROLLOUT_TIMEOUT_MS - ROLLOUT_SHUTDOWN_GRACE_MS + 1_001),
      ],
    ],
  ])("rejects a %s from the guarded wrapper", (_name, args) => {
    expect(() => parseRolloutArguments(args, 1_000)).toThrow(
      /deadline|expected/u,
    );
  });

  it("does not provide live side-effect defaults from the reusable module", async () => {
    await expect(executeBoundaryRollout()).rejects.toThrow(
      /side-effect dependencies must be injected/u,
    );
    await expect(runBoundaryRolloutCli()).rejects.toThrow(
      /executor must be injected/u,
    );
  });

  it("prints bounded success through the CLI entry point", async () => {
    let stdout = "";
    let stderr = "";
    let failed = false;
    await runBoundaryRolloutCli({
      execute: async () => ({ status: "complete", verifiedRoleCount: 4 }),
      setFailureExitCode: () => {
        failed = true;
      },
      stderr: { write: (value) => (stderr += value) },
      stdout: { write: (value) => (stdout += value) },
    });
    expect(stdout).toContain("Bounded roles verified: 4");
    expect(stderr).toBe("");
    expect(failed).toBe(false);
  });

  it("prints only redacted recovery guidance on CLI failure", async () => {
    let stdout = "";
    let stderr = "";
    let failed = false;
    const failure = new Error("sensitive internal failure");
    failure.quarantineAttempted = true;
    failure.resumeCommand = "safe-resume-command";
    await runBoundaryRolloutCli({
      execute: async () => {
        throw failure;
      },
      setFailureExitCode: () => {
        failed = true;
      },
      stderr: { write: (value) => (stderr += value) },
      stdout: { write: (value) => (stdout += value) },
    });
    expect(stdout).toBe("");
    expect(stderr).toContain("Quarantine was attempted");
    expect(stderr).toContain("Resume: safe-resume-command");
    expect(stderr).not.toContain("sensitive internal failure");
    expect(failed).toBe(true);
  });

  it("requires maintenance acknowledgement before invoking Node or AWS", () => {
    const result = spawnSync("bash", [rolloutWrapperPath], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        WORKLOAD_BOUNDARY_MAINTENANCE_ACK: "",
        WORKLOAD_BOUNDARY_SKIP_DOTENV: "true",
      },
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain(
      "No boundary or IAM mutation was attempted",
    );
  });

  it("rejects a concurrent rollout before GitHub or AWS access", async () => {
    const lockPath = resolve(root, ".workload-boundary-rollout.local.lock");
    const holder = spawn(
      "bash",
      [
        "-c",
        'exec 8>"$ROLLOUT_LOCK"; flock -x 8; printf "ready\\n"; exec sleep 30',
      ],
      {
        env: { ...process.env, ROLLOUT_LOCK: lockPath },
        stdio: ["ignore", "pipe", "ignore"],
      },
    );
    holder.stdout.setEncoding("utf8");
    await new Promise((resolvePromise, rejectPromise) => {
      const timer = setTimeout(() => {
        rejectPromise(new Error("rollout lock holder did not start"));
      }, 5_000);
      holder.stdout.once("data", () => {
        clearTimeout(timer);
        resolvePromise();
      });
    });
    try {
      const { calls, result, resumeState } = await runRolloutGateMock();
      expect(result.status).toBe(2);
      expect(result.stderr).toContain("rollout is already active");
      expect(calls).toBe("");
      expect(resumeState).toBe("");
    } finally {
      holder.kill("SIGTERM");
      await new Promise((resolvePromise) => {
        holder.once("close", resolvePromise);
      });
    }
  });

  it("refuses to overwrite retained recovery state with an initial command", async () => {
    const retainedResumeState = [
      "AWS_PROFILE=retained-operator",
      `WORKLOAD_BOUNDARY_EXPECTED_ACCOUNT_ID=${accountId}`,
      `WORKLOAD_BOUNDARY_EXPECTED_PARTITION=${partition}`,
      "",
    ].join("\n");
    const { calls, result, resumeState } = await runRolloutGateMock({
      retainedResumeState,
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("use the printed Resume command");
    expect(calls).toBe("");
    expect(resumeState).toBe(retainedResumeState);
  });

  it.each(["infra-ci.yml", "reconcile-previews.yml"])(
    "refuses rollout while %s has any nonterminal run",
    async (activeWorkflow) => {
      const { calls, result } = await runRolloutGateMock({ activeWorkflow });
      expect(result.status).toBe(2);
      expect(result.stderr).toContain(
        "An AWS deployment workflow is queued or active",
      );
      expect(calls).toContain(`--workflow ${activeWorkflow}`);
      expect(calls).toContain("--status queued");
      expect(calls).not.toContain("node invoked");
    },
  );

  it("refuses rollout when a workflow starts between the two drain checks", async () => {
    const { calls, result } = await runRolloutGateMock({
      activeWorkflowAfterFirstDrain: "infra-ci.yml",
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain(
      "An AWS deployment workflow started during the drain",
    );
    expect(calls).not.toContain("node invoked");
  });

  it.each([
    ["false", false],
    ["", false],
    ["malformed", false],
    ["", true],
  ])(
    "refuses an unverified pause value %j (command failure: %s)",
    async (pauseValue, pauseCommandFails) => {
      const { calls, result } = await runRolloutGateMock({
        pauseCommandFails,
        pauseValue,
      });
      expect(result.status).toBe(2);
      expect(result.stderr).toContain("Set DEPLOYMENT_MAINTENANCE_PAUSED=true");
      expect(calls).not.toContain("node invoked");
    },
  );

  it("requires the gate-bearing revision on the default branch", async () => {
    const { calls, result } = await runRolloutGateMock({
      gateRevision: false,
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain(
      "Merge the exact reviewed maintenance-gate workflows",
    );
    expect(calls).not.toContain("variable get");
    expect(calls).not.toContain("node invoked");
  });

  it("requires the local checkout to equal the current default-branch commit", async () => {
    const { calls, result } = await runRolloutGateMock({
      headMatches: false,
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain(
      "Run the rollout from the exact current default-branch commit",
    );
    expect(calls).not.toContain("variable get");
    expect(calls).not.toContain("node invoked");
  });

  it("requires the reviewed repository origin before reading maintenance state", async () => {
    const { calls, result } = await runRolloutGateMock({
      originMatches: false,
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("Local repository identity");
    expect(calls).not.toContain("variable get");
    expect(calls).not.toContain("node invoked");
  });

  it.each([
    ["unstaged", { dirtyWorktree: true }],
    ["staged", { dirtyIndex: true }],
  ])(
    "rejects %s tracked changes before reading maintenance state",
    async (_name, options) => {
      const { calls, result } = await runRolloutGateMock(options);
      expect(result.status).toBe(2);
      expect(result.stderr).toContain(
        "Tracked files differ from the reviewed default-branch commit",
      );
      expect(calls).not.toContain("variable get");
      expect(calls).not.toContain("node invoked");
    },
  );

  it("rejects a caller-controlled repository override", async () => {
    const { calls, result } = await runRolloutGateMock({
      repositoryOverride: "other/repository",
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("repository identity");
    expect(calls).not.toContain("node invoked");
  });

  it("requires a completed exact-head push run", async () => {
    const { calls, result } = await runRolloutGateMock({
      headRunCompleted: false,
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("exact-head push CI run must complete");
    expect(calls).not.toContain("workflow disable");
    expect(calls).not.toContain("node invoked");
  });

  it("requires successful exact-head non-AWS validation", async () => {
    const { calls, result } = await runRolloutGateMock({
      headCiSucceeded: false,
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain(
      "exact-head non-AWS validation job must succeed",
    );
    expect(calls).not.toContain("workflow disable");
    expect(calls).not.toContain("node invoked");
  });

  it("starts rollout only after the merged gates, pause, and drain verify", async () => {
    const { calls, result } = await runRolloutGateMock();
    expect(result.status, result.stderr).toBe(0);
    expect(calls).toContain("api --method GET");
    expect(calls).toContain("git -C");
    expect(calls).toContain("--workflow infra-ci.yml");
    expect(calls).toContain("--workflow reconcile-previews.yml");
    expect(calls).toContain("Typecheck & Unit Tests");
    expect(calls).not.toContain("--status success");
    expect(calls).not.toContain("--status action_required");
    expect(calls).toContain("--all");
    expect(calls).toContain(
      "workflow disable infra-ci.yml --repo zxkane/mem9-on-aws",
    );
    expect(calls).toContain(
      "workflow disable reconcile-previews.yml --repo zxkane/mem9-on-aws",
    );
    expect(calls).toContain("node invoked");
    expect(calls).toContain("--deadline-at");
  });

  it("does not reset the deadline after slow successful GitHub gates", async () => {
    const { calls, result } = await runRolloutGateMock({
      clockStepMs: 600_000,
    });
    expect(result.status, result.stderr).toBe(2);
    expect(calls).toContain("repo view");
    expect(calls).not.toContain("node invoked");
  }, 10_000);

  it.each([
    ["SIGINT", 130],
    ["SIGTERM", 143],
  ])(
    "forwards %s from the wrapper, waits for child recovery, and preserves the exit code",
    async (signal, expectedStatus) => {
      const { calls, result, resumeState } = await runRolloutGateMock({
        interruptSignal: signal,
      });
      expect(result.status, result.stderr).toBe(expectedStatus);
      expect(calls).toContain(`node received ${signal}`);
      expect(resumeState).toContain(
        `WORKLOAD_BOUNDARY_EXPECTED_ACCOUNT_ID=${accountId}`,
      );
    },
    20_000,
  );

  it("bounds a hanging GitHub call after deployment workflows are disabled", async () => {
    const startedAt = Date.now();
    const { calls, result } = await runRolloutGateMock({
      hangAfterWorkflowDisable: true,
      timeout: "0.1s",
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain(
      "Could not disable every deployment workflow",
    );
    expect(calls).toContain(
      "workflow disable infra-ci.yml --repo zxkane/mem9-on-aws",
    );
    expect(calls).not.toContain("node invoked");
    expect(Date.now() - startedAt).toBeLessThan(3_000);
  });

  it("keeps the Node module import-only so the wrapper gates cannot be bypassed", () => {
    const result = spawnSync(process.execPath, [rolloutModulePath], {
      cwd: root,
      encoding: "utf8",
      env: { ...process.env, PATH: "/nonexistent" },
      timeout: 5_000,
    });
    expect(result.status).toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("");
  });

  it("refuses the live CLI without the verified shell-gate marker", () => {
    const result = spawnSync(process.execPath, [rolloutCliPath], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: "/nonexistent",
        WORKLOAD_BOUNDARY_GATES_VERIFIED: "",
      },
      timeout: 5_000,
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("guarded workload permissions-boundary");
  });

  it("preserves the command-scoped acknowledgement over .env defaults", async () => {
    const { calls, result } = await runRolloutGateMock({
      dotenvAck: "false",
    });
    expect(result.status).toBe(0);
    expect(calls).toContain("node invoked");
    expect(calls).toContain(`--reviewed-commit ${reviewedCommit}`);
  });

  it.each([
    [
      "custom environment file",
      { dotenvAck: "true", dotenvProfile: "custom-operator" },
      "custom-operator",
    ],
    [
      "ambient profile",
      { ambientProfile: "ambient-operator" },
      "ambient-operator",
    ],
  ])(
    "retains the effective AWS profile from the %s for recovery",
    async (_name, gateOptions, expectedProfile) => {
      const { calls, result, resumeState } = await runRolloutGateMock({
        ...gateOptions,
        nodeExit: 9,
      });
      expect(result.status).toBe(9);
      expect(calls).toContain(`node invoked profile=${expectedProfile}`);
      expect(resumeState).toContain(`AWS_PROFILE=${expectedProfile}`);
      expect(resumeState).toContain(
        `WORKLOAD_BOUNDARY_EXPECTED_ACCOUNT_ID=${accountId}`,
      );
      expect(resumeState).toContain(
        `WORKLOAD_BOUNDARY_EXPECTED_PARTITION=${partition}`,
      );
      expect(resumeState).not.toMatch(/(?:secret|token|key)=/iu);
    },
  );

  it("retains every downstream non-secret deployment selector for recovery", async () => {
    const { calls, result, resumeState } = await runRolloutGateMock({
      dotenvAck: "true",
      dotenvApplicationRegion: "eu-west-1",
      dotenvProfile: "custom-operator",
      dotenvProjectRegion: "eu-west-1",
      dotenvTemplateBucket: "reviewed-template-bucket",
      dotenvVpcId: "vpc-0abc1234",
      nodeExit: 9,
    });
    expect(result.status).toBe(9);
    expect(calls).toContain(
      "node invoked profile=custom-operator region=eu-west-1 project_region=eu-west-1 vpc=vpc-0abc1234 bucket=reviewed-template-bucket",
    );
    expect(resumeState).toContain(
      "WORKLOAD_BOUNDARY_APPLICATION_REGION=eu-west-1",
    );
    expect(resumeState).toContain("PROJECT_REGION=eu-west-1");
    expect(resumeState).toContain(
      "MEM9_TEMPLATE_BUCKET=reviewed-template-bucket",
    );
    expect(resumeState).toContain("MEM9_VPC_ID=vpc-0abc1234");
    expect(ROLLOUT_RESUME_COMMAND).toContain(
      "WORKLOAD_BOUNDARY_SKIP_DOTENV=false",
    );
  });

  it("rejects conflicting application region selectors before mutation", async () => {
    const { calls, result, resumeState } = await runRolloutGateMock({
      dotenvAck: "true",
      dotenvApplicationRegion: "eu-west-1",
      dotenvProjectRegion: "ap-northeast-1",
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("Application region settings disagree");
    expect(calls).not.toContain("aws sts get-caller-identity");
    expect(calls).not.toContain("workflow disable");
    expect(resumeState).toBe("");
  });

  it("rejects a resume under a different AWS account before mutation", async () => {
    const otherAccount = ["000000", "000000"].join("");
    const { calls, result, resumeState } = await runRolloutGateMock({
      dotenvAck: "true",
      expectedAccount: otherAccount,
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain(
      "AWS caller account differs from the retained rollout context",
    );
    expect(calls).not.toContain("workflow disable");
    expect(calls).not.toContain("node invoked");
    expect(resumeState).toBe("");
  });

  it("refuses an attached policy drift outside the guarded rollout", async () => {
    const { calls, result } = await runBoundaryDeployMock();
    expect(result.status).toBe(1);
    expect(
      calls.some((call) => call.startsWith("cloudformation update-stack")),
    ).toBe(false);
  });

  it("refuses any existing policy update outside the guarded rollout", async () => {
    const { calls, result } = await runBoundaryDeployMock();
    expect(result.status).toBe(1);
    expect(
      calls.some((call) => call.startsWith("iam list-entities-for-policy")),
    ).toBe(false);
    expect(
      calls.some((call) => call.startsWith("cloudformation update-stack")),
    ).toBe(false);
  });

  it("creates the first unattached boundary stack without quarantine", async () => {
    const { calls, result } = await runBoundaryDeployMock({
      quarantine: false,
      stackExists: false,
    });
    expect(result.status).toBe(0);
    expect(
      calls.some((call) => call.startsWith("cloudformation create-stack")),
    ).toBe(true);
    expect(
      calls.some((call) => call.startsWith("cloudformation update-stack")),
    ).toBe(false);
    expect(calls.some((call) => call.startsWith("iam get-role-policy"))).toBe(
      false,
    );
  });

  it("refuses a guarded attached-policy update without quarantine", async () => {
    const { calls, result } = await runBoundaryDeployMock({
      guarded: true,
      quarantine: false,
    });
    expect(result.status).toBe(1);
    expect(
      calls.some((call) => call.startsWith("cloudformation update-stack")),
    ).toBe(false);
  });

  it("updates an attached policy only after guarded quarantine verification", async () => {
    const { calls, result } = await runBoundaryDeployMock({ guarded: true });
    expect(result.status).toBe(0);
    const update = calls.findIndex((call) =>
      call.startsWith("cloudformation update-stack"),
    );
    expect(update).toBeGreaterThan(
      calls.findIndex((call) => call.startsWith("iam get-role-policy")),
    );
    expect(update).toBeGreaterThan(
      calls.findIndex((call) =>
        call.startsWith("iam simulate-custom-policy"),
      ),
    );
    expect(calls[update]).toContain(
      "ParameterKey=PolicyRevision,ParameterValue=r",
    );
    const simulation = calls.find((call) =>
      call.startsWith("iam simulate-custom-policy"),
    );
    expect(simulation).toContain("iam:PassRole");
    expect(simulation).toContain("iam:PutRolePermissionsBoundary");
    expect(
      calls.filter((call) => call.startsWith("iam get-role-policy")),
    ).toHaveLength(2);
  });

  it("refuses a guarded update when quarantine disappears after simulation", async () => {
    const { calls, result } = await runBoundaryDeployMock({
      guarded: true,
      quarantineLostAfterSimulation: true,
    });
    expect(result.status).toBe(1);
    expect(
      calls.filter((call) => call.startsWith("iam get-role-policy")),
    ).toHaveLength(2);
    expect(
      calls.some((call) => call.startsWith("cloudformation update-stack")),
    ).toBe(false);
  });

  it.each([
    ["create", { quarantine: false, stackExists: false }],
    ["update", { guarded: true }],
  ])(
    "rejects a boundary policy that remains drifted after %s",
    async (_name, options) => {
      const { calls, result } = await runBoundaryDeployMock({
        ...options,
        postMutationDrift: true,
      });
      expect(result.status).toBe(1);
      expect(
        calls.some((call) =>
          call.startsWith(
            options.stackExists === false
              ? "cloudformation create-stack"
              : "cloudformation update-stack",
          ),
        ),
      ).toBe(true);
      expect(
        calls.filter((call) => call.startsWith("iam get-policy-version")),
      ).not.toHaveLength(0);
    },
  );

  it.each([
    [
      "missing action",
      {
        EvaluationResults: QUARANTINE_PROBE_ACTIONS.slice(1).map((action) => ({
          EvalActionName: action,
          EvalDecision: "explicitDeny",
        })),
      },
      false,
    ],
    [
      "duplicate action",
      {
        EvaluationResults: QUARANTINE_PROBE_ACTIONS.map((action, index) => ({
          EvalActionName:
            index === QUARANTINE_PROBE_ACTIONS.length - 1
              ? QUARANTINE_PROBE_ACTIONS[0]
              : action,
          EvalDecision: "explicitDeny",
        })),
      },
      false,
    ],
    [
      "unexpected action",
      {
        EvaluationResults: QUARANTINE_PROBE_ACTIONS.map((action, index) => ({
          EvalActionName: index === 0 ? "iam:DeleteUser" : action,
          EvalDecision: "explicitDeny",
        })),
      },
      false,
    ],
    [
      "implicit deny",
      {
        EvaluationResults: QUARANTINE_PROBE_ACTIONS.map((action, index) => ({
          EvalActionName: action,
          EvalDecision: index === 0 ? "implicitDeny" : "explicitDeny",
        })),
      },
      false,
    ],
    ["malformed result", { EvaluationResults: [{}] }, false],
    ["failed probe", undefined, true],
  ])(
    "refuses a guarded update when quarantine simulation has a %s",
    async (_name, quarantineSimulation, simulationCommandFails) => {
      const { calls, result } = await runBoundaryDeployMock({
        guarded: true,
        quarantineSimulation,
        simulationCommandFails,
      });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(
        "Deploy-role quarantine is not effective for every probe",
      );
      expect(
        calls.some((call) => call.startsWith("cloudformation update-stack")),
      ).toBe(false);
    },
  );

  it("verifies an attached exact policy without attempting an update", async () => {
    const { calls, result } = await runBoundaryDeployMock({ matching: true });
    expect(result.status).toBe(0);
    expect(
      calls.some((call) =>
        /^cloudformation describe-stack-resource(?:\s|$)/u.test(call),
      ),
    ).toBe(false);
    expect(
      calls.some(
        (call) =>
          call.startsWith("cloudformation describe-stack-resources") &&
          call.includes("--logical-resource-id WorkloadPermissionsBoundary") &&
          call.includes("--query StackResources[0].PhysicalResourceId"),
      ),
    ).toBe(true);
    expect(
      calls.some((call) => call.startsWith("iam list-entities-for-policy")),
    ).toBe(false);
    expect(
      calls.some((call) => call.startsWith("cloudformation update-stack")),
    ).toBe(false);
  });

  it("verifies an exact active policy in read-only mode", async () => {
    const { calls, result } = await runBoundaryDeployMock({
      matching: true,
      verifyOnly: true,
    });
    expect(result.status).toBe(0);
    expect(calls.some((call) => call.startsWith("iam get-policy"))).toBe(true);
    expect(
      calls.some((call) => call.startsWith("cloudformation update-stack")),
    ).toBe(false);
  });

  it("gates the active boundary with runtime KMS semantics", async () => {
    const { calls, result } = await runBoundaryDeployMock({
      matching: true,
      verifyOnly: true,
    });
    expect(result.status, result.stderr).toBe(0);
    const simulations = calls.filter(
      (call) =>
        call.startsWith("iam simulate-custom-policy") &&
        call.includes("--permissions-boundary-policy-input-list"),
    );
    expect(simulations).toHaveLength(17);
    const projectLambda = simulations.find(
      (call) =>
        call.includes("function:mem9-on-aws-regression-probe") &&
        call.includes("Mem9OauthFacadeFnRole-regression-probe") &&
        !call.includes("ContextKeyName=lambda:SourceFunctionArn"),
    );
    expect(projectLambda).toContain(
      "ContextKeyName=kms:EncryptionContext:aws:lambda:FunctionArn",
    );
    expect(projectLambda).not.toContain("ContextKeyName=kms:ViaService");
    const facadeAuthorizerLambda = simulations.find(
      (call) =>
        call.includes("function:mem9-on-aws-regression-probe") &&
        call.includes("Mem9OauthFacadeAllowAllRole"),
    );
    expect(facadeAuthorizerLambda).toContain(
      "ContextKeyName=kms:EncryptionContext:aws:lambda:FunctionArn",
    );
    expect(facadeAuthorizerLambda).not.toContain(
      "ContextKeyName=kms:ViaService",
    );
    const projectSsm = simulations.find((call) =>
      call.includes("ContextKeyName=kms:EncryptionContext:PARAMETER_ARN") &&
      call.includes("ContextKeyName=kms:ViaService"),
    );
    expect(projectSsm).toContain("ContextKeyName=lambda:SourceFunctionArn");
    const serverSecret = simulations.find(
      (call) =>
        call.includes("ContextKeyName=kms:EncryptionContext:SecretARN") &&
        call.includes("Mem9DbSecret-regression") &&
        call.includes("Mem9ServerExecutionRole-regression-probe") &&
        call.includes(
          "ContextKeyValues=secretsmanager.ap-northeast-1.amazonaws.com",
        ),
    );
    expect(serverSecret).toContain(
      "ContextKeyName=kms:EncryptionContext:SecretVersionId",
    );
    const bootstrapSecret = simulations.find(
      (call) =>
        call.includes("tenant-api-key-regression") &&
        call.includes("Mem9BootstrapExecutionRole-regression-probe"),
    );
    expect(bootstrapSecret).toContain(
      "ContextKeyValues=secretsmanager.ap-northeast-1.amazonaws.com",
    );
    const directSsm = simulations.find(
      (call) =>
        call.includes("ContextKeyName=kms:EncryptionContext:PARAMETER_ARN") &&
        !call.includes("ContextKeyName=kms:ViaService"),
    );
    expect(directSsm).toBeDefined();
    expect(
      simulations.find(
        (call) =>
          call.includes("Mem9DbSecret-regression") &&
          call.includes("Mem9ServerExecutionRole-regression-probe") &&
          !call.includes("ContextKeyName=kms:ViaService"),
      ),
    ).toBeDefined();
    expect(
      simulations.find((call) =>
        call.includes("secret:outside-project-regression"),
      ),
    ).toBeDefined();
    expect(
      simulations.find(
        (call) =>
          call.includes("Mem9DbSecret-regression") &&
          call.includes("Mem9ServerTaskRole-regression-probe"),
      ),
    ).toBeDefined();
    expect(
      simulations.find(
        (call) =>
          call.includes("Mem9DbSecret-regression") &&
          call.includes("Mem9OauthFacadeFnRole-regression-probe"),
      ),
    ).toBeDefined();
    expect(
      simulations.find((call) =>
        call.includes(
          "ContextKeyValues=secretsmanager.us-west-2.amazonaws.com",
        ),
      ),
    ).toBeDefined();
    expect(
      simulations.find(
        (call) =>
          call.includes("Mem9DbSecret-regression") &&
          call.includes("ContextKeyValues=ssm.ap-northeast-1.amazonaws.com"),
      ),
    ).toBeDefined();
    expect(
      simulations.find(
        (call) =>
          call.includes("ContextKeyName=kms:EncryptionContext:PARAMETER_ARN") &&
          call.includes(
            "ContextKeyValues=secretsmanager.ap-northeast-1.amazonaws.com",
          ),
      ),
    ).toBeDefined();
    const directFunction = simulations.find(
      (call) =>
        call.includes(
          "ContextKeyName=kms:EncryptionContext:aws:lambda:FunctionArn",
        ) && call.includes("ContextKeyName=lambda:SourceFunctionArn"),
    );
    expect(directFunction).toBeDefined();
    expect(directFunction).not.toContain("ContextKeyName=kms:ViaService");
    const nonlambdaForgedLambda = simulations.find(
      (call) =>
        call.includes("Mem9ServerTaskRole-regression-probe") &&
        call.includes(
          "ContextKeyName=kms:EncryptionContext:aws:lambda:FunctionArn",
        ),
    );
    expect(nonlambdaForgedLambda).toContain(
      "ContextKeyName=kms:EncryptionContext:aws:lambda:FunctionArn",
    );
    expect(
      simulations.find((call) =>
        call.includes("function:outside-project-regression-probe"),
      ),
    ).toBeDefined();
    expect(
      simulations.find((call) => !call.includes("--context-entries")),
    ).toBeDefined();
  });

  it.each([
    "project-lambda",
    "facade-authorizer-lambda",
    "project-ssm",
    "server-secret",
    "bootstrap-secret",
    "direct-ssm",
    "direct-secret",
    "outside-secret",
    "task-role-secret",
    "lambda-role-secret",
    "cross-region-secret",
    "secret-via-ssm",
    "parameter-via-secretsmanager",
    "direct-function",
    "nonlambda-forged-lambda",
    "outside-lambda",
    "missing-context",
  ])("rejects a boundary with incorrect %s KMS semantics", async (probe) => {
    const { calls, result } = await runBoundaryDeployMock({
      boundarySimulationBadProbe: probe,
      matching: true,
      verifyOnly: true,
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "Workload permissions-boundary policy drift detected",
    );
    expect(
      calls.some((call) => call.startsWith("cloudformation update-stack")),
    ).toBe(false);
  });

  it.each([
    ["an AWS command failure", { simulationCommandFails: true }],
    [
      "a malformed response",
      { boundarySimulationMalformedProbe: "project-lambda" },
    ],
  ])("fails closed when boundary simulation has %s", async (_name, options) => {
    const { calls, result } = await runBoundaryDeployMock({
      ...options,
      matching: true,
      verifyOnly: true,
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "Workload permissions-boundary policy drift detected",
    );
    expect(
      calls.some((call) => call.startsWith("cloudformation update-stack")),
    ).toBe(false);
  });

  it("rejects a default-version change during semantic verification", async () => {
    const { calls, result } = await runBoundaryDeployMock({
      defaultVersionDriftsAfterSimulation: true,
      matching: true,
      verifyOnly: true,
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "Workload permissions-boundary policy drift detected",
    );
    expect(
      calls.filter((call) => call.startsWith("iam get-policy ")),
    ).toHaveLength(2);
    expect(
      calls.some((call) => call.startsWith("cloudformation update-stack")),
    ).toBe(false);
  });

  it.each([
    ["policy drift", { matching: false }],
    ["missing stack", { matching: false, stackExists: false }],
  ])("keeps --verify-only mutation-free for %s", async (_name, options) => {
    const { calls, result } = await runBoundaryDeployMock({
      ...options,
      verifyOnly: true,
    });
    expect(result.status).toBe(1);
    expect(
      calls.some(
        (call) =>
          call.startsWith("cloudformation create-stack") ||
          call.startsWith("cloudformation update-stack"),
      ),
    ).toBe(false);
  });

  it("rejects an exact policy while its CloudFormation stack is nonterminal", async () => {
    const { calls, result } = await runBoundaryDeployMock({
      matching: true,
      stackStatus: "UPDATE_IN_PROGRESS",
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "Boundary stack is not in an accepted complete state",
    );
    expect(calls.some((call) => call.startsWith("iam get-policy"))).toBe(false);
  });

  it("recovers UPDATE_ROLLBACK_COMPLETE only through the guarded rollout", async () => {
    const guarded = await runBoundaryDeployMock({
      guarded: true,
      matching: true,
      stackStatus: "UPDATE_ROLLBACK_COMPLETE",
    });
    expect(guarded.result.status, guarded.result.stderr).toBe(0);
    expect(
      guarded.calls.some((call) =>
        call.startsWith("cloudformation update-stack"),
      ),
    ).toBe(true);

    for (const options of [
      { matching: true, stackStatus: "UPDATE_ROLLBACK_COMPLETE" },
      {
        matching: true,
        stackStatus: "UPDATE_ROLLBACK_COMPLETE",
        verifyOnly: true,
      },
    ]) {
      const { calls, result } = await runBoundaryDeployMock(options);
      expect(result.status).toBe(1);
      expect(
        calls.some((call) => call.startsWith("cloudformation update-stack")),
      ).toBe(false);
    }
  });

  it("requires explicit CloudFormation recovery from UPDATE_ROLLBACK_FAILED", async () => {
    const { calls, result } = await runBoundaryDeployMock({
      guarded: true,
      matching: true,
      stackStatus: "UPDATE_ROLLBACK_FAILED",
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("continue-update-rollback");
    expect(
      calls.some((call) => call.startsWith("cloudformation update-stack")),
    ).toBe(false);
  });
});

describe("boundary and deploy-role templates", () => {
  it("declares a retained action and project-resource permissions ceiling", () => {
    const template = parseCloudFormation(boundaryTemplatePath);
    const boundary = template.Resources.WorkloadPermissionsBoundary;
    expect(boundary.Type).toBe("AWS::IAM::ManagedPolicy");
    expect(boundary.DeletionPolicy).toBe("Retain");
    expect(boundary.UpdateReplacePolicy).toBe("Retain");
    expect(boundary.Properties.ManagedPolicyName).toBe(
      "mem9-on-aws-workload-boundary",
    );

    const statements = resolveTemplateValue(
      boundary.Properties.PolicyDocument,
    ).Statement;
    const allows = statements.filter(
      (statement) => statement.Effect === "Allow",
    );
    const bySid = (sid) =>
      statements.find((statement) => statement.Sid === sid);
    expect(allows).toEqual([
      {
        Sid: "AllowRuntimeIdentityPermissions",
        Effect: "Allow",
        Action: "*",
        Resource: "*",
      },
    ]);
    const actionCeiling = bySid("DenyOutsideRuntimeActionCeilingr1");
    expect(actionCeiling).toMatchObject({
      Effect: "Deny",
      Resource: "*",
    });
    expect(actionCeiling.Action).toBeUndefined();
    expect([...actionCeiling.NotAction].sort()).toEqual(
      independentRuntimeActions,
    );
    expect(actionCeiling.NotAction).not.toEqual(
      expect.arrayContaining([
        "iam:CreateRole",
        "sts:AssumeRole",
        "cloudformation:UpdateStack",
        "ecr:PutRegistryScanningConfiguration",
      ]),
    );
    expect(
      resolveTemplateValue(
        bySid("DenyProjectRuntimeOutsideResources").NotResource,
      ),
    ).toEqual(
      expect.arrayContaining([
        boundaryContract.bedrockProjectArn,
        expect.stringContaining("repository/mem9-on-aws/*"),
        expect.stringContaining("function:mem9-on-aws-*"),
        expect.stringContaining("secret:mem9-on-aws-*"),
        "arn:aws:sqs:ap-northeast-1:123456789012:" +
          "AlertTransportFailureQueue-*",
        "arn:aws:sqs:ap-northeast-1:123456789012:" +
          "AlertExecutionFailureQueue-*",
        "arn:aws:sns:ap-northeast-1:123456789012:mem9-on-aws-*-alerts",
        expect.stringContaining("parameter/mem9-on-aws/*"),
      ]),
    );
    expect(bySid("DenyProjectRuntimeOutsideResources").Action).toEqual(
      expect.arrayContaining([
        "secretsmanager:GetSecretValue",
        "sns:Publish",
        "sqs:SendMessage",
        "ssm:GetParameters",
        // Admitting a WRITE to the action ceiling is only safe if it is also
        // resource-scoped. A boundary never GRANTS: effective permissions are the
        // intersection of the boundary and the identity policy. So without this
        // entry the boundary simply stops constraining `ssm:PutParameter` by
        // resource, and any identity-policy grant — including an over-broad one
        // added later — would take effect account-wide (#123).
        "ssm:PutParameter",
      ]),
    );
    expect(bySid("DenyProjectRuntimeOutsideResources").Action).not.toEqual(
      expect.arrayContaining([
        "ssm:GetParameter",
        "ssm:GetParameterHistory",
        "ssm:GetParametersByPath",
      ]),
    );
    // DenyProjectRuntimeOutsideResources scopes the write to the PROJECT prefix,
    // which is every stage's whole SSM tree. That is too wide for a write: the
    // ceiling is the only control on what a workload role may do, because
    // identity policies are PR-authored and the deploy role's
    // DenyUnboundedProjectRolePolicyWrites only requires that the boundary be
    // ATTACHED, never constrains its content. Preview roles are bounded too
    // (shouldRegisterWorkloadRoleBoundary returns true for every non-prod
    // stage), so without a second, tighter deny a PR could grant one of its own
    // preview Lambdas ssm:PutParameter on `/mem9-on-aws/prod/*` and overwrite
    // prod's plain-String parameters — `oauth/allowed-callback-urls` is an
    // open-redirect primitive, and the bootstrap/consolidation `task-def-arn`
    // and `cluster-name` are consumed unvalidated by scripts/run-*-task.sh.
    // SecureString parameters are already out of reach (a SecureString write
    // needs kms:Encrypt or kms:GenerateDataKey, neither of which the ceiling
    // admits), so the plain-String ones are exactly the exposure this closes.
    const approvalScope = bySid("DenyPutParameterOutsideApprovalRecords");
    expect(approvalScope).toMatchObject({
      Effect: "Deny",
      Action: ["ssm:PutParameter"],
    });
    expect(resolveTemplateValue(approvalScope.NotResource)).toEqual([
      "arn:aws:ssm:ap-northeast-1:123456789012:" +
        "parameter/mem9-on-aws/*/approvals/*",
    ]);
    expect(
      bySid(
        "DenyKmsDecryptOutsideProjectParameterFunctionOrSecretContexts",
      ),
    ).toEqual({
      Sid: "DenyKmsDecryptOutsideProjectParameterFunctionOrSecretContexts",
      Effect: "Deny",
      Action: ["kms:Decrypt"],
      Resource: "*",
      Condition: {
        StringNotLikeIfExists: {
          "kms:EncryptionContext:PARAMETER_ARN":
            "arn:aws:ssm:ap-northeast-1:123456789012:" +
            "parameter/mem9-on-aws/*",
          "kms:EncryptionContext:aws:lambda:FunctionArn":
            "arn:aws:lambda:ap-northeast-1:123456789012:" +
            "function:mem9-on-aws-*",
          "kms:EncryptionContext:SecretARN": [
            "arn:aws:secretsmanager:ap-northeast-1:123456789012:" +
              "secret:mem9-on-aws-*-Mem9DbProxySecret-*",
            "arn:aws:secretsmanager:ap-northeast-1:123456789012:" +
              "secret:mem9-on-aws-*-Mem9DbSecret-*",
            "arn:aws:secretsmanager:ap-northeast-1:123456789012:" +
              "secret:mem9-on-aws-*-tenant-api-key-*",
          ],
        },
      },
    });
    expect(bySid("DenyKmsDecryptOutsideSsm")).toBeUndefined();
    expect(
      bySid("DenyKmsDecryptOutsideSsmSecretsManagerOrProjectLambdaPath"),
    ).toEqual({
      Sid: "DenyKmsDecryptOutsideSsmSecretsManagerOrProjectLambdaPath",
      Effect: "Deny",
      Action: ["kms:Decrypt"],
      Resource: "*",
      Condition: {
        StringNotEqualsIfExists: {
          "kms:ViaService": [
            "ssm.ap-northeast-1.amazonaws.com",
            "secretsmanager.ap-northeast-1.amazonaws.com",
          ],
        },
        StringNotLikeIfExists: {
          "kms:EncryptionContext:aws:lambda:FunctionArn":
            "arn:aws:lambda:ap-northeast-1:123456789012:" +
            "function:mem9-on-aws-*",
        },
      },
    });
    expect(
      bySid("DenySecretContextDecryptFromNonEcsExecutionRoles"),
    ).toEqual({
      Sid: "DenySecretContextDecryptFromNonEcsExecutionRoles",
      Effect: "Deny",
      Action: ["kms:Decrypt"],
      Resource: "*",
      Condition: {
        Null: {
          "kms:EncryptionContext:SecretARN": "false",
        },
        ArnNotLike: {
          "aws:PrincipalArn": [
            "arn:aws:iam::123456789012:role/" +
              "mem9-on-a*-*Mem9ServerExecutionRole-*",
            "arn:aws:iam::123456789012:role/" +
              "mem9-on-a*-*Mem9BootstrapExecutionRole-*",
            "arn:aws:iam::123456789012:role/" +
              "mem9-on-a*-*Mem9ConsolidationExecutionRole-*",
          ],
        },
      },
    });
    expect(bySid("DenyParameterContextDecryptOutsideSsm")).toEqual({
      Sid: "DenyParameterContextDecryptOutsideSsm",
      Effect: "Deny",
      Action: ["kms:Decrypt"],
      Resource: "*",
      Condition: {
        Null: {
          "kms:EncryptionContext:PARAMETER_ARN": "false",
        },
        StringNotEqualsIfExists: {
          "kms:ViaService": "ssm.ap-northeast-1.amazonaws.com",
        },
      },
    });
    expect(
      bySid("DenySecretContextDecryptOutsideSecretsManager"),
    ).toEqual({
      Sid: "DenySecretContextDecryptOutsideSecretsManager",
      Effect: "Deny",
      Action: ["kms:Decrypt"],
      Resource: "*",
      Condition: {
        Null: {
          "kms:EncryptionContext:SecretARN": "false",
        },
        StringNotEqualsIfExists: {
          "kms:ViaService":
            "secretsmanager.ap-northeast-1.amazonaws.com",
        },
      },
    });
    expect(bySid("DenyDirectKmsDecryptFromFunctionCode")).toEqual({
      Sid: "DenyDirectKmsDecryptFromFunctionCode",
      Effect: "Deny",
      Action: ["kms:Decrypt"],
      Resource: "*",
      Condition: {
        Null: {
          "lambda:SourceFunctionArn": "false",
        },
        StringNotEqualsIfExists: {
          "kms:ViaService": "ssm.ap-northeast-1.amazonaws.com",
        },
      },
    });
    expect(bySid("DenyLambdaContextDecryptFromNonLambdaRoles")).toEqual({
      Sid: "DenyLambdaContextDecryptFromNonLambdaRoles",
      Effect: "Deny",
      Action: ["kms:Decrypt"],
      Resource: "*",
      Condition: {
        Null: {
          "kms:EncryptionContext:aws:lambda:FunctionArn": "false",
        },
        ArnNotLike: {
          "aws:PrincipalArn": [
            "arn:aws:iam::123456789012:role/" +
              "mem9-on-a*-*Mem9AlertRouterRole-*",
            "arn:aws:iam::123456789012:role/" +
              "mem9-on-a*-*Mem9OauthFacadeAllowAllRole",
            "arn:aws:iam::123456789012:role/" +
              "mem9-on-a*-*Mem9OauthFacadeFnRole-*",
            "arn:aws:iam::123456789012:role/" +
              "mem9-on-a*-*Mem9ProxyFnRole-*",
          ],
        },
      },
    });
    expect(
      bySid("DenyNonShortTermMantleBearer").Condition.StringNotEqualsIfExists[
        "bedrock-mantle:BearerTokenType"
      ],
    ).toBe("SHORT_TERM");
    expect(bySid("DenyEniFromNonVpcLambdaRoles")).toMatchObject({
      Effect: "Deny",
      Resource: "*",
      Condition: {
        ArnNotLike: {
          "aws:PrincipalArn":
            "arn:aws:iam::123456789012:role/" + "mem9-on-a*-*Mem9ProxyFnRole-*",
        },
      },
    });
    expect(bySid("DenyEniFromFunctionCode")).toMatchObject({
      Effect: "Deny",
      Resource: "*",
      Condition: {
        Null: {
          "lambda:SourceFunctionArn": "false",
        },
      },
    });
    expect(
      verifyBoundaryPolicyDocument(
        resolveTemplateValue(boundary.Properties.PolicyDocument),
        boundaryContract,
      ),
    ).toBe(true);
  });

  // Every guard on ssm:PutParameter names it as a literal, so nothing stops the
  // NEXT write from being admitted with no resource scope at all — a mistake that
  // stays invisible if the template and the contract library are edited
  // consistently. This turns the allowlist into an explicit decision: a mutating
  // action is either resource-scoped by some Deny/NotResource statement, or it is
  // listed below as a reviewed account-wide admission.
  it("resource-scopes every mutating action admitted to the ceiling", () => {
    const document = expectedBoundaryPolicyDocument(boundaryContract);
    const ceiling = document.Statement.find(({ NotAction }) => NotAction);
    // Admitted account-wide by deliberate review. ecs:RunTask and iam:PassRole
    // are constrained by the deploy role's PassRole scoping plus
    // DenyEcsExecutionRolePassToOtherServices rather than by NotResource; the
    // ec2/ssmmessages/logs entries are service-mediated calls with no useful
    // per-resource ARN, and each is separately gated by a principal condition.
    const reviewedGlobalWrites = new Set([
      "bedrock-mantle:CallWithBearerToken",
      "bedrock-mantle:CreateInference",
      "ec2:AssignPrivateIpAddresses",
      "ec2:CreateNetworkInterface",
      "ec2:DeleteNetworkInterface",
      "ec2:UnassignPrivateIpAddresses",
      "ecs:RunTask",
      "iam:PassRole",
      "lambda:InvokeFunction",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]);
    const scopedByNotResource = new Set(
      document.Statement.filter(
        (statement) => statement.Effect === "Deny" && statement.NotResource,
      ).flatMap((statement) => statement.Action ?? []),
    );
    const mutating =
      /:(Put|Create|Delete|Update|Send|Publish|Run|Pass|Invoke|Assign|Unassign|Open|Call)/u;
    for (const action of ceiling.NotAction.filter((a) => mutating.test(a))) {
      expect(
        scopedByNotResource.has(action) || reviewedGlobalWrites.has(action),
        `${action} mutates but is neither resource-scoped by a Deny/NotResource ` +
          `statement nor listed as a reviewed account-wide admission`,
      ).toBe(true);
    }
  });

  it("keeps the boundary within the IAM managed-policy size quota", () => {
    const template = parseCloudFormation(boundaryTemplatePath);
    const size = JSON.stringify(
      resolveTemplateValue(
        template.Resources.WorkloadPermissionsBoundary.Properties.PolicyDocument,
      ),
    ).length;
    expect(size).toBeLessThanOrEqual(6_144);
  });

  // The assertion above measures the template, where resolveTemplateValue
  // collapses the !If for OpenAiBedrockProjectArn to AWS::NoValue — so it only
  // ever sizes the OpenAI-UNCONFIGURED shape. The Responses route configures
  // that second project ARN in the live account, adding bytes CI never counted.
  // Without this case the boundary can pass every gate and still be rejected by
  // IAM at rollout time, which is the one failure mode a size test exists to
  // prevent.
  it("keeps the boundary within the IAM size quota with both Mantle projects", () => {
    const size = JSON.stringify(
      expectedBoundaryPolicyDocument({
        ...boundaryContract,
        openAiBedrockProjectArn:
          "arn:aws:bedrock-mantle:us-west-2:123456789012:project/proj_openai",
      }),
    ).length;
    expect(size).toBeLessThanOrEqual(6_144);
  });

  it("keeps every deploy-role managed policy within the IAM size quota", () => {
    const template = parseCloudFormation(deployRoleTemplatePath);
    for (const [logicalId, resource] of Object.entries(template.Resources)) {
      if (resource.Type !== "AWS::IAM::ManagedPolicy") continue;
      const size = JSON.stringify(resource.Properties.PolicyDocument).length;
      expect(
        size,
        `${logicalId} exceeds 6,144 policy characters`,
      ).toBeLessThanOrEqual(6_144);
    }
  });

  it("keeps fixed identifiers consistent across every rollout artifact", () => {
    const contract = JSON.parse(readFileSync(rolloutContractPath, "utf8"));
    expect({
      boundaryPolicyName: WORKLOAD_BOUNDARY_POLICY_NAME,
      boundaryStackName: WORKLOAD_BOUNDARY_STACK_NAME,
      denyDangerousPolicyName: DENY_DANGEROUS_POLICY_NAME,
      deployRoleName: DEPLOY_ROLE_NAME,
      quarantinePolicyName: QUARANTINE_POLICY_NAME,
    }).toEqual(contract.identifiers);

    const boundaryTemplate = parseCloudFormation(boundaryTemplatePath);
    expect(
      boundaryTemplate.Resources.WorkloadPermissionsBoundary.Properties
        .ManagedPolicyName,
    ).toBe(contract.identifiers.boundaryPolicyName);

    const deployRoleTemplate = parseCloudFormation(deployRoleTemplatePath);
    const deployRole = Object.values(deployRoleTemplate.Resources).find(
      ({ Type }) => Type === "AWS::IAM::Role",
    );
    expect(resolveTemplateValue(deployRole.Properties.RoleName)).toBe(
      contract.identifiers.deployRoleName,
    );
    const deployRoleSource = JSON.stringify(
      resolveTemplateValue(deployRoleTemplate),
    );
    expect(deployRoleSource).toContain(contract.identifiers.boundaryPolicyName);
    expect(deployRoleSource).toContain(contract.identifiers.boundaryStackName);
    expect(deployRoleSource).toContain(
      `stack/${contract.identifiers.deployRoleName}/`,
    );
    expect(
      resolveTemplateValue(
        deployRoleTemplate.Resources.DenyPolicy.Properties.ManagedPolicyName,
      ),
    ).toBe(contract.identifiers.denyDangerousPolicyName);

    const typescriptSource = readFileSync(
      resolve(root, "infra/workload-permissions-boundary.ts"),
      "utf8",
    );
    expect(typescriptSource).toContain(
      "rolloutContract.identifiers.boundaryPolicyName",
    );

    const shellSource = readFileSync(boundaryDeployPath, "utf8");
    for (const field of [
      "boundaryPolicyName",
      "boundaryStackName",
      "denyDangerousPolicyName",
      "deployRoleName",
      "quarantinePolicyName",
    ]) {
      expect(shellSource).toContain(`.${field}`);
    }
  });

  it("enforces the exact boundary while preserving safe role deletion", () => {
    const template = parseCloudFormation(deployRoleTemplatePath);
    const denyStatements =
      template.Resources.DenyPolicy.Properties.PolicyDocument.Statement;
    const roleStatements =
      template.Resources.ComputePolicy.Properties.PolicyDocument.Statement;
    const bySid = (statements, sid) =>
      statements.find((statement) => statement.Sid === sid);

    for (const sid of [
      "DenyUnboundedProjectRoleCreation",
      "DenyUnboundedProjectRolePolicyWrites",
      "DenyLambdaRolePassToOtherServices",
      "DenyEcsExecutionRolePassToOtherServices",
      "DenyConsolidationSchedulerRolePassToOtherServices",
      "DenyWorkloadBoundaryRemoval",
      "DenyOperatorOwnedIamMutation",
      "DenyOperatorOwnedStackMutation",
    ]) {
      expect(bySid(denyStatements, sid), `missing ${sid}`).toBeDefined();
    }

    for (const sid of [
      "EcsTaskRoleCreateWithBoundary",
      "EcsTaskRolePolicyWritesWithBoundary",
      "EcsTaskRoleLifecycle",
      "WorkloadBoundaryRead",
      "WorkloadBoundarySimulation",
    ]) {
      expect(bySid(roleStatements, sid), `missing ${sid}`).toBeDefined();
    }

    expect(
      bySid(roleStatements, "EcsTaskRoleCreateWithBoundary").Action,
    ).toEqual(
      expect.arrayContaining([
        "iam:CreateRole",
        "iam:PutRolePermissionsBoundary",
      ]),
    );
    expect(
      bySid(roleStatements, "EcsTaskRolePolicyWritesWithBoundary").Action,
    ).toEqual(
      expect.arrayContaining(["iam:PutRolePolicy", "iam:AttachRolePolicy"]),
    );
    expect(
      resolveTemplateValue(bySid(roleStatements, "WorkloadBoundaryRead")),
    ).toEqual({
      Sid: "WorkloadBoundaryRead",
      Effect: "Allow",
      Action: ["iam:GetPolicy", "iam:GetPolicyVersion"],
      Resource: boundaryArn,
    });
    expect(
      resolveTemplateValue(bySid(roleStatements, "WorkloadBoundarySimulation")),
    ).toEqual({
      Sid: "WorkloadBoundarySimulation",
      Effect: "Allow",
      Action: ["iam:SimulateCustomPolicy"],
      Resource: "*",
    });
    const lambdaStatements =
      template.Resources.LambdaProxyPolicy.Properties.PolicyDocument.Statement;
    expect(bySid(lambdaStatements, "LambdaCreate").Action).toContain(
      "lambda:ListFunctions",
    );
    expect(
      resolveTemplateValue(bySid(roleStatements, "EcsTaskRoleLifecycle")),
    ).toEqual({
      Sid: "EcsTaskRoleLifecycle",
      Effect: "Allow",
      Action: [
        "iam:DeleteRole",
        "iam:GetRole",
        "iam:DeleteRolePolicy",
        "iam:GetRolePolicy",
        "iam:ListRolePolicies",
        "iam:DetachRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:ListRoleTags",
        "iam:ListInstanceProfilesForRole",
        "iam:TagRole",
        "iam:UntagRole",
      ],
      Resource: patterns,
    });
    expect(
      resolveTemplateValue(
        bySid(denyStatements, "DenyLambdaRolePassToOtherServices"),
      ),
    ).toMatchObject({
      Effect: "Deny",
      Action: ["iam:PassRole"],
      Resource: [
        "arn:aws:iam::123456789012:role/mem9-on-a*-*Mem9AlertRouterRole-*",
        "arn:aws:iam::123456789012:role/mem9-on-a*-*Mem9OauthFacadeAllowAllRole",
        "arn:aws:iam::123456789012:role/mem9-on-a*-*Mem9OauthFacadeFnRole-*",
        "arn:aws:iam::123456789012:role/mem9-on-a*-*Mem9ProxyFnRole-*",
      ],
      Condition: {
        StringNotEquals: {
          "iam:PassedToService": "lambda.amazonaws.com",
        },
      },
    });
    expect(
      resolveTemplateValue(
        bySid(denyStatements, "DenyEcsExecutionRolePassToOtherServices"),
      ),
    ).toMatchObject({
      Effect: "Deny",
      Action: ["iam:PassRole"],
      Resource: [
        "arn:aws:iam::123456789012:role/" +
          "mem9-on-a*-*Mem9ServerExecutionRole-*",
        "arn:aws:iam::123456789012:role/" +
          "mem9-on-a*-*Mem9BootstrapExecutionRole-*",
        "arn:aws:iam::123456789012:role/" +
          "mem9-on-a*-*Mem9ConsolidationExecutionRole-*",
      ],
      Condition: {
        StringNotEquals: {
          "iam:PassedToService": "ecs-tasks.amazonaws.com",
        },
      },
    });
    expect(
      resolveTemplateValue(
        bySid(
          denyStatements,
          "DenyConsolidationSchedulerRolePassToOtherServices",
        ),
      ),
    ).toMatchObject({
      Effect: "Deny",
      Action: ["iam:PassRole"],
      Resource: [consolidationSchedulerRolePattern],
      Condition: {
        StringNotEquals: {
          "iam:PassedToService": "scheduler.amazonaws.com",
        },
      },
    });
    expect(
      verifyPermanentEnforcementDocuments(deployedManagedPolicyDocuments(), {
        accountId,
        boundaryArn,
        partition,
      }),
    ).toBe(true);
  });

  it("wires both templates and rollout shell entry points into CI", () => {
    const workflow = readFileSync(workflowPath, "utf8");
    const documentationSecurityWorkflow = readFileSync(
      documentationSecurityWorkflowPath,
      "utf8",
    );
    const reconciliationWorkflow = readFileSync(
      reconciliationWorkflowPath,
      "utf8",
    );
    expect(workflow).toContain(
      "cfn-lint infra/cloudformation/workload-permissions-boundary.yaml --regions us-west-2",
    );
    expect(workflow).toContain(
      "cfn-lint infra/cloudformation/github-actions-role.yaml --regions us-west-2",
    );
    expect(workflow).not.toContain("--ignore-checks W3037");
    expect(workflow).not.toContain("describe-stack-resource \\\n");
    expect(workflow).not.toContain("cloudformation describe-stack-resources");
    expect(
      workflow.match(
        /deploy-workload-permissions-boundary\.sh --verify-only/gu,
      ),
    ).toHaveLength(2);
    expect(workflow).toContain(
      "shellcheck scripts/deploy-workload-permissions-boundary.sh",
    );
    expect(workflow).toContain(
      "scripts/rollout-workload-permissions-boundary.sh",
    );
    expect(workflow).toContain("uses: pulumi/actions@v7");
    expect(workflow).toContain("pulumi-version: 3.215.0");
    expect(workflow).not.toContain("sst install --config");
    expect(workflow).not.toContain("Cache SST/Pulumi runtime");
    expect(workflow).not.toContain("node scripts/scan-public-artifacts.mjs");
    expect(documentationSecurityWorkflow).toContain("fetch-depth: 0");
    expect(documentationSecurityWorkflow).toContain("node-version: 24");
    expect(documentationSecurityWorkflow).toContain(
      "name: Scan every changed path and historical blob",
    );
    expect(documentationSecurityWorkflow).toContain(
      "node scripts/scan-public-artifacts.mjs",
    );
    expect(documentationSecurityWorkflow).toContain(
      '--git-range "$DIFF_BASE" "$DIFF_HEAD"',
    );
    const documentationSecurity = parse(documentationSecurityWorkflow);
    expect(documentationSecurity.on.pull_request.paths).toBeUndefined();
    expect(documentationSecurity.on.push.paths).toBeUndefined();
    expect(workflow).toContain(
      "WORKLOAD_BOUNDARY_PROD_ENABLED: ${{ vars.WORKLOAD_BOUNDARY_PROD_ENABLED }}",
    );
    expect(
      workflow.match(
        /Operator-owned workload boundary is missing or drifted/gu,
      ),
    ).toHaveLength(2);
    expect(workflow.match(/name: Deployment maintenance gate/gu)).toHaveLength(
      4,
    );
    expect(
      reconciliationWorkflow.match(/name: Deployment maintenance gate/gu),
    ).toHaveLength(2);
    for (const [name, source] of [
      ["infra-ci.yml", workflow],
      ["reconcile-previews.yml", reconciliationWorkflow],
    ]) {
      const document = parse(source);
      for (const [jobName, job] of Object.entries(document.jobs)) {
        const credentialIndex = job.steps.findIndex(
          (step) =>
            typeof step.uses === "string" &&
            step.uses.startsWith("aws-actions/configure-aws-credentials@"),
        );
        if (credentialIndex < 0) continue;
        const gates = job.steps.filter(
          (step) => step.name === "Deployment maintenance gate",
        );
        expect(
          gates,
          `${name}:${jobName} must have exactly one gate`,
        ).toHaveLength(1);
        const gate = gates[0];
        const gateIndex = job.steps.indexOf(gate);
        expect(
          gateIndex,
          `${name}:${jobName} must gate before AWS credentials`,
        ).toBeGreaterThanOrEqual(0);
        expect(
          gateIndex,
          `${name}:${jobName} gate must precede AWS credentials`,
        ).toBeLessThan(credentialIndex);
        expect(gate.env?.PAUSED).toBe(
          "${{ vars.DEPLOYMENT_MAINTENANCE_PAUSED }}",
        );
        expect(gate.run).toContain('if [ "$PAUSED" = "true" ]; then');
        expect(gate.run).toContain(
          "::error::AWS deployments are paused for guarded IAM maintenance",
        );
        expect(gate.run).toMatch(/exit 1\s+fi/u);
        expect(gate["continue-on-error"]).toBeUndefined();

        if (name === "reconcile-previews.yml") {
          expect(job.if).toContain(
            "vars.WORKLOAD_BOUNDARY_PROD_ENABLED == 'true'",
          );
          continue;
        }
        if (jobName === "deploy-prod") {
          expect(gate.env?.BOUNDARY_ENFORCED).toBe(
            "${{ vars.WORKLOAD_BOUNDARY_PROD_ENABLED }}",
          );
          expect(gate.run).toContain(
            'if [ "$BOUNDARY_ENFORCED" != "true" ]; then',
          );
          expect(gate.run).toContain(
            "Guarded workload-boundary migration is incomplete — refusing prod deployment",
          );
          continue;
        }

        const awsGate = job.steps.find(
          (step) => step.name === "Gate on AWS_ROLE_ARN",
        );
        expect(
          awsGate,
          `${name}:${jobName} must gate boundary activation`,
        ).toBeDefined();
        expect(awsGate.env?.BOUNDARY_ENFORCED).toBe(
          "${{ vars.WORKLOAD_BOUNDARY_PROD_ENABLED }}",
        );
        expect(awsGate.run).toContain(
          'if [ "$BOUNDARY_ENFORCED" != "true" ]; then',
        );
        expect(job.steps[credentialIndex].if).toBe(
          "steps.gate.outputs.skip != 'true'",
        );
      }
    }
    expect(workflow).toContain("DEPLOYMENT_MAINTENANCE_PAUSED");
    expect(reconciliationWorkflow).toContain("DEPLOYMENT_MAINTENANCE_PAUSED");
    expect(workflow).toContain(
      "Workload-boundary maintenance gate revision: 1",
    );
    expect(reconciliationWorkflow).toContain(
      "Workload-boundary maintenance gate revision: 1",
    );
  });

  it("reads back and verifies the deployed boundary policy version", () => {
    const deployScript = readFileSync(boundaryDeployPath, "utf8");
    expect(deployScript).toContain("aws iam get-policy");
    expect(deployScript).toContain("aws iam get-policy-version");
    expect(deployScript).toContain(
      "scripts/verify-workload-permissions-boundary.mjs",
    );
    expect(deployScript).not.toContain("list-entities-for-policy");
    expect(deployScript).toContain("--guarded-update");
    expect(deployScript).toContain("--verify-only");
    const awsAdapter = readFileSync(
      resolve(root, "scripts/lib/workload-permissions-boundary-aws.mjs"),
      "utf8",
    );
    const rolloutModule = readFileSync(rolloutModulePath, "utf8");
    expect(awsAdapter).toContain(
      "{ signal, timeoutMs = AWS_CLI_TIMEOUT_MS } = {}",
    );
    expect(awsAdapter).toContain("runBoundedCommand");
    expect(awsAdapter).toContain("remainingCommandTimeout");
    expect(rolloutModule).toContain("runBoundedCommand");
    expect(rolloutModule).toContain("remainingCommandTimeout");
    const contract = JSON.parse(readFileSync(rolloutContractPath, "utf8"));
    expect(contract.quarantineProbeActions).toContain(
      "lambda:UpdateFunctionCode",
    );
  });

  it("requires a mechanical deployment pause before the guarded migration", () => {
    const rolloutScript = readFileSync(rolloutWrapperPath, "utf8");
    const contract = JSON.parse(readFileSync(rolloutContractPath, "utf8"));
    expect(rolloutScript).toContain("DEPLOYMENT_MAINTENANCE_PAUSED");
    expect(rolloutScript).toContain("gh run list");
    expect(contract.deploymentWorkflows.map(({ id }) => id)).toEqual([
      ...DEPLOYMENT_WORKFLOWS,
    ]);
    expect(contract.deploymentWorkflows).toEqual([
      {
        id: "infra-ci.yml",
        path: ".github/workflows/infra-ci.yml",
        reviewedBlob: expect.stringMatching(/^[0-9a-f]{40}$/u),
      },
      {
        id: "reconcile-previews.yml",
        path: ".github/workflows/reconcile-previews.yml",
        reviewedBlob: expect.stringMatching(/^[0-9a-f]{40}$/u),
      },
    ]);
    for (const { path, reviewedBlob } of contract.deploymentWorkflows) {
      expect(reviewedBlob).toBe(gitBlobHash(resolve(root, path)));
    }
    expect([...contract.quarantineProbeActions].sort()).toEqual([
      ...QUARANTINE_PROBE_ACTIONS,
    ]);
    expect(contract.quarantineProbeActions).toEqual(
      expect.arrayContaining([
        "iam:PassRole",
        "iam:PutRolePermissionsBoundary",
      ]),
    );
    expect(contract.nonterminalWorkflowStatuses).toEqual(
      NONTERMINAL_WORKFLOW_STATUSES,
    );
    expect(contract.rolloutTimeoutMs).toBe(ROLLOUT_TIMEOUT_MS);
    expect(contract.rolloutTimeoutMs).toBe(3_600_000);
    expect(contract.shutdownGraceMs).toBe(ROLLOUT_SHUTDOWN_GRACE_MS);
    expect(contract.shutdownGraceMs).toBeGreaterThan(0);
    expect(contract.shutdownGraceMs).toBeLessThan(contract.rolloutTimeoutMs);
    expect(rolloutScript).toContain("count_active_runs");
    expect(rolloutScript).toContain(
      "workload-permissions-boundary-contract.json",
    );
    expect(rolloutScript).toContain(
      "Merge the exact reviewed maintenance-gate workflows",
    );
    expect(rolloutScript).toContain("nonterminalWorkflowStatuses");
    expect(rolloutScript).toContain("rollout_hard_deadline_at_ms");
    expect(rolloutScript).toContain("shutdownGraceMs");
    expect(rolloutScript).toContain("timeout --signal=KILL");
    expect(rolloutScript).toContain("flock -n 9");
    expect(rolloutScript).toContain("forward_rollout_signal");
    expect(rolloutScript).toContain("gh workflow disable");
    expect(rolloutScript).toContain('--commit "$default_sha"');
    const rolloutModule = readFileSync(rolloutModulePath, "utf8");
    expect(rolloutModule).toContain(
      '["workflow", "enable", workflow, "--repo", repository]',
    );
    expect(rolloutModule).toContain(
      "deployment workflow enable read-back failed",
    );
    expect(rolloutScript).not.toContain(
      'bash "$repo_root/scripts/deploy-workload-permissions-boundary.sh"',
    );
  });
});
