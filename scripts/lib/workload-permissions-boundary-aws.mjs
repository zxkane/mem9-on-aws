import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { validateDecisionArtifactBucketName } from "./authorization-maintenance-isolation.mjs";
import { createRetainedOperatorInventory, RETAINED_OPERATOR_ROLE_NAMES } from "./retained-operator-inventory.mjs";
import { verifyRetainedOperatorEnforcement } from "./retained-operator-enforcement.mjs";
import {
  DENY_DANGEROUS_POLICY_NAME,
  DEPLOY_ROLE_NAME,
  QUARANTINE_POLICY_NAME,
  ROLLOUT_SHUTDOWN_GRACE_MS,
  WORKLOAD_BOUNDARY_POLICY_NAME,
  WORKLOAD_BOUNDARY_STACK_NAME,
  expectedRolePatterns,
  loadRolePolicyDocuments,
  quarantinePolicyDocument,
  validateProductionRuntimeBindings,
  verifyLambdaExecutionRoleTrustPolicy,
  verifyPermanentEnforcementDocuments,
  verifyQuarantinePolicy,
} from "./workload-permissions-boundary.mjs";
import {
  remainingCommandTimeout,
  runBoundedCommand,
} from "./bounded-subprocess.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const rolloutContract = JSON.parse(
  readFileSync(
    resolve(repoRoot, "scripts/workload-permissions-boundary-contract.json"),
    "utf8",
  ),
);
export const QUARANTINE_PROBE_ACTIONS = Object.freeze(
  [...rolloutContract.quarantineProbeActions].sort(),
);
export const AWS_CLI_TIMEOUT_MS = 60_000;
export const DEPLOY_COMMAND_TIMEOUT_MS = 20 * 60_000;
const MAX_SERVICE_PAGES = 100;
const MAX_SERVICE_ITEMS = 10_000;
const OPERATOR_STACK_REGION = "us-west-2";
const RECOVERY_AWS_CLI_TIMEOUT_MS = 5_000;

function commandLabel(args) {
  return args.slice(0, 2).join(" ");
}

export async function invokeAwsCli(
  args,
  { signal, timeoutMs = AWS_CLI_TIMEOUT_MS } = {},
) {
  const result = await runBoundedCommand(
    "aws",
    [...args, "--output", "json", "--no-cli-pager"],
    {
      env: process.env,
      signal,
      timeoutMs,
    },
  );
  if (result.status !== 0) {
    throw new Error(`AWS command failed: ${commandLabel(args)}`);
  }
  if (result.stdout.trim() === "") return {};
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error(`AWS command returned invalid JSON: ${commandLabel(args)}`);
  }
}

async function deployRoleEnforcement({
  signal,
  timeoutMs = DEPLOY_COMMAND_TIMEOUT_MS,
} = {}) {
  const result = await runBoundedCommand(
    "bash",
    [resolve(repoRoot, "scripts/deploy-github-role.sh"), "--update"],
    {
      cwd: repoRoot,
      env: {
        ...process.env,
        STACK_NAME: DEPLOY_ROLE_NAME,
        WORKLOAD_BOUNDARY_SKIP_DOTENV: "true",
      },
      signal,
      timeoutMs,
    },
  );
  if (result.status !== 0) {
    throw new Error("deploy-role enforcement update failed");
  }
}

async function deployBoundaryStack({
  signal,
  timeoutMs = DEPLOY_COMMAND_TIMEOUT_MS,
} = {}) {
  const result = await runBoundedCommand(
    "bash",
    [
      resolve(repoRoot, "scripts/deploy-workload-permissions-boundary.sh"),
      "--guarded-update",
    ],
    {
      cwd: repoRoot,
      env: {
        ...process.env,
        WORKLOAD_BOUNDARY_SKIP_DOTENV: "true",
      },
      signal,
      timeoutMs,
    },
  );
  if (result.status !== 0) {
    throw new Error("guarded boundary deployment failed");
  }
}

function pageMarker(response, field) {
  if (
    !response ||
    typeof response !== "object" ||
    !Array.isArray(response[field]) ||
    typeof response.IsTruncated !== "boolean"
  ) {
    throw new Error("AWS IAM pagination response is malformed");
  }
  if (response.IsTruncated !== true) return undefined;
  if (typeof response.Marker !== "string" || response.Marker.length === 0) {
    throw new Error("AWS IAM pagination page is truncated without a marker");
  }
  return response.Marker;
}

function markerArgs(marker) {
  return marker === undefined ? [] : ["--marker", marker];
}

async function collectBoundedPages({
  decodePage,
  fetchPage,
  label,
  maxItems = MAX_SERVICE_ITEMS,
  maxPages = MAX_SERVICE_PAGES,
}) {
  const items = [];
  const seenTokens = new Set();
  let token;
  let pageCount = 0;
  do {
    pageCount += 1;
    if (pageCount > maxPages) {
      throw new Error(`${label} exceeded the page limit`);
    }
    const decoded = decodePage(await fetchPage(token));
    if (
      !decoded ||
      !Array.isArray(decoded.items) ||
      (decoded.nextToken !== undefined &&
        (typeof decoded.nextToken !== "string" ||
          decoded.nextToken.length === 0))
    ) {
      throw new Error(`${label} response is malformed`);
    }
    items.push(...decoded.items);
    if (items.length > maxItems) {
      throw new Error(`${label} exceeded the item limit`);
    }
    token = decoded.nextToken;
    if (token !== undefined) {
      if (seenTokens.has(token)) {
        throw new Error(`${label} pagination is malformed`);
      }
      seenTokens.add(token);
    }
  } while (token !== undefined);
  return items;
}

async function retry(check, { attempts, sleep }) {
  if (!Number.isInteger(attempts) || attempts < 1 || attempts > 100) {
    throw new Error("retry attempt limit is invalid");
  }
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    if (await check()) return true;
    if (attempt < attempts) await sleep(2_000);
  }
  return false;
}

function defaultSleep(milliseconds) {
  return new Promise((resolvePromise) => {
    setTimeout(resolvePromise, milliseconds);
  });
}

function serializePolicyInput(document) {
  if (typeof document === "string") {
    return document.trimStart().startsWith("{")
      ? document
      : decodeURIComponent(document);
  }
  return JSON.stringify(document);
}

export async function resolveAwsIdentity(invokeAws = invokeAwsCli) {
  const response = await invokeAws(["sts", "get-caller-identity"]);
  const accountId = response.Account;
  const partition = /^arn:([^:]+):/u.exec(response.Arn ?? "")?.[1];
  if (
    typeof accountId !== "string" ||
    !/^[0-9]{12}$/u.test(accountId) ||
    typeof partition !== "string" ||
    !/^[a-z0-9-]+$/u.test(partition)
  ) {
    throw new Error("AWS caller identity is malformed");
  }
  return { accountId, partition };
}

export function createAwsCliAdapter({
  identity,
  applicationRegion = process.env.WORKLOAD_BOUNDARY_APPLICATION_REGION,
  decisionArtifactBucketName = process.env.MEM9_DECISION_ARTIFACT_BUCKET || `mem9-audit-${identity?.accountId}`,
  invokeAws = invokeAwsCli,
  deployBoundary = deployBoundaryStack,
  deployEnforcement = deployRoleEnforcement,
  activateProductionBoundary = async () => {
    throw new Error("production boundary activation is not configured");
  },
  verifyFinalGithubInterlock = async () => {
    throw new Error("final GitHub interlock is not configured");
  },
  resumeDeployments = async () => {
    throw new Error("deployment resume is not configured");
  },
  consistencyAttempts = 10,
  deadlineAt,
  signal,
  sleep = defaultSleep,
}) {
  if (!/^[a-z]{2}(?:-gov)?-[a-z0-9-]+-[0-9]+$/u.test(applicationRegion)) {
    throw new Error("application region is malformed");
  }
  const { accountId, partition } = identity;
  validateDecisionArtifactBucketName(decisionArtifactBucketName);
  const [primaryRolePattern] = expectedRolePatterns(identity);
  const denyPolicyArn =
    `arn:${partition}:iam::${accountId}:policy/` +
    DENY_DANGEROUS_POLICY_NAME;
  const probeRoleArn = `${primaryRolePattern.slice(0, -1)}quarantine-probe`;
  const boundaryPolicyArn = `arn:${partition}:iam::${accountId}:policy/${WORKLOAD_BOUNDARY_POLICY_NAME}`;
  const boundaryStackArn =
    `arn:${partition}:cloudformation:us-west-2:${accountId}:stack/` +
    `${WORKLOAD_BOUNDARY_STACK_NAME}/propagation-probe`;
  const namespaceOperatorStackArn =
    `arn:${partition}:cloudformation:us-west-2:${accountId}:stack/` +
    "memory-namespace-operator-mem9-on-aws/propagation-probe";
  const ecrScanningStackArn =
    `arn:${partition}:cloudformation:us-west-2:${accountId}:stack/` +
    "ecr-registry-scanning-mem9-on-aws/propagation-probe";
  const vpcProxyRoleArn =
    `arn:${partition}:iam::${accountId}:role/` +
    "mem9-on-aws-prod-Mem9ProxyFnRole-propagation-probe";
  const awsTimeout = () =>
    remainingCommandTimeout({
      deadlineAt,
      maximumMs: AWS_CLI_TIMEOUT_MS,
    });
  const deployTimeout = () =>
    remainingCommandTimeout({
      deadlineAt,
      maximumMs: DEPLOY_COMMAND_TIMEOUT_MS,
    });
  const invokeAwsCommand = (args) =>
    invokeAws(args, {
      signal,
      timeoutMs: awsTimeout(),
    });
  const retainedOperators = createRetainedOperatorInventory({
    invokeAws: invokeAwsCommand, identity, applicationRegion,
  });

  const deploymentRoleNames = [DEPLOY_ROLE_NAME, `${DEPLOY_ROLE_NAME}-preview`, `${DEPLOY_ROLE_NAME}-prod`].sort();
  let deploymentRoleSnapshot;
  const deploymentError = () => {throw new Error("deployment-role owner identity is malformed or changed");};
  const canonical = value => Array.isArray(value)
    ? value.map(canonical).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)))
    : value && typeof value === "object"
      ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]))
      : value;
  const roleNamesForVerification = () => deploymentRoleSnapshot === undefined ? [DEPLOY_ROLE_NAME] : deploymentRoleNames;

  async function resolveDeploymentRoles() {
    await retainedOperators.verifyDeploymentRoleCatalog();
    const response = await invokeAwsCommand([
      "cloudformation", "describe-stacks", "--stack-name", DEPLOY_ROLE_NAME,
      "--region", OPERATOR_STACK_REGION,
    ]);
    if (response.NextToken || response.Stacks?.length !== 1) deploymentError();
    const stack = response.Stacks[0];
    const prefix = `arn:${partition}:cloudformation:${OPERATOR_STACK_REGION}:${accountId}:stack/${DEPLOY_ROLE_NAME}/`;
    if (stack.StackName !== DEPLOY_ROLE_NAME || !stack.StackId?.startsWith(prefix) ||
      !/^[A-Za-z0-9-]+$/.test(stack.StackId.slice(prefix.length)) ||
      !["CREATE_COMPLETE", "UPDATE_COMPLETE"].includes(stack.StackStatus) || stack.ParentId || stack.RootId || stack.RoleARN) deploymentError();
    const fields = (rows, key, value) => {
      if (!Array.isArray(rows)) deploymentError();
      const result = new Map();
      for (const row of rows) {
        if (!row || typeof row[key] !== "string" || typeof row[value] !== "string" || result.has(row[key])) deploymentError();
        result.set(row[key], row[value]);
      }
      return result;
    };
    const parameters = fields(stack.Parameters, "ParameterKey", "ParameterValue");
    if (parameters.get("ApplicationRegion") !== applicationRegion ||
      parameters.get("ProjectName") !== "mem9-on-aws" || parameters.get("GitHubRepo") !== "mem9-on-aws" ||
      !["true", "false"].includes(parameters.get("LegacyRoleEnabled"))) deploymentError();
    if (parameters.has("DecisionArtifactBucketName") && parameters.get("DecisionArtifactBucketName") !== decisionArtifactBucketName) deploymentError();
    const outputs = fields(stack.Outputs, "OutputKey", "OutputValue");
    for (const [key, name] of [["LegacyRoleArn", DEPLOY_ROLE_NAME], ["RoleArn", DEPLOY_ROLE_NAME],
      ["PreviewRoleArn", `${DEPLOY_ROLE_NAME}-preview`], ["ProductionRoleArn", `${DEPLOY_ROLE_NAME}-prod`]]) {
      if (outputs.get(key) !== `arn:${partition}:iam::${accountId}:role/${name}`) deploymentError();
    }
    const roles = [];
    for (const name of deploymentRoleNames) {
      const {Role: role} = await invokeAwsCommand(["iam", "get-role", "--role-name", name, "--region", "us-east-1"]);
      if (!role || role.RoleName !== name || role.Arn !== `arn:${partition}:iam::${accountId}:role/${name}` ||
        typeof role.RoleId !== "string" || !role.RoleId || role.RoleId.length > 128) deploymentError();
      let trust = role.AssumeRolePolicyDocument;
      if (typeof trust === "string") {
        try {trust = JSON.parse(trust.trimStart().startsWith("{") ? trust : decodeURIComponent(trust));}
        catch {deploymentError();}
      }
      if (!trust || typeof trust !== "object" || Array.isArray(trust)) deploymentError();
      roles.push({name, arn: role.Arn, id: role.RoleId, trust,
        boundary: role.PermissionsBoundary?.PermissionsBoundaryArn ?? null,
        maximumSession: role.MaxSessionDuration ?? null, tags: role.Tags ?? []});
    }
    // This pins identity and stability, not approval of the trust policies.
    // Their owner/purpose and effective-permission review remain independent.
    const snapshot = JSON.stringify(canonical({stackId: stack.StackId,
      legacyRoleEnabled: parameters.get("LegacyRoleEnabled"), roles}));
    if (deploymentRoleSnapshot !== undefined && deploymentRoleSnapshot !== snapshot) deploymentError();
    deploymentRoleSnapshot = snapshot;
    return [...deploymentRoleNames];
  }

  async function putQuarantine(
    invokeCommand,
    { roleName, policyName, policyDocument },
  ) {
    if (
      !deploymentRoleNames.includes(roleName) ||
      policyName !== QUARANTINE_POLICY_NAME ||
      !verifyQuarantinePolicy(policyDocument)
    ) {
      throw new Error("refusing malformed quarantine request");
    }
    await invokeCommand([
      "iam",
      "put-role-policy",
      "--role-name",
      roleName,
      "--policy-name",
      policyName,
      "--policy-document",
      JSON.stringify(policyDocument),
    ]);
  }

  function verifyQuarantine(invokeCommand, retrySleep = sleep, roleName = DEPLOY_ROLE_NAME) {
    return retry(
      async () => {
        let response;
        let simulation;
        try {
          response = await invokeCommand([
            "iam",
            "get-role-policy",
            "--role-name",
            roleName,
            "--policy-name",
            QUARANTINE_POLICY_NAME,
          ]);
          if (!verifyQuarantinePolicy(response.PolicyDocument)) {
            return false;
          }
          simulation = await invokeCommand([
            "iam",
            "simulate-custom-policy",
            "--policy-input-list",
            serializePolicyInput(response.PolicyDocument),
            "--action-names",
            ...QUARANTINE_PROBE_ACTIONS,
          ]);
        } catch {
          return false;
        }
        if (!Array.isArray(simulation.EvaluationResults)) {
          return false;
        }
        if (
          simulation.EvaluationResults.length !==
          QUARANTINE_PROBE_ACTIONS.length
        ) {
          return false;
        }
        const expected = new Set(
          QUARANTINE_PROBE_ACTIONS.map((action) => action.toLowerCase()),
        );
        const decisions = new Map();
        for (const result of simulation.EvaluationResults) {
          if (
            !result ||
            typeof result.EvalActionName !== "string" ||
            result.EvalDecision !== "explicitDeny"
          ) {
            return false;
          }
          const action = result.EvalActionName.toLowerCase();
          if (!expected.has(action) || decisions.has(action)) return false;
          decisions.set(action, result.EvalDecision);
        }
        if (decisions.size !== expected.size) return false;
        try {
          const postSimulation = await invokeCommand([
            "iam",
            "get-role-policy",
            "--role-name",
            roleName,
            "--policy-name",
            QUARANTINE_POLICY_NAME,
          ]);
          return verifyQuarantinePolicy(postSimulation.PolicyDocument);
        } catch {
          return false;
        }
      },
      { attempts: consistencyAttempts, sleep: retrySleep },
    );
  }

  async function verifyQuarantines(invokeCommand, retrySleep = sleep, roleNames = roleNamesForVerification()) {
    const results = await Promise.all(roleNames.map(roleName => verifyQuarantine(invokeCommand, retrySleep, roleName)));
    return results.every(Boolean);
  }

  function createRecoveryContext() {
    const now = Date.now();
    const hardDeadlineAt =
      deadlineAt === undefined
        ? now + ROLLOUT_SHUTDOWN_GRACE_MS
        : deadlineAt + ROLLOUT_SHUTDOWN_GRACE_MS;
    const recoveryDeadlineAt = Math.min(
      hardDeadlineAt,
      now + ROLLOUT_SHUTDOWN_GRACE_MS,
    );
    if (!Number.isFinite(recoveryDeadlineAt) || recoveryDeadlineAt <= now) {
      throw new Error("deploy-role quarantine recovery deadline exceeded");
    }
    const recoverySignal = AbortSignal.timeout(
      Math.max(1, Math.floor(recoveryDeadlineAt - now)),
    );
    return {
      invokeCommand: (args) =>
        invokeAws(args, {
          signal: recoverySignal,
          timeoutMs: remainingCommandTimeout({
            deadlineAt: recoveryDeadlineAt,
            maximumMs: RECOVERY_AWS_CLI_TIMEOUT_MS,
          }),
        }),
      sleep: (milliseconds) => {
        const remaining = recoveryDeadlineAt - Date.now();
        if (remaining <= 0) {
          throw new Error("deploy-role quarantine recovery deadline exceeded");
        }
        return sleep(Math.min(milliseconds, remaining));
      },
    };
  }

  function operationalContextExpired() {
    return (
      signal?.aborted === true ||
      (deadlineAt !== undefined && Date.now() >= deadlineAt)
    );
  }

  async function readBoundaryStackParameters() {
    const boundaryStackResponse = await invokeAwsCommand([
      "cloudformation",
      "describe-stacks",
      "--stack-name",
      WORKLOAD_BOUNDARY_STACK_NAME,
      "--region",
      OPERATOR_STACK_REGION,
    ]);
    if (
      !Array.isArray(boundaryStackResponse.Stacks) ||
      boundaryStackResponse.Stacks.length !== 1
    ) {
      throw new Error("workload boundary stack response is malformed");
    }
    const boundaryStack = boundaryStackResponse.Stacks[0];
    if (
      !boundaryStack ||
      !["CREATE_COMPLETE", "UPDATE_COMPLETE"].includes(
        boundaryStack.StackStatus,
      ) ||
      !Array.isArray(boundaryStack.Parameters)
    ) {
      throw new Error("workload boundary stack response is malformed");
    }
    const boundaryParameters = new Map();
    for (const parameter of boundaryStack.Parameters) {
      if (
        !parameter ||
        typeof parameter.ParameterKey !== "string" ||
        typeof parameter.ParameterValue !== "string" ||
        boundaryParameters.has(parameter.ParameterKey)
      ) {
        throw new Error("workload boundary stack response is malformed");
      }
      boundaryParameters.set(parameter.ParameterKey, parameter.ParameterValue);
    }
    return boundaryParameters;
  }

  async function removeQuarantine({roleName, policyName}) {
    if (!deploymentRoleNames.includes(roleName) || policyName !== QUARANTINE_POLICY_NAME) deploymentError();
    let deletionError;
    try {
      await invokeAwsCommand([
        "iam",
        "delete-role-policy",
        "--role-name",
        roleName,
        "--policy-name",
        policyName,
      ]);
    } catch (error) {
      deletionError = error;
    }
    let absenceError;
    let absent = false;
    if (!deletionError) {
      try {
        absent = await retry(
          async () => {
            try {
              const names = await collectBoundedPages({
                decodePage: (page) => ({
                  items: page?.policyNames,
                  nextToken: page?.marker,
                }),
                fetchPage: (marker) =>
                  adapter.listInlinePolicies({ roleName, marker }),
                label: "quarantine policy listing",
              });
              return !names.includes(policyName);
            } catch (error) {
              if (operationalContextExpired()) throw error;
              return false;
            }
          },
          { attempts: consistencyAttempts, sleep },
        );
      } catch (error) {
        absenceError = error;
      }
    }
    if (deletionError || absenceError || !absent) {
      throw new AggregateError([deletionError, absenceError].filter(Boolean), "deploy-role quarantine removal was not observed");
    }
  }

  const adapter = {
    resolveDeploymentRoles,

    async verifyRetainedOperators() {
      await retainedOperators.verify();
      return true;
    },

    async verifyRetainedOperatorEnforcement({ roleNames }) {
      await retainedOperators.verify();
      return verifyRetainedOperatorEnforcement({
        invokeAws: invokeAwsCommand, identity, roleNames,
      });
    },

    async putQuarantine(request) {
      await putQuarantine(invokeAwsCommand, request);
    },

    async verifyQuarantine() {
      return verifyQuarantines(invokeAwsCommand);
    },

    async verifyBoundaryRegion() {
      const boundaryParameters = await readBoundaryStackParameters();
      if (boundaryParameters.get("ApplicationRegion") !== applicationRegion) {
        throw new Error("workload boundary application region is mismatched");
      }
      if (boundaryParameters.get("DecisionArtifactBucketName") !== decisionArtifactBucketName) {
        throw new Error("workload boundary artifact bucket is mismatched");
      }
    },

    async verifyProductionRuntimeBindings() {
      const boundaryParameters = await readBoundaryStackParameters();
      if (
        boundaryParameters.get("ApplicationRegion") !== applicationRegion ||
        !boundaryParameters.has("BedrockProjectArn")
      ) {
        throw new Error("workload boundary stack project is mismatched");
      }
      const bedrockProjectArn = boundaryParameters.get("BedrockProjectArn");

      const parameterNames = {
        bootstrapTaskDefinition: "/mem9-on-aws/prod/bootstrap/task-def-arn",
        cluster: "/mem9-on-aws/prod/ecs/cluster-name",
        gateway: "/mem9-on-aws/prod/gateway/id",
        service: "/mem9-on-aws/prod/ecs/service-name",
      };
      const parameterResponse = await invokeAwsCommand([
        "ssm",
        "get-parameters",
        "--region",
        applicationRegion,
        "--names",
        ...Object.values(parameterNames),
      ]);
      if (
        !Array.isArray(parameterResponse.Parameters) ||
        !Array.isArray(parameterResponse.InvalidParameters) ||
        parameterResponse.InvalidParameters.length !== 0
      ) {
        throw new Error("production parameter read response is malformed");
      }
      const parameters = new Map();
      for (const parameter of parameterResponse.Parameters) {
        if (
          !parameter ||
          typeof parameter.Name !== "string" ||
          !Object.values(parameterNames).includes(parameter.Name) ||
          typeof parameter.Value !== "string" ||
          parameter.Value.length === 0 ||
          parameters.has(parameter.Name)
        ) {
          throw new Error("production parameter read response is malformed");
        }
        parameters.set(parameter.Name, parameter.Value);
      }
      if (parameters.size !== Object.keys(parameterNames).length) {
        throw new Error("production parameter read response is incomplete");
      }
      const cluster = parameters.get(parameterNames.cluster);
      const serviceName = parameters.get(parameterNames.service);
      const bootstrapTaskDefinitionArn = parameters.get(
        parameterNames.bootstrapTaskDefinition,
      );
      const gatewayId = parameters.get(parameterNames.gateway);

      const serviceResponse = await invokeAwsCommand([
        "ecs",
        "describe-services",
        "--region",
        applicationRegion,
        "--cluster",
        cluster,
        "--services",
        serviceName,
      ]);
      if (
        !Array.isArray(serviceResponse.failures) ||
        serviceResponse.failures.length !== 0 ||
        !Array.isArray(serviceResponse.services) ||
        serviceResponse.services.length !== 1
      ) {
        throw new Error("production ECS service response is malformed");
      }
      const service = serviceResponse.services[0];
      if (
        !service ||
        service.serviceName !== serviceName ||
        typeof service.taskDefinition !== "string" ||
        !Array.isArray(service.deployments) ||
        service.deployments.length === 0 ||
        service.deployments.some(
          (deployment) =>
            !deployment ||
            typeof deployment.taskDefinition !== "string" ||
            typeof deployment.status !== "string",
        )
      ) {
        throw new Error("production ECS service response is malformed");
      }
      const primaryDeployments = service.deployments.filter(
        (deployment) => deployment.status === "PRIMARY",
      );
      if (
        primaryDeployments.length !== 1 ||
        primaryDeployments[0].taskDefinition !== service.taskDefinition
      ) {
        throw new Error(
          "production ECS service PRIMARY deployment is malformed",
        );
      }

      const listTasks = (desiredStatus) =>
        collectBoundedPages({
          decodePage: (response) => {
            if (
              !response ||
              !Array.isArray(response.taskArns) ||
              response.taskArns.some(
                (taskArn) =>
                  typeof taskArn !== "string" || taskArn.length === 0,
              )
            ) {
              throw new Error(
                "production ECS task listing response is malformed",
              );
            }
            return {
              items: response.taskArns,
              nextToken: response.nextToken,
            };
          },
          fetchPage: (nextToken) =>
            invokeAwsCommand([
              "ecs",
              "list-tasks",
              "--region",
              applicationRegion,
              "--cluster",
              cluster,
              "--service-name",
              serviceName,
              "--desired-status",
              desiredStatus,
              "--no-paginate",
              ...(nextToken ? ["--next-token", nextToken] : []),
            ]),
          label: "production ECS task listing",
        });
      const runningTaskArns = await listTasks("RUNNING");
      const pendingTaskArns = await listTasks("PENDING");
      if (runningTaskArns.length === 0) {
        throw new Error("production ECS service has no running task");
      }
      const taskArns = [...new Set([...runningTaskArns, ...pendingTaskArns])];
      const tasks = [];
      for (let offset = 0; offset < taskArns.length; offset += 100) {
        const batch = taskArns.slice(offset, offset + 100);
        const response = await invokeAwsCommand([
          "ecs",
          "describe-tasks",
          "--region",
          applicationRegion,
          "--cluster",
          cluster,
          "--tasks",
          ...batch,
        ]);
        if (
          !Array.isArray(response.failures) ||
          response.failures.length !== 0 ||
          !Array.isArray(response.tasks)
        ) {
          throw new Error("production ECS task response is malformed");
        }
        tasks.push(...response.tasks);
      }
      const taskArnSet = new Set(taskArns);
      const describedTaskArns = new Set();
      for (const task of tasks) {
        if (
          !task ||
          typeof task.taskArn !== "string" ||
          !taskArnSet.has(task.taskArn) ||
          describedTaskArns.has(task.taskArn) ||
          typeof task.taskDefinitionArn !== "string"
        ) {
          throw new Error("production ECS task response is malformed");
        }
        describedTaskArns.add(task.taskArn);
      }
      if (describedTaskArns.size !== taskArns.length) {
        throw new Error("production ECS task response is incomplete");
      }

      const serviceTaskDefinitionArns = [
        ...new Set([
          service.taskDefinition,
          ...service.deployments.map((deployment) => deployment.taskDefinition),
          ...tasks.map((task) => task.taskDefinitionArn),
        ]),
      ];
      const taskDefinitionArns = [
        ...new Set([...serviceTaskDefinitionArns, bootstrapTaskDefinitionArn]),
      ].sort();
      const taskDefinitions = [];
      for (const taskDefinitionArn of taskDefinitionArns) {
        const response = await invokeAwsCommand([
          "ecs",
          "describe-task-definition",
          "--region",
          applicationRegion,
          "--task-definition",
          taskDefinitionArn,
        ]);
        if (!response || typeof response.taskDefinition !== "object") {
          throw new Error(
            "production ECS task definition response is malformed",
          );
        }
        taskDefinitions.push(response.taskDefinition);
      }

      const lambdaFunctions = (
        await collectBoundedPages({
          decodePage: (response) => {
            if (!response || !Array.isArray(response.Functions)) {
              throw new Error(
                "production Lambda listing response is malformed",
              );
            }
            return {
              items: response.Functions,
              nextToken: response.NextMarker,
            };
          },
          fetchPage: (marker) =>
            invokeAwsCommand([
              "lambda",
              "list-functions",
              "--region",
              applicationRegion,
              "--no-paginate",
              ...(marker ? ["--marker", marker] : []),
            ]),
          label: "production Lambda listing",
        })
      ).filter(({ FunctionName }) =>
        FunctionName?.startsWith("mem9-on-aws-prod-"),
      );

      const gateway = await invokeAwsCommand([
        "bedrock-agentcore-control",
        "get-gateway",
        "--region",
        applicationRegion,
        "--gateway-identifier",
        gatewayId,
      ]);

      return validateProductionRuntimeBindings({
        accountId,
        applicationRegion,
        bedrockProjectArn,
        bootstrapTaskDefinitionArn,
        gateway,
        gatewayId,
        lambdaFunctions,
        partition,
        serviceTaskDefinitionArns,
        taskDefinitions,
      });
    },

    async listAttachedPolicies({ roleName, marker }) {
      const response = await invokeAwsCommand([
        "iam",
        "list-attached-role-policies",
        "--role-name",
        roleName,
        "--no-paginate",
        ...markerArgs(marker),
      ]);
      const markerValue = pageMarker(response, "AttachedPolicies");
      return {
        policies: response.AttachedPolicies.map((policy) => ({
          arn: policy.PolicyArn,
        })),
        marker: markerValue,
      };
    },

    async getManagedPolicy({ policyArn }) {
      const response = await invokeAwsCommand([
        "iam",
        "get-policy",
        "--policy-arn",
        policyArn,
      ]);
      return { defaultVersionId: response.Policy?.DefaultVersionId };
    },

    async getManagedPolicyVersion({ policyArn, versionId }) {
      const response = await invokeAwsCommand([
        "iam",
        "get-policy-version",
        "--policy-arn",
        policyArn,
        "--version-id",
        versionId,
      ]);
      return { document: response.PolicyVersion?.Document };
    },

    async listInlinePolicies({ roleName, marker }) {
      const response = await invokeAwsCommand([
        "iam",
        "list-role-policies",
        "--role-name",
        roleName,
        "--no-paginate",
        ...markerArgs(marker),
      ]);
      const markerValue = pageMarker(response, "PolicyNames");
      return {
        policyNames: response.PolicyNames,
        marker: markerValue,
      };
    },

    async getInlinePolicy({ roleName, policyName }) {
      const response = await invokeAwsCommand([
        "iam",
        "get-role-policy",
        "--role-name",
        roleName,
        "--policy-name",
        policyName,
      ]);
      return { document: response.PolicyDocument };
    },

    async listRoles({ marker }) {
      const response = await invokeAwsCommand([
        "iam",
        "list-roles",
        "--no-paginate",
        // --max-items is a CLI paginator option. Set the service page size
        // explicitly while retaining raw IsTruncated/Marker handling.
        "--cli-input-json",
        '{"MaxItems":1000}',
        ...markerArgs(marker),
      ]);
      const markerValue = pageMarker(response, "Roles");
      await retainedOperators.verify();
      const roles = retainedOperators.filterRoles(response.Roles);
      return {
        roles: roles.map((role) => ({
          arn: role.Arn,
          assumeRolePolicyDocument: role.AssumeRolePolicyDocument,
          name: role.RoleName,
        })),
        marker: markerValue,
      };
    },

    async putRoleBoundary({ roleName, permissionsBoundary }) {
      if (RETAINED_OPERATOR_ROLE_NAMES.includes(roleName)) {
        throw new Error("retained operator cannot receive the workload boundary");
      }
      await invokeAwsCommand([
        "iam",
        "put-role-permissions-boundary",
        "--role-name",
        roleName,
        "--permissions-boundary",
        permissionsBoundary,
      ]);
    },

    async getRole({ roleName }) {
      const response = await invokeAwsCommand([
        "iam",
        "get-role",
        "--role-name",
        roleName,
      ]);
      return {
        assumeRolePolicyDocument: response.Role?.AssumeRolePolicyDocument,
        permissionsBoundaryArn:
          response.Role?.PermissionsBoundary?.PermissionsBoundaryArn,
      };
    },

    async updateAssumeRolePolicy({ roleName, policyDocument }) {
      if (!verifyLambdaExecutionRoleTrustPolicy(policyDocument)) {
        throw new Error("refusing malformed Lambda trust repair");
      }
      await invokeAwsCommand([
        "iam",
        "update-assume-role-policy",
        "--role-name",
        roleName,
        "--policy-document",
        JSON.stringify(policyDocument),
      ]);
    },

    async deployBoundary() {
      await deployBoundary({ signal, timeoutMs: deployTimeout() });
    },

    async deployPermanentEnforcement() {
      await deployEnforcement({ signal, timeoutMs: deployTimeout() });
    },

    async activateProductionBoundary() {
      await activateProductionBoundary();
    },

    async verifyFinalGithubInterlock({ reviewedCommit }) {
      await verifyFinalGithubInterlock({ reviewedCommit });
    },

    async resumeDeployments() {
      await resumeDeployments();
    },

    async verifyPermanentEnforcement({ boundaryArn, roleNames = roleNamesForVerification() }) {
      if (!Array.isArray(roleNames) || JSON.stringify(roleNames) !== JSON.stringify(roleNamesForVerification())) deploymentError();
      const parameterArn = `arn:${partition}:ssm:${applicationRegion}:${accountId}:parameter/mem9-on-aws/prod/consolidation-runtime/data-release`;
      const bucketArn = `arn:${partition}:s3:::${decisionArtifactBucketName}`;
      const probes = [
        {
          action: "iam:CreatePolicyVersion",
          resource: boundaryPolicyArn,
        },
        {
          action: "cloudformation:UpdateStack",
          resource: boundaryStackArn,
        },
        {
          action: "cloudformation:UpdateStack",
          resource: namespaceOperatorStackArn,
        },
        {
          action: "cloudformation:UpdateStack",
          resource: ecrScanningStackArn,
        },
        {
          action: "iam:CreateRole",
          resource: probeRoleArn,
        },
        {
          action: "iam:PutRolePolicy",
          resource: probeRoleArn,
        },
        {
          action: "iam:DeleteRolePermissionsBoundary",
          resource: probeRoleArn,
        },
        {
          action: "iam:PassRole",
          resource: vpcProxyRoleArn,
        },
        ...["ssm:PutParameter", "ssm:DeleteParameter", "ssm:LabelParameterVersion", "ssm:UnlabelParameterVersion"]
          .map(action => ({action, resource: parameterArn})),
        {action: "s3:PutObject", resource: `${bucketArn}/data-authorizations/propagation-probe`},
        {action: "s3:PutBucketPolicy", resource: bucketArn},
        {action: "s3:PutObject", resource: `arn:${partition}:s3:${applicationRegion}:${accountId}:accesspoint/propagation-probe/object/data-authorizations/probe`},
        {action: "s3:CreateAccessPoint", resource: "*"},
        {action: "cloudformation:UpdateStack", resource: `arn:${partition}:cloudformation:${applicationRegion}:${accountId}:stack/decision-artifact-bucket-mem9-on-aws/propagation-probe`},
      ];
      const verifyRole = async (roleName) => {
        const verifyLivePolicyDocuments = async () => {
          const documents = await loadRolePolicyDocuments(
            adapter,
            roleName,
          );
          verifyPermanentEnforcementDocuments(documents, {
            accountId,
            boundaryArn,
            partition,
            applicationRegion,
            decisionArtifactBucketName,
          });
        };
        const readDenyPolicyState = async ({ includeDocument = false } = {}) => {
          const attachedPolicies = await collectBoundedPages({
            decodePage: (page) => ({
              items: page?.policies,
              nextToken: page?.marker,
            }),
            fetchPage: (marker) =>
              adapter.listAttachedPolicies({
                marker,
                roleName,
              }),
            label: "deploy-role attached policy listing",
          });
          const denyPolicies = attachedPolicies.filter(
            (policy) => policy?.arn === denyPolicyArn,
          );
          if (denyPolicies.length !== 1) return undefined;
          const metadata = await adapter.getManagedPolicy({
            policyArn: denyPolicyArn,
          });
          if (
            !metadata ||
            typeof metadata.defaultVersionId !== "string" ||
            !/^v[1-9][0-9]*$/u.test(metadata.defaultVersionId)
          ) {
            return undefined;
          }
          if (!includeDocument) {
            return { defaultVersionId: metadata.defaultVersionId };
          }
          const version = await adapter.getManagedPolicyVersion({
            policyArn: denyPolicyArn,
            versionId: metadata.defaultVersionId,
          });
          if (!version?.document) return undefined;
          return {
            defaultVersionId: metadata.defaultVersionId,
            document: version.document,
          };
        };
        return retry(
          async () => {
            try {
              await verifyLivePolicyDocuments();
              const denyPolicyBefore = await readDenyPolicyState({
                includeDocument: true,
              });
              if (!denyPolicyBefore) return false;
              for (const { action, resource } of probes) {
                const response = await invokeAwsCommand([
                  "iam",
                  "simulate-custom-policy",
                  "--policy-input-list",
                  serializePolicyInput(denyPolicyBefore.document),
                  "--action-names",
                  action,
                  "--resource-arns",
                  resource,
                  "--context-entries",
                  "ContextKeyName=iam:PassedToService," +
                    "ContextKeyValues=ecs-tasks.amazonaws.com," +
                    "ContextKeyType=string",
                ]);
                if (
                  (Object.hasOwn(response, "IsTruncated") &&
                    typeof response.IsTruncated !== "boolean") ||
                  response.IsTruncated === true ||
                  Object.hasOwn(response, "Marker") ||
                  !Array.isArray(response.EvaluationResults) ||
                  response.EvaluationResults.length !== 1
                ) {
                  return false;
                }
                const [result] = response.EvaluationResults;
                if (
                  result.EvalActionName !== action ||
                  result.EvalResourceName !== resource ||
                  result.EvalDecision !== "explicitDeny" ||
                  !Array.isArray(result.MatchedStatements) ||
                  result.MatchedStatements.length === 0
                ) {
                  return false;
                }
              }

              const denyPolicyAfter = await readDenyPolicyState();
              if (
                denyPolicyAfter?.defaultVersionId !==
                denyPolicyBefore.defaultVersionId
              ) {
                return false;
              }
              await verifyLivePolicyDocuments();
              const finalDenyPolicy = await readDenyPolicyState();
              return (
                finalDenyPolicy?.defaultVersionId ===
                denyPolicyBefore.defaultVersionId
              );
            } catch {
              return false;
            }
          },
          { attempts: consistencyAttempts, sleep },
        );
      };
      for (const roleName of roleNames) if (!(await verifyRole(roleName))) return false;
      return true;
    },

    async deleteQuarantine({roleName, policyName}) {
      if (!deploymentRoleNames.includes(roleName) || policyName !== QUARANTINE_POLICY_NAME) deploymentError();
      try {
        await removeQuarantine({roleName, policyName});
      } catch (releaseError) {
        try {
          const recovery = createRecoveryContext();
          await putQuarantine(recovery.invokeCommand, {roleName, policyName, policyDocument: quarantinePolicyDocument()});
          if (!(await verifyQuarantine(recovery.invokeCommand, recovery.sleep, roleName))) {
            throw new Error("deploy-role quarantine recovery verification failed");
          }
        } catch (recoveryError) {
          throw new AggregateError([...(releaseError instanceof AggregateError ? releaseError.errors : [releaseError]), recoveryError],
            "deploy-role quarantine removal was ambiguous and recovery failed");
        }
        throw new Error("deploy-role quarantine removal was not observed");
      }
    },

    async deleteQuarantines({roleNames, policyName}) {
      if (deploymentRoleSnapshot === undefined || policyName !== QUARANTINE_POLICY_NAME ||
        !Array.isArray(roleNames) || JSON.stringify(roleNames) !== JSON.stringify(deploymentRoleNames)) deploymentError();
      await resolveDeploymentRoles();
      try {
        for (const roleName of roleNames) await removeQuarantine({roleName, policyName});
      } catch (releaseError) {
        try {
          const recovery = createRecoveryContext();
          // Independent roles are restored together so a failed peer does not
          // consume the entire shared recovery window before others are tried.
          const results = await Promise.allSettled(roleNames.map(roleName => putQuarantine(recovery.invokeCommand, {
            roleName, policyName, policyDocument: quarantinePolicyDocument(),
          })));
          if (results.some(result => result.status === "rejected") ||
            !(await verifyQuarantines(recovery.invokeCommand, recovery.sleep, roleNames))) {
            throw new Error("deployment-role group quarantine recovery failed");
          }
        } catch (recoveryError) {
          throw new AggregateError([releaseError, recoveryError], "deployment-role group quarantine recovery failed");
        }
        throw new Error("deployment-role quarantine release was uncertain; group restored");
      }
    },
  };

  return adapter;
}
