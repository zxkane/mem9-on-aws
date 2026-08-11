#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEPLOY_ROLE_NAME,
  ROLLOUT_SHUTDOWN_GRACE_MS,
  ROLLOUT_TIMEOUT_MS as CORE_ROLLOUT_TIMEOUT_MS,
  ROLLOUT_RESUME_COMMAND,
  WORKLOAD_BOUNDARY_POLICY_NAME,
  redactedRolloutFailure,
  runBoundaryRollout,
} from "./lib/workload-permissions-boundary.mjs";
import {
  AWS_CLI_TIMEOUT_MS,
  createAwsCliAdapter,
  resolveAwsIdentity,
} from "./lib/workload-permissions-boundary-aws.mjs";
import {
  remainingCommandTimeout,
  runBoundedCommand,
} from "./lib/bounded-subprocess.mjs";

export const GH_CLI_TIMEOUT_MS = 30_000;
export const ROLLOUT_TIMEOUT_MS = CORE_ROLLOUT_TIMEOUT_MS;
export { ROLLOUT_SHUTDOWN_GRACE_MS };
const GH_RECOVERY_CLI_TIMEOUT_MS = 5_000;
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const rolloutContract = JSON.parse(
  readFileSync(
    resolve(
      repositoryRoot,
      "scripts/workload-permissions-boundary-contract.json",
    ),
    "utf8",
  ),
);
export const ROLLOUT_REPOSITORY = rolloutContract.repository;
export const NONTERMINAL_WORKFLOW_STATUSES = Object.freeze([
  ...rolloutContract.nonterminalWorkflowStatuses,
]);
const deploymentWorkflowSpecs = Object.freeze(
  rolloutContract.deploymentWorkflows.map((workflow) =>
    Object.freeze({ ...workflow }),
  ),
);
export const DEPLOYMENT_WORKFLOWS = Object.freeze(
  deploymentWorkflowSpecs.map(({ id }) => id),
);

async function runGh(
  args,
  label,
  { signal, timeoutMs = GH_CLI_TIMEOUT_MS } = {},
) {
  const result = await runBoundedCommand("gh", args, {
    env: process.env,
    signal,
    timeoutMs,
  });
  if (result.status !== 0) {
    throw new Error(label);
  }
  return result.stdout.trim();
}

function assertRepositoryIdentity() {
  if (
    process.env.GITHUB_REPOSITORY &&
    process.env.GITHUB_REPOSITORY !== ROLLOUT_REPOSITORY
  ) {
    throw new Error("GitHub repository identity mismatch");
  }
}

function requireReviewedCommit(reviewedCommit) {
  if (
    typeof reviewedCommit !== "string" ||
    !/^[0-9a-f]{40}$/u.test(reviewedCommit)
  ) {
    throw new Error("reviewed commit must be a full lowercase Git SHA");
  }
  return reviewedCommit;
}

export function parseRolloutArguments(args, now = Date.now()) {
  if (
    !Array.isArray(args) ||
    args.length !== 4 ||
    args[0] !== "--reviewed-commit" ||
    args[2] !== "--deadline-at"
  ) {
    throw new Error(
      "expected --reviewed-commit <sha> --deadline-at <epoch-ms>",
    );
  }
  const deadlineAt = Number(args[3]);
  if (
    !Number.isSafeInteger(now) ||
    !Number.isSafeInteger(deadlineAt) ||
    deadlineAt <= now ||
    deadlineAt > now + ROLLOUT_TIMEOUT_MS - ROLLOUT_SHUTDOWN_GRACE_MS
  ) {
    throw new Error("rollout deadline is invalid or expired");
  }
  return {
    deadlineAt,
    reviewedCommit: requireReviewedCommit(args[1]),
  };
}

export function createGithubMaintenanceController({
  runGh: invokeGh = runGh,
  deadlineAt,
  signal,
} = {}) {
  const repository = ROLLOUT_REPOSITORY;
  const createInvoker =
    ({
      commandDeadlineAt = deadlineAt,
      commandSignal = signal,
      maximumMs = GH_CLI_TIMEOUT_MS,
    } = {}) =>
    (args, label) =>
      invokeGh(args, label, {
        signal: commandSignal,
        timeoutMs: remainingCommandTimeout({
          deadlineAt: commandDeadlineAt,
          maximumMs,
        }),
      });
  const invokeGhCommand = createInvoker();

  async function setVariable(
    name,
    value,
    label,
    invokeCommand = invokeGhCommand,
  ) {
    await invokeCommand(
      ["variable", "set", name, "--repo", repository, "--body", value],
      `${label} update failed`,
    );
    const readback = await invokeCommand(
      [
        "variable",
        "get",
        name,
        "--repo",
        repository,
        "--json",
        "value",
        "--jq",
        ".value",
      ],
      `${label} read-back failed`,
    );
    if (readback !== value) {
      throw new Error(`${label} read-back failed`);
    }
  }

  function workflowState(workflow, invokeCommand = invokeGhCommand) {
    return invokeCommand(
      [
        "api",
        `repos/${repository}/actions/workflows/${workflow}`,
        "--jq",
        ".state",
      ],
      "deployment workflow state read failed",
    );
  }

  function createRecoveryInvoker() {
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
      throw new Error("deployment resume recovery deadline exceeded");
    }
    return createInvoker({
      commandDeadlineAt: recoveryDeadlineAt,
      commandSignal: AbortSignal.timeout(
        Math.max(1, Math.floor(recoveryDeadlineAt - now)),
      ),
      maximumMs: GH_RECOVERY_CLI_TIMEOUT_MS,
    });
  }

  return {
    async activateProductionBoundary() {
      assertRepositoryIdentity();
      await setVariable(
        "WORKLOAD_BOUNDARY_PROD_ENABLED",
        "true",
        "production boundary activation",
      );
    },

    async verifyFinalInterlock({ reviewedCommit }) {
      assertRepositoryIdentity();
      requireReviewedCommit(reviewedCommit);
      const defaultBranch = await invokeGhCommand(
        ["api", `repos/${repository}`, "--jq", ".default_branch"],
        "default branch read failed",
      );
      if (!/^[A-Za-z0-9._/-]+$/u.test(defaultBranch)) {
        throw new Error("default branch read failed");
      }
      const defaultHead = await invokeGhCommand(
        ["api", `repos/${repository}/commits/${defaultBranch}`, "--jq", ".sha"],
        "default branch head read failed",
      );
      if (defaultHead !== reviewedCommit) {
        throw new Error("default branch changed during rollout");
      }

      for (const { id, path, reviewedBlob } of deploymentWorkflowSpecs) {
        const currentBlob = await invokeGhCommand(
          [
            "api",
            "--method",
            "GET",
            `repos/${repository}/contents/${path}`,
            "-f",
            `ref=${reviewedCommit}`,
            "--jq",
            ".sha",
          ],
          "reviewed workflow blob read failed",
        );
        if (currentBlob !== reviewedBlob) {
          throw new Error(`reviewed workflow changed during rollout: ${id}`);
        }
      }

      const pauseValue = await invokeGhCommand(
        [
          "variable",
          "get",
          "DEPLOYMENT_MAINTENANCE_PAUSED",
          "--repo",
          repository,
          "--json",
          "value",
          "--jq",
          ".value",
        ],
        "deployment maintenance pause read failed",
      );
      if (pauseValue !== "true") {
        throw new Error("deployment maintenance pause changed during rollout");
      }

      for (const workflow of DEPLOYMENT_WORKFLOWS) {
        if ((await workflowState(workflow)) !== "disabled_manually") {
          throw new Error("deployment workflow is not manually disabled");
        }
        for (const status of NONTERMINAL_WORKFLOW_STATUSES) {
          const count = await invokeGhCommand(
            [
              "run",
              "list",
              "--repo",
              repository,
              "--workflow",
              workflow,
              "--status",
              status,
              "--all",
              "--limit",
              "1",
              "--json",
              "databaseId",
              "--jq",
              "length",
            ],
            "deployment workflow run read failed",
          );
          if (count !== "0") {
            throw new Error(
              "deployment workflow became nonterminal during rollout",
            );
          }
        }
      }
    },

    async resumeDeployments() {
      assertRepositoryIdentity();
      const enabledByInvocation = [];
      try {
        for (const workflow of DEPLOYMENT_WORKFLOWS) {
          const state = await workflowState(workflow);
          if (state === "disabled_manually") {
            enabledByInvocation.push(workflow);
            await invokeGhCommand(
              ["workflow", "enable", workflow, "--repo", repository],
              "deployment workflow enable failed",
            );
          } else if (state !== "active") {
            throw new Error("deployment workflow is not manually disabled");
          }
          if ((await workflowState(workflow)) !== "active") {
            throw new Error("deployment workflow enable read-back failed");
          }
        }
        await setVariable(
          "DEPLOYMENT_MAINTENANCE_PAUSED",
          "false",
          "deployment maintenance resume",
        );
      } catch (error) {
        const restoreErrors = [];
        let pauseRestored = false;
        let workflowsRestored = true;
        let invokeRecovery;
        try {
          invokeRecovery = createRecoveryInvoker();
        } catch (restoreError) {
          restoreErrors.push(restoreError);
        }
        try {
          if (!invokeRecovery) {
            throw new Error("deployment resume recovery is unavailable");
          }
          await setVariable(
            "DEPLOYMENT_MAINTENANCE_PAUSED",
            "true",
            "deployment maintenance pause restore",
            invokeRecovery,
          );
          pauseRestored = true;
        } catch (restoreError) {
          restoreErrors.push(restoreError);
        }
        for (const workflow of enabledByInvocation.reverse()) {
          try {
            if (!invokeRecovery) {
              throw new Error("deployment resume recovery is unavailable");
            }
            const state = await workflowState(workflow, invokeRecovery);
            if (state === "active") {
              await invokeRecovery(
                ["workflow", "disable", workflow, "--repo", repository],
                "deployment workflow disable rollback failed",
              );
            } else if (state !== "disabled_manually") {
              throw new Error("deployment workflow rollback state is unsafe");
            }
            if (
              (await workflowState(workflow, invokeRecovery)) !==
              "disabled_manually"
            ) {
              throw new Error(
                "deployment workflow disable rollback read-back failed",
              );
            }
          } catch (restoreError) {
            workflowsRestored = false;
            restoreErrors.push(restoreError);
          }
        }
        if (restoreErrors.length > 0) {
          const aggregate = new AggregateError(
            [error, ...restoreErrors],
            "deployment resume failed and rollback was incomplete",
          );
          aggregate.deploymentPauseRestored = pauseRestored;
          aggregate.deploymentWorkflowsRestored = workflowsRestored;
          throw aggregate;
        }
        if (error && typeof error === "object") {
          error.deploymentPauseRestored = true;
          error.deploymentWorkflowsRestored = true;
        }
        throw error;
      }
    },
  };
}

export async function executeBoundaryRollout({
  applicationRegion = process.env.WORKLOAD_BOUNDARY_APPLICATION_REGION,
  invokeAws,
  deployBoundary,
  deployEnforcement,
  activateProduction,
  verifyFinalGithubInterlock,
  resumeDeploymentWorkflows,
  reviewedCommit,
  consistencyAttempts,
  signal,
  sleep,
  createAdapter = createAwsCliAdapter,
  rollout = runBoundaryRollout,
  deadlineAt = Date.now() + ROLLOUT_TIMEOUT_MS,
} = {}) {
  if (
    typeof invokeAws !== "function" ||
    typeof activateProduction !== "function" ||
    typeof verifyFinalGithubInterlock !== "function" ||
    typeof resumeDeploymentWorkflows !== "function"
  ) {
    throw new Error("rollout side-effect dependencies must be injected");
  }
  requireReviewedCommit(reviewedCommit);
  const identity = await resolveAwsIdentity((args) =>
    invokeAws(args, {
      signal,
      timeoutMs: remainingCommandTimeout({
        deadlineAt,
        maximumMs: AWS_CLI_TIMEOUT_MS,
      }),
    }),
  );
  const boundaryArn =
    `arn:${identity.partition}:iam::${identity.accountId}:policy/` +
    WORKLOAD_BOUNDARY_POLICY_NAME;
  const adapter = createAdapter({
    applicationRegion,
    identity,
    invokeAws,
    deployBoundary,
    deployEnforcement,
    activateProductionBoundary: activateProduction,
    verifyFinalGithubInterlock,
    resumeDeployments: resumeDeploymentWorkflows,
    signal,
    consistencyAttempts,
    deadlineAt,
    sleep,
  });
  return rollout(adapter, {
    accountId: identity.accountId,
    boundaryArn,
    deployRoleName: DEPLOY_ROLE_NAME,
    partition: identity.partition,
    reviewedCommit,
    resumeCommand: ROLLOUT_RESUME_COMMAND,
    deadlineAt,
  });
}

export async function runBoundaryRolloutCli({
  execute,
  stdout = process.stdout,
  stderr = process.stderr,
  setFailureExitCode = () => {
    process.exitCode = 1;
  },
} = {}) {
  if (typeof execute !== "function") {
    throw new Error("rollout executor must be injected");
  }
  try {
    const result = await execute();
    stdout.write(
      [
        "Workload permissions-boundary rollout complete.",
        `Bounded roles verified: ${result.verifiedRoleCount}`,
        "Permanent enforcement verified; quarantine removed.",
        "",
      ].join("\n"),
    );
  } catch (error) {
    stderr.write(`${redactedRolloutFailure(error)}\n`);
    setFailureExitCode();
  }
}
