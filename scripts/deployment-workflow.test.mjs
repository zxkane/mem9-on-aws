import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const workflowPath = resolve(root, ".github/workflows/infra-ci.yml");
const rolePath = resolve(root, "infra/cloudformation/github-actions-role.yaml");
const reconcilePath = resolve(here, "reconcile-ecs-deployment.mjs");
const fakeAwsPath = resolve(here, "fixtures/fake-aws.mjs");
const tempDirs = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function runFixture(name) {
  const dir = mkdtempSync(join(tmpdir(), "mem9-reconcile-"));
  tempDirs.push(dir);
  const calls = join(dir, "calls.jsonl");
  const result = spawnSync(process.execPath, [reconcilePath, "--stage", "prod"], {
    encoding: "utf8",
    env: {
      ...process.env,
      AWS_CLI: fakeAwsPath,
      AWS_FIXTURE_FILE: resolve(here, `fixtures/reconciliation/${name}.json`),
      AWS_CALL_LOG: calls,
    },
  });
  const callRecords = readFileSync(calls, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  return { result, callRecords };
}

function actionSetForSid(source, sid) {
  const start = source.indexOf(`- Sid: ${sid}`);
  expect(start, `missing IAM Sid ${sid}`).toBeGreaterThanOrEqual(0);
  const tail = source.slice(start);
  const next = tail.slice(1).search(/\n\s+- Sid: /);
  const block = next >= 0 ? tail.slice(0, next + 1) : tail;
  return [...block.matchAll(/^\s+- ((?:ecs|ssm):[A-Za-z]+)$/gm)].map((m) => m[1]);
}

describe("workflow integration", () => {
  it("uses the tested tag selector and reconciles preview and prod deployments", () => {
    const workflow = readFileSync(workflowPath, "utf8");

    expect(workflow).toContain("node scripts/image-tags.mjs");
    expect(workflow.match(/node scripts\/reconcile-ecs-deployment\.mjs/g)).toHaveLength(2);
  });

  it("routes a reconciliation failure through the existing prod failure reporter", () => {
    const workflow = readFileSync(workflowPath, "utf8");
    const reconcile = workflow.indexOf("name: Reconcile prod ECS deployment");
    const failureReporter = workflow.indexOf("name: Create issue on prod deploy failure");

    expect(reconcile).toBeGreaterThanOrEqual(0);
    expect(failureReporter).toBeGreaterThan(reconcile);
    const reporterBlock = workflow.slice(failureReporter, failureReporter + 500);
    expect(reporterBlock).toContain("if: failure()");
  });
});

describe("reconciliation IAM", () => {
  it("grants exactly the read actions exercised by the command", () => {
    const role = readFileSync(rolePath, "utf8");
    const actions = [
      ...actionSetForSid(role, "EcsDeploymentReconciliationRead"),
      ...actionSetForSid(role, "SsmDeploymentReconciliationRead"),
    ].sort();

    expect(actions).toEqual(
      [
        "ecs:DescribeServices",
        "ecs:DescribeTasks",
        "ecs:ListTasks",
        "ssm:GetParameters",
      ].sort(),
    );
  });
});

describe("reconciliation command fixtures", () => {
  it("succeeds on an exact match and calls only the expected read commands", () => {
    const { result, callRecords } = runFixture("match");
    const calls = callRecords.map(({ args }) => args.slice(0, 2).join(" "));

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("status=match");
    expect(calls).toEqual([
      "ssm get-parameters",
      "ecs wait",
      "ecs describe-services",
      "ecs list-tasks",
      "ecs describe-tasks",
    ]);
    expect(JSON.stringify(callRecords)).not.toMatch(
      /update-service|register-task-definition|deregister-task-definition/i,
    );
  });

  it("fails on drift, remains redacted, and makes no mutating ECS call", () => {
    const { result, callRecords } = runFixture("exported-new-ecs-old");
    const diagnostic = `${result.stdout}\n${result.stderr}`;

    expect(result.status).not.toBe(0);
    expect(diagnostic).toContain("status=mismatch");
    expect(diagnostic).toContain("task_definition=mem9-on-aws-prod-Mem9Server:42");
    expect(diagnostic).not.toMatch(/\d{12}/);
    expect(diagnostic).not.toContain("arn:");
    expect(JSON.stringify(callRecords)).not.toMatch(
      /update-service|register-task-definition|deregister-task-definition|list-task-definitions/i,
    );
  });
});
