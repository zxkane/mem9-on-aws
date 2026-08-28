import { describe, expect, it, vi } from "vitest";

import {
  formatReconciliationDiagnostic,
  reconcileDeployment,
} from "./reconcile-ecs-deployment.mjs";

const ACCOUNT = "123456789012";
const REGION = "ap-northeast-1";
const DESIRED_ID = "mem9-on-aws-prod-Mem9Server:42";
const OLD_ID = "mem9-on-aws-prod-Mem9Server:41";
const DESIRED_TASK_DEF = `arn:aws:ecs:${REGION}:${ACCOUNT}:task-definition/${DESIRED_ID}`;
const OLD_TASK_DEF = `arn:aws:ecs:${REGION}:${ACCOUNT}:task-definition/${OLD_ID}`;
const DESIRED_TAG = "mem9-abcdef0";
const TASK_1 = `arn:aws:ecs:${REGION}:${ACCOUNT}:task/mem9-cluster/task-1`;
const TASK_2 = `arn:aws:ecs:${REGION}:${ACCOUNT}:task/mem9-cluster/task-2`;
const APP_CONTAINERS = ["mnemo-server", "qwen3-embed", "llm-proxy"];

function image(name, tag = DESIRED_TAG) {
  return `${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/mem9-on-aws/${name}:${tag}`;
}

function task(taskArn = TASK_1, taskDefinitionArn = DESIRED_TASK_DEF, tags = {}) {
  return {
    taskArn,
    taskDefinitionArn,
    desiredStatus: "RUNNING",
    lastStatus: "RUNNING",
    containers: APP_CONTAINERS.map((name) => ({
      name,
      image: image(name, tags[name] ?? DESIRED_TAG),
    })),
  };
}

function baseResponses() {
  return {
    "ssm get-parameters": {
      Parameters: [
        { Name: "/mem9-on-aws/prod/ecs/cluster-name", Value: "mem9-cluster" },
        { Name: "/mem9-on-aws/prod/ecs/service-name", Value: "mem9-service" },
        { Name: "/mem9-on-aws/prod/ecs/task-definition", Value: DESIRED_TASK_DEF },
        { Name: "/mem9-on-aws/prod/ecs/image-tag", Value: DESIRED_TAG },
      ],
      InvalidParameters: [],
    },
    "ecs describe-services": {
      services: [
        {
          serviceArn: `arn:aws:ecs:${REGION}:${ACCOUNT}:service/mem9-cluster/mem9-service`,
          desiredCount: 1,
          runningCount: 1,
          pendingCount: 0,
          deployments: [
            {
              status: "PRIMARY",
              rolloutState: "COMPLETED",
              taskDefinition: DESIRED_TASK_DEF,
            },
          ],
        },
      ],
      failures: [],
    },
    "ecs list-tasks": { taskArns: [TASK_1] },
    "ecs describe-tasks": { tasks: [task()], failures: [] },
  };
}

function mockAws(overrides = {}) {
  const responses = { ...baseResponses(), ...overrides };
  const calls = [];
  const runAws = vi.fn((args) => {
    const key = args.slice(0, 2).join(" ");
    calls.push(key);
    const response = responses[key];
    if (response instanceof Error) throw response;
    if (typeof response === "function") return response();
    return response;
  });
  return { runAws, calls };
}

describe("reconcileDeployment", () => {
  it("accepts one stable PRIMARY deployment and exact task/container matches", () => {
    const { runAws, calls } = mockAws();
    const result = reconcileDeployment({ stage: "prod", runAws });

    expect(result.ok).toBe(true);
    expect(result.reasons).toEqual([]);
    expect(calls).toEqual([
      "ssm get-parameters",
      "ecs describe-services",
      "ecs list-tasks",
      "ecs describe-tasks",
    ]);
  });

  it("waits for PRIMARY rollout completion", () => {
    let serviceReads = 0;
    const sleep = vi.fn();
    const completed = baseResponses()["ecs describe-services"];
    const { runAws, calls } = mockAws({
      "ecs describe-services": () => {
        serviceReads += 1;
        if (serviceReads > 1) return completed;
        return {
          services: [
            {
              desiredCount: 1,
              runningCount: 0,
              pendingCount: 1,
              deployments: [
                {
                  status: "PRIMARY",
                  rolloutState: "IN_PROGRESS",
                  taskDefinition: DESIRED_TASK_DEF,
                },
              ],
            },
          ],
          failures: [],
        };
      },
    });

    const result = reconcileDeployment({ stage: "prod", runAws, sleep });

    expect(result.ok).toBe(true);
    expect(sleep).toHaveBeenCalledOnce();
    expect(calls.filter((call) => call === "ecs describe-services")).toHaveLength(2);
  });

  it("bounds PRIMARY rollout polling and reports an incomplete rollout", () => {
    const sleep = vi.fn();
    const { runAws, calls } = mockAws({
      "ecs describe-services": {
        services: [
          {
            desiredCount: 1,
            runningCount: 0,
            pendingCount: 1,
            deployments: [
              {
                status: "PRIMARY",
                rolloutState: "IN_PROGRESS",
                taskDefinition: DESIRED_TASK_DEF,
              },
            ],
          },
        ],
        failures: [],
      },
    });

    const result = reconcileDeployment({
      stage: "prod",
      runAws,
      sleep,
      rolloutPollAttempts: 3,
      rolloutPollIntervalMs: 1,
    });

    expect(result.reasons).toContain("primary_not_completed");
    expect(sleep).toHaveBeenCalledTimes(2);
    expect(calls.filter((call) => call === "ecs describe-services")).toHaveLength(3);
  });

  it("detects exported-new/ECS-old drift without exposing ARNs or account IDs", () => {
    const { runAws } = mockAws({
      "ecs describe-services": {
        services: [
          {
            desiredCount: 1,
            runningCount: 1,
            pendingCount: 0,
            deployments: [
              {
                status: "PRIMARY",
                rolloutState: "COMPLETED",
                taskDefinition: OLD_TASK_DEF,
              },
            ],
          },
        ],
        failures: [],
      },
      "ecs describe-tasks": {
        tasks: [task(TASK_1, OLD_TASK_DEF, Object.fromEntries(APP_CONTAINERS.map((n) => [n, "mem9-deadbee"])))],
        failures: [],
      },
    });
    const result = reconcileDeployment({ stage: "prod", runAws });
    const diagnostic = formatReconciliationDiagnostic(result);

    expect(result.ok).toBe(false);
    expect(result.reasons).toEqual(
      expect.arrayContaining(["primary_task_definition", "task_definition_mismatch", "image_tag_mismatch"]),
    );
    expect(diagnostic).toMatchInlineSnapshot(
      `"deployment_reconciliation status=mismatch stage=prod reasons=primary_task_definition,task_definition_mismatch,image_tag_mismatch task_definition=mem9-on-aws-prod-Mem9Server:42 image_tag=mem9-abcdef0 running_tasks=1 actual_task_definitions=mem9-on-aws-prod-Mem9Server:41 actual_image_tags=mem9-deadbee"`,
    );
    expect(diagnostic).not.toMatch(/\d{12}/);
    expect(diagnostic).not.toContain("arn:");
  });

  it("detects mixed application container tags", () => {
    const { runAws } = mockAws({
      "ecs describe-tasks": {
        tasks: [task(TASK_1, DESIRED_TASK_DEF, { "llm-proxy": "mem9-deadbee" })],
        failures: [],
      },
    });
    const result = reconcileDeployment({ stage: "prod", runAws });

    expect(result.reasons).toEqual(
      expect.arrayContaining(["mixed_image_tags", "image_tag_mismatch"]),
    );
  });

  it("detects no running task", () => {
    const { runAws, calls } = mockAws({
      "ecs list-tasks": { taskArns: [] },
    });
    const result = reconcileDeployment({ stage: "prod", runAws });

    expect(result.reasons).toContain("no_running_tasks");
    expect(calls).not.toContain("ecs describe-tasks");
  });

  it("detects multiple unresolved service deployments", () => {
    const sleep = vi.fn();
    const { runAws } = mockAws({
      "ecs describe-services": {
        services: [
          {
            desiredCount: 1,
            runningCount: 1,
            pendingCount: 0,
            deployments: [
              {
                status: "PRIMARY",
                rolloutState: "COMPLETED",
                taskDefinition: DESIRED_TASK_DEF,
              },
              {
                status: "ACTIVE",
                rolloutState: "COMPLETED",
                taskDefinition: OLD_TASK_DEF,
              },
            ],
          },
        ],
        failures: [],
      },
    });
    const result = reconcileDeployment({
      stage: "prod",
      runAws,
      sleep,
      rolloutPollAttempts: 1,
      rolloutPollIntervalMs: 1,
    });

    expect(result.reasons).toEqual(
      expect.arrayContaining(["stabilization_timeout", "multiple_deployments"]),
    );
    expect(sleep).not.toHaveBeenCalled();
  });

  it("detects mixed running task definitions", () => {
    const { runAws } = mockAws({
      "ecs list-tasks": { taskArns: [TASK_1, TASK_2] },
      "ecs describe-tasks": {
        tasks: [task(TASK_1), task(TASK_2, OLD_TASK_DEF)],
        failures: [],
      },
    });
    const result = reconcileDeployment({ stage: "prod", runAws });

    expect(result.reasons).toEqual(
      expect.arrayContaining(["mixed_task_definitions", "task_definition_mismatch"]),
    );
  });

  it("bounds stability polling and still inspects safe state on timeout", () => {
    const sleep = vi.fn();
    const { runAws, calls } = mockAws({
      "ecs describe-services": {
        services: [
          {
            desiredCount: 1,
            runningCount: 0,
            pendingCount: 1,
            deployments: [
              {
                status: "PRIMARY",
                rolloutState: "IN_PROGRESS",
                taskDefinition: DESIRED_TASK_DEF,
              },
            ],
          },
        ],
        failures: [],
      },
      "ecs list-tasks": { taskArns: [] },
    });
    const result = reconcileDeployment({
      stage: "prod",
      runAws,
      sleep,
      rolloutPollAttempts: 3,
      rolloutPollIntervalMs: 1,
    });

    expect(result.reasons).toEqual([
      "stabilization_timeout",
      "primary_not_completed",
      "no_running_tasks",
    ]);
    expect(sleep).toHaveBeenCalledTimes(2);
    expect(calls).toEqual([
      "ssm get-parameters",
      "ecs describe-services",
      "ecs describe-services",
      "ecs describe-services",
      "ecs list-tasks",
    ]);
  });

  it("stops polling immediately when the deployment circuit breaker fails", () => {
    const sleep = vi.fn();
    const { runAws, calls } = mockAws({
      "ecs describe-services": {
        services: [
          {
            desiredCount: 1,
            runningCount: 0,
            pendingCount: 0,
            deployments: [
              {
                status: "PRIMARY",
                rolloutState: "FAILED",
                taskDefinition: DESIRED_TASK_DEF,
              },
            ],
          },
        ],
        failures: [],
      },
      "ecs list-tasks": { taskArns: [] },
    });

    const result = reconcileDeployment({ stage: "prod", runAws, sleep });

    expect(result.reasons).toEqual(["primary_failed", "no_running_tasks"]);
    expect(sleep).not.toHaveBeenCalled();
    expect(calls.filter((call) => call === "ecs describe-services")).toHaveLength(1);
  });

  it("ignores a failed historical deployment while the desired PRIMARY recovers", () => {
    let serviceReads = 0;
    const sleep = vi.fn();
    const completed = baseResponses()["ecs describe-services"];
    const { runAws, calls } = mockAws({
      "ecs describe-services": () => {
        serviceReads += 1;
        if (serviceReads > 1) return completed;
        return {
          services: [
            {
              desiredCount: 1,
              runningCount: 0,
              pendingCount: 1,
              deployments: [
                {
                  status: "PRIMARY",
                  rolloutState: "IN_PROGRESS",
                  taskDefinition: DESIRED_TASK_DEF,
                },
                {
                  status: "ACTIVE",
                  rolloutState: "FAILED",
                  taskDefinition: OLD_TASK_DEF,
                },
              ],
            },
          ],
          failures: [],
        };
      },
    });

    const result = reconcileDeployment({ stage: "prod", runAws, sleep });

    expect(result.ok).toBe(true);
    expect(sleep).toHaveBeenCalledOnce();
    expect(calls.filter((call) => call === "ecs describe-services")).toHaveLength(2);
  });

  it("redacts account-like values even when malformed desired state contains them", () => {
    const { runAws } = mockAws({
      "ssm get-parameters": {
        Parameters: [
          { Name: "/mem9-on-aws/prod/ecs/cluster-name", Value: "mem9-cluster" },
          { Name: "/mem9-on-aws/prod/ecs/service-name", Value: "mem9-service" },
          {
            Name: "/mem9-on-aws/prod/ecs/task-definition",
            Value: `arn:aws:ecs:${REGION}:${ACCOUNT}:task-definition/family-${ACCOUNT}:42`,
          },
          { Name: "/mem9-on-aws/prod/ecs/image-tag", Value: ACCOUNT },
        ],
        InvalidParameters: [],
      },
    });
    const diagnostic = formatReconciliationDiagnostic(
      reconcileDeployment({ stage: "prod", runAws }),
    );

    expect(diagnostic).not.toContain(ACCOUNT);
    expect(diagnostic).toContain("task_definition=<unavailable>");
    expect(diagnostic).toContain("image_tag=<unavailable>");
  });
});

describe("rollout poll budget", () => {
  it("stays above the task's own cold-start health floor", async () => {
    const {
      ROLLOUT_POLL_ATTEMPTS,
      ROLLOUT_POLL_INTERVAL_MS,
      ROLLOUT_HEALTH_FLOOR_MS,
    } = await import("./reconcile-ecs-deployment.mjs");

    const budgetMs = (ROLLOUT_POLL_ATTEMPTS - 1) * ROLLOUT_POLL_INTERVAL_MS;
    // The AWS services-stable waiter is about 10 minutes and timed out on a
    // healthy fresh preview before any task reached RUNNING. Keep enough room
    // for the measured 30-35 minute end-to-end bring-up after SST returns.
    expect(budgetMs).toBeGreaterThan(ROLLOUT_HEALTH_FLOOR_MS);
    expect(budgetMs).toBeGreaterThanOrEqual(25 * 60 * 1000);
    expect(budgetMs).toBeLessThan(35 * 60 * 1000);
  });
});
