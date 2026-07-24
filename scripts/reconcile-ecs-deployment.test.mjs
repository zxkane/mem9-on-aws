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
    "ecs wait": undefined,
    "ecs describe-services": {
      services: [
        {
          serviceArn: `arn:aws:ecs:${REGION}:${ACCOUNT}:service/mem9-cluster/mem9-service`,
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
      "ecs wait",
      "ecs describe-services",
      "ecs list-tasks",
      "ecs describe-tasks",
    ]);
  });

  it("waits for PRIMARY rollout completion after the stable waiter returns", () => {
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
        services: [{ deployments: [{ status: "PRIMARY", taskDefinition: OLD_TASK_DEF }] }],
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
    const { runAws } = mockAws({
      "ecs describe-services": {
        services: [
          {
            deployments: [
              { status: "PRIMARY", taskDefinition: DESIRED_TASK_DEF },
              { status: "ACTIVE", taskDefinition: OLD_TASK_DEF },
            ],
          },
        ],
        failures: [],
      },
    });
    const result = reconcileDeployment({ stage: "prod", runAws });

    expect(result.reasons).toContain("multiple_deployments");
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

  it("treats stabilization timeout as a mismatch and stops before state reads", () => {
    const timeout = Object.assign(new Error("waiter failed"), {
      command: "ecs.wait",
      status: 255,
    });
    const { runAws, calls } = mockAws({ "ecs wait": timeout });
    const result = reconcileDeployment({ stage: "prod", runAws });

    expect(result.reasons).toEqual(["stabilization_timeout"]);
    expect(calls).toEqual(["ssm get-parameters", "ecs wait"]);
    expect(formatReconciliationDiagnostic(result)).not.toContain("waiter failed");
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
