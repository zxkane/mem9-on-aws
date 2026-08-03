#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const APP_CONTAINERS = ["mnemo-server", "qwen3-embed", "llm-proxy"];
const SAFE_VALUE = /^[A-Za-z0-9._:-]+$/;
const ACCOUNT_ID = /\d{12}/;
// A FRESH preview stack is the slow case: the service pulls three container
// images and waits for the mnemo-server health check before the rollout reports
// COMPLETED. The previous 12 attempts gave ~110s of sleep, and a measured
// successful run (#121) needed 132s wall-clock — it only fit because the twelve
// DescribeServices round trips padded the budget, leaving effectively no margin.
// A marginally slower stack then fails with `primary_not_completed` even though
// the deploy itself is healthy. 30 attempts (~290s of sleep) covers observed
// cold starts with real headroom; a genuinely stuck rollout still fails, just
// later.
const ROLLOUT_POLL_ATTEMPTS = 30;
const ROLLOUT_POLL_INTERVAL_MS = 10_000;

function sleepSync(milliseconds) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function addReason(result, reason) {
  if (!result.reasons.includes(reason)) result.reasons.push(reason);
}

function normalizedTaskDefinition(value) {
  const candidate = String(value ?? "").split("/").at(-1) ?? "";
  return /^[A-Za-z0-9_-]+:\d+$/.test(candidate) && !ACCOUNT_ID.test(candidate)
    ? candidate
    : "<unavailable>";
}

function safeTag(value) {
  const tag = String(value ?? "");
  return SAFE_VALUE.test(tag) && !ACCOUNT_ID.test(tag) ? tag : "<unavailable>";
}

function imageTag(image) {
  const value = String(image ?? "");
  const slash = value.lastIndexOf("/");
  const colon = value.lastIndexOf(":");
  if (value.includes("@") || colon <= slash) return "<unavailable>";
  return safeTag(value.slice(colon + 1));
}

function emptyResult(stage, desiredTaskDefinition, desiredImageTag) {
  return {
    ok: false,
    stage,
    reasons: [],
    desiredTaskDefinition: normalizedTaskDefinition(desiredTaskDefinition),
    desiredImageTag: safeTag(desiredImageTag),
    runningTasks: 0,
    actualTaskDefinitions: [],
    actualImageTags: [],
  };
}

function readDesiredState(stage, runAws) {
  const prefix = `/mem9-on-aws/${stage}/ecs`;
  const names = {
    cluster: `${prefix}/cluster-name`,
    service: `${prefix}/service-name`,
    taskDefinition: `${prefix}/task-definition`,
    imageTag: `${prefix}/image-tag`,
  };
  const response = runAws([
    "ssm",
    "get-parameters",
    "--names",
    ...Object.values(names),
    "--output",
    "json",
  ]);
  const values = new Map(
    (response?.Parameters ?? []).map((parameter) => [
      parameter.Name,
      parameter.Value,
    ]),
  );
  if (
    (response?.InvalidParameters ?? []).length > 0 ||
    Object.values(names).some((name) => !values.has(name))
  ) {
    throw new Error("desired state parameters are incomplete");
  }
  return {
    cluster: values.get(names.cluster),
    service: values.get(names.service),
    taskDefinition: values.get(names.taskDefinition),
    imageTag: values.get(names.imageTag),
  };
}

function describeAllTasks(cluster, taskArns, runAws) {
  const tasks = [];
  const failures = [];
  for (let offset = 0; offset < taskArns.length; offset += 100) {
    const response = runAws([
      "ecs",
      "describe-tasks",
      "--cluster",
      cluster,
      "--tasks",
      ...taskArns.slice(offset, offset + 100),
      "--output",
      "json",
    ]);
    tasks.push(...(response?.tasks ?? []));
    failures.push(...(response?.failures ?? []));
  }
  return { tasks, failures };
}

function describeService(cluster, service, runAws) {
  return runAws([
    "ecs",
    "describe-services",
    "--cluster",
    cluster,
    "--services",
    service,
    "--output",
    "json",
  ]);
}

function waitForPrimaryRollout({
  cluster,
  service,
  runAws,
  sleep,
  rolloutPollAttempts,
  rolloutPollIntervalMs,
}) {
  let response;
  for (let attempt = 0; attempt < rolloutPollAttempts; attempt += 1) {
    response = describeService(cluster, service, runAws);
    const services = response?.services ?? [];
    const deployments = services[0]?.deployments ?? [];
    const primaries = deployments.filter((deployment) => deployment.status === "PRIMARY");
    const rolloutState =
      services.length === 1 && deployments.length === 1 && primaries.length === 1
        ? primaries[0].rolloutState
        : undefined;

    if (rolloutState !== "IN_PROGRESS") return response;
    if (attempt + 1 < rolloutPollAttempts) sleep(rolloutPollIntervalMs);
  }
  return response;
}

export function reconcileDeployment({
  stage,
  runAws,
  sleep = sleepSync,
  rolloutPollAttempts = ROLLOUT_POLL_ATTEMPTS,
  rolloutPollIntervalMs = ROLLOUT_POLL_INTERVAL_MS,
}) {
  if (!/^[A-Za-z0-9-]+$/.test(stage ?? "")) {
    throw new Error("stage must contain only letters, digits, and hyphens");
  }

  let desired;
  try {
    desired = readDesiredState(stage, runAws);
  } catch {
    const result = emptyResult(stage);
    addReason(result, "desired_state_unavailable");
    return result;
  }

  const result = emptyResult(stage, desired.taskDefinition, desired.imageTag);

  try {
    runAws([
      "ecs",
      "wait",
      "services-stable",
      "--cluster",
      desired.cluster,
      "--services",
      desired.service,
    ]);
  } catch {
    addReason(result, "stabilization_timeout");
    return result;
  }

  let serviceResponse;
  let taskArns;
  try {
    serviceResponse = waitForPrimaryRollout({
      cluster: desired.cluster,
      service: desired.service,
      runAws,
      sleep,
      rolloutPollAttempts,
      rolloutPollIntervalMs,
    });
    taskArns =
      runAws([
        "ecs",
        "list-tasks",
        "--cluster",
        desired.cluster,
        "--service-name",
        desired.service,
        "--desired-status",
        "RUNNING",
        "--output",
        "json",
      ])?.taskArns ?? [];
  } catch {
    addReason(result, "ecs_state_unavailable");
    return result;
  }

  const services = serviceResponse?.services ?? [];
  if ((serviceResponse?.failures ?? []).length > 0 || services.length !== 1) {
    addReason(result, "service_lookup");
  }

  const deployments = services[0]?.deployments ?? [];
  if (deployments.length > 1) addReason(result, "multiple_deployments");
  const primaries = deployments.filter((deployment) => deployment.status === "PRIMARY");
  if (primaries.length !== 1) {
    addReason(result, "primary_deployment");
  } else {
    if (primaries[0].taskDefinition !== desired.taskDefinition) {
      addReason(result, "primary_task_definition");
    }
    if (primaries[0].rolloutState && primaries[0].rolloutState !== "COMPLETED") {
      addReason(result, "primary_not_completed");
    }
  }

  if (taskArns.length === 0) {
    addReason(result, "no_running_tasks");
    return result;
  }

  let described;
  try {
    described = describeAllTasks(desired.cluster, taskArns, runAws);
  } catch {
    addReason(result, "task_lookup");
    return result;
  }

  const tasks = described.tasks;
  result.runningTasks = tasks.length;
  if (described.failures.length > 0 || tasks.length !== taskArns.length) {
    addReason(result, "task_lookup");
  }
  if (
    tasks.some(
      (task) =>
        task.desiredStatus !== "RUNNING" || task.lastStatus !== "RUNNING",
    )
  ) {
    addReason(result, "task_not_running");
  }

  const rawTaskDefinitions = new Set(
    tasks.map((task) => task.taskDefinitionArn).filter(Boolean),
  );
  result.actualTaskDefinitions = [...rawTaskDefinitions]
    .map(normalizedTaskDefinition)
    .sort();
  if (rawTaskDefinitions.size > 1) addReason(result, "mixed_task_definitions");
  if (tasks.some((task) => task.taskDefinitionArn !== desired.taskDefinition)) {
    addReason(result, "task_definition_mismatch");
  }

  const tags = [];
  for (const task of tasks) {
    const containers = new Map(
      (task.containers ?? []).map((container) => [container.name, container]),
    );
    for (const name of APP_CONTAINERS) {
      if (!containers.has(name)) {
        addReason(result, "missing_container");
        continue;
      }
      tags.push(imageTag(containers.get(name).image));
    }
  }
  result.actualImageTags = [...new Set(tags)].sort();
  if (result.actualImageTags.length > 1) addReason(result, "mixed_image_tags");
  if (tags.some((tag) => tag !== desired.imageTag)) {
    addReason(result, "image_tag_mismatch");
  }

  result.ok = result.reasons.length === 0;
  return result;
}

export function formatReconciliationDiagnostic(result) {
  const fields = [
    "deployment_reconciliation",
    `status=${result.ok ? "match" : "mismatch"}`,
    `stage=${result.stage}`,
  ];
  if (!result.ok) fields.push(`reasons=${result.reasons.join(",")}`);
  fields.push(
    `task_definition=${result.desiredTaskDefinition}`,
    `image_tag=${result.desiredImageTag}`,
    `running_tasks=${result.runningTasks}`,
  );
  if (!result.ok && result.actualTaskDefinitions.length > 0) {
    fields.push(`actual_task_definitions=${result.actualTaskDefinitions.join("|")}`);
  }
  if (!result.ok && result.actualImageTags.length > 0) {
    fields.push(`actual_image_tags=${result.actualImageTags.join("|")}`);
  }
  return fields.join(" ");
}

export function createAwsCliRunner(env = process.env) {
  const executable = env.AWS_CLI || "aws";
  return (args) => {
    const response = spawnSync(executable, args, {
      encoding: "utf8",
      env,
      maxBuffer: 10 * 1024 * 1024,
    });
    if (response.error || response.status !== 0) {
      const error = new Error("AWS command failed");
      error.command = args.slice(0, 2).join(".");
      error.status = response.status;
      throw error;
    }
    if (!args.includes("--output")) return undefined;
    try {
      return JSON.parse(response.stdout);
    } catch {
      const error = new Error("AWS command returned invalid JSON");
      error.command = args.slice(0, 2).join(".");
      throw error;
    }
  };
}

function parseStage(argv) {
  if (argv.length !== 2 || argv[0] !== "--stage") {
    throw new Error("usage: reconcile-ecs-deployment.mjs --stage <stage>");
  }
  return argv[1];
}

function main() {
  const result = reconcileDeployment({
    stage: parseStage(process.argv.slice(2)),
    runAws: createAwsCliRunner(),
  });
  const diagnostic = formatReconciliationDiagnostic(result);
  if (result.ok) {
    process.stdout.write(`${diagnostic}\n`);
  } else {
    process.stderr.write(`::error::${diagnostic}\n`);
    process.exitCode = 1;
  }
}

const isMain =
  process.argv[1] &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isMain) {
  try {
    main();
  } catch {
    const result = emptyResult("unavailable");
    addReason(result, "command_failed");
    process.stderr.write(`::error::${formatReconciliationDiagnostic(result)}\n`);
    process.exitCode = 1;
  }
}
