import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const script = resolve("scripts/run-consolidation-task.sh");
const temporaryPaths = [];

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) {
    rmSync(path, { force: true, recursive: true });
  }
});

function runFixture({
  exitCode = "0",
  marker = true,
  digestEnabled = false,
  statusSequence = ["STOPPED"],
  sleepAdvanceSeconds,
  sleepAdvanceSequence,
  waitSeconds,
  runFailures = [],
  failCommand,
  failureStderr = "",
} = {}) {
  const directory = mkdtempSync(join(tmpdir(), "mem9-consolidation-runner-"));
  temporaryPaths.push(directory);
  const bin = join(directory, "bin");
  const calls = join(directory, "calls.jsonl");
  const statusIndex = join(directory, "status-index");
  const bashEnv = join(directory, "bash-env");
  const clock = join(directory, "clock");
  mkdirSync(bin);
  writeFileSync(calls, "");
  writeFileSync(statusIndex, "0");
  writeFileSync(clock, "4102444800");
  writeFileSync(
    bashEnv,
    `MOCK_SLEEP_INDEX=0
sleep() {
  local advance="\${MOCK_SLEEP_ADVANCE_SECONDS:-$1}"
  if [[ -n "\${MOCK_SLEEP_ADVANCE_SEQUENCE:-}" ]]; then
    local -a advances
    IFS=',' read -r -a advances <<<"$MOCK_SLEEP_ADVANCE_SEQUENCE"
    advance="\${advances[$MOCK_SLEEP_INDEX]:-$1}"
    MOCK_SLEEP_INDEX=$((MOCK_SLEEP_INDEX + 1))
  fi
  local current
  current=$(<"$MOCK_CLOCK")
  printf '%s' "$((current + advance))" >"$MOCK_CLOCK"
}
`,
  );
  writeFileSync(
    join(bin, "date"),
    `#!/usr/bin/env bash
if [[ "\${1:-}" == "+%s" ]]; then
  cat "$MOCK_CLOCK"
else
  /bin/date "$@"
fi
`,
    { mode: 0o755 },
  );

  const aws = join(bin, "aws");
  writeFileSync(
    aws,
    `#!/usr/bin/env node
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(process.env.AWS_CALLS, JSON.stringify(args) + "\\n");
const option = (name) => {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
};
const command = args.slice(0, 2).join(" ");
const failureKey = command === "ecs describe-tasks"
  ? command + ":" + option("--query")
  : command;
if (failureKey === process.env.MOCK_FAIL_COMMAND) {
  console.error(process.env.MOCK_FAILURE_STDERR);
  process.exit(1);
}
if (command === "ssm get-parameters") {
  const names = args.slice(args.indexOf("--names") + 1, args.indexOf("--region"));
  const values = {
    "cluster-name": "mem9-preview-cluster",
    "task-def-arn": "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-consolidation:7",
    "task-sg-id": "sg-consolidation",
    "subnet-ids": "subnet-a,subnet-b",
    "log-group-name": "/sst/consolidation-preview",
  };
  console.log(JSON.stringify({
    InvalidParameters: [],
    Parameters: names.map((Name) => ({
      Name,
      Value: values[Name.split("/").at(-1)],
    })),
  }));
} else if (command === "ecs run-task") {
  const failures = JSON.parse(process.env.MOCK_RUN_FAILURES);
  console.log(JSON.stringify({
    failures,
    tasks: failures.length === 0 ? [{
      taskArn: "arn:aws:ecs:ap-northeast-1:123456789012:task/mem9-preview-cluster/task-123",
    }] : [],
  }));
} else if (command === "ecs describe-tasks") {
  const query = option("--query");
  if (query?.includes("lastStatus")) {
    const statuses = JSON.parse(process.env.MOCK_STATUS_SEQUENCE);
    const index = Number(readFileSync(process.env.MOCK_STATUS_INDEX, "utf8"));
    console.log(statuses[Math.min(index, statuses.length - 1)]);
    writeFileSync(process.env.MOCK_STATUS_INDEX, String(index + 1));
  }
  else if (query?.includes("exitCode")) console.log(process.env.MOCK_EXIT_CODE);
  else if (query?.includes("stoppedReason")) console.log("Essential container in task exited");
  else console.log(JSON.stringify({ tasks: [] }));
} else if (command === "ecs describe-task-definition") {
  console.log(JSON.stringify({
    taskDefinition: {
      containerDefinitions: [{
        name: "Mem9Consolidation",
        logConfiguration: {
          options: { "awslogs-stream-prefix": "sst" },
        },
      }],
    },
  }));
} else if (command === "logs filter-log-events") {
  if (process.env.MOCK_MARKER === "true") {
    console.log('CONSOLIDATION_REVIEW_LIST {"stage":"pr-103","reportOnly":true,"reviewItems":0,"digestEnabled":' + process.env.MOCK_DIGEST_ENABLED + '}');
  }
} else {
  console.error("unexpected aws command:", command, args.join(" "));
  process.exit(2);
}
`,
    { mode: 0o755 },
  );
  chmodSync(aws, 0o755);

  const env = {
    ...process.env,
    AWS_CALLS: calls,
    BASH_ENV: bashEnv,
    MOCK_EXIT_CODE: exitCode,
    MOCK_DIGEST_ENABLED: String(digestEnabled),
    MOCK_CLOCK: clock,
    MOCK_FAIL_COMMAND: failCommand ?? "",
    MOCK_FAILURE_STDERR: failureStderr,
    MOCK_MARKER: String(marker),
    MOCK_RUN_FAILURES: JSON.stringify(runFailures),
    MOCK_STATUS_INDEX: statusIndex,
    MOCK_STATUS_SEQUENCE: JSON.stringify(statusSequence),
    PATH: `${bin}${delimiter}${process.env.PATH}`,
    STAGE: "pr-103",
  };
  delete env.CONSOLIDATION_TASK_WAIT_SECONDS;
  if (waitSeconds !== undefined) {
    env.CONSOLIDATION_TASK_WAIT_SECONDS = String(waitSeconds);
  }
  if (sleepAdvanceSeconds !== undefined) {
    env.MOCK_SLEEP_ADVANCE_SECONDS = String(sleepAdvanceSeconds);
  }
  if (sleepAdvanceSequence !== undefined) {
    env.MOCK_SLEEP_ADVANCE_SEQUENCE = sleepAdvanceSequence.join(",");
  }
  const result = spawnSync("bash", [script], {
    encoding: "utf8",
    env,
  });
  const callRecords = readFileSync(calls, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  return { callRecords, result };
}

function expectOutputOmits(result, forbiddenValues) {
  const output = `${result.stdout}\n${result.stderr}`;
  for (const value of forbiddenValues) {
    expect(output).not.toContain(value);
  }
}

describe("report-only consolidation ECS runner", () => {
  it("TC-CONSOL-040/041: forces report-only and reads only the exact task marker", () => {
    const { callRecords, result } = runFixture();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("CONSOLIDATION_REVIEW_LIST");
    expect(result.stdout).toContain('"digestEnabled":false');
    expectOutputOmits(result, [
      "task-123",
      "arn:aws",
      "123456789012",
      "Essential container in task exited",
    ]);

    const runCalls = callRecords.filter(
      ([service, operation]) => service === "ecs" && operation === "run-task",
    );
    expect(runCalls).toHaveLength(1);
    const overrides = JSON.parse(
      runCalls[0][runCalls[0].indexOf("--overrides") + 1],
    );
    expect(overrides).toEqual({
      containerOverrides: [
        {
          name: "Mem9Consolidation",
          command: [
            // Must match infra/consolidation.ts's task `command`. The image
            // preserves the repo layout (/app/scripts/...) because
            // memory-cleanup.mjs imports ../docker/llm-proxy/server.mjs; a
            // flattened /app/ path breaks that import at startup.
            "/app/scripts/memory-consolidation.mjs",
            "--report-only",
            "--check-llm",
          ],
        },
      ],
    });
    expect(JSON.stringify(overrides)).not.toContain(
      "MEM9_CONSOLIDATION_SCHEDULED",
    );
    expect(runCalls[0]).toEqual(
      expect.arrayContaining([
        "--task-definition",
        "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-consolidation:7",
      ]),
    );
    expect(
      JSON.parse(
        runCalls[0][runCalls[0].indexOf("--network-configuration") + 1],
      ),
    ).toEqual({
      awsvpcConfiguration: {
        subnets: ["subnet-a", "subnet-b"],
        securityGroups: ["sg-consolidation"],
        assignPublicIp: "DISABLED",
      },
    });

    const logCall = callRecords.find(
      ([service, operation]) =>
        service === "logs" && operation === "filter-log-events",
    );
    expect(logCall).toContain("/sst/consolidation-preview");
    expect(logCall).toContain("sst/Mem9Consolidation/task-123");
    expect(logCall).toContain('"CONSOLIDATION_REVIEW_LIST"');
    expect(logCall.join(" ")).not.toContain("CONSOLIDATION_REVIEW ");
  });

  it("TC-CONSOL-071: rejects a report-only marker that enables digest work", () => {
    const { result } = runFixture({ digestEnabled: true });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("CONSOLIDATION_REVIEW_LIST");
  });

  it("TC-CONSOL-041: fails when the exact task stream has no summary marker", () => {
    const { callRecords, result } = runFixture({ marker: false });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("CONSOLIDATION_REVIEW_LIST");
    expect(
      callRecords.filter(
        ([service, operation]) =>
          service === "logs" && operation === "filter-log-events",
      ),
    ).toHaveLength(6);
  });

  it("TC-CONSOL-080: tolerates a production-sized task beyond 20 minutes", () => {
    const { callRecords, result } = runFixture({
      statusSequence: [
        "RUNNING",
        "RUNNING",
        "RUNNING",
        "RUNNING",
        "RUNNING",
        "RUNNING",
        "RUNNING",
        "RUNNING",
        "STOPPED",
      ],
      sleepAdvanceSeconds: 600,
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(
      'CONSOLIDATION_REVIEW_LIST {"stage":"pr-103","reportOnly":true,"reviewItems":0,"digestEnabled":false}',
    );
    expect(
      callRecords.filter(
        ([service, operation, ...args]) =>
          service === "ecs" &&
          operation === "describe-tasks" &&
          args.includes("tasks[0].lastStatus"),
      ),
    ).toHaveLength(9);
  });

  it("TC-CONSOL-081: validates the bounded wait before any AWS call", () => {
    for (const waitSeconds of ["", "0", "59", "43201", "1.5", "invalid"]) {
      const invalid = runFixture({ waitSeconds });
      expect(invalid.result.status).toBe(1);
      expect(invalid.callRecords).toEqual([]);
      expect(invalid.result.stderr).toContain(
        "CONSOLIDATION_TASK_WAIT_SECONDS must be an integer from 60 to 43200",
      );
    }

    for (const waitSeconds of ["60", "3600", "43200"]) {
      const valid = runFixture({ waitSeconds });
      expect(valid.result.status, valid.result.stderr).toBe(0);
    }
  });

  it("TC-CONSOL-082: rejects a non-zero final container exit", () => {
    const { callRecords, result } = runFixture({ exitCode: "17" });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("report-only consolidation exited 17");
    expect(
      callRecords.some(
        ([service, operation]) =>
          service === "logs" && operation === "filter-log-events",
      ),
    ).toBe(false);
  });

  it("TC-CONSOL-083: expires at the default bound without stopping or leaking the task", () => {
    const timedOut = runFixture({
      statusSequence: ["RUNNING", "RUNNING", "STOPPED"],
      sleepAdvanceSequence: [43199, 1],
    });
    expect(timedOut.result.status).toBe(1);
    expect(timedOut.result.stderr).toContain(
      "did not stop within 43200s; task remains running",
    );
    expect(
      timedOut.callRecords.filter(
        ([service, operation, ...args]) =>
          service === "ecs" &&
          operation === "describe-tasks" &&
          args.includes("tasks[0].lastStatus"),
      ),
    ).toHaveLength(2);
    expect(
      timedOut.callRecords.some(
        ([service, operation]) =>
          (service === "ecs" && operation === "stop-task") ||
          (service === "logs" && operation === "filter-log-events"),
      ),
    ).toBe(false);
    expectOutputOmits(timedOut.result, [
      "task-123",
      "arn:aws",
      "123456789012",
    ]);

    const failedStart = runFixture({
      runFailures: [{
        arn: "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/private:9",
        reason: "private failure detail",
      }],
    });
    expect(failedStart.result.status).toBe(1);
    expect(failedStart.result.stderr).toContain(
      "run-task started no task (1 failure records)",
    );
    expectOutputOmits(failedStart.result, [
      "private failure detail",
      "arn:aws",
      "123456789012",
    ]);

    for (const failCommand of [
      "ssm get-parameters",
      "ecs describe-tasks:tasks[0].containers[0].exitCode",
      "ecs describe-task-definition",
    ]) {
      const failedRead = runFixture({
        failCommand,
        failureStderr:
          "private error arn:aws:ecs:ap-northeast-1:123456789012:task/task-123",
      });
      expect(failedRead.result.status).toBe(1);
      expectOutputOmits(failedRead.result, [
        "private error",
        "task-123",
        "arn:aws",
        "123456789012",
      ]);
    }
  });
});

describe("entrypoint path agreement (TC-CONSOL-045)", () => {
  it("keeps the operator script, the task definition, and the image in sync", () => {
    const root = new URL("..", import.meta.url);
    const read = (rel) => readFileSync(new URL(rel, root), "utf8");

    const runner = read("scripts/run-consolidation-task.sh");
    const infra = read("infra/consolidation.ts");
    const dockerfile = read("docker/llm-proxy/Dockerfile");

    // The operator script and the task definition both name the entrypoint, and
    // they drifted: the Dockerfile fix moved the script to /app/scripts/ and
    // updated the task `command`, but run-consolidation-task.sh kept the old
    // /app/ path. Nothing caught it because each was asserted in isolation.
    const EXPECTED = "/app/scripts/memory-consolidation.mjs";
    expect(runner).toContain(EXPECTED);
    expect(infra).toContain(EXPECTED);
    // And the image must actually place the file there — a flattened COPY breaks
    // memory-cleanup.mjs's `../docker/llm-proxy/server.mjs` import at startup.
    expect(dockerfile).toContain("/app/scripts/memory-consolidation.mjs");
    expect(dockerfile).toContain("/app/docker/llm-proxy/server.mjs");
    // Neither may still reference the flattened path.
    for (const [label, content] of [["runner", runner], ["infra", infra]]) {
      expect(
        /["'\s]\/app\/memory-consolidation\.mjs/.test(content),
        `${label} still references the flattened /app/ entrypoint`,
      ).toBe(false);
    }
  });
});
