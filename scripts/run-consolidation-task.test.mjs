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

function runFixture({ exitCode = "0", marker = true } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "mem9-consolidation-runner-"));
  temporaryPaths.push(directory);
  const bin = join(directory, "bin");
  const calls = join(directory, "calls.jsonl");
  mkdirSync(bin);

  const aws = join(bin, "aws");
  writeFileSync(
    aws,
    `#!/usr/bin/env node
import { appendFileSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(process.env.AWS_CALLS, JSON.stringify(args) + "\\n");
const option = (name) => {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
};
const command = args.slice(0, 2).join(" ");
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
  console.log(JSON.stringify({
    failures: [],
    tasks: [{
      taskArn: "arn:aws:ecs:ap-northeast-1:123456789012:task/mem9-preview-cluster/task-123",
    }],
  }));
} else if (command === "ecs describe-tasks") {
  const query = option("--query");
  if (query?.includes("lastStatus")) console.log("STOPPED");
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
    console.log('CONSOLIDATION_REVIEW_LIST {"stage":"pr-103","reportOnly":true,"reviewItems":0}');
  }
} else {
  console.error("unexpected aws command:", command, args.join(" "));
  process.exit(2);
}
`,
    { mode: 0o755 },
  );
  chmodSync(aws, 0o755);
  const sleep = join(bin, "sleep");
  writeFileSync(sleep, "#!/usr/bin/env bash\nexit 0\n", { mode: 0o755 });

  const result = spawnSync("bash", [script], {
    encoding: "utf8",
    env: {
      ...process.env,
      AWS_CALLS: calls,
      MOCK_EXIT_CODE: exitCode,
      MOCK_MARKER: String(marker),
      PATH: `${bin}${delimiter}${process.env.PATH}`,
      STAGE: "pr-103",
    },
  });
  const callRecords = readFileSync(calls, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  return { callRecords, result };
}

describe("report-only consolidation ECS runner", () => {
  it("TC-CONSOL-040/041: forces report-only and reads only the exact task marker", () => {
    const { callRecords, result } = runFixture();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("CONSOLIDATION_REVIEW_LIST");

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

    const logCall = callRecords.find(
      ([service, operation]) =>
        service === "logs" && operation === "filter-log-events",
    );
    expect(logCall).toContain("/sst/consolidation-preview");
    expect(logCall).toContain("sst/Mem9Consolidation/task-123");
    expect(logCall).toContain('"CONSOLIDATION_REVIEW_LIST"');
    expect(logCall.join(" ")).not.toContain("CONSOLIDATION_REVIEW ");
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
