import {
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

const script = resolve("scripts/run-bootstrap-task.sh");
const temporaryPaths = [];

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) {
    rmSync(path, { force: true, recursive: true });
  }
});

function runFixture() {
  const directory = mkdtempSync(join(tmpdir(), "mem9-bootstrap-runner-"));
  temporaryPaths.push(directory);
  const bin = join(directory, "bin");
  const calls = join(directory, "calls.jsonl");
  mkdirSync(bin);

  writeFileSync(
    join(bin, "aws"),
    `#!/usr/bin/env node
import { appendFileSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(process.env.AWS_CALLS, JSON.stringify(args) + "\\n");
const option = (name) => {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
};
const command = args.slice(0, 2).join(" ");
if (command === "ssm get-parameter") {
  const values = {
    "cluster-name": "mem9-pr-42-cluster",
    "task-def-arn": "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-bootstrap:7",
    "task-sg-id": "sg-bootstrap",
    "subnet-ids": "subnet-a,subnet-b"
  };
  process.stdout.write(values[option("--name").split("/").at(-1)] + "\\n");
} else if (command === "ecs describe-task-definition") {
  console.log(JSON.stringify({
    taskDefinition: {
      containerDefinitions: [{
        name: "Mem9Bootstrap",
        logConfiguration: {
          options: {
            "awslogs-group": "/sst/cluster/mem9-pr-42/bootstrap/Mem9Bootstrap",
            "awslogs-stream-prefix": "/service"
          }
        }
      }]
    }
  }));
} else if (command === "ecs run-task") {
  console.log(JSON.stringify({
    failures: [],
    tasks: [{
      taskArn: "arn:aws:ecs:ap-northeast-1:123456789012:task/mem9-pr-42-cluster/task-private"
    }]
  }));
} else if (command === "ecs describe-tasks") {
  const query = option("--query");
  if (query.includes("lastStatus")) process.stdout.write("STOPPED\\n");
  else if (query.includes("exitCode")) process.stdout.write("1\\n");
  else if (query.includes("stoppedReason")) {
    process.stdout.write("Essential container in task exited\\n");
  } else {
    console.log(JSON.stringify({ tasks: [] }));
  }
} else if (command === "logs filter-log-events") {
  console.log(JSON.stringify({
    events: [{ message: "preview namespace preparation failed: fixture failure" }]
  }));
} else {
  console.error("unexpected aws command:", command);
  process.exit(2);
}
`,
    { mode: 0o755 },
  );
  writeFileSync(join(bin, "sleep"), "#!/usr/bin/env bash\nexit 0\n", {
    mode: 0o755,
  });

  const result = spawnSync("bash", [script], {
    encoding: "utf8",
    env: {
      ...process.env,
      AWS_CALLS: calls,
      AWS_REGION: "ap-northeast-1",
      PATH: `${bin}${delimiter}${process.env.PATH}`,
      STAGE: "pr-42",
    },
  });
  const callRecords = readFileSync(calls, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  return { callRecords, result };
}

describe("schema bootstrap ECS runner", () => {
  it("prints the failed task's exact awslogs stream with existing deploy-role permissions", () => {
    const { callRecords, result } = runFixture();
    const output = result.stdout + result.stderr;

    expect(result.status).toBe(1);
    expect(output).toContain(
      "preview namespace preparation failed: fixture failure",
    );
    const logCall = callRecords.find(
      ([service, operation]) =>
        service === "logs" && operation === "filter-log-events",
    );
    expect(logCall).toEqual(
      expect.arrayContaining([
        "--log-group-name",
        "/sst/cluster/mem9-pr-42/bootstrap/Mem9Bootstrap",
        "--log-stream-name-prefix",
        "/service/Mem9Bootstrap/task-private",
      ]),
    );
    expect(
      callRecords.some(
        ([service, operation]) =>
          service === "logs" &&
          ["describe-log-groups", "describe-log-streams", "get-log-events"].includes(
            operation,
          ),
      ),
    ).toBe(false);
  });
});
