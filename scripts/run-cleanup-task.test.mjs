import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const SCRIPT = resolve("scripts/run-cleanup-task.sh");
const NAMESPACE_ID = "60000000-0000-4000-8000-000000000101";
const TASK_DEF = "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/fixture-cleanup:7";
const TASK_ARN = "arn:aws:ecs:ap-northeast-1:123456789012:task/fixture-cluster/fixture-task";
const LOG_GROUP = "/sst/fixture/cleanup";
const COMMAND = ["/app/scripts/memory-cleanup.mjs", "--stage", "pr-42", "--base-url", "http://mnemo.example.com:8080"];
const paths = [];
afterEach(() => {
  for (const path of paths.splice(0)) rmSync(path, { recursive: true, force: true });
});

function runFixture(options = {}) {
  const directory = mkdtempSync(join(tmpdir(), "mem9-cleanup-launcher-"));
  paths.push(directory);
  const bin = join(directory, "bin"), calls = join(directory, "calls.jsonl");
  mkdirSync(bin);
  writeFileSync(calls, "");
  writeFileSync(join(bin, "sleep"), "#!/usr/bin/env bash\nexit 0\n", { mode: 0o755 });
  const configuration = {
    taskDefinition: {
      taskDefinitionArn: TASK_DEF,
      containerDefinitions: [{
        name: "Mem9Cleanup", entryPoint: ["node"], command: options.command ?? COMMAND,
        logConfiguration: { logDriver: "awslogs", options: {
          "awslogs-group": LOG_GROUP, "awslogs-stream-prefix": "sst", "awslogs-region": "ap-northeast-1",
        } },
      }],
    },
  };
  if (options.missingContainer) configuration.taskDefinition.containerDefinitions[0].name = "Other";
  if (options.missingLogPrefix) delete configuration.taskDefinition.containerDefinitions[0].logConfiguration.options["awslogs-stream-prefix"];
  const fixture = {
    configuration, taskArn: TASK_ARN, taskDef: TASK_DEF,
    metadata: { "cluster-name": "fixture-cluster", "task-def-arn": TASK_DEF, "task-sg-id": "sg-01234567", "subnet-ids": "subnet-01234567,subnet-89abcdef", "log-group-name": LOG_GROUP },
    statuses: options.statuses ?? ["STOPPED"], exitCode: options.exitCode ?? 0,
    logs: options.logs ?? [JSON.stringify({ event: "memory_cleanup", kind: "summary", writeCalls: 0, capUsed: 0,
      namespaceId: NAMESPACE_ID, principalId: "private-principal", message: "private memory content", taskArn: TASK_ARN })],
    logDelay: options.logDelay ?? 0, fail: options.fail, malformed: options.malformed,
    missingParameter: options.missingParameter, duplicateParameter: options.duplicateParameter,
    runFailures: options.runFailures ?? false, describeFailures: options.describeFailures ?? false,
  };
  const fixturePath = join(directory, "fixture.json");
  writeFileSync(fixturePath, JSON.stringify(fixture));
  writeFileSync(join(bin, "aws"), `#!/usr/bin/env node
import { appendFileSync, readFileSync, writeFileSync, existsSync } from "node:fs";
const args = process.argv.slice(2), fixture = JSON.parse(readFileSync(process.env.MOCK_FIXTURE, "utf8"));
const command = args.slice(0, 2).join(" ");
const option = (key) => { const i = args.indexOf(key); return i < 0 ? undefined : args[i + 1]; };
let input;
if (option("--cli-input-json")) input = JSON.parse(readFileSync(option("--cli-input-json").replace("file://", ""), "utf8"));
appendFileSync(process.env.MOCK_CALLS, JSON.stringify({ args, input, profile: process.env.AWS_PROFILE }) + "\\n");
if (fixture.fail === command || fixture.malformed === command) {
  console.error("private memory content " + process.env.MEM9_NAMESPACE_ID + " " + fixture.taskArn);
  console.log("private-command-output " + fixture.taskDef);
  process.exit(fixture.fail === command ? 1 : 0);
}
const count = (name) => {
  const path = process.env.MOCK_FIXTURE + "." + name;
  const value = existsSync(path) ? Number(readFileSync(path, "utf8")) : 0;
  writeFileSync(path, String(value + 1)); return value;
};
if (command === "ssm get-parameters") {
  const names = []; for (let i = args.indexOf("--names") + 1; i < args.length && !args[i].startsWith("--"); i++) names.push(args[i]);
  const Parameters = names.map(Name => ({ Name, Value: fixture.metadata[Name.split("/").at(-1)] }));
  if (fixture.missingParameter) Parameters.pop();
  if (fixture.duplicateParameter) Parameters.push(Parameters[0]);
  console.log(JSON.stringify({ Parameters, InvalidParameters: [] }));
} else if (command === "ecs describe-task-definition") console.log(JSON.stringify(fixture.configuration));
else if (command === "ecs run-task") console.log(JSON.stringify(fixture.runFailures
  ? { tasks: [], failures: [{ arn: fixture.taskArn, reason: "private memory content" }] }
  : { tasks: [{ taskArn: fixture.taskArn, taskDefinitionArn: fixture.taskDef }], failures: [] }));
else if (command === "ecs describe-tasks") {
  const status = fixture.statuses[Math.min(count("status"), fixture.statuses.length - 1)];
  console.log(JSON.stringify({ failures: fixture.describeFailures ? [{ arn: fixture.taskArn }] : [], tasks: [{
    taskArn: fixture.taskArn, taskDefinitionArn: fixture.taskDef, lastStatus: status,
    containers: [{ name: "Other", exitCode: 99 }, { name: "Mem9Cleanup", exitCode: fixture.exitCode }],
  }] }));
} else if (command === "logs filter-log-events") console.log(JSON.stringify(count("logs") < fixture.logDelay ? [] : fixture.logs));
else { console.error("unexpected command"); process.exit(2); }
`, { mode: 0o755 });
  const env = {
    ...process.env, PATH: `${bin}${delimiter}${process.env.PATH}`, STAGE: options.stage ?? "pr-42",
    MEM9_NAMESPACE_ID: options.namespaceId ?? NAMESPACE_ID, AWS_REGION: "ap-northeast-1", AWS_PROFILE: "fixture-profile",
    CLEANUP_TASK_WAIT_SECONDS: String(options.waitSeconds ?? 30), MOCK_CALLS: calls, MOCK_FIXTURE: fixturePath,
  };
  delete env.BASH_ENV;
  if (options.stage === null) delete env.STAGE;
  if (options.namespaceId === null) delete env.MEM9_NAMESPACE_ID;
  const result = spawnSync("bash", [SCRIPT, ...(options.args ?? [])], { env, encoding: "utf8", timeout: 10_000 });
  const records = readFileSync(calls, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
  return { result, records };
}

function expectPrivateOutputAbsent(result) {
  const output = `${result.stdout}\n${result.stderr}`;
  for (const value of [NAMESPACE_ID, TASK_DEF, TASK_ARN, "private-principal", "private memory content", "private-command-output"])
    expect(output).not.toContain(value);
}

describe("namespace cleanup report-only task launcher", () => {
  it.each([null, "", "../prod", "-prod", "a".repeat(65)])("rejects invalid stages before AWS (case %#)", (stage) => {
    const { result, records } = runFixture({ stage });
    expect(result.status).not.toBe(0); expect(records).toEqual([]);
  });
  it.each([null, "", "all", `${NAMESPACE_ID},${NAMESPACE_ID}`, NAMESPACE_ID.slice(0, -1) + "A"])("rejects invalid namespace scope before AWS (case %#)", (namespaceId) => {
    const { result, records } = runFixture({ namespaceId });
    expect(result.status).not.toBe(0); expect(records).toEqual([]);
    expectPrivateOutputAbsent(result);
  });
  it.each(["--apply", "--restore", "--list-inactive", "--namespace-id"])("does not forward operator flags: %s", (flag) => {
    const { result, records } = runFixture({ args: [flag] });
    expect(result.status).not.toBe(0); expect(records).toEqual([]);
  });
  it.each(["", "0", "-1", "1.5", "43201", "999999999999999999999999"])("rejects an invalid wait budget: %s", (waitSeconds) => {
    const { result, records } = runFixture({ waitSeconds });
    expect(result.status).not.toBe(0); expect(records).toEqual([]);
  });
  it("reads only cleanup metadata, preserves the command and roles, and emits a sanitized summary", () => {
    const { result, records } = runFixture();
    expect(result.error).toBeUndefined(); expect(result.status, result.stderr).toBe(0);
    const metadata = records.find(({ args }) => args[0] === "ssm");
    const start = metadata.args.indexOf("--names") + 1;
    expect(metadata.args.slice(start, start + 5).sort()).toEqual([
      "cluster-name", "task-def-arn", "task-sg-id", "subnet-ids", "log-group-name",
    ].map((name) => `/mem9-on-aws/pr-42/maintenance/cleanup/${name}`).sort());
    expect(records.filter(({ args }) => args[0] === "ssm")).toHaveLength(1);
    const launch = records.find(({ args }) => args.slice(0, 2).join(" ") === "ecs run-task");
    expect(launch.input.overrides).toEqual({ containerOverrides: [{ name: "Mem9Cleanup", environment: [{ name: "MEM9_NAMESPACE_ID", value: NAMESPACE_ID }] }] });
    expect(launch.input).toMatchObject({ cluster: "fixture-cluster", taskDefinition: TASK_DEF, count: 1, launchType: "FARGATE", networkConfiguration: { awsvpcConfiguration: { assignPublicIp: "DISABLED" } } });
    expect(launch.profile).toBe("fixture-profile");
    const logs = records.find(({ args }) => args[0] === "logs").args;
    expect(logs[logs.indexOf("--log-stream-names") + 1]).toBe("sst/Mem9Cleanup/fixture-task");
    expect(result.stdout).toContain('CLEANUP_REPORT {"event":"memory_cleanup","kind":"summary","writeCalls":0');
    expectPrivateOutputAbsent(result);
  });
  it.each([
    [...COMMAND, "--apply"], [...COMMAND, "--restore"],
    ["/app/scripts/other.mjs", ...COMMAND.slice(1)],
    [COMMAND[0], "--stage", "prod", ...COMMAND.slice(3)],
  ].map((command) => ({ command })))("refuses changed task commands before launching (case %#)", ({ command }) => {
    const { result, records } = runFixture({ command });
    expect(result.status).not.toBe(0);
    expect(records.some(({ args }) => args[1] === "run-task")).toBe(false);
    expectPrivateOutputAbsent(result);
  });
  it.each(["missingParameter", "duplicateParameter", "missingContainer", "missingLogPrefix", "runFailures", "describeFailures"])("fails closed on %s", (option) => {
    const { result } = runFixture({ [option]: true });
    expect(result.status).not.toBe(0); expectPrivateOutputAbsent(result);
  });
  it.each(["ssm get-parameters", "ecs describe-task-definition", "ecs run-task", "ecs describe-tasks", "logs filter-log-events"])("hides raw failures from %s", (fail) => {
    const { result } = runFixture({ fail });
    expect(result.status).not.toBe(0); expectPrivateOutputAbsent(result);
  });
  it.each(["ssm get-parameters", "ecs describe-task-definition", "ecs run-task", "ecs describe-tasks", "logs filter-log-events"])("hides malformed output from %s", (malformed) => {
    const { result } = runFixture({ malformed });
    expect(result.status).not.toBe(0); expectPrivateOutputAbsent(result);
  });
  it.each([1, 5, null, "0", 256])("requires a successful named-container exit code (case %#)", (exitCode) => {
    const { result } = runFixture({ exitCode: exitCode === null ? "unavailable" : exitCode });
    expect(result.status).not.toBe(0); expectPrivateOutputAbsent(result);
  });
  it("bounds polling without stopping the task or launching another", () => {
    const { result, records } = runFixture({ statuses: ["RUNNING"], waitSeconds: 1 });
    expect(result.status).not.toBe(0); expect(result.stderr).toContain("may still be running");
    expect(records.filter(({ args }) => args[1] === "run-task")).toHaveLength(1);
    expect(records.filter(({ args }) => args[1] === "describe-tasks")).toHaveLength(1);
    expect(records.some(({ args }) => ["stop-task", "update-service"].includes(args[1]))).toBe(false);
  });
  it("retries task status and delayed log delivery within fixed bounds", () => {
    const { result, records } = runFixture({ statuses: ["RUNNING", "STOPPED"], waitSeconds: 20, logDelay: 2 });
    expect(result.status, result.stderr).toBe(0);
    expect(records.filter(({ args }) => args[1] === "describe-tasks")).toHaveLength(2);
    expect(records.filter(({ args }) => args[0] === "logs")).toHaveLength(3);
  });
  it.each([[], ["private memory content"], [JSON.stringify({ event: "memory_cleanup", kind: NAMESPACE_ID })], [JSON.stringify({ event: "memory_cleanup", kind: "summary", writeCalls: 1 })], [JSON.stringify({ event: "memory_cleanup", kind: "summary", writeCalls: 0, capUsed: NAMESPACE_ID })]].map((logs) => ({ logs })))("refuses absent or unsafe summary records (case %#)", ({ logs }) => {
    const { result, records } = runFixture({ logs });
    expect(result.status).not.toBe(0);
    expect(records.filter(({ args }) => args[0] === "logs")).toHaveLength(6);
    expectPrivateOutputAbsent(result);
  });
});
