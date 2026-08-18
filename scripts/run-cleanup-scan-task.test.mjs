import {
  chmodSync,
  existsSync,
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

const script = resolve("scripts/run-cleanup-scan-task.sh");
const temporaryPaths = [];

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) {
    rmSync(path, { force: true, recursive: true });
  }
});

function runFixture({
  stage = "prod",
  confirmProd = "prod",
  exitCode = 0,
  invalidParameters = [],
  runFailures = [],
  baseUrl = `http://mnemo.mem9-${stage}.local:8080`,
  offer,
  offerModified = 4_102_444_800,
} = {}) {
  const directory = mkdtempSync(join(tmpdir(), "mem9-cleanup-scan-runner-"));
  temporaryPaths.push(directory);
  const bin = join(directory, "bin");
  const calls = join(directory, "calls.jsonl");
  mkdirSync(bin);

  const offered = offer ?? {
    stage,
    issuedAt: "2099-12-31T23:59:00.000Z",
    expiresAt: "2100-01-03T23:59:00.000Z",
    ids: ["private-memory-id"],
    hash: `sha256:${"a".repeat(64)}`,
    artifactBucket: "private-decision-bucket",
    artifactKey: `decisions/${stage}/private-decision.json`,
  };

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
    "cluster-name": "mem9-prod-cluster",
    "task-def-arn": "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-cleanup:7",
    "task-sg-id": "sg-cleanup",
    "subnet-ids": "subnet-a,subnet-b",
  };
  console.log(JSON.stringify({
    InvalidParameters: JSON.parse(process.env.MOCK_INVALID_PARAMETERS),
    Parameters: names.map((Name) => ({
      Name,
      Value: values[Name.split("/").at(-1)],
    })),
  }));
} else if (command === "ecs describe-task-definition") {
  console.log(JSON.stringify({
    taskDefinition: {
      containerDefinitions: [{
        name: "Mem9Cleanup",
        command: [
          "/app/scripts/memory-cleanup.mjs",
          "--stage",
          process.env.MOCK_STAGE,
          "--base-url",
          process.env.MOCK_BASE_URL,
          "--apply",
          "--ids",
          "/tmp/approved-ids.txt",
          "--cap",
          "50"
        ],
      }],
    },
  }));
} else if (command === "ecs run-task") {
  const failures = JSON.parse(process.env.MOCK_RUN_FAILURES);
  console.log(JSON.stringify({
    failures,
    tasks: failures.length === 0 ? [{
      taskArn: "arn:aws:ecs:ap-northeast-1:123456789012:task/mem9-prod-cluster/task-private",
    }] : [],
  }));
} else if (command === "ecs describe-tasks") {
  console.log(JSON.stringify({
    failures: [],
    tasks: [{
      lastStatus: "STOPPED",
      stoppedReason: "Essential container in task exited",
      containers: [{
        name: "Mem9Cleanup",
        exitCode: Number(process.env.MOCK_EXIT_CODE),
      }],
    }],
  }));
} else if (command === "ssm get-parameter") {
  console.log(JSON.stringify({
    Parameter: {
      Name: option("--name"),
      LastModifiedDate: Number(process.env.MOCK_OFFER_MODIFIED),
      Value: process.env.MOCK_OFFER,
    },
  }));
} else {
  console.error("unexpected aws command:", command);
  process.exit(2);
}
`,
    { mode: 0o755 },
  );
  chmodSync(aws, 0o755);
  writeFileSync(join(bin, "sleep"), "#!/usr/bin/env bash\nexit 0\n", {
    mode: 0o755,
  });
  writeFileSync(
    join(bin, "date"),
    "#!/usr/bin/env bash\nif [[ \"$1\" == \"+%s\" ]]; then echo 4102444700; else /bin/date \"$@\"; fi\n",
    { mode: 0o755 },
  );

  const result = spawnSync("bash", [script], {
    encoding: "utf8",
    env: {
      ...process.env,
      AWS_CALLS: calls,
      CONFIRM_PROD_SCAN: confirmProd,
      MOCK_BASE_URL: baseUrl,
      MOCK_EXIT_CODE: String(exitCode),
      MOCK_INVALID_PARAMETERS: JSON.stringify(invalidParameters),
      MOCK_OFFER: JSON.stringify(offered),
      MOCK_OFFER_MODIFIED: String(offerModified),
      MOCK_RUN_FAILURES: JSON.stringify(runFailures),
      MOCK_STAGE: stage,
      PATH: `${bin}${delimiter}${process.env.PATH}`,
      STAGE: stage,
    },
  });
  const callRecords = (existsSync(calls) ? readFileSync(calls, "utf8") : "")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  return { callRecords, result };
}

describe("manual cleanup scan ECS runner", () => {
  it("TC-SLACKAPP-241: validates the stage and requires explicit prod confirmation", () => {
    const unconfirmed = runFixture({ confirmProd: "" });
    expect(unconfirmed.result.status).toBe(1);
    expect(unconfirmed.callRecords).toEqual([]);
    expect(unconfirmed.result.stderr).toContain("CONFIRM_PROD_SCAN=prod");

    for (const stage of ["production", "dev", "pr-0", "pr-01", "pr-x"]) {
      const invalid = runFixture({ stage, confirmProd: "" });
      expect(invalid.result.status).toBe(1);
      expect(invalid.callRecords).toEqual([]);
      expect(invalid.result.stderr).toContain("invalid cleanup scan stage");
    }

    const preview = runFixture({ stage: "pr-42", confirmProd: "" });
    expect(preview.result.status, preview.result.stderr).toBe(0);
  });

  it("TC-SLACKAPP-242: starts only the deployed dry-run command in private networking", () => {
    const { callRecords, result } = runFixture();
    expect(result.status, result.stderr).toBe(0);

    const parameterCall = callRecords.find(
      ([service, operation]) =>
        service === "ssm" && operation === "get-parameters",
    );
    expect(parameterCall).toEqual(
      expect.arrayContaining([
        "/mem9-on-aws/prod/cleanup/cluster-name",
        "/mem9-on-aws/prod/cleanup/task-def-arn",
        "/mem9-on-aws/prod/cleanup/task-sg-id",
        "/mem9-on-aws/prod/cleanup/subnet-ids",
      ]),
    );

    const runCall = callRecords.find(
      ([service, operation]) =>
        service === "ecs" && operation === "run-task",
    );
    const option = (name) => runCall[runCall.indexOf(name) + 1];
    expect(JSON.parse(option("--network-configuration"))).toEqual({
      awsvpcConfiguration: {
        subnets: ["subnet-a", "subnet-b"],
        securityGroups: ["sg-cleanup"],
        assignPublicIp: "DISABLED",
      },
    });
    const overrides = JSON.parse(option("--overrides"));
    expect(overrides).toEqual({
      containerOverrides: [{
        name: "Mem9Cleanup",
        command: [
          "/app/scripts/memory-cleanup.mjs",
          "--stage",
          "prod",
          "--base-url",
          "http://mnemo.mem9-prod.local:8080",
          "--consensus-passes",
          "2",
          "--out",
          "/tmp/mem9-cleanup-scan",
        ],
      }],
    });
    expect(JSON.stringify(overrides)).not.toMatch(
      /--apply|--ids|MEM9_CLEANUP_SCHEDULED/u,
    );
  });

  it("TC-SLACKAPP-243: verifies a fresh artifact-backed offer without leaking it", () => {
    const { callRecords, result } = runFixture();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("recorded 1 reviewed id(s)");

    const output = `${result.stdout}\n${result.stderr}`;
    for (const privateValue of [
      "private-memory-id",
      "a".repeat(64),
      "private-decision-bucket",
      "private-decision.json",
      "task-private",
      "arn:aws:",
    ]) {
      expect(output).not.toContain(privateValue);
    }
    expect(
      callRecords.some(
        ([service, operation]) =>
          service === "logs" && operation === "filter-log-events",
      ),
    ).toBe(false);
  });

  it("TC-SLACKAPP-244: fails closed on task input, launch, exit, and offer drift", () => {
    const missing = runFixture({
      invalidParameters: ["/mem9-on-aws/prod/cleanup/task-def-arn"],
    });
    expect(missing.result.status).toBe(1);
    expect(
      missing.callRecords.some(
        ([service, operation]) => service === "ecs" && operation === "run-task",
      ),
    ).toBe(false);

    const crossStage = runFixture({
      baseUrl: "http://mnemo.mem9-pr-42.local:8080",
    });
    expect(crossStage.result.status).toBe(1);
    expect(crossStage.result.stderr).toContain("base URL");

    const launch = runFixture({
      runFailures: [{ arn: "redacted", reason: "RESOURCE:CPU" }],
    });
    expect(launch.result.status).toBe(1);
    expect(launch.result.stderr).toContain("started no task");

    const failed = runFixture({ exitCode: 1 });
    expect(failed.result.status).toBe(1);
    expect(failed.result.stderr).toContain("exited 1");

    const stale = runFixture({ offerModified: 4_102_444_600 });
    expect(stale.result.status).toBe(1);
    expect(stale.result.stderr).toContain("fresh approval offer");

    const noArtifact = runFixture({
      offer: {
        stage: "prod",
        issuedAt: "2099-12-31T23:59:00.000Z",
        expiresAt: "2100-01-03T23:59:00.000Z",
        ids: [],
        hash: `sha256:${"a".repeat(64)}`,
      },
    });
    expect(noArtifact.result.status).toBe(1);
    expect(noArtifact.result.stderr).toContain("artifact-backed");
  });
});
