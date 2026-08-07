/**
 * Unit tests for the Slack approval E2E harness (issue #123, TC-SLACKAPP-090).
 * Test ids map to docs/test-cases/slack-approval-loop.md.
 *
 * The harness itself talks to a deployed stage, so every case here runs it
 * against a fake `aws` and a fake `curl` on PATH. That is the only way to assert
 * the properties that actually matter — that a 200 on the INVALID signature
 * fails the run, that "a record exists" is read back by name, that the signing
 * secret never reaches stdout — without a deployed stage and a Slack workspace.
 */

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

const script = resolve("scripts/run-slack-approval-e2e.sh");
const SECRET = "fixture-signing-secret";
const temporaryPaths = [];

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) {
    rmSync(path, { force: true, recursive: true });
  }
});

/**
 * Run the harness with a fake `aws` and `curl`.
 *
 * Every knob is a MOCK_* env var read inside the fakes rather than a fixture
 * file, so a case reads as the one deviation it is testing.
 */
function runFixture({
  secret = SECRET,
  facade = "https://facade.example.com",
  badSignatureStatus = "401",
  approveStatus = "200",
  claim = null,
  stage = "pr-123",
  taskExitCode = "0",
  taskStatus = "STOPPED",
} = {}) {
  const directory = mkdtempSync(join(tmpdir(), "mem9-slack-e2e-"));
  temporaryPaths.push(directory);
  const bin = join(directory, "bin");
  const calls = join(directory, "calls.jsonl");
  mkdirSync(bin);

  const aws = join(bin, "aws");
  writeFileSync(
    aws,
    // The shebang is the ABSOLUTE interpreter, never `env node`: this fixture
    // prepends `bin` to PATH (below), so `env node` would resolve to any file
    // named `node` in `bin` — and a stub that re-invokes `node` then forks
    // forever. That is not hypothetical; it once spawned ~70k processes and
    // exhausted the systemd user slice's TasksMax.
    `#!${process.execPath}
import { appendFileSync, existsSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(process.env.MOCK_CALLS, JSON.stringify(["aws", ...args]) + "\\n");
const option = (name) => {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
};
const command = args.slice(0, 2).join(" ");
if (command === "ssm get-parameter") {
  const name = option("--name") ?? "";
  if (name.endsWith("/facade/url")) {
    if (!process.env.MOCK_FACADE) process.exit(255);
    console.log(process.env.MOCK_FACADE);
  } else if (name.endsWith("/slack/signing-secret")) {
    if (!process.env.MOCK_SECRET) process.exit(255);
    console.log(process.env.MOCK_SECRET);
  } else if (name.includes("/approvals/approved-")) {
    // Stateful, like a real stage: no claim exists until the signed click
    // creates one. A fake that served it unconditionally would make the
    // pre-click "no record was written" assertion fail against a correct script.
    if (!existsSync(process.env.MOCK_CLICKED) || !process.env.MOCK_CLAIM) {
      process.exit(255);
    }
    console.log(process.env.MOCK_CLAIM);
  } else {
    console.error("unexpected parameter:", name);
    process.exit(2);
  }
} else if (command === "ssm put-parameter" || command === "ssm delete-parameter") {
  process.exit(0);
} else if (command === "ecs describe-tasks") {
  const query = option("--query") ?? "";
  if (query.includes("lastStatus")) console.log(process.env.MOCK_TASK_STATUS);
  else if (query.includes("exitCode")) console.log(process.env.MOCK_TASK_EXIT);
  else console.log("Essential container in task exited");
} else {
  console.error("unexpected aws command:", command);
  process.exit(2);
}
`,
    { mode: 0o755 },
  );
  chmodSync(aws, 0o755);

  // The fake `curl` decides which POST it is by the SIGNATURE header, exactly as
  // the real endpoint does: that is the one thing this E2E exists to exercise.
  const curl = join(bin, "curl");
  writeFileSync(
    curl,
    `#!${process.execPath}
import { appendFileSync, writeFileSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(process.env.MOCK_CALLS, JSON.stringify(["curl", ...args]) + "\\n");
const option = (name) => {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
};
const headers = args.filter((a, i) => args[i - 1] === "-H");
const signature = headers.find((h) => /^x-slack-signature:/i.test(h)) ?? "";
const invalid = /deadbeef|invalid/i.test(signature);
const status = invalid ? process.env.MOCK_BAD_STATUS : process.env.MOCK_APPROVE_STATUS;
const body = invalid
  ? "unauthorized"
  : JSON.stringify({ response_type: "ephemeral", text: "Apply started for 1 memories." });
const out = option("-o");
if (out) writeFileSync(out, body);
// A 200 on the VALID signature is what creates the claim on a real stage.
if (!invalid && status === "200") writeFileSync(process.env.MOCK_CLICKED, "1");
process.stdout.write(status);
`,
    { mode: 0o755 },
  );
  chmodSync(curl, 0o755);

  const sleep = join(bin, "sleep");
  writeFileSync(sleep, "#!/usr/bin/env bash\nexit 0\n", { mode: 0o755 });
  chmodSync(sleep, 0o755);

  const result = spawnSync("bash", [script], {
    encoding: "utf8",
    env: {
      ...process.env,
      MOCK_CALLS: calls,
      MOCK_CLICKED: join(directory, "clicked"),
      MOCK_FACADE: facade,
      MOCK_SECRET: secret,
      MOCK_BAD_STATUS: badSignatureStatus,
      MOCK_APPROVE_STATUS: approveStatus,
      MOCK_CLAIM: claim === null ? "" : claim,
      MOCK_TASK_EXIT: taskExitCode,
      MOCK_TASK_STATUS: taskStatus,
      PATH: `${bin}${delimiter}${process.env.PATH}`,
      STAGE: stage,
      AWS_REGION: "ap-northeast-1",
    },
  });
  // The log file only exists once a fake has been invoked, and the whole point of
  // the protected-stage case is that NOTHING is invoked — so an absent file is a
  // valid result (no calls), not a fixture error.
  const callRecords = (existsSync(calls) ? readFileSync(calls, "utf8") : "")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  return { callRecords, result, output: `${result.stdout}${result.stderr}` };
}

/** The claim the callback writes when it wins and RunTask succeeds. */
function claimWith(overrides = {}) {
  return JSON.stringify({
    stage: "pr-123",
    hash: "sha256:unused-by-the-harness",
    ids: ["mem9-e2e-nonexistent"],
    claimedAt: "2026-08-05T12:00:00.000Z",
    taskArn: "arn:aws:ecs:ap-northeast-1:123456789012:task/mem9-pr-123/task-abc",
    ...overrides,
  });
}

describe("Slack approval E2E harness (TC-SLACKAPP-090)", () => {
  it("TC-SLACKAPP-090 signs a synthetic interaction, proves the record exists, and waits for the apply", () => {
    const { callRecords, result, output } = runFixture({ claim: claimWith() });
    expect(result.status, output).toBe(0);

    const curls = callRecords.filter(([tool]) => tool === "curl");
    expect(curls).toHaveLength(2);

    // The INVALID signature goes first, so "no record" is asserted before the
    // valid click creates one. Reversed, the 401 case would have to assert the
    // absence of a record that already exists, which nothing can do.
    const [bad, good] = curls;
    expect(bad.join(" ")).toMatch(/x-slack-signature:\s*v0=deadbeef/iu);
    expect(good.join(" ")).toMatch(/x-slack-signature:\s*v0=[0-9a-f]{64}/u);

    // Same body both times. A different body would make the 401 provable by the
    // body rather than by the signature, which is not the property under test.
    const bodyOf = (call) => call[call.indexOf("--data-binary") + 1];
    expect(bodyOf(bad)).toBe(bodyOf(good));
    expect(bodyOf(good)).toMatch(/^payload=/u);
    expect(decodeURIComponent(bodyOf(good).slice("payload=".length))).toContain(
      "cleanup_approve",
    );

    // The record is read back BY NAME, so "a record was written" is a positive
    // assertion rather than the absence of an error.
    const claimReads = callRecords.filter(
      ([tool, service, operation, , name]) =>
        tool === "aws" &&
        service === "ssm" &&
        operation === "get-parameter" &&
        String(name).includes("/approvals/approved-"),
    );
    expect(claimReads.length).toBeGreaterThanOrEqual(2);

    // And the apply task's own exit code is checked. Without this the harness
    // would pass on a click that started a task which then crashed.
    const describes = callRecords.filter(
      ([tool, service, operation]) =>
        tool === "aws" && service === "ecs" && operation === "describe-tasks",
    );
    expect(describes.length).toBeGreaterThanOrEqual(1);
    expect(describes.some((c) => c.join(" ").includes("task-abc"))).toBe(true);

    // Both parameters are removed, so a rerun is not blocked by its own leftovers
    // (the offered record is overwritten, but the claim is written with
    // Overwrite:false and would make the second run's click a losing claim).
    const deletes = callRecords.filter(
      ([tool, service, operation]) =>
        tool === "aws" && service === "ssm" && operation === "delete-parameter",
    );
    expect(deletes).toHaveLength(2);
  });

  it("TC-SLACKAPP-090 the secret never reaches the output, and never an argv", () => {
    const { callRecords, output } = runFixture({ claim: claimWith() });
    // stdout/stderr is CI output, which is retained per-run and readable by
    // anyone with Actions access.
    expect(output).not.toContain(SECRET);
    expect(JSON.stringify(callRecords)).not.toContain(SECRET);

    // The argv half is asserted against the SOURCE, not the run. An argv is
    // visible to every process on the box, but the fakes above only see the
    // commands they replace — so a signer written as
    // `openssl dgst -hmac "$SIGNING_SECRET"` would put the secret in a
    // world-readable argv and satisfy every runtime assertion here. That is the
    // obvious way to write this in bash, which is exactly why it is pinned:
    // the secret must reach its consumer through the ENVIRONMENT.
    //
    // Scanned over EXECUTABLE lines only. The comment above the signer names
    // `openssl dgst -hmac "$SECRET"` as the anti-pattern it exists to warn about,
    // and a scan of the raw file flags that prose as the very thing it forbids.
    // Full-line comments only — `#` also appears mid-code in `${VAR##*/}`, so
    // truncating every line at its first `#` would mangle the code being scanned,
    // and a trailing comment cannot hide a command from this either way.
    const code = readFileSync(script, "utf8")
      .split("\n")
      .filter((line) => !/^\s*#/u.test(line))
      .join("\n");
    const secretRefs = code.match(/[^\n]*\$\{?SIGNING_SECRET\}?[^\n]*/gu) ?? [];
    expect(secretRefs.length).toBeGreaterThan(0);
    for (const line of secretRefs) {
      // Allowed: the SSM read that produces it, the emptiness check that gates
      // the skip, and an `NAME="$SIGNING_SECRET"` environment assignment.
      const isEnvAssignment = /\b[A-Z_]+="\$SIGNING_SECRET"/u.test(line);
      const isGuard = /^\s*(SIGNING_SECRET=|if \[\[|.*-z "\$SIGNING_SECRET")/u.test(line);
      expect(
        isEnvAssignment || isGuard,
        `the secret is interpolated into a command line: ${line.trim()}`,
      ).toBe(true);
    }
    expect(code).not.toMatch(/-hmac\s+"?\$/u);
  });

  it("TC-SLACKAPP-090 a 200 on the INVALID signature fails the run", () => {
    // The case the whole harness exists for. A facade that accepted an unsigned
    // interaction would otherwise pass every other assertion here.
    const { result, output } = runFixture({
      badSignatureStatus: "200",
      claim: claimWith(),
    });
    expect(result.status).not.toBe(0);
    expect(output).toMatch(/invalid signature/iu);
  });

  it("TC-SLACKAPP-090 a non-200 on the VALID signature fails the run", () => {
    const { result, output } = runFixture({ approveStatus: "500", claim: claimWith() });
    expect(result.status).not.toBe(0);
    expect(output).toMatch(/signed interaction/iu);
  });

  it("TC-SLACKAPP-090 an absent approval record fails the run", () => {
    // A 200 is not proof: the handler answers 200 for "already applied", for an
    // unknown action, and for a stale hash. Only the record proves the claim.
    const { result, output } = runFixture({ claim: null });
    expect(result.status).not.toBe(0);
    // Pinned to the phrase only THIS branch emits. `/approval record/` also
    // matches the taskArn branch's message, so a script that dropped the record
    // check entirely still satisfied it — the failure arrived one step later, from
    // `jq` finding no taskArn in an empty string, and looked identical.
    expect(output).toMatch(/no approval record at/iu);
  });

  it("TC-SLACKAPP-090 a claim with no taskArn fails the run", () => {
    // The claim exists but nothing was started — the exact state a RunTask
    // failure leaves behind, and the one an operator most needs surfaced.
    const raw = JSON.parse(claimWith());
    delete raw.taskArn;
    const { result, output } = runFixture({ claim: JSON.stringify(raw) });
    expect(result.status).not.toBe(0);
    expect(output).toMatch(/has no taskArn/iu);
  });

  it("TC-SLACKAPP-090 an apply task that exits non-zero fails the run", () => {
    const { result, output } = runFixture({ claim: claimWith(), taskExitCode: "6" });
    expect(result.status).not.toBe(0);
    expect(output).toMatch(/exited 6/iu);
  });

  it("TC-SLACKAPP-090 a stage with no Slack secret skips instead of failing", () => {
    // Slack approval is gated on MEM9_SLACK_APPROVAL_ENABLED at SYNTH time, so a
    // stage that did not seed the secrets has no endpoint to test. A hard failure
    // there would block every PR on a feature the stage does not deploy — the
    // same shape as run-oauth-facade-smoke.sh's absent-facade skip.
    const { callRecords, result, output } = runFixture({ secret: "" });
    expect(result.status, output).toBe(0);
    expect(output).toMatch(/skipping/iu);
    // And it must not have half-run: no seeded record, no POST.
    expect(
      callRecords.filter(
        ([tool, service, operation]) =>
          tool === "aws" && service === "ssm" && operation === "put-parameter",
      ),
    ).toHaveLength(0);
    expect(callRecords.filter(([tool]) => tool === "curl")).toHaveLength(0);
  });

  it("TC-SLACKAPP-090 a failure still removes the records it seeded", () => {
    // Otherwise the first failure leaves an `approvals/offered` record behind on
    // the stage, and the NEXT run's click is answered against it.
    const { callRecords, result } = runFixture({ approveStatus: "500", claim: claimWith() });
    expect(result.status).not.toBe(0);
    const deletes = callRecords.filter(
      ([tool, service, operation]) =>
        tool === "aws" && service === "ssm" && operation === "delete-parameter",
    );
    expect(deletes.length).toBeGreaterThanOrEqual(1);
  });

  it("TC-SLACKAPP-090 a protected stage is refused before anything is written", () => {
    // The harness OVERWRITES `approvals/offered` to seed its synthetic id. On prod
    // that destroys a pending human approval — the operator's next click is then
    // answered against CI's record — and the id it approves is a DELETION against
    // the live database. The CI step is preview-only, but a workflow edit or a
    // manual run is one env var away from prod, so the refusal lives in the script
    // where neither can bypass it.
    for (const stage of ["prod", "PROD", "production", "staging"]) {
      const { callRecords, result, output } = runFixture({ stage, claim: claimWith() });
      expect(result.status, `${stage}: ${output}`).not.toBe(0);
      expect(output).toMatch(/refusing to run against/iu);
      // Refused BEFORE the seed, not after: a run that wrote first and failed
      // second has already clobbered the record it was protecting.
      expect(
        callRecords.filter(
          ([tool, service, operation]) =>
            tool === "aws" && service === "ssm" && operation === "put-parameter",
        ),
        `${stage} seeded a record before refusing`,
      ).toHaveLength(0);
      expect(callRecords.filter(([tool]) => tool === "curl")).toHaveLength(0);
    }

    // And it is a REFUSAL, not a skip: an exit 0 here would let a workflow edit
    // silently stop testing anything while reporting green.
    const { result } = runFixture({ stage: "prod", claim: claimWith() });
    expect(result.status).toBe(1);
  });

  it("TC-SLACKAPP-090 the approved id cannot name a real memory", () => {
    // The harness approves a DELETION. An id that resolved to real preview data
    // would delete it — so the id is a synthetic sentinel, and the apply's
    // "already gone" branch is what makes the run exit 0.
    const { callRecords } = runFixture({ claim: claimWith() });
    const put = callRecords.find(
      ([tool, service, operation]) =>
        tool === "aws" && service === "ssm" && operation === "put-parameter",
    );
    const value = JSON.parse(put[put.indexOf("--value") + 1]);
    expect(value.ids).toHaveLength(1);
    expect(value.ids[0]).toMatch(/e2e/iu);
    // Hash over the ids, the same derivation the apply task re-computes. A
    // mismatch there refuses the apply, so this is what makes the run reach it.
    expect(value.hash).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(value.stage).toBe("pr-123");
  });
});
