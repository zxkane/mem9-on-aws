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
  cluster = "mem9-cleanup-cluster",
  stoppedReason = "Essential container in task exited",
  facadeError = "",
  noisyStderr = "",
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
// The real CLI writes to stderr on SUCCESSFUL calls too — a botocore deprecation
// notice, a credential-source line. Every other knob in this fake writes stderr
// only when it also exits non-zero, which is exactly why merging the streams with
// \`2>&1\` looked harmless: no case could produce the polluted-value shape.
if (process.env.MOCK_NOISY_STDERR) console.error(process.env.MOCK_NOISY_STDERR);
// The real CLI writes this to STDERR and exits 255 for an absent parameter. The
// script distinguishes it from every other failure by that text, so a fake that
// merely exited 255 would let an AccessDenied-style regression pass as a skip —
// the fake has to be wrong in the same shape as reality to test anything.
const notFound = (name) => {
  console.error(
    "An error occurred (ParameterNotFound) when calling the GetParameter " +
      \`operation: Parameter \${name} not found.\`,
  );
  process.exit(255);
};
// Every OTHER way a read can fail: no ParameterNotFound text, so the script has
// no license to treat it as "not deployed". The real CLI's exit code for these is
// 255 as well, which is precisely why the code cannot be the discriminator.
const readError = (name, code) => {
  console.error(
    \`An error occurred (\${code}) when calling the GetParameter operation: \` +
      \`explicit deny in a service control policy or resource policy for \${name}\`,
  );
  process.exit(255);
};
if (command === "ssm get-parameter") {
  const name = option("--name") ?? "";
  if (name.endsWith("/facade/url")) {
    if (process.env.MOCK_FACADE_ERROR) {
      readError(name, process.env.MOCK_FACADE_ERROR);
    }
    if (!process.env.MOCK_FACADE) notFound(name);
    console.log(process.env.MOCK_FACADE);
  } else if (name.endsWith("/slack/signing-secret")) {
    if (!process.env.MOCK_SECRET) notFound(name);
    console.log(process.env.MOCK_SECRET);
  } else if (name.endsWith("/cleanup/cluster-name")) {
    if (!process.env.MOCK_CLUSTER) notFound(name);
    console.log(process.env.MOCK_CLUSTER);
  } else if (name.includes("/approvals/approved-")) {
    // Stateful, like a real stage: no claim exists until the signed click
    // creates one. A fake that served it unconditionally would make the
    // pre-click "no record was written" assertion fail against a correct script.
    if (!existsSync(process.env.MOCK_CLICKED) || !process.env.MOCK_CLAIM) {
      notFound(name);
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
  // The cluster is asserted, not ignored: the script must pass the name it read
  // from SSM. Slicing it out of the task ARN (the previous implementation) yields
  // the task id on an account without the long-ARN opt-in, and a fake that
  // accepted any --cluster could not tell the two apart.
  if (option("--cluster") !== process.env.MOCK_CLUSTER) {
    console.error(
      "An error occurred (ClusterNotFoundException) when calling the " +
        \`DescribeTasks operation: cluster not found: \${option("--cluster")}\`,
    );
    process.exit(254);
  }
  if (query.includes("lastStatus")) console.log(process.env.MOCK_TASK_STATUS);
  else if (query.includes("exitCode")) console.log(process.env.MOCK_TASK_EXIT);
  else console.log(process.env.MOCK_STOP_REASON);
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
      MOCK_CLUSTER: cluster,
      MOCK_STOP_REASON: stoppedReason,
      MOCK_FACADE_ERROR: facadeError,
      MOCK_NOISY_STDERR: noisyStderr,
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

  it("TC-SLACKAPP-090b a parameter read that fails for any reason OTHER than absence is a hard failure", () => {
    // The distinction the gate depends on. `2>/dev/null || true` collapsed every
    // error into "" and every "" into a skip, so an AccessDenied — say a boundary
    // change leaving the CI role only the plural `ssm:GetParameters` — would have
    // reported green forever while sending no request at all. That is the same
    // vacuous-gate failure the pr-N refusal exists to prevent.
    const { callRecords, result, output } = runFixture({ facadeError: "AccessDeniedException" });
    expect(result.status, output).not.toBe(0);
    expect(output).toMatch(/AccessDeniedException/u);
    // And it must not be mistaken for the benign skip.
    expect(output).not.toMatch(/skipping/iu);
    expect(callRecords.filter(([tool]) => tool === "curl")).toHaveLength(0);
  });

  it("TC-SLACKAPP-090b the cluster comes from SSM, not from slicing the task ARN", () => {
    // `${TASK_ARN##*:task/}` assumes the long ARN format. On an account without
    // the long-ARN opt-in the ARN carries no cluster segment, so the slice yields
    // the task id and every describe-tasks runs against a cluster that does not
    // exist. The fake rejects a mismatched --cluster, so this fails if the script
    // ever goes back to deriving it.
    const { callRecords, result, output } = runFixture({
      claim: claimWith(),
      cluster: "mem9-real-cluster",
    });
    expect(result.status, output).toBe(0);
    const describes = callRecords.filter(
      ([tool, service, operation]) =>
        tool === "aws" && service === "ecs" && operation === "describe-tasks",
    );
    expect(describes.length).toBeGreaterThanOrEqual(1);
    for (const call of describes) {
      expect(call).toContain("mem9-real-cluster");
    }
  });

  it("TC-SLACKAPP-090b a task that never ran its container is named as a startup failure", () => {
    // ECS reports a NULL exitCode as the literal "None" when the task died before
    // the entrypoint — the predicted first-deploy outcome while the execution role
    // is outside the boundary's secret-decrypt exception list. "exited None" would
    // send the next engineer looking for an application bug.
    const { result, output } = runFixture({
      claim: claimWith(),
      taskExitCode: "None",
      stoppedReason: "ResourceInitializationError: unable to pull secrets",
    });
    expect(result.status, output).not.toBe(0);
    expect(output).toMatch(/never ran its container/iu);
    expect(output).toMatch(/ResourceInitializationError/u);
  });

  it("TC-SLACKAPP-090b an unexpected stoppedReason fails the run even when the exit code is 0", () => {
    // stoppedReason used to be fetched, printed, and never asserted. A task killed
    // by OOM can stop with a reason set, and only the essential-container message
    // is benign here.
    const { result, output } = runFixture({
      claim: claimWith(),
      taskExitCode: "0",
      stoppedReason: "OutOfMemoryError: container killed due to memory usage",
    });
    expect(result.status, output).not.toBe(0);
    expect(output).toMatch(/unexpected reason/iu);
    expect(output).toMatch(/OutOfMemoryError/u);
  });

  it("TC-SLACKAPP-090b a warning the CLI prints on a SUCCESSFUL call never lands in the value", () => {
    // `out=$(aws ... 2>&1)` reads as a harmless way to capture the error text for
    // the classifier, but on the success path it prepends stderr onto the VALUE.
    // Two of the values read here make that a real failure rather than cosmetic:
    // the cluster name, which then matches no cluster, and the signing secret,
    // which is HMAC'd — producing a signature the facade correctly rejects, so the
    // harness would blame the facade for its own contamination.
    const { callRecords, result, output } = runFixture({
      claim: claimWith(),
      cluster: "mem9-real-cluster",
      noisyStderr: "urllib3 v2 only supports OpenSSL 1.1.1+",
    });
    expect(result.status, output).toBe(0);
    // The signature is the load-bearing one: a polluted secret still produces a
    // well-formed hex digest, so only the fake's own signature check can tell.
    // The fake `curl` treats any non-matching signature as invalid, and the valid
    // click must still have been accepted for the run to reach exit 0 at all.
    const describes = callRecords.filter(
      ([tool, service, operation]) =>
        tool === "aws" && service === "ecs" && operation === "describe-tasks",
    );
    expect(describes.length).toBeGreaterThanOrEqual(1);
    for (const call of describes) {
      // The value, not the value with a warning glued to its front.
      expect(call).toContain("mem9-real-cluster");
    }
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
