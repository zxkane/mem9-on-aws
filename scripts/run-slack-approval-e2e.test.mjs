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
  readdirSync,
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
 * Taint-audit the harness source for the one property TC-SLACKAPP-090 pins: the
 * signing secret, and anything assigned from it, may reach a child process only
 * through the ENVIRONMENT — never as a command word.
 *
 * That distinction is the whole point. A prefix assignment
 * (`NAME="$SECRET" cmd ...`) puts the value in the child's environment, readable
 * through `/proc/PID/environ` by its owner alone. A command word (`cmd "$SECRET"`,
 * `cmd -hmac "$SECRET"`, `cmd --key="$SECRET"`) puts it in `/proc/PID/cmdline`,
 * which is world-readable — on a shared or self-hosted runner that is every other
 * process on the box.
 *
 * Deliberately spelling-independent: it audits the POSITION each expansion holds
 * in its line, not the flag preceding it, so no tool name or flag needs listing
 * and a signer rewritten around a different tool is judged by the same rule. The
 * exempting position is the one a COMMAND could occupy; `atCommandStart` below
 * explains why that is stricter than "an identifier and an `=` precede the value",
 * and has to be.
 *
 * @param code the script with full-line comments already stripped
 * @returns `taint` — every name transitively assigned from `SIGNING_SECRET`,
 *          `SIGNING_SECRET` first; `uses` — how many expansions of a tainted name
 *          were examined and `envUses` how many of those actually handed the value
 *          to a child through the environment, so the caller can reject a vacuous
 *          pass; `violations` — each use of a tainted name that is neither an
 *          assignment nor inside a test builtin.
 */
function auditSecretTaint(code) {
  // Line continuations joined first, so every rule below sees a whole simple
  // command. Split, `NAME="$SECRET" \` ends its line and the child on the next line
  // is invisible — which would report the sanctioned form as reaching no child.
  const lines = code.replace(/\\\n\s*/gu, " ").split("\n");
  const taint = new Set(["SIGNING_SECRET"]);
  // One shell word of the form `NAME=value`, value double-quoted, single-quoted, or
  // bare. Used twice: to recognise the assignment an expansion sits in, and to skip
  // the assignments that may precede the command word in `A=1 B=2 cmd`.
  const ASSIGNMENT_WORD = String.raw`[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|[^\s"']*)`;
  // A `NAME=` standing exactly where a COMMAND could start: between it and the last
  // command boundary lies nothing but other assignment words and an optional
  // declarator. That POSITION, rather than the mere presence of an identifier and an
  // `=`, is what separates the sanctioned prefix assignment from an `=`-bearing
  // argument to a command already underway — `awk -v key="$TAINTED"` and
  // `docker run -e SEC="$TAINTED"` are identical in the two characters before the
  // expansion yet put the value on a world-readable cmdline. Requiring the command
  // position rejects both, and `cmd --key="$TAINTED"` with them.
  const atCommandStart = (declarator) =>
    new RegExp(
      String.raw`(?:^|[;&|(){]|\b(?:then|do|else|in)\s)\s*${declarator}` +
        String.raw`(?:${ASSIGNMENT_WORD}\s+)*[A-Za-z_][A-Za-z0-9_]*=(?:"|')?$`,
      "u",
    );
  // Any assignment — standalone, prefix, or declared — versus the `export` subset,
  // which reaches every later child's environment without a command on its own line.
  const ASSIGNMENT = atCommandStart(String.raw`(?:(?:local|export|declare|readonly)\s+)?`);
  const EXPORT = atCommandStart(String.raw`export\s+`);
  // The command a prefix assignment run hands the value to, past any further
  // assignment words: `A="$T" B=2 cmd` is one prefix run, one command.
  const COMMAND_AFTER_PREFIX = new RegExp(String.raw`^(?:\s+${ASSIGNMENT_WORD})*\s+[^\s#;&|)]`, "u");
  // `$NAME`, or `${NAME` followed by ANY parameter-expansion operator — `${NAME}`,
  // but equally `${NAME:-}`, `${NAME#}`, `${NAME%%x}`, `${NAME@Q}`, `${NAME:0:99}`,
  // `${NAME^^}`, `${NAME//a/b}`. Matching only the bare `${NAME}` left the whole
  // audit defeasible by ONE character: `"${SIGNING_SECRET#}"` on a command line is
  // the secret, verbatim, yet went unseen — and unseen by `uses` too, so not even
  // the non-vacuity counter noticed. The operator does not have to be meaningful to
  // be an exfiltration route; it only has to be syntax the auditor did not enumerate,
  // which is the same mistake the `-hmac` allowlist made one layer up.
  //
  // The trailing guard on the bare form keeps a taint on `KEY` from flagging every
  // `$KEYSTORE`, and the braced form gets it too, so `${KEYSTORE}` is not read as a
  // modified `${KEY}`. `${#NAME}` is deliberately NOT matched: that is the length,
  // not the value.
  const expansion = (name, flags = "u") =>
    new RegExp(String.raw`\$(?:\{${name}(?![A-Za-z0-9_])[^}]*\}|${name}(?![A-Za-z0-9_]))`, flags);
  // Assignments anywhere a shell word can start, not only at a line's start: a
  // launder hidden after `;` or `&&` (`if x; then B="$SECRET"; fi`) is still a
  // launder. A declarator needs no clause of its own — the space after `local` or
  // `readonly` is itself the boundary the target name follows.
  const assignments = (line) =>
    [...line.matchAll(/(?:^|[\s;&|(])([A-Za-z_][A-Za-z0-9_]*)=(\S*)/gu)];

  // Transitive closure over `NAME="$TAINTED"` / `NAME=$TAINTED`, repeated until it
  // stops growing: a two-hop launder (`A="$SIGNING_SECRET"; B="$A"; cmd "$B"`) is
  // no less an argv leak than a one-hop one.
  let size = 0;
  while (size !== taint.size) {
    size = taint.size;
    for (const line of lines) {
      for (const [, target, value] of assignments(line)) {
        if ([...taint].some((name) => expansion(name).test(value))) taint.add(target);
      }
    }
  }

  const violations = [];
  let uses = 0;
  let envUses = 0;
  for (const name of taint) {
    for (const line of lines) {
      // Every expansion of this name on this line, judged by what precedes it.
      for (const match of line.matchAll(expansion(name, "gu"))) {
        uses += 1;
        const before = line.slice(0, match.index);
        const after = line.slice(match.index + match[0].length).replace(/^["']/u, "");
        // An assignment — `NAME=$TAINTED`, whether standalone, `local`/`export`, or
        // the prefix form `NAME="$TAINTED" cmd` — is the sanctioned channel, since it
        // reaches the child through the environment. See `atCommandStart` for why the
        // position and not the `=` is what is tested.
        if (ASSIGNMENT.test(before)) {
          // Counted so the caller can tell "the harness signs something with this
          // secret" from "nothing here mentions it any more". A PREFIX assignment
          // counts only once a COMMAND is found after it; an `export` counts on its
          // own, having no command to wait for. "Something follows on the line" would
          // not support the claim: full-line comments are stripped before this but
          // TRAILING ones are not, so `K="$SECRET"  # alias` would read as handing the
          // value to a child, and a signer deleted with its alias left behind would
          // satisfy the very non-vacuity check that exists to fail it.
          if (EXPORT.test(before) || COMMAND_AFTER_PREFIX.test(after)) envUses += 1;
          continue;
        }
        // `[[ -z "$TAINTED" ]]` and `[[ "$TAINTED" == None ]]` — the emptiness
        // guard that gates the skip. A test builtin forks no child, so there is no
        // cmdline for the value to land in.
        //
        // Scoped to the test builtin the expansion is INSIDE, not to "a `[[`
        // appeared earlier on this line": the latter excused everything after a
        // guard, so `[[ -n "$X" ]] && cmd "$TAINTED"` passed. Closed by requiring no
        // `]]`/`]` between the opening bracket and this expansion.
        const opened = before.search(/(?:^|\s)\[\[?(?:\s|$)/u);
        const insideTestBuiltin =
          opened !== -1 && !/(?:^|\s)\]\]?(?:\s|$|;|&|\|)/u.test(before.slice(opened));
        if (insideTestBuiltin) continue;
        // A here-string is not an argv either, and the rule was inverted for it:
        // `cmd <<<"$TAINTED"` hands the value over on a file descriptor, which is
        // strictly MORE private than the environment this test sanctions, yet it was
        // reported as "argv is world-readable" about a line containing no argv. A
        // maintainer hardening the signer that way would have hit a failure telling
        // them to do the opposite, which is worse than a missing rule. Recognised by
        // the redirection operator, so it stays a position rule.
        if (/(?:<<<|(?:^|\s)<)\s*["']?$/u.test(before)) continue;
        // Everything else is a violation, INCLUDING two shapes that are safe in
        // practice and are rejected on purpose, because admitting them costs more
        // than the false positive does:
        //
        // `printf '%s' "$TAINTED" | cmd` is safe only because `printf` is a bash
        // builtin that forks nothing. The position alone cannot tell that: an
        // external command in the same spot — `openssl dgst -hmac "$TAINTED" | tee` —
        // is a genuine leak, and separating them means enumerating builtins, which is
        // the vocabulary-dependence this whole audit exists to avoid. Piping from a
        // builtin is a refactor nobody needs; a leak waved through is not recoverable.
        //
        // `sign() { ... }; sign "$TAINTED"` likewise forks no process, but exempting a
        // call to a function defined in this file would only move the question inside
        // it: whether `$1` then reaches a command word is an analysis this does not
        // do, so the exemption would be a laundering route with a `()` for a key.
        violations.push({ name, segment: line.trim() });
      }
    }
  }
  return { taint: [...taint], uses, envUses, violations };
}

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
  expiryBehavior = "refuse",
  tamperBehavior = "refuse",
  accountId = "123456789012",
  taskDef = "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-cleanup:7",
  containerName = "Mem9Cleanup",
  logGroup = "/sst/cluster/mem9-pr-123-a1b2c3/Mem9Cleanup-d4e5f6",
  logPrefix = "mem9",
  replayLines = "1",
  failingJqFilter = "",
} = {}) {
  const directory = mkdtempSync(join(tmpdir(), "mem9-slack-e2e-"));
  temporaryPaths.push(directory);
  const bin = join(directory, "bin");
  const calls = join(directory, "calls.jsonl");
  const s3Directory = join(directory, "s3");
  const tmpRoot = join(directory, "tmp");
  mkdirSync(bin);
  mkdirSync(s3Directory);
  mkdirSync(tmpRoot);

  /**
   * Write an executable stub onto the fixture's PATH.
   *
   * The `chmodSync` after the `mode` is not redundant: `writeFileSync`'s mode is
   * masked by the process umask, so under a 0o077 umask the file lands 0o700 —
   * still executable by this test, but the explicit chmod is what keeps that from
   * depending on the runner's umask at all. Every stub needs both, which is the
   * whole reason this is a helper rather than five call sites.
   */
  const stub = (name, source) => {
    const path = join(bin, name);
    writeFileSync(path, source, { mode: 0o755 });
    chmodSync(path, 0o755);
    return path;
  };

  stub(
    "aws",
    // The shebang is the ABSOLUTE interpreter, never `env node`: this fixture
    // prepends `bin` to PATH (below), so `env node` would resolve to any file
    // named `node` in `bin` — and a stub that re-invokes `node` then forks
    // forever. That is not hypothetical; it once spawned ~70k processes and
    // exhausted the systemd user slice's TasksMax.
    `#!${process.execPath}
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
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
  } else if (name.endsWith("/cleanup/task-def-arn")) {
    if (!process.env.MOCK_TASK_DEF) notFound(name);
    console.log(process.env.MOCK_TASK_DEF);
  } else if (name.includes("/approvals/approved-")) {
    // Stateful, like a real stage: no claim exists until the signed click
    // creates one. A fake that served it unconditionally would make the
    // pre-click "no record was written" assertion fail against a correct script.
    //
    // And served under ONE name — the dashed hash of the record the click was
    // answered against, which is what \`claimParameterName(prefix, offered.hash)\`
    // keys the real claim on. A fake that answered every \`approved-*\` name would
    // hide the mistake this models: a click accepted against a TAMPERED record
    // writes its claim under the tampered hash, so a harness watching only the
    // reviewed name would report "no claim" while an apply was running (#150).
    const claimedHash = existsSync(process.env.MOCK_CLICKED)
      ? readFileSync(process.env.MOCK_CLICKED, "utf8").trim()
      : "";
    if (!claimedHash || !process.env.MOCK_CLAIM || !name.endsWith(claimedHash)) {
      notFound(name);
    }
    console.log(process.env.MOCK_CLAIM);
  } else {
    console.error("unexpected parameter:", name);
    process.exit(2);
  }
} else if (command === "ssm put-parameter") {
  // The offered record is kept, not discarded, because the fake facade below
  // decides the TTL question from it — exactly as the real handler does, which
  // reads \`approvals/offered\` rather than trusting anything in the payload. A fake
  // that answered every signed click identically could not tell an expired list
  // from a live one, so the expiry step would pass against a handler with no
  // expiry check at all (#149).
  if ((option("--name") ?? "").endsWith("/approvals/offered")) {
    writeFileSync(process.env.MOCK_OFFERED, option("--value") ?? "");
  }
  process.exit(0);
} else if (command === "ssm delete-parameter") {
  process.exit(0);
} else if (command === "sts get-caller-identity") {
  // The artifact bucket is NOT an SSM parameter — it is an environment entry on
  // the task definition — so the harness derives \`mem9-audit-<account>\` from the
  // caller's own identity. A malformed value here is a fixture knob because the
  // script has to refuse it: an empty or non-numeric account would build a bucket
  // name that S3 rejects, and the resulting upload failure would read as a
  // permissions problem.
  console.log(process.env.MOCK_ACCOUNT_ID ?? "");
} else if (command === "s3api put-object") {
  // The artifact objects. Recorded rather than stored, and the BODY is read from
  // the path the script passed: the assertions are about what the script
  // serialized, and a fake that only logged the flags could not tell a reviewed
  // artifact from its tampered twin.
  const body = option("--body");
  writeFileSync(
    \`\${process.env.MOCK_S3_DIR}/\${(option("--key") ?? "").replace(/\\//gu, "_")}\`,
    body ? readFileSync(body) : "",
  );
  // No --server-side-encryption is EXPECTED here, so it is not defaulted or
  // validated: the bucket's own rule applies (SSE-KMS, bucket keys on), and naming
  // the key would present an encryption context the apply task's conditioned
  // kms:Decrypt does not match.
  process.exit(0);
} else if (command === "s3api delete-object") {
  process.exit(0);
} else if (command === "ecs describe-task-definition") {
  // The log group and stream prefix the replay assertion needs, shaped like SST's
  // real output: hash-suffixed names nobody can compute by hand, which is why the
  // script reads them from here (#137) rather than assuming a \`/sst/...\` path.
  console.log(
    JSON.stringify({
      taskDefinition: {
        containerDefinitions: [
          {
            name: process.env.MOCK_CONTAINER_NAME,
            logConfiguration: {
              options: {
                "awslogs-group": process.env.MOCK_LOG_GROUP,
                "awslogs-stream-prefix": process.env.MOCK_LOG_PREFIX,
              },
            },
          },
        ],
      },
    }),
  );
} else if (command === "logs filter-log-events") {
  // \`--query length(events)\` — so this answers a COUNT, which is all the script
  // reads. The line itself names the bucket, and the bucket name carries the
  // account id, so a harness that printed a match would leak it into public CI
  // logs.
  //
  // The pattern is asserted, not ignored: a script that queried for the wrong
  // phrase would find nothing on a healthy stage and report a re-classification
  // that never happened.
  const matched = (option("--filter-pattern") ?? "").includes(
    "reviewed decision(s) from s3://",
  );
  console.log(matched ? (process.env.MOCK_REPLAY_LINES ?? "0") : "0");
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
  );

  // The fake `curl` decides which POST it is by the SIGNATURE header, exactly as
  // the real endpoint does: that is the one thing this E2E exists to exercise.
  //
  // It also re-implements the handler's ONE other decision the harness now depends
  // on — the 72h offer window — by reading the seeded `approvals/offered` record,
  // which is where the real `loadOffered` reads it from too. Modelling it rather
  // than answering every signed click alike is what gives the expiry step teeth: a
  // fake that always accepted would pass the same whether the script stamped
  // `issuedAt` or not, which is the exact regression this exists to catch.
  stub(
    "curl",
    `#!${process.execPath}
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(process.env.MOCK_CALLS, JSON.stringify(["curl", ...args]) + "\\n");
const option = (name) => {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
};
const headers = args.filter((a, i) => args[i - 1] === "-H");
const signature = headers.find((h) => /^x-slack-signature:/i.test(h)) ?? "";
const invalid = /deadbeef|invalid/i.test(signature);
// OFFER_TTL_MS, duplicated a third time and deliberately not imported: the value
// lives in a .ts Lambda source and a .mjs container script, and this fake is
// neither. TC-SLACKAPP-137 pins the two REAL copies to each other; this one only
// has to be the same order of magnitude as the ages the script seeds, which are
// "now" and "96h ago".
const OFFER_TTL_MS = 72 * 60 * 60 * 1000;
// Absent or unparseable \`issuedAt\` is EXPIRED, matching \`offerExpiry\` in
// infra/src/oauth-facade/slack-interactions.ts. That direction is what makes an
// unstamped seed a FAILURE here rather than a silent pass: a fake that treated an
// unknown age as live would accept the click and the harness would report green
// against a facade that refuses every one of its clicks in production.
const offered = existsSync(process.env.MOCK_OFFERED)
  ? JSON.parse(readFileSync(process.env.MOCK_OFFERED, "utf8") || "{}")
  : {};
const issuedAtMs = Date.parse(offered.issuedAt ?? "");
const expired = !Number.isFinite(issuedAtMs) || Date.now() - issuedAtMs > OFFER_TTL_MS;
// The hash comparison \`loadOffered\` makes BEFORE the expiry check: the button's
// value against the current record's. This is the guard the tampered-artifact step
// exercises, and modelling it is what gives that step teeth — a fake that answered
// every signed click alike would pass whether the façade compared hashes or not,
// which is precisely the regression that would let an unreviewed absorbed id be
// deleted (#150).
//
// Read out of the POSTed body rather than taken from a knob, so a script that
// clicked the TAMPERED hash instead of the reviewed one would find itself accepted
// and fail the ordering assertions instead of passing vacuously.
const body_ = args[args.indexOf("--data-binary") + 1] ?? "";
const clicked = (() => {
  try {
    const payload = new URLSearchParams(body_).get("payload") ?? "{}";
    return JSON.parse(payload).actions?.[0]?.value ?? "";
  } catch {
    return "";
  }
})();
// Ordered as the handler orders them: stale-hash BEFORE expiry, because an expired
// click must be told it expired rather than that the list was regenerated, and a
// fake with the comparison the other way round would let the script's
// \`grep -qi 'expire'\` assertion pass on a hash mismatch.
const staleHash = typeof offered.hash === "string" && offered.hash !== clicked;
// How this fake facade answers a click against an expired list. \`refuse\` is the
// real handler; the other three are the ways it could be broken, and each has to
// be REACHABLE for the script's expiry step to be worth anything — \`accept\` is a
// facade with no TTL check at all, \`cosmetic\` is one whose refusal message is
// right but which claims the approval anyway (so an apply starts), and \`error\`
// answers the refusal with a 5xx, which Slack renders as its own "operation
// failed" and shows the operator no reason at all.
const behavior = process.env.MOCK_EXPIRY_BEHAVIOR || "refuse";
// How this fake facade answers a click whose hash does not match the record.
// \`refuse\` is the real handler; \`accept\` is one with no comparison at all, which is
// the tampered-artifact regression, and \`cosmetic\` is one that says "regenerated"
// and claims the approval anyway — so an apply runs against a list nobody reviewed.
const tamperBehavior = process.env.MOCK_TAMPER_BEHAVIOR || "refuse";
const refusedForHash = staleHash && tamperBehavior !== "accept";
const refused = refusedForHash || (expired && behavior !== "accept");
// Slack renders a non-200 as its own "operation failed" and shows the operator
// nothing, so EVERY refusal the real handler makes goes through \`reply()\` — a 200
// with an ephemeral body. The refusal is in the body, never the status.
//
// Hence MOCK_APPROVE_STATUS answers only the click the facade ACCEPTS, and a
// refusal's status is independent of it: keeping the two knobs separate is what
// lets one fixture test a broken transport on the live click without also failing
// the expiry step two steps earlier.
let status;
if (invalid) status = process.env.MOCK_BAD_STATUS;
else if (!refused) status = process.env.MOCK_APPROVE_STATUS;
else if (refusedForHash) status = tamperBehavior === "error" ? "500" : "200";
else status = behavior === "error" ? "500" : "200";
// The refusal texts are the handler's own, in the handler's precedence: a stale
// hash reads "regenerated" and an expired list reads "expire". The script asserts
// the specific word for each case, so a fake that answered one generic refusal
// would let a script pass while testing the wrong guard.
const refusalText = refusedForHash
  ? "That list has been regenerated since it was posted. Nothing was applied."
  : "That list was issued a while ago and approvals expire after 72h. Nothing was applied.";
const body = invalid
  ? "unauthorized"
  : JSON.stringify({
      response_type: "ephemeral",
      text: refused ? refusalText : "Apply started for 1 memories.",
    });
const out = option("-o");
if (out) writeFileSync(out, body);
// A 200 on the VALID signature is what creates the claim on a real stage — but
// only when the handler did not refuse. \`cosmetic\` claims despite refusing, which
// is the whole point of it.
const accepted = !invalid && !refused && status === "200";
const claimedDespiteRefusing =
  !invalid &&
  refused &&
  (refusedForHash ? tamperBehavior === "cosmetic" : behavior === "cosmetic");
if (accepted || claimedDespiteRefusing) {
  // The dashed hash of the record this click was answered AGAINST, not the button's
  // — that is what \`claimParameterName(prefix, offered.hash)\` keys the real claim
  // on, so an accepted tamper is discoverable only under the tampered name.
  writeFileSync(
    process.env.MOCK_CLICKED,
    String(offered.hash ?? clicked).replace(/:/gu, "-"),
  );
}
process.stdout.write(status);
`,
  );

  stub("sleep", "#!/usr/bin/env bash\nexit 0\n");

  // `mktemp` is stubbed unconditionally — into THIS case's directory and recording
  // every path it hands out, which is what lets a case assert that none of them
  // outlived the run. It stays a real temp file with a real unique name, so the
  // script cannot tell the difference; the only change is where it lands and that
  // the path is logged. TMPDIR alone would not do: the paths would be knowable but
  // not enumerable, and `mktemp` is called in `ssm_value` on every read too.
  const mktempLog = join(directory, "mktemp.log");
  stub(
    "mktemp",
    `#!${process.execPath}
import { appendFileSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
const path = join(mkdtempSync(process.env.MOCK_TMP_ROOT + "/t-"), "body");
appendFileSync(process.env.MOCK_MKTEMP_LOG, path + "\\n");
// Created empty, exactly as \`mktemp\` leaves it.
appendFileSync(path, "");
process.stdout.write(path + "\\n");
`,
  );

  // A `jq` that fails on ONE named filter and delegates everything else to the real
  // binary. Used to place an exit at a chosen point in the script without editing
  // it — the alternative, asserting on source text, could not tell a trap that runs
  // from one that is merely written down.
  if (failingJqFilter) {
    stub(
      "jq",
      `#!${process.execPath}
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
const args = process.argv.slice(2);
if (args.includes(process.env.MOCK_FAILING_JQ_FILTER)) {
  console.error("jq: error: simulated failure for " + process.env.MOCK_FAILING_JQ_FILTER);
  process.exit(5);
}
// stdin is a here-string in every call the script makes, so it must be forwarded.
const stdin = readFileSync(0);
const real = spawnSync("/usr/bin/jq", args, { input: stdin, encoding: "buffer" });
if (real.stdout) process.stdout.write(real.stdout);
if (real.stderr) process.stderr.write(real.stderr);
process.exit(real.status ?? 1);
`,
    );
  }

  const result = spawnSync("bash", [script], {
    encoding: "utf8",
    env: {
      ...process.env,
      MOCK_CALLS: calls,
      MOCK_CLICKED: join(directory, "clicked"),
      // Where the fake `aws` records the seeded offered record and the fake `curl`
      // reads it back, standing in for the SSM parameter both really use.
      MOCK_OFFERED: join(directory, "offered.json"),
      // Where the fake `s3api` lands the uploaded artifacts, so a case can read
      // back the exact bytes the script serialized.
      MOCK_S3_DIR: s3Directory,
      MOCK_TMP_ROOT: tmpRoot,
      MOCK_MKTEMP_LOG: mktempLog,
      MOCK_FAILING_JQ_FILTER: failingJqFilter,
      MOCK_EXPIRY_BEHAVIOR: expiryBehavior,
      MOCK_TAMPER_BEHAVIOR: tamperBehavior,
      MOCK_ACCOUNT_ID: accountId,
      MOCK_TASK_DEF: taskDef,
      MOCK_CONTAINER_NAME: containerName,
      MOCK_LOG_GROUP: logGroup,
      MOCK_LOG_PREFIX: logPrefix,
      MOCK_REPLAY_LINES: replayLines,
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
  // The uploaded objects, keyed by their S3 key with slashes flattened — the
  // artifacts a case parses to assert what was actually serialized.
  const uploads = Object.fromEntries(
    readdirSync(s3Directory).map((name) => [
      name,
      readFileSync(join(s3Directory, name), "utf8"),
    ]),
  );
  // Every path the stubbed `mktemp` handed out. `ssm_value`'s own scratch files are
  // in here too and it removes them itself, so a case asserting "none survived"
  // covers those as a free side-benefit.
  const temporaryBodies = (existsSync(mktempLog) ? readFileSync(mktempLog, "utf8") : "")
    .split("\n")
    .filter(Boolean);
  return {
    callRecords,
    uploads,
    result,
    temporaryBodies,
    output: `${result.stdout}${result.stderr}`,
  };
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

    // Four POSTs: the invalid signature, the expired list (TC-SLACKAPP-155), the
    // tampered artifact (TC-SLACKAPP-208), and the live click.
    const curls = callRecords.filter(([tool]) => tool === "curl");
    expect(curls).toHaveLength(4);

    // The INVALID signature goes first, so "no record" is asserted before the
    // valid click creates one. Reversed, the 401 case would have to assert the
    // absence of a record that already exists, which nothing can do.
    const [bad, , , good] = curls;
    expect(bad.join(" ")).toMatch(/x-slack-signature:\s*v0=deadbeef/iu);
    expect(good.join(" ")).toMatch(/x-slack-signature:\s*v0=[0-9a-f]{64}/u);

    // Same body every time. A different body would make the 401 provable by the
    // body rather than by the signature, which is not the property under test —
    // and would likewise make the expiry refusal provable by the stale-hash guard.
    const bodyOf = (call) => call[call.indexOf("--data-binary") + 1];
    for (const call of curls) expect(bodyOf(call)).toBe(bodyOf(good));
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

    // Every parameter is removed, so a rerun is not blocked by its own leftovers
    // (the offered record is overwritten, but a claim is written with
    // Overwrite:false and would make the second run's click a losing claim).
    // THREE names now: the offer, the reviewed claim, and the tampered claim — the
    // last because an accepted tamper would write under its own hash, and a leftover
    // there would silently disarm the next run's tampered-artifact step.
    const deletes = callRecords.filter(
      ([tool, service, operation]) =>
        tool === "aws" && service === "ssm" && operation === "delete-parameter",
    );
    expect(deletes).toHaveLength(3);

    // And both artifact objects, so a torn-down preview stage leaves no readable
    // list behind — the tampered one especially, since it names an id no operator
    // reviewed.
    const objectDeletes = callRecords.filter(
      ([tool, service, operation]) =>
        tool === "aws" && service === "s3api" && operation === "delete-object",
    );
    expect(objectDeletes).toHaveLength(2);
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

    // Asserted as a TAINT property over the whole file, not as a per-line
    // allowlist. The earlier version inspected only lines that mention
    // `SIGNING_SECRET` and separately forbade the token `-hmac`, so one alias
    // defeated it: after `SIG_KEY="$SIGNING_SECRET"`, the signing line no longer
    // mentions the secret and is never inspected, the alias line itself reads as a
    // legal env assignment, and any tool whose flag is not spelled `-hmac` puts the
    // key on a world-readable argv with the whole suite still passing (issue #141).
    // What matters is not which flag carries the value but WHICH CHANNEL: an
    // assignment reaches the child through its environment (`/proc/PID/environ`,
    // owner-only), a command word reaches it through `/proc/PID/cmdline`, which every
    // user on the box can read.
    const { uses, envUses, violations } = auditSecretTaint(code);
    // The leak assertion comes FIRST so a real leak is reported as a leak. A
    // signer rewritten to pass the key on argv also stops passing it through the
    // environment, so it trips the non-vacuity check below too — and a failure
    // reading "expected 0 to be greater than 0" would send the reader looking for a
    // deleted signer rather than at the argv they just introduced.
    expect(
      violations,
      `a name tainted by SIGNING_SECRET reaches a command argument (argv is world-readable):\n${violations
        .map((v) => `  ${v.name}: ${v.segment}`)
        .join("\n")}`,
    ).toEqual([]);
    // Non-vacuity, asserted on what was EXAMINED rather than on the taint set:
    // `SIGNING_SECRET` is seeded by the auditor, so `taint` containing it proves
    // nothing. A file-wide rename of the secret drops `uses` to zero and fails here
    // rather than passing an audit of nothing. `envUses` is the positive half — the
    // secret does still reach a child, and through the environment — so this cannot
    // be satisfied by never using it, nor by deleting the signer and leaving the
    // alias assignment behind (`envUses` requires a command after the prefix).
    expect(uses).toBeGreaterThan(0);
    expect(envUses).toBeGreaterThan(0);
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

  it("TC-SLACKAPP-155 stamps issuedAt on the seeded offer, so the facade's TTL gate can pass it", () => {
    // The omission this case exists for was FATAL, not cosmetic. `offerExpiry` in
    // infra/src/oauth-facade/slack-interactions.ts reads an absent `issuedAt` as
    // EXPIRED (fail-closed: never apply against a record of unknown age), so a seed
    // carrying only `generatedAt` is refused at the expiry gate and the run dies
    // four steps later at "no approval record after a 200" — a message that names
    // the claim write and sends the reader to the Lambda's SSM grants.
    const { callRecords, result, output } = runFixture({ claim: claimWith() });
    expect(result.status, output).toBe(0);

    const seeds = callRecords.filter(
      ([tool, service, operation, , name]) =>
        tool === "aws" &&
        service === "ssm" &&
        operation === "put-parameter" &&
        String(name).endsWith("/approvals/offered"),
    );
    // Three seeds: the expired probe, the tampered record, then the live list. All
    // are asserted, because a script that stamped only the live one would leave the
    // expiry step passing for the WRONG reason — an unstamped record is refused as
    // expired too — and an unstamped TAMPERED record would be refused as expired
    // rather than as a hash mismatch, passing the wrong guard's test.
    expect(seeds).toHaveLength(3);
    const records = seeds.map((call) => JSON.parse(call[call.indexOf("--value") + 1]));
    for (const record of records) {
      expect(typeof record.issuedAt).toBe("string");
      // A real timestamp, not the string "now" or an empty field: `Date.parse` is
      // what the facade calls, and it is the only judge that matters.
      expect(Number.isFinite(Date.parse(record.issuedAt))).toBe(true);
    }

    // The ages, which is what the expiry pair is FOR: the first outside the 72h
    // window and the rest inside it. All derived from the same clock, so this holds
    // regardless of when the suite runs.
    const OFFER_TTL_MS = 72 * 60 * 60 * 1000;
    const ages = records.map((record) => Date.now() - Date.parse(record.issuedAt));
    expect(ages[0]).toBeGreaterThan(OFFER_TTL_MS);
    for (const age of ages.slice(1)) expect(age).toBeLessThan(OFFER_TTL_MS);

    // Same ids and same hash across the EXPIRED and LIVE seeds: what changes between
    // that refusal and the acceptance is `issuedAt` alone. A differing hash would
    // make the refusal provable by the stale-hash guard instead of the TTL — the
    // same same-body discipline the invalid-signature POST follows. The tampered
    // seed in between is the deliberate exception and is asserted separately
    // (TC-SLACKAPP-208).
    const [expiredRecord, , liveRecord] = records;
    expect(expiredRecord.hash).toBe(liveRecord.hash);
    expect(expiredRecord.ids).toEqual(liveRecord.ids);
  });

  it("TC-SLACKAPP-155 a facade that accepts an expired list fails the run", () => {
    // The property the expiry step actually asserts. Without a fake that can be
    // WRONG about the TTL, the step passes against a facade with no TTL check at
    // all, and the harness would report green on exactly the regression #149 adds
    // the gate to prevent.
    const { result, output } = runFixture({
      claim: claimWith(),
      expiryBehavior: "accept",
    });
    expect(result.status, output).not.toBe(0);
    expect(output).toMatch(/not refused as expired/iu);
  });

  it("TC-SLACKAPP-155 a refusal that still claims the approval fails the run", () => {
    // A facade whose MESSAGE is right and whose behaviour is not: it tells the
    // operator the list expired and starts the apply anyway. The reply assertion
    // alone cannot see this — only reading the claim back can, which is why the
    // expiry step ends with the same by-name read the 401 step uses.
    const { result, output } = runFixture({
      claim: claimWith(),
      expiryBehavior: "cosmetic",
    });
    expect(result.status, output).not.toBe(0);
    expect(output).toMatch(/the refusal is cosmetic/iu);
  });

  it("TC-SLACKAPP-155 a refusal answered with a 5xx fails the run", () => {
    // The refusal has to reach the OPERATOR, and Slack only renders a body it got
    // with a 200 — a non-200 becomes its own "operation failed" notice with no
    // reason in it. So a facade that refused correctly but answered 500 has an
    // expiry gate nobody can see the output of, which is a different bug from an
    // absent gate and is not covered by the message assertion.
    const { result, output } = runFixture({
      claim: claimWith(),
      expiryBehavior: "error",
    });
    expect(result.status, output).not.toBe(0);
    expect(output).toMatch(/answered HTTP 500, not 200/u);
    expect(output).toMatch(/shows the operator no reason/iu);
  });

  it("TC-SLACKAPP-155 the expired probe runs before any claim exists", () => {
    // Ordering, asserted rather than left to a comment. "An expired approval wrote
    // no claim" is only provable while no claim exists, so the probe has to sit
    // after the 401 and before the live click — and a maintainer moving it below
    // the successful click would find it passing vacuously against the record that
    // click created.
    const { callRecords, result, output } = runFixture({ claim: claimWith() });
    expect(result.status, output).toBe(0);
    const isSeed = ([tool, service, operation, , name]) =>
      tool === "aws" &&
      service === "ssm" &&
      operation === "put-parameter" &&
      String(name).endsWith("/approvals/offered");
    const clicks = callRecords
      .map((call, index) => ({ call, index }))
      .filter(({ call }) => call[0] === "curl");
    expect(clicks).toHaveLength(4);
    const [bad, expiredClick, , live] = clicks;
    expect(bad.call.join(" ")).toMatch(/x-slack-signature:\s*v0=deadbeef/iu);
    // The expired click is correctly SIGNED — the refusal is the TTL's doing, not
    // the signature's. Sharing the signature with the live click is what proves it.
    const signatureOf = (call) => call[call.indexOf("-H") + 1];
    expect(expiredClick.call.join(" ")).toMatch(/x-slack-signature:\s*v0=[0-9a-f]{64}/u);
    expect(signatureOf(expiredClick.call)).toBe(signatureOf(live.call));

    // And each click is preceded by the seed it is about: no seed before the 401
    // (nothing is written until the signature is proven to be rejected), one
    // before each of the three that follow.
    const seedsBefore = (index) =>
      callRecords.filter((call, i) => i < index && isSeed(call)).length;
    expect(seedsBefore(bad.index)).toBe(0);
    expect(seedsBefore(expiredClick.index)).toBe(1);
    expect(seedsBefore(live.index)).toBe(3);
  });

  it("TC-SLACKAPP-090 no approved id can name a real memory", () => {
    // The harness approves a DELETION and, since #150, a MERGE — which rewrites a
    // survivor as well as deleting its absorbed ids. An id that resolved to real
    // preview data would be destroyed either way, so EVERY id is a synthetic
    // sentinel and the apply's "already gone" / "survivor no longer active"
    // branches are what make the run exit 0.
    const { callRecords, uploads } = runFixture({ claim: claimWith() });
    const put = callRecords.find(
      ([tool, service, operation]) =>
        tool === "aws" && service === "ssm" && operation === "put-parameter",
    );
    const value = JSON.parse(put[put.indexOf("--value") + 1]);
    // Three: the DELETE, the merge survivor, and the absorbed id — the merge's full
    // destructive footprint, which is what `buildOfferedRecord` offers.
    expect(value.ids).toHaveLength(3);
    for (const id of value.ids) expect(id).toMatch(/^mem9-e2e-/u);
    expect(value.hash).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(value.stage).toBe("pr-123");

    // Asserted over the ARTIFACT as well, not just the record: the artifact is what
    // the apply task replays, so an id in there that the record omits is an id no
    // operator approved. The bound is `applyDecisions`' refusal, and this is the
    // harness's own half of it.
    for (const body of Object.values(uploads)) {
      const artifact = JSON.parse(body);
      for (const decision of artifact.decisions) {
        expect(decision.id).toMatch(/^mem9-e2e-/u);
        for (const absorbed of decision.absorbs ?? []) {
          expect(absorbed.id).toMatch(/^mem9-e2e-/u);
        }
      }
    }
  });

  it("TC-SLACKAPP-208 offers an approved MERGE whose artifact is built by the script under test", () => {
    // The MERGE half of #150, and the reason the artifact is serialized by importing
    // `serializeDecisionArtifact`/`decisionArtifactHash`/`decisionArtifactKey` rather
    // than by hand: a hand-written JSON literal plus a shell `shasum` would prove
    // only that the harness agrees with itself. The property that matters is that the
    // bytes the apply task FETCHES hash to the value the button carried, and those
    // three functions are the sole authority on it — a re-implemented key or a
    // different field order would pass this harness and fail the real loop.
    const { uploads, callRecords, result, output } = runFixture({ claim: claimWith() });
    expect(result.status, output).toBe(0);

    // Two objects: the reviewed list and its tampered twin.
    const keys = Object.keys(uploads);
    expect(keys).toHaveLength(2);
    // The per-stage prefix, which is where cross-stage isolation lives (the boundary
    // pins the bucket, the identity policy pins `decisions/<stage>/`). Flattened
    // slashes, since that is how the fixture names its files.
    for (const key of keys) expect(key).toMatch(/^decisions_pr-123_sha256-[0-9a-f]{64}\.json$/u);

    const artifacts = keys.map((key) => JSON.parse(uploads[key]));
    for (const artifact of artifacts) {
      expect(artifact.stage).toBe("pr-123");
      const merge = artifact.decisions.find((d) => d.verdict === "MERGE");
      // A MERGE is the point: it is the verdict a re-classification cannot
      // reconstruct, because `mergedContent` is prose anchored on the survivor's
      // ORIGINAL hash. A DELETE-only artifact would leave that untested.
      expect(merge).toBeDefined();
      expect(typeof merge.mergedContent).toBe("string");
      expect(merge.mergedContentHash).toMatch(/^sha256:[0-9a-f]{64}$/u);
      expect(merge.version).toBeGreaterThanOrEqual(1);
      // Every absorbed id carries its own anchors, because the apply re-reads and
      // LWW-checks each one separately — an artifact without them makes
      // `validateDecisions` refuse the replay at load.
      for (const absorbed of merge.absorbs) {
        expect(absorbed.contentHash).toMatch(/^sha256:[0-9a-f]{64}$/u);
        expect(absorbed.version).toBeGreaterThanOrEqual(1);
      }
      expect(artifact.decisions.some((d) => d.verdict === "DELETE")).toBe(true);
    }

    // The record points at the reviewed object, in the bucket derived from the
    // CALLER's account — the artifact bucket is a task-definition environment entry,
    // never an SSM parameter, so deriving it is also the stricter check: it asserts
    // the name this repo computes rather than whatever the stage was configured with.
    const seeds = callRecords.filter(
      ([tool, service, operation, , name]) =>
        tool === "aws" &&
        service === "ssm" &&
        operation === "put-parameter" &&
        String(name).endsWith("/approvals/offered"),
    );
    const live = JSON.parse(seeds.at(-1)[seeds.at(-1).indexOf("--value") + 1]);
    expect(live.artifactBucket).toBe("mem9-audit-123456789012");
    expect(live.artifactKey).toBe(`decisions/pr-123/${live.hash.replace(":", "-")}.json`);
    // Both coordinates or neither: `artifactCoordinates` THROWS on a half-set rather
    // than treating it as absent, because absence means "verify this by the weaker
    // id-list rule" and a tamperer's cheapest edit is deleting one field.
    expect(typeof live.artifactBucket).toBe("string");
    expect(typeof live.artifactKey).toBe("string");
  });

  it("TC-SLACKAPP-208 the tampered artifact is refused and starts no apply task", () => {
    // #150's acceptance criterion: a tampered artifact is refused with no fallback to
    // re-classification, and NO apply task runs. The tamper is one extra absorbed id
    // in the artifact while the offered record's `ids` stay byte-identical — under an
    // id-list hash that tamper was invisible; under the artifact hash the record's
    // hash moves and the button no longer matches it.
    const { callRecords, uploads, result, output } = runFixture({ claim: claimWith() });
    expect(result.status, output).toBe(0);

    // The two artifacts differ by exactly one absorbed id, and their hashes differ.
    // Both halves matter: a tamper that did not move the hash would make the refusal
    // vacuous, and a tamper elsewhere would not model an unreviewed DELETION.
    const artifacts = Object.entries(uploads)
      .map(([key, body]) => ({ key, ...JSON.parse(body) }))
      .sort(
        (a, b) =>
          a.decisions.flatMap((d) => d.absorbs ?? []).length -
          b.decisions.flatMap((d) => d.absorbs ?? []).length,
      );
    const absorbedIds = artifacts.map((a) =>
      a.decisions.flatMap((d) => (d.absorbs ?? []).map((x) => x.id)),
    );
    expect(absorbedIds[1].length).toBe(absorbedIds[0].length + 1);
    expect(artifacts[0].key).not.toBe(artifacts[1].key);

    // The tampered record is seeded SECOND — after the expired probe and before the
    // live click — because "no apply task ran" is only assertable while no claim
    // exists, and the live click creates one.
    const seeds = callRecords.filter(
      ([tool, service, operation, , name]) =>
        tool === "aws" &&
        service === "ssm" &&
        operation === "put-parameter" &&
        String(name).endsWith("/approvals/offered"),
    );
    const records = seeds.map((call) => JSON.parse(call[call.indexOf("--value") + 1]));
    const [, tampered, liveRecord] = records;
    // The tamper is in the ARTIFACT, so the ids the operator saw are unchanged and
    // only the hash and the key move. That triple is the whole scenario.
    expect(tampered.ids).toEqual(liveRecord.ids);
    expect(tampered.hash).not.toBe(liveRecord.hash);
    expect(tampered.artifactKey).not.toBe(liveRecord.artifactKey);

    // And the click carries the REVIEWED hash — the value the message the operator
    // was shown put on its button. Every POST shares one body for that reason: each
    // case differs in what the STORE says, never in what the operator clicked.
    const curls = callRecords.filter(([tool]) => tool === "curl");
    const bodyOf = (call) => call[call.indexOf("--data-binary") + 1];
    const clickedHash = JSON.parse(
      new URLSearchParams(bodyOf(curls.at(-1))).get("payload"),
    ).actions[0].value;
    expect(clickedHash).toBe(liveRecord.hash);
    for (const call of curls) expect(bodyOf(call)).toBe(bodyOf(curls.at(-1)));
  });

  it("TC-SLACKAPP-208 a facade that accepts a hash-mismatched artifact fails the run", () => {
    // The non-vacuity half. Without a fake that can be WRONG about the comparison,
    // the tampered step passes against a façade with no hash check at all — and that
    // façade would claim an approval covering an absorbed id nobody reviewed, then
    // start a task that soft-deletes it.
    const { result, output } = runFixture({
      claim: claimWith(),
      tamperBehavior: "accept",
    });
    expect(result.status, output).not.toBe(0);
    expect(output).toMatch(/not refused as a hash mismatch/iu);
  });

  it("TC-SLACKAPP-208 a hash-mismatch refusal that still claims the approval fails the run", () => {
    // The dangerous shape: the operator is told the list was regenerated and an apply
    // starts anyway. The reply assertion alone cannot see it — only reading the claim
    // back can, and it has to be read under the TAMPERED hash, because that is the
    // name `claimParameterName(prefix, offered.hash)` keys it on. A harness watching
    // only the reviewed name would report "no claim" while a task was deleting.
    const { result, output } = runFixture({
      claim: claimWith(),
      tamperBehavior: "cosmetic",
    });
    expect(result.status, output).not.toBe(0);
    expect(output).toMatch(/an apply task may have deleted an id no operator reviewed/iu);
  });

  it("TC-SLACKAPP-208 a refusal answered with a 5xx fails the run", () => {
    // Same reason as the expiry case: Slack renders a non-200 as its own "operation
    // failed" and shows the operator no reason at all, so a correct refusal delivered
    // with a 500 is a guard whose output nobody can see.
    const { result, output } = runFixture({
      claim: claimWith(),
      tamperBehavior: "error",
    });
    expect(result.status, output).not.toBe(0);
    expect(output).toMatch(/answered HTTP 500, not 200/u);
  });

  it("TC-SLACKAPP-209 the run fails unless the task logged an artifact replay", () => {
    // Everything else in the harness is ALSO satisfied by a task that ignored the
    // artifact and re-classified: the ids are synthetic, so a fresh scan finds
    // nothing to delete and exits 0 too. This assertion is the only thing separating
    // the two, and without it the MERGE case proves nothing.
    const { result, output } = runFixture({ claim: claimWith(), replayLines: "0" });
    expect(result.status, output).not.toBe(0);
    expect(output).toMatch(/never logged an artifact replay/iu);
    expect(output).toMatch(/re-classifying/iu);
  });

  it("TC-SLACKAPP-209 the log group and stream come from the task definition, never a computed path", () => {
    // SST auto-names container log groups with random hash segments and sets
    // `ignoreChanges: ["name"]`, so a hand-computed `/sst/...` path matches no real
    // group: every query answers ResourceNotFoundException, and a swallowed error
    // then reads as "clean". That is how the mnemo-server log-scan guard silently
    // never ran on any stage (#137). The fixture's group name is hash-suffixed for
    // exactly that reason — a script that computed one could not produce it.
    const { callRecords, result, output } = runFixture({
      claim: claimWith(),
      logGroup: "/sst/cluster/mem9-pr-123-zz9y8x/Mem9Cleanup-w7v6u5",
      logPrefix: "mem9",
    });
    expect(result.status, output).toBe(0);

    const filters = callRecords.filter(
      ([tool, service, operation]) =>
        tool === "aws" && service === "logs" && operation === "filter-log-events",
    );
    expect(filters.length).toBeGreaterThanOrEqual(1);
    for (const call of filters) {
      expect(call).toContain("/sst/cluster/mem9-pr-123-zz9y8x/Mem9Cleanup-w7v6u5");
      // The EXACT stream of THIS task, `<prefix>/<container>/<task id>` — not a
      // group-wide scan, which a previous run's replay line would satisfy.
      expect(call).toContain("mem9/Mem9Cleanup/task-abc");
    }

    // And the matched line is never echoed. It names `s3://mem9-audit-<account>/...`,
    // so printing a match would put the account id in a public CI log.
    expect(output).not.toContain("123456789012");
  });

  it("TC-SLACKAPP-209 a task definition whose container has no awslogs config fails the run", () => {
    // The alternative is a `|| true` that yields an empty group name and a query that
    // matches nothing — reported as "the task re-classified", which sends the reader
    // to the apply path instead of to the container name that changed. The container
    // is selected by the name the callback Lambda's `containerOverrides` targets, so
    // a rename surfaces HERE rather than as an opaque ECS validation error.
    const { result, output } = runFixture({
      claim: claimWith(),
      containerName: "SomethingElse",
    });
    expect(result.status, output).not.toBe(0);
    expect(output).toMatch(/no awslogs group\/stream prefix/iu);
  });

  it("TC-SLACKAPP-208 an account id the CLI cannot resolve is a refusal, not a malformed bucket name", () => {
    // The bucket is derived from `sts:GetCallerIdentity`, so an empty or non-numeric
    // account would build a name S3 rejects — and the resulting upload failure reads
    // as a permissions problem, sending the reader to the boundary. Refuse where the
    // value is read instead.
    for (const accountId of ["", "None", "not-an-account"]) {
      const { callRecords, result, output } = runFixture({ accountId, claim: claimWith() });
      expect(result.status, `${accountId}: ${output}`).not.toBe(0);
      expect(output).toMatch(/12-digit account id/iu);
      // And nothing was written: no artifact upload, no seeded record, no POST.
      expect(
        callRecords.filter(([tool, service]) => tool === "aws" && service === "s3api"),
      ).toHaveLength(0);
      expect(callRecords.filter(([tool]) => tool === "curl")).toHaveLength(0);
    }
  });

  it("TC-SLACKAPP-212 an exit between building the artifacts and the full trap still deletes them", () => {
    // The two temp bodies are `mktemp`ed before the `cleanup` trap that removes
    // them is installed, and everything in between can exit: the node child under
    // `set -e`, the `jq` reads of its output, and the identical-hash refusal. A
    // leftover body is not a tidiness problem — one of them holds synthetic
    // `mergedContent`, i.e. the shape of real memory text, and the runner's temp
    // dir is covered by no lifecycle rule. So the paths must be trapped where they
    // are created, not where the S3 cleanup arrives.
    //
    // Driven by a `jq` that fails on the FIRST read of the node child's output,
    // which lands the exit squarely inside that window. The assertion is on the
    // files, not on the exit code: a run that aborted there and left both bodies
    // behind also exits non-zero, so an exit-code-only check would pass with the
    // trap deleted.
    const { result, output, temporaryBodies } = runFixture({
      claim: claimWith(),
      failingJqFilter: ".clean.hash",
    });
    expect(result.status, output).not.toBe(0);
    // The script names its temp files on stdout only via this fixture's `jq` stub;
    // what matters is that none of the paths it created survive.
    expect(temporaryBodies).not.toHaveLength(0);
    for (const path of temporaryBodies) {
      expect(existsSync(path), `${path} outlived the run: ${output}`).toBe(false);
    }
  });
});
