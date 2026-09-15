#!/usr/bin/env node
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { lstat, open, readFile, unlink, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createFixturePlan,
  HUMAN_CASES,
  HumanAcceptanceError,
  HumanNamespaceFixture,
  readDeploymentManifest,
  validateFixturePlan,
  verifyHumanOperatorOutput,
} from "./lib/human-namespace-acceptance.mjs";
import { HumanOAuthBrowser } from "./lib/human-namespace-browser.mjs";
import { verifyHumanPreviewTarget } from "./lib/human-namespace-target.mjs";
import { writePrivateRecord } from "./lib/human-namespace-records.mjs";
import { runHumanNamespaceScenarios } from "./lib/human-namespace-scenarios.mjs";

const usage = `usage: node scripts/run-human-namespace-e2e.mjs --deployment-file <owner-only.local.json> --fixtures-file <new.local.json> --evidence-file <content-free.json> [--cleanup-only]\n`;
export async function main(args = process.argv.slice(2)) {
  if (args.length === 1 && args[0] === "--help") {
    process.stdout.write(usage);
    return;
  }
  if (args.length === 2 && args[0] === "--verify-output-file") {
    const result = verifyHumanOperatorOutput(await readFile(args[1], "utf8"));
    process.stdout.write(JSON.stringify(result) + "\n");
    return;
  }
  const options = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--cleanup-only") options.cleanup = true;
    else if (
      ["--deployment-file", "--fixtures-file", "--evidence-file"].includes(
        args[i],
      ) &&
      args[i + 1]
    )
      options[args[i].slice(2)] = resolve(args[++i]);
    else throw new HumanAcceptanceError("invalid_arguments");
  }
  for (const key of ["deployment-file", "fixtures-file", "evidence-file"])
    if (!options[key]) throw new HumanAcceptanceError("missing_operator_file");
  if (
    !options["fixtures-file"].endsWith(".local.json") ||
    !options["deployment-file"].endsWith(".local.json") ||
    options["evidence-file"] ===
      options["fixtures-file"] + ".failure.local.json" ||
    new Set([
      options["fixtures-file"],
      options["deployment-file"],
      options["evidence-file"],
    ]).size !== 3
  )
    throw new HumanAcceptanceError("private_input_paths_required");
  try {
    await lstat(options["evidence-file"]);
    throw new HumanAcceptanceError("evidence_file_already_exists");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const manifest = await readDeploymentManifest(options["deployment-file"]);
  const git = promisify(execFile),
    repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const { stdout: head } = await git("git", ["rev-parse", "HEAD"], {
    cwd: repoRoot,
  });
  if (!options.cleanup && head.trim() !== manifest.commit)
    throw new HumanAcceptanceError("operator_commit_mismatch");
  try {
    await git("git", ["diff", "--quiet", "HEAD", "--"], { cwd: repoRoot });
  } catch {
    throw new HumanAcceptanceError("operator_checkout_has_changes");
  }
  const target = await verifyHumanPreviewTarget(manifest, {
    cleanupOnly: options.cleanup,
  });
  let plan;
  if (options.cleanup) {
    const stat = await (
      await import("node:fs/promises")
    ).lstat(options["fixtures-file"]);
    if (
      !stat.isFile() ||
      (stat.mode & 0o077) !== 0 ||
      stat.uid !== process.getuid()
    )
      throw new HumanAcceptanceError("fixture_file_must_be_owner_only");
    plan = validateFixturePlan(
      JSON.parse(await readFile(options["fixtures-file"], "utf8")),
    );
  } else {
    plan = createFixturePlan(target.targetFingerprint);
    const file = await open(options["fixtures-file"], "wx", 0o600);
    try {
      await file.writeFile(JSON.stringify(plan));
    } finally {
      await file.close();
    }
  }
  const passed = [],
    sensitive = new Set(
      Object.values(plan.users).flatMap((x) => [x.username, x.password]),
    );
  const report = (label) => {
    if (!HUMAN_CASES.includes(label))
      throw new HumanAcceptanceError("unsafe_case_label");
    passed.push(label);
    process.stdout.write(`PASS ${label}\n`);
  };
  const controller = new AbortController();
  const fixture = new HumanNamespaceFixture({
    manifest,
    plan,
    ...target,
    report,
    signal: controller.signal,
    cognito: {
      send: (command) =>
        target.cognito.send(command, { abortSignal: controller.signal }),
    },
    persist: async (updated) =>
      writePrivateRecord(options["fixtures-file"], updated),
  });
  let browser,
    problem,
    cleanupComplete = false,
    interrupted = false;
  const stop = () => {
    interrupted = true;
    controller.abort();
    void browser?.close();
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  try {
    if (!options.cleanup) {
      await fixture.prepare();
      if (interrupted) throw new HumanAcceptanceError("operator_interrupted");
      const { chromium } = await import("playwright");
      browser = await chromium.launch({ headless: true });
      const oauth = new HumanOAuthBrowser({
        browser,
        facadeUrl: manifest.facadeUrl,
        providerOrigin: target.providerOrigin,
        issuer: target.issuer,
        signal: controller.signal,
      });
      await runHumanNamespaceScenarios({
        fixture,
        oauth,
        gatewayUrl: manifest.gatewayUrl,
        onToken: (token) => sensitive.add(token),
        signal: controller.signal,
        readDenialStatus: target.readDenialStatus,
      });
    }
  } catch (error) {
    problem = error;
  } finally {
    await browser?.close().catch(() => {});
    fixture.cognito = {
      send: (command) =>
        target.cognito.send(command, {
          abortSignal: AbortSignal.timeout(60000),
        }),
    };
    try {
      await fixture.cleanup();
      cleanupComplete = true;
    } catch (error) {
      problem ??= error;
    }
    process.off("SIGINT", stop);
    process.off("SIGTERM", stop);
  }
  if (!options.cleanup && !HUMAN_CASES.every((label) => passed.includes(label)))
    problem ??= new HumanAcceptanceError("acceptance_cases_incomplete");
  const evidence = {
    version: 1,
    commit: manifest.commit,
    kind: options.cleanup ? "cleanup" : "acceptance",
    ...(!options.cleanup ? { success: !problem && !interrupted } : {}),
    cleanup_complete: cleanupComplete,
    cases: passed,
  };
  const rendered = JSON.stringify(evidence, null, 2) + "\n";
  for (const value of sensitive)
    if (rendered.includes(value))
      throw new HumanAcceptanceError("sensitive_evidence_rejected");
  await writeFile(options["evidence-file"], rendered, {
    mode: 0o600,
    flag: "wx",
  });
  if (cleanupComplete) await unlink(options["fixtures-file"]);
  if (problem || interrupted) {
    await writePrivateRecord(options["fixtures-file"] + ".failure.local.json", {
      name: problem?.name,
      message: problem?.message,
      stack: problem?.stack,
      interrupted,
    });
    throw new HumanAcceptanceError(
      cleanupComplete
        ? "human_acceptance_failed"
        : "human_acceptance_cleanup_incomplete",
    );
  }
  process.stdout.write(
    options.cleanup
      ? "human namespace cleanup: complete\n"
      : "human namespace acceptance: complete\n",
  );
}
if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
)
  main().catch((error) => {
    const code =
      error instanceof HumanAcceptanceError
        ? error.message
        : "operator_failure";
    process.stderr.write(
      `human namespace acceptance incomplete (${code}); inspect private operator records\n`,
    );
    process.exitCode = 1;
  });
