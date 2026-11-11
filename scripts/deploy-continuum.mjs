#!/usr/bin/env node
// Operator-only, out-of-band declarative deployment. No credentials, GitHub
// tokens, IAM changes, repository clones, or production data are provisioned.
import { constants } from "node:fs";
import { open, realpath, rename, unlink } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import { makePlan, applyPlan, inspectEnvironment, validateInputs } from "./lib/continuum-environment.mjs";
import { checkGithubAdmission } from "./lib/continuum-github-admission.mjs";

export async function readPrivate(path, optional = false) {
  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await file.stat();
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0 || stat.size > 1024 * 1024) throw new Error("Local binding, state and plan must be owned, private regular files (mode 600)");
    return JSON.parse(await file.readFile("utf8"));
  } catch (error) {
    if (optional && error.code === "ENOENT") return null;
    throw error;
  } finally {
    await file?.close();
  }
}

export async function writePrivate(path, value) {
  // Atomic replacement, durable before the first non-idempotent AWS request.
  await readPrivate(path, true);
  const temporary = `${path}.${randomUUID()}.tmp`;
  let file;
  try {
    file = await open(temporary, "wx", 0o600);
    await file.writeFile(`${JSON.stringify(value, null, 2)}\n`);
    await file.sync();
    await file.close();
    file = null;
    await rename(temporary, path);
    const directory = await open(dirname(path), constants.O_RDONLY);
    try { await directory.sync(); } finally { await directory.close(); }
  } finally {
    await file?.close();
    await unlink(temporary).catch((error) => { if (error.code !== "ENOENT") throw error; });
  }
}

export async function canonicalPaths(values) {
  const result = { ...values, config: await realpath(values.config) };
  for (const key of ["binding", "state", "plan"]) {
    if (values[key]) result[key] = join(await realpath(dirname(resolve(values[key]))), basename(values[key]));
  }
  const paths = [result.binding, result.state, result.plan].filter(Boolean);
  if (paths.some((path) => !path.endsWith(".local.json")) || new Set(paths).size !== paths.length || paths.includes(result.config)) throw new Error("Binding, state and plan must be distinct *.local.json files");
  return result;
}


async function main() {
  let { values, positionals } = parseArgs({ allowPositionals: true, options: {
    config: { type: "string", default: "infra/continuum/environment.json" },
    binding: { type: "string" }, state: { type: "string" }, plan: { type: "string" },
    help: { type: "boolean" },
  } });
  if (values.help) {
    console.log("Usage: node scripts/deploy-continuum.mjs <plan|apply|status> --binding binding.local.json --state state.local.json [--plan plan.local.json] [--config infra/continuum/environment.json]");
    return;
  }
  const [action] = positionals;
  if (positionals.length !== 1 || !["plan", "apply", "status"].includes(action)) throw new Error("Choose plan, apply or status");
  if (!values.binding || !values.state || (action !== "status" && !values.plan)) throw new Error("Missing binding, state or plan path");
  values = await canonicalPaths(values);
  const { readFile } = await import("node:fs/promises");
  const desired = JSON.parse(await readFile(values.config, "utf8"));
  const binding = await readPrivate(values.binding);
  validateInputs(desired, binding);
  let lock;
  let api;
  const lockPath = `${values.state}.lock`;
  try {
    // A second local apply must not race the ownership journal. A crashed lock
    // is intentionally retained until the operator verifies no writer exists.
    if (action === "apply") lock = await open(lockPath, "wx", 0o600);
    const state = await readPrivate(values.state, true);
    const { clients } = await import("./continuum/aws-client.mjs");
    api = await clients(binding.region);
    // Automatic PR delivery introduces untrusted code into CI. Validate the
    // external GitHub protection immediately before planning/applying it.
    // Status and turning off patch delivery remain available during incidents.
    if (action !== "status" && desired.patchCreationPolicy === "ENABLED") await checkGithubAdmission(desired.repository, binding, api);
    if (action === "plan") {
      const plan = await makePlan({ api, desired, binding, state });
      await writePrivate(values.plan, plan);
      console.log(JSON.stringify({ action: plan.action, planFile: values.plan }));
    } else if (action === "apply") {
      const plan = await readPrivate(values.plan);
      const result = await applyPlan({ api, desired, binding, state, plan, journal: (value) => writePrivate(values.state, value) });
      console.log(JSON.stringify({ environmentId: result.environmentId, configurationVerified: true, scanVerified: false }));
    } else {
      console.log(JSON.stringify(await inspectEnvironment({ api, desired, binding, state }), null, 2));
    }
  } finally {
    api?.destroy();
    if (lock) { await lock.close(); await unlink(lockPath); }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    // AWS error messages may contain environment context; never print them.
    if (error.$metadata) console.error(JSON.stringify({ error: error.name, status: error.$metadata.httpStatusCode, requestId: error.$metadata.requestId }));
    else console.error(`Continuum deployment failed: ${error.message}`);
    process.exitCode = 1;
  });
}
