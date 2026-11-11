import { expect, it } from "vitest";
import { checkPrivateRepository } from "./lib/continuum-github-admission.mjs";
const repository = "owner/project";
const source = { full_name: repository, html_url: `https://github.com/${repository}`, default_branch: "main", private: true };
it("accepts an explicitly private, exact GitHub main source", async () => {
  const calls = [];
  expect(await checkPrivateRepository(repository, async path => { calls.push(path); return source; })).toEqual(source);
  expect(calls).toEqual(["repos/owner/project"]);
});
it.each([false, undefined, null])("rejects public or unknown visibility (%s) before provisioning", async visibility => {
  await expect(checkPrivateRepository(repository, async () => ({ ...source, private: visibility }))).rejects.toThrow(/only private GitHub repositories/);
});
it("rejects identity substitution even if the response is private", async () => {
  await expect(checkPrivateRepository(repository, async () => ({ ...source, full_name: "other/project" }))).rejects.toThrow(/identity/);
});

import { mkdtempSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, delimiter } from "node:path";
import { spawnSync } from "node:child_process";
it.each(["plan", "apply"].flatMap(action => ["ENABLED", "DISABLED"].map(policy => [action, policy])))("%s rejects a public %s source without AWS credentials or a creation journal", (action, policy) => {
  const directory = mkdtempSync(join(tmpdir(), "continuum-public-source-"));
  try {
    writeFileSync(join(directory, "gh"), `#!/usr/bin/env node\nconsole.log(${JSON.stringify(JSON.stringify({ ...source, private: false }))});\n`, { mode: 0o755 });
    const config = join(directory, "config.json"), binding = join(directory, "binding.local.json"), state = join(directory, "state.local.json"), plan = join(directory, "plan.local.json");
    writeFileSync(config, JSON.stringify({ name: "example", repository, defaultBranch: "main", scanFrequency: "P1D", patchCreationPolicy: policy, allowedDomains: ["registry.npmjs.org"] }));
    writeFileSync(binding, JSON.stringify({ accountId: "123456789012", region: "us-east-1", integrationId: "example" }), { mode: 0o600 });
    const result = spawnSync(process.execPath, [new URL("./deploy-continuum.mjs", import.meta.url).pathname, action, "--config", config, "--binding", binding, "--state", state, "--plan", plan], { encoding: "utf8", timeout: 10000, env: { ...process.env, PATH: directory + delimiter + process.env.PATH, AWS_PROFILE: "unavailable-fixture", AWS_EC2_METADATA_DISABLED: "true" } });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("only private GitHub repositories");
    for (const path of [state, plan, state + ".lock"]) expect(existsSync(path)).toBe(false);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
