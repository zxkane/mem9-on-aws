import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

const root = resolve(import.meta.dirname, "..");
const inventory = JSON.parse(
  readFileSync(
    resolve(root, "scripts/memory-namespace-release-gates.json"),
    "utf8",
  ),
);
const acceptedStates = new Set([
  "enabled_v1",
  "disabled_v1",
  "future_capability",
  "postdeploy_nonblocking",
]);

function expandAcceptance(items) {
  const result = [];
  for (const item of items) {
    const match = item.match(/^(\d{3})(?:-(\d{3}))?$/);
    if (!match) throw new Error(`invalid acceptance range: ${item}`);
    const start = Number(match[1]);
    const end = Number(match[2] ?? match[1]);
    if (end < start) throw new Error(`reversed acceptance range: ${item}`);
    for (let value = start; value <= end; value += 1) {
      result.push(value.toString().padStart(3, "0"));
    }
  }
  return result;
}

describe("memory namespace coverage ownership map", () => {
  it("is a coverage ownership map, not an AC execution result", () => {
    expect(inventory.kind).toBe("coverage_ownership_map");
  });

  it("TC-GROUPNS-001..133: assigns every acceptance criterion exactly once", () => {
    const assigned = inventory.capabilities.flatMap(({ acceptance }) =>
      expandAcceptance(acceptance),
    );
    const expected = Array.from({ length: 133 }, (_, index) =>
      (index + 1).toString().padStart(3, "0"),
    );

    expect(assigned.toSorted()).toEqual(expected);
    expect(new Set(assigned).size).toBe(assigned.length);
  });

  it("fails when an enabled v1 capability lacks a named verification surface", () => {
    for (const capability of inventory.capabilities) {
      expect(acceptedStates.has(capability.state), capability.id).toBe(true);
      expect(capability.verification.length, capability.id).toBeGreaterThan(0);
      if (capability.state === "enabled_v1") {
        expect(capability.acceptance.length, capability.id).toBeGreaterThan(0);
      }
      for (const surface of capability.verification) {
        expect(existsSync(resolve(root, surface)), `${capability.id}: ${surface}`)
          .toBe(true);
      }
    }
  });

  it("keeps future and post-deploy exceptions narrow and explicit", () => {
    const byState = Object.groupBy(
      inventory.capabilities,
      ({ state }) => state,
    );
    expect(
      byState.future_capability.flatMap(({ acceptance }) =>
        expandAcceptance(acceptance),
      ),
    ).toEqual(["102"]);
    expect(
      byState.postdeploy_nonblocking.flatMap(({ acceptance }) =>
        expandAcceptance(acceptance),
      ).toSorted(),
    ).toEqual(["107", "114"]);
  });

  it("TC-GROUPNS-097..104: proves disabled-v1 maintenance invariants", () => {
    const sst = readFileSync(resolve(root, "sst.config.ts"), "utf8");
    const workflow = readFileSync(
      resolve(root, ".github/workflows/infra-ci.yml"),
      "utf8",
    );
    expect(sst).toMatch(
      /const namespaceMaintenanceEnabled = false;/,
    );
    const parsedWorkflow = parse(workflow);
    const deploymentSteps = [
      ...parsedWorkflow.jobs["deploy-preview"].steps,
      ...parsedWorkflow.jobs["deploy-prod"].steps,
    ];
    for (const forbidden of [
      "MEM9_CLEANUP_SCAN_ENABLED",
      "MEM9_CONSOLIDATION_SCHEDULE_ENABLED",
      "MEM9_SLACK_APPROVAL_ENABLED",
    ]) {
      expect(
        deploymentSteps.some(({ env = {} }) =>
          Object.hasOwn(env, forbidden),
        ),
      ).toBe(false);
    }
    for (const forbidden of [
      "run-consolidation-task.sh",
      "run-slack-approval-e2e.sh",
    ]) {
      expect(
        deploymentSteps.some(({ run }) =>
          String(run).includes(forbidden),
        ),
      ).toBe(false);
    }

    const commands = [
      ["scripts/memory-cleanup.mjs", "--stage", "prod", "--list-inactive"],
      ["scripts/memory-consolidation.mjs", "--stage", "prod", "--report-only"],
    ];
    for (const [script, ...args] of commands) {
      const result = spawnSync(
        process.execPath,
        [resolve(root, script), ...args],
        {
          cwd: root,
          encoding: "utf8",
          env: {
            HOME: process.env.HOME,
            PATH: process.env.PATH,
          },
          timeout: 5_000,
        },
      );
      expect(result.error, script).toBeUndefined();
      expect(result.status, script).toBe(1);
      expect(result.stderr, script).toContain(
        "legacy maintenance is disabled in memory namespace v1",
      );
    }
  });

  it("matches the complete acceptance document", () => {
    const document = readFileSync(
      resolve(root, inventory.acceptance_document),
      "utf8",
    );
    const documented = [
      ...document.matchAll(/\bTC-GROUPNS-(\d{3})\b/g),
    ].map((match) => match[1]);
    const unique = [...new Set(documented)].toSorted();
    const expected = Array.from({ length: 133 }, (_, index) =>
      (index + 1).toString().padStart(3, "0"),
    );

    expect(unique).toEqual(expected);
  });
});
