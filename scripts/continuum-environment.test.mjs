import { describe, expect, it, vi } from "vitest";
import {
  configuration, makePlan, applyPlan, inspectEnvironment,
} from "./lib/continuum-environment.mjs";

const desired = {
  name: "mem9Security", repository: "owner/repository", defaultBranch: "main",
  scanFrequency: "P1D", patchCreationPolicy: "ENABLED", allowedDomains: ["registry.npmjs.org"],
};
const binding = { accountId: "123456789012", region: "us-east-1", integrationId: "integration1" };
const envId = "environment1";
const identity = { Account: binding.accountId };
const integration = {
  integrationId: binding.integrationId, integrationType: "GITHUB",
  integrationArn: `arn:aws:continuum:${binding.region}:${binding.accountId}:integrations/${binding.integrationId}`,
};
const current = () => ({
  environmentId: envId, environmentArn: `arn:aws:continuum:${binding.region}:${binding.accountId}:environments/${envId}`,
  name: desired.name, status: "ACTIVE", configuration: configuration(desired, binding),
});
const state = () => ({ version: 1, phase: "bound", binding, environmentId: envId, name: desired.name, repository: desired.repository, defaultBranch: desired.defaultBranch });

function api(overrides = {}) {
  return {
    identity: vi.fn(async () => identity), integration: vi.fn(async () => integration),
    environments: vi.fn(async () => []), environment: vi.fn(async () => current()),
    collectors: vi.fn(async () => []),
    create: vi.fn(async () => ({ environmentId: envId })),
    update: vi.fn(async () => ({})), ...overrides,
  };
}
const plan = (client = api(), saved = null, settings = desired) => makePlan({ api: client, desired: settings, binding, state: saved, now: 1000 });
const apply = (client, proposed, saved = null, journal = vi.fn(async () => {}), settings = desired) => applyPlan({
  api: client, desired: settings, binding, state: saved, plan: proposed, journal, now: 2000,
});

describe("Continuum environment deployment", () => {
  it("plans creation without making mutations and journals before creating", async () => {
    const client = api();
    const proposed = await plan(client);
    expect(proposed.action).toBe("create");
    expect(client.create).not.toHaveBeenCalled();
    const journal = vi.fn(async () => {});
    const result = await apply(client, proposed, null, journal);
    expect(journal.mock.calls[0][0].phase).toBe("creating");
    expect(journal.mock.invocationCallOrder[0]).toBeLessThan(client.create.mock.invocationCallOrder[0]);
    expect(result.phase).toBe("bound");
    expect(client.create).toHaveBeenCalledWith({ name: desired.name, configuration: configuration(desired, binding) });
  });

  it("updates an owned environment and verifies the read-back", async () => {
    const old = current();
    old.configuration.codeConfiguration.environmentConfiguration.scanFrequency = "P7D";
    const client = api({ environment: vi.fn(async () => old) });
    const proposed = await plan(client, state());
    expect(proposed.action).toBe("update");
    client.update.mockImplementation(async () => { client.environment.mockResolvedValue(current()); });
    await apply(client, proposed, state());
    expect(client.update).toHaveBeenCalledWith(envId, configuration(desired, binding));
  });

  it("makes an identical deployment a no-op", async () => {
    const client = api();
    await apply(client, await plan(client, state()), state());
    expect(client.create).not.toHaveBeenCalled();
    expect(client.update).not.toHaveBeenCalled();
  });

  it.each([
    ["wrong account", { identity: async () => ({ Account: "9".repeat(12) }) }],
    ["non-GitHub integration", { integration: async () => ({ ...integration, integrationType: "S3" }) }],
    ["cross-region integration", { integration: async () => ({ ...integration, integrationArn: integration.integrationArn.replace("us-east-1", "us-west-2") }) }],
    ["pre-existing name", { environments: async () => [{ name: desired.name, environmentId: "someoneelse" }] }],
  ])("rejects %s before mutation", async (_, overrides) => {
    const client = api(overrides);
    await expect(plan(client)).rejects.toThrow();
    expect(client.create).not.toHaveBeenCalled();
    expect(client.update).not.toHaveBeenCalled();
  });

  it.each([
    { scanFrequency: "PT1M" }, { patchCreationPolicy: "AUTO_MERGE" },
    { allowedDomains: [] }, { allowedDomains: ["*"] }, { repository: "owner/repo;command" },
    { defaultBranch: "refs/heads/main" }, { unknownOption: true },
  ])("rejects unsupported or unsafe configuration %j", async (change) => {
    await expect(plan(api(), null, { ...desired, ...change })).rejects.toThrow();
  });

  it("refuses an ambiguous create retry", async () => {
    const client = api({ create: vi.fn(async () => { throw new Error("timeout"); }) });
    let saved;
    await expect(apply(client, await plan(client), null, async (value) => { saved = value; })).rejects.toThrow("timeout");
    expect(saved.phase).toBe("creating");
    await expect(plan(api(), saved)).rejects.toThrow(/ambiguous/i);
  });

  it("rejects stale plans, changed input and observed drift", async () => {
    const client = api();
    const proposed = await plan(client, state());
    await expect(applyPlan({ api: client, desired, binding, state: state(), plan: proposed, journal: async () => {}, now: 4000000 })).rejects.toThrow(/expired/i);
    await expect(apply(client, proposed, state(), undefined, { ...desired, scanFrequency: "P7D" })).rejects.toThrow(/changed/i);
    client.environment.mockResolvedValue({ ...current(), updatedAt: "later", configuration: configuration({ ...desired, scanFrequency: "P2D" }, binding) });
    await expect(apply(client, proposed, state())).rejects.toThrow(/changed/i);
    expect(client.update).not.toHaveBeenCalled();
  });

  it.each(["repository", "integrationId", "defaultBranch"])("refuses source drift in %s", async (field) => {
    const other = current();
    other.configuration.codeConfiguration.sourceConfiguration.repositorySources[0][field] = "someoneelse";
    await expect(plan(api({ environment: async () => other }), state())).rejects.toThrow(/source/i);
  });

  it("rejects added sources and cross-account environment identity", async () => {
    const other = current();
    other.configuration.codeConfiguration.sourceConfiguration.s3Sources = [{ integrationId: "other" }];
    await expect(plan(api({ environment: async () => other }), state())).rejects.toThrow(/source/i);
    other.configuration = configuration(desired, binding);
    other.environmentArn = other.environmentArn.replace(binding.accountId, "9".repeat(12));
    await expect(plan(api({ environment: async () => other }), state())).rejects.toThrow(/identity/i);
  });

  it("fails verification when AWS does not apply the requested update", async () => {
    const old = current();
    old.configuration.codeConfiguration.environmentConfiguration.scanFrequency = "P7D";
    const client = api({ environment: async () => old });
    await expect(apply(client, await plan(client, state()), state())).rejects.toThrow(/verification/i);
  });

  it("rejects Collector access and associations introduced after planning", async () => {
    const client = api();
    const proposed = await plan(client, state());
    const withCollector = current();
    withCollector.configuration.codeConfiguration.collectorDetails = { collectorDataAccessRoleArn: "unexpected-role" };
    client.environment.mockResolvedValue(withCollector);
    await expect(apply(client, proposed, state())).rejects.toThrow(/Collector/);
    client.environment.mockResolvedValue(current());
    client.collectors.mockResolvedValue([{ collectorId: "unexpected" }]);
    await expect(apply(client, proposed, state())).rejects.toThrow(/Collector/);
    expect(client.update).not.toHaveBeenCalled();
  });

  it("reports scan state separately from configuration readiness", async () => {
    const live = current();
    live.configuration.codeConfiguration.latestScan = { status: "FAILED", failureMessage: "sensitive diagnostic" };
    const result = await inspectEnvironment({ api: api({ environment: async () => live }), desired, binding, state: state() });
    expect(result.latestScan.status).toBe("FAILED");
    expect(JSON.stringify(result)).not.toContain("sensitive diagnostic");
  });
});
