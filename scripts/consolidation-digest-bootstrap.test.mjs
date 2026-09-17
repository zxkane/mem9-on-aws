import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DIGEST_SCHEMA_VERSION, buildDigestOutcome, createProductionDeps,
  digestStateKey, initializeScheduledDigest, runConsolidation,
} from "./memory-consolidation.mjs";

const NS = "60000000-0000-4000-8000-000000000101";
const OTHER = "60000000-0000-4000-8000-000000000102";
const NOW = Date.parse("2026-09-01T00:00:00Z");
const options = { stage: "prod", namespaceId: NS, scheduled: true, reportOnly: false };
const emptyState = () => ({
  schemaVersion: DIGEST_SCHEMA_VERSION, stage: "prod", namespaceId: NS,
  generatedAt: new Date(NOW).toISOString(), unchangedRuns: 0, kindCounts: {}, topics: [],
});
const error = (name, status) => Object.assign(new Error(name), {
  name, $metadata: { httpStatusCode: status },
});

async function fixture({ existing, putError, getError, afterPut } = {}) {
  for (const [name, value] of Object.entries({
    AWS_REGION: "ap-northeast-1", MEM9_NAMESPACE_ID: NS,
    MEM9_SERVICE_TRANSPORT_SIGNING_KEYS: JSON.stringify({ current: Buffer.alloc(32, 9).toString("base64url") }),
    MEM9_DB_HOST: "database.example.com", MEM9_DB_NAME: "fixture",
    MEM9_DB_SECRET: JSON.stringify({ username: "fixture", password: "fixture-password" }),
    MEM9_TENANT_ID: "fixture-tenant", MEM9_BASE_URL: "http://mnemo.example.com",
    MEM9_DECISION_ARTIFACT_BUCKET: "example-consolidation", MEM9_DECISION_ARTIFACT_BUCKET_OWNER: "123456789012",
    SLACK_BOT_TOKEN: "", MEM9_SLACK_APPROVAL_CHANNEL: "", MEM9_SLACK_APPROVAL_ENABLED: "0",
  })) vi.stubEnv(name, value);
  const events = [], commands = [];
  const state = { active: true, role: "owner", body: existing, version: existing === undefined ? 0 : 1 };
  class Client {
    async connect() {}
    async end() {}
    async query(sql) {
      if (sql.includes("FROM memory_namespace_migration_state"))
        return { rowCount: 1, rows: [{ phase: "constraints_complete" }] };
      if (sql.includes("FROM memory_namespaces")) {
        events.push("authorize");
        return { rowCount: state.active ? 1 : 0, rows: [{ namespace_id: NS }] };
      }
      if (sql.includes("FROM memory_principals"))
        return { rowCount: 1, rows: [{ principal_id: "70000000-0000-4000-8000-000000000101" }] };
      if (sql.includes("FROM memory_namespace_memberships"))
        return { rowCount: 1, rows: [{ role: state.role }] };
      return { rowCount: 1, rows: [] };
    }
  }
  class GetObjectCommand { constructor(input) { this.input = input; } }
  class PutObjectCommand { constructor(input) { this.input = input; } }
  class S3Client {
    async send(command) {
      commands.push(command);
      if (command instanceof GetObjectCommand) {
        events.push("get");
        if (getError) throw getError;
        if (state.body === undefined) throw error("AccessDenied", 403);
        return { ETag: String(state.version), Body: state.body };
      }
      events.push(command.input.IfNoneMatch ? "create" : "update");
      if (putError) throw putError;
      if (command.input.IfNoneMatch === "*" && state.body !== undefined)
        throw error("PreconditionFailed", 412);
      if (command.input.IfMatch && command.input.IfMatch !== String(state.version))
        throw error("PreconditionFailed", 412);
      state.body = command.input.Body;
      state.version++;
      afterPut?.(state);
      return { ETag: String(state.version) };
    }
    destroy() {}
  }
  const production = await createProductionDeps(options, {
    Client, S3Client, GetObjectCommand, PutObjectCommand,
    getToken: vi.fn(), fromNodeProviderChain: () => ({}),
  });
  const deps = {
    ...production.deps, clock: () => NOW,
    listActiveMemories: vi.fn(async () => { events.push("memories"); return []; }),
    completeChat: vi.fn(async () => { events.push("model"); return '{"actions":[]}'; }),
    log: vi.fn(), emitMetrics: vi.fn(), publishHealthAlarm: vi.fn(),
  };
  return { state, events, commands, deps, close: production.close, GetObjectCommand, PutObjectCommand };
}

afterEach(() => vi.unstubAllEnvs());

describe("scheduled digest bootstrap", () => {
  it("TC-CONSOL-094: creates a valid empty baseline before model work, then updates with the read ETag", async () => {
    const f = await fixture();
    try {
      const result = await runConsolidation({ ...options, checkLlm: true }, f.deps);
      expect(result.exitCode).toBe(0);
      expect(f.events.indexOf("authorize")).toBeLessThan(f.events.indexOf("create"));
      expect(f.events.indexOf("create")).toBeLessThan(f.events.indexOf("get"));
      expect(f.events.indexOf("get")).toBeLessThan(f.events.indexOf("memories"));
      expect(f.events.indexOf("get")).toBeLessThan(f.events.indexOf("model"));
      expect(f.commands[0].input).toMatchObject({
        Bucket: "example-consolidation", Key: digestStateKey("prod", NS),
        ExpectedBucketOwner: "123456789012", IfNoneMatch: "*", ContentType: "application/json",
      });
      expect(JSON.parse(f.commands[0].input.Body)).toEqual(emptyState());
      expect(f.commands.at(-1).input).toMatchObject({ IfMatch: "1" });
      expect(f.state.version).toBe(2);
    } finally { await f.close(); }
  });

  it("TC-CONSOL-095: does not replace existing state before the model, including a concurrent winner", async () => {
    const initial = JSON.stringify({ ...emptyState(), unchangedRuns: 3, kindCounts: { CLASSIFICATION_FAILED: 1 } });
    const f = await fixture({ existing: initial });
    f.deps.completeChat.mockImplementation(async () => {
      expect(f.state.body).toBe(initial);
      expect(f.state.version).toBe(1);
      return '{"actions":[]}';
    });
    try {
      const result = await runConsolidation({ ...options, checkLlm: true }, f.deps);
      expect(result.exitCode).toBe(0);
      expect(f.events.filter(e => e === "create")).toHaveLength(1);
      expect(f.commands.at(-1).input.IfMatch).toBe("1");
      expect(JSON.parse(f.state.body).unchangedRuns).toBe(4);
    } finally { await f.close(); }
  });

  it("TC-CONSOL-095: concurrent initializers converge without replacing the winner", async () => {
    const f = await fixture();
    try {
      await Promise.all([0, 1].map(() => initializeScheduledDigest({ ...options, now: NOW }, f.deps)));
      expect(f.events.filter(e => e === "create")).toHaveLength(2);
      expect(f.events.filter(e => e === "get")).toHaveLength(2);
      expect(f.state.version).toBe(1);
      expect(JSON.parse(f.state.body)).toEqual(emptyState());
      expect(f.deps.completeChat).not.toHaveBeenCalled();
    } finally { await f.close(); }
  });

  it("TC-CONSOL-095: final CAS uses freshly reloaded state, not the bootstrap ETag", async () => {
    const f = await fixture();
    f.deps.completeChat.mockImplementation(async () => {
      f.state.body = JSON.stringify({ ...emptyState(), unchangedRuns: 2 });
      f.state.version = 3;
      return '{"actions":[]}';
    });
    try {
      expect((await runConsolidation({ ...options, checkLlm: true }, f.deps)).exitCode).toBe(0);
      expect(f.commands.at(-1).input.IfMatch).toBe("3");
      expect(JSON.parse(f.state.body).unchangedRuns).toBe(3);
    } finally { await f.close(); }
  });

  it("TC-CONSOL-094: validates bootstrap before an actual memory apply", async () => {
    const f = await fixture();
    const row = { id: "synthetic-stale", namespace_id: NS, content: "synthetic old setting", embedding: [1, 0],
      memory_type: "insight", state: "active", version: 1, tags: [], metadata: {},
      created_at: "2020-01-01T00:00:00Z", updated_at: "2020-01-01T00:00:00Z" };
    f.deps.listActiveMemories.mockResolvedValue([row]);
    f.deps.completeChat.mockImplementation(async () => {
      f.events.push("model");
      return JSON.stringify({ actions: [{ type: "STALE", ids: [row.id], rationale: "aged synthetic setting" }] });
    });
    f.deps.acquireMutex = async () => ({ release: async () => {} });
    f.deps.getMemory = async () => row;
    f.deps.markMemoryStale = async () => { f.events.push("apply"); return true; };
    try {
      const result = await runConsolidation(options, f.deps);
      expect(result.mutations).toBe(1);
      expect(f.events.indexOf("get")).toBeLessThan(f.events.indexOf("model"));
      expect(f.events.indexOf("model")).toBeLessThan(f.events.indexOf("apply"));
    } finally { await f.close(); }
  });

  it.each([undefined, "", 17])("TC-CONSOL-096: refuses invalid ETag %j before any model work", async etag => {
    const f = await fixture();
    f.deps.loadDigestState = async () => ({ status: "ok", state: emptyState(), etag });
    try {
      await expect(runConsolidation(options, f.deps)).rejects.toThrow(/valid readable state/);
      expect(f.deps.listActiveMemories).not.toHaveBeenCalled();
    } finally { await f.close(); }
  });

  it.each([
    ["put403", { putError: error("AccessDenied", 403) }],
    ["kms", { putError: error("KMSAccessDeniedException", 400) }],
    ["conflict409", { putError: error("ConditionalRequestConflict", 409) }],
    ["transport", { putError: new Error("transport failed") }],
    ["name-only412", { putError: error("PreconditionFailed", 403) }],
    ["name-without-status", { putError: Object.assign(new Error("precondition"), { name: "PreconditionFailed" }) }],
    ["get403", { getError: error("AccessDenied", 403) }],
    ["disappeared", { getError: error("NoSuchKey", 404) }],
  ])("TC-CONSOL-096: %s aborts before model and memory reads", async (_name, config) => {
    const f = await fixture(config);
    try {
      await expect(runConsolidation({ ...options, checkLlm: true }, f.deps)).rejects.toThrow();
      expect(f.deps.completeChat).not.toHaveBeenCalled();
      expect(f.deps.listActiveMemories).not.toHaveBeenCalled();
      expect(f.events).not.toContain("update");
    } finally { await f.close(); }
  });

  it.each([
    ["json", "not-json"],
    ["namespace", JSON.stringify({ ...emptyState(), namespaceId: OTHER })],
    ["stage", JSON.stringify({ ...emptyState(), stage: "pr-example" })],
    ["schema", JSON.stringify({ ...emptyState(), schemaVersion: 999 })],
  ])("TC-CONSOL-096: preserves invalid existing %s and blocks model/apply", async (_name, existing) => {
    const f = await fixture({ existing });
    try {
      await expect(runConsolidation({ ...options, checkLlm: true }, f.deps)).rejects.toThrow();
      expect(f.state.body).toBe(existing);
      expect(f.state.version).toBe(1);
      expect(f.deps.listActiveMemories).not.toHaveBeenCalled();
      expect(f.deps.completeChat).not.toHaveBeenCalled();
    } finally { await f.close(); }
  });

  it.each(["revoked", "viewer", "invalid-scope"])("TC-CONSOL-097: %s sends no S3 request", async mode => {
    const f = await fixture();
    if (mode === "revoked") f.state.active = false;
    if (mode === "viewer") f.state.role = "viewer";
    try {
      await expect(runConsolidation({ ...options, namespaceId: mode === "invalid-scope" ? OTHER : NS }, f.deps)).rejects.toThrow();
      expect(f.commands).toEqual([]);
      expect(f.deps.listActiveMemories).not.toHaveBeenCalled();
    } finally { await f.close(); }
  });

  it("TC-CONSOL-097: reauthorizes after initialization and refuses a revoked namespace before reading/model", async () => {
    const f = await fixture({ afterPut: state => { state.active = false; } });
    try {
      await expect(runConsolidation({ ...options, checkLlm: true }, f.deps)).rejects.toThrow(/namespace denied/);
      expect(f.commands).toHaveLength(1);
      expect(f.events).not.toContain("get");
      expect(f.deps.completeChat).not.toHaveBeenCalled();
    } finally { await f.close(); }
  });

  it.each([
    { reportOnly: true, scheduled: true }, { reportOnly: true, scheduled: false },
    { reportOnly: false, scheduled: false },
  ])("TC-CONSOL-098: no digest requests for %j", async flags => {
    const f = await fixture();
    try {
      expect((await runConsolidation({ ...options, ...flags }, f.deps)).exitCode).toBe(0);
      expect(f.commands).toEqual([]);
      expect(f.state.body).toBeUndefined();
    } finally { await f.close(); }
  });

  it("TC-CONSOL-098: empty baseline has the same initial health/reminder/transitions as missing", () => {
    for (const review of [[], [{ kind: "CLASSIFICATION_FAILED", ids: [], rationale: "synthetic" }]]) {
      const input = { stage: "prod", namespaceId: NS, review, byId: new Map(), now: NOW,
        metrics: { scanned: 0 }, mutations: 0, attemptedClusters: 10, classificationFailures: review.length };
      expect(buildDigestOutcome({ ...input, previousState: emptyState() })).toEqual(buildDigestOutcome(input));
    }
  });
});
