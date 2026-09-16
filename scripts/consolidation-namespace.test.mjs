import { afterEach, describe, expect, it, vi } from "vitest";
import {
  buildReviewTopic,
  buildDigestOutcome,
  createConsolidationDatabase,
  createProductionDeps,
  digestStateKey,
  parseConsolidationArgs,
  processScheduledDigest,
  runConsolidation,
} from "./memory-consolidation.mjs";
import { requireMaintenanceConfig } from "./lib/maintenance-scope.mjs";
import { verifyTransportEnvelope } from "../infra/gateway/namespace-auth.mjs";

const NAMESPACE_A = "60000000-0000-4000-8000-000000000101";
const NAMESPACE_B = "60000000-0000-4000-8000-000000000102";
const PRINCIPAL_ID = "70000000-0000-4000-8000-000000000101";
const SIGNING_KEYS = JSON.stringify({ current: Buffer.alloc(32, 9).toString("base64url") });

function scope(namespaceId = NAMESPACE_A) {
  return requireMaintenanceConfig({ stage: "prod", namespaceId }, {
    MEM9_SERVICE_TRANSPORT_SIGNING_KEYS: SIGNING_KEYS,
  }, "consolidation");
}

function fakeDatabase(namespaceId = NAMESPACE_A) {
  const state = { phase: "constraints_complete", allowed: true, membershipActive: true, role: "owner", rows: [memory(namespaceId)] };
  const query = vi.fn(async (sql) => {
    if (sql.includes("FROM memory_namespace_migration_state"))
      return { rowCount: state.phase ? 1 : 0, rows: state.phase ? [{ phase: state.phase }] : [] };
    if (sql.includes("FROM memory_namespaces"))
      return { rowCount: state.allowed ? 1 : 0, rows: [{ namespace_id: namespaceId }] };
    if (sql.includes("FROM memory_principals"))
      return { rowCount: 1, rows: [{ principal_id: PRINCIPAL_ID }] };
    if (sql.includes("FROM memory_namespace_memberships"))
      return { rowCount: state.membershipActive ? 1 : 0, rows: state.membershipActive ? [{ role: state.role }] : [] };
    if (sql.includes("FROM memories") && !sql.includes("UPDATE"))
      return { rowCount: state.rows.length, rows: state.rows };
    if (sql.includes("pg_try_advisory_lock"))
      return { rowCount: 1, rows: [{ acquired: true }] };
    return { rowCount: 1, rows: [] };
  });
  class Client {
    query = query;
    async connect() {}
    async end() {}
  }
  return { state, query, Client, db: { query } };
}

function productionEnvironment() {
  for (const [key, value] of Object.entries({
    AWS_REGION: "ap-northeast-1",
    MEM9_NAMESPACE_ID: NAMESPACE_A,
    MEM9_SERVICE_TRANSPORT_SIGNING_KEYS: SIGNING_KEYS,
    MEM9_DB_HOST: "database.example.com",
    MEM9_DB_NAME: "fixture",
    MEM9_DB_SECRET: JSON.stringify({ username: "fixture", password: "fixture-password" }),
    MEM9_TENANT_ID: "fixture-tenant",
    MEM9_BASE_URL: "http://mnemo.example.com",
    MEM9_DECISION_ARTIFACT_BUCKET: "example-consolidation",
    MEM9_DECISION_ARTIFACT_BUCKET_OWNER: "123456789012",
    SLACK_BOT_TOKEN: "",
    MEM9_SLACK_APPROVAL_CHANNEL: "",
    MEM9_SLACK_APPROVAL_ENABLED: "0",
  })) vi.stubEnv(key, value);
}

function digestInput(namespaceId = NAMESPACE_A) {
  return {
    stage: "prod", namespaceId, review: [], byId: new Map(),
    metrics: { scanned: 0, merged: 0, archived: 0, flaggedStale: 0, reviewItems: 0, skippedLww: 0 },
    mutations: 0, attemptedClusters: 0, classificationFailures: 0,
    now: Date.parse("2026-09-01T00:00:00Z"),
  };
}

function memory(namespaceId = NAMESPACE_A) {
  return {
    id: "81000000-0000-4000-8000-000000000101",
    namespace_id: namespaceId,
    content: "synthetic configuration",
    embedding: [1, 0],
    memory_type: "insight",
    state: "active",
    version: 1,
    tags: [],
    metadata: {},
    created_at: "2024-01-01T00:00:00Z",
    updated_at: "2024-01-01T00:00:00Z",
  };
}

function deps(rows = []) {
  return {
    listActiveMemories: vi.fn(async () => rows),
    completeChat: vi.fn(async () => '{"actions":[]}'),
    log: vi.fn(),
    emitMetrics: vi.fn(),
    clock: () => Date.parse("2026-09-01T00:00:00Z"),
  };
}

afterEach(() => vi.unstubAllEnvs());

describe("TC-GROUPNS-099: one namespace per consolidation run", () => {
  it.each([undefined, "", "all", "*", [NAMESPACE_A, NAMESPACE_B]].map((value) => [value]))(
    "rejects invalid namespace %j before model or content reads",
    async (namespaceId) => {
      const adapters = deps();
      await expect(runConsolidation({ stage: "prod", namespaceId, checkLlm: true }, adapters))
        .rejects.toThrow(/namespace/i);
      expect(adapters.listActiveMemories).not.toHaveBeenCalled();
      expect(adapters.completeChat).not.toHaveBeenCalled();
    },
  );

  it.each([NAMESPACE_B, undefined])("rejects a foreign or unscoped row before classification", async (namespaceId) => {
    const row = memory();
    row.namespace_id = namespaceId;
    const adapters = deps([row]);
    await expect(runConsolidation({ stage: "prod", namespaceId: NAMESPACE_A, checkLlm: true }, adapters))
      .rejects.toThrow(/namespace/i);
    expect(adapters.completeChat).not.toHaveBeenCalled();
  });

  it("rejects mismatched adapter scope before any content read", async () => {
    const adapters = { ...deps(), namespaceId: NAMESPACE_B };
    await expect(runConsolidation({ stage: "prod", namespaceId: NAMESPACE_A }, adapters))
      .rejects.toThrow(/namespace/i);
    expect(adapters.listActiveMemories).not.toHaveBeenCalled();
  });

  it("rejects legacy Slack configuration before constructing adapters", async () => {
    vi.stubEnv("AWS_REGION", "ap-northeast-1");
    vi.stubEnv("MEM9_SLACK_APPROVAL_CHANNEL", "fixture-channel");
    const Client = vi.fn();
    await expect(createProductionDeps({ stage: "prod", namespaceId: NAMESPACE_A }, { Client }))
      .rejects.toThrow(/Slack/i);
    expect(Client).not.toHaveBeenCalled();
  });

  it("parses an explicit namespace and rejects repeated flags", () => {
    vi.stubEnv("MEM9_NAMESPACE_ID", NAMESPACE_A);
    expect(parseConsolidationArgs(["--stage", "prod"]).namespaceId).toBe(NAMESPACE_A);
    expect(parseConsolidationArgs(["--namespace-id", NAMESPACE_B]).namespaceId).toBe(NAMESPACE_B);
    expect(() => parseConsolidationArgs(["--namespace-id", NAMESPACE_A, "--namespace-id", NAMESPACE_B]))
      .toThrow(/one namespace/i);
  });

  it("uses scoped transactions for reads, stale writes, and both archive sides", async () => {
    const fixture = fakeDatabase();
    const database = createConsolidationDatabase(fixture.db, scope());
    expect(await database.listActiveMemories()).toHaveLength(1);
    const list = fixture.query.mock.calls.find(([sql]) => sql.includes("SELECT id, namespace_id"));
    expect(list[0]).toContain("WHERE namespace_id = $1");
    expect(list[1]).toEqual([NAMESPACE_A]);
    await database.archiveMemory({ id: "loser", supersededBy: "winner", version: 3,
      content: "old", winnerVersion: 7, winnerContent: "new" });
    const archive = fixture.query.mock.calls.find(([sql]) => sql.includes("UPDATE memories AS loser"));
    expect(archive[0]).toContain("loser.namespace_id = $7");
    expect(archive[0]).toContain("winner.namespace_id = $7");
    expect(archive[0]).toContain("updated_by_principal_id = $8");
    expect(archive[1]).toEqual(["loser", "winner", 3, "old", 7, "new", NAMESPACE_A, PRINCIPAL_ID]);
    await database.markMemoryStale({ id: "stale", tags: ["stale"], metadata: {}, version: 2, content: "old" });
    const stale = fixture.query.mock.calls.find(([sql]) => sql.includes("SET tags = $2"));
    expect(stale[0]).toContain("namespace_id = $6");
    expect(stale[0]).toContain("updated_by_principal_id = $7");
    expect(stale[0]).not.toMatch(/embedding\s*=/);
    expect(stale[1]).toEqual(["stale", '["stale"]', "{}", 2, "old", NAMESPACE_A, PRINCIPAL_ID]);
    expect(fixture.query.mock.calls.filter(([sql]) => sql === "COMMIT")).toHaveLength(3);
    fixture.state.role = "viewer";
    fixture.query.mockClear();
    await expect(database.markMemoryStale({})).rejects.toThrow(/membership denied/);
    expect(fixture.query.mock.calls.some(([sql]) => sql.includes("UPDATE memories"))).toBe(false);
    expect(fixture.query.mock.calls.at(-1)[0]).toBe("ROLLBACK");
  });

  it("signs every REST verb with the fixed service and requested namespace", async () => {
    productionEnvironment();
    const fixture = fakeDatabase();
    const fetch = vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ deleted: 1 }) }));
    const production = await createProductionDeps({ stage: "prod" }, { Client: fixture.Client, fetch });
    try {
      await production.deps.getMemory("known-id");
      await production.deps.putMemory("known-id", { content: "replacement" }, 1);
      await production.deps.deleteMemories(["known-id"]);
      for (const [url, options] of fetch.mock.calls) {
        const signed = verifyTransportEnvelope({ envelope: options.headers.get("X-Mem9-Transport"),
          issuer: scope().issuer, keys: scope().keys, method: options.method,
          path: new URL(url).pathname, body: options.body ?? "" });
        expect(signed).toMatchObject({ principal_type: "service", principal_key: scope().principalKey,
          namespace_id: NAMESPACE_A });
        expect(options.headers.get("X-API-Key")).toBe("fixture-tenant");
      }
      expect(fetch.mock.calls[1][1].headers.get("If-Match")).toBe("1");
    } finally { await production.close(); }
  });

  it("authorizes before model and digest calls and strips arbitrary production log data", async () => {
    productionEnvironment();
    const fixture = fakeDatabase();
    const fetch = vi.fn();
    const getToken = vi.fn();
    const send = vi.fn();
    const writeStdout = vi.fn();
    class Command { constructor(input) { this.input = input; } }
    class S3Client { send = send; destroy() {} }
    const production = await createProductionDeps({ stage: "prod" }, {
      Client: fixture.Client, fetch, getToken, fromNodeProviderChain: () => ({}),
      S3Client, GetObjectCommand: Command, PutObjectCommand: Command, writeStdout,
    });
    try {
      fixture.state.allowed = false;
      await expect(production.deps.completeChat("fixture", [])).rejects.toThrow(/namespace denied/);
      await expect(production.deps.loadDigestState()).rejects.toThrow(/namespace denied/);
      const state = buildDigestOutcome(digestInput()).nextState;
      await expect(production.deps.writeDigestState({ state })).rejects.toThrow(/namespace denied/);
      expect(fetch).not.toHaveBeenCalled();
      expect(getToken).not.toHaveBeenCalled();
      expect(send).not.toHaveBeenCalled();
      production.deps.log(`MERGE private-id: private content ${NAMESPACE_A}`);
      production.deps.log(`CONSOLIDATION_REVIEW ${JSON.stringify({ kind: "DELETE", count: 2,
        ids: ["private-id"], snippets: ["private content"], namespaceId: NAMESPACE_A })}`);
      production.deps.log(`CONSOLIDATION_DIGEST ${JSON.stringify({ event: "state_write_failed",
        errorClass: "private content", reason: "private content", namespaceId: NAMESPACE_A })}`);
      const lines = writeStdout.mock.calls.map(([line]) => line).join("");
      expect(lines).not.toMatch(/private-id|private content|60000000/);
      expect(lines).toContain('"kind":"DELETE"');
      expect(lines).toContain('"status":"state_write_failed"');
    } finally { await production.close(); }
  });

  it.each([401, 403])("rechecks membership after provider HTTP %i before resending memory content", async (status) => {
    productionEnvironment();
    vi.stubEnv("MEM9_LLM_MODEL", "zai.glm-5");
    const fixture = fakeDatabase();
    let queriesAtProviderFailure;
    const fetch = vi.fn(async () => {
      if (fetch.mock.calls.length === 1) {
        queriesAtProviderFailure = fixture.query.mock.calls.length;
        fixture.state.membershipActive = false;
        return { ok: false, status, json: async () => ({}) };
      }
      return { ok: true, status: 200, json: async () => ({
        choices: [{ message: { content: '{"actions":[]}' } }],
      }) };
    });
    const production = await createProductionDeps({ stage: "prod" }, {
      Client: fixture.Client, fetch,
      getToken: vi.fn(async () => "fixture-bearer"), fromNodeProviderChain: () => ({}),
    });
    try {
      await expect(production.deps.completeChat("synthetic classifier", [memory()]))
        .rejects.toThrow(/membership denied/);
      expect(fetch).toHaveBeenCalledOnce();
      expect(fetch.mock.calls[0][1].body).toContain("synthetic configuration");
      expect(fixture.query.mock.calls.slice(queriesAtProviderFailure)
        .some(([sql]) => sql.includes("FROM memory_namespace_memberships"))).toBe(true);
      expect(fixture.query.mock.calls.at(-1)[0]).toBe("ROLLBACK");
    } finally { await production.close(); }
  });

  it.each(["application_ready", undefined])("rejects phase %j before namespace, model, or digest access", async (phase) => {
    productionEnvironment();
    const fixture = fakeDatabase();
    const fetch = vi.fn(), getToken = vi.fn();
    const production = await createProductionDeps({ stage: "prod" }, {
      Client: fixture.Client, fetch, getToken, fromNodeProviderChain: () => ({}),
    });
    try {
      expect(await production.deps.listActiveMemories()).toHaveLength(1);
      fixture.state.phase = phase;
      fixture.query.mockClear();
      await expect(production.deps.listActiveMemories()).rejects.toThrow(/requires namespace enforcement/);
      await expect(production.deps.completeChat("fixture", [])).rejects.toThrow(/requires namespace enforcement/);
      await expect(production.deps.loadDigestState()).rejects.toThrow(/requires namespace enforcement/);
      await expect(production.deps.writeDigestState({ state: buildDigestOutcome(digestInput()).nextState }))
        .rejects.toThrow(/requires namespace enforcement/);
      expect(fetch).not.toHaveBeenCalled();
      expect(getToken).not.toHaveBeenCalled();
      expect(fixture.query.mock.calls.some(([sql]) =>
        /FROM (memory_namespaces|memory_principals|memory_namespace_memberships|memories)\b/u.test(sql),
      )).toBe(false);
    } finally { await production.close(); }
  });
});

describe("TC-GROUPNS-100: namespace-specific digest subjects", () => {
  it.each([
    { kind: "DELETE", ids: [memory().id] },
    { kind: "APPLY_FAILED", ids: [] },
    { kind: "LOCK_HELD", ids: [] },
  ])("separates $kind across namespaces", (item) => {
    const byId = new Map([[memory().id, memory()]]);
    const a = buildReviewTopic(item, byId, NAMESPACE_A);
    const b = buildReviewTopic(item, byId, NAMESPACE_B);
    expect(a.topicId).not.toBe(b.topicId);
    expect(a.payloadHash).not.toBe(b.payloadHash);
  });

  it("uses independent namespace mutex keys for acquisition and release", async () => {
    const a = fakeDatabase(NAMESPACE_A), b = fakeDatabase(NAMESPACE_B);
    const first = await createConsolidationDatabase(a.db, scope(NAMESPACE_A)).acquireMutex();
    const second = await createConsolidationDatabase(b.db, scope(NAMESPACE_B)).acquireMutex();
    const key = (fixture) => fixture.query.mock.calls.find(([sql]) => sql.includes("pg_try_advisory_lock"))[1][0];
    expect(key(a)).not.toBe(key(b));
    await first.release();
    await second.release();
    expect(a.query.mock.calls.at(-1)[1]).toEqual([key(a)]);
    expect(b.query.mock.calls.at(-1)[1]).toEqual([key(b)]);
  });

  it("rejects foreign digest state without resolving its topics or overwriting it", async () => {
    expect(digestStateKey("prod", NAMESPACE_A)).toBe(`consolidation-digests/prod/${NAMESPACE_A}/current-v1.json`);
    expect(digestStateKey("prod", NAMESPACE_A)).not.toBe(digestStateKey("prod", NAMESPACE_B));
    const foreign = buildDigestOutcome({ ...digestInput(NAMESPACE_B),
      review: [{ kind: "LOCK_HELD", ids: [] }] }).nextState;
    const writeDigestState = vi.fn();
    const result = await processScheduledDigest(digestInput(NAMESPACE_A), {
      loadDigestState: async () => ({ status: "ok", etag: "foreign", state: foreign }),
      writeDigestState, log: vi.fn(),
    });
    expect(result).toMatchObject({ failed: true, dedupUnavailable: true });
    expect(result.transitions.resolved).toEqual([]);
    expect(result.nextState.namespaceId).toBe(NAMESPACE_A);
    expect(result.nextState.kindCounts).toEqual({});
    expect(writeDigestState).not.toHaveBeenCalled();
  });

  it("isolates concurrent digest failures and success", async () => {
    const writes = [];
    const [a, b] = await Promise.all([NAMESPACE_A, NAMESPACE_B].map((namespaceId) =>
      processScheduledDigest(digestInput(namespaceId), {
        loadDigestState: async () => ({ status: "missing" }),
        writeDigestState: async ({ state }) => {
          if (namespaceId === NAMESPACE_A) throw new Error("injected failure");
          writes.push(state);
        },
        log: vi.fn(),
      })));
    expect(a.failed).toBe(true);
    expect(b.failed).toBe(false);
    expect(writes).toHaveLength(1);
    expect(writes[0].namespaceId).toBe(NAMESPACE_B);
    expect(writes[0].kindCounts).toEqual({});
  });
});
