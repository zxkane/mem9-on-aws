import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import pg from "pg";
import { createMaintenanceIdentity } from "./lib/maintenance-scope.mjs";
import { parseSigningKeys, verifyTransportEnvelope } from "../infra/gateway/namespace-auth.mjs";
import {
  contentHash,
  createCleanupDeps,
  inactiveMemoryAdapter,
  parseArgs,
  recoveryDeps,
  runCleanup,
  runListInactive,
  runRestore,
  sharedCleanupMutexKey,
} from "./memory-cleanup.mjs";

const NS = "60000000-0000-4000-8000-000000000101";
const OTHER_NS = "60000000-0000-4000-8000-000000000102";
const PRINCIPAL = "70000000-0000-4000-8000-000000000101";
const SCOPE = { ...createMaintenanceIdentity("cleanup"), stage: "test", namespaceId: NS };
const SIGNING_KEYS = JSON.stringify({ active: "a", a: Buffer.alloc(32, 1).toString("base64url"), b: Buffer.alloc(32, 2).toString("base64url") });
const directories = [];
const directory = () => {
  const path = mkdtempSync(join(tmpdir(), "memclean-namespace-"));
  directories.push(path);
  return path;
};
afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe("production recovery reporting", () => {
  it.each(["after_scan", "between_passes"])("reauthorizes model calls when membership is revoked %s", async (when) => {
    for (const [key, value] of Object.entries({
      AWS_REGION: "ap-northeast-1", MEM9_NAMESPACE_ID: NS,
      MEM9_SERVICE_TRANSPORT_SIGNING_KEYS: SIGNING_KEYS, MEM9_TENANT_ID: "fixture-tenant",
      MEM9_DB_HOST: "fixture.invalid", MEM9_DB_NAME: "fixture", MEM9_BEDROCK_PROJECT: "fixture-project",
      MEM9_DB_SECRET: JSON.stringify({ username: "fixture", password: "fixture" }),
    })) vi.stubEnv(key, value);
    let revoked = false;
    const row = { id: "own", content: "durable own fact", namespace_id: NS, state: "active", version: 1, memory_type: "insight" };
    class Client {
      async connect() {}
      async end() {}
      async query(sql) {
        if (sql.includes("FROM memory_namespace_migration_state")) return { rowCount: 1, rows: [{ phase: "constraints_complete" }] };
        if (sql.includes("FROM memory_namespaces")) return { rowCount: 1, rows: [{ namespace_id: NS }] };
        if (sql.includes("FROM memory_principals")) return { rowCount: 1, rows: [{ principal_id: PRINCIPAL }] };
        if (sql.includes("FROM memory_namespace_memberships")) return revoked ? { rowCount: 0, rows: [] } : { rowCount: 1, rows: [{ role: "member" }] };
        if (sql.includes("FROM memories")) {
          if (when === "after_scan") revoked = true;
          return { rowCount: 1, rows: [row] };
        }
        return { rows: [] };
      }
    }
    const provider = vi.fn(async () => {
      if (when === "between_passes") revoked = true;
      return new Response(JSON.stringify({ choices: [{ finish_reason: "stop", message: { content: JSON.stringify({ verdicts: [{ id: "own", verdict: "KEEP", topic: "engineering", reason: "durable" }] }) } }] }));
    });
    const fetchImpl = vi.fn(async (url, request) => new URL(url).hostname === "fixture.invalid"
      ? new Response(JSON.stringify({ memories: [row] })) : provider(url, request));
    const getToken = vi.fn(async () => "fixture-provider-token");
    const opts = { stage: "test", namespaceId: NS, baseUrl: "http://fixture.invalid", model: "zai.glm-5", consensusPasses: 2, outDir: directory() };
    const production = await createCleanupDeps(opts, { Client, fetchImpl, getToken, fromNodeProviderChain: vi.fn(), emit: vi.fn() });
    try {
      await runCleanup({ ...opts, tenantId: production.tenantId }, production.deps);
      expect(revoked).toBe(true);
      expect(provider).toHaveBeenCalledTimes(when === "after_scan" ? 0 : 1);
      expect(getToken).toHaveBeenCalledTimes(when === "after_scan" ? 0 : 1);
      await expect(production.deps.completeChat("system", [row])).rejects.toThrow(/denied/);
      expect(provider).toHaveBeenCalledTimes(when === "after_scan" ? 0 : 1);
    } finally { await production.close(); }
  });

  it("binds the ordinary cleanup fetch to the fixed service and namespace while retaining the tenant header", async () => {
    for (const [key, value] of Object.entries({
      AWS_REGION: "ap-northeast-1", MEM9_NAMESPACE_ID: NS,
      MEM9_SERVICE_TRANSPORT_SIGNING_KEYS: SIGNING_KEYS, MEM9_TENANT_ID: "fixture-tenant",
      MEM9_DB_HOST: "fixture.invalid", MEM9_DB_NAME: "fixture",
      MEM9_DB_SECRET: JSON.stringify({ username: "fixture", password: "fixture" }),
    })) vi.stubEnv(key, value);
    class Client {
      async connect() {}
      async end() {}
      async query(sql) {
        if (sql.includes("FROM memory_namespace_migration_state")) return { rowCount: 1, rows: [{ phase: "constraints_complete" }] };
        if (sql.includes("FROM memory_namespaces")) return { rowCount: 1, rows: [{ namespace_id: NS }] };
        if (sql.includes("FROM memory_principals")) return { rowCount: 1, rows: [{ principal_id: PRINCIPAL }] };
        if (sql.includes("FROM memory_namespace_memberships")) return { rowCount: 1, rows: [{ role: "member" }] };
        return { rows: [] };
      }
    }
    const fetchImpl = vi.fn(async () => new Response("{}"));
    const production = await createCleanupDeps({ stage: "test", namespaceId: NS, outDir: directory() }, {
      Client, fetchImpl, getToken: vi.fn(), fromNodeProviderChain: vi.fn(), emit: vi.fn(),
    });
    try {
      const path = "/v1alpha2/mem9s/memories?limit=200&offset=0";
      const headers = new Headers();
      headers.set("X-API-Key", production.tenantId);
      await production.deps.fetchImpl(`http://fixture.invalid${path}`, { headers });
      const [, request] = fetchImpl.mock.calls[0];
      expect(request.headers.get("X-API-Key")).toBe("fixture-tenant");
      const identity = verifyTransportEnvelope({
        envelope: request.headers.get("X-Mem9-Transport"), issuer: SCOPE.issuer,
        method: "GET", path, keys: parseSigningKeys(SIGNING_KEYS),
      });
      expect(identity).toMatchObject({ principal_type: "service", principal_key: SCOPE.principalKey, namespace_id: NS });
      expect(production.deps.postApproval).toBeUndefined();
      expect(production.deps.loadReviewedDecisions).toBeUndefined();
    } finally { await production.close(); }
  });

  it("keeps console output content-free and stores its full report at owner-only permissions", async () => {
    const dir = directory();
    for (const [key, value] of Object.entries({
      AWS_REGION: "ap-northeast-1", MEM9_NAMESPACE_ID: NS,
      MEM9_SERVICE_TRANSPORT_SIGNING_KEYS: SIGNING_KEYS,
      MEM9_DB_HOST: "fixture.invalid", MEM9_DB_NAME: "fixture",
      MEM9_DB_SECRET: JSON.stringify({ username: "fixture", password: "fixture" }),
    })) vi.stubEnv(key, value);
    const marker = "private operator content";
    class Client {
      async connect() {}
      async end() {}
      async query(sql) {
        if (sql.includes("FROM memory_namespace_migration_state")) return { rowCount: 1, rows: [{ phase: "constraints_complete" }] };
        if (sql.includes("FROM memory_namespaces")) return { rowCount: 1, rows: [{ namespace_id: NS }] };
        if (sql.includes("FROM memory_principals")) return { rowCount: 1, rows: [{ principal_id: PRINCIPAL }] };
        if (sql.includes("FROM memory_namespace_memberships")) return { rowCount: 1, rows: [{ role: "member" }] };
        if (sql.includes("count(*)")) return { rows: [{ total: "1" }] };
        if (sql.includes("FROM memories")) return { rows: [{ id: "private-row-id", state: "deleted", content: marker, version: 1, updated_at: new Date(0) }] };
        return { rows: [] };
      }
    }
    const emit = vi.fn();
    const opts = { stage: "test", namespaceId: NS, listInactive: true, outDir: dir };
    const production = await recoveryDeps(opts, { Client, emit });
    const result = await runListInactive(opts, production.deps);
    production.recordResult(result);
    await production.close();
    const consoleOutput = JSON.stringify(emit.mock.calls);
    for (const value of [marker, NS, PRINCIPAL, "private-row-id"]) expect(consoleOutput).not.toContain(value);
    for (const [line] of emit.mock.calls) expect(["progress", "summary"]).toContain(JSON.parse(line).kind);
    const path = join(dir, NS, readdirSync(join(dir, NS)).find((name) => name.startsWith("report-")));
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(statSync(join(dir, NS)).mode & 0o777).toBe(0o700);
    const report = JSON.parse(readFileSync(path, "utf8"));
    expect(report.namespaceId).toBe(NS);
    expect(report.result.rows[0].snippet).toBe(marker);
  });
});

async function postgresFixture(work) {
  const connectionString = process.env.MEM9_NAMESPACE_TEST_DSN;
  if (!["localhost", "127.0.0.1", "[::1]"].includes(new URL(connectionString).hostname))
    throw new Error("cleanup integration requires a loopback test database");
  const db = new pg.Client({ connectionString });
  const schema = `cleanup_${randomUUID().replaceAll("-", "")}`;
  await db.connect();
  try {
    await db.query("CREATE EXTENSION IF NOT EXISTS vector");
    await db.query(`CREATE SCHEMA ${schema}`);
    await db.query(`SET search_path TO ${schema}, public`);
    await db.query(`
      CREATE TABLE memory_namespace_migration_state(singleton_id boolean PRIMARY KEY, phase text NOT NULL);
      INSERT INTO memory_namespace_migration_state VALUES(true, 'constraints_complete');
      CREATE TABLE memory_namespaces(namespace_id varchar(36) PRIMARY KEY, status text NOT NULL);
      CREATE TABLE memory_principals(principal_id varchar(36) PRIMARY KEY, principal_key text NOT NULL, principal_type text NOT NULL, status text NOT NULL);
      CREATE TABLE memory_namespace_memberships(namespace_id varchar(36) REFERENCES memory_namespaces, principal_id varchar(36) REFERENCES memory_principals, role text NOT NULL, status text NOT NULL, source_type text NOT NULL, PRIMARY KEY(namespace_id, principal_id));
      CREATE TABLE memories(id varchar(36) PRIMARY KEY, namespace_id varchar(36) NOT NULL REFERENCES memory_namespaces,
        content text, state text, version integer, embedding vector(1024), updated_at timestamptz,
        superseded_by varchar(36), updated_by_principal_id varchar(36) REFERENCES memory_principals);
      CREATE FUNCTION touch_memory() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.updated_at = NOW(); RETURN NEW; END $$;
      CREATE TRIGGER touch_memory BEFORE UPDATE ON memories FOR EACH ROW EXECUTE FUNCTION touch_memory();
    `);
    await db.query("INSERT INTO memory_namespaces VALUES ($1,'active'),($2,'active')", [NS, OTHER_NS]);
    await db.query("INSERT INTO memory_principals VALUES ($1,$2,'service','active')", [PRINCIPAL, SCOPE.principalKey]);
    await db.query("INSERT INTO memory_namespace_memberships VALUES ($1,$3,'member','active','service'),($2,$3,'member','active','service')", [NS, OTHER_NS, PRINCIPAL]);
    const rows = [
      ["a-active", NS, "same fact", "active", 3, null],
      ["a-deleted", NS, "own deleted", "deleted", 7, null],
      ["a-archived", NS, "own archived", "archived", 9, "a-active"],
      ["a-link", NS, "own linked", "deleted", 4, "b-active"],
      ["b-active", OTHER_NS, "same fact", "active", 3, null],
      ["b-deleted", OTHER_NS, "foreign private marker", "deleted", 7, null],
      ["b-archived", OTHER_NS, "foreign private marker", "archived", 9, "b-active"],
    ];
    for (const row of rows) await db.query(`INSERT INTO memories(id,namespace_id,content,state,version,superseded_by,embedding,updated_at)
      VALUES($1,$2,$3,$4,$5,$6,(ARRAY[1::real] || array_fill(0::real, ARRAY[1023]))::vector,'2000-01-01')`, row);
    await work(db);
  } finally {
    await db.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await db.end();
  }
}

describe.skipIf(!process.env.MEM9_NAMESPACE_TEST_DSN)("TC-GROUPNS-097/098 with two PostgreSQL namespaces", () => {
  it.each(["provider_401", "during_refresh_mint"])("blocks a provider retry after PostgreSQL revocation: %s", async (when) => postgresFixture(async (db) => {
    for (const [key, value] of Object.entries({
      AWS_REGION: "ap-northeast-1", MEM9_NAMESPACE_ID: NS,
      MEM9_SERVICE_TRANSPORT_SIGNING_KEYS: SIGNING_KEYS, MEM9_TENANT_ID: "fixture-tenant",
      MEM9_DB_HOST: "fixture.invalid", MEM9_DB_NAME: "fixture", MEM9_BEDROCK_PROJECT: "fixture-project",
      MEM9_DB_SECRET: JSON.stringify({ username: "fixture", password: "fixture" }),
    })) vi.stubEnv(key, value);
    const { pid, schema } = (await db.query("SELECT pg_backend_pid() AS pid, current_schema() AS schema")).rows[0];
    const inspector = new pg.Client({ connectionString: process.env.MEM9_NAMESPACE_TEST_DSN });
    await inspector.connect();
    let production;
    try {
      await inspector.query("SELECT set_config('search_path', $1, false)", [schema]);
      await inspector.query("SET lock_timeout='1s'");
      await inspector.query("SET statement_timeout='3s'");
      const idle = async () => {
        const activity = (await inspector.query("SELECT state, xact_start FROM pg_stat_activity WHERE pid=$1", [pid])).rows[0];
        expect(activity).toMatchObject({ state: "idle", xact_start: null });
      };
      const revoke = () => inspector.query("UPDATE memory_namespace_memberships SET status='revoked' WHERE namespace_id=$1 AND principal_id=$2", [NS, PRINCIPAL]);
      class Client {
        async connect() {}
        query(...args) { return db.query(...args); }
        async end() {} // postgresFixture owns this borrowed connection.
      }
      let mints = 0;
      const getToken = vi.fn(async () => {
        await idle(); mints++;
        if (when === "during_refresh_mint" && mints === 2) await revoke();
        return `fixture-token-${mints}`;
      });
      const fetchImpl = vi.fn(async () => {
        await idle();
        if (when === "provider_401") await revoke();
        return new Response("{}", { status: 401 });
      });
      production = await createCleanupDeps({ stage: "test", namespaceId: NS, model: "zai.glm-5", outDir: directory() }, {
        Client, getToken, fetchImpl, fromNodeProviderChain: vi.fn(), emit: vi.fn(),
      });
      await expect(production.deps.completeChat("system", [{ id: "a-active", content: "same fact" }])).rejects.toThrow(/denied/);
      expect(fetchImpl).toHaveBeenCalledTimes(1);
      expect(getToken).toHaveBeenCalledTimes(when === "provider_401" ? 1 : 2);
      await idle();
    } finally { await production?.close(); await inspector.end(); }
  }));

  it("scopes counts, pages, all-state lookups and direct restore mutations", async () => postgresFixture(async (db) => {
    const adapter = inactiveMemoryAdapter(db, SCOPE);
    const page = await adapter.listInactive({ limit: 1 });
    expect(page.total).toBe(3);
    expect(page.rows).toHaveLength(1);
    expect((await adapter.listInactive({ state: "archived" })).total).toBe(1);
    expect((await adapter.findByIds(["a-active", "a-deleted", "b-active", "b-deleted", "missing"])).map((row) => row.id).sort()).toEqual(["a-active", "a-deleted"]);
    const snapshot = async () => JSON.stringify((await db.query("SELECT * FROM memories WHERE namespace_id=$1 ORDER BY id", [OTHER_NS])).rows);
    const before = await snapshot();
    expect(await adapter.restoreMemory({ id: "b-deleted", priorState: "deleted", version: 7 })).toBe(false);
    expect(await adapter.restoreMemory({ id: "a-deleted", priorState: "deleted", version: 6 })).toBe(false);
    const ownBefore = (await db.query("SELECT * FROM memories WHERE id='a-deleted'")).rows[0];
    expect(await adapter.restoreMemory({ id: "a-deleted", priorState: "deleted", version: 7 })).toBe(true);
    const ownAfter = (await db.query("SELECT * FROM memories WHERE id='a-deleted'")).rows[0];
    expect(ownAfter).toMatchObject({ state: "active", updated_by_principal_id: PRINCIPAL, namespace_id: NS, version: ownBefore.version, embedding: ownBefore.embedding, content: ownBefore.content });
    expect(ownAfter.updated_at.getTime()).toBeGreaterThan(ownBefore.updated_at.getTime());
    expect(await snapshot()).toBe(before);
    expect((await inactiveMemoryAdapter(db, { ...SCOPE, namespaceId: OTHER_NS }).listInactive()).total).toBe(2);
  }));

  it("treats foreign restore IDs as absent, preserves force gates and hides foreign successor IDs", async () => postgresFixture(async (db) => {
    const dir = directory();
    const idsFile = join(dir, "ids.json");
    writeFileSync(idsFile, JSON.stringify({ stage: "test", namespaceId: NS, ids: ["a-deleted", "a-archived", "a-link", "b-active", "b-deleted", "b-archived", "missing"] }));
    const adapter = inactiveMemoryAdapter(db, SCOPE), log = vi.fn();
    const deps = { ...adapter, log, outDir: dir, lockFile: join(dir, "restore.lock") };
    const opts = { stage: "test", namespaceId: NS, idsFile };
    const dry = await runRestore(opts, deps);
    expect(dry.planned).toEqual(["a-deleted"]);
    expect(dry.refusedArchived).toEqual(["a-archived", "a-link"]);
    expect(dry.alreadyActive).toEqual([]);
    expect(dry.notFound).toEqual(["b-active", "b-deleted", "b-archived", "missing"]);
    const listing = await runListInactive(opts, deps);
    expect(listing.rows.find((row) => row.id === "a-link").superseded_by).toBeNull();
    expect(JSON.stringify([listing, log.mock.calls])).not.toContain("foreign private marker");
    const forced = await runRestore({ ...opts, apply: true, force: true }, deps);
    expect(forced.restored).toEqual(["a-deleted", "a-archived", "a-link"]);
    const report = readFileSync(forced.logPath, "utf8");
    expect(report).not.toContain("b-active");
    expect(report).not.toContain("foreign private marker");
    expect(JSON.parse(report).entries.find((entry) => entry.id === "a-link").forced).toBe(true);
    expect((await db.query("SELECT state FROM memories WHERE id='b-archived'")).rows[0].state).toBe("archived");
  }));

  it("reauthorizes service membership and roles before reading or restoring rows", async () => postgresFixture(async (db) => {
    const adapter = inactiveMemoryAdapter(db, SCOPE);
    await db.query("UPDATE memory_namespace_memberships SET role='viewer' WHERE namespace_id=$1", [NS]);
    expect((await adapter.listInactive()).total).toBe(3);
    await expect(adapter.restoreMemory({ id: "a-deleted", priorState: "deleted", version: 7 })).rejects.toThrow(/denied/);
    await db.query("UPDATE memory_namespace_memberships SET status='revoked' WHERE namespace_id=$1", [NS]);
    await expect(adapter.findByIds(["a-deleted"])).rejects.toThrow(/denied/);
    await db.query("UPDATE memory_namespace_memberships SET status='active',role='member' WHERE namespace_id=$1", [NS]);
    await db.query("UPDATE memory_principals SET status='disabled' WHERE principal_id=$1", [PRINCIPAL]);
    await expect(adapter.listInactive()).rejects.toThrow(/denied/);
    expect((await db.query("SELECT state FROM memories WHERE id='a-deleted'")).rows[0].state).toBe("deleted");
  }));
});

function fixture() {
  const dir = directory();
  const rows = new Map([
    ["own", { id: "own", namespace_id: NS, content: "same fact", state: "active", version: 1 }],
    ["fragment", { id: "fragment", namespace_id: NS, content: "fragment fact", state: "active", version: 1 }],
    ["foreign", { id: "foreign", namespace_id: OTHER_NS, content: "same fact", state: "active", version: 1 }],
  ]);
  const requests = [];
  const fetchImpl = vi.fn(async (url, init = {}) => {
    const path = new URL(url).pathname;
    const method = init.method ?? "GET";
    requests.push({ path, method, body: init.body });
    const own = (id) => rows.get(id)?.namespace_id === NS ? rows.get(id) : undefined;
    const reply = (status, data) => new Response(JSON.stringify(data), { status });
    if (path.endsWith("/batch-delete")) {
      let deleted = 0;
      for (const id of JSON.parse(init.body).ids) {
        const row = own(id);
        if (row?.state === "active") { row.state = "deleted"; deleted++; }
      }
      return reply(200, { deleted });
    }
    if (path.endsWith("/memories")) {
      return reply(200, { memories: [...rows.values()].filter((row) => row.namespace_id === NS && row.state === "active") });
    }
    const row = own(decodeURIComponent(path.split("/").at(-1)));
    if (!row || row.state !== "active") return reply(404, {});
    if (method === "PUT") { row.content = JSON.parse(init.body).content; row.version++; }
    return reply(200, row);
  });
  const findByIds = vi.fn(async (ids) => ids.flatMap((id) => {
    const row = rows.get(id);
    return row?.namespace_id === NS ? [{ ...row }] : [];
  }));
  const opts = { stage: "test", namespaceId: NS, tenantId: "fixture", baseUrl: "http://fixture.invalid", apply: true };
  const deps = { fetchImpl, findByIds, log: vi.fn(), completeChat: vi.fn(), outDir: dir, lockFile: join(dir, "apply.lock") };
  return { dir, rows, requests, opts, deps };
}

describe("TC-GROUPNS-097: explicit maintenance namespace", () => {
  it.each([runCleanup, runListInactive, runRestore])("rejects a missing namespace before invoking dependencies", async (run) => {
    const io = vi.fn(() => { throw new Error("unexpected I/O"); });
    await expect(run({ stage: "test" }, { db: { query: io }, findByIds: io, listInactive: io, fetchImpl: io, discoverInstances: io, fs: new Proxy({}, { get: () => io }) })).rejects.toThrow(/namespace/i);
    expect(io).not.toHaveBeenCalled();
  });

  it("requires an explicit namespace for SQL adapters and mutexes", () => {
    const db = { query: vi.fn() };
    expect(() => inactiveMemoryAdapter(db)).toThrow(/namespace|scope/i);
    expect(() => sharedCleanupMutexKey("test")).toThrow(/namespace/i);
    expect(sharedCleanupMutexKey("test", NS)).not.toBe(sharedCleanupMutexKey("test", OTHER_NS));
    expect(db.query).not.toHaveBeenCalled();
  });

  it("accepts the namespace flag or environment, never an implicit all-namespace mode", () => {
    vi.stubEnv("MEM9_NAMESPACE_ID", "");
    expect(() => parseArgs(["--stage", "test"])).toThrow(/namespace/i);
    expect(parseArgs(["--stage", "test", "--namespace-id", NS]).namespaceId).toBe(NS);
    for (const value of ["all", "*", " ", `${NS},${OTHER_NS}`]) {
      expect(() => parseArgs(["--stage", "test", "--namespace-id", value])).toThrow(/namespace/i);
    }
    vi.stubEnv("MEM9_NAMESPACE_ID", NS);
    expect(parseArgs(["--stage", "test"]).namespaceId).toBe(NS);
    expect(parseArgs(["--help"]).help).toBe(true);
  });

  it.each([
    ["MEM9_CLEANUP_SCAN_ENABLED", "1"],
    ["MEM9_CLEANUP_SCHEDULED", "1"],
    ["MEM9_SLACK_APPROVAL_ENABLED", "1"],
    ["MEM9_SLACK_APPROVAL_CHANNEL", "fixture-channel"],
    ["MEM9_APPROVAL_HASH", "fixture-hash"],
    ["MEM9_REVIEW_ARTIFACT_KEY", "fixture-key"],
    ["MEM9_REVIEW_ARTIFACT_HASH", "fixture-hash"],
  ])("keeps production %s disabled before external I/O", async (key, value) => {
    vi.stubEnv(key, value);
    const io = vi.fn();
    await expect(createCleanupDeps({ stage: "test", namespaceId: NS }, { ssm: { send: io }, secrets: { send: io }, s3: { send: io }, Client: io })).rejects.toThrow(/disabled|unsupported/i);
    expect(io).not.toHaveBeenCalled();
  });
});

describe("TC-GROUPNS-098: foreign IDs and namespace-bound replay", () => {
  it("rejects mismatched namespace ID files before SQL, REST, or classification", async () => {
    const f = fixture();
    const path = join(f.dir, "ids.json");
    writeFileSync(path, JSON.stringify({ stage: "test", namespaceId: OTHER_NS, ids: ["foreign"] }));
    await expect(runCleanup({ ...f.opts, idsFile: path }, f.deps)).rejects.toThrow(/namespace/i);
    await expect(runRestore({ ...f.opts, idsFile: path }, f.deps)).rejects.toThrow(/namespace/i);
    expect(f.deps.findByIds).not.toHaveBeenCalled();
    expect(f.deps.fetchImpl).not.toHaveBeenCalled();
    expect(f.deps.completeChat).not.toHaveBeenCalled();
  });

  it("rejects an unbound or foreign decision envelope before row lookup", async () => {
    const f = fixture();
    const path = join(f.dir, "decisions.json");
    for (const namespaceId of [undefined, OTHER_NS]) {
      writeFileSync(path, JSON.stringify({ stage: "test", namespaceId, decisions: [] }));
      await expect(runCleanup({ ...f.opts, decisionsFile: path }, f.deps)).rejects.toThrow(/namespace/i);
    }
    expect(f.deps.findByIds).not.toHaveBeenCalled();
    expect(f.deps.fetchImpl).not.toHaveBeenCalled();
  });

  it("treats foreign and nonexistent decision IDs as absent without returning their payloads", async () => {
    const f = fixture();
    const path = join(f.dir, "decisions.json");
    const decisions = ["own", "foreign", "absent"].map((id) => ({ id, verdict: "DELETE", contentHash: contentHash("same fact"), snippet: id === "own" ? "own" : "private foreign payload" }));
    writeFileSync(path, JSON.stringify({ stage: "test", namespaceId: NS, decisions }));
    const result = await runCleanup({ ...f.opts, decisionsFile: path }, f.deps);
    expect(result.decisions.map((d) => d.id)).toEqual(["own"]);
    expect(f.rows.get("own").state).toBe("deleted");
    expect(f.rows.get("foreign").state).toBe("active");
    expect(JSON.stringify([result, f.deps.log.mock.calls])).not.toContain("private foreign payload");
    expect(f.requests.some((r) => r.path.endsWith("/foreign") || r.body?.includes("foreign"))).toBe(false);
    expect(f.deps.completeChat).not.toHaveBeenCalled();
  });

  it("rejects a merge containing any foreign ID before rewriting its own survivor", async () => {
    const f = fixture();
    const path = join(f.dir, "decisions.json");
    const decision = { id: "own", verdict: "MERGE", version: 1, contentHash: contentHash("same fact"), mergedContent: "mixed foreign text", mergedContentHash: contentHash("mixed foreign text"), absorbs: [{ id: "foreign", version: 1, contentHash: contentHash("same fact") }] };
    writeFileSync(path, JSON.stringify({ stage: "test", namespaceId: NS, decisions: [decision] }));
    const result = await runCleanup({ ...f.opts, decisionsFile: path }, f.deps);
    expect(result.decisions).toEqual([]);
    expect(result.writeCalls).toBe(0);
    expect(f.rows.get("own").content).toBe("same fact");
    expect(f.rows.get("foreign").state).toBe("active");
  });

  it("keeps same-namespace merge recovery valid when a fragment is already deleted", async () => {
    const f = fixture();
    f.rows.get("own").content = "merged fact";
    f.rows.get("own").version = 2;
    f.rows.get("fragment").state = "deleted";
    const path = join(f.dir, "decisions.json");
    const decision = { id: "own", verdict: "MERGE", version: 1, contentHash: contentHash("same fact"), mergedContent: "merged fact", mergedContentHash: contentHash("merged fact"), absorbs: [{ id: "fragment", version: 1, contentHash: contentHash("fragment fact") }] };
    writeFileSync(path, JSON.stringify({ stage: "test", namespaceId: NS, decisions: [decision] }));
    const result = await runCleanup({ ...f.opts, decisionsFile: path }, f.deps);
    expect(result.decisions).toHaveLength(1);
    expect(result.exitCode).toBe(0);
    expect(result.writeCalls).toBe(0);
  });

  it("writes generated decisions under the namespace and binds the envelope", async () => {
    const f = fixture();
    f.deps.completeChat.mockImplementation(async (_prompt, rows) => JSON.stringify({ verdicts: rows.map(({ id }) => ({ id, verdict: "KEEP", topic: "engineering", reason: "durable" })) }));
    const result = await runCleanup({ ...f.opts, apply: false }, f.deps);
    expect(result.decisionPath).toContain(NS);
    expect(JSON.parse(readFileSync(result.decisionPath, "utf8")).namespaceId).toBe(NS);
    expect(JSON.stringify(f.deps.completeChat.mock.calls)).not.toContain('"foreign"');
  });
});
