import { randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import pg from "pg";
import { describe, expect, it, vi } from "vitest";
import { serviceIdentity } from "../infra/gateway/service-auth.mjs";
import { createScopedDatabase } from "./lib/maintenance-scope.mjs";
import { lockNamespaceLifecycle } from "./lib/memory-ingest-cancellation.mjs";
import {
  initializeServiceMemberships,
  manageMemoryService,
} from "./manage-memory-services.mjs";
import {
  buildDigestOutcome,
  buildReviewTopic,
  createConsolidationDatabase,
  digestStateKey,
  runConsolidation,
} from "./memory-consolidation.mjs";

const execute = promisify(execFile);
const NOW = Date.parse("2026-09-01T00:00:00Z");
const VECTOR = JSON.stringify([1, 0.25, ...Array(1022).fill(0)]);

// Every test owns its clone and all sessions. The supplied database is used
// only as a template; no fixture DML or service operation runs against it.
async function withFixture(work) {
  const source = new URL(process.env.MEM9_NAMESPACE_TEST_DSN);
  const template = decodeURIComponent(source.pathname.slice(1));
  if (!template) throw new Error("PostgreSQL fixture template is required");
  source.pathname = "/postgres";
  const admin = new pg.Client({ connectionString: source.href });
  const name = `maintenance_${randomUUID().replaceAll("-", "")}`;
  const sessions = [];
  let created = false;
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE "${name}" TEMPLATE "${template.replaceAll('"', '""')}"`);
    created = true;
    source.pathname = `/${name}`;
    const connect = async () => {
      const db = new pg.Client({ connectionString: source.href, statement_timeout: 8000 });
      await db.connect();
      sessions.push(db);
      return db;
    };
    const db = await connect();
    const namespaces = { a: randomUUID(), b: randomUUID(), c: randomUUID() };
    for (const [label, id] of Object.entries(namespaces)) {
      await db.query(
        "INSERT INTO memory_namespaces(namespace_id,slug,display_name) VALUES($1,$2,$3)",
        [id, `maintenance-${id}`, `Synthetic namespace ${label}`],
      );
    }
    const scope = (namespaceId, service = "consolidation") =>
      Object.freeze({ ...serviceIdentity(service), stage: "pr-maintenance", namespaceId });
    const manage = (command, namespaceId, service = "consolidation") =>
      manageMemoryService({ db, command, binding: { namespace_id: namespaceId, service } });
    const principalId = async (service = "consolidation") => {
      const result = await db.query("SELECT principal_id FROM memory_principals WHERE principal_key=$1", [serviceIdentity(service).principalKey]);
      return result.rows[0]?.principal_id;
    };
    const initialize = async (ids, services) => {
      await db.query("BEGIN");
      try {
        await lockNamespaceLifecycle(db);
        await db.query(
          "SELECT namespace_id FROM memory_namespaces WHERE namespace_id=ANY($1::varchar[]) ORDER BY namespace_id FOR NO KEY UPDATE",
          [ids],
        );
        await initializeServiceMemberships(db, ids, services);
        await db.query("COMMIT");
      } catch (error) {
        await db.query("ROLLBACK");
        throw error;
      }
    };
    const row = async (id) => (await db.query(
      "SELECT *,embedding::text AS embedding FROM memories WHERE id=$1", [id],
    )).rows[0];
    const seed = async (namespaceId, label, time = "2024-01-01T00:00:00Z") => {
      const id = randomUUID();
      const actor = await principalId();
      await db.query(
        `INSERT INTO memories(id,namespace_id,content,embedding,memory_type,tags,metadata,version,
          created_at,updated_at,created_by_principal_id,updated_by_principal_id)
         VALUES($1,$2,$3,$4::vector,'insight','["existing"]','{"fixture":true}',1,$5,$5,$6,$6)`,
        [id, namespaceId, `Synthetic ${label}`, VECTOR, time, actor],
      );
      return row(id);
    };
    await work({ db, connect, namespaces, scope, manage, principalId, initialize, seed, row, dsn: source.href });
  } finally {
    const closed = await Promise.allSettled(sessions.map((db) => db.end()));
    try {
      if (created) await admin.query(`DROP DATABASE "${name}" WITH (FORCE)`);
    } finally {
      await admin.end();
    }
    const failedClose = closed.find((result) => result.status === "rejected");
    if (failedClose) throw failedClose.reason;
  }
}

function archive(loser, winner) {
  return { id: loser.id, supersededBy: winner.id, version: loser.version, content: loser.content,
    winnerVersion: winner.version, winnerContent: winner.content };
}

function stale(memory) {
  return { id: memory.id, version: memory.version, content: memory.content,
    tags: [...memory.tags, "stale"], metadata: { ...memory.metadata, consolidation: { stale: true } } };
}

function runnerDeps(database, completeChat) {
  return { ...database, completeChat, log: vi.fn(), emitMetrics: vi.fn(), clock: () => NOW };
}

async function waitForBlock(observer, pid) {
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    const result = await observer.query("SELECT cardinality(pg_blocking_pids($1::int)) AS blockers", [pid]);
    if (result.rows[0].blockers > 0) return;
    await delay(10);
  }
  throw new Error("expected lifecycle update to wait for the authorized transaction");
}

describe.skipIf(!process.env.MEM9_NAMESPACE_TEST_DSN)("maintenance with real PostgreSQL", () => {
  it("TC-GROUPNS-099: A/B scans and classifier inputs stay inside their namespace", async () =>
    withFixture(async ({ namespaces: ns, manage, seed, connect, scope, row }) => {
      await manage("enable", ns.a);
      await manage("enable", ns.b);
      const a = [await seed(ns.a, "A first"), await seed(ns.a, "A second")];
      const b = [await seed(ns.b, "B first"), await seed(ns.b, "B second")];
      const databaseA = createConsolidationDatabase(await connect(), scope(ns.a));
      const databaseB = createConsolidationDatabase(await connect(), scope(ns.b));
      for (const [database, expected] of [[databaseA, a], [databaseB, b]]) {
        expect((await database.listActiveMemories()).map(({ id }) => id).sort())
          .toEqual(expected.map(({ id }) => id).sort());
      }
      const classify = () => vi.fn(async (_prompt, memories) => JSON.stringify({
        actions: [{ type: "KEEP", ids: memories.map(({ id }) => id) }],
      }));
      const classifyA = classify(), classifyB = classify();
      const results = await Promise.all([
        runConsolidation({ stage: "pr-maintenance", namespaceId: ns.a }, runnerDeps(databaseA, classifyA)),
        runConsolidation({ stage: "pr-maintenance", namespaceId: ns.b }, runnerDeps(databaseB, classifyB)),
      ]);
      for (const [classifier, expected] of [[classifyA, a], [classifyB, b]]) {
        expect(classifier).toHaveBeenCalledOnce();
        expect(classifier.mock.calls[0][1].map(({ id }) => id).sort()).toEqual(expected.map(({ id }) => id).sort());
        expect(classifier.mock.calls[0][1].map(({ content }) => content).sort()).toEqual(expected.map(({ content }) => content).sort());
      }
      expect(results.map(({ exitCode, metrics }) => [exitCode, metrics.scanned])).toEqual([[0, 2], [0, 2]]);
      for (const original of [...a, ...b]) expect(await row(original.id)).toEqual(original);
    }), 30_000);

  it("TC-GROUPNS-099: archive fences both aliases and stale preserves embeddings and foreign rows", async () =>
    withFixture(async ({ db, namespaces: ns, manage, seed, connect, scope, row, principalId }) => {
      await manage("enable", ns.a);
      await manage("enable", ns.b);
      const loserA = await seed(ns.a, "A old"), winnerA = await seed(ns.a, "A new", "2025-01-01T00:00:00Z");
      const loserB = await seed(ns.b, "B old"), winnerB = await seed(ns.b, "B new", "2025-01-01T00:00:00Z");
      const inactiveB = [];
      for (const state of ["archived", "deleted"]) {
        const original = await seed(ns.b, `B inactive ${state}`);
        await db.query("UPDATE memories SET state=$2,metadata=$3 WHERE id=$1 AND namespace_id=$4", [
          original.id, state, JSON.stringify({ fixture: true, retention: { state, source: "synthetic fixture" } }), ns.b,
        ]);
        inactiveB.push(await row(original.id));
      }
      const database = createConsolidationDatabase(await connect(), scope(ns.a));
      expect(await database.archiveMemory(archive(loserA, winnerB))).toBe(false);
      expect(await database.archiveMemory(archive(loserB, winnerA))).toBe(false);
      expect(await database.archiveMemory(archive(loserB, winnerB))).toBe(false);
      expect(await database.markMemoryStale(stale(loserB))).toBe(false);
      for (const original of inactiveB) expect(await database.markMemoryStale(stale(original))).toBe(false);
      for (const original of [loserA, winnerA, loserB, winnerB, ...inactiveB]) expect(await row(original.id)).toEqual(original);
      expect(await database.archiveMemory(archive(loserA, winnerA))).toBe(true);
      expect(await row(loserA.id)).toMatchObject({ state: "archived", superseded_by: winnerA.id,
        version: loserA.version + 1, updated_by_principal_id: await principalId(), embedding: loserA.embedding });
      expect(await database.markMemoryStale(stale(winnerA))).toBe(true);
      expect(await row(winnerA.id)).toMatchObject({ state: "active", version: winnerA.version + 1,
        content: winnerA.content, embedding: winnerA.embedding, tags: ["existing", "stale"],
        metadata: { fixture: true, consolidation: { stale: true } }, updated_by_principal_id: await principalId() });
      expect(await database.markMemoryStale(stale(winnerA))).toBe(false);
      for (const original of [loserB, winnerB, ...inactiveB]) expect(await row(original.id)).toEqual(original);
    }), 30_000);

  it("TC-GROUPNS-100: A1/A2 exclude each other while B holds an independent session mutex", async () =>
    withFixture(async ({ namespaces: ns, manage, connect, scope }) => {
      await manage("enable", ns.a);
      await manage("enable", ns.b);
      const a1 = createConsolidationDatabase(await connect(), scope(ns.a));
      const a2 = createConsolidationDatabase(await connect(), scope(ns.a));
      const b = createConsolidationDatabase(await connect(), scope(ns.b));
      const first = await a1.acquireMutex();
      expect(first).not.toBeNull();
      try {
        expect(await a2.acquireMutex()).toBeNull();
        const independent = await b.acquireMutex();
        expect(independent).not.toBeNull();
        await independent.release();
      } finally { await first.release(); }
      const next = await a2.acquireMutex();
      expect(next).not.toBeNull();
      await next.release();
    }), 30_000);

  it("TC-GROUPNS-100: a real SQL apply failure releases A's mutex and leaves B usable", async () =>
    withFixture(async ({ db, namespaces: ns, manage, seed, connect, scope, row }) => {
      await manage("enable", ns.a);
      await manage("enable", ns.b);
      const loser = await seed(ns.a, "A old"), winner = await seed(ns.a, "A new", "2025-01-01T00:00:00Z");
      const foreign = await seed(ns.b, "B unaffected");
      await db.query("ALTER TABLE memories ADD CONSTRAINT maintenance_fixture_no_archive CHECK (state <> 'archived') NOT VALID");
      const a1 = createConsolidationDatabase(await connect(), scope(ns.a));
      const a2 = createConsolidationDatabase(await connect(), scope(ns.a));
      const b = createConsolidationDatabase(await connect(), scope(ns.b));
      const independent = await b.acquireMutex();
      expect(independent).not.toBeNull();
      try {
        const completeChat = vi.fn(async () => JSON.stringify({ actions: [{ type: "CONTRADICTION",
          ids: [loser.id, winner.id], winner_id: winner.id, rationale: "synthetic replacement" }] }));
        const result = await runConsolidation({ stage: "pr-maintenance", namespaceId: ns.a, reportOnly: false }, runnerDeps(a1, completeChat));
        expect(result.exitCode).toBe(1);
        expect(result.mutations).toBe(0);
        expect(result.review).toContainEqual(expect.objectContaining({ kind: "APPLY_FAILED" }));
        expect(await row(loser.id)).toEqual(loser);
        const recovered = await a2.acquireMutex();
        expect(recovered).not.toBeNull();
        await recovered.release();
        expect(await b.markMemoryStale(stale(foreign))).toBe(true);
        expect((await row(foreign.id)).embedding).toBe(foreign.embedding);
      } finally { await independent.release(); }
    }), 30_000);

  it.each(["read", "write"])(
    "TC-GROUPNS-100: concurrent runs isolate a real digest %s failure and retain confirmed mutations",
    async (failure) => withFixture(async ({ db, namespaces: ns, manage, seed, connect, scope, row }) => {
      await manage("enable", ns.a);
      await manage("enable", ns.b);
      // PostgreSQL stands in for conditional object storage here, allowing real
      // persistence failures without AWS. Run/classify/mutate/refresh/digest
      // orchestration and namespace authorization are the production functions.
      await db.query(`CREATE TABLE maintenance_fixture_digests (
        namespace_id varchar(36) PRIMARY KEY, object_key text UNIQUE NOT NULL,
        state jsonb NOT NULL, version integer NOT NULL DEFAULT 1,
        block_write boolean NOT NULL DEFAULT false,
        CHECK (NOT block_write OR version = 1))`);
      const fixtures = [];
      for (const namespaceId of [ns.a, ns.b]) {
        const loser = await seed(namespaceId, "digest old");
        const winner = await seed(namespaceId, "digest new", "2025-01-01T00:00:00Z");
        const review = await seed(namespaceId, "digest review");
        const identity = scope(namespaceId);
        const key = digestStateKey(identity.stage, namespaceId);
        const initial = buildDigestOutcome({
          stage: identity.stage, namespaceId, now: NOW - 1,
          review: [{ kind: namespaceId === ns.a ? "APPLY_FAILED" : "LOCK_HELD", ids: [] }],
          byId: new Map(), mutations: 0, attemptedClusters: 0, classificationFailures: 0,
          metrics: { scanned: 0, merged: 0, archived: 0, flaggedStale: 0, reviewItems: 1, skippedLww: 0 },
        }).nextState;
        await db.query(
          "INSERT INTO maintenance_fixture_digests(namespace_id,object_key,state,block_write) VALUES($1,$2,$3,$4)",
          [namespaceId, key, JSON.stringify(initial), namespaceId === ns.a && failure === "write"],
        );
        const database = createConsolidationDatabase(await connect(), identity);
        const digestDatabase = createScopedDatabase(await connect(), identity);
        const completeChat = vi.fn(async () => JSON.stringify({ actions: [
          { type: "CONTRADICTION", ids: [loser.id, winner.id], winner_id: winner.id, rationale: "synthetic replacement" },
          { type: "DELETE", ids: [review.id], rationale: "synthetic review" },
        ] }));
        const adapters = {
          ...runnerDeps(database, completeChat),
          loadDigestState: () => digestDatabase.read(async (tx, actor) => {
            if (actor.namespaceId === ns.a && failure === "read") await tx.query("SELECT 1 / 0");
            const result = await tx.query(
              "SELECT state,version FROM maintenance_fixture_digests WHERE namespace_id=$1 AND object_key=$2",
              [actor.namespaceId, key],
            );
            return { status: "ok", state: result.rows[0].state, etag: String(result.rows[0].version) };
          }),
          writeDigestState: ({ state, etag }) => digestDatabase.write(async (tx, actor) => {
            expect(state.namespaceId).toBe(actor.namespaceId);
            if (etag === undefined) {
              // The degraded read path may only conditionally create. An
              // existing row rejects this without replacing its prior state.
              await tx.query("INSERT INTO maintenance_fixture_digests(namespace_id,object_key,state) VALUES($1,$2,$3)",
                [actor.namespaceId, key, JSON.stringify(state)]);
            } else {
              const changed = await tx.query(
                "UPDATE maintenance_fixture_digests SET state=$3,version=version+1 WHERE namespace_id=$1 AND object_key=$2 AND version=$4",
                [actor.namespaceId, key, JSON.stringify(state), Number(etag)],
              );
              expect(changed.rowCount).toBe(1);
            }
          }),
        };
        fixtures.push({ namespaceId, key, initial, loser, winner, review, adapters });
      }
      const [a, b] = await Promise.all(fixtures.map(({ namespaceId, adapters }) => runConsolidation({
        stage: "pr-maintenance", namespaceId, reportOnly: false, scheduled: true,
      }, adapters)));
      expect(a.exitCode).toBe(1);
      expect(b.exitCode).toBe(0);
      expect(a.metrics.dedupUnavailable).toBe(failure === "read" ? 1 : 0);
      expect(b.metrics.dedupUnavailable).toBe(0);
      expect([a.mutations, b.mutations]).toEqual([1, 1]);
      const states = (await db.query("SELECT namespace_id,object_key,state,version FROM maintenance_fixture_digests")).rows;
      const savedA = states.find(({ namespace_id }) => namespace_id === ns.a);
      const savedB = states.find(({ namespace_id }) => namespace_id === ns.b);
      expect(savedA.state).toEqual(fixtures[0].initial);
      expect(savedA.version).toBe(1);
      expect(savedB.version).toBe(2);
      expect(savedA.object_key).not.toBe(savedB.object_key);
      expect(savedB.state).toMatchObject({ namespaceId: ns.b, kindCounts: { DELETE: 1 } });
      expect(savedB.state.kindCounts).not.toHaveProperty("APPLY_FAILED");
      const expectedTopic = buildReviewTopic({ kind: "DELETE", ids: [fixtures[1].review.id] },
        new Map([[fixtures[1].review.id, fixtures[1].review]]), ns.b);
      expect(savedB.state.topics).toEqual([expect.objectContaining({ topicId: expectedTopic.topicId, payloadHash: expectedTopic.payloadHash })]);
      for (const fixture of fixtures) {
        expect(await row(fixture.loser.id)).toMatchObject({ state: "archived", superseded_by: fixture.winner.id });
        expect(await row(fixture.review.id)).toEqual(fixture.review);
        const retry = createConsolidationDatabase(await connect(), scope(fixture.namespaceId));
        const mutex = await retry.acquireMutex();
        expect(mutex).not.toBeNull();
        await mutex.release();
      }
    }), 30_000,
  );

  it("TC-GROUPNS-099/105: a phase downgrade blocks reads and writes before namespace or model access", async () =>
    withFixture(async ({ db, namespaces: ns, manage, seed, connect, scope, row }) => {
      await manage("enable", ns.a);
      const own = await seed(ns.a, "phase enforcement fixture");
      const client = await connect();
      const database = createConsolidationDatabase(client, scope(ns.a));
      expect(await database.listActiveMemories()).toHaveLength(1);
      const changed = await db.query(
        "UPDATE memory_namespace_migration_state SET phase='application_ready' WHERE singleton_id RETURNING phase",
      );
      expect(changed.rows).toEqual([{ phase: "application_ready" }]);
      const queries = vi.spyOn(client, "query");
      try {
        await expect(database.listActiveMemories()).rejects.toThrow(/requires namespace enforcement/);
        await expect(database.markMemoryStale(stale(own))).rejects.toThrow(/requires namespace enforcement/);
        const completeChat = vi.fn();
        await expect(runConsolidation({ stage: "pr-maintenance", namespaceId: ns.a, checkLlm: true },
          runnerDeps(database, completeChat))).rejects.toThrow(/requires namespace enforcement/);
        expect(completeChat).not.toHaveBeenCalled();
        expect(queries.mock.calls.some(([sql]) =>
          /FROM (memory_namespaces|memory_principals|memory_namespace_memberships|memories)\b/u.test(sql),
        )).toBe(false);
        expect(queries.mock.calls.at(-1)[0]).toBe("ROLLBACK");
        expect(await row(own.id)).toEqual(own);
      } finally { queries.mockRestore(); }
    }), 30_000);

  it.each(["namespace", "principal", "membership", "missing-membership"])(
    "TC-GROUPNS-099/105: actual SQL authorization refuses revoked %s without content/model work",
    async (revocation) => withFixture(async ({ db, namespaces: ns, manage, seed, connect, scope, row, principalId }) => {
      await manage("enable", ns.a);
      await manage("enable", ns.b);
      const own = await seed(ns.a, "A authorization"), winner = await seed(ns.a, "A authorization winner", "2025-01-01T00:00:00Z");
      const foreign = await seed(ns.b, "B authorization");
      const a = createConsolidationDatabase(await connect(), scope(ns.a));
      const b = createConsolidationDatabase(await connect(), scope(ns.b));
      const scoped = createScopedDatabase(await connect(), scope(ns.a));
      await a.authorize(true);
      expect(await a.listActiveMemories()).toHaveLength(2);
      const actor = await principalId();
      if (revocation === "namespace") await db.query("UPDATE memory_namespaces SET status='disabled' WHERE namespace_id=$1", [ns.a]);
      if (revocation === "principal") await db.query("UPDATE memory_principals SET status='disabled' WHERE principal_id=$1", [actor]);
      if (revocation === "membership") await db.query("UPDATE memory_namespace_memberships SET status='revoked' WHERE namespace_id=$1 AND principal_id=$2", [ns.a, actor]);
      if (revocation === "missing-membership") await db.query("DELETE FROM memory_namespace_memberships WHERE namespace_id=$1 AND principal_id=$2", [ns.a, actor]);
      await expect(a.listActiveMemories()).rejects.toThrow(/denied/);
      await expect(a.markMemoryStale(stale(own))).rejects.toThrow(/denied/);
      await expect(a.archiveMemory(archive(own, winner))).rejects.toThrow(/denied/);
      const mutation = vi.fn(async (tx, authorized) => tx.query(
        "UPDATE memories SET version=version+1 WHERE id=$1 AND namespace_id=$2", [own.id, authorized.namespaceId],
      ));
      await expect(scoped.write(mutation)).rejects.toThrow(/denied/);
      expect(mutation).not.toHaveBeenCalled();
      const completeChat = vi.fn();
      await expect(runConsolidation({ stage: "pr-maintenance", namespaceId: ns.a }, runnerDeps(a, completeChat))).rejects.toThrow(/denied/);
      expect(completeChat).not.toHaveBeenCalled();
      if (revocation === "principal") await expect(b.authorize()).rejects.toThrow(/service denied/);
      else expect((await b.listActiveMemories()).map(({ id }) => id)).toEqual([foreign.id]);
      if (revocation === "missing-membership") expect((await db.query(
        "SELECT count(*)::int AS total FROM memory_namespace_memberships WHERE namespace_id=$1 AND principal_id=$2", [ns.a, actor],
      )).rows[0].total).toBe(0);
      expect(await row(own.id)).toEqual(own);
      expect(await row(winner.id)).toEqual(winner);
      expect(await row(foreign.id)).toEqual(foreign);
    }), 30_000,
  );

  it.each(["namespace", "principal", "membership"])(
    "TC-GROUPNS-105: an authorized transaction retains its %s lock until completion",
    async (target) => withFixture(async ({ db, namespaces: ns, manage, seed, connect, scope, principalId }) => {
      await manage("enable", ns.a);
      const own = await seed(ns.a, "held authorization");
      const worker = await connect(), revoker = await connect();
      const scoped = createScopedDatabase(worker, scope(ns.a));
      const actor = await principalId();
      const pid = (await revoker.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
      const entered = Promise.withResolvers(), release = Promise.withResolvers();
      const operation = scoped.write(async (tx, authorized) => {
        entered.resolve();
        await release.promise;
        return tx.query("UPDATE memories SET version=version+1,updated_by_principal_id=$3 WHERE id=$1 AND namespace_id=$2", [own.id, authorized.namespaceId, authorized.principalId]);
      });
      let revocation;
      try {
        await Promise.race([entered.promise, operation]);
        if (target === "namespace") revocation = revoker.query("UPDATE memory_namespaces SET status='disabled' WHERE namespace_id=$1", [ns.a]);
        if (target === "principal") revocation = revoker.query("UPDATE memory_principals SET status='disabled' WHERE principal_id=$1", [actor]);
        if (target === "membership") revocation = revoker.query("UPDATE memory_namespace_memberships SET status='revoked' WHERE namespace_id=$1 AND principal_id=$2", [ns.a, actor]);
        // Attach a handler immediately while observing PostgreSQL's lock wait.
        revocation.catch(() => {});
        await waitForBlock(db, pid);
        release.resolve();
        expect((await operation).rowCount).toBe(1);
        await revocation;
        await expect(scoped.authorize()).rejects.toThrow(/denied/);
      } finally {
        release.resolve();
        await Promise.allSettled([operation, revocation]);
      }
    }), 30_000,
  );

  it("TC-GROUPNS-105: downgrade after scanning preserves reads but prevents audited writes", async () =>
    withFixture(async ({ db, namespaces: ns, manage, seed, connect, scope, row, principalId }) => {
      await manage("enable", ns.a);
      const own = await seed(ns.a, "viewer fixture"), winner = await seed(ns.a, "viewer winner", "2025-01-01T00:00:00Z");
      const database = createConsolidationDatabase(await connect(), scope(ns.a));
      expect(await database.listActiveMemories()).toHaveLength(2);
      await db.query("UPDATE memory_namespace_memberships SET role='viewer' WHERE namespace_id=$1 AND principal_id=$2", [ns.a, await principalId()]);
      expect(await database.listActiveMemories()).toHaveLength(2);
      await expect(database.markMemoryStale(stale(own))).rejects.toThrow(/membership denied/);
      await expect(database.archiveMemory(archive(own, winner))).rejects.toThrow(/membership denied/);
      expect(await row(own.id)).toEqual(own);
      expect(await row(winner.id)).toEqual(winner);
    }), 30_000);

  it("TC-GROUPNS-105: real service CLI enable/disable/show preserves B when disabling A", async () =>
    withFixture(async ({ db, namespaces: ns, dsn }) => {
      const directory = await mkdtemp(join(tmpdir(), "mem9-maintenance-cli-"));
      const files = new Map();
      try {
        for (const id of [ns.a, ns.b]) {
          const path = join(directory, `${id}.local.json`);
          await writeFile(path, JSON.stringify({ namespace_id: id, service: "consolidation" }), { mode: 0o600 });
          files.set(id, path);
        }
        const cli = async (command, id) => {
          const result = await execute(process.execPath,
            [resolve(import.meta.dirname, "manage-memory-services.mjs"), command, "--config", files.get(id)],
            { env: { ...process.env, MNEMO_DSN: dsn }, timeout: 10_000, maxBuffer: 64 * 1024 });
          expect(result.stderr).toBe("");
          return JSON.parse(result.stdout);
        };
        const count = async () => (await db.query("SELECT count(*)::int AS count FROM memory_principals")).rows[0].count;
        const before = await count();
        expect(await cli("show", ns.a)).toMatchObject({ namespace_status: "active" });
        expect(await count()).toBe(before);
        expect(await cli("enable", ns.a)).toEqual({ status: "enabled" });
        expect(await cli("enable", ns.b)).toEqual({ status: "enabled" });
        expect(await cli("disable", ns.a)).toEqual({ status: "disabled" });
        expect(await cli("show", ns.a)).toMatchObject({ principal_status: "active", membership_status: "revoked", role: "member" });
        expect(await cli("show", ns.b)).toMatchObject({ principal_status: "active", membership_status: "active", role: "member" });
        expect(await cli("enable", ns.a)).toEqual({ status: "enabled" });
        expect(await cli("show", ns.a)).toMatchObject({ membership_status: "active" });
      } finally { await rm(directory, { recursive: true, force: true }); }
    }), 30_000);

  it("TC-GROUPNS-105: initialization preserves revoked memberships and uses viewer sampler grants", async () =>
    withFixture(async ({ db, namespaces: ns, manage, initialize, principalId }) => {
      await manage("enable", ns.a);
      await manage("enable", ns.b);
      await manage("disable", ns.a);
      await initialize([ns.a, ns.b], ["consolidation"]);
      expect(await manage("show", ns.a)).toMatchObject({ membership_status: "revoked" });
      expect(await manage("show", ns.b)).toMatchObject({ membership_status: "active" });
      await initialize([ns.a, ns.b]);
      const sampler = await principalId("sampler");
      const memberships = async () => (await db.query(
        "SELECT namespace_id,role,status,source_type FROM memory_namespace_memberships WHERE principal_id=$1 AND namespace_id=ANY($2::varchar[]) ORDER BY namespace_id",
        [sampler, [ns.a, ns.b]],
      )).rows;
      expect(await memberships()).toEqual([ns.a, ns.b].sort().map((namespace_id) => ({ namespace_id, role: "viewer", status: "active", source_type: "service" })));
      await db.query("UPDATE memory_namespace_memberships SET status='revoked' WHERE namespace_id=$1 AND principal_id=$2", [ns.a, sampler]);
      await initialize([ns.a, ns.b]);
      expect((await memberships()).find(({ namespace_id }) => namespace_id === ns.a).status).toBe("revoked");
    }), 30_000);

  it("TC-GROUPNS-105: global service disable survives enable attempts and initialization", async () =>
    withFixture(async ({ db, namespaces: ns, manage, initialize, principalId, connect, scope }) => {
      await manage("enable", ns.a);
      await manage("enable", ns.b);
      await manage("disable", ns.a);
      const actor = await principalId();
      await db.query("UPDATE memory_principals SET status='disabled' WHERE principal_id=$1", [actor]);
      await expect(manage("enable", ns.a)).rejects.toThrow(/disabled/);
      await initialize([ns.a, ns.b, ns.c], ["consolidation"]);
      expect(await manage("show", ns.a)).toMatchObject({ principal_status: "disabled", membership_status: "revoked" });
      expect(await manage("show", ns.b)).toMatchObject({ principal_status: "disabled", membership_status: "active" });
      expect(await manage("show", ns.c)).toMatchObject({ principal_status: "disabled", membership_status: null });
      const database = createConsolidationDatabase(await connect(), scope(ns.b));
      await expect(database.authorize()).rejects.toThrow(/service denied/);
    }), 30_000);
});
