// Unit tests for scripts/memory-cleanup.mjs (issue #102).
// Test IDs map to docs/test-cases/memory-cleanup.md. All I/O is faked through
// the injected deps object — no network, no real filesystem outside tmpdirs.
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  contentHash,
  parseVerdicts,
  planDecisions,
  runCleanup,
  DURABLE_ONLY_RULES,
} from "./memory-cleanup.mjs";

const tempDirs = [];
function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), "memclean-"));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

const TENANT = "tenant-key-0123456789abcdef";

function memory(id, content, version = 1) {
  return { id, content, version, state: "active", memory_type: "insight" };
}

/**
 * Fake mem9 REST server over an in-memory store.
 * Records every request; mutates the store like the probed upstream:
 *  - GET  /memories?limit&offset — pages active memories
 *  - GET  /memories/{id}         — single read (re-read guard)
 *  - PUT  /memories/{id}         — LWW update, bumps version
 *  - POST /memories/batch-delete — soft delete, skips already-deleted
 */
function fakeServer(initial) {
  const store = new Map(initial.map((m) => [m.id, { ...m }]));
  const calls = [];
  const fetchImpl = vi.fn(async (url, opts = {}) => {
    const method = (opts.method || "GET").toUpperCase();
    const u = new URL(url);
    calls.push({ method, path: u.pathname, search: u.search, body: opts.body });
    const json = (status, body) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

    if (method === "POST" && u.pathname.endsWith("/memories/batch-delete")) {
      const { ids } = JSON.parse(opts.body);
      if (!Array.isArray(ids) || ids.length === 0) return json(400, { error: "ids required" });
      if (ids.length > 1000) return json(400, { error: "too many (max 1000)" });
      let affected = 0;
      for (const id of ids) {
        const m = store.get(id);
        if (m && m.state !== "deleted") {
          m.state = "deleted";
          affected += 1;
        }
      }
      return json(200, { deleted: affected });
    }
    const single = u.pathname.match(/\/memories\/([^/]+)$/);
    if (single && method === "GET") {
      const m = store.get(single[1]);
      return m ? json(200, m) : json(404, { error: "not found" });
    }
    if (single && method === "PUT") {
      const m = store.get(single[1]);
      if (!m) return json(404, { error: "not found" });
      const body = JSON.parse(opts.body);
      // LWW: version mismatch is only a server-side warning upstream.
      if (body.content) m.content = body.content;
      m.version += 1;
      return json(200, m);
    }
    if (method === "GET" && u.pathname.endsWith("/memories")) {
      const limit = Number(u.searchParams.get("limit") || 200);
      const offset = Number(u.searchParams.get("offset") || 0);
      const active = [...store.values()].filter((m) => m.state === "active");
      return json(200, { memories: active.slice(offset, offset + limit), total: active.length });
    }
    return json(404, { error: `unhandled ${method} ${u.pathname}` });
  });
  return { store, calls, fetchImpl };
}

/** LLM fake: verdictsByBatch is an array of responses (JSON string or object) per call. */
function fakeLlm(verdictsByBatch) {
  let call = 0;
  return vi.fn(async () => {
    const v = verdictsByBatch[Math.min(call, verdictsByBatch.length - 1)];
    call += 1;
    return typeof v === "string" ? v : JSON.stringify({ verdicts: v });
  });
}

function baseDeps(server, llm, dir) {
  return {
    fetchImpl: server.fetchImpl,
    completeChat: llm,
    log: vi.fn(),
    outDir: dir,
    lockFile: join(dir, "test.lock"),
    clock: () => new Date("2026-07-31T00:00:00Z").getTime(),
  };
}

function baseOpts(overrides = {}) {
  return {
    stage: "test",
    baseUrl: "http://mnemo.test.local:8080",
    tenantId: TENANT,
    apply: false,
    cap: 50,
    ...overrides,
  };
}

const keepAll = (memories) => memories.map((m) => ({ id: m.id, verdict: "KEEP", reason: "durable" }));

describe("scan & pagination", () => {
  it("TC-MEMCLEAN-001 pages through windows and sees every memory once", async () => {
    const memories = Array.from({ length: 450 }, (_, i) => memory(`m-${i}`, `fact ${i}`));
    const server = fakeServer(memories);
    const llm = fakeLlm([]);
    llm.mockImplementation(async (_p, batch) => JSON.stringify({ verdicts: keepAll(batch) }));
    const result = await runCleanup(baseOpts(), baseDeps(server, llm, tempDir()));
    expect(result.decisions).toHaveLength(450);
    expect(new Set(result.decisions.map((d) => d.id)).size).toBe(450);
    const pageCalls = server.calls.filter((c) => c.method === "GET" && !c.path.match(/memories\/./));
    expect(pageCalls.length).toBeGreaterThanOrEqual(3); // 200 + 200 + 50
  });

  it("TC-MEMCLEAN-002 empty store → empty decisions, zero writes", async () => {
    const server = fakeServer([]);
    const result = await runCleanup(baseOpts(), baseDeps(server, fakeLlm([]), tempDir()));
    expect(result.decisions).toHaveLength(0);
    expect(result.writeCalls).toBe(0);
    expect(result.exitCode).toBe(0);
  });
});

describe("classification", () => {
  it("TC-MEMCLEAN-010 verdicts map 1:1 with snapshots; MERGE carries merged content", async () => {
    const m1 = memory("keep-1", "durable fact");
    const m2 = memory("del-1", "session noise");
    const m3 = memory("surv-1", "fragment a", 2);
    const m4 = memory("abs-1", "fragment b");
    const server = fakeServer([m1, m2, m3, m4]);
    const llm = fakeLlm([
      [
        { id: "keep-1", verdict: "KEEP", reason: "durable" },
        { id: "del-1", verdict: "DELETE", reason: "session-state" },
        { id: "surv-1", verdict: "MERGE", reason: "fragments", merge_into: "surv-1", absorbs: ["abs-1"], merged_content: "fragment a + b" },
        { id: "abs-1", verdict: "MERGE", reason: "fragments", merge_into: "surv-1" },
      ],
    ]);
    const result = await runCleanup(baseOpts(), baseDeps(server, llm, tempDir()));
    const byId = Object.fromEntries(result.decisions.map((d) => [d.id, d]));
    expect(byId["keep-1"].verdict).toBe("KEEP");
    expect(byId["del-1"]).toMatchObject({
      verdict: "DELETE",
      version: 1,
      contentHash: contentHash("session noise"),
    });
    expect(byId["surv-1"]).toMatchObject({
      verdict: "MERGE",
      mergedContent: "fragment a + b",
      mergedContentHash: contentHash("fragment a + b"),
    });
    expect(byId["surv-1"].absorbs).toEqual([
      { id: "abs-1", version: 1, contentHash: contentHash("fragment b") },
    ]);
    // The absorbed member itself is folded into the survivor's decision.
    expect(byId["abs-1"]).toBeUndefined();
  });

  it("TC-MEMCLEAN-011 malformed JSON retries once then batch-SKIPs, never destructive", async () => {
    const server = fakeServer([memory("m-1", "x"), memory("m-2", "y")]);
    const llm = fakeLlm(["not json", "still not json"]);
    const result = await runCleanup(baseOpts({ apply: true }), baseDeps(server, llm, tempDir()));
    expect(llm).toHaveBeenCalledTimes(2);
    expect(result.decisions.every((d) => d.verdict === "SKIP")).toBe(true);
    expect(result.capUsed).toBe(0);
    expect(server.calls.filter((c) => c.method !== "GET")).toHaveLength(0);
  });

  it("TC-MEMCLEAN-012 verdict for an id outside the batch is discarded", async () => {
    const server = fakeServer([memory("m-1", "x")]);
    const llm = fakeLlm([
      [
        { id: "m-1", verdict: "KEEP", reason: "ok" },
        { id: "ghost-9", verdict: "DELETE", reason: "hallucinated" },
      ],
    ]);
    const deps = baseDeps(server, llm, tempDir());
    const result = await runCleanup(baseOpts(), deps);
    expect(result.decisions.map((d) => d.id)).toEqual(["m-1"]);
    expect(deps.log).toHaveBeenCalledWith(expect.stringContaining("ghost-9"));
  });

  it("TC-MEMCLEAN-013 prompt embeds the D1-D4 durability rules from patch 0002", () => {
    const patch = readFileSync(
      join(import.meta.dirname, "..", "docker", "mnemo-server", "patches", "0002-ingest-durable-only-extraction-filter.patch"),
      "utf8",
    );
    const patchBody = patch
      .split("\n")
      .filter((l) => l.startsWith("+"))
      .map((l) => l.slice(1))
      .join("\n");
    for (const rule of ["D1.", "D2.", "D3.", "D4."]) {
      expect(DURABLE_ONLY_RULES).toContain(rule);
    }
    // Every non-empty line of our embedded copy must exist verbatim in the patch.
    for (const line of DURABLE_ONLY_RULES.split("\n").map((l) => l.trim()).filter(Boolean)) {
      expect(patchBody).toContain(line);
    }
  });
});

describe("dry-run", () => {
  it("TC-MEMCLEAN-020 zero write calls; writeCalls counter is 0", async () => {
    const server = fakeServer([memory("m-1", "x"), memory("m-2", "y")]);
    const llm = fakeLlm([
      [
        { id: "m-1", verdict: "DELETE", reason: "noise" },
        { id: "m-2", verdict: "DELETE", reason: "noise" },
      ],
    ]);
    const result = await runCleanup(baseOpts({ apply: false }), baseDeps(server, llm, tempDir()));
    expect(result.writeCalls).toBe(0);
    expect(server.calls.every((c) => c.method === "GET")).toBe(true);
    expect(server.store.get("m-1").state).toBe("active");
  });

  it("TC-MEMCLEAN-021 decision log has id/verdict/reason for every memory; path printed", async () => {
    const dir = tempDir();
    const server = fakeServer([memory("m-1", "x")]);
    const llm = fakeLlm([[{ id: "m-1", verdict: "KEEP", reason: "durable" }]]);
    const deps = baseDeps(server, llm, dir);
    const result = await runCleanup(baseOpts(), deps);
    const logged = JSON.parse(readFileSync(result.decisionPath, "utf8"));
    expect(logged.decisions).toHaveLength(1);
    expect(logged.decisions[0]).toMatchObject({ id: "m-1", verdict: "KEEP", reason: "durable" });
    expect(result.decisionPath.startsWith(dir)).toBe(true);
    expect(deps.log).toHaveBeenCalledWith(expect.stringContaining(result.decisionPath));
  });
});

describe("apply, cap, --ids", () => {
  it("TC-MEMCLEAN-030 DELETE via batch-delete; MERGE via PUT-then-delete", async () => {
    const server = fakeServer([
      memory("del-1", "noise"),
      memory("surv-1", "frag a"),
      memory("abs-1", "frag b"),
    ]);
    const llm = fakeLlm([
      [
        { id: "del-1", verdict: "DELETE", reason: "noise" },
        { id: "surv-1", verdict: "MERGE", reason: "frags", merge_into: "surv-1", absorbs: ["abs-1"], merged_content: "frag a+b" },
      ],
    ]);
    const result = await runCleanup(baseOpts({ apply: true }), baseDeps(server, llm, tempDir()));
    expect(server.store.get("del-1").state).toBe("deleted");
    expect(server.store.get("abs-1").state).toBe("deleted");
    expect(server.store.get("surv-1")).toMatchObject({ content: "frag a+b", state: "active" });
    const mutations = server.calls.filter((c) => c.method !== "GET");
    const putIdx = mutations.findIndex((c) => c.method === "PUT");
    const delAfterPut = mutations.slice(putIdx + 1).some(
      (c) => c.method === "POST" && c.body.includes("abs-1"),
    );
    expect(putIdx).toBeGreaterThanOrEqual(0);
    expect(delAfterPut).toBe(true);
    expect(result.capUsed).toBe(3); // DELETE(1) + MERGE PUT(1) + absorbed(1)
    expect(result.writeCalls).toBeGreaterThan(0);
  });

  it("TC-MEMCLEAN-031 cap reservation aborts before the overflowing decision's PUT; exact hit allowed", async () => {
    // cap=5, two MERGEs each costing 3 (PUT + 2 absorbed): second must not start.
    const mems = [
      memory("s1", "a"), memory("a1", "b"), memory("a2", "c"),
      memory("s2", "d"), memory("a3", "e"), memory("a4", "f"),
    ];
    const server = fakeServer(mems);
    const llm = fakeLlm([
      [
        { id: "s1", verdict: "MERGE", reason: "r", merge_into: "s1", absorbs: ["a1", "a2"], merged_content: "abc" },
        { id: "s2", verdict: "MERGE", reason: "r", merge_into: "s2", absorbs: ["a3", "a4"], merged_content: "def" },
      ],
    ]);
    const result = await runCleanup(baseOpts({ apply: true, cap: 5 }), baseDeps(server, llm, tempDir()));
    expect(result.exitCode).not.toBe(0);
    expect(result.capUsed).toBe(3);
    expect(server.store.get("s2").content).toBe("d"); // second MERGE never PUT
    expect(server.store.get("a3").state).toBe("active");

    // Exact hit: cap=6 lets both run to completion.
    const server2 = fakeServer(mems.map((m) => ({ ...m })));
    const result2 = await runCleanup(
      baseOpts({ apply: true, cap: 6 }),
      baseDeps(server2, fakeLlm([
        [
          { id: "s1", verdict: "MERGE", reason: "r", merge_into: "s1", absorbs: ["a1", "a2"], merged_content: "abc" },
          { id: "s2", verdict: "MERGE", reason: "r", merge_into: "s2", absorbs: ["a3", "a4"], merged_content: "def" },
        ],
      ]), tempDir()),
    );
    expect(result2.exitCode).toBe(0);
    expect(result2.capUsed).toBe(6);
  });

  it("TC-MEMCLEAN-032 --ids applies only listed decisions", async () => {
    const dir = tempDir();
    const server = fakeServer([memory("d1", "x"), memory("d2", "y")]);
    const llm = fakeLlm([
      [
        { id: "d1", verdict: "DELETE", reason: "noise" },
        { id: "d2", verdict: "DELETE", reason: "noise" },
      ],
    ]);
    const idsFile = join(dir, "approved.txt");
    writeFileSync(idsFile, "d1\n");
    const result = await runCleanup(baseOpts({ apply: true, idsFile }), baseDeps(server, llm, dir));
    expect(server.store.get("d1").state).toBe("deleted");
    expect(server.store.get("d2").state).toBe("active");
    expect(result.skippedByFilter).toBe(1);
  });

  it("TC-MEMCLEAN-033 MERGE recovery is hash-anchored (three-way)", async () => {
    const dir = tempDir();
    const decisions = {
      stage: "test",
      generatedAt: "2026-07-31T00:00:00Z",
      decisions: [{
        id: "surv-1", verdict: "MERGE", reason: "frags",
        version: 1, contentHash: contentHash("frag a"),
        mergedContent: "frag a+b", mergedContentHash: contentHash("frag a+b"),
        absorbs: [{ id: "abs-1", version: 1, contentHash: contentHash("frag b") }],
      }],
    };
    const decisionsFile = join(dir, "decisions.json");
    writeFileSync(decisionsFile, JSON.stringify(decisions));

    // Branch 1: survivor at original hash → PUT happens, then delete.
    const s1 = fakeServer([memory("surv-1", "frag a"), memory("abs-1", "frag b")]);
    const r1 = await runCleanup(
      baseOpts({ apply: true, decisionsFile }),
      baseDeps(s1, fakeLlm([]), dir),
    );
    expect(s1.store.get("surv-1").content).toBe("frag a+b");
    expect(s1.store.get("abs-1").state).toBe("deleted");
    expect(r1.exitCode).toBe(0);

    // Branch 2: survivor already at merged hash (crash after PUT) → NO PUT, delete only.
    const s2 = fakeServer([
      { ...memory("surv-1", "frag a+b", 2) },
      memory("abs-1", "frag b"),
    ]);
    const r2 = await runCleanup(
      baseOpts({ apply: true, decisionsFile }),
      baseDeps(s2, fakeLlm([]), dir),
    );
    expect(s2.calls.filter((c) => c.method === "PUT")).toHaveLength(0);
    expect(s2.store.get("abs-1").state).toBe("deleted");
    expect(r2.exitCode).toBe(0);

    // Branch 3: survivor at a foreign hash (external LWW write) → whole merge SKIP.
    const s3 = fakeServer([
      { ...memory("surv-1", "externally rewritten", 5) },
      memory("abs-1", "frag b"),
    ]);
    const r3 = await runCleanup(
      baseOpts({ apply: true, decisionsFile }),
      baseDeps(s3, fakeLlm([]), dir),
    );
    expect(s3.calls.filter((c) => c.method !== "GET")).toHaveLength(0);
    expect(s3.store.get("abs-1").state).toBe("active");
    expect(r3.capUsed).toBe(0);
    expect(r3.skippedLww).toBe(1);
  });

  it("TC-MEMCLEAN-034 batch-delete chunks at 1000 and never sends an empty list", async () => {
    const mems = Array.from({ length: 1200 }, (_, i) => memory(`m-${i}`, `noise ${i}`));
    const server = fakeServer(mems);
    const llm = fakeLlm([]);
    llm.mockImplementation(async (_p, batch) =>
      JSON.stringify({ verdicts: batch.map((m) => ({ id: m.id, verdict: "DELETE", reason: "noise" })) }),
    );
    const result = await runCleanup(
      baseOpts({ apply: true, cap: 2000 }),
      baseDeps(server, llm, tempDir()),
    );
    const deletes = server.calls.filter((c) => c.method === "POST");
    expect(deletes.length).toBe(2);
    const sizes = deletes.map((c) => JSON.parse(c.body).ids.length);
    expect(Math.max(...sizes)).toBeLessThanOrEqual(1000);
    expect(sizes.every((n) => n > 0)).toBe(true);
    expect(result.capUsed).toBe(1200);

    // Empty delete set: KEEP-only run issues no POST.
    const server2 = fakeServer([memory("k", "keep me")]);
    await runCleanup(
      baseOpts({ apply: true }),
      baseDeps(server2, fakeLlm([[{ id: "k", verdict: "KEEP", reason: "ok" }]]), tempDir()),
    );
    expect(server2.calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });

  it("TC-MEMCLEAN-035 affected < requested warns and does not release cap", async () => {
    const dir = tempDir();
    const server = fakeServer([memory("d1", "x"), memory("d2", "y")]);
    // d2 is deleted out-of-band after its re-read but before the batch-delete,
    // so the server reports 1 affected for the 2 requested ids.
    const llm = fakeLlm([
      [
        { id: "d1", verdict: "DELETE", reason: "noise" },
        { id: "d2", verdict: "DELETE", reason: "noise" },
      ],
    ]);
    const deps = baseDeps(server, llm, dir);
    const realFetch = server.fetchImpl;
    deps.fetchImpl = vi.fn(async (url, opts = {}) => {
      const method = (opts.method || "GET").toUpperCase();
      if (method === "POST" && String(url).endsWith("/batch-delete")) {
        server.store.get("d2").state = "deleted"; // concurrent deletion race
      }
      return realFetch(url, opts);
    });
    const result = await runCleanup(baseOpts({ apply: true }), deps);
    expect(result.capUsed).toBe(2); // reserved for both, not released
    expect(deps.log).toHaveBeenCalledWith(expect.stringMatching(/affected 1.*requested 2|requested 2.*affected 1/));
    expect(result.exitCode).toBe(0);
  });
});

describe("concurrency guards", () => {
  it("TC-MEMCLEAN-040 LWW guard skips changed memories without consuming cap", async () => {
    const server = fakeServer([memory("d1", "orig"), memory("s1", "frag a"), memory("a1", "frag b")]);
    const llm = fakeLlm([
      [
        { id: "d1", verdict: "DELETE", reason: "noise" },
        { id: "s1", verdict: "MERGE", reason: "frags", merge_into: "s1", absorbs: ["a1"], merged_content: "frag a+b" },
      ],
    ]);
    // Mutate d1 and a1 after classification (between scan and apply re-read):
    // intercept the FIRST single-memory GET to bump them.
    const deps = baseDeps(server, llm, tempDir());
    let mutated = false;
    const realFetch = server.fetchImpl;
    deps.fetchImpl = vi.fn(async (url, opts = {}) => {
      if (!mutated && /memories\/[^/?]+$/.test(String(url))) {
        mutated = true;
        const d1 = server.store.get("d1");
        d1.content = "edited concurrently";
        d1.version += 1;
        const a1 = server.store.get("a1");
        a1.content = "also edited";
        a1.version += 1;
      }
      return realFetch(url, opts);
    });
    const result = await runCleanup(baseOpts({ apply: true }), deps);
    expect(server.store.get("d1").state).toBe("active"); // skipped
    expect(result.skippedLww).toBeGreaterThanOrEqual(1);
    // The merge survivor was unchanged → PUT happened; changed absorbed id dropped.
    expect(server.store.get("s1").content).toBe("frag a+b");
    expect(server.store.get("a1").state).toBe("active");
    expect(result.capUsed).toBe(1); // only the PUT
  });

  it("TC-MEMCLEAN-041 mutex blocks a second apply; stale lock broken only if holder is dead", async () => {
    const dir = tempDir();
    const lockFile = join(dir, "stage.lock");
    const server = fakeServer([memory("d1", "x")]);
    const llm = fakeLlm([[{ id: "d1", verdict: "DELETE", reason: "noise" }]]);
    const host = (await import("node:os")).hostname();

    // Fresh lock held by "another process" → fail fast regardless of liveness.
    writeFileSync(lockFile, JSON.stringify({ pid: 99999, host, at: Date.now() }));
    const deps = { ...baseDeps(server, llm, dir), lockFile, clock: () => Date.now() };
    const blocked = await runCleanup(baseOpts({ apply: true }), deps);
    expect(blocked.exitCode).not.toBe(0);
    expect(server.store.get("d1").state).toBe("active");

    // Stale (>2h) but the same-host holder pid is ALIVE → never broken.
    writeFileSync(lockFile, JSON.stringify({ pid: process.pid, host, at: Date.now() - 3 * 3600 * 1000 }));
    const depsLive = { ...baseDeps(server, llm, dir), lockFile, clock: () => Date.now() };
    const stillBlocked = await runCleanup(baseOpts({ apply: true }), depsLive);
    expect(stillBlocked.exitCode).not.toBe(0);
    expect(server.store.get("d1").state).toBe("active");

    // Stale lock (>2h) with a dead same-host pid → broken with a warning, run proceeds.
    writeFileSync(lockFile, JSON.stringify({ pid: 999999999, host, at: Date.now() - 3 * 3600 * 1000 }));
    const deps2 = { ...baseDeps(server, llm, dir), lockFile, clock: () => Date.now() };
    const ok = await runCleanup(baseOpts({ apply: true }), deps2);
    expect(ok.exitCode).toBe(0);
    expect(deps2.log).toHaveBeenCalledWith(expect.stringContaining("stale"));
    expect(server.store.get("d1").state).toBe("deleted");
  });
});

describe("secrets", () => {
  it("TC-MEMCLEAN-050 tenant key never appears in decision log or logged output", async () => {
    const dir = tempDir();
    const server = fakeServer([memory("m-1", "x")]);
    const llm = fakeLlm([[{ id: "m-1", verdict: "KEEP", reason: "ok" }]]);
    const deps = baseDeps(server, llm, dir);
    const result = await runCleanup(baseOpts(), deps);
    const logFile = readFileSync(result.decisionPath, "utf8");
    expect(logFile).not.toContain(TENANT);
    for (const call of deps.log.mock.calls) {
      expect(String(call[0])).not.toContain(TENANT);
    }
  });
});

describe("discovery", () => {
  it("TC-MEMCLEAN-055 healthy instance selected; none → error; --base-url bypasses", async () => {
    const server = fakeServer([]);
    const llm = fakeLlm([]);
    // Healthy instance path.
    const discover = vi.fn(async () => [{ ip: "10.0.0.7", port: 8080 }]);
    const deps = { ...baseDeps(server, llm, tempDir()), discoverInstances: discover };
    const opts = baseOpts({ baseUrl: undefined });
    const result = await runCleanup(opts, deps);
    expect(result.exitCode).toBe(0);
    expect(discover).toHaveBeenCalled();
    expect(String(server.fetchImpl.mock.calls[0][0])).toContain("10.0.0.7:8080");

    // No healthy instance after retries → clear error.
    const discoverEmpty = vi.fn(async () => []);
    const deps2 = { ...baseDeps(server, llm, tempDir()), discoverInstances: discoverEmpty, sleep: async () => {} };
    const fail = await runCleanup(baseOpts({ baseUrl: undefined }), deps2);
    expect(fail.exitCode).not.toBe(0);
    expect(discoverEmpty.mock.calls.length).toBeGreaterThanOrEqual(3);

    // Explicit base-url bypasses discovery entirely.
    const discoverUnused = vi.fn();
    const deps3 = { ...baseDeps(server, llm, tempDir()), discoverInstances: discoverUnused };
    await runCleanup(baseOpts(), deps3);
    expect(discoverUnused).not.toHaveBeenCalled();
  });
});

describe("verdict parsing units", () => {
  it("parseVerdicts accepts valid shapes and rejects garbage", () => {
    expect(parseVerdicts('{"verdicts":[{"id":"a","verdict":"KEEP","reason":"r"}]}')).toEqual([
      { id: "a", verdict: "KEEP", reason: "r" },
    ]);
    expect(() => parseVerdicts("nope")).toThrow();
    expect(() => parseVerdicts('{"verdicts":"x"}')).toThrow();
    expect(() => parseVerdicts('{"verdicts":[{"id":"a","verdict":"EXPLODE"}]}')).toThrow(/verdict/i);
  });

  it("planDecisions validates the merge graph (no DELETE targets, no cycles)", () => {
    const mems = [memory("a", "1"), memory("b", "2"), memory("c", "3")];
    // Target of a merge is itself deleted → invalid, downgraded to SKIP.
    const bad = planDecisions(mems, [
      { id: "a", verdict: "DELETE", reason: "r" },
      { id: "b", verdict: "MERGE", reason: "r", merge_into: "a", merged_content: "x" },
    ]);
    expect(bad.find((d) => d.id === "b").verdict).toBe("SKIP");
    // Merge cycle a→b, b→a → both SKIP.
    const cyc = planDecisions(mems, [
      { id: "a", verdict: "MERGE", reason: "r", merge_into: "b", merged_content: "x" },
      { id: "b", verdict: "MERGE", reason: "r", merge_into: "a", merged_content: "y" },
    ]);
    expect(cyc.every((d) => d.verdict === "SKIP")).toBe(true);
  });

  it("contentHash is a stable sha256 label", () => {
    expect(contentHash("abc")).toBe(`sha256:${createHash("sha256").update("abc").digest("hex")}`);
  });
});
