// Unit tests for scripts/memory-cleanup.mjs (issue #102).
// Test IDs map to docs/test-cases/memory-cleanup.md. All I/O is faked through
// the injected deps object — no network, no real filesystem outside tmpdirs.
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  buildCompleteChat,
  contentHash,
  parseArgs,
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
 *  - PUT  /memories/{id}         — update, bumps version; a mismatched
 *                                  `If-Match` is 412 and writes nothing
 *  - POST /memories/batch-delete — soft delete, skips already-deleted
 */
function fakeServer(initial) {
  const store = new Map(initial.map((m) => [m.id, { ...m }]));
  const calls = [];
  const fetchImpl = vi.fn(async (url, opts = {}) => {
    const method = (opts.method || "GET").toUpperCase();
    const u = new URL(url);
    calls.push({
      method,
      path: u.pathname,
      search: u.search,
      body: opts.body,
      ifMatch: opts.headers?.["If-Match"],
    });
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
      // Probed upstream: GetByID selects WHERE state='active', so deleted
      // (and archived) memories 404 on single GET.
      const m = store.get(single[1]);
      return m && m.state === "active" ? json(200, m) : json(404, { error: "not found" });
    }
    if (single && method === "PUT") {
      const m = store.get(single[1]);
      if (!m) return json(404, { error: "not found" });
      const body = JSON.parse(opts.body);
      // `If-Match` FENCES the write (patch 0008, issue #128): a mismatch is 412
      // and the write is NOT applied. Accepting a stale version here would make
      // every fence test vacuous.
      const ifMatch = Number(opts.headers?.["If-Match"]);
      if (ifMatch && ifMatch !== m.version) {
        return json(412, { error: "precondition failed: version changed" });
      }
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
    const deps = baseDeps(server, llm, tempDir());
    const result = await runCleanup(baseOpts({ apply: true }), deps);
    expect(llm).toHaveBeenCalledTimes(2);
    expect(result.decisions.every((d) => d.verdict === "SKIP")).toBe(true);
    expect(result.capUsed).toBe(0);
    expect(server.calls.filter((c) => c.method !== "GET")).toHaveLength(0);
    // Classification failing for EVERY batch is a broken-classifier signal,
    // not a clean store: distinct exit code so CI can't green-light it.
    expect(result.exitCode).toBe(5);
    // Raw LLM text (which can echo memory content) never reaches the logs.
    for (const call of deps.log.mock.calls) {
      expect(String(call[0])).not.toContain("not json");
    }
  });

  it("hallucinated field types are malformed responses, not crashes (batch SKIPs)", async () => {
    const server = fakeServer([memory("m-1", "x")]);
    // absorbs as a string instead of an array — twice, so the batch gives up.
    const bad = JSON.stringify({
      verdicts: [{ id: "m-1", verdict: "MERGE", merge_into: "m-1", absorbs: "m-1", merged_content: "y", reason: "r" }],
    });
    const llm = fakeLlm([bad, bad]);
    const result = await runCleanup(baseOpts({ apply: true }), baseDeps(server, llm, tempDir()));
    expect(result.decisions[0]).toMatchObject({ id: "m-1", verdict: "SKIP" });
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
        { id: "abs-1", verdict: "MERGE", reason: "frags", merge_into: "surv-1" },
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
        { id: "a1", verdict: "MERGE", reason: "r", merge_into: "s1" },
        { id: "a2", verdict: "MERGE", reason: "r", merge_into: "s1" },
        { id: "s2", verdict: "MERGE", reason: "r", merge_into: "s2", absorbs: ["a3", "a4"], merged_content: "def" },
        { id: "a3", verdict: "MERGE", reason: "r", merge_into: "s2" },
        { id: "a4", verdict: "MERGE", reason: "r", merge_into: "s2" },
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
          { id: "a1", verdict: "MERGE", reason: "r", merge_into: "s1" },
          { id: "a2", verdict: "MERGE", reason: "r", merge_into: "s1" },
          { id: "s2", verdict: "MERGE", reason: "r", merge_into: "s2", absorbs: ["a3", "a4"], merged_content: "def" },
          { id: "a3", verdict: "MERGE", reason: "r", merge_into: "s2" },
          { id: "a4", verdict: "MERGE", reason: "r", merge_into: "s2" },
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

  it("TC-MEMCLEAN-034 batch-delete flushes in bounded chunks and never sends an empty list", async () => {
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
    const sizes = deletes.map((c) => JSON.parse(c.body).ids.length);
    // Mid-run flush threshold (20) bounds the TOCTOU window; the server-side
    // 1000-id cap is never exceeded, no request is empty, and every id lands.
    expect(Math.max(...sizes)).toBeLessThanOrEqual(1000);
    expect(sizes.every((n) => n > 0)).toBe(true);
    expect(sizes.reduce((a, b) => a + b, 0)).toBe(1200);
    expect([...server.store.values()].every((m) => m.state === "deleted")).toBe(true);
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
        { id: "a1", verdict: "MERGE", reason: "frags", merge_into: "s1" },
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

  it("TC-MEMCLEAN-042 ingest write landing between the survivor's read and rewrite is fenced out", async () => {
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

    const server = fakeServer([memory("surv-1", "frag a"), memory("abs-1", "frag b")]);
    // Interleave explicitly: the survivor's guard GET sees the expected version,
    // then an ingest write lands BEFORE the rewrite. Only the server-side fence
    // can catch this — the client's own re-read already passed.
    const deps = baseDeps(server, fakeLlm([]), dir);
    const realFetch = server.fetchImpl;
    deps.fetchImpl = vi.fn(async (url, opts = {}) => {
      const method = (opts.method || "GET").toUpperCase();
      if (method === "PUT" && /memories\/surv-1$/.test(String(url))) {
        const s = server.store.get("surv-1");
        s.content = "ingested concurrently";
        s.version += 1;
      }
      return realFetch(url, opts);
    });
    const result = await runCleanup(baseOpts({ apply: true, decisionsFile }), deps);

    // The concurrent write survives; the merged content never lands.
    expect(server.store.get("surv-1").content).toBe("ingested concurrently");
    expect(result.skippedLww).toBeGreaterThanOrEqual(1);
    // Absorbed ids are NOT deleted — the merge's survivor never got the content.
    expect(server.store.get("abs-1").state).toBe("active");
    expect(server.calls.filter((c) => c.method === "POST")).toHaveLength(0);
    // A fenced merge is a skip, not a run failure.
    expect(result.exitCode).toBe(0);
  });

  it("TC-MEMCLEAN-043 a 412 on the survivor rewrite is a skip, and other decisions still apply", async () => {
    const dir = tempDir();
    const decisions = {
      stage: "test",
      generatedAt: "2026-07-31T00:00:00Z",
      decisions: [
        {
          id: "surv-1", verdict: "MERGE", reason: "frags",
          version: 1, contentHash: contentHash("frag a"),
          mergedContent: "frag a+b", mergedContentHash: contentHash("frag a+b"),
          absorbs: [{ id: "abs-1", version: 1, contentHash: contentHash("frag b") }],
        },
        { id: "junk-1", verdict: "DELETE", reason: "noise", version: 1, contentHash: contentHash("noise") },
      ],
    };
    writeFileSync(join(dir, "decisions.json"), JSON.stringify(decisions));

    const server = fakeServer([
      memory("surv-1", "frag a"),
      memory("abs-1", "frag b"),
      memory("junk-1", "noise"),
    ]);
    const deps = baseDeps(server, fakeLlm([]), dir);
    const realFetch = server.fetchImpl;
    deps.fetchImpl = vi.fn(async (url, opts = {}) => {
      const method = (opts.method || "GET").toUpperCase();
      if (method === "PUT" && /memories\/surv-1$/.test(String(url))) {
        server.store.get("surv-1").version += 1; // ingest bumps the version only
      }
      return realFetch(url, opts);
    });
    const result = await runCleanup(
      baseOpts({ apply: true, decisionsFile: join(dir, "decisions.json") }),
      deps,
    );

    // The fenced merge did not consume cap and did not abort the run. Charging
    // it would shrink the blast-radius budget for the rest of the run, and a
    // mostly-fenced run could trip the exit-4 cap abort having applied nothing:
    // only the unrelated DELETE below may be charged.
    expect(result.capUsed).toBe(1);
    expect(result.skippedLww).toBeGreaterThanOrEqual(1);
    expect(server.store.get("abs-1").state).toBe("active");
    // ...while an unrelated DELETE in the same run still applied.
    expect(server.store.get("junk-1").state).toBe("deleted");
    expect(result.exitCode).toBe(0);
    expect(deps.log).toHaveBeenCalledWith(expect.stringMatching(/surv-1.*concurrent|surv-1.*fenc|surv-1.*412/i));
  });

  it("TC-MEMCLEAN-044 a successful merge sends If-Match and leaves the survivor at the merged content", async () => {
    const dir = tempDir();
    const decisions = {
      stage: "test",
      generatedAt: "2026-07-31T00:00:00Z",
      decisions: [{
        id: "surv-1", verdict: "MERGE", reason: "frags",
        version: 3, contentHash: contentHash("frag a"),
        mergedContent: "frag a+b", mergedContentHash: contentHash("frag a+b"),
        absorbs: [{ id: "abs-1", version: 1, contentHash: contentHash("frag b") }],
      }],
    };
    writeFileSync(join(dir, "decisions.json"), JSON.stringify(decisions));
    const server = fakeServer([memory("surv-1", "frag a", 3), memory("abs-1", "frag b")]);
    const result = await runCleanup(
      baseOpts({ apply: true, decisionsFile: join(dir, "decisions.json") }),
      baseDeps(server, fakeLlm([]), dir),
    );
    const put = server.calls.find((c) => c.method === "PUT");
    // The rewrite must be predicated on the observed version — without the
    // header the server cannot fence it, and the write is unprotected.
    expect(put.ifMatch).toBe("3");
    // A content-bearing PUT is what makes upstream re-embed; the survivor's
    // embedding therefore matches its new content (issue #128 requirement d).
    expect(JSON.parse(put.body).content).toBe("frag a+b");
    expect(server.store.get("surv-1").content).toBe("frag a+b");
    expect(server.store.get("abs-1").state).toBe("deleted");
    expect(result.skippedLww).toBe(0);
    expect(result.exitCode).toBe(0);
  });

  it("TC-MEMCLEAN-047 only 412 is a skip — any other write failure still aborts the run", async () => {
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
    writeFileSync(join(dir, "decisions.json"), JSON.stringify(decisions));
    const server = fakeServer([memory("surv-1", "frag a"), memory("abs-1", "frag b")]);
    const deps = baseDeps(server, fakeLlm([]), dir);
    const realFetch = server.fetchImpl;
    deps.fetchImpl = vi.fn(async (url, opts = {}) => {
      if ((opts.method || "GET").toUpperCase() === "PUT") {
        return new Response(JSON.stringify({ error: "boom" }), { status: 500 });
      }
      return realFetch(url, opts);
    });
    // Narrowing 412 to "skip" must not widen into swallowing real failures: a
    // 5xx on the survivor rewrite is a transport fault and must still abort the
    // run (main() maps the rejection to exit 1), never be mistaken for a fence.
    await expect(
      runCleanup(baseOpts({ apply: true, decisionsFile: join(dir, "decisions.json") }), deps),
    ).rejects.toThrow(/HTTP 500/);
    // Aborted before the delete leg: the absorbed fragment is untouched.
    expect(server.store.get("abs-1").state).toBe("active");
    expect(server.calls.filter((c) => c.method === "POST")).toHaveLength(0);

    // And 412 is opt-in per call site, not global: only a fenced write carries a
    // precondition, so a 412 on the unversioned batch-delete has no race to have
    // lost and must still abort. If it were swallowed to null, `flushDeletes`
    // would then read `.deleted` off null and throw an unrelated TypeError.
    const dir2 = tempDir();
    writeFileSync(join(dir2, "decisions.json"), JSON.stringify({
      stage: "test",
      decisions: [{ id: "junk-1", verdict: "DELETE", reason: "noise", version: 1, contentHash: contentHash("noise") }],
    }));
    const s2 = fakeServer([memory("junk-1", "noise")]);
    const d2 = baseDeps(s2, fakeLlm([]), dir2);
    const realFetch2 = s2.fetchImpl;
    d2.fetchImpl = vi.fn(async (url, opts = {}) => {
      if (String(url).endsWith("/batch-delete")) {
        return new Response(JSON.stringify({ error: "precondition failed" }), { status: 412 });
      }
      return realFetch2(url, opts);
    });
    await expect(
      runCleanup(baseOpts({ apply: true, decisionsFile: join(dir2, "decisions.json") }), d2),
    ).rejects.toThrow(/HTTP 412/);
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

  it("TC-CONSOL-014 shares the database apply mutex with consolidation", async () => {
    const dir = tempDir();
    const server = fakeServer([memory("d1", "x")]);
    const llm = fakeLlm([
      [{ id: "d1", verdict: "DELETE", reason: "noise" }],
    ]);
    const acquireMutex = vi.fn(async () => null);
    const blocked = await runCleanup(
      baseOpts({ apply: true }),
      { ...baseDeps(server, llm, dir), acquireMutex },
    );
    expect(acquireMutex).toHaveBeenCalledWith("test");
    expect(blocked.exitCode).toBe(3);
    expect(server.store.get("d1").state).toBe("active");

    const release = vi.fn(async () => {});
    const localLock = join(dir, "local.lock");
    writeFileSync(
      localLock,
      JSON.stringify({ pid: 99999, host: "other-host", at: Date.now() }),
    );
    const localBlocked = await runCleanup(
      baseOpts({ apply: true }),
      {
        ...baseDeps(server, llm, dir),
        acquireMutex: vi.fn(async () => ({ release })),
        lockFile: localLock,
      },
    );
    expect(localBlocked.exitCode).toBe(3);
    expect(release).toHaveBeenCalledOnce();
    expect(server.store.get("d1").state).toBe("active");
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

  it("planDecisions never lets `absorbs` override an id's own verdict (TC-MEMCLEAN-014)", () => {
    const mems = [memory("s", "survivor"), memory("k", "kept"), memory("n", "no verdict")];
    // "k" is judged KEEP, "n" has no verdict at all — a MERGE listing either
    // in `absorbs` must not delete them.
    const out = planDecisions(mems, [
      { id: "s", verdict: "MERGE", reason: "r", merge_into: "s", absorbs: ["k", "n"], merged_content: "x" },
      { id: "k", verdict: "KEEP", reason: "durable" },
    ]);
    const byId = Object.fromEntries(out.map((d) => [d.id, d]));
    expect(byId["k"].verdict).toBe("KEEP");
    // With no consenting absorbed ids the merge itself degrades to SKIP.
    expect(byId["s"].verdict).toBe("SKIP");
    expect(out.some((d) => d.verdict === "MERGE")).toBe(false);
  });

  it("planDecisions SKIPs an id with contradictory duplicate verdicts (TC-MEMCLEAN-015)", () => {
    const mems = [memory("a", "1")];
    const out = planDecisions(mems, [
      { id: "a", verdict: "KEEP", reason: "durable" },
      { id: "a", verdict: "DELETE", reason: "noise" },
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].verdict).toBe("SKIP");
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

  it("planDecisions SKIPs a memory whose version cannot be fenced (TC-MEMCLEAN-051)", () => {
    // `validateDecisions` only guards the REPLAY path. A fresh scan builds its
    // own anchors from the store, and upstream's column is `version INT
    // DEFAULT 1` — nullable — so an unfenceable version is a data condition
    // here too. `anchor()` copies it verbatim and `put()` does
    // `String(version)`, so a null would go on the wire as `If-Match: "null"`,
    // which patch 0008 rejects as a 400 that aborts the run mid-apply, after
    // earlier decisions may already have deleted rows. SKIP instead: one bad
    // row must not abort an otherwise-valid audit.
    for (const version of [null, undefined, 0, "1"]) {
      const survivor = { ...memory("s", "survivor"), version };
      const out = planDecisions([survivor, memory("a", "absorbed")], [
        { id: "s", verdict: "MERGE", reason: "r", merge_into: "s", absorbs: ["a"], merged_content: "x" },
        { id: "a", verdict: "MERGE", reason: "r", merge_into: "s" },
      ]);
      const byId = Object.fromEntries(out.map((d) => [d.id, d]));
      expect(byId["s"].verdict, `survivor version ${JSON.stringify(version)}`).toBe("SKIP");
      expect(byId["s"].reason).toMatch(/cannot be fenced/i);
      expect(out.some((d) => d.verdict === "MERGE")).toBe(false);
    }

    // An unfenceable ABSORBED side must disqualify the merge too: its delete
    // leg is guarded by a version re-read the same way.
    const absorbedNull = { ...memory("a", "absorbed"), version: null };
    const out = planDecisions([memory("s", "survivor"), absorbedNull], [
      { id: "s", verdict: "MERGE", reason: "r", merge_into: "s", absorbs: ["a"], merged_content: "x" },
      { id: "a", verdict: "MERGE", reason: "r", merge_into: "s" },
    ]);
    expect(out.find((d) => d.id === "s").verdict).toBe("SKIP");
    expect(out.some((d) => d.verdict === "MERGE")).toBe(false);

    // Positive control: a well-formed version still merges, so the guard is not
    // simply refusing everything.
    const good = planDecisions([memory("s", "survivor"), memory("a", "absorbed")], [
      { id: "s", verdict: "MERGE", reason: "r", merge_into: "s", absorbs: ["a"], merged_content: "x" },
      { id: "a", verdict: "MERGE", reason: "r", merge_into: "s" },
    ]);
    expect(good.find((d) => d.id === "s").verdict).toBe("MERGE");
  });

  it("planDecisions SKIPs a non-MERGE verdict whose version cannot be fenced (TC-MEMCLEAN-051)", () => {
    // DELETE's delete leg and every other mutation anchor on the same version.
    // A null-versioned DELETE would reach `flushDeletes` unfenced.
    const out = planDecisions([{ ...memory("d", "noise"), version: null }], [
      { id: "d", verdict: "DELETE", reason: "noise" },
    ]);
    expect(out[0].verdict).toBe("SKIP");
    expect(out[0].reason).toMatch(/cannot be fenced/i);
  });

  it("parseArgs validates flags, values, and the positive-cap guard", () => {
    expect(parseArgs(["--stage", "prod"])).toMatchObject({ stage: "prod", apply: false, cap: 50 });
    expect(
      parseArgs(["--stage", "prod", "--apply", "--cap", "10", "--ids", "a.txt", "--lock-ttl", "4"]),
    ).toMatchObject({ apply: true, cap: 10, idsFile: "a.txt", lockTtlHours: 4 });
    expect(() => parseArgs([])).toThrow(/--stage/);
    expect(() => parseArgs(["--stage", "prod", "--cap", "abc"])).toThrow(/positive/);
    expect(() => parseArgs(["--stage", "prod", "--cap", "0"])).toThrow(/positive/);
    expect(() => parseArgs(["--stage", "prod", "--cap", "-5"])).toThrow(/positive/);
    expect(() => parseArgs(["--stage", "prod", "--cap"])).toThrow(/requires a value/);
    expect(() => parseArgs(["--bogus"])).toThrow(/unknown argument/);
  });

  it("runCleanup rejects a non-finite cap even if parseArgs is bypassed", async () => {
    const server = fakeServer([]);
    await expect(
      runCleanup(baseOpts({ cap: Number.NaN }), baseDeps(server, fakeLlm([]), tempDir())),
    ).rejects.toThrow(/positive finite/);
  });

  it("refuses to replay a decision file generated for a different stage", async () => {
    const dir = tempDir();
    const decisionsFile = join(dir, "decisions.json");
    writeFileSync(decisionsFile, JSON.stringify({ stage: "pr-7", decisions: [] }));
    const server = fakeServer([]);
    await expect(
      runCleanup(
        baseOpts({ apply: true, decisionsFile }), // stage: "test"
        baseDeps(server, fakeLlm([]), dir),
      ),
    ).rejects.toThrow(/stage/);
  });

  it("TC-MEMCLEAN-048 refuses a MERGE decision with no usable version anchor", async () => {
    const dir = tempDir();
    const merge = (overrides) => ({
      stage: "test",
      decisions: [{
        id: "surv-1", verdict: "MERGE", reason: "frags",
        version: 1, contentHash: contentHash("frag a"),
        mergedContent: "frag a+b", mergedContentHash: contentHash("frag a+b"),
        absorbs: [{ id: "abs-1", version: 1, contentHash: contentHash("frag b") }],
        ...overrides,
      }],
    });
    const replay = async (doc) => {
      const decisionsFile = join(dir, "decisions.json");
      writeFileSync(decisionsFile, JSON.stringify(doc));
      const server = fakeServer([memory("surv-1", "frag a"), memory("abs-1", "frag b")]);
      const promise = runCleanup(
        baseOpts({ apply: true, decisionsFile }),
        baseDeps(server, fakeLlm([]), dir),
      );
      return { promise, server };
    };

    // The survivor's version is the `If-Match` value. Post-patch-0008 an absent
    // one would be sent as the literal "undefined" and earn an opaque 400
    // mid-apply, after earlier decisions have already deleted rows. Fail at load.
    for (const bad of [{ version: undefined }, { version: "1" }, { version: 0 }]) {
      const { promise, server } = await replay(merge(bad));
      await expect(promise).rejects.toThrow(/entry 0 invalid: MERGE without a version anchor/);
      expect(server.calls).toHaveLength(0);
    }

    // An absorbed entry's version is compared against the re-read. An absent one
    // never matches, so the fragment would be silently dropped from the delete
    // set as "changed externally" — a misattributed LWW skip, not a real one.
    const { promise, server } = await replay(
      merge({ absorbs: [{ id: "abs-1", contentHash: contentHash("frag b") }] }),
    );
    await expect(promise).rejects.toThrow(/entry 0 invalid: MERGE with invalid absorbs/);
    expect(server.calls).toHaveLength(0);

    // The valid anchor still replays.
    const ok = await replay(merge({}));
    await expect(ok.promise).resolves.toMatchObject({ exitCode: 0 });
    expect(ok.server.store.get("surv-1").content).toBe("frag a+b");
  });

  it("contentHash is a stable sha256 label", () => {
    expect(contentHash("abc")).toBe(`sha256:${createHash("sha256").update("abc").digest("hex")}`);
  });
});

// ---------------------------------------------------------------------------
// LLM route (TC-MEMCLEAN-070..078) — docs/test-cases/cleanup-reasoning-model.md

describe("LLM route", () => {
  const APP_REGION = "ap-northeast-1";
  const CLASSIFY_ATTEMPTS = 2; // mirrors memory-cleanup.mjs

  /** Record every request; reply with the queued responses in order. */
  function recorder(replies) {
    const calls = [];
    const queue = [...replies];
    const fetchImpl = (url, init) => {
      calls.push({ url, body: JSON.parse(init.body), headers: init.headers });
      const next = queue.shift();
      if (!next) throw new Error("unexpected extra request");
      return Promise.resolve({
        ok: next.status === undefined || next.status < 400,
        status: next.status ?? 200,
        json: async () => next.body,
      });
    };
    return { calls, fetchImpl };
  }

  const chatReply = (content) => ({ body: { choices: [{ message: { content } }] } });
  const responsesReply = (overrides) => ({
    body: {
      id: "resp_1",
      status: "completed",
      output: [{ content: [{ type: "output_text", text: "[]" }] }],
      usage: { input_tokens: 10, output_tokens: 20 },
      ...overrides,
    },
  });

  const build = (opts, deps) =>
    buildCompleteChat({ region: APP_REGION, ...opts }, { mintToken: async (r) => `tok-${r}`, ...deps });

  it("TC-MEMCLEAN-070: GLM-5 keeps the chat-completions contract unchanged", async () => {
    const { calls, fetchImpl } = recorder([chatReply("[]")]);
    const completeChat = build({ model: "zai.glm-5" }, { fetchImpl });

    expect(await completeChat("sys", [{ id: "m1" }])).toBe("[]");
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe(`https://bedrock-mantle.${APP_REGION}.api.aws/v1/chat/completions`);
    // The chat route must keep the 4096 cap and the messages shape: GLM-5 has
    // no Responses surface, and a reasoning field would 400.
    expect(calls[0].body).toMatchObject({
      model: "zai.glm-5",
      max_tokens: 4096,
      messages: [
        { role: "system", content: "sys" },
        { role: "user", content: JSON.stringify({ memories: [{ id: "m1" }] }) },
      ],
    });
    expect(calls[0].body.input).toBeUndefined();
    expect(calls[0].body.reasoning).toBeUndefined();
    expect(calls[0].headers.authorization).toBe(`Bearer tok-${APP_REGION}`);
  });

  it("TC-MEMCLEAN-071: a gpt-5.6 model routes to Responses in the responses region", async () => {
    const { calls, fetchImpl } = recorder([responsesReply()]);
    const completeChat = build(
      { model: "openai.gpt-5.6-terra", effort: "high", llmRegion: "us-west-2" },
      { fetchImpl },
    );

    await completeChat("sysprompt", [{ id: "m1" }]);
    expect(calls[0].url).toBe("https://bedrock-mantle.us-west-2.api.aws/openai/v1/responses");
    expect(calls[0].body).toMatchObject({
      model: "openai.gpt-5.6-terra",
      instructions: "sysprompt",
      reasoning: { effort: "high" },
      // 4096 truncates reasoning output mid-JSON — the measured GLM-5 failure.
      max_output_tokens: 24000,
    });
    expect(calls[0].body.input).toEqual([
      { role: "user", content: JSON.stringify({ memories: [{ id: "m1" }] }) },
    ]);
    expect(calls[0].body.messages).toBeUndefined();
    // The bearer is minted for the RESPONSES region, not the app region.
    expect(calls[0].headers.authorization).toBe("Bearer tok-us-west-2");
  });

  it("TC-MEMCLEAN-072: responses output_text parts reach parseVerdicts verbatim", async () => {
    const verdicts = '{"verdicts":[{"id":"m1","verdict":"KEEP","reason":"durable"}]}';
    const { fetchImpl } = recorder([
      responsesReply({
        // Split across parts: the route must concatenate, not take the first.
        output: [
          { content: [{ type: "output_text", text: verdicts.slice(0, 10) }] },
          { content: [{ type: "output_text", text: verdicts.slice(10) }] },
        ],
      }),
    ]);
    const completeChat = build({ model: "openai.gpt-5.6-terra" }, { fetchImpl });

    const raw = await completeChat("sys", [{ id: "m1" }]);
    expect(raw).toBe(verdicts);
    expect(parseVerdicts(raw)).toEqual([{ id: "m1", verdict: "KEEP", reason: "durable" }]);
  });

  it("TC-MEMCLEAN-073: a failed responses status throws instead of returning empty", async () => {
    // status:"failed" arrives as HTTP 200 with empty output. Returning "" would
    // parse as "no verdicts" and SKIP a whole batch on a non-answer that looks
    // authoritative — the exact silent skip this route must not introduce.
    const { fetchImpl } = recorder([
      responsesReply({ status: "failed", output: [], error: { message: "upstream boom" } }),
    ]);
    const completeChat = build({ model: "openai.gpt-5.6-terra" }, { fetchImpl });

    await expect(completeChat("sys", [{ id: "m1" }])).rejects.toThrow(/failed/);
  });

  it("TC-MEMCLEAN-073b: a completed reply with no output_text throws", async () => {
    const { fetchImpl } = recorder([responsesReply({ output: [{ content: [] }] })]);
    const completeChat = build({ model: "openai.gpt-5.6-terra" }, { fetchImpl });

    await expect(completeChat("sys", [{ id: "m1" }])).rejects.toThrow(/no output_text/);
  });

  it("TC-MEMCLEAN-074: a truncated reply is rejected even when its JSON parses", async () => {
    // The dangerous case is truncation that lands on VALID JSON. Parsing it
    // would delete memories the model never finished judging, so an
    // `incomplete` status must fail the batch (→ retry → SKIP), not classify.
    const truncatedButValid = JSON.stringify({
      verdicts: [{ id: "m1", verdict: "DELETE", reason: "noise" }],
    });
    for (const text of [truncatedButValid, '{"verdicts":[{"id":"m1"']) {
      const { fetchImpl } = recorder([
        responsesReply({
          status: "incomplete",
          incomplete_details: { reason: "max_output_tokens" },
          output: [{ content: [{ type: "output_text", text }] }],
        }),
      ]);
      const completeChat = build({ model: "openai.gpt-5.6-terra" }, { fetchImpl });
      await expect(completeChat("sys", [{ id: "m1" }])).rejects.toThrow(/truncated/);
    }
  });

  it("TC-MEMCLEAN-074b: a truncated reply cannot delete or merge end-to-end", async () => {
    // Drives the REAL buildCompleteChat through runCleanup: a truncated MERGE
    // whose merged_content is cut mid-sentence must not rewrite the survivor
    // or delete the absorbed memory.
    const dir = tempDir();
    const server = fakeServer([memory("s", "fragment a"), memory("a", "fragment b")]);
    const { fetchImpl } = recorder([
      responsesReply({
        status: "incomplete",
        output: [{
          content: [{
            type: "output_text",
            text: JSON.stringify({
              verdicts: [
                { id: "s", verdict: "MERGE", reason: "frags", merge_into: "s",
                  absorbs: ["a"], merged_content: "fragment a and the deploy pipeline was" },
                { id: "a", verdict: "MERGE", reason: "frags", merge_into: "s" },
              ],
            }),
          }],
        }],
      }),
      // classifyBatch retries once; fail the same way.
      responsesReply({
        status: "incomplete",
        output: [{ content: [{ type: "output_text", text: "{}" }] }],
      }),
    ]);
    const completeChat = build({ model: "openai.gpt-5.6-terra" }, { fetchImpl });

    const result = await runCleanup(
      baseOpts({ apply: true }),
      { ...baseDeps(server, completeChat, dir), completeChat },
    );
    expect(result.decisions.map((d) => d.verdict)).toEqual(["SKIP", "SKIP"]);
    expect(result.writeCalls).toBe(0);
    expect(server.store.get("s").content).toBe("fragment a");
    expect(server.store.get("a").state).toBe("active");
  });

  it("TC-MEMCLEAN-074c: a near-miss model id must not silently use the 4096 cap", async () => {
    // Prefix matching is exact: a typo or the next model generation would
    // otherwise route to chat-completions at the truncating cap and produce a
    // run that looks successful while a third of the corpus goes unclassified.
    for (const model of ["openai.gpt-5.6terra", "openai.gpt-6-terra", "OPENAI.GPT-5.6-TERRA"]) {
      const { calls, fetchImpl } = recorder([chatReply('{"verdicts":[]}')]);
      await build({ model }, { fetchImpl })("sys", []);
      // Documents the CURRENT behavior so a future prefix change is a visible
      // test change, not a silent capability regression.
      expect(calls[0].body.max_tokens).toBe(4096);
    }
  });

  it("TC-MEMCLEAN-075: a 401 re-mints once per route, then gives up", async () => {
    const minted = [];
    const { calls, fetchImpl } = recorder([{ status: 401, body: {} }, responsesReply()]);
    const completeChat = build(
      { model: "openai.gpt-5.6-terra", llmRegion: "us-west-2" },
      { fetchImpl, mintToken: async (r) => `tok-${r}-${minted.push(r)}` },
    );

    await completeChat("sys", [{ id: "m1" }]);
    expect(minted).toEqual(["us-west-2", "us-west-2"]);
    expect(calls[1].headers.authorization).toBe("Bearer tok-us-west-2-2");

    const second = recorder([{ status: 401, body: {} }, { status: 401, body: {} }]);
    const giveUp = build({ model: "openai.gpt-5.6-terra" }, { fetchImpl: second.fetchImpl });
    await expect(giveUp("sys", [{ id: "m1" }])).rejects.toThrow(/after bearer re-mint/);
  });

  it("TC-MEMCLEAN-075b: a non-auth HTTP error names the route and does not retry", async () => {
    const { calls, fetchImpl } = recorder([{ status: 500, body: {} }]);
    const completeChat = build({ model: "openai.gpt-5.6-terra" }, { fetchImpl });

    await expect(completeChat("sys", [{ id: "m1" }])).rejects.toThrow(/responses -> HTTP 500/);
    expect(calls).toHaveLength(1);
  });

  it("TC-MEMCLEAN-076: --model/--effort/--llm-region parse; --effort is bounded", () => {
    expect(
      parseArgs([
        "--stage", "prod",
        "--model", "openai.gpt-5.6-luna",
        "--effort", "medium",
        "--llm-region", "us-east-1",
      ]),
    ).toMatchObject({ model: "openai.gpt-5.6-luna", effort: "medium", llmRegion: "us-east-1" });

    // An unbounded effort would reach Mantle and 400 mid-scan.
    expect(() => parseArgs(["--stage", "prod", "--effort", "ultra"])).toThrow(/low\|medium\|high/);
    expect(parseArgs(["--stage", "prod"]).model).toBeUndefined();
  });

  it("TC-MEMCLEAN-077: each route carries its own timeout budget", async () => {
    const budgets = [];
    const spy = vi.spyOn(AbortSignal, "timeout");
    try {
      for (const model of ["zai.glm-5", "openai.gpt-5.6-terra"]) {
        const reply = model === "zai.glm-5" ? chatReply("[]") : responsesReply();
        const { fetchImpl } = recorder([reply]);
        spy.mockClear();
        await build({ model }, { fetchImpl })("sys", [{ id: "m1" }]);
        budgets.push(spy.mock.calls.at(-1)[0]);
      }
    } finally {
      spy.mockRestore();
    }
    // High-effort reasoning legitimately outlives the 120s chat budget.
    expect(budgets).toEqual([120_000, 300_000]);
  });

  it("TC-MEMCLEAN-080: a partial classification outage is reported, not hidden in SKIP", async () => {
    // 3 batches of 20. The first fails BOTH attempts (classifyBatch retries
    // once), so exactly one batch goes unclassified while two succeed.
    // classifierBroken requires ALL batches to fail, so this exits 0 — the
    // summary MUST say how much of the corpus went unaudited, or a partial
    // outage is indistinguishable from a clean audit.
    const memories = Array.from({ length: 60 }, (_, i) => memory(`m-${i}`, `fact ${i}`));
    const server = fakeServer(memories);
    let call = 0;
    const llm = vi.fn(async (_p, batch) => {
      call += 1;
      if (call <= CLASSIFY_ATTEMPTS) throw new Error("Mantle responses -> HTTP 500");
      // A merge group in a SUCCEEDING batch: planDecisions folds the absorbed
      // ids into the survivor's row, so decisions.length < scanned memories.
      // The denominator must still be the memory count an operator can verify
      // against the store, not the row count.
      if (call === CLASSIFY_ATTEMPTS + 1) {
        const [s1, a1, a2, ...rest] = batch;
        return JSON.stringify({
          verdicts: [
            { id: s1.id, verdict: "MERGE", reason: "frags", merge_into: s1.id,
              absorbs: [a1.id, a2.id], merged_content: "merged fact" },
            { id: a1.id, verdict: "MERGE", reason: "frags", merge_into: s1.id },
            { id: a2.id, verdict: "MERGE", reason: "frags", merge_into: s1.id },
            ...keepAll(rest),
          ],
        });
      }
      return JSON.stringify({ verdicts: keepAll(batch) });
    });
    const deps = baseDeps(server, llm, tempDir());
    const result = await runCleanup(baseOpts(), deps);

    expect(result.exitCode).toBe(0);
    expect(result.decisions.length).toBeLessThan(60); // merge folding shrank the rows
    const summaryLine = deps.log.mock.calls.map((c) => c[0]).find((m) => m.startsWith("dry-run:"));
    expect(summaryLine).toMatch(/UNCLASSIFIED=20 of 60 memories \(1\/3 batches failed, 33%\)/);
    expect(summaryLine).toMatch(/NOT audited by this classification/);
    // The old summary reported only SKIP:20, which is also what a legitimate
    // planner SKIP looks like — the whole point of the new note.
    expect(summaryLine).toContain('"SKIP":20');

    // The apply run replays the file and is the run that DELETES, so it must
    // carry the same warning; batch counters are absent there.
    const applyServer = fakeServer(memories);
    const applyDeps = baseDeps(applyServer, llm, tempDir());
    await runCleanup(
      baseOpts({ apply: true, decisionsFile: result.decisionPath, cap: 500 }),
      applyDeps,
    );
    const applyLine = applyDeps.log.mock.calls.map((c) => c[0]).find((m) => m.startsWith("apply done:"));
    expect(applyLine).toMatch(/UNCLASSIFIED=20 of 60 memories \(from the replayed decision list\)/);
  });

  it("TC-MEMCLEAN-081: a deterministic request-translation defect aborts the run", async () => {
    // Non-string message content is rejected by the translator BEFORE any
    // network call, so it fails identically on every batch. Retrying it and
    // degrading to SKIP would turn an invocation bug into a clean-looking
    // audit of an unexamined corpus.
    const server = fakeServer([memory("m-1", "x")]);
    const { fetchImpl } = recorder([]);
    const completeChat = build({ model: "openai.gpt-5.6-terra" }, { fetchImpl });
    const boom = () => completeChat(null, [{ id: "m-1" }]); // null system prompt

    await expect(boom()).rejects.toThrow(/string content/);
    await expect(
      runCleanup(baseOpts(), { ...baseDeps(server, boom, tempDir()), completeChat: boom }),
    ).rejects.toThrow(/string content/);
  });

  it("TC-MEMCLEAN-079: ambient LLM_PROXY_* sidecar env cannot alter the route", async () => {
    // The config is assembled from a CLOSED object, not a spread of process.env.
    // A debug host with the sidecar's container env exported would otherwise
    // silently route terra to chat-completions at its 4096 cap (reintroducing
    // the truncation this route exists to fix) or crash on a limit cleanup
    // never reads.
    vi.stubEnv("LLM_PROXY_RESPONSES_MODEL_PREFIXES", "nothing-matches");
    vi.stubEnv("LLM_PROXY_UPSTREAM_BASE", "http://localhost:8082/v1");
    vi.stubEnv("LLM_PROXY_MAX_BODY_BYTES", "0");
    vi.stubEnv("LLM_PROXY_REASONING_EFFORT", "not-an-effort");
    try {
      const { calls, fetchImpl } = recorder([responsesReply()]);
      await build({ model: "openai.gpt-5.6-terra" }, { fetchImpl })("sys", []);
      expect(calls[0].url).toBe("https://bedrock-mantle.us-west-2.api.aws/openai/v1/responses");
      expect(calls[0].body.max_output_tokens).toBe(24000);
      expect(calls[0].body.reasoning).toEqual({ effort: "high" });
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("TC-MEMCLEAN-078: regional project ids are never cross-applied", async () => {
    vi.stubEnv("MEM9_BEDROCK_PROJECT", "proj_tokyo");
    vi.stubEnv("MEM9_BEDROCK_PROJECT_OPENAI", "proj_uswest");
    try {
      const chat = recorder([chatReply("[]")]);
      await build({ model: "zai.glm-5" }, { fetchImpl: chat.fetchImpl })("sys", []);
      expect(chat.calls[0].headers["OpenAI-Project"]).toBe("proj_tokyo");

      const resp = recorder([responsesReply()]);
      await build({ model: "openai.gpt-5.6-terra" }, { fetchImpl: resp.fetchImpl })("sys", []);
      // Mantle projects are regional: the Tokyo id means nothing in us-west-2.
      expect(resp.calls[0].headers["OpenAI-Project"]).toBe("proj_uswest");
    } finally {
      vi.unstubAllEnvs();
    }
  });
});
