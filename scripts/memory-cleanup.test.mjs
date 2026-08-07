// Unit tests for scripts/memory-cleanup.mjs (issue #102).
// Test IDs map to docs/test-cases/memory-cleanup.md. All I/O is faked through
// the injected deps object — no network, no real filesystem outside tmpdirs.
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  assertClaimParameterName,
  buildApprovalMessage,
  buildCompleteChat,
  buildOfferedRecord,
  buildOutcomeMessage,
  claimParameterName,
  contentHash,
  createCleanupDeps,
  inactiveMemoryAdapter,
  materializeApprovedIds,
  parseArgs,
  postApprovalRequest,
  updateApprovalMessage,
  consensusDecisions,
  parseVerdicts,
  planDecisions,
  runCleanup,
  runListInactive,
  runRestore,
  snippetLogDir,
  verdictSummary,
  ARG_SPECS,
  DURABLE_ONLY_RULES,
  TOPICS,
  USAGE,
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

// dirname(dirname(scripts/memory-cleanup.mjs)) — the same bound `snippetLogDir`
// computes, derived the same way rather than hardcoded, and shared by both tests
// of the guard so they cannot disagree about where the tree ends.
const SCRIPT_TREE = dirname(dirname(fileURLToPath(import.meta.url)));

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
      // `If-Match` FENCES the write (patch 0009, issue #128): a mismatch is 412
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

/**
 * LLM fake: verdictsByBatch is an array of responses (JSON string or object) per
 * call.
 *
 * Object-form verdicts get `topic: "engineering"` when the key is ABSENT, so the
 * fake models a classifier that honours the #123 contract and the pre-existing
 * cases stay about what they were written to test. Present-but-wrong is passed
 * through untouched (`topic: null`, `topic: "bogus"`), which is how a case
 * expresses a non-compliant response in object form; a raw JSON string is passed
 * through verbatim either way.
 */
function fakeLlm(verdictsByBatch) {
  let call = 0;
  return vi.fn(async () => {
    const v = verdictsByBatch[Math.min(call, verdictsByBatch.length - 1)];
    call += 1;
    if (typeof v === "string") return v;
    return JSON.stringify({ verdicts: v.map(withTopic) });
  });
}

const withTopic = (v) => ("topic" in v ? v : { ...v, topic: "engineering" });

/**
 * SSM/Secrets Manager double, keyed by parameter name.
 *
 * `GetParameters` is the only read the workload boundary admits, so an absent name
 * is echoed in `InvalidParameters` and simply MISSING from `Parameters` — never an
 * exception. Fakes that threw would let a script relying on a throw pass here and
 * silently read `undefined` in production.
 *
 * The name constraint is borrowed from the SERVICE (`assertClaimParameterName`)
 * rather than accepting any string: a Map-keyed fake is precisely why a claim name
 * carrying the `:` of `sha256:` passed this whole suite while PutParameter would
 * have rejected it on every real click (TC-SLACKAPP-131).
 */
function fakeAwsClient(values = {}) {
  const client = {
    sent: [],
    send: vi.fn(async (command) => {
      client.sent.push(command.input);
      if (command.input.Names) {
        for (const name of command.input.Names) assertClaimParameterName(name);
        const names = command.input.Names;
        return {
          Parameters: names
            .filter((name) => name in values)
            .map((name) => ({ Name: name, Value: values[name] })),
          InvalidParameters: names.filter((name) => !(name in values)),
        };
      }
      return { SecretString: values[command.input.SecretId] };
    }),
    destroy: () => {},
  };
  return client;
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

// `topic` is required on every verdict (#123 / TC-SLACKAPP-051), so the fakes
// emit it exactly as the real classifier now must. "engineering" is the neutral
// default here: it is NOT protected, so a case that means to exercise the
// protected-topic rule has to say so explicitly rather than inherit it.
const keepAll = (memories) =>
  memories.map((m) => ({ id: m.id, verdict: "KEEP", reason: "durable", topic: "engineering" }));

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

  it("TC-SLACKAPP-132 --ids refuses a MERGE outright, absorbed ids included", async () => {
    // The privilege-escalation hole this closes. `buildOfferedRecord` offers
    // DELETE verdicts only, so no MERGE can ever be in an approved list — but the
    // filter checked `approved.has(decision.id)` on the SURVIVOR only, and a
    // MERGE deletes its `absorbs[]` and rewrites the survivor's content. The
    // Slack-triggered task re-classifies instead of replaying the reviewed
    // artifact, so a fresh MERGE naming an approved id as its survivor deleted two
    // memories the operator never saw and exited 0 reporting success.
    const dir = tempDir();
    const server = fakeServer([
      memory("surv", "survivor"),
      memory("frag-1", "fragment one"),
      memory("frag-2", "fragment two"),
    ]);
    const llm = fakeLlm([
      [
        { id: "surv", verdict: "MERGE", reason: "r", merge_into: "surv", absorbs: ["frag-1", "frag-2"], merged_content: "MERGED" },
        { id: "frag-1", verdict: "MERGE", reason: "r", merge_into: "surv" },
        { id: "frag-2", verdict: "MERGE", reason: "r", merge_into: "surv" },
      ],
    ]);
    const idsFile = join(dir, "approved.txt");
    // The operator approved exactly the survivor id, as a DELETION.
    writeFileSync(idsFile, "surv\n");
    const deps = baseDeps(server, llm, dir);
    const result = await runCleanup(baseOpts({ apply: true, idsFile }), deps);

    // Nothing destroyed and nothing rewritten.
    expect(server.store.get("frag-1").state).toBe("active");
    expect(server.store.get("frag-2").state).toBe("active");
    expect(server.store.get("surv").state).toBe("active");
    expect(server.store.get("surv").content).toBe("survivor");
    expect(result.capUsed).toBe(0);
    // No write of ANY kind reached the server: asserted on the request log rather
    // than only on the store, because a PUT that happened to write identical
    // content would leave the store looking untouched.
    expect(server.calls.filter((c) => c.method !== "GET")).toEqual([]);
    // Counted AND logged: a silent skip is how a shortfall in the Slack outcome
    // message becomes unexplainable.
    expect(result.skippedByFilter).toBe(1);
    const logged = deps.log.mock.calls.map((c) => String(c[0])).join("\n");
    expect(logged).toMatch(/refused under an approved-ids run/u);
  });

  it("TC-SLACKAPP-132 an approved id the re-classifier now KEEPs is reported, not silently dropped", async () => {
    // The converse gap. An approved id whose fresh verdict is KEEP falls out at
    // `destructiveCost === 0`, so it incremented nothing: the outcome message said
    // "1 of 2 approved deletion(s)" with no note, which reads as a partial failure
    // rather than a changed verdict.
    const dir = tempDir();
    const server = fakeServer([memory("d1", "x"), memory("d2", "y")]);
    const llm = fakeLlm([
      [
        { id: "d1", verdict: "DELETE", reason: "noise" },
        { id: "d2", verdict: "KEEP", reason: "durable now" },
      ],
    ]);
    const idsFile = join(dir, "approved.txt");
    writeFileSync(idsFile, "d1\nd2\n");
    const result = await runCleanup(baseOpts({ apply: true, idsFile }), baseDeps(server, llm, dir));

    expect(server.store.get("d1").state).toBe("deleted");
    expect(server.store.get("d2").state).toBe("active");
    expect(result.reclassified).toBe(1);
    // Distinct from skippedByFilter: that counts things the operator did NOT
    // approve, this counts things they DID.
    expect(result.skippedByFilter).toBe(0);

    const message = buildOutcomeMessage({
      channel: "C1",
      messageTs: "1.1",
      hash: contentHash("d1\nd2"),
      stage: "test",
      approved: 2,
      result,
      appliedAt: "2026-08-05T04:00:00.000Z",
    });
    expect(JSON.stringify(message)).toMatch(/no longer classified as deletions/u);
  });

  it("TC-SLACKAPP-132 an approved id that matched no decision is not counted as reclassified", async () => {
    // The two counts must not describe one id two contradictory ways. An id that
    // appears in NO decision was never classified, so calling it "no longer
    // classified as deletions" tells the operator the classifier changed its mind
    // when in fact their list named something this run never saw — a typo, or an id
    // from a different stage. `runCleanup` already reports those BY NAME, and that
    // message is the one with the actionable fix.
    const dir = tempDir();
    const server = fakeServer([memory("d1", "x")]);
    const llm = fakeLlm([[{ id: "d1", verdict: "DELETE", reason: "noise" }]]);
    const idsFile = join(dir, "approved.txt");
    writeFileSync(idsFile, "d1\nd-typo\n");
    const deps = baseDeps(server, llm, dir);
    const result = await runCleanup(baseOpts({ apply: true, idsFile }), deps);

    expect(server.store.get("d1").state).toBe("deleted");
    expect(result.reclassified).toBe(0);
    expect(result.skippedByFilter).toBe(0);
    const logged = deps.log.mock.calls.map((c) => String(c[0])).join("\n");
    expect(logged).toMatch(/1 approved id\(s\) matched no decision: d-typo/u);
    expect(logged).not.toMatch(/no longer classified as deletions/u);

    const message = buildOutcomeMessage({
      channel: "C1",
      messageTs: "1.1",
      hash: contentHash("d1\nd-typo"),
      stage: "test",
      approved: 2,
      result,
      appliedAt: "2026-08-05T04:00:00.000Z",
    });
    expect(JSON.stringify(message)).not.toMatch(/no longer classified as deletions/u);
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
      JSON.stringify({
        verdicts: batch.map((m) => ({ id: m.id, verdict: "DELETE", reason: "noise", topic: "engineering" })),
      }),
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

describe("snippet log location", () => {
  it("TC-MEMRESTORE-064 the --out bound is the script's tree, and a sibling is not inside it", () => {
    // No --out: the documented default, outside any checkout.
    expect(snippetLogDir(undefined, "prod")).toBe(join(homedir(), ".mem9-cleanup", "prod"));
    expect(snippetLogDir("", "prod")).toBe(join(homedir(), ".mem9-cleanup", "prod"));

    // Inside, and the tree root itself — `relative` answers "" for the root, which
    // is why the guard tests the two `..` forms rather than truthiness of `inside`.
    // `..cache` is the case the `${sep}` in that check carries: a directory INSIDE
    // the tree whose NAME begins with `..`, which a bare `startsWith("..")` would
    // wave through as outside.
    for (const bad of [
      join(SCRIPT_TREE, "tmp"),
      join(SCRIPT_TREE, "docs", "x"),
      SCRIPT_TREE,
      join(SCRIPT_TREE, "..cache"),
      // The form an operator actually types. Bare and relative, resolved against
      // cwd — which for any invocation from a checkout is the checkout.
      "tmp-decisions",
    ]) {
      expect(() => snippetLogDir(bad, "prod")).toThrow(/must not be written into a checkout/u);
    }

    // A relative --out is resolved, not passed through: an accepted path comes
    // back absolute, so the caller cannot end up writing relative to a cwd that
    // has since changed.
    const relOut = join("..", "mem9-logs");
    expect(snippetLogDir(relOut, "prod")).toBe(resolve(relOut));

    // Outside: the parent, and — the case a `startsWith(scriptTree)` check gets
    // wrong — a sibling worktree whose name merely EXTENDS this one's. Refusing
    // it would lock an operator out of the adjacent checkout for no reason.
    const sibling = `${SCRIPT_TREE}-other`;
    expect(snippetLogDir(sibling, "prod")).toBe(sibling);
    expect(snippetLogDir(dirname(SCRIPT_TREE), "prod")).toBe(dirname(SCRIPT_TREE));
    expect(snippetLogDir("/tmp/mem9-logs", "prod")).toBe(resolve("/tmp/mem9-logs"));
  });

  it("TC-MEMCLEAN-082 a cleanup --out inside the checkout is refused before the scan", async () => {
    // The guard's other call site. It first sat at the write inside
    // `loadDecisions`, which runs AFTER the scan and the whole classification
    // pass: `--out ./tmp` on a prod dry run burned a reasoning-model run at
    // `--effort high`, then threw and discarded every decision — the entire
    // artifact of a dry run. Untested, that regression is invisible.
    const inCheckout = join(SCRIPT_TREE, "tmp-decision-logs");
    const server = fakeServer([memory("m-1", "x")]);
    const llm = fakeLlm([[{ id: "m-1", verdict: "DELETE", reason: "stale" }]]);
    await expect(runCleanup(baseOpts(), baseDeps(server, llm, inCheckout))).rejects.toThrow(
      /must not be written into a checkout/u,
    );
    expect(llm).not.toHaveBeenCalled();
    expect(server.fetchImpl).not.toHaveBeenCalled();
    expect(existsSync(inCheckout)).toBe(false);
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
    expect(parseVerdicts('{"verdicts":[{"id":"a","verdict":"KEEP","reason":"r","topic":"engineering"}]}')).toEqual([
      { id: "a", verdict: "KEEP", reason: "r", topic: "engineering" },
    ]);
    expect(() => parseVerdicts("nope")).toThrow();
    expect(() => parseVerdicts('{"verdicts":"x"}')).toThrow();
    expect(() => parseVerdicts('{"verdicts":[{"id":"a","verdict":"EXPLODE"}]}')).toThrow(/verdict/i);
  });

  it("TC-SLACKAPP-050 every known topic parses and survives onto the verdict", () => {
    for (const topic of TOPICS) {
      const [v] = parseVerdicts(
        JSON.stringify({ verdicts: [{ id: "a", verdict: "KEEP", reason: "r", topic }] }),
      );
      expect(v.topic).toBe(topic);
    }
    // The set itself is pinned: silently adding a sixth topic would let the
    // classifier route finance memories somewhere `protectedTopics` never looks.
    expect([...TOPICS].sort()).toEqual([
      "content",
      "engineering",
      "operations",
      "other",
      "personal-finance",
    ]);
  });

  it("TC-SLACKAPP-051 a missing topic is malformed, never defaulted to `other`", () => {
    expect(() =>
      parseVerdicts('{"verdicts":[{"id":"a","verdict":"DELETE","reason":"r"}]}'),
    ).toThrow(/topic/iu);
    // Defaulting is the specific hazard: `other` is unprotected, so a batch
    // whose model forgot the field would have every personal-finance memory in
    // it silently eligible for deletion.
    expect(() =>
      parseVerdicts('{"verdicts":[{"id":"a","verdict":"KEEP","reason":"r"}]}'),
    ).toThrow(/topic/iu);
  });

  it("TC-SLACKAPP-052 an unknown topic is malformed and the message never echoes it", () => {
    const secretish = "personal-finance-但是我的密码是 hunter2";
    let caught;
    try {
      parseVerdicts(
        JSON.stringify({ verdicts: [{ id: "a", verdict: "KEEP", reason: "r", topic: secretish }] }),
      );
    } catch (err) {
      caught = err;
    }
    expect(caught?.name).toBe("MalformedResponse");
    expect(caught.message).toMatch(/topic/iu);
    // Fixed strings only — a response can carry memory content, and this error
    // is logged.
    expect(caught.message).not.toContain(secretish);
    expect(caught.message).not.toContain("hunter2");
  });

  it("TC-SLACKAPP-053 a non-string topic is malformed, not a crash mid-plan", () => {
    for (const topic of [["personal-finance"], { name: "other" }, 7, null, true]) {
      expect(() =>
        parseVerdicts(JSON.stringify({ verdicts: [{ id: "a", verdict: "KEEP", reason: "r", topic }] })),
      ).toThrow(/topic/iu);
    }
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
    // which patch 0009 rejects as a 400 that aborts the run mid-apply, after
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

  it("planDecisions still logs a decision for every scanned id when a merge is unfenceable (TC-MEMCLEAN-051)", () => {
    // Audit completeness (TC-MEMCLEAN-021) is not suspended by the fence guard.
    // A rejected merge must be non-emitting BEFORE its absorbed ids are folded
    // away, exactly like the skip/verdict/missing-content rejections above it —
    // otherwise the absorbed id is neither merged nor reported and the decision
    // log silently loses a row the operator scanned.
    for (const unfenceable of ["s", "a"]) {
      const mems = [memory("s", "survivor"), memory("a", "absorbed")].map((m) =>
        m.id === unfenceable ? { ...m, version: null } : m,
      );
      const out = planDecisions(mems, [
        { id: "s", verdict: "MERGE", reason: "r", merge_into: "s", absorbs: ["a"], merged_content: "x" },
        { id: "a", verdict: "MERGE", reason: "r", merge_into: "s" },
      ]);
      expect(
        out.map((d) => d.id).sort(),
        `unfenceable ${unfenceable}: every scanned id needs a decision row`,
      ).toEqual(["a", "s"]);
      expect(out.some((d) => d.verdict === "MERGE")).toBe(false);
    }
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

    // The survivor's version is the `If-Match` value. Post-patch-0009 an absent
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
    const verdicts =
      '{"verdicts":[{"id":"m1","verdict":"KEEP","reason":"durable","topic":"engineering"}]}';
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
    expect(parseVerdicts(raw)).toEqual([
      { id: "m1", verdict: "KEEP", reason: "durable", topic: "engineering" },
    ]);
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
            { id: s1.id, verdict: "MERGE", reason: "frags", merge_into: s1.id, topic: "engineering",
              absorbs: [a1.id, a2.id], merged_content: "merged fact" },
            { id: a1.id, verdict: "MERGE", reason: "frags", merge_into: s1.id, topic: "engineering" },
            { id: a2.id, verdict: "MERGE", reason: "frags", merge_into: s1.id, topic: "engineering" },
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

  it("TC-SLACKAPP-054 a topic failure retries once then SKIPs the batch, like any malformed response", async () => {
    // The spec's stated cost, asserted rather than assumed: requiring `topic` on
    // EVERY verdict means a response that omits it batch-SKIPs the plain #102
    // path too, including the scheduled weekly run. That is only acceptable if a
    // topic failure lands in the SAME machinery as any other malformed response
    // — one retry, then a non-destructive whole-batch SKIP that the
    // "how much went unaudited" note counts. A topic check bolted on somewhere
    // that bypasses `classifyBatch`'s retry, or that produces a SKIP the
    // UNCLASSIFIED note does not recognise, would turn a recoverable hiccup into
    // a silently unaudited corpus.
    const memories = Array.from({ length: 40 }, (_, i) => memory(`m-${i}`, `fact ${i}`));
    const server = fakeServer(memories);
    let call = 0;
    const llm = vi.fn(async (_p, batch) => {
      call += 1;
      // Batch 0 omits `topic` on BOTH attempts; batch 1 is well-formed.
      if (call <= CLASSIFY_ATTEMPTS) {
        return JSON.stringify({
          verdicts: batch.map((m) => ({ id: m.id, verdict: "DELETE", reason: "stale" })),
        });
      }
      return JSON.stringify({ verdicts: keepAll(batch) });
    });
    const deps = baseDeps(server, llm, tempDir());
    const result = await runCleanup(baseOpts(), deps);

    // Retried exactly once, not indefinitely and not zero times.
    expect(llm).toHaveBeenCalledTimes(CLASSIFY_ATTEMPTS + 1);

    // The failed batch is SKIP with the SAME reason string the note counts —
    // not a new "bad topic" reason that the accounting would miss.
    const skipped = result.decisions.filter((d) => d.verdict === "SKIP");
    expect(skipped).toHaveLength(20);
    for (const d of skipped) {
      expect(d.reason).toBe("classification failed after retry");
    }
    // Non-destructive: the batch the classifier wanted to DELETE yields no
    // DELETE decision at all.
    expect(result.decisions.some((d) => d.verdict === "DELETE")).toBe(false);

    // Counted by the unaudited note, and the retry log names the topic failure
    // so an operator can tell a prompt-contract break from a transport outage.
    const summaryLine = deps.log.mock.calls.map((c) => c[0]).find((m) => m.startsWith("dry-run:"));
    expect(summaryLine).toMatch(/UNCLASSIFIED=20 of 40 memories \(1\/2 batches failed, 50%\)/);
    const attempts = deps.log.mock.calls
      .map((c) => c[0])
      .filter((m) => /classification batch 0 attempt \d failed/u.test(m));
    expect(attempts).toHaveLength(CLASSIFY_ATTEMPTS);
    for (const line of attempts) expect(line).toMatch(/topic/iu);
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

// ---------------------------------------------------------------------------
// Inactive listing & restore (TC-MEMRESTORE-001..070) — issue #124.
// Test IDs map to docs/test-cases/memory-restore.md.
//
// The REST surface cannot reach these rows at all: upstream's GetByID and list
// both select `WHERE state = 'active'` (the fakeServer above 404s a deleted id
// for exactly that reason), so recovery has to go through SQL. #103 already
// does, and this file's `productionDatabaseMutex` already holds a `pg` client,
// so the tests below fake the client rather than the HTTP layer.

/** Row as `memories` stores it — snake_case, because the adapter reads raw rows. */
function inactiveRow(id, state, overrides = {}) {
  return {
    id,
    content: `fact about ${id}`,
    state,
    version: 3,
    updated_at: new Date("2026-06-01T09:00:00Z"),
    // #103 sets this when it archives the loser of a contradiction; #102's
    // soft delete never does. The asymmetry is the whole point of TC-040..042.
    superseded_by: state === "archived" ? `winner-of-${id}` : null,
    ...overrides,
  };
}

/**
 * Minimal `pg` client fake: records every statement, and answers the ones the
 * test names. Statements are matched on a substring so the assertions stay on
 * the SQL the adapter actually built (values included) rather than on a mock's
 * return shape.
 *
 * Handlers are tried in declaration order and a COUNT also reads `FROM
 * memories`, so declare the narrower `"count("` key first wherever both are
 * needed — otherwise the count silently answers with the listing's rows.
 *
 * Every statement is checked for placeholder/values arity, because that is the
 * one class of bug a permissive fake hides completely: real Postgres rejects a
 * surplus bind outright ("Expected 1 parameters but got 2"), so a statement that
 * this fake answers happily can still be a hard runtime error. Sharing one
 * mutable values array across two statements is how that happens.
 */
function fakeDb(handlers = {}) {
  const queries = [];
  const query = vi.fn(async (text, values = []) => {
    assertBindArity(text, values);
    queries.push({ text, values });
    for (const [needle, handler] of Object.entries(handlers)) {
      if (text.includes(needle)) return handler(values);
    }
    return { rows: [], rowCount: 0 };
  });
  return { queries, query };
}

/**
 * Reject what the server would reject: the highest `$n` referenced must equal
 * the number of values supplied, and every index below it must be referenced.
 */
function assertBindArity(text, values) {
  const referenced = new Set(
    [...text.matchAll(/\$(\d+)/gu)].map((m) => Number(m[1])),
  );
  const highest = referenced.size ? Math.max(...referenced) : 0;
  const missing = Array.from({ length: highest }, (_, i) => i + 1).filter(
    (n) => !referenced.has(n),
  );
  const detail = `${JSON.stringify(text)} values=${JSON.stringify(values)}`;
  expect(missing, `unreferenced placeholder(s) in ${detail}`).toEqual([]);
  expect(
    values.length,
    `bind arity mismatch: statement uses $1..$${highest} in ${detail}`,
  ).toBe(highest);
}

const restoreOpts = (overrides = {}) => ({
  stage: "test",
  apply: false,
  cap: 50,
  force: false,
  ...overrides,
});

function restoreDeps(overrides = {}) {
  return {
    log: vi.fn(),
    outDir: overrides.outDir,
    clock: () => new Date("2026-08-05T00:00:00Z").getTime(),
    // Restore must never re-embed: `vector(1024)` survived the soft delete
    // (schema.sql line 76). Any HTTP call would go through here, so an
    // untouched spy is the evidence (TC-MEMRESTORE-044).
    fetchImpl: vi.fn(async () => {
      throw new Error("restore must not make HTTP calls");
    }),
    ...overrides,
  };
}

describe("inactive-memory SQL adapter", () => {
  it("TC-MEMRESTORE-020 filters by state and never returns active rows", async () => {
    // The count handler is declared first and is no longer optional: the total
    // is the truncation signal, so the adapter refuses a count that answered
    // nothing rather than defaulting the denominator (TC-MEMRESTORE-024).
    const db = fakeDb({
      "count(": () => ({ rows: [{ total: "1" }] }),
      "FROM memories": () => ({ rows: [inactiveRow("d-1", "deleted")] }),
    });
    const adapter = inactiveMemoryAdapter(db);

    await adapter.listInactive({ state: "deleted" });
    const scoped = db.queries.at(-1);
    // `state = $n` alone is not enough: an unparameterised or absent state
    // predicate would still return rows and read as a successful filter.
    expect(scoped.values).toContain("deleted");
    expect(scoped.text).toMatch(/state\s*=\s*\$\d/u);

    await adapter.listInactive({});
    const both = db.queries.at(-1);
    // With no --state the query must still exclude active rows. A bare
    // `SELECT ... FROM memories` would list the entire corpus, which for a
    // 2811-memory store is not a listing an operator can review.
    expect(both.text).toMatch(/state\s*(<>|!=)\s*'active'|state\s+IN\s*\(\s*'archived'\s*,\s*'deleted'\s*\)|state\s+IN\s*\(\s*'deleted'\s*,\s*'archived'\s*\)/u);
    expect(both.values).not.toContain("active");
  });

  it("TC-MEMRESTORE-021 --since filters updated_at, the only timestamp that exists", async () => {
    const db = fakeDb({ "count(": () => ({ rows: [{ total: "0" }] }), "FROM memories": () => ({ rows: [] }) });
    const adapter = inactiveMemoryAdapter(db);
    await adapter.listInactive({ since: "2026-07-01T00:00:00Z" });
    const { text, values } = db.queries.at(-1);
    // There is no `memories.deleted_at` — only `tenants` has one (schema.sql
    // line 40). A query that referenced one would fail at runtime against the
    // real database, so pin the column here where it is cheap to catch.
    expect(text).not.toMatch(/deleted_at/u);
    expect(text).toMatch(/updated_at\s*>=?\s*\$\d/u);
    expect(values).toContain("2026-07-01T00:00:00Z");
  });

  it("TC-MEMRESTORE-022 --limit bounds the rows but the total is counted unbounded", async () => {
    const db = fakeDb({
      "count(": () => ({ rows: [{ total: "42" }] }),
      "FROM memories": (values) =>
        // Mirror LIMIT: the fake returns as many rows as asked for, so a
        // missing LIMIT shows up as an unbounded listing rather than passing.
        ({ rows: Array.from({ length: Math.min(5, values.at(-1) ?? 5) }, (_, i) => inactiveRow(`d-${i}`, "deleted")) }),
    });
    const adapter = inactiveMemoryAdapter(db);
    const page = await adapter.listInactive({ limit: 2 });
    expect(page.rows).toHaveLength(2);
    // A silent cap is the failure mode: 2 of 42 must never read as "42 is all
    // there is", so the total comes from a separate unbounded COUNT.
    expect(page.total).toBe(42);
    const counted = db.queries.find((q) => /count\(/iu.test(q.text));
    expect(counted).toBeDefined();
    expect(counted.text).not.toMatch(/LIMIT/iu);

    // The count and the page must not share one values array. `fakeDb` records
    // the array by reference, so if the page appended its LIMIT parameter to the
    // count's array, the count would be recorded here carrying a parameter its
    // SQL never references. That reads as a surplus bind — which real Postgres
    // rejects outright — even when the live call happened to be well-formed.
    expect(counted.values).toHaveLength(0);
    expect(counted.values).not.toBe(db.queries.at(-1).values);
  });

  it("TC-MEMRESTORE-041 the restore UPDATE is fenced, preserves version, and touches nothing else", async () => {
    const db = fakeDb({ "UPDATE memories": () => ({ rowCount: 1 }) });
    const adapter = inactiveMemoryAdapter(db);
    const ok = await adapter.restoreMemory({ id: "a-1", priorState: "archived", version: 7 });
    expect(ok).toBe(true);
    const { text, values } = db.queries.at(-1);

    // Fenced on BOTH the observed state and version. Without the state
    // predicate a row someone else already restored (and then edited) would be
    // re-"restored" over their change; without the version predicate the write
    // is unprotected in exactly the way #128 fixed for the merge path.
    expect(text).toMatch(/state\s*=\s*\$\d/u);
    expect(text).toMatch(/version\s*=\s*\$\d/u);
    expect(values).toEqual(expect.arrayContaining(["a-1", "archived", 7]));

    // `version` is the concurrency token #128's If-Match compares against.
    // Restore changes no content, so bumping it would invalidate a concurrent
    // writer's fence for nothing. Preserved, and asserted because either
    // choice is defensible and silence is not (TC-MEMRESTORE-045).
    expect(text).not.toMatch(/version\s*=\s*version\s*\+/u);

    // `superseded_by` is PRESERVED for an archived row: it is the audit link to
    // the winner and #103's handle on the pair. Clearing it would make a
    // resurrected contradiction look like an ordinary independent memory.
    expect(text).not.toMatch(/superseded_by\s*=/u);

    // The embedding survived the soft delete, so restore must not clear or
    // rewrite it — that would silently drop the row out of vector search while
    // reporting a successful restore.
    expect(text).not.toMatch(/embedding/iu);

    // A lost fence is reported, not swallowed.
    const stale = fakeDb({ "UPDATE memories": () => ({ rowCount: 0 }) });
    expect(
      await inactiveMemoryAdapter(stale).restoreMemory({ id: "a-1", priorState: "deleted", version: 1 }),
    ).toBe(false);
  });

  it("TC-MEMRESTORE-045 the restore UPDATE sets exactly one column", async () => {
    const db = fakeDb({ "UPDATE memories": () => ({ rowCount: 1 }) });
    await inactiveMemoryAdapter(db).restoreMemory({ id: "a", priorState: "deleted", version: 1 });
    const setClause = db.queries.at(-1).text.match(/SET([\s\S]*?)WHERE/iu)[1];
    // Enumerated rather than spot-checked: a future edit that adds a column to
    // the SET clause has to come through this assertion and say why.
    expect(setClause.match(/\w+\s*=/gu).map((s) => s.replace(/\s*=$/u, ""))).toEqual(["state"]);
    expect(setClause).toMatch(/'active'/u);
  });

  it("findByIds reads the pre-restore state, version, and updated_at for the log", async () => {
    const db = fakeDb({ "FROM memories": () => ({ rows: [inactiveRow("d-1", "deleted")] }) });
    await inactiveMemoryAdapter(db).findByIds(["d-1", "d-2"]);
    const { text, values } = db.queries.at(-1);
    // Parameterised as an array, never interpolated: ids come from an operator
    // file, and this is a destructive tool holding a live database connection.
    expect(text).toMatch(/id\s*=\s*ANY\s*\(\s*\$1\s*\)/u);
    expect(values[0]).toEqual(["d-1", "d-2"]);
    // The pre-restore `updated_at` cannot be recovered afterwards:
    // trg_memories_updated is BEFORE UPDATE and unconditionally assigns NOW()
    // (schema.sql 105-111), so it has to be read here.
    for (const column of ["state", "version", "updated_at", "superseded_by"]) {
      expect(text).toContain(column);
    }
    // Deliberately NOT scoped to inactive rows: an already-active id must come
    // back so restore can report it as a no-op instead of "not found"
    // (TC-MEMRESTORE-034 vs 035).
    expect(text).not.toMatch(/state\s*(<>|!=)\s*'active'/u);
  });
});

describe("--list-inactive", () => {
  it("TC-MEMRESTORE-001 reports id, state, updated_at, superseded_by and a snippet, with zero writes", async () => {
    const rows = [inactiveRow("d-1", "deleted"), inactiveRow("a-1", "archived")];
    const db = fakeDb({
      "count(": () => ({ rows: [{ total: "2" }] }),
      "FROM memories": () => ({ rows }),
    });
    const deps = restoreDeps({ db });
    const result = await runListInactive(restoreOpts(), deps);

    expect(result.exitCode).toBe(0);
    expect(result.rows).toHaveLength(2);
    expect(result.rows[0]).toMatchObject({
      id: "d-1",
      state: "deleted",
      superseded_by: null,
      snippet: "fact about d-1",
    });
    expect(result.rows[0].updated_at).toBe("2026-06-01T09:00:00.000Z");
    // The archived row carries its winner, which is what makes the --force
    // refusal message in TC-040 actionable.
    expect(result.rows[1]).toMatchObject({ state: "archived", superseded_by: "winner-of-a-1" });

    // Read-only means read-only: a listing that mutated anything would be a
    // recovery tool an operator cannot safely run against prod to look around.
    expect(db.queries.every((q) => /^\s*SELECT/iu.test(q.text))).toBe(true);
    expect(result.writes).toBe(0);
    expect(deps.fetchImpl).not.toHaveBeenCalled();
  });

  it("TC-MEMRESTORE-003 an empty result says so instead of printing nothing", async () => {
    const db = fakeDb({ "count(": () => ({ rows: [{ total: "0" }] }), "FROM memories": () => ({ rows: [] }) });
    const deps = restoreDeps({ db });
    const result = await runListInactive(restoreOpts(), deps);
    expect(result.exitCode).toBe(0);
    expect(result.rows).toHaveLength(0);
    // A bare empty listing is indistinguishable from a broken query or a
    // wrong-stage connection, which is the moment an operator most needs to
    // know which one happened.
    expect(deps.log).toHaveBeenCalledWith(expect.stringMatching(/no inactive memories/iu));
  });

  it("TC-MEMRESTORE-004 snippets are bounded, marked when truncated, and single-line", async () => {
    const long = "x".repeat(400);
    const db = fakeDb({
      "count(": () => ({ rows: [{ total: "2" }] }),
      "FROM memories": () => ({
        rows: [
          inactiveRow("long", "deleted", { content: long }),
          inactiveRow("multi", "deleted", { content: "line one\nline two\nline three" }),
        ],
      }),
    });
    const result = await runListInactive(restoreOpts(), restoreDeps({ db }));
    const [longRow, multiRow] = result.rows;
    expect(longRow.snippet.length).toBeLessThanOrEqual(120);
    expect(longRow.truncated).toBe(true);
    // Unmarked truncation invites an operator to restore or discard a memory
    // based on a sentence that was never the whole sentence.
    expect(multiRow.truncated).toBe(false);
    // One record per line keeps the output greppable; an embedded newline would
    // split one memory across what looks like three records.
    expect(multiRow.snippet).not.toContain("\n");
    expect(multiRow.snippet).toContain("line one");
  });

  it("TC-MEMRESTORE-005 listing takes no lock, so two concurrent listings both succeed", async () => {
    const db = fakeDb({ "count(": () => ({ rows: [{ total: "0" }] }), "FROM memories": () => ({ rows: [] }) });
    const acquireMutex = vi.fn(async () => null);
    const deps = restoreDeps({ db, acquireMutex });
    const [a, b] = await Promise.all([
      runListInactive(restoreOpts(), deps),
      runListInactive(restoreOpts(), deps),
    ]);
    expect(a.exitCode).toBe(0);
    expect(b.exitCode).toBe(0);
    // Taking the shared apply mutex here would let a long weekly consolidation
    // block an operator from even looking at what was deleted.
    expect(acquireMutex).not.toHaveBeenCalled();
  });

  it("TC-MEMRESTORE-022 a truncated listing reports the total it was truncated from", async () => {
    const db = fakeDb({
      "count(": () => ({ rows: [{ total: "42" }] }),
      "FROM memories": () => ({ rows: [inactiveRow("d-1", "deleted")] }),
    });
    const deps = restoreDeps({ db });
    const result = await runListInactive(restoreOpts({ limit: 1 }), deps);
    expect(result.total).toBe(42);
    expect(deps.log).toHaveBeenCalledWith(expect.stringMatching(/1 of 42/u));
  });

  it("TC-MEMRESTORE-021 the output names updated_at as the column --since filtered", async () => {
    const db = fakeDb({
      "count(": () => ({ rows: [{ total: "1" }] }),
      "FROM memories": () => ({ rows: [inactiveRow("d-1", "deleted")] }),
    });
    const deps = restoreDeps({ db });
    await runListInactive(restoreOpts({ since: "2026-07-01T00:00:00Z" }), deps);
    // Documenting the limitation in --help is not enough: the operator reading
    // this listing is deciding what to restore from it, and a row deleted long
    // ago but touched since is in the result set. `deleted_at` does not exist.
    expect(deps.log).toHaveBeenCalledWith(
      expect.stringMatching(/updated_at[\s\S]*deleted_at/u),
    );
  });

  it("TC-MEMRESTORE-020/021 an empty listing echoes back the filters it applied", async () => {
    const db = fakeDb({ "count(": () => ({ rows: [{ total: "0" }] }), "FROM memories": () => ({ rows: [] }) });
    const deps = restoreDeps({ db });
    await runListInactive(
      restoreOpts({ state: "archived", since: "2026-07-01T00:00:00Z" }),
      deps,
    );
    // "No results" plus the filters is diagnosable; "no results" alone leaves an
    // operator unable to tell a too-narrow filter from an empty corpus.
    const [message] = deps.log.mock.calls.at(-1);
    expect(message).toMatch(/state=archived/u);
    expect(message).toMatch(/since=2026-07-01T00:00:00Z/u);
  });

  it("TC-MEMRESTORE-023 one unreadable updated_at marks that row, and never kills the listing", async () => {
    const db = fakeDb({
      "count(": () => ({ rows: [{ total: "3" }] }),
      "FROM memories": () => ({
        rows: [
          inactiveRow("d-1", "deleted"),
          inactiveRow("d-bad", "deleted", { updated_at: "not a timestamp" }),
          inactiveRow("d-3", "deleted"),
        ],
      }),
    });
    const deps = restoreDeps({ db });
    // `new Date("not a timestamp").toISOString()` throws RangeError: Invalid
    // time value — with no id, no column, and no row in the message. One
    // unexpected value must not take down the operator's only view into
    // inactive data, and the row it came from has to be identifiable.
    const result = await runListInactive(restoreOpts(), deps);
    expect(result.exitCode).toBe(0);
    expect(result.rows.map((r) => r.id)).toEqual(["d-1", "d-bad", "d-3"]);
    const bad = result.rows.find((r) => r.id === "d-bad");
    expect(bad.updated_at).toBeNull();
    expect(deps.log).toHaveBeenCalledWith(expect.stringMatching(/d-bad[\s\S]*updated_at/u));
  });

  it("TC-MEMRESTORE-024 a COUNT that answers nothing throws instead of printing 'of 0'", async () => {
    // The denominator is the whole truncation signal: "listed 100 of 2811" is
    // how an operator learns the page is partial. `?? 0` on a missing count row
    // prints "listed 1 of 0" and exits 0 — a default masking a failed query,
    // not an absent value.
    const missing = fakeDb({ "count(": () => ({ rows: [] }), "FROM memories": () => ({ rows: [inactiveRow("d-1", "deleted")] }) });
    await expect(runListInactive(restoreOpts(), restoreDeps({ db: missing }))).rejects.toThrow(/count/iu);

    const renamed = fakeDb({ "count(": () => ({ rows: [{ tally: "7" }] }), "FROM memories": () => ({ rows: [inactiveRow("d-1", "deleted")] }) });
    await expect(runListInactive(restoreOpts(), restoreDeps({ db: renamed }))).rejects.toThrow(/count/iu);
  });

  it("TC-MEMRESTORE-001 accepts a pre-built adapter, which is how the CLI supplies it", async () => {
    // `recoveryDeps` spreads `inactiveMemoryAdapter(db)` into deps, so in
    // production this branch is the ONLY one taken — untested, it would be the
    // one seam that unit tests never reach.
    const listInactive = vi.fn(async () => ({ rows: [inactiveRow("d-1", "deleted")], total: 1 }));
    const result = await runListInactive(restoreOpts(), restoreDeps({ listInactive, db: undefined }));
    expect(listInactive).toHaveBeenCalledOnce();
    expect(result.rows[0].id).toBe("d-1");
  });
});

describe("--restore", () => {
  function idsFile(dir, ids) {
    const path = join(dir, "ids.txt");
    writeFileSync(path, `${ids.join("\n")}\n`);
    return path;
  }

  function applyDeps(dir, rows, overrides = {}) {
    const store = new Map(rows.map((r) => [r.id, { ...r }]));
    const restoreMemory = vi.fn(async ({ id, priorState, version }) => {
      const row = store.get(id);
      if (!row || row.state !== priorState || row.version !== version) return false;
      row.state = "active";
      return true;
    });
    return {
      store,
      restoreMemory,
      deps: restoreDeps({
        outDir: dir,
        lockFile: join(dir, "restore.lock"),
        findByIds: vi.fn(async (ids) => ids.map((id) => store.get(id)).filter(Boolean)),
        restoreMemory,
        ...overrides,
      }),
    };
  }

  it("TC-MEMRESTORE-030 dry-run is the default: zero writes, full plan printed", async () => {
    const dir = tempDir();
    const { deps, store, restoreMemory } = applyDeps(dir, [inactiveRow("d-1", "deleted")]);
    const result = await runRestore(
      restoreOpts({ idsFile: idsFile(dir, ["d-1"]) }),
      deps,
    );
    // Consistent with #102: the destructive verb is --apply, never the absence
    // of a guard flag. An operator's first run must not change anything.
    expect(restoreMemory).not.toHaveBeenCalled();
    expect(store.get("d-1").state).toBe("deleted");
    expect(result.exitCode).toBe(0);
    expect(result.planned).toEqual(["d-1"]);
    expect(deps.log).toHaveBeenCalledWith(expect.stringMatching(/dry-run/iu));
  });

  it("TC-MEMRESTORE-031 --apply flips listed ids to active, fenced on what was read", async () => {
    const dir = tempDir();
    const { deps, store, restoreMemory } = applyDeps(dir, [
      inactiveRow("d-1", "deleted", { version: 4 }),
      inactiveRow("d-2", "deleted", { version: 9 }),
    ]);
    const result = await runRestore(
      restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1", "d-2"]) }),
      deps,
    );
    expect(result.exitCode).toBe(0);
    expect(result.restored).toEqual(["d-1", "d-2"]);
    expect(store.get("d-1").state).toBe("active");
    expect(store.get("d-2").state).toBe("active");
    // Each write carries the version and state that were actually observed for
    // THAT row — not a shared or defaulted anchor.
    expect(restoreMemory).toHaveBeenCalledWith(
      expect.objectContaining({ id: "d-1", priorState: "deleted", version: 4 }),
    );
    expect(restoreMemory).toHaveBeenCalledWith(
      expect.objectContaining({ id: "d-2", priorState: "deleted", version: 9 }),
    );
  });

  it("TC-MEMRESTORE-032 cap reserves one mutation per id and aborts before overflowing", async () => {
    const dir = tempDir();
    const rows = ["d-1", "d-2", "d-3"].map((id) => inactiveRow(id, "deleted"));
    const { deps, store, restoreMemory } = applyDeps(dir, rows);
    const result = await runRestore(
      restoreOpts({ apply: true, cap: 2, idsFile: idsFile(dir, ["d-1", "d-2", "d-3"]) }),
      deps,
    );
    expect(result.exitCode).toBe(4);
    expect(restoreMemory).toHaveBeenCalledTimes(2);
    expect(store.get("d-3").state).toBe("deleted");
    expect(result.capUsed).toBe(2);
    // Silent truncation at the cap would read as "all three restored".
    expect(deps.log).toHaveBeenCalledWith(expect.stringMatching(/cap/iu));
    // The log is written even though the run aborted — this is the ONE run
    // guaranteed to be partial, so it is the run whose record matters most. An
    // early return on abort would lose the record of the ids that DID change.
    const aborted = JSON.parse(readFileSync(result.logPath, "utf8"));
    expect(aborted.entries.map((e) => e.id)).toEqual(["d-1", "d-2"]);
    expect(aborted.entries.every((e) => e.outcome === "restored")).toBe(true);

    // Exact hit (used == cap) is allowed, not off-by-one refused.
    const dir2 = tempDir();
    const exact = applyDeps(dir2, rows.map((r) => ({ ...r })));
    const ok = await runRestore(
      restoreOpts({ apply: true, cap: 3, idsFile: idsFile(dir2, ["d-1", "d-2", "d-3"]) }),
      exact.deps,
    );
    expect(ok.exitCode).toBe(0);
    expect(ok.capUsed).toBe(3);
  });

  it("TC-MEMRESTORE-033 a second concurrent restore refuses; a stale lock with a dead holder is reclaimed", async () => {
    const dir = tempDir();
    const lockFile = join(dir, "stage.lock");
    const host = (await import("node:os")).hostname();
    const rows = [inactiveRow("d-1", "deleted")];

    writeFileSync(lockFile, JSON.stringify({ pid: 99999, host, at: Date.now() }));
    const held = applyDeps(dir, rows, { lockFile, clock: () => Date.now() });
    const blocked = await runRestore(
      restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1"]) }),
      held.deps,
    );
    expect(blocked.exitCode).toBe(3);
    expect(held.store.get("d-1").state).toBe("deleted");

    writeFileSync(lockFile, JSON.stringify({ pid: 999999999, host, at: Date.now() - 3 * 3600 * 1000 }));
    const stale = applyDeps(dir, rows, { lockFile, clock: () => Date.now() });
    const reclaimed = await runRestore(
      restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1"]) }),
      stale.deps,
    );
    // Without reclaim, one crashed run locks the operator out of recovery
    // permanently — the worst possible time for that.
    expect(reclaimed.exitCode).toBe(0);
    expect(stale.store.get("d-1").state).toBe("active");
  });

  it("TC-MEMRESTORE-033 restore shares the database apply mutex with cleanup and consolidation", async () => {
    const dir = tempDir();
    const acquireMutex = vi.fn(async () => null);
    const held = applyDeps(dir, [inactiveRow("d-1", "deleted")], { acquireMutex });
    const blocked = await runRestore(
      restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1"]) }),
      held.deps,
    );
    // A restore racing consolidation could re-activate the loser of a
    // contradiction while #103 is mid-resolution on the same pair.
    expect(acquireMutex).toHaveBeenCalledWith("test");
    expect(blocked.exitCode).toBe(3);
    expect(held.store.get("d-1").state).toBe("deleted");

    const release = vi.fn(async () => {});
    const ok = applyDeps(dir, [inactiveRow("d-1", "deleted")], {
      acquireMutex: vi.fn(async () => ({ release })),
    });
    await runRestore(restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1"]) }), ok.deps);
    // Released even on the happy path, or the next weekly run finds it held.
    expect(release).toHaveBeenCalledOnce();
  });

  it("TC-MEMRESTORE-033 the mutex is taken before the lockfile and released if the lockfile is held", async () => {
    const dir = tempDir();
    const lockFile = join(dir, "ordering.lock");
    const host = (await import("node:os")).hostname();
    // A live holder, so acquireLock fails and the run bails out AFTER the mutex
    // was already taken.
    writeFileSync(lockFile, JSON.stringify({ pid: process.pid, host, at: Date.now() }));

    const order = [];
    const release = vi.fn(async () => {
      order.push("release");
    });
    const acquireMutex = vi.fn(async () => {
      order.push("mutex");
      return { release };
    });
    const ctx = applyDeps(dir, [inactiveRow("d-1", "deleted")], {
      lockFile,
      acquireMutex,
      clock: () => Date.now(),
    });
    const result = await runRestore(
      restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1"]) }),
      ctx.deps,
    );
    expect(result.exitCode).toBe(3);
    // Bailing out on the lockfile while still holding the shared mutex blocks
    // the next weekly consolidation until something else releases it — and
    // nothing else will.
    expect(release).toHaveBeenCalledOnce();
    // Ordering, not just release: the mutex is acquired first, so a run that
    // loses the lockfile race has already taken and given back the mutex.
    expect(order).toEqual(["mutex", "release"]);

    // And the same order in `runCleanup`, observed the same way. Two writers
    // that acquire the same two locks in opposite orders deadlock; that failure
    // appears only under real concurrency, never in CI, so both orders are
    // pinned rather than left to match by luck.
    const cleanupOrder = [];
    const cleanupLock = join(dir, "cleanup-ordering.lock");
    writeFileSync(cleanupLock, JSON.stringify({ pid: process.pid, host, at: Date.now() }));
    const cleanupResult = await runCleanup(baseOpts({ apply: true }), {
      ...baseDeps(fakeServer([memory("m-1", "x")]), fakeLlm([[]]), dir),
      lockFile: cleanupLock,
      clock: () => Date.now(),
      acquireMutex: vi.fn(async () => {
        cleanupOrder.push("mutex");
        return { release: vi.fn(async () => cleanupOrder.push("release")) };
      }),
    });
    expect(cleanupResult.exitCode).toBe(3);
    expect(cleanupOrder).toEqual(["mutex", "release"]);
  });

  it("TC-MEMRESTORE-034 an already-active id is a reported no-op: exit 0, no write, no cap", async () => {
    const dir = tempDir();
    const { deps, restoreMemory } = applyDeps(dir, [inactiveRow("act-1", "active", { superseded_by: null })]);
    const result = await runRestore(
      restoreOpts({ apply: true, idsFile: idsFile(dir, ["act-1"]) }),
      deps,
    );
    // Idempotence is what makes finishing a partially-applied restore safe.
    // Treating this as an error would push an operator toward hand-written SQL.
    expect(result.exitCode).toBe(0);
    expect(result.alreadyActive).toEqual(["act-1"]);
    expect(restoreMemory).not.toHaveBeenCalled();
    expect(result.capUsed).toBe(0);
    expect(deps.log).toHaveBeenCalledWith(expect.stringMatching(/act-1.*already active/iu));
  });

  it("TC-MEMRESTORE-035 an unknown id is reported, does not abort the rest, and changes the exit code", async () => {
    const dir = tempDir();
    const { deps, store } = applyDeps(dir, [inactiveRow("d-1", "deleted")]);
    const result = await runRestore(
      restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1", "typo-1"]) }),
      deps,
    );
    expect(store.get("d-1").state).toBe("active");
    expect(result.notFound).toEqual(["typo-1"]);
    // A typo must not be able to look like a clean run: the good ids still
    // apply, but the exit code says the file was not fully honoured.
    expect(result.exitCode).toBe(6);
    expect(deps.log).toHaveBeenCalledWith(expect.stringMatching(/typo-1/u));
  });

  it("TC-MEMRESTORE-036 the decision log lands outside any checkout at 0600", async () => {
    const dir = tempDir();
    const { deps } = applyDeps(dir, [inactiveRow("d-1", "deleted")]);
    const result = await runRestore(
      restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1"]) }),
      deps,
    );
    const { statSync } = await import("node:fs");
    expect(result.logPath.startsWith(dir)).toBe(true);
    // The log holds memory snippets — instance-private data in a repo that is
    // planned to be open-sourced.
    expect(statSync(result.logPath).mode & 0o777).toBe(0o600);
    expect(deps.log).toHaveBeenCalledWith(expect.stringContaining(result.logPath));
  });

  it("TC-MEMRESTORE-037 an ids file bound to another stage is refused before any read", async () => {
    const dir = tempDir();
    const path = join(dir, "prod-ids.json");
    writeFileSync(path, JSON.stringify({ stage: "prod", ids: ["d-1"] }));
    const { deps, restoreMemory } = applyDeps(dir, [inactiveRow("d-1", "deleted")]);
    // Ids collide across stages, so a prod file replayed against preview would
    // silently resurrect whatever happens to share those ids.
    await expect(
      runRestore(restoreOpts({ apply: true, idsFile: path }), deps),
    ).rejects.toThrow(/stage/u);
    expect(restoreMemory).not.toHaveBeenCalled();
    expect(deps.findByIds).not.toHaveBeenCalled();
  });

  it("TC-MEMRESTORE-037 an empty ids file is an error, not a silent no-op run", async () => {
    const dir = tempDir();
    const path = join(dir, "empty.txt");
    writeFileSync(path, "\n  \n");
    const { deps } = applyDeps(dir, [inactiveRow("d-1", "deleted")]);
    // "Restored 0 of 0" from a file the operator believed held ids is the
    // report that ends with a second, hand-written attempt.
    await expect(
      runRestore(restoreOpts({ apply: true, idsFile: path }), deps),
    ).rejects.toThrow(/no ids/iu);
  });

  it("TC-MEMRESTORE-039 a lost fence is reported as skipped, not counted as restored", async () => {
    const dir = tempDir();
    const { deps } = applyDeps(dir, [inactiveRow("d-1", "deleted")], {
      restoreMemory: vi.fn(async () => false),
    });
    const result = await runRestore(
      restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1"]) }),
      deps,
    );
    // rowCount 0 means the row moved between the read and the write. Counting
    // it as restored would tell the operator a memory is back when it is not.
    expect(result.restored).toEqual([]);
    expect(result.fencedOut).toEqual(["d-1"]);
    expect(result.exitCode).toBe(6);
    // A fenced-out id is IN the log with its outcome, not omitted from it. A log
    // that only records successes cannot answer "what did this run attempt",
    // which is the question it exists for — and a run where every id fenced out
    // still has to leave a record behind.
    const logged = JSON.parse(readFileSync(result.logPath, "utf8"));
    expect(logged.entries).toHaveLength(1);
    expect(logged.entries[0]).toMatchObject({ id: "d-1", outcome: "fenced-out" });
  });

  it("TC-MEMRESTORE-047 a write that throws mid-run still leaves the log and the summary behind", async () => {
    const dir = tempDir();
    const outDir = join(dir, "logs");
    const rows = ["d-1", "d-2", "d-3", "d-4"].map((id) => inactiveRow(id, "deleted"));
    const store = new Map(rows.map((r) => [r.id, { ...r }]));
    let calls = 0;
    const ctx = applyDeps(dir, rows, {
      outDir,
      restoreMemory: vi.fn(async ({ id }) => {
        calls += 1;
        if (calls === 3) throw new Error("connection reset by peer");
        store.get(id).state = "active";
        return true;
      }),
    });
    // The throw propagates — the run really did fail, and a destructive tool
    // must not swallow that. What must NOT happen is that it takes the record
    // of the two rows already flipped to active down with it: the operator's
    // next move is reconstructing a half-applied run, and exit 1 with a bare
    // stack tells them nothing was done.
    await expect(
      runRestore(restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1", "d-2", "d-3", "d-4"]) }), ctx.deps),
    ).rejects.toThrow(/connection reset/u);

    const written = readdirSync(outDir).filter((f) => f.startsWith("restore-"));
    expect(written).toHaveLength(1);
    const logged = JSON.parse(readFileSync(join(outDir, written[0]), "utf8"));
    expect(logged.entries.map((e) => e.id)).toEqual(["d-1", "d-2"]);
    expect(ctx.deps.log).toHaveBeenCalledWith(expect.stringMatching(/apply done: restored=2/u));
  });

  it("TC-MEMRESTORE-048 a log that cannot be written degrades to the ids on stderr, never to silence", async () => {
    const dir = tempDir();
    // A file where a directory is expected: the ENOTDIR a typo'd --out gives,
    // and the same shape a full disk gives at writeFileSync.
    const blocker = join(dir, "not-a-dir");
    writeFileSync(blocker, "x");
    const ctx = applyDeps(dir, [inactiveRow("d-1", "deleted"), inactiveRow("d-2", "deleted")], {
      outDir: join(blocker, "logs"),
    });
    const result = await runRestore(
      restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1", "d-2"]) }),
      ctx.deps,
    );
    // Two rows ARE active. Losing the log AND the summary would leave the
    // operator with an exception and no way to learn which ids moved, so the
    // ids fall back to stderr and the exit code says the run needs attention.
    expect(ctx.store.get("d-1").state).toBe("active");
    expect(result.restored).toEqual(["d-1", "d-2"]);
    expect(result.exitCode).toBe(1);
    expect(result.logPath).toBeUndefined();
    const failure = ctx.deps.log.mock.calls.flat().find((m) => /could not be written/iu.test(m));
    expect(failure).toMatch(/d-1/u);
    expect(failure).toMatch(/d-2/u);
    // The fallback carries ids only. The entries hold memory snippets, and
    // stderr on a scheduled task lands in CloudWatch — outside the 0600 file
    // the snippets are supposed to stay in.
    expect(failure).not.toMatch(/fact about/u);
    expect(ctx.deps.log).toHaveBeenCalledWith(expect.stringMatching(/apply done: restored=2/u));
  });

  it("TC-MEMRESTORE-049 a failing lock or mutex release is logged and never replaces the real error", async () => {
    const dir = tempDir();
    const realFs = await import("node:fs");
    const release = vi.fn(async () => {
      throw new Error("Connection terminated unexpectedly");
    });
    const ctx = applyDeps(dir, [inactiveRow("d-1", "deleted")], {
      fs: { ...realFs, rmSync: vi.fn(() => { throw new Error("EROFS: read-only file system"); }) },
      acquireMutex: vi.fn(async () => ({ release })),
      restoreMemory: vi.fn(async () => { throw new Error("connection reset by peer"); }),
    });
    // The mutex release runs `pg_advisory_unlock` on the SAME client the loop
    // just died on, so it throws for the same reason — and an exception from a
    // `finally` REPLACES the in-flight one. The operator would be told
    // "Connection terminated unexpectedly" for a run that died of something
    // else, with the real cause gone.
    await expect(
      runRestore(restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1"]) }), ctx.deps),
    ).rejects.toThrow(/connection reset by peer/u);
    // ...and a lock that could not be removed must not skip the mutex release:
    // a leaked advisory lock blocks the next weekly consolidation outright.
    expect(release).toHaveBeenCalledOnce();
    expect(ctx.deps.log).toHaveBeenCalledWith(expect.stringMatching(/EROFS/u));
    expect(ctx.deps.log).toHaveBeenCalledWith(expect.stringMatching(/Connection terminated/u));
  });

  it("TC-MEMRESTORE-052 a dry-run whose plan exceeds --cap says so instead of exiting 0", async () => {
    const dir = tempDir();
    const ids = Array.from({ length: 5 }, (_, i) => `d-${i}`);
    const ctx = applyDeps(dir, ids.map((id) => inactiveRow(id, "deleted")), {});
    const result = await runRestore(
      restoreOpts({ cap: 2, idsFile: idsFile(dir, ids) }),
      ctx.deps,
    );
    // The dry run is where the operator decides. "would restore 5", exit 0,
    // then --apply restores 2 and exits 4 is the plan reading as executable
    // when it is not — the same class of defect as a silent truncation.
    expect(result.exitCode).toBe(6);
    expect(ctx.deps.log).toHaveBeenCalledWith(expect.stringMatching(/5[\s\S]*cap 2|cap 2[\s\S]*5/u));
  });

  it("TC-MEMRESTORE-053 a NULL updated_at is recorded as null, not as 1970", async () => {
    const dir = tempDir();
    const ctx = applyDeps(dir, [inactiveRow("d-1", "deleted", { updated_at: null })], {});
    const result = await runRestore(
      restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1"]) }),
      ctx.deps,
    );
    // `memories.updated_at` is nullable (schema.sql: TIMESTAMPTZ DEFAULT NOW(),
    // no NOT NULL) and `new Date(null)` is epoch 0, not an error. This is the
    // one field the log exists to preserve — #103's timeline gate reads it so a
    // restore cannot be read as recency evidence, and a fabricated 1970 reads
    // as maximally stale. An absent timestamp must look absent.
    expect(result.restored).toEqual(["d-1"]);
    const logged = JSON.parse(readFileSync(result.logPath, "utf8"));
    expect(logged.entries[0].updatedAtBefore).toBeNull();
  });

  it("TC-MEMRESTORE-055 a NULL version is refused as unfenceable, not attempted and blamed on a race", async () => {
    const dir = tempDir();
    const ctx = applyDeps(dir, [
      inactiveRow("d-1", "deleted", { version: null }),
      inactiveRow("d-2", "deleted"),
    ], {});
    const result = await runRestore(
      restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1", "d-2"]) }),
      ctx.deps,
    );
    // `version` is nullable in schema.sql too, and the NOT NULL only arrives via
    // a migration guarded by `IF to_regclass('memories') IS NOT NULL`. In SQL
    // `version = NULL` is never true, so the fence can never be satisfied: the
    // row is unrestorable until the schema is fixed. Reporting that as "state or
    // version changed since it was read" sends the operator into an unbounded
    // retry loop against a row that cannot move.
    expect(ctx.restoreMemory).not.toHaveBeenCalledWith(expect.objectContaining({ id: "d-1" }));
    expect(result.restored).toEqual(["d-2"]);
    expect(result.exitCode).toBe(6);
    const message = ctx.deps.log.mock.calls.flat().find((m) => /d-1/u.test(m));
    expect(message).toMatch(/version/u);
    expect(message).not.toMatch(/changed since/u);
  });

  it("TC-MEMRESTORE-057 a JSON array ids file is rejected, not line-split into garbage", async () => {
    const dir = tempDir();
    const path = join(dir, "ids.json");
    writeFileSync(path, '[\n  "m-1",\n  "m-2"\n]\n');
    const ctx = applyDeps(dir, [inactiveRow("m-1", "deleted")], {});
    // Line-splitting this yields ids of `[`, `"m-1",`, `"m-2"`, `]`, which
    // present as "4 ids not found" — a format error disguised as a bad id list,
    // and the operator's next guess is that the ids are wrong.
    await expect(
      runRestore(restoreOpts({ apply: true, idsFile: path }), ctx.deps),
    ).rejects.toThrow(/array|one id per line|\{"stage"/u);
    expect(ctx.restoreMemory).not.toHaveBeenCalled();
  });

  it("TC-MEMRESTORE-058 a fenced-out id does not consume cap", async () => {
    const dir = tempDir();
    const ctx = applyDeps(dir, [
      inactiveRow("d-1", "deleted"),
      inactiveRow("d-2", "deleted"),
      inactiveRow("d-3", "deleted"),
    ], {
      restoreMemory: vi.fn(async ({ id }) => id !== "d-1"),
    });
    const result = await runRestore(
      restoreOpts({ apply: true, cap: 2, idsFile: idsFile(dir, ["d-1", "d-2", "d-3"]) }),
      ctx.deps,
    );
    // Same decision #102 already made for a fenced merge (TC-MEMCLEAN-043):
    // charging a lost fence against the cap shrinks the blast-radius budget for
    // work that never happened, and a mostly-fenced run could trip the exit-4
    // abort having restored almost nothing. The cap is still checked BEFORE the
    // write, so it cannot be overrun.
    expect(result.capUsed).toBe(2);
    expect(result.restored).toEqual(["d-2", "d-3"]);
    expect(result.fencedOut).toEqual(["d-1"]);
    expect(result.exitCode).toBe(6);
  });

  it("TC-MEMRESTORE-062 a failed teardown does not mask the cap abort or a lost fence", async () => {
    const realFs = await import("node:fs");
    // Both outcome codes, against the same teardown failure. Asserted as a table
    // because the defect was the ORDER of one ternary: with `teardownFailed`
    // tested first, both of these reported 1, and 1 is also what an outright
    // crash gives — so a run that had hit the cap and left the ids file
    // half-applied was indistinguishable from one that did nothing at all.
    const cases = [
      {
        what: "the cap abort",
        ids: ["d-1", "d-2", "d-3"],
        cap: 2,
        overrides: {},
        exitCode: 4,
        restored: ["d-1", "d-2"],
      },
      {
        what: "a lost fence",
        ids: ["d-1"],
        cap: 50,
        overrides: { restoreMemory: vi.fn(async () => false) },
        exitCode: 6,
        restored: [],
      },
    ];
    for (const { what, ids, cap, overrides, exitCode, restored } of cases) {
      const dir = tempDir();
      const ctx = applyDeps(
        dir,
        ["d-1", "d-2", "d-3"].map((id) => inactiveRow(id, "deleted")),
        {
          // An EROFS lock file: the teardown step furthest from the store, so the
          // only thing it can legitimately change is the bookkeeping code.
          fs: {
            ...realFs,
            rmSync: vi.fn(() => {
              throw new Error("EROFS: read-only file system");
            }),
          },
          ...overrides,
        },
      );
      const result = await runRestore(
        restoreOpts({ apply: true, cap, idsFile: idsFile(dir, ids) }),
        ctx.deps,
      );
      expect(result.exitCode, `${what} must survive a failed teardown`).toBe(exitCode);
      expect(result.restored).toEqual(restored);
      // The teardown failure is never silent — it just does not win the code.
      expect(ctx.deps.log).toHaveBeenCalledWith(expect.stringMatching(/EROFS/u));
    }
  });

  it("TC-MEMRESTORE-063 --out inside the checkout is refused before any row moves", async () => {
    const dir = tempDir();
    // The repo root as an operator reviewing a plan would reach for it: the log
    // holds memory snippets, and CI's scan-public-artifacts.mjs looks for keys,
    // tokens, and ARNs — nothing that memory prose resembles — on a range that
    // only exists once the commit does. The header comment said "outside the
    // repository" and `--out` had no constraint.
    const inCheckout = join(SCRIPT_TREE, "tmp-restore-logs");
    const ctx = applyDeps(dir, [inactiveRow("d-1", "deleted")], { outDir: inCheckout });
    await expect(
      runRestore(restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1"]) }), ctx.deps),
    ).rejects.toThrow(/must not be written into a checkout/u);
    // Refused at the top of the run, NOT in the teardown `finally`: rejecting it
    // there would restore the row first and then report the operator's typo as a
    // lost log — the one record of a run that did happen.
    expect(ctx.store.get("d-1").state).toBe("deleted");
    expect(ctx.deps.restoreMemory).not.toHaveBeenCalled();
    expect(existsSync(inCheckout)).toBe(false);

    // ...and the default still works, so the guard rejects the path rather than
    // the feature.
    const ok = applyDeps(dir, [inactiveRow("d-2", "deleted")], {});
    const result = await runRestore(
      restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-2"]) }),
      ok.deps,
    );
    expect(result.restored).toEqual(["d-2"]);
  });

  it("TC-MEMRESTORE-030 a dry-run that cannot fully honour the file still says so", async () => {
    const dir = tempDir();
    const { deps, restoreMemory } = applyDeps(dir, [inactiveRow("a-1", "archived")]);
    const result = await runRestore(
      restoreOpts({ idsFile: idsFile(dir, ["a-1", "typo-1"]) }),
      deps,
    );
    // The dry run is where the operator decides whether to pass --apply. Exiting
    // 0 here and 6 on apply would hide the refusal until after the decision.
    expect(result.exitCode).toBe(6);
    expect(result.refusedArchived).toEqual(["a-1"]);
    expect(result.notFound).toEqual(["typo-1"]);
    expect(restoreMemory).not.toHaveBeenCalled();
    expect(deps.log).toHaveBeenCalledWith(
      expect.stringMatching(/dry-run: would restore 0[\s\S]*archivedRefused=1/u),
    );
  });

  it("TC-MEMRESTORE-037 a stage-matched JSON ids file is accepted and de-duplicated", async () => {
    const dir = tempDir();
    const path = join(dir, "ids.json");
    // The form #102's own decision log emits, including a repeated id: charging
    // the cap twice for one memory would abort a run that fits.
    writeFileSync(path, JSON.stringify({ stage: "test", ids: ["d-1", "d-1", "d-2"] }));
    const { deps, restoreMemory } = applyDeps(dir, [
      inactiveRow("d-1", "deleted"),
      inactiveRow("d-2", "deleted"),
    ]);
    const result = await runRestore(restoreOpts({ apply: true, idsFile: path }), deps);
    expect(result.exitCode).toBe(0);
    expect(result.restored).toEqual(["d-1", "d-2"]);
    expect(restoreMemory).toHaveBeenCalledTimes(2);
    expect(result.capUsed).toBe(2);
  });

  it("TC-MEMRESTORE-037 a JSON ids file for the right stage but with no ids array is an error", async () => {
    const dir = tempDir();
    const path = join(dir, "ids.json");
    // A hand-edited or half-written log: the stage matches, so the guard passes,
    // and the run would otherwise report a clean "restored 0 of 0".
    writeFileSync(path, JSON.stringify({ stage: "test", decisions: [{ id: "d-1" }] }));
    const { deps } = applyDeps(dir, [inactiveRow("d-1", "deleted")]);
    await expect(
      runRestore(restoreOpts({ apply: true, idsFile: path }), deps),
    ).rejects.toThrow(/no ids/iu);
    expect(deps.findByIds).not.toHaveBeenCalled();
  });

  it("TC-MEMRESTORE-032 a non-positive or non-finite --cap is refused before any read", async () => {
    const dir = tempDir();
    const { deps } = applyDeps(dir, [inactiveRow("d-1", "deleted")]);
    // cap=0 must not read as "unbounded". A restore is a write path, so an
    // unparseable bound has to stop the run, not default to one.
    for (const cap of [0, -1, Number.NaN]) {
      await expect(
        runRestore(restoreOpts({ apply: true, cap, idsFile: idsFile(dir, ["d-1"]) }), deps),
      ).rejects.toThrow(/cap/iu);
    }
    expect(deps.findByIds).not.toHaveBeenCalled();
  });

  it("TC-MEMRESTORE-031 accepts a pre-built adapter, which is how the CLI supplies it", async () => {
    const dir = tempDir();
    const store = new Map([["d-1", { ...inactiveRow("d-1", "deleted") }]]);
    // Mirrors `recoveryDeps`: the adapter methods arrive spread onto deps with
    // no `db`, so this is the shape production actually runs.
    const deps = restoreDeps({
      outDir: dir,
      lockFile: join(dir, "restore.lock"),
      findByIds: async (ids) => ids.map((id) => store.get(id)).filter(Boolean),
      restoreMemory: async ({ id }) => {
        store.get(id).state = "active";
        return true;
      },
    });
    const result = await runRestore(
      restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1"]) }),
      deps,
    );
    expect(result.restored).toEqual(["d-1"]);
    expect(store.get("d-1").state).toBe("active");
  });

  it("TC-MEMRESTORE-033 the lock and the shared mutex are released even when a write throws", async () => {
    const dir = tempDir();
    const lockFile = join(dir, "restore.lock");
    const release = vi.fn(async () => {});
    const { deps } = applyDeps(dir, [inactiveRow("d-1", "deleted")], {
      lockFile,
      acquireMutex: vi.fn(async () => ({ release })),
      restoreMemory: vi.fn(async () => {
        throw new Error("connection reset");
      }),
    });
    await expect(
      runRestore(restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1"]) }), deps),
    ).rejects.toThrow(/connection reset/u);
    // A crashed apply that keeps the lock and the mutex locks the operator out
    // of recovery and blocks the next weekly consolidation — at the worst time.
    expect(existsSync(lockFile)).toBe(false);
    expect(release).toHaveBeenCalledOnce();
  });
});

describe("archived-vs-deleted separation", () => {
  function idsFile(dir, ids) {
    const path = join(dir, "ids.txt");
    writeFileSync(path, `${ids.join("\n")}\n`);
    return path;
  }
  function deps(dir, rows, overrides = {}) {
    const store = new Map(rows.map((r) => [r.id, { ...r }]));
    const restoreMemory = vi.fn(async ({ id, priorState, version }) => {
      const row = store.get(id);
      if (!row || row.state !== priorState || row.version !== version) return false;
      row.state = "active";
      return true;
    });
    return {
      store,
      restoreMemory,
      deps: restoreDeps({
        outDir: dir,
        lockFile: join(dir, "restore.lock"),
        findByIds: vi.fn(async (ids) => ids.map((id) => store.get(id)).filter(Boolean)),
        restoreMemory,
        ...overrides,
      }),
    };
  }

  it("TC-MEMRESTORE-059 a deleted row that still names a live winner is refused like an archived one", async () => {
    const dir = tempDir();
    // Reachable today, with only the two states: #103 archives a loser
    // (superseded_by=winner-1) → an operator --force-restores it, and
    // `superseded_by` is PRESERVED by design → a later #102 cleanup judges it
    // DELETE, and the soft delete sets state='deleted' without touching
    // superseded_by. The row is now `deleted` while still naming a live winner.
    const ctx = deps(dir, [
      inactiveRow("d-1", "deleted", { superseded_by: "winner-1" }),
    ]);
    const result = await runRestore(
      restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1"]) }),
      ctx.deps,
    );
    // The hazard the gate exists to stop is "restoring this returns a memory
    // that lost a contradiction while the winner is still active" — which is a
    // statement about `superseded_by`, not about `state`. Keying on the state
    // alone lets the row through at exit 0 with no warning, while the run's own
    // log entry records the disqualifying fact.
    expect(ctx.restoreMemory).not.toHaveBeenCalled();
    expect(result.refusedArchived).toEqual(["d-1"]);
    expect(result.exitCode).toBe(6);
    expect(ctx.deps.log).toHaveBeenCalledWith(expect.stringContaining("winner-1"));
  });

  it("TC-MEMRESTORE-060 --force names every superseded id it is about to resurrect, on the dry run", async () => {
    const dir = tempDir();
    const ctx = deps(dir, [
      inactiveRow("a-1", "archived"),
      inactiveRow("a-2", "archived"),
      inactiveRow("d-1", "deleted"),
    ]);
    const result = await runRestore(
      restoreOpts({ force: true, idsFile: idsFile(dir, ["a-1", "a-2", "d-1"]) }),
      ctx.deps,
    );
    // --force is per-run, never per id (by design), so an operator who adds it
    // for ONE known-archived id silently consents for every other archived id in
    // the same file. The dry run is where that decision is made, so it is where
    // the names have to appear — after the write is too late.
    expect(result.exitCode).toBe(0);
    expect(result.planned).toEqual(["a-1", "a-2", "d-1"]);
    for (const id of ["a-1", "a-2"]) {
      expect(ctx.deps.log).toHaveBeenCalledWith(
        expect.stringMatching(new RegExp(`${id}[\\s\\S]*winner-of-${id}`, "u")),
      );
    }
    expect(ctx.deps.log).toHaveBeenCalledWith(expect.stringMatching(/archivedForced=2/u));
    expect(ctx.restoreMemory).not.toHaveBeenCalled();
  });

  it("TC-MEMRESTORE-040 an archived id without --force is refused, names the winner, writes nothing", async () => {
    const dir = tempDir();
    const ctx = deps(dir, [inactiveRow("a-1", "archived")]);
    const result = await runRestore(
      restoreOpts({ apply: true, idsFile: idsFile(dir, ["a-1"]) }),
      ctx.deps,
    );
    // Restoring the loser of a contradiction while the winner is still active
    // puts two directly contradictory memories back in search — the exact
    // defect #103 exists to remove. It must not happen by default.
    expect(ctx.restoreMemory).not.toHaveBeenCalled();
    expect(ctx.store.get("a-1").state).toBe("archived");
    expect(result.refusedArchived).toEqual(["a-1"]);
    expect(result.exitCode).toBe(6);
    // The winner's id is the fact the decision turns on, so the refusal has to
    // carry it: "use --force" alone tells the operator nothing.
    expect(ctx.deps.log).toHaveBeenCalledWith(expect.stringContaining("winner-of-a-1"));
    expect(ctx.deps.log).toHaveBeenCalledWith(expect.stringMatching(/--force/u));
  });

  it("TC-MEMRESTORE-041 --force restores the archived row, preserves superseded_by, still warns", async () => {
    const dir = tempDir();
    const ctx = deps(dir, [inactiveRow("a-1", "archived", { version: 5 })]);
    const result = await runRestore(
      restoreOpts({ apply: true, force: true, idsFile: idsFile(dir, ["a-1"]) }),
      ctx.deps,
    );
    expect(result.exitCode).toBe(0);
    expect(result.restored).toEqual(["a-1"]);
    expect(ctx.store.get("a-1").state).toBe("active");
    // Preserved: it is the audit link, and #103's re-resolution needs the pair.
    expect(ctx.store.get("a-1").superseded_by).toBe("winner-of-a-1");
    expect(ctx.restoreMemory).toHaveBeenCalledWith(
      expect.objectContaining({ id: "a-1", priorState: "archived", version: 5 }),
    );
    // --force suppresses the refusal, not the warning: the operator has just
    // put a known contradiction back and the log has to say so.
    expect(ctx.deps.log).toHaveBeenCalledWith(expect.stringContaining("winner-of-a-1"));
  });

  it("TC-MEMRESTORE-042 a mixed file restores the deleted ids and refuses EVERY archived one", async () => {
    const dir = tempDir();
    // TWO archived ids, deliberately. With only one, a refusal that applies to
    // the first archived id and then silently lets the rest through is
    // invisible — the per-id gate and a first-one-only gate agree on a
    // single-archived file. That is the whole "--force never leaks" claim, so
    // the case has to be able to see the difference.
    const ctx = deps(dir, [
      inactiveRow("d-1", "deleted"),
      inactiveRow("a-1", "archived"),
      inactiveRow("d-2", "deleted"),
      inactiveRow("a-2", "archived"),
    ]);
    const result = await runRestore(
      restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1", "a-1", "d-2", "a-2"]) }),
      ctx.deps,
    );
    expect(result.restored).toEqual(["d-1", "d-2"]);
    expect(result.refusedArchived).toEqual(["a-1", "a-2"]);
    expect(ctx.store.get("a-1").state).toBe("archived");
    expect(ctx.store.get("a-2").state).toBe("archived");
    // --force is per run and never inferred: if one archived id in a file could
    // imply consent for the batch, the flag would protect nothing.
    expect(result.exitCode).toBe(6);
    // Both groups reported, so the operator does not have to diff the file
    // against the store to learn what happened.
    expect(result.restored).not.toContain("a-1");
    expect(result.restored).not.toContain("a-2");
    expect(ctx.restoreMemory).toHaveBeenCalledTimes(2);
    // Each refusal names its own winner: one message covering "some archived
    // ids" would leave the operator to work out which.
    for (const id of ["a-1", "a-2"]) {
      expect(ctx.deps.log).toHaveBeenCalledWith(expect.stringContaining(`winner-of-${id}`));
    }
  });

  it("TC-MEMRESTORE-046 an unrecognised state is refused, not silently restored", async () => {
    const dir = tempDir();
    // Only `deleted` and `archived` exist today, so this is latent — but the
    // whole premise of this feature is that the inactive states are NOT
    // interchangeable, and a gate that names one state and lets everything else
    // through treats the next one as the permissive case. A future `purged` or
    // `quarantined` must arrive as a refusal that an operator reads, not as a
    // restore nobody asked for.
    const ctx = deps(dir, [
      inactiveRow("d-1", "deleted"),
      inactiveRow("p-1", "purged"),
    ]);
    const result = await runRestore(
      restoreOpts({ apply: true, force: true, idsFile: idsFile(dir, ["d-1", "p-1"]) }),
      ctx.deps,
    );
    expect(result.restored).toEqual(["d-1"]);
    expect(ctx.store.get("p-1").state).toBe("purged");
    // --force is consent to resurrect a contradiction loser, not blanket
    // consent for a state this tool has never been taught to reason about.
    expect(result.refusedUnknownState).toEqual(["p-1"]);
    expect(result.exitCode).toBe(6);
    expect(ctx.deps.log).toHaveBeenCalledWith(
      expect.stringMatching(/p-1[\s\S]*purged[\s\S]*not a state this tool/u),
    );
  });

  it("TC-MEMRESTORE-043 the log records the prior state and the pre-restore updated_at", async () => {
    const dir = tempDir();
    const ctx = deps(dir, [
      inactiveRow("d-1", "deleted", { updated_at: new Date("2025-11-02T03:04:05Z") }),
      inactiveRow("a-1", "archived"),
    ]);
    const result = await runRestore(
      restoreOpts({ apply: true, force: true, idsFile: idsFile(dir, ["d-1", "a-1"]) }),
      ctx.deps,
    );
    const logged = JSON.parse(readFileSync(result.logPath, "utf8"));
    expect(logged.stage).toBe("test");
    const byId = Object.fromEntries(logged.entries.map((e) => [e.id, e]));
    // trg_memories_updated has already overwritten the row's updated_at with
    // NOW() by the time this file is read back, so this is the only surviving
    // record of how old the memory really is — and #103's timeline gate must
    // read the real age, not mistake a restore for recency evidence.
    expect(byId["d-1"]).toMatchObject({
      priorState: "deleted",
      updatedAtBefore: "2025-11-02T03:04:05.000Z",
      outcome: "restored",
    });
    expect(byId["a-1"]).toMatchObject({
      priorState: "archived",
      supersededBy: "winner-of-a-1",
      forced: true,
    });
  });

  it("TC-MEMRESTORE-040/041 an archived row with no recorded winner still refuses, and still warns", async () => {
    const dir = tempDir();
    // Archived with a null `superseded_by`: the column is nullable, so this is
    // representable, and it is the case where the operator has the LEAST
    // information. Falling through to a silent restore would be backwards.
    const rows = () => [inactiveRow("a-1", "archived", { superseded_by: null })];
    const refused = deps(dir, rows());
    const blocked = await runRestore(
      restoreOpts({ apply: true, idsFile: idsFile(dir, ["a-1"]) }),
      refused.deps,
    );
    expect(blocked.refusedArchived).toEqual(["a-1"]);
    expect(refused.restoreMemory).not.toHaveBeenCalled();
    // "superseded by null" or "superseded by undefined" reads as a bug and tells
    // the operator nothing; it has to say the winner was not recorded.
    expect(refused.deps.log).toHaveBeenCalledWith(
      expect.stringMatching(/a-1: archived[\s\S]*unrecorded winner/u),
    );

    const dir2 = tempDir();
    const forced = deps(dir2, rows());
    const result = await runRestore(
      restoreOpts({ apply: true, force: true, idsFile: idsFile(dir2, ["a-1"]) }),
      forced.deps,
    );
    expect(result.restored).toEqual(["a-1"]);
    // Emitted during planning (so the dry run carries it too, TC-060), which is
    // why this reads "will be restored" rather than "restored".
    expect(forced.deps.log).toHaveBeenCalledWith(
      expect.stringMatching(/restored under --force[\s\S]*unrecorded winner/u),
    );
    const logged = JSON.parse(readFileSync(result.logPath, "utf8"));
    expect(logged.entries[0]).toMatchObject({ supersededBy: null, forced: true });
  });

  it("TC-MEMRESTORE-036/043 a row with no content logs an empty snippet rather than crashing", async () => {
    const dir = tempDir();
    // `content` is not part of the fence and a row could be read with it absent;
    // a TypeError here would abort the whole run after some ids were written.
    const ctx = deps(dir, [inactiveRow("d-1", "deleted", { content: undefined })]);
    const result = await runRestore(
      restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1"]) }),
      ctx.deps,
    );
    expect(result.restored).toEqual(["d-1"]);
    expect(JSON.parse(readFileSync(result.logPath, "utf8")).entries[0].snippet).toBe("");
  });

  it("TC-MEMRESTORE-044 restore issues no embedding request over any route", async () => {
    const dir = tempDir();
    // Driven through the REAL adapter over a fake `db`, not through injected
    // method spies: that is what makes the SQL inspectable below.
    const db = fakeDb({
      "UPDATE memories": () => ({ rowCount: 1 }),
      "FROM memories": () => ({ rows: [inactiveRow("d-1", "deleted")] }),
    });
    // `runRestore` never receives `fetchImpl`, so asserting that an injected spy
    // went uncalled is true by construction and proves nothing. Close the routes
    // a re-embed could actually take instead: the global fetch (what a bare
    // `fetch(...)` resolves to), and the SQL itself.
    const globalFetch = vi.fn(async () => {
      throw new Error("restore must not make network calls");
    });
    vi.stubGlobal("fetch", globalFetch);
    let result;
    try {
      result = await runRestore(
        restoreOpts({ apply: true, idsFile: idsFile(dir, ["d-1"]) }),
        restoreDeps({ outDir: dir, lockFile: join(dir, "restore.lock"), db }),
      );
    } finally {
      vi.unstubAllGlobals();
    }
    expect(result.restored).toEqual(["d-1"]);
    // The row was never removed and `vector(1024)` is still populated, so a
    // re-embed would burn inference cost and could shift the vector under a
    // different model version than the rest of the corpus.
    expect(globalFetch).not.toHaveBeenCalled();
    // Nor via SQL: no statement this run issued so much as mentions the column,
    // and the run did issue statements (otherwise this loop is vacuous). The
    // live round trip confirmed the vector is byte-identical across a restore;
    // this is the assertion that keeps it that way in CI.
    expect(db.queries.length).toBeGreaterThan(0);
    for (const q of db.queries) {
      expect(q.text).not.toMatch(/embedding/iu);
    }
  });
});

describe("shared apply mutex key", () => {
  it("TC-MEMRESTORE-033 restore, cleanup, and consolidation derive one key per stage", async () => {
    // The mutex is an advisory lock over `hashtextextended(key)`, so it only
    // serialises the three writers if all three derive the SAME string. This is
    // imported by memory-consolidation.mjs and used by restore's --apply, and
    // nothing else would fail if a caller drifted to its own literal — the locks
    // would simply stop colliding, silently.
    const { sharedCleanupMutexKey } = await import("./memory-cleanup.mjs");
    expect(sharedCleanupMutexKey("prod")).toBe("mem9-cleanup:prod");
    // Stage-scoped: a preview apply must never block a prod apply.
    expect(sharedCleanupMutexKey("preview")).not.toBe(sharedCleanupMutexKey("prod"));

    const consolidation = readFileSync("scripts/memory-consolidation.mjs", "utf8");
    expect(consolidation).toMatch(/sharedCleanupMutexKey/u);
    expect(consolidation).not.toMatch(/["'`]mem9-cleanup:/u);
  });
});

describe("restore CLI validation", () => {
  it("TC-MEMRESTORE-050 rejects mode conflicts, a missing --ids, and misapplied filters", () => {
    expect(parseArgs(["--stage", "test", "--list-inactive"])).toMatchObject({ listInactive: true });
    expect(
      parseArgs(["--stage", "test", "--restore", "--ids", "a.txt", "--force"]),
    ).toMatchObject({ restore: true, idsFile: "a.txt", force: true });

    // One mode per run: with both flags it is not knowable whether --apply was
    // meant to write.
    expect(() => parseArgs(["--stage", "test", "--list-inactive", "--restore", "--ids", "a.txt"])).toThrow(
      /one of --list-inactive or --restore/u,
    );
    expect(() => parseArgs(["--stage", "test", "--restore"])).toThrow(/--restore requires --ids/u);
    // Silently ignoring a filter on --restore is the dangerous reading: an
    // operator who believes --state narrowed the run would restore more than
    // they intended.
    for (const filter of [["--state", "deleted"], ["--since", "2026-01-01T00:00:00Z"], ["--limit", "5"]]) {
      expect(() =>
        parseArgs(["--stage", "test", "--restore", "--ids", "a.txt", ...filter]),
      ).toThrow(new RegExp(`${filter[0]}.*--list-inactive|--restore.*${filter[0]}`, "u"));
    }
    // --force only means anything for --restore.
    expect(() => parseArgs(["--stage", "test", "--list-inactive", "--force"])).toThrow(/--force/u);
  });

  it("TC-MEMRESTORE-020/021/022 validates --state, --since, and --limit values", () => {
    expect(parseArgs(["--stage", "test", "--list-inactive", "--state", "archived"])).toMatchObject({
      state: "archived",
    });
    // An unrecognised --state must not fall through to "return everything":
    // a typo'd filter that silently widens the listing is how an operator ends
    // up reviewing the active corpus and restoring something never deleted.
    expect(() => parseArgs(["--stage", "test", "--list-inactive", "--state", "purged"])).toThrow(
      /deleted\|archived|archived\|deleted/u,
    );
    expect(() => parseArgs(["--stage", "test", "--list-inactive", "--state", "active"])).toThrow();
    expect(() => parseArgs(["--stage", "test", "--list-inactive", "--since", "yesterday"])).toThrow(
      /ISO/iu,
    );
    expect(
      parseArgs(["--stage", "test", "--list-inactive", "--since", "2026-07-01T00:00:00Z"]),
    ).toMatchObject({ since: "2026-07-01T00:00:00Z" });
    expect(() => parseArgs(["--stage", "test", "--list-inactive", "--limit", "0"])).toThrow(/positive/u);
    expect(() => parseArgs(["--stage", "test", "--list-inactive", "--limit", "abc"])).toThrow(/positive/u);
  });

  it("TC-MEMRESTORE-054 every flag is rejected outside the mode it belongs to", () => {
    // Table-driven off the same `mode` field the parser reads, so a flag added to
    // ARG_SPECS without a mode fails here rather than being silently accepted in
    // all three modes. The rationale the parser already states for --state — an
    // operator who believes a flag narrowed the run acts on that belief — does
    // not stop applying at the flags that happen to have been thought of.
    const base = { cleanup: ["--stage", "test"], list: ["--stage", "test", "--list-inactive"], restore: ["--stage", "test", "--restore", "--ids", "a.txt"] };
    const sample = { number: "5", iso: "2026-01-01T00:00:00Z" };
    for (const [flag, spec] of Object.entries(ARG_SPECS)) {
      if (flag === "--help") continue;
      const value = spec.flag ? [] : [spec.choices ? spec.choices[0] : spec.number ? sample.number : spec.iso ? sample.iso : "x"];
      const modes = spec.mode ?? ["cleanup", "list", "restore"];
      expect(Array.isArray(modes), `${flag} has no mode declared in ARG_SPECS`).toBe(true);
      for (const [mode, argv] of Object.entries(base)) {
        // A flag that IS its own mode selector is excluded: passing --restore in
        // "restore" mode is the mode, not a misapplied flag.
        if (["--list-inactive", "--restore"].includes(flag)) continue;
        if (modes.includes(mode)) continue;
        expect(
          () => parseArgs([...argv, flag, ...value]),
          `${flag} should be rejected in ${mode} mode`,
        ).toThrow(flag);
      }
    }
    // The specific combinations both reviewers reached for by hand.
    expect(() => parseArgs(["--stage", "test", "--list-inactive", "--apply"])).toThrow(/--apply/u);
    expect(() => parseArgs(["--stage", "test", "--restore", "--ids", "a.txt", "--decisions", "d.json"])).toThrow(
      /--decisions/u,
    );
    // ...and the modes each flag DOES belong to still parse.
    expect(parseArgs([...base.list, "--limit", "5"])).toMatchObject({ limit: 5 });
    expect(parseArgs([...base.restore, "--apply", "--force"])).toMatchObject({ apply: true, force: true });
    expect(parseArgs([...base.cleanup, "--decisions", "d.json"])).toMatchObject({ decisionsFile: "d.json" });
  });

  it("TC-MEMRESTORE-056 --limit and --cap reject non-integers Postgres would refuse", () => {
    // `LIMIT $n` takes a bigint bind, so a fractional value fails at the server
    // after the connection, the SSM reads, and the secret fetch have all
    // happened. A count of memories is a count; reject it at the boundary.
    for (const bad of ["5.5", "1e30", "Infinity"]) {
      expect(() => parseArgs(["--stage", "test", "--list-inactive", "--limit", bad])).toThrow(/--limit/u);
      expect(() => parseArgs(["--stage", "test", "--cap", bad])).toThrow(/--cap/u);
    }
    expect(parseArgs(["--stage", "test", "--list-inactive", "--limit", "250"])).toMatchObject({ limit: 250 });
    // --lock-ttl is genuinely fractional (a 0.5-hour TTL is meaningful), so it
    // must NOT be swept into the same rule.
    expect(parseArgs(["--stage", "test", "--lock-ttl", "0.5"])).toMatchObject({ lockTtlHours: 0.5 });
  });

  it("TC-MEMRESTORE-051 --help documents dry-run as the default and --force as archived-only", () => {
    expect(parseArgs(["--help"])).toMatchObject({ help: true });
    // --help must not require --stage: an operator reaching for it does not
    // yet know the invocation.
    for (const flag of Object.keys(ARG_SPECS)) {
      expect(USAGE, `${flag} is undocumented`).toContain(flag);
    }
    expect(USAGE).toMatch(/--restore[\s\S]*dry-run|dry-run[\s\S]*--restore/u);
    // Case-insensitive: the assertion is that the --force entry names the state
    // it gates, not how the prose capitalises it.
    expect(USAGE).toMatch(/--force[\s\S]{0,200}archived/iu);
    // There is no memories.deleted_at, so --since cannot mean "deleted since".
    // Documenting that is the difference between a filter an operator trusts
    // and one they misread.
    expect(USAGE).toMatch(/--since[\s\S]{0,200}updated_at/u);
  });

  it("TC-MEMRESTORE-061 the CLI never truncates its own output through a pipe", async () => {
    // The only case in this file that needs a real process: `process.exit()`
    // discards writes still queued in a pipe, and no in-process test can observe
    // that. A `--list-inactive` of 1000 rows through `| cat` loses its tail rows
    // AND the "listed N of TOTAL" trailer — the sole signal that the page was
    // truncated — so a partial listing reads as complete, nondeterministically.
    // The listing itself needs a database, so this drives the same exit path
    // through --help, which writes a comparable volume and needs nothing.
    const { execFileSync } = await import("node:child_process");
    const script = new URL("./memory-cleanup.mjs", import.meta.url).pathname;
    // Every run, not one: the defect is a race, and a single green run is what
    // makes it look fixed. `sh -c` with a pipe is what puts stdout on a pipe
    // rather than on the test's own fd.
    for (let i = 0; i < 5; i += 1) {
      const piped = execFileSync("sh", ["-c", `node ${script} --help | cat`], { encoding: "utf8" });
      expect(piped, `run ${i} was truncated`).toContain(USAGE.trimEnd());
    }
    // ...and the source has no `process.exit(` left to reintroduce it. Behaviour
    // above is the real assertion; this pins the mechanism so the next exit site
    // added to the CLI has to make the same decision deliberately.
    const code = readFileSync(script, "utf8")
      .split("\n")
      .filter((line) => !/^\s*(\/\/|\*|\/\*)/u.test(line))
      .join("\n");
    expect(code).not.toMatch(/process\.exit\(/u);
  });
});

describe("protected topics (#123)", () => {
  // The invariant under test is stronger than "never offered for deletion": a
  // protected memory is never MUTATED by this tool at all — not deleted, not
  // absorbed into a merge, not rewritten as a merge survivor. One invariant with
  // one test surface, rather than a per-verdict list that a fourth verdict would
  // silently escape.
  const finance = (id, content, version = 1) => ({ ...memory(id, content, version) });
  const verdict = (id, v, topic, extra = {}) => ({
    id,
    verdict: v,
    reason: "r",
    topic,
    ...extra,
  });

  it("TC-SLACKAPP-060 a protected DELETE is downgraded to RETAIN, never offered", () => {
    const out = planDecisions(
      [finance("f-1", "my brokerage rule"), memory("e-1", "a build flag")],
      [verdict("f-1", "DELETE", "personal-finance"), verdict("e-1", "DELETE", "engineering")],
      { protectedTopics: ["personal-finance"] },
    );
    const byId = Object.fromEntries(out.map((d) => [d.id, d]));

    // Its own verdict, not a KEEP with a note: the summary counts it without
    // special-casing, and applyDecisions cannot reach a DELETE/MERGE branch.
    expect(byId["f-1"].verdict).toBe("RETAIN");
    // The report must show that the classifier judged it deletable and policy
    // overrode that — not that the classifier decided to keep it.
    expect(byId["f-1"].originalVerdict).toBe("DELETE");
    expect(byId["f-1"].retainedReason).toBe("protected topic personal-finance");
    // Unprotected topics are untouched by the rule.
    expect(byId["e-1"].verdict).toBe("DELETE");
  });

  it("TC-SLACKAPP-061 a policy retain is counted separately from SKIP", async () => {
    // SKIP means "something went wrong or was not audited". A policy retain is
    // neither, and conflating them would make a classifier outage and a working
    // protection rule read identically in the summary.
    const memories = [finance("f-1", "my positions"), memory("e-1", "a flag")];
    const server = fakeServer(memories);
    const llm = vi.fn(async (_p, batch) =>
      JSON.stringify({
        verdicts: batch.map((m) =>
          m.id === "f-1"
            ? verdict(m.id, "DELETE", "personal-finance")
            : verdict(m.id, "KEEP", "engineering"),
        ),
      }),
    );
    const deps = baseDeps(server, llm, tempDir());
    const result = await runCleanup(baseOpts({ protectedTopics: ["personal-finance"] }), deps);

    const summaryLine = deps.log.mock.calls.map((c) => c[0]).find((m) => m.startsWith("dry-run:"));
    expect(summaryLine).toContain('"RETAIN":1');
    expect(summaryLine).not.toContain('"SKIP":1');
    expect(result.decisions.find((d) => d.id === "f-1").verdict).toBe("RETAIN");
  });

  it("TC-SLACKAPP-066 the summary reports every verdict, zeros included, and invents no bucket", async () => {
    // Two properties, both about a summary an operator compares across runs.
    // Zeros must be printed: a run where protection matched nothing must say
    // `"RETAIN":0` rather than omit the key, because an absent key is
    // indistinguishable from a build that has no protection rule at all — the
    // exact silence that would hide the flag being dropped from the invocation.
    // And the key SET must be closed: `summary[d.verdict] = ... || 0` happily
    // invents a bucket, so a verdict misspelled at one push site would report
    // `"RETAINED":1` beside `"RETAIN":0` and look like a data oddity rather than a
    // routing bug that put a protected memory on an unaudited path.
    const memories = [memory("e-1", "a flag")];
    const server = fakeServer(memories);
    const llm = vi.fn(async (_p, batch) => JSON.stringify({ verdicts: keepAll(batch) }));
    const deps = baseDeps(server, llm, tempDir());
    await runCleanup(baseOpts({ protectedTopics: ["personal-finance"] }), deps);

    const summaryLine = deps.log.mock.calls.map((c) => c[0]).find((m) => m.startsWith("dry-run:"));
    const summary = JSON.parse(summaryLine.match(/\{.*\}/u)[0]);
    expect(Object.keys(summary).sort()).toEqual(
      ["DELETE", "KEEP", "MERGE", "RETAIN", "SKIP", "UNSTABLE"],
    );
    expect(summary.RETAIN).toBe(0);
    expect(summary.UNSTABLE).toBe(0);
    expect(summary.KEEP).toBe(1);

    // Asserted directly, not through a run: `validateDecisions` rejects an unknown
    // verdict in a replayed file before the summary is built, so no INPUT can reach
    // this branch — only a planner push site can, and an invariant nothing can
    // trigger from outside still has to be proven from inside or it is decoration.
    expect(() => verdictSummary([{ id: "x", verdict: "RETAINED" }])).toThrow(/uncountable/u);
  });

  it("TC-SLACKAPP-062 a protected memory is withheld from a merge, as survivor and as absorbed", () => {
    // Absorbing a protected memory into a survivor deletes it just as surely as
    // DELETE does, so a rule that only checks the top-level verdict is a hole.
    const asAbsorbed = planDecisions(
      [memory("s-1", "survivor"), finance("f-1", "my cash plan")],
      [
        verdict("s-1", "MERGE", "engineering", {
          merge_into: "s-1",
          absorbs: ["f-1"],
          merged_content: "merged",
        }),
        verdict("f-1", "MERGE", "personal-finance", { merge_into: "s-1" }),
      ],
      { protectedTopics: ["personal-finance"] },
    );
    const absorbedById = Object.fromEntries(asAbsorbed.map((d) => [d.id, d]));
    expect(absorbedById["f-1"].verdict).toBe("RETAIN");
    // With its only absorbed id withheld the merge has nothing to absorb, so it
    // must not rewrite the survivor either.
    expect(asAbsorbed.some((d) => d.verdict === "MERGE")).toBe(false);

    // As the survivor: a merge REWRITES the survivor's content, which is a
    // mutation of a protected memory even though nothing is deleted.
    const asSurvivor = planDecisions(
      [finance("f-2", "my brokerage"), memory("e-2", "a flag")],
      [
        verdict("f-2", "MERGE", "personal-finance", {
          merge_into: "f-2",
          absorbs: ["e-2"],
          merged_content: "merged",
        }),
        verdict("e-2", "MERGE", "engineering", { merge_into: "f-2" }),
      ],
      { protectedTopics: ["personal-finance"] },
    );
    const survivorById = Object.fromEntries(asSurvivor.map((d) => [d.id, d]));
    expect(survivorById["f-2"].verdict).toBe("RETAIN");
    expect(asSurvivor.some((d) => d.verdict === "MERGE")).toBe(false);
    // e-2 is not protected, but its group did not emit — it must still carry a
    // decision row, because the decision log covers every scanned memory.
    expect(survivorById["e-2"]).toBeDefined();
    expect(survivorById["e-2"].verdict).not.toBe("MERGE");
  });

  it("TC-SLACKAPP-063 protectedTopics defaults to personal-finance; an empty list protects nothing", () => {
    // Omitted → the default. An operator who wants the default omits the flag.
    const defaulted = planDecisions(
      [finance("f-1", "my holdings")],
      [verdict("f-1", "DELETE", "personal-finance")],
      {},
    );
    expect(defaulted[0].verdict).toBe("RETAIN");
    expect(parseArgs(["--stage", "test"]).protectedTopics).toEqual(["personal-finance"]);

    // Explicitly empty → protect nothing. A silent fallback to the default would
    // make a deliberate opt-out impossible to express.
    const optedOut = planDecisions(
      [finance("f-1", "my holdings")],
      [verdict("f-1", "DELETE", "personal-finance")],
      { protectedTopics: [] },
    );
    expect(optedOut[0].verdict).toBe("DELETE");
    expect(parseArgs(["--stage", "test", "--protected-topics", ""]).protectedTopics).toEqual([]);
  });

  it("TC-SLACKAPP-065 an --apply run issues no write for a RETAIN row", async () => {
    // The invariant is "never mutated by this tool at all", so it has to hold on
    // the run that actually writes — not only in the planner. RETAIN survives
    // that path because `destructiveCost` returns 0 for it, which is exactly the
    // kind of implicit protection a fourth verdict would inherit by accident and
    // a refactor could remove without any test noticing.
    const memories = [finance("f-1", "my positions"), memory("e-1", "session noise")];
    const server = fakeServer(memories);
    const llm = vi.fn(async (_p, batch) =>
      JSON.stringify({
        verdicts: batch.map((m) =>
          m.id === "f-1"
            ? verdict(m.id, "DELETE", "personal-finance")
            : verdict(m.id, "DELETE", "engineering"),
        ),
      }),
    );
    const dryDeps = baseDeps(server, llm, tempDir());
    const dry = await runCleanup(baseOpts({ protectedTopics: ["personal-finance"] }), dryDeps);
    expect(dry.writeCalls).toBe(0);

    // Replay the decision file, which is the run that deletes.
    const applyServer = fakeServer(memories);
    const applyDeps = baseDeps(applyServer, llm, tempDir());
    const applied = await runCleanup(
      baseOpts({ apply: true, decisionsFile: dry.decisionPath, protectedTopics: ["personal-finance"] }),
      applyDeps,
    );

    // The unprotected id is deleted, proving the run was capable of deleting.
    expect(JSON.stringify(applyServer.calls)).toContain("e-1");
    // Asserted over EVERY call, GETs included, not just the writes. A RETAIN row
    // that reaches the delete branch is re-read and then skipped as an "LWW
    // guard" — it has no contentHash to match — so filtering to non-GETs would
    // pass while protection had become accidental and the run reported the
    // memory as protected by a concurrent write. The tool must not touch it.
    expect(JSON.stringify(applyServer.calls)).not.toContain("f-1");
    const lww = applyDeps.log.mock.calls.map((c) => c[0]).filter((m) => /f-1/u.test(m));
    expect(lww).toEqual([]);
    // And no cap was charged for it: a protected row must not shrink the
    // blast-radius budget for work that never happens.
    expect(applied.capUsed).toBe(1);
  });

  it("TC-SLACKAPP-064 an unrecognised protected topic is rejected at argument validation", () => {
    // A typo that matches no topic silently protects nothing, and the operator
    // does not find out until finance memories are deleted. Rejected up front.
    expect(() => parseArgs(["--stage", "test", "--protected-topics", "personal_finance"])).toThrow(
      /personal_finance/,
    );
    expect(() =>
      parseArgs(["--stage", "test", "--protected-topics", "personal-finance,nope"]),
    ).toThrow(/nope/);
    expect(
      parseArgs(["--stage", "test", "--protected-topics", "personal-finance,operations"])
        .protectedTopics,
    ).toEqual(["personal-finance", "operations"]);
  });
});

describe("two-pass consensus (#123)", () => {
  // The 66%-agreement finding that motivated the issue: one classification pass
  // is not reproducible enough to authorize deletions from. Consensus is the
  // narrowing operation — an id is offered only if EVERY pass independently said
  // DELETE, and everything else is reported rather than acted on.
  const del = (id, extra = {}) => ({
    id,
    verdict: "DELETE",
    reason: "stale",
    contentHash: contentHash(`c-${id}`),
    version: 1,
    ...extra,
  });
  const keep = (id) => ({ id, verdict: "KEEP", reason: "durable" });

  // Numbered outside 070-079 because it is a CLI-validation case, a sibling of
  // TC-SLACKAPP-064, rather than a property of the intersection itself.
  it("TC-SLACKAPP-069 --consensus-passes must be an integer of at least 2", () => {
    // 2.5 is the case that matters: `Number.isFinite` and `> 0` both accept it,
    // the pass loop silently runs twice, and the log says "pass 1 of 2.5" while
    // the report says 2 — a run whose own summary disagrees with its own
    // invocation. And `--consensus-passes 1` asks for consensus and gets none,
    // which is the single-pass behavior the flag exists to replace: refused by
    // name rather than accepted and quietly downgraded.
    expect(() => parseArgs(["--stage", "test", "--consensus-passes", "2.5"])).toThrow(/integer/u);
    expect(() => parseArgs(["--stage", "test", "--consensus-passes", "1"])).toThrow(/at least 2/u);
    expect(() => parseArgs(["--stage", "test", "--consensus-passes", "0"])).toThrow();
    expect(parseArgs(["--stage", "test", "--consensus-passes", "3"]).consensusPasses).toBe(3);
    // Omitted is the single-pass default, not an error: consensus is opt-in.
    expect(parseArgs(["--stage", "test"]).consensusPasses).toBeUndefined();
  });

  it("TC-SLACKAPP-070 only ids DELETEd by both passes are offered; the rest are unstable", () => {
    const { decisions, report } = consensusDecisions([
      [del("both"), del("one-only"), keep("neither")],
      [del("both"), keep("one-only"), keep("neither")],
    ]);
    const byId = Object.fromEntries(decisions.map((d) => [d.id, d]));

    expect(byId["both"].verdict).toBe("DELETE");
    // Its own verdict, not a KEEP: a KEEP would claim the classifier judged it
    // durable, when in fact one pass wanted it gone and the passes disagreed —
    // which is the number this whole design exists to surface.
    expect(byId["one-only"].verdict).toBe("UNSTABLE");
    expect(byId["one-only"].verdicts).toEqual(["DELETE", "KEEP"]);
    expect(byId["neither"].verdict).toBe("KEEP");
    expect(report.disagreed).toBe(1);
  });

  it("TC-SLACKAPP-071 the passes are independent and the INTERSECTION decides", () => {
    // Neither "first response wins" nor "last response wins" can produce this
    // answer: pass 1 alone would offer a+b, pass 2 alone would offer b+c.
    const { decisions } = consensusDecisions([
      [del("a"), del("b"), keep("c")],
      [keep("a"), del("b"), del("c")],
    ]);
    const offered = decisions.filter((d) => d.verdict === "DELETE").map((d) => d.id);
    expect(offered).toEqual(["b"]);
  });

  it("TC-SLACKAPP-072 the summary reports both pass counts, the intersection, and the disagreement rate", async () => {
    const memories = [memory("a", "x"), memory("b", "y"), memory("c", "z")];
    const server = fakeServer(memories);
    let pass = 0;
    const llm = vi.fn(async (_p, batch) => {
      pass += 1;
      // Pass 1 deletes a+b; pass 2 deletes b only. Intersection = {b}.
      const deleting = pass === 1 ? ["a", "b"] : ["b"];
      return JSON.stringify({
        verdicts: batch.map((m) => ({
          id: m.id,
          verdict: deleting.includes(m.id) ? "DELETE" : "KEEP",
          reason: "r",
          topic: "engineering",
        })),
      });
    });
    const deps = baseDeps(server, llm, tempDir());
    await runCleanup(baseOpts({ consensusPasses: 2 }), deps);

    // A drop in reproducibility must be visible: an unreported number is a
    // number nobody watches.
    const line = deps.log.mock.calls.map((c) => c[0]).find((m) => /CONSENSUS/u.test(m));
    expect(line).toMatch(/pass 1 DELETE=2/u);
    expect(line).toMatch(/pass 2 DELETE=1/u);
    expect(line).toMatch(/agreed=1/u);
    expect(line).toMatch(/disagreed=1/u);
    expect(line).toMatch(/50%/u); // 1 of 2 ids either pass wanted deleted
  });

  it("TC-SLACKAPP-073 one usable pass is NOT consensus: nothing is offered", () => {
    // Falling back to "use the other pass" would quietly restore exactly the
    // non-reproducible single-pass behavior consensus exists to remove.
    const { decisions, report } = consensusDecisions([[del("a"), del("b")], null]);
    expect(decisions.some((d) => d.verdict === "DELETE")).toBe(false);
    expect(report.usablePasses).toBe(1);
    expect(report.consensusReached).toBe(false);
  });

  it("TC-SLACKAPP-074 an id a later pass never judged is not treated as agreement", () => {
    // Absence of a verdict is not a DELETE and is not a KEEP.
    const { decisions } = consensusDecisions([
      [del("judged-twice"), del("judged-once")],
      [del("judged-twice")],
    ]);
    const byId = Object.fromEntries(decisions.map((d) => [d.id, d]));
    expect(byId["judged-twice"].verdict).toBe("DELETE");
    expect(byId["judged-once"].verdict).toBe("UNSTABLE");
    expect(byId["judged-once"].verdicts).toEqual(["DELETE", null]);
  });

  it("TC-SLACKAPP-075 protection wins over the intersection, even when the passes disagree on topic", () => {
    // Order is asserted because both orders agree today and only one keeps
    // agreeing when a pass returns a DIFFERENT topic for the same id — the
    // realistic failure, since topic is a model judgment like any other.
    const out = planDecisions(
      [memory("f-1", "my positions")],
      [{ id: "f-1", verdict: "DELETE", reason: "r", topic: "personal-finance" }],
      { protectedTopics: ["personal-finance"] },
    );
    const alsoOut = planDecisions(
      [memory("f-1", "my positions")],
      [{ id: "f-1", verdict: "DELETE", reason: "r", topic: "engineering" }],
      { protectedTopics: ["personal-finance"] },
    );
    // Pass 2 mis-topics it, so an intersection over RAW verdicts would see
    // DELETE/DELETE and offer it. Protection is applied per pass FIRST, so the
    // protected pass contributes RETAIN and the id can never be offered.
    const { decisions } = consensusDecisions([out, alsoOut]);
    const byId = Object.fromEntries(decisions.map((d) => [d.id, d]));
    expect(byId["f-1"].verdict).not.toBe("DELETE");
    expect(["RETAIN", "UNSTABLE"]).toContain(byId["f-1"].verdict);
  });

  it("TC-SLACKAPP-076 MERGE is withheld from the offered set in v1, and the count is reported", () => {
    const merge = {
      id: "s",
      verdict: "MERGE",
      reason: "frags",
      contentHash: contentHash("c-s"),
      version: 1,
      mergedContent: "m",
      mergedContentHash: contentHash("m"),
      absorbs: [{ id: "a", contentHash: contentHash("c-a"), version: 1 }],
    };
    const { decisions, report } = consensusDecisions([
      [merge, del("d")],
      [merge, del("d")],
    ]);
    const byId = Object.fromEntries(decisions.map((d) => [d.id, d]));
    // v1 approves deletions only. An unreported withholding would read as "the
    // classifier found no merges".
    expect(byId["s"].verdict).not.toBe("MERGE");
    expect(report.mergesWithheld).toBe(1);
    expect(byId["d"].verdict).toBe("DELETE");
  });

  it("TC-SLACKAPP-078 a pass that failed every batch is reported as no consensus, not as disagreement", async () => {
    // The dangerous shape: `classifyAll` reports a total failure as a full list of
    // SKIP rows, which look exactly like "this pass judged the memory and declined
    // to delete it". The intersection is still safe — a SKIP is not a DELETE, so
    // nothing extra is offered — but the REPORT would claim the two passes
    // disagreed, when in truth the second pass never ran. An operator reading
    // "agreement=0%" would go looking for a classifier that changed its mind
    // instead of a transport that broke.
    const memories = [memory("a", "x"), memory("b", "y")];
    const server = fakeServer(memories);
    let call = 0;
    const llm = vi.fn(async (_p, batch) => {
      call += 1;
      // Attempts 1 (pass 1) succeed; every later attempt (pass 2 and its retry)
      // throws, so pass 2 loses all of its batches.
      if (call > 1) throw new Error("transport is down");
      return JSON.stringify({
        verdicts: batch.map((m) => ({ id: m.id, verdict: "DELETE", reason: "r", topic: "engineering" })),
      });
    });
    const deps = baseDeps(server, llm, tempDir());
    const result = await runCleanup(baseOpts({ consensusPasses: 2 }), deps);

    const line = deps.log.mock.calls.map((c) => c[0]).find((m) => /CONSENSUS/u.test(m));
    expect(line).toMatch(/NO CONSENSUS/u);
    expect(line).toMatch(/pass 2 DELETE=failed/u);
    // Nothing offered, and the reason names the failure rather than a
    // disagreement the model never had.
    expect(result.decisions.some((d) => d.verdict === "DELETE")).toBe(false);
    const unstable = result.decisions.filter((d) => d.verdict === "UNSTABLE");
    expect(unstable.length).toBe(2);
    for (const d of unstable) expect(d.reason).toMatch(/pass failed/u);
    // A partial outage across passes is NOT the broken-classifier exit: pass 1
    // classified the whole corpus, so the path works and 5 would misdiagnose it.
    expect(result.exitCode).toBe(0);
  });

  it("TC-SLACKAPP-079 a consensus dry run can be replayed with --apply", async () => {
    // The same defect class TC-SLACKAPP-065 caught for RETAIN: the planner writes
    // UNSTABLE rows to the decision file, so a replay validator that does not know
    // the verdict makes every `--apply` after a consensus run fail at load — the
    // safety mechanism breaking the tool it exists to make safe.
    const memories = [memory("agreed", "x"), memory("contested", "y")];
    const server = fakeServer(memories);
    let pass = 0;
    const llm = vi.fn(async (_p, batch) => {
      pass += 1;
      const deleting = pass === 1 ? ["agreed", "contested"] : ["agreed"];
      return JSON.stringify({
        verdicts: batch.map((m) => ({
          id: m.id,
          verdict: deleting.includes(m.id) ? "DELETE" : "KEEP",
          reason: "r",
          topic: "engineering",
        })),
      });
    });
    const dryDeps = baseDeps(server, llm, tempDir());
    const dry = await runCleanup(baseOpts({ consensusPasses: 2 }), dryDeps);
    expect(dry.decisions.find((d) => d.id === "contested").verdict).toBe("UNSTABLE");

    const applyServer = fakeServer(memories);
    const applyDeps = baseDeps(applyServer, llm, tempDir());
    const applied = await runCleanup(
      baseOpts({ apply: true, decisionsFile: dry.decisionPath }),
      applyDeps,
    );

    expect(applied.exitCode).toBe(0);
    // The agreed id is deleted; the contested one is not touched at all — asserted
    // over every call, GETs included, because an UNSTABLE row that reached the
    // delete branch would be re-read and then skipped as an LWW guard, which
    // reports as "a concurrent write protected me" rather than as a defect.
    expect(JSON.stringify(applyServer.calls)).toContain("agreed");
    expect(JSON.stringify(applyServer.calls)).not.toContain("contested");
    expect(applied.capUsed).toBe(1);
  });

  it("TC-SLACKAPP-077 consensus never widens the destructive set", () => {
    // Asserted as a SET RELATION, not a count, so a future refactor cannot add
    // an id sourced from anywhere other than the intersection.
    const passes = [
      [del("a"), del("b"), keep("c"), del("d")],
      [del("a"), keep("b"), del("c"), del("d")],
    ];
    const { decisions } = consensusDecisions(passes);
    const deleteIds = (list) =>
      new Set(list.filter((d) => d.verdict === "DELETE").map((d) => d.id));
    const intersection = new Set(
      [...deleteIds(passes[0])].filter((id) => deleteIds(passes[1]).has(id)),
    );
    for (const id of deleteIds(decisions)) {
      expect(intersection.has(id)).toBe(true);
    }
    expect(deleteIds(decisions).size).toBeGreaterThan(0); // not vacuously empty
  });
});

describe("the offered approval record (#123)", () => {
  const del = (id) => ({
    id,
    verdict: "DELETE",
    reason: "stale",
    contentHash: contentHash(`c-${id}`),
    version: 1,
  });

  it("TC-SLACKAPP-023b the offered record carries ids, a hash, a stage, and a timestamp — no memory content", () => {
    // This parameter is a plain `String` (the boundary admits neither
    // `kms:Encrypt` nor `kms:GenerateDataKey`, so a SecureString write is denied
    // at runtime), readable by anything holding `ssm:GetParameters` on the stage
    // tree. Asserted structurally over the SERIALIZED value rather than by
    // eyeballing fields: a nested `snippet` added later would satisfy a
    // field-by-field check and still publish memory content.
    const record = buildOfferedRecord({
      stage: "prod",
      decisions: [
        del("m-1"),
        { ...del("m-2"), snippet: "SENTINEL-CONTENT" },
        // Only DELETE is offered. Every other verdict in the list is a memory
        // the run decided NOT to destroy, and a RETAIN is one policy actively
        // protected — so a record built over every row would hand the apply task
        // exactly the ids the protected-topic rule exists to withhold, with the
        // operator's approval attached.
        { id: "m-keep", verdict: "KEEP", reason: "durable" },
        { id: "m-protected", verdict: "RETAIN", reason: "protected topic personal-finance" },
        { id: "m-unstable", verdict: "UNSTABLE", reason: "passes disagreed on deletion" },
      ],
      generatedAt: "2026-08-05T00:00:00.000Z",
    });
    expect(Object.keys(record).sort()).toEqual(["generatedAt", "hash", "ids", "stage"]);
    expect(record.ids).toEqual(["m-1", "m-2"]);
    expect(record.stage).toBe("prod");
    expect(JSON.stringify(record)).not.toMatch(/SENTINEL-CONTENT/u);
    // The hash is over the ids, so the callback's comparison detects a
    // regenerated list (TC-SLACKAPP-020) — and it is over a JOIN with a
    // separator no id can contain, so two different lists whose ids concatenate
    // identically get different hashes. Without the separator `["ab","c"]` and
    // `["a","bc"]` are one hash, and a click approving one list would be accepted
    // against the other.
    expect(record.hash).toMatch(/^sha256:[0-9a-f]{64}$/u);
    const stamp = { stage: "prod", generatedAt: "2026-08-05T00:00:00.000Z" };
    expect(buildOfferedRecord({ ...stamp, decisions: [del("ab"), del("c")] }).hash).not.toBe(
      buildOfferedRecord({ ...stamp, decisions: [del("a"), del("bc")] }).hash,
    );
  });

  it("TC-SLACKAPP-024 an offered list over the 4096-byte parameter limit throws rather than truncating", () => {
    // Truncating would ask the operator to approve a list that is not the list
    // they were shown, and the ids are what the apply task deletes — so a
    // silently shortened record is the one failure mode that produces a WRONG
    // apply rather than a failed one. It must be loud.
    //
    // 4096 is the STANDARD tier's content limit; the advanced tier's 8 KB is not
    // an option here, since an advanced parameter incurs a charge and cannot be
    // reverted. `--cap 50` keeps a real record at ~2 KB, so hitting this needs a
    // cap far above the default — which is exactly the operator mistake worth
    // failing on.
    const many = Array.from({ length: 200 }, (_, i) => del(`memory-with-a-realistic-id-${i}`));
    expect(() =>
      buildOfferedRecord({ stage: "prod", decisions: many, generatedAt: "2026-08-05T00:00:00.000Z" }),
    ).toThrow(/4096|parameter limit/u);
    // Asserted on the SERIALIZED length, not the id count: a limit expressed as
    // "N ids" drifts from the real constraint the moment ids get longer, and the
    // thing SSM rejects is bytes.
    const ok = buildOfferedRecord({
      stage: "prod",
      decisions: many.slice(0, 40),
      generatedAt: "2026-08-05T00:00:00.000Z",
    });
    expect(JSON.stringify(ok).length).toBeLessThanOrEqual(4096);
    expect(ok.ids).toHaveLength(40);
  });
});

describe("materializing the approved ids in the apply task (#123)", () => {
  const OFFERED = "/mem9-on-aws/prod/approvals/offered";
  const claimName = (hash) => claimParameterName("/mem9-on-aws/prod", hash);

  /**
   * Fake SSM whose `send` answers `GetParametersCommand` from a name→value map.
   *
   * Keyed on the command's `input.Names` rather than on the class, so a
   * production switch to `GetParameterCommand` (singular) still reads here —
   * that distinction is IAM's, and TC-SLACKAPP-047g pins it on the Lambda side.
   * What this fake exists to model is the shape SSM actually returns: an absent
   * name is simply MISSING from `Parameters` and echoed in `InvalidParameters`,
   * never an empty-valued entry.
   */
  function fakeSsm(values) {
    const reads = [];
    return {
      reads,
      send: vi.fn(async (command) => {
        const names = command?.input?.Names ?? [];
        reads.push(...names);
        const found = names.filter((n) => n in values);
        return {
          Parameters: found.map((n) => ({ Name: n, Value: values[n] })),
          InvalidParameters: names.filter((n) => !(n in values)),
        };
      }),
    };
  }

  const offered = (ids, extra = {}) =>
    JSON.stringify({
      stage: "prod",
      hash: contentHash(ids.join("\n")),
      ids,
      generatedAt: "2026-08-05T00:00:00.000Z",
      ...extra,
    });

  it("TC-SLACKAPP-131 the claim name is one SSM will accept on WRITE, and matches the facade's copy", async () => {
    // The defect this pins was total and silent: `contentHash` returns
    // `sha256:<hex>`, and a `:` cannot appear in an SSM parameter name.
    // PutParameter answers ValidationException, which `claimAndRun` classifies by
    // error NAME — not `ParameterAlreadyExists`, so it fell to the generic branch
    // and answered "The approval could not be recorded" for EVERY click on every
    // stage. Probed live in ap-northeast-1: colon rejected on write, dash
    // accepted. Nothing caught it because every SSM double was a Map keyed on the
    // name string, so no double could reject a name's SHAPE.
    const hash = contentHash("m-1");
    expect(hash).toMatch(/^sha256:/u);
    const name = claimParameterName("/mem9-on-aws/prod", hash);
    expect(name).not.toContain(":");
    expect(() => assertClaimParameterName(name)).not.toThrow();
    // The prefix is kept rather than stripped so an operator reading
    // describe-parameters output can still tell which algorithm produced it.
    expect(name).toBe(`/mem9-on-aws/prod/approvals/approved-${hash.replace(":", "-")}`);
    // And the guard has to actually reject the old form, or it is decoration.
    expect(() =>
      assertClaimParameterName(`/mem9-on-aws/prod/approvals/approved-${hash}`),
    ).toThrow(/ValidationException/u);

    // The WRITER of this record is the facade Lambda, which shares no module with
    // this script — so the derivation is duplicated and this is the only thing
    // keeping the two in agreement. A drift here means the task looks for a claim
    // at a name the Lambda never wrote and dies with "no approval record", which
    // is the same symptom as a tampered claim from a cause nobody would guess.
    //
    // Both functions are CALLED rather than their sources compared: comparing
    // source text passes as long as the facade matches a literal in this file,
    // which is not the property that matters and does not notice the script side
    // changing at all. Only this direction is importable — vitest transforms the
    // TS for an .mjs test, while an infra/*.test.ts importing the .mjs fails
    // typecheck (TS7016), the same asymmetry noted at slack-approval.test.ts's
    // boundaryStatements().
    const { claimParameterName: facadeClaimParameterName } = await import(
      "../infra/src/oauth-facade/slack-interactions.ts"
    );
    for (const prefix of ["/mem9-on-aws/prod", "/mem9-on-aws/pr-123"]) {
      expect(facadeClaimParameterName(prefix, hash)).toBe(
        claimParameterName(prefix, hash),
      );
    }
  });

  it("TC-SLACKAPP-091 the ids come from the CLAIM named by the hash, not from the offered record", async () => {
    // The claim is what the operator's click actually approved. `offered` is
    // overwritten by every run, so a task that read `offered` would delete the
    // list the CURRENT run produced rather than the one the operator saw — and
    // it would do so carrying a valid approval. The claim is immutable once
    // written (`Overwrite: false`), which is the only reason a click is safe to
    // honour minutes later.
    //
    // Both records are seeded with DIFFERENT ids, so a read from the wrong one
    // cannot pass: an assertion that only counted ids, or that seeded both with
    // the same list, would be satisfied by either source.
    const approvedIds = ["m-approved-1", "m-approved-2"];
    const hash = contentHash(approvedIds.join("\n"));
    const ssm = fakeSsm({
      [OFFERED]: offered(["m-regenerated-since"]),
      [claimName(hash)]: JSON.stringify({
        stage: "prod",
        hash,
        ids: approvedIds,
        claimedAt: "2026-08-05T00:05:00.000Z",
        taskArn: "arn:aws:ecs:ap-northeast-1:123456789012:task/mem9/abc",
      }),
    });
    const dir = tempDir();
    const idsFile = join(dir, "approved.txt");

    await materializeApprovedIds({
      ssm,
      stage: "prod",
      ssmPrefix: "/mem9-on-aws/prod",
      hash,
      idsFile,
      fs: { writeFileSync },
    });

    expect(readFileSync(idsFile, "utf8").trim().split("\n")).toEqual(approvedIds);
    expect(ssm.reads).toContain(claimName(hash));
    expect(ssm.reads).not.toContain(OFFERED);
  });

  it("TC-SLACKAPP-092 a claim whose ids do not hash to the requested hash is refused", async () => {
    // The hash arrives as a container override, which `DescribeTasks` echoes and
    // any holder of ecs:RunTask on this task definition can choose. Trusting the
    // record it names without re-deriving the hash over the ids would let a
    // caller point the apply at a tampered record. Re-deriving makes the ids
    // themselves the thing the hash vouches for.
    const hash = contentHash(["m-1"].join("\n"));
    const ssm = fakeSsm({
      [claimName(hash)]: JSON.stringify({
        stage: "prod",
        hash,
        // Hash says one id; the record carries another. The record's OWN `hash`
        // field agrees with the request, so a check that compared those two
        // strings would pass this.
        ids: ["m-substituted"],
        claimedAt: "2026-08-05T00:05:00.000Z",
      }),
    });
    const dir = tempDir();
    const idsFile = join(dir, "approved.txt");

    await expect(
      materializeApprovedIds({
        ssm,
        stage: "prod",
        ssmPrefix: "/mem9-on-aws/prod",
        hash,
        idsFile,
        fs: { writeFileSync },
      }),
    ).rejects.toThrow(/hash/u);
    expect(() => readFileSync(idsFile, "utf8")).toThrow();
  });

  it("TC-SLACKAPP-093 a claim naming another stage is refused", async () => {
    // Same reasoning as #102's decision-file stage guard: a preview approval must
    // never apply to prod. The parameter PREFIX is stage-scoped, so this can only
    // happen through a hand-written record — which is exactly the case a guard is
    // for, since the alternative is an apply the operator never approved.
    const ids = ["m-1"];
    const hash = contentHash(ids.join("\n"));
    const ssm = fakeSsm({
      [claimName(hash)]: JSON.stringify({
        stage: "pr-7",
        hash,
        ids,
        claimedAt: "2026-08-05T00:05:00.000Z",
      }),
    });
    const dir = tempDir();
    const idsFile = join(dir, "approved.txt");

    await expect(
      materializeApprovedIds({
        ssm,
        stage: "prod",
        ssmPrefix: "/mem9-on-aws/prod",
        hash,
        idsFile,
        fs: { writeFileSync },
      }),
    ).rejects.toThrow(/stage/u);
    expect(() => readFileSync(idsFile, "utf8")).toThrow();
  });

  it("TC-SLACKAPP-094 an absent claim is refused, not treated as an empty approval", async () => {
    // An absent name comes back in `InvalidParameters`, missing from
    // `Parameters` — so `find(...)?.Value` is `undefined` and a permissive path
    // would write an EMPTY ids file. `--ids` with an empty file means "approve
    // nothing", so the run would exit 0 having deleted nothing and the operator
    // would read a successful apply that never happened.
    const ssm = fakeSsm({});
    const dir = tempDir();
    const idsFile = join(dir, "approved.txt");

    await expect(
      materializeApprovedIds({
        ssm,
        stage: "prod",
        ssmPrefix: "/mem9-on-aws/prod",
        hash: contentHash("m-1"),
        idsFile,
        fs: { writeFileSync },
      }),
    ).rejects.toThrow(/approval record/u);
    expect(() => readFileSync(idsFile, "utf8")).toThrow();
  });

  it("TC-SLACKAPP-095 a claim with an empty id list is refused rather than written", async () => {
    // `[]` hashes consistently, so the hash check cannot catch it, and it is
    // exactly what a partially-written record looks like. An empty `--ids` file
    // is indistinguishable from "approve nothing" — a silent no-op reported as a
    // clean apply.
    const ids = [];
    const hash = contentHash(ids.join("\n"));
    const ssm = fakeSsm({
      [claimName(hash)]: JSON.stringify({
        stage: "prod",
        hash,
        ids,
        claimedAt: "2026-08-05T00:05:00.000Z",
      }),
    });
    const dir = tempDir();
    const idsFile = join(dir, "approved.txt");

    await expect(
      materializeApprovedIds({
        ssm,
        stage: "prod",
        ssmPrefix: "/mem9-on-aws/prod",
        hash,
        idsFile,
        fs: { writeFileSync },
      }),
    ).rejects.toThrow(/no ids/u);
    expect(() => readFileSync(idsFile, "utf8")).toThrow();
  });

  it("TC-SLACKAPP-096 a malformed claim is refused by shape", async () => {
    // A truncated or non-JSON value must not reach `JSON.parse` unguarded: an
    // uncaught SyntaxError exits 1 with a stack that quotes the parameter value,
    // and this value is the one place ids legitimately live.
    const hash = contentHash("m-1");
    const ssm = fakeSsm({ [claimName(hash)]: '{"stage":"prod","ids":' });
    const dir = tempDir();
    const idsFile = join(dir, "approved.txt");

    await expect(
      materializeApprovedIds({
        ssm,
        stage: "prod",
        ssmPrefix: "/mem9-on-aws/prod",
        hash,
        idsFile,
        fs: { writeFileSync },
      }),
    ).rejects.toThrow(/approval record/u);
    expect(() => readFileSync(idsFile, "utf8")).toThrow();
  });

  it("TC-SLACKAPP-097 the ids file is newline-delimited exactly as --ids parses it", async () => {
    // `readApprovedIds` splits on "\n" and trims, so the two formats that would
    // silently produce ONE id are a JSON array and a comma-joined line. Asserted
    // by round-tripping through the real parser rather than by matching a
    // string, so the contract is proven against the consumer.
    const ids = ["m-1", "m-2", "m-3"];
    const hash = contentHash(ids.join("\n"));
    const ssm = fakeSsm({
      [claimName(hash)]: JSON.stringify({
        stage: "prod",
        hash,
        ids,
        claimedAt: "2026-08-05T00:05:00.000Z",
      }),
    });
    const dir = tempDir();
    const idsFile = join(dir, "approved.txt");

    await materializeApprovedIds({
      ssm,
      stage: "prod",
      ssmPrefix: "/mem9-on-aws/prod",
      hash,
      idsFile,
      fs: { writeFileSync },
    });

    // The consumer's own reading of the file, through runCleanup's --ids path:
    // three memories offered, all three approved, all three deleted.
    const server = fakeServer(ids.map((id) => memory(id, `c-${id}`)));
    const llm = fakeLlm([
      ids.map((id) => ({ id, verdict: "DELETE", reason: "stale" })),
    ]);
    const result = await runCleanup(
      baseOpts({ apply: true, idsFile }),
      baseDeps(server, llm, dir),
    );
    expect(result.skippedByFilter).toBe(0);
    for (const id of ids) {
      expect(server.store.get(id).state).toBe("deleted");
    }
  });

  it("TC-SLACKAPP-098 the ids file never contains memory content, and no log line quotes an id", async () => {
    // The task's log goes to CloudWatch, which is an accepted surface for
    // snippets — but the ids file lands on the task's ephemeral disk, and the
    // record it is built from is a plain String parameter readable by anything
    // with ssm:GetParameters on the stage tree. A record that grew a `snippet`
    // field must not have it copied into the file.
    const ids = ["m-1"];
    const hash = contentHash(ids.join("\n"));
    const ssm = fakeSsm({
      [claimName(hash)]: JSON.stringify({
        stage: "prod",
        hash,
        ids,
        claimedAt: "2026-08-05T00:05:00.000Z",
        snippet: "SENTINEL-CONTENT",
      }),
    });
    const dir = tempDir();
    const idsFile = join(dir, "approved.txt");
    const log = vi.fn();

    await materializeApprovedIds({
      ssm,
      stage: "prod",
      ssmPrefix: "/mem9-on-aws/prod",
      hash,
      idsFile,
      fs: { writeFileSync },
      log,
    });

    expect(readFileSync(idsFile, "utf8")).not.toContain("SENTINEL-CONTENT");
    for (const call of log.mock.calls) {
      expect(String(call[0])).not.toContain("SENTINEL-CONTENT");
    }
    // The COUNT is logged, never the ids: a log line naming them would put
    // memory identifiers in CloudWatch for an operator who only needs to know
    // the apply matched the approval.
    expect(log).toHaveBeenCalled();
    for (const call of log.mock.calls) {
      expect(String(call[0])).not.toContain("m-1");
    }
  });

  it("TC-SLACKAPP-098b what is returned to the caller is a count and the coordinates, never the ids", async () => {
    // The return value is what the outcome update closes over, and it travels to
    // `chat.update`. Ids on it would reach a Slack message the moment anything
    // spread the claim into a payload — so the file is the ONLY place they go.
    const ids = ["m-1", "m-2"];
    const hash = contentHash(ids.join("\n"));
    const ssm = fakeSsm({
      [claimName(hash)]: JSON.stringify({
        stage: "prod",
        hash,
        ids,
        claimedAt: "2026-08-05T00:05:00.000Z",
        messageTs: "1754400000.000100",
        messageChannel: "C0APPROVAL",
      }),
    });
    const dir = tempDir();
    const idsFile = join(dir, "approved.txt");

    const claim = await materializeApprovedIds({
      ssm,
      stage: "prod",
      ssmPrefix: "/mem9-on-aws/prod",
      hash,
      idsFile,
      fs: { writeFileSync },
    });

    expect(claim.count).toBe(2);
    expect(claim.messageTs).toBe("1754400000.000100");
    expect(claim.messageChannel).toBe("C0APPROVAL");
    expect(JSON.stringify(claim)).not.toContain("m-1");
    // The ids DID land, in the file, which is the other half of the same property.
    expect(readFileSync(idsFile, "utf8")).toBe("m-1\nm-2\n");

    // A record with no coordinates yields none rather than `undefined` values that
    // would reach `chat.update` as a `channel_not_found`.
    const bare = fakeSsm({
      [claimName(hash)]: JSON.stringify({
        stage: "prod",
        hash,
        ids,
        claimedAt: "2026-08-05T00:05:00.000Z",
      }),
    });
    const plain = await materializeApprovedIds({
      ssm: bare,
      stage: "prod",
      ssmPrefix: "/mem9-on-aws/prod",
      hash,
      idsFile,
      fs: { writeFileSync },
    });
    expect(plain.messageTs).toBeUndefined();
    expect(plain.messageChannel).toBeUndefined();
  });
});

describe("the apply task's in-container runtime (#123)", () => {
  const environmentKeys = [
    "AWS_REGION",
    "MEM9_APPROVAL_HASH",
    "MEM9_BEDROCK_PROJECT",
    "MEM9_DB_HOST",
    "MEM9_DB_NAME",
    "MEM9_DB_PORT",
    "MEM9_DB_SECRET",
    "MEM9_LLM_MODEL",
    "MEM9_SSM_PREFIX",
    "MEM9_TENANT_ID",
  ];
  afterEach(() => {
    for (const key of environmentKeys) delete process.env[key];
  });

  /** The env the ECS task definition (infra/slack-approval.ts) actually sets. */
  function containerEnv(extra = {}) {
    Object.assign(process.env, {
      AWS_REGION: "ap-northeast-1",
      MEM9_DB_HOST: "writer.example.com",
      MEM9_DB_NAME: "mem9",
      MEM9_DB_PORT: "5432",
      // ECS resolves the `ssm:` entry to the secret's JSON before the process
      // starts, exactly as it does for the consolidation task.
      MEM9_DB_SECRET: JSON.stringify({
        username: "mem9",
        password: "fixture-password",
      }),
      MEM9_SSM_PREFIX: "/mem9-on-aws/prod",
      MEM9_TENANT_ID: TENANT,
      ...extra,
    });
  }

  /** pg double that records every construction and query. */
  function fakeClientClass(calls) {
    return class Client {
      constructor(options) {
        calls.push(["construct", options]);
      }
      async connect() {
        calls.push(["connect"]);
      }
      async query(sql, parameters) {
        calls.push(["query", sql, parameters]);
        if (sql.includes("pg_try_advisory_lock")) {
          return { rows: [{ acquired: true }] };
        }
        return { rows: [] };
      }
      async end() {
        calls.push(["end"]);
      }
    };
  }

  it("TC-SLACKAPP-100 takes its database configuration from the environment, with no SSM or Secrets Manager read", async () => {
    // The image ships @aws-sdk/client-ssm now, so this is no longer about a
    // missing module — it is about grants. The task role holds ssm:GetParameters
    // ONLY under `approvals/*` (infra/slack-approval.ts), so the operator CLI's
    // `db/*` discovery is an AccessDenied inside the container, and the DB secret
    // arrives pre-resolved in `MEM9_DB_SECRET` instead. Mirrors
    // memory-consolidation.mjs's createProductionDeps.
    containerEnv();
    const calls = [];
    const ssm = fakeAwsClient();
    const secrets = fakeAwsClient();

    const production = await createCleanupDeps(
      { stage: "prod", apply: true, cap: 50 },
      { Client: fakeClientClass(calls), ssm, secrets, getToken: vi.fn(), fromNodeProviderChain: vi.fn() },
    );

    expect(ssm.send).not.toHaveBeenCalled();
    expect(secrets.send).not.toHaveBeenCalled();
    expect(production.tenantId).toBe(TENANT);
    // Asserted on the connection options, not merely on "it connected": a path
    // that read the env and then handed pg a partly-undefined config would still
    // construct and would fail at TLS time with an unrelated message.
    expect(calls[0]).toEqual([
      "construct",
      expect.objectContaining({
        host: "writer.example.com",
        port: 5432,
        database: "mem9",
        user: "mem9",
        password: "fixture-password",
      }),
    ]);
    // The shared mutex is what stops a click-triggered apply from racing the
    // weekly consolidation. Absent, the two would interleave writes.
    const mutex = await production.deps.acquireMutex("prod");
    expect(mutex).not.toBeNull();
    await mutex.release();
    await production.close();
    expect(calls.at(-1)).toEqual(["end"]);
  });

  it("TC-SLACKAPP-101 still resolves the database through SSM and Secrets Manager for the operator CLI", async () => {
    // The operator path has no MEM9_DB_SECRET and its human IAM identity CAN read
    // `db/*`. Both paths must keep working from one function: a container-only
    // rewrite would break the #102 runbook the README documents.
    process.env.AWS_REGION = "ap-northeast-1";
    process.env.MEM9_TENANT_ID = TENANT;
    const calls = [];
    const secretArn =
      "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:mem9-db-x";
    const ssm = fakeAwsClient({
      "/mem9-on-aws/prod/db/host": "writer.example.com",
      "/mem9-on-aws/prod/db/port": "5432",
      "/mem9-on-aws/prod/db/name": "mem9",
      "/mem9-on-aws/prod/db/secret-arn": secretArn,
    });
    const secrets = fakeAwsClient({
      [secretArn]: JSON.stringify({ username: "mem9", password: "from-secret" }),
    });

    const production = await createCleanupDeps(
      { stage: "prod", apply: true, cap: 50 },
      { Client: fakeClientClass(calls), ssm, secrets, getToken: vi.fn(), fromNodeProviderChain: vi.fn() },
    );

    expect(ssm.sent[0].Names).toEqual([
      "/mem9-on-aws/prod/db/host",
      "/mem9-on-aws/prod/db/port",
      "/mem9-on-aws/prod/db/name",
      "/mem9-on-aws/prod/db/secret-arn",
    ]);
    expect(secrets.sent[0].SecretId).toBe(secretArn);
    expect(calls[0][1]).toMatchObject({ password: "from-secret" });
    await production.close();
  });

  it("TC-SLACKAPP-102 materializes the approved ids at the --ids path the task definition passes", async () => {
    const ids = ["m-1", "m-2"];
    const hash = contentHash(ids.join("\n"));
    const dir = tempDir();
    const idsFile = join(dir, "approved.txt");
    containerEnv({ MEM9_APPROVAL_HASH: hash });
    const ssm = fakeAwsClient({
      [claimParameterName("/mem9-on-aws/prod", hash)]: JSON.stringify({
        stage: "prod",
        hash,
        ids,
        claimedAt: "2026-08-05T00:05:00.000Z",
      }),
    });

    const production = await createCleanupDeps(
      { stage: "prod", apply: true, cap: 50, idsFile },
      {
        Client: fakeClientClass([]),
        ssm,
        secrets: fakeAwsClient(),
        getToken: vi.fn(),
        fromNodeProviderChain: vi.fn(),
      },
    );

    // The path is the CONTRACT with the task definition's `--ids` argument. A file
    // written anywhere else leaves `readApprovedIds` reading a missing file, so the
    // run dies loud — or worse, reads a stale one.
    expect(readFileSync(idsFile, "utf8")).toBe("m-1\nm-2\n");
    await production.close();
  });

  it("TC-SLACKAPP-103 refuses an approval hash with no ids file rather than applying unfiltered", async () => {
    // This is the whole loop's failure mode. `readApprovedIds` returns null for a
    // missing `--ids`, and null means "no filter" — so a hash-driven run that
    // materialized nowhere would delete EVERY DELETE verdict in the run, not the
    // ones the operator approved, and exit 0 reporting success.
    const hash = contentHash(["m-1"].join("\n"));
    containerEnv({ MEM9_APPROVAL_HASH: hash });

    await expect(
      createCleanupDeps(
        { stage: "prod", apply: true, cap: 50 },
        { Client: fakeClientClass([]), ssm: fakeAwsClient(), secrets: fakeAwsClient() },
      ),
    ).rejects.toThrow(/--ids/u);
  });

  it("TC-SLACKAPP-104 aborts before opening the database when the claim does not match the hash", async () => {
    // Ordering, not just the error: materialization is the cheapest guard and the
    // only one that can prove the ids are the approved ids, so it runs before the
    // connection and before the advisory lock. Reversed, a tampered claim would
    // hold the shared mutex for the length of its own failure and could block the
    // weekly consolidation.
    const ids = ["m-1"];
    const hash = contentHash(ids.join("\n"));
    const dir = tempDir();
    const idsFile = join(dir, "approved.txt");
    containerEnv({ MEM9_APPROVAL_HASH: hash });
    const calls = [];
    const ssm = fakeAwsClient({
      [claimParameterName("/mem9-on-aws/prod", hash)]: JSON.stringify({
        stage: "prod",
        // Agrees with the request, so a string comparison of the two would pass.
        hash,
        ids: ["m-substituted"],
        claimedAt: "2026-08-05T00:05:00.000Z",
      }),
    });

    await expect(
      createCleanupDeps(
        { stage: "prod", apply: true, cap: 50, idsFile },
        { Client: fakeClientClass(calls), ssm, secrets: fakeAwsClient() },
      ),
    ).rejects.toThrow(/hash/u);
    expect(calls).toEqual([]);
    expect(existsSync(idsFile)).toBe(false);
  });
});

describe("offering the list to Slack (#123)", () => {
  const BOT_TOKEN = "xoxb-fixture-not-a-real-token";
  const CHANNEL = "C0APPROVAL";
  const OFFERED = "/mem9-on-aws/prod/approvals/offered";
  const SNIPPET = "SENTINEL-MEMORY-SNIPPET";

  const del = (id, snippet = `${SNIPPET}-${id}`) => ({
    id,
    verdict: "DELETE",
    reason: "session-state",
    version: 1,
    contentHash: contentHash(`c-${id}`),
    snippet,
  });

  /**
   * SSM and Slack sharing ONE event log, because the ordering between them is a
   * correctness property and not an implementation detail: a button that exists
   * before the record it is validated against is a promise the backend cannot
   * keep.
   */
  function offerFakes(slackBodies = {}) {
    const events = [];
    const ssm = {
      puts: [],
      send: vi.fn(async (command) => {
        events.push(["ssm", command.input.Name]);
        ssm.puts.push(command.input);
        return {};
      }),
    };
    const slack = {
      calls: [],
      fetchImpl: vi.fn(async (url, options = {}) => {
        const method = String(url).split("/").pop();
        events.push(["slack", method]);
        slack.calls.push({
          url: String(url),
          method: options.method,
          headers: options.headers,
          redirect: options.redirect,
          body: JSON.parse(options.body),
        });
        const body = slackBodies[method] ?? {
          ok: true,
          channel: CHANNEL,
          ts: "1754400000.000100",
        };
        return new Response(JSON.stringify(body), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }),
    };
    return { events, ssm, slack };
  }

  function offer(overrides = {}) {
    const { ssm, slack, events } = overrides.fakes ?? offerFakes();
    return {
      events,
      ssm,
      slack,
      log: overrides.log,
      promise: postApprovalRequest({
        ssm,
        ssmPrefix: "/mem9-on-aws/prod",
        stage: "prod",
        decisions: overrides.decisions ?? [del("m-1"), del("m-2")],
        generatedAt: "2026-08-05T03:00:00.000Z",
        channel: CHANNEL,
        botToken: BOT_TOKEN,
        fetchImpl: slack.fetchImpl,
        log: overrides.log ?? vi.fn(),
      }),
    };
  }

  it("TC-SLACKAPP-105 writes the offered record before the button exists, as an overwritable plain String", async () => {
    const fakes = offerFakes();
    const log = vi.fn();
    const { promise } = offer({ fakes, log });
    const result = await promise;

    // ORDER. Posting first leaves a live Approve button whose click the callback
    // rejects with "there is no current approval list" — a spent click and an
    // operator hunting a backend fault. The write is also what INVALIDATES last
    // week's button, so it must not be reachable only through the post.
    expect(fakes.events).toEqual([
      ["ssm", OFFERED],
      ["slack", "chat.postMessage"],
      ["ssm", OFFERED],
    ]);
    const [first] = fakes.ssm.puts;
    expect(first.Name).toBe(OFFERED);
    // Runtime-only, exactly like TC-SLACKAPP-047f: `SecureString` is denied by the
    // workload boundary (no `kms:Encrypt`, no `kms:GenerateDataKey`), and
    // `Overwrite: false` would succeed once and then fail every subsequent week
    // with `ParameterAlreadyExists` — the loop would silently stop offering.
    expect(first.Type).toBe("String");
    expect(first.Overwrite).toBe(true);
    const record = JSON.parse(first.Value);
    expect(Object.keys(record).sort()).toEqual(["generatedAt", "hash", "ids", "stage"]);
    expect(record.ids).toEqual(["m-1", "m-2"]);
    expect(record.hash).toBe(contentHash("m-1\nm-2"));
    expect(result.record.hash).toBe(record.hash);
    expect(result.messageTs).toBe("1754400000.000100");
  });

  it("TC-SLACKAPP-106 carries that exact hash in both action values and shows every id it asks about", async () => {
    const { promise, slack } = offer();
    const { record } = await promise;
    const [call] = slack.calls;

    expect(call.url).toBe("https://slack.com/api/chat.postMessage");
    expect(call.method).toBe("POST");
    expect(call.headers.Authorization).toBe(`Bearer ${BOT_TOKEN}`);
    // The alert-router precedent: a redirect from an API host is never something
    // to follow with a bearer token attached.
    expect(call.redirect).toBe("manual");
    expect(call.body.channel).toBe(CHANNEL);

    const actions = call.body.blocks.filter((b) => b.type === "actions");
    expect(actions).toHaveLength(1);
    const ids = actions[0].elements.map((e) => e.action_id).sort();
    // The action ids the deployed handler branches on. A rename here is a click
    // the callback answers with "that button is not one this app knows how to
    // handle" — after the operator has reviewed the whole list.
    expect(ids).toEqual(["cleanup_approve", "cleanup_reject"]);
    for (const element of actions[0].elements) {
      // The hash is the ONLY thing the click carries. Ids cannot ride here (the
      // 2000-character value cap), and must not: the signature proves the request
      // came from the workspace, never that ids inside it are the classifier's.
      expect(element.value).toBe(record.hash);
    }

    // Every offered id appears in the message. Approving a list longer than the
    // list shown is the one failure mode that produces a WRONG apply rather than
    // a failed one — the same argument as TC-SLACKAPP-024, on the other surface.
    const rendered = JSON.stringify(call.body.blocks);
    for (const id of record.ids) expect(rendered).toContain(id);
    // Snippets are the point of the review, and Slack is an approved destination
    // for them (unlike the repository or the SSM record).
    expect(rendered).toContain(SNIPPET);
  });

  it("TC-SLACKAPP-107 refuses to post a list Block Kit would not carry whole", async () => {
    // Slack's own ceilings: 50 blocks per message, 3000 characters per section
    // text, 2000 per button value, 150 per header. A message over any of them is
    // rejected wholesale, so the operator sees nothing at all — but a message
    // that silently dropped the overflow would be worse: they would approve a
    // hash covering ids they never saw.
    const many = Array.from({ length: 4000 }, (_, i) => del(`memory-${i}`));
    const record = {
      stage: "prod",
      hash: contentHash(many.map((d) => d.id).join("\n")),
      ids: many.map((d) => d.id),
      generatedAt: "2026-08-05T03:00:00.000Z",
    };
    expect(() => buildApprovalMessage({ record, decisions: many, channel: CHANNEL })).toThrow(
      /block|too large|does not fit/iu,
    );

    const small = [del("m-1"), del("m-2")];
    const message = buildApprovalMessage({
      record: buildOfferedRecord({
        stage: "prod",
        decisions: small,
        generatedAt: "2026-08-05T03:00:00.000Z",
      }),
      decisions: small,
      channel: CHANNEL,
    });
    expect(message.blocks.length).toBeLessThanOrEqual(50);
    for (const block of message.blocks) {
      if (block.type === "header") expect(block.text.text.length).toBeLessThanOrEqual(150);
      if (block.type === "section") expect(block.text.text.length).toBeLessThanOrEqual(3000);
      for (const element of block.elements ?? []) {
        if (element.value) expect(element.value.length).toBeLessThanOrEqual(2000);
      }
    }
  });

  it("TC-SLACKAPP-108 treats Slack's HTTP 200 application errors as failures, without echoing the token", async () => {
    // Every Slack Web API method answers HTTP 200 for application errors and puts
    // the failure in `{ok: false, error}`. A `response.ok` check alone reports a
    // message that was never delivered — and the loop would appear healthy while
    // no operator ever sees a review list.
    const fakes = offerFakes({
      "chat.postMessage": { ok: false, error: "channel_not_found" },
    });
    const log = vi.fn();
    await expect(offer({ fakes, log }).promise).rejects.toThrow(/channel_not_found/u);

    const logged = log.mock.calls.flat().join("\n");
    expect(logged).not.toContain(BOT_TOKEN);
    expect(logged).not.toContain(SNIPPET);
    // The record was already written, which is deliberate: it invalidates the
    // previous week's button even when this week's post fails, so no stale click
    // can apply an old list.
    expect(fakes.ssm.puts).toHaveLength(1);
  });

  it("TC-SLACKAPP-109 overwrites the record but posts nothing when the run offers no deletions", async () => {
    // The write is NOT conditional on there being something to post. Last week's
    // Approve button is still live in the channel and its hash still matches the
    // record it was posted with, so a run that skipped the write entirely would
    // leave a click that applies a list this run's audit no longer stands behind.
    const fakes = offerFakes();
    const result = await offer({
      fakes,
      decisions: [
        { id: "m-keep", verdict: "KEEP", reason: "durable" },
        { id: "m-unstable", verdict: "UNSTABLE", reason: "passes disagreed on deletion" },
      ],
    }).promise;

    expect(fakes.ssm.puts).toHaveLength(1);
    expect(JSON.parse(fakes.ssm.puts[0].Value).ids).toEqual([]);
    expect(fakes.slack.fetchImpl).not.toHaveBeenCalled();
    expect(result.posted).toBe(false);
    expect(result.messageTs).toBeUndefined();
  });

  it("TC-SLACKAPP-110 stamps the message timestamp onto the record without failing the offer", async () => {
    // The apply task has to `chat.update` the message it was approved from, and
    // the only durable place that `ts` can reach it is the approval record. The
    // stamp is a SECOND write on purpose — the first has to precede the post, and
    // `ts` does not exist until the post returns.
    const fakes = offerFakes();
    const result = await offer({ fakes }).promise;
    expect(fakes.ssm.puts).toHaveLength(2);
    const stamped = JSON.parse(fakes.ssm.puts[1].Value);
    expect(stamped.messageTs).toBe("1754400000.000100");
    expect(stamped.messageChannel).toBe(CHANNEL);
    expect(stamped.hash).toBe(result.record.hash);
    expect(stamped.ids).toEqual(["m-1", "m-2"]);

    // A stamp failure does not undo a posted message or an offered list, so it is
    // reported and the offer stands: losing the audit-trail update is strictly
    // better than refusing an approval the operator can act on.
    const flaky = offerFakes();
    let put = 0;
    flaky.ssm.send = vi.fn(async (command) => {
      put += 1;
      if (put === 2) throw new Error("ThrottlingException");
      flaky.ssm.puts.push(command.input);
      return {};
    });
    const log = vi.fn();
    const survived = await offer({ fakes: flaky, log }).promise;
    expect(survived.posted).toBe(true);
    expect(log.mock.calls.flat().join("\n")).toMatch(/stamp|timestamp/iu);
  });

  it("TC-SLACKAPP-111 reports what policy withheld, so a shrinking approve set is visible", async () => {
    // A RETAIN is a deletion the protected-topic rule refused and an UNSTABLE is
    // one the passes disagreed on. Neither is offered — but a message that showed
    // only the approve set would make a rule that started matching everything
    // look like a clean corpus.
    const { promise, slack } = offer({
      decisions: [
        del("m-1"),
        { id: "m-protected", verdict: "RETAIN", reason: "stale", retainedReason: "protected topic personal-finance" },
        { id: "m-unstable", verdict: "UNSTABLE", reason: "passes disagreed on deletion" },
        { id: "m-keep", verdict: "KEEP", reason: "durable" },
      ],
    });
    await promise;
    const rendered = JSON.stringify(slack.calls[0].body.blocks);
    expect(rendered).toMatch(/RETAIN[^0-9]*1/u);
    expect(rendered).toMatch(/UNSTABLE[^0-9]*1/u);
  });

  it("TC-SLACKAPP-112 offers from a dry run and never from an apply", async () => {
    // An apply that re-offered would overwrite the very record its own claim was
    // derived from, so a redelivered click mid-apply would compare against a list
    // the running task never saw.
    const server = fakeServer([memory("del-1", "session noise")]);
    const llm = fakeLlm([[{ id: "del-1", verdict: "DELETE", reason: "session-state" }]]);
    const postApproval = vi.fn(async () => ({ posted: true, record: { hash: "sha256:x", ids: ["del-1"] } }));

    const dry = await runCleanup(baseOpts(), {
      ...baseDeps(server, llm, tempDir()),
      postApproval,
    });
    expect(dry.exitCode).toBe(0);
    expect(postApproval).toHaveBeenCalledTimes(1);
    const [{ decisions, generatedAt }] = postApproval.mock.calls[0];
    expect(decisions.map((d) => d.id)).toEqual(["del-1"]);
    expect(generatedAt).toBe("2026-07-31T00:00:00.000Z");

    postApproval.mockClear();
    const applyServer = fakeServer([memory("del-1", "session noise")]);
    const applied = await runCleanup(baseOpts({ apply: true }), {
      ...baseDeps(applyServer, fakeLlm([[{ id: "del-1", verdict: "DELETE", reason: "session-state" }]]), tempDir()),
      postApproval,
    });
    expect(applied.exitCode).toBe(0);
    expect(postApproval).not.toHaveBeenCalled();
  });

  it("TC-SLACKAPP-113 fails the run when the offer fails, naming the decision list it kept", async () => {
    // A scheduled review run whose post failed has done its audit and offered
    // nothing. Exit 0 would make that indistinguishable from a healthy week, and
    // the operator would notice only by the absence of a Slack message they were
    // not expecting on any particular day.
    const server = fakeServer([memory("del-1", "session noise")]);
    const llm = fakeLlm([[{ id: "del-1", verdict: "DELETE", reason: "session-state" }]]);
    const deps = {
      ...baseDeps(server, llm, tempDir()),
      postApproval: vi.fn(async () => {
        throw new Error("channel_not_found");
      }),
    };
    const result = await runCleanup(baseOpts(), deps);
    expect(result.exitCode).toBe(1);
    // The decision list survives the failed offer: it is the artefact the
    // operator falls back to for a manual `--apply --ids`.
    expect(result.decisionPath).toBeTruthy();
    expect(existsSync(result.decisionPath)).toBe(true);
    const logged = deps.log.mock.calls.flat().join("\n");
    expect(logged).toMatch(/channel_not_found/u);
    expect(logged).toContain(result.decisionPath);
  });

  it("TC-SLACKAPP-119 re-offers a replayed decision file under the FILE's stamp, not the moment it was reposted", async () => {
    // A `--decisions <file>` dry run with Slack configured re-offers that list —
    // the path an operator takes to repost a review after a failed offer. The
    // record's `generatedAt` is what dates the list, so stamping it `now` would
    // claim a fresh audit for a classification that may be days old, and the
    // operator's only cue that they are approving stale judgments would be gone.
    const dir = tempDir();
    const decisionsFile = join(dir, "decisions.json");
    writeFileSync(
      decisionsFile,
      JSON.stringify({
        stage: "test",
        generatedAt: "2026-07-24T00:00:00.000Z",
        decisions: [
          {
            id: "del-1",
            verdict: "DELETE",
            reason: "session-state",
            version: 1,
            contentHash: contentHash("session noise"),
          },
        ],
      }),
    );
    const server = fakeServer([memory("del-1", "session noise")]);
    const postApproval = vi.fn(async () => ({ posted: true, record: { hash: "sha256:x", ids: ["del-1"] } }));

    const result = await runCleanup(baseOpts({ decisionsFile }), {
      ...baseDeps(server, fakeLlm([]), dir),
      postApproval,
    });

    expect(result.exitCode).toBe(0);
    expect(postApproval.mock.calls[0][0].generatedAt).toBe("2026-07-24T00:00:00.000Z");
  });
});


describe("wiring the offer into the review run (#123)", () => {
  const environmentKeys = [
    "AWS_REGION",
    "MEM9_DB_HOST",
    "MEM9_DB_NAME",
    "MEM9_DB_PORT",
    "MEM9_DB_SECRET",
    "MEM9_SLACK_APPROVAL_CHANNEL",
    "MEM9_SSM_PREFIX",
    "MEM9_TENANT_ID",
    "SLACK_BOT_TOKEN",
  ];
  afterEach(() => {
    for (const key of environmentKeys) delete process.env[key];
  });

  function reviewEnv(extra = {}) {
    Object.assign(process.env, {
      AWS_REGION: "ap-northeast-1",
      MEM9_SSM_PREFIX: "/mem9-on-aws/prod",
      MEM9_TENANT_ID: TENANT,
      ...extra,
    });
  }

  function ssmFake(values = {}) {
    const client = {
      sent: [],
      send: vi.fn(async (command) => {
        client.sent.push(command.input);
        if (command.input.Names) {
          return {
            Parameters: command.input.Names.filter((n) => n in values).map((name) => ({
              Name: name,
              Value: values[name],
            })),
            InvalidParameters: command.input.Names.filter((n) => !(n in values)),
          };
        }
        return {};
      }),
      destroy: () => {},
    };
    return client;
  }

  it("TC-SLACKAPP-114 builds no offer dep when Slack is not configured, so the #102 CLI is unchanged", async () => {
    // The operator CLI at #102 has no Slack anything. An offer dep that existed
    // unconditionally would make every hand-run dry run try to write an approval
    // record the operator's identity may not be able to write — and would post a
    // clickable Approve button for a list they ran locally to look at.
    reviewEnv();
    const production = await createCleanupDeps(
      { stage: "prod", apply: false, cap: 50 },
      { ssm: ssmFake(), getToken: vi.fn(), fromNodeProviderChain: vi.fn() },
    );
    expect(production.deps.postApproval).toBeUndefined();
    await production.close();
  });

  it("TC-SLACKAPP-115 reads the bot token from the stage tree DECRYPTED when the channel is configured", async () => {
    reviewEnv({ MEM9_SLACK_APPROVAL_CHANNEL: "C0APPROVAL" });
    const ssm = ssmFake({ "/mem9-on-aws/prod/slack/bot-token": "xoxb-from-ssm" });
    const production = await createCleanupDeps(
      { stage: "prod", apply: false, cap: 50 },
      { ssm, getToken: vi.fn(), fromNodeProviderChain: vi.fn() },
    );
    expect(typeof production.deps.postApproval).toBe("function");
    const read = ssm.sent.find((input) => input.Names);
    expect(read.Names).toEqual(["/mem9-on-aws/prod/slack/bot-token"]);
    // The parameter is a SecureString, so without this the value comes back as
    // ciphertext and every post 401s with `invalid_auth`.
    expect(read.WithDecryption).toBe(true);
    await production.close();
  });

  it("TC-SLACKAPP-116 prefers an injected token over the stage tree, reading no parameter at all", async () => {
    // The apply task gets `SLACK_BOT_TOKEN` from ECS `ssm:`, and its task role
    // holds `ssm:GetParameters` under `approvals/*` ONLY — a read of
    // `slack/bot-token` is an AccessDenied there. Env-first is what lets one
    // function serve both identities, exactly as `resolveDatabaseConfig` does.
    reviewEnv({ MEM9_SLACK_APPROVAL_CHANNEL: "C0APPROVAL", SLACK_BOT_TOKEN: "xoxb-injected" });
    const ssm = ssmFake();
    const production = await createCleanupDeps(
      { stage: "prod", apply: false, cap: 50 },
      { ssm, getToken: vi.fn(), fromNodeProviderChain: vi.fn() },
    );
    expect(typeof production.deps.postApproval).toBe("function");
    expect(ssm.sent.filter((input) => input.Names)).toEqual([]);
    await production.close();
  });

  it("TC-SLACKAPP-117 refuses a configured channel it has no token for, rather than offering nothing", async () => {
    // Silently skipping the post is the TC-SLACKAPP-113 failure with the alarm
    // removed: the run does its whole audit, offers nothing, and exits 0 — and the
    // operator finds out by never receiving a message they were not expecting on
    // any particular day.
    reviewEnv({ MEM9_SLACK_APPROVAL_CHANNEL: "C0APPROVAL" });
    await expect(
      createCleanupDeps(
        { stage: "prod", apply: false, cap: 50 },
        { ssm: ssmFake(), getToken: vi.fn(), fromNodeProviderChain: vi.fn() },
      ),
    ).rejects.toThrow(/bot-token|bot token/u);
  });

  it("TC-SLACKAPP-118 passes the stage, prefix and channel through to a real offer", async () => {
    reviewEnv({ MEM9_SLACK_APPROVAL_CHANNEL: "C0APPROVAL", SLACK_BOT_TOKEN: "xoxb-injected" });
    const ssm = ssmFake();
    const fetchImpl = vi.fn(
      async () =>
        new Response(JSON.stringify({ ok: true, channel: "C0APPROVAL", ts: "1754400000.000200" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    const production = await createCleanupDeps(
      { stage: "prod", apply: false, cap: 50 },
      { ssm, getToken: vi.fn(), fromNodeProviderChain: vi.fn(), fetchImpl },
    );

    const offer = await production.deps.postApproval({
      decisions: [
        {
          id: "m-1",
          verdict: "DELETE",
          reason: "session-state",
          version: 1,
          contentHash: contentHash("c-m-1"),
          snippet: "a session detail",
        },
      ],
      generatedAt: "2026-08-05T03:00:00.000Z",
    });

    expect(offer.posted).toBe(true);
    const put = ssm.sent.find((input) => input.Name);
    // Built from the injected prefix, not a constant: a preview run writing prod's
    // record would hand prod's callback a list preview generated.
    expect(put.Name).toBe("/mem9-on-aws/prod/approvals/offered");
    expect(JSON.parse(put.Value).stage).toBe("prod");
    expect(JSON.parse(fetchImpl.mock.calls[0][1].body).channel).toBe("C0APPROVAL");
    await production.close();
  });
});

describe("closing the loop on the message (#123)", () => {
  const BOT_TOKEN = "xoxb-fixture-not-a-real-token";
  const CHANNEL = "C0APPROVAL";
  const TS = "1754400000.000100";
  const HASH = "sha256:whatever-the-claim-said";

  function updateFakes(body = { ok: true, channel: CHANNEL, ts: TS }) {
    const calls = [];
    const fetchImpl = vi.fn(async (url, options = {}) => {
      calls.push({
        url: String(url),
        headers: options.headers,
        redirect: options.redirect,
        body: JSON.parse(options.body),
      });
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    return { calls, fetchImpl };
  }

  it("TC-SLACKAPP-120 the outcome update reports what was DELETED, not what was approved", async () => {
    // The single number an operator reads off this message is the one that must
    // not be optimistic. An apply that approved 3 and deleted 1 (two lost to the
    // LWW guard) has to say 1 deleted and 2 skipped — reporting the approved
    // count would tell them the memories are gone when they are still there, and
    // this message IS the audit trail, so nothing else would ever correct it.
    const fakes = updateFakes();
    const message = buildOutcomeMessage({
      channel: CHANNEL,
      messageTs: TS,
      hash: HASH,
      stage: "prod",
      approved: 3,
      result: { capUsed: 1, skippedLww: 2, skippedByFilter: 0, exitCode: 0 },
      appliedAt: "2026-08-05T04:00:00.000Z",
    });
    const flat = JSON.stringify(message);
    expect(message.channel).toBe(CHANNEL);
    expect(message.ts).toBe(TS);
    // The ACHIEVED count first, the approved count second. Asserted as an
    // ordering rather than against a phrase so it does not pin the wording: the
    // defect this exists to catch is reporting 3 where 1 is true, and "3 of 3"
    // fails the first of these while a swapped "3 of 1" fails the second.
    expect(message.text).toMatch(/\b1\b[^0-9]*\b3\b/u);
    expect(message.text).not.toMatch(/\b3\b[^0-9]*\b1\b/u);
    expect(flat).toMatch(/2\b[^"]*(skip|unchanged|changed)/iu);
    // The buttons are GONE. A live Approve button under an applied outcome is an
    // invitation to click a hash whose claim already exists, which the callback
    // answers with "someone else is already applying" — a confusing dead end
    // rather than the record of what happened.
    expect(flat).not.toContain("cleanup_approve");
    expect(flat).not.toContain("cleanup_reject");
    expect(message.blocks.some((b) => b.type === "actions")).toBe(false);
    // `text` is not required alongside `blocks` but IS what a notification and a
    // screen reader read, and the outcome is the part worth notifying.
    expect(message.text).toMatch(/1\b/u);
    void fakes;
  });

  it("TC-SLACKAPP-121 a partial or capped apply says so on the message rather than reading as clean", async () => {
    // exitCode 4 (cap exceeded) and 6 (partial) are the two ways an apply stops
    // early with real deletions already done. A message that showed only the
    // count would read identically to a complete run, and the operator's next
    // move differs: a capped run has approved ids that were never touched and
    // needs a re-offer, a clean one does not.
    const capped = buildOutcomeMessage({
      channel: CHANNEL,
      messageTs: TS,
      hash: HASH,
      stage: "prod",
      approved: 60,
      result: { capUsed: 50, skippedLww: 0, skippedByFilter: 0, exitCode: 4 },
      appliedAt: "2026-08-05T04:00:00.000Z",
    });
    expect(JSON.stringify(capped)).toMatch(/cap/iu);

    const clean = buildOutcomeMessage({
      channel: CHANNEL,
      messageTs: TS,
      hash: HASH,
      stage: "prod",
      approved: 2,
      result: { capUsed: 2, skippedLww: 0, skippedByFilter: 0, exitCode: 0 },
      appliedAt: "2026-08-05T04:00:00.000Z",
    });
    expect(JSON.stringify(clean)).not.toMatch(/cap exceeded|incomplete|partial/iu);
    // Distinguishable from each other, which is the actual requirement — two
    // outcomes that serialize the same would make the assertion above vacuous.
    expect(JSON.stringify(capped)).not.toBe(JSON.stringify(clean));
  });

  it("TC-SLACKAPP-122 the outcome message names no memory id and no content", async () => {
    // The review message legitimately carries ids and snippets: it is what the
    // operator reviews. The outcome does not need them, and this message is
    // posted by the APPLY task, whose log already goes to CloudWatch — adding
    // them here widens where memory identifiers live for no operator benefit.
    const message = buildOutcomeMessage({
      channel: CHANNEL,
      messageTs: TS,
      hash: HASH,
      stage: "prod",
      approved: 1,
      result: { capUsed: 1, skippedLww: 0, skippedByFilter: 0, exitCode: 0 },
      appliedAt: "2026-08-05T04:00:00.000Z",
      ids: ["SENTINEL-MEMORY-ID"],
    });
    expect(JSON.stringify(message)).not.toContain("SENTINEL-MEMORY-ID");
  });

  it("TC-SLACKAPP-123 the update targets the claim's coordinates and is skipped when they are absent", async () => {
    const fakes = updateFakes();
    const posted = await updateApprovalMessage({
      claim: { messageChannel: CHANNEL, messageTs: TS, hash: HASH, stage: "prod" },
      approved: 1,
      stage: "prod",
      result: { capUsed: 1, skippedLww: 0, skippedByFilter: 0, exitCode: 0 },
      appliedAt: "2026-08-05T04:00:00.000Z",
      botToken: BOT_TOKEN,
      fetchImpl: fakes.fetchImpl,
    });
    expect(posted).toBe(true);
    expect(fakes.calls).toHaveLength(1);
    expect(fakes.calls[0].url).toBe("https://slack.com/api/chat.update");
    expect(fakes.calls[0].headers.Authorization).toBe(`Bearer ${BOT_TOKEN}`);
    // Both required arguments, from the CLAIM. `chat.update` needs channel AND
    // ts; either missing is `channel_not_found` or `message_not_found`.
    expect(fakes.calls[0].body.channel).toBe(CHANNEL);
    expect(fakes.calls[0].body.ts).toBe(TS);

    // A claim with no coordinates (a review run whose stamp write failed, or a
    // pre-#123 record) calls NOTHING rather than calling with undefined. The
    // deletions still happened, so this is not an error — but it must not be
    // silent either, or a systematically unstamped record would look like a
    // working loop forever.
    // HALF a pair is included, and is the sharper case: `chat.update` needs both,
    // so one coordinate is not a usable coordinate — a guard that required both to
    // be missing would call Slack with `ts: undefined` and earn a
    // `channel_not_found` that reads like a misconfigured channel. The Lambda's
    // `loadOffered` already refuses to carry half a pair into the claim, so this is
    // the second of two independent guards, in the process that would have to
    // report the confusing error.
    for (const claim of [
      { hash: HASH, stage: "prod" },
      { hash: HASH, stage: "prod", messageTs: TS },
      { hash: HASH, stage: "prod", messageChannel: CHANNEL },
    ]) {
      const none = updateFakes();
      const log = vi.fn();
      const skipped = await updateApprovalMessage({
        claim,
        approved: 1,
        stage: "prod",
        result: { capUsed: 1, skippedLww: 0, skippedByFilter: 0, exitCode: 0 },
        appliedAt: "2026-08-05T04:00:00.000Z",
        botToken: BOT_TOKEN,
        fetchImpl: none.fetchImpl,
        log,
      });
      expect(skipped, JSON.stringify(claim)).toBe(false);
      expect(none.fetchImpl, JSON.stringify(claim)).not.toHaveBeenCalled();
      expect(log.mock.calls.map(String).join("\n")).toMatch(/coordinate|messageTs|not update/iu);
    }
  });

  it("TC-SLACKAPP-124 a refused update never turns a completed apply into a failure", async () => {
    // The deletions are DONE and irreversible by the time this runs. An
    // `edit_window_closed` or a revoked token must not make the task exit
    // non-zero: that would alarm on a successful apply, and — worse under the
    // callback's recovery path — a retried task would re-apply ids already gone.
    // It must be LOUD in the log and harmless to the exit code.
    const fakes = updateFakes({ ok: false, error: "edit_window_closed" });
    const log = vi.fn();
    const posted = await updateApprovalMessage({
      claim: { messageChannel: CHANNEL, messageTs: TS, hash: HASH, stage: "prod" },
      approved: 1,
      stage: "prod",
      result: { capUsed: 1, skippedLww: 0, skippedByFilter: 0, exitCode: 0 },
      appliedAt: "2026-08-05T04:00:00.000Z",
      botToken: BOT_TOKEN,
      fetchImpl: fakes.fetchImpl,
      log,
    });
    expect(posted).toBe(false);
    const logged = log.mock.calls.map(String).join("\n");
    expect(logged).toMatch(/edit_window_closed/u);
    expect(logged).toMatch(/deletion|applied|already/iu);
  });
});

describe("wiring the outcome update into the apply run (#123)", () => {
  const environmentKeys = [
    "AWS_REGION",
    "MEM9_APPROVAL_HASH",
    "MEM9_DB_HOST",
    "MEM9_DB_NAME",
    "MEM9_DB_PORT",
    "MEM9_DB_SECRET",
    "MEM9_SLACK_APPROVAL_CHANNEL",
    "MEM9_SSM_PREFIX",
    "MEM9_TENANT_ID",
    "SLACK_BOT_TOKEN",
  ];
  afterEach(() => {
    for (const key of environmentKeys) delete process.env[key];
  });

  it("TC-SLACKAPP-125 the apply run reports its outcome once, with the numbers it actually achieved", async () => {
    // Three approved, one edited between the scan and the re-read. The apply
    // deletes two and skips one, and the message has to say two — the count the
    // operator would otherwise take on faith.
    const dir = tempDir();
    const idsFile = join(dir, "approved.txt");
    writeFileSync(idsFile, "d1\nd2\nd3\n");
    const server = fakeServer([memory("d1", "a"), memory("d2", "b"), memory("d3", "c")]);
    const llm = fakeLlm([
      [
        { id: "d1", verdict: "DELETE", reason: "stale" },
        { id: "d2", verdict: "DELETE", reason: "stale" },
        { id: "d3", verdict: "DELETE", reason: "stale" },
      ],
    ]);
    const deps = baseDeps(server, llm, dir);
    const realFetch = server.fetchImpl;
    let mutated = false;
    deps.fetchImpl = vi.fn(async (url, opts = {}) => {
      if (!mutated && /memories\/[^/?]+$/.test(String(url))) {
        mutated = true;
        const d = server.store.get("d1");
        d.content = "edited concurrently";
        d.version += 1;
      }
      return realFetch(url, opts);
    });
    const reportOutcome = vi.fn(async () => true);
    const result = await runCleanup(
      baseOpts({ apply: true, idsFile }),
      { ...deps, reportOutcome },
    );

    expect(result.exitCode).toBe(0);
    expect(result.capUsed).toBe(2);
    expect(result.skippedLww).toBe(1);
    // Once — not per decision and not per flush. A message updated three times
    // would show intermediate counts as if they were outcomes.
    expect(reportOutcome).toHaveBeenCalledTimes(1);
    const reported = reportOutcome.mock.calls[0][0];
    expect(reported.result.capUsed).toBe(2);
    expect(reported.result.skippedLww).toBe(1);
    expect(reported.result.exitCode).toBe(0);
    // The stamp is the run's clock, not `Date.now()`: a container whose report is
    // dated by wall time while everything else uses the injected clock makes two
    // timestamps on one run disagree.
    expect(reported.appliedAt).toBe("2026-07-31T00:00:00.000Z");
  });

  it("TC-SLACKAPP-126 a dry run and an unreported apply both leave the message alone", async () => {
    // The review run posts; it must not also UPDATE, and the #102 operator CLI has
    // no Slack at all — an apply with no dep must run to completion rather than
    // throwing on a missing function.
    const dir = tempDir();
    const server = fakeServer([memory("d1", "a")]);
    const llm = fakeLlm([[{ id: "d1", verdict: "DELETE", reason: "stale" }]]);
    const reportOutcome = vi.fn(async () => true);
    const dry = await runCleanup(baseOpts({ apply: false }), {
      ...baseDeps(server, llm, dir),
      reportOutcome,
    });
    expect(dry.exitCode).toBe(0);
    expect(reportOutcome).not.toHaveBeenCalled();

    const dir2 = tempDir();
    const server2 = fakeServer([memory("d1", "a")]);
    const llm2 = fakeLlm([[{ id: "d1", verdict: "DELETE", reason: "stale" }]]);
    const plain = await runCleanup(
      baseOpts({ apply: true }),
      baseDeps(server2, llm2, dir2),
    );
    expect(plain.exitCode).toBe(0);
    expect(server2.store.get("d1").state).toBe("deleted");
  });

  it("TC-SLACKAPP-127 a failed report does not change the exit code of a completed apply", async () => {
    // The deletions are done and irreversible. A non-zero exit here would alarm on
    // a successful apply, and the callback's stale-claim recovery would let a
    // retried task re-apply ids that are already gone.
    const dir = tempDir();
    const server = fakeServer([memory("d1", "a")]);
    const llm = fakeLlm([[{ id: "d1", verdict: "DELETE", reason: "stale" }]]);
    const log = vi.fn();
    const result = await runCleanup(baseOpts({ apply: true }), {
      ...baseDeps(server, llm, dir),
      log,
      reportOutcome: vi.fn(async () => {
        throw new Error("SENTINEL-REPORT-EXPLODED");
      }),
    });
    expect(result.exitCode).toBe(0);
    expect(server.store.get("d1").state).toBe("deleted");
    // Loud, though: a systematically broken report must not be invisible.
    expect(log.mock.calls.map(String).join("\n")).toMatch(/SENTINEL-REPORT-EXPLODED/u);
  });

  it("TC-SLACKAPP-128 the claim's coordinates reach the report dep the container builds", async () => {
    // End of the chain the offer started: offered record → claim → materialize →
    // this dep → `chat.update`. Every other link is tested; this one carries the
    // coordinates out of the read that was already happening, which is the link
    // most likely to be forgotten because nothing else needs them.
    const ids = ["m-1", "m-2"];
    const hash = contentHash(ids.join("\n"));
    const dir = tempDir();
    const idsFile = join(dir, "approved.txt");
    Object.assign(process.env, {
      AWS_REGION: "ap-northeast-1",
      MEM9_DB_HOST: "writer.example.com",
      MEM9_DB_NAME: "mem9",
      MEM9_DB_PORT: "5432",
      MEM9_DB_SECRET: JSON.stringify({ username: "mem9", password: "fixture-password" }),
      MEM9_SSM_PREFIX: "/mem9-on-aws/prod",
      MEM9_TENANT_ID: TENANT,
      MEM9_APPROVAL_HASH: hash,
      // The apply task's role holds ssm:GetParameters under approvals/* ONLY, so
      // the token arrives through the task definition's `ssm:` block, already
      // decrypted. A GetParameters read of slack/bot-token here is AccessDenied.
      SLACK_BOT_TOKEN: "xoxb-fixture-not-a-real-token",
    });
    const ssm = {
      send: vi.fn(async (command) => ({
        Parameters: (command.input.Names ?? [])
          .filter((n) => n === claimParameterName("/mem9-on-aws/prod", hash))
          .map((name) => ({
            Name: name,
            Value: JSON.stringify({
              stage: "prod",
              hash,
              ids,
              claimedAt: "2026-08-05T00:05:00.000Z",
              messageTs: "1754400000.000100",
              messageChannel: "C0APPROVAL",
            }),
          })),
        InvalidParameters: [],
      })),
      destroy: () => {},
    };
    const slackCalls = [];
    const fetchImpl = vi.fn(async (url, options = {}) => {
      slackCalls.push({ url: String(url), body: JSON.parse(options.body) });
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    const production = await createCleanupDeps(
      { stage: "prod", apply: true, cap: 50, idsFile },
      {
        Client: class {
          async connect() {}
          async query() {
            return { rows: [{ locked: true }] };
          }
          async end() {}
        },
        ssm,
        secrets: fakeAwsClient(),
        getToken: vi.fn(),
        fromNodeProviderChain: vi.fn(),
        fetchImpl,
      },
    );

    expect(production.deps.reportOutcome).toBeTypeOf("function");
    await production.deps.reportOutcome({
      result: { capUsed: 2, skippedLww: 0, skippedByFilter: 0, exitCode: 0 },
      appliedAt: "2026-08-05T04:00:00.000Z",
    });
    expect(slackCalls).toHaveLength(1);
    expect(slackCalls[0].url).toBe("https://slack.com/api/chat.update");
    expect(slackCalls[0].body.ts).toBe("1754400000.000100");
    expect(slackCalls[0].body.channel).toBe("C0APPROVAL");
    // No ids ANYWHERE on the way through, not just on the message. The claim the
    // container carries is the object this dep closes over, so an id list added to
    // `materializeApprovedIds`'s return would reach the message body the moment
    // anything spread the claim into it — asserted on both so the omission is a
    // property of the data, not of one call site's field list.
    expect(JSON.stringify(slackCalls[0].body)).not.toContain("m-1");
    expect(slackCalls[0].body.text).toMatch(/2\b[^0-9]*2\b/u);
    // The hash identifies WHICH approval was applied, and it is the only handle an
    // operator has for correlating this message with the task log and the claim
    // parameter. A message without it says a cleanup happened but not which one.
    expect(JSON.stringify(slackCalls[0].body)).toContain(hash);
    await production.close();
  });

  it("TC-SLACKAPP-129 a review run builds no report dep, and a hash-driven run with no token still applies", async () => {
    // Two independent absences, both of which must degrade rather than fail: a
    // review run has no claim to update against, and a token misconfiguration must
    // not stop deletions the operator already approved — it must cost the audit
    // update and say so.
    Object.assign(process.env, {
      AWS_REGION: "ap-northeast-1",
      MEM9_SSM_PREFIX: "/mem9-on-aws/prod",
      MEM9_TENANT_ID: TENANT,
    });
    const review = await createCleanupDeps(
      { stage: "prod", apply: false, cap: 50 },
      { ssm: fakeAwsClient(), getToken: vi.fn(), fromNodeProviderChain: vi.fn() },
    );
    expect(review.deps.reportOutcome).toBeUndefined();
    await review.close();

    const ids = ["m-1"];
    const hash = contentHash(ids.join("\n"));
    const dir = tempDir();
    const idsFile = join(dir, "approved.txt");
    Object.assign(process.env, {
      MEM9_DB_HOST: "writer.example.com",
      MEM9_DB_NAME: "mem9",
      MEM9_DB_PORT: "5432",
      MEM9_DB_SECRET: JSON.stringify({ username: "mem9", password: "fixture-password" }),
      MEM9_APPROVAL_HASH: hash,
    });
    delete process.env.SLACK_BOT_TOKEN;
    const ssm = fakeAwsClient({
      [claimParameterName("/mem9-on-aws/prod", hash)]: JSON.stringify({
        stage: "prod",
        hash,
        ids,
        claimedAt: "2026-08-05T00:05:00.000Z",
        messageTs: "1754400000.000100",
        messageChannel: "C0APPROVAL",
      }),
    });
    const production = await createCleanupDeps(
      { stage: "prod", apply: true, cap: 50, idsFile },
      {
        Client: class {
          async connect() {}
          async query() {
            return { rows: [{ locked: true }] };
          }
          async end() {}
        },
        ssm,
        secrets: fakeAwsClient(),
        getToken: vi.fn(),
        fromNodeProviderChain: vi.fn(),
      },
    );
    // The ids were still materialized — the apply is unaffected.
    expect(readFileSync(idsFile, "utf8")).toBe("m-1\n");
    expect(production.deps.reportOutcome).toBeUndefined();
    await production.close();
  });
});
