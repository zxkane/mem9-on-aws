import { afterEach, describe, expect, it, vi } from "vitest";

import {
  CONSOLIDATION_METRICS,
  DIGEST_SCHEMA_VERSION,
  buildDigestOutcome,
  buildEmfRecord,
  buildReviewTopic,
  clusterMemories,
  compareDigestTopics,
  createProductionDeps,
  evaluateDigestHealth,
  parseActions,
  parseConsolidationArgs,
  processScheduledDigest,
  reviewDisposition,
  routeActions,
  runConsolidation,
  serializeDigestState,
} from "./memory-consolidation.mjs";
import largeDigestFixture from "./fixtures/consolidation-digest-large-v1.json" with {
  type: "json",
};

const DAY_MS = 24 * 60 * 60 * 1000;
const NOW = Date.parse("2026-08-01T00:00:00Z");

function memory(id, content, embedding, overrides = {}) {
  return {
    id,
    content,
    embedding,
    version: 1,
    state: "active",
    memory_type: "insight",
    tags: [],
    metadata: {},
    created_at: "2026-06-01T00:00:00Z",
    updated_at: "2026-06-01T00:00:00Z",
    ...overrides,
  };
}

function fakeDeps(memories, responses) {
  const store = new Map(memories.map((item) => [item.id, structuredClone(item)]));
  const logs = [];
  const writes = [];
  const completeChat = vi.fn(async () => responses.shift() ?? '{"actions":[]}');
  const mutexRelease = vi.fn(async () => {});
  return {
    store,
    logs,
    writes,
    completeChat,
    mutexRelease,
    deps: {
      listActiveMemories: vi.fn(async () =>
        [...store.values()].map((item) => structuredClone(item)),
      ),
      completeChat,
      acquireMutex: vi.fn(async () => ({ release: mutexRelease })),
      getMemory: vi.fn(async (id) => {
        const item = store.get(id);
        return item?.state === "active" ? structuredClone(item) : null;
      }),
      putMemory: vi.fn(async (id, patch, version) => {
        const item = store.get(id);
        // `If-Match` FENCES the write (patch 0009, issue #128): a version
        // mismatch means the server rejected it with 412 and applied nothing.
        // Silently accepting a stale version would make the fence tests vacuous.
        if (version && item && item.version !== version) return null;
        writes.push({ type: "put", id, patch: structuredClone(patch) });
        Object.assign(item, patch, { version: item.version + 1 });
        return structuredClone(item);
      }),
      deleteMemories: vi.fn(async (ids) => {
        writes.push({ type: "delete", ids: [...ids] });
        for (const id of ids) store.get(id).state = "deleted";
        return ids.length;
      }),
      markMemoryStale: vi.fn(async ({ id, tags, metadata, version, content }) => {
        const item = store.get(id);
        if (
          item?.state !== "active" ||
          item.version !== version ||
          item.content !== content
        ) {
          return false;
        }
        writes.push({ type: "stale", id, tags: [...tags] });
        item.tags = [...tags];
        item.metadata = structuredClone(metadata);
        item.version += 1;
        // The whole point of this dep: the embedding column is NOT written.
        return true;
      }),
      archiveMemory: vi.fn(async ({
        id,
        supersededBy,
        version,
        content,
        winnerVersion,
        winnerContent,
      }) => {
        const item = store.get(id);
        const winner = store.get(supersededBy);
        if (
          item?.state !== "active" ||
          item.version !== version ||
          item.content !== content ||
          winner?.state !== "active" ||
          winner.version !== winnerVersion ||
          winner.content !== winnerContent
        ) return false;
        writes.push({ type: "archive", id, supersededBy });
        item.state = "archived";
        item.superseded_by = supersededBy;
        return true;
      }),
      loadDigestState: vi.fn(async () => ({ status: "missing" })),
      writeDigestState: vi.fn(async (input) => {
        writes.push({ type: "state", input: structuredClone(input) });
      }),
      postDigest: vi.fn(async (message) => {
        writes.push({ type: "slack", message: structuredClone(message) });
      }),
      publishHealthAlarm: vi.fn(async (alarm) => {
        writes.push({ type: "health", alarm: structuredClone(alarm) });
      }),
      log: (line) => logs.push(line),
      clock: () => NOW,
    },
  };
}

afterEach(() => vi.restoreAllMocks());

describe("embedding clustering", () => {
  it("TC-CONSOL-001/002: builds cosine components and includes only stale singletons", () => {
    const memories = [
      memory("a", "a", [1, 0]),
      memory("b", "b", [0.99, 0.01]),
      memory("c", "c", [0, 1]),
      memory("d", "d", [0, 0.99]),
      memory("old", "old config", [-1, 0], {
        memory_type: "pinned",
        updated_at: "2025-01-01T00:00:00Z",
      }),
      memory("recent", "recent singleton", [-0.7, -0.7], {
        updated_at: "2026-07-31T00:00:00Z",
      }),
    ];

    expect(
      clusterMemories(memories, {
        similarityThreshold: 0.95,
        now: NOW,
        staleAfterMs: { insight: 90 * DAY_MS, pinned: 180 * DAY_MS },
      }).map((cluster) => cluster.map((item) => item.id)),
    ).toEqual([["a", "b"], ["c", "d"], ["old"]]);
  });

  it("TC-CONSOL-019: excludes session memories from consolidation", async () => {
    const session = memory("session", "old raw session", [1, 0], {
      memory_type: "session",
      updated_at: "2025-01-01T00:00:00Z",
    });

    expect(clusterMemories([session], { now: NOW })).toEqual([]);

    const fake = fakeDeps([session], []);
    const result = await runConsolidation(
      { stage: "prod", reportOnly: true, cap: 20 },
      fake.deps,
    );
    expect(fake.completeChat).not.toHaveBeenCalled();
    expect(result.metrics.scanned).toBe(0);
    expect(result.review).toEqual([]);
  });

  it("handles unusable vectors and missing timestamps conservatively", () => {
    const invalidVectors = [
      memory("invalid", "invalid", undefined),
      memory("zero", "zero", [0, 0]),
      memory("valid", "valid", [1, 0]),
    ];
    expect(
      clusterMemories(invalidVectors, {
        now: NOW,
        staleAfterMs: { insight: Number.POSITIVE_INFINITY },
      }),
    ).toEqual([]);

    const unknownType = memory("unknown-type", "old", [1, 0], {
      memory_type: "future-type",
      updated_at: undefined,
    });
    expect(
      clusterMemories([unknownType], {
        now: NOW,
        staleAfterMs: { insight: DAY_MS },
      }),
    ).toEqual([[unknownType]]);
  });
});

describe("LLM action validation and tiers", () => {
  it("TC-CONSOL-003: rejects malformed actions and unknown ids", () => {
    expect(() => parseActions("not json")).toThrow(/JSON/i);
    expect(() =>
      parseActions('{"actions":[{"type":"EXPLODE","ids":["a"]}]}'),
    ).toThrow(/action/i);

    const memories = [memory("a", "one", [1, 0])];
    const routed = routeActions(memories, [
      { type: "STALE", ids: ["ghost"], rationale: "invented" },
    ]);
    expect(routed.auto).toEqual([]);
    expect(routed.review).toContainEqual(
      expect.objectContaining({ kind: "UNKNOWN_ID", ids: ["ghost"] }),
    );
  });

  it("TC-CONSOL-004/005/012: DELETE and ambiguous contradictions are always review-only", () => {
    const memories = [
      memory("a", "old approach", [1, 0]),
      memory("b", "new approach", [1, 0], {
        updated_at: "2026-07-01T00:00:00Z",
      }),
      memory("delete", "delete candidate", [0, 1]),
    ];
    const routed = routeActions(memories, [
      {
        type: "DELETE",
        ids: ["delete"],
        rationale: "model says remove it",
        auto_execute: true,
      },
      {
        type: "CONTRADICTION",
        ids: ["a", "b"],
        rationale: "no evidence of transition",
      },
    ]);

    expect(routed.auto).toEqual([]);
    expect(routed.review).toHaveLength(2);
    expect(routed.review[0]).toMatchObject({
      kind: "DELETE",
      ids: ["delete"],
      rationale: "model says remove it",
    });
    expect(routed.review[0].snippets[0]).toContain("delete candidate");
  });

  it("TC-CONSOL-006: routes only a strictly newer contradiction winner to archive", () => {
    const memories = [
      memory("old", "use v1", [1, 0], {
        created_at: "2025-12-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      }),
      memory("new", "use v2", [1, 0], {
        created_at: "2026-06-01T00:00:00Z",
        updated_at: "2026-07-01T00:00:00Z",
      }),
    ];
    const routed = routeActions(memories, [
      {
        type: "CONTRADICTION",
        ids: ["old", "new"],
        winner_id: "new",
        rationale: "explicit replacement",
      },
    ]);
    expect(routed.review).toEqual([]);
    expect(routed.auto).toEqual([
      expect.objectContaining({
        type: "ARCHIVE",
        id: "old",
        supersededBy: "new",
        cost: 1,
      }),
    ]);
  });

  it("TC-CONSOL-043: reviews a winner whose update and creation timelines disagree", () => {
    const memories = [
      memory("older-edited", "use the legacy deploy path", [1, 0], {
        created_at: "2024-01-01T00:00:00Z",
        updated_at: "2026-07-31T00:00:00Z",
      }),
      memory("newer-fact", "use the current deploy path", [1, 0], {
        created_at: "2026-06-01T00:00:00Z",
        updated_at: "2026-06-01T00:00:00Z",
      }),
    ];

    const routed = routeActions(memories, [{
      type: "CONTRADICTION",
      ids: ["older-edited", "newer-fact"],
      winner_id: "older-edited",
      rationale: "the edited row appears newer",
    }]);

    expect(routed.auto).toEqual([]);
    expect(routed.review).toContainEqual(
      expect.objectContaining({
        kind: "CONTRADICTION",
        ids: ["older-edited", "newer-fact"],
      }),
    );
  });

  it("TC-CONSOL-044: reviews either contradiction side carrying a prior stale marker", () => {
    for (const markedId of ["old", "new"]) {
      const memories = [
        memory("old", "use the legacy deploy path", [1, 0], {
          created_at: "2025-12-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        }),
        memory("new", "use the current deploy path", [1, 0], {
          created_at: "2026-06-01T00:00:00Z",
          updated_at: "2026-07-01T00:00:00Z",
        }),
      ];
      const marked = memories.find(({ id }) => id === markedId);
      marked.tags = ["stale"];
      marked.metadata = {
        consolidation: {
          stale: true,
          flagged_at: "2026-07-31T00:00:00Z",
        },
      };

      const routed = routeActions(memories, [{
        type: "CONTRADICTION",
        ids: ["old", "new"],
        winner_id: "new",
        rationale: "the new fact otherwise has a clear timeline",
      }]);

      expect(routed.auto).toEqual([]);
      expect(routed.review).toContainEqual(
        expect.objectContaining({
          kind: "CONTRADICTION",
          ids: ["old", "new"],
        }),
      );
    }
  });

  it("rejects malformed fields and reviews conflicting or invalid safe actions", () => {
    expect(() => parseActions("{}")).toThrow(/actions array/u);
    expect(() =>
      parseActions('{"actions":[{"type":"STALE","ids":[]}]}'),
    ).toThrow(/ids/u);
    expect(() =>
      parseActions(
        '{"actions":[{"type":"STALE","ids":["a"],"rationale":7}]}',
      ),
    ).toThrow(/rationale/u);

    const memories = [
      memory("a", "one", [1, 0], { tags: "invalid", metadata: null }),
      memory("b", "two", [1, 0]),
    ];
    expect(
      routeActions(memories, [
        { type: "STALE", ids: ["a"], rationale: "first" },
        { type: "DELETE", ids: ["a"], rationale: "second" },
      ]).review,
    ).toEqual([
      expect.objectContaining({ kind: "CONFLICTING_ACTION" }),
      expect.objectContaining({ kind: "CONFLICTING_ACTION" }),
    ]);
    expect(
      routeActions(memories, [
        { type: "KEEP", ids: ["b"], rationale: "unchanged" },
        { type: "KEEP", ids: [], rationale: "empty" },
      ]),
    ).toEqual({ auto: [], review: [] });
    expect(
      routeActions(memories, [
        { type: "MERGE", ids: ["a"], survivor_id: "a", rationale: "short" },
      ]).review,
    ).toContainEqual(expect.objectContaining({ kind: "INVALID_MERGE" }));
    expect(
      routeActions(memories, [
        { type: "STALE", ids: ["a", "b"], rationale: "not singular" },
      ]).review,
    ).toContainEqual(expect.objectContaining({ kind: "INVALID_STALE" }));
    expect(
      routeActions(memories, [
        { type: "KEEP", ids: ["a"], rationale: "leave it" },
        {
          type: "MERGE",
          ids: ["a", "b"],
          survivor_id: "a",
          merged_content: "one two",
          rationale: "same topic",
        },
      ]).auto,
    ).toEqual([]);
    expect(
      routeActions(memories, [
        {
          type: "MERGE",
          ids: ["a", "b", "hallucinated"],
          survivor_id: "a",
          merged_content: "one two",
          rationale: "same topic",
        },
      ]),
    ).toMatchObject({
      auto: [],
      review: [
        expect.objectContaining({
          kind: "UNKNOWN_ID",
          ids: ["a", "b", "hallucinated"],
        }),
      ],
    });
    expect(
      routeActions(memories, [
        {
          type: "CONTRADICTION",
          ids: ["a", "b"],
          winner_id: "a",
          rationale: "same timestamp",
        },
      ]).review,
    ).toContainEqual(expect.objectContaining({ kind: "CONTRADICTION" }));
    expect(
      routeActions([memories[0]], [
        { type: "STALE", ids: ["a"], rationale: "" },
      ], { now: NOW }).review,
    ).toContainEqual(expect.objectContaining({ kind: "INELIGIBLE_STALE" }));
    expect(
      routeActions([
        memory("old", "old config", [1, 0], {
          tags: "invalid",
          metadata: null,
          updated_at: "2025-01-01T00:00:00Z",
        }),
      ], [
        { type: "STALE", ids: ["old"], rationale: "" },
      ], { now: NOW }).auto[0],
    ).toMatchObject({
      rationale: "no rationale supplied",
    });
  });

  it("TC-CONSOL-050: a memory with no usable version is never auto-merged, because it cannot be fenced", () => {
    // `If-Match` is omitted when the version is falsy (restAdapter), so upstream
    // falls back to LWW and the fence is silently OFF — issue #128's overwrite,
    // reintroduced. It also fails *closed-looking*: the client's own guard
    // compares `current.version !== action.version`, and null !== null is false,
    // so that guard passes too and the merge proceeds fully unfenced.
    // Upstream's schema declares `version INT DEFAULT 1` with no NOT NULL. This
    // repo's bootstrap does harden it (NOT NULL + CHECK version > 0) after
    // creating `memories` — and the check rejects even a hand-run
    // `SET version = 0` — so on a healthy stage the input below takes a partial
    // migration or a dropped constraint. Asserted anyway because this task reads
    // the column with direct SQL, where a bad value arrives silently.
    for (const unfenceable of [null, undefined, 0, "1"]) {
      const routed = routeActions(
        [
          memory("surv", "one", [1, 0], { version: unfenceable }),
          memory("frag", "two", [1, 0]),
        ],
        [{
          type: "MERGE",
          ids: ["surv", "frag"],
          survivor_id: "surv",
          merged_content: "one two",
          rationale: "same topic",
        }],
      );
      expect(routed.auto).toEqual([]);
      expect(routed.review).toContainEqual(
        expect.objectContaining({ kind: "UNFENCEABLE_MERGE" }),
      );
    }

    // An absorbed fragment's version is compared against its re-read before the
    // delete, so an unfenceable one there is equally disqualifying.
    const absorbed = routeActions(
      [
        memory("surv", "one", [1, 0]),
        memory("frag", "two", [1, 0], { version: null }),
      ],
      [{
        type: "MERGE",
        ids: ["surv", "frag"],
        survivor_id: "surv",
        merged_content: "one two",
        rationale: "same topic",
      }],
    );
    expect(absorbed.auto).toEqual([]);
    expect(absorbed.review).toContainEqual(
      expect.objectContaining({ kind: "UNFENCEABLE_MERGE" }),
    );

    // A normal version still auto-merges — the guard must not disqualify everything.
    expect(
      routeActions(
        [memory("surv", "one", [1, 0]), memory("frag", "two", [1, 0])],
        [{
          type: "MERGE",
          ids: ["surv", "frag"],
          survivor_id: "surv",
          merged_content: "one two",
          rationale: "same topic",
        }],
      ).auto,
    ).toHaveLength(1);
  });
});

describe("execution safety", () => {
  it("TC-CONSOL-007/008/010: applies safe tiers in order and defers cap overflow", async () => {
    const memories = [
      memory("survivor", "fragment one", [1, 0]),
      memory("absorbed", "fragment two", [1, 0]),
      memory("stale", "old region config", [0, 1], {
        tags: ["config"],
        metadata: { source: "agent" },
        updated_at: "2025-01-01T00:00:00Z",
      }),
      memory("old", "use v1", [-1, 0], {
        created_at: "2025-12-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      }),
      memory("new", "use v2", [-1, 0], {
        created_at: "2026-06-01T00:00:00Z",
        updated_at: "2026-07-01T00:00:00Z",
      }),
    ];
    const fake = fakeDeps(memories, [
      JSON.stringify({
        actions: [
          {
            type: "MERGE",
            ids: ["survivor", "absorbed"],
            survivor_id: "survivor",
            merged_content: "fragment one and fragment two",
            rationale: "same topic",
          },
        ],
      }),
      JSON.stringify({
        actions: [
          { type: "STALE", ids: ["stale"], rationale: "environment fact aged out" },
        ],
      }),
      JSON.stringify({
        actions: [
          {
            type: "CONTRADICTION",
            ids: ["old", "new"],
            winner_id: "new",
            rationale: "v2 replaced v1",
          },
        ],
      }),
    ]);

    const result = await runConsolidation(
      {
        stage: "prod",
        reportOnly: false,
        cap: 3,
        similarityThreshold: 0.95,
      },
      fake.deps,
    );

    expect(fake.writes.slice(0, 2)).toEqual([
      expect.objectContaining({ type: "put", id: "survivor" }),
      { type: "delete", ids: ["absorbed"] },
    ]);
    // Stale marking must go through markMemoryStale (direct SQL), NOT putMemory:
    // a content-free REST PUT nulls the pgvector embedding on the postgres
    // backend, permanently removing the memory from semantic recall. Verified
    // against prod. Asserting the write TYPE is the regression guard.
    expect(fake.writes).toContainEqual(
      expect.objectContaining({
        type: "stale",
        id: "stale",
        tags: ["config", "stale"],
      }),
    );
    expect(
      fake.writes.some((write) => write.type === "put" && write.id === "stale"),
    ).toBe(false);
    expect(fake.deps.putMemory).not.toHaveBeenCalledWith(
      "stale",
      expect.anything(),
      expect.anything(),
    );
    expect(fake.store.get("stale").metadata.source).toBe("agent");
    expect(fake.writes.some((write) => write.type === "archive")).toBe(false);
    expect(result.metrics.merged).toBe(1);
    expect(result.metrics.flaggedStale).toBe(1);
    expect(result.review).toContainEqual(
      expect.objectContaining({ kind: "CAP_DEFERRED", ids: ["old", "new"] }),
    );
    expect(result.mutations).toBe(3);
  });

  it("TC-CONSOL-009: skips a stale action changed after scan", async () => {
    const item = memory("stale", "old config", [1, 0], {
      updated_at: "2025-01-01T00:00:00Z",
    });
    const fake = fakeDeps([item], [
      '{"actions":[{"type":"STALE","ids":["stale"],"rationale":"old"}]}',
    ]);
    fake.deps.getMemory.mockResolvedValueOnce({
      ...item,
      version: 2,
      content: "updated concurrently",
    });

    const result = await runConsolidation(
      { stage: "prod", reportOnly: false, cap: 20 },
      fake.deps,
    );
    expect(fake.writes.filter((write) => write.type === "put")).toEqual([]);
    expect(result.metrics.skippedLww).toBe(1);
    expect(result.mutations).toBe(0);
  });

  it("TC-CONSOL-018: reviews stale marking when all 20 tag slots are occupied", async () => {
    const item = memory("stale", "old config", [1, 0], {
      tags: Array.from({ length: 20 }, (_, index) => `tag-${index}`),
      updated_at: "2025-01-01T00:00:00Z",
    });
    const fake = fakeDeps([item], [
      '{"actions":[{"type":"STALE","ids":["stale"],"rationale":"old"}]}',
    ]);

    const result = await runConsolidation(
      { stage: "prod", reportOnly: false, cap: 20 },
      fake.deps,
    );

    expect(fake.writes.filter((write) => write.type === "put")).toEqual([]);
    expect(result.metrics.flaggedStale).toBe(0);
    expect(result.review).toContainEqual(
      expect.objectContaining({
        kind: "TAG_LIMIT_REACHED",
        ids: ["stale"],
      }),
    );
  });

  it("TC-CONSOL-017: emits review and EMF after a mid-apply mutation error", async () => {
    const memories = [
      memory("a", "first fragment", [1, 0]),
      memory("b", "second fragment", [1, 0]),
      memory("c", "third fragment", [0, 1]),
      memory("d", "fourth fragment", [0, 1]),
    ];
    const fake = fakeDeps(memories, [
      JSON.stringify({
        actions: [{
          type: "MERGE",
          ids: ["a", "b"],
          survivor_id: "a",
          merged_content: "first merged memory",
          rationale: "same first topic",
        }],
      }),
      JSON.stringify({
        actions: [{
          type: "MERGE",
          ids: ["c", "d"],
          survivor_id: "c",
          merged_content: "second merged memory",
          rationale: "same second topic",
        }],
      }),
    ]);
    const putMemory = fake.deps.putMemory.getMockImplementation();
    fake.deps.putMemory
      .mockImplementationOnce(putMemory)
      .mockRejectedValueOnce(new Error("injected PUT failure"));

    const result = await runConsolidation(
      {
        stage: "prod",
        reportOnly: false,
        cap: 20,
        similarityThreshold: 0.95,
      },
      fake.deps,
    );

    expect(result.exitCode).toBe(1);
    expect(result.metrics.merged).toBe(1);
    expect(result.review).toContainEqual(
      expect.objectContaining({ kind: "APPLY_FAILED", ids: ["c", "d"] }),
    );
    expect(fake.mutexRelease).toHaveBeenCalledOnce();
    expect(
      fake.logs.some((line) => line.startsWith("CONSOLIDATION_REVIEW_LIST ")),
    ).toBe(true);
    const emf = fake.logs
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .find((record) => record?._aws);
    expect(emf).toMatchObject({
      ConsolidationMerged: 1,
      ConsolidationReviewItems: 1,
    });
  });

  it("TC-CONSOL-017: records a survivor PUT when MERGE deletion fails", async () => {
    const memories = [
      memory("survivor", "first fragment", [1, 0]),
      memory("absorbed", "second fragment", [1, 0]),
    ];
    const fake = fakeDeps(memories, [
      JSON.stringify({
        actions: [{
          type: "MERGE",
          ids: ["survivor", "absorbed"],
          survivor_id: "survivor",
          merged_content: "merged memory",
          rationale: "same topic",
        }],
      }),
    ]);
    fake.deps.deleteMemories.mockRejectedValueOnce(
      new Error("injected batch-delete failure"),
    );

    const result = await runConsolidation(
      { stage: "prod", reportOnly: false, cap: 20 },
      fake.deps,
    );

    expect(result.exitCode).toBe(1);
    expect(result.mutations).toBe(1);
    expect(result.metrics.merged).toBe(0);
    expect(result.review).toContainEqual(
      expect.objectContaining({
        kind: "APPLY_FAILED",
        ids: ["survivor", "absorbed"],
        rationale: expect.stringContaining("after 1 confirmed mutation"),
      }),
    );
  });

  it("TC-CONSOL-017: rejects an invalid batch-delete count", async () => {
    const memories = [
      memory("survivor", "first fragment", [1, 0]),
      memory("absorbed", "second fragment", [1, 0]),
    ];
    const fake = fakeDeps(memories, [
      JSON.stringify({
        actions: [{
          type: "MERGE",
          ids: ["survivor", "absorbed"],
          survivor_id: "survivor",
          merged_content: "merged memory",
          rationale: "same topic",
        }],
      }),
    ]);
    fake.deps.deleteMemories.mockResolvedValueOnce(undefined);

    const result = await runConsolidation(
      { stage: "prod", reportOnly: false, cap: 20 },
      fake.deps,
    );

    expect(result).toMatchObject({
      exitCode: 1,
      mutations: 1,
      metrics: { merged: 0 },
    });
    expect(result.review).toContainEqual(
      expect.objectContaining({
        kind: "APPLY_FAILED",
        rationale: expect.stringContaining("after 1 confirmed mutation"),
      }),
    );
  });

  it("TC-CONSOL-017: records a survivor PUT when an absorbed re-read fails", async () => {
    const memories = [
      memory("survivor", "first fragment", [1, 0]),
      memory("absorbed", "second fragment", [1, 0]),
    ];
    const fake = fakeDeps(memories, [
      JSON.stringify({
        actions: [{
          type: "MERGE",
          ids: ["survivor", "absorbed"],
          survivor_id: "survivor",
          merged_content: "merged memory",
          rationale: "same topic",
        }],
      }),
    ]);
    const getMemory = fake.deps.getMemory.getMockImplementation();
    fake.deps.getMemory
      .mockImplementationOnce(getMemory)
      .mockRejectedValueOnce(new Error("injected absorbed read failure"));

    const result = await runConsolidation(
      { stage: "prod", reportOnly: false, cap: 20 },
      fake.deps,
    );

    expect(result.exitCode).toBe(1);
    expect(result.mutations).toBe(1);
    expect(result.metrics.merged).toBe(0);
    expect(result.review).toContainEqual(
      expect.objectContaining({
        kind: "APPLY_FAILED",
        rationale: expect.stringContaining("after 1 confirmed mutation"),
      }),
    );
  });

  it("TC-CONSOL-009: does not absorb a memory whose version changed after scan", async () => {
    const memories = [
      memory("survivor", "fragment one", [1, 0]),
      memory("absorbed", "fragment two", [1, 0]),
    ];
    const decision = JSON.stringify({
      actions: [{
        type: "MERGE",
        ids: ["survivor", "absorbed"],
        survivor_id: "survivor",
        merged_content: "fragment one and fragment two",
        rationale: "same topic",
      }],
    });
    const fake = fakeDeps(memories, []);
    fake.completeChat.mockImplementationOnce(async () => {
      fake.store.get("absorbed").metadata = { changed: true };
      fake.store.get("absorbed").version = 2;
      return decision;
    });

    const result = await runConsolidation(
      { stage: "prod", reportOnly: false, cap: 20 },
      fake.deps,
    );

    expect(fake.writes).toContainEqual(
      expect.objectContaining({ type: "put", id: "survivor" }),
    );
    expect(fake.writes.some(({ type }) => type === "delete")).toBe(false);
    expect(result.metrics.skippedLww).toBe(1);
  });

  it("TC-CONSOL-038: an ingest write between the survivor's read and rewrite fences the merge", async () => {
    const memories = [
      memory("survivor", "fragment one", [1, 0]),
      memory("absorbed", "fragment two", [1, 0]),
    ];
    const fake = fakeDeps(memories, [
      JSON.stringify({
        actions: [{
          type: "MERGE",
          ids: ["survivor", "absorbed"],
          survivor_id: "survivor",
          merged_content: "fragment one and fragment two",
          rationale: "same topic",
        }],
      }),
    ]);
    // Interleave explicitly: the survivor's guard GET passes, then an ingest
    // write lands before the rewrite. Only the server-side fence catches this.
    const realPut = fake.deps.putMemory.getMockImplementation();
    fake.deps.putMemory.mockImplementationOnce(async (id, patch, version) => {
      const item = fake.store.get("survivor");
      item.content = "ingested concurrently";
      item.version += 1;
      return realPut(id, patch, version);
    });

    const result = await runConsolidation(
      { stage: "prod", reportOnly: false, cap: 20 },
      fake.deps,
    );

    // The concurrent write survives and the merged content never lands.
    expect(fake.store.get("survivor").content).toBe("ingested concurrently");
    expect(fake.writes.filter(({ type }) => type === "put")).toEqual([]);
    // Absorbed ids are NOT deleted: the survivor never received their content.
    expect(fake.store.get("absorbed").state).toBe("active");
    expect(fake.writes.some(({ type }) => type === "delete")).toBe(false);
    // A fenced merge is a skip, not a failed apply.
    expect(result.metrics.skippedLww).toBe(1);
    expect(result.metrics.merged).toBe(0);
    expect(result.mutations).toBe(0);
    expect(result.exitCode).toBe(0);
    expect(
      result.review.some((item) => item.kind === "APPLY_FAILED"),
    ).toBe(false);
  });

  it("TC-CONSOL-039: a successful merge predicates the rewrite on the observed version", async () => {
    const memories = [
      memory("survivor", "fragment one", [1, 0]),
      memory("absorbed", "fragment two", [1, 0]),
    ];
    const fake = fakeDeps(memories, [
      JSON.stringify({
        actions: [{
          type: "MERGE",
          ids: ["survivor", "absorbed"],
          survivor_id: "survivor",
          merged_content: "fragment one and fragment two",
          rationale: "same topic",
        }],
      }),
    ]);

    const result = await runConsolidation(
      { stage: "prod", reportOnly: false, cap: 20 },
      fake.deps,
    );

    // Without the version argument the server cannot fence the rewrite.
    expect(fake.deps.putMemory).toHaveBeenCalledWith(
      "survivor",
      { content: "fragment one and fragment two" },
      1,
    );
    // A content-bearing PUT is what makes upstream re-embed, so the survivor's
    // embedding matches its merged content (issue #128 requirement d).
    expect(fake.store.get("survivor").content).toBe(
      "fragment one and fragment two",
    );
    expect(fake.store.get("absorbed").state).toBe("deleted");
    expect(result.metrics.skippedLww).toBe(0);
    expect(result.metrics.merged).toBe(1);
    expect(result.exitCode).toBe(0);
  });

  it("TC-CONSOL-011/012: report-only emits review summary and performs no writes or mutex", async () => {
    const memories = [
      memory("a", "remove me", [1, 0], {
        updated_at: "2025-01-01T00:00:00Z",
      }),
    ];
    const fake = fakeDeps(memories, [
      '{"actions":[{"type":"DELETE","ids":["a"],"rationale":"candidate"}]}',
    ]);
    const result = await runConsolidation(
      { stage: "pr-103", reportOnly: true, cap: 20 },
      fake.deps,
    );

    expect(fake.writes).toEqual([]);
    expect(fake.deps.acquireMutex).not.toHaveBeenCalled();
    expect(fake.deps.loadDigestState).not.toHaveBeenCalled();
    expect(fake.deps.postDigest).not.toHaveBeenCalled();
    expect(fake.deps.publishHealthAlarm).not.toHaveBeenCalled();
    expect(fake.logs.some((line) => line.startsWith("CONSOLIDATION_REVIEW "))).toBe(true);
    expect(fake.logs.some((line) => line.startsWith("CONSOLIDATION_REVIEW_LIST "))).toBe(true);
    expect(result.exitCode).toBe(0);
  });

  it("TC-CONSOL-067: manual apply does not touch weekly digest transports", async () => {
    const fake = fakeDeps(
      [memory("a", "remove me", [1, 0])],
      ['{"actions":[{"type":"DELETE","ids":["a"],"rationale":"candidate"}]}'],
    );

    const result = await runConsolidation(
      { stage: "prod", reportOnly: false, scheduled: false, cap: 20 },
      fake.deps,
    );

    expect(fake.deps.loadDigestState).not.toHaveBeenCalled();
    expect(fake.deps.writeDigestState).not.toHaveBeenCalled();
    expect(fake.deps.postDigest).not.toHaveBeenCalled();
    expect(fake.deps.publishHealthAlarm).not.toHaveBeenCalled();
    expect(result.exitCode).toBe(0);
  });

  it("TC-CONSOL-040: report-only can smoke the live classifier with no memory content", async () => {
    const fake = fakeDeps([], ['{"actions":[]}']);
    const result = await runConsolidation(
      {
        stage: "pr-103",
        reportOnly: true,
        checkLlm: true,
        cap: 20,
      },
      fake.deps,
    );

    expect(fake.completeChat).toHaveBeenCalledOnce();
    expect(fake.completeChat.mock.calls[0][1]).toEqual([]);
    expect(fake.writes).toEqual([]);
    expect(result.exitCode).toBe(0);
  });

  it("TC-CONSOL-006: archives an unchanged timeline loser", async () => {
    const memories = [
      memory("old", "use v1", [1, 0], {
        created_at: "2025-12-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      }),
      memory("new", "use v2", [1, 0], {
        created_at: "2026-06-01T00:00:00Z",
        updated_at: "2026-07-01T00:00:00Z",
      }),
    ];
    const fake = fakeDeps(memories, [
      JSON.stringify({
        actions: [{
          type: "CONTRADICTION",
          ids: ["old", "new"],
          winner_id: "new",
          rationale: "new replaced old",
        }],
      }),
    ]);

    const result = await runConsolidation(
      { stage: "prod", reportOnly: false, cap: 20 },
      fake.deps,
    );

    expect(fake.writes).toContainEqual({
      type: "archive",
      id: "old",
      supersededBy: "new",
    });
    expect(result.metrics.archived).toBe(1);
  });

  it("TC-CONSOL-009: skips archival when the timeline winner changed after scan", async () => {
    const memories = [
      memory("old", "use v1", [1, 0], {
        created_at: "2025-12-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      }),
      memory("new", "use v2", [1, 0], {
        created_at: "2026-06-01T00:00:00Z",
        updated_at: "2026-07-01T00:00:00Z",
      }),
    ];
    const decision = JSON.stringify({
      actions: [{
        type: "CONTRADICTION",
        ids: ["old", "new"],
        winner_id: "new",
        rationale: "new replaced old",
      }],
    });
    const fake = fakeDeps(memories, []);
    fake.completeChat.mockImplementationOnce(async () => {
      fake.store.get("new").content = "use v3";
      fake.store.get("new").version = 2;
      return decision;
    });

    const result = await runConsolidation(
      { stage: "prod", reportOnly: false, cap: 20 },
      fake.deps,
    );

    expect(fake.writes.some(({ type }) => type === "archive")).toBe(false);
    expect(result.metrics.skippedLww).toBe(1);
  });

  it("TC-CONSOL-011/014: reports safe actions and a held mutex without mutation", async () => {
    const item = memory("stale", "old config", [1, 0], {
      updated_at: "2025-01-01T00:00:00Z",
    });
    const report = fakeDeps([item], [
      '{"actions":[{"type":"STALE","ids":["stale"],"rationale":"aged"}]}',
    ]);
    const reportResult = await runConsolidation(
      { stage: "pr-103", reportOnly: true, cap: 20 },
      report.deps,
    );
    expect(reportResult.review).toContainEqual(
      expect.objectContaining({ kind: "REPORT_ONLY_STALE", ids: ["stale"] }),
    );
    // The review row alone is not proof: STALE is an AUTO-tier action, so this
    // case only tests report-only suppression if it also asserts that NOTHING
    // was written. Without these, the test passes even if suppression breaks.
    expect(report.writes).toEqual([]);
    expect(report.deps.markMemoryStale).not.toHaveBeenCalled();
    expect(report.deps.putMemory).not.toHaveBeenCalled();
    expect(report.deps.archiveMemory).not.toHaveBeenCalled();
    expect(report.deps.deleteMemories).not.toHaveBeenCalled();
    expect(reportResult.mutations).toBe(0);
    expect(report.store.get("stale").tags).not.toContain("stale");

    const locked = fakeDeps([item], [
      '{"actions":[{"type":"STALE","ids":["stale"],"rationale":"aged"}]}',
    ]);
    locked.deps.acquireMutex.mockResolvedValueOnce(null);
    const lockedResult = await runConsolidation(
      { stage: "prod", reportOnly: false, cap: 20 },
      locked.deps,
    );
    expect(locked.writes.filter(({ type }) => type === "put")).toEqual([]);
    expect(lockedResult.review).toContainEqual(
      expect.objectContaining({ kind: "LOCK_HELD" }),
    );
  });

  it("TC-CONSOL-003: turns a classifier failure into review-only output", async () => {
    const fake = fakeDeps(
      [memory("a", "one", [1, 0]), memory("b", "two", [1, 0])],
      ["not json"],
    );
    const result = await runConsolidation(
      { stage: "prod", reportOnly: false, cap: 20 },
      fake.deps,
    );
    expect(result.review).toContainEqual(
      expect.objectContaining({
        kind: "CLASSIFICATION_FAILED",
        ids: ["a", "b"],
      }),
    );
    expect(fake.writes.filter(({ type }) => type !== "notify")).toEqual([]);
    expect(result.exitCode).toBe(1);
  });

  it("TC-CONSOL-003: defers an oversized cluster without calling the model", async () => {
    const memories = Array.from({ length: 51 }, (_, index) =>
      memory(`memory-${index}`, `content ${index}`, [1, 0]),
    );
    const fake = fakeDeps(memories, []);

    const result = await runConsolidation(
      { stage: "prod", reportOnly: true, cap: 20 },
      fake.deps,
    );

    expect(fake.completeChat).not.toHaveBeenCalled();
    expect(result.review).toContainEqual(
      expect.objectContaining({ kind: "CLUSTER_TOO_LARGE" }),
    );
    expect(result.exitCode).toBe(0);
  });
});

describe("production adapters and CLI", () => {
  const environmentKeys = [
    "AWS_REGION",
    "MEM9_ALERTS_TOPIC_ARN",
    "MEM9_BASE_URL",
    "MEM9_BEDROCK_PROJECT",
    "MEM9_CONSOLIDATION_REPORT_ONLY",
    "MEM9_CONSOLIDATION_SCHEDULED",
    "MEM9_DB_HOST",
    "MEM9_DB_NAME",
    "MEM9_DB_PORT",
    "MEM9_DB_SECRET",
    "MEM9_DECISION_ARTIFACT_BUCKET",
    "MEM9_DECISION_ARTIFACT_BUCKET_OWNER",
    "MEM9_LLM_MODEL",
    "MEM9_SLACK_APPROVAL_CHANNEL",
    "MEM9_STAGE",
    "MEM9_TENANT_ID",
    "SLACK_BOT_TOKEN",
  ];

  afterEach(() => {
    for (const key of environmentKeys) delete process.env[key];
  });

  it("TC-CONSOL-016: connects DB/REST/Mantle/SNS adapters without exposing content", async () => {
    Object.assign(process.env, {
      AWS_REGION: "ap-northeast-1",
      MEM9_ALERTS_TOPIC_ARN:
        "arn:aws:sns:ap-northeast-1:123456789012:mem9-on-aws-prod-alerts",
      MEM9_BASE_URL: "http://mnemo.local:8080/",
      MEM9_BEDROCK_PROJECT: "project-test",
      MEM9_DB_HOST: "writer.example.com",
      MEM9_DB_NAME: "mem9",
      MEM9_DB_PORT: "5432",
      MEM9_DB_SECRET: JSON.stringify({
        username: "mem9",
        password: "fixture-password",
      }),
      MEM9_LLM_MODEL: "zai.glm-5",
      MEM9_TENANT_ID: "tenant-fixture",
    });
    const dbCalls = [];
    const sent = [];
    const writeStdout = vi.fn();
    const getToken = vi.fn(async () => `bearer-${getToken.mock.calls.length}`);
    let mantleCalls = 0;
    const fetch = vi.fn(async (url, init) => {
      if (String(url).includes("bedrock-mantle")) {
        mantleCalls += 1;
        return mantleCalls === 1
          ? { ok: false, status: 401, json: async () => ({}) }
          : {
              ok: true,
              status: 200,
              json: async () => ({
                choices: [{ message: { content: '{"actions":[]}' } }],
              }),
            };
      }
      if (init.method === "GET") {
        return { ok: false, status: 404, json: async () => ({}) };
      }
      return {
        ok: true,
        status: 200,
        json: async () =>
          String(url).endsWith("/batch-delete")
            ? { deleted: 2 }
            : { status: "accepted" },
      };
    });
    class Client {
      constructor(options) {
        dbCalls.push(["construct", options]);
      }
      async connect() {
        dbCalls.push(["connect"]);
      }
      async query(sql, parameters) {
        dbCalls.push(["query", sql, parameters]);
        if (sql.includes("SELECT id, content")) {
          return {
            rows: [{
              id: "memory-1",
              content: "private content",
              tags: null,
              metadata: '{"source":"fixture"}',
              embedding: "[1,0.5]",
            }],
          };
        }
        if (sql.includes("pg_try_advisory_lock")) {
          return { rows: [{ acquired: true }] };
        }
        if (sql.includes("UPDATE memories")) return { rowCount: 1, rows: [] };
        return { rows: [] };
      }
      async end() {
        dbCalls.push(["end"]);
      }
    }
    class PublishCommand {
      constructor(input) {
        this.input = input;
      }
    }
    class SNSClient {
      async send(command) {
        sent.push(command.input);
      }
      async destroy() {
        sent.push("destroyed");
      }
    }

    const production = await createProductionDeps(
      { stage: "prod" },
      {
        Client,
        fetch,
        fromNodeProviderChain: () => "credentials",
        getToken,
        PublishCommand,
        SNSClient,
        writeStdout,
      },
    );
    const memories = await production.deps.listActiveMemories();
    expect(memories[0]).toMatchObject({
      tags: [],
      metadata: { source: "fixture" },
      embedding: [1, 0.5],
    });
    expect(await production.deps.getMemory("missing")).toBeNull();
    await production.deps.putMemory("memory/1", { tags: ["stale"] }, 2);
    expect(await production.deps.deleteMemories(["a", "b"])).toBe(2);
    const mutex = await production.deps.acquireMutex("prod");
    await mutex.release();
    expect(
      await production.deps.archiveMemory({
        id: "a",
        supersededBy: "b",
        version: 1,
        content: "old",
        winnerVersion: 2,
        winnerContent: "new",
      }),
    ).toBe(true);
    const archiveQuery = dbCalls.find(
      ([kind, sql]) => kind === "query" && sql.includes("UPDATE memories"),
    );
    expect(archiveQuery[1]).toContain("version = loser.version + 1");
    expect(archiveQuery[1]).toContain("EXISTS");
    expect(archiveQuery[2]).toEqual(["a", "b", 1, "old", 2, "new"]);
    expect(
      await production.deps.completeChat("system", [{ id: "a" }]),
    ).toBe('{"actions":[]}');
    expect(getToken).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls.at(-1)[1].headers["OpenAI-Project"]).toBe(
      "project-test",
    );

    await production.deps.publishHealthAlarm({
      reasons: [{ kind: "APPLY_FAILED", rule: "immediate", count: 1 }],
      totals: {
        scanned: 2,
        attemptedClusters: 1,
        classificationFailures: 0,
        reviewItems: 1,
        mutations: 0,
      },
    });
    expect(sent[0].TopicArn).toContain("mem9-on-aws-prod-alerts");
    expect(sent[0].Message).not.toMatch(/private content|tenant-fixture/);
    expect(sent[0].Message).toContain("WeeklyMemoryConsolidationHealth");
    const emf = buildEmfRecord("prod", {
      scanned: 2,
      merged: 0,
      archived: 0,
      flaggedStale: 0,
      reviewItems: 1,
      skippedLww: 0,
    }, NOW);
    production.deps.emitMetrics(emf);
    expect(writeStdout).toHaveBeenCalledOnce();
    const [emfLine] = writeStdout.mock.calls[0];
    expect(emfLine.endsWith("\n")).toBe(true);
    expect(emfLine.endsWith("\r\n")).toBe(false);
    expect(JSON.parse(emfLine)).toEqual(emf);
    await production.close();
    expect(sent.at(-1)).toBe("destroyed");
    expect(dbCalls.at(-1)).toEqual(["end"]);
  });

  it("TC-CONSOL-049: the production REST adapter turns a fenced 412 into null, and only for a versioned write", async () => {
    Object.assign(process.env, {
      AWS_REGION: "ap-northeast-1",
      MEM9_BASE_URL: "http://mnemo.local:8080/",
      MEM9_DB_HOST: "writer.example.com",
      MEM9_DB_NAME: "mem9",
      MEM9_DB_SECRET: JSON.stringify({
        username: "mem9",
        password: "fixture-password",
      }),
      MEM9_TENANT_ID: "tenant-fixture",
    });
    // Every non-GET answers 412 so each call site is judged on its own gate,
    // not on which URL it happened to hit.
    const fetch = vi.fn(async () => ({
      ok: false,
      status: 412,
      json: async () => ({ error: "precondition failed: version changed" }),
    }));
    class Client {
      async connect() {}
      async query() {
        return { rows: [] };
      }
      async end() {}
    }
    const production = await createProductionDeps(
      { stage: "prod" },
      { Client, fetch, fromNodeProviderChain: () => "credentials", getToken: vi.fn(async () => "t") },
    );

    // This is the line the unattended weekly task depends on: without it the
    // 412 throws, the apply aborts, and every later action is deferred instead
    // of the intended "skip this merge and carry on".
    await expect(
      production.deps.putMemory("memory/1", { content: "merged" }, 2),
    ).resolves.toBeNull();
    expect(fetch.mock.calls[0][1].headers["If-Match"]).toBe("2");

    // The fence only exists for a versioned write. An unversioned write has no
    // precondition to lose, so a 412 there is an unexplained server answer and
    // must still fail loud rather than be read as "skipped".
    await expect(production.deps.deleteMemories(["a"])).rejects.toThrow(/HTTP 412/u);
    await expect(
      production.deps.putMemory("memory/1", { content: "merged" }),
    ).rejects.toThrow(/HTTP 412/u);
  });

  it("TC-CONSOL-064: uses owner-bound conditional S3 reads and writes", async () => {
    Object.assign(process.env, {
      AWS_REGION: "ap-northeast-1",
      MEM9_BASE_URL: "http://mnemo.local:8080/",
      MEM9_DB_HOST: "writer.example.com",
      MEM9_DB_NAME: "mem9",
      MEM9_DB_SECRET: JSON.stringify({
        username: "mem9",
        password: "fixture-password",
      }),
      MEM9_DECISION_ARTIFACT_BUCKET: "example-mem9-artifacts",
      MEM9_DECISION_ARTIFACT_BUCKET_OWNER: "123456789012",
      MEM9_TENANT_ID: "tenant-fixture",
    });
    const sent = [];
    let readMode = "missing";
    let writeMode = "ok";
    class Client {
      async connect() {}
      async query() {
        return { rows: [] };
      }
      async end() {}
    }
    class GetObjectCommand {
      constructor(input) {
        this.input = input;
      }
    }
    class PutObjectCommand {
      constructor(input) {
        this.input = input;
      }
    }
    class S3Client {
      async send(command) {
        sent.push(command.input);
        if (command instanceof GetObjectCommand) {
          if (readMode === "missing") {
            const error = new Error("missing");
            error.name = "NoSuchKey";
            throw error;
          }
          if (readMode === "corrupt") {
            return {
              ETag: '"etag-1"',
              Body: { transformToString: async () => "{not-json" },
            };
          }
          return {
            ETag: '"etag-1"',
            Body: {
              transformToString: async () =>
                serializeDigestState({
                  schemaVersion: DIGEST_SCHEMA_VERSION,
                  stage: "prod",
                  generatedAt: "2026-08-16T03:00:00.000Z",
                  unchangedRuns: 0,
                  kindCounts: {},
                  topics: [],
                }),
            },
          };
        }
        if (writeMode === "precondition") {
          const error = new Error("stale");
          error.name = "PreconditionFailed";
          error.$metadata = { httpStatusCode: 412 };
          throw error;
        }
        if (writeMode === "failure") throw new Error("S3 unavailable");
        return { ETag: '"etag-2"' };
      }
      destroy() {}
    }
    const production = await createProductionDeps(
      { stage: "prod" },
      { Client, GetObjectCommand, PutObjectCommand, S3Client },
    );
    expect(await production.deps.loadDigestState()).toEqual({
      status: "missing",
    });
    const state = {
      schemaVersion: DIGEST_SCHEMA_VERSION,
      stage: "prod",
      generatedAt: "2026-08-23T03:00:00.000Z",
      unchangedRuns: 0,
      kindCounts: {},
      topics: [],
    };
    await production.deps.writeDigestState({ state });
    expect(sent.at(-1)).toMatchObject({
      Bucket: "example-mem9-artifacts",
      Key: "consolidation-digests/prod/current-v1.json",
      ExpectedBucketOwner: "123456789012",
      IfNoneMatch: "*",
    });
    expect(sent.at(-1)).not.toHaveProperty("IfMatch");

    readMode = "ok";
    expect(await production.deps.loadDigestState()).toEqual({
      status: "ok",
      etag: '"etag-1"',
      state: expect.objectContaining({ stage: "prod", topics: [] }),
    });
    await production.deps.writeDigestState({ state, etag: '"etag-1"' });
    expect(sent.at(-1)).toMatchObject({
      ExpectedBucketOwner: "123456789012",
      IfMatch: '"etag-1"',
    });
    expect(sent.at(-1)).not.toHaveProperty("IfNoneMatch");

    readMode = "corrupt";
    await expect(production.deps.loadDigestState()).rejects.toThrow(
      /digest state/iu,
    );
    writeMode = "precondition";
    await expect(
      production.deps.writeDigestState({ state, etag: '"stale"' }),
    ).rejects.toMatchObject({ name: "PreconditionFailed" });
    writeMode = "failure";
    await expect(
      production.deps.writeDigestState({ state, etag: '"etag-1"' }),
    ).rejects.toThrow("S3 unavailable");
    await production.close();
  });

  it("rejects incomplete production configuration before connecting", async () => {
    await expect(
      createProductionDeps(
        { stage: "prod" },
        { Client: vi.fn() },
      ),
    ).rejects.toThrow(/tenant id and base URL/u);
  });

  it("parses explicit report/apply arguments and rejects unknown options", () => {
    process.env.MEM9_STAGE = "prod";
    expect(
      parseConsolidationArgs(["--report-only", "--check-llm", "--cap", "7"]),
    ).toEqual({
      stage: "prod",
      reportOnly: true,
      scheduled: false,
      checkLlm: true,
      cap: 7,
    });
    expect(
      parseConsolidationArgs(["--apply", "--stage", "pr-103"]),
    ).toMatchObject({
      stage: "pr-103",
      reportOnly: false,
      checkLlm: false,
    });
    expect(() => parseConsolidationArgs(["--delete"])).toThrow(/unknown/u);
  });
});

describe("content-free telemetry", () => {
  it("TC-CONSOL-013: emits the documented stage-only EMF contract", () => {
    expect(CONSOLIDATION_METRICS).toEqual([
      "ConsolidationScanned",
      "ConsolidationMerged",
      "ConsolidationArchived",
      "ConsolidationFlaggedStale",
      "ConsolidationReviewItems",
      "ConsolidationSkippedLww",
      "ConsolidationDedupUnavailable",
    ]);
    const record = buildEmfRecord("prod", {
      scanned: 10,
      merged: 2,
      archived: 1,
      flaggedStale: 3,
      reviewItems: 4,
      skippedLww: 1,
    }, NOW);
    expect(record._aws.CloudWatchMetrics).toEqual([
      {
        Namespace: "mem9-on-aws",
        Dimensions: [["stage"]],
        Metrics: CONSOLIDATION_METRICS.map((Name) => ({ Name, Unit: "Count" })),
      },
    ]);
    expect(record.stage).toBe("prod");
    expect(JSON.stringify(record)).not.toMatch(/content|snippet|rationale|embedding|tenant/i);
  });

  it("TC-CONSOL-051: routes metrics through the dedicated emitter", async () => {
    const fake = fakeDeps([], []);
    fake.deps.emitMetrics = vi.fn();

    await runConsolidation(
      { stage: "prod", reportOnly: true },
      fake.deps,
    );

    expect(fake.deps.emitMetrics).toHaveBeenCalledOnce();
    expect(fake.deps.emitMetrics.mock.calls[0][0]).toMatchObject({
      stage: "prod",
      ConsolidationScanned: 0,
      ConsolidationReviewItems: 0,
    });
    expect(fake.logs.some((line) => line.includes('"_aws"'))).toBe(false);
  });
});

describe("risk-tiered consolidation digests", () => {
  const operatorKinds = ["DELETE", "CONTRADICTION"];
  const deferredKinds = [
    "CAP_DEFERRED",
    "LOCK_HELD",
    "CLUSTER_TOO_LARGE",
    "TAG_LIMIT_REACHED",
  ];
  const healthKinds = [
    "APPLY_FAILED",
    "UNFENCEABLE_MERGE",
    "CLASSIFICATION_FAILED",
    "UNKNOWN_ID",
    "CONFLICTING_ACTION",
    "INVALID_MERGE",
    "INVALID_STALE",
    "INELIGIBLE_STALE",
  ];

  it("TC-CONSOL-052: maps every review kind and excludes report-only records", () => {
    for (const kind of operatorKinds) {
      expect(reviewDisposition(kind)).toBe("OPERATOR_DECISION");
    }
    for (const kind of deferredKinds) {
      expect(reviewDisposition(kind)).toBe("DEFERRED_RETRY");
    }
    for (const kind of healthKinds) {
      expect(reviewDisposition(kind)).toBe("SYSTEM_HEALTH");
    }
    expect(reviewDisposition("FUTURE_UNKNOWN_KIND")).toBe("SYSTEM_HEALTH");
    expect(reviewDisposition("REPORT_ONLY_MERGE")).toBeNull();
    expect(reviewDisposition(undefined)).toBeNull();
  });

  it("TC-CONSOL-053: folds deferred actions into APPLY_FAILED.abortedCount", async () => {
    const memories = [
      memory("a", "merge a", [1, 0]),
      memory("b", "merge b", [0.99, 0.01]),
      memory("c", "stale c", [0, 1], {
        updated_at: "2025-01-01T00:00:00Z",
      }),
      memory("d", "stale d", [0, 0.99], {
        updated_at: "2025-01-01T00:00:00Z",
      }),
    ];
    const fake = fakeDeps(memories, [
      JSON.stringify({
        actions: [
          {
            type: "MERGE",
            ids: ["a", "b"],
            survivor_id: "a",
            merged_content: "merged",
            rationale: "merge",
          },
        ],
      }),
      JSON.stringify({
        actions: [
          { type: "STALE", ids: ["c"], rationale: "old" },
          { type: "STALE", ids: ["d"], rationale: "old" },
        ],
      }),
    ]);
    fake.deps.deleteMemories.mockRejectedValueOnce(new Error("delete failed"));

    const result = await runConsolidation(
      { stage: "prod", reportOnly: false },
      fake.deps,
    );

    expect(result.review.filter(({ kind }) => kind === "APPLY_FAILED")).toEqual([
      expect.objectContaining({ abortedCount: 2 }),
    ]);
    expect(result.review.some(({ kind }) => kind === "APPLY_ABORTED")).toBe(false);
  });

  it("hashes current content after a partially confirmed merge", async () => {
    const memories = [
      memory("survivor", "fragment one", [1, 0]),
      memory("absorbed", "fragment two", [0.99, 0.01]),
    ];
    const fake = fakeDeps(memories, [
      JSON.stringify({
        actions: [{
          type: "MERGE",
          ids: ["survivor", "absorbed"],
          survivor_id: "survivor",
          merged_content: "merged current content",
          rationale: "same topic",
        }],
      }),
    ]);
    fake.deps.deleteMemories.mockRejectedValueOnce(new Error("delete failed"));

    const result = await runConsolidation(
      {
        stage: "prod",
        reportOnly: false,
        scheduled: true,
        cap: 20,
      },
      fake.deps,
    );

    const failedReview = result.review.find(
      ({ kind }) => kind === "APPLY_FAILED",
    );
    const currentById = new Map(
      [...fake.store.values()]
        .filter(({ state }) => state === "active")
        .map((item) => [item.id, item]),
    );
    const expected = buildReviewTopic(failedReview, currentById);
    const stateWrite = fake.writes.find(({ type }) => type === "state");
    expect(stateWrite.input.state.topics).toContainEqual(
      expect.objectContaining({ payloadHash: expected.payloadHash }),
    );
  });

  it("TC-CONSOL-054/055: separates stable topic identity from mutable content", () => {
    const original = memory("a", "alpha", [1, 0]);
    const other = memory("b", "beta", [0.99, 0.01]);
    const byId = new Map([
      ["a", original],
      ["b", other],
    ]);
    const item = {
      kind: "DELETE",
      ids: ["b", "a", "a"],
      snippets: ["alpha"],
      rationale: "first",
    };
    const first = buildReviewTopic(item, byId);
    const metadataOnly = buildReviewTopic(
      {
        ...item,
        ids: ["a", "b"],
        rationale: "changed",
        snippets: ["changed"],
      },
      new Map([
        ["a", { ...original, version: 9, metadata: { changed: true } }],
        ["b", other],
      ]),
    );
    expect(metadataOnly.topicId).toBe(first.topicId);
    expect(metadataOnly.payloadHash).toBe(first.payloadHash);

    const contentChanged = buildReviewTopic(
      { ...item, ids: ["a", "b"] },
      new Map([
        ["a", { ...original, content: "alpha changed" }],
        ["b", other],
      ]),
    );
    expect(contentChanged.topicId).toBe(first.topicId);
    expect(contentChanged.payloadHash).not.toBe(first.payloadHash);

    expect(buildReviewTopic(
      { kind: "REPORT_ONLY_MERGE", ids: ["a"], snippets: ["alpha"] },
      byId,
    )).toBeNull();
    const sparse = buildReviewTopic(
      { kind: "DELETE", ids: "invalid", snippets: "invalid" },
      new Map(),
    );
    const missing = buildReviewTopic(
      { kind: "DELETE", ids: ["missing"], snippets: [null] },
      new Map(),
    );
    expect(sparse.samples).toEqual([]);
    expect(missing.samples).toEqual([]);
    expect(missing.payloadHash).not.toBe(sparse.payloadHash);
  });

  it("TC-CONSOL-056: classifies new, updated, continuing, and resolved topics", () => {
    const byId = new Map([
      ["new", memory("new", "new", [1, 0])],
      ["updated", memory("updated", "updated-v2", [1, 0])],
      ["continuing", memory("continuing", "same", [1, 0])],
    ]);
    const current = [
      buildReviewTopic(
        { kind: "DELETE", ids: ["new"], snippets: [], rationale: "" },
        byId,
      ),
      buildReviewTopic(
        { kind: "DELETE", ids: ["updated"], snippets: [], rationale: "" },
        byId,
      ),
      buildReviewTopic(
        { kind: "DELETE", ids: ["continuing"], snippets: [], rationale: "" },
        byId,
      ),
    ];
    const previousUpdated = buildReviewTopic(
      { kind: "DELETE", ids: ["updated"], snippets: [], rationale: "" },
      new Map([["updated", memory("updated", "updated-v1", [1, 0])]]),
    );
    const previousContinuing = current[2];
    const previousResolved = buildReviewTopic(
      { kind: "DELETE", ids: ["resolved"], snippets: [], rationale: "" },
      new Map([["resolved", memory("resolved", "gone", [1, 0])]]),
    );
    const previousState = {
      schemaVersion: DIGEST_SCHEMA_VERSION,
      stage: "prod",
      generatedAt: "2026-07-26T00:00:00.000Z",
      unchangedRuns: 0,
      kindCounts: {},
      topics: [previousUpdated, previousContinuing, previousResolved].map(
        ({ topicId, payloadHash, kind, disposition }) => ({
          topicId,
          payloadHash,
          kind,
          disposition,
        }),
      ),
    };

    const compared = compareDigestTopics(current, previousState);
    expect(compared.current.map(({ transition }) => transition).sort()).toEqual([
      "continuing",
      "new",
      "updated",
    ]);
    expect(compared.resolved).toHaveLength(1);
    expect(compared.resolved[0]).toMatchObject({ transition: "resolved" });
  });

  it("TC-CONSOL-057: reminds only on the fourth unchanged scheduled run", () => {
    const byId = new Map([["a", memory("a", "same", [1, 0])]]);
    const review = [{
      kind: "DELETE",
      ids: ["a"],
      snippets: ["same"],
      rationale: "manual",
    }];
    let previousState;
    const reminders = [];
    for (let run = 1; run <= 5; run += 1) {
      const outcome = buildDigestOutcome({
        stage: "prod",
        review,
        byId,
        previousState,
        metrics: {
          scanned: 1,
          merged: 0,
          archived: 0,
          flaggedStale: 0,
          reviewItems: 1,
          skippedLww: 0,
        },
        mutations: 0,
        attemptedClusters: 1,
        classificationFailures: 0,
        now: NOW + run,
      });
      reminders.push({ post: outcome.shouldPost, reminder: outcome.reminder });
      previousState = outcome.nextState;
    }
    expect(reminders).toEqual([
      { post: true, reminder: false },
      { post: false, reminder: false },
      { post: false, reminder: false },
      { post: false, reminder: false },
      { post: true, reminder: true },
    ]);

    const changed = buildDigestOutcome({
      stage: "prod",
      review: [...review, {
        kind: "DELETE",
        ids: ["b"],
        snippets: ["new"],
        rationale: "manual",
      }],
      byId: new Map([...byId, ["b", memory("b", "new", [1, 0])]]),
      previousState,
      metrics: {
        scanned: 2,
        merged: 0,
        archived: 0,
        flaggedStale: 0,
        reviewItems: 2,
        skippedLww: 0,
      },
      mutations: 0,
      attemptedClusters: 1,
      classificationFailures: 0,
      now: NOW + 6,
    });
    expect(changed.shouldPost).toBe(true);
    expect(changed.nextState.unchangedRuns).toBe(0);
  });

  it("TC-CONSOL-058/059: bounds groups and samples while forcing new oversized clusters visible", () => {
    const kinds = [
      "APPLY_FAILED",
      "UNFENCEABLE_MERGE",
      "CLASSIFICATION_FAILED",
      "UNKNOWN_ID",
      "CONFLICTING_ACTION",
      "INVALID_MERGE",
      "INVALID_STALE",
      "INELIGIBLE_STALE",
      "DELETE",
      "CONTRADICTION",
      "CAP_DEFERRED",
      "LOCK_HELD",
      "TAG_LIMIT_REACHED",
      "CLUSTER_TOO_LARGE",
      "FUTURE_UNKNOWN_KIND",
    ];
    const byId = new Map();
    const review = [];
    for (const [kindIndex, kind] of kinds.entries()) {
      for (let sample = 0; sample < 5; sample += 1) {
        const id = `${kindIndex}-${sample}`;
        byId.set(id, memory(id, `sample ${id}`, [1, 0]));
        review.push({
          kind,
          ids: [id],
          snippets: [`sample ${id}`],
          rationale: "fixture",
        });
      }
    }
    const outcome = buildDigestOutcome({
      stage: "prod",
      review,
      byId,
      previousState: undefined,
      metrics: {
        scanned: byId.size,
        merged: 1,
        archived: 2,
        flaggedStale: 3,
        reviewItems: review.length,
        skippedLww: 4,
      },
      mutations: 6,
      attemptedClusters: 20,
      classificationFailures: 0,
      now: NOW,
    });

    expect(outcome.groups).toHaveLength(10);
    expect(
      outcome.groups.some(({ kind }) => kind === "CLUSTER_TOO_LARGE"),
    ).toBe(true);
    expect(outcome.groups.every(({ samples }) => samples.length <= 3)).toBe(true);
    expect(outcome.slackMessage.blocks).toHaveLength(12);
    expect(JSON.stringify(outcome.slackMessage)).not.toMatch(
      /"type":"actions"|approve|reject|bulk/iu,
    );
  });

  it("TC-CONSOL-060: evaluates immediate, count, ratio, repeat, and affected-memory thresholds", () => {
    const item = (kind, ids = []) => ({
      kind,
      ids,
      snippets: [],
      rationale: "",
    });
    expect(evaluateDigestHealth({
      review: [item("APPLY_FAILED")],
      previousState: undefined,
      attemptedClusters: 1,
      classificationFailures: 0,
      scanned: 100,
    }).alarm).toBe(true);
    expect(evaluateDigestHealth({
      review: [item("UNFENCEABLE_MERGE", ["a"])],
      previousState: undefined,
      attemptedClusters: 1,
      classificationFailures: 0,
      scanned: 100,
    }).alarm).toBe(true);
    expect(evaluateDigestHealth({
      review: [item("FUTURE_UNKNOWN_KIND", ["a"])],
      previousState: undefined,
      attemptedClusters: 1,
      classificationFailures: 0,
      scanned: 100,
    }).alarm).toBe(true);
    expect(evaluateDigestHealth({
      review: Array.from({ length: 9 }, () => item("CLASSIFICATION_FAILED")),
      previousState: undefined,
      attemptedClusters: 50,
      classificationFailures: 9,
      scanned: 100,
    }).alarm).toBe(false);
    expect(evaluateDigestHealth({
      review: Array.from({ length: 10 }, () => item("CLASSIFICATION_FAILED")),
      previousState: undefined,
      attemptedClusters: 100,
      classificationFailures: 10,
      scanned: 100,
    }).alarm).toBe(true);
    expect(evaluateDigestHealth({
      review: [item("CLASSIFICATION_FAILED")],
      previousState: undefined,
      attemptedClusters: 5,
      classificationFailures: 1,
      scanned: 100,
    }).alarm).toBe(true);
    expect(evaluateDigestHealth({
      review: Array.from({ length: 10 }, (_, index) =>
        item("INVALID_MERGE", [`id-${index}`])),
      previousState: undefined,
      attemptedClusters: 20,
      classificationFailures: 0,
      scanned: 100,
    }).alarm).toBe(true);
    expect(evaluateDigestHealth({
      review: [item("INVALID_MERGE", ["a"])],
      previousState: { kindCounts: { INVALID_MERGE: 1 } },
      attemptedClusters: 20,
      classificationFailures: 0,
      scanned: 100,
    }).alarm).toBe(true);
    for (const kind of ["LOCK_HELD", "CLUSTER_TOO_LARGE", "TAG_LIMIT_REACHED"]) {
      expect(evaluateDigestHealth({
        review: [item(kind, ["a"])],
        previousState: { kindCounts: { [kind]: 1 } },
        attemptedClusters: 20,
        classificationFailures: 0,
        scanned: 100,
      }).alarm, kind).toBe(true);
    }
    expect(evaluateDigestHealth({
      review: [item(
        "CLUSTER_TOO_LARGE",
        Array.from({ length: 20 }, (_, index) => `id-${index}`),
      )],
      previousState: undefined,
      attemptedClusters: 20,
      classificationFailures: 0,
      scanned: 100,
    }).alarm).toBe(true);
    expect(evaluateDigestHealth({
      review: [item("REPORT_ONLY_MERGE")],
      previousState: undefined,
      attemptedClusters: 1,
      classificationFailures: 0,
      scanned: 0,
    })).toEqual({ alarm: false, reasons: [], kindCounts: {} });
  });

  it("TC-CONSOL-061/062: delivers required notifications before state and preserves confirmed mutations on failure", async () => {
    const order = [];
    const base = {
      stage: "prod",
      review: [{
        kind: "APPLY_FAILED",
        ids: [],
        snippets: [],
        rationale: "failed",
      }],
      byId: new Map(),
      metrics: {
        scanned: 1,
        merged: 1,
        archived: 0,
        flaggedStale: 0,
        reviewItems: 1,
        skippedLww: 0,
      },
      mutations: 1,
      attemptedClusters: 1,
      classificationFailures: 0,
      now: NOW,
    };
    const deps = {
      loadDigestState: vi.fn(async () => {
        order.push("read");
        return { status: "missing" };
      }),
      postDigest: vi.fn(async () => {
        order.push("slack");
      }),
      publishHealthAlarm: vi.fn(async () => {
        order.push("sns");
      }),
      writeDigestState: vi.fn(async () => {
        order.push("state");
      }),
      log: vi.fn(),
    };
    const delivered = await processScheduledDigest(base, deps);
    expect(delivered.failed).toBe(false);
    expect(order).toEqual(["read", "slack", "sns", "state"]);

    for (const transport of ["slack", "sns", "state"]) {
      order.length = 0;
      deps.postDigest.mockImplementation(async () => {
        order.push("slack");
        if (transport === "slack") throw new Error("slack failed");
      });
      deps.publishHealthAlarm.mockImplementation(async () => {
        order.push("sns");
        if (transport === "sns") throw new Error("sns failed");
      });
      deps.writeDigestState.mockImplementation(async () => {
        order.push("state");
        if (transport === "state") throw new Error("S3 failed");
      });
      const failed = await processScheduledDigest(base, deps);
      expect(failed.failed, transport).toBe(true);
      expect(failed.mutations).toBe(1);
      if (transport === "slack") {
        expect(order).toEqual(["read", "slack", "sns"]);
      } else if (transport === "sns") {
        expect(order).toEqual(["read", "slack", "sns"]);
      } else {
        expect(order).toEqual(["read", "slack", "sns", "state"]);
      }
    }
  });

  it("TC-CONSOL-063: degrades on unreadable state and permits only conditional creation", async () => {
    const calls = [];
    const writeDigestState = vi.fn(async (input) =>
      calls.push(["state", input]));
    const result = await processScheduledDigest(
      {
        stage: "prod",
        review: [{
          kind: "DELETE",
          ids: ["a"],
          snippets: ["private alpha"],
          rationale: "manual",
        }],
        byId: new Map([["a", memory("a", "private alpha", [1, 0])]]),
        metrics: {
          scanned: 1,
          merged: 0,
          archived: 0,
          flaggedStale: 0,
          reviewItems: 1,
          skippedLww: 0,
        },
        mutations: 0,
        attemptedClusters: 1,
        classificationFailures: 0,
        now: NOW,
      },
      {
        loadDigestState: vi.fn(async () => {
          throw new Error("AccessDenied");
        }),
        postDigest: vi.fn(async (message) => calls.push(["slack", message])),
        publishHealthAlarm: vi.fn(async (alarm) => calls.push(["sns", alarm])),
        writeDigestState,
        log: vi.fn((line) => calls.push(["log", line])),
      },
    );

    expect(result.dedupUnavailable).toBe(true);
    expect(result.transitions.current).toEqual([
      expect.objectContaining({ transition: "continuing" }),
    ]);
    expect(result.transitions.resolved).toEqual([]);
    expect(calls.map(([kind]) => kind)).toEqual([
      "log",
      "slack",
      "sns",
      "state",
    ]);
    expect(writeDigestState).toHaveBeenCalledWith({
      state: result.nextState,
    });
    expect(JSON.stringify(calls.find(([kind]) => kind === "sns"))).not.toContain(
      "private alpha",
    );
  });

  it("TC-CONSOL-065: serializes only content-free snapshot state", () => {
    const byId = new Map([
      ["private-id", memory("private-id", "private memory text", [1, 0])],
    ]);
    const outcome = buildDigestOutcome({
      stage: "prod",
      review: [{
        kind: "DELETE",
        ids: ["private-id"],
        snippets: ["private memory text"],
        rationale: "private rationale",
      }],
      byId,
      previousState: undefined,
      metrics: {
        scanned: 1,
        merged: 0,
        archived: 0,
        flaggedStale: 0,
        reviewItems: 1,
        skippedLww: 0,
      },
      mutations: 0,
      attemptedClusters: 1,
      classificationFailures: 0,
      now: NOW,
    });
    const serialized = serializeDigestState(outcome.nextState);
    expect(serialized).not.toMatch(
      /private-id|private memory text|private rationale|snippet|rationale|ids/iu,
    );
    expect(JSON.parse(serialized)).toEqual(outcome.nextState);
    expect(JSON.parse(serializeDigestState({
      schemaVersion: DIGEST_SCHEMA_VERSION,
      stage: "prod",
      generatedAt: new Date(NOW).toISOString(),
      unchangedRuns: 0,
    }))).toMatchObject({ kindCounts: {}, topics: [] });
  });

  it("TC-CONSOL-066: integrates bounded delivery and state across 1,000-record runs", async () => {
    const makeRun = (second) => {
      const review = [];
      const byId = new Map();
      for (const group of largeDigestFixture.groups) {
        for (let index = 0; index < group.count; index += 1) {
          if (second && index === 1) continue;
          const id = `${group.kind}-${index}`;
          const content =
            second && index === 0
              ? `updated ${group.kind}`
              : `sample ${group.kind} ${index}`;
          byId.set(id, memory(id, content, [1, 0]));
          review.push({
            kind: group.kind,
            ids: [id],
            snippets: [content],
            rationale: "fixture",
          });
        }
        if (second) {
          const id = `${group.kind}-new`;
          byId.set(id, memory(id, `new ${group.kind}`, [1, 0]));
          review.push({
            kind: group.kind,
            ids: [id],
            snippets: [`new ${group.kind}`],
            rationale: "fixture",
          });
        }
      }
      return { review, byId };
    };
    const firstRun = makeRun(false);
    expect(firstRun.review.length).toBeGreaterThan(1_000);
    let persisted;
    let etagSequence = 0;
    const deliveryOrder = [];
    const postDigest = vi.fn(async (message) => {
      deliveryOrder.push("slack");
      expect(message.blocks.length).toBeLessThanOrEqual(12);
    });
    const writeDigestState = vi.fn(async ({ state, etag }) => {
      deliveryOrder.push("state");
      expect(etag).toBe(persisted?.etag);
      persisted = {
        state: JSON.parse(serializeDigestState(state)),
        etag: `"etag-${etagSequence += 1}"`,
      };
    });
    const deps = {
      loadDigestState: vi.fn(async () =>
        persisted
          ? { status: "ok", ...persisted }
          : { status: "missing" }),
      postDigest,
      publishHealthAlarm: vi.fn(async () => {
        deliveryOrder.push("sns");
      }),
      writeDigestState,
      log: vi.fn(),
    };
    const first = await processScheduledDigest({
      stage: largeDigestFixture.stage,
      ...firstRun,
      metrics: {
        scanned: firstRun.byId.size,
        merged: 0,
        archived: 0,
        flaggedStale: 0,
        reviewItems: firstRun.review.length,
        skippedLww: 0,
      },
      mutations: 0,
      attemptedClusters: firstRun.review.length,
      classificationFailures: 90,
      now: NOW,
    }, deps);
    const secondRun = makeRun(true);
    const second = await processScheduledDigest({
      stage: largeDigestFixture.stage,
      ...secondRun,
      metrics: {
        scanned: secondRun.byId.size,
        merged: 0,
        archived: 0,
        flaggedStale: 0,
        reviewItems: secondRun.review.length,
        skippedLww: 0,
      },
      mutations: 0,
      attemptedClusters: secondRun.review.length,
      classificationFailures: 90,
      now: NOW + 1,
    }, deps);

    for (const outcome of [first, second]) {
      expect(outcome.groups.length).toBeLessThanOrEqual(10);
      expect(outcome.groups.every(({ samples }) => samples.length <= 3)).toBe(true);
      expect(outcome.slackMessage.blocks.length).toBeLessThanOrEqual(12);
    }
    expect(second.transitions.current.some(({ transition }) => transition === "new")).toBe(true);
    expect(second.transitions.current.some(({ transition }) => transition === "updated")).toBe(true);
    expect(second.transitions.current.some(({ transition }) => transition === "continuing")).toBe(true);
    expect(second.transitions.resolved.length).toBeGreaterThan(0);
    expect(postDigest).toHaveBeenCalledTimes(2);
    expect(writeDigestState).toHaveBeenCalledTimes(2);
    expect(deliveryOrder).toEqual([
      "slack",
      "sns",
      "state",
      "slack",
      "sns",
      "state",
    ]);
  });
});
