import { afterEach, describe, expect, it, vi } from "vitest";

import {
  CONSOLIDATION_METRICS,
  buildEmfRecord,
  clusterMemories,
  createProductionDeps,
  parseActions,
  parseConsolidationArgs,
  routeActions,
  runConsolidation,
} from "./memory-consolidation.mjs";

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
      putMemory: vi.fn(async (id, patch) => {
        writes.push({ type: "put", id, patch: structuredClone(patch) });
        const item = store.get(id);
        Object.assign(item, patch, { version: item.version + 1 });
        return structuredClone(item);
      }),
      deleteMemories: vi.fn(async (ids) => {
        writes.push({ type: "delete", ids: [...ids] });
        for (const id of ids) store.get(id).state = "deleted";
        return ids.length;
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
      publishSummary: vi.fn(async (summary) => {
        writes.push({ type: "notify", summary: structuredClone(summary) });
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
        updated_at: "2026-01-01T00:00:00Z",
      }),
      memory("new", "use v2", [1, 0], {
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
        updated_at: "2026-01-01T00:00:00Z",
      }),
      memory("new", "use v2", [-1, 0], {
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
    expect(fake.writes).toContainEqual(
      expect.objectContaining({
        type: "put",
        id: "stale",
        patch: expect.objectContaining({
          tags: ["config", "stale"],
          metadata: expect.objectContaining({ source: "agent" }),
        }),
      }),
    );
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
    expect(fake.deps.publishSummary).not.toHaveBeenCalled();
    expect(fake.logs.some((line) => line.startsWith("CONSOLIDATION_REVIEW "))).toBe(true);
    expect(fake.logs.some((line) => line.startsWith("CONSOLIDATION_REVIEW_LIST "))).toBe(true);
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
        updated_at: "2026-01-01T00:00:00Z",
      }),
      memory("new", "use v2", [1, 0], {
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
        updated_at: "2026-01-01T00:00:00Z",
      }),
      memory("new", "use v2", [1, 0], {
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
    expect(locked.deps.publishSummary).toHaveBeenCalledOnce();
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
    "MEM9_DB_HOST",
    "MEM9_DB_NAME",
    "MEM9_DB_PORT",
    "MEM9_DB_SECRET",
    "MEM9_LLM_MODEL",
    "MEM9_STAGE",
    "MEM9_TENANT_ID",
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

    await production.deps.publishSummary({
      scanned: 2,
      merged: 0,
      archived: 0,
      flaggedStale: 0,
      reviewItems: 1,
      skippedLww: 0,
    });
    expect(sent[0].TopicArn).toContain("mem9-on-aws-prod-alerts");
    expect(sent[0].Message).not.toMatch(/private content|tenant-fixture/);
    await production.close();
    expect(sent.at(-1)).toBe("destroyed");
    expect(dbCalls.at(-1)).toEqual(["end"]);
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
});
