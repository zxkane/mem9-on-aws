import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  M2M_RESOLUTION_QUERY,
  benchmarkNamespaceResolution,
  percentile95,
} from "./benchmark-memory-namespaces.mjs";

function fixtureDb({ phase = "constraints_complete" } = {}) {
  const queries = [];
  return {
    queries,
    async query(sql, args = []) {
      const text = typeof sql === "string" ? sql : sql.text;
      if (typeof sql === "object") args = sql.values;
      queries.push({ text, args });
      if (text.includes("FROM memory_namespace_migration_state")) {
        return { rowCount: 1, rows: [{ phase }] };
      }
      if (text.includes("FROM memory_m2m_namespace_bindings AS binding") &&
        text.includes("LIMIT 1")) {
        return {
          rowCount: 1,
          rows: [{
            client_key: "a".repeat(64),
            principal_key: "b".repeat(64),
          }],
        };
      }
      if (text.includes("SELECT principal.principal_id")) {
        return {
          rowCount: 1,
          rows: [[
            "fixture-principal",
            "m2m",
            "active",
            "fixture-namespace",
            "member",
            "active",
            "active",
            "member",
            "active",
          ]],
        };
      }
      if (
        ["BEGIN", "COMMIT", "ROLLBACK"].includes(text) ||
        text.includes("pg_advisory_xact_lock") ||
        text.includes("UPDATE memory_principals")
      ) {
        return { rowCount: 1, rows: [] };
      }
      throw new Error(`unexpected benchmark SQL: ${text}`);
    },
  };
}

function clockForDurations(durations) {
  const values = durations.flatMap((duration, index) => [
    index * 100,
    index * 100 + duration,
  ]);
  let offset = 0;
  return () => values[offset++];
}

describe("namespace resolution benchmark", () => {
  it("TC-GROUPNS-112: records bounded resolution p95", async () => {
    const db = fixtureDb();
    const result = await benchmarkNamespaceResolution(db, {
      warmups: 1,
      samples: 5,
      thresholdMs: 20,
      now: clockForDurations([1, 1, 2, 3, 4, 5]),
    });

    expect(result).toEqual({
      version: 1,
      samples: 5,
      p95_ms: 5,
      threshold_ms: 20,
    });
    expect(JSON.stringify(result)).not.toMatch(
      /fixture|principal_key|client_key|namespace_id/iu,
    );
    expect(
      db.queries.filter(({ text }) => text === "BEGIN"),
    ).toHaveLength(6);
    expect(
      db.queries.filter(({ text }) => text === "COMMIT"),
    ).toHaveLength(6);
  });

  it("fails closed on phase or latency", async () => {
    await expect(
      benchmarkNamespaceResolution(fixtureDb({ phase: "application_ready" }), {
        warmups: 0,
        samples: 1,
        now: clockForDurations([1]),
      }),
    ).rejects.toThrow(/constraints_complete/u);
    await expect(
      benchmarkNamespaceResolution(fixtureDb(), {
        warmups: 0,
        samples: 1,
        thresholdMs: 20,
        now: clockForDurations([21]),
      }),
    ).rejects.toThrow(/p95/u);
  });

  it("computes nearest-rank p95", () => {
    expect(percentile95([5, 1, 4, 2, 3])).toBe(5);
    expect(() => percentile95([])).toThrow(/sample/u);
  });

  it("locks the JavaScript benchmark to the production Go M2M query", async () => {
    const patch = (
      await readFile(
        resolve(
          import.meta.dirname,
          "../docker/mnemo-server/patches/0010-group-memory-namespaces.patch",
        ),
        "utf8",
      )
    ).replace(/^\+/gmu, "");
    const normalize = (value) => value.replace(/\s+/gu, " ").trim();
    expect(normalize(patch)).toContain(normalize(M2M_RESOLUTION_QUERY));
  });
});

describe("preview benchmark packaging and runner", () => {
  it("packages the benchmark in the bootstrap image", async () => {
    const dockerfile = await readFile(
      resolve(import.meta.dirname, "../docker/bootstrap/Dockerfile"),
      "utf8",
    );
    expect(dockerfile).toContain(
      "COPY scripts/benchmark-memory-namespaces.mjs /bootstrap/operator/scripts/benchmark-memory-namespaces.mjs",
    );
  });

  it("uses the stage bootstrap task without retained-role overrides", async () => {
    const runner = await readFile(
      resolve(import.meta.dirname, "run-memory-namespace-benchmark.sh"),
      "utf8",
    );
    expect(runner).toMatch(/\^pr-\[1-9\]\[0-9\]\*\$/u);
    expect(runner).toContain("MEM9_BOOTSTRAP_OPERATION");
    expect(runner).toContain("benchmark");
    expect(runner).toContain("MEM9_NAMESPACE_BENCHMARK_SAMPLES");
    expect(runner).toContain("MEM9_NAMESPACE_BENCHMARK_WARMUPS");
    expect(runner).not.toContain("taskRoleArn");
    expect(runner).toContain("namespace_resolution_benchmark");
    expect(runner).toContain("fromjson?");
    expect(runner).toContain("trap cleanup EXIT");
    expect(runner).toContain("aws ecs stop-task");
    expect(runner).not.toContain(".events[-200:][] | .message");
  });

  it("pins and exercises a separate namespace-aware rollback source", async () => {
    const rollbackRef = (
      await readFile(
        resolve(import.meta.dirname, "namespace-rollback-ref.txt"),
        "utf8",
      )
    ).trim();
    const integration = await readFile(
      resolve(import.meta.dirname, "run-ingest-queue-integration.sh"),
      "utf8",
    );
    expect(rollbackRef).toMatch(/^[0-9a-f]{40}$/u);
    expect(integration).toContain("namespace-rollback-ref.txt");
    expect(integration).toContain("mnemo-server-rollback");
    expect(integration).toContain("rollback namespace-aware server");
    expect(integration).toContain("/healthz");
    expect(integration).toContain(
      "namespace compatibility mode cannot start in phase",
    );
  });
});
