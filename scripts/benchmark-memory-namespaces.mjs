#!/usr/bin/env node

import { performance } from "node:perf_hooks";
import process from "node:process";
import pg from "pg";

export const M2M_RESOLUTION_QUERY = `
  SELECT principal.principal_id,
         principal.principal_type,
         principal.status, binding.namespace_id, binding.role,
         binding.status, namespace.status, membership.role,
         membership.status
  FROM memory_m2m_namespace_bindings AS binding
  JOIN memory_principals AS principal
    ON principal.principal_id = binding.principal_id
  JOIN memory_namespaces AS namespace
    ON namespace.namespace_id = binding.namespace_id
  JOIN memory_namespace_memberships AS membership
    ON membership.namespace_id = binding.namespace_id
   AND membership.principal_id = binding.principal_id
  WHERE binding.client_key = $1
    AND principal.principal_key = $2
  FOR UPDATE`;

function boundedInteger(value, fallback, minimum, maximum, name) {
  const parsed = value == null ? fallback : Number(value);
  if (
    !Number.isInteger(parsed) ||
    parsed < minimum ||
    parsed > maximum
  ) {
    throw new Error(`${name} is invalid`);
  }
  return parsed;
}

export function percentile95(samples) {
  if (!Array.isArray(samples) || samples.length === 0) {
    throw new Error("latency sample is required");
  }
  const ordered = [...samples].sort((left, right) => left - right);
  return ordered[Math.ceil(ordered.length * 0.95) - 1];
}

async function resolveM2M(db, fixture) {
  await db.query("BEGIN");
  try {
    await db.query(
      `SELECT pg_advisory_xact_lock(hashtext($1))`,
      [fixture.principal_key],
    );
    const resolved = await db.query({
      text: M2M_RESOLUTION_QUERY,
      values: [fixture.client_key, fixture.principal_key],
      rowMode: "array",
    });
    const row = resolved.rows[0];
    if (
      resolved.rowCount !== 1 ||
      row?.[1] !== "m2m" ||
      row[2] !== "active" ||
      row[5] !== "active" ||
      row[6] !== "active" ||
      row[8] !== "active" ||
      row[7] !== row[4]
    ) {
      throw new Error("benchmark namespace fixture is not active");
    }
    await db.query(
      `UPDATE memory_principals
       SET last_seen_at = statement_timestamp()
       WHERE principal_id = $1`,
      [row[0]],
    );
    await db.query("COMMIT");
  } catch (error) {
    await db.query("ROLLBACK");
    throw error;
  }
}

export async function benchmarkNamespaceResolution(
  db,
  {
    warmups = 20,
    samples = 100,
    thresholdMs = 20,
    now = () => performance.now(),
  } = {},
) {
  warmups = boundedInteger(warmups, 20, 0, 100, "benchmark warmups");
  samples = boundedInteger(samples, 100, 1, 500, "benchmark samples");
  if (!Number.isFinite(thresholdMs) || thresholdMs <= 0) {
    throw new Error("benchmark threshold is invalid");
  }
  const phase = await db.query(`
    SELECT phase
    FROM memory_namespace_migration_state
    WHERE singleton_id
  `);
  if (phase.rows[0]?.phase !== "constraints_complete") {
    throw new Error("benchmark requires constraints_complete");
  }
  const fixtureResult = await db.query(`
    SELECT binding.client_key, principal.principal_key
    FROM memory_m2m_namespace_bindings AS binding
    JOIN memory_principals AS principal
      ON principal.principal_id = binding.principal_id
    JOIN memory_namespaces AS namespace
      ON namespace.namespace_id = binding.namespace_id
    JOIN memory_namespace_memberships AS membership
      ON membership.namespace_id = binding.namespace_id
     AND membership.principal_id = binding.principal_id
    WHERE binding.status = 'active'
      AND principal.principal_type = 'm2m'
      AND principal.status = 'active'
      AND namespace.status = 'active'
      AND membership.status = 'active'
      AND membership.role = binding.role
    ORDER BY binding.created_at, binding.client_key
    LIMIT 1
  `);
  if (fixtureResult.rowCount !== 1) {
    throw new Error("benchmark requires one active M2M fixture");
  }
  const fixture = fixtureResult.rows[0];
  const durations = [];
  for (let index = 0; index < warmups + samples; index += 1) {
    const started = now();
    await resolveM2M(db, fixture);
    const elapsed = now() - started;
    if (index >= warmups) durations.push(elapsed);
  }
  const p95 = percentile95(durations);
  const roundedP95 = Math.round(p95 * 1000) / 1000;
  if (roundedP95 >= thresholdMs) {
    throw new Error(
      `namespace resolution p95 ${roundedP95}ms exceeds ${thresholdMs}ms`,
    );
  }
  return {
    version: 1,
    samples,
    p95_ms: roundedP95,
    threshold_ms: thresholdMs,
  };
}

async function main() {
  if (!/^pr-[1-9][0-9]*$/u.test(process.env.MEM9_STAGE ?? "")) {
    throw new Error("namespace benchmark is restricted to pr-N stages");
  }
  const dsn = process.env.MNEMO_DSN;
  if (!dsn) throw new Error("MNEMO_DSN is required");
  const db = new pg.Client({
    connectionString: dsn,
    statement_timeout: 30_000,
  });
  await db.connect();
  try {
    const result = await benchmarkNamespaceResolution(db, {
      samples: boundedInteger(
        process.env.MEM9_NAMESPACE_BENCHMARK_SAMPLES,
        100,
        20,
        500,
        "benchmark samples",
      ),
      warmups: boundedInteger(
        process.env.MEM9_NAMESPACE_BENCHMARK_WARMUPS,
        20,
        0,
        100,
        "benchmark warmups",
      ),
    });
    process.stdout.write(
      `${JSON.stringify({
        event: "namespace_resolution_benchmark",
        ...result,
      })}\n`,
    );
  } finally {
    await db.end();
  }
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  main().catch((error) => {
    process.stderr.write(`namespace benchmark failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
