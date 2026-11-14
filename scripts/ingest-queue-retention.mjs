#!/usr/bin/env node
// ingest-queue-retention.mjs — maintenance-plane retention sweep for the
// durable ingest queue (ingest_jobs, ingest_job_plans).
//
// Why: IngestJobRepo.Enqueue (patch 0004) stores a verbatim copy of every
// submitted transcript in canonical_payload, and up to a few plan revisions
// in ingest_job_plans.plan_payload. The runtime never deletes these rows,
// so terminal (succeeded/dead) jobs retain plaintext transcripts
// indefinitely — including content that the owning principal later deletes
// from sessions or memories. This script invokes the
// purge_terminal_ingest_payloads function added in migration
// 008_ingest_queue_retention.sql to NULL out those payload columns on rows
// whose completed_at is older than the configured retention window. The row
// itself is kept so that idempotency keys and operational metadata remain
// available; only the sensitive content is removed.
//
// Payloads of non-terminal rows are never touched; those must transition to
// terminal via the normal worker path before they become eligible. The sweep
// is batched (SELECT ... FOR UPDATE SKIP LOCKED) so an in-flight claim or
// write is never blocked.
//
// Environment:
//   MEM9_DB_HOST, MEM9_DB_PORT, MEM9_DB_NAME                 — target cluster
//   MEM9_INGEST_RETENTION_DB_SECRET                          — {username,password}
//   MEM9_INGEST_RETENTION_WINDOW   (default: "24 hours")     — Postgres interval
//   MEM9_INGEST_RETENTION_BATCH    (default: 1000, max 10000)
//   MEM9_INGEST_RETENTION_MAX_BATCHES (default: 100)         — safety stop
//
// Output: one JSON line per invocation summarizing total rows whose payloads
// were nulled. Exit code is non-zero on configuration or database error.

import { pathToFileURL } from "node:url";

const DEFAULT_RETENTION_WINDOW = "24 hours";
const DEFAULT_BATCH = 1000;
const MAX_BATCH = 10000;
const DEFAULT_MAX_BATCHES = 100;

function parsePositiveInt(raw, fallback, { max } = {}) {
  if (raw === undefined || raw === null || raw === "") return fallback;
  if (!/^[1-9][0-9]*$/.test(raw)) {
    throw new Error("invalid positive integer");
  }
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) throw new Error("invalid positive integer");
  if (max !== undefined && n > max) return max;
  return n;
}

function parseRetentionWindow(raw) {
  if (raw === undefined || raw === null || raw === "") return DEFAULT_RETENTION_WINDOW;
  // Allow only a small vocabulary of interval forms so an operator typo cannot
  // produce a surprising query parse at the far end: digits, whitespace, and
  // the units Postgres accepts for an INTERVAL literal in this project.
  if (!/^[0-9]+ (seconds?|minutes?|hours?|days?|weeks?|months?)$/.test(raw)) {
    throw new Error("invalid retention window; expected '<n> <unit>'");
  }
  return raw;
}

export async function runIngestQueueRetention(env = process.env, { pgModule } = {}) {
  const credentialsRaw = env.MEM9_INGEST_RETENTION_DB_SECRET;
  if (!credentialsRaw) throw new Error("MEM9_INGEST_RETENTION_DB_SECRET is required");
  let credentials;
  try {
    credentials = JSON.parse(credentialsRaw);
  } catch {
    throw new Error("MEM9_INGEST_RETENTION_DB_SECRET must be JSON");
  }
  if (!credentials || typeof credentials.username !== "string" || typeof credentials.password !== "string") {
    throw new Error("MEM9_INGEST_RETENTION_DB_SECRET must contain username and password");
  }
  if (!env.MEM9_DB_HOST || !env.MEM9_DB_NAME) {
    throw new Error("MEM9_DB_HOST and MEM9_DB_NAME are required");
  }
  const retentionWindow = parseRetentionWindow(env.MEM9_INGEST_RETENTION_WINDOW);
  const batchSize = parsePositiveInt(env.MEM9_INGEST_RETENTION_BATCH, DEFAULT_BATCH, { max: MAX_BATCH });
  const maxBatches = parsePositiveInt(env.MEM9_INGEST_RETENTION_MAX_BATCHES, DEFAULT_MAX_BATCHES);

  const pg = pgModule || (await import("pg")).default;
  const db = new pg.Client({
    host: env.MEM9_DB_HOST,
    port: Number(env.MEM9_DB_PORT || 5432),
    database: env.MEM9_DB_NAME,
    user: credentials.username,
    password: credentials.password,
    ssl: { rejectUnauthorized: true },
    connectionTimeoutMillis: 10000,
    query_timeout: 60000,
    application_name: "mem9-ingest-queue-retention",
  });
  await db.connect();
  try {
    let totalPurged = 0;
    let batches = 0;
    for (; batches < maxBatches; batches++) {
      const result = await db.query(
        "SELECT purge_terminal_ingest_payloads($1::interval, $2::int) AS purged",
        [retentionWindow, batchSize],
      );
      const purged = Number(result.rows?.[0]?.purged || 0);
      totalPurged += purged;
      if (purged < batchSize) {
        batches++;
        break;
      }
    }
    return { retentionWindow, batchSize, batches, totalPurged };
  } finally {
    await db.end();
  }
}

async function main() {
  const result = await runIngestQueueRetention(process.env);
  process.stdout.write(JSON.stringify({ event: "ingest_queue_retention", ...result }) + "\n");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stdout.write(
      JSON.stringify({
        event: "ingest_queue_retention_failed",
        errorMessage: String(error?.message || error),
      }) + "\n",
    );
    process.exitCode = 1;
  });
}
