#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import process from "node:process";
import pg from "pg";

import { deriveLookupKey, parseOperatorArgs } from "./lib/memory-namespace.mjs";

export const SHARED_HISTORY_ACKNOWLEDGEMENT =
  "I_ACKNOWLEDGE_EXISTING_MEMORY_IS_SHARED_TEAM_HISTORY";
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const MIGRATION_PHASE_EXIT_CODES = Object.freeze({
  additive_ready: 31,
  frozen: 32,
  backfilling: 33,
  application_ready: 34,
  constraints_complete: 35,
});
const BACKFILL_LOCK = "mem9-memory-namespace-backfill-v1";
const INDEX_LOCK = "mem9-memory-namespace-indexes-v1";
const NAMESPACE_INDEXES = Object.freeze([
  {
    name: "idx_memories_namespace_state",
    table: "memories",
    unique: false,
    keys: ["namespace_id", "state", "updated_at", "id"],
    options: [0, 0, 3, 0],
    predicate: "",
    create: `CREATE INDEX CONCURRENTLY idx_memories_namespace_state
      ON memories (namespace_id, state, updated_at DESC, id)`,
  },
  {
    name: "idx_memories_namespace_agent",
    table: "memories",
    unique: false,
    keys: ["namespace_id", "agent_id", "state"],
    predicate: "",
    create: `CREATE INDEX CONCURRENTLY idx_memories_namespace_agent
      ON memories (namespace_id, agent_id, state)`,
  },
  {
    name: "idx_sessions_namespace_scope",
    table: "sessions",
    unique: false,
    keys: ["namespace_id", "app_id", "session_id", "seq", "id"],
    predicate: "state='active'",
    create: `CREATE INDEX CONCURRENTLY idx_sessions_namespace_scope
      ON sessions (namespace_id, app_id, session_id, seq, id)
      WHERE state = 'active'`,
  },
  {
    name: "idx_ingest_jobs_namespace_status",
    table: "ingest_jobs",
    unique: false,
    keys: ["tenant_id", "namespace_id", "state", "updated_at"],
    options: [0, 0, 0, 3],
    predicate: "",
    create: `CREATE INDEX CONCURRENTLY idx_ingest_jobs_namespace_status
      ON ingest_jobs (tenant_id, namespace_id, state, updated_at DESC)`,
  },
  {
    name: "idx_ingest_jobs_namespace_claim",
    table: "ingest_jobs",
    unique: false,
    keys: ["tenant_id", "namespace_id", "available_at", "created_at", "job_id"],
    predicate:
      "state=ANY(ARRAY['queued','retry_wait','processing','planning','applying'])",
    create: `CREATE INDEX CONCURRENTLY idx_ingest_jobs_namespace_claim
      ON ingest_jobs (
        tenant_id, namespace_id, available_at, created_at, job_id
      )
      WHERE state IN (
        'queued', 'retry_wait', 'processing', 'planning', 'applying'
      )`,
  },
  {
    name: "uq_ingest_jobs_namespace_idempotency",
    table: "ingest_jobs",
    unique: true,
    keys: ["tenant_id", "namespace_id", "idempotency_key"],
    predicate: "",
    create: `CREATE UNIQUE INDEX CONCURRENTLY uq_ingest_jobs_namespace_idempotency
      ON ingest_jobs (tenant_id, namespace_id, idempotency_key)`,
  },
  {
    name: "uq_ingest_jobs_namespace_job",
    table: "ingest_jobs",
    unique: true,
    keys: ["tenant_id", "namespace_id", "job_id"],
    predicate: "",
    create: `CREATE UNIQUE INDEX CONCURRENTLY uq_ingest_jobs_namespace_job
      ON ingest_jobs (tenant_id, namespace_id, job_id)`,
  },
  {
    name: "uq_ingest_job_plans_namespace_hash",
    table: "ingest_job_plans",
    unique: true,
    keys: ["tenant_id", "namespace_id", "job_id", "plan_hash"],
    predicate: "",
    create: `CREATE UNIQUE INDEX CONCURRENTLY uq_ingest_job_plans_namespace_hash
      ON ingest_job_plans (tenant_id, namespace_id, job_id, plan_hash)`,
  },
  {
    name: "uq_ingest_job_plans_namespace_revision",
    aliases: ["ingest_job_plans_pkey"],
    table: "ingest_job_plans",
    unique: true,
    keys: ["tenant_id", "namespace_id", "job_id", "plan_revision"],
    predicate: "",
    create: `CREATE UNIQUE INDEX CONCURRENTLY uq_ingest_job_plans_namespace_revision
      ON ingest_job_plans (tenant_id, namespace_id, job_id, plan_revision)`,
  },
  {
    name: "uq_sessions_namespace_message",
    table: "sessions",
    unique: true,
    keys: ["namespace_id", "app_id", "session_id", "content_hash"],
    predicate: "",
    create: `CREATE UNIQUE INDEX CONCURRENTLY uq_sessions_namespace_message
      ON sessions (namespace_id, app_id, session_id, content_hash)`,
  },
  {
    name: "idx_upload_tasks_namespace_poll",
    table: "upload_tasks",
    unique: false,
    keys: ["namespace_id", "status", "created_at"],
    predicate: "",
    create: `CREATE INDEX CONCURRENTLY idx_upload_tasks_namespace_poll
      ON upload_tasks (namespace_id, status, created_at)`,
  },
]);
const USAGE = `usage:
  node scripts/migrate-memory-namespaces.mjs <command> [options]

commands:
  assert-phase --expected-phase <phase>
  preflight
  freeze
  backfill --stage <stage> --namespace <slug> --display-name <name>
  enforce

required environment:
  MNEMO_DSN
`;

function requireUUID(name, value) {
  if (!UUID_RE.test(value ?? "")) {
    throw new Error(`${name} must be a UUID`);
  }
  return value;
}

async function readEmbeddingDigest(db) {
  await db.query(`
    CREATE OR REPLACE FUNCTION pg_temp.mem9_embedding_digest_step(
      state BYTEA,
      memory_id TEXT,
      embedding_text TEXT
    ) RETURNS BYTEA
    LANGUAGE SQL
    IMMUTABLE
    PARALLEL SAFE
    AS $$
      SELECT sha256(
        COALESCE(state, decode('', 'hex'))
        || convert_to(memory_id, 'UTF8')
        || decode('00', 'hex')
        || convert_to(COALESCE(embedding_text, '<null>'), 'UTF8')
        || decode('0a', 'hex')
      )
    $$;
    DROP AGGREGATE IF EXISTS pg_temp.mem9_embedding_digest(TEXT, TEXT);
    CREATE AGGREGATE pg_temp.mem9_embedding_digest(TEXT, TEXT) (
      SFUNC = pg_temp.mem9_embedding_digest_step,
      STYPE = BYTEA
    )
  `);
  const result = await db.query(`
    SELECT
      COALESCE(
        encode(
          pg_temp.mem9_embedding_digest(
            id,
            embedding::text
            ORDER BY id
          ),
          'hex'
        ),
        encode(sha256(decode('', 'hex')), 'hex')
      ) AS digest,
      COUNT(*)::int AS row_count,
      COUNT(*) FILTER (WHERE embedding IS NULL)::int AS null_count,
      COUNT(*) FILTER (
        WHERE embedding IS NOT NULL
          AND embedding = array_fill(
            0::real,
            ARRAY[vector_dims(embedding)]
          )::vector
      )::int AS zero_vector_count
    FROM memories
  `);
  return result.rows[0];
}

async function withSessionAdvisoryLock(db, name, callback) {
  const lock = await db.query(
    `SELECT pg_try_advisory_lock(hashtext($1)) AS acquired`,
    [name],
  );
  if (lock.rows[0]?.acquired !== true) {
    throw new Error(`another namespace operator holds ${name}`);
  }
  try {
    return await callback();
  } finally {
    await db.query(`SELECT pg_advisory_unlock(hashtext($1))`, [name]);
  }
}

async function readIndexDefinitions(db, spec) {
  const names = [spec.name, ...(spec.aliases ?? [])];
  const result = await db.query(
    `SELECT
       index_class.relname AS index_name,
       index_state.indisvalid,
       index_state.indisready,
       index_state.indisunique,
       table_class.relname AS table_name,
       ARRAY(
         SELECT pg_get_indexdef(
           index_state.indexrelid,
           key_position,
           TRUE
         )
         FROM generate_series(
           1,
           index_state.indnkeyatts
         ) AS key_position
         ORDER BY key_position
       ) AS key_expressions,
       string_to_array(
         index_state.indoption::text,
         ' '
       )::int[] AS index_options,
       COALESCE(
         pg_get_expr(
           index_state.indpred,
           index_state.indrelid,
           TRUE
         ),
         ''
       ) AS predicate
     FROM pg_index AS index_state
     JOIN pg_class AS index_class
       ON index_class.oid = index_state.indexrelid
     JOIN pg_class AS table_class
       ON table_class.oid = index_state.indrelid
     WHERE index_class.relname = ANY($1::text[])`,
    [names],
  );
  return result.rows;
}

function normalizeIndexPredicate(predicate) {
  let normalized = String(predicate)
    .replace(/::(?:text|character varying)(?:\[\])?/gu, "")
    .replace(/\s+/gu, "");
  if (normalized.startsWith("(") && normalized.endsWith(")")) {
    normalized = normalized.slice(1, -1);
  }
  return normalized;
}

function indexDefinitionMatches(spec, actual) {
  if (
    actual.indisvalid !== true ||
    actual.indisready !== true ||
    actual.indisunique !== spec.unique ||
    actual.table_name !== spec.table ||
    JSON.stringify(actual.key_expressions) !== JSON.stringify(spec.keys) ||
    JSON.stringify(actual.index_options) !==
      JSON.stringify(spec.options ?? spec.keys.map(() => 0))
  ) {
    return false;
  }
  if (normalizeIndexPredicate(actual.predicate) !== spec.predicate) {
    return false;
  }
  return true;
}

function assertIndexDefinition(spec, actual) {
  if (!indexDefinitionMatches(spec, actual)) {
    throw new Error(`namespace index ${spec.name} definition mismatch`);
  }
}

async function readIndexDefinition(db, spec) {
  const candidates = await readIndexDefinitions(db, spec);
  const canonical = candidates.find(
    (candidate) => candidate.index_name === spec.name,
  );
  if (canonical) return canonical;
  const matchingAliases = candidates.filter((candidate) =>
    indexDefinitionMatches(spec, candidate),
  );
  if (matchingAliases.length > 1) {
    throw new Error(`namespace index ${spec.name} is ambiguous`);
  }
  return matchingAliases[0] ?? null;
}

export async function ensureNamespaceIndexes(db) {
  return withSessionAdvisoryLock(db, INDEX_LOCK, async () => {
    await db.query(`SET lock_timeout = '5s'`);
    await db.query(`SET statement_timeout = '25min'`);
    try {
      for (const spec of NAMESPACE_INDEXES) {
        let actual = await readIndexDefinition(db, spec);
        if (actual && (!actual.indisvalid || !actual.indisready)) {
          if (actual.index_name !== spec.name) {
            throw new Error(
              `attached namespace index ${actual.index_name} is invalid`,
            );
          }
          await db.query(`DROP INDEX CONCURRENTLY IF EXISTS ${spec.name}`);
          actual = null;
        }
        if (actual) {
          assertIndexDefinition(spec, actual);
          continue;
        }
        await db.query(spec.create);
        actual = await readIndexDefinition(db, spec);
        if (!actual) {
          throw new Error(`namespace index ${spec.name} was not created`);
        }
        assertIndexDefinition(spec, actual);
      }
      await db.query(
        `UPDATE memory_namespace_migration_state
         SET checkpoint = 'namespace_indexes_ready',
             updated_at = statement_timestamp()
         WHERE singleton_id
           AND phase IN ('frozen', 'backfilling')`,
      );
    } finally {
      await db.query(`RESET statement_timeout`);
      await db.query(`RESET lock_timeout`);
    }
    return { index_count: NAMESPACE_INDEXES.length };
  });
}

async function updateBatches(db, statement, values, batchSize) {
  let updated = 0;
  for (;;) {
    const result = await db.query(statement, [...values, batchSize]);
    updated += result.rowCount;
    if (result.rowCount === 0) return updated;
  }
}

async function migrationPhase(db, lock = false) {
  const result = await db.query(
    `SELECT
       phase,
       checkpoint,
       legacy_namespace_id,
       legacy_principal_id,
       legacy_namespace_slug,
       legacy_namespace_display_name,
       legacy_principal_key
     FROM memory_namespace_migration_state
     WHERE singleton_id
     ${lock ? "FOR UPDATE" : ""}`,
  );
  if (result.rowCount !== 1) {
    throw new Error("namespace migration state is missing");
  }
  return result.rows[0];
}

function assertLegacyBinding(observed, expected) {
  const fields = [
    ["legacy_namespace_id", expected.namespaceID],
    ["legacy_principal_id", expected.principalID],
    ["legacy_namespace_slug", expected.namespaceSlug],
    ["legacy_namespace_display_name", expected.namespaceDisplayName],
    ["legacy_principal_key", expected.principalKey],
  ];
  const present = fields.map(([field]) => observed[field] != null);
  if (present.some(Boolean) && !present.every(Boolean)) {
    throw new Error("legacy namespace migration binding is incomplete");
  }
  if (
    present.every(Boolean) &&
    fields.some(([field, value]) => observed[field] !== value)
  ) {
    throw new Error(
      "legacy namespace migration is already bound to another seed",
    );
  }
}

export async function assertMigrationPhase(db, expectedPhase) {
  if (!Object.hasOwn(MIGRATION_PHASE_EXIT_CODES, expectedPhase)) {
    throw new Error("expected namespace migration phase is invalid");
  }
  const observed = await migrationPhase(db);
  if (observed.phase !== expectedPhase) {
    const error = new Error(
      `namespace migration phase is ${observed.phase}; required ${expectedPhase}`,
    );
    error.exitCode = MIGRATION_PHASE_EXIT_CODES[observed.phase] ?? 39;
    throw error;
  }
  return { phase: observed.phase };
}

export async function namespaceMigrationPreflight(db) {
  const phase = await migrationPhase(db);
  const result = await db.query(`
    SELECT
      (SELECT COUNT(*)::int FROM ingest_jobs
       WHERE state NOT IN ('succeeded', 'dead')) AS nonterminal_jobs,
      (SELECT COUNT(*)::int FROM upload_tasks
       WHERE status IN ('pending', 'processing')) AS active_uploads,
      (SELECT COUNT(*)::int FROM memories WHERE namespace_id IS NULL)
        AS unassigned_memories,
      (SELECT COUNT(*)::int FROM sessions WHERE namespace_id IS NULL)
        AS unassigned_sessions
  `);
  return { phase: phase.phase, ...result.rows[0] };
}

export async function freezeNamespaceWriters(db) {
  await db.query("BEGIN");
  try {
    await db.query(
      `SELECT pg_advisory_xact_lock(
         hashtext('mem9-memory-namespace-backfill-v1')
       )`,
    );
    const observed = await migrationPhase(db, true);
    if (!["additive_ready", "frozen"].includes(observed.phase)) {
      throw new Error(`cannot freeze from phase ${observed.phase}`);
    }
    await db.query(`SET LOCAL lock_timeout = '5s'`);
    await db.query(
      `LOCK TABLE
         memories,
         sessions,
         ingest_jobs,
         ingest_job_plans,
         upload_tasks
       IN SHARE MODE`,
    );
    const drain = await db.query(`
      SELECT
        (SELECT COUNT(*)::int FROM ingest_jobs
         WHERE state NOT IN ('succeeded', 'dead')) AS nonterminal_jobs,
        (SELECT COUNT(*)::int FROM upload_tasks
         WHERE status IN ('pending', 'processing')) AS active_uploads
    `);
    if (
      Number(drain.rows[0].nonterminal_jobs) !== 0 ||
      Number(drain.rows[0].active_uploads) !== 0
    ) {
      throw new Error("writers or asynchronous work are not drained");
    }
    await db.query(
      `UPDATE memory_namespace_migration_state
       SET phase = 'frozen',
           checkpoint = 'writer_fence_enabled',
           updated_at = statement_timestamp()
       WHERE singleton_id`,
    );
    await db.query("COMMIT");
  } catch (error) {
    await db.query("ROLLBACK");
    throw error;
  }
  return namespaceMigrationPreflight(db);
}

export async function backfillNamespaces({
  db,
  stage,
  namespaceID,
  namespaceSlug,
  namespaceDisplayName,
  principalID,
  acknowledgement,
  batchSize = 1000,
}) {
  if (acknowledgement !== SHARED_HISTORY_ACKNOWLEDGEMENT) {
    throw new Error("shared-history acknowledgement is required");
  }
  requireUUID("MEM9_LEGACY_NAMESPACE_ID", namespaceID);
  requireUUID("MEM9_LEGACY_SERVICE_PRINCIPAL_ID", principalID);
  if (!stage || !namespaceSlug || !namespaceDisplayName) {
    throw new Error("stage and legacy namespace metadata are required");
  }
  const principalKey = deriveLookupKey(
    "mem9-service-principal-v1",
    stage,
    "legacy-unattributed-service",
  );

  return withSessionAdvisoryLock(db, BACKFILL_LOCK, async () => {
    return backfillNamespacesLocked({
      db,
      namespaceID,
      namespaceSlug,
      namespaceDisplayName,
      principalID,
      principalKey,
      batchSize,
    });
  });
}

async function backfillNamespacesLocked({
  db,
  namespaceID,
  namespaceSlug,
  namespaceDisplayName,
  principalID,
  principalKey,
  batchSize,
}) {
  const preflight = await namespaceMigrationPreflight(db);
  if (preflight.nonterminal_jobs !== 0 || preflight.active_uploads !== 0) {
    throw new Error("writers or asynchronous work are not drained");
  }
  if (
    !["frozen", "backfilling", "application_ready"].includes(preflight.phase)
  ) {
    throw new Error(`cannot backfill from phase ${preflight.phase}`);
  }

  const boundState = await migrationPhase(db);
  assertLegacyBinding(boundState, {
    namespaceID,
    principalID,
    namespaceSlug,
    namespaceDisplayName,
    principalKey,
  });
  await ensureNamespaceIndexes(db);
  const before = await readEmbeddingDigest(db);

  await db.query("BEGIN");
  try {
    const observed = await migrationPhase(db, true);
    if (
      !["frozen", "backfilling", "application_ready"].includes(observed.phase)
    ) {
      throw new Error(`cannot backfill from phase ${observed.phase}`);
    }
    assertLegacyBinding(observed, {
      namespaceID,
      principalID,
      namespaceSlug,
      namespaceDisplayName,
      principalKey,
    });
    const namespace = await db.query(
      `INSERT INTO memory_namespaces (
         namespace_id, slug, display_name, status
       ) VALUES ($1, $2, $3, 'active')
       ON CONFLICT (slug) DO UPDATE
       SET display_name = EXCLUDED.display_name,
           status = 'active',
           updated_at = statement_timestamp()
       RETURNING namespace_id`,
      [namespaceID, namespaceSlug, namespaceDisplayName],
    );
    if (namespace.rows[0].namespace_id !== namespaceID) {
      throw new Error("legacy namespace seed ID mismatch");
    }
    const principal = await db.query(
      `INSERT INTO memory_principals (
         principal_id, principal_key, principal_type, status, last_seen_at
       ) VALUES ($1, $2, 'service', 'active', statement_timestamp())
       ON CONFLICT (principal_key) DO UPDATE
       SET status = 'active',
           last_seen_at = statement_timestamp()
       WHERE memory_principals.principal_type = 'service'
       RETURNING principal_id`,
      [principalID, principalKey],
    );
    if (
      principal.rowCount !== 1 ||
      principal.rows[0].principal_id !== principalID
    ) {
      throw new Error("legacy service principal seed ID mismatch");
    }
    await db.query(
      `INSERT INTO memory_namespace_memberships (
         namespace_id, principal_id, role, status, source_type,
         source_key, revoked_at
       ) VALUES ($1, $2, 'owner', 'active', 'service', NULL, NULL)
       ON CONFLICT (namespace_id, principal_id) DO UPDATE
       SET role = 'owner',
           status = 'active',
           source_type = 'service',
           source_key = NULL,
           revoked_at = NULL`,
      [namespaceID, principalID],
    );
    await db.query(
      `UPDATE memory_namespace_migration_state
       SET phase = 'backfilling',
           checkpoint = 'seed_verified',
           legacy_namespace_id = $1,
           legacy_principal_id = $2,
           legacy_namespace_slug = $3,
           legacy_namespace_display_name = $4,
           legacy_principal_key = $5,
           updated_at = statement_timestamp()
       WHERE singleton_id`,
      [
        namespaceID,
        principalID,
        namespaceSlug,
        namespaceDisplayName,
        principalKey,
      ],
    );
    await db.query("COMMIT");
  } catch (error) {
    await db.query("ROLLBACK");
    throw error;
  }

  const counts = {};
  await db.query(
    `SELECT set_config(
       'mem9.namespace_migration_actor',
       'backfill',
       FALSE
     )`,
  );
  try {
    counts.memories = await updateBatches(
      db,
      `WITH batch AS (
         SELECT ctid FROM memories WHERE namespace_id IS NULL LIMIT $2
       )
       UPDATE memories AS target
       SET namespace_id = $1
       FROM batch
       WHERE target.ctid = batch.ctid
       RETURNING target.id`,
      [namespaceID],
      batchSize,
    );
    counts.sessions = await updateBatches(
      db,
      `WITH batch AS (
         SELECT ctid FROM sessions
         WHERE namespace_id IS NULL OR principal_id IS NULL
         LIMIT $3
       )
       UPDATE sessions AS target
       SET namespace_id = COALESCE(target.namespace_id, $1),
           principal_id = COALESCE(target.principal_id, $2)
       FROM batch
       WHERE target.ctid = batch.ctid
       RETURNING target.id`,
      [namespaceID, principalID],
      batchSize,
    );
    counts.jobs = await updateBatches(
      db,
      `WITH batch AS (
         SELECT ctid FROM ingest_jobs
         WHERE namespace_id IS NULL OR principal_id IS NULL
         LIMIT $3
       )
       UPDATE ingest_jobs AS target
       SET namespace_id = COALESCE(target.namespace_id, $1),
           principal_id = COALESCE(target.principal_id, $2)
       FROM batch
       WHERE target.ctid = batch.ctid
       RETURNING target.job_id`,
      [namespaceID, principalID],
      batchSize,
    );
    counts.plans = await updateBatches(
      db,
      `WITH batch AS (
         SELECT plan.ctid, job.namespace_id, job.principal_id
         FROM ingest_job_plans AS plan
         JOIN ingest_jobs AS job
           ON job.tenant_id = plan.tenant_id
          AND job.job_id = plan.job_id
         WHERE plan.namespace_id IS NULL OR plan.principal_id IS NULL
         LIMIT $1
       )
       UPDATE ingest_job_plans AS target
       SET namespace_id = batch.namespace_id,
           principal_id = batch.principal_id
       FROM batch
       WHERE target.ctid = batch.ctid
       RETURNING target.job_id`,
      [],
      batchSize,
    );
    counts.uploads = await updateBatches(
      db,
      `WITH batch AS (
         SELECT ctid FROM upload_tasks WHERE namespace_id IS NULL LIMIT $2
       )
       UPDATE upload_tasks AS target
       SET namespace_id = $1
       FROM batch
       WHERE target.ctid = batch.ctid
       RETURNING target.task_id`,
      [namespaceID],
      batchSize,
    );
  } finally {
    await db.query(
      `SELECT set_config('mem9.namespace_migration_actor', '', FALSE)`,
    );
  }

  const after = await readEmbeddingDigest(db);
  if (JSON.stringify(before) !== JSON.stringify(after)) {
    throw new Error("embedding preservation verification failed");
  }

  const verification = await db.query(`
    SELECT
      (SELECT COUNT(*) FROM memories WHERE namespace_id IS NULL)
      + (SELECT COUNT(*) FROM sessions
         WHERE namespace_id IS NULL OR principal_id IS NULL)
      + (SELECT COUNT(*) FROM ingest_jobs
         WHERE namespace_id IS NULL OR principal_id IS NULL)
      + (SELECT COUNT(*) FROM ingest_job_plans
         WHERE namespace_id IS NULL OR principal_id IS NULL)
      + (SELECT COUNT(*) FROM upload_tasks WHERE namespace_id IS NULL)
      AS unassigned
  `);
  if (Number(verification.rows[0].unassigned) !== 0) {
    throw new Error("namespace backfill verification found unassigned rows");
  }
  await db.query(
    `UPDATE memory_namespace_migration_state
     SET phase = 'application_ready',
         checkpoint = 'embedding_digest_verified',
         updated_at = statement_timestamp()
     WHERE singleton_id`,
  );
  return { counts, embedding: after, phase: "application_ready" };
}

export async function enforceNamespaces(db, migrationPath) {
  return withSessionAdvisoryLock(db, BACKFILL_LOCK, async () => {
    const phase = await migrationPhase(db);
    if (!["application_ready", "constraints_complete"].includes(phase.phase)) {
      throw new Error(`cannot enforce from phase ${phase.phase}`);
    }
    await ensureNamespaceIndexes(db);
    await db.query(await readFile(migrationPath, "utf8"));
    return { phase: "constraints_complete" };
  });
}

async function main() {
  const args = parseOperatorArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(USAGE);
    return;
  }
  const dsn = process.env.MNEMO_DSN;
  if (!dsn) throw new Error("MNEMO_DSN is required");
  const db = new pg.Client({ connectionString: dsn });
  await db.connect();
  try {
    let result;
    switch (args.command) {
      case "assert-phase":
        result = await assertMigrationPhase(db, args.expected_phase);
        break;
      case "preflight":
        result = await namespaceMigrationPreflight(db);
        break;
      case "freeze":
        result = await freezeNamespaceWriters(db);
        break;
      case "backfill":
        result = await backfillNamespaces({
          db,
          stage: args.stage ?? process.env.MEM9_STAGE,
          namespaceID: process.env.MEM9_LEGACY_NAMESPACE_ID,
          namespaceSlug:
            args.namespace ?? process.env.MEM9_LEGACY_NAMESPACE_SLUG,
          namespaceDisplayName:
            args.display_name ?? process.env.MEM9_LEGACY_NAMESPACE_DISPLAY_NAME,
          principalID: process.env.MEM9_LEGACY_SERVICE_PRINCIPAL_ID,
          acknowledgement:
            args.acknowledge_shared_history ??
            process.env.MEM9_SHARED_HISTORY_ACKNOWLEDGEMENT,
          batchSize: Number(args.batch_size ?? 1000),
        });
        break;
      case "enforce":
        result = await enforceNamespaces(
          db,
          new URL(
            "../docker/bootstrap/migrations/003_enforce_memory_namespaces.sql",
            import.meta.url,
          ),
        );
        break;
      default:
        throw new Error(
          "supported commands: assert-phase, preflight, freeze, backfill, enforce",
        );
    }
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } finally {
    await db.end();
  }
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  main().catch((error) => {
    process.stderr.write(`namespace migration failed: ${error.message}\n`);
    process.exitCode = Number.isInteger(error.exitCode) ? error.exitCode : 1;
  });
}
