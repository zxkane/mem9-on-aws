#!/usr/bin/env bash

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONTAINER="mem9-namespace-migration-${RANDOM}-${BASHPID}"
DATABASE="mem9_namespace_migration"
NAMESPACE_ID="60000000-0000-4000-8000-000000000101"
PRINCIPAL_ID="70000000-0000-4000-8000-000000000101"
OTHER_NAMESPACE_ID="60000000-0000-4000-8000-000000000102"
OTHER_PRINCIPAL_ID="70000000-0000-4000-8000-000000000102"
ACKNOWLEDGEMENT="I_ACKNOWLEDGE_EXISTING_MEMORY_IS_SHARED_TEAM_HISTORY"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d \
  --name "$CONTAINER" \
  -e POSTGRES_PASSWORD=test \
  -e POSTGRES_DB="$DATABASE" \
  -p 127.0.0.1::5432 \
  pgvector/pgvector:pg17 >/dev/null

for attempt in $(seq 1 60); do
  if docker exec "$CONTAINER" sh -c \
      'test "$(cat /proc/1/comm)" = "postgres"' >/dev/null 2>&1 &&
    docker exec "$CONTAINER" \
      psql -qAt -v ON_ERROR_STOP=1 -U postgres -d "$DATABASE" \
      -c "SELECT 1" 2>/dev/null |
      grep -qx "1"; then
    break
  fi
  if [[ "$attempt" == "60" ]]; then
    echo "PostgreSQL did not become ready" >&2
    docker logs "$CONTAINER" >&2 || true
    exit 1
  fi
  sleep 1
done

docker cp "$ROOT/docker/bootstrap/." "$CONTAINER:/bootstrap"
docker exec "$CONTAINER" mkdir -p /usr/local/share/mem9
docker cp \
  "$ROOT/docker/bootstrap/schema.sql" \
  "$CONTAINER:/usr/local/share/mem9/schema.sql"
docker cp \
  "$ROOT/docker/bootstrap/migrations" \
  "$CONTAINER:/usr/local/share/mem9/"
docker cp \
  "$ROOT/docker/mnemo-server/entrypoint.sh" \
  "$CONTAINER:/usr/local/bin/mem9-entrypoint.sh"
docker exec "$CONTAINER" sh -c "
  printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/mnemo-server
  chmod +x /usr/local/bin/mnemo-server /usr/local/bin/mem9-entrypoint.sh
"

psql_file() {
  docker exec "$CONTAINER" \
    psql -q -v ON_ERROR_STOP=1 -U postgres -d "$DATABASE" -f "$1"
}

psql_sql() {
  docker exec "$CONTAINER" \
    psql -q -v ON_ERROR_STOP=1 -U postgres -d "$DATABASE" -c "$1"
}

psql_value() {
  docker exec "$CONTAINER" \
    psql -qAt -v ON_ERROR_STOP=1 -U postgres -d "$DATABASE" -c "$1"
}

# Exercise the real ECS ordering on an empty database: mnemo-server starts
# before the later one-shot tenant bootstrap, so its entrypoint must create the
# base schema before applying namespace migration 002.
docker exec \
  -e "MNEMO_DSN=postgres://postgres:test@127.0.0.1:5432/${DATABASE}?sslmode=disable" \
  -e MNEMO_MIGRATION_MAX_ATTEMPTS=1 \
  "$CONTAINER" \
  /usr/local/bin/mem9-entrypoint.sh

# The same complete schema reruns on later starts and remains idempotent.
psql_file /usr/local/share/mem9/schema.sql

psql_value "SELECT to_regclass('idx_memories_namespace_state') IS NULL" |
  grep -qx "t"

# A later migration phase cannot be dispatched early. PostgreSQL rolls the
# failed transaction back and leaves the additive checkpoint intact.
if psql_file /bootstrap/migrations/003_enforce_memory_namespaces.sql \
  >/dev/null 2>&1; then
  echo "namespace enforcement unexpectedly bypassed the phase gate" >&2
  exit 1
fi
psql_value \
  "SELECT phase FROM memory_namespace_migration_state WHERE singleton_id" |
  grep -qx "additive_ready"

PORT=$(docker port "$CONTAINER" 5432/tcp | head -n 1 | awk -F: '{print $NF}')
export MNEMO_DSN="postgres://postgres:test@127.0.0.1:${PORT}/${DATABASE}?sslmode=disable"

set +e
PHASE_ERROR=$(
  node "$ROOT/scripts/migrate-memory-namespaces.mjs" assert-phase \
    --expected-phase constraints_complete 2>&1
)
PHASE_STATUS=$?
set -e
[[ "$PHASE_STATUS" == "31" ]] || {
  echo "additive phase mismatch exited ${PHASE_STATUS}, expected 31" >&2
  exit 1
}
printf '%s' "$PHASE_ERROR" |
  grep -q "phase is additive_ready; required constraints_complete"

psql_sql "
  INSERT INTO memories (
    id, content, embedding, memory_type, app_id, state, version
  ) VALUES
    (
      '81000000-0000-4000-8000-000000000001',
      'legacy nonzero vector',
      (ARRAY[1::real] || array_fill(0::real, ARRAY[1023]))::vector,
      'pinned', 'legacy-app', 'active', 1
    ),
    (
      '81000000-0000-4000-8000-000000000002',
      'legacy zero vector',
      array_fill(0::real, ARRAY[1024])::vector,
      'pinned', 'legacy-app', 'active', 1
    ),
    (
      '81000000-0000-4000-8000-000000000003',
      'legacy null vector',
      NULL,
      'pinned', 'legacy-app', 'active', 1
    );

  INSERT INTO sessions (
    id, session_id, app_id, role, content, content_hash, state
  ) VALUES (
    '82000000-0000-4000-8000-000000000001',
    'legacy-session',
    'legacy-app',
    'user',
    'legacy message',
    repeat('a', 64),
    'active'
  );

  INSERT INTO ingest_jobs (
    job_id, tenant_id, idempotency_key, canonical_payload, state, completed_at
  ) VALUES (
    '83000000-0000-4000-8000-000000000001',
    'legacy-tenant',
    repeat('b', 64),
    convert_to('{}', 'UTF8'),
    'succeeded',
    statement_timestamp()
  );

  INSERT INTO ingest_job_plans (
    tenant_id, job_id, plan_revision, attempt_generation, plan_hash,
    plan_payload, state
  ) VALUES (
    'legacy-tenant',
    '83000000-0000-4000-8000-000000000001',
    1,
    1,
    repeat('c', 64),
    convert_to('{}', 'UTF8'),
    'applied'
  );

  INSERT INTO upload_tasks (
    task_id, tenant_id, file_name, file_path, file_type, status
  ) VALUES (
    '84000000-0000-4000-8000-000000000001',
    'legacy-tenant',
    'legacy.txt',
    '/tmp/legacy.txt',
    'text',
    'done'
  );
"

BEFORE_EMBEDDINGS=$(psql_value "
  SELECT md5(string_agg(
    id || ':' || COALESCE(embedding::text, '<null>'),
    E'\n' ORDER BY id
  ))
  FROM memories
")

node "$ROOT/scripts/migrate-memory-namespaces.mjs" freeze |
  grep -q '"phase":"frozen"'

if psql_sql "
  INSERT INTO memories (id, content)
  VALUES ('85000000-0000-4000-8000-000000000001', 'must be frozen')
" >/dev/null 2>&1; then
  echo "database writer fence did not reject a frozen-phase write" >&2
  exit 1
fi

# A valid index with the expected name but the opposite predicate is not a
# resumable checkpoint. Catalog validation must reject it before any backfill
# seed or row mutation occurs.
psql_sql "
  CREATE INDEX idx_sessions_namespace_scope
  ON sessions (namespace_id, app_id, session_id, seq, id)
  WHERE state <> 'active'
"
set +e
PREDICATE_ERROR=$(
  MEM9_LEGACY_NAMESPACE_ID="$NAMESPACE_ID" \
  MEM9_LEGACY_SERVICE_PRINCIPAL_ID="$PRINCIPAL_ID" \
  MEM9_SHARED_HISTORY_ACKNOWLEDGEMENT="$ACKNOWLEDGEMENT" \
    node "$ROOT/scripts/migrate-memory-namespaces.mjs" backfill \
      --stage ci \
      --namespace legacy-team \
      --display-name "Legacy Team" 2>&1
)
PREDICATE_STATUS=$?
set -e
[[ "$PREDICATE_STATUS" -ne 0 ]] || {
  echo "opposite namespace index predicate was accepted" >&2
  exit 1
}
printf '%s' "$PREDICATE_ERROR" |
  grep -q "idx_sessions_namespace_scope definition mismatch"
psql_value "
  SELECT phase FROM memory_namespace_migration_state WHERE singleton_id
" | grep -qx "frozen"
psql_value "SELECT COUNT(*) FROM memory_namespaces" | grep -qx "0"
psql_sql "DROP INDEX idx_sessions_namespace_scope"

BACKFILL_RESULT=$(
  MEM9_LEGACY_NAMESPACE_ID="$NAMESPACE_ID" \
  MEM9_LEGACY_SERVICE_PRINCIPAL_ID="$PRINCIPAL_ID" \
  MEM9_SHARED_HISTORY_ACKNOWLEDGEMENT="$ACKNOWLEDGEMENT" \
    node "$ROOT/scripts/migrate-memory-namespaces.mjs" backfill \
      --stage ci \
      --namespace legacy-team \
      --display-name "Legacy Team"
)
printf '%s' "$BACKFILL_RESULT" |
  jq -e '
    .phase == "application_ready"
    and .counts.memories == 3
    and .counts.sessions == 1
    and .counts.jobs == 1
    and .counts.plans == 1
    and .counts.uploads == 1
    and .embedding.row_count == 3
    and .embedding.null_count == 1
    and .embedding.zero_vector_count == 1
  ' >/dev/null

# A retry after application_ready is bound to the original legacy seed. It
# cannot create a second namespace/principal or silently claim success with
# different IDs or metadata.
set +e
REBIND_ERROR=$(
  MEM9_LEGACY_NAMESPACE_ID="$OTHER_NAMESPACE_ID" \
  MEM9_LEGACY_SERVICE_PRINCIPAL_ID="$OTHER_PRINCIPAL_ID" \
  MEM9_SHARED_HISTORY_ACKNOWLEDGEMENT="$ACKNOWLEDGEMENT" \
    node "$ROOT/scripts/migrate-memory-namespaces.mjs" backfill \
      --stage ci \
      --namespace replacement-team \
      --display-name "Replacement Team" 2>&1
)
REBIND_STATUS=$?
set -e
[[ "$REBIND_STATUS" -ne 0 ]] || {
  echo "legacy identity rebind unexpectedly succeeded" >&2
  exit 1
}
printf '%s' "$REBIND_ERROR" |
  grep -q "already bound to another seed"
psql_value "
  SELECT COUNT(*)
  FROM memory_namespaces
  WHERE namespace_id = '${OTHER_NAMESPACE_ID}'
     OR slug = 'replacement-team'
" | grep -qx "0"
psql_value "
  SELECT
    legacy_namespace_id || ':' ||
    legacy_principal_id || ':' ||
    legacy_namespace_slug
  FROM memory_namespace_migration_state
  WHERE singleton_id
" | grep -qx "${NAMESPACE_ID}:${PRINCIPAL_ID}:legacy-team"

psql_value "
  SELECT COUNT(*)
  FROM pg_index AS index_state
  JOIN pg_class AS index_class
    ON index_class.oid = index_state.indexrelid
  WHERE index_class.relname IN (
    'idx_memories_namespace_state',
    'idx_memories_namespace_agent',
    'idx_sessions_namespace_scope',
    'idx_ingest_jobs_namespace_status',
    'idx_ingest_jobs_namespace_claim',
    'uq_ingest_jobs_namespace_idempotency',
    'uq_ingest_jobs_namespace_job',
    'uq_ingest_job_plans_namespace_hash',
    'uq_ingest_job_plans_namespace_revision',
    'uq_sessions_namespace_message',
    'idx_upload_tasks_namespace_poll'
  )
    AND index_state.indisvalid
    AND index_state.indisready
" | grep -qx "11"

# TC-GROUPNS-070/124: fail enforcement after the verified index/backfill
# checkpoints by holding the plan table lock past the migration lock budget.
# The bounded transaction must roll back, retain the last checkpoint, and leave
# the concurrently prepared primary-key index ready for an idempotent rerun.
docker exec "$CONTAINER" \
  psql -q -v ON_ERROR_STOP=1 -U postgres -d "$DATABASE" -c "
    BEGIN;
    LOCK TABLE ingest_job_plans IN ACCESS EXCLUSIVE MODE;
    SELECT pg_sleep(12);
    COMMIT;
  " >/dev/null &
LOCK_HOLDER_PID=$!
LOCK_READY=false
for _ in $(seq 1 50); do
  if psql_value "
    SELECT EXISTS (
      SELECT 1
      FROM pg_locks
      WHERE relation = 'ingest_job_plans'::regclass
        AND mode = 'AccessExclusiveLock'
        AND granted
    )
  " | grep -qx "t"; then
    LOCK_READY=true
    break
  fi
  sleep 0.1
done
if [[ "$LOCK_READY" != "true" ]]; then
  echo "failed to acquire enforcement fault-injection lock" >&2
  wait "$LOCK_HOLDER_PID" || true
  exit 1
fi

set +e
LOCK_TIMEOUT_ERROR=$(
  node "$ROOT/scripts/migrate-memory-namespaces.mjs" enforce 2>&1
)
LOCK_TIMEOUT_STATUS=$?
set -e
[[ "$LOCK_TIMEOUT_STATUS" -ne 0 ]] || {
  echo "namespace enforcement ignored the lock timeout" >&2
  wait "$LOCK_HOLDER_PID" || true
  exit 1
}
printf '%s' "$LOCK_TIMEOUT_ERROR" |
  grep -q "canceling statement due to lock timeout"
wait "$LOCK_HOLDER_PID"

psql_value "
  SELECT phase || ':' || checkpoint
  FROM memory_namespace_migration_state
  WHERE singleton_id
" | grep -qx "application_ready:embedding_digest_verified"
psql_value "
  SELECT to_regclass(
    'uq_ingest_job_plans_namespace_revision'
  ) IS NOT NULL
" | grep -qx "t"
psql_value "
  SELECT pg_get_constraintdef(oid)
  FROM pg_constraint
  WHERE conrelid = 'ingest_job_plans'::regclass
    AND contype = 'p'
" | grep -qx "PRIMARY KEY (tenant_id, job_id, plan_revision)"

psql_sql "
  INSERT INTO memories (
    id, content, namespace_id, created_by_principal_id
  ) VALUES (
    '85000000-0000-4000-8000-000000000002',
    'namespaced write after backfill',
    '${NAMESPACE_ID}',
    '${PRINCIPAL_ID}'
  )
"

node "$ROOT/scripts/migrate-memory-namespaces.mjs" enforce |
  grep -q '"phase":"constraints_complete"'
node "$ROOT/scripts/migrate-memory-namespaces.mjs" enforce |
  grep -q '"phase":"constraints_complete"'
node "$ROOT/scripts/migrate-memory-namespaces.mjs" assert-phase \
  --expected-phase constraints_complete |
  grep -q '"phase":"constraints_complete"'
psql_value "
  SELECT pg_get_constraintdef(oid)
  FROM pg_constraint
  WHERE conrelid = 'ingest_job_plans'::regclass
    AND contype = 'p'
" | grep -qx \
  "PRIMARY KEY (tenant_id, namespace_id, job_id, plan_revision)"
psql_value "
  SELECT to_regclass(
    'uq_ingest_job_plans_namespace_revision'
  ) IS NULL
" | grep -qx "t"
psql_value "
  SELECT COUNT(*)
  FROM pg_constraint
  WHERE conrelid = 'ingest_job_plans'::regclass
    AND contype = 'p'
" | grep -qx "1"

# The normal deploy runs the complete bootstrap on every rollout. After cutover,
# that idempotent rerun must preserve required mode and must not recreate the
# tenant-wide HNSW index removed by enforcement.
psql_file /bootstrap/schema.sql
psql_value \
  "SELECT phase FROM memory_namespace_migration_state WHERE singleton_id" |
  grep -qx "constraints_complete"

AFTER_EMBEDDINGS=$(psql_value "
  SELECT md5(string_agg(
    id || ':' || COALESCE(embedding::text, '<null>'),
    E'\n' ORDER BY id
  ))
  FROM memories
  WHERE id LIKE '81%'
")
if [[ "$BEFORE_EMBEDDINGS" != "$AFTER_EMBEDDINGS" ]]; then
  echo "embedding digest changed during namespace migration" >&2
  exit 1
fi

psql_value "
  SELECT phase || ':' || checkpoint
  FROM memory_namespace_migration_state
  WHERE singleton_id
" | grep -qx "constraints_complete:constraints_validated"

psql_value "
  SELECT count(*)
  FROM information_schema.columns
  WHERE table_schema = 'public'
    AND (
      (table_name = 'memories' AND column_name = 'namespace_id')
      OR (
        table_name IN ('sessions', 'ingest_jobs', 'ingest_job_plans')
        AND column_name IN ('namespace_id', 'principal_id')
      )
      OR (table_name = 'upload_tasks' AND column_name = 'namespace_id')
    )
    AND is_nullable <> 'NO'
" | grep -qx "0"

psql_value "
  SELECT convalidated
  FROM pg_constraint
  WHERE conrelid = 'ingest_job_plans'::regclass
    AND conname = 'fk_ingest_job_plans_job_namespace'
" | grep -qx "t"

psql_value "SELECT to_regclass('idx_memories_embedding') IS NULL" |
  grep -qx "t"
psql_value "
  SELECT COUNT(*)
  FROM pg_class
  WHERE relname IN (
    'uq_ingest_jobs_tenant_idempotency',
    'uq_ingest_job_plans_hash',
    'uq_sessions_message'
  )
" | grep -qx "0"

if psql_sql "
  INSERT INTO memories (id, content)
  VALUES ('85000000-0000-4000-8000-000000000003', 'null namespace')
" >/dev/null 2>&1; then
  echo "enforced schema accepted a null namespace" >&2
  exit 1
fi

echo "memory namespace migration integration: OK"
