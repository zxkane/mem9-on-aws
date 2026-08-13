#!/usr/bin/env bash

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MIGRATION="$ROOT/docker/bootstrap/migrations/001_ingest_jobs.sql"
MEM9_REF=$(sed -n 's/^ARG MEM9_REF=//p' "$ROOT/docker/mnemo-server/Dockerfile")
TMP_DIR=$(mktemp -d)
CONTAINER="mem9-ingest-queue-${RANDOM}-${BASHPID}"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

docker run -d \
  --name "$CONTAINER" \
  -e POSTGRES_PASSWORD=test \
  -e POSTGRES_DB=mem9_queue \
  -p 127.0.0.1::5432 \
  postgres:17-alpine >/dev/null

for attempt in $(seq 1 60); do
  # The image starts a temporary server before creating POSTGRES_DB, then
  # replaces PID 1 with the final postgres process.
  if docker exec "$CONTAINER" sh -c \
      'test "$(cat /proc/1/comm)" = "postgres"' >/dev/null 2>&1 &&
    docker exec "$CONTAINER" \
      psql -qAt -v ON_ERROR_STOP=1 -U postgres -d mem9_queue \
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

apply_migration() {
  local database=$1
  docker exec -i "$CONTAINER" \
    psql -q -v ON_ERROR_STOP=1 -U postgres -d "$database" < "$MIGRATION"
}

expect_ingest_job_insert_rejected() {
  local description=$1
  local statement=$2
  if docker exec "$CONTAINER" \
    psql -q -v ON_ERROR_STOP=1 -U postgres -d mem9_queue \
    -c "$statement" >/dev/null 2>&1; then
    echo "$description unexpectedly bypassed an ingest_jobs constraint" >&2
    exit 1
  fi
}

# Empty schema: initial application and repeat application must both succeed.
apply_migration mem9_queue
apply_migration mem9_queue

expect_ingest_job_insert_rejected \
  "active plan revision without a hash" \
  "INSERT INTO ingest_jobs (
      job_id, tenant_id, idempotency_key, active_plan_revision
    ) VALUES (
      '00000000-0000-4000-8000-00000000a201',
      'tenant-a',
      repeat('c', 64),
      1
    )"
expect_ingest_job_insert_rejected \
  "active plan hash without a revision" \
  "INSERT INTO ingest_jobs (
      job_id, tenant_id, idempotency_key, active_plan_hash
    ) VALUES (
      '00000000-0000-4000-8000-00000000a202',
      'tenant-a',
      repeat('d', 64),
      repeat('e', 64)
    )"
expect_ingest_job_insert_rejected \
  "runtime operation without a finalization state" \
  "INSERT INTO ingest_jobs (
      job_id, tenant_id, idempotency_key, runtime_operation_id
    ) VALUES (
      '00000000-0000-4000-8000-00000000a203',
      'tenant-a',
      repeat('f', 64),
      '00000000-0000-7000-8000-00000000a203'
    )"

# Add the runtime memory table as it would exist before this migration, including
# a nullable legacy version. Reapplying must backfill and constrain the token.
docker exec "$CONTAINER" psql -q -v ON_ERROR_STOP=1 -U postgres -d mem9_queue \
  -c "CREATE TABLE memories (
        id VARCHAR(36) PRIMARY KEY,
        content TEXT NOT NULL,
        source VARCHAR(100),
        tags JSONB,
        metadata JSONB,
        embedding TEXT NULL,
        memory_type VARCHAR(20) NOT NULL DEFAULT 'pinned',
        agent_id VARCHAR(100) NULL,
        session_id VARCHAR(100) NULL,
        app_id VARCHAR(100) NOT NULL DEFAULT '',
        state VARCHAR(20) NOT NULL DEFAULT 'active',
        version INT NULL,
        updated_by VARCHAR(100),
        superseded_by VARCHAR(36) NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      INSERT INTO memories (id, content, version)
      VALUES ('00000000-0000-4000-8000-00000000a054', 'legacy', NULL);"
apply_migration mem9_queue
docker exec "$CONTAINER" psql -qAt -v ON_ERROR_STOP=1 -U postgres -d mem9_queue \
  -c "SELECT version FROM memories WHERE id = '00000000-0000-4000-8000-00000000a054'" |
  grep -qx "1"
docker exec "$CONTAINER" psql -qAt -v ON_ERROR_STOP=1 -U postgres -d mem9_queue \
  -c "SELECT is_nullable || ':' || column_default
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'memories'
        AND column_name = 'version'" |
  grep -qx "NO:1"
docker exec "$CONTAINER" psql -q -v ON_ERROR_STOP=1 -U postgres -d mem9_queue \
  -c "DELETE FROM memories"

# Upgraded schema: migrate the preceding foundation's synthetic key and
# length-only constraint while preserving its row.
docker exec "$CONTAINER" psql -q -v ON_ERROR_STOP=1 -U postgres -d postgres \
  -c "CREATE DATABASE mem9_queue_upgraded"
docker exec "$CONTAINER" psql -q -v ON_ERROR_STOP=1 -U postgres -d mem9_queue_upgraded \
  -c "CREATE TABLE ingest_jobs (
        job_id VARCHAR(36) PRIMARY KEY,
        tenant_id VARCHAR(36) NOT NULL DEFAULT '',
        idempotency_key VARCHAR(64) NOT NULL,
        canonical_payload BYTEA NOT NULL DEFAULT '\x7b7d'::bytea,
        CONSTRAINT ck_ingest_jobs_idempotency_key CHECK (length(idempotency_key) = 64)
      )"
docker exec "$CONTAINER" psql -q -v ON_ERROR_STOP=1 -U postgres -d mem9_queue_upgraded \
  -c "INSERT INTO ingest_jobs (job_id, idempotency_key, canonical_payload)
      VALUES (
        '00000000-0000-4000-8000-00000000a099',
        md5('00000000-0000-4000-8000-00000000a099')
          || md5('ingest-v1:00000000-0000-4000-8000-00000000a099'),
        decode(repeat('aa', 1048577), 'hex')
      )"
apply_migration mem9_queue_upgraded
apply_migration mem9_queue_upgraded
docker exec "$CONTAINER" psql -qAt -v ON_ERROR_STOP=1 -U postgres -d mem9_queue_upgraded \
  -c "SELECT idempotency_key FROM ingest_jobs WHERE job_id = '00000000-0000-4000-8000-00000000a099'" |
  grep -qx "legacy:00000000-0000-4000-8000-00000000a099"
docker exec "$CONTAINER" psql -qAt -v ON_ERROR_STOP=1 -U postgres -d mem9_queue_upgraded \
  -c "SELECT pg_get_constraintdef(oid)
      FROM pg_constraint
      WHERE conrelid = 'ingest_jobs'::regclass
        AND conname = 'ck_ingest_jobs_idempotency_key'" |
  grep -q "legacy:"
docker exec "$CONTAINER" psql -qAt -v ON_ERROR_STOP=1 -U postgres -d mem9_queue_upgraded \
  -c "SELECT octet_length(canonical_payload)
      FROM ingest_jobs
      WHERE job_id = '00000000-0000-4000-8000-00000000a099'" |
  grep -qx "1048577"
docker exec "$CONTAINER" psql -qAt -v ON_ERROR_STOP=1 -U postgres -d mem9_queue_upgraded \
  -c "SELECT convalidated
      FROM pg_constraint
      WHERE conrelid = 'ingest_jobs'::regclass
        AND conname = 'ck_ingest_jobs_payload_size'" |
  grep -qx "f"
if docker exec "$CONTAINER" psql -q -v ON_ERROR_STOP=1 -U postgres -d mem9_queue_upgraded \
  -c "INSERT INTO ingest_jobs (job_id, tenant_id, idempotency_key, canonical_payload)
      VALUES (
        '00000000-0000-4000-8000-00000000a101',
        '',
        repeat('b', 64),
        decode(repeat('bb', 1048577), 'hex')
      )" >/dev/null 2>&1; then
  echo "oversized canonical payload unexpectedly bypassed the not-valid constraint" >&2
  exit 1
fi
docker exec "$CONTAINER" psql -q -v ON_ERROR_STOP=1 -U postgres -d mem9_queue_upgraded \
  -c "INSERT INTO ingest_jobs (job_id, tenant_id, idempotency_key) VALUES ('00000000-0000-4000-8000-00000000a100', '', repeat('a', 64))"
docker exec "$CONTAINER" psql -qAt -v ON_ERROR_STOP=1 -U postgres -d mem9_queue_upgraded \
  -c "SELECT count(*) FROM ingest_jobs WHERE tenant_id = ''" |
  grep -qx "2"

git -C "$TMP_DIR" init -q upstream
git -C "$TMP_DIR/upstream" remote add origin https://github.com/mem9-ai/mem9.git
git -C "$TMP_DIR/upstream" fetch -q --depth 1 origin "$MEM9_REF"
git -C "$TMP_DIR/upstream" checkout -q FETCH_HEAD
git -C "$TMP_DIR/upstream" apply "$ROOT"/docker/mnemo-server/patches/*.patch

PORT=$(docker port "$CONTAINER" 5432/tcp | head -n 1 | awk -F: '{print $NF}')
export MNEMO_TEST_POSTGRES_DSN="postgres://postgres:test@127.0.0.1:${PORT}/mem9_queue?sslmode=disable"

cd "$TMP_DIR/upstream/server"
go test -count=1 \
  ./internal/repository \
  ./internal/repository/postgres \
  ./internal/ingestqueue \
  ./internal/handler \
  ./internal/service \
  ./internal/config \
  ./cmd/mnemo-server
