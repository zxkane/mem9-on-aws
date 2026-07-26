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

docker run --rm -d \
  --name "$CONTAINER" \
  -e POSTGRES_PASSWORD=test \
  -e POSTGRES_DB=mem9_queue \
  -p 127.0.0.1::5432 \
  postgres:17-alpine >/dev/null

for attempt in $(seq 1 30); do
  if docker exec "$CONTAINER" pg_isready -U postgres -d mem9_queue >/dev/null 2>&1; then
    break
  fi
  if [[ "$attempt" == "30" ]]; then
    echo "PostgreSQL did not become ready" >&2
    exit 1
  fi
  sleep 1
done

apply_migration() {
  local database=$1
  docker exec -i "$CONTAINER" \
    psql -q -v ON_ERROR_STOP=1 -U postgres -d "$database" < "$MIGRATION"
}

# Empty schema: initial application and repeat application must both succeed.
apply_migration mem9_queue
apply_migration mem9_queue

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
        '00000000-0000-4000-8000-000000000099',
        md5('00000000-0000-4000-8000-000000000099')
          || md5('ingest-v1:00000000-0000-4000-8000-000000000099'),
        decode(repeat('aa', 1048577), 'hex')
      )"
apply_migration mem9_queue_upgraded
apply_migration mem9_queue_upgraded
docker exec "$CONTAINER" psql -qAt -v ON_ERROR_STOP=1 -U postgres -d mem9_queue_upgraded \
  -c "SELECT idempotency_key FROM ingest_jobs WHERE job_id = '00000000-0000-4000-8000-000000000099'" |
  grep -qx "legacy:00000000-0000-4000-8000-000000000099"
docker exec "$CONTAINER" psql -qAt -v ON_ERROR_STOP=1 -U postgres -d mem9_queue_upgraded \
  -c "SELECT pg_get_constraintdef(oid)
      FROM pg_constraint
      WHERE conrelid = 'ingest_jobs'::regclass
        AND conname = 'ck_ingest_jobs_idempotency_key'" |
  grep -q "legacy:"
docker exec "$CONTAINER" psql -qAt -v ON_ERROR_STOP=1 -U postgres -d mem9_queue_upgraded \
  -c "SELECT octet_length(canonical_payload)
      FROM ingest_jobs
      WHERE job_id = '00000000-0000-4000-8000-000000000099'" |
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
        '00000000-0000-4000-8000-000000000101',
        '',
        repeat('b', 64),
        decode(repeat('bb', 1048577), 'hex')
      )" >/dev/null 2>&1; then
  echo "oversized canonical payload unexpectedly bypassed the not-valid constraint" >&2
  exit 1
fi
docker exec "$CONTAINER" psql -q -v ON_ERROR_STOP=1 -U postgres -d mem9_queue_upgraded \
  -c "INSERT INTO ingest_jobs (job_id, tenant_id, idempotency_key) VALUES ('00000000-0000-4000-8000-000000000100', '', repeat('a', 64))"
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
go test ./internal/repository/postgres -run '^TestIngestJob' -count=1
go test ./internal/ingestqueue -count=1
go test ./internal/handler -run '^TestDurableIngest' -count=1
go test ./internal/config -run '^TestDurableIngest' -count=1
go test ./cmd/mnemo-server -run '^TestDurableIngest' -count=1
