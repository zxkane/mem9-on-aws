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

# Upgraded schema: preserve a legacy row while adding every foundation column.
docker exec "$CONTAINER" psql -q -v ON_ERROR_STOP=1 -U postgres -d postgres \
  -c "CREATE DATABASE mem9_queue_upgraded"
docker exec "$CONTAINER" psql -q -v ON_ERROR_STOP=1 -U postgres -d mem9_queue_upgraded \
  -c "CREATE TABLE ingest_jobs (job_id VARCHAR(36) PRIMARY KEY)"
docker exec "$CONTAINER" psql -q -v ON_ERROR_STOP=1 -U postgres -d mem9_queue_upgraded \
  -c "INSERT INTO ingest_jobs (job_id) VALUES ('00000000-0000-4000-8000-000000000099')"
apply_migration mem9_queue_upgraded
apply_migration mem9_queue_upgraded
docker exec "$CONTAINER" psql -qAt -v ON_ERROR_STOP=1 -U postgres -d mem9_queue_upgraded \
  -c "SELECT count(*) FROM ingest_jobs WHERE idempotency_key IS NOT NULL" |
  grep -qx "1"

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
