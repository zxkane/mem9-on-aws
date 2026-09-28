#!/usr/bin/env bash
# Isolated synthetic PostgreSQL rehearsal; never accepts an operator/database DSN.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONTAINER="mem9-consolidation-storage-${BASHPID}-${RANDOM}"
TMP_DIR=$(mktemp -d)
# Invoked by the EXIT trap on both setup failure and successful test completion.
# shellcheck disable=SC2329
cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap 'cleanup' EXIT
docker run -d --name "$CONTAINER" \
  -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=consolidation_storage_test \
  -p 127.0.0.1::5432 pgvector/pgvector:pg17 >/dev/null
ready=false
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" sh -c 'test "$(cat /proc/1/comm)" = postgres' &&
    docker exec "$CONTAINER" pg_isready -U postgres -d consolidation_storage_test >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
[[ "$ready" == true ]] || { echo 'Synthetic PostgreSQL did not start' >&2; exit 1; }
docker cp "$ROOT/docker/bootstrap/." "$CONTAINER:/bootstrap"
if ! docker exec "$CONTAINER" psql -q -U postgres -d consolidation_storage_test \
  -v ON_ERROR_STOP=1 -f /bootstrap/schema.sql >"$TMP_DIR/schema.log" 2>&1; then
  cat "$TMP_DIR/schema.log" >&2
  exit 1
fi
PORT=$(docker port "$CONTAINER" 5432/tcp | head -n 1 | awk -F: '{print $NF}')
export MEM9_CONSOLIDATION_TEST_DSN="postgres://postgres@127.0.0.1:${PORT}/consolidation_storage_test"
cd "$ROOT"
exec_status=0
npm exec vitest run scripts/consolidation-storage.postgres.test.mjs || exec_status=$?
exit "$exec_status"
