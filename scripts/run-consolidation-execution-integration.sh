#!/usr/bin/env bash
# One disposable local database; caller DSNs and production data are never used.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONTAINER="mem9-execution-test-${BASHPID}-${RANDOM}"
TMP_DIR=$(mktemp -d)
# shellcheck disable=SC2329
cleanup() {
  docker rm -fv "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap 'cleanup' EXIT
docker run -d --name "$CONTAINER" -e POSTGRES_HOST_AUTH_METHOD=trust \
  -e POSTGRES_DB=consolidation_execution_test -p 127.0.0.1::5432 pgvector/pgvector:pg17 >/dev/null
ready=false
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" sh -c 'test "$(cat /proc/1/comm)" = postgres' &&
    docker exec "$CONTAINER" pg_isready -U postgres -d consolidation_execution_test >/dev/null 2>&1; then ready=true;break;fi
  sleep 1
done
[[ "$ready" == true ]] || { echo 'PostgreSQL fixture did not start' >&2; exit 1; }
docker cp "$ROOT/docker/bootstrap/." "$CONTAINER:/bootstrap"
if ! docker exec "$CONTAINER" psql -q -U postgres -d consolidation_execution_test -v ON_ERROR_STOP=1 \
  -f /bootstrap/schema.sql >"$TMP_DIR/schema.log" 2>&1;then tail -30 "$TMP_DIR/schema.log" >&2;exit 1;fi
PORT=$(docker port "$CONTAINER" 5432/tcp | head -n 1 | awk -F: '{print $NF}')
export MEM9_EXECUTION_TEST_DSN="postgres://postgres@127.0.0.1:${PORT}/consolidation_execution_test"
cd "$ROOT"
npm exec -- vitest run scripts/consolidation-execution.postgres.test.mjs
if [[ -n "${MEM9_EXECUTION_GO_ROOT:-}" ]]; then
  MNEMO_TEST_POSTGRES_DSN="$MEM9_EXECUTION_TEST_DSN" go -C "$MEM9_EXECUTION_GO_ROOT/server" test \
    ./internal/handler ./internal/embed ./internal/middleware -run 'TestConsolidation|TestMaintenanceEmbeddingBoundary|TestService'
fi
