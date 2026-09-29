#!/usr/bin/env bash
# Disposable local fixture. Never accepts a production DSN.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONTAINER="mem9-planner-test-${BASHPID}-${RANDOM}"
TASK_TMP=$(mktemp -d)
# shellcheck disable=SC2329
cleanup() {
  docker rm -fv "$CONTAINER" >/dev/null 2>&1 || true
  rm -r -- "$TASK_TMP"
}
trap cleanup EXIT
docker run -d --name "$CONTAINER" -e POSTGRES_HOST_AUTH_METHOD=trust \
  -e POSTGRES_DB=consolidation_planner_test -p 127.0.0.1::5432 pgvector/pgvector:pg17 >/dev/null
ready=false
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" sh -c 'test "$(cat /proc/1/comm)" = postgres' &&
    docker exec "$CONTAINER" pg_isready -U postgres -d consolidation_planner_test >/dev/null 2>&1; then ready=true; break; fi
  sleep 1
done
[[ "$ready" == true ]] || { echo 'Planner database fixture did not start' >&2; exit 1; }
docker cp "$ROOT/docker/bootstrap/." "$CONTAINER:/bootstrap"
if ! docker exec "$CONTAINER" psql -q -U postgres -d consolidation_planner_test -v ON_ERROR_STOP=1 \
  -f /bootstrap/schema.sql >"$TASK_TMP/schema.log" 2>&1; then tail -30 "$TASK_TMP/schema.log" >&2; exit 1; fi
PORT=$(docker port "$CONTAINER" 5432/tcp | head -n 1 | awk -F: '{print $NF}')
export MEM9_PLANNER_TEST_DSN="postgres://postgres@127.0.0.1:${PORT}/consolidation_planner_test"
cd "$ROOT"
npm exec -- vitest run scripts/consolidation-planner.postgres.test.mjs
