#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONTAINER="mem9-scheduling-test-${BASHPID}-${RANDOM}"
TASK_TMP=$(mktemp -d)
# shellcheck disable=SC2329
cleanup() {
  docker rm -fv "$CONTAINER" >/dev/null 2>&1 || true
  rm -r -- "$TASK_TMP"
}
trap cleanup EXIT
docker run -d --name "$CONTAINER" -e POSTGRES_HOST_AUTH_METHOD=trust \
  -e POSTGRES_DB=consolidation_scheduling_test -p 127.0.0.1::5432 pgvector/pgvector:pg17 >/dev/null
ready=false
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" sh -c 'test "$(cat /proc/1/comm)" = postgres' &&
    docker exec "$CONTAINER" pg_isready -U postgres -d consolidation_scheduling_test >/dev/null 2>&1; then ready=true;break;fi
  sleep 1
done
[[ "$ready" == true ]] || { echo 'Scheduling fixture did not start' >&2;exit 1; }
# Exercise real SCRAM authentication for synthetic fixture logins. The other
# scheduler tests use passwordless, disposable roles in separate databases.
SYNTHETIC_DB=$(node --input-type=module -e "import {previewConfiguration} from '${ROOT}/scripts/lib/consolidation-preview-config.mjs';process.stdout.write(previewConfiguration('pr-982731','b'.repeat(64),'fixture').database)")
printf 'host all postgres 0.0.0.0/0 trust\nhost %s all 0.0.0.0/0 scram-sha-256\n' "$SYNTHETIC_DB" >"$TASK_TMP/pg_hba.conf"
docker exec "$CONTAINER" cat /var/lib/postgresql/data/pg_hba.conf >>"$TASK_TMP/pg_hba.conf"
docker cp "$TASK_TMP/pg_hba.conf" "$CONTAINER:/var/lib/postgresql/data/pg_hba.conf"
docker exec "$CONTAINER" psql -q -U postgres -c 'SELECT pg_reload_conf()' >/dev/null
docker cp "$ROOT/docker/bootstrap/." "$CONTAINER:/bootstrap"
if ! docker exec "$CONTAINER" psql -q -U postgres -d consolidation_scheduling_test -v ON_ERROR_STOP=1 \
  -f /bootstrap/schema.sql >"$TASK_TMP/schema.log" 2>&1;then tail -30 "$TASK_TMP/schema.log" >&2;exit 1;fi
PORT=$(docker port "$CONTAINER" 5432/tcp | head -n 1 | awk -F: '{print $NF}')
export MEM9_SCHEDULING_TEST_DSN="postgres://postgres@127.0.0.1:${PORT}/consolidation_scheduling_test"
cd "$ROOT"
npm exec -- vitest run --no-file-parallelism scripts/consolidation-scheduling.postgres.test.mjs scripts/consolidation-preview.postgres.test.mjs
