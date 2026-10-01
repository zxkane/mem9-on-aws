#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONTAINER="mem9-runtime-test-${BASHPID}-${RANDOM}"
TASK_TMP=$(mktemp -d)
# shellcheck disable=SC2329
cleanup() { docker rm -fv "$CONTAINER" >/dev/null 2>&1 || true; rm -r -- "$TASK_TMP"; }
trap cleanup EXIT
docker run -d --name "$CONTAINER" -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=runtime_credentials_test \
  -p 127.0.0.1::5432 pgvector/pgvector:pg17 >/dev/null
ready=false
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" sh -c 'test "$(cat /proc/1/comm)" = postgres' && docker exec "$CONTAINER" pg_isready -U postgres >/dev/null 2>&1;then ready=true;break;fi
  sleep 1
done
[[ "$ready" == true ]] || exit 1
printf 'host all postgres 0.0.0.0/0 trust\nhost all all 0.0.0.0/0 scram-sha-256\n' >"$TASK_TMP/pg_hba.conf"
docker exec "$CONTAINER" cat /var/lib/postgresql/data/pg_hba.conf >>"$TASK_TMP/pg_hba.conf"
docker cp "$TASK_TMP/pg_hba.conf" "$CONTAINER:/var/lib/postgresql/data/pg_hba.conf"
docker exec "$CONTAINER" psql -q -U postgres -c 'SELECT pg_reload_conf()' >/dev/null
PORT=$(docker port "$CONTAINER" 5432/tcp | head -n 1 | awk -F: '{print $NF}')
export MEM9_RUNTIME_TEST_DSN="postgres://postgres@127.0.0.1:${PORT}/runtime_credentials_test"
export MEM9_RUNTIME_TEST_CONTAINER="$CONTAINER"
cd "$ROOT"
npm exec -- vitest run --no-file-parallelism scripts/runtime-credentials.postgres.test.mjs scripts/production-runtime-state.postgres.test.mjs scripts/production-runtime-credentials.postgres.test.mjs scripts/production-runtime-operator.postgres.test.mjs scripts/production-runtime-rehearsal.postgres.test.mjs scripts/production-consolidation-operator.postgres.test.mjs
