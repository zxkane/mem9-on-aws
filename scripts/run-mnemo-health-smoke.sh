#!/usr/bin/env bash
# Build or pull the mnemo-server image, then exercise the exact ECS liveness
# command against a real mnemo-server process and an unavailable endpoint.

set -euo pipefail

readonly HEALTH_COMMAND="wget -q -O /dev/null http://localhost:8080/healthz || exit 1"
readonly RUN_ID="$$"
readonly NETWORK="mnemo-health-${RUN_ID}"
readonly DB_CONTAINER="mnemo-health-db-${RUN_ID}"
readonly SERVER_CONTAINER="mnemo-health-server-${RUN_ID}"
readonly LOCAL_IMAGE="mnemo-health-smoke:${RUN_ID}"
readonly POSTGRES_IMAGE="postgres:17-alpine"
readonly DB_USER="mnemo"
readonly DB_PASSWORD='mnemo:@/?#retry'
readonly DB_SECRET='{"username":"mnemo","password":"mnemo:@/?#retry"}'
readonly VALIDATE_EMF="${MNEMO_VALIDATE_EMF:-false}"
TLS_DIR="$(mktemp -d)"
readonly TLS_DIR

IMAGE="${MNEMO_IMAGE:-$LOCAL_IMAGE}"
BUILT_LOCAL_IMAGE=false

cleanup() {
  docker rm -f "$SERVER_CONTAINER" "$DB_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  rm -rf "$TLS_DIR"
  if [ "$BUILT_LOCAL_IMAGE" = true ]; then
    docker image rm "$LOCAL_IMAGE" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [ -z "${MNEMO_IMAGE:-}" ]; then
  echo "mnemo-health-smoke: building linux/arm64 mnemo-server image"
  docker buildx build \
    --platform linux/arm64 \
    --load \
    --tag "$LOCAL_IMAGE" \
    --file docker/mnemo-server/Dockerfile \
    .
  BUILT_LOCAL_IMAGE=true
else
  echo "mnemo-health-smoke: pulling $IMAGE"
  docker pull --platform linux/arm64 "$IMAGE"
fi

echo "mnemo-health-smoke: verifying Alpine BusyBox wget"
docker run --rm --entrypoint /bin/sh "$IMAGE" -c \
  'command -v wget >/dev/null && busybox --list | grep -qx wget'

echo "mnemo-health-smoke: pre-pulling PostgreSQL before the migration retry window"
docker pull "$POSTGRES_IMAGE" >/dev/null

openssl req \
  -x509 \
  -newkey rsa:2048 \
  -nodes \
  -days 1 \
  -subj "/CN=${DB_CONTAINER}" \
  -keyout "$TLS_DIR/server.key" \
  -out "$TLS_DIR/server.crt" >/dev/null 2>&1
printf '%s\n' \
  "local all all trust" \
  "hostssl all all all scram-sha-256" \
  "hostnossl all all all reject" \
  > "$TLS_DIR/pg_hba.conf"
chmod 755 "$TLS_DIR"

echo "mnemo-health-smoke: rejecting migration settings that could skip or unbound startup"
if docker run --rm \
    --env MNEMO_DSN=postgres://unused/unused \
    --env MNEMO_MIGRATION_MAX_ATTEMPTS=00 \
    "$IMAGE" >/dev/null 2>&1; then
  echo "mnemo-health-smoke: zero-valued migration attempts were accepted" >&2
  exit 1
fi
if docker run --rm \
    --env MNEMO_DSN=postgres://unused/unused \
    --env PGCONNECT_TIMEOUT=0 \
    "$IMAGE" >/dev/null 2>&1; then
  echo "mnemo-health-smoke: unbounded PostgreSQL connect timeout was accepted" >&2
  exit 1
fi

docker network create "$NETWORK" >/dev/null

emf_args=()
if [ "$VALIDATE_EMF" = true ]; then
  emf_args=(
    --env MNEMO_DURABLE_INGEST_ENABLED=true
    --env MEM9_TENANT_ID=emf-smoke-tenant
    --env MNEMO_DURABLE_INGEST_METRIC_STAGE=prod
  )
fi

docker run --detach \
  --name "$SERVER_CONTAINER" \
  --network "$NETWORK" \
  --tty=false \
  --env "MEM9_DB_HOST=${DB_CONTAINER}" \
  --env MEM9_DB_PORT=5432 \
  --env MEM9_DB_NAME=mnemo \
  --env "MEM9_DB_SECRET=${DB_SECRET}" \
  --env MNEMO_DB_BACKEND=postgres \
  --env MNEMO_INGEST_MODE=raw \
  --env MNEMO_MIGRATION_RETRY_DELAY_SECONDS=1 \
  --env MNEMO_TIDB_ZERO_ENABLED=false \
  "${emf_args[@]}" \
  "$IMAGE" >/dev/null

if docker exec "$SERVER_CONTAINER" /bin/sh -c "$HEALTH_COMMAND"; then
  echo "mnemo-health-smoke: server became healthy before the startup migration" >&2
  exit 1
fi

echo "mnemo-health-smoke: verifying ECS startup migration retries until PostgreSQL is reachable"
migration_retried=false
for _ in $(seq 1 30); do
  if docker logs "$SERVER_CONTAINER" 2>&1 |
      grep -Eq "migration attempt 1/[0-9]+ failed"; then
    migration_retried=true
    break
  fi
  sleep 1
done
if [ "$migration_retried" != true ]; then
  echo "mnemo-health-smoke: startup migration did not expose a retry" >&2
  docker logs "$SERVER_CONTAINER" >&2
  exit 1
fi

docker run --detach \
  --name "$DB_CONTAINER" \
  --network "$NETWORK" \
  --volume "$TLS_DIR:/tls" \
  --env "POSTGRES_USER=${DB_USER}" \
  --env "POSTGRES_PASSWORD=${DB_PASSWORD}" \
  --env POSTGRES_DB=mnemo \
  "$POSTGRES_IMAGE" \
  /bin/sh -c '
    chown postgres:postgres /tls/server.crt /tls/server.key
    chmod 600 /tls/server.key
    exec docker-entrypoint.sh postgres \
      -c ssl=on \
      -c ssl_cert_file=/tls/server.crt \
      -c ssl_key_file=/tls/server.key \
      -c hba_file=/tls/pg_hba.conf
  ' >/dev/null

db_ready=false
for _ in $(seq 1 30); do
  if docker exec "$DB_CONTAINER" pg_isready --username "$DB_USER" --dbname mnemo >/dev/null 2>&1; then
    db_ready=true
    break
  fi
  sleep 1
done
if [ "$db_ready" != true ]; then
  echo "mnemo-health-smoke: PostgreSQL did not become ready" >&2
  docker logs "$DB_CONTAINER" >&2
  exit 1
fi

server_healthy=false
for _ in $(seq 1 30); do
  if docker exec "$SERVER_CONTAINER" /bin/sh -c "$HEALTH_COMMAND"; then
    server_healthy=true
    break
  fi
  sleep 1
done
if [ "$server_healthy" != true ]; then
  echo "mnemo-health-smoke: /healthz did not become healthy" >&2
  docker logs "$SERVER_CONTAINER" >&2
  exit 1
fi

if ! docker logs "$SERVER_CONTAINER" 2>&1 |
    grep -Eq "migration applied after [1-9][0-9]* retries"; then
  echo "mnemo-health-smoke: startup migration did not recover after PostgreSQL became reachable" >&2
  docker logs "$SERVER_CONTAINER" >&2
  exit 1
fi

if docker exec \
    --env "PGPASSWORD=${DB_PASSWORD}" \
    --env PGSSLMODE=disable \
    "$DB_CONTAINER" \
    psql \
      --host "$DB_CONTAINER" \
      --username "$DB_USER" \
      --dbname mnemo \
      --command "SELECT 1" >/dev/null 2>&1; then
  echo "mnemo-health-smoke: PostgreSQL accepted a plaintext host connection" >&2
  exit 1
fi

migration_complete=$(
  docker exec \
    --env "PGPASSWORD=${DB_PASSWORD}" \
    --env PGSSLMODE=require \
    "$DB_CONTAINER" \
    psql \
    --host "$DB_CONTAINER" \
    --username "$DB_USER" \
    --dbname mnemo \
    --tuples-only \
    --no-align \
    --command "
      SELECT to_regclass('public.ingest_jobs') IS NOT NULL
         AND to_regclass('public.ingest_job_plans') IS NOT NULL
         AND to_regclass('public.sessions') IS NOT NULL
         AND (
           SELECT ssl
           FROM pg_stat_ssl
           WHERE pid = pg_backend_pid()
         );
    "
)
if [ "$migration_complete" != "t" ]; then
  echo "mnemo-health-smoke: atomic-ingest relations are missing after startup" >&2
  docker logs "$SERVER_CONTAINER" >&2
  exit 1
fi
server_logs=$(docker logs "$SERVER_CONTAINER" 2>&1)
if printf '%s\n' "$server_logs" | grep -Fq "$DB_PASSWORD"; then
  echo "mnemo-health-smoke: database password appeared in server logs" >&2
  exit 1
fi
if [ "$VALIDATE_EMF" = true ]; then
  docker logs "$SERVER_CONTAINER" >"$TLS_DIR/server-stdout.log" 2>/dev/null
  node scripts/validate-emf-event.mjs --docker-stream <"$TLS_DIR/server-stdout.log"
fi
echo "mnemo-health-smoke: ECS startup migration retried over enforced TLS and created atomic-ingest relations"
echo "mnemo-health-smoke: exact ECS command succeeds against running server"

docker stop --time 10 "$SERVER_CONTAINER" >/dev/null
if docker run --rm --entrypoint /bin/sh "$IMAGE" -c "$HEALTH_COMMAND"; then
  echo "mnemo-health-smoke: health command unexpectedly succeeded without the server" >&2
  exit 1
fi
echo "mnemo-health-smoke: exact ECS command fails when the server is unavailable"
