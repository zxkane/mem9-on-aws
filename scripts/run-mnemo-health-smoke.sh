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

IMAGE="${MNEMO_IMAGE:-$LOCAL_IMAGE}"
BUILT_LOCAL_IMAGE=false

cleanup() {
  docker rm -f "$SERVER_CONTAINER" "$DB_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
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

docker network create "$NETWORK" >/dev/null
docker run --detach \
  --name "$DB_CONTAINER" \
  --network "$NETWORK" \
  --env POSTGRES_USER=mnemo \
  --env POSTGRES_PASSWORD=mnemo \
  --env POSTGRES_DB=mnemo \
  postgres:17-alpine >/dev/null

db_ready=false
for _ in $(seq 1 30); do
  if docker exec "$DB_CONTAINER" pg_isready --username mnemo --dbname mnemo >/dev/null 2>&1; then
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

docker run --detach \
  --name "$SERVER_CONTAINER" \
  --network "$NETWORK" \
  --env "MNEMO_DSN=postgres://mnemo:mnemo@${DB_CONTAINER}:5432/mnemo?sslmode=disable" \
  --env MNEMO_DB_BACKEND=postgres \
  --env MNEMO_INGEST_MODE=raw \
  --env MNEMO_TIDB_ZERO_ENABLED=false \
  "$IMAGE" >/dev/null

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
echo "mnemo-health-smoke: exact ECS command succeeds against running server"

docker stop --time 10 "$SERVER_CONTAINER" >/dev/null
if docker run --rm --entrypoint /bin/sh "$IMAGE" -c "$HEALTH_COMMAND"; then
  echo "mnemo-health-smoke: health command unexpectedly succeeded without the server" >&2
  exit 1
fi
echo "mnemo-health-smoke: exact ECS command fails when the server is unavailable"
