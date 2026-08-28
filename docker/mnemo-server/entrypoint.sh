#!/bin/sh
# entrypoint.sh — assemble MNEMO_DSN, apply the repeatable atomic migration, then
# exec mnemo-server. Runs as PID 1 in the mnemo-server container.
#
# WHY (docs/mem9-facts.md "DB connection mechanism"): mem9 reads a SINGLE static
# `MNEMO_DSN` env var and does NOT compose it from host/user/pass/dbname parts —
# there are no such vars in mem9. The DB password is a runtime secret (Secrets
# Manager → ECS `secrets: valueFrom`), so it CANNOT be string-concatenated into a
# committed task def. This script does the composition at container start, from:
#
#   MEM9_DB_HOST    - Aurora cluster writer endpoint (plain env, from infra/ecs.ts)
#   MEM9_DB_PORT    - 5432                           (plain env)
#   MEM9_DB_NAME    - "mem9"                          (plain env)
#   MEM9_DB_SECRET  - JSON {"username":..,"password":..}  (ECS secret, whole value)
#
#   → MNEMO_DSN=postgres://<user>:<url-encoded-pw>@<host>:<port>/<db>?sslmode=require
#
# If MNEMO_DSN is ALREADY set (for example, a local run), it
# is respected as-is and this assembly is skipped.
#
# Fail LOUD on any missing piece — a silent fallback to a malformed DSN would let
# the container start and then fail every query with a confusing auth error.

set -eu

MNEMO_DSN_ASSEMBLED=false
if [ -z "${MNEMO_DSN:-}" ]; then
  : "${MEM9_DB_HOST:?MEM9_DB_HOST is required to assemble MNEMO_DSN}"
  : "${MEM9_DB_PORT:?MEM9_DB_PORT is required to assemble MNEMO_DSN}"
  : "${MEM9_DB_NAME:?MEM9_DB_NAME is required to assemble MNEMO_DSN}"
  : "${MEM9_DB_SECRET:?MEM9_DB_SECRET (Secrets Manager JSON) is required to assemble MNEMO_DSN}"

  # Extract user + password before URL-encoding them for MNEMO_DSN. The field is
  # validated for null/absence first: encoding null would produce the truthy
  # string "null" and silently create a malformed credential.
  extract_field() {
    printf '%s' "$MEM9_DB_SECRET" | jq -re "(.$1 // error(\"missing .$1\")) | strings" || {
      echo "entrypoint: MEM9_DB_SECRET has no .$1 field" >&2
      exit 1
    }
  }
  DB_USER=$(extract_field username)
  DB_PASS=$(extract_field password)
  DB_USER_URI=$(printf '%s' "$DB_USER" | jq -sRr '@uri')
  DB_PASS_URI=$(printf '%s' "$DB_PASS" | jq -sRr '@uri')

  # sslmode=require protects the direct Aurora connection; mem9 uses the pgx
  # stdlib driver, which honors the DSN query parameter.
  export MNEMO_DSN="postgres://${DB_USER_URI}:${DB_PASS_URI}@${MEM9_DB_HOST}:${MEM9_DB_PORT}/${MEM9_DB_NAME}?sslmode=require"
  MNEMO_DSN_ASSEMBLED=true

  # Log the DSN with the password redacted (host/port/db/user are safe to show
  # and help diagnose connectivity; the secret value never appears in logs).
  echo "entrypoint: assembled MNEMO_DSN=postgres://${DB_USER_URI}:***@${MEM9_DB_HOST}:${MEM9_DB_PORT}/${MEM9_DB_NAME}?sslmode=require"
fi

# Apply the complete repeatable base schema before the process can become
# healthy. schema.sql creates the base tables first, then includes the durable
# ingest and namespace migrations in dependency order. This is required on a
# brand-new stage where ECS starts before the later one-shot tenant bootstrap.
# A URI must be supplied through psql's dbname connection parameter; PGDATABASE
# treats the same URI as a literal database name. The ECS path uses discrete
# libpq variables so its password stays out of process arguments. A
# caller-supplied local MNEMO_DSN uses --dbname directly.
run_migration() {
  if [ "$MNEMO_DSN_ASSEMBLED" = true ]; then
    PGHOST="$MEM9_DB_HOST" \
      PGPORT="$MEM9_DB_PORT" \
      PGDATABASE="$MEM9_DB_NAME" \
      PGUSER="$DB_USER" \
      PGPASSWORD="$DB_PASS" \
      PGSSLMODE=require \
      psql --quiet --no-password -v ON_ERROR_STOP=1 \
        -f /usr/local/share/mem9/schema.sql
  else
    psql --dbname="$MNEMO_DSN" --quiet -v ON_ERROR_STOP=1 \
      -f /usr/local/share/mem9/schema.sql
  fi
}

export PGCONNECT_TIMEOUT="${PGCONNECT_TIMEOUT:-8}"
MIGRATION_MAX_ATTEMPTS="${MNEMO_MIGRATION_MAX_ATTEMPTS:-15}"
MIGRATION_RETRY_DELAY_SECONDS="${MNEMO_MIGRATION_RETRY_DELAY_SECONDS:-8}"

case "$MIGRATION_MAX_ATTEMPTS" in
  [1-9]|[1-9][0-9]|100) ;;
  *)
    echo "entrypoint: MNEMO_MIGRATION_MAX_ATTEMPTS must be an integer from 1 to 100" >&2
    exit 1
    ;;
esac
case "$MIGRATION_RETRY_DELAY_SECONDS" in
  0|[1-9]|[1-5][0-9]|60) ;;
  *)
    echo "entrypoint: MNEMO_MIGRATION_RETRY_DELAY_SECONDS must be an integer from 0 to 60" >&2
    exit 1
    ;;
esac
case "$PGCONNECT_TIMEOUT" in
  [1-9]|[1-5][0-9]|60) ;;
  *)
    echo "entrypoint: PGCONNECT_TIMEOUT must be an integer from 1 to 60" >&2
    exit 1
    ;;
esac

MIGRATION_RETRY_BUDGET_SECONDS=$((
  (MIGRATION_MAX_ATTEMPTS * PGCONNECT_TIMEOUT) +
  ((MIGRATION_MAX_ATTEMPTS - 1) * MIGRATION_RETRY_DELAY_SECONDS)
))
if [ "$MIGRATION_RETRY_BUDGET_SECONDS" -ge 300 ]; then
  echo "entrypoint: combined migration retry budget must be less than the 300-second ECS startup grace" >&2
  exit 1
fi

echo "entrypoint: applying atomic-ingest migration (up to ${MIGRATION_MAX_ATTEMPTS} attempts)"
MIGRATION_SUCCEEDED=false
i=1
while [ "$i" -le "$MIGRATION_MAX_ATTEMPTS" ]; do
  if MIGRATION_ERR=$(run_migration 2>&1); then
    MIGRATION_SUCCEEDED=true
    echo "entrypoint: migration applied after $((i - 1)) retries"
    break
  else
    migration_rc=$?
  fi
  echo "entrypoint: migration attempt ${i}/${MIGRATION_MAX_ATTEMPTS} failed: ${MIGRATION_ERR}" >&2

  # psql exit 2 means the server connection failed. SQL/script errors use a
  # different status under ON_ERROR_STOP and cannot improve by waiting.
  if [ "$migration_rc" -ne 2 ]; then
    echo "entrypoint: migration failed with non-connection status ${migration_rc}; not retrying" >&2
    exit "$migration_rc"
  fi
  if [ "$i" -eq "$MIGRATION_MAX_ATTEMPTS" ]; then
    echo "entrypoint: database remained unreachable after ${MIGRATION_MAX_ATTEMPTS} attempts" >&2
    exit "$migration_rc"
  fi

  sleep "$MIGRATION_RETRY_DELAY_SECONDS"
  i=$((i + 1))
done
if [ "$MIGRATION_SUCCEEDED" != true ]; then
  echo "entrypoint: migration did not complete; refusing to start mnemo-server" >&2
  exit 1
fi

# Hand off to the server as PID 1 (proper signal handling / graceful shutdown).
exec /usr/local/bin/mnemo-server "$@"
