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

if [ -z "${MNEMO_DSN:-}" ]; then
  : "${MEM9_DB_HOST:?MEM9_DB_HOST is required to assemble MNEMO_DSN}"
  : "${MEM9_DB_PORT:?MEM9_DB_PORT is required to assemble MNEMO_DSN}"
  : "${MEM9_DB_NAME:?MEM9_DB_NAME is required to assemble MNEMO_DSN}"
  : "${MEM9_DB_SECRET:?MEM9_DB_SECRET (Secrets Manager JSON) is required to assemble MNEMO_DSN}"

  # Extract user + password from the secret JSON and URL-encode BOTH (the
  # password can hold DSN-reserved chars; the username is encoded defensively).
  # The field is validated for null/absence BEFORE @uri: `jq -e '.x | @uri'`
  # would turn a null field into the STRING "null" (a truthy output → exit 0),
  # silently producing "postgres://null:null@...". So assert non-null first
  # (`// error(...)` → jq exits 5), THEN encode. The value is never printed —
  # only the field name appears in the error message.
  extract_field() {
    printf '%s' "$MEM9_DB_SECRET" | jq -re "(.$1 // error(\"missing .$1\")) | @uri" || {
      echo "entrypoint: MEM9_DB_SECRET has no .$1 field" >&2
      exit 1
    }
  }
  DB_USER=$(extract_field username)
  DB_PASS=$(extract_field password)

  # sslmode=require protects the direct Aurora connection; mem9 uses the pgx
  # stdlib driver, which honors the DSN query parameter.
  export MNEMO_DSN="postgres://${DB_USER}:${DB_PASS}@${MEM9_DB_HOST}:${MEM9_DB_PORT}/${MEM9_DB_NAME}?sslmode=require"

  # Log the DSN with the password redacted (host/port/db/user are safe to show
  # and help diagnose connectivity; the secret value never appears in logs).
  echo "entrypoint: assembled MNEMO_DSN=postgres://${DB_USER}:***@${MEM9_DB_HOST}:${MEM9_DB_PORT}/${MEM9_DB_NAME}?sslmode=require"
fi

# Apply the repeatable atomic-ingest migration before the process can become
# healthy or route durable jobs. PGDATABASE keeps the credential-bearing DSN
# out of the process arguments visible through `ps`.
PGDATABASE="$MNEMO_DSN" psql -q -v ON_ERROR_STOP=1 \
  -f /usr/local/share/mem9/001_ingest_jobs.sql

# Hand off to the server as PID 1 (proper signal handling / graceful shutdown).
exec /usr/local/bin/mnemo-server "$@"
