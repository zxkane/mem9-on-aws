#!/bin/sh
# bootstrap entrypoint — one-shot schema + tenant seed for mem9-on-aws (§8).
#
# Runs ONCE per deploy as a short-lived ECS task, then exits 0. Idempotent: safe
# to re-run on every deploy (all DDL is IF NOT EXISTS; the tenant upsert is
# ON CONFLICT DO NOTHING). It:
#   1. assembles the DB DSN from the injected env + Secrets Manager JSON (same
#      contract as the mnemo-server entrypoint),
#   2. applies schema.sql (pgvector + control-plane tenants + memories vector(1024)
#      + idx_app + FTS/HNSW indexes),
#   3. seeds ONE active tenant row whose id IS the X-API-Key (mem9 does
#      tenants.GetByID(apiKey)); the id is supplied via MEM9_TENANT_ID so it's
#      stable across re-runs (generated once by SST, stored in Secrets Manager).
#
# Fails LOUD (set -e) — a half-applied schema must surface, not be swallowed.

set -eu

: "${MEM9_DB_HOST:?MEM9_DB_HOST required}"
: "${MEM9_DB_PORT:?MEM9_DB_PORT required}"
: "${MEM9_DB_NAME:?MEM9_DB_NAME required}"
: "${MEM9_DB_SECRET:?MEM9_DB_SECRET (Secrets Manager JSON {username,password}) required}"
: "${MEM9_TENANT_ID:?MEM9_TENANT_ID (the X-API-Key / tenants.id to seed) required}"

# The same private-network task definition also runs namespace operator
# commands. The Node entrypoint constructs MNEMO_DSN without printing it, reads
# short-lived SecureString inputs, and invokes only a fixed operation allowlist.
if [ -n "${MEM9_BOOTSTRAP_OPERATION:-}" ]; then
  case "$MEM9_BOOTSTRAP_OPERATION" in
    production-runtime)
      exec node /bootstrap/operator/scripts/production-runtime-operator.mjs ;;
    runtime-admin-probe|runtime-admin-probe-cleanup)
      exec node /bootstrap/operator/scripts/runtime-admin-probe.mjs ;;
    runtime-bootstrap|runtime-verify)
      exec node /bootstrap/operator/scripts/runtime-bootstrap.mjs ;;
    consolidation-preview-setup|consolidation-preview-pause|consolidation-preview-verify-planned|consolidation-preview-verify-executed|consolidation-preview-verify-repeated)
      exec node /bootstrap/operator/scripts/consolidation-preview-fixture.mjs ;;
  esac
  exec node /bootstrap/operator/operator-entrypoint.mjs
fi

if [ -n "${MEM9_RUNTIME_DB_SECRET:-}" ]; then
  exec node /bootstrap/operator/scripts/runtime-bootstrap.mjs
fi

DB_USER=$(printf '%s' "$MEM9_DB_SECRET" | jq -re '(.username // error("missing .username"))') || {
  echo "bootstrap: MEM9_DB_SECRET has no .username" >&2; exit 1; }
DB_PASS=$(printf '%s' "$MEM9_DB_SECRET" | jq -re '(.password // error("missing .password"))') || {
  echo "bootstrap: MEM9_DB_SECRET has no .password" >&2; exit 1; }

# psql reads the password from PGPASSWORD (never on the command line / in the
# process args). The direct Aurora connection requires TLS, as does mnemo-server.
export PGPASSWORD="$DB_PASS"
export PGSSLMODE=require
export PGCONNECT_TIMEOUT=8

PSQL="psql --host=${MEM9_DB_HOST} --port=${MEM9_DB_PORT} --username=${DB_USER} \
  --dbname=${MEM9_DB_NAME} -v ON_ERROR_STOP=1 --no-password"

# Wait for the Aurora writer endpoint to accept connections before applying the
# schema. This runs immediately after `sst deploy`; the cluster is available, but
# the first client connection can still race the final seconds of readiness.
# Retry patiently: PGCONNECT_TIMEOUT=8 plus 30 attempts with an 8-second delay is
# about five minutes worst case. Then exit non-zero with the real psql error so
# run-bootstrap-task.sh can surface whether networking, authentication, or
# database readiness failed.
echo "bootstrap: probing ${MEM9_DB_HOST}:${MEM9_DB_PORT} (patient, up to ~5 min)..."
ready=0
i=1
while [ "$i" -le 30 ]; do
  # Capture the error so the LAST failure's reason is shown if we give up.
  if PROBE_ERR=$($PSQL -tAc 'SELECT 1' 2>&1); then
    ready=1
    echo "bootstrap: DB reachable after $((i - 1)) retries"
    break
  fi
  echo "bootstrap: attempt ${i}/30 failed: ${PROBE_ERR}"
  sleep 8
  i=$((i + 1))
done
if [ "$ready" -ne 1 ]; then
  echo "bootstrap: DB unreachable after ~5 min. Last error above." >&2
  echo "bootstrap: (common causes: Aurora SG blocks 5432 from the task SG; writer not ready; bad creds)" >&2
  exit 1
fi

echo "bootstrap: applying schema to ${MEM9_DB_HOST}:${MEM9_DB_PORT}/${MEM9_DB_NAME} (user ${DB_USER})"
$PSQL -f /bootstrap/schema.sql

# Seed with bound parameters inside Node; no password or tenant API key is
# written into process arguments, interpolated SQL, or bootstrap output.
node /bootstrap/operator/scripts/seed-tenant.mjs

if [ -n "${MEM9_PREVIEW_NAMESPACE_ALPHA_CLIENT_ID:-}" ]; then
  echo "bootstrap: preparing isolated PR namespace fixtures"
  node /bootstrap/operator/scripts/prepare-preview-memory-namespaces.mjs
fi

echo "bootstrap: done — schema applied and tenant binding active"
