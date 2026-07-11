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

DB_USER=$(printf '%s' "$MEM9_DB_SECRET" | jq -re '(.username // error("missing .username"))') || {
  echo "bootstrap: MEM9_DB_SECRET has no .username" >&2; exit 1; }
DB_PASS=$(printf '%s' "$MEM9_DB_SECRET" | jq -re '(.password // error("missing .password"))') || {
  echo "bootstrap: MEM9_DB_SECRET has no .password" >&2; exit 1; }

# psql reads the password from PGPASSWORD (never on the command line / in the
# process args). TLS required (RDS Proxy mandates it), same as mnemo-server.
export PGPASSWORD="$DB_PASS"
export PGSSLMODE=require
export PGCONNECT_TIMEOUT=15

PSQL="psql --host=${MEM9_DB_HOST} --port=${MEM9_DB_PORT} --username=${DB_USER} \
  --dbname=${MEM9_DB_NAME} -v ON_ERROR_STOP=1 --no-password"

echo "bootstrap: applying schema to ${MEM9_DB_HOST}:${MEM9_DB_PORT}/${MEM9_DB_NAME} (user ${DB_USER})"
$PSQL -f /bootstrap/schema.sql

# Seed one active tenant. id == X-API-Key. The tenant's db_* point at THIS Aurora
# (single operator, one active tenant on the same cluster).
#
# db_user + db_password MUST be the REAL working credentials: on EVERY request
# mem9's auth middleware reads the tenant row, decrypts db_password
# (MNEMO_ENCRYPT_TYPE=plain by default → used literally), and opens a PER-TENANT
# connection via DSNForBackend =
# postgres://<db_user>:<db_password>@<db_host>:<db_port>/<db_name>?sslmode=require
# (verified in mem9 middleware/auth.go + domain/types.go). A placeholder password
# would make every add/search fail auth at query time. So we write the actual
# proxy username+password (from MEM9_DB_SECRET) into the row. db_tls=TRUE →
# sslmode=require (RDS Proxy mandates TLS).
#
# Passed to psql as VARIABLES (:'var' → correctly-quoted literal), never
# interpolated into the SQL text or argv, so the password isn't in shell
# history/process args. It IS stored in the tenants table — that is mem9's
# plain-mode design; the DB is the operator's own and the same password already
# authenticates the proxy hop. (MNEMO_ENCRYPT_TYPE=kms could encrypt it at rest
# later — recorded as a follow-up, not needed for launch.)
echo "bootstrap: seeding tenant ${MEM9_TENANT_ID} (idempotent)"
$PSQL \
  --set=tid="$MEM9_TENANT_ID" \
  --set=duser="$DB_USER" \
  --set=dpass="$DB_PASS" \
  --set=dhost="$MEM9_DB_HOST" \
  --set=dport="$MEM9_DB_PORT" \
  --set=dname="$MEM9_DB_NAME" <<'SQL'
INSERT INTO tenants (id, name, db_host, db_port, db_user, db_password, db_name, db_tls, provider, status, schema_version)
VALUES (
  :'tid',
  'mem9-on-aws',
  :'dhost',
  :'dport'::int,
  :'duser',
  :'dpass',
  :'dname',
  TRUE,
  'self-hosted',
  'active',
  1
)
ON CONFLICT (id) DO UPDATE SET
  db_host     = EXCLUDED.db_host,
  db_port     = EXCLUDED.db_port,
  db_user     = EXCLUDED.db_user,
  db_password = EXCLUDED.db_password,
  db_name     = EXCLUDED.db_name,
  db_tls      = EXCLUDED.db_tls,
  status      = 'active',
  updated_at  = NOW();
SQL

echo "bootstrap: done — schema applied + tenant ${MEM9_TENANT_ID} active"
