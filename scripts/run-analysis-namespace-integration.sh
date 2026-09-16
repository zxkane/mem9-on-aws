#!/usr/bin/env bash

# TC-GROUPNS-105: real psql evaluation over populated synthetic namespaces.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONTAINER="mem9-analysis-${BASHPID}-${RANDOM}"
DATABASE="analysis_test"
TMP_DIR=$(mktemp -d)
cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

docker run -d --name "$CONTAINER" -e POSTGRES_PASSWORD=test \
  -e "POSTGRES_DB=$DATABASE" pgvector/pgvector:pg17 >/dev/null
ready=false
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" sh -c 'test "$(cat /proc/1/comm)" = postgres' &&
    docker exec "$CONTAINER" pg_isready -U postgres -d "$DATABASE" >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
[[ "$ready" == true ]] || { echo "analysis PostgreSQL fixture did not start" >&2; exit 1; }
docker cp "$ROOT/docker/bootstrap/." "$CONTAINER:/bootstrap"
docker cp "$ROOT/scripts/analyze-ingest-prescreen.sql" "$CONTAINER:/analysis.sql"
docker exec "$CONTAINER" psql -q -U postgres -d "$DATABASE" \
  -v ON_ERROR_STOP=1 -f /bootstrap/schema.sql >"$TMP_DIR/schema.log" 2>&1

sql() {
  docker exec -i "$CONTAINER" psql -q -U postgres -d "$DATABASE" -v ON_ERROR_STOP=1
}
sql <<'SQL'
INSERT INTO memory_namespaces (namespace_id, slug, display_name) VALUES
 ('60000000-0000-4000-8000-000000000001', 'analysis-a', 'Analysis A'),
 ('60000000-0000-4000-8000-000000000002', 'analysis-b', 'Analysis B'),
 ('60000000-0000-4000-8000-000000000003', 'analysis-denied', 'Analysis Denied');
INSERT INTO memory_principals (principal_id, principal_key, principal_type) VALUES
 ('70000000-0000-4000-8000-000000000001',
  encode(sha256(convert_to('mem9-service-principal-v1','UTF8') || decode('00','hex') || convert_to('analysis','UTF8')), 'hex'), 'service'),
 ('70000000-0000-4000-8000-000000000002', repeat('a', 64), 'service');
INSERT INTO memory_namespace_memberships (namespace_id, principal_id, role, source_type) VALUES
 ('60000000-0000-4000-8000-000000000001', '70000000-0000-4000-8000-000000000001', 'viewer', 'service'),
 ('60000000-0000-4000-8000-000000000002', '70000000-0000-4000-8000-000000000001', 'viewer', 'service'),
 ('60000000-0000-4000-8000-000000000003', '70000000-0000-4000-8000-000000000002', 'owner', 'service');
INSERT INTO ingest_jobs (job_id, tenant_id, namespace_id, principal_id, idempotency_key, state, canonical_payload)
SELECT '80000000-0000-4000-8000-' || lpad(n::text, 12, '0'), 'fixture-tenant',
 CASE WHEN n=1 THEN '60000000-0000-4000-8000-000000000001' ELSE '60000000-0000-4000-8000-000000000002' END,
 '70000000-0000-4000-8000-000000000001', lpad(n::text, 64, '0'), 'succeeded',
 convert_to('{"messages":[{"role":"user","content":"PRIVATE_FIXTURE_PAYLOAD"}]}', 'UTF8')
FROM generate_series(1, 3) n;
INSERT INTO ingest_job_plans (tenant_id, namespace_id, job_id, plan_revision, attempt_generation, plan_hash, plan_payload, state, applied_at)
SELECT tenant_id, namespace_id, job_id, 1, 1, repeat('f',64),
 convert_to('{"zero_fact":true,"actions":[]}', 'UTF8'), 'applied', '2001-01-20T00:00:00Z'
FROM ingest_jobs;
SQL

analyze() {
  docker exec -e PGOPTIONS='-c default_transaction_read_only=on' "$CONTAINER" \
    psql -qAt -U postgres -d "$DATABASE" -v ON_ERROR_STOP=1 \
    -v "namespace_id=$1" -v analysis_cutoff=2001-02-01T00:00:00Z \
    -v label_start=2001-01-01T00:00:00Z \
    -v service_principal_id=70000000-0000-4000-8000-000000000002 -f /analysis.sql
}
assert_count() {
  local namespace=$1 count=$2
  analyze "$namespace" >"$TMP_DIR/results.jsonl"
  python3 - "$TMP_DIR/results.jsonl" "$count" <<'PY'
import json,sys
text=open(sys.argv[1]).read()
rows=[json.loads(line) for line in text.splitlines() if line.strip()]
baseline=next(row['data'] for row in rows if row['section']=='baseline')
assert baseline['sessions']==int(sys.argv[2]), baseline
assert any(row['section']=='complete' and row['data']['consistent'] for row in rows)
assert 'PRIVATE_FIXTURE_PAYLOAD' not in text and 'fixture-tenant' not in text
assert '60000000-' not in text and '70000000-' not in text and '80000000-' not in text
PY
}
assert_denied() {
  if analyze "$1" >"$TMP_DIR/denied.out" 2>"$TMP_DIR/denied.err"; then
    echo "unauthorized analysis succeeded" >&2
    exit 1
  fi
  grep -q 'analysis namespace access denied' "$TMP_DIR/denied.err"
  [[ ! -s "$TMP_DIR/denied.out" ]] || { echo "denied analysis emitted results" >&2; exit 1; }
}

assert_count 60000000-0000-4000-8000-000000000001 1
assert_count 60000000-0000-4000-8000-000000000002 2
# Another service's owner membership cannot substitute for the fixed analysis identity.
assert_denied 60000000-0000-4000-8000-000000000003
assert_denied 60000000-0000-4000-8000-000000000004

sql <<'SQL'
UPDATE ingest_jobs SET canonical_payload=convert_to('FOREIGN_MALFORMED_JSON','UTF8')
WHERE namespace_id='60000000-0000-4000-8000-000000000002';
UPDATE memory_namespace_memberships SET status='revoked'
WHERE namespace_id='60000000-0000-4000-8000-000000000002';
SQL
assert_count 60000000-0000-4000-8000-000000000001 1
# Reject before attempting to decode the revoked namespace's deliberately bad payload.
assert_denied 60000000-0000-4000-8000-000000000002

sql <<'SQL'
UPDATE memory_principals SET status='disabled' WHERE principal_id='70000000-0000-4000-8000-000000000001';
SQL
assert_denied 60000000-0000-4000-8000-000000000001
sql <<'SQL'
UPDATE memory_principals SET status='active' WHERE principal_id='70000000-0000-4000-8000-000000000001';
UPDATE memory_namespaces SET status='disabled' WHERE namespace_id='60000000-0000-4000-8000-000000000001';
SQL
assert_denied 60000000-0000-4000-8000-000000000001
echo "namespace analysis PostgreSQL integration: OK"
