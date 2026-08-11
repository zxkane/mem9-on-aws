#!/usr/bin/env bash
# run-mcp-e2e.sh — live end-to-end test of the MCP surface (§6/§6a).
#
# This is the live write→search round-trip for the whole project.
# It proves the full chain works against a deployed stage:
#   Cognito M2M JWT → AgentCore Gateway (MCP) → VPC-attached proxy Lambda
#   → Cloud Map private DNS → mnemo-server → Aurora writer endpoint
#   → qwen3-embed sidecar → search.
#
# Steps:
#   1. Wait for the ECS service to stabilize and verify every running task uses
#      the service's active task definition.
#   2. Read the Cognito token endpoint + client id/secret + scope, and the Gateway
#      MCP URL, from the stage's SSM parameters.
#   3. Mint a Cognito `client_credentials` JWT at the token endpoint.
#   4. Call the `add_memory` MCP tool via the Gateway (JSON-RPC `tools/call`).
#   5. Poll the `search_memories` tool until the written memory surfaces — mem9
#      ingest is ASYNC (a write returns "accepted"; it's searchable seconds later),
#      so this retries up to ~5 min before failing.
#
# Env:
#   STAGE       (required) — e.g. prod / pr-7.
#   AWS_REGION  (optional) — defaults to the SST application region.
#   E2E_COGNITO_CLIENT_PREFIX (optional) — SSM prefix containing client-id and
#               client-secret. Defaults to /mem9-on-aws/<stage>/cognito. Recovery
#               uses a dedicated client under a separate prefix.
#   E2E_EXPECTED_DB_CLUSTER_IDENTIFIER (optional) — fail unless the active task
#               definition's MEM9_DB_HOST is the writer endpoint of this cluster.
#   E2E_SOFT    (optional) — if "1", a search-timeout logs a ::warning:: and exits 0
#               (used on PR previews where async timing can flake); default hard-fails.

set -euo pipefail

STAGE="${STAGE:?STAGE is required (e.g. prod or pr-7)}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="${AWS_REGION:-$(node "$REPO_ROOT/scripts/resolve-application-region.mjs")}"
PREFIX="/mem9-on-aws/${STAGE}"
COGNITO_CLIENT_PREFIX="${E2E_COGNITO_CLIENT_PREFIX:-${PREFIX}/cognito}"
SOFT="${E2E_SOFT:-0}"

ssm() { aws ssm get-parameter --name "$1" --region "$REGION" --with-decryption --query Parameter.Value --output text; }

echo "run-mcp-e2e: waiting for the ECS service to converge"
ECS_CLUSTER=$(ssm "${PREFIX}/ecs/cluster-name")
ECS_SERVICE=$(ssm "${PREFIX}/ecs/service-name")
aws ecs wait services-stable \
  --cluster "$ECS_CLUSTER" \
  --services "$ECS_SERVICE" \
  --region "$REGION"

SERVICE_JSON=$(aws ecs describe-services \
  --cluster "$ECS_CLUSTER" \
  --services "$ECS_SERVICE" \
  --region "$REGION" \
  --output json)
ACTIVE_TASK_DEFINITION=$(printf '%s' "$SERVICE_JSON" | jq -r '.services[0].taskDefinition // ""')
TASK_ARNS_JSON=$(aws ecs list-tasks \
  --cluster "$ECS_CLUSTER" \
  --service-name "$ECS_SERVICE" \
  --desired-status RUNNING \
  --region "$REGION" \
  --query taskArns \
  --output json)

if [[ -z "$ACTIVE_TASK_DEFINITION" || "$ACTIVE_TASK_DEFINITION" == "null" ]] ||
  ! printf '%s' "$TASK_ARNS_JSON" | jq -e 'length > 0' >/dev/null; then
  echo "::error::ECS service has no active task definition or running task"
  exit 1
fi

TASKS_JSON=$(aws ecs describe-tasks \
  --cluster "$ECS_CLUSTER" \
  --tasks $(printf '%s' "$TASK_ARNS_JSON" | jq -r '.[]') \
  --region "$REGION" \
  --output json)
TASK_DEF_MISMATCHES=$(printf '%s' "$TASKS_JSON" | jq --arg active "$ACTIVE_TASK_DEFINITION" \
  '[.tasks[] | select(.taskDefinitionArn != $active)] | length')
if [[ "$TASK_DEF_MISMATCHES" != "0" ]]; then
  echo "::error::${TASK_DEF_MISMATCHES} running ECS task(s) do not use the active task definition"
  exit 1
fi

if [[ -n "${E2E_EXPECTED_DB_CLUSTER_IDENTIFIER:-}" ]]; then
  EXPECTED_DB_HOST=$(aws rds describe-db-clusters \
    --db-cluster-identifier "$E2E_EXPECTED_DB_CLUSTER_IDENTIFIER" \
    --region "$REGION" \
    --query 'DBClusters[0].Endpoint' \
    --output text)
  TASK_DEFINITION_JSON=$(aws ecs describe-task-definition \
    --task-definition "$ACTIVE_TASK_DEFINITION" \
    --region "$REGION" \
    --output json)
  ACTIVE_DB_HOST=$(printf '%s' "$TASK_DEFINITION_JSON" | jq -r \
    '.taskDefinition.containerDefinitions[]
     | select(.name == "mnemo-server")
     | .environment[]
     | select(.name == "MEM9_DB_HOST")
     | .value')
  if [[ -z "$EXPECTED_DB_HOST" || "$EXPECTED_DB_HOST" == "None" ||
    "$ACTIVE_DB_HOST" != "$EXPECTED_DB_HOST" ]]; then
    echo "::error::active ECS task definition does not target the expected recovery cluster"
    exit 1
  fi
fi
echo "run-mcp-e2e: ECS service stable; all running tasks use the active task definition"

echo "run-mcp-e2e: reading MCP config from SSM ${PREFIX}/{cognito,gateway}/* (region ${REGION})"
TOKEN_ENDPOINT=$(ssm "${PREFIX}/cognito/token-endpoint")
CLIENT_ID=$(ssm "${COGNITO_CLIENT_PREFIX}/client-id")
CLIENT_SECRET=$(ssm "${COGNITO_CLIENT_PREFIX}/client-secret")
SCOPE=$(ssm "${PREFIX}/cognito/scope")
GATEWAY_URL=$(ssm "${PREFIX}/gateway/url")

if [[ -z "$TOKEN_ENDPOINT" || -z "$CLIENT_ID" || -z "$GATEWAY_URL" ]]; then
  echo "::error::missing MCP SSM params under ${PREFIX} — has sst deploy run for this stage?"
  exit 1
fi

# 2. Mint the M2M JWT (client_credentials). Cognito wants form-encoded creds.
echo "run-mcp-e2e: minting Cognito M2M token at ${TOKEN_ENDPOINT}"
TOKEN_RESP=$(curl -fsS -X POST "$TOKEN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -d "grant_type=client_credentials&scope=$(printf '%s' "$SCOPE" | sed 's/ /%20/g')" 2>&1) || {
    echo "::error::Cognito token request failed: $TOKEN_RESP"; exit 1; }
JWT=$(printf '%s' "$TOKEN_RESP" | jq -r '.access_token // ""')
if [[ -z "$JWT" || "$JWT" == "null" ]]; then
  echo "::error::no access_token in Cognito response: $TOKEN_RESP"; exit 1
fi
echo "run-mcp-e2e: got JWT (len ${#JWT})"

# A unique marker so the search unambiguously finds THIS run's memory.
MARKER="mcp-e2e-${STAGE}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
MEMORY_TEXT="mem9 MCP e2e probe: the secret marker is ${MARKER}."

# MCP streamable-HTTP session id (captured from initialize; propagated on later
# calls if the Gateway is stateful). Empty is fine for a stateless Gateway.
MCP_SESSION=""

# Low-level MCP JSON-RPC POST. Captures response headers (for Mcp-Session-Id) and
# body. The Gateway may reply as application/json OR text/event-stream (SSE); the
# body parser (mcp_result) handles both.
mcp_post() {  # $1 = method, $2 = params JSON  → sets MCP_RESP (body) + MCP_SESSION
  local hdrs body
  hdrs=$(mktemp)
  body=$(curl -sS -D "$hdrs" -X POST "$GATEWAY_URL" \
    -H "Authorization: Bearer ${JWT}" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    ${MCP_SESSION:+-H "Mcp-Session-Id: ${MCP_SESSION}"} \
    -d "$(jq -nc --arg m "$1" --argjson p "$2" \
      '{jsonrpc:"2.0", id:1, method:$m, params:$p}')" 2>&1)
  # Capture a session id from the response headers if the Gateway issued one.
  local sid
  sid=$(grep -i '^mcp-session-id:' "$hdrs" 2>/dev/null | head -1 | sed 's/^[^:]*: *//' | tr -d '\r' || true)
  [[ -n "$sid" ]] && MCP_SESSION="$sid"
  rm -f "$hdrs"
  MCP_RESP="$body"
}

# Extract the JSON-RPC `result` from an MCP response body — handles both a plain
# JSON body and an SSE stream (lines of `data: {...}`). Returns the raw result JSON.
mcp_result() {  # stdin = response body → stdout = .result (or empty)
  # Try plain JSON first; if that fails, pull the last `data:` SSE frame.
  local raw; raw=$(cat)
  local r; r=$(printf '%s' "$raw" | jq -c '.result // empty' 2>/dev/null || true)
  if [[ -z "$r" ]]; then
    r=$(printf '%s' "$raw" | sed -n 's/^data: //p' | tail -1 | jq -c '.result // empty' 2>/dev/null || true)
  fi
  printf '%s' "$r"
}

# 3a. MCP handshake: initialize (some Gateways require it + issue a session id).
echo "run-mcp-e2e: MCP initialize"
mcp_post "initialize" '{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"mem9-e2e","version":"1"}}'
echo "run-mcp-e2e: initialize response: $(printf '%s' "$MCP_RESP" | head -c 200)${MCP_SESSION:+ (session ${MCP_SESSION})}"

# 3b. Resolve the actual tool names. AgentCore Gateway namespaces OpenAPI-target
# tools (commonly `<target>___<operationId>`), so match by suffix rather than
# hardcoding the bare operationId.
mcp_post "tools/list" '{}'
TOOLS_JSON=$(printf '%s' "$MCP_RESP" | mcp_result)
resolve_tool() {  # $1 = operationId suffix → prints the full exposed tool name
  printf '%s' "$TOOLS_JSON" | jq -r --arg s "$1" \
    '(.tools // [])[] | select(.name | endswith($s)) | .name' 2>/dev/null | head -1
}
ADD_TOOL=$(resolve_tool "add_memory")
SEARCH_TOOL=$(resolve_tool "search_memories")
echo "run-mcp-e2e: resolved tools — add='${ADD_TOOL:-?}' search='${SEARCH_TOOL:-?}'"
if [[ -z "$ADD_TOOL" || -z "$SEARCH_TOOL" ]]; then
  echo "::error::Gateway tools/list did not expose add_memory/search_memories. tools/list result: $(printf '%s' "$TOOLS_JSON" | head -c 500)"
  exit 1
fi

tools_call() {  # $1 = tool name, $2 = args JSON → sets MCP_RESP
  mcp_post "tools/call" "$(jq -nc --arg name "$1" --argjson args "$2" '{name:$name, arguments:$args}')"
}

# 3c. add_memory — retry a few times. The gateway invokes a VPC-attached proxy
# Lambda that reaches mnemo-server over Cloud Map DNS; on a fresh stage the first
# calls can transiently fail (Lambda cold-start DNS / task just-registered) and the
# gateway returns isError. Retry with backoff before treating it as a real failure.
echo "run-mcp-e2e: calling ${ADD_TOOL} (marker ${MARKER})"
ADD_OK=0
for attempt in 1 2 3 4 5; do
  tools_call "$ADD_TOOL" "$(jq -nc --arg c "$MEMORY_TEXT" '{content:$c}')"
  echo "run-mcp-e2e: add_memory attempt ${attempt} response: $(printf '%s' "$MCP_RESP" | head -c 300)"
  if printf '%s' "$MCP_RESP" | grep -qiE '"isError":true|"code":-3[0-9]{4}'; then
    sleep 15
    continue
  fi
  ADD_OK=1
  break
done
if [[ "$ADD_OK" != "1" ]]; then
  echo "::error::add_memory returned an MCP error after retries: $MCP_RESP"; exit 1
fi

# 4. Poll search_memories until the marker surfaces (async ingest → retry ~5 min).
echo "run-mcp-e2e: polling ${SEARCH_TOOL} for the marker (async ingest; up to ~5 min)"
DEADLINE=$((SECONDS + 300))
FOUND=0
SEARCH_RESP=""
while [[ $SECONDS -lt $DEADLINE ]]; do
  tools_call "$SEARCH_TOOL" "$(jq -nc --arg q "$MARKER" '{q:$q, limit:5}')"
  SEARCH_RESP="$MCP_RESP"
  if printf '%s' "$SEARCH_RESP" | grep -qF "$MARKER"; then
    FOUND=1
    break
  fi
  sleep 15
done

if [[ "$FOUND" != "1" ]]; then
  MSG="search_memories did not surface the marker within ~5 min (async ingest may be slow or the chain is broken). Last response: $(printf '%s' "${SEARCH_RESP:-}" | head -c 400)"
  if [[ "$SOFT" == "1" ]]; then
    echo "::warning::${MSG}"
    exit 0
  fi
  echo "::error::${MSG}"
  exit 1
fi
echo "run-mcp-e2e: OK — write→search round-trip verified (marker found) for stage ${STAGE}"

# 5. Natural-language recall probe (TC-RECALL-031, issue #23). The keyword
# search above proves the memory is indexed; now assert that a long (≥25 char)
# natural-language query — the style the recall hooks instruct agents to use —
# returns a NON-EMPTY result set. That is the exact #23 regression signature:
# the hard-coded min_confidence cutoff rejected ALL candidates for long
# queries (cutoff_reason=min_confidence, 88% zero-hit) regardless of match
# quality. Rank ORDER is deliberately NOT asserted: on a long-lived tenant
# (prod) hundreds of real memories legitimately compete for the top-N, so
# "this run's marker in the top 10" is a flakiness generator, not a
# regression guard (bit run 30085629030). Finding the marker is logged as a
# bonus signal when it happens.
#
# The query MUST NOT interpolate the run id or the marker (issue #137). A
# run-scoped high-cardinality literal makes retrieval return ZERO candidates, so
# the cutoff never runs at all and the server logs cutoff_reason=no_candidates —
# not the min_confidence signature this probe exists to catch. The previous query
# here interpolated the run id and was therefore deterministically zero: the probe
# failed every prod deploy on a condition unrelated to #23. A leading "what " also
# classifies the query as shape=exact upstream, which reorders candidate buckets,
# but shape alone is not the cause — a shape=general query carrying the marker also
# returns zero. Queries built from the memory's ordinary words retrieve reliably.
#
# So: keep the query free of the run id and the marker. Reintroducing either turns
# a #23 cutoff guard back into a retrieval check that always fails. To re-measure,
# compare a query's `total` here against the server's `confidence recall search`
# log line for the same window, which reports shape and candidate count.
NL_QUERY="recall what the mem9 end-to-end probe recorded about its secret marker"
echo "run-mcp-e2e: natural-language recall probe (query: ${NL_QUERY})"
NL_NONEMPTY=0
for attempt in 1 2 3; do
  tools_call "$SEARCH_TOOL" "$(jq -nc --arg q "$NL_QUERY" '{q:$q, limit:10}')"
  NL_TOTAL=$(printf '%s' "$MCP_RESP" | mcp_result | jq -r '.content[0].text // "{}" | fromjson | .total // 0' 2>/dev/null || echo 0)
  if [[ "$NL_TOTAL" =~ ^[0-9]+$ && "$NL_TOTAL" -gt 0 ]]; then
    NL_NONEMPTY=1
    if printf '%s' "$MCP_RESP" | grep -qF "$MARKER"; then
      echo "run-mcp-e2e: NL probe bonus — this run's marker ranked in the top ${NL_TOTAL}"
    fi
    break
  fi
  sleep 10
done

if [[ "$NL_NONEMPTY" != "1" ]]; then
  # Do NOT name a root cause here. The MCP response carries only
  # {limit,memories,offset,total} — `cutoff_reason` is a server-side slog field,
  # not part of the payload — so a client-side zero-result is consistent with a
  # min_confidence cutoff regression (#23) AND with retrieval simply returning no
  # candidates. The previous wording asserted #23 unconditionally and sent the
  # last three prod investigations down the wrong path. Point at the log line
  # that actually discriminates instead.
  MSG="natural-language recall probe returned ZERO results for query: ${NL_QUERY} — check the mnemo-server 'confidence recall search' log line for this window: cutoff_reason=min_confidence with non-zero candidates is the issue #23 cutoff regression; cutoff_reason=no_candidates means retrieval/embedding returned nothing and #23 is NOT implicated. Last response: $(printf '%s' "${MCP_RESP:-}" | head -c 400)"
  if [[ "$SOFT" == "1" ]]; then
    echo "::warning::${MSG}"
    exit 0
  fi
  echo "::error::${MSG}"
  exit 1
fi
echo "run-mcp-e2e: OK — natural-language recall verified (non-empty, ${NL_TOTAL} results) for stage ${STAGE}"

# 6. Log-scan hardening (TC-OBS-010, issue #26). Scan the mnemo-server log
# group for LLM auth failures (401s) that occurred during this E2E run window.
# A 401 means the llm-proxy bearer is dead — smart-ingest data is being lost
# silently (the 2026-07-22 incident). HARD fail on any 401 regardless of
# E2E_SOFT — an auth failure is never a timing flake.
#
# The group name comes from the ACTIVE task definition's mnemo-server
# awslogs-group — the only reliable source. SST auto-names container log groups
# with random hash segments and sets ignoreChanges:["name"], so the hand-computed
# "/sst/cluster/mem9-on-aws-<stage>/mnemo-server" this used to assume matches no
# real group on any stage: prod's is
# /sst/cluster/<cluster>-<hash>/<service>-<hash>/mnemo-server. start-query
# answered ResourceNotFoundException every time and the old `2>/dev/null || true`
# turned that into an empty QUERY_ID, i.e. the "log group may not exist yet"
# skip. This guard had therefore never run once, on any stage (issue #137).
# infra/ecs.ts derives the alarm's group the same way for the same reason.
LOG_GROUP=$(aws ecs describe-task-definition \
  --task-definition "$ACTIVE_TASK_DEFINITION" \
  --region "$REGION" \
  --output json | jq -r \
  '.taskDefinition.containerDefinitions[]
   | select(.name == "mnemo-server")
   | .logConfiguration.options["awslogs-group"] // empty')
if [[ -z "$LOG_GROUP" ]]; then
  echo "::error::could not read the mnemo-server awslogs-group from task definition ${ACTIVE_TASK_DEFINITION} — the issue #26 log-scan guard cannot run"
  exit 1
fi

echo "run-mcp-e2e: log-scan for auth failures in ${LOG_GROUP} (last 10 min)"
SCAN_START=$(( $(date +%s) - 600 ))000
SCAN_END=$(date +%s)000

# stderr goes to a FILE, never merged into a captured value with `2>&1`: the real
# CLI writes to stderr on SUCCESSFUL calls too (a botocore deprecation notice, a
# credential-source line), and merging that into the JSON below would break `jq`
# on a call that actually worked.
ERR_FILE=$(mktemp)
trap 'rm -f "$ERR_FILE"' EXIT

scan_for_auth_failures() {
  local query_id out status auth_failures
  query_id=$(aws logs start-query --region "$REGION" \
    --log-group-name "$LOG_GROUP" \
    --start-time "$SCAN_START" --end-time "$SCAN_END" \
    --query-string 'filter msg = "extraction LLM call failed" and err like /401/' \
    --output text 2>"$ERR_FILE") || query_id=""

  if [[ -z "$query_id" ]]; then
    # An absent log group is the ONE legitimate skip: a brand-new stage whose
    # service has not written a log event yet. Every other start-query failure
    # (throttling, an IAM regression, a malformed query string) means this guard
    # did not run — and scoring that as "clean" is exactly how a dead llm-proxy
    # bearer stayed invisible for weeks.
    if grep -q 'ResourceNotFoundException' "$ERR_FILE"; then
      echo "run-mcp-e2e: log-scan skipped — ${LOG_GROUP} does not exist yet (fresh stage, no service logs)"
      return 0
    fi
    echo "::error::log-scan could not start a Logs Insights query on ${LOG_GROUP}: $(head -c 400 "$ERR_FILE")"
    return 1
  fi

  # Wait for the query to actually finish. A Running query returns an EMPTY
  # results array, which the previous single `sleep 5` + one read scored as
  # "clean" whenever Insights took longer than five seconds.
  status="Unknown"
  for _ in {1..20}; do
    out=$(aws logs get-query-results --region "$REGION" \
      --query-id "$query_id" --output json 2>"$ERR_FILE") || {
      echo "::error::log-scan get-query-results failed on ${LOG_GROUP}: $(head -c 400 "$ERR_FILE")"
      return 1
    }
    status=$(printf '%s' "$out" | jq -r '.status // "Unknown"')
    [[ "$status" == "Running" || "$status" == "Scheduled" ]] || break
    sleep 3
  done
  if [[ "$status" != "Complete" ]]; then
    echo "::error::log-scan query on ${LOG_GROUP} ended in status ${status} (not Complete) — the issue #26 auth-failure guard did not run"
    return 1
  fi

  auth_failures=$(printf '%s' "$out" | jq -r '.results | length')
  if [[ "$auth_failures" != "0" ]]; then
    echo "::error::log-scan found ${auth_failures} LLM auth failure(s) (401) in ${LOG_GROUP} during the E2E window — llm-proxy bearer may be dead (issue #24 regression). Investigate immediately."
    return 1
  fi
  echo "run-mcp-e2e: log-scan clean — no auth failures in ${LOG_GROUP} in the last 10 min"
}

scan_for_auth_failures || exit 1
