#!/usr/bin/env bash
# run-mcp-e2e.sh — live end-to-end test of the MCP surface (§6/§6a).
#
# This is the FIRST exercisable write→search round-trip for the whole project.
# It proves the full chain works against a deployed stage:
#   Cognito M2M JWT → AgentCore Gateway (MCP) → managed VPC Lattice → internal ALB
#   (public-cert TLS) → mnemo-server → Aurora → qwen3 embed → search.
#
# Steps:
#   1. Read the Cognito token endpoint + client id/secret + scope, and the Gateway
#      MCP URL, from the /mem9-on-aws/<stage>/... SSM params this stage exported.
#   2. Mint a Cognito `client_credentials` JWT at the token endpoint.
#   3. Call the `add_memory` MCP tool via the Gateway (JSON-RPC `tools/call`).
#   4. Poll the `search_memories` tool until the written memory surfaces — mem9
#      ingest is ASYNC (a write returns "accepted"; it's searchable seconds later),
#      so this retries up to ~5 min before failing.
#
# Env:
#   STAGE       (required) — e.g. prod / pr-7.
#   AWS_REGION  (optional) — defaults to ap-northeast-1.
#   E2E_SOFT    (optional) — if "1", a search-timeout logs a ::warning:: and exits 0
#               (used on PR previews where async timing can flake); default hard-fails.

set -euo pipefail

STAGE="${STAGE:?STAGE is required (e.g. prod or pr-7)}"
REGION="${AWS_REGION:-ap-northeast-1}"
PREFIX="/mem9-on-aws/${STAGE}"
SOFT="${E2E_SOFT:-0}"

ssm() { aws ssm get-parameter --name "$1" --region "$REGION" --with-decryption --query Parameter.Value --output text; }

echo "run-mcp-e2e: reading MCP config from SSM ${PREFIX}/{cognito,gateway}/* (region ${REGION})"
TOKEN_ENDPOINT=$(ssm "${PREFIX}/cognito/token-endpoint")
CLIENT_ID=$(ssm "${PREFIX}/cognito/client-id")
CLIENT_SECRET=$(ssm "${PREFIX}/cognito/client-secret")
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
# also surfaces it. Before the recall-threshold fix these scored below the
# hard-coded min_confidence and returned 0 results (the cutoff rejected ALL
# candidates regardless of rank, so an anchored sentence still regresses).
# The run id anchors the query to THIS run's memory: probe memories from past
# deploys accumulate in the tenant, and an unanchored query would compete with
# them for the top-N. The memory is already searchable, so the short retry
# loop only absorbs transient gateway errors.
NL_QUERY="what secret marker did the e2e probe store for run ${GITHUB_RUN_ID:-local}"
echo "run-mcp-e2e: natural-language recall probe (query: ${NL_QUERY})"
NL_FOUND=0
for attempt in 1 2 3; do
  tools_call "$SEARCH_TOOL" "$(jq -nc --arg q "$NL_QUERY" '{q:$q, limit:10}')"
  if printf '%s' "$MCP_RESP" | grep -qF "$MARKER"; then
    NL_FOUND=1
    break
  fi
  sleep 10
done

if [[ "$NL_FOUND" != "1" ]]; then
  MSG="natural-language recall probe failed: an indexed memory was not returned for a NL query (recall min_confidence regression? see issue #23). Last response: $(printf '%s' "${MCP_RESP:-}" | head -c 400)"
  if [[ "$SOFT" == "1" ]]; then
    echo "::warning::${MSG}"
    exit 0
  fi
  echo "::error::${MSG}"
  exit 1
fi
echo "run-mcp-e2e: OK — natural-language recall verified for stage ${STAGE}"

# 6. Log-scan hardening (TC-OBS-010, issue #26). Scan the mnemo-server log
# group for LLM auth failures (401s) that occurred during this E2E run window.
# A 401 means the llm-proxy bearer is dead — smart-ingest data is being lost
# silently (the 2026-07-22 incident). HARD fail on any 401 regardless of
# E2E_SOFT — an auth failure is never a timing flake.
LOG_GROUP="/sst/cluster/mem9-on-aws-${STAGE}/mnemo-server"
echo "run-mcp-e2e: log-scan for auth failures in ${LOG_GROUP} (last 10 min)"
SCAN_START=$(( $(date +%s) - 600 ))000
SCAN_END=$(date +%s)000
QUERY_ID=$(aws logs start-query --region "$REGION" \
  --log-group-name "$LOG_GROUP" \
  --start-time "$SCAN_START" --end-time "$SCAN_END" \
  --query-string 'filter msg = "extraction LLM call failed" and err like /401/' \
  --output text 2>/dev/null || true)

if [[ -n "$QUERY_ID" ]]; then
  sleep 5
  AUTH_FAILURES=$(aws logs get-query-results --region "$REGION" \
    --query-id "$QUERY_ID" \
    --query 'results | length(@)' --output text 2>/dev/null || echo "0")
  if [[ "$AUTH_FAILURES" != "0" && "$AUTH_FAILURES" != "None" ]]; then
    echo "::error::log-scan found ${AUTH_FAILURES} LLM auth failure(s) (401) in ${LOG_GROUP} during the E2E window — llm-proxy bearer may be dead (issue #24 regression). Investigate immediately."
    exit 1
  fi
  echo "run-mcp-e2e: log-scan clean — no auth failures in the last 10 min"
else
  echo "run-mcp-e2e: log-scan skipped (could not start Logs Insights query — log group may not exist yet on fresh stages)"
fi
