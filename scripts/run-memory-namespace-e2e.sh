#!/usr/bin/env bash
# Live PR-stage isolation test for the shared PostgreSQL namespace model.
#
# Two short-lived Cognito M2M clients are bound to different namespaces in the
# same preview database. The stage's default M2M client shares preview-alpha.
# Each fixture recalls its own marker, the default client must recall alpha's
# marker, and foreign-marker queries must not return the other marker. The
# deterministic PostgreSQL integration suite proves exhaustive row isolation.

set -euo pipefail

STAGE="${STAGE:?STAGE is required (pr-N)}"
if ! [[ "$STAGE" =~ ^pr-[1-9][0-9]*$ ]]; then
  echo "::error::namespace E2E is restricted to pr-N stages"
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="${AWS_REGION:-$(node "$REPO_ROOT/scripts/resolve-application-region.mjs")}"
PREFIX="/mem9-on-aws/${STAGE}"
TEMP_DIR=$(mktemp -d)
chmod 700 "$TEMP_DIR"
trap 'rm -rf "$TEMP_DIR"' EXIT

ssm() {
  aws ssm get-parameter \
    --name "$1" \
    --region "$REGION" \
    --with-decryption \
    --query Parameter.Value \
    --output text
}

TOKEN_ENDPOINT=$(ssm "${PREFIX}/cognito/token-endpoint")
SCOPES=$(ssm "${PREFIX}/cognito/scope")
GATEWAY_URL=$(ssm "${PREFIX}/gateway/url")
DEFAULT_CLIENT_ID=$(ssm "${PREFIX}/cognito/client-id")
DEFAULT_CLIENT_SECRET=$(ssm "${PREFIX}/cognito/client-secret")
ALPHA_CLIENT_ID=$(ssm "${PREFIX}/cognito/namespace-e2e-alpha/client-id")
ALPHA_CLIENT_SECRET=$(ssm "${PREFIX}/cognito/namespace-e2e-alpha/client-secret")
BETA_CLIENT_ID=$(ssm "${PREFIX}/cognito/namespace-e2e-beta/client-id")
BETA_CLIENT_SECRET=$(ssm "${PREFIX}/cognito/namespace-e2e-beta/client-secret")

mint_auth_config() {
  local client_id="$1" client_secret="$2" output_path="$3"
  local credentials_path response token
  if [[ "$client_id" == *[$'\r\n"\\']* ||
    "$client_secret" == *[$'\r\n"\\']* ]]; then
    echo "::error::Cognito fixture credentials contain unsupported characters"
    return 1
  fi
  credentials_path=$(mktemp "${TEMP_DIR}/cognito-credentials.XXXXXX")
  chmod 600 "$credentials_path"
  printf 'user = "%s:%s"\n' "$client_id" "$client_secret" >"$credentials_path"
  response=$(curl -fsS --config "$credentials_path" -X POST "$TOKEN_ENDPOINT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials&scope=$(printf '%s' "$SCOPES" | sed 's/ /%20/g')")
  rm -f "$credentials_path"
  token=$(printf '%s' "$response" | jq -r '.access_token // ""')
  if [[ -z "$token" || "$token" == "null" ||
    ! "$token" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "::error::Cognito returned no access token for a namespace fixture"
    return 1
  fi
  printf 'header = "Authorization: Bearer %s"\n' "$token" >"$output_path"
  chmod 600 "$output_path"
}

DEFAULT_AUTH_CONFIG="${TEMP_DIR}/default-auth.curl"
ALPHA_AUTH_CONFIG="${TEMP_DIR}/alpha-auth.curl"
BETA_AUTH_CONFIG="${TEMP_DIR}/beta-auth.curl"
mint_auth_config \
  "$DEFAULT_CLIENT_ID" "$DEFAULT_CLIENT_SECRET" "$DEFAULT_AUTH_CONFIG"
mint_auth_config \
  "$ALPHA_CLIENT_ID" "$ALPHA_CLIENT_SECRET" "$ALPHA_AUTH_CONFIG"
mint_auth_config \
  "$BETA_CLIENT_ID" "$BETA_CLIENT_SECRET" "$BETA_AUTH_CONFIG"
unset DEFAULT_CLIENT_SECRET ALPHA_CLIENT_SECRET BETA_CLIENT_SECRET
declare -A MCP_SESSIONS=([default]="" [alpha]="" [beta]="")
MCP_RESP=""

mcp_post() {
  local auth_config="$1" session_key="$2" method="$3" params="$4"
  local session="${MCP_SESSIONS[$session_key]}"
  local headers body_path http_status next_session
  local -a session_header=()
  if [[ -n "$session" ]]; then
    session_header=(-H "Mcp-Session-Id: ${session}")
  fi
  headers=$(mktemp "${TEMP_DIR}/mcp-headers.XXXXXX")
  body_path=$(mktemp "${TEMP_DIR}/mcp-body.XXXXXX")
  if ! http_status=$(curl -sS --config "$auth_config" -D "$headers" \
    -o "$body_path" -w '%{http_code}' -X POST "$GATEWAY_URL" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    "${session_header[@]}" \
    -d "$(jq -nc --arg method "$method" --argjson params "$params" \
      '{jsonrpc:"2.0",id:1,method:$method,params:$params}')"); then
    rm -f "$headers" "$body_path"
    echo "::error::Gateway request failed at the HTTP transport"
    exit 1
  fi
  MCP_RESP=$(cat "$body_path")
  next_session=$(grep -i '^mcp-session-id:' "$headers" 2>/dev/null |
    head -1 | sed 's/^[^:]*: *//' | tr -d '\r' || true)
  rm -f "$headers" "$body_path"
  if ! [[ "$http_status" =~ ^2[0-9][0-9]$ ]]; then
    echo "::error::Gateway returned HTTP ${http_status}: $(printf '%s' "$MCP_RESP" | head -c 500)"
    exit 1
  fi
  if [[ -n "$next_session" ]]; then
    MCP_SESSIONS["$session_key"]="$next_session"
  fi
}

mcp_result() {
  local raw result
  raw=$(cat)
  result=$(printf '%s' "$raw" | jq -c '.result // empty' 2>/dev/null || true)
  if [[ -z "$result" ]]; then
    result=$(printf '%s' "$raw" | sed -n 's/^data: //p' |
      tail -1 | jq -c '.result // empty' 2>/dev/null || true)
  fi
  printf '%s' "$result"
}

initialize() {
  mcp_post "$1" "$2" "initialize" \
    '{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"mem9-namespace-e2e","version":"1"}}'
}

resolve_tools() {
  mcp_post "$1" "$2" "tools/list" '{}'
  local tools
  tools=$(printf '%s' "$MCP_RESP" | mcp_result)
  if [[ -z "$tools" ]]; then
    echo "::error::namespace fixture tools/list returned no JSON-RPC result"
    exit 1
  fi
  ADD_TOOL=$(printf '%s' "$tools" | jq -r \
    '(.tools // [])[] | select(.name | endswith("add_memory")) | .name' |
    head -1)
  SEARCH_TOOL=$(printf '%s' "$tools" | jq -r \
    '(.tools // [])[] | select(.name | endswith("search_memories")) | .name' |
    head -1)
  if [[ -z "$ADD_TOOL" || -z "$SEARCH_TOOL" ]]; then
    echo "::error::namespace fixture client cannot discover memory tools"
    exit 1
  fi
}

call_tool() {
  local auth_config="$1" session_variable="$2" tool="$3" arguments="$4"
  mcp_post "$auth_config" "$session_variable" "tools/call" \
    "$(jq -nc --arg name "$tool" --argjson arguments "$arguments" \
      '{name:$name,arguments:$arguments}')"
}

assert_call_succeeded() {
  local result
  result=$(printf '%s' "$MCP_RESP" | mcp_result)
  if [[ -z "$result" ]] || printf '%s' "$MCP_RESP" |
    grep -qiE '"isError":[[:space:]]*true|"error":[[:space:]]*\{|\"code\":[[:space:]]*-3[0-9]{4}'; then
    echo "::error::$1 failed: $(printf '%s' "$MCP_RESP" | head -c 500)"
    exit 1
  fi
}

parse_search_payload() {
  local label="$1" result payload
  assert_call_succeeded "$label"
  result=$(printf '%s' "$MCP_RESP" | mcp_result)
  if ! payload=$(printf '%s' "$result" | jq -cer \
    '.content[0].text | fromjson
     | select(
         type == "object"
         and (.memories | type == "array")
         and (.total | type == "number")
       )'); then
    echo "::error::${label} returned an invalid memory-search payload"
    exit 1
  fi
  SEARCH_PAYLOAD="$payload"
}

payload_contains_marker() {
  printf '%s' "$SEARCH_PAYLOAD" | jq -e --arg marker "$1" \
    'tostring | contains($marker)' >/dev/null
}

initialize "$ALPHA_AUTH_CONFIG" alpha
resolve_tools "$ALPHA_AUTH_CONFIG" alpha
initialize "$DEFAULT_AUTH_CONFIG" default
initialize "$BETA_AUTH_CONFIG" beta

RUN_MARKER="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
ALPHA_MARKER="namespace-alpha-${STAGE}-${RUN_MARKER}"
BETA_MARKER="namespace-beta-${STAGE}-${RUN_MARKER}"

call_tool "$ALPHA_AUTH_CONFIG" alpha "$ADD_TOOL" \
  "$(jq -nc --arg content "PR namespace isolation marker ${ALPHA_MARKER}" \
    '{
      content:$content,
      namespace_id:"forged-beta-namespace",
      namespace_slug:"preview-beta"
    }')"
assert_call_succeeded "alpha namespace write"

call_tool "$BETA_AUTH_CONFIG" beta "$ADD_TOOL" \
  "$(jq -nc --arg content "PR namespace isolation marker ${BETA_MARKER}" \
    '{content:$content}')"
assert_call_succeeded "beta namespace write"

echo "run-memory-namespace-e2e: polling both isolated namespaces"
DEADLINE=$((SECONDS + 360))
ALPHA_FOUND=0
BETA_FOUND=0
while [[ $SECONDS -lt $DEADLINE ]]; do
  if [[ "$ALPHA_FOUND" != "1" ]]; then
    call_tool "$ALPHA_AUTH_CONFIG" alpha "$SEARCH_TOOL" \
      "$(jq -nc --arg q "$ALPHA_MARKER" '{q:$q,limit:100}')"
    parse_search_payload "alpha own-marker search"
    if payload_contains_marker "$ALPHA_MARKER"; then
      ALPHA_FOUND=1
    fi
  fi
  if [[ "$BETA_FOUND" != "1" ]]; then
    call_tool "$BETA_AUTH_CONFIG" beta "$SEARCH_TOOL" \
      "$(jq -nc --arg q "$BETA_MARKER" '{q:$q,limit:100}')"
    parse_search_payload "beta own-marker search"
    if payload_contains_marker "$BETA_MARKER"; then
      BETA_FOUND=1
    fi
  fi
  if [[ "$ALPHA_FOUND" == "1" && "$BETA_FOUND" == "1" ]]; then
    break
  fi
  sleep 15
done

if [[ "$ALPHA_FOUND" != "1" || "$BETA_FOUND" != "1" ]]; then
  echo "::error::one or both namespace markers were not recalled within 6 minutes"
  exit 1
fi

call_tool "$DEFAULT_AUTH_CONFIG" default "$SEARCH_TOOL" \
  "$(jq -nc --arg q "$ALPHA_MARKER" '{q:$q,limit:100}')"
parse_search_payload "default-client shared-alpha search"
if ! payload_contains_marker "$ALPHA_MARKER"; then
  echo "::error::default client did not observe its shared alpha namespace"
  exit 1
fi

call_tool "$ALPHA_AUTH_CONFIG" alpha "$SEARCH_TOOL" \
  "$(jq -nc --arg q "$BETA_MARKER" '{q:$q,limit:100}')"
parse_search_payload "alpha foreign-marker search"
if payload_contains_marker "$BETA_MARKER"; then
  echo "::error::alpha namespace observed beta memory"
  exit 1
fi

call_tool "$BETA_AUTH_CONFIG" beta "$SEARCH_TOOL" \
  "$(jq -nc --arg q "$ALPHA_MARKER" '{q:$q,limit:100}')"
parse_search_payload "beta foreign-marker search"
if payload_contains_marker "$ALPHA_MARKER"; then
  echo "::error::beta namespace observed alpha memory"
  exit 1
fi

echo "run-memory-namespace-e2e: OK — shared namespace recalled; cross-namespace markers absent"
