#!/usr/bin/env bash
# run-oauth-facade-smoke.sh — verify the OAuth façade's public protocol boundary.
# The full authorization-code flow needs an interactive login, so CI validates
# metadata, registration, and the authorize redirect/cookie response.
set -euo pipefail
STAGE="${STAGE:?STAGE is required}"
REGION="${AWS_REGION:-ap-northeast-1}"
PREFIX="/mem9-on-aws/${STAGE}"
ssm() { aws ssm get-parameter --name "$1" --region "$REGION" --query Parameter.Value --output text; }

echo "run-oauth-facade-smoke: reading façade URL from SSM ${PREFIX}/facade/url"
FACADE=$(ssm "${PREFIX}/facade/url")
if [[ -z "$FACADE" ]]; then
  echo "::warning::no facade/url SSM param — OAuth façade not deployed on this stage (skipping)"
  exit 0
fi
echo "run-oauth-facade-smoke: façade=${FACADE}"

echo "run-oauth-facade-smoke: checking /.well-known/oauth-authorization-server"
AS=$(curl -fsS "${FACADE}/.well-known/oauth-authorization-server")
echo "$AS" | jq -e '.authorization_endpoint | endswith("/oauth/authorize")' >/dev/null || { echo "::error::authorization_endpoint does not point at the façade"; exit 1; }
echo "$AS" | jq -e '.token_endpoint | endswith("/oauth/token")' >/dev/null || { echo "::error::token_endpoint does not point at the façade"; exit 1; }
echo "$AS" | jq -e '.code_challenge_methods_supported == ["S256"]' >/dev/null || { echo "::error::S256 not advertised"; exit 1; }
echo "$AS" | jq -e '.registration_endpoint | endswith("/register")' >/dev/null || { echo "::error::no registration_endpoint"; exit 1; }
echo "$AS" | jq -e '.token_endpoint_auth_methods_supported | index("none")' >/dev/null || { echo "::error::public-client auth method \"none\" not in token_endpoint_auth_methods_supported"; exit 1; }

echo "run-oauth-facade-smoke: checking /.well-known/oauth-protected-resource"
PR=$(curl -fsS "${FACADE}/.well-known/oauth-protected-resource")
echo "$PR" | jq -e '.resource | endswith("/mcp")' >/dev/null || { echo "::error::protected-resource.resource does not end with /mcp"; exit 1; }

echo "run-oauth-facade-smoke: checking /register returns a public client (no secret)"
DCR=$(curl -fsS -X POST -H 'Content-Type: application/json' -d '{"redirect_uris":["http://localhost:8080/cb"]}' "${FACADE}/register")
echo "$DCR" | jq -e '.client_id | length > 0' >/dev/null || { echo "::error::DCR did not return client_id"; exit 1; }
echo "$DCR" | jq -e 'has("client_secret") | not' >/dev/null || { echo "::error::DCR must NOT return client_secret (public client)"; exit 1; }
echo "$DCR" | jq -e '.token_endpoint_auth_method == "none"' >/dev/null || { echo "::error::DCR token_endpoint_auth_method must be \"none\""; exit 1; }

echo "run-oauth-facade-smoke: checking /oauth/authorize state cookie"
AUTH_HEADERS=$(mktemp)
AUTH_BODY=$(mktemp)
trap 'rm -f "$AUTH_HEADERS" "$AUTH_BODY"' EXIT
CLIENT_ID=$(echo "$DCR" | jq -er '.client_id')
LONG_STATE=$(printf '%*s' 2200 '' | tr ' ' g)
AUTH_STATUS=$(
  curl -sS -G -D "$AUTH_HEADERS" -o "$AUTH_BODY" -w '%{http_code}' \
    --data-urlencode 'response_type=code' \
    --data-urlencode "client_id=${CLIENT_ID}" \
    --data-urlencode 'redirect_uri=http://localhost:8080/cb' \
    --data-urlencode 'scope=mem9-mcp/read' \
    --data-urlencode 'code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
    --data-urlencode 'code_challenge_method=S256' \
    --data-urlencode "state=${LONG_STATE}" \
    "${FACADE}/oauth/authorize"
)
if [[ "$AUTH_STATUS" != "302" ]]; then
  AUTH_ERROR=$(
    jq -r '.error_description // .message // .error // "non-JSON response"' \
      "$AUTH_BODY" 2>/dev/null || printf '%s' 'non-JSON response'
  )
  echo "::error::authorize returned HTTP ${AUTH_STATUS}: ${AUTH_ERROR}"
  exit 1
fi
SET_COOKIE_COUNT=$(awk 'tolower($1) == "set-cookie:" { count++ } END { print count + 0 }' "$AUTH_HEADERS")
[[ "$SET_COOKIE_COUNT" == "1" ]] || { echo "::error::authorize must return exactly one transaction cookie"; exit 1; }
TRANSACTION_COOKIE=$(
  awk 'tolower($1) == "set-cookie:" {
    sub(/^[^:]+:[[:space:]]*/, "")
    sub(/\r$/, "")
    print
    exit
  }' "$AUTH_HEADERS"
)
[[ "$TRANSACTION_COOKIE" == __Secure-mem9-oauth=* ]] || { echo "::error::authorize returned the wrong transaction cookie"; exit 1; }
for ATTRIBUTE in 'Path=/oauth/callback' 'Secure' 'HttpOnly' 'SameSite=Lax'; do
  [[ "$TRANSACTION_COOKIE" == *"; ${ATTRIBUTE}"* ]] || { echo "::error::transaction cookie is missing ${ATTRIBUTE}"; exit 1; }
done
COOKIE_BYTES=$(printf '%s' "$TRANSACTION_COOKIE" | wc -c | tr -d ' ')
(( COOKIE_BYTES <= 4096 )) || { echo "::error::transaction cookie exceeds 4 KiB"; exit 1; }
LOCATION=$(
  awk 'tolower($1) == "location:" {
    sub(/^[^:]+:[[:space:]]*/, "")
    sub(/\r$/, "")
    print
    exit
  }' "$AUTH_HEADERS"
)
COGNITO_STATE_LENGTH=$(
  LOCATION="$LOCATION" node -e '
    const location = new URL(process.env.LOCATION);
    process.stdout.write(String(location.searchParams.get("state")?.length ?? 0));
  '
)
(( COGNITO_STATE_LENGTH > 0 && COGNITO_STATE_LENGTH <= 1024 )) || { echo "::error::upstream state exceeds Cognito limit"; exit 1; }
[[ "$LOCATION" != *"$LONG_STATE"* ]] || { echo "::error::client state leaked into the upstream redirect"; exit 1; }

echo "run-oauth-facade-smoke: OK — façade metadata valid for stage ${STAGE}"
