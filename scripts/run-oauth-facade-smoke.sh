#!/usr/bin/env bash
# run-oauth-facade-smoke.sh — verify the OAuth façade's public protocol boundary.
# The full authorization-code flow needs an interactive login, so CI validates
# metadata, registration, and the authorize redirect/cookie response.
set -euo pipefail
STAGE="${STAGE:?STAGE is required}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="${AWS_REGION:-$(node "$REPO_ROOT/scripts/resolve-application-region.mjs")}"
PREFIX="/mem9-on-aws/${STAGE}"
ssm() { aws ssm get-parameter --name "$1" --region "$REGION" --query Parameter.Value --output text; }

echo "run-oauth-facade-smoke: reading façade URL from SSM ${PREFIX}/facade/url"
FACADE=$(ssm "${PREFIX}/facade/url")
if [[ -z "$FACADE" ]]; then
  echo "::warning::no facade/url SSM param — OAuth façade not deployed on this stage (skipping)"
  exit 0
fi
echo "run-oauth-facade-smoke: façade=${FACADE}"

echo "run-oauth-facade-smoke: checking deployed reader refresh-token rotation"
COGNITO_ISSUER=$(ssm "${PREFIX}/cognito/issuer")
READER_CLIENT_ID=$(ssm "${PREFIX}/cognito/reader/client-id")
USER_POOL_ID="${COGNITO_ISSUER##*/}"
if [[ -z "$USER_POOL_ID" || "$USER_POOL_ID" == "$COGNITO_ISSUER" || -z "$READER_CLIENT_ID" ]]; then
  echo "::error::reader client identifiers are missing from the stage configuration"
  exit 1
fi
READER_CLIENT_CONFIG=$(
  aws cognito-idp describe-user-pool-client \
    --user-pool-id "$USER_POOL_ID" \
    --client-id "$READER_CLIENT_ID" \
    --region "$REGION" \
    --query 'UserPoolClient.{RefreshTokenRotation:RefreshTokenRotation,ExplicitAuthFlows:ExplicitAuthFlows}' \
    --output json
)
echo "$READER_CLIENT_CONFIG" | jq -e '.RefreshTokenRotation.Feature == "ENABLED"' >/dev/null || {
  echo "::error::reader client refresh-token rotation is not enabled"
  exit 1
}
echo "$READER_CLIENT_CONFIG" | jq -e '.RefreshTokenRotation.RetryGracePeriodSeconds == 10' >/dev/null || {
  echo "::error::reader client refresh-token retry grace period is not 10 seconds"
  exit 1
}
echo "$READER_CLIENT_CONFIG" | jq -e '.ExplicitAuthFlows == ["ALLOW_USER_SRP_AUTH"]' >/dev/null || {
  echo "::error::reader client explicit auth flows do not exclude the incompatible ALLOW_REFRESH_TOKEN_AUTH default"
  exit 1
}
echo "run-oauth-facade-smoke: reader refresh-token rotation OK (10-second retry grace)"

echo "run-oauth-facade-smoke: checking /.well-known/oauth-authorization-server"
AS=$(curl -fsS "${FACADE}/.well-known/oauth-authorization-server")
echo "$AS" | jq -e '.authorization_endpoint | endswith("/oauth/authorize")' >/dev/null || { echo "::error::authorization_endpoint does not point at the façade"; exit 1; }
echo "$AS" | jq -e '.token_endpoint | endswith("/oauth/token")' >/dev/null || { echo "::error::token_endpoint does not point at the façade"; exit 1; }
echo "$AS" | jq -e '.code_challenge_methods_supported == ["S256"]' >/dev/null || { echo "::error::S256 not advertised"; exit 1; }
echo "$AS" | jq -e '.registration_endpoint | endswith("/register")' >/dev/null || { echo "::error::no registration_endpoint"; exit 1; }
echo "$AS" | jq -e '.token_endpoint_auth_methods_supported | index("none")' >/dev/null || { echo "::error::public-client auth method \"none\" not in token_endpoint_auth_methods_supported"; exit 1; }
echo "$AS" | jq -e '(["mem9-mcp/read", "mem9-mcp/write"] - (.scopes_supported // [])) | length == 0' >/dev/null || { echo "::error::authorization-server metadata must advertise read and write scopes"; exit 1; }

echo "run-oauth-facade-smoke: checking /.well-known/oauth-protected-resource"
PR=$(curl -fsS "${FACADE}/.well-known/oauth-protected-resource")
echo "$PR" | jq -e '.resource | endswith("/mcp")' >/dev/null || { echo "::error::protected-resource.resource does not end with /mcp"; exit 1; }

# TC-MCPGW-079. RFC 8414 §3.3: the AS metadata `issuer` MUST be identical to the
# issuer identifier the client inserted the well-known string into — which is the
# `authorization_servers` entry published above. A mismatch makes a compliant
# client (rmcp >= 3.0.0) discard the document and fail MCP startup entirely. The
# checks above validated every other advertised field but never this one, which is
# why the façade advertised Cognito's issuer undetected.
#
# Each field is PRESENCE-CHECKED before it is read, in this shell, using the same
# `jq -e ... || { echo; exit 1; }` idiom as the checks above. Neither shorter form
# works: a bare `jq -er` in the assignment lets `set -e` kill the script AT the
# assignment with no `::error::` and no field named, and moving the diagnostic into
# a helper called as `$(field ...)` only swallows it into the captured stdout —
# same silent non-zero exit. Verified against a mock serving a null `.issuer`.
#
# This block prints its own progress line for the same reason: a green job is not
# evidence that a specific assertion ran, and without a line of its own the only
# proof these checks executed is `set -e` having reached the next section.
echo "run-oauth-facade-smoke: checking metadata issuer identity (RFC 8414 §3.3)"
echo "$AS" | jq -e '(.issuer // "") != ""' >/dev/null || { echo "::error::authorization-server metadata .issuer is missing or empty"; exit 1; }
echo "$PR" | jq -e '(.authorization_servers[0] // "") != ""' >/dev/null || { echo "::error::protected-resource .authorization_servers[0] is missing or empty"; exit 1; }
AS_ISSUER=$(echo "$AS" | jq -r '.issuer')
ADVERTISED_AS=$(echo "$PR" | jq -r '.authorization_servers[0]')
# The relationship alone is NOT enough: documents that agree on the UPSTREAM issuer
# satisfy §3.3 while pointing clients at Cognito, which publishes no
# `registration_endpoint` — so DCR fails and #143's symptom returns by another
# route. Anchor to the façade URL read from SSM above, which is deployment ground
# truth rather than a hardcoded host, so this still holds on any stage/domain.
if [[ "${ADVERTISED_AS%/}" != "${FACADE%/}" ]]; then
  echo "::error::protected-resource authorization_servers[0] (${ADVERTISED_AS}) is not this façade (${FACADE}) — clients would be sent elsewhere for authorization"
  exit 1
fi
if [[ "$AS_ISSUER" != "$ADVERTISED_AS" ]]; then
  echo "::error::AS metadata issuer (${AS_ISSUER}) != authorization_servers[0] (${ADVERTISED_AS}) — RFC 8414 §3.3 violation; compliant clients will refuse this façade"
  exit 1
fi
OIDC=$(curl -fsS "${FACADE}/.well-known/openid-configuration")
echo "$OIDC" | jq -e '(.issuer // "") != ""' >/dev/null || { echo "::error::openid-configuration .issuer is missing or empty"; exit 1; }
echo "$OIDC" | jq -e '(["mem9-mcp/read", "mem9-mcp/write"] - (.scopes_supported // [])) | length == 0' >/dev/null || { echo "::error::OIDC metadata must advertise read and write scopes"; exit 1; }
OIDC_ISSUER=$(echo "$OIDC" | jq -r '.issuer')
if [[ "$OIDC_ISSUER" != "$ADVERTISED_AS" ]]; then
  echo "::error::OIDC discovery issuer (${OIDC_ISSUER}) != authorization_servers[0] (${ADVERTISED_AS}) — clients discovering via openid-configuration will refuse this façade"
  exit 1
fi
echo "run-oauth-facade-smoke: issuer identity OK — AS and OIDC both self-identify as ${ADVERTISED_AS}"

echo "run-oauth-facade-smoke: checking /register returns a public client (no secret)"
DCR=$(curl -fsS -X POST -H 'Content-Type: application/json' -d '{"redirect_uris":["http://localhost:8080/cb"]}' "${FACADE}/register")
echo "$DCR" | jq -e '.client_id | length > 0' >/dev/null || { echo "::error::DCR did not return client_id"; exit 1; }
echo "$DCR" | jq -e 'has("client_secret") | not' >/dev/null || { echo "::error::DCR must NOT return client_secret (public client)"; exit 1; }
echo "$DCR" | jq -e '.token_endpoint_auth_method == "none"' >/dev/null || { echo "::error::DCR token_endpoint_auth_method must be \"none\""; exit 1; }
echo "$DCR" | jq -e '(.scope | split(" ")) as $scopes | (["mem9-mcp/read", "mem9-mcp/write"] - $scopes) | length == 0' >/dev/null || { echo "::error::DCR must return read and write scopes"; exit 1; }

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
    --data-urlencode 'scope=mem9-mcp/read mem9-mcp/write' \
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
