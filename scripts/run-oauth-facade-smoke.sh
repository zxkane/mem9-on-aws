#!/usr/bin/env bash
# run-oauth-facade-smoke.sh — verify the OAuth façade metadata endpoints are live.
# The full browser authorization-code flow can't run headless (needs a human at a
# browser), so CI validates the RFC 8414/9728 metadata + registration endpoint.
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

echo "run-oauth-facade-smoke: checking /.well-known/oauth-protected-resource"
PR=$(curl -fsS "${FACADE}/.well-known/oauth-protected-resource")
echo "$PR" | jq -e '.resource | endswith("/mcp")' >/dev/null || { echo "::error::protected-resource.resource does not end with /mcp"; exit 1; }

echo "run-oauth-facade-smoke: OK — façade metadata valid for stage ${STAGE}"
