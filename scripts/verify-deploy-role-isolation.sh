#!/usr/bin/env bash

set -euo pipefail

SCOPE="${1:-}"
REGION="${AWS_REGION:?AWS_REGION is required}"
case "$SCOPE" in
  preview)
    EXPECTED_ROLE="github-actions-mem9-on-aws-preview"
    ALLOWED_PARAMETER="/sst/bootstrap"
    DENIED_PARAMETER="/mem9-on-aws/prod/ecs/image-tag"
    ;;
  production)
    EXPECTED_ROLE="github-actions-mem9-on-aws-prod"
    ALLOWED_PARAMETER="/mem9-on-aws/prod/ecs/image-tag"
    DENIED_PARAMETER="/mem9-on-aws/pr-0/ecs/image-tag"
    ;;
  *)
    echo "usage: verify-deploy-role-isolation.sh <preview|production>" >&2
    exit 2
    ;;
esac

CALLER_ARN=$(aws sts get-caller-identity --query Arn --output text)
if [[ "$CALLER_ARN" != *":assumed-role/${EXPECTED_ROLE}/"* ]]; then
  echo "::error::unexpected deployment role identity"
  exit 1
fi

aws ssm get-parameter \
  --name "$ALLOWED_PARAMETER" \
  --region "$REGION" \
  --query Parameter.Type \
  --output text >/dev/null

ERROR_FILE=$(mktemp)
trap 'rm -f "$ERROR_FILE"' EXIT

expect_denied() {
  local label=$1
  shift
  : >"$ERROR_FILE"
  if "$@" >/dev/null 2>"$ERROR_FILE"; then
    echo "::error::${label} unexpectedly succeeded"
    exit 1
  fi
  if ! grep -qE 'AccessDenied|not authorized|explicit deny' "$ERROR_FILE"; then
    echo "::error::${label} did not fail through IAM"
    exit 1
  fi
}

expect_denied "opposite-stage SSM access" \
  aws ssm get-parameter \
    --name "$DENIED_PARAMETER" \
    --region "$REGION" \
    --query Parameter.Type \
    --output text

if [[ "$SCOPE" == "preview" ]]; then
  PROD_HOSTED_ZONE_ID="${MEM9_PROD_HOSTED_ZONE_ID:?MEM9_PROD_HOSTED_ZONE_ID is required}"
  if [[ ! "$PROD_HOSTED_ZONE_ID" =~ ^Z[A-Z0-9]+$ ]]; then
    echo "::error::production hosted-zone input is malformed"
    exit 1
  fi
  expect_denied "production hosted-zone access" \
    aws route53 get-hosted-zone --id "$PROD_HOSTED_ZONE_ID"
fi

echo "deploy_role_isolation scope=${SCOPE} own_stage_read=allowed opposite_stage_read=denied"
