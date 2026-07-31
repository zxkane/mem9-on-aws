#!/usr/bin/env bash
# run-memory-cleanup-e2e.sh — live DRY-RUN of the memory cleanup script against
# a deployed stage (TC-MEMCLEAN-060, issue #102).
#
# Proves the operator tool works end-to-end from a VPC-internal runner:
#   Cloud Map DiscoverInstances → mnemo-server REST scan → GLM-5 classification
#   (Bedrock Mantle) → decision list written locally. NO write calls: the script
#   asserts its internal write counter is 0 (dry-run is the default mode and
#   this wrapper never passes --apply).
#
# Env:
#   STAGE       (required) — e.g. prod / pr-7.
#   AWS_REGION  (optional) — defaults to ap-northeast-1.

set -euo pipefail

STAGE="${STAGE:?STAGE is required (e.g. prod or pr-7)}"
REGION="${AWS_REGION:-ap-northeast-1}"

# SST publishes the tenant secret's ARN to SSM (infra/tenant-identity.ts) so
# this stays inside the already-scoped /mem9-on-aws/<stage>/* reads — no
# account-wide ListSecrets. The VALUE never touches this shell — the cleanup
# script reads it via the SDK.
TENANT_SECRET_ARN=$(aws ssm get-parameter \
  --name "/mem9-on-aws/${STAGE}/tenant/secret-arn" \
  --region "$REGION" \
  --query Parameter.Value \
  --output text) || TENANT_SECRET_ARN=""
if [[ -z "$TENANT_SECRET_ARN" || "$TENANT_SECRET_ARN" == "None" ]]; then
  echo "::error::no tenant secret ARN parameter for stage ${STAGE}"
  exit 1
fi

OUT_DIR=$(mktemp -d)
trap 'rm -rf "$OUT_DIR"' EXIT

echo "memory-cleanup e2e: dry-run against stage ${STAGE}"
RC=0
OUTPUT=$(node scripts/memory-cleanup.mjs \
  --stage "$STAGE" \
  --tenant-secret-arn "$TENANT_SECRET_ARN" \
  --out "$OUT_DIR" 2>&1) || RC=$?
printf '%s\n' "$OUTPUT"

if [[ $RC -ne 0 ]]; then
  echo "::error::memory-cleanup dry-run exited ${RC}"
  exit "$RC"
fi

# Assertions (TC-MEMCLEAN-060): a decision list exists and writeCalls == 0.
shopt -s nullglob
DECISIONS=("$OUT_DIR"/decisions-*.json)
shopt -u nullglob
if [[ ${#DECISIONS[@]} -eq 0 ]]; then
  echo "::error::no decision list produced"
  exit 1
fi
# Trailing-delimiter anchor: matches writeCalls=0 only as a whole number, so a
# future counter format change can't make a non-zero value pass.
if ! grep -qE 'writeCalls=0([^0-9]|$)' <<<"$OUTPUT"; then
  echo "::error::dry-run reported a non-zero write counter"
  exit 1
fi
COUNT=$(jq '.decisions | length' "${DECISIONS[0]}")
# An all-SKIP list on a non-empty store means classification never succeeded
# (exit code 5 covers the all-batches-failed case; this guards partial rot on
# a store the earlier smoke steps have already seeded).
NON_SKIP=$(jq '[.decisions[] | select(.verdict != "SKIP")] | length' "${DECISIONS[0]}")
if [[ "$COUNT" -gt 0 && "$NON_SKIP" -eq 0 ]]; then
  echo "::error::all ${COUNT} decisions are SKIP — GLM-5 classification produced no verdicts"
  exit 1
fi
echo "memory-cleanup e2e: OK — ${COUNT} decisions (${NON_SKIP} classified), zero write calls"
