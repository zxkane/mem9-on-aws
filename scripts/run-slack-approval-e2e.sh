#!/usr/bin/env bash
# run-slack-approval-e2e.sh — end-to-end check of the Slack approval loop
# (issue #123, TC-SLACKAPP-090) against a deployed stage.
#
# A real Slack workspace round trip is not reproducible in CI, and it is not what
# needs proving: the handler distinguishes Slack from anyone else ONLY by the
# request signature, so a correctly signed synthetic interaction exercises the
# identical path. What this adds over the unit tests is everything they inject —
# API Gateway's routing and base64 handling, the Lambda's own SSM and ECS grants,
# the task definition, and the container's entrypoint.
#
# The invalid-signature POST runs FIRST and its 401 is a hard requirement: a
# facade that accepted an unsigned interaction would pass every other check here.
# It has to precede the valid click so "no record was written" is assertable at
# all — after a successful click there is a record, and nothing can then tell the
# two writers apart.
#
# The approved id is a synthetic sentinel that names no real memory. This
# approves a DELETION against a live stage, so an id that resolved to preview
# data would delete it; the apply's "already gone" branch is what makes the run
# exit 0.

set -euo pipefail

STAGE="${STAGE:?STAGE is required (for example, prod or pr-123)}"
REGION="${AWS_REGION:-ap-northeast-1}"
PREFIX="/mem9-on-aws/${STAGE}"

# Disposable stages only, refused BEFORE the first write, and one pattern rather
# than a general stage check plus a prod denylist: `pr-N` is the only shape that is
# safe, so an allowlist cannot be outrun by a stage name nobody thought to deny.
# Seeding `offered` OVERWRITES it, so on a shared stage this destroys a pending
# human approval — the operator's next click is then answered against CI's record —
# and the id it approves is a DELETION against that stage's database. A REFUSAL
# rather than a skip: an exit 0 here would let a workflow edit silently stop
# testing anything while still reporting green. The pattern doubles as the
# injection guard on every `${PREFIX}/...` parameter name built below.
if ! [[ "$STAGE" =~ ^pr-[0-9]+$ ]]; then
  echo "::error::refusing to run against ${STAGE}: this seeds and deletes approval records, so it is limited to disposable pr-N stages" >&2
  exit 1
fi

# `|| true` on every probe: an absent parameter is `ParameterNotFound`, which is
# a SKIP condition here, not a failure (see the gate below).
ssm_value() {
  aws ssm get-parameter --name "$1" --region "$REGION" \
    --with-decryption --query Parameter.Value --output text 2>/dev/null || true
}

FACADE=$(ssm_value "${PREFIX}/facade/url")
if [[ -z "$FACADE" || "$FACADE" == "None" ]]; then
  echo "::warning::no facade/url on ${STAGE} — OAuth façade not deployed (skipping)"
  exit 0
fi

# Slack approval is gated on MEM9_SLACK_APPROVAL_ENABLED at SYNTH time, so a
# stage that never seeded the secrets has no endpoint to exercise. Failing hard
# there would block every PR on a feature the stage does not deploy.
SIGNING_SECRET=$(ssm_value "${PREFIX}/slack/signing-secret")
if [[ -z "$SIGNING_SECRET" || "$SIGNING_SECRET" == "None" ]]; then
  echo "::warning::no slack/signing-secret on ${STAGE} — Slack approval not enabled (skipping)"
  exit 0
fi

# An id no memory can have. `mem9-e2e-` is not the store's id format, so the
# apply's `client.get` resolves nothing and its "already gone" branch runs. The
# stage is in the id so two concurrent preview runs cannot claim the same hash.
APPROVED_ID="mem9-e2e-nonexistent-${STAGE}"
# The same derivation `buildOfferedRecord` and `materializeApprovedIds` use:
# sha256 over the ids joined by newline. Recomputed by the apply task, which
# refuses on a mismatch — so this is what lets the run reach the apply at all.
IDS_HASH="sha256:$(printf '%s' "$APPROVED_ID" | shasum -a 256 | cut -d' ' -f1)"
OFFERED_NAME="${PREFIX}/approvals/offered"
CLAIM_NAME="${PREFIX}/approvals/approved-${IDS_HASH}"

cleanup() {
  # Both records, always, including on failure: `offered` is overwritten by the
  # next real run, but the claim is written with `Overwrite: false`, so a
  # leftover would make the NEXT run's click a losing claim that starts nothing.
  aws ssm delete-parameter --name "$OFFERED_NAME" --region "$REGION" >/dev/null 2>&1 || true
  aws ssm delete-parameter --name "$CLAIM_NAME" --region "$REGION" >/dev/null 2>&1 || true
}
trap cleanup EXIT

OFFERED=$(jq -cn --arg stage "$STAGE" --arg hash "$IDS_HASH" --arg id "$APPROVED_ID" \
  '{stage: $stage, hash: $hash, ids: [$id], generatedAt: (now | todate)}')
echo "run-slack-approval-e2e: seeding ${OFFERED_NAME} with one synthetic id"
aws ssm put-parameter --name "$OFFERED_NAME" --type String --value "$OFFERED" \
  --overwrite --region "$REGION" >/dev/null

# Slack's own encoding: form-urlencoded with the JSON in a `payload` field. A
# JSON body would 400 here and pass nothing but a smoke test.
PAYLOAD=$(jq -cn --arg hash "$IDS_HASH" \
  '{type: "block_actions",
    user: {id: "U0E2E", username: "ci"},
    actions: [{action_id: "cleanup_approve", type: "button", value: $hash}]}')
BODY="payload=$(jq -rn --arg p "$PAYLOAD" '$p | @uri')"
TIMESTAMP=$(date +%s)

# The HMAC is computed in a node child that reads the secret from its
# ENVIRONMENT. `openssl dgst -hmac "$SECRET"` would put it in an argv, which is
# world-readable on the runner (TC-SLACKAPP-090).
#
# The single quotes are load-bearing, so SC2016 is disabled rather than "fixed":
# the `${...}` below are JS template-literal substitutions that NODE must
# evaluate, and the values arrive through the child's environment. Switching to
# double quotes would interpolate them in the SHELL — which both breaks the
# script (the shell has no such variables) and would defeat the argv-avoidance
# this block exists for.
# shellcheck disable=SC2016
SIGNATURE=$(
  SLACK_SIGNING_SECRET="$SIGNING_SECRET" SIG_TS="$TIMESTAMP" SIG_BODY="$BODY" node -e '
    const { createHmac } = require("node:crypto");
    const mac = createHmac("sha256", process.env.SLACK_SIGNING_SECRET)
      .update(`v0:${process.env.SIG_TS}:${process.env.SIG_BODY}`)
      .digest("hex");
    process.stdout.write(`v0=${mac}`);
  '
)

post() {
  local signature="$1" out="$2"
  curl -sS -o "$out" -w '%{http_code}' \
    -X POST \
    -H 'content-type: application/x-www-form-urlencoded' \
    -H "x-slack-request-timestamp: ${TIMESTAMP}" \
    -H "x-slack-signature: ${signature}" \
    --data-binary "$BODY" \
    "${FACADE}/slack/interactions"
}

RESPONSE_BODY=$(mktemp)
trap 'rm -f "$RESPONSE_BODY"; cleanup' EXIT

# 1. Invalid signature FIRST. The same body, so the rejection is provably the
#    signature's doing and not the payload's.
echo "run-slack-approval-e2e: POSTing with an invalid signature (expecting 401)"
BAD_STATUS=$(post "v0=deadbeef" "$RESPONSE_BODY")
if [[ "$BAD_STATUS" != "401" ]]; then
  echo "::error::an invalid signature was answered HTTP ${BAD_STATUS}, not 401" >&2
  exit 1
fi
if aws ssm get-parameter --name "$CLAIM_NAME" --region "$REGION" >/dev/null 2>&1; then
  echo "::error::a rejected interaction still wrote an approval record" >&2
  exit 1
fi

# 2. The correctly signed click.
echo "run-slack-approval-e2e: POSTing a correctly signed interaction (expecting 200)"
GOOD_STATUS=$(post "$SIGNATURE" "$RESPONSE_BODY")
if [[ "$GOOD_STATUS" != "200" ]]; then
  echo "::error::the signed interaction was answered HTTP ${GOOD_STATUS}, not 200" >&2
  exit 1
fi

# 3. The RECORD, read back by name. A 200 alone proves nothing: the handler also
#    answers 200 for a stale hash, an unknown action, and "already applied".
echo "run-slack-approval-e2e: reading the approval record back by name"
CLAIM=""
for attempt in 1 2 3 4 5 6; do
  CLAIM=$(ssm_value "$CLAIM_NAME")
  [[ -n "$CLAIM" && "$CLAIM" != "None" ]] && break
  echo "run-slack-approval-e2e: record not visible yet (attempt ${attempt}/6)"
  sleep 5
done
if [[ -z "$CLAIM" || "$CLAIM" == "None" ]]; then
  echo "::error::no approval record at ${CLAIM_NAME} after a 200" >&2
  exit 1
fi

TASK_ARN=$(jq -r '.taskArn // empty' <<<"$CLAIM")
if [[ -z "$TASK_ARN" ]]; then
  echo "::error::the approval record has no taskArn — the claim was recorded but no apply started" >&2
  exit 1
fi
echo "run-slack-approval-e2e: apply task ${TASK_ARN##*/} started"

# 4. The apply task's own exit code. Without this the check passes on a click
#    that started a task which then crashed.
CLUSTER="${TASK_ARN##*:task/}"
CLUSTER="${CLUSTER%%/*}"
DEADLINE=$((SECONDS + 900))
LAST_STATUS=""
while [[ $SECONDS -lt $DEADLINE ]]; do
  LAST_STATUS=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK_ARN" \
    --region "$REGION" --query 'tasks[0].lastStatus' --output text 2>/dev/null || echo "UNKNOWN")
  [[ "$LAST_STATUS" == "STOPPED" ]] && break
  sleep 10
done
if [[ "$LAST_STATUS" != "STOPPED" ]]; then
  echo "::error::the apply task did not stop within 15 minutes (lastStatus=${LAST_STATUS})" >&2
  exit 1
fi

EXIT_CODE=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK_ARN" \
  --region "$REGION" --query 'tasks[0].containers[0].exitCode' --output text)
STOP_REASON=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK_ARN" \
  --region "$REGION" --query 'tasks[0].stoppedReason' --output text)
echo "run-slack-approval-e2e: apply task stopped (exitCode=${EXIT_CODE}, reason='${STOP_REASON}')"
if [[ "$EXIT_CODE" != "0" ]]; then
  echo "::error::the apply task exited ${EXIT_CODE}" >&2
  exit 1
fi

echo "run-slack-approval-e2e: OK — signed click accepted, record written, apply exited 0 on ${STAGE}"
