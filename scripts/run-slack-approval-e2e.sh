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
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="${AWS_REGION:-$(node "$REPO_ROOT/scripts/resolve-application-region.mjs")}"
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

# An absent parameter is a SKIP condition here; anything else is a FAILURE.
# `2>/dev/null || true` would collapse the two, and that is not a cosmetic
# difference: `AccessDenied` (say a boundary change that leaves the CI role only
# the plural `ssm:GetParameters`), a KMS denial on `--with-decryption`, throttling,
# expired credentials, or the wrong region would all read as "not deployed" and
# exit 0. The gate would then report green forever while sending no request at
# all — the exact failure the `pr-N` refusal above exists to prevent, so it gets
# the same treatment: only the one benign cause skips.
#
# The two streams are captured SEPARATELY rather than merged with `2>&1`. On the
# success path a merge would prepend whatever the CLI wrote to stderr — a botocore
# deprecation notice, a credential-source line — onto the returned VALUE, and one
# of the values returned here is the signing secret that gets HMAC'd. A polluted
# secret produces a signature the facade rejects, which would read as the facade
# being broken. The unit-test fakes cannot catch this: they only write to stderr
# on the paths where they also exit non-zero.
ssm_value() {
  local out err rc=0
  err=$(mktemp)
  # `|| rc=$?` rather than a bare `rc=$?` on the next line: a plain assignment is
  # subject to errexit, and while a call in a command substitution survives it
  # (the subshell carries the failure to the caller's assignment), a direct call
  # would abort the script before reaching the classifier below.
  out=$(aws ssm get-parameter --name "$1" --region "$REGION" \
    --with-decryption --query Parameter.Value --output text 2>"$err") || rc=$?
  local stderr_text
  stderr_text=$(<"$err")
  rm -f "$err"
  if ((rc == 0)); then
    printf '%s' "$out"
    return 0
  fi
  if [[ "$stderr_text" == *ParameterNotFound* ]]; then
    return 0
  fi
  echo "::error::reading $1 failed (exit ${rc}): ${stderr_text}" >&2
  exit 1
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
# The colon of `sha256:` is replaced, matching `claimParameterName` in
# scripts/memory-cleanup.mjs and infra/src/oauth-facade/slack-interactions.ts. An
# SSM parameter name may contain only letters, numbers and `.-_` per sub-path, so
# the colon form is rejected by PutParameter — and on a READ it is parsed as a
# version selector instead, which is why the mismatch does not simply 404.
CLAIM_NAME="${PREFIX}/approvals/approved-${IDS_HASH//:/-}"

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
#
# The cluster comes from SSM, NOT from slicing the task ARN. `${TASK_ARN##*:task/}`
# assumes the long ARN format (`.../task/<cluster>/<id>`); on an account without
# the long-ARN opt-in the ARN is `.../task/<id>`, so the slice yields the task id
# and every describe-tasks below would be called with a nonexistent cluster.
CLUSTER=$(ssm_value "${PREFIX}/cleanup/cluster-name")
if [[ -z "$CLUSTER" || "$CLUSTER" == "None" ]]; then
  echo "::error::no cleanup/cluster-name on ${STAGE}, so the apply task cannot be polled" >&2
  exit 1
fi

# A failed describe is NOT an unknown status. Swallowing it would spin the full
# 15 minutes and then report `lastStatus=UNKNOWN`, which reads as "the task hung"
# and sends the next engineer to debug the apply task when the real cause is an
# IAM denial or a bad cluster.
#
# Streams kept separate for the same reason as `ssm_value`: the value returned here
# is compared against `STOPPED` and against exit codes, and a warning line merged
# onto it would make the comparison silently never match — the 15-minute spin the
# error message above is meant to rule out.
describe_task() {
  local out err rc=0
  err=$(mktemp)
  out=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK_ARN" \
    --region "$REGION" --query "$1" --output text 2>"$err") || rc=$?
  local stderr_text
  stderr_text=$(<"$err")
  rm -f "$err"
  if ((rc != 0)); then
    echo "::error::describe-tasks ($1) failed (exit ${rc}): ${stderr_text}" >&2
    exit 1
  fi
  printf '%s' "$out"
}

DEADLINE=$((SECONDS + 900))
LAST_STATUS=""
while [[ $SECONDS -lt $DEADLINE ]]; do
  LAST_STATUS=$(describe_task 'tasks[0].lastStatus')
  [[ "$LAST_STATUS" == "STOPPED" ]] && break
  sleep 10
done
if [[ "$LAST_STATUS" != "STOPPED" ]]; then
  echo "::error::the apply task did not stop within 15 minutes (lastStatus=${LAST_STATUS})" >&2
  exit 1
fi

EXIT_CODE=$(describe_task 'tasks[0].containers[0].exitCode')
STOP_REASON=$(describe_task 'tasks[0].stoppedReason')
echo "run-slack-approval-e2e: apply task stopped (exitCode=${EXIT_CODE}, reason='${STOP_REASON}')"
# `None` means the container never produced an exit code — the task died before
# or outside the entrypoint (a pull failure, or the secret-fetch phase, which is
# the predicted first-deploy outcome while the execution role is not admitted to
# the boundary's secret-decrypt exception list). Named separately because
# "exited None" invites the reader to look for a bug in the app instead.
if [[ "$EXIT_CODE" == "None" ]]; then
  echo "::error::the apply task never ran its container (reason='${STOP_REASON}'); this is a startup failure, not an application exit" >&2
  exit 1
fi
if [[ "$EXIT_CODE" != "0" ]]; then
  echo "::error::the apply task exited ${EXIT_CODE}" >&2
  exit 1
fi
# `stoppedReason` is asserted, not merely printed: a task killed by OOM or a
# failed secret/image pull can stop with a reason set, and the essential-container
# message is the only benign value here.
if [[ -n "$STOP_REASON" && "$STOP_REASON" != "None" ]] \
  && [[ "$STOP_REASON" != *"Essential container in task exited"* ]]; then
  echo "::error::the apply task stopped for an unexpected reason: ${STOP_REASON}" >&2
  exit 1
fi

echo "run-slack-approval-e2e: OK — signed click accepted, record written, apply exited 0 on ${STAGE}"
