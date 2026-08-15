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
# two writers apart. The expired-offer probe (#149) is second for the same reason:
# it is a correctly signed click that must be REFUSED and must write nothing, and
# only a run with no claim yet can prove the second half.
#
# The reviewed list is a remote ARTIFACT since #150, and the button's hash covers
# its BYTES rather than the id list — which is what fits a third refusal between
# the expired probe and the live click. The tampered artifact has gained one
# absorbed id since the offer (the deletion the operator never saw) while the
# offered record's ids are UNCHANGED: under an id-list hash that tamper was
# invisible, and under the artifact hash the record's hash moves, the button no
# longer matches it, and the façade refuses before writing anything. That is what
# makes "no apply task ran" assertable at all — the claim is taken with
# `Overwrite: false` BEFORE `RunTask`, so an absent claim IS an absent task.
#
# The byte-level half of the same guard — an artifact swapped under a record that
# still names its old hash — is the APPLY TASK's refusal rather than the façade's,
# and it stays in the four invalid-artifact unit tests: proving it live costs a
# second Fargate task lifecycle inside a job that already runs five E2Es, and all
# it would add over those tests is that the task's own S3 grant works, which the
# live case below exercises on its success path.
#
# The live click then replays a list carrying a MERGE as well as a DELETE, and the
# run is OK only once the task's own log stream shows it REPLAYED that list.
# Without that assertion the MERGE case proves nothing: a task that ignored the
# artifact and re-classified would find these synthetic ids absent too, and would
# also exit 0.
#
# Every approved id is a synthetic sentinel that names no real memory. This
# approves a DELETION and a MERGE against a live stage, so an id that resolved to
# preview data would delete it or rewrite it; the apply's "already gone" and
# "survivor no longer active" branches are what make the run exit 0.

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

# The bucket is derived, not read from SSM: `slackApproval()` publishes the
# cluster, the task-def arn, the SG and the subnets under `cleanup/`, but the
# artifact bucket is an ENVIRONMENT entry on the task definition and never a
# parameter. Deriving it from the caller's own account id is also the stricter
# check — it asserts the name this repo computes rather than the name the stage
# happens to have been configured with, so a drift between
# `decisionArtifactBucketName` and the deployed bucket fails here instead of
# silently exercising whatever bucket the stage names.
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
if ! [[ "$ACCOUNT_ID" =~ ^[0-9]{12}$ ]]; then
  echo "::error::could not read a 12-digit account id from sts:GetCallerIdentity" >&2
  exit 1
fi
ARTIFACT_BUCKET="mem9-audit-${ACCOUNT_ID}"

# The reviewed list, its tampered twin, and the ids the offer will name — all
# built by the SAME functions the scan uses, imported from the script under test.
# Rehashing a hand-written JSON literal here would prove only that this file and
# itself agree: the property that matters is that the bytes the apply task fetches
# hash to the value the button carried, and only `serializeDecisionArtifact` +
# `decisionArtifactHash` + `decisionArtifactKey` decide that. A key or a byte
# ordering re-implemented in shell would pass this harness and fail the real loop.
#
# `--input-type=module` because the script is an ES module, and the import is
# dynamic so the path can come from the environment. Importing it is side-effect
# free: `scripts/memory-cleanup.mjs` re-exports pure helpers from
# docker/llm-proxy/server.mjs, whose own listener is behind an `isMain` guard.
#
# The MERGE is what #150 admitted to the loop, and it is here rather than a
# DELETE-only list precisely because a merge is the verdict a re-classification
# cannot reconstruct: its `mergedContent` is model prose hash-anchored on the
# survivor's ORIGINAL content, so a task that ignored the artifact would produce
# different bytes and a hash matching nothing.
#
# The tampered twin absorbs one MORE id than the reviewed list while the offer's
# `ids` stay identical. Written to S3 for real, so the case is a tampered artifact
# and not a fabricated record: were the click accepted, the task would fetch those
# bytes, find them hash-consistent with the record, and soft-delete a memory that
# appeared on no reviewed list. The button's hash is the only thing in the way.
#
# Every id is synthetic (`mem9-e2e-` is not the store's id format) so the apply's
# `client.get` resolves nothing — the DELETE takes its "already gone" branch and
# the MERGE takes "survivor no longer active", which is what makes an exit 0
# provable against a live stage. The stage rides in each id so two concurrent
# preview runs cannot collide, and `mergedContent` is synthetic text this file
# authors — it is written to a temp file and uploaded, never echoed.
ARTIFACT_BODY=$(mktemp)
TAMPERED_BODY=$(mktemp)
# Removed by a trap installed HERE rather than only by the full `cleanup` below,
# because everything between this line and that one can exit: the node child under
# `set -e`, the `jq` reads of its output, and the identical-hash refusal. Any of
# those would otherwise leave both bodies on the runner's disk, and one of them is
# synthetic memory text — the case for deleting the S3 copies applies to these
# harder, since a runner's temp dir outlives no lifecycle rule. Superseded (not
# duplicated) once `cleanup` takes over.
trap 'rm -f "$ARTIFACT_BODY" "$TAMPERED_BODY"' EXIT
# shellcheck disable=SC2016
ARTIFACT_META=$(
  E2E_STAGE="$STAGE" E2E_ROOT="$REPO_ROOT" \
    E2E_CLEAN_PATH="$ARTIFACT_BODY" E2E_TAMPERED_PATH="$TAMPERED_BODY" \
    node --input-type=module -e '
    import { writeFileSync } from "node:fs";
    const {
      contentHash, serializeDecisionArtifact, decisionArtifactHash, decisionArtifactKey,
    } = await import(`${process.env.E2E_ROOT}/scripts/memory-cleanup.mjs`);
    const stage = process.env.E2E_STAGE;
    const id = (what) => `mem9-e2e-${what}-${stage}`;
    const generatedAt = new Date().toISOString();
    const merged = "mem9 e2e synthetic merged content";
    const absorbed = (what) => ({
      id: id(what),
      contentHash: contentHash(`e2e ${what}`),
      version: 1,
    });
    const decisions = [
      { id: id("nonexistent"), verdict: "DELETE", contentHash: contentHash("e2e delete"), version: 1 },
      {
        id: id("survivor"),
        verdict: "MERGE",
        contentHash: contentHash("e2e survivor"),
        version: 1,
        mergedContent: merged,
        mergedContentHash: contentHash(merged),
        absorbs: [absorbed("absorbed")],
      },
    ];
    const write = (path, list) => {
      const body = serializeDecisionArtifact({ stage, generatedAt, decisions: list });
      const hash = decisionArtifactHash(body);
      writeFileSync(path, body, { mode: 0o600 });
      return { hash, key: decisionArtifactKey(stage, hash) };
    };
    const clean = write(process.env.E2E_CLEAN_PATH, decisions);
    const tampered = write(process.env.E2E_TAMPERED_PATH, [
      decisions[0],
      { ...decisions[1], absorbs: [...decisions[1].absorbs, absorbed("unreviewed")] },
    ]);
    // The ids the OFFER names: every id a destructive decision touches, which for a
    // merge is the survivor plus each absorbed id (`decisionFootprint`). The
    // tampered list is deliberately not represented here — that is the tamper.
    const ids = [
      decisions[0].id,
      decisions[1].id,
      ...decisions[1].absorbs.map((a) => a.id),
    ];
    process.stdout.write(JSON.stringify({ ids, clean, tampered }));
  '
)
IDS_JSON=$(jq -c '.ids' <<<"$ARTIFACT_META")
ARTIFACT_HASH=$(jq -r '.clean.hash' <<<"$ARTIFACT_META")
ARTIFACT_KEY=$(jq -r '.clean.key' <<<"$ARTIFACT_META")
TAMPERED_HASH=$(jq -r '.tampered.hash' <<<"$ARTIFACT_META")
TAMPERED_KEY=$(jq -r '.tampered.key' <<<"$ARTIFACT_META")
# A tamper that did not move the hash would make the whole case vacuous — the
# click would be refused for no reason at all and the harness would still pass.
if [[ "$ARTIFACT_HASH" == "$TAMPERED_HASH" ]]; then
  echo "::error::the tampered artifact hashes identically to the reviewed one — the refusal below would prove nothing" >&2
  exit 1
fi

OFFERED_NAME="${PREFIX}/approvals/offered"
# The colon of `sha256:` is replaced, matching `claimParameterName` in
# scripts/memory-cleanup.mjs and infra/src/oauth-facade/slack-interactions.ts. An
# SSM parameter name may contain only letters, numbers and `.-_` per sub-path, so
# the colon form is rejected by PutParameter — and on a READ it is parsed as a
# version selector instead, which is why the mismatch does not simply 404.
#
# TWO names, because the claim is named after the OFFERED record's hash rather
# than the button's (`claimParameterName(deps.ssmPrefix, offered.hash)`). So an
# accepted tamper would write its claim under the tampered hash, and a harness
# watching only the reviewed name would report "no claim" while an apply ran.
CLAIM_NAME="${PREFIX}/approvals/approved-${ARTIFACT_HASH//:/-}"
TAMPERED_CLAIM_NAME="${PREFIX}/approvals/approved-${TAMPERED_HASH//:/-}"

cleanup() {
  # Every record, always, including on failure: `offered` is overwritten by the
  # next real run, but a claim is written with `Overwrite: false`, so a leftover
  # would make the NEXT run's click a losing claim that starts nothing.
  aws ssm delete-parameter --name "$OFFERED_NAME" --region "$REGION" >/dev/null 2>&1 || true
  aws ssm delete-parameter --name "$CLAIM_NAME" --region "$REGION" >/dev/null 2>&1 || true
  aws ssm delete-parameter --name "$TAMPERED_CLAIM_NAME" --region "$REGION" >/dev/null 2>&1 || true
  # The lifecycle rule would expire both objects in 3 days anyway
  # (DECISION_ARTIFACT_TTL_DAYS); deleting them now keeps a torn-down preview
  # stage from leaving a readable list behind, and the tampered one especially:
  # it names an id no operator reviewed.
  for key in "$ARTIFACT_KEY" "$TAMPERED_KEY"; do
    [[ -n "$key" ]] || continue
    aws s3api delete-object --bucket "$ARTIFACT_BUCKET" --key "$key" \
      --region "$REGION" >/dev/null 2>&1 || true
  done
  rm -f "$ARTIFACT_BODY" "$TAMPERED_BODY"
}
trap cleanup EXIT

# `s3api put-object`, not `s3 cp`: the latter switches to a multipart upload above
# a threshold, and a multipart object's ETag is not its MD5 — irrelevant to the
# hash the apply checks (that one is over the BODY), but it also means the CLI
# needs additional permissions this role's grant is not scoped for.
#
# No `--server-side-encryption`: the bucket's default rule applies (SSE-KMS with
# `alias/aws/s3`, bucket keys on), and naming the key here would present an
# encryption context — the same reason `putDecisionArtifact` omits it. The apply
# task's `kms:Decrypt` is conditioned on the BUCKET arn as the context, which is
# what bucket keys make S3 present.
put_artifact() {
  local key="$1" body="$2"
  aws s3api put-object --bucket "$ARTIFACT_BUCKET" --key "$key" --body "$body" \
    --content-type application/json --region "$REGION" >/dev/null
}
echo "run-slack-approval-e2e: uploading the reviewed decision artifact and its tampered twin"
put_artifact "$ARTIFACT_KEY" "$ARTIFACT_BODY"
put_artifact "$TAMPERED_KEY" "$TAMPERED_BODY"

# `issuedAt` is what the facade measures the 72h offer window against (#149), and
# it is REQUIRED here rather than optional: an absent or unparseable stamp reads as
# EXPIRED on the callback side, so a record seeded without one is refused and the
# whole check below fails at "no approval record after a 200". `jq`'s `now` rather
# than `date -u -d`, which is GNU-only — this script is also run by hand on macOS.
#
# Ages are seconds off `now` so the two cases below stay readable: `0` is a list
# issued this instant, and `OFFER_EXPIRED_AGE` is comfortably past the window
# rather than one second over it, so a clock skew between the runner and the Lambda
# cannot make the expired case accidentally live.
OFFER_EXPIRED_AGE=$((96 * 3600))
# The offer's `hash` and its artifact coordinates are parameters rather than
# constants, because the tampered case turns on those three moving TOGETHER while
# the ids stay fixed — that is what an operator-invisible tamper looks like from
# the record's side.
seed_offer() {
  local age="$1" hash="$2" key="$3" record
  record=$(jq -cn --arg stage "$STAGE" --arg hash "$hash" --argjson ids "$IDS_JSON" \
    --arg bucket "$ARTIFACT_BUCKET" --arg key "$key" --argjson age "$age" \
    '{stage: $stage,
      hash: $hash,
      ids: $ids,
      artifactBucket: $bucket,
      artifactKey: $key,
      generatedAt: (now - $age | todate),
      issuedAt: (now - $age | todate)}')
  aws ssm put-parameter --name "$OFFERED_NAME" --type String --value "$record" \
    --overwrite --region "$REGION" >/dev/null
}

# Slack's own encoding: form-urlencoded with the JSON in a `payload` field. A
# JSON body would 400 here and pass nothing but a smoke test.
#
# ONE body, carrying the REVIEWED hash, for all three POSTs. That is deliberate:
# the button's value is whatever the message the operator saw put there, and every
# case below differs in what the STORE says, never in what the operator clicked.
# A second body signed over the tampered hash would be a different scenario — an
# operator clicking a button they were never shown.
PAYLOAD=$(jq -cn --arg hash "$ARTIFACT_HASH" \
  '{type: "block_actions",
    user: {id: "U0E2E", username: "ci"},
    actions: [{action_id: "cleanup_approve", type: "button", value: $hash}]}')
BODY="payload=$(jq -rn --arg p "$PAYLOAD" '$p | @uri')"

# The HMAC is computed in a node child that reads the secret from its
# ENVIRONMENT. `openssl dgst -hmac "$SECRET"` would put it in an argv, which is
# world-readable on the runner (TC-SLACKAPP-090). The BODY travels the same way,
# for the same reason it is a `--data-binary` argument below and not a here-doc:
# an argv is the one place it must not be, since a future payload could carry ids.
#
# The single quotes are load-bearing, so SC2016 is disabled rather than "fixed":
# the `${...}` below are JS template-literal substitutions that NODE must
# evaluate, and the values arrive through the child's environment. Switching to
# double quotes would interpolate them in the SHELL — which both breaks the
# script (the shell has no such variables) and would defeat the argv-avoidance
# this block exists for.
#
# One timestamp for the one signature, and that is a CONSTRAINT on the ordering
# below rather than an incidental choice: the façade enforces a 5-minute skew
# window (`MAX_TIMESTAMP_SKEW_MS`), so a click issued after the up-to-15-minute
# apply poll would be refused as a stale timestamp — a refusal indistinguishable
# from the ones under test. Every click therefore comes BEFORE the poll.
TIMESTAMP=$(date +%s)
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

# No claim under EITHER name. Both are checked on every assertion because the claim
# is keyed on the OFFERED record's hash: a step that wrote the wrong one would
# otherwise read as "nothing happened".
#
# Classified exactly like `ssm_value` above, and for the same reason stated there —
# `>/dev/null 2>&1` inside a bare `if` collapses "absent" with AccessDenied, a
# throttle, expired credentials, and the wrong region. Every one of those is a
# FAILED READ, but the collapsed form reads them all as "no claim", which is this
# function's PASS condition. That inverts the strongest assertion in the tampered
# step, where "no claim" is the sole evidence that no apply task ran: a single
# transient SSM error would let a facade that claims the approval and starts an
# apply anyway report `OK` and exit 0. `set -e` cannot help, because the failure is
# consumed by the `if` condition. So only ParameterNotFound means absent.
assert_no_claim() {
  local why="$1" name err rc
  for name in "$CLAIM_NAME" "$TAMPERED_CLAIM_NAME"; do
    err=$(mktemp)
    rc=0
    aws ssm get-parameter --name "$name" --region "$REGION" >/dev/null 2>"$err" ||
      rc=$?
    local stderr_text
    stderr_text=$(<"$err")
    rm -f "$err"
    if ((rc == 0)); then
      echo "::error::${why} (a claim exists at ${name})" >&2
      exit 1
    fi
    if [[ "$stderr_text" != *ParameterNotFound* ]]; then
      echo "::error::${why} — could not determine whether a claim exists at ${name} (exit ${rc}): ${stderr_text}" >&2
      exit 1
    fi
  done
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
assert_no_claim "a rejected interaction still wrote an approval record"

# 2. The EXPIRED offer (#149). A correctly signed click against a list issued
#    outside the 72h window must be refused, and must write no claim.
#
#    This runs before the live click and after the 401 for the same reason the 401
#    comes first: "no claim was written" is only assertable while no claim exists.
#    Reversed, the expired probe would have to prove the absence of a record the
#    successful click had already created.
#
#    The refusal is an HTTP 200 with an ephemeral Slack message, not an error
#    status — Slack renders a non-200 as its own "operation failed" and the
#    operator never sees the reason. So the status alone cannot distinguish this
#    from an ACCEPTED click; the body and the absent claim are what do.
echo "run-slack-approval-e2e: seeding ${OFFERED_NAME} with a list issued $((OFFER_EXPIRED_AGE / 3600))h ago"
seed_offer "$OFFER_EXPIRED_AGE" "$ARTIFACT_HASH" "$ARTIFACT_KEY"
echo "run-slack-approval-e2e: POSTing a signed click against the expired list (expecting a refusal)"
EXPIRED_STATUS=$(post "$SIGNATURE" "$RESPONSE_BODY")
if [[ "$EXPIRED_STATUS" != "200" ]]; then
  echo "::error::the click against an expired list was answered HTTP ${EXPIRED_STATUS}, not 200 — Slack shows the operator no reason for a non-200" >&2
  exit 1
fi
# `expire` is the one word no OTHER refusal in the handler uses: "regenerated",
# "names stage", "could not be read" and "already been applied" are all 200s with a
# body too, so matching a generic "nothing was applied" would pass on a stale-hash
# refusal and prove nothing about the TTL.
EXPIRED_REPLY=$(<"$RESPONSE_BODY")
if ! grep -qi 'expire' <<<"$EXPIRED_REPLY"; then
  echo "::error::the click against an expired list was not refused as expired: ${EXPIRED_REPLY}" >&2
  exit 1
fi
assert_no_claim "an expired approval still wrote a claim — the refusal is cosmetic and an apply may have started"

# 3. The TAMPERED artifact (#150). The offered record now names the tampered
#    object and carries its hash, while its `ids` are byte-identical to the
#    reviewed offer's — the operator saw one list and the store holds another.
#    The click carries the REVIEWED hash, which is the whole point: that is the
#    value the message the operator was shown put on its button.
#
#    Third for the same reason the 401 is first: "no apply task ran" is only
#    assertable while no claim exists, and the live click below creates one. The
#    refusal comes from the façade's hash comparison, ahead of the
#    `Overwrite: false` claim write and therefore ahead of `RunTask` — so an
#    absent claim IS an absent task, and no second Fargate lifecycle is needed to
#    prove it.
echo "run-slack-approval-e2e: seeding ${OFFERED_NAME} against the TAMPERED artifact, issued now"
seed_offer 0 "$TAMPERED_HASH" "$TAMPERED_KEY"
echo "run-slack-approval-e2e: POSTing the reviewed hash against the tampered record (expecting a refusal)"
TAMPERED_STATUS=$(post "$SIGNATURE" "$RESPONSE_BODY")
if [[ "$TAMPERED_STATUS" != "200" ]]; then
  echo "::error::the click against a tampered artifact was answered HTTP ${TAMPERED_STATUS}, not 200 — Slack shows the operator no reason for a non-200" >&2
  exit 1
fi
# `regenerated` is the handler's word for a hash that does not match the current
# record, and it is asserted rather than accepting any refusal: an `expire` reply
# here would mean the record's `issuedAt` was wrong and the hash comparison never
# ran, which is a pass for the wrong reason.
TAMPERED_REPLY=$(<"$RESPONSE_BODY")
if ! grep -qi 'regenerated' <<<"$TAMPERED_REPLY"; then
  echo "::error::the click against a tampered artifact was not refused as a hash mismatch: ${TAMPERED_REPLY}" >&2
  exit 1
fi
assert_no_claim "a tampered artifact still produced a claim — an apply task may have deleted an id no operator reviewed"

# 4. The correctly signed click against the REVIEWED list. Reseeded rather than
#    reusing the record above: the ids are the same either way, so what changes
#    between the refusals and the acceptance is `issuedAt` and the artifact the
#    record points at.
echo "run-slack-approval-e2e: seeding ${OFFERED_NAME} against the reviewed artifact, issued now"
seed_offer 0 "$ARTIFACT_HASH" "$ARTIFACT_KEY"
echo "run-slack-approval-e2e: POSTing a correctly signed interaction (expecting 200)"
GOOD_STATUS=$(post "$SIGNATURE" "$RESPONSE_BODY")
if [[ "$GOOD_STATUS" != "200" ]]; then
  echo "::error::the signed interaction was answered HTTP ${GOOD_STATUS}, not 200" >&2
  exit 1
fi

# 5. The RECORD, read back by name. A 200 alone proves nothing: the handler also
#    answers 200 for a stale hash, an expired list, an unknown action, and
#    "already applied".
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

# 6. The apply task's own exit code. Without this the check passes on a click
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

# 7. The task REPLAYED the reviewed artifact (#150). Everything above is also
#    satisfied by a task that ignored the artifact and re-classified: the ids are
#    synthetic, so a fresh scan finds nothing to delete and exits 0 too. This is
#    the only assertion that separates the two, and without it the MERGE case
#    proves nothing at all.
#
# The log group comes from the task definition's own `awslogs-group`, not from a
# hand-computed `/sst/...` path: SST auto-names container log groups with random
# hash segments and sets `ignoreChanges: ["name"]`, so an assumed name matches no
# real group and every query answers ResourceNotFoundException — which is how the
# mnemo-server log-scan guard silently never ran (#137). The stream is derived the
# same way `run-consolidation-task.sh` derives its own.
TASK_DEF=$(ssm_value "${PREFIX}/cleanup/task-def-arn")
if [[ -z "$TASK_DEF" || "$TASK_DEF" == "None" ]]; then
  echo "::error::no cleanup/task-def-arn on ${STAGE}, so the replay assertion cannot run" >&2
  exit 1
fi
TASK_DEFINITION=$(aws ecs describe-task-definition --task-definition "$TASK_DEF" \
  --region "$REGION" --output json)
# Selected by the container name the callback Lambda's `containerOverrides` targets,
# so a rename that would make `RunTask` reject the override fails HERE with a name
# in the message rather than as an opaque ECS validation error after a spent click.
CONTAINER_NAME="Mem9Cleanup"
LOG_GROUP=""
LOG_PREFIX=""
# `|| true`: a container that does not match selects nothing, so `read` hits EOF and
# returns 1 — which under `set -e` would abort the run right here, with no message at
# all. Letting it fail into empty strings is what lets the check below name the
# container instead.
read -r LOG_GROUP LOG_PREFIX < <(jq -r --arg name "$CONTAINER_NAME" \
  '.taskDefinition.containerDefinitions[]
   | select(.name == $name)
   | .logConfiguration.options
   | "\(.["awslogs-group"] // "") \(.["awslogs-stream-prefix"] // "")"' \
  <<<"$TASK_DEFINITION") || true
if [[ -z "$LOG_GROUP" || -z "$LOG_PREFIX" ]]; then
  # `${TASK_DEF##*/}` — family:revision, NOT the full ARN. `TASK_DEF` is read from
  # SSM and carries the live account id, so interpolating it here would print that
  # id into public CI logs on exactly the failure path a reader has to look at. The
  # comment below already refuses to echo a matched log line for that reason; this
  # line was contradicting it. family:revision is what identifies the definition to
  # a reader anyway.
  echo "::error::container ${CONTAINER_NAME} in ${TASK_DEF##*/} has no awslogs group/stream prefix — the replay assertion cannot run" >&2
  exit 1
fi
LOG_STREAM="${LOG_PREFIX}/${CONTAINER_NAME}/${TASK_ARN##*/}"

# `TIMESTAMP` is the second the click was signed, which is before RunTask and after
# any earlier run's logs — a start bound that costs nothing and keeps a previous
# preview run's replay line from satisfying this.
#
# Only the COUNT is ever read, never a matched message. The line names the artifact
# as `s3://mem9-audit-<account-id>/...`, so echoing a match would print the account
# id into public CI logs; and `filter-log-events` matches the pattern as a
# SUBSTRING, so in principle any line quoting it also matches. A count is the whole
# assertion — `loadDecisionArtifact` emits this line only after the fetched bytes
# hashed to the approved value, so its presence IS "the reviewed list was replayed".
echo "run-slack-approval-e2e: checking ${LOG_STREAM} for the artifact-replay line"
REPLAYED=0
for attempt in 1 2 3 4 5 6; do
  MATCHES=$(aws logs filter-log-events \
    --log-group-name "$LOG_GROUP" \
    --log-stream-names "$LOG_STREAM" \
    --filter-pattern '"reviewed decision(s) from s3://"' \
    --start-time "$((TIMESTAMP * 1000))" \
    --region "$REGION" \
    --query 'length(events)' \
    --output text 2>/dev/null || true)
  if [[ "$MATCHES" =~ ^[0-9]+$ ]] && ((MATCHES > 0)); then
    REPLAYED=$MATCHES
    break
  fi
  echo "run-slack-approval-e2e: replay line not visible yet (attempt ${attempt}/6)"
  sleep 10
done
if ((REPLAYED == 0)); then
  echo "::error::the apply task never logged an artifact replay — it exited 0 by re-classifying instead of applying the reviewed list, so the approved MERGE was not what ran" >&2
  exit 1
fi

echo "run-slack-approval-e2e: OK — expired list refused, tampered artifact refused with no apply task, signed click accepted, record written, reviewed list (DELETE + MERGE) replayed, apply exited 0 on ${STAGE}"
