#!/usr/bin/env bash
# rollout-workload-permissions-boundary.sh - Guarded, resumable migration for
# every project workload role in the deployed iam:PassRole scope.
#
# Usage:
#   WORKLOAD_BOUNDARY_MAINTENANCE_ACK=true \
#     scripts/rollout-workload-permissions-boundary.sh
#
# The acknowledgement means application deploys are paused for the migration.
# Any failure after the quarantine write leaves it in place. Correct the error
# and run the exact Resume command printed on failure; never remove the
# quarantine manually.

set -euo pipefail

now_epoch_ms() {
  local epoch_nanoseconds
  epoch_nanoseconds="$(date +%s%N)"
  if [[ ! "$epoch_nanoseconds" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  printf '%s' "$((epoch_nanoseconds / 1000000))"
}
rollout_started_at_ms="$(now_epoch_ms)"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
contract_file="$repo_root/scripts/workload-permissions-boundary-contract.json"
resume_state_file="$repo_root/.env.workload-boundary-resume"
rollout_lock_file="$repo_root/.workload-boundary-rollout.local.lock"
maintenance_ack_override_set="${WORKLOAD_BOUNDARY_MAINTENANCE_ACK+x}"
maintenance_ack_override="${WORKLOAD_BOUNDARY_MAINTENANCE_ACK-}"
dotenv_file="${WORKLOAD_BOUNDARY_ENV_FILE:-$repo_root/.env}"
if [[ "$dotenv_file" != /* ]]; then
  dotenv_file="$repo_root/$dotenv_file"
fi
if [[ -f "$resume_state_file" &&
      "$dotenv_file" != "$resume_state_file" &&
      "${1:-}" != "--help" &&
      "${1:-}" != "-h" ]]; then
  echo "Retained rollout context exists; use the printed Resume command." >&2
  exit 2
fi
# shellcheck source=/dev/null
if [[ "${WORKLOAD_BOUNDARY_SKIP_DOTENV:-false}" != "true" && -f "$dotenv_file" ]]; then
  set -a
  . "$dotenv_file"
  set +a
fi
if [[ "$maintenance_ack_override_set" == "x" ]]; then
  export WORKLOAD_BOUNDARY_MAINTENANCE_ACK="$maintenance_ack_override"
fi
configured_application_region="$(node "$repo_root/scripts/resolve-application-region.mjs")"
effective_application_region="${WORKLOAD_BOUNDARY_APPLICATION_REGION:-$configured_application_region}"
if [[ "$effective_application_region" != "$configured_application_region" ]]; then
  echo "Application region must match sst.config.ts; no mutation was attempted." >&2
  exit 2
fi
if [[ ! "$effective_application_region" =~ ^[a-z]{2}(-gov)?-[a-z0-9-]+-[0-9]+$ ]]; then
  echo "Application region is malformed; no mutation was attempted." >&2
  exit 2
fi
export WORKLOAD_BOUNDARY_APPLICATION_REGION="$effective_application_region"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
  exit 0
fi
if [[ $# -ne 0 ]]; then
  echo "Unknown option: $1" >&2
  exit 2
fi
if [[ "${WORKLOAD_BOUNDARY_MAINTENANCE_ACK:-}" != "true" ]]; then
  echo "Set and verify the deployment pause, then acknowledge the maintenance window." >&2
  echo "No boundary or IAM mutation was attempted." >&2
  exit 2
fi

gh_timeout="${WORKLOAD_BOUNDARY_GH_TIMEOUT:-30s}"
if [[ ! "$gh_timeout" =~ ^[0-9]+([.][0-9]+)?[smh]?$ ]]; then
  echo "WORKLOAD_BOUNDARY_GH_TIMEOUT is malformed." >&2
  exit 2
fi
if ! command -v aws >/dev/null 2>&1 ||
    ! command -v flock >/dev/null 2>&1 ||
    ! command -v gh >/dev/null 2>&1 ||
    ! command -v jq >/dev/null 2>&1 ||
    ! command -v timeout >/dev/null 2>&1; then
  echo "aws, flock, gh, jq, and timeout are required to verify the guarded rollout." >&2
  exit 2
fi
exec 9>"$rollout_lock_file"
if ! flock -n 9; then
  echo "Another workload permissions-boundary rollout is already active." >&2
  exit 2
fi
if ! gh_timeout_ms="$(jq -ner --arg value "$gh_timeout" '
    ($value
      | capture("^(?<amount>[0-9]+(?:[.][0-9]+)?)(?<unit>[smh]?)$")
    ) as $parsed
    | (
        ($parsed.amount | tonumber) *
        (if $parsed.unit == "h" then 3600
         elif $parsed.unit == "m" then 60
         else 1
         end) *
        1000
        | floor
      )
    | select(. > 0)
  ')"; then
  echo "WORKLOAD_BOUNDARY_GH_TIMEOUT is malformed." >&2
  exit 2
fi
if ! rollout_timeout_ms="$(jq -er '
    .rolloutTimeoutMs
    | select(
        type == "number" and
        floor == . and
        . > 0 and
        . <= 3600000
      )
  ' "$contract_file" 2>/dev/null)"; then
  echo "Workload permissions-boundary contract is malformed." >&2
  exit 2
fi
if ! shutdown_grace_ms="$(jq -er --argjson rollout "$rollout_timeout_ms" '
    .shutdownGraceMs
    | select(
        type == "number" and
        floor == . and
        . > 0 and
        . < $rollout and
        . <= 60000
      )
  ' "$contract_file" 2>/dev/null)"; then
  echo "Workload permissions-boundary contract is malformed." >&2
  exit 2
fi
rollout_hard_deadline_at_ms=$((rollout_started_at_ms + rollout_timeout_ms))
rollout_deadline_at_ms=$((rollout_hard_deadline_at_ms - shutdown_grace_ms))
if ! repository="$(jq -er '
    .repository
    | select(type == "string" and test("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"))
  ' "$contract_file" 2>/dev/null)"; then
  echo "Workload permissions-boundary contract is malformed." >&2
  exit 2
fi
if [[ -n "${GITHUB_REPOSITORY:-}" &&
      "${GITHUB_REPOSITORY}" != "$repository" ]]; then
  echo "GitHub repository identity does not match this rollout." >&2
  exit 2
fi
remaining_deadline_ms() {
  local remaining
  remaining=$((rollout_deadline_at_ms - $(now_epoch_ms)))
  if [[ "$remaining" -le 0 ]]; then
    return 1
  fi
  printf '%s' "$remaining"
}
remaining_hard_deadline_ms() {
  local remaining
  remaining=$((rollout_hard_deadline_at_ms - $(now_epoch_ms)))
  if [[ "$remaining" -le 0 ]]; then
    return 1
  fi
  printf '%s' "$remaining"
}
run_gh() {
  local effective_timeout remaining remaining_duration
  remaining="$(remaining_deadline_ms)" || return 124
  effective_timeout="$gh_timeout_ms"
  if [[ "$remaining" -lt "$effective_timeout" ]]; then
    effective_timeout="$remaining"
  fi
  printf -v remaining_duration '%d.%03ds' \
    "$((effective_timeout / 1000))" "$((effective_timeout % 1000))"
  timeout --signal=TERM --kill-after=1s "$remaining_duration" gh "$@"
}
if ! workflows_json="$(jq -ce '
    .deploymentWorkflows
    | select(
        type == "array" and
        length > 0 and
        all(
          .[];
          (.id | type) == "string" and
          (.path | type) == "string" and
          (.reviewedBlob | type) == "string" and
          (.reviewedBlob | test("^[0-9a-f]{40}$"))
        )
      )
    | select(
        ([.[].id] | length) == ([.[].id] | unique | length) and
        ([.[].path] | length) == ([.[].path] | unique | length)
      )
  ' "$contract_file" 2>/dev/null)"; then
  echo "Workload permissions-boundary contract is malformed." >&2
  exit 2
fi
if ! nonterminal_statuses_json="$(jq -ce '
    .nonterminalWorkflowStatuses
    | select(
        type == "array" and
        length > 0 and
        all(.[]; type == "string" and test("^[a-z_]+$")) and
        length == (unique | length)
      )
  ' "$contract_file" 2>/dev/null)"; then
  echo "Workload permissions-boundary contract is malformed." >&2
  exit 2
fi
origin_url="$(git -C "$repo_root" remote get-url origin 2>/dev/null || true)"
if [[ "$origin_url" != "git@github.com:${repository}.git" &&
      "$origin_url" != "https://github.com/${repository}.git" ]]; then
  echo "Local repository identity does not match this rollout." >&2
  exit 2
fi
default_branch="$(run_gh repo view "$repository" \
  --json defaultBranchRef --jq .defaultBranchRef.name 2>/dev/null || true)"
if [[ ! "$default_branch" =~ ^[A-Za-z0-9._/-]+$ ]]; then
  echo "Could not resolve the repository default branch; no IAM mutation attempted." >&2
  exit 2
fi
default_sha="$(run_gh api "repos/$repository/commits/$default_branch" \
  --jq .sha 2>/dev/null || true)"
local_sha="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || true)"
if [[ ! "$default_sha" =~ ^[0-9a-f]{40}$ || "$local_sha" != "$default_sha" ]]; then
  echo "Run the rollout from the exact current default-branch commit." >&2
  exit 2
fi
if ! git -C "$repo_root" diff --quiet HEAD -- ||
    ! git -C "$repo_root" diff --cached --quiet HEAD --; then
  echo "Tracked files differ from the reviewed default-branch commit." >&2
  exit 2
fi

verify_reviewed_workflow() {
  local path="$1"
  local expected_blob="$2"
  local remote_blob local_blob
  remote_blob="$(run_gh api --method GET \
    "repos/$repository/contents/$path" \
    -f "ref=$default_branch" \
    --jq .sha 2>/dev/null || true)"
  local_blob="$(git -C "$repo_root" hash-object "$path" 2>/dev/null || true)"
  [[ "$remote_blob" == "$expected_blob" && "$local_blob" == "$expected_blob" ]]
}

# Exact reviewed workflow blobs. Any later workflow edit must update the
# contract in a reviewed change before the one-time migration can run.
while IFS=$'\t' read -r workflow_path expected_blob; do
  if ! verify_reviewed_workflow "$workflow_path" "$expected_blob"; then
    echo "Merge the exact reviewed maintenance-gate workflows before rollout." >&2
    exit 2
  fi
done < <(jq -r '.[] | [.path, .reviewedBlob] | @tsv' <<<"$workflows_json")
validated_run_id="$(run_gh run list \
  --repo "$repository" \
  --workflow infra-ci.yml \
  --commit "$default_sha" \
  --event push \
  --limit 20 \
  --json databaseId,status \
  --jq '[.[] | select(.status == "completed")][0].databaseId // empty' \
  2>/dev/null || true)"
if [[ ! "$validated_run_id" =~ ^[0-9]+$ ]]; then
  echo "The exact-head push CI run must complete before rollout." >&2
  exit 2
fi
successful_validation_job_count="$(run_gh run view "$validated_run_id" \
  --repo "$repository" \
  --json jobs \
  --jq '[.jobs[] | select(.name == "Typecheck & Unit Tests" and .conclusion == "success")] | length' \
  2>/dev/null || true)"
if [[ "$successful_validation_job_count" != "1" ]]; then
  echo "The exact-head non-AWS validation job must succeed before rollout." >&2
  exit 2
fi

remaining="$(remaining_deadline_ms)" || {
  echo "The rollout deadline expired before AWS identity verification." >&2
  exit 2
}
effective_identity_timeout="$gh_timeout_ms"
if [[ "$remaining" -lt "$effective_identity_timeout" ]]; then
  effective_identity_timeout="$remaining"
fi
printf -v identity_timeout_duration '%d.%03ds' \
  "$((effective_identity_timeout / 1000))" \
  "$((effective_identity_timeout % 1000))"
caller_identity="$(timeout --signal=TERM --kill-after=1s \
  "$identity_timeout_duration" aws sts get-caller-identity \
  --output json --no-cli-pager 2>/dev/null || true)"
caller_account_id="$(jq -r '.Account // empty' <<<"$caller_identity")"
caller_partition="$(jq -r '.Arn // empty' <<<"$caller_identity" |
  sed -n 's/^arn:\([^:]*\):.*/\1/p')"
if [[ ! "$caller_account_id" =~ ^[0-9]{12}$ ||
      ! "$caller_partition" =~ ^[a-z0-9-]+$ ]]; then
  echo "AWS caller identity is malformed; no IAM mutation attempted." >&2
  exit 2
fi
if [[ -n "${WORKLOAD_BOUNDARY_EXPECTED_ACCOUNT_ID:-}" &&
      "$caller_account_id" != "$WORKLOAD_BOUNDARY_EXPECTED_ACCOUNT_ID" ]]; then
  echo "AWS caller account differs from the retained rollout context." >&2
  exit 2
fi
if [[ -n "${WORKLOAD_BOUNDARY_EXPECTED_PARTITION:-}" &&
      "$caller_partition" != "$WORKLOAD_BOUNDARY_EXPECTED_PARTITION" ]]; then
  echo "AWS partition differs from the retained rollout context." >&2
  exit 2
fi

resume_state_tmp="${resume_state_file}.tmp.$$"
# Invoked by the EXIT trap below.
# shellcheck disable=SC2329
cleanup_resume_state_tmp() {
  rm -f "$resume_state_tmp"
}
trap cleanup_resume_state_tmp EXIT
write_resume_assignment() {
  local name="$1"
  if [[ -v "$name" ]]; then
    printf '%s=' "$name"
    printf '%q' "${!name}"
    printf '\n'
  fi
}
(
  umask 077
  {
    for name in \
      AWS_PROFILE \
      AWS_DEFAULT_PROFILE \
      AWS_REGION \
      AWS_DEFAULT_REGION \
      AWS_CONFIG_FILE \
      AWS_SHARED_CREDENTIALS_FILE \
      AWS_CA_BUNDLE \
      MEM9_LLM_RESPONSES_REGION \
      WORKLOAD_BOUNDARY_APPLICATION_REGION \
      WORKLOAD_BOUNDARY_OPENAI_PROJECT_REGION \
      BEDROCK_PROJECT_STACK_NAME \
      MEM9_TEMPLATE_BUCKET \
      MEM9_VPC_ID \
      WORKLOAD_BOUNDARY_GH_TIMEOUT; do
      write_resume_assignment "$name"
    done
    printf 'WORKLOAD_BOUNDARY_EXPECTED_ACCOUNT_ID=%q\n' "$caller_account_id"
    printf 'WORKLOAD_BOUNDARY_EXPECTED_PARTITION=%q\n' "$caller_partition"
  } > "$resume_state_tmp"
)
chmod 600 "$resume_state_tmp"
mv -f "$resume_state_tmp" "$resume_state_file"

pause_value="$(run_gh variable get DEPLOYMENT_MAINTENANCE_PAUSED \
  --repo "$repository" --json value --jq .value 2>/dev/null || true)"
if [[ "$pause_value" != "true" ]]; then
  echo "Set DEPLOYMENT_MAINTENANCE_PAUSED=true before any IAM mutation." >&2
  exit 2
fi

disable_deployment_workflow() {
  local workflow="$1"
  local state
  state="$(run_gh api "repos/$repository/actions/workflows/$workflow" \
    --jq .state 2>/dev/null || true)"
  case "$state" in
    active)
      if ! run_gh workflow disable "$workflow" --repo "$repository" >/dev/null; then
        return 1
      fi
      ;;
    disabled_manually)
      ;;
    *)
      return 1
      ;;
  esac
  state="$(run_gh api "repos/$repository/actions/workflows/$workflow" \
    --jq .state 2>/dev/null || true)"
  [[ "$state" == "disabled_manually" ]]
}

while IFS= read -r workflow; do
  if ! disable_deployment_workflow "$workflow"; then
    echo "Could not disable every deployment workflow; keep maintenance paused and re-run." >&2
    exit 2
  fi
done < <(jq -r '.[].id' <<<"$workflows_json")

count_active_runs() {
  local workflow="$1"
  local count status total=0
  while IFS= read -r status; do
    count="$(run_gh run list \
      --repo "$repository" \
      --workflow "$workflow" \
      --status "$status" \
      --all \
      --limit 1 \
      --json databaseId \
      --jq 'length' 2>/dev/null || true)"
    if [[ ! "$count" =~ ^[0-9]+$ ]]; then
      return 1
    fi
    total=$((total + count))
  done < <(jq -r '.[]' <<<"$nonterminal_statuses_json")
  printf '%s' "$total"
}

require_idle_deployment_workflows() {
  local workflow count total=0
  while IFS= read -r workflow; do
    count="$(count_active_runs "$workflow")" || return 1
    total=$((total + count))
  done < <(jq -r '.[].id' <<<"$workflows_json")
  [[ "$total" -eq 0 ]]
}

if ! require_idle_deployment_workflows; then
  echo "An AWS deployment workflow is queued or active; no IAM mutation attempted." >&2
  exit 2
fi

node_major="$(node -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null || true)"
if [[ ! "$node_major" =~ ^[0-9]+$ || "$node_major" -lt 24 ]]; then
  echo "Node.js 24 or newer is required before any boundary or IAM mutation." >&2
  exit 2
fi

if ! require_idle_deployment_workflows; then
  echo "An AWS deployment workflow started during the drain; no IAM mutation attempted." >&2
  exit 2
fi

remaining_deadline_ms >/dev/null || {
  echo "The rollout deadline expired before IAM migration started." >&2
  exit 2
}
remaining="$(remaining_hard_deadline_ms)" || {
  echo "The rollout deadline expired before IAM migration started." >&2
  exit 2
}
printf -v remaining_duration '%d.%03ds' \
  "$((remaining / 1000))" "$((remaining % 1000))"
set +e
rollout_pid=""
rollout_signal_name=""
rollout_signal_exit=""
# Invoked indirectly by the signal traps below.
# shellcheck disable=SC2329
forward_rollout_signal() {
  local signal_name="$1"
  local signal_exit="$2"
  rollout_signal_name="$signal_name"
  rollout_signal_exit="$signal_exit"
  if [[ -n "$rollout_pid" ]] && kill -0 "$rollout_pid" 2>/dev/null; then
    kill -s "$signal_name" "$rollout_pid" 2>/dev/null || true
  fi
}
trap 'forward_rollout_signal INT 130' INT
trap 'forward_rollout_signal TERM 143' TERM
WORKLOAD_BOUNDARY_GATES_VERIFIED=true \
WORKLOAD_BOUNDARY_SKIP_DOTENV=true \
  timeout --signal=KILL "$remaining_duration" \
    node "$repo_root/scripts/run-workload-permissions-boundary-rollout.mjs" \
      --reviewed-commit "$default_sha" \
      --deadline-at "$rollout_deadline_at_ms" &
rollout_pid=$!
if [[ -n "$rollout_signal_exit" ]]; then
  kill -s "$rollout_signal_name" "$rollout_pid" 2>/dev/null || true
fi
while true; do
  wait "$rollout_pid"
  rollout_exit=$?
  if ! kill -0 "$rollout_pid" 2>/dev/null; then
    break
  fi
done
trap - INT TERM
if [[ -n "$rollout_signal_exit" ]]; then
  rollout_exit="$rollout_signal_exit"
fi
set -e
if [[ "$rollout_exit" -eq 0 ]]; then
  rm -f "$resume_state_file"
fi
exit "$rollout_exit"
