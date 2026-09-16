#!/usr/bin/env bash
# Launch the shared cleanup task with its deployed report-only command.
# Credentials are inherited. Only the selected stage's cleanup metadata is read.
# Task and log identifiers remain private; console output is reconstructed.

set +x
set -euo pipefail

fail() { printf 'run-cleanup: %s\n' "$1" >&2; exit 1; }

if [[ $# == 1 && "$1" == "--help" ]]; then
  printf '%s\n' 'STAGE=<stage> MEM9_NAMESPACE_ID=<uuid> scripts/run-cleanup-task.sh' \
    'Report-only; no command flags accepted. CLEANUP_TASK_WAIT_SECONDS: 1..43200 (default 43200).' \
    'A timeout leaves the task running; avoid launching a duplicate report.'
  exit 0
fi
[[ $# == 0 ]] || fail 'report-only launcher accepts no command flags'
STAGE="${STAGE:-}"
MEM9_NAMESPACE_ID="${MEM9_NAMESPACE_ID:-}"
WAIT_SECONDS="${CLEANUP_TASK_WAIT_SECONDS-43200}"
[[ "$STAGE" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,63}$ ]] || fail 'valid STAGE is required'
[[ "$MEM9_NAMESPACE_ID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ||
  fail 'one lowercase namespace UUID is required'
[[ "$WAIT_SECONDS" =~ ^[1-9][0-9]{0,4}$ ]] || fail 'invalid cleanup wait budget'
(( WAIT_SECONDS <= 43200 )) || fail 'invalid cleanup wait budget'
export MEM9_NAMESPACE_ID AWS_CLI_AUTO_PROMPT=off AWS_PAGER=""

for program in aws jq timeout; do
  command -v "$program" >/dev/null 2>&1 || fail 'required launcher tool is unavailable'
done
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${AWS_REGION:-}" ]]; then
  REGION="$AWS_REGION"
else
  REGION=$(node "$REPO_ROOT/scripts/resolve-application-region.mjs" 2>/dev/null) || fail 'application region is unavailable'
fi
[[ "$REGION" =~ ^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$ ]] || fail 'invalid application region'
PREFIX="/mem9-on-aws/${STAGE}/maintenance/cleanup"
CONTAINER_NAME="Mem9Cleanup"

# Bound the entire CLI process, including credential resolution. During task
# polling, each call also fits within the remaining observation budget.
aws_json() {
  local budget=40 remaining
  if [[ -n "${POLL_DEADLINE:-}" ]]; then
    remaining=$((POLL_DEADLINE - SECONDS))
    (( remaining > 0 )) || return 124
    if (( remaining < budget )); then budget=$remaining; fi
  fi
  timeout --kill-after=5 "$budget" aws "$@" \
    --cli-connect-timeout 5 --cli-read-timeout 30 --no-cli-pager --output json 2>/dev/null
}

PARAMETER_NAMES=(
  "${PREFIX}/cluster-name" "${PREFIX}/task-def-arn" "${PREFIX}/task-sg-id"
  "${PREFIX}/subnet-ids" "${PREFIX}/log-group-name"
)
PARAMETERS=$(aws_json ssm get-parameters --names "${PARAMETER_NAMES[@]}" --region "$REGION") ||
  fail 'cleanup metadata could not be read'
EXPECTED_NAMES=$(printf '%s\n' "${PARAMETER_NAMES[@]}" | jq -Rsc 'split("\n")[:-1]')
if ! jq -e --argjson expected "$EXPECTED_NAMES" '
  (.InvalidParameters // [] | length) == 0
  and (.Parameters | type == "array")
  and ([.Parameters[].Name] | sort) == ($expected | sort)
  and all(.Parameters[]; (.Value | type == "string") and (.Value | length > 0) and (.Value | test("[\\r\\n]") | not))
' >/dev/null 2>&1 <<<"$PARAMETERS"; then fail 'cleanup metadata is incomplete or malformed'; fi
parameter_value() { jq -er --arg name "$1" '.Parameters[] | select(.Name == $name) | .Value' <<<"$PARAMETERS"; }
CLUSTER=$(parameter_value "${PREFIX}/cluster-name")
TASK_DEF=$(parameter_value "${PREFIX}/task-def-arn")
TASK_SG_CSV=$(parameter_value "${PREFIX}/task-sg-id")
SUBNETS_CSV=$(parameter_value "${PREFIX}/subnet-ids")
LOG_GROUP=$(parameter_value "${PREFIX}/log-group-name")

DEFINITION=$(aws_json ecs describe-task-definition --task-definition "$TASK_DEF" --region "$REGION") ||
  fail 'cleanup task configuration could not be read'
# Preserve the exact default command. Refuse drift to apply/restore or another
# executable before RunTask, rather than attempting to sanitize arbitrary argv.
if ! CONTAINER=$(jq -ce --arg name "$CONTAINER_NAME" --arg stage "$STAGE" --arg group "$LOG_GROUP" '
  [.taskDefinition.containerDefinitions[] | select(.name == $name)]
  | select(length == 1) | .[0]
  | select(.entryPoint == ["node"])
  | select((.command | length) == 5
      and .command[0] == "/app/scripts/memory-cleanup.mjs"
      and .command[1] == "--stage" and .command[2] == $stage
      and .command[3] == "--base-url" and (.command[4] | test("^https?://[^[:space:]]+$")))
  | select(.logConfiguration.logDriver == "awslogs"
      and .logConfiguration.options["awslogs-group"] == $group)
  | select(.logConfiguration.options["awslogs-stream-prefix"] | type == "string" and length > 0)
' 2>/dev/null <<<"$DEFINITION"); then fail 'cleanup task defaults are not the expected report-only configuration'; fi
LOG_PREFIX=$(jq -r '.logConfiguration.options["awslogs-stream-prefix"]' <<<"$CONTAINER")
LOG_REGION=$(jq -r --arg region "$REGION" '.logConfiguration.options["awslogs-region"] // $region' <<<"$CONTAINER")
[[ "$LOG_REGION" =~ ^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$ ]] || fail 'invalid task log region'

umask 077
WORK_DIR=$(mktemp -d) || fail 'private launcher workspace could not be created'
trap 'rm -rf -- "$WORK_DIR"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if ! jq -ne --arg cluster "$CLUSTER" --arg task "$TASK_DEF" --arg container "$CONTAINER_NAME" \
    --arg subnets "$SUBNETS_CSV" --arg groups "$TASK_SG_CSV" '
  ($subnets | split(",")) as $subnets | ($groups | split(",")) as $groups
  | select(all($subnets[]; test("^subnet-[A-Za-z0-9]+$")) and all($groups[]; test("^sg-[A-Za-z0-9]+$")))
  | {cluster:$cluster, taskDefinition:$task, launchType:"FARGATE", count:1,
      networkConfiguration:{awsvpcConfiguration:{subnets:$subnets,securityGroups:$groups,assignPublicIp:"DISABLED"}},
      overrides:{containerOverrides:[{name:$container,environment:[{name:"MEM9_NAMESPACE_ID",value:$ENV.MEM9_NAMESPACE_ID}]}]}}
' >"$WORK_DIR/run-task.json" 2>/dev/null; then fail 'cleanup network metadata is invalid'; fi
START_TIME_MS=$(( $(date +%s) * 1000 ))
printf '%s\n' 'run-cleanup: starting report-only task'
RUN_OUT=$(aws_json ecs run-task --cli-input-json "file://$WORK_DIR/run-task.json" --region "$REGION") ||
  fail 'task launch was not confirmed; avoid launching a duplicate report'
TASK_ARN=$(jq -er '
  select((.failures // [] | length) == 0 and (.tasks | length) == 1)
  | .tasks[0].taskArn | select(type == "string" and length > 0)
' 2>/dev/null <<<"$RUN_OUT") || fail 'cleanup task launch was not confirmed'

POLL_DEADLINE=$((SECONDS + WAIT_SECONDS))
MAX_POLLS=$(((WAIT_SECONDS + 9) / 10))
STOPPED=false
for ((attempt=0; attempt<MAX_POLLS && SECONDS<POLL_DEADLINE; attempt++)); do
  DESCRIPTION=$(aws_json ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK_ARN" --region "$REGION") ||
    fail 'task status is unavailable; the task may still be running'
  TASK=$(jq -ce --arg arn "$TASK_ARN" --arg definition "$TASK_DEF" '
    select((.failures // [] | length) == 0 and (.tasks | length) == 1)
    | .tasks[0] | select(.taskArn == $arn and .taskDefinitionArn == $definition)
    | select(.lastStatus | type == "string")
  ' 2>/dev/null <<<"$DESCRIPTION") || fail 'cleanup task status was not verified'
  if [[ "$(jq -r '.lastStatus' <<<"$TASK")" == "STOPPED" ]]; then STOPPED=true; break; fi
  remaining=$((POLL_DEADLINE - SECONDS))
  if (( attempt + 1 < MAX_POLLS && remaining > 0 )); then
    if (( remaining > 10 )); then remaining=10; fi
    sleep "$remaining"
  fi
done
unset POLL_DEADLINE
[[ "$STOPPED" == true ]] || fail 'wait budget exhausted; the task may still be running; avoid a duplicate report'
EXIT_CODE=$(jq -er --arg name "$CONTAINER_NAME" '
  [.containers[] | select(.name == $name)] | select(length == 1) | .[0].exitCode
  | select(type == "number" and . >= 0 and . <= 255 and floor == .)
' 2>/dev/null <<<"$TASK") || fail 'cleanup container result is unavailable'
[[ "$EXIT_CODE" == 0 ]] || fail 'report-only cleanup task failed'
LOG_STREAM="${LOG_PREFIX}/${CONTAINER_NAME}/${TASK_ARN##*/}"

for attempt in 1 2 3 4 5 6; do
  MARKER=$(aws_json logs filter-log-events --log-group-name "$LOG_GROUP" \
    --log-stream-names "$LOG_STREAM" --filter-pattern '{ $.event = "memory_cleanup" }' \
    --start-time "$START_TIME_MS" --region "$LOG_REGION" --query 'events[].message') || MARKER='[]'
  SUMMARY=$(jq -cr '
    [ .[]? | fromjson? | select(type == "object")
      | select(.event == "memory_cleanup" and .kind == "summary" and .writeCalls == 0)
      | select(all(to_entries[] | select(.key | IN("capUsed","writeCalls","skippedLww","skippedByFilter","restored","alreadyActive","notFound","fencedOut"));
          .value | type == "number" and . >= 0 and . <= 9007199254740991 and floor == .))
      | {event,kind,writeCalls} + with_entries(select(.key | IN("capUsed","skippedLww","skippedByFilter","restored","alreadyActive","notFound","fencedOut")))
    ] | last // empty
  ' 2>/dev/null <<<"$MARKER") || SUMMARY=''
  if [[ -n "$SUMMARY" ]]; then
    printf 'CLEANUP_REPORT %s\n' "$SUMMARY"
    printf '%s\n' 'run-cleanup: report-only verification passed'
    exit 0
  fi
  if (( attempt < 6 )); then sleep 10; fi
done
fail 'safe cleanup summary was absent from the exact task log stream'
