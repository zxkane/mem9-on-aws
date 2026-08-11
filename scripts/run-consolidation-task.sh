#!/usr/bin/env bash
# Run the deployed consolidation task once in report-only mode. This is the
# preview E2E path and is also safe for an operator to run before enablement.

set -euo pipefail

STAGE="${STAGE:?STAGE is required (for example, prod or pr-103)}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="${AWS_REGION:-$(node "$REPO_ROOT/scripts/resolve-application-region.mjs")}"
PREFIX="/mem9-on-aws/${STAGE}/consolidation"
CONTAINER_NAME="Mem9Consolidation"

if ! [[ "$STAGE" =~ ^[A-Za-z0-9-]+$ ]]; then
  echo "::error::invalid consolidation stage: ${STAGE}" >&2
  exit 1
fi

PARAMETER_NAMES=(
  "${PREFIX}/cluster-name"
  "${PREFIX}/task-def-arn"
  "${PREFIX}/task-sg-id"
  "${PREFIX}/subnet-ids"
  "${PREFIX}/log-group-name"
)
echo "run-consolidation: reading report-task inputs from ${PREFIX}/*"
PARAMETERS=$(aws ssm get-parameters \
  --names "${PARAMETER_NAMES[@]}" \
  --region "$REGION" \
  --output json)

if [[ "$(jq '.InvalidParameters | length' <<<"$PARAMETERS")" != "0" ]]; then
  echo "::error::missing consolidation SSM parameters under ${PREFIX}" >&2
  exit 1
fi

parameter_value() {
  jq -r --arg name "$1" \
    '.Parameters[] | select(.Name == $name) | .Value // empty' \
    <<<"$PARAMETERS"
}

CLUSTER=$(parameter_value "${PREFIX}/cluster-name")
TASK_DEF=$(parameter_value "${PREFIX}/task-def-arn")
TASK_SG_CSV=$(parameter_value "${PREFIX}/task-sg-id")
SUBNETS_CSV=$(parameter_value "${PREFIX}/subnet-ids")
LOG_GROUP=$(parameter_value "${PREFIX}/log-group-name")
if [[ -z "$CLUSTER" || -z "$TASK_DEF" || -z "$TASK_SG_CSV" ||
      -z "$SUBNETS_CSV" || -z "$LOG_GROUP" ]]; then
  echo "::error::incomplete consolidation SSM parameters under ${PREFIX}" >&2
  exit 1
fi

SUBNETS_JSON=$(jq -cn --arg values "$SUBNETS_CSV" '$values | split(",")')
SECURITY_GROUPS_JSON=$(jq -cn --arg values "$TASK_SG_CSV" \
  '$values | split(",")')
NETWORK_CONFIG=$(jq -cn \
  --argjson subnets "$SUBNETS_JSON" \
  --argjson securityGroups "$SECURITY_GROUPS_JSON" \
  '{
    awsvpcConfiguration: {
      subnets: $subnets,
      securityGroups: $securityGroups,
      assignPublicIp: "DISABLED"
    }
  }')
OVERRIDES=$(jq -cn --arg name "$CONTAINER_NAME" \
  '{
    containerOverrides: [{
      name: $name,
      command: [
        "/app/scripts/memory-consolidation.mjs",
        "--report-only",
        "--check-llm"
      ]
    }]
  }')
START_TIME_MS=$(( $(date +%s) * 1000 ))

echo "run-consolidation: starting report-only task on ${CLUSTER}"
RUN_OUT=$(aws ecs run-task \
  --cluster "$CLUSTER" \
  --task-definition "$TASK_DEF" \
  --launch-type FARGATE \
  --count 1 \
  --network-configuration "$NETWORK_CONFIG" \
  --overrides "$OVERRIDES" \
  --region "$REGION" \
  --output json)
TASK_ARN=$(jq -r '.tasks[0].taskArn // empty' <<<"$RUN_OUT")
if [[ -z "$TASK_ARN" ]]; then
  echo "::error::consolidation run-task started no task; failures:" >&2
  jq -c '.failures // []' <<<"$RUN_OUT" >&2
  exit 1
fi

echo "run-consolidation: started ${TASK_ARN##*/}, waiting for STOPPED"
DEADLINE=$((SECONDS + 1200))
LAST_STATUS=""
while [[ $SECONDS -lt $DEADLINE ]]; do
  LAST_STATUS=$(aws ecs describe-tasks \
    --cluster "$CLUSTER" \
    --tasks "$TASK_ARN" \
    --region "$REGION" \
    --query 'tasks[0].lastStatus' \
    --output text 2>/dev/null || echo "UNKNOWN")
  [[ "$LAST_STATUS" == "STOPPED" ]] && break
  sleep 10
done
if [[ "$LAST_STATUS" != "STOPPED" ]]; then
  echo "::error::report-only consolidation did not stop within 20 minutes" >&2
  exit 1
fi

EXIT_CODE=$(aws ecs describe-tasks \
  --cluster "$CLUSTER" \
  --tasks "$TASK_ARN" \
  --region "$REGION" \
  --query 'tasks[0].containers[0].exitCode' \
  --output text)
STOP_REASON=$(aws ecs describe-tasks \
  --cluster "$CLUSTER" \
  --tasks "$TASK_ARN" \
  --region "$REGION" \
  --query 'tasks[0].stoppedReason' \
  --output text)
echo "run-consolidation: task stopped (exitCode=${EXIT_CODE}, reason='${STOP_REASON}')"
if [[ "$EXIT_CODE" != "0" ]]; then
  echo "::error::report-only consolidation exited ${EXIT_CODE}" >&2
  exit 1
fi

TASK_DEFINITION=$(aws ecs describe-task-definition \
  --task-definition "$TASK_DEF" \
  --region "$REGION" \
  --output json)
LOG_PREFIX=$(jq -r --arg name "$CONTAINER_NAME" \
  '.taskDefinition.containerDefinitions[]
   | select(.name == $name)
   | .logConfiguration.options["awslogs-stream-prefix"] // empty' \
  <<<"$TASK_DEFINITION")
if [[ -z "$LOG_PREFIX" ]]; then
  echo "::error::consolidation task has no awslogs stream prefix" >&2
  exit 1
fi
LOG_STREAM="${LOG_PREFIX}/${CONTAINER_NAME}/${TASK_ARN##*/}"

# Query only the content-free list summary. Ordinary CONSOLIDATION_REVIEW lines
# contain private memory snippets and must never be copied into CI output.
for attempt in 1 2 3 4 5 6; do
  MARKER=$(aws logs filter-log-events \
    --log-group-name "$LOG_GROUP" \
    --log-stream-names "$LOG_STREAM" \
    --filter-pattern '"CONSOLIDATION_REVIEW_LIST"' \
    --start-time "$START_TIME_MS" \
    --region "$REGION" \
    --query 'events[].message' \
    --output text 2>/dev/null || true)
  # Never print a matched line raw. `filter-log-events` matches the token as a
  # SUBSTRING, so an ordinary CONSOLIDATION_REVIEW record whose snippet or
  # rationale happens to contain "CONSOLIDATION_REVIEW_LIST" also matches — and
  # those records carry private memory content that must not reach CI output
  # (this repo is planned to be open-sourced). Select the line that STARTS with
  # the marker, then re-emit only the known content-free fields.
  SUMMARY=$(printf '%s\n' "$MARKER" | jq -Rr '
    select(startswith("CONSOLIDATION_REVIEW_LIST "))
    | ltrimstr("CONSOLIDATION_REVIEW_LIST ")
    | fromjson?
    | {stage, reportOnly, reviewItems}
    | tostring' | head -1)
  if [[ -n "$SUMMARY" ]]; then
    printf 'CONSOLIDATION_REVIEW_LIST %s\n' "$SUMMARY"
    echo "run-consolidation: report-only E2E passed for ${STAGE}"
    exit 0
  fi
  echo "run-consolidation: summary marker not available (attempt ${attempt}/6)"
  sleep 10
done

echo "::error::CONSOLIDATION_REVIEW_LIST was absent from the exact task log stream" >&2
exit 1
