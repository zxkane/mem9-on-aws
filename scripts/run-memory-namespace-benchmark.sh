#!/usr/bin/env bash

set -euo pipefail

STAGE="${STAGE:?STAGE is required (pr-N)}"
if ! [[ "$STAGE" =~ ^pr-[1-9][0-9]*$ ]]; then
  echo "::error::namespace benchmark is restricted to pr-N stages"
  exit 2
fi
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REGION="${AWS_REGION:-$(node "$ROOT/scripts/resolve-application-region.mjs")}"
SAMPLES="${MEM9_NAMESPACE_BENCHMARK_SAMPLES:-100}"
WARMUPS="${MEM9_NAMESPACE_BENCHMARK_WARMUPS:-20}"
[[ "$SAMPLES" =~ ^[0-9]+$ && "$WARMUPS" =~ ^[0-9]+$ ]] || {
  echo "::error::benchmark sample counts must be integers"
  exit 2
}
PREFIX="/mem9-on-aws/${STAGE}/bootstrap"
TASK_ARN=""
CLUSTER=""
TASK_STOPPED=false

stop_task() {
  [[ -n "$TASK_ARN" && -n "$CLUSTER" && "$TASK_STOPPED" != "true" ]] ||
    return 0
  local status
  status=$(aws ecs describe-tasks \
    --cluster "$CLUSTER" \
    --tasks "$TASK_ARN" \
    --region "$REGION" \
    --query 'tasks[0].lastStatus' \
    --output text 2>/dev/null || true)
  if [[ "$status" != "STOPPED" && -n "$status" && "$status" != "None" ]]; then
    aws ecs stop-task \
      --cluster "$CLUSTER" \
      --task "$TASK_ARN" \
      --reason "namespace benchmark runner ended" \
      --region "$REGION" >/dev/null
    for _ in $(seq 1 18); do
      status=$(aws ecs describe-tasks \
        --cluster "$CLUSTER" \
        --tasks "$TASK_ARN" \
        --region "$REGION" \
        --query 'tasks[0].lastStatus' \
        --output text 2>/dev/null || true)
      [[ "$status" == "STOPPED" ]] && break
      sleep 5
    done
  fi
  [[ "$status" == "STOPPED" ]] || return 1
  TASK_STOPPED=true
}

cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM
  if ! stop_task; then
    echo "::error::namespace benchmark task stop was not confirmed" >&2
    exit 1
  fi
  exit "$exit_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ssm() {
  aws ssm get-parameter \
    --name "$1" \
    --region "$REGION" \
    --query Parameter.Value \
    --output text
}

CLUSTER=$(ssm "${PREFIX}/cluster-name")
TASK_DEF=$(ssm "${PREFIX}/task-def-arn")
TASK_SG=$(ssm "${PREFIX}/task-sg-id")
SUBNETS_CSV=$(ssm "${PREFIX}/subnet-ids")
TASK_DEF_JSON=$(aws ecs describe-task-definition \
  --task-definition "$TASK_DEF" \
  --region "$REGION" \
  --output json)
CONTAINER=$(printf '%s' "$TASK_DEF_JSON" | jq -er \
  '.taskDefinition.containerDefinitions[0].name')
LOG_GROUP=$(printf '%s' "$TASK_DEF_JSON" | jq -er \
  '.taskDefinition.containerDefinitions[0].logConfiguration.options["awslogs-group"]')
LOG_PREFIX=$(printf '%s' "$TASK_DEF_JSON" | jq -er \
  '.taskDefinition.containerDefinitions[0].logConfiguration.options["awslogs-stream-prefix"]')
SUBNETS=$(printf '%s' "$SUBNETS_CSV" | jq -Rc 'split(",")')
NETWORK=$(jq -cn --argjson subnets "$SUBNETS" --arg sg "$TASK_SG" '
  {awsvpcConfiguration:{
    subnets:$subnets,
    securityGroups:[$sg],
    assignPublicIp:"DISABLED"
  }}')
OVERRIDES=$(jq -cn \
  --arg container "$CONTAINER" \
  --arg samples "$SAMPLES" \
  --arg warmups "$WARMUPS" '
  {containerOverrides:[{
    name:$container,
    environment:[
      {name:"MEM9_BOOTSTRAP_OPERATION",value:"benchmark"},
      {name:"MEM9_NAMESPACE_BENCHMARK_SAMPLES",value:$samples},
      {name:"MEM9_NAMESPACE_BENCHMARK_WARMUPS",value:$warmups}
    ]
  }]}')

RUN=$(aws ecs run-task \
  --cluster "$CLUSTER" \
  --task-definition "$TASK_DEF" \
  --launch-type FARGATE \
  --count 1 \
  --network-configuration "$NETWORK" \
  --overrides "$OVERRIDES" \
  --region "$REGION" \
  --output json)
TASK_ARN=$(printf '%s' "$RUN" | jq -er '.tasks[0].taskArn')
TASK_ID="${TASK_ARN##*/}"
DEADLINE=$((SECONDS + 900))
STATUS=""
while [[ $SECONDS -lt $DEADLINE ]]; do
  STATUS=$(aws ecs describe-tasks \
    --cluster "$CLUSTER" \
    --tasks "$TASK_ARN" \
    --region "$REGION" \
    --query 'tasks[0].lastStatus' \
    --output text)
  [[ "$STATUS" == "STOPPED" ]] && break
  sleep 10
done
[[ "$STATUS" == "STOPPED" ]] || {
  echo "::error::namespace benchmark task did not stop"
  exit 1
}
TASK_STOPPED=true
EXIT_CODE=$(aws ecs describe-tasks \
  --cluster "$CLUSTER" \
  --tasks "$TASK_ARN" \
  --region "$REGION" \
  --query 'tasks[0].containers[0].exitCode' \
  --output text)
STREAM="${LOG_PREFIX}/${CONTAINER}/${TASK_ID}"
EVENTS=""
for _ in 1 2 3 4 5; do
  EVENTS=$(aws logs filter-log-events \
    --log-group-name "$LOG_GROUP" \
    --log-stream-name-prefix "$STREAM" \
    --region "$REGION" \
    --output json 2>/dev/null || true)
  printf '%s' "$EVENTS" | jq -e '.events | length > 0' >/dev/null 2>&1 &&
    break
  sleep 5
done
if [[ "$EXIT_CODE" != "0" ]]; then
  echo "::error::namespace benchmark task failed with exit ${EXIT_CODE}"
  exit 1
fi
RESULT=$(printf '%s' "$EVENTS" | jq -cer '
  [.events[].message | fromjson?
   | select(.event == "namespace_resolution_benchmark")]
  | last
  | select(
      .version == 1
      and .samples >= 20
      and .p95_ms < .threshold_ms
      and .threshold_ms == 20
    )')
printf '%s\n' "$RESULT"
