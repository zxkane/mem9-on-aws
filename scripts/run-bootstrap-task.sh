#!/usr/bin/env bash
# run-bootstrap-task.sh — run the one-shot schema-bootstrap ECS task and wait for
# it to finish (ARCHITECTURE.md §8). Used by CI after `sst deploy` (both the prod
# and pr-N stages) and runnable by an operator manually.
#
# SST DEFINES the task (infra/bootstrap.ts) but does not run it; this script does.
# It reads the run inputs SST exported to SSM, invokes `aws ecs run-task` in the
# DB task SG + private subnets (awsvpc mode, no public IP — the task reaches
# Aurora via the SG and pulls its image via the subnets' NAT/ECR path), then polls
# DescribeTasks until the task STOPS and asserts the container exited 0.
#
# The bootstrap is idempotent (schema DDL is IF NOT EXISTS; the tenant seed is
# ON CONFLICT DO NOTHING/UPDATE), so re-running on every deploy is safe.
#
# Env:
#   STAGE       (required) — e.g. prod / pr-7. Selects the /mem9-on-aws/<stage>/
#               bootstrap/* SSM params.
#   AWS_REGION  (optional) — defaults to the SST application region.

set -euo pipefail

STAGE="${STAGE:?STAGE is required (e.g. prod or pr-7)}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="${AWS_REGION:-$(node "$REPO_ROOT/scripts/resolve-application-region.mjs")}"
PREFIX="/mem9-on-aws/${STAGE}/bootstrap"

echo "run-bootstrap: reading run inputs from SSM ${PREFIX}/* (region ${REGION})"
CLUSTER=$(aws ssm get-parameter --name "${PREFIX}/cluster-name" --region "$REGION" --query Parameter.Value --output text)
TASK_DEF=$(aws ssm get-parameter --name "${PREFIX}/task-def-arn" --region "$REGION" --query Parameter.Value --output text)
TASK_SG=$(aws ssm get-parameter --name "${PREFIX}/task-sg-id" --region "$REGION" --query Parameter.Value --output text)
# subnet-ids is a StringList → comma-joined; run-task wants a JSON array.
SUBNETS_CSV=$(aws ssm get-parameter --name "${PREFIX}/subnet-ids" --region "$REGION" --query Parameter.Value --output text)

if [[ -z "$CLUSTER" || -z "$TASK_DEF" || -z "$TASK_SG" || -z "$SUBNETS_CSV" ]]; then
  echo "::error::missing bootstrap SSM params under ${PREFIX} — has sst deploy run for this stage?"
  exit 1
fi

# Resolve the exact awslogs destination from the deployed task definition before
# starting the task. The deploy role already has DescribeTaskDefinition and
# FilterLogEvents; using these values avoids broad log-group discovery and does
# not require DescribeLogStreams/GetLogEvents.
TASK_DEF_JSON=$(aws ecs describe-task-definition \
  --task-definition "$TASK_DEF" \
  --region "$REGION" \
  --output json 2>/dev/null || true)
LOG_CONTAINER_NAME=$(printf '%s' "$TASK_DEF_JSON" | jq -r \
  '.taskDefinition.containerDefinitions[0].name // empty' 2>/dev/null || true)
LOG_GROUP=$(printf '%s' "$TASK_DEF_JSON" | jq -r \
  '.taskDefinition.containerDefinitions[0].logConfiguration.options["awslogs-group"] // empty' 2>/dev/null || true)
LOG_STREAM_PREFIX=$(printf '%s' "$TASK_DEF_JSON" | jq -r \
  '.taskDefinition.containerDefinitions[0].logConfiguration.options["awslogs-stream-prefix"] // empty' 2>/dev/null || true)

# NO RDS Proxy readiness gate: this project connects mem9 + this bootstrap task
# DIRECTLY to the Aurora cluster writer endpoint (no proxy — see infra/db.ts). SST's
# sst.aws.Aurora deploy already waits for the cluster to be `available`, so by the
# time this runs the writer endpoint accepts connections. The bootstrap container's
# own entrypoint still retries the DB briefly to cover the last few seconds of
# instance readiness. Empirical 2026-07-12: a former proxy target remained
# PENDING_PROXY_CAPACITY for more than 40 minutes at the selected 0.5 ACU floor in
# two regions, so the repository removed the proxy. This is not a general AWS
# root-cause or capacity guarantee.

# Build the awsvpc network config: subnets as a JSON array (split the CSV on
# commas into separate quoted elements), no public IP. jq builds the array so the
# quoting is correct regardless of subnet-id contents.
SUBNETS_JSON=$(printf '%s' "$SUBNETS_CSV" | jq -Rc 'split(",")')
NET_CONFIG="{\"awsvpcConfiguration\":{\"subnets\":${SUBNETS_JSON},\"securityGroups\":[\"${TASK_SG}\"],\"assignPublicIp\":\"DISABLED\"}}"

echo "run-bootstrap: run-task on cluster ${CLUSTER} (task-def ${TASK_DEF##*/})"
# Capture the FULL run-task response ONCE (tasks[] + failures[]) so a failure path
# never re-invokes run-task (which would start a second task). Parse the task ARN
# from the captured JSON.
RUN_OUT=$(aws ecs run-task \
  --cluster "$CLUSTER" \
  --task-definition "$TASK_DEF" \
  --launch-type FARGATE \
  --count 1 \
  --propagate-tags TASK_DEFINITION \
  --enable-ecs-managed-tags \
  --network-configuration "$NET_CONFIG" \
  --region "$REGION" \
  --output json)
TASK_ARN=$(printf '%s' "$RUN_OUT" | jq -r '.tasks[0].taskArn // ""')

if [[ -z "$TASK_ARN" || "$TASK_ARN" == "null" ]]; then
  echo "::error::run-task started no task. failures:"
  printf '%s' "$RUN_OUT" | jq -c '.failures // []'
  exit 1
fi
echo "run-bootstrap: started ${TASK_ARN##*/}, waiting for it to stop..."

# Print the task's own CloudWatch logs INLINE (debuggable even after auto-cleanup
# tears the stage down). Called on ANY failure path — wait timeout OR non-zero
# exit. The awslogs stream name is <prefix>/<container>/<task-id>, so the exact
# task definition plus task ARN identifies one stream without account-wide log
# discovery. Retries cover CloudWatch ingestion lag after the task stops.
print_task_logs() {
  local attempt events stream task_id
  if [[ -z "$LOG_GROUP" || -z "$LOG_STREAM_PREFIX" || -z "$LOG_CONTAINER_NAME" ]]; then
    echo "run-bootstrap: WARNING — task definition has no readable awslogs configuration"
    return 0
  fi
  task_id="${TASK_ARN##*/}"
  stream="${LOG_STREAM_PREFIX}/${LOG_CONTAINER_NAME}/${task_id}"
  for attempt in 1 2 3 4 5; do
    events=$(aws logs filter-log-events \
      --log-group-name "$LOG_GROUP" \
      --log-stream-name-prefix "$stream" \
      --region "$REGION" \
      --output json 2>/dev/null || true)
    if printf '%s' "$events" | jq -e '.events | length > 0' >/dev/null 2>&1; then
      echo "----- bootstrap task logs (${LOG_GROUP} / ${stream}) -----"
      printf '%s' "$events" | jq -r '.events[-200:][] | .message'
      echo "----- end bootstrap task logs -----"
      return 0
    fi
    echo "run-bootstrap: task logs not available yet (attempt ${attempt}/5), waiting 8s for CloudWatch ingestion..."
    sleep 8
  done
  echo "run-bootstrap: WARNING — could not retrieve bootstrap task logs (log group may be gone). group=${LOG_GROUP} stream=${stream}"
}

# Manual wait loop (NOT `aws ecs wait`, whose 100×6s=10m cap can't be raised via
# the AWS_MAX_ATTEMPTS env in all CLI builds). Poll lastStatus until STOPPED, up
# to ~15 min. The bootstrap connects to the Aurora writer endpoint directly (no
# proxy), and its entrypoint retries the DB for up to ~5 min then exits, so a
# STOPPED task should arrive well within this; a full 15-min timeout means the
# task is genuinely stuck (image pull, etc.) — we then dump logs + describe-tasks.
DEADLINE=$((SECONDS + 900))
LAST_STATUS=""
while [[ $SECONDS -lt $DEADLINE ]]; do
  LAST_STATUS=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK_ARN" --region "$REGION" \
    --query 'tasks[0].lastStatus' --output text 2>/dev/null || echo "UNKNOWN")
  [[ "$LAST_STATUS" == "STOPPED" ]] && break
  sleep 10
done

if [[ "$LAST_STATUS" != "STOPPED" ]]; then
  echo "::error::bootstrap task did not STOP within 15 min (lastStatus=${LAST_STATUS}). Dumping task detail + logs:"
  aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK_ARN" --region "$REGION" \
    --query 'tasks[0].{lastStatus:lastStatus,containers:containers[].{name:name,lastStatus:lastStatus,reason:reason}}' --output json 2>&1 || true
  print_task_logs
  exit 1
fi

# STOPPED — assert the container exited 0.
EXIT_CODE=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK_ARN" --region "$REGION" \
  --query 'tasks[0].containers[0].exitCode' --output text)
STOP_REASON=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK_ARN" --region "$REGION" \
  --query 'tasks[0].stoppedReason' --output text)

echo "run-bootstrap: task stopped (exitCode=${EXIT_CODE}, reason='${STOP_REASON}')"
if [[ "$EXIT_CODE" != "0" ]]; then
  print_task_logs
  echo "::error::bootstrap task did not exit 0 (exitCode=${EXIT_CODE}, reason='${STOP_REASON}')."
  exit 1
fi
echo "run-bootstrap: OK — schema + tenant bootstrap applied for stage ${STAGE}"
