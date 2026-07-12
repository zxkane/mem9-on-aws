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
#   AWS_REGION  (optional) — defaults to ap-northeast-1 (the app region).

set -euo pipefail

STAGE="${STAGE:?STAGE is required (e.g. prod or pr-7)}"
REGION="${AWS_REGION:-ap-northeast-1}"
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
# exit. SST logs the container to /sst/cluster/<cluster>/...Bootstrap.../<container>.
# Retries for CloudWatch ingestion lag (the task just stopped seconds ago) and
# falls back to a broader query if the cluster-scoped one misses.
print_task_logs() {
  local lg stream attempt
  for attempt in 1 2 3 4 5; do
    # Prefer the cluster-scoped Bootstrap log group; fall back to any Bootstrap
    # group for this stage's SSM prefix if the cluster substring doesn't match.
    lg=$(aws logs describe-log-groups --region "$REGION" \
      --query "logGroups[?contains(logGroupName,'${CLUSTER}') && contains(logGroupName,'Bootstrap')].logGroupName | [0]" \
      --output text 2>/dev/null || true)
    if [[ -z "$lg" || "$lg" == "None" ]]; then
      lg=$(aws logs describe-log-groups --region "$REGION" \
        --query "logGroups[?contains(logGroupName,'${STAGE}') && contains(logGroupName,'Bootstrap')].logGroupName | [0]" \
        --output text 2>/dev/null || true)
    fi
    if [[ -n "$lg" && "$lg" != "None" ]]; then
      stream=$(aws logs describe-log-streams --log-group-name "$lg" --region "$REGION" \
        --order-by LastEventTime --descending --max-items 1 \
        --query 'logStreams[0].logStreamName' --output text 2>/dev/null || true)
      if [[ -n "$stream" && "$stream" != "None" ]]; then
        echo "----- bootstrap task logs (${lg} / ${stream}) -----"
        aws logs get-log-events --log-group-name "$lg" --log-stream-name "$stream" \
          --region "$REGION" --limit 200 --start-from-head \
          --query 'events[].message' --output text 2>/dev/null || true
        echo "----- end bootstrap task logs -----"
        return 0
      fi
    fi
    echo "run-bootstrap: task logs not available yet (attempt ${attempt}/5), waiting 8s for CloudWatch ingestion..."
    sleep 8
  done
  echo "run-bootstrap: WARNING — could not retrieve bootstrap task logs (log group may be gone). cluster=${CLUSTER}"
}

# Manual wait loop (NOT `aws ecs wait`, whose 100×6s=10m cap can't be raised via
# the AWS_MAX_ATTEMPTS env in all CLI builds). Poll lastStatus until STOPPED, up
# to ~15 min. The entrypoint now fails FAST (~2 min) if the DB is unreachable, so
# a STOPPED task should arrive well within this; a full timeout means the task is
# genuinely stuck (image pull, etc.) — we then dump logs + describe-tasks.
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
