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

# Wait for the task to reach STOPPED (bootstrap is quick; cap the wait).
aws ecs wait tasks-stopped --cluster "$CLUSTER" --tasks "$TASK_ARN" --region "$REGION"

# Assert the container exited 0. stoppedReason + container exitCode tell the story.
EXIT_CODE=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK_ARN" --region "$REGION" \
  --query 'tasks[0].containers[0].exitCode' --output text)
STOP_REASON=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK_ARN" --region "$REGION" \
  --query 'tasks[0].stoppedReason' --output text)

echo "run-bootstrap: task stopped (exitCode=${EXIT_CODE}, reason='${STOP_REASON}')"
if [[ "$EXIT_CODE" != "0" ]]; then
  # Print the task's own logs INLINE so the failure is debuggable even after the
  # stage (+ its log group) is torn down by auto-cleanup. SST logs the container
  # to /sst/cluster/<cluster>/<...>Bootstrap.../<container>; grab the most-recent
  # stream (= this just-failed task).
  LG=$(aws logs describe-log-groups --region "$REGION" \
    --query "logGroups[?contains(logGroupName,'${CLUSTER}') && contains(logGroupName,'Bootstrap')].logGroupName | [0]" \
    --output text 2>/dev/null || true)
  if [[ -n "$LG" && "$LG" != "None" ]]; then
    STREAM=$(aws logs describe-log-streams --log-group-name "$LG" --region "$REGION" \
      --order-by LastEventTime --descending --max-items 1 \
      --query 'logStreams[0].logStreamName' --output text 2>/dev/null || true)
    if [[ -n "$STREAM" && "$STREAM" != "None" ]]; then
      echo "----- bootstrap task logs (${LG} / ${STREAM}) -----"
      aws logs get-log-events --log-group-name "$LG" --log-stream-name "$STREAM" \
        --region "$REGION" --limit 100 --query 'events[].message' --output text 2>/dev/null || true
      echo "----- end bootstrap task logs -----"
    fi
  fi
  echo "::error::bootstrap task did not exit 0 (exitCode=${EXIT_CODE}, reason='${STOP_REASON}')."
  exit 1
fi
echo "run-bootstrap: OK — schema + tenant bootstrap applied for stage ${STAGE}"
