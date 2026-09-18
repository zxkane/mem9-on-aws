#!/usr/bin/env bash
set -euo pipefail

: "${STAGE:?STAGE is required}"
[[ "$STAGE" =~ ^pr-[1-9][0-9]*$ ]] || {
  echo "::error::Human namespace acceptance requires a PR stage"
  exit 2
}
REGION="${AWS_REGION:?AWS_REGION is required}"
EXPECTED_HUMAN_IMAGE_TAG="${EXPECTED_HUMAN_IMAGE_TAG:?expected image tag is required}"
PREFIX="/mem9-on-aws/${STAGE}/human-acceptance"
read_parameter() {
  aws ssm get-parameter --name "${PREFIX}/$1" --region "$REGION" \
    --query Parameter.Value --output text
}
CLUSTER=$(read_parameter cluster-name)
TASK_DEF=$(read_parameter task-def-arn)
TASK_SG=$(read_parameter task-sg-id)
SUBNETS=$(read_parameter subnet-ids)
TASK_ROLE_ARN=$(aws iam get-role \
  --role-name mem9-on-aws-preview-human-acceptance \
  --query Role.Arn --output text)
TASK_DEF_JSON=$(aws ecs describe-task-definition --task-definition "$TASK_DEF" \
  --region "$REGION" --output json)
CONTAINER=$(jq -r '.taskDefinition.containerDefinitions[0].name // empty' <<<"$TASK_DEF_JSON")
IMAGE=$(jq -r '.taskDefinition.containerDefinitions[0].image // empty' <<<"$TASK_DEF_JSON")
DEPLOY_COMMIT=$(jq -r '
  .taskDefinition.containerDefinitions[0].environment[]
  | select(.name == "MEM9_DEPLOY_COMMIT") | .value
' <<<"$TASK_DEF_JSON")
[[ -n "$CONTAINER" && "$IMAGE" == *":${EXPECTED_HUMAN_IMAGE_TAG}" ]] || {
  echo "::error::Human acceptance task definition does not pin the expected image"
  exit 1
}
[[ "$DEPLOY_COMMIT" == "$GITHUB_SHA" ]] || {
  echo "::error::Human acceptance task definition commit mismatch"
  exit 1
}
NETWORK=$(jq -cn --arg subnets "$SUBNETS" --arg sg "$TASK_SG" '
  {awsvpcConfiguration:{
    subnets:($subnets|split(",")),
    securityGroups:[$sg],
    assignPublicIp:"DISABLED"
  }}')
OVERRIDES=$(jq -cn --arg role "$TASK_ROLE_ARN" '{taskRoleArn:$role}')
RUN=$(aws ecs run-task --cluster "$CLUSTER" --task-definition "$TASK_DEF" \
  --launch-type FARGATE --count 1 --started-by "human-${STAGE}" \
  --propagate-tags TASK_DEFINITION --enable-ecs-managed-tags \
  --overrides "$OVERRIDES" \
  --network-configuration "$NETWORK" --region "$REGION" --output json)
TASK=$(jq -r '.tasks[0].taskArn // empty' <<<"$RUN")
[[ -n "$TASK" ]] || {
  echo "::error::Human namespace acceptance task did not start"
  exit 1
}
deadline=$((SECONDS + 2700))
status=""
while (( SECONDS < deadline )); do
  status=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK" \
    --region "$REGION" --query 'tasks[0].lastStatus' --output text)
  [[ "$status" == "STOPPED" ]] && break
  sleep 10
done
[[ "$status" == "STOPPED" ]] || {
  aws ecs stop-task --cluster "$CLUSTER" --task "$TASK" --region "$REGION" \
    --reason "human acceptance timeout" >/dev/null || true
  echo "::error::Human namespace acceptance exceeded 45 minutes"
  exit 1
}
EXIT=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK" \
  --region "$REGION" --query 'tasks[0].containers[0].exitCode' --output text)
[[ "$EXIT" == "0" ]] || {
  echo "::error::Human namespace acceptance task failed"
  exit 1
}
LOG_GROUP=$(jq -r '.taskDefinition.containerDefinitions[0].logConfiguration.options["awslogs-group"] // empty' <<<"$TASK_DEF_JSON")
LOG_PREFIX=$(jq -r '.taskDefinition.containerDefinitions[0].logConfiguration.options["awslogs-stream-prefix"] // empty' <<<"$TASK_DEF_JSON")
TASK_ID=${TASK##*/}
STREAM="${LOG_PREFIX}/${CONTAINER}/${TASK_ID}"
OUTPUT=$(mktemp)
trap 'rm -f "$OUTPUT"' EXIT
for _ in $(seq 1 12); do
  aws logs filter-log-events --log-group-name "$LOG_GROUP" \
    --log-stream-name-prefix "$STREAM" --region "$REGION" \
    --query 'events[].message' --output text 2>/dev/null \
    | tr '\t' '\n' \
    | grep -E '^(PASS |human namespace acceptance: complete$)' >"$OUTPUT" || true
  grep -qx 'human namespace acceptance: complete' "$OUTPUT" && break
  sleep 5
done
node scripts/verify-human-namespace-output.mjs "$OUTPUT"
