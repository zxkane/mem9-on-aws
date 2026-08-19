#!/usr/bin/env bash
# Start the deployed cleanup task once in manual dry-run mode. This writes a
# reviewed decision artifact and approval offer, but never mutates a memory and
# never contributes to the scheduled-scan liveness/quiet-week metrics.

set -euo pipefail

STAGE="${STAGE:?STAGE is required (prod or pr-N)}"
CONFIRM_PROD_SCAN="${CONFIRM_PROD_SCAN:-}"
CLEANUP_SCAN_WAIT_SECONDS="${CLEANUP_SCAN_WAIT_SECONDS:-21600}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="${AWS_REGION:-$(node "$REPO_ROOT/scripts/resolve-application-region.mjs")}"
PREFIX="/mem9-on-aws/${STAGE}"
CLEANUP_PREFIX="${PREFIX}/cleanup"
OFFER_PARAMETER="${PREFIX}/approvals/offered"
CONTAINER_NAME="Mem9Cleanup"

if [[ "$STAGE" != "prod" && ! "$STAGE" =~ ^pr-[1-9][0-9]*$ ]]; then
  echo "::error::invalid cleanup scan stage: ${STAGE}; expected prod or pr-N" >&2
  exit 1
fi
if [[ "$STAGE" == "prod" && "$CONFIRM_PROD_SCAN" != "prod" ]]; then
  echo "::error::set CONFIRM_PROD_SCAN=prod to start a production approval scan" >&2
  exit 1
fi
if ! [[ "$CLEANUP_SCAN_WAIT_SECONDS" =~ ^[1-9][0-9]*$ ]] ||
   (( CLEANUP_SCAN_WAIT_SECONDS < 60 || CLEANUP_SCAN_WAIT_SECONDS > 43200 )); then
  echo "::error::CLEANUP_SCAN_WAIT_SECONDS must be an integer from 60 to 43200" >&2
  exit 1
fi

PARAMETER_NAMES=(
  "${CLEANUP_PREFIX}/cluster-name"
  "${CLEANUP_PREFIX}/task-def-arn"
  "${CLEANUP_PREFIX}/task-sg-id"
  "${CLEANUP_PREFIX}/subnet-ids"
)
echo "run-cleanup-scan: reading deployed task inputs"
PARAMETERS=$(aws ssm get-parameters \
  --names "${PARAMETER_NAMES[@]}" \
  --region "$REGION" \
  --output json)

if [[ "$(jq '.InvalidParameters | length' <<<"$PARAMETERS")" != "0" ]]; then
  echo "::error::missing cleanup SSM parameters for ${STAGE}" >&2
  exit 1
fi

parameter_value() {
  jq -r --arg name "$1" '
    [.Parameters[] | select(.Name == $name) | .Value]
    | if length == 1 and (.[0] | type == "string" and length > 0)
      then .[0]
      else empty
      end
  ' <<<"$PARAMETERS"
}

CLUSTER=$(parameter_value "${CLEANUP_PREFIX}/cluster-name")
TASK_DEF=$(parameter_value "${CLEANUP_PREFIX}/task-def-arn")
TASK_SG_CSV=$(parameter_value "${CLEANUP_PREFIX}/task-sg-id")
SUBNETS_CSV=$(parameter_value "${CLEANUP_PREFIX}/subnet-ids")
if [[ -z "$CLUSTER" || -z "$TASK_DEF" || -z "$TASK_SG_CSV" ||
      -z "$SUBNETS_CSV" ]]; then
  echo "::error::incomplete cleanup SSM parameters for ${STAGE}" >&2
  exit 1
fi

if ! SUBNETS_JSON=$(jq -nce --arg values "$SUBNETS_CSV" '
    $values
    | split(",")
    | select(length > 0 and all(.[]; test("^subnet-[0-9a-z]+$")))
  '); then
  echo "::error::cleanup subnet parameters are malformed" >&2
  exit 1
fi
if ! SECURITY_GROUPS_JSON=$(jq -nce --arg values "$TASK_SG_CSV" '
    $values
    | split(",")
    | select(length > 0 and all(.[]; test("^sg-[0-9a-z]+$")))
  '); then
  echo "::error::cleanup security-group parameters are malformed" >&2
  exit 1
fi
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

TASK_DEFINITION=$(aws ecs describe-task-definition \
  --task-definition "$TASK_DEF" \
  --region "$REGION" \
  --output json)
BASE_URL=$(jq -r --arg name "$CONTAINER_NAME" '
  [
    .taskDefinition.containerDefinitions[]
    | select(.name == $name)
    | .command as $command
    | ($command | index("--base-url")) as $index
    | select($index != null and ($index + 1) < ($command | length))
    | $command[$index + 1]
    | select(type == "string")
  ]
  | if length == 1 then .[0] else empty end
' <<<"$TASK_DEFINITION")
EXPECTED_BASE_URL="http://mnemo.mem9-${STAGE}.local:8080"
if [[ "$BASE_URL" != "$EXPECTED_BASE_URL" ]]; then
  echo "::error::deployed cleanup task base URL does not match stage ${STAGE}" >&2
  exit 1
fi

OVERRIDES=$(jq -cn \
  --arg name "$CONTAINER_NAME" \
  --arg stage "$STAGE" \
  --arg baseUrl "$BASE_URL" \
  '{
    containerOverrides: [{
      name: $name,
      command: [
        "/app/scripts/memory-cleanup.mjs",
        "--stage",
        $stage,
        "--base-url",
        $baseUrl,
        "--consensus-passes",
        "2",
        "--out",
        "/tmp/mem9-cleanup-scan"
      ]
    }]
  }')
START_TIME_SECONDS=$(date +%s)

echo "run-cleanup-scan: starting manual dry-run task"
RUN_OUT=$(aws ecs run-task \
  --cluster "$CLUSTER" \
  --task-definition "$TASK_DEF" \
  --launch-type FARGATE \
  --count 1 \
  --network-configuration "$NETWORK_CONFIG" \
  --overrides "$OVERRIDES" \
  --started-by "mem9-cleanup-operator-${STAGE}" \
  --region "$REGION" \
  --output json)
TASK_ARN=$(jq -r '
  select((.failures // []) | length == 0)
  | [.tasks[]?.taskArn]
  | if length == 1 then .[0] else empty end
' <<<"$RUN_OUT")
if [[ -z "$TASK_ARN" ]]; then
  echo "::error::cleanup scan run-task started no task" >&2
  exit 1
fi

echo "run-cleanup-scan: waiting for the dry-run task to stop"
DEADLINE=$((SECONDS + CLEANUP_SCAN_WAIT_SECONDS))
TASK_STATE=""
while [[ $SECONDS -lt $DEADLINE ]]; do
  if ! TASK_STATE=$(aws ecs describe-tasks \
      --cluster "$CLUSTER" \
      --tasks "$TASK_ARN" \
      --region "$REGION" \
      --output json); then
    echo "::error::could not read cleanup scan task state" >&2
    exit 1
  fi
  if [[ "$(jq -r '.tasks[0].lastStatus // empty' <<<"$TASK_STATE")" == "STOPPED" ]]; then
    break
  fi
  sleep 10
done
if [[ "$(jq -r '.tasks[0].lastStatus // empty' <<<"$TASK_STATE")" != "STOPPED" ]]; then
  echo "::error::cleanup scan task did not stop within ${CLEANUP_SCAN_WAIT_SECONDS}s; task remains running, do not start another scan" >&2
  exit 1
fi

EXIT_CODE=$(jq -r --arg name "$CONTAINER_NAME" '
  [
    .tasks[0].containers[]?
    | select(.name == $name)
    | .exitCode
    | select(type == "number")
  ]
  | if length == 1 then .[0] else empty end
' <<<"$TASK_STATE")
if [[ -z "$EXIT_CODE" ]]; then
  echo "::error::cleanup scan task stopped without a container exit code" >&2
  exit 1
fi
if [[ "$EXIT_CODE" != "0" ]]; then
  echo "::error::cleanup scan task exited ${EXIT_CODE}" >&2
  exit 1
fi

if ! OFFER_RESPONSE=$(aws ssm get-parameter \
    --name "$OFFER_PARAMETER" \
    --region "$REGION" \
    --output json); then
  echo "::error::cleanup scan completed without a readable approval offer" >&2
  exit 1
fi
OFFER_MODIFIED=$(jq -r '
  .Parameter.LastModifiedDate
  | select(type == "number")
' <<<"$OFFER_RESPONSE")
if [[ -z "$OFFER_MODIFIED" ]] ||
   ! awk -v modified="$OFFER_MODIFIED" -v started="$START_TIME_SECONDS" \
      'BEGIN { exit !(modified >= started) }'; then
  echo "::error::cleanup scan completed without a fresh approval offer" >&2
  exit 1
fi

if ! OFFER_COUNT=$(jq -er --arg stage "$STAGE" '
    .Parameter.Value
    | fromjson
    | select(
        .stage == $stage
        and (.issuedAt | type == "string" and length > 0)
        and (.expiresAt | type == "string" and length > 0)
        and (.ids | type == "array" and all(.[]; type == "string"))
        and (.hash | type == "string" and test("^sha256:[0-9a-f]{64}$"))
        and (.artifactBucket | type == "string" and length > 0)
        and (
          .artifactKey
          | type == "string"
          and startswith("decisions/\($stage)/")
        )
      )
    | .ids
    | length
  ' <<<"$OFFER_RESPONSE"); then
  echo "::error::cleanup scan did not produce a shaped artifact-backed offer" >&2
  exit 1
fi

echo "run-cleanup-scan: recorded ${OFFER_COUNT} reviewed id(s)"
echo "run-cleanup-scan: inspect the private Slack channel before approving"
