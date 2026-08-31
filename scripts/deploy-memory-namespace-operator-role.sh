#!/usr/bin/env bash

# Deploy the retained, operator-owned role used only by
# run-memory-namespace-task.sh. The account-global role is pinned to one
# long-lived stage's exact Cognito user pool and temporary SSM input path.
# PR previews use the preview bootstrap task's stage-scoped role instead.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
usage() {
  cat <<'EOF'
usage:
  MEM9_NAMESPACE_OPERATOR_STAGE=<prod|dev> \
    scripts/deploy-memory-namespace-operator-role.sh

The compatible SST release must already export the selected stage's Cognito
user-pool ID to SSM. The retained CloudFormation stack is hosted in us-west-2.
EOF
}
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi
if [[ $# -ne 0 ]]; then
  echo "unsupported operator-role deployment argument" >&2
  exit 2
fi
# shellcheck source=/dev/null
if [[ -f "$ROOT/.env" ]]; then
  set -a
  . "$ROOT/.env"
  set +a
fi

STACK_REGION="us-west-2"
STAGE="${MEM9_NAMESPACE_OPERATOR_STAGE:-prod}"
case "$STAGE" in
  prod|dev) ;;
  *)
    echo "invalid MEM9_NAMESPACE_OPERATOR_STAGE: expected prod or dev" >&2
    exit 2
    ;;
esac
APPLICATION_REGION=$(node "$ROOT/scripts/resolve-application-region.mjs")
STACK_NAME="memory-namespace-operator-mem9-on-aws"
TEMPLATE="$ROOT/infra/cloudformation/memory-namespace-operator-role.yaml"

read_stack_parameter() {
  local description=$1
  local parameter=$2
  local values
  local count
  if ! values=$(jq -cer \
    --arg parameter "$parameter" \
    '[.Stacks[0].Parameters[]?
      | select(.ParameterKey == $parameter)
      | .ParameterValue]' <<<"$description"); then
    echo "CloudFormation stack description is malformed" >&2
    return 1
  fi
  count=$(jq -r 'length' <<<"$values")
  if [[ "$count" != "1" ]]; then
    echo "CloudFormation stack must have exactly one ${parameter} parameter" >&2
    return 1
  fi
  jq -r '.[0]' <<<"$values"
}

verify_stack_description() {
  local description=$1
  local context=$2
  local stack_count
  local stack_status
  if ! stack_count=$(jq -er '.Stacks | length' <<<"$description") ||
    [[ "$stack_count" != "1" ]]; then
    echo "${context} CloudFormation response must contain exactly one stack" >&2
    return 1
  fi
  if ! stack_status=$(jq -er '.Stacks[0].StackStatus' <<<"$description"); then
    echo "${context} CloudFormation stack status is missing" >&2
    return 1
  fi
  case "$stack_status" in
    CREATE_COMPLETE|UPDATE_COMPLETE) ;;
    *)
      echo "${context} CloudFormation stack is not stable: ${stack_status}" >&2
      return 1
      ;;
  esac
}

USER_POOL_ID=$(aws ssm get-parameter \
  --name "/mem9-on-aws/${STAGE}/cognito/user-pool-id" \
  --region "$APPLICATION_REGION" \
  --query Parameter.Value \
  --output text)
if [[ ! "$USER_POOL_ID" =~ ^[a-z0-9-]+_[A-Za-z0-9]+$ ]]; then
  echo "Cognito user-pool id is missing or malformed; deploy the compatible SST release first." >&2
  exit 1
fi

PARAMETERS=(
  "ParameterKey=ApplicationRegion,ParameterValue=${APPLICATION_REGION}"
  "ParameterKey=Stage,ParameterValue=${STAGE}"
  "ParameterKey=CognitoUserPoolId,ParameterValue=${USER_POOL_ID}"
)

set +e
STACK_DESCRIPTION=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$STACK_REGION" \
  --output json 2>&1)
DESCRIBE_STATUS=$?
set -e

STACK_EXISTS=true
if [[ $DESCRIBE_STATUS -ne 0 ]]; then
  if grep -Eq 'ValidationError.*(does not exist|not exist)' \
    <<<"$STACK_DESCRIPTION"; then
    STACK_EXISTS=false
  else
    printf '%s\n' "$STACK_DESCRIPTION" >&2
    exit "$DESCRIBE_STATUS"
  fi
fi

if [[ "$STACK_EXISTS" == "true" ]]; then
  verify_stack_description "$STACK_DESCRIPTION" "Existing"
  EXISTING_APPLICATION_REGION=$(
    read_stack_parameter "$STACK_DESCRIPTION" "ApplicationRegion"
  )
  EXISTING_STAGE=$(read_stack_parameter "$STACK_DESCRIPTION" "Stage")
  if [[ "$EXISTING_APPLICATION_REGION" != "$APPLICATION_REGION" ]]; then
    echo "Existing namespace operator stack belongs to application region ${EXISTING_APPLICATION_REGION}; refusing to retarget it to ${APPLICATION_REGION}." >&2
    exit 1
  fi
  if [[ "$EXISTING_STAGE" != "$STAGE" ]]; then
    echo "Existing namespace operator stack belongs to stage ${EXISTING_STAGE}; refusing to retarget it to ${STAGE}." >&2
    exit 1
  fi

  set +e
  OUTPUT=$(aws cloudformation update-stack \
    --stack-name "$STACK_NAME" \
    --template-body "file://${TEMPLATE}" \
    --parameters "${PARAMETERS[@]}" \
    --capabilities CAPABILITY_NAMED_IAM \
    --region "$STACK_REGION" 2>&1)
  STATUS=$?
  set -e
  if [[ $STATUS -ne 0 ]]; then
    if grep -q "No updates are to be performed" <<<"$OUTPUT"; then
      echo "memory namespace operator role: no changes"
    else
      printf '%s\n' "$OUTPUT" >&2
      exit "$STATUS"
    fi
  else
    aws cloudformation wait stack-update-complete \
      --stack-name "$STACK_NAME" \
      --region "$STACK_REGION"
  fi
else
  aws cloudformation create-stack \
    --stack-name "$STACK_NAME" \
    --template-body "file://${TEMPLATE}" \
    --parameters "${PARAMETERS[@]}" \
    --capabilities CAPABILITY_NAMED_IAM \
    --region "$STACK_REGION" \
    --tags Key=Project,Value=mem9-on-aws Key=ManagedBy,Value=cli >/dev/null
  aws cloudformation wait stack-create-complete \
    --stack-name "$STACK_NAME" \
    --region "$STACK_REGION"
fi

STACK_DESCRIPTION=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$STACK_REGION" \
  --output json)
verify_stack_description "$STACK_DESCRIPTION" "Final"
FINAL_APPLICATION_REGION=$(
  read_stack_parameter "$STACK_DESCRIPTION" "ApplicationRegion"
)
FINAL_STAGE=$(read_stack_parameter "$STACK_DESCRIPTION" "Stage")
FINAL_USER_POOL_ID=$(
  read_stack_parameter "$STACK_DESCRIPTION" "CognitoUserPoolId"
)
if [[ "$FINAL_APPLICATION_REGION" != "$APPLICATION_REGION" ||
  "$FINAL_STAGE" != "$STAGE" ||
  "$FINAL_USER_POOL_ID" != "$USER_POOL_ID" ]]; then
  echo "Final namespace operator stack parameters do not match the requested owner." >&2
  exit 1
fi

echo "memory namespace operator role: ready"
