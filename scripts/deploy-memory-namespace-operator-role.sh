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
STACK_NAME="${MEM9_NAMESPACE_OPERATOR_STACK_NAME:-memory-namespace-operator-mem9-on-aws}"
TEMPLATE="$ROOT/infra/cloudformation/memory-namespace-operator-role.yaml"

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

if aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$STACK_REGION" >/dev/null 2>&1; then
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
      exit 0
    fi
    printf '%s\n' "$OUTPUT" >&2
    exit "$STATUS"
  fi
  aws cloudformation wait stack-update-complete \
    --stack-name "$STACK_NAME" \
    --region "$STACK_REGION"
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

echo "memory namespace operator role: ready"
