#!/usr/bin/env bash
# deploy-bedrock-mantle-project.sh — Create or update the OUT-OF-BAND Bedrock
# Mantle Project for mem9-on-aws LLM (GLM-5 smart-ingest) cost attribution.
#
# Scope: **the Bedrock Mantle Project only**. The SST/Pulumi app does NOT manage
# it — the llm-proxy sidecar (docker/llm-proxy) just passes its Id as the
# `OpenAI-Project` header on every Mantle call. Owning it out-of-band (like the
# ECR repos + the GitHub Actions role) means `sst remove --stage pr-N` can never
# drop the shared project + its accumulated cost history (§7).
#
# Bootstrap ONCE per AWS account (in the Tokyo region — where the ECS task calls
# Mantle), and RE-RUN only if bedrock-mantle-project.yaml changes.
#
# Region: ap-northeast-1 (Tokyo) — MUST match the SST app region so the project
# is in the same region the llm-proxy sidecar targets. Hard-coded (not the
# ambient AWS_REGION) so a leftover AWS_REGION can't create it in the wrong one.
#
# Local deploy profile: your-aws-profile (set AWS_PROFILE).
#
# Usage:
#   AWS_PROFILE=your-aws-profile scripts/deploy-bedrock-mantle-project.sh   # auto create/update
#   scripts/deploy-bedrock-mantle-project.sh --create   # force create-stack
#   scripts/deploy-bedrock-mantle-project.sh --update   # force update-stack
#
# After success, feed the ProjectId output to CI so infra/ecs.ts injects it:
#   gh variable set MEM9_BEDROCK_PROJECT --repo zxkane/mem9-on-aws --body "<project-id>"

set -euo pipefail

STACK_NAME="${STACK_NAME:-bedrock-mantle-project-mem9-on-aws}"
TEMPLATE_FILE="infra/cloudformation/bedrock-mantle-project.yaml"
# Tokyo — MUST equal sst.config.ts's providers.aws.region. Hard-coded, NOT read
# from the ambient AWS_REGION (a stray value would create it in the wrong region).
# Override deliberately with PROJECT_REGION only if the whole app moves regions.
REGION="${PROJECT_REGION:-ap-northeast-1}"

MODE=""
for arg in "$@"; do
  case "$arg" in
    --create) MODE="create" ;;
    --update) MODE="update" ;;
    -h|--help)
      sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "$TEMPLATE_FILE" ]]; then
  echo "Error: template not found at $TEMPLATE_FILE (run from repo root)" >&2
  exit 2
fi

echo "Stack:    $STACK_NAME"
echo "Region:   $REGION"
echo "Template: $TEMPLATE_FILE"

# Auto-detect create vs update when the caller did not pass --create / --update.
if [[ -z "$MODE" ]]; then
  if aws cloudformation describe-stacks \
      --stack-name "$STACK_NAME" \
      --region "$REGION" \
      >/dev/null 2>&1; then
    MODE="update"
  else
    MODE="create"
  fi
fi

case "$MODE" in
  create)
    echo "Creating stack..."
    aws cloudformation create-stack \
      --stack-name "$STACK_NAME" \
      --template-body "file://$TEMPLATE_FILE" \
      --region "$REGION" \
      --tags Key=Project,Value=mem9-on-aws Key=ManagedBy,Value=cli
    aws cloudformation wait stack-create-complete \
      --stack-name "$STACK_NAME" \
      --region "$REGION"
    ;;
  update)
    echo "Updating stack..."
    # update-stack exits non-zero with "No updates are to be performed" when the
    # template is unchanged — swallow that so re-running for idempotency is safe.
    set +e
    UPDATE_OUTPUT=$(aws cloudformation update-stack \
      --stack-name "$STACK_NAME" \
      --template-body "file://$TEMPLATE_FILE" \
      --region "$REGION" 2>&1)
    UPDATE_EXIT=$?
    set -e
    if [[ $UPDATE_EXIT -ne 0 ]]; then
      if echo "$UPDATE_OUTPUT" | grep -q "No updates are to be performed"; then
        echo "No changes to apply."
      else
        echo "$UPDATE_OUTPUT" >&2
        exit $UPDATE_EXIT
      fi
    else
      aws cloudformation wait stack-update-complete \
        --stack-name "$STACK_NAME" \
        --region "$REGION"
    fi
    ;;
esac

PROJECT_ID=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='ProjectId'].OutputValue" \
  --output text)

echo
echo "ProjectId: $PROJECT_ID"
echo
echo "Next steps:"
echo "  1. Set the CI variable so deploys inject it into the llm-proxy sidecar:"
echo "       gh variable set MEM9_BEDROCK_PROJECT --repo zxkane/mem9-on-aws --body \"$PROJECT_ID\""
echo "  2. infra/ecs.ts reads MEM9_BEDROCK_PROJECT → LLM_PROXY_OPENAI_PROJECT →"
echo "     the OpenAI-Project header on every Mantle /chat/completions call."
