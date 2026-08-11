#!/usr/bin/env bash
# deploy-bedrock-mantle-project.sh — Create or update the OUT-OF-BAND Bedrock
# Mantle Project for mem9-on-aws LLM (GLM-5 smart-ingest) cost attribution.
#
# Scope: **the Bedrock Mantle Project only**. The SST/Pulumi app does NOT manage
# it. When its Id is supplied as MEM9_BEDROCK_PROJECT, the llm-proxy sidecar
# passes it as `OpenAI-Project` on calls from that deployment. Owning it
# out-of-band (like the ECR repos + the GitHub Actions role) means `sst remove
# --stage pr-N` cannot drop the shared project or its accumulated cost history.
#
# Bootstrap ONCE per AWS account and region, and RE-RUN only if
# bedrock-mantle-project.yaml changes.
#
# Region: defaults to the SST application region. PROJECT_REGION deliberately
# selects another region for an independent model route such as OpenAI
# Responses. Ambient AWS_REGION is ignored.
#
# Config: set AWS_PROFILE (and any overrides) in a gitignored .env at the repo
# root — copy .env.example.
#
# Usage:
#   scripts/deploy-bedrock-mantle-project.sh            # auto create/update (reads .env)
#   scripts/deploy-bedrock-mantle-project.sh --create   # force create-stack
#   scripts/deploy-bedrock-mantle-project.sh --update   # force update-stack
#
# After success, feed the ProjectId output to CI so infra/ecs.ts injects it:
#   gh variable set MEM9_BEDROCK_PROJECT --repo <owner>/mem9-on-aws --body "<project-id>"

set -euo pipefail

# Load repo-root .env (gitignored) for AWS_PROFILE etc., if present.
_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -f "$_repo_root/.env" ] && set -a && . "$_repo_root/.env" && set +a

STACK_NAME="${STACK_NAME:-bedrock-mantle-project-mem9-on-aws}"
TEMPLATE_FILE="infra/cloudformation/bedrock-mantle-project.yaml"
APPLICATION_REGION="$(node "$_repo_root/scripts/resolve-application-region.mjs")"
REGION="${PROJECT_REGION:-$APPLICATION_REGION}"
if [[ -n "${PROJECT_REGION:-}" ]]; then
  PROJECT_VARIABLE="MEM9_BEDROCK_PROJECT_OPENAI"
  PROXY_PROJECT_VARIABLE="LLM_PROXY_RESPONSES_OPENAI_PROJECT"
else
  PROJECT_VARIABLE="MEM9_BEDROCK_PROJECT"
  PROXY_PROJECT_VARIABLE="LLM_PROXY_OPENAI_PROJECT"
fi

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
echo "       gh variable set $PROJECT_VARIABLE --repo zxkane/mem9-on-aws --body \"$PROJECT_ID\""
echo "  2. infra/ecs.ts reads $PROJECT_VARIABLE → $PROXY_PROJECT_VARIABLE →"
echo "     the OpenAI-Project header on calls from that configured deployment."
