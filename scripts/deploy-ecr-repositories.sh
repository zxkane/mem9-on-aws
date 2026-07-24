#!/usr/bin/env bash
# deploy-ecr-repositories.sh — Create or update the four OUT-OF-BAND ECR
# repositories for the mem9-on-aws workload images.
#
# Scope: **ECR repositories only**. The SST/Pulumi app does not manage these
# repositories; it references them read-only. Owning them out-of-band means
# `sst remove --stage pr-N` cannot wipe the image history prod runs on.
#
# Bootstrap ONCE per AWS account (in the Tokyo region — ECR is regional and
# Fargate pulls same-region), and RE-RUN only if
# infra/cloudformation/ecr-repositories.yaml changes.
#
# Region: ap-northeast-1 (Tokyo) — MUST match the SST app region (sst.config.ts)
# so Fargate pulls the images from the same region (no cross-region pull cost /
# latency). This is unlike deploy-github-role.sh, which pins us-west-2 for the
# global IAM role stack; ECR repositories are regional data resources.
#
# Config: set AWS_PROFILE (and any overrides) in a gitignored .env at the repo
# root — copy .env.example. Targets account <aws-account-id>.
#
# Usage:
#   scripts/deploy-ecr-repositories.sh            # auto create/update (reads .env)
#   scripts/deploy-ecr-repositories.sh --create   # force create-stack
#   scripts/deploy-ecr-repositories.sh --update   # force update-stack

set -euo pipefail

# Load repo-root .env (gitignored) for AWS_PROFILE etc., if present.
_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -f "$_repo_root/.env" ] && set -a && . "$_repo_root/.env" && set +a

STACK_NAME="${STACK_NAME:-ecr-repositories-mem9-on-aws}"
TEMPLATE_FILE="infra/cloudformation/ecr-repositories.yaml"
# Tokyo — MUST equal sst.config.ts's providers.aws.region so Fargate pulls the
# image same-region. Hard-coded, NOT read from the ambient AWS_REGION: a stray
# AWS_REGION in the shell (e.g. left over from deploy-github-role.sh's us-west-2)
# would silently create the repo in the wrong region, and Fargate would then pull
# cross-region (cost + latency) or fail. Override deliberately with ECR_REGION
# only if the whole app moves regions.
REGION="${ECR_REGION:-ap-northeast-1}"

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

REPO_URIS=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query "Stacks[0].Outputs[?ends_with(OutputKey, 'RepoUri')].[OutputKey,OutputValue]" \
  --output text)

echo
echo "Repository URIs:"
printf '%s\n' "$REPO_URIS"
echo
echo "Next steps:"
echo "  1. CI builds four arm64 images and pushes each to its matching repository."
echo "  2. infra/ecr.ts composes the same URIs from account+region+namespace and"
echo "     references \${uri}:\${tag} read-only."
