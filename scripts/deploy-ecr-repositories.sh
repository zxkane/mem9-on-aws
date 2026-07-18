#!/usr/bin/env bash
# deploy-ecr-repositories.sh — Create or update the OUT-OF-BAND ECR repository
# for the mem9-on-aws mnemo-server container image.
#
# Scope: **ECR repository only**. The SST/Pulumi app does NOT manage this repo —
# it references it read-only (see docs/ARCHITECTURE.md §4). Owning it out-of-band
# means `sst remove --stage pr-N` can never wipe the image history prod runs on.
#
# Bootstrap ONCE per AWS account (in the Tokyo region — ECR is regional and
# Fargate pulls same-region), and RE-RUN only if
# infra/cloudformation/ecr-repositories.yaml changes.
#
# Region: ap-northeast-1 (Tokyo) — MUST match the SST app region (sst.config.ts)
# so Fargate pulls the image from the same region (no cross-region pull cost /
# latency). This is UNLIKE deploy-github-role.sh, which pins us-west-2 for the
# global IAM role stack; the ECR repo is a regional data resource.
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

REPO_URI=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='MnemoServerRepoUri'].OutputValue" \
  --output text)

echo
echo "MnemoServerRepoUri: $REPO_URI"
echo
echo "Next steps:"
echo "  1. CI (push to main) builds the arm64 image + pushes to this repo."
echo "  2. infra/ecs.ts composes the same URI from account+region+namespace and"
echo "     references \${uri}:\${tag} read-only (default tag: 'latest')."
