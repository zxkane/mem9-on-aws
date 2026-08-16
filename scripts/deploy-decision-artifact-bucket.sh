#!/usr/bin/env bash
# deploy-decision-artifact-bucket.sh — Create or update the OUT-OF-BAND reviewed-
# decision artifact bucket (`mem9-audit-<account-id>`) for the Slack approval
# loop (#123/#150).
#
# Scope: **the artifact bucket only**. The SST/Pulumi app does NOT manage it; it
# derives the same name and reads/writes objects under a stage-scoped key.
#
# Why out-of-band, and this one is a hard requirement rather than only teardown
# hygiene: the boundary pins the exact bucket ARN, so the name must be fixed, and
# it is account-scoped — every stage computes `mem9-audit-<account-id>`. S3 bucket
# names are globally unique. If the SST app owned it, whichever stage deployed
# first would own it and every later stage's CreateBucket would fail
# `BucketAlreadyOwnedByYou` (the provider surfaces that error, it does not adopt
# the bucket), while `retainOnDelete` left a torn-down preview's bucket behind to
# poison prod. Provisioned here it exists once, before any stage, for all of them.
#
# Bootstrap ONCE per AWS account, in the application region, and RE-RUN only if
# decision-artifact-bucket.yaml changes.
#
# Region: the SST application region (sst.config.ts). Ambient AWS_REGION is
# ignored, so a shell pointed elsewhere cannot create the bucket in the wrong
# region — where the stages would still compute this name and still collide.
#
# Config: set AWS_PROFILE (and any overrides) in a gitignored .env at the repo
# root — copy .env.example.
#
# Usage:
#   scripts/deploy-decision-artifact-bucket.sh            # auto create/update (reads .env)
#   scripts/deploy-decision-artifact-bucket.sh --create   # force create-stack
#   scripts/deploy-decision-artifact-bucket.sh --update   # force update-stack
#
# Nothing needs to be fed to CI afterwards: both the SST app and
# scripts/run-slack-approval-e2e.sh derive the name from the caller's own account
# id rather than reading it back.

set -euo pipefail

# Load repo-root .env (gitignored) for AWS_PROFILE etc., if present.
_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -f "$_repo_root/.env" ] && set -a && . "$_repo_root/.env" && set +a

STACK_NAME="${STACK_NAME:-decision-artifact-bucket-mem9-on-aws}"
TEMPLATE_FILE="infra/cloudformation/decision-artifact-bucket.yaml"
REGION="$(node "$_repo_root/scripts/resolve-application-region.mjs")"

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

# Derived, never read back from a stack output — the same way the SST app and the
# E2E harness compute it, which is the stricter check. Hoisted above the preflight
# because the summary at the end needs it too, and the template deliberately has no
# Outputs block to read (an Outputs block would break the IMPORT adoption path
# printed below).
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET_NAME="mem9-audit-${ACCOUNT_ID}"

# A bucket that already exists OUTSIDE this stack cannot be adopted by a
# create-stack — CloudFormation fails with "already exists" and rolls back. That
# is the state a stage-owned deploy would have left behind, so name the remedy
# here rather than leaving the operator to read a raw CFN failure.
if [[ "$MODE" == "create" ]]; then
  # --region for the same reason the header claims ambient AWS_REGION is ignored:
  # the preflight must ask about the bucket in the region this stack targets.
  if aws s3api head-bucket --bucket "$BUCKET_NAME" --region "$REGION" >/dev/null 2>&1; then
    echo "Error: bucket $BUCKET_NAME already exists but this stack does not own it." >&2
    echo "  A stage-owned deploy created it. Adopt it with an IMPORT change set --" >&2
    echo "  which does work for a stack that does not exist yet, but must name EVERY" >&2
    echo "  resource in the template (both, here) or CFN rejects the change set:" >&2
    echo "    aws cloudformation create-change-set --stack-name $STACK_NAME \\" >&2
    echo "      --change-set-name adopt-artifact-bucket \\" >&2
    echo "      --change-set-type IMPORT --region $REGION \\" >&2
    echo "      --template-body file://$TEMPLATE_FILE \\" >&2
    echo "      --resources-to-import \\" >&2
    echo "      '[{\"ResourceType\":\"AWS::S3::Bucket\",\"LogicalResourceId\":\"DecisionArtifactBucket\",\"ResourceIdentifier\":{\"BucketName\":\"$BUCKET_NAME\"}},{\"ResourceType\":\"AWS::S3::BucketPolicy\",\"LogicalResourceId\":\"DecisionArtifactBucketPolicy\",\"ResourceIdentifier\":{\"Bucket\":\"$BUCKET_NAME\"}}]'" >&2
    echo "  Then: aws cloudformation execute-change-set --stack-name $STACK_NAME \\" >&2
    echo "          --change-set-name adopt-artifact-bucket --region $REGION" >&2
    exit 1
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

echo
echo "BucketName: $BUCKET_NAME"
echo
echo "No CI variable to set — the SST app and the E2E harness both derive this"
echo "name from the caller's account id. The next deploy of any stage will find"
echo "the bucket already present."
