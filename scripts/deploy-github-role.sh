#!/usr/bin/env bash
# deploy-github-role.sh — Create or update the GitHub Actions IAM role for
# mem9-on-aws SST deployments.
#
# Scope: **IAM role only**. The Pulumi/SST app does NOT manage this role —
# running CI requires the role to exist beforehand (chicken-and-egg).
# Bootstrap once per AWS account, and RE-RUN whenever a new resource TYPE is
# added to infra/cloudformation/github-actions-role.yaml (else the first
# deploy that provisions it 403s).
#
# Local deploy profile: your-aws-profile (set AWS_PROFILE), account <aws-account-id>.
#
# Usage:
#   AWS_PROFILE=your-aws-profile scripts/deploy-github-role.sh   # auto create/update
#   scripts/deploy-github-role.sh --create   # force create-stack
#   scripts/deploy-github-role.sh --update   # force update-stack
#
# After success, copy the RoleArn output to the GitHub repository secret:
#   gh secret set AWS_ROLE_ARN --repo zxkane/mem9-on-aws --body "<role-arn>"

set -euo pipefail

STACK_NAME="${STACK_NAME:-github-actions-mem9-on-aws}"
TEMPLATE_FILE="infra/cloudformation/github-actions-role.yaml"
# Pinned to us-west-2 — IAM is global, but CFN stacks are regional; sister
# stacks in this account collide on IAM role + ManagedPolicy names if created
# in different regions (EntityAlreadyExists rollback). Keep all GitHub Actions
# role stacks in one region so they share one OIDC provider collision-free.
REGION="${AWS_REGION:-us-west-2}"

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

# Reuse the account's existing GitHub Actions OIDC provider if present (sister
# projects created one already). Fail the discovery loud — silently falling
# through to "empty" would attempt a duplicate provider create on a transient
# API blip, and IAM forbids two providers for the same URL.
if ! OIDC_PROVIDER_ARN=$(aws iam list-open-id-connect-providers \
    --query "OpenIDConnectProviderList[?ends_with(Arn, ':oidc-provider/token.actions.githubusercontent.com')].Arn | [0]" \
    --output text); then
  echo "Error: list-open-id-connect-providers failed; refusing to assume 'create new'." >&2
  exit 1
fi
if [[ "$OIDC_PROVIDER_ARN" == "None" ]]; then
  OIDC_PROVIDER_ARN=""
  echo "OIDC ARN: (none — stack will create one)"
else
  echo "OIDC ARN: $OIDC_PROVIDER_ARN"
fi
PARAMS=("ParameterKey=OIDCProviderArn,ParameterValue=$OIDC_PROVIDER_ARN")

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
      --parameters "${PARAMS[@]}" \
      --capabilities CAPABILITY_NAMED_IAM \
      --region "$REGION" \
      --tags Key=Project,Value=mem9-on-aws Key=ManagedBy,Value=cli
    aws cloudformation wait stack-create-complete \
      --stack-name "$STACK_NAME" \
      --region "$REGION"
    ;;
  update)
    echo "Updating stack..."
    # update-stack exits non-zero with "No updates are to be performed" when
    # the template is unchanged — handle that so re-running for idempotency
    # doesn't fail the script.
    set +e
    UPDATE_OUTPUT=$(aws cloudformation update-stack \
      --stack-name "$STACK_NAME" \
      --template-body "file://$TEMPLATE_FILE" \
      --parameters "${PARAMS[@]}" \
      --capabilities CAPABILITY_NAMED_IAM \
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

ROLE_ARN=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='RoleArn'].OutputValue" \
  --output text)

echo
echo "RoleArn:  $ROLE_ARN"
echo
echo "Next steps:"
echo "  1. Set the GitHub secret:"
echo "       gh secret set AWS_ROLE_ARN --repo zxkane/mem9-on-aws --body \"$ROLE_ARN\""
echo "  2. (Optional) configure a self-hosted runner pool via RUNNER_LABEL:"
echo "       gh variable set RUNNER_LABEL --repo zxkane/mem9-on-aws \\"
echo "         --body '[\"self-hosted\", \"linux\", \"arm64\"]'"
