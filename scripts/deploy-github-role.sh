#!/usr/bin/env bash
# deploy-github-role.sh — Create or update the GitHub Actions IAM role for
# mem9-on-aws SST deployments.
#
# Scope: **IAM role only**. The Pulumi/SST app does NOT manage this role —
# running CI requires the role to exist beforehand (chicken-and-egg).
# Bootstrap once per AWS account, and RE-RUN after every policy or resource-type
# change in infra/cloudformation/github-actions-role.yaml. Policy-only changes
# such as explicit denies are not active until this out-of-band stack is updated.
#
# Config: set AWS_PROFILE (and any overrides) in a gitignored .env at the repo
# root — copy .env.example and fill in your own profile. Targets account
# <aws-account-id>.
# MEM9_DECISION_ARTIFACT_BUCKET selects the exact owner/boundary bucket;
# unset defaults to mem9-audit-<caller-account-id>. Names must be 3-33 characters.
#
# Usage:
#   scripts/deploy-github-role.sh            # auto create/update (reads .env)
#   scripts/deploy-github-role.sh --create   # force create-stack
#   scripts/deploy-github-role.sh --update   # force update-stack
#   scripts/deploy-github-role.sh --retire-legacy
#
# After the additive rollout, configure PreviewRoleArn and ProductionRoleArn as
# the repository secrets AWS_PREVIEW_ROLE_ARN and AWS_PROD_ROLE_ARN.

set -euo pipefail

# Load repo-root .env (gitignored) for AWS_PROFILE etc., if present. Guarded
# callers set WORKLOAD_BOUNDARY_SKIP_DOTENV after loading their selected file so
# this subprocess cannot silently switch profiles.
_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${WORKLOAD_BOUNDARY_SKIP_DOTENV:-false}" != "true" && -f "$_repo_root/.env" ]]; then
  set -a
  # shellcheck source=/dev/null
  . "$_repo_root/.env"
  set +a
fi

STACK_NAME="${STACK_NAME:-github-actions-mem9-on-aws}"
TEMPLATE_FILE="infra/cloudformation/github-actions-role.yaml"
# Pinned to us-west-2 — IAM is global, but CFN stacks are regional; sister
# stacks in this account collide on IAM role + ManagedPolicy names if created
# in different regions (EntityAlreadyExists rollback). Keep all GitHub Actions
# role stacks in one region so they share one OIDC provider collision-free.
readonly STACK_REGION="us-west-2"
# The application remains regional even though the IAM stack is pinned
# elsewhere. Resolve the same provider region SST uses, then discover the VPC
# and private-1* subnets selected by the app.
APPLICATION_REGION="$(node "$_repo_root/scripts/resolve-application-region.mjs")"

MODE=""
LEGACY_ROLE_REQUEST=""
for arg in "$@"; do
  case "$arg" in
    --create|--update)
      if [[ -n "$MODE" ]]; then echo 'Choose exactly one operation mode.' >&2; exit 2; fi
      MODE="${arg#--}"
      ;;
    --retire-legacy) LEGACY_ROLE_REQUEST=false ;;
    --enable-legacy) LEGACY_ROLE_REQUEST=true ;;
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

# Bind one bucket to the source application region and authenticated account.
# Existing owner/boundary mismatch or unreadable metadata fails before upload.
ISOLATION_HELPER="$_repo_root/scripts/lib/authorization-maintenance-isolation.mjs"
BUCKET_OVERRIDE="${MEM9_DECISION_ARTIFACT_BUCKET:-}"
BINDINGS_JSON="$(node "$ISOLATION_HELPER" inspect "$APPLICATION_REGION" "$STACK_NAME" "$BUCKET_OVERRIDE" "$MODE")"
MODE="$(jq -r '.mode' <<<"$BINDINGS_JSON")"
ACCOUNT_ID="$(jq -r '.accountId' <<<"$BINDINGS_JSON")"
PARTITION="$(jq -r '.partition' <<<"$BINDINGS_JSON")"
DECISION_ARTIFACT_BUCKET_NAME="$(jq -r '.decisionArtifactBucketName' <<<"$BINDINGS_JSON")"
read_existing_legacy_role_enabled() {
  jq -r '.legacyRoleEnabled' <<<"$BINDINGS_JSON"
}
LEGACY_ROLE_ENABLED="${LEGACY_ROLE_REQUEST:-$(read_existing_legacy_role_enabled)}"

recheck_owner_bindings() {
  local current
  current="$(node "$ISOLATION_HELPER" inspect "$APPLICATION_REGION" "$STACK_NAME" "$DECISION_ARTIFACT_BUCKET_NAME" "$MODE")"
  if [[ "$current" != "$BINDINGS_JSON" ]]; then
    echo 'Error: deployment owner bindings changed before mutation.' >&2
    return 1
  fi
}

echo "Stack:    $STACK_NAME"
echo "Region:   $STACK_REGION"
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

APPLICATION_VPC_ID="${MEM9_VPC_ID:-}"
if [[ -z "$APPLICATION_VPC_ID" ]]; then
  if ! APPLICATION_VPC_ID=$(aws ec2 describe-vpcs \
      --region "$APPLICATION_REGION" \
      --filters Name=is-default,Values=true \
      --query "Vpcs[0].VpcId" \
      --output text); then
    echo "Error: failed to resolve the default VPC in $APPLICATION_REGION." >&2
    exit 1
  fi
else
  if ! aws ec2 describe-vpcs \
      --region "$APPLICATION_REGION" \
      --vpc-ids "$APPLICATION_VPC_ID" \
      --query "Vpcs[0].VpcId" \
      --output text >/dev/null; then
    echo "Error: MEM9_VPC_ID does not resolve in $APPLICATION_REGION." >&2
    exit 1
  fi
fi
if [[ -z "$APPLICATION_VPC_ID" || "$APPLICATION_VPC_ID" == "None" ]]; then
  echo "Error: no application VPC resolved in $APPLICATION_REGION." >&2
  exit 1
fi

if ! PRIVATE_SUBNET_TEXT=$(aws ec2 describe-subnets \
    --region "$APPLICATION_REGION" \
    --filters \
      "Name=vpc-id,Values=$APPLICATION_VPC_ID" \
      "Name=tag:Name,Values=private-1*" \
    --query "sort_by(Subnets, &SubnetId)[].SubnetId" \
    --output text); then
  echo "Error: failed to resolve application private subnets in $APPLICATION_REGION." >&2
  exit 1
fi
read -r -a PRIVATE_SUBNET_IDS <<< "$PRIVATE_SUBNET_TEXT"
if [[ ${#PRIVATE_SUBNET_IDS[@]} -eq 0 || "$PRIVATE_SUBNET_TEXT" == "None" ]]; then
  echo "Error: no private-1* subnets found in the application VPC." >&2
  exit 1
fi
for subnet_id in "${PRIVATE_SUBNET_IDS[@]}"; do
  if [[ ! "$subnet_id" =~ ^subnet-[0-9a-f]+$ ]]; then
    echo "Error: invalid private subnet id returned by EC2." >&2
    exit 1
  fi
done

APPLICATION_VPC_ARN="arn:${PARTITION}:ec2:${APPLICATION_REGION}:${ACCOUNT_ID}:vpc/${APPLICATION_VPC_ID}"
APPLICATION_SUBNET_ARNS=""
for subnet_id in "${PRIVATE_SUBNET_IDS[@]}"; do
  [[ -n "$APPLICATION_SUBNET_ARNS" ]] && APPLICATION_SUBNET_ARNS+=","
  APPLICATION_SUBNET_ARNS+="arn:${PARTITION}:ec2:${APPLICATION_REGION}:${ACCOUNT_ID}:subnet/${subnet_id}"
done

PROD_NAMESPACE_IDS=$(aws servicediscovery list-namespaces \
  --region "$APPLICATION_REGION" \
  --query "Namespaces[?Name=='mem9-prod.local'].Id" \
  --output json)
PROD_NAMESPACE_COUNT=$(jq 'length' <<<"$PROD_NAMESPACE_IDS")
case "$PROD_NAMESPACE_COUNT" in
  0)
    PRODUCTION_HOSTED_ZONE_ARN=""
    ;;
  1)
    PROD_NAMESPACE_ID=$(jq -r '.[0]' <<<"$PROD_NAMESPACE_IDS")
    PROD_HOSTED_ZONE_ID=$(aws servicediscovery get-namespace \
      --id "$PROD_NAMESPACE_ID" \
      --region "$APPLICATION_REGION" \
      --query "Namespace.Properties.DnsProperties.HostedZoneId" \
      --output text)
    if [[ ! "$PROD_HOSTED_ZONE_ID" =~ ^Z[A-Z0-9]+$ ]]; then
      echo "Error: production Cloud Map hosted zone is unavailable." >&2
      exit 1
    fi
    HOSTED_ZONE_VPCS=$(aws route53 get-hosted-zone \
      --id "$PROD_HOSTED_ZONE_ID" \
      --query "VPCs[].VPCId" \
      --output json)
    if ! jq -e --arg vpc "$APPLICATION_VPC_ID" \
      'length > 0 and all(.[]; . == $vpc)' <<<"$HOSTED_ZONE_VPCS" >/dev/null; then
      echo "Error: production hosted zone is not bound only to the application VPC." >&2
      exit 1
    fi
    PRODUCTION_HOSTED_ZONE_ARN="arn:${PARTITION}:route53:::hostedzone/${PROD_HOSTED_ZONE_ID}"
    ;;
  *)
    echo "Error: multiple production Cloud Map namespaces were discovered." >&2
    exit 1
    ;;
esac

PARAMS_JSON=$(printf \
  '[{"ParameterKey":"OIDCProviderArn","ParameterValue":"%s"},{"ParameterKey":"ApplicationRegion","ParameterValue":"%s"},{"ParameterKey":"ApplicationVpcArn","ParameterValue":"%s"},{"ParameterKey":"ApplicationPrivateSubnetArns","ParameterValue":"%s"},{"ParameterKey":"ProductionHostedZoneArn","ParameterValue":"%s"},{"ParameterKey":"LegacyRoleEnabled","ParameterValue":"%s"},{"ParameterKey":"DecisionArtifactBucketName","ParameterValue":"%s"}]' \
  "$OIDC_PROVIDER_ARN" \
  "$APPLICATION_REGION" \
  "$APPLICATION_VPC_ARN" \
  "$APPLICATION_SUBNET_ARNS" \
  "$PRODUCTION_HOSTED_ZONE_ARN" \
  "$LEGACY_ROLE_ENABLED" \
  "$DECISION_ARTIFACT_BUCKET_NAME")
echo "ENI scope: $APPLICATION_REGION, one VPC, ${#PRIVATE_SUBNET_IDS[@]} private subnet(s)"
echo "Legacy role enabled: $LEGACY_ROLE_ENABLED"

# Check every full rendered managed policy with the actual deployment inputs.
# A large subnet list or changed template cannot bypass the quota gate.
jq --arg partition "$PARTITION" --arg account "$ACCOUNT_ID" \
  --arg region "$STACK_REGION" --arg stack "$STACK_NAME" \
  'map({key: .ParameterKey, value: .ParameterValue}) | from_entries |
   . + {"AWS::Partition": $partition, "AWS::AccountId": $account,
        "AWS::Region": $region, "AWS::StackName": $stack,
        "AWS::URLSuffix": (if $partition == "aws-cn" then "amazonaws.com.cn" else "amazonaws.com" end)}' \
  <<<"$PARAMS_JSON" | node "$ISOLATION_HELPER" template "$TEMPLATE_FILE" >/dev/null

# CloudFormation's inline --template-body cap is 51200 bytes. This role template
# grew past that as resource-type policies accumulated (including former
# ELB/ACM/VPC-Lattice resources plus current Route53/Cognito/AgentCore resources),
# which made `update-stack --template-body` SILENTLY
# fail validation → the role froze at a stale version and every downstream deploy
# 403'd on "missing" grants that were in git but never applied. So above ~50KB we
# upload the template to S3 and use --template-url (1 MB cap). The bucket is a
# reused SST state bucket (MEM9_TEMPLATE_BUCKET overrides); the object is a
# throwaway under tmp/.
TEMPLATE_SIZE=$(wc -c < "$TEMPLATE_FILE" | tr -d ' ')
if [[ "$TEMPLATE_SIZE" -gt 50000 ]]; then
  TEMPLATE_BUCKET="${MEM9_TEMPLATE_BUCKET:-}"
  if [[ -z "$TEMPLATE_BUCKET" ]]; then
    TEMPLATE_BUCKET=$(aws s3api list-buckets \
      --query "Buckets[?starts_with(Name, 'sst-state-')].Name | [0]" --output text 2>/dev/null)
  fi
  if [[ -z "$TEMPLATE_BUCKET" || "$TEMPLATE_BUCKET" == "None" ]]; then
    echo "Error: template is ${TEMPLATE_SIZE}B (> 50KB inline cap) but no S3 bucket found for --template-url. Set MEM9_TEMPLATE_BUCKET." >&2
    exit 1
  fi
  # Bucket region for the virtual-hosted URL (CFN reads it cross-region over https).
  BUCKET_REGION=$(aws s3api get-bucket-location --bucket "$TEMPLATE_BUCKET" \
    --query 'LocationConstraint' --output text 2>/dev/null)
  [[ "$BUCKET_REGION" == "None" || -z "$BUCKET_REGION" ]] && BUCKET_REGION="us-east-1"
  TEMPLATE_KEY="tmp/${STACK_NAME}.yaml"
  recheck_owner_bindings
  aws s3 cp "$TEMPLATE_FILE" "s3://${TEMPLATE_BUCKET}/${TEMPLATE_KEY}" --region "$BUCKET_REGION" >/dev/null
  TEMPLATE_URL="https://${TEMPLATE_BUCKET}.s3.${BUCKET_REGION}.amazonaws.com/${TEMPLATE_KEY}"
  TEMPLATE_ARG=(--template-url "$TEMPLATE_URL")
  echo "Template: ${TEMPLATE_SIZE}B > 50KB → uploaded to s3://${TEMPLATE_BUCKET}/${TEMPLATE_KEY} (--template-url)"
else
  TEMPLATE_ARG=(--template-body "file://$TEMPLATE_FILE")
fi

recheck_owner_bindings

case "$MODE" in
  create)
    echo "Creating stack..."
    aws cloudformation create-stack \
      --stack-name "$STACK_NAME" \
      "${TEMPLATE_ARG[@]}" \
      --parameters "$PARAMS_JSON" \
      --capabilities CAPABILITY_NAMED_IAM \
      --region "$STACK_REGION" \
      --tags Key=Project,Value=mem9-on-aws Key=ManagedBy,Value=cli
    aws cloudformation wait stack-create-complete \
      --stack-name "$STACK_NAME" \
      --region "$STACK_REGION"
    ;;
  update)
    echo "Updating stack..."
    # update-stack exits non-zero with "No updates are to be performed" when
    # the template is unchanged — handle that so re-running for idempotency
    # doesn't fail the script.
    set +e
    UPDATE_OUTPUT=$(aws cloudformation update-stack \
      --stack-name "$STACK_NAME" \
      "${TEMPLATE_ARG[@]}" \
      --parameters "$PARAMS_JSON" \
      --capabilities CAPABILITY_NAMED_IAM \
      --region "$STACK_REGION" 2>&1)
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
        --region "$STACK_REGION"
    fi
    ;;
esac

PREVIEW_ROLE_ARN=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$STACK_REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='PreviewRoleArn'].OutputValue" \
  --output text)
PROD_ROLE_ARN=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$STACK_REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='ProductionRoleArn'].OutputValue" \
  --output text)
LEGACY_ROLE_ARN=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$STACK_REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='LegacyRoleArn'].OutputValue" \
  --output text)

echo
echo "PreviewRoleArn:    $PREVIEW_ROLE_ARN"
echo "ProductionRoleArn: $PROD_ROLE_ARN"
if [[ "$LEGACY_ROLE_ENABLED" == "true" ]]; then
  echo "LegacyRoleArn:     $LEGACY_ROLE_ARN"
else
  echo "LegacyRoleArn:     $LEGACY_ROLE_ARN (trust disabled)"
fi
echo
echo "Next steps:"
echo "  1. Set the role secrets without printing their values:"
echo "       gh secret set AWS_PREVIEW_ROLE_ARN --repo zxkane/mem9-on-aws"
echo "       gh secret set AWS_PROD_ROLE_ARN --repo zxkane/mem9-on-aws"
echo "  2. After both paths pass, rerun with --retire-legacy and delete AWS_ROLE_ARN."
