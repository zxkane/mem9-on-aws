#!/usr/bin/env bash
# deploy-ecr-registry-scanning.sh - Safely adopt or update the OUT-OF-BAND ECR
# registry scanning singleton.
#
# The ECR registry scanning configuration is account/region-wide and every
# write replaces its complete ruleset. This wrapper reads the complete current
# state and CloudFormation ownership before it permits a stack mutation.
#
# Safe outcomes:
#   adopt         - default registry; create the dedicated stack
#   verify-owned  - owned configuration already equals the declaration
#   update-owned  - owning stack may restore its complete declaration
#   verify-only   - external BASIC scan-on-push rules cover all project repos
#   fail-closed   - every other external/conflicting state; no mutation
#
# Config: set AWS_PROFILE (and any override below) in the gitignored repo-root
# .env. This script is operator-run and is not part of SST or CI deployment.
#
# Overrides:
#   ECR_REGION              default ap-northeast-1
#   ECR_SCAN_STACK_NAME     default ecr-registry-scanning-mem9-on-aws
#   PROJECT_NAME            default mem9-on-aws

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
[ -f "$repo_root/.env" ] && set -a && . "$repo_root/.env" && set +a

stack_name="${ECR_SCAN_STACK_NAME:-ecr-registry-scanning-mem9-on-aws}"
project_name="${PROJECT_NAME:-mem9-on-aws}"
region="${ECR_REGION:-ap-northeast-1}"
template_file="$repo_root/infra/cloudformation/ecr-registry-scanning.yaml"
preflight="$repo_root/scripts/lib/ecr-registry-scanning-preflight.mjs"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
  exit 0
fi
if [[ $# -ne 0 ]]; then
  echo "Unknown option: $1" >&2
  exit 2
fi
if [[ ! -f "$template_file" || ! -f "$preflight" ]]; then
  echo "Registry scanning template or preflight module is missing." >&2
  exit 2
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
current_file="$tmp_dir/current.json"
stack_error="$tmp_dir/stack-error.log"

# This must remain the first AWS call. No CloudFormation mutation is considered
# until the complete account/region registry configuration has been captured.
aws ecr get-registry-scanning-configuration \
  --region "$region" \
  --output json \
  >"$current_file"

stack_exists=false
owns_resource=false
stack_status=""
if stack_status="$(aws cloudformation describe-stacks \
    --stack-name "$stack_name" \
    --region "$region" \
    --query "Stacks[0].StackStatus" \
    --output text 2>"$stack_error")"; then
  stack_exists=true

  # Backticks are JMESPath JSON literals, not shell substitutions.
  # shellcheck disable=SC2016
  owns_resource="$(aws cloudformation describe-stack-resources \
    --stack-name "$stack_name" \
    --region "$region" \
    --query 'length(StackResources[?LogicalResourceId==`RegistryScanningConfiguration` && ResourceType==`AWS::ECR::RegistryScanningConfiguration`]) > `0`' \
    --output text)"
  owns_resource="${owns_resource,,}"
  if [[ "$owns_resource" != "true" && "$owns_resource" != "false" ]]; then
    echo "Could not determine whether the stack owns the registry singleton." >&2
    exit 2
  fi
elif grep -qi "does not exist" "$stack_error"; then
  stack_exists=false
else
  echo "Could not determine CloudFormation ownership:" >&2
  cat "$stack_error" >&2
  exit 2
fi

preflight_result="$(node "$preflight" \
  --input "$current_file" \
  --project-name "$project_name" \
  --stack-exists "$stack_exists" \
  --owns-resource "$owns_resource" \
  --stack-status "$stack_status" \
  --format tsv)"
uncovered=""
IFS=$'\t' read -r action reason uncovered <<<"$preflight_result"

echo "Preflight decision: $action"
echo "$reason"

case "$action" in
  verify-owned|verify-only)
    exit 0
    ;;
  fail-closed)
    [[ -n "$uncovered" ]] && echo "Uncovered repositories: $uncovered" >&2
    echo "No registry configuration was mutated. Resolve the complete account-level ruleset with its owner." >&2
    exit 3
    ;;
  adopt|update-owned)
    aws cloudformation validate-template \
      --template-body "file://$template_file" \
      --region "$region" \
      >/dev/null
    ;;
  *)
    echo "Unknown preflight action: $action" >&2
    exit 2
    ;;
esac

if [[ "$action" == "adopt" ]]; then
  aws cloudformation create-stack \
    --stack-name "$stack_name" \
    --template-body "file://$template_file" \
    --parameters "ParameterKey=ProjectName,ParameterValue=$project_name" \
    --region "$region" \
    --tags "Key=Project,Value=$project_name" "Key=ManagedBy,Value=cli"
  aws cloudformation wait stack-create-complete \
    --stack-name "$stack_name" \
    --region "$region"
  echo "Registry scanning configuration adopted by $stack_name."
  exit 0
fi

set +e
update_output="$(aws cloudformation update-stack \
  --stack-name "$stack_name" \
  --template-body "file://$template_file" \
  --parameters "ParameterKey=ProjectName,ParameterValue=$project_name" \
  --region "$region" 2>&1)"
update_exit=$?
set -e

if [[ $update_exit -ne 0 ]]; then
  if grep -q "No updates are to be performed" <<<"$update_output"; then
    echo "No CloudFormation changes to apply."
    exit 0
  fi
  echo "$update_output" >&2
  exit "$update_exit"
fi

aws cloudformation wait stack-update-complete \
  --stack-name "$stack_name" \
  --region "$region"
echo "Owned registry scanning configuration updated from its complete declaration."
