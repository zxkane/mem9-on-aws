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
#   ECR_SCAN_EXCLUSIVE_WRITER_ACK
#                           must be true before a mutation; set only after the
#                           account owner pauses other registry config writers
#   ECR_SCAN_BACKUP_FILE    optional protected path for direct-repair rollback;
#                           defaults to a timestamped repo-root *.local.json
#   ECR_SCAN_SKIP_DOTENV    test harness only; true prevents fixture runs from
#                           reading operator values from the repo-root .env

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
if [[ "${ECR_SCAN_SKIP_DOTENV:-false}" != "true" && -f "$repo_root/.env" ]]; then
  set -a
  . "$repo_root/.env"
  set +a
fi

project_name="mem9-on-aws"
# This exact derivation is protected by the GitHub Actions role's DenyPolicy.
# Keeping it non-configurable prevents an alternate ownership stack from
# falling back under the pull-request-capable role's broad CFN permissions.
stack_name="ecr-registry-scanning-${project_name}"
region="${ECR_REGION:-ap-northeast-1}"
template_file="$repo_root/infra/cloudformation/ecr-registry-scanning.yaml"
preflight="$repo_root/scripts/lib/ecr-registry-scanning-preflight.mjs"

if [[ ${#project_name} -lt 2 ||
      ${#project_name} -gt 243 ||
      ! "$project_name" =~ ^[a-z0-9]+([._/-][a-z0-9]+)*$ ]]; then
  echo "Internal project name must be a 2-243 character lowercase ECR repository prefix without wildcards." >&2
  exit 2
fi

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
current_file="$tmp_dir/current.json"
stack_error="$tmp_dir/stack-error.log"
declared_file="$tmp_dir/declared.json"

stack_exists=false
owns_resource=false
stack_status=""
action=""
reason=""
uncovered=""
rollback_file=""
rollback_required=false

print_rollback_guidance() {
  local file="$1"
  echo "Restore the captured baseline while the exclusive-writer window remains active:" >&2
  printf '  aws' >&2
  if [[ -n "${AWS_PROFILE:-}" ]]; then
    printf ' --profile %q' "$AWS_PROFILE" >&2
  fi
  printf ' ecr put-registry-scanning-configuration --region %q --cli-input-json %q\n' \
    "$region" "file://$file" >&2
}

cleanup() {
  local exit_code=$?
  rm -rf "$tmp_dir"
  if [[ $exit_code -ne 0 && "$rollback_required" == "true" && -n "$rollback_file" ]]; then
    print_rollback_guidance "$rollback_file"
  fi
  trap - EXIT
  exit "$exit_code"
}
trap cleanup EXIT

read_registry_configuration() {
  aws ecr get-registry-scanning-configuration \
    --region "$region" \
    --output json \
    >"$current_file"
}

read_stack_ownership() {
  stack_exists=false
  owns_resource=false
  stack_status=""
  : >"$stack_error"

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
}

evaluate_preflight() {
  local result
  result="$(node "$preflight" \
    --input "$current_file" \
    --project-name "$project_name" \
    --stack-exists "$stack_exists" \
    --owns-resource "$owns_resource" \
    --stack-status "$stack_status" \
    --format tsv)"
  uncovered=""
  IFS=$'\t' read -r action reason uncovered <<<"$result"
}

print_decision() {
  local label="$1"
  echo "$label: $action"
  echo "$reason"
}

exit_if_non_mutating() {
  case "$action" in
    verify-owned|verify-only)
      exit 0
      ;;
    fail-closed)
      [[ -n "$uncovered" ]] && echo "Uncovered repositories: $uncovered" >&2
      echo "No registry configuration was mutated. Resolve the complete account-level ruleset with its owner." >&2
      exit 3
      ;;
  esac
}

refresh_preflight() {
  read_registry_configuration
  read_stack_ownership
  evaluate_preflight
}

verify_owned_convergence() {
  local label="$1"
  refresh_preflight
  print_decision "$label"
  if [[ "$action" != "verify-owned" ]]; then
    echo "Registry configuration did not converge to the owned complete declaration." >&2
    exit 4
  fi
}

# This must remain the first AWS call. No mutation is considered until the
# complete account/region registry configuration has been captured.
refresh_preflight
print_decision "Preflight decision"
exit_if_non_mutating

case "$action" in
  adopt|update-owned) initial_action="$action" ;;
  *)
    echo "Unknown preflight action: $action" >&2
    exit 2
    ;;
esac

if [[ "${ECR_SCAN_EXCLUSIVE_WRITER_ACK:-}" != "true" ]]; then
  echo "Mutation requires an exclusive account/region registry-writer window." >&2
  echo "Pause other registry configuration writers, then set ECR_SCAN_EXCLUSIVE_WRITER_ACK=true." >&2
  exit 2
fi

aws cloudformation validate-template \
  --template-body "file://$template_file" \
  --region "$region" \
  >/dev/null

# Narrow the read/mutate race by repeating the complete registry + ownership
# decision immediately before every mutation. ECR exposes no conditional write.
refresh_preflight
print_decision "Mutation preflight decision"
exit_if_non_mutating
if [[ "$action" != "$initial_action" ]]; then
  echo "Ownership changed during preflight; refusing to switch mutation paths." >&2
  exit 3
fi

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
  verify_owned_convergence "Adoption verification"
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
    echo "CloudFormation template is unchanged; checking for owned resource drift."
    refresh_preflight
    print_decision "Drift repair preflight decision"
    exit_if_non_mutating
    if [[ "$action" != "update-owned" ]]; then
      echo "Ownership changed before drift repair; refusing direct registry mutation." >&2
      exit 3
    fi

    node "$preflight" \
      --project-name "$project_name" \
      --format configuration \
      >"$declared_file"

    rollback_file="${ECR_SCAN_BACKUP_FILE:-$repo_root/ecr-registry-scanning-rollback-$(date -u +%Y%m%dT%H%M%SZ).local.json}"
    node - "$current_file" "$rollback_file" <<'NODE'
const [inputFile, outputFile] = process.argv.slice(2);
const { readFileSync, writeFileSync } = require("node:fs");
const current = JSON.parse(readFileSync(inputFile, "utf8"));
writeFileSync(outputFile, `${JSON.stringify(current.scanningConfiguration)}\n`, {
  encoding: "utf8",
  mode: 0o600,
  flag: "wx",
});
NODE
    rollback_required=true
    echo "Captured pre-repair registry configuration: $rollback_file"

    aws ecr put-registry-scanning-configuration \
      --region "$region" \
      --cli-input-json "file://$declared_file" \
      >/dev/null

    verify_owned_convergence "Drift repair verification"
    rollback_required=false
    echo "Owned registry drift repaired from the complete declaration."
    exit 0
  fi
  echo "$update_output" >&2
  exit "$update_exit"
fi

aws cloudformation wait stack-update-complete \
  --stack-name "$stack_name" \
  --region "$region"
verify_owned_convergence "Update verification"
echo "Owned registry scanning configuration updated from its complete declaration."
