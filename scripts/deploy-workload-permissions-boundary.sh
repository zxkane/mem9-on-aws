#!/usr/bin/env bash
# deploy-workload-permissions-boundary.sh - Create or update the retained,
# operator-owned workload permissions boundary.
#
# This stack is out of band: SST and the GitHub Actions deploy role may refer to
# the fixed policy ARN but cannot mutate the policy or its ownership stack.
# This script may be run alone to create or verify the unattached boundary policy
# for a preview deployment. Any update to an existing stack must run through
# rollout-workload-permissions-boundary.sh so maintenance acknowledgement and
# quarantine ordering are enforced.
#
# --guarded-update is reserved for the rollout adapter. It permits an update to
# an attached policy only after independently verifying the full deploy-role
# quarantine and its effective explicit denies.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
if [[ "${WORKLOAD_BOUNDARY_SKIP_DOTENV:-false}" != "true" && -f "$repo_root/.env" ]]; then
  set -a
  . "$repo_root/.env"
  set +a
fi

# IAM is global, but CloudFormation ownership is regional. Keep this stack
# pinned beside the deploy-role stack so another region cannot claim the name.
region="us-west-2"
application_region="${WORKLOAD_BOUNDARY_APPLICATION_REGION:-${PROJECT_REGION:-ap-northeast-1}}"
bedrock_stack_name="${BEDROCK_PROJECT_STACK_NAME:-bedrock-mantle-project-mem9-on-aws}"
template_file="$repo_root/infra/cloudformation/workload-permissions-boundary.yaml"
contract_file="$repo_root/scripts/workload-permissions-boundary-contract.json"
guarded_update=false
verify_only=false

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
  exit 0
fi
case "${1:-}" in
  --guarded-update)
    guarded_update=true
    shift
    ;;
  --verify-only)
    verify_only=true
    shift
    ;;
esac
[[ $# -eq 0 ]] || { echo "Unknown option: $1" >&2; exit 2; }
if [[ ! -f "$template_file" || ! -f "$contract_file" ]]; then
  echo "Workload permissions-boundary template or contract is missing." >&2
  exit 2
fi
if ! contract_identifiers="$(jq -ce '
    .identifiers
    | select(
        (.boundaryPolicyName | type) == "string" and
        (.boundaryStackName | type) == "string" and
        (.denyDangerousPolicyName | type) == "string" and
        (.deployRoleName | type) == "string" and
        (.quarantinePolicyName | type) == "string" and
        all(.[]; test("^[A-Za-z0-9+=,.@_-]+$"))
      )
  ' "$contract_file" 2>/dev/null)"; then
  echo "Workload permissions-boundary contract is malformed." >&2
  exit 2
fi
stack_name="$(jq -r '.boundaryStackName' <<<"$contract_identifiers")"
policy_name="$(jq -r '.boundaryPolicyName' <<<"$contract_identifiers")"
deploy_role_name="$(jq -r '.deployRoleName' <<<"$contract_identifiers")"
quarantine_policy_name="$(jq -r '.quarantinePolicyName' <<<"$contract_identifiers")"
node_major="$(node -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null || true)"
if [[ ! "$node_major" =~ ^[0-9]+$ || "$node_major" -lt 24 ]]; then
  echo "Node.js 24 or newer is required before any boundary mutation." >&2
  exit 2
fi

identity_json="$(aws sts get-caller-identity --output json 2>/dev/null || true)"
account_id="$(jq -r '.Account // empty' <<<"$identity_json")"
partition="$(jq -r '.Arn // empty' <<<"$identity_json" | sed -n 's/^arn:\([^:]*\):.*/\1/p')"
if [[ ! "$account_id" =~ ^[0-9]{12}$ || ! "$partition" =~ ^[a-z0-9-]+$ ]]; then
  echo "AWS caller identity is malformed; no boundary mutation attempted." >&2
  exit 1
fi
if [[ "$partition" == "aws-cn" ]]; then
  url_suffix="amazonaws.com.cn"
else
  url_suffix="amazonaws.com"
fi
bedrock_project_arn="$(aws cloudformation describe-stacks \
  --stack-name "$bedrock_stack_name" \
  --region "$application_region" \
  --query "Stacks[0].Outputs[?OutputKey=='ProjectArn'].OutputValue | [0]" \
  --output text 2>/dev/null || true)"
expected_project_prefix="arn:${partition}:bedrock-mantle:${application_region}:${account_id}:project/"
if [[ "$bedrock_project_arn" != "$expected_project_prefix"* ]]; then
  echo "Bedrock Mantle project identity is missing or mismatched." >&2
  exit 1
fi

if ! aws cloudformation validate-template \
  --template-body "file://$template_file" \
  --region "$region" >/dev/null 2>&1; then
  echo "Boundary template validation failed; no stack mutation attempted." >&2
  exit 1
fi

set +e
describe_output="$(aws cloudformation describe-stacks \
  --stack-name "$stack_name" \
  --region "$region" 2>&1)"
describe_exit=$?
set -e

policy_arn=""
policy_revision="r1"
force_guarded_recovery=false
read_policy_arn() {
  aws cloudformation describe-stack-resources \
    --stack-name "$stack_name" \
    --logical-resource-id WorkloadPermissionsBoundary \
    --region "$region" \
    --query 'StackResources[0].PhysicalResourceId' \
    --output text 2>/dev/null || true
}

read_policy_revision() {
  local revision
  revision="$(aws cloudformation describe-stacks \
    --stack-name "$stack_name" \
    --region "$region" \
    --query "Stacks[0].Parameters[?ParameterKey=='PolicyRevision'].ParameterValue | [0]" \
    --output text 2>/dev/null || true)"
  if [[ "$revision" == "None" || -z "$revision" ]]; then
    revision="r1"
  fi
  [[ "$revision" =~ ^r[0-9]{1,20}$ ]] || return 1
  printf '%s' "$revision"
}

verify_boundary_policy() {
  local boundary_policy default_version
  default_version="$(aws iam get-policy \
    --policy-arn "$policy_arn" \
    --query 'Policy.DefaultVersionId' \
    --output text 2>/dev/null || true)"
  [[ "$default_version" =~ ^v[1-9][0-9]*$ ]] || return 1
  boundary_policy="$(aws iam get-policy-version \
    --policy-arn "$policy_arn" \
    --version-id "$default_version" \
    --query 'PolicyVersion.Document' \
    --output json 2>/dev/null)" || return 1
  [[ -n "$boundary_policy" ]] || return 1
  if ! WORKLOAD_BOUNDARY_ACCOUNT_ID="$account_id" \
    WORKLOAD_BOUNDARY_APPLICATION_REGION="$application_region" \
    WORKLOAD_BOUNDARY_BEDROCK_PROJECT_ARN="$bedrock_project_arn" \
    WORKLOAD_BOUNDARY_PARTITION="$partition" \
    WORKLOAD_BOUNDARY_POLICY_REVISION="$policy_revision" \
      node "$repo_root/scripts/verify-workload-permissions-boundary.mjs" \
      <<<"$boundary_policy"; then
    return 1
  fi

  local allow_decrypt_policy
  allow_decrypt_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:Decrypt","Resource":"*"}]}'

  verify_decrypt_probe() {
    local expected_decision="$1"
    shift
    local simulation
    local -a simulation_args=(
      iam simulate-custom-policy
      --policy-input-list "$allow_decrypt_policy"
      --permissions-boundary-policy-input-list "$boundary_policy"
      --action-names kms:Decrypt
      --resource-arns "*"
      --output json
    )
    if [[ $# -gt 0 ]]; then
      simulation_args+=(--context-entries "$@")
    fi
    if ! simulation="$(aws "${simulation_args[@]}" 2>/dev/null)" ||
        [[ -z "$simulation" ]]; then
      return 1
    fi
    jq -e --arg expected "$expected_decision" '
      try (
        select(type == "object")
        | .EvaluationResults as $results
        | ($results | type) == "array"
        and ($results | length) == 1
        and $results[0].EvalActionName == "kms:Decrypt"
        and $results[0].EvalResourceName == "*"
        and $results[0].EvalDecision == $expected
        and (
          $expected != "explicitDeny"
          or (
            ($results[0].MatchedStatements | type) == "array"
            and ($results[0].MatchedStatements | length) > 0
          )
        )
      ) catch false
    ' <<<"$simulation" >/dev/null
  }

  local bootstrap_execution_principal_context cross_region_secret_via_context
  local facade_authorizer_principal_context
  local lambda_context lambda_principal_context nonlambda_principal_context
  local outside_lambda_context outside_secret_context
  local secret_context secret_version_context secret_via_context
  local server_execution_principal_context source_function_context
  local ssm_context ssm_via_context task_principal_context tenant_secret_context
  local other_region
  if [[ "$application_region" == "us-west-2" ]]; then
    other_region="us-east-1"
  else
    other_region="us-west-2"
  fi
  lambda_context="ContextKeyName=kms:EncryptionContext:aws:lambda:FunctionArn,ContextKeyValues=arn:${partition}:lambda:${application_region}:${account_id}:function:mem9-on-aws-regression-probe,ContextKeyType=string"
  lambda_principal_context="ContextKeyName=aws:PrincipalArn,ContextKeyValues=arn:${partition}:iam::${account_id}:role/mem9-on-aws-prod-Mem9OauthFacadeFnRole-regression-probe,ContextKeyType=string"
  facade_authorizer_principal_context="ContextKeyName=aws:PrincipalArn,ContextKeyValues=arn:${partition}:iam::${account_id}:role/mem9-on-aws-prod-Mem9OauthFacadeAllowAllRole,ContextKeyType=string"
  nonlambda_principal_context="ContextKeyName=aws:PrincipalArn,ContextKeyValues=arn:${partition}:iam::${account_id}:role/mem9-on-aws-prod-Mem9ServerTaskRole-regression-probe,ContextKeyType=string"
  outside_lambda_context="ContextKeyName=kms:EncryptionContext:aws:lambda:FunctionArn,ContextKeyValues=arn:${partition}:lambda:${application_region}:${account_id}:function:outside-project-regression-probe,ContextKeyType=string"
  source_function_context="ContextKeyName=lambda:SourceFunctionArn,ContextKeyValues=arn:${partition}:lambda:${application_region}:${account_id}:function:mem9-on-aws-regression-probe,ContextKeyType=string"
  ssm_context="ContextKeyName=kms:EncryptionContext:PARAMETER_ARN,ContextKeyValues=arn:${partition}:ssm:${application_region}:${account_id}:parameter/mem9-on-aws/regression-probe,ContextKeyType=string"
  ssm_via_context="ContextKeyName=kms:ViaService,ContextKeyValues=ssm.${application_region}.${url_suffix},ContextKeyType=string"
  secret_context="ContextKeyName=kms:EncryptionContext:SecretARN,ContextKeyValues=arn:${partition}:secretsmanager:${application_region}:${account_id}:secret:mem9-on-aws-prod-Mem9DbSecret-regression,ContextKeyType=string"
  tenant_secret_context="ContextKeyName=kms:EncryptionContext:SecretARN,ContextKeyValues=arn:${partition}:secretsmanager:${application_region}:${account_id}:secret:mem9-on-aws-prod-tenant-api-key-regression,ContextKeyType=string"
  outside_secret_context="ContextKeyName=kms:EncryptionContext:SecretARN,ContextKeyValues=arn:${partition}:secretsmanager:${application_region}:${account_id}:secret:outside-project-regression,ContextKeyType=string"
  secret_version_context="ContextKeyName=kms:EncryptionContext:SecretVersionId,ContextKeyValues=regression-version,ContextKeyType=string"
  secret_via_context="ContextKeyName=kms:ViaService,ContextKeyValues=secretsmanager.${application_region}.${url_suffix},ContextKeyType=string"
  cross_region_secret_via_context="ContextKeyName=kms:ViaService,ContextKeyValues=secretsmanager.${other_region}.${url_suffix},ContextKeyType=string"
  server_execution_principal_context="ContextKeyName=aws:PrincipalArn,ContextKeyValues=arn:${partition}:iam::${account_id}:role/mem9-on-aws-prod-Mem9ServerExecutionRole-regression-probe,ContextKeyType=string"
  bootstrap_execution_principal_context="ContextKeyName=aws:PrincipalArn,ContextKeyValues=arn:${partition}:iam::${account_id}:role/mem9-on-aws-prod-Mem9BootstrapExecutionRole-regression-probe,ContextKeyType=string"
  task_principal_context="ContextKeyName=aws:PrincipalArn,ContextKeyValues=arn:${partition}:iam::${account_id}:role/mem9-on-aws-prod-Mem9ServerTaskRole-regression-probe,ContextKeyType=string"

  if ! verify_decrypt_probe allowed \
        "$lambda_context" "$lambda_principal_context" ||
      ! verify_decrypt_probe allowed \
        "$lambda_context" "$facade_authorizer_principal_context" ||
      ! verify_decrypt_probe allowed \
        "$ssm_context" "$ssm_via_context" "$source_function_context" ||
      ! verify_decrypt_probe allowed \
        "$secret_context" "$secret_version_context" "$secret_via_context" \
        "$server_execution_principal_context" ||
      ! verify_decrypt_probe allowed \
        "$tenant_secret_context" "$secret_version_context" \
        "$secret_via_context" "$bootstrap_execution_principal_context" ||
      ! verify_decrypt_probe explicitDeny "$ssm_context" ||
      ! verify_decrypt_probe explicitDeny \
        "$secret_context" "$secret_version_context" \
        "$server_execution_principal_context" ||
      ! verify_decrypt_probe explicitDeny \
        "$outside_secret_context" "$secret_version_context" \
        "$secret_via_context" "$server_execution_principal_context" ||
      ! verify_decrypt_probe explicitDeny \
        "$secret_context" "$secret_version_context" "$secret_via_context" \
        "$task_principal_context" ||
      ! verify_decrypt_probe explicitDeny \
        "$secret_context" "$secret_version_context" "$secret_via_context" \
        "$lambda_principal_context" ||
      ! verify_decrypt_probe explicitDeny \
        "$secret_context" "$secret_version_context" \
        "$cross_region_secret_via_context" \
        "$server_execution_principal_context" ||
      ! verify_decrypt_probe explicitDeny \
        "$secret_context" "$secret_version_context" "$ssm_via_context" \
        "$server_execution_principal_context" ||
      ! verify_decrypt_probe explicitDeny \
        "$ssm_context" "$secret_via_context" \
        "$server_execution_principal_context" ||
      ! verify_decrypt_probe explicitDeny \
        "$lambda_context" "$lambda_principal_context" \
        "$source_function_context" ||
      ! verify_decrypt_probe explicitDeny \
        "$lambda_context" "$nonlambda_principal_context" ||
      ! verify_decrypt_probe explicitDeny \
        "$outside_lambda_context" "$lambda_principal_context" ||
      ! verify_decrypt_probe explicitDeny; then
    return 1
  fi

  local current_default_version
  current_default_version="$(aws iam get-policy \
    --policy-arn "$policy_arn" \
    --query 'Policy.DefaultVersionId' \
    --output text 2>/dev/null || true)"
  [[ "$current_default_version" == "$default_version" ]]
}

verify_guarded_update() {
  if [[ "$guarded_update" != "true" ||
        "${WORKLOAD_BOUNDARY_MAINTENANCE_ACK:-}" != "true" ]]; then
    echo "Attached boundary updates require the guarded rollout." >&2
    return 1
  fi
  local quarantine_policy
  if ! quarantine_policy="$(aws iam get-role-policy \
      --role-name "$deploy_role_name" \
      --policy-name "$quarantine_policy_name" \
      --query PolicyDocument \
      --output json 2>/dev/null)" ||
      [[ -z "$quarantine_policy" ]] ||
      ! node "$repo_root/scripts/verify-workload-permissions-boundary.mjs" \
        --quarantine <<<"$quarantine_policy"; then
    return 1
  fi

  local simulation quarantine_actions_json
  local -a quarantine_actions
  quarantine_actions_json="$(jq -c '
    .quarantineProbeActions
    | select(
        type == "array" and
        length > 0 and
        all(.[]; type == "string" and length > 0)
      )
    | sort
    | select(length == (unique | length))
  ' "$contract_file")"
  if [[ -z "$quarantine_actions_json" ]]; then
    echo "Workload permissions-boundary contract is malformed." >&2
    return 1
  fi
  mapfile -t quarantine_actions < <(
    jq -r '.[]' <<<"$quarantine_actions_json"
  )
  if ! simulation="$(aws iam simulate-custom-policy \
      --policy-input-list "$quarantine_policy" \
      --action-names "${quarantine_actions[@]}" \
      --output json 2>/dev/null)" ||
      [[ -z "$simulation" ]]; then
    echo "Deploy-role quarantine is not effective for every probe." >&2
    return 1
  fi
  if ! jq -e --argjson expected "$quarantine_actions_json" '
    try (
      select(type == "object")
      | .EvaluationResults as $results
      | ($results | type) == "array"
      and ($results | length) == ($expected | length)
      and all(
        $results[];
        (.EvalActionName | type) == "string"
        and .EvalDecision == "explicitDeny"
      )
      and (
        [$results[].EvalActionName | ascii_downcase] | sort
      ) == (
        [$expected[] | ascii_downcase] | sort
      )
    ) catch false
  ' <<<"$simulation" >/dev/null; then
    echo "Deploy-role quarantine is not effective for every probe." >&2
    return 1
  fi
  local quarantine_policy_after
  if ! quarantine_policy_after="$(aws iam get-role-policy \
      --role-name "$deploy_role_name" \
      --policy-name "$quarantine_policy_name" \
      --query PolicyDocument \
      --output json 2>/dev/null)" ||
      [[ -z "$quarantine_policy_after" ]] ||
      ! node "$repo_root/scripts/verify-workload-permissions-boundary.mjs" \
        --quarantine <<<"$quarantine_policy_after"; then
    echo "Deploy-role quarantine changed after simulation." >&2
    return 1
  fi
}

if [[ $describe_exit -eq 0 ]]; then
  stack_status="$(jq -r '.Stacks[0].StackStatus // empty' <<<"$describe_output")"
  case "$stack_status" in
    CREATE_COMPLETE|UPDATE_COMPLETE)
      ;;
    UPDATE_ROLLBACK_COMPLETE)
      if [[ "$verify_only" == "true" ]]; then
        echo "Boundary stack requires a guarded recovery update." >&2
        exit 1
      fi
      force_guarded_recovery=true
      ;;
    UPDATE_ROLLBACK_FAILED)
      echo "Boundary stack rollback failed; run CloudFormation continue-update-rollback before retrying." >&2
      exit 1
      ;;
    *)
      echo "Boundary stack is not in an accepted complete state." >&2
      exit 1
      ;;
  esac
  policy_arn="$(read_policy_arn)"
  if [[ "$policy_arn" != "arn:${partition}:iam::${account_id}:policy/${policy_name}" ]]; then
    echo "Boundary policy identity read-back failed." >&2
    exit 1
  fi
  policy_revision="$(read_policy_revision)" || {
    echo "Boundary policy revision read-back failed." >&2
    exit 1
  }
  if [[ "$force_guarded_recovery" != "true" ]] &&
      verify_boundary_policy >/dev/null 2>&1; then
    echo "Retained workload permissions-boundary stack verified."
    exit 0
  fi
  if [[ "$verify_only" == "true" ]]; then
    echo "Workload permissions-boundary policy drift detected." >&2
    exit 1
  fi

  # Attachment state can change between a read and UpdateStack. Every update to
  # an existing policy therefore requires the deploy-role quarantine; only the
  # first stack creation is allowed outside the guarded rollout.
  if ! verify_guarded_update; then
    exit 1
  fi
  policy_revision="r$(node -p 'Date.now().toString() + process.pid.toString()')"

  set +e
  aws cloudformation update-stack \
    --stack-name "$stack_name" \
    --template-body "file://$template_file" \
    --parameters \
      "ParameterKey=ApplicationRegion,ParameterValue=$application_region" \
      "ParameterKey=BedrockProjectArn,ParameterValue=$bedrock_project_arn" \
      "ParameterKey=PolicyRevision,ParameterValue=$policy_revision" \
    --capabilities CAPABILITY_NAMED_IAM \
    --region "$region" >/dev/null 2>&1
  update_exit=$?
  set -e
  if [[ $update_exit -eq 0 ]]; then
    if ! aws cloudformation wait stack-update-complete \
      --stack-name "$stack_name" \
      --region "$region" >/dev/null 2>&1; then
      echo "Boundary stack update did not complete." >&2
      exit 1
    fi
  else
    echo "Boundary stack update failed." >&2
    exit 1
  fi
elif grep -qi "does not exist" <<<"$describe_output"; then
  if [[ "$verify_only" == "true" ]]; then
    echo "Workload permissions-boundary stack is not bootstrapped." >&2
    exit 1
  fi
  if ! aws cloudformation create-stack \
    --stack-name "$stack_name" \
    --template-body "file://$template_file" \
    --parameters \
      "ParameterKey=ApplicationRegion,ParameterValue=$application_region" \
      "ParameterKey=BedrockProjectArn,ParameterValue=$bedrock_project_arn" \
      "ParameterKey=PolicyRevision,ParameterValue=r1" \
    --capabilities CAPABILITY_NAMED_IAM \
    --region "$region" \
    --tags Key=Project,Value=mem9-on-aws Key=ManagedBy,Value=cli \
    >/dev/null 2>&1; then
    echo "Boundary stack creation failed." >&2
    exit 1
  fi
  if ! aws cloudformation wait stack-create-complete \
    --stack-name "$stack_name" \
    --region "$region" >/dev/null 2>&1; then
    echo "Boundary stack creation did not complete." >&2
    exit 1
  fi
else
  echo "Could not determine whether the boundary stack exists." >&2
  exit 1
fi

# Backticks are JMESPath literals, not shell substitutions.
# shellcheck disable=SC2016
resource_count="$(aws cloudformation describe-stack-resources \
  --stack-name "$stack_name" \
  --region "$region" \
  --query 'length(StackResources[?LogicalResourceId==`WorkloadPermissionsBoundary` && ResourceType==`AWS::IAM::ManagedPolicy`])' \
  --output text 2>/dev/null || true)"
stack_status="$(aws cloudformation describe-stacks \
  --stack-name "$stack_name" \
  --region "$region" \
  --query 'Stacks[0].StackStatus' \
  --output text 2>/dev/null || true)"
if [[ "$resource_count" != "1" || ! "$stack_status" =~ ^(CREATE|UPDATE)_COMPLETE$ ]]; then
  echo "Boundary stack read-back verification failed." >&2
  exit 1
fi

policy_arn="$(read_policy_arn)"
if [[ "$policy_arn" != "arn:${partition}:iam::${account_id}:policy/${policy_name}" ]]; then
  echo "Boundary policy identity read-back failed." >&2
  exit 1
fi
policy_revision="$(read_policy_revision)" || {
  echo "Boundary policy revision read-back failed." >&2
  exit 1
}
if ! verify_boundary_policy; then
  exit 1
fi

echo "Retained workload permissions-boundary stack verified."
