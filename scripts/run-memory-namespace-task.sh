#!/usr/bin/env bash

# Run a guarded namespace operator command inside an existing long-lived
# environment's private bootstrap Fargate task. PR previews use their
# stage-scoped bootstrap task directly in CI and must not assume the retained
# account-global operator role. Desired state and usernames are uploaded as
# short-lived SecureString parameters and deleted on every exit path.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/memory-namespace-operator.sh
# shellcheck disable=SC1091
source "$ROOT/scripts/lib/memory-namespace-operator.sh"
usage() {
  cat <<'EOF'
usage:
  STAGE=<prod|dev> scripts/run-memory-namespace-task.sh <operation> [options]

operations:
  preflight
  freeze
  backfill --legacy-namespace-id <uuid> --legacy-service-principal-id <uuid>
           --namespace <slug> --display-name <name>
           --acknowledge-shared-history I_ACKNOWLEDGE_EXISTING_MEMORY_IS_SHARED_TEAM_HISTORY
  enforce
  assert-phase --expected-phase <phase>
  reconcile --config <owner-only-json>
  assign-user --config <owner-only-json> --username-file <owner-only-file>
              --namespace <slug>
  move-user --config <owner-only-json> --username-file <owner-only-file>
            --namespace <slug>
  revoke-user --config <owner-only-json> --username-file <owner-only-file>
              [--emergency]
  show-user --config <owner-only-json> --username-file <owner-only-file>
EOF
}
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi
STAGE="${STAGE:?STAGE is required (for example prod)}"
OPERATION="${1:-}"
shift || true

case "$STAGE" in
  prod|dev) ;;
  *)
    echo "invalid STAGE: retained namespace operator supports only prod or dev" >&2
    exit 2
    ;;
esac
REGION="${AWS_REGION:-$(node "$ROOT/scripts/resolve-application-region.mjs")}"
case "$OPERATION" in
  reconcile|assign-user|move-user|revoke-user|show-user|assert-phase|preflight|freeze|backfill|enforce) ;;
  *) echo "unsupported namespace operation" >&2; exit 2 ;;
esac

CONFIG_FILE=""
USERNAME_FILE=""
NAMESPACE_SLUG=""
DISPLAY_NAME=""
LEGACY_NAMESPACE_ID=""
LEGACY_PRINCIPAL_ID=""
ACKNOWLEDGEMENT=""
EMERGENCY="0"
EXPECTED_PHASE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_FILE="${2:-}"
      shift 2
      ;;
    --username-file)
      USERNAME_FILE="${2:-}"
      shift 2
      ;;
    --namespace)
      NAMESPACE_SLUG="${2:-}"
      shift 2
      ;;
    --display-name)
      DISPLAY_NAME="${2:-}"
      shift 2
      ;;
    --legacy-namespace-id)
      LEGACY_NAMESPACE_ID="${2:-}"
      shift 2
      ;;
    --legacy-service-principal-id)
      LEGACY_PRINCIPAL_ID="${2:-}"
      shift 2
      ;;
    --acknowledge-shared-history)
      ACKNOWLEDGEMENT="${2:-}"
      shift 2
      ;;
    --emergency)
      EMERGENCY="1"
      shift
      ;;
    --expected-phase)
      EXPECTED_PHASE="${2:-}"
      shift 2
      ;;
    *)
      echo "unknown namespace operator option" >&2
      exit 2
      ;;
  esac
done

need_config=false
need_username=false
case "$OPERATION" in
  reconcile)
    need_config=true
    ;;
  assign-user|move-user|revoke-user|show-user)
    need_config=true
    need_username=true
    ;;
esac

if [[ "$need_config" == "true" ]]; then
  [[ -f "$CONFIG_FILE" ]] || { echo "--config is required" >&2; exit 2; }
  mode=$(stat -c '%a' "$CONFIG_FILE")
  [[ "$mode" == "600" ]] || {
    echo "namespace config must have mode 600" >&2
    exit 2
  }
fi
if [[ "$OPERATION" == "assign-user" || "$OPERATION" == "move-user" ]]; then
  [[ -n "$NAMESPACE_SLUG" ]] || {
    echo "--namespace is required for assignment" >&2
    exit 2
  }
fi
if [[ "$OPERATION" == "backfill" ]]; then
  [[ "$LEGACY_NAMESPACE_ID" =~ ^[0-9a-fA-F-]{36}$ ]] ||
    { echo "--legacy-namespace-id is required" >&2; exit 2; }
  [[ "$LEGACY_PRINCIPAL_ID" =~ ^[0-9a-fA-F-]{36}$ ]] ||
    { echo "--legacy-service-principal-id is required" >&2; exit 2; }
  [[ -n "$NAMESPACE_SLUG" && -n "$DISPLAY_NAME" ]] ||
    { echo "--namespace and --display-name are required" >&2; exit 2; }
  [[ "$ACKNOWLEDGEMENT" == "I_ACKNOWLEDGE_EXISTING_MEMORY_IS_SHARED_TEAM_HISTORY" ]] ||
    { echo "exact shared-history acknowledgement is required" >&2; exit 2; }
fi
if [[ "$OPERATION" == "assert-phase" ]]; then
  case "$EXPECTED_PHASE" in
    additive_ready|frozen|backfilling|application_ready|constraints_complete) ;;
    *) echo "--expected-phase is required for assert-phase" >&2; exit 2 ;;
  esac
fi

TMP_DIR=$(mktemp -d)
chmod 700 "$TMP_DIR"
PARAMETERS=()
TASK_ARN=""
CLUSTER=""
TASK_STOPPED=false

stop_operator_task() {
  [[ -n "$TASK_ARN" && -n "$CLUSTER" && "$TASK_STOPPED" != "true" ]] ||
    return 0
  local status
  status=$(aws ecs describe-tasks \
    --cluster "$CLUSTER" --tasks "$TASK_ARN" --region "$REGION" \
    --query 'tasks[0].lastStatus' --output text 2>/dev/null || true)
  if [[ "$status" != "STOPPED" && -n "$status" && "$status" != "None" ]]; then
    aws ecs stop-task \
      --cluster "$CLUSTER" \
      --task "$TASK_ARN" \
      --reason "namespace operator runner ended before task completion" \
      --region "$REGION" >/dev/null 2>&1 || true
    for _ in $(seq 1 18); do
      status=$(aws ecs describe-tasks \
        --cluster "$CLUSTER" --tasks "$TASK_ARN" --region "$REGION" \
        --query 'tasks[0].lastStatus' --output text 2>/dev/null || true)
      [[ "$status" == "STOPPED" ]] && break
      sleep 5
    done
  fi
  if [[ "$status" != "STOPPED" ]]; then
    echo "warning: namespace operator task did not confirm STOPPED" >&2
    return 1
  fi
  TASK_STOPPED=true
}

cleanup() {
  local exit_status=$?
  local cleanup_status=$exit_status
  trap - EXIT INT TERM
  if ! stop_operator_task; then
    echo "error: namespace operator task stop was not confirmed" >&2
    if [[ ${#PARAMETERS[@]} -gt 0 ]]; then
      echo "operator inputs retained because the task may still be running" >&2
    fi
    rm -rf "$TMP_DIR"
    exit 1
  fi
  if [[ ${#PARAMETERS[@]} -gt 0 ]]; then
    local delete_response="$TMP_DIR/delete-parameters.json"
    deleted=false
    for delay in 1 2 4; do
      if aws ssm delete-parameters \
        --names "${PARAMETERS[@]}" \
        --region "$REGION" \
        --output json >"$delete_response" 2>/dev/null &&
        verify_ssm_delete_response \
          "$delete_response" "${PARAMETERS[@]}"; then
        deleted=true
        break
      fi
      sleep "$delay"
    done
    if [[ "$deleted" != "true" ]]; then
      echo "error: failed to delete short-lived namespace operator inputs" >&2
      cleanup_status=1
    fi
  fi
  rm -rf "$TMP_DIR"
  exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$need_username" == "true" && -z "$USERNAME_FILE" ]]; then
  USERNAME_FILE="$TMP_DIR/username"
  umask 077
  cat >"$USERNAME_FILE"
fi
if [[ "$need_username" == "true" ]]; then
  [[ -f "$USERNAME_FILE" ]] || {
    echo "username input is required through stdin or --username-file" >&2
    exit 2
  }
  [[ "$(stat -c '%a' "$USERNAME_FILE")" == "600" ]] || {
    echo "username file must have mode 600" >&2
    exit 2
  }
fi

CONFIG_HASH=""
USERNAME_HASH=""
if [[ "$need_config" == "true" ]]; then
  CONFIG_HASH=$(sha256sum "$CONFIG_FILE" | awk '{print $1}')
fi
if [[ "$need_username" == "true" ]]; then
  USERNAME_HASH=$(sha256sum "$USERNAME_FILE" | awk '{print $1}')
fi
OPERATION_KEY=$(
  jq -cn \
    --arg operation "$OPERATION" \
    --arg namespace "$NAMESPACE_SLUG" \
    --arg displayName "$DISPLAY_NAME" \
    --arg legacyNamespace "$LEGACY_NAMESPACE_ID" \
    --arg legacyPrincipal "$LEGACY_PRINCIPAL_ID" \
    --arg acknowledgement "$ACKNOWLEDGEMENT" \
    --arg emergency "$EMERGENCY" \
    --arg expectedPhase "$EXPECTED_PHASE" \
    --arg configHash "$CONFIG_HASH" \
    --arg usernameHash "$USERNAME_HASH" \
    '{
      operation:$operation,
      namespace:$namespace,
      displayName:$displayName,
      legacyNamespace:$legacyNamespace,
      legacyPrincipal:$legacyPrincipal,
      acknowledgement:$acknowledgement,
      emergency:$emergency,
      expectedPhase:$expectedPhase,
      configHash:$configHash,
      usernameHash:$usernameHash
    }' |
    sha256sum |
    awk '{print $1}'
)

RUN_ID="$(date +%s)-${BASHPID}-${RANDOM}"
PARAM_PREFIX="/mem9-on-aws/${STAGE}/namespace-operator/${RUN_ID}"

put_secure_parameter() {
  local name=$1
  local value_file=$2
  local request_file
  request_file="$TMP_DIR/put-$(basename "$name").json"
  jq -n \
    --arg Name "$name" \
    --rawfile Value "$value_file" \
    '{Name:$Name,Type:"SecureString",Value:$Value,Overwrite:false}' \
    >"$request_file"
  chmod 600 "$request_file"
  aws ssm put-parameter \
    --cli-input-json "file://${request_file}" \
    --region "$REGION" >/dev/null
  PARAMETERS+=("$name")
}

CONFIG_PARAMETER=""
USERNAME_PARAMETER=""
if [[ "$need_config" == "true" ]]; then
  CONFIG_PARAMETER="${PARAM_PREFIX}/config"
  put_secure_parameter "$CONFIG_PARAMETER" "$CONFIG_FILE"
fi
if [[ "$need_username" == "true" ]]; then
  USERNAME_PARAMETER="${PARAM_PREFIX}/username"
  put_secure_parameter "$USERNAME_PARAMETER" "$USERNAME_FILE"
fi

PREFIX="/mem9-on-aws/${STAGE}/bootstrap"
CLUSTER=$(aws ssm get-parameter \
  --name "${PREFIX}/cluster-name" --region "$REGION" \
  --query Parameter.Value --output text)
TASK_DEF=$(aws ssm get-parameter \
  --name "${PREFIX}/task-def-arn" --region "$REGION" \
  --query Parameter.Value --output text)
TASK_SG=$(aws ssm get-parameter \
  --name "${PREFIX}/task-sg-id" --region "$REGION" \
  --query Parameter.Value --output text)
SUBNETS_CSV=$(aws ssm get-parameter \
  --name "${PREFIX}/subnet-ids" --region "$REGION" \
  --query Parameter.Value --output text)
CONTAINER_NAME=$(aws ecs describe-task-definition \
  --task-definition "$TASK_DEF" --region "$REGION" \
  --query 'taskDefinition.containerDefinitions[0].name' --output text)
OPERATOR_ROLE_NAME="${MEM9_NAMESPACE_OPERATOR_ROLE_NAME:-mem9-on-aws-namespace-operator}"
OPERATOR_ROLE_ARN=$(aws iam get-role \
  --role-name "$OPERATOR_ROLE_NAME" \
  --query Role.Arn \
  --output text)

TASK_OPERATION="$OPERATION"
[[ "$OPERATION" == "reconcile" ]] && TASK_OPERATION="namespace-reconcile"

ENVIRONMENT=$(
  jq -n \
    --arg operation "$TASK_OPERATION" \
    --arg config "$CONFIG_PARAMETER" \
    --arg username "$USERNAME_PARAMETER" \
    --arg namespace "$NAMESPACE_SLUG" \
    --arg emergency "$EMERGENCY" \
    --arg legacyNamespace "$LEGACY_NAMESPACE_ID" \
    --arg legacyPrincipal "$LEGACY_PRINCIPAL_ID" \
    --arg displayName "$DISPLAY_NAME" \
    --arg expectedPhase "$EXPECTED_PHASE" \
    --arg operationKey "$OPERATION_KEY" \
    --arg acknowledgement "$ACKNOWLEDGEMENT" '
      [
        {name:"MEM9_BOOTSTRAP_OPERATION",value:$operation},
        {name:"MEM9_NAMESPACE_CONFIG_PARAMETER",value:$config},
        {name:"MEM9_NAMESPACE_USERNAME_PARAMETER",value:$username},
        {name:"MEM9_NAMESPACE_SLUG",value:$namespace},
        {name:"MEM9_NAMESPACE_EMERGENCY",value:$emergency},
        {name:"MEM9_LEGACY_NAMESPACE_ID",value:$legacyNamespace},
        {name:"MEM9_LEGACY_SERVICE_PRINCIPAL_ID",value:$legacyPrincipal},
        {name:"MEM9_LEGACY_NAMESPACE_SLUG",value:$namespace},
        {name:"MEM9_LEGACY_NAMESPACE_DISPLAY_NAME",value:$displayName},
        {name:"MEM9_NAMESPACE_OPERATION_KEY",value:$operationKey},
        {name:"MEM9_SHARED_HISTORY_ACKNOWLEDGEMENT",value:$acknowledgement},
        {name:"MEM9_EXPECTED_NAMESPACE_PHASE",value:$expectedPhase}
      ] | map(select(.value != ""))
    '
)
OVERRIDES=$(jq -n \
  --arg name "$CONTAINER_NAME" \
  --arg taskRoleArn "$OPERATOR_ROLE_ARN" \
  --argjson environment "$ENVIRONMENT" \
  '{
    taskRoleArn:$taskRoleArn,
    containerOverrides:[{name:$name,environment:$environment}]
  }')
SUBNETS_JSON=$(printf '%s' "$SUBNETS_CSV" | jq -Rc 'split(",")')
NET_CONFIG=$(jq -cn \
  --argjson subnets "$SUBNETS_JSON" \
  --arg sg "$TASK_SG" '
    {awsvpcConfiguration:{
      subnets:$subnets,
      securityGroups:[$sg],
      assignPublicIp:"DISABLED"
    }}
  ')

STARTED_BY="mem9-ns-${STAGE}"
EXISTING_TASK_LIST=$(aws ecs list-tasks \
  --cluster "$CLUSTER" \
  --started-by "$STARTED_BY" \
  --region "$REGION" \
  --output json)
mapfile -t LISTED_TASK_ARNS < <(
  printf '%s' "$EXISTING_TASK_LIST" | jq -r '.taskArns[]?'
)
if [[ ${#LISTED_TASK_ARNS[@]} -gt 0 ]]; then
  DESCRIBED_TASKS=$(aws ecs describe-tasks \
    --cluster "$CLUSTER" \
    --tasks "${LISTED_TASK_ARNS[@]}" \
    --region "$REGION" \
    --output json)
else
  DESCRIBED_TASKS='{"tasks":[]}'
fi
EXISTING_TASKS=$(printf '%s' "$DESCRIBED_TASKS" | jq '
  {
    tasks: [
      .tasks[]
      | select(
          .lastStatus != "STOPPED"
          and .desiredStatus != "STOPPED"
        )
    ]
  }
')
EXISTING_COUNT=$(printf '%s' "$EXISTING_TASKS" | jq '.tasks | length')
if [[ "$EXISTING_COUNT" -gt 1 ]]; then
  echo "multiple namespace operator tasks are active; refusing another launch" >&2
  exit 1
fi
if [[ "$EXISTING_COUNT" -eq 1 ]]; then
  EXISTING_TASK_ARN=$(printf '%s' "$EXISTING_TASKS" | jq -r '.tasks[0].taskArn')
  EXISTING_TASK="$EXISTING_TASKS"
  EXISTING_OPERATION_KEY=$(printf '%s' "$EXISTING_TASK" | jq -r '
    .tasks[0].overrides.containerOverrides[].environment[]
    | select(.name == "MEM9_NAMESPACE_OPERATION_KEY")
    | .value
  ' | head -1)
  if [[ "$EXISTING_OPERATION_KEY" != "$OPERATION_KEY" ]]; then
    echo "another namespace operator invocation is active" >&2
    exit 1
  fi
  while IFS= read -r parameter; do
    [[ -n "$parameter" ]] && PARAMETERS+=("$parameter")
  done < <(printf '%s' "$EXISTING_TASK" | jq -r '
    .tasks[0].overrides.containerOverrides[].environment[]
    | select(
        .name == "MEM9_NAMESPACE_CONFIG_PARAMETER"
        or .name == "MEM9_NAMESPACE_USERNAME_PARAMETER"
      )
    | .value
    | select(length > 0)
  ')
  TASK_ARN="$EXISTING_TASK_ARN"
  echo "namespace operator: reattached to the active invocation"
else
  RUN_OUT=$(aws ecs run-task \
    --cluster "$CLUSTER" \
    --task-definition "$TASK_DEF" \
    --launch-type FARGATE \
    --count 1 \
    --started-by "$STARTED_BY" \
    --network-configuration "$NET_CONFIG" \
    --overrides "$OVERRIDES" \
    --region "$REGION" \
    --output json)
  TASK_ARN=$(printf '%s' "$RUN_OUT" | jq -r '.tasks[0].taskArn // ""')
  if [[ -z "$TASK_ARN" ]]; then
    printf '%s' "$RUN_OUT" | jq -c '.failures // []' >&2
    TASK_ARN=""
    exit 1
  fi
fi

DEADLINE=$((SECONDS + 1800))
STATUS=""
while [[ $SECONDS -lt $DEADLINE ]]; do
  STATUS=$(aws ecs describe-tasks \
    --cluster "$CLUSTER" --tasks "$TASK_ARN" --region "$REGION" \
    --query 'tasks[0].lastStatus' --output text)
  [[ "$STATUS" == "STOPPED" ]] && break
  sleep 10
done
[[ "$STATUS" == "STOPPED" ]] || {
  echo "namespace operator task did not stop within 30 minutes" >&2
  stop_operator_task || true
  exit 1
}
TASK_STOPPED=true

EXIT_CODE=$(aws ecs describe-tasks \
  --cluster "$CLUSTER" --tasks "$TASK_ARN" --region "$REGION" \
  --query 'tasks[0].containers[0].exitCode' --output text)
if [[ "$EXIT_CODE" != "0" ]]; then
  if [[ "$OPERATION" == "assert-phase" ]]; then
    case "$EXIT_CODE" in
      31) OBSERVED_PHASE="additive_ready" ;;
      32) OBSERVED_PHASE="frozen" ;;
      33) OBSERVED_PHASE="backfilling" ;;
      34) OBSERVED_PHASE="application_ready" ;;
      35) OBSERVED_PHASE="constraints_complete" ;;
      39) OBSERVED_PHASE="unknown" ;;
      *) OBSERVED_PHASE="" ;;
    esac
    if [[ -n "$OBSERVED_PHASE" ]]; then
      echo "namespace phase check failed: observed ${OBSERVED_PHASE}; required ${EXPECTED_PHASE}" >&2
      exit 1
    fi
  fi
  echo "namespace operator task failed with exit code ${EXIT_CODE}" >&2
  exit 1
fi
echo "namespace operator ${OPERATION}: OK"
