#!/usr/bin/env bash
# deploy-decision-artifact-bucket.sh — Own the account-level reviewed-decision
# artifact bucket outside SST/Pulumi.
#
# Every SST stage shares this bucket and uses a stage-scoped object prefix.
# Keeping one CloudFormation owner avoids same-name CreateBucket failures and
# prevents preview teardown from owning shared audit data.
#
# Configuration (repo-root, gitignored .env or ambient environment):
#   AWS_PROFILE
#   MEM9_DECISION_ARTIFACT_BUCKET  optional exact bucket name; defaults to
#                                  mem9-audit-<caller-account-id>
#   STACK_NAME                    optional CloudFormation stack name
#
# Existing buckets are adopted automatically in two phases:
#   1. IMPORT the bucket alone with decision-artifact-bucket-import.yaml.
#   2. UPDATE to decision-artifact-bucket.yaml to reconcile hardening and create
#      the TLS-only policy.
#
# Usage:
#   scripts/deploy-decision-artifact-bucket.sh
#   scripts/deploy-decision-artifact-bucket.sh --create
#   scripts/deploy-decision-artifact-bucket.sh --update

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
if [[ -f "$repo_root/.env" ]]; then
  set -a
  . "$repo_root/.env"
  set +a
fi

stack_name="${STACK_NAME:-decision-artifact-bucket-mem9-on-aws}"
full_template="$repo_root/infra/cloudformation/decision-artifact-bucket.yaml"
import_template="$repo_root/infra/cloudformation/decision-artifact-bucket-import.yaml"
region="$(node "$repo_root/scripts/resolve-application-region.mjs")"
mode=""

for arg in "$@"; do
  case "$arg" in
    --create) mode="create" ;;
    --update) mode="update" ;;
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

if [[ ! -f "$full_template" || ! -f "$import_template" ]]; then
  echo "Decision-artifact CloudFormation template is missing." >&2
  exit 2
fi

valid_bucket_name() {
  local name="$1"
  [[ "$name" =~ ^[a-z0-9][a-z0-9-]{1,31}[a-z0-9]$ ]] &&
    [[ "$name" != xn--* ]] &&
    [[ "$name" != sthree-* ]] &&
    [[ "$name" != amzn-s3-demo-* ]] &&
    [[ "$name" != *-s3alias ]] &&
    [[ "$name" != *--ol-s3 ]] &&
    [[ "$name" != *--x-s3 ]] &&
    [[ "$name" != *--table-s3 ]] &&
    [[ "$name" != *-an ]]
}

# Validate an explicit override before the first AWS call. Besides producing a
# clearer error, this keeps an invalid external value from selecting an account.
bucket_name="${MEM9_DECISION_ARTIFACT_BUCKET:-}"
if [[ -n "$bucket_name" ]] && ! valid_bucket_name "$bucket_name"; then
  echo "MEM9_DECISION_ARTIFACT_BUCKET is an invalid decision-artifact bucket name." >&2
  exit 2
fi

account_id="$(aws sts get-caller-identity --query Account --output text)"
if [[ ! "$account_id" =~ ^[0-9]{12}$ ]]; then
  echo "AWS caller identity did not return a 12-digit account id." >&2
  exit 1
fi
bucket_name="${bucket_name:-mem9-audit-${account_id}}"
if ! valid_bucket_name "$bucket_name"; then
  echo "Resolved decision-artifact bucket name is invalid." >&2
  exit 2
fi

parameters=(
  "ParameterKey=DecisionArtifactBucketName,ParameterValue=$bucket_name"
)
import_change_set_name="adopt-decision-artifact-bucket"
import_change_set_description="mem9 decision-artifact bucket adoption"

read_stack_resources() {
  aws cloudformation describe-stack-resources \
    --stack-name "$stack_name" \
    --region "$region"
}

require_empty_stack_shell() {
  local resources
  if ! resources="$(read_stack_resources)"; then
    echo "Reading decision-artifact stack resources failed." >&2
    return 1
  fi
  if ! jq -e '
      .StackResources
      | type == "array" and length == 0
    ' <<<"$resources" >/dev/null; then
    echo "Decision-artifact recovery stack unexpectedly owns resources." >&2
    return 1
  fi
}

require_stack_bucket() {
  local resources
  if ! resources="$(read_stack_resources)"; then
    echo "Reading existing decision-artifact stack resources failed." >&2
    return 1
  fi
  if ! jq -e --arg bucket "$bucket_name" '
      [
        .StackResources[]?
        | select(
            .LogicalResourceId == "DecisionArtifactBucket"
            and .ResourceType == "AWS::S3::Bucket"
            and .PhysicalResourceId == $bucket
          )
      ]
      | length == 1
    ' <<<"$resources" >/dev/null; then
    echo "Existing decision-artifact stack owns a different bucket; refusing replacement." >&2
    return 1
  fi
}

execute_verified_import_change_set() {
  local change_set
  if ! aws cloudformation wait change-set-create-complete \
      --stack-name "$stack_name" \
      --change-set-name "$import_change_set_name" \
      --region "$region"; then
    echo "Bucket import change set did not become ready." >&2
    return 1
  fi
  if ! change_set="$(aws cloudformation describe-change-set \
      --stack-name "$stack_name" \
      --change-set-name "$import_change_set_name" \
      --region "$region")"; then
    echo "Reading the bucket import change set failed." >&2
    return 1
  fi
  if ! jq -e \
      --arg bucket "$bucket_name" \
      --arg description "$import_change_set_description" '
      .Description == $description
      and .Status == "CREATE_COMPLETE"
      and .ExecutionStatus == "AVAILABLE"
      and (
        .Parameters == [{
          ParameterKey: "DecisionArtifactBucketName",
          ParameterValue: $bucket
        }]
      )
      and (
        [
          .Changes[]?
          | select(
              .Type == "Resource"
              and .ResourceChange.Action == "Import"
              and .ResourceChange.LogicalResourceId == "DecisionArtifactBucket"
              and .ResourceChange.ResourceType == "AWS::S3::Bucket"
            )
        ]
        | length == 1
      )
      and (.Changes | length == 1)
    ' <<<"$change_set" >/dev/null; then
    echo "Bucket import change set read-back mismatch; refusing execution." >&2
    return 1
  fi
  if ! aws cloudformation execute-change-set \
      --stack-name "$stack_name" \
      --change-set-name "$import_change_set_name" \
      --region "$region"; then
    echo "Executing the bucket import change set failed." >&2
    return 1
  fi
  if ! aws cloudformation wait stack-import-complete \
      --stack-name "$stack_name" \
      --region "$region"; then
    echo "Bucket import did not complete." >&2
    return 1
  fi
}

if ! aws cloudformation validate-template \
    --template-body "file://$full_template" \
    --region "$region" >/dev/null; then
  echo "Decision-artifact full template validation failed." >&2
  exit 1
fi
if ! aws cloudformation validate-template \
    --template-body "file://$import_template" \
    --region "$region" >/dev/null; then
  echo "Decision-artifact import template validation failed." >&2
  exit 1
fi

set +e
describe_output="$(aws cloudformation describe-stacks \
  --stack-name "$stack_name" \
  --region "$region" 2>&1)"
describe_exit=$?
set -e
stack_exists=false
recovering_stack=false
resume_import_change_set=false
resume_import_wait=false
if [[ $describe_exit -eq 0 ]]; then
  stack_exists=true
elif grep -qiE 'does not exist|not exist' <<<"$describe_output"; then
  stack_exists=false
else
  echo "Could not determine whether the decision-artifact stack exists: $describe_output" >&2
  exit 1
fi

if [[ "$stack_exists" == "true" ]]; then
  if ! stack_status="$(jq -er '
      .Stacks
      | select(type == "array" and length == 1)
      | .[0].StackStatus
      | select(type == "string")
    ' <<<"$describe_output")"; then
    echo "Decision-artifact stack status is malformed." >&2
    exit 1
  fi
  case "$stack_status" in
    REVIEW_IN_PROGRESS)
      recovering_stack=true
      resume_import_change_set=true
      ;;
    IMPORT_IN_PROGRESS)
      recovering_stack=true
      resume_import_wait=true
      ;;
    IMPORT_ROLLBACK_COMPLETE)
      recovering_stack=true
      ;;
    CREATE_COMPLETE|IMPORT_COMPLETE|UPDATE_COMPLETE|UPDATE_ROLLBACK_COMPLETE) ;;
    IMPORT_ROLLBACK_FAILED)
      echo "Decision-artifact import rollback failed; recover it in CloudFormation before retrying." >&2
      exit 1
      ;;
    UPDATE_ROLLBACK_FAILED)
      echo "Decision-artifact stack rollback failed; run CloudFormation continue-update-rollback before retrying." >&2
      exit 1
      ;;
    *)
      echo "Decision-artifact stack is not in an accepted complete state: $stack_status" >&2
      exit 1
      ;;
  esac
  existing_bucket_name="$(jq -r '
    [
      .Stacks[0].Parameters[]?
      | select(.ParameterKey == "DecisionArtifactBucketName")
      | .ParameterValue
    ]
    | if length == 0 then "" elif length == 1 then .[0] else error("duplicate") end
  ' <<<"$describe_output")" || {
    echo "Decision-artifact stack parameters are malformed." >&2
    exit 1
  }
  if [[ "$recovering_stack" == "true" &&
        -n "$existing_bucket_name" &&
        "$existing_bucket_name" != "$bucket_name" ]]; then
    echo "Recovery stack names a different decision-artifact bucket; refusing mutation." >&2
    exit 1
  fi
  if [[ "$recovering_stack" != "true" &&
        -n "$existing_bucket_name" &&
        "$existing_bucket_name" != "$bucket_name" ]]; then
    echo "Existing decision-artifact stack owns a different bucket; refusing replacement." >&2
    exit 1
  fi
  case "$stack_status" in
    REVIEW_IN_PROGRESS|IMPORT_ROLLBACK_COMPLETE)
      require_empty_stack_shell || exit 1
      ;;
    IMPORT_IN_PROGRESS)
      ;;
    *)
      require_stack_bucket || exit 1
      ;;
  esac
  if [[ "$stack_status" == "IMPORT_ROLLBACK_COMPLETE" ]]; then
    echo "Removing the verified empty import-rollback stack shell..."
    if ! aws cloudformation delete-stack \
        --stack-name "$stack_name" \
        --region "$region"; then
      echo "Deleting the empty import-rollback stack shell failed." >&2
      exit 1
    fi
    if ! aws cloudformation wait stack-delete-complete \
        --stack-name "$stack_name" \
        --region "$region"; then
      echo "Empty import-rollback stack shell did not delete." >&2
      exit 1
    fi
    stack_exists=false
  fi
fi

if [[ "$mode" == "create" &&
      "$stack_exists" == "true" &&
      "$recovering_stack" != "true" ]]; then
  echo "Decision-artifact stack already exists; --create refused." >&2
  exit 1
fi
if [[ "$mode" == "update" &&
      "$stack_exists" != "true" &&
      "$recovering_stack" != "true" ]]; then
  echo "Decision-artifact stack does not exist; --update refused." >&2
  exit 1
fi

bucket_exists=false
if [[ "$stack_exists" != "true" ||
      "$resume_import_change_set" == "true" ]]; then
  set +e
  bucket_probe="$(aws s3api head-bucket \
    --bucket "$bucket_name" \
    --expected-bucket-owner "$account_id" \
    --region "$region" 2>&1)"
  bucket_probe_exit=$?
  set -e
  if [[ $bucket_probe_exit -eq 0 ]]; then
    bucket_exists=true
  elif grep -qiE '\(404\)|NoSuchBucket|Not Found' <<<"$bucket_probe"; then
    bucket_exists=false
  else
    echo "Could not safely determine whether bucket $bucket_name exists: $bucket_probe" >&2
    exit 1
  fi
fi

echo "Stack:      $stack_name"
echo "Region:     $region"
echo "BucketName: $bucket_name"

import_completed=false
if [[ "$resume_import_wait" == "true" ]]; then
  echo "Waiting for the in-progress bucket import..."
  if ! aws cloudformation wait stack-import-complete \
      --stack-name "$stack_name" \
      --region "$region"; then
    echo "Bucket import did not complete." >&2
    exit 1
  fi
  import_completed=true
elif [[ "$resume_import_change_set" == "true" ]]; then
  if [[ "$bucket_exists" != "true" ]]; then
    echo "Recovery change set targets a bucket that no longer exists." >&2
    exit 1
  fi
  echo "Resuming the pending bucket import change set..."
  execute_verified_import_change_set || exit 1
  import_completed=true
elif [[ "$stack_exists" != "true" && "$bucket_exists" == "true" ]]; then
  resources_to_import="$(jq -cn --arg bucket "$bucket_name" '[
    {
      ResourceType: "AWS::S3::Bucket",
      LogicalResourceId: "DecisionArtifactBucket",
      ResourceIdentifier: { BucketName: $bucket }
    }
  ]')"
  echo "Importing existing bucket with the import-only template..."
  if ! aws cloudformation create-change-set \
      --stack-name "$stack_name" \
      --change-set-name "$import_change_set_name" \
      --description "$import_change_set_description" \
      --change-set-type IMPORT \
      --template-body "file://$import_template" \
      --parameters "${parameters[@]}" \
      --resources-to-import "$resources_to_import" \
      --region "$region" >/dev/null; then
    echo "Creating the bucket import change set failed." >&2
    exit 1
  fi
  execute_verified_import_change_set || exit 1
  import_completed=true
elif [[ "$stack_exists" != "true" ]]; then
  echo "Creating the decision-artifact stack..."
  if ! aws cloudformation create-stack \
      --stack-name "$stack_name" \
      --template-body "file://$full_template" \
      --parameters "${parameters[@]}" \
      --region "$region" \
      --tags Key=Project,Value=mem9-on-aws Key=ManagedBy,Value=cli >/dev/null; then
    echo "Decision-artifact stack creation failed." >&2
    exit 1
  fi
  if ! aws cloudformation wait stack-create-complete \
      --stack-name "$stack_name" \
      --region "$region"; then
    echo "Decision-artifact stack creation did not complete." >&2
    exit 1
  fi
  stack_exists=created
fi

if [[ "$import_completed" == "true" ]]; then
  require_stack_bucket || exit 1
  stack_exists=true
fi

# An import records the live properties but does not reconcile them. The normal
# update is therefore mandatory after adoption, even if the bucket looked close
# to the desired declaration before import.
if [[ "$stack_exists" == "true" ]]; then
  echo "Applying the complete decision-artifact template..."
  set +e
  update_output="$(aws cloudformation update-stack \
    --stack-name "$stack_name" \
    --template-body "file://$full_template" \
    --parameters "${parameters[@]}" \
    --region "$region" 2>&1)"
  update_exit=$?
  set -e
  if [[ $update_exit -eq 0 ]]; then
    if ! aws cloudformation wait stack-update-complete \
        --stack-name "$stack_name" \
        --region "$region"; then
      echo "Decision-artifact stack update did not complete." >&2
      exit 1
    fi
  elif grep -q "No updates are to be performed" <<<"$update_output"; then
    echo "No template update was required; live verification still runs."
  else
    echo "Decision-artifact stack update failed: $update_output" >&2
    exit 1
  fi
fi

if ! final_stack="$(aws cloudformation describe-stacks \
    --stack-name "$stack_name" \
    --region "$region")"; then
  echo "Reading the final decision-artifact stack failed." >&2
  exit 1
fi
if ! jq -e --arg bucket "$bucket_name" '
    .Stacks
    | select(type == "array" and length == 1)
    | .[0]
      | select(
        .StackStatus == "CREATE_COMPLETE"
        or .StackStatus == "IMPORT_COMPLETE"
        or .StackStatus == "UPDATE_COMPLETE"
        or .StackStatus == "UPDATE_ROLLBACK_COMPLETE"
      )
    | [
        .Parameters[]?
        | select(.ParameterKey == "DecisionArtifactBucketName")
        | .ParameterValue
      ]
    | length == 1 and .[0] == $bucket
  ' <<<"$final_stack" >/dev/null; then
  echo "Decision-artifact stack read-back mismatch." >&2
  exit 1
fi

if ! stack_resources="$(aws cloudformation describe-stack-resources \
    --stack-name "$stack_name" \
    --region "$region")"; then
  echo "Reading decision-artifact stack resources failed." >&2
  exit 1
fi
if ! jq -e --arg bucket "$bucket_name" '
    .StackResources
    | select(type == "array")
    | . as $resources
    | (
        [
          $resources[]
          | select(
              .LogicalResourceId == "DecisionArtifactBucket"
              and .ResourceType == "AWS::S3::Bucket"
              and .PhysicalResourceId == $bucket
            )
        ]
        | length == 1
      )
      and (
        [
          $resources[]
          | select(
              .LogicalResourceId == "DecisionArtifactBucketPolicy"
              and .ResourceType == "AWS::S3::BucketPolicy"
            )
        ]
        | length == 1
      )
  ' <<<"$stack_resources" >/dev/null; then
  echo "Decision-artifact bucket or policy ownership read-back mismatch." >&2
  exit 1
fi

s3_args=(
  --bucket "$bucket_name"
  --expected-bucket-owner "$account_id"
  --region "$region"
)

if ! location_json="$(aws s3api get-bucket-location "${s3_args[@]}")"; then
  echo "Reading decision-artifact bucket location failed." >&2
  exit 1
fi
location="$(jq -r '
  .LocationConstraint
  | if . == null or . == "None" then "us-east-1"
    elif . == "EU" then "eu-west-1"
    else .
    end
' <<<"$location_json")" || {
  echo "Decision-artifact bucket location response is malformed." >&2
  exit 1
}
if [[ "$location" != "$region" ]]; then
  echo "Decision-artifact bucket is in $location, expected $region." >&2
  exit 1
fi

if ! public_access="$(aws s3api get-public-access-block "${s3_args[@]}")"; then
  echo "Reading decision-artifact public-access block failed." >&2
  exit 1
fi
if ! jq -e '
    .PublicAccessBlockConfiguration == {
      BlockPublicAcls: true,
      BlockPublicPolicy: true,
      IgnorePublicAcls: true,
      RestrictPublicBuckets: true
    }
  ' <<<"$public_access" >/dev/null; then
  echo "Decision-artifact public-access block read-back mismatch." >&2
  exit 1
fi

if ! encryption="$(aws s3api get-bucket-encryption "${s3_args[@]}")"; then
  echo "Reading decision-artifact bucket encryption failed." >&2
  exit 1
fi
if ! jq -e '
    .ServerSideEncryptionConfiguration.Rules
    | select(type == "array" and length == 1)
    | .[0]
    | .BucketKeyEnabled == true
      and .ApplyServerSideEncryptionByDefault.SSEAlgorithm == "aws:kms"
      and (
        .ApplyServerSideEncryptionByDefault.KMSMasterKeyID == "alias/aws/s3"
        or .ApplyServerSideEncryptionByDefault.KMSMasterKeyID == "aws/s3"
        or (
          .ApplyServerSideEncryptionByDefault.KMSMasterKeyID
          | endswith(":alias/aws/s3")
        )
      )
  ' <<<"$encryption" >/dev/null; then
  echo "Decision-artifact bucket encryption read-back mismatch." >&2
  exit 1
fi

if ! lifecycle="$(aws s3api get-bucket-lifecycle-configuration \
    "${s3_args[@]}")"; then
  echo "Reading decision-artifact lifecycle failed." >&2
  exit 1
fi
if ! jq -e '
    .Rules
    | select(type == "array" and length == 1)
    | .[0]
    | .ID == "expire-decision-artifacts"
      and .Status == "Enabled"
      and ((.Filter.Prefix // .Prefix // "") == "")
      and .Expiration.Days == 3
      and .AbortIncompleteMultipartUpload.DaysAfterInitiation == 1
  ' <<<"$lifecycle" >/dev/null; then
  echo "Decision-artifact lifecycle read-back mismatch." >&2
  exit 1
fi

if ! policy="$(aws s3api get-bucket-policy "${s3_args[@]}")"; then
  echo "Reading decision-artifact bucket policy failed." >&2
  exit 1
fi
if ! jq -e --arg bucket_arn "arn:aws:s3:::$bucket_name" '
    .Policy
    | fromjson
    | select(.Version == "2012-10-17")
    | .Statement
    | select(type == "array" and length == 1)
    | .[0]
    | .Sid == "DenyInsecureTransport"
      and .Effect == "Deny"
      and (.Principal == "*" or .Principal == {AWS: "*"})
      and (.Action == "s3:*" or .Action == ["s3:*"])
      and (
        (if (.Resource | type) == "array" then .Resource else [.Resource] end)
        | sort == ([$bucket_arn, ($bucket_arn + "/*")] | sort)
      )
      and .Condition.Bool["aws:SecureTransport"] == "false"
  ' <<<"$policy" >/dev/null; then
  echo "Decision-artifact bucket policy read-back mismatch." >&2
  exit 1
fi

if ! tags="$(aws s3api get-bucket-tagging "${s3_args[@]}")"; then
  echo "Reading decision-artifact bucket tags failed." >&2
  exit 1
fi
if ! jq -e '
    .TagSet
    | map(select(
        (.Key == "ManagedBy" and .Value == "cloudformation")
        or (.Key == "Project" and .Value == "mem9-on-aws")
      ))
    | length == 2
  ' <<<"$tags" >/dev/null; then
  echo "Decision-artifact bucket tags read-back mismatch." >&2
  exit 1
fi

if ! drift_detection_id="$(aws cloudformation detect-stack-drift \
    --stack-name "$stack_name" \
    --region "$region" \
    --query StackDriftDetectionId \
    --output text)" ||
    [[ -z "$drift_detection_id" || "$drift_detection_id" == "None" ]]; then
  echo "Starting decision-artifact stack drift detection failed." >&2
  exit 1
fi
drift_status=""
for _ in {1..60}; do
  if ! drift_status="$(aws cloudformation describe-stack-drift-detection-status \
      --stack-drift-detection-id "$drift_detection_id" \
      --region "$region")"; then
    echo "Reading decision-artifact stack drift status failed." >&2
    exit 1
  fi
  detection_status="$(jq -r '.DetectionStatus // empty' <<<"$drift_status")"
  case "$detection_status" in
    DETECTION_COMPLETE) break ;;
    DETECTION_IN_PROGRESS) sleep 5 ;;
    DETECTION_FAILED)
      echo "Decision-artifact stack drift detection failed." >&2
      exit 1
      ;;
    *)
      echo "Decision-artifact stack drift status is malformed." >&2
      exit 1
      ;;
  esac
done
if ! jq -e '
    .DetectionStatus == "DETECTION_COMPLETE"
    and .StackDriftStatus == "IN_SYNC"
  ' <<<"$drift_status" >/dev/null; then
  echo "Decision-artifact stack drift verification failed." >&2
  exit 1
fi

echo "Decision-artifact bucket is CloudFormation-owned, hardened, and IN_SYNC."
