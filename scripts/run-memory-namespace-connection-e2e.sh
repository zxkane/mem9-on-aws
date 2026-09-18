#!/usr/bin/env bash

set -euo pipefail

STAGE="${STAGE:?STAGE is required (pr-N)}"
if ! [[ "$STAGE" =~ ^pr-[1-9][0-9]*$ ]]; then
  echo "::error::namespace connection E2E is restricted to pr-N stages"
  exit 2
fi
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REGION="${AWS_REGION:-$(node "$ROOT/scripts/resolve-application-region.mjs")}"
PREFIX="/mem9-on-aws/${STAGE}"

ssm() {
  aws ssm get-parameter \
    --name "$1" \
    --region "$REGION" \
    --query Parameter.Value \
    --output text
}

TASK_SG=$(ssm "${PREFIX}/db/task-sg-id")
DB_SG=$(ssm "${PREFIX}/db/db-sg-id")
DB_HOST=$(ssm "${PREFIX}/db/host")
PROXY_SG=$(ssm "${PREFIX}/gateway/proxy-sg-id")
PROXY_FUNCTION=$(ssm "${PREFIX}/gateway/proxy-function-name")

LAMBDA_SGS=$(aws lambda get-function-configuration \
  --function-name "$PROXY_FUNCTION" \
  --region "$REGION" \
  --query 'VpcConfig.SecurityGroupIds' \
  --output json)
DB_RULES=$(aws ec2 describe-security-groups \
  --group-ids "$DB_SG" \
  --region "$REGION" \
  --query 'SecurityGroups[0].IpPermissions' \
  --output json)
DB_CLUSTERS=$(aws rds describe-db-clusters \
  --region "$REGION" \
  --output json)
NETWORK_INPUT=$(jq -cn \
  --arg taskSecurityGroup "$TASK_SG" \
  --arg dbSecurityGroup "$DB_SG" \
  --arg proxySecurityGroup "$PROXY_SG" \
  --arg dbHost "$DB_HOST" \
  --argjson lambdaSecurityGroups "$LAMBDA_SGS" \
  --argjson dbPermissions "$DB_RULES" \
  --argjson dbClusters "$(printf '%s' "$DB_CLUSTERS" | jq -c '.DBClusters')" '
    {
      taskSecurityGroup:$taskSecurityGroup,
      dbSecurityGroup:$dbSecurityGroup,
      proxySecurityGroup:$proxySecurityGroup,
      dbHost:$dbHost,
      lambdaSecurityGroups:$lambdaSecurityGroups,
      dbPermissions:$dbPermissions,
      dbClusters:$dbClusters
    }
  ')
printf '%s' "$NETWORK_INPUT" |
  node "$ROOT/scripts/validate-memory-namespace-network.mjs"

snapshot() {
  MEM9_PREVIEW_OBSERVATION_OPERATION=connection-snapshot \
  MEM9_PREVIEW_OBSERVATION_EVENT=namespace_connection_snapshot \
    bash "$ROOT/scripts/run-memory-namespace-benchmark.sh"
}

BEFORE=$(snapshot)
MEM9_NAMESPACE_CONNECTION_PROBE_ONLY=1 \
  bash "$ROOT/scripts/run-memory-namespace-e2e.sh"
AFTER=$(snapshot)

RESULT=$(MEM9_REPO_ROOT="$ROOT" node --input-type=module - "$BEFORE" "$AFTER" <<'NODE'
import { pathToFileURL } from "node:url";
const { compareConnectionSnapshots } = await import(
  pathToFileURL(`${process.env.MEM9_REPO_ROOT}/scripts/observe-memory-namespace-connections.mjs`).href
);
const before = JSON.parse(process.argv[2]);
const after = JSON.parse(process.argv[3]);
process.stdout.write(JSON.stringify({
  event: "namespace_connection_attribution",
  ...compareConnectionSnapshots(before, after),
}));
NODE
)
printf '%s\n' "$RESULT"

bash "$ROOT/scripts/run-memory-namespace-e2e.sh"
