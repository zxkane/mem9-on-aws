#!/usr/bin/env node

import {
  boundaryPolicyDriftDiagnostic,
  verifyBoundaryPolicyDocument,
  verifyGatewayBoundaryPolicyDocument,
  verifyQuarantinePolicy,
} from "./lib/workload-permissions-boundary.mjs";
import {gatewayBoundaryProbeCases} from './lib/gateway-workload-boundary.mjs';

try {
  let input = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) {
    input += chunk;
    if (Buffer.byteLength(input) > 1024 * 1024) throw new Error("policy input exceeds limit");
  }
  const quarantine = process.argv[2] === "--quarantine";
  const contract = {
    accountId: process.env.WORKLOAD_BOUNDARY_ACCOUNT_ID,
    applicationRegion: process.env.WORKLOAD_BOUNDARY_APPLICATION_REGION,
    bedrockProjectArn: process.env.WORKLOAD_BOUNDARY_BEDROCK_PROJECT_ARN,
    decisionArtifactBucketName:
      process.env.WORKLOAD_BOUNDARY_DECISION_ARTIFACT_BUCKET,
    openAiBedrockProjectArn:
      process.env.WORKLOAD_BOUNDARY_OPENAI_BEDROCK_PROJECT_ARN || "",
    partition: process.env.WORKLOAD_BOUNDARY_PARTITION,
    policyRevision: process.env.WORKLOAD_BOUNDARY_POLICY_REVISION,
  };
  if (process.argv[2] === '--gateway-probes') {
    process.stdout.write(JSON.stringify(gatewayBoundaryProbeCases(contract))+'\n');
    process.exit(0);
  }
  const gateway = process.argv[2] === '--gateway';
  const valid = quarantine
    ? verifyQuarantinePolicy(input)
    : gateway ? verifyGatewayBoundaryPolicyDocument(input, contract) : verifyBoundaryPolicyDocument(input, contract);
  if (!valid) {
    const label = quarantine
      ? "Deploy-role quarantine"
      : "Workload permissions-boundary";
    process.stderr.write(`${label} policy read-back mismatch.\n`);
    if (!quarantine && !gateway) {
      process.stderr.write(
        `${boundaryPolicyDriftDiagnostic(input, contract)}\n`,
      );
    }
    process.exitCode = 1;
  }
} catch {
  const label =
    process.argv[2] === "--quarantine"
      ? "Deploy-role quarantine"
      : "Workload permissions-boundary";
  process.stderr.write(`${label} policy read-back mismatch.\n`);
  process.exitCode = 1;
}
