#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import {
  boundaryPolicyDriftDiagnostic,
  verifyBoundaryPolicyDocument,
  verifyQuarantinePolicy,
} from "./lib/workload-permissions-boundary.mjs";

try {
  const input = await readFile("/dev/stdin", "utf8");
  const document = JSON.parse(input);
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
  const valid = quarantine
    ? verifyQuarantinePolicy(document)
    : verifyBoundaryPolicyDocument(document, contract);
  if (!valid) {
    const label = quarantine
      ? "Deploy-role quarantine"
      : "Workload permissions-boundary";
    process.stderr.write(`${label} policy read-back mismatch.\n`);
    if (!quarantine) {
      process.stderr.write(
        `${boundaryPolicyDriftDiagnostic(document, contract)}\n`,
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
