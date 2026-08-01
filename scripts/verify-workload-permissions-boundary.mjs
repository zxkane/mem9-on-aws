#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import {
  verifyBoundaryPolicyDocument,
  verifyQuarantinePolicy,
} from "./lib/workload-permissions-boundary.mjs";

try {
  const input = await readFile("/dev/stdin", "utf8");
  const document = JSON.parse(input);
  const valid =
    process.argv[2] === "--quarantine"
      ? verifyQuarantinePolicy(document)
      : verifyBoundaryPolicyDocument(document, {
          accountId: process.env.WORKLOAD_BOUNDARY_ACCOUNT_ID,
          applicationRegion: process.env.WORKLOAD_BOUNDARY_APPLICATION_REGION,
          bedrockProjectArn: process.env.WORKLOAD_BOUNDARY_BEDROCK_PROJECT_ARN,
          openAiBedrockProjectArn:
            process.env.WORKLOAD_BOUNDARY_OPENAI_BEDROCK_PROJECT_ARN || "",
          partition: process.env.WORKLOAD_BOUNDARY_PARTITION,
          policyRevision: process.env.WORKLOAD_BOUNDARY_POLICY_REVISION,
        });
  if (!valid) {
    throw new Error("mismatch");
  }
} catch {
  const label =
    process.argv[2] === "--quarantine"
      ? "Deploy-role quarantine"
      : "Workload permissions-boundary";
  process.stderr.write(`${label} policy read-back mismatch.\n`);
  process.exitCode = 1;
}
