export const DECISION_ARTIFACT_BUCKET_ENV =
  "MEM9_DECISION_ARTIFACT_BUCKET";
export const DECISION_ARTIFACT_BUCKET_OWNER_ENV =
  "MEM9_DECISION_ARTIFACT_BUCKET_OWNER";
// Keep decision artifacts aligned with the 72-hour Slack approval lifetime.
export const DECISION_ARTIFACT_TTL_DAYS = 3;

/**
 * Resolve the exact account-scoped bucket name shared by all stages. The
 * workload boundary pins this name without a wildcard because S3 bucket names
 * are global and a wildcard could admit an attacker-owned bucket.
 */
export function decisionArtifactBucketName(
  account: Output<string> | string,
): Output<string> | string {
  const configured = process.env[DECISION_ARTIFACT_BUCKET_ENV];
  if (configured) {
    if (
      !/^[a-z0-9][a-z0-9-]{1,31}[a-z0-9]$/u.test(configured) ||
      /^(?:xn--|sthree-|amzn-s3-demo-)/u.test(configured) ||
      /(?:-s3alias|--ol-s3|--x-s3|--table-s3|-an)$/u.test(configured)
    ) {
      throw new Error(
        `${DECISION_ARTIFACT_BUCKET_ENV} is an invalid decision-artifact bucket name`,
      );
    }
    return configured;
  }
  return $interpolate`mem9-audit-${account}`;
}

// The trailing slash is required for stage isolation in object-scoped IAM.
export function decisionArtifactKeyPrefix(stage: string): string {
  return `decisions/${stage}/`;
}

// Keep this transformation aligned with scripts/memory-cleanup.mjs.
export function decisionArtifactKey(stage: string, hash: string): string {
  return `${decisionArtifactKeyPrefix(stage)}${hash.replace(/:/gu, "-")}.json`;
}

export function consolidationDigestKey(stage: string): string {
  return `consolidation-digests/${stage}/current-v1.json`;
}
