/**
 * Shared helper for composing OUT-OF-BAND ECR image URIs.
 *
 * All mem9-on-aws container images live in ECR repos owned out-of-band by
 * infra/cloudformation/ecr-repositories.yaml (DeletionPolicy: Retain), NOT by
 * SST — so `sst remove` can never wipe image history. SST stacks only REFERENCE
 * the images by URI. Every reference is
 * `<account>.dkr.ecr.<region>.amazonaws.com/<namespace>:<tag>` where the account
 * comes from the caller identity (never hardcoded) and region = the app region.
 *
 * Centralized here so ecs.ts (mnemo-server, qwen3-embed, and llm-proxy) and
 * bootstrap.ts share one composition and the active provider region.
 */

let regionOut: Output<string> | undefined;
export function applicationRegion(): Output<string> {
  if (!regionOut) {
    regionOut = aws.getRegionOutput().name;
  }
  return regionOut;
}

// Cache the caller-identity Output so repeated ecrImage()/accountId() calls don't
// each create a new getCallerIdentityOutput invoke. Exported so ecs.ts can build
// the Bedrock Mantle project ARN with the same deploy-time-resolved account id.
let accountIdOut: Output<string> | undefined;
export function accountId(): Output<string> {
  if (!accountIdOut) accountIdOut = aws.getCallerIdentityOutput().accountId;
  return accountIdOut;
}

/**
 * Compose an ECR image URI for `<namespace>:<tag>` in the app account+region.
 * @param namespace e.g. "mem9-on-aws/mnemo-server" (the ECR RepositoryName)
 * @param tag e.g. "mem9-abc1234" or "latest"
 */
export function ecrImage(namespace: string, tag: string): Output<string> {
  return $interpolate`${accountId()}.dkr.ecr.${applicationRegion()}.amazonaws.com/${namespace}:${tag}`;
}
