import rolloutContract from "../scripts/workload-permissions-boundary-contract.json";

export const WORKLOAD_BOUNDARY_POLICY_NAME =
  rolloutContract.identifiers.boundaryPolicyName;

export function shouldRegisterWorkloadRoleBoundary({
  stage,
  prodEnabled,
}: {
  stage: string;
  prodEnabled?: string;
}): boolean {
  if (stage !== "prod") return true;
  if (prodEnabled === "true") return true;
  if (prodEnabled === "false") return false;
  throw new Error(
    "WORKLOAD_BOUNDARY_PROD_ENABLED must be explicitly true or false for prod",
  );
}

export function registerWorkloadRoleBoundary(): Output<string> {
  const partition = aws.getPartitionOutput().partition;
  const accountId = aws.getCallerIdentityOutput().accountId;
  const boundaryArn = $interpolate`arn:${partition}:iam::${accountId}:policy/${WORKLOAD_BOUNDARY_POLICY_NAME}`;

  $transform<Record<string, unknown>>(aws.iam.Role, (args) => {
    args.permissionsBoundary = boundaryArn;
  });
  return boundaryArn;
}
