import rolloutContract from "../scripts/workload-permissions-boundary-contract.json";
import { GATEWAY_LOGICAL_ROLES } from "../scripts/lib/gateway-workload-boundary.mjs";

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
  const stage = $app.stage;
  const partition = aws.getPartitionOutput().partition;
  const accountId = aws.getCallerIdentityOutput().accountId;
  const boundaryArn = $interpolate`arn:${partition}:iam::${accountId}:policy/${WORKLOAD_BOUNDARY_POLICY_NAME}`;
  const gatewayArn = $interpolate`arn:${partition}:iam::${accountId}:policy/${rolloutContract.identifiers.gatewayBoundaryPolicyName}`;

  $transform<Record<string, unknown>>(aws.iam.Role, (args, _opts, name) => {
    const gateway = GATEWAY_LOGICAL_ROLES.includes(name);
    args.permissionsBoundary = gateway ? gatewayArn : boundaryArn;
    if (gateway) args.tags = $jsonStringify(args.tags ?? {}).apply(raw => ({
      ...JSON.parse(raw), Project: "mem9-on-aws", Stage: stage,
    }));
  });
  return boundaryArn;
}
