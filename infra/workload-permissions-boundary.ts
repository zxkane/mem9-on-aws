import rolloutContract from "../scripts/workload-permissions-boundary-contract.json";
import { GATEWAY_LOGICAL_ROLES } from "../scripts/lib/gateway-workload-boundary.mjs";

export const WORKLOAD_BOUNDARY_POLICY_NAME =
  rolloutContract.identifiers.boundaryPolicyName;
export const GATEWAY_BOUNDARY_POLICY_NAME =
  rolloutContract.identifiers.gatewayBoundaryPolicyName;

// Match SST logical role names, before physical-name prefixes/truncation. The
// existing scaffold policy requires this boundary for exactly these two roles.
export function roleBoundaryPolicyName(roleName: string): string {
  return GATEWAY_LOGICAL_ROLES.includes(roleName)
    ? GATEWAY_BOUNDARY_POLICY_NAME
    : WORKLOAD_BOUNDARY_POLICY_NAME;
}

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

  $transform<Record<string, unknown>>(aws.iam.Role, (args, _opts, name) => {
    args.permissionsBoundary = $interpolate`arn:${partition}:iam::${accountId}:policy/${roleBoundaryPolicyName(name)}`;
    if (GATEWAY_LOGICAL_ROLES.includes(name)) {
      args.tags = $jsonStringify(args.tags ?? {}).apply(raw => ({
        ...JSON.parse(raw), Project: "mem9-on-aws", Stage: stage,
      }));
    }
  });
  return boundaryArn;
}
