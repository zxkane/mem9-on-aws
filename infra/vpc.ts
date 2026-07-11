/**
 * VPC resolver — lookup only, creates NO billable resources.
 *
 * Resolves the VPC + its NAT-routed private subnets that later stacks
 * (ECS Fargate, Aurora) will live in. Two modes:
 *
 *   - `MEM9_VPC_ID` env set  → import that VPC (fails loud at deploy if the
 *     id doesn't exist in-region — no silent fallback).
 *   - unset (default)        → the account default VPC.
 *
 * The account default VPC in ap-northeast-1 was verified (2026-07-11) to be a
 * customized default with `private-1a/1c/1d` subnets across 3 AZs, each routing
 * 0.0.0.0/0 through a NAT gateway. We select those three by the `private-1*`
 * Name tag, which excludes the secondary `172.32.x` private subnets. See
 * docs/mem9-facts.md "Verified AWS facts".
 *
 * Deploy-role impact: read-only `ec2:DescribeVpcs`/`DescribeSubnets`.
 */

export interface ResolvedVpc {
  vpcId: Output<string>;
  privateSubnetIds: Output<string[]>;
}

export function resolveVpc(): ResolvedVpc {
  const explicitId = process.env.MEM9_VPC_ID?.trim();

  const vpc = explicitId
    ? aws.ec2.getVpcOutput({ id: explicitId }) // import existing
    : aws.ec2.getVpcOutput({ default: true }); // account default VPC

  // NAT-routed private subnets. The `private-1*` Name filter selects the
  // three primary-CIDR private subnets and excludes the secondary-CIDR
  // (`secondary-private-subnet-*`) ones. Refined when the ECS/Aurora stack
  // lands and needs an exact AZ set.
  const privateSubnets = aws.ec2.getSubnetsOutput({
    filters: [
      { name: "vpc-id", values: [vpc.id] },
      { name: "tag:Name", values: ["private-1*"] },
    ],
  });

  return { vpcId: vpc.id, privateSubnetIds: privateSubnets.ids };
}
