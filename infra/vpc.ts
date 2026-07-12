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
 * The account default VPC in ap-southeast-1 (Singapore) was verified (2026-07-12)
 * to be a customized default with three `private-subnet-1a/1b/1c` subnets across
 * 3 AZs, each `map-public-ip-on-launch=false` and routing 0.0.0.0/0 through a
 * single NAT gateway. We select the private subnets by the GENERIC
 * `map-public-ip-on-launch=false` filter (NOT a region-specific Name tag), so this
 * resolver is portable across regions/accounts: it picks exactly the NAT-routed
 * private subnets and excludes the public (IGW) ones. See docs/mem9-facts.md.
 *
 * (Historical note: this project ran in ap-northeast-1 first, whose default VPC
 * used `private-1*` Name tags + had extra secondary-CIDR private subnets. Moving
 * to ap-southeast-1 — see docs/ARCHITECTURE.md — we switched to the generic
 * public-ip filter, which is cleaner and works in both.)
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

  // NAT-routed private subnets = those that do NOT auto-assign a public IP.
  // `map-public-ip-on-launch=false` is the region-agnostic signal for "private"
  // in an account default VPC (the public/IGW subnets set it true). This selects
  // exactly the three per-AZ private subnets in the Singapore default VPC.
  const privateSubnets = aws.ec2.getSubnetsOutput({
    filters: [
      { name: "vpc-id", values: [vpc.id] },
      { name: "map-public-ip-on-launch", values: ["false"] },
    ],
  });

  return { vpcId: vpc.id, privateSubnetIds: privateSubnets.ids };
}
