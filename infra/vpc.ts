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
 * The account default VPC in ap-northeast-1 (Tokyo) was verified (2026-07-12) to be
 * a customized default with `private-1a/1c/1d` subnets across 3 AZs (172.31.96/
 * 112/128.0/20), each routing 0.0.0.0/0 through a NAT gateway, PLUS three
 * `secondary-private-subnet-*` subnets (172.32.x) that are ALSO
 * `map-public-ip-on-launch=false` but have NO NAT egress (route to nowhere). So a
 * generic public-ip filter would wrongly include the no-NAT secondaries and land
 * ECS/Aurora in subnets with no internet (can't pull ECR / reach Bedrock). We
 * therefore select the three NAT-routed private subnets by the `private-1*` Name
 * tag, which the secondary subnets don't carry. See docs/mem9-facts.md.
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

  // NAT-routed private subnets. The `private-1*` Name filter selects the three
  // primary-CIDR (172.31.x) private subnets that route 0.0.0.0/0 through a NAT
  // gateway, and EXCLUDES the `secondary-private-subnet-*` (172.32.x) subnets
  // which are also private but have no NAT egress. A generic
  // `map-public-ip-on-launch=false` filter would wrongly pull those in.
  const privateSubnets = aws.ec2.getSubnetsOutput({
    filters: [
      { name: "vpc-id", values: [vpc.id] },
      { name: "tag:Name", values: ["private-1*"] },
    ],
  });

  return { vpcId: vpc.id, privateSubnetIds: privateSubnets.ids };
}
