/**
 * `alb` stack — internal Application Load Balancer fronting mnemo-server (§6a).
 *
 * The AgentCore Gateway reaches mnemo-server privately over managed VPC Lattice,
 * which requires the target to present a publicly trusted TLS cert (a private CA
 * won't do). So this internal ALB terminates TLS with the public ACM cert
 * (infra/certs.ts) and forwards to mnemo-server over plain HTTP :8080 inside the
 * private subnets. The ALB is `internal` — the public cert is ONLY for Lattice's
 * TLS trust, not for public reachability.
 *
 * Path: Lattice → ALB HTTPS :443 (public cert) → [host-header rule] → target group
 * (mnemo-server :8080, registered in infra/ecs.ts). The Gateway target's
 * `routingDomain` = this ALB's internal DNS name (set in infra/gateway.ts), while
 * the SNI/cert domain (mem9.aws.kane.mx) is decoupled — the documented flow.
 *
 * Consumes ecsOut.targetGroupArn (the TG is created with the Service so the
 * service→TG registration lives there and there's no ordering cycle), dbOut for
 * the task SG (to open :8080 from the ALB SG), and certOut for the listener cert.
 */

import { resolveVpc } from "./vpc";
import type { DbOutputs } from "./db";
import type { EcsOutputs } from "./ecs";
import type { CertOutputs } from "./certs";

// @ts-ignore - `aws` injected globally by SST; lb/ec2 types declared loosely.
const awsAny = aws as unknown as Record<string, any>;

const ALB_HTTPS_PORT = 443;
const MNEMO_PORT = 8080;

export interface AlbOutputs {
  ssmPrefix: string;
  albDnsName: Output<string>;
  albSecurityGroupId: Output<string>;
}

export function alb(ecsOut: EcsOutputs, dbOut: DbOutputs, certOut: CertOutputs): AlbOutputs {
  const prefix = `/mem9-on-aws/${$app.stage}`;
  const { vpcId, privateSubnetIds } = resolveVpc();
  const tags = { Project: "mem9-on-aws", Stage: $app.stage, ManagedBy: "sst" };

  // The VPC CIDR — the ALB is internal, so ingress is scoped to intra-VPC (the
  // managed-Lattice endpoint lands in our private subnets; it reaches the ALB
  // from within the VPC). No public ingress.
  const vpcCidr = awsAny.ec2.getVpcOutput({ id: vpcId }).cidrBlock;

  // ALB security group: 443 from the VPC CIDR only (internal), egress open (to
  // reach the task on 8080).
  const albSg = new awsAny.ec2.SecurityGroup("Mem9AlbSg", {
    vpcId,
    description: "mem9 internal ALB SG; 443 from the VPC only (Lattice to ALB)",
    ingress: [
      {
        protocol: "tcp",
        fromPort: ALB_HTTPS_PORT,
        toPort: ALB_HTTPS_PORT,
        cidrBlocks: [vpcCidr],
        description: "HTTPS from within the VPC (managed VPC Lattice endpoint)",
      },
    ],
    egress: [{ protocol: "-1", fromPort: 0, toPort: 0, cidrBlocks: ["0.0.0.0/0"] }],
    tags: { ...tags, Name: `mem9-on-aws-${$app.stage}-alb` },
  });

  // Open mnemo-server's :8080 to the ALB SG. Added as a STANDALONE rule on the
  // EXISTING task SG (dbOut.taskSecurityGroupId, from infra/db.ts) — mutating
  // db.ts's inline SG would churn it; a separate rule is owned by this stack.
  new awsAny.ec2.SecurityGroupRule("Mem9TaskFromAlb", {
    type: "ingress",
    securityGroupId: dbOut.taskSecurityGroupId,
    sourceSecurityGroupId: albSg.id,
    protocol: "tcp",
    fromPort: MNEMO_PORT,
    toPort: MNEMO_PORT,
    description: "mnemo-server HTTP from the internal ALB",
  });

  // Internal ALB in the NAT-routed private subnets.
  const loadBalancer = new awsAny.lb.LoadBalancer("Mem9Alb", {
    name: `mem9-${$app.stage}`.slice(0, 32), // ELB name cap 32 chars
    internal: true,
    loadBalancerType: "application",
    securityGroups: [albSg.id],
    subnets: privateSubnetIds,
    tags: { ...tags, Name: `mem9-on-aws-${$app.stage}-alb` },
  });

  // HTTPS listener with the public ACM cert. Default action = deny (403) so only
  // the host-header rule below forwards traffic; anything else is rejected.
  const listener = new awsAny.lb.Listener("Mem9AlbHttps", {
    loadBalancerArn: loadBalancer.arn,
    port: ALB_HTTPS_PORT,
    protocol: "HTTPS",
    sslPolicy: "ELBSecurityPolicy-TLS13-1-2-2021-06",
    certificateArn: certOut.certificateArn,
    defaultActions: [
      {
        type: "fixed-response",
        fixedResponse: {
          contentType: "text/plain",
          messageBody: "forbidden",
          statusCode: "403",
        },
      },
    ],
    tags,
  });

  // Host-header rule: requests for the cert/SNI domain forward to mnemo-server's
  // target group (the documented Lattice host-header → target transform).
  new awsAny.lb.ListenerRule("Mem9AlbHostRule", {
    listenerArn: listener.arn,
    priority: 1,
    conditions: [{ hostHeader: { values: [certOut.domainName] } }],
    actions: [{ type: "forward", targetGroupArn: ecsOut.targetGroupArn }],
    tags,
  });

  // Private DNS record: the AgentCore Gateway (via managed VPC Lattice) resolves
  // the OpenAPI servers URL host (mem9.aws.kane.mx) to connect to the ALB. The
  // domain is name-only (cert subject + TLS SNI) and has NO public A record → the
  // Gateway's error "Error executing HTTP request for unknown: mem9.aws.kane.mx"
  // results from DNS-lookup failure. Fix: a PRIVATE R53 hosted zone (VPC-associated)
  // + an A-alias record pointing the domain at the ALB, so the Gateway's Lattice
  // endpoint resolves it to the ALB within the VPC. Cost: $0.50/mo (one private zone).
  const privateZone = new awsAny.route53.Zone("Mem9McpPrivateZone", {
    name: certOut.domainName, // mem9.aws.kane.mx (the cert/SNI domain)
    vpcs: [{ vpcId }], // associate with the default VPC so Lattice resolves it
    forceDestroy: true,
    tags: { ...tags, Name: `mem9-on-aws-${$app.stage}-mcp-private` },
  });
  new awsAny.route53.Record("Mem9McpAlbAlias", {
    zoneId: privateZone.zoneId,
    name: certOut.domainName,
    type: "A",
    aliases: [{
      name: loadBalancer.dnsName,
      zoneId: loadBalancer.zoneId,
      evaluateTargetHealth: true,
    }],
  });

  new awsAny.ssm.Parameter("SsmAlbDnsName", {
    name: `${prefix}/alb/dns-name`,
    type: "String",
    value: loadBalancer.dnsName,
    tags,
  });
  new awsAny.ssm.Parameter("SsmAlbArn", {
    name: `${prefix}/alb/arn`,
    type: "String",
    value: loadBalancer.arn,
    tags,
  });

  return {
    ssmPrefix: prefix,
    albDnsName: loadBalancer.dnsName,
    albSecurityGroupId: albSg.id,
  };
}
