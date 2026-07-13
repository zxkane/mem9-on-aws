/**
 * `certs` stack — public ACM certificate for the MCP internal ALB (§6a).
 *
 * The AgentCore Gateway reaches mnemo-server privately over managed VPC Lattice,
 * which requires the target endpoint (our internal ALB) to present a **publicly
 * trusted** TLS certificate — Lattice's TLS handshake won't trust a private CA.
 * So this stack requests a PUBLIC ACM cert and the ALB terminates TLS with it.
 *
 * The domain is **name-only**: it is the cert subject + the Lattice TLS SNI. It
 * does NOT need to publicly resolve to the ALB — actual routing uses the target's
 * `routingDomain` = the ALB's internal AWS DNS name (set in infra/gateway.ts).
 * SNI (this domain) and routing (ALB AWS DNS) are decoupled — the documented flow.
 *
 * Domain: `mem9.aws.kane.mx` — a subdomain of the EXISTING public Route53 zone
 * `aws.kane.mx` (the design's original `mem9.internal.kane.mx` was never a real
 * zone; `aws.kane.mx` is delegated + public, so ACM DNS validation is automatic).
 * Override via MEM9_MCP_DOMAIN (and MEM9_MCP_ZONE for the parent zone) if needed.
 *
 * Region: the cert is requested in-region (ap-northeast-1) — ALB-attached certs
 * are REGIONAL (unlike CloudFront, which needs us-east-1). The SST provider region
 * (sst.config.ts) is ap-northeast-1, so a plain aws.acm.Certificate is in-region.
 */

// @ts-ignore - `aws` is injected globally by SST; the loose Pulumi types for
// acm/route53 are declared minimally in sst-types.d.ts (cast where needed).
const awsAny = aws as unknown as Record<string, any>;

export interface CertOutputs {
  certificateArn: Output<string>;
  domainName: string;
}

// The MCP ALB domain (cert subject + Lattice SNI). Name-only; see header.
const MCP_DOMAIN = process.env.MEM9_MCP_DOMAIN || "mem9.aws.kane.mx";
// The parent public hosted zone that ACM DNS-validation writes the CNAME into.
const MCP_ZONE = process.env.MEM9_MCP_ZONE || "aws.kane.mx";

export function certs(): CertOutputs {
  const prefix = `/mem9-on-aws/${$app.stage}`;
  const tags = { Project: "mem9-on-aws", Stage: $app.stage, ManagedBy: "sst" };

  // The existing public hosted zone (lookup, no billable resource).
  const zone = awsAny.route53.getZoneOutput({ name: MCP_ZONE, privateZone: false });

  // Public cert, DNS-validated. One cert per stage on the same name is fine —
  // the domain is SNI-only (not per-stage-resolvable) and public certs are free.
  const cert = new awsAny.acm.Certificate("Mem9McpCert", {
    domainName: MCP_DOMAIN,
    validationMethod: "DNS",
    tags: { ...tags, Name: `mem9-on-aws-${$app.stage}-mcp` },
  });

  // Write the ACM validation CNAME into the aws.kane.mx zone. domainValidationOptions
  // is an Output<[]>; index [0] is the single-domain cert's validation record.
  const validationRecord = new awsAny.route53.Record("Mem9McpCertValidation", {
    zoneId: zone.zoneId,
    name: cert.domainValidationOptions[0].resourceRecordName,
    type: cert.domainValidationOptions[0].resourceRecordType,
    records: [cert.domainValidationOptions[0].resourceRecordValue],
    ttl: 300,
    allowOverwrite: true,
  });

  // Block until ACM sees the CNAME + issues the cert (so the ALB listener never
  // references an unissued cert). certificateArn resolves post-validation.
  const validation = new awsAny.acm.CertificateValidation("Mem9McpCertValidated", {
    certificateArn: cert.arn,
    validationRecordFqdns: [validationRecord.fqdn],
  });

  new awsAny.ssm.Parameter("SsmMcpCertArn", {
    name: `${prefix}/mcp/cert-arn`,
    type: "String",
    value: cert.arn,
    tags,
  });

  return {
    // Use the validation resource's certificateArn so downstream (the ALB
    // listener) depends on the cert being ISSUED, not merely requested.
    certificateArn: validation.certificateArn as Output<string>,
    domainName: MCP_DOMAIN,
  };
}
