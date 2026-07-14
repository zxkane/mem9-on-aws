/**
 * `gateway` stack — AgentCore Gateway MCP surface (§6/§6a).
 *
 * The globally-reachable, Cognito-authed MCP endpoint. Mirrors the proven
 * zxkane/podcast-curation `infra/gateway.ts`, adapted for OUR two differences:
 *   1. Outbound auth = **API key** (X-API-Key = tenant id), not OAuth — mnemo-server
 *      authenticates with X-API-Key, and SigV4/OAuth-to-a-3P don't apply.
 *   2. The target is **private** (mnemo-server has no public URL): the OpenAPI
 *      target carries `privateEndpoint.managedVpcResource` (managed VPC Lattice) with
 *      `routingDomain` = the internal ALB's DNS name. podcast-curation targets a
 *      public API URL, so it has no privateEndpoint.
 * v1 has NO interceptor Lambda (single-operator, single-tenant → per-tool scoping
 * deferred). The OpenAPI schema is inlined (static server URL; no per-stage
 * substitution needed, unlike podcast-curation).
 *
 * Provisioned via typed Pulumi `aws.bedrock.Agentcore*` resources (proven in
 * podcast-curation prod). Kept operational IAM that was hard-won there: the
 * `bedrock-agentcore.amazonaws.com`-trust service role + GetWorkloadAccessToken /
 * GetResourceApiKey grants + the `bedrock-agentcore-identity!*` secret read.
 */

import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import type { CognitoOutputs } from "./cognito";
import type { AlbOutputs } from "./alb";
import type { BootstrapOutputs } from "./bootstrap";

// @ts-ignore - `aws` injected globally by SST; bedrock/iam/lambda types loose.
const awsAny = aws as unknown as Record<string, any>;

const gatewayFilename = fileURLToPath(import.meta.url);
const gatewayDirname = path.dirname(gatewayFilename);

export interface GatewayOutputs {
  ssmPrefix: string;
  gatewayId: Output<string>;
  gatewayUrl: Output<string>;
}

export function gateway(
  cognitoOut: CognitoOutputs,
  albOut: AlbOutputs,
  bootstrapOut: BootstrapOutputs,
): GatewayOutputs {
  const prefix = `/mem9-on-aws/${$app.stage}`;
  const stage = $app.stage;
  const tags = { Project: "mem9-on-aws", Stage: stage, ManagedBy: "sst" };
  // The GatewayTarget provision script (below) needs the region for its SDK client.
  const region = awsAny.getRegionOutput().name;

  // Resolve the `infra/gateway/` directory that holds both openapi.yaml and the
  // target-provision script. SST's esbuild bundle relocates the config, so
  // `gatewayDirname` (from import.meta.url) may not point at the source tree —
  // fall back to the workspace-root `infra/gateway`. We MUST resolve this dir
  // (not just the schema) because provisionScript below is passed to `node` on
  // the deploy host: a wrong path → "Cannot find module" at target-create time.
  const moduleGatewayDir = path.resolve(gatewayDirname, "gateway");
  const gatewayAssetDir = fs.existsSync(path.join(moduleGatewayDir, "openapi.yaml"))
    ? moduleGatewayDir
    : path.resolve(process.cwd(), "infra", "gateway");

  // Load the OpenAPI schema (inline payload; static server URL, no substitution).
  const openApiSchema = fs.readFileSync(path.join(gatewayAssetDir, "openapi.yaml"), "utf-8");

  // (The OpenAPI schema is passed inline to the target's CreateGatewayTarget call
  // below — no S3 bucket/object. Inline matches the proven-READY direct API call.)

  // --- Gateway service role (assumed by AgentCore) ---
  // Name it explicitly so the CI role's mem9-on-aws-* iam grants (ComputePolicy)
  // can PutRolePolicy on it (an auto-hashed name wouldn't match the prefix).
  const gatewayServiceRole = new awsAny.iam.Role("Mem9GatewayServiceRole", {
    name: `mem9-on-aws-${stage}-gateway-service-role`,
    assumeRolePolicy: JSON.stringify({
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Action: "sts:AssumeRole",
          Principal: { Service: "bedrock-agentcore.amazonaws.com" },
        },
      ],
    }),
    tags,
  });

  // Workload-identity + outbound-credential access. AgentCore's outbound flow
  // assumes this role and calls GetWorkloadAccessToken → then reads the API key
  // from its service-managed secret (bedrock-agentcore-identity!*). Without these
  // every tool call fails with "Failed to get workload identity token" / a
  // secretsmanager AccessDenied (both hard-won in podcast-curation prod).
  new awsAny.iam.RolePolicy("Mem9GatewayWorkloadIdentityAccess", {
    role: gatewayServiceRole.name,
    policy: JSON.stringify({
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Action: [
            "bedrock-agentcore:GetWorkloadAccessToken",
            "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
            "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
            "bedrock-agentcore:GetResourceApiKey",
          ],
          Resource: "*",
        },
        {
          Effect: "Allow",
          Action: ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
          Resource: "arn:aws:secretsmanager:*:*:secret:bedrock-agentcore-identity!*",
        },
        {
          // The managed VPC Lattice resource gateway (created when the target's
          // privateEndpoint.managedVpcResource is provisioned) places ENIs in our
          // private subnets. AgentCore assumes THIS role to do it, so it needs the
          // ENI lifecycle + VPC read. Without ec2:CreateNetworkInterface the target
          // create FAILS with "caller does not have ec2:CreateNetworkInterface".
          Effect: "Allow",
          Action: [
            "ec2:CreateNetworkInterface",
            "ec2:DeleteNetworkInterface",
            "ec2:DescribeNetworkInterfaces",
            "ec2:CreateNetworkInterfacePermission",
            "ec2:DescribeSubnets",
            "ec2:DescribeVpcs",
            "ec2:DescribeSecurityGroups",
          ],
          Resource: "*",
        },
      ],
    }),
  });

  // (No S3 schema-read policy needed — the OpenAPI schema is inlined into the
  // target, not fetched from S3.)

  // --- AgentCore Gateway (typed aws.bedrock.AgentcoreGateway) ---
  // CUSTOM_JWT authorizer matching on allowedClients (Cognito client_credentials
  // tokens carry client_id, not aud). Only name+authorizerType are RequiresReplace
  // → adding a client later does NOT rotate the URL.
  const gatewayName = `${stage}-mem9-mcp`;
  const bedrockGateway = new awsAny.bedrock.AgentcoreGateway(
    "Mem9Gateway",
    {
      name: gatewayName,
      description: `AgentCore Gateway for mem9 MCP in stage ${stage}`,
      protocolType: "MCP",
      authorizerType: "CUSTOM_JWT",
      roleArn: gatewayServiceRole.arn,
      authorizerConfiguration: {
        customJwtAuthorizer: {
          discoveryUrl: $interpolate`${cognitoOut.issuer}/.well-known/openid-configuration`,
          allowedClients: cognitoOut.allowedClientIds,
        },
      },
      protocolConfiguration: { mcp: { supportedVersions: ["2025-03-26"] } },
      tags,
    },
    { dependsOn: [gatewayServiceRole] },
  );

  // --- API-key credential provider (outbound auth to mnemo-server) ---
  // Holds the X-API-Key = tenant id (from bootstrap()). AgentCore stores it in its
  // service-managed secret (bedrock-agentcore-identity!*, read via the role above).
  const apiKeyProvider = new awsAny.bedrock.AgentcoreApiKeyCredentialProvider(
    "Mem9ApiKeyProvider",
    {
      name: `${stage}-mem9-mcp-apikey`,
      apiKey: bootstrapOut.tenantId,
    },
    { dependsOn: [bedrockGateway] },
  );

  // --- Gateway Target (OpenAPI, private via self-managed VPC Lattice → internal ALB) ---
  //
  // Provisioned via a `command.local.Command` that drives the DIRECT
  // bedrock-agentcore-control `CreateGatewayTarget` API (infra/gateway/
  // provision-target.mjs), NOT `aws.cloudcontrol.Resource`.
  //
  // ROOT CAUSE (proven 2026-07-14): the typed pulumi-aws 7.20.0
  // `aws.bedrock.AgentcoreGatewayTarget` has NO `privateEndpoint` field (silently
  // dropped), so we tried CloudControl. But CloudControl's
  // `AWS::BedrockAgentCore::GatewayTarget` handler FAILEDs EVERY time (~20 CI
  // iterations) with "NotStabilized: FAILED, internal error" whenever
  // PrivateEndpoint is present — while the IDENTICAL config via a direct
  // `CreateGatewayTarget` SDK call reaches READY in ~3.5 min (verified with the
  // exact resolving domain, self-managed Lattice RC, inline schema, API-key
  // provider). So CloudControl's handler is broken for the private-endpoint path
  // in ap-northeast-1; the underlying API is fine. This Command drives that
  // proven-working API directly (create → poll to READY; delete on teardown).
  //
  // SELF-MANAGED VPC Lattice (§6a): infra/alb.ts creates the Lattice
  // ResourceGateway + ResourceConfiguration ourselves (so the ENIs are created by
  // OUR deploy role, which has ec2:CreateNetworkInterface). AgentCore's MANAGED
  // path fails to create those ENIs in ap-northeast-1 despite the vpc-lattice SLR
  // having the perm — a service-side gap. We reference our ResourceConfiguration
  // by ARN. Its dnsResource domain = mem9.aws.kane.mx (the cert/SNI), resolved to
  // the ALB by the private R53 zone; Lattice sends that as the TLS SNI.
  const targetName = `${stage}-mem9-rest`;
  const provisionScript = path.join(gatewayAssetDir, "provision-target.mjs");
  // `command.local.Command`'s `environment` block applies to BOTH create and
  // delete, so MEM9_TGT_OP can't live there (it must differ per lifecycle).
  // Instead set it as an inline `VAR=... node …` prefix on each command line —
  // `create` runs with op=create (build + poll to READY), `delete` with op=delete
  // (best-effort teardown by name). All other inputs (Outputs) go in `environment`.
  new command.local.Command(
    "Mem9GatewayTarget",
    {
      create: $interpolate`MEM9_TGT_OP=create node ${provisionScript}`,
      delete: $interpolate`MEM9_TGT_OP=delete node ${provisionScript}`,
      // Re-run `create` (delete-then-recreate) when any of these change. The set
      // covers every field of the target's config that actually varies here
      // (gateway id, credential-provider ARN, Lattice RC ARN, and the schema).
      // The API-key HEADER and description are constants, so they're deliberately
      // omitted. CAVEAT: because a fire-once Command has no read/diff, if the
      // target drifts out-of-band (manual edit/delete) with NO input change, a
      // plain redeploy won't reconcile it — bump a trigger or `sst refresh` then
      // redeploy. (A failed create always re-runs, so FAILED targets self-heal.)
      triggers: [
        bedrockGateway.gatewayId,
        apiKeyProvider.credentialProviderArn,
        albOut.latticeResourceConfigArn,
        openApiSchema,
      ],
      environment: {
        MEM9_TGT_REGION: region,
        MEM9_TGT_GATEWAY_ID: bedrockGateway.gatewayId,
        MEM9_TGT_NAME: targetName,
        MEM9_TGT_DESCRIPTION:
          "mnemo-server REST tools (add_memory, search_memories) via internal ALB",
        MEM9_TGT_SCHEMA: openApiSchema,
        MEM9_TGT_APIKEY_PROVIDER_ARN: apiKeyProvider.credentialProviderArn,
        MEM9_TGT_APIKEY_HEADER: "X-API-Key",
        MEM9_TGT_LATTICE_RC_ARN: albOut.latticeResourceConfigArn,
      },
    },
    { dependsOn: [bedrockGateway, apiKeyProvider] },
  );

  const gatewayId = bedrockGateway.gatewayId;
  const gatewayUrl = bedrockGateway.gatewayUrl;

  new awsAny.ssm.Parameter("SsmGatewayUrl", {
    name: `${prefix}/gateway/url`,
    type: "String",
    value: gatewayUrl,
    tags,
  });
  new awsAny.ssm.Parameter("SsmGatewayId", {
    name: `${prefix}/gateway/id`,
    type: "String",
    value: gatewayId,
    tags,
  });

  return { ssmPrefix: prefix, gatewayId, gatewayUrl };
}
