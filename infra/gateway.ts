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

  // Load the OpenAPI schema (inline payload; static server URL, no substitution).
  // Resolve module-relative first, then workspace-root (SST build changes __dirname).
  let openApiSchema: string;
  const moduleRelative = path.resolve(gatewayDirname, "gateway", "openapi.yaml");
  try {
    openApiSchema = fs.readFileSync(moduleRelative, "utf-8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    openApiSchema = fs.readFileSync(path.resolve(process.cwd(), "infra", "gateway", "openapi.yaml"), "utf-8");
  }

  // (The OpenAPI schema is inlined into the target's desiredState below — no S3
  // bucket/object. The S3-schema variant caused the target to FAIL to stabilize;
  // inline is proven to reach READY.)

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

  // --- Gateway Target (OpenAPI, private via managed VPC Lattice → internal ALB) ---
  //
  // Provisioned via aws.cloudcontrol.Resource, NOT the typed
  // aws.bedrock.AgentcoreGatewayTarget (pulumi-aws 7.20.0's typed resource has NO
  // privateEndpoint field — it silently dropped it). CloudControl provisions the
  // full CFN AWS::BedrockAgentCore::GatewayTarget incl. PrivateEndpoint.
  //
  // SELF-MANAGED VPC Lattice (§6a): infra/alb.ts creates the Lattice
  // ResourceGateway + ResourceConfiguration ourselves (so the ENIs are created by
  // OUR deploy role, which has ec2:CreateNetworkInterface). AgentCore's MANAGED
  // path fails to create those ENIs in ap-northeast-1 ("caller does not have
  // ec2:CreateNetworkInterface") despite the vpc-lattice SLR having the perm — a
  // service-side gap. We reference our ResourceConfiguration by ARN instead.
  // The resource config's dnsResource domain = mem9.aws.kane.mx (the cert/SNI),
  // resolved to the ALB by the private R53 zone; Lattice sends that as the TLS SNI.
  const targetDesiredState = $jsonStringify({
    GatewayIdentifier: bedrockGateway.gatewayId,
    Name: `${stage}-mem9-rest`,
    Description: "mnemo-server REST tools (add_memory, search_memories) via internal ALB",
    TargetConfiguration: {
      Mcp: {
        // INLINE the OpenAPI schema (not S3). Verified via a direct API test: an
        // inline-payload self-managed-Lattice target stabilizes CREATING→READY in
        // ~3.5 min, whereas the S3-schema variant FAILEDs to stabilize (the async
        // S3 fetch during stabilization is the failing factor). CloudControl takes
        // inlinePayload as a plain string (unlike the typed pulumi-aws resource,
        // which rejected it — that's why we're on CloudControl). Schema is ~4KB,
        // well under the inline limit.
        OpenApiSchema: { InlinePayload: openApiSchema },
      },
    },
    CredentialProviderConfigurations: [
      {
        CredentialProviderType: "API_KEY",
        CredentialProvider: {
          ApiKeyCredentialProvider: {
            ProviderArn: apiKeyProvider.credentialProviderArn,
            CredentialLocation: "HEADER",
            CredentialParameterName: "X-API-Key",
          },
        },
      },
    ],
    PrivateEndpoint: {
      SelfManagedLatticeResource: {
        ResourceConfigurationIdentifier: albOut.latticeResourceConfigArn,
      },
    },
  });
  new awsAny.cloudcontrol.Resource(
    "Mem9GatewayTarget",
    {
      typeName: "AWS::BedrockAgentCore::GatewayTarget",
      desiredState: targetDesiredState,
    },
    {
      dependsOn: [bedrockGateway, apiKeyProvider],
      // The target with a self-managed-Lattice privateEndpoint takes ~3-4 min to
      // stabilize (verified via a direct API test: CREATING → READY at ~3.5 min).
      // CloudControl's default create wait is too short → it reported the target
      // as "NotStabilized / FAILED" mid-CREATING. A generous create timeout lets
      // Pulumi poll through to READY.
      customTimeouts: { create: "20m", update: "20m", delete: "20m" },
    },
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
