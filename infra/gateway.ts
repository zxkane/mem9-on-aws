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
import { resolveVpc } from "./vpc";

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
  const { vpcId, privateSubnetIds } = resolveVpc();

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

  // The AgentcoreGatewayTarget's openApiSchema takes the schema from S3 (the
  // proven podcast-curation path — the `inlinePayload` variant the Pulumi
  // provider rejects a plain string for). Upload the schema to a private bucket
  // and reference it by URI; the gateway service role reads it (policy below).
  const schemasBucket = new awsAny.s3.Bucket("Mem9McpSchemas", {
    forceDestroy: true,
    tags,
  });
  const schemaKey = "mcp-schema.yaml";
  const schemaObject = new awsAny.s3.BucketObject("Mem9OpenApiSchema", {
    bucket: schemasBucket.id,
    key: schemaKey,
    content: openApiSchema,
    contentType: "application/yaml",
  });

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

  // Let the gateway service role read the OpenAPI schema object from S3.
  new awsAny.iam.RolePolicy("Mem9GatewayS3SchemaAccess", {
    role: gatewayServiceRole.name,
    policy: schemasBucket.arn.apply((bucketArn: string) =>
      JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          { Effect: "Allow", Action: "s3:GetObject", Resource: `${bucketArn}/${schemaKey}` },
        ],
      }),
    ),
  });

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
  // aws.bedrock.AgentcoreGatewayTarget: the typed resource in pulumi-aws 7.20.0
  // (the version SST bundles) has NO `privateEndpoint` field at all, so it
  // SILENTLY DROPPED our privateEndpoint/routingDomain — the Gateway then tried to
  // DNS-resolve the OpenAPI server URL (mem9.aws.kane.mx) directly and failed with
  // "Error executing HTTP request for unknown: mem9.aws.kane.mx". The CFN type
  // AWS::BedrockAgentCore::GatewayTarget DOES have PrivateEndpoint.ManagedVpcResource
  // .RoutingDomain (verified in the CFN ref), and CloudControl provisions it.
  //
  // desiredState is CFN PascalCase JSON. routingDomain = the ALB internal DNS (the
  // real route); the OpenAPI server URL / cert SNI (mem9.aws.kane.mx) is the SNI
  // AgentCore sends on the wire — decoupled, per the AWS "routing domain" docs.
  const targetDesiredState = $jsonStringify({
    GatewayIdentifier: bedrockGateway.gatewayId,
    Name: `${stage}-mem9-rest`,
    Description: "mnemo-server REST tools (add_memory, search_memories) via internal ALB",
    TargetConfiguration: {
      Mcp: {
        OpenApiSchema: {
          S3: { Uri: $interpolate`s3://${schemasBucket.id}/${schemaKey}` },
        },
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
      ManagedVpcResource: {
        VpcIdentifier: vpcId,
        SubnetIds: privateSubnetIds,
        EndpointIpAddressType: "IPV4",
        SecurityGroupIds: [albOut.albSecurityGroupId],
        RoutingDomain: albOut.albDnsName,
      },
    },
  });
  new awsAny.cloudcontrol.Resource(
    "Mem9GatewayTarget",
    {
      typeName: "AWS::BedrockAgentCore::GatewayTarget",
      desiredState: targetDesiredState,
    },
    { dependsOn: [bedrockGateway, apiKeyProvider, schemaObject] },
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
