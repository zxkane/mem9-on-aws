/**
 * `gateway` stack — AgentCore Gateway MCP surface (§6/§6a), Lambda-proxy path.
 *
 * The globally-reachable, Cognito-authed MCP endpoint. Inbound = CUSTOM_JWT
 * (Cognito M2M). The target is a **Lambda-proxy GatewayTarget**: AgentCore invokes
 * a VPC-attached proxy Lambda (docker-less zip, nodejs24.x) that reaches
 * mnemo-server PRIVATELY over Cloud Map DNS (`mnemo.mem9-<stage>.local:8080`),
 * injecting the X-API-Key (= tenant id). No ALB, no ACM cert, no VPC Lattice, no
 * private R53 zone.
 *
 * WHY A LAMBDA TARGET (not ALB + self-managed-Lattice privateEndpoint): that path
 * FAILED to stabilize 100% of the time in the full CI deploy — an AgentCore
 * control-plane internal error on the self-managed-Lattice privateEndpoint target
 * in ap-northeast-1 (verified: the identical config reached READY in isolation but
 * never in a full-stack deploy). A Lambda target is AgentCore's out-of-the-box
 * private path — "the gateway can immediately invoke Lambda functions configured
 * with VPC access" — so it sidesteps Lattice entirely.
 *
 * The target is provisioned via a `command.local.Command` driving the direct
 * bedrock-agentcore-control `CreateGatewayTarget` API (infra/gateway/
 * provision-target.mjs) with `targetConfiguration.mcp.lambda`. The Command wrapper
 * gives a create→poll-READY→delete lifecycle + a dependsOn edge on the Lambda.
 * v1 has NO interceptor Lambda (single-operator, single-tenant → per-tool scoping
 * deferred).
 */

import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { resolveVpc } from "./vpc";
import type { CognitoOutputs } from "./cognito";
import type { EcsOutputs } from "./ecs";
import type { BootstrapOutputs } from "./bootstrap";

// @ts-ignore - `aws` injected globally by SST; bedrock/iam/ssm types loose.
const awsAny = aws as unknown as Record<string, any>;

const gatewayFilename = fileURLToPath(import.meta.url);
const gatewayDirname = path.dirname(gatewayFilename);

const MNEMO_PORT = 8080;

// The two MCP tools the proxy Lambda exposes. Names are bare (`add_memory` /
// `search_memories`) — AgentCore prefixes them as `${targetName}___${tool}`, which
// the Lambda strips and the E2E's endsWith matcher tolerates. inputSchema mirrors
// the mem9 REST contract (infra/gateway/proxy-handler.mjs maps these to the calls).
//
// SHAPE: this schema is passed to the DIRECT bedrock-agentcore-control
// `CreateGatewayTarget` API (via provision-target.mjs), so it uses the SDK's
// `SchemaDefinition` shape — `properties` is a MAP keyed by property name and
// `required` is an ARRAY of names (standard JSON-schema), NOT the pulumi typed-
// resource's list-of-{name,required:boolean}. (Getting this wrong => the API
// rejects with "Unexpected field type".)
const TOOL_SCHEMA = [
  {
    name: "add_memory",
    description:
      "Add a memory (raw content) for later recall. Writes are async; returns {status:'accepted'}.",
    inputSchema: {
      type: "object",
      properties: {
        content: { type: "string", description: "Raw content to store as a memory." },
        agent_id: {
          type: "string",
          description: "Optional agent id to attribute the write to (per-agent scoping).",
        },
      },
      required: ["content"],
    },
  },
  {
    name: "search_memories",
    description: "Search stored memories by semantic query; returns the most relevant memories.",
    inputSchema: {
      type: "object",
      properties: {
        q: { type: "string", description: "The natural-language search query." },
        limit: { type: "integer", description: "Max results to return (default 20)." },
        agent_id: {
          type: "string",
          description: "Optional: restrict results to memories written by this agent.",
        },
      },
      required: ["q"],
    },
  },
  {
    // Transcript ingest. Hits the SAME mnemo-server endpoint as add_memory
    // (POST /v1alpha2/mem9s/memories); mnemo-server branches on the presence of
    // `messages` — a messages[] body triggers smart-ingest (LLM extraction +
    // reconciliation) instead of storing one raw string. Used by the Claude Code
    // ingest hooks (Stop/PreCompact/SessionEnd) to upload a bounded conversation
    // window. See infra/gateway/proxy-handler.mjs `ingestMessages`.
    name: "ingest_messages",
    description:
      "Ingest a conversation window (messages[]) for smart extraction into memories. Writes are async; returns {status:'accepted'}.",
    inputSchema: {
      type: "object",
      properties: {
        messages: {
          type: "array",
          description: "Ordered conversation turns to extract memories from.",
          items: {
            type: "object",
            properties: {
              role: { type: "string", description: "'user' or 'assistant'." },
              content: { type: "string", description: "The message text." },
            },
            required: ["role", "content"],
          },
        },
        session_id: {
          type: "string",
          description: "Optional session id to group the ingested turns.",
        },
        agent_id: {
          type: "string",
          description: "Optional agent id to attribute the write to (per-agent scoping).",
        },
        mode: {
          type: "string",
          description: "Ingest mode: 'smart' (LLM extraction, default) or 'raw'.",
        },
      },
      required: ["messages"],
    },
  },
];

export interface GatewayOutputs {
  ssmPrefix: string;
  gatewayId: Output<string>;
  gatewayUrl: Output<string>;
}

export function gateway(
  cognitoOut: CognitoOutputs,
  ecsOut: EcsOutputs,
  bootstrapOut: BootstrapOutputs,
  readerClientId: Output<string>,
): GatewayOutputs {
  const prefix = `/mem9-on-aws/${$app.stage}`;
  const stage = $app.stage;
  const tags = { Project: "mem9-on-aws", Stage: stage, ManagedBy: "sst" };
  const { privateSubnetIds } = resolveVpc();
  // The GatewayTarget provision script (below) needs the region for its SDK client.
  const region = awsAny.getRegionOutput().name;

  // Resolve the `infra/gateway/` directory that holds the target-provision
  // script. SST's esbuild bundle relocates the config, so `gatewayDirname`
  // (from import.meta.url) may not point at the source tree — fall back to the
  // workspace-root `infra/gateway`. The `node <script>` invocation below needs a
  // correct path (the proxy Lambda's handler uses an app-root-relative string).
  const moduleGatewayDir = path.resolve(gatewayDirname, "gateway");
  const gatewayAssetDir = fs.existsSync(path.join(moduleGatewayDir, "proxy-handler.mjs"))
    ? moduleGatewayDir
    : path.resolve(process.cwd(), "infra", "gateway");

  // --- Proxy Lambda (VPC-attached, nodejs24.x) ---
  // An `sst.aws.Function` (not a raw aws.lambda.Function): SST zips the handler,
  // creates the exec role with the VPC-ENI + logs perms, and forces nodejs24.x via
  // the sst.config $transform. Attaches to the task SG (shares it with mnemo-server)
  // so the self-ingress :8080 rule in ecs.ts lets it reach the server. Env carries
  // the Cloud Map URL + the X-API-Key (tenant id). The handler path is app-root-
  // relative (SST resolves handlers from the sst.config.ts dir, not the esbuild
  // bundle location — so no gatewayDirname/cwd dance needed here, unlike the
  // provision-target.mjs `node` invocation below).
  const proxyFn = new sst.aws.Function("Mem9ProxyFn", {
    handler: "infra/gateway/proxy-handler.handler",
    runtime: "nodejs24.x",
    timeout: "30 seconds",
    vpc: {
      privateSubnets: privateSubnetIds,
      securityGroups: [ecsOut.taskSecurityGroupId],
    },
    environment: {
      MEM9_SERVER_BASE_URL: $interpolate`http://${ecsOut.serviceDnsName}:${MNEMO_PORT}`,
      MEM9_API_KEY: bootstrapOut.tenantId,
    },
  });

  // --- Gateway service role (assumed by AgentCore to invoke the proxy Lambda) ---
  // Name it explicitly so the CI role's mem9-on-aws-* iam grants can PutRolePolicy.
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
  // Least privilege: the gateway invokes the proxy Lambda AS THIS ROLE, so it needs
  // only lambda:InvokeFunction on that one function. (No workload-identity / secret
  // / ENI grants — those were for the removed API-key credential provider + the
  // managed-Lattice ENI path.)
  new awsAny.iam.RolePolicy("Mem9GatewayInvokeLambda", {
    role: gatewayServiceRole.name,
    policy: proxyFn.arn.apply((arn: string) =>
      JSON.stringify({
        Version: "2012-10-17",
        Statement: [{ Effect: "Allow", Action: "lambda:InvokeFunction", Resource: arn }],
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
          // Trust BOTH the M2M client (CI/headless) AND the browser-login reader client.
          allowedClients: [...cognitoOut.allowedClientIds, readerClientId],
        },
      },
      protocolConfiguration: { mcp: { supportedVersions: ["2025-03-26"] } },
      tags,
    },
    { dependsOn: [gatewayServiceRole] },
  );

  // --- Gateway Target (Lambda) ---
  // Provisioned via a `command.local.Command` driving the direct
  // bedrock-agentcore-control `CreateGatewayTarget` API (infra/gateway/
  // provision-target.mjs) with `targetConfiguration.mcp.lambda`. A Lambda target
  // has no privateEndpoint, so the Lattice-target flake doesn't apply — but the
  // Command wrapper still gives a clean create→poll-READY→delete lifecycle + a
  // dependsOn edge on the proxy Lambda + gateway.
  const targetName = `${stage}-mem9-rest`;
  const provisionScript = path.join(gatewayAssetDir, "provision-target.mjs");
  const toolSchemaJson = JSON.stringify(TOOL_SCHEMA);
  // `command.local.Command`'s `environment` block applies to BOTH create and
  // delete, so MEM9_TGT_OP can't live there (it must differ per lifecycle) — set it
  // as an inline `VAR=... node …` prefix on each command line.
  new command.local.Command(
    "Mem9GatewayTarget",
    {
      create: $interpolate`MEM9_TGT_OP=create node ${provisionScript}`,
      delete: $interpolate`MEM9_TGT_OP=delete node ${provisionScript}`,
      // Re-run create (delete-then-recreate) when the gateway, the Lambda, or the
      // tool schema changes. A fire-once Command has no read/diff, so out-of-band
      // drift needs a trigger bump or `sst refresh`; a failed create always re-runs.
      triggers: [bedrockGateway.gatewayId, proxyFn.arn, toolSchemaJson],
      environment: {
        MEM9_TGT_REGION: region,
        MEM9_TGT_GATEWAY_ID: bedrockGateway.gatewayId,
        MEM9_TGT_NAME: targetName,
        MEM9_TGT_DESCRIPTION:
          "mnemo-server MCP tools (add_memory, search_memories, ingest_messages) via a proxy Lambda",
        MEM9_TGT_LAMBDA_ARN: proxyFn.arn,
        MEM9_TGT_TOOL_SCHEMA: toolSchemaJson,
      },
    },
    { dependsOn: [bedrockGateway, proxyFn] },
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
