/**
 * `cognito` stack — Cognito M2M user pool for MCP inbound auth (§6).
 *
 * The AgentCore Gateway's inbound authorizer is a CUSTOM_JWT authorizer that
 * validates Cognito `client_credentials` (M2M) JWTs. This stack provisions the
 * pool + domain (OAuth token endpoint) + resource server (scopes) + one M2M
 * client. Additional clients would not rotate the Gateway URL because only
 * `name`/`authorizerType` are RequiresReplace on the Gateway.
 *
 * The Gateway matches on `allowedClients` (Cognito client_credentials tokens carry
 * `client_id`, not `aud`), so infra/gateway.ts lists this client id there.
 *
 * Exports the issuer + token endpoint (for clients to mint tokens) and the client
 * id + secret via SSM. The client secret is a SecureString surfaced only to the
 * operator.
 */

import { createHash } from "node:crypto";

// @ts-ignore - `aws` injected globally by SST; cognito types declared loosely.
const awsAny = aws as unknown as Record<string, any>;

export interface CognitoOutputs {
  ssmPrefix: string;
  userPoolId: Output<string>;
  issuer: Output<string>;
  tokenEndpoint: Output<string>;
  authorizeEndpoint: Output<string>;
  userInfoEndpoint: Output<string>;
  revocationEndpoint: Output<string>;
  jwksUri: Output<string>;
  resourceServerId: string;
  clientId: Output<string>;
  clientSecret: Output<string>;
  // The list of client ids the Gateway JWT authorizer trusts (allowedClients).
  allowedClientIds: Output<string>[];
}

export const MCP_RESOURCE_SERVER_ID = "mem9-mcp";
export const MCP_RESOURCE_SCOPES = [
  `${MCP_RESOURCE_SERVER_ID}/read`,
  `${MCP_RESOURCE_SERVER_ID}/write`,
] as const;
export const MCP_BROWSER_SCOPES = [
  "openid",
  "email",
  ...MCP_RESOURCE_SCOPES,
] as const;
export const MCP_TOOL_SCOPES = {
  add_memory: MCP_RESOURCE_SCOPES[1],
  search_memories: MCP_RESOURCE_SCOPES[0],
  ingest_messages: MCP_RESOURCE_SCOPES[1],
  get_ingest_job_status: MCP_RESOURCE_SCOPES[0],
} as const;
const DOMAIN_HASH_NAMESPACE = "mem9-cognito-domain-v1";
const DOMAIN_PREFIX_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const DOMAIN_RESERVED_KEYWORDS = ["aws", "amazon", "cognito"];

export interface CognitoDomainPrefixInput {
  accountId: string;
  region: string;
  stage: string;
}

export function cognitoDomainOverride(
  override = process.env.MEM9_COGNITO_DOMAIN_PREFIX,
): string | undefined {
  const configured = override?.trim();
  if (!configured) return undefined;

  const hasReservedKeyword = DOMAIN_RESERVED_KEYWORDS.some((keyword) =>
    configured.includes(keyword),
  );
  if (!DOMAIN_PREFIX_PATTERN.test(configured) || hasReservedKeyword) {
    throw new Error(
      "MEM9_COGNITO_DOMAIN_PREFIX must be 1-63 lowercase letters, digits, or hyphens, without an edge hyphen or the reserved aws, amazon, or cognito keywords.",
    );
  }
  return configured;
}

// Prefixes share a namespace across AWS accounts in each Region. Derive a stable
// default from the deployment identity without exposing the account id in the
// public hostname. The version marker makes an algorithm change an explicit
// migration. An existing stage must pin its current prefix through the override
// before adopting this default.
export function cognitoDomainPrefix({
  accountId,
  region,
  stage,
}: CognitoDomainPrefixInput): string {
  const digest = createHash("sha256")
    .update(
      JSON.stringify([DOMAIN_HASH_NAMESPACE, accountId, region, stage]),
    )
    .digest("hex")
    .slice(0, 20);
  return `mem9-${digest}`;
}

export function cognito(): CognitoOutputs {
  const prefix = `/mem9-on-aws/${$app.stage}`;
  const stage = $app.stage;
  const region = awsAny.getRegionOutput().name;
  const accountId = awsAny.getCallerIdentityOutput().accountId;
  const tags = { Project: "mem9-on-aws", Stage: stage, ManagedBy: "sst" };
  const configuredDomainPrefix = cognitoDomainOverride();

  // Validate an override synchronously so malformed operator input aborts the
  // Pulumi program before deployment. Otherwise resolve the account and Region
  // outputs and derive a stable default.
  const domainPrefix =
    configuredDomainPrefix ??
    accountId.apply((resolvedAccountId: string) =>
      region.apply((resolvedRegion: string) =>
        cognitoDomainPrefix({
          accountId: resolvedAccountId,
          region: resolvedRegion,
          stage,
        }),
      ),
    );

  // Deterministic per-stage pool name (Cognito allows duplicate names, so embed
  // the stage to guarantee isolation). deleteBeforeReplace on non-prod so a
  // `sst remove --stage pr-N` tears down cleanly; prod is guarded by the
  // app-level removal:retain + protect in sst.config.ts (a pool replacement
  // would wipe M2M clients — CLAUDE-AWS §Cognito).
  const nonProd = stage !== "prod";
  const pool = new awsAny.cognito.UserPool(
    "Mem9McpPool",
    {
      name: `${stage}-mem9-mcp`,
      // Hosted-UI config: an `email` attribute for the login form, no forced
      // re-verification on attribute update.
      schema: [{ name: "email", attributeDataType: "String", mutable: true, required: false }],
      userAttributeUpdateSettings: { attributesRequireVerificationBeforeUpdate: [] },
      // Auto-verify email so the Hosted-UI ForgotPassword flow can send a
      // recovery code (AccountRecovery defaults to verified_email). Without this,
      // the operator can't reset their password via the browser — reset 503s
      // because no verified recovery channel exists. Cognito's own /oauth login
      // + this recovery path are separate from the OAuth2 FAÇADE, which brokers
      // the authorization-code flow but not password management. Email sending
      // uses the pool's COGNITO_DEFAULT sender (50/day — ample for one operator).
      autoVerifiedAttributes: ["email"],
      // Single-operator: NO self-service sign-up. Only an admin (admin-create-user)
      // provisions users; enabling email auto-verify above must NOT open public
      // registration. This flag locks the Hosted-UI sign-up path.
      adminCreateUserConfig: { allowAdminCreateUserOnly: true },
      tags,
    },
    { deleteBeforeReplace: nonProd },
  );

  // OAuth token endpoint domain. The repository's production workflow supplies
  // its legacy prefix as an override; new stages use the stable derived default.
  const domain = new awsAny.cognito.UserPoolDomain(
    "Mem9McpDomain",
    { domain: domainPrefix, userPoolId: pool.id },
    { deleteBeforeReplace: nonProd },
  );

  const resourceServer = new awsAny.cognito.ResourceServer("Mem9McpResourceServer", {
    identifier: MCP_RESOURCE_SERVER_ID,
    name: "mem9 MCP",
    userPoolId: pool.id,
    scopes: [
      { scopeName: "read", scopeDescription: "Search memories" },
      { scopeName: "write", scopeDescription: "Add/update/delete memories" },
    ],
  });

  const client = new awsAny.cognito.UserPoolClient("Mem9McpClient", {
    name: `${stage}-mem9-mcp-client`,
    userPoolId: pool.id,
    generateSecret: true,
    explicitAuthFlows: [],
    allowedOauthFlows: ["client_credentials"],
    allowedOauthFlowsUserPoolClient: true,
    // Keep the resource-server output dependency while sharing the exact scope
    // values with the browser client, Gateway authorizer, and facade metadata.
    allowedOauthScopes: resourceServer.identifier.apply(() => [
      ...MCP_RESOURCE_SCOPES,
    ]),
    preventUserExistenceErrors: "ENABLED",
    enableTokenRevocation: true,
  });

  // $interpolate (NOT a template literal) resolves the embedded Output<string>s;
  // a plain literal would stringify them and break CFN/JWT-authorizer validation.
  const issuer = $interpolate`https://cognito-idp.${region}.amazonaws.com/${pool.id}`;
  const tokenEndpoint = $interpolate`https://${domain.domain}.auth.${region}.amazoncognito.com/oauth2/token`;
  const authorizeEndpoint = $interpolate`https://${domain.domain}.auth.${region}.amazoncognito.com/oauth2/authorize`;
  const userInfoEndpoint = $interpolate`https://${domain.domain}.auth.${region}.amazoncognito.com/oauth2/userInfo`;
  const revocationEndpoint = $interpolate`https://${domain.domain}.auth.${region}.amazoncognito.com/oauth2/revoke`;
  const jwksUri = $interpolate`https://cognito-idp.${region}.amazonaws.com/${pool.id}/.well-known/jwks.json`;

  new awsAny.ssm.Parameter("SsmCognitoIssuer", {
    name: `${prefix}/cognito/issuer`,
    type: "String",
    value: issuer,
    tags,
  });
  new awsAny.ssm.Parameter("SsmCognitoTokenEndpoint", {
    name: `${prefix}/cognito/token-endpoint`,
    type: "String",
    value: tokenEndpoint,
    tags,
  });
  new awsAny.ssm.Parameter("SsmCognitoClientId", {
    name: `${prefix}/cognito/client-id`,
    type: "String",
    value: client.id,
    tags,
  });
  new awsAny.ssm.Parameter("SsmCognitoClientSecret", {
    name: `${prefix}/cognito/client-secret`,
    type: "SecureString",
    value: client.clientSecret,
    tags,
  });
  new awsAny.ssm.Parameter("SsmCognitoScope", {
    name: `${prefix}/cognito/scope`,
    type: "String",
    value: MCP_RESOURCE_SCOPES.join(" "),
    tags,
  });

  return {
    ssmPrefix: prefix,
    userPoolId: pool.id,
    issuer,
    tokenEndpoint,
    authorizeEndpoint,
    userInfoEndpoint,
    revocationEndpoint,
    jwksUri,
    resourceServerId: MCP_RESOURCE_SERVER_ID,
    clientId: client.id,
    clientSecret: client.clientSecret,
    allowedClientIds: [client.id],
  };
}
