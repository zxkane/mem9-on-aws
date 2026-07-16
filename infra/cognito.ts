/**
 * `cognito` stack — Cognito M2M user pool for MCP inbound auth (§6).
 *
 * The AgentCore Gateway's inbound authorizer is a CUSTOM_JWT authorizer that
 * validates Cognito `client_credentials` (M2M) JWTs. This stack provisions the
 * pool + domain (OAuth token endpoint) + resource server (scopes) + ONE M2M
 * client (single-operator; a sibling project runs several tenant clients — we keep
 * one and can add more later without rotating the Gateway URL, since only
 * `name`/`authorizerType` are RequiresReplace on the Gateway).
 *
 * The Gateway matches on `allowedClients` (Cognito client_credentials tokens carry
 * `client_id`, not `aud`), so infra/gateway.ts lists this client's id there.
 *
 * Exports the issuer + token endpoint (for clients to mint tokens) and the client
 * id + secret ARN via SSM. The client SECRET is a SecureString (needed by the
 * caller — Claude Code — to mint tokens; surfaced to the operator at setup).
 */

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

const RESOURCE_SERVER_ID = "mem9-mcp";

export function cognito(): CognitoOutputs {
  const prefix = `/mem9-on-aws/${$app.stage}`;
  const stage = $app.stage;
  const region = awsAny.getRegionOutput().name;
  const tags = { Project: "mem9-on-aws", Stage: stage, ManagedBy: "sst" };

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

  // OAuth token endpoint domain. Cognito domains are globally unique → embed the
  // stage; PR stages append the PR number for deterministic re-deploys.
  const domainSuffix = stage.startsWith("pr-") ? `-${stage.split("-")[1]}` : "";
  const domain = new awsAny.cognito.UserPoolDomain(
    "Mem9McpDomain",
    { domain: `${stage}-mem9-mcp${domainSuffix}`, userPoolId: pool.id },
    { deleteBeforeReplace: nonProd },
  );

  const resourceServer = new awsAny.cognito.ResourceServer("Mem9McpResourceServer", {
    identifier: RESOURCE_SERVER_ID,
    name: "mem9 MCP",
    userPoolId: pool.id,
    scopes: [
      { scopeName: "read", scopeDescription: "Search memories" },
      { scopeName: "write", scopeDescription: "Add/update/delete memories" },
    ],
  });

  // Single M2M client (client_credentials, both scopes). Used as BOTH the caller
  // and the Gateway's allowedClients entry.
  const client = new awsAny.cognito.UserPoolClient("Mem9McpClient", {
    name: `${stage}-mem9-mcp-client`,
    userPoolId: pool.id,
    generateSecret: true,
    explicitAuthFlows: [],
    allowedOauthFlows: ["client_credentials"],
    allowedOauthFlowsUserPoolClient: true,
    allowedOauthScopes: resourceServer.identifier.apply((id: string) => [
      `${id}/read`,
      `${id}/write`,
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
    value: `${RESOURCE_SERVER_ID}/read ${RESOURCE_SERVER_ID}/write`,
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
    resourceServerId: RESOURCE_SERVER_ID,
    clientId: client.id,
    clientSecret: client.clientSecret,
    allowedClientIds: [client.id],
  };
}
