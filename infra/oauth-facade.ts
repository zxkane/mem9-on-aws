/**
 * `oauthFacade` stack — the OAuth2 browser-login façade (§7).
 *
 * MCP clients (Claude Desktop, etc.) speak the authorization-code + PKCE flow to
 * a public endpoint, but Cognito's Hosted-UI is a plain OAuth2 provider that the
 * MCP client can't drive directly (no PKCE-registered public client, no
 * `/mcp` resource-metadata surface). This façade is an ApiGatewayV2-fronted Lambda
 * that bridges the two: it advertises the protected-resource / authorization-server
 * metadata, proxies /oauth/authorize → Cognito Hosted-UI, and swaps the code for
 * tokens at /oauth/callback (HMAC-signed state guards CSRF).
 *
 * CYCLE BREAK (creation order matters): the ApiGatewayV2 is created FIRST because
 * `facadeApi.url` is needed for the reader UserPoolClient's `callbackUrls`. The
 * reader client is a SEPARATE Cognito app client from the M2M client in cognito.ts
 * — it's a public authorization-code client (Hosted-UI), scoped to read-only
 * (`mem9-mcp/read`), returned via `readerClientId` for gateway.ts to trust.
 *
 * The HMAC state-signing key is an `sst.Secret` seeded EMPTY — the handler returns
 * 503 until the operator seeds it (config.ts treats an empty key as unconfigured),
 * so a fresh deploy never runs the flow with a guessable state signature.
 *
 * The façade Function is NOT VPC-attached: it only reaches Cognito + SSM over the
 * public internet, so a VPC/NAT hop would only add cold-start ENI latency.
 */

import type { CognitoOutputs } from "./cognito";

// @ts-ignore - `aws`/`sst` injected globally by SST; cognito/ssm types loose.
const awsAny = aws as unknown as Record<string, any>;

export interface OauthFacadeOutputs {
  ssmPrefix: string;
  readerClientId: Output<string>;
  facadeUrl: Output<string>;
}

export function oauthFacade(cognitoOut: CognitoOutputs): OauthFacadeOutputs {
  const prefix = `/mem9-on-aws/${$app.stage}`;
  const stage = $app.stage;
  const tags = { Project: "mem9-on-aws", Stage: stage, ManagedBy: "sst" };
  const region = awsAny.getRegionOutput().name;
  const accountId = awsAny.getCallerIdentityOutput().accountId;

  // Small helper: emit an SSM export under this stage's prefix. `secure` flips the
  // type to SecureString (the reader client secret; the MCP client needs it to
  // exchange the code, surfaced to the operator at setup).
  const param = (
    logicalName: string,
    suffix: string,
    value: Output<string>,
    secure = false,
  ) =>
    new awsAny.ssm.Parameter(logicalName, {
      name: `${prefix}/${suffix}`,
      type: secure ? "SecureString" : "String",
      value,
      tags,
    });

  // --- ApiGatewayV2 (created FIRST — cycle break) ---
  // CORS scoped to the headers an MCP client sends: the bearer, JSON bodies, the
  // Accept negotiation, and the MCP protocol-version header the transport adds.
  const facadeApi = new sst.aws.ApiGatewayV2("Mem9OauthFacadeApi", {
    cors: {
      allowHeaders: ["Authorization", "Content-Type", "Accept", "MCP-Protocol-Version"],
      allowOrigins: ["*"],
      allowMethods: ["*"],
      maxAge: "1 day",
    },
  });

  // --- Reader UserPoolClient (authorization-code + PKCE, read-only) ---
  // A SEPARATE app client from cognito.ts's M2M client: this one drives the
  // browser Hosted-UI flow. `generateSecret` (confidential client — the façade
  // holds the secret server-side and does the code exchange). callbackUrls /
  // logoutUrls point back at THIS api's routes (hence the create-first ordering).
  const readerClient = new awsAny.cognito.UserPoolClient(
    "Mem9McpReaderClient",
    {
      name: `${stage}-mem9-mcp-reader`,
      userPoolId: cognitoOut.userPoolId,
      generateSecret: true,
      explicitAuthFlows: ["ALLOW_REFRESH_TOKEN_AUTH"],
      supportedIdentityProviders: ["COGNITO"],
      callbackUrls: [$interpolate`${facadeApi.url}/oauth/callback`],
      logoutUrls: [$interpolate`${facadeApi.url}/oauth/logout`],
      allowedOauthFlows: ["code"],
      allowedOauthScopes: ["openid", "email", "mem9-mcp/read"],
      allowedOauthFlowsUserPoolClient: true,
      preventUserExistenceErrors: "ENABLED",
      enableTokenRevocation: true,
    },
    { dependsOn: [facadeApi] },
  );

  // --- HMAC state-signing key (empty default → façade 503 until seeded) ---
  const hmacKey = new sst.Secret("OauthStateHmacKey", "");

  // --- Façade Function (public, NOT VPC-attached) ---
  // arm64 nodejs24.x. Env carries the SSM prefix (the handler reads the reader
  // client id/secret from SSM at runtime) + the Cognito endpoint URLs + the
  // resource scope + the live HMAC key. Least-privilege: SSM read scoped to this
  // stage's parameter path only.
  const facadeFn = new sst.aws.Function("Mem9OauthFacadeFn", {
    handler: "infra/src/oauth-facade/handler.handler",
    runtime: "nodejs24.x",
    architecture: "arm64",
    timeout: "30 seconds",
    memory: "256 MB",
    environment: {
      SSM_PREFIX: prefix,
      COGNITO_ISSUER: cognitoOut.issuer,
      COGNITO_AUTHORIZE_ENDPOINT: cognitoOut.authorizeEndpoint,
      COGNITO_TOKEN_ENDPOINT: cognitoOut.tokenEndpoint,
      COGNITO_USERINFO_ENDPOINT: cognitoOut.userInfoEndpoint,
      COGNITO_REVOCATION_ENDPOINT: cognitoOut.revocationEndpoint,
      COGNITO_JWKS_URI: cognitoOut.jwksUri,
      RESOURCE_SCOPES: "mem9-mcp/read",
      OAUTH_STATE_HMAC_KEY: hmacKey.value,
    },
    permissions: [
      {
        actions: ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"],
        resources: [$interpolate`arn:aws:ssm:${region}:${accountId}:parameter${prefix}/*`],
      },
    ],
  });

  // --- Routes ---
  // A catch-all proxy (the handler routes internally by path/method) + the root.
  facadeApi.route("ANY /{proxy+}", facadeFn.arn);
  facadeApi.route("ANY /", facadeFn.arn);

  // --- SSM exports ---
  param("SsmReaderClientId", "cognito/reader/client-id", readerClient.id);
  param("SsmReaderClientSecret", "cognito/reader/client-secret", readerClient.clientSecret, true);
  param("SsmFacadeUrl", "facade/url", facadeApi.url);
  param("SsmFacadeMcpEndpoint", "facade/mcp-endpoint", $interpolate`${facadeApi.url}/mcp`);

  return {
    ssmPrefix: prefix,
    readerClientId: readerClient.id,
    facadeUrl: facadeApi.url,
  };
}
