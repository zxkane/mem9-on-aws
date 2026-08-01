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

import { createHash } from "node:crypto";

import type { CognitoOutputs } from "./cognito";

// @ts-ignore - `aws`/`sst` injected globally by SST; cognito/ssm types loose.
const awsAny = aws as unknown as Record<string, any>;
const FACADE_AUTHORIZER_ENABLED =
  process.env.MEM9_FACADE_AUTHORIZER_ENABLED === "1";
const FACADE_CUSTOM_DOMAIN_ENV = "MEM9_FACADE_CUSTOM_DOMAIN";
const CLOUDFLARE_API_TOKEN_ENV = "CLOUDFLARE_API_TOKEN";
const CLOUDFLARE_ZONE_ID_ENV = "CLOUDFLARE_ZONE_ID";

export function facadeCustomDomain(
  stage: string,
  raw = process.env[FACADE_CUSTOM_DOMAIN_ENV],
): string | undefined {
  // One hostname can map to only one stage. CI intentionally reserves the
  // optional shared hostname for production and leaves previews on execute-api.
  if (stage !== "prod" || !raw?.trim()) return undefined;

  const domain = raw.trim().toLowerCase().replace(/\.$/u, "");
  const labels = domain.split(".");
  const validLabel = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
  if (
    domain.length > 253 ||
    labels.length < 2 ||
    labels.some((label) => !validLabel.test(label))
  ) {
    throw new Error(
      `${FACADE_CUSTOM_DOMAIN_ENV} must be a hostname such as memory.example.com (without a scheme, port, or path).`,
    );
  }
  return domain;
}

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
  const customDomain = facadeCustomDomain(stage);
  const cloudflareToken = process.env[CLOUDFLARE_API_TOKEN_ENV]?.trim();
  const cloudflareZoneId = process.env[CLOUDFLARE_ZONE_ID_ENV]?.trim();
  if (customDomain && (!cloudflareToken || !cloudflareZoneId)) {
    const missing = [
      !cloudflareToken && CLOUDFLARE_API_TOKEN_ENV,
      !cloudflareZoneId && CLOUDFLARE_ZONE_ID_ENV,
    ].filter(Boolean);
    throw new Error(
      `${FACADE_CUSTOM_DOMAIN_ENV} requires ${missing.join(" and ")} for Cloudflare DNS.`,
    );
  }
  const customDomainConfig = customDomain
    ? {
        name: customDomain,
        dns: sst.cloudflare.dns({
          zone: cloudflareZoneId!,
          // Keep both ACM validation and API Gateway CNAMEs DNS-only.
          proxy: false,
        }),
      }
    : undefined;

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
    ...(customDomainConfig ? { domain: customDomainConfig } : {}),
    cors: {
      allowHeaders: [
        "Authorization",
        "Content-Type",
        "Accept",
        "MCP-Protocol-Version",
      ],
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
  // Stage-scoped JSON array of exact HTTPS callbacks for hosted MCP clients.
  // Loopback callbacks remain built in; an empty array preserves that default.
  const allowedCallbackUrls = new sst.Secret(
    "OauthAllowedCallbackUrls",
    "[]",
  );
  const allowedCallbackUrlsParameter = param(
    "SsmAllowedCallbackUrls",
    "oauth/allowed-callback-urls",
    allowedCallbackUrls.value,
  );
  // Deriving the version from the Parameter output orders its update before
  // Lambda replacement, so a new cold start cannot cache the previous value.
  const allowedCallbackUrlsVersion = allowedCallbackUrlsParameter.value.apply(
    (value: string) => createHash("sha256").update(value).digest("hex"),
  );

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
      OAUTH_ALLOWED_CALLBACK_URLS_VERSION: allowedCallbackUrlsVersion,
    },
    permissions: [
      {
        actions: ["ssm:GetParameters"],
        resources: [
          $interpolate`arn:aws:ssm:${region}:${accountId}:parameter${prefix}/*`,
        ],
      },
      {
        actions: ["kms:Decrypt"],
        resources: ["*"],
        conditions: [
          {
            test: "StringEquals",
            variable: "kms:ViaService",
            values: [$interpolate`ssm.${region}.amazonaws.com`],
          },
          {
            test: "ArnLike",
            variable: "kms:EncryptionContext:PARAMETER_ARN",
            values: [
              $interpolate`arn:aws:ssm:${region}:${accountId}:parameter${prefix}/*`,
            ],
          },
        ],
      },
    ],
  });

  // --- Routes ---
  // A catch-all proxy (the handler routes internally by path/method) + the root.
  const authorizer = FACADE_AUTHORIZER_ENABLED
    ? facadeApi.addAuthorizer({
        name: "Mem9OauthFacadeAllowAll",
        lambda: {
          function: {
            handler: "infra/src/oauth-facade/authorizer.handler",
            architecture: "arm64",
            name: `mem9-on-aws-${stage}-Mem9OauthFacadeAllowAll`,
            transform: {
              role: {
                name: `mem9-on-aws-${stage}-Mem9OauthFacadeAllowAllRole`,
              },
            },
          },
          identitySources: [],
          response: "simple",
          ttl: "0 seconds",
        },
      })
    : undefined;
  const addRoute = (route: string) => {
    if (authorizer) {
      facadeApi.route(route, facadeFn.arn, {
        auth: { lambda: authorizer.id },
      });
    } else {
      facadeApi.route(route, facadeFn.arn);
    }
  };
  addRoute("ANY /{proxy+}");
  addRoute("ANY /");

  // --- SSM exports ---
  param("SsmReaderClientId", "cognito/reader/client-id", readerClient.id);
  param(
    "SsmReaderClientSecret",
    "cognito/reader/client-secret",
    readerClient.clientSecret,
    true,
  );
  param("SsmFacadeUrl", "facade/url", facadeApi.url);
  param(
    "SsmFacadeMcpEndpoint",
    "facade/mcp-endpoint",
    $interpolate`${facadeApi.url}/mcp`,
  );

  return {
    ssmPrefix: prefix,
    readerClientId: readerClient.id,
    facadeUrl: facadeApi.url,
  };
}
