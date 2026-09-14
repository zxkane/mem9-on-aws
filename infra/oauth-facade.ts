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
 * — it's a public authorization-code client (Hosted-UI) that supports both
 * resource scopes, returned via the legacy `readerClientId` output for
 * gateway.ts to trust.
 *
 * Production uses an operator-seeded `sst.Secret` and fails closed while it is
 * empty. Ephemeral stages use a stable Pulumi RandomPassword secret output so
 * preview OAuth smoke tests exercise the signed flow without shared credentials.
 *
 * The façade Function is NOT VPC-attached: it only reaches Cognito + SSM over the
 * public internet, so a VPC/NAT hop would only add cold-start ENI latency.
 */

import { createHash } from "node:crypto";
import type { AuthConfig } from "./auth-config";

import {
  MCP_BROWSER_SCOPES,
  MCP_RESOURCE_SCOPES,
  type CognitoOutputs,
} from "./cognito";

// @ts-ignore - `aws`/`sst` injected globally by SST; cognito/ssm types loose.
const awsAny = aws as unknown as Record<string, any>;
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
  /**
   * The façade Function's execution role NAME (not ARN — `aws.iam.RolePolicy`
   * takes the name). `infra/slack-approval.ts` attaches the approval-record write
   * and the RunTask/PassRole grants to this role rather than creating a second
   * one, which would need its own workload-boundary exception (#123).
   */
  functionRoleName: Output<string>;
}

export function oauthFacade(
  cognitoOut: CognitoOutputs | undefined,
  auth: AuthConfig = {
    mode: "managed",
    retainManaged: false,
    groupClaim: "cognito:groups",
  },
): OauthFacadeOutputs {
  const external = auth.oidc;
  if (!external && !cognitoOut)
    throw new Error("Managed authentication requires Cognito");
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
      `${FACADE_CUSTOM_DOMAIN_ENV} requires ${missing.join(
        " and ",
      )} for Cloudflare DNS.`,
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
    retain = false,
  ) =>
    new awsAny.ssm.Parameter(
      logicalName,
      {
        name: `${prefix}/${suffix}`,
        type: secure ? "SecureString" : "String",
        value,
        tags,
        ...(retain ? { overwrite: true } : {}),
      },
      retain ? { retainOnDelete: true, protect: false } : {},
    );

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

  // --- Browser UserPoolClient (authorization-code + PKCE, read/write scopes) ---
  // A SEPARATE app client from cognito.ts's M2M client: this one drives the
  // browser Hosted-UI flow. `generateSecret` (confidential client — the façade
  // holds the secret server-side and does the code exchange). callbackUrls /
  // logoutUrls point back at THIS api's routes (hence the create-first ordering).
  const readerClient = cognitoOut
    ? new awsAny.cognito.UserPoolClient(
        "Mem9McpReaderClient",
        {
          name: `${stage}-mem9-mcp-reader`,
          userPoolId: cognitoOut.userPoolId,
          generateSecret: true,
          // Cognito restores ALLOW_REFRESH_TOKEN_AUTH when this property is absent.
          // Keep one non-refresh API flow so the deployed client has an explicit
          // list that excludes the flow incompatible with token rotation.
          explicitAuthFlows: ["ALLOW_USER_SRP_AUTH"],
          refreshTokenRotation: {
            feature: "ENABLED",
            retryGracePeriodSeconds: 10,
          },
          supportedIdentityProviders: ["COGNITO"],
          callbackUrls: [$interpolate`${facadeApi.url}/oauth/callback`],
          logoutUrls: [$interpolate`${facadeApi.url}/oauth/logout`],
          allowedOauthFlows: ["code"],
          allowedOauthScopes: [...MCP_BROWSER_SCOPES],
          allowedOauthFlowsUserPoolClient: true,
          accessTokenValidity: 15,
          tokenValidityUnits: {
            accessToken: "minutes",
          },
          preventUserExistenceErrors: "ENABLED",
          enableTokenRevocation: true,
        },
        { dependsOn: [facadeApi] },
      )
    : undefined;

  const readerClientId = external
    ? $interpolate`${external.clientId}`
    : readerClient!.id;
  const activeClientSecret = external
    ? external.clientSecret
      ? new sst.Secret("OidcClientSecret").value
      : undefined
    : readerClient!.clientSecret;
  // Keep legacy credentials unchanged for Lambda versions still using legacy
  // endpoints. External credentials never overwrite these shared SSM names.
  const legacyReaderIdParam = readerClient
    ? param("SsmReaderClientId", "cognito/reader/client-id", readerClient.id)
    : undefined;
  const legacyReaderSecretParam = readerClient
    ? param(
        "SsmReaderClientSecret",
        "cognito/reader/client-secret",
        readerClient.clientSecret,
        true,
      )
    : undefined;
  const issuer = external?.issuer ?? cognitoOut!.issuer;
  const tokenEndpoint = external?.tokenEndpoint ?? cognitoOut!.tokenEndpoint;
  const providerKey = external
    ? createHash("sha256")
        .update(
          JSON.stringify([
            external.issuer,
            external.clientId,
            external.tokenEndpoint,
            external.tokenAuthMethod,
            external.m2mClientId ?? null,
          ]),
        )
        .digest("hex")
    : undefined;
  const providerSuffix = `auth/providers/${providerKey}`;
  const credentialPrefix = external
    ? `${prefix}/${providerSuffix}/browser`
    : `${prefix}/cognito/reader`;
  const readerIdParam = external
    ? param(
        "SsmOidcReaderClientId",
        `${providerSuffix}/browser/client-id`,
        readerClientId,
        false,
        true,
      )
    : legacyReaderIdParam!;
  const readerSecretParam = external
    ? activeClientSecret
      ? param(
          "SsmOidcReaderClientSecret",
          `${providerSuffix}/browser/client-secret`,
          activeClientSecret,
          true,
          true,
        )
      : undefined
    : legacyReaderSecretParam;
  param("SsmAuthMode", "auth/mode", $interpolate`${auth.mode}`);
  param("SsmAuthIssuer", "auth/issuer", $interpolate`${issuer}`);
  param(
    "SsmAuthTokenEndpoint",
    "auth/token-endpoint",
    $interpolate`${tokenEndpoint}`,
  );
  param(
    "SsmAuthScope",
    "auth/scope",
    $interpolate`${MCP_RESOURCE_SCOPES.join(" ")}`,
  );
  if (external?.m2mClientId) {
    param(
      "SsmOidcM2mClientId",
      `${providerSuffix}/m2m/client-id`,
      $interpolate`${external.m2mClientId}`,
      false,
      true,
    );
    param(
      "SsmOidcM2mClientSecret",
      `${providerSuffix}/m2m/client-secret`,
      new sst.Secret("OidcM2mClientSecret").value,
      true,
      true,
    );
  }
  if (external) {
    param(
      "SsmOidcProviderTokenEndpoint",
      `${providerSuffix}/token-endpoint`,
      $interpolate`${tokenEndpoint}`,
      false,
      true,
    );
    param(
      "SsmOidcProviderScope",
      `${providerSuffix}/scope`,
      $interpolate`${MCP_RESOURCE_SCOPES.join(" ")}`,
      false,
      true,
    );
    param(
      "SsmOidcProviderPrefix",
      "auth/provider-prefix",
      $interpolate`${prefix}/${providerSuffix}`,
    );
  }
  const authContext = $interpolate`${issuer}|${readerIdParam.value}|${tokenEndpoint}|${facadeApi.url}`;
  const authContextVersion = authContext.apply((value: string) =>
    createHash("sha256").update(value).digest("hex"),
  );
  const secretVersion =
    readerSecretParam?.value.apply((value: string) =>
      createHash("sha256").update(value).digest("hex"),
    ) ?? "none";

  // Production fails closed until its operator-owned key is seeded. Ephemeral
  // stages get a secret Pulumi output that remains stable across stack updates
  // and disappears with the stage.
  const hmacKeyValue =
    stage === "prod"
      ? new sst.Secret("OauthStateHmacKey", "").value
      : new random.RandomPassword("OauthStateHmacKey", {
          length: 64,
          special: false,
        }).result;
  // Stage-scoped JSON array of exact HTTPS callbacks for hosted MCP clients.
  // Loopback callbacks remain built in; an empty array preserves that default.
  const allowedCallbackUrls = new sst.Secret("OauthAllowedCallbackUrls", "[]");
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
      // Read by buildSlackDeps (#123). It THROWS when a Slack signing secret is
      // configured but STAGE is unset, and it throws at cold start on every
      // invocation — so the interactions endpoint would 500 on every click while
      // the deploy stayed green. Neither loadConfig nor resolveSsm reads STAGE,
      // so nothing else in the config path would surface the omission.
      STAGE: stage,
      // The upstream Cognito issuer is deliberately NOT passed to the façade: its
      // metadata documents must advertise their OWN issuer (RFC 8414 §3.3), which
      // left the upstream value with no consumer (#143). The Gateway's JWT
      // authorizer builds its discoveryUrl from `cognitoOut.issuer` directly
      // (infra/gateway.ts), so token validation does not depend on this env.
      AUTH_MODE: auth.mode,
      AUTH_CREDENTIAL_PREFIX: credentialPrefix,
      AUTH_TOKEN_AUTH_METHOD: external?.tokenAuthMethod ?? "client_secret_post",
      AUTH_CONTEXT_VERSION: authContextVersion,
      AUTH_CLIENT_SECRET_VERSION: secretVersion,
      COGNITO_AUTHORIZE_ENDPOINT:
        external?.authorizeEndpoint ?? cognitoOut!.authorizeEndpoint,
      COGNITO_TOKEN_ENDPOINT: tokenEndpoint,
      COGNITO_USERINFO_ENDPOINT:
        external?.userInfoEndpoint ?? cognitoOut!.userInfoEndpoint,
      COGNITO_REVOCATION_ENDPOINT:
        external?.revocationEndpoint ?? cognitoOut!.revocationEndpoint,
      COGNITO_JWKS_URI: external?.jwksUri ?? cognitoOut!.jwksUri,
      RESOURCE_SCOPES: MCP_RESOURCE_SCOPES.join(","),
      OAUTH_STATE_HMAC_KEY: hmacKeyValue,
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
  // API Gateway requires an authorizer on every internet-reachable route. These
  // protocol endpoints must remain public, so the request authorizer has no
  // identity sources or cache and always returns an HTTP API v2 simple Allow.
  // Real `/mcp` bearer enforcement remains in the facade handler.
  const authorizer = facadeApi.addAuthorizer({
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
  });
  const addRoute = (route: string) => {
    facadeApi.route(route, facadeFn.arn, {
      auth: { lambda: authorizer.id },
    });
  };
  addRoute("ANY /{proxy+}");
  addRoute("ANY /");

  // --- SSM exports ---
  param("SsmFacadeUrl", "facade/url", facadeApi.url);
  param(
    "SsmFacadeMcpEndpoint",
    "facade/mcp-endpoint",
    $interpolate`${facadeApi.url}/mcp`,
  );

  return {
    ssmPrefix: prefix,
    readerClientId,
    facadeUrl: facadeApi.url,
    functionRoleName: facadeFn.nodes.role.name,
  };
}
