/**
 * Façade runtime config (design §6.4 + the cycle break).
 *
 * The façade is fronted by an `ApiGatewayV2` HTTP API (NOT a Lambda Function
 * URL — that exposes an open `Principal: "*"` resource policy). The Pulumi
 * dependency cycle
 *
 *   readerClient.callbackUrls  ←  façade URL          (Cognito needs the URL)
 *   façade env                 ←  readerClient.id/secret + gatewayUrl
 *
 * is broken at the infra layer by creating the API resource first
 * (`facadeApi.url` is independent of the Lambda). Independently, the façade
 * reads the gateway URL + reader client creds
 * from SSM at RUNTIME (cold-start singleton in the handler) instead of taking
 * them as construction-time env vars, keeping the Lambda free of any
 * constructor dependency on the reader client or the gateway:
 *   - `{mcpPrefix}/gateway/url`                    (UPSTREAM gateway)
 *   - `{mcpPrefix}/cognito/reader/client-id`
 *   - `{mcpPrefix}/cognito/reader/client-secret`   (SecureString)
 *   - `{mcpPrefix}/oauth/allowed-callback-urls`
 *
 * The remaining, non-cyclic values (Cognito endpoint URLs that depend only on
 * the user pool + domain, the stage-specific HMAC key, and the resource scopes)
 * are plain env vars. Production sources the key from an operator-set SST
 * secret; ephemeral stages use a Pulumi-generated secret output. The SSM client
 * is injected (`SsmLike`) so the loader is unit-testable without AWS.
 */

import { GetParametersCommand, SSMClient } from "@aws-sdk/client-ssm";

export interface FacadeConfig {
  /** AgentCore Gateway URL the façade proxies to (`/mcp` + fallthrough). */
  upstream: string;
  /** Cognito OIDC issuer. */
  issuer: string;
  /** Cognito Hosted-UI authorize / token / userinfo / revocation / jwks. */
  authorize: string;
  token: string;
  userinfo: string;
  revocation: string;
  jwks: string;
  /** Resource-server scopes advertised in metadata (e.g. `mem9/memory/read`). */
  resourceScopes: string[];
  /** Reader app client credentials returned by `/register` (DCR). */
  userClientId: string;
  userClientSecret: string;
  /** Exact HTTPS redirect URIs allowed in addition to RFC 8252 loopback URLs. */
  allowedClientRedirectUris: string[];
  /** HMAC key for state signing; empty disables the proxy (503). */
  hmacKey: string;
}

/** Minimal SSM surface used here — injected so tests need no AWS. */
export interface SsmLike {
  send(command: unknown): Promise<{
    Parameters?: Array<{ Name?: string; Value?: string }>;
  }>;
}

type Env = Record<string, string | undefined>;
const ALLOWED_CALLBACK_URLS_SETTING = "OauthAllowedCallbackUrls";
const MAX_ALLOWED_CALLBACK_URLS = 20;
const MAX_CALLBACK_URL_LENGTH = 2048;
const MAX_CALLBACK_CONFIG_BYTES = 1024;

function reqEnv(env: Env, name: string): string {
  const v = env[name];
  if (!v) throw new Error(`missing env ${name}`);
  return v;
}

export function parseAllowedCallbackUrls(raw = ""): string[] {
  if (Buffer.byteLength(raw, "utf8") > MAX_CALLBACK_CONFIG_BYTES) {
    throw new Error(
      `${ALLOWED_CALLBACK_URLS_SETTING} must not exceed ${MAX_CALLBACK_CONFIG_BYTES} UTF-8 bytes`,
    );
  }
  if (!raw.trim()) return [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${ALLOWED_CALLBACK_URLS_SETTING} must be a JSON array`);
  }
  if (!Array.isArray(parsed)) {
    throw new Error(`${ALLOWED_CALLBACK_URLS_SETTING} must be a JSON array`);
  }
  const urls = new Set<string>();
  for (const entry of parsed) {
    if (
      typeof entry !== "string" ||
      !entry ||
      entry !== entry.trim() ||
      entry.length > MAX_CALLBACK_URL_LENGTH
    ) {
      throw new Error(
        `${ALLOWED_CALLBACK_URLS_SETTING} entries must be non-empty URL strings`,
      );
    }

    let url: URL;
    try {
      url = new URL(entry);
    } catch {
      throw new Error(
        `${ALLOWED_CALLBACK_URLS_SETTING} entries must be valid HTTPS URLs`,
      );
    }
    if (
      url.protocol !== "https:" ||
      !url.hostname ||
      url.username ||
      url.password ||
      url.hash
    ) {
      throw new Error(
        `${ALLOWED_CALLBACK_URLS_SETTING} entries must be HTTPS URLs without credentials or fragments`,
      );
    }
    urls.add(entry);
    if (urls.size > MAX_ALLOWED_CALLBACK_URLS) {
      throw new Error(
        `${ALLOWED_CALLBACK_URLS_SETTING} supports at most ${MAX_ALLOWED_CALLBACK_URLS} unique URLs`,
      );
    }
  }
  return [...urls];
}

/** Resolve runtime values from SSM (decrypting the client secret). */
export async function resolveSsm(
  prefix: string,
  ssm: SsmLike,
): Promise<{
  upstream: string;
  userClientId: string;
  userClientSecret: string;
  allowedCallbackUrls: string;
}> {
  const names = [
    `${prefix}/gateway/url`,
    `${prefix}/cognito/reader/client-id`,
    `${prefix}/cognito/reader/client-secret`,
    `${prefix}/oauth/allowed-callback-urls`,
  ];
  const res = await ssm.send(
    new GetParametersCommand({ Names: names, WithDecryption: true }),
  );
  const byName = new Map(
    (res.Parameters ?? []).map((p) => [p.Name, p.Value ?? ""]),
  );
  const get = (n: string): string => {
    const v = byName.get(n);
    if (!v) throw new Error(`missing SSM parameter ${n}`);
    return v;
  };
  return {
    upstream: get(names[0]!),
    userClientId: get(names[1]!),
    userClientSecret: get(names[2]!),
    allowedCallbackUrls: get(names[3]!),
  };
}

/**
 * Build the façade config from env + SSM. The handler wraps this in a
 * cold-start singleton; tests inject `ssm` + `env` and call it directly.
 */
export async function loadConfig(
  opts: { ssm?: SsmLike; env?: Env } = {},
): Promise<FacadeConfig> {
  const env = opts.env ?? process.env;
  const ssm = opts.ssm ?? new SSMClient({});
  const prefix = reqEnv(env, "SSM_PREFIX");
  const resolved = await resolveSsm(prefix, ssm);
  return {
    upstream: resolved.upstream,
    issuer: reqEnv(env, "COGNITO_ISSUER"),
    authorize: reqEnv(env, "COGNITO_AUTHORIZE_ENDPOINT"),
    token: reqEnv(env, "COGNITO_TOKEN_ENDPOINT"),
    userinfo: reqEnv(env, "COGNITO_USERINFO_ENDPOINT"),
    revocation: reqEnv(env, "COGNITO_REVOCATION_ENDPOINT"),
    jwks: reqEnv(env, "COGNITO_JWKS_URI"),
    resourceScopes: (env.RESOURCE_SCOPES ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    userClientId: resolved.userClientId,
    userClientSecret: resolved.userClientSecret,
    allowedClientRedirectUris: parseAllowedCallbackUrls(
      resolved.allowedCallbackUrls,
    ),
    // Empty (not missing) is the intended "proxy disabled" sentinel.
    hmacKey: env.OAUTH_STATE_HMAC_KEY ?? "",
  };
}
