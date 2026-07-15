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
 *
 * The remaining, non-cyclic values (Cognito endpoint URLs that depend only on
 * the user pool + domain, the HMAC key from the SST Secret, and the resource
 * scopes) are plain env vars. The SSM client is injected (`SsmLike`) so the
 * loader is unit-testable without AWS.
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

function reqEnv(env: Env, name: string): string {
  const v = env[name];
  if (!v) throw new Error(`missing env ${name}`);
  return v;
}

/** Resolve the three cyclic values from SSM (decrypting the client secret). */
export async function resolveSsm(
  prefix: string,
  ssm: SsmLike,
): Promise<{ upstream: string; userClientId: string; userClientSecret: string }> {
  const names = [
    `${prefix}/gateway/url`,
    `${prefix}/cognito/reader/client-id`,
    `${prefix}/cognito/reader/client-secret`,
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
    // Empty (not missing) is the intended "proxy disabled" sentinel.
    hmacKey: env.OAUTH_STATE_HMAC_KEY ?? "",
  };
}
