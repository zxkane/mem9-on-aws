/** Operator configuration; evaluated before creating any application resources. */
type Env = Record<string, string | undefined>;
export type TokenAuthMethod =
  | "none"
  | "client_secret_basic"
  | "client_secret_post";
export interface OidcConfig {
  issuer: string;
  discoveryUrl: string;
  clientId: string;
  clientSecret?: string;
  tokenAuthMethod: TokenAuthMethod;
  m2mClientId?: string;
  m2mClientSecret?: string;
  audience?: string;
  clientIdClaim: string;
  authorizeEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  userInfoEndpoint: string;
  revocationEndpoint: string;
}
export interface AuthConfig {
  mode: "managed" | "oidc";
  retainManaged: boolean;
  requiredGroup?: string;
  groupClaim: string;
  oidc?: OidcConfig;
}
function text(env: Env, name: string): string | undefined {
  const value = env[name];
  if (!value) return undefined;
  if (value !== value.trim() || value.length > 2048)
    throw new Error(`Invalid ${name}`);
  return value;
}
function https(value: unknown, name: string): string {
  if (typeof value !== "string") throw new Error(`Missing ${name}`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`Invalid ${name}`);
  }
  if (
    url.protocol !== "https:" ||
    !url.hostname ||
    url.username ||
    url.password ||
    url.hash ||
    url.search ||
    value !== value.trim()
  )
    throw new Error(`Invalid HTTPS ${name}`);
  return value;
}
export function readAuthConfig(env: Env = process.env): AuthConfig {
  const mode = text(env, "MEM9_AUTH_MODE") ?? "managed";
  if (mode !== "managed" && mode !== "oidc")
    throw new Error("MEM9_AUTH_MODE must be managed or oidc");
  const retain = text(env, "MEM9_RETAIN_MANAGED_AUTH");
  if (retain && retain !== "1" && retain !== "0")
    throw new Error("MEM9_RETAIN_MANAGED_AUTH must be 0 or 1");
  const base: AuthConfig = {
    mode,
    retainManaged: retain === "1",
    requiredGroup: text(env, "MEM9_AUTH_REQUIRED_GROUP"),
    groupClaim:
      text(env, "MEM9_AUTH_GROUP_CLAIM") ??
      (mode === "managed" ? "cognito:groups" : "groups"),
  };
  for (const value of [base.groupClaim, base.requiredGroup])
    if (value !== undefined && !/^[\x21-\x7e]{1,256}$/u.test(value))
      throw new Error("Invalid authentication group setting");
  if (mode === "managed") {
    if (
      Object.keys(env).some(
        (key) =>
          (key.startsWith("MEM9_OIDC_") ||
            [
              "SST_SECRET_OidcClientSecret",
              "SST_SECRET_OidcM2mClientSecret",
            ].includes(key)) &&
          env[key],
      )
    )
      throw new Error("OIDC settings require MEM9_AUTH_MODE=oidc");
    return base;
  }
  const issuer = https(text(env, "MEM9_OIDC_ISSUER"), "MEM9_OIDC_ISSUER");
  const clientId = text(env, "MEM9_OIDC_CLIENT_ID");
  if (!clientId) throw new Error("MEM9_OIDC_CLIENT_ID is required");
  const clientSecret = env.SST_SECRET_OidcClientSecret || undefined;
  const method =
    text(env, "MEM9_OIDC_TOKEN_AUTH_METHOD") ??
    (clientSecret ? "client_secret_basic" : "none");
  if (
    !["none", "client_secret_basic", "client_secret_post"].includes(method) ||
    (method === "none") === Boolean(clientSecret)
  )
    throw new Error(
      "OIDC token authentication method and client secret do not agree",
    );
  const m2mClientId = text(env, "MEM9_OIDC_M2M_CLIENT_ID");
  const m2mClientSecret = env.SST_SECRET_OidcM2mClientSecret || undefined;
  if (
    Boolean(m2mClientId) !== Boolean(m2mClientSecret) ||
    m2mClientId === clientId
  )
    throw new Error(
      "OIDC M2M requires a separate client ID and secret together",
    );
  const clientIdClaim = text(env, "MEM9_OIDC_CLIENT_ID_CLAIM") ?? "client_id";
  const audience = text(env, "MEM9_OIDC_AUDIENCE");
  for (const value of [clientId, m2mClientId, clientIdClaim, audience])
    if (value !== undefined && !/^[\x21-\x7e]{1,256}$/u.test(value))
      throw new Error("Invalid OIDC client or audience setting");
  if (
    audience === clientId ||
    (audience === m2mClientId && audience !== undefined)
  )
    throw new Error("API audience must differ from client IDs");
  if (clientIdClaim !== "client_id" && !audience)
    throw new Error(
      "A nonstandard OIDC client claim requires MEM9_OIDC_AUDIENCE",
    );
  return {
    ...base,
    oidc: {
      issuer,
      discoveryUrl: `${issuer.replace(
        /\/$/u,
        "",
      )}/.well-known/openid-configuration`,
      clientId,
      clientSecret,
      tokenAuthMethod: method as TokenAuthMethod,
      m2mClientId,
      m2mClientSecret,
      audience,
      clientIdClaim,
      authorizeEndpoint: "",
      tokenEndpoint: "",
      jwksUri: "",
      userInfoEndpoint: "",
      revocationEndpoint: "",
    },
  };
}
export async function resolveAuthConfig(
  env: Env = process.env,
  fetcher: typeof fetch = fetch,
): Promise<AuthConfig> {
  const config = readAuthConfig(env);
  const oidc = config.oidc;
  if (!oidc) return config;
  const response = await fetcher(oidc.discoveryUrl, {
    redirect: "error",
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw new Error("OIDC discovery request failed");
  const reader = response.body?.getReader();
  if (!reader) throw new Error("OIDC discovery is empty");
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const item = await reader.read();
    if (item.done) break;
    size += item.value.byteLength;
    if (size > 65536) {
      await reader.cancel();
      throw new Error("OIDC discovery is too large");
    }
    chunks.push(item.value);
  }
  let metadata: Record<string, unknown>;
  try {
    metadata = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new Error("Invalid OIDC discovery JSON");
  }
  if (!metadata || metadata.issuer !== oidc.issuer)
    throw new Error("OIDC discovery issuer mismatch");
  // Cognito's discovery omits S256 and advertises only confidential-client
  // methods even though its documented public-client flow supports PKCE.
  const cognito =
    /^https:\/\/cognito-idp\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?\/[a-z0-9-]+_[A-Za-z0-9]+$/u.test(
      oidc.issuer,
    );
  if (metadata.token_endpoint_auth_methods_supported === undefined)
    metadata.token_endpoint_auth_methods_supported = ["client_secret_basic"];
  for (const [key, required] of [
    ["response_types_supported", "code"],
    ["code_challenge_methods_supported", "S256"],
    ["token_endpoint_auth_methods_supported", oidc.tokenAuthMethod],
  ] as const) {
    if (
      (key === "code_challenge_methods_supported" &&
        metadata[key] === undefined) ||
      (cognito &&
        key === "token_endpoint_auth_methods_supported" &&
        required === "none")
    )
      continue;
    if (!Array.isArray(metadata[key]) || !metadata[key].includes(required))
      throw new Error(`OIDC discovery must support ${key}: ${required}`);
  }
  return {
    ...config,
    oidc: {
      ...oidc,
      authorizeEndpoint: https(
        metadata.authorization_endpoint,
        "authorization_endpoint",
      ),
      tokenEndpoint: https(metadata.token_endpoint, "token_endpoint"),
      jwksUri: https(metadata.jwks_uri, "jwks_uri"),
      userInfoEndpoint: metadata.userinfo_endpoint
        ? https(metadata.userinfo_endpoint, "userinfo_endpoint")
        : "",
      revocationEndpoint: metadata.revocation_endpoint
        ? https(metadata.revocation_endpoint, "revocation_endpoint")
        : "",
    },
  };
}
