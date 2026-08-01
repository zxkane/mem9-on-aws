/**
 * OAuth2 façade for the mem9 MCP surface (§6).
 *
 * Adapted from a proven OAuth2-façade router:
 *
 *   - Config is injected (`route(event, cfg)`) and resolved at runtime from
 *     env + SSM (`./config.ts`) — see that file for the SSM-at-runtime config.
 *     The router remains fully unit-testable without AWS.
 *
 * The façade is fronted by an `ApiGatewayV2` HTTP API (NOT a Lambda Function
 * URL — that would expose an open `Principal: "*"` resource policy). The event
 * payload is API-GW-v2 format 2.0
 * (`rawPath`, `requestContext.http.method`, `rawQueryString`), which is what
 * this handler reads — identical to the Function-URL payload shape, so the
 * routing logic is independent of the entry resource.
 *
 * Why a façade at all (verbatim rationale from the reference):
 * - Claude Code's OAuth client needs RFC 8414 / RFC 9728 metadata + RFC 7591
 *   DCR, none of which Cognito serves at the discovery path the Gateway
 *   advertises.
 * - Native clients can pick a random loopback port, while hosted clients use
 *   stage-configured exact HTTPS callbacks; Cognito requires static
 *   `callbackUrls`. The façade is the single registered Cognito target and
 *   302-redirects to the validated client URL. State + the original
 *   redirect_uri are held in a short-lived HMAC-signed HttpOnly cookie while a
 *   compact signed nonce rides through Cognito. This keeps third-party client
 *   state out of Cognito's bounded `state` parameter without adding server-side
 *   session storage.
 *
 * Routes: `/.well-known/*` metadata, `/oauth/authorize|callback|token|logout`,
 * `/register`, and a catch-all proxy to the AgentCore Gateway (`/mcp`).
 */

import { randomBytes } from "node:crypto";

import { loadConfig, type FacadeConfig } from "./config.js";
import {
  COGNITO_STATE_MAX_LENGTH,
  SIGNED_PAYLOAD_TTL_SECONDS,
  signAuthorizationCode,
  signOAuthTransaction,
  signState,
  verifyAuthorizationCode,
  verifyOAuthTransaction,
  verifyState,
} from "./state.js";

interface ApiGwEvent {
  rawPath?: string;
  path?: string;
  rawQueryString?: string;
  headers?: Record<string, string>;
  cookies?: string[];
  body?: string;
  isBase64Encoded?: boolean;
  requestContext?: {
    http?: { method?: string };
    domainName?: string;
  };
  httpMethod?: string;
}

interface ApiGwResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  cookies?: string[];
}

const OAUTH_STATE_COOKIE_NAME = "__Secure-mem9-oauth";
const OAUTH_STATE_COOKIE_PATH = "/oauth/callback";
const OAUTH_STATE_COOKIE_MAX_BYTES = 4096;
const OAUTH_STATE_HANDLE_MARKER = "cookie-v1";
const OAUTH_STATE_NONCE_BYTES = 16;
const OAUTH_STATE_NONCE_LENGTH = Math.ceil((OAUTH_STATE_NONCE_BYTES * 4) / 3);
const OAUTH_STATE_NONCE_PATTERN = new RegExp(
  `^[A-Za-z0-9_-]{${OAUTH_STATE_NONCE_LENGTH}}$`,
  "u",
);

function json(
  status: number,
  body: unknown,
  extraHeaders: Record<string, string> = {},
): ApiGwResponse {
  return {
    statusCode: status,
    headers: { "content-type": "application/json", ...extraHeaders },
    body: JSON.stringify(body),
  };
}

function redirect(location: string, cookies?: string[]): ApiGwResponse {
  return {
    statusCode: 302,
    headers: { location, "cache-control": "no-store" },
    body: "",
    ...(cookies?.length ? { cookies } : {}),
  };
}

function stateCookie(name: string, value: string, maxAge: number): string {
  return [
    `${name}=${value}`,
    `Max-Age=${maxAge}`,
    `Path=${OAUTH_STATE_COOKIE_PATH}`,
    "Secure",
    "HttpOnly",
    "SameSite=Lax",
  ].join("; ");
}

function createTransactionCookie(
  clientState: string,
  clientRedirect: string,
  hmacKey: string,
  now: number,
  nonce: string,
): string | null {
  const transaction = signOAuthTransaction(
    {
      nonce,
      clientState,
      redirectUri: clientRedirect,
    },
    hmacKey,
    now,
  );
  const cookie = stateCookie(
    OAUTH_STATE_COOKIE_NAME,
    transaction,
    SIGNED_PAYLOAD_TTL_SECONDS,
  );
  return Buffer.byteLength(cookie, "utf8") <= OAUTH_STATE_COOKIE_MAX_BYTES
    ? cookie
    : null;
}

function canFitTransactionCookie(clientRedirect: string): boolean {
  return (
    createTransactionCookie(
      "",
      clientRedirect,
      "",
      1_000_000_000_000,
      "n".repeat(OAUTH_STATE_NONCE_LENGTH),
    ) !== null
  );
}

function readCookie(event: ApiGwEvent, name: string): string | null {
  const values: string[] = [];
  for (const header of event.cookies ?? []) {
    for (const pair of header.split(";")) {
      const separator = pair.indexOf("=");
      if (separator < 0) continue;
      if (pair.slice(0, separator).trim() !== name) continue;
      values.push(pair.slice(separator + 1).trim());
    }
  }
  return values.length === 1 ? values[0]! : null;
}

function selfBaseUrl(event: ApiGwEvent): string {
  const host = event.headers?.host ?? event.requestContext?.domainName;
  return `https://${host}`;
}

function logEvent(name: string, fields: Record<string, unknown>): void {
  // One structured line per OAuth step. No token bodies — only grant_type /
  // outcome / non-secret query params.
  console.log(JSON.stringify({ event: name, ...fields }));
}

function ensureHmacConfigured(cfg: FacadeConfig): ApiGwResponse | null {
  if (!cfg.hmacKey) {
    return json(503, {
      error: "server_misconfigured",
      error_description:
        "OAUTH_STATE_HMAC_KEY is not set; the OAuth2 redirect proxy is unavailable.",
    });
  }
  return null;
}

/**
 * Native-app loopback redirect_uri validation (RFC 8252 §7.3) plus exact-match
 * HTTPS callbacks configured for hosted clients. Without this the façade would
 * be an open redirector leaking auth codes to attacker URLs.
 */
export function isAllowedClientRedirect(
  uri: string,
  allowedHttpsUris: readonly string[] = [],
): boolean {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  if (url.protocol === "http:") {
    return (
      url.hostname === "localhost" ||
      url.hostname === "127.0.0.1" ||
      url.hostname === "[::1]" ||
      url.hostname === "::1"
    );
  }
  return url.protocol === "https:" && allowedHttpsUris.includes(uri);
}

/** Pure router — all façade logic; config injected so tests need no AWS. */
export async function route(
  event: ApiGwEvent,
  cfg: FacadeConfig,
): Promise<ApiGwResponse> {
  const path = event.rawPath ?? event.path ?? "/";
  const method =
    event.requestContext?.http?.method ?? event.httpMethod ?? "GET";
  const base = selfBaseUrl(event);

  // Per RFC 9728 §3.1 / RFC 8414 §3.1, a client that found the resource at
  // `<base>/mcp` queries the metadata at the resource-suffixed well-known path
  // (`/.well-known/<doc>/mcp`), then falls back to the bare path. Our API
  // Gateway sends every path to this handler via `ANY /{proxy+}`, so a suffixed
  // well-known path that we don't match here would fall through to the catch-all
  // proxy and return the RAW AgentCore Gateway's Cognito metadata (no `/register`
  // DCR) — which is exactly what broke a spec-compliant MCP client. Normalize by
  // stripping a trailing `/mcp` from any well-known path so the bare and
  // resource-suffixed variants both resolve to the façade's own metadata.
  const wellKnown = path.startsWith("/.well-known/")
    ? path.replace(/\/mcp$/, "")
    : path;

  // RFC 9728 — Protected Resource Metadata.
  if (wellKnown === "/.well-known/oauth-protected-resource") {
    return json(200, {
      resource: `${base}/mcp`,
      authorization_servers: [base],
      scopes_supported: cfg.resourceScopes,
      bearer_methods_supported: ["header"],
    });
  }

  // RFC 8414 — Authorization Server Metadata. authorize/token point at the
  // façade so clients hit the redirect proxy; the rest pass through to Cognito.
  if (wellKnown === "/.well-known/oauth-authorization-server") {
    return json(200, {
      issuer: cfg.issuer,
      authorization_endpoint: `${base}/oauth/authorize`,
      token_endpoint: `${base}/oauth/token`,
      userinfo_endpoint: cfg.userinfo,
      revocation_endpoint: cfg.revocation,
      jwks_uri: cfg.jwks,
      registration_endpoint: `${base}/register`,
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: [
        "none",
        "client_secret_basic",
        "client_secret_post",
      ],
      // Advertise only what the reader client actually allows: openid + email
      // + the read resource scope. `profile` and the `write` scope are NOT in
      // the reader client's allowedOauthScopes, so advertising them here would
      // make a client that requests the full set fail Cognito's authorize step
      // with `invalid_scope`.
      scopes_supported: ["openid", "email", ...cfg.resourceScopes],
    });
  }

  // OIDC discovery (some clients only know this path).
  if (wellKnown === "/.well-known/openid-configuration") {
    return json(200, {
      issuer: cfg.issuer,
      authorization_endpoint: `${base}/oauth/authorize`,
      token_endpoint: `${base}/oauth/token`,
      userinfo_endpoint: cfg.userinfo,
      revocation_endpoint: cfg.revocation,
      jwks_uri: cfg.jwks,
      registration_endpoint: `${base}/register`,
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      code_challenge_methods_supported: ["S256"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      // Aligned with the reader client's allowedOauthScopes (no `profile`, no
      // `write`) — see the oauth-authorization-server metadata above.
      scopes_supported: ["openid", "email", ...cfg.resourceScopes],
    });
  }

  // GET /oauth/authorize — store state + client redirect_uri in a signed
  // callback cookie, then send a compact signed nonce to Cognito Hosted UI.
  if (path === "/oauth/authorize" && method === "GET") {
    const misconfigured = ensureHmacConfigured(cfg);
    if (misconfigured) return misconfigured;

    const inParams = new URLSearchParams(event.rawQueryString ?? "");
    const clientRedirect = inParams.get("redirect_uri");
    const clientState = inParams.get("state") ?? "";
    if (!clientRedirect) {
      return json(400, {
        error: "invalid_request",
        error_description: "missing redirect_uri",
      });
    }
    if (
      !isAllowedClientRedirect(
        clientRedirect,
        cfg.allowedClientRedirectUris,
      )
    ) {
      return json(400, {
        error: "invalid_request",
        error_description:
          "redirect_uri must be an allowed callback URL",
      });
    }
    // Require PKCE so the auth code is useless without the code_verifier.
    if (!inParams.get("code_challenge")) {
      return json(400, {
        error: "invalid_request",
        error_description: "code_challenge is required (PKCE)",
      });
    }
    // Enforce S256 explicitly. A missing `code_challenge_method` defaults to
    // `plain` per RFC 7636 §4.3, so silently accepting it would let the flow
    // fall back to non-S256 PKCE even though our discovery metadata advertises
    // `code_challenge_methods_supported: ["S256"]`. Reject anything that is not
    // exactly `S256` (missing, `plain`, or any other value).
    const challengeMethod = inParams.get("code_challenge_method");
    if (challengeMethod !== "S256") {
      return json(400, {
        error: "invalid_request",
        error_description: "code_challenge_method must be S256",
      });
    }

    const now = Date.now();
    const nonce = randomBytes(OAUTH_STATE_NONCE_BYTES).toString("base64url");
    const transactionCookie = createTransactionCookie(
      clientState,
      clientRedirect,
      cfg.hmacKey,
      now,
      nonce,
    );
    if (!transactionCookie) {
      return json(400, {
        error: "invalid_request",
        error_description:
          "redirect_uri and state exceed the supported cookie length",
      });
    }

    const facadeState = signState(
      { cs: nonce, r: OAUTH_STATE_HANDLE_MARKER },
      cfg.hmacKey,
      now,
    );
    if (facadeState.length > COGNITO_STATE_MAX_LENGTH) {
      return json(500, {
        error: "server_error",
        error_description: "generated OAuth state exceeds the upstream limit",
      });
    }

    const out = new URLSearchParams();
    for (const [k, v] of inParams.entries()) {
      if (k === "redirect_uri" || k === "state") continue;
      out.append(k, v);
    }
    out.set("redirect_uri", `${base}/oauth/callback`);
    out.set("state", facadeState);

    logEvent("oauth.authorize", {
      client_id: inParams.get("client_id") ?? null,
      has_pkce: inParams.get("code_challenge") !== null,
    });
    return redirect(`${cfg.authorize}?${out.toString()}`, [
      transactionCookie,
    ]);
  }

  // GET /oauth/callback — verify HMAC, decode original client state +
  // redirect_uri, then 302 back to that client URL with the upstream code.
  if (path === "/oauth/callback" && method === "GET") {
    const misconfigured = ensureHmacConfigured(cfg);
    if (misconfigured) return misconfigured;

    const params = new URLSearchParams(event.rawQueryString ?? "");
    const code = params.get("code");
    const facadeState = params.get("state");
    const error = params.get("error");

    if (!facadeState) {
      return json(400, {
        error: "invalid_request",
        error_description: "missing state",
      });
    }

    const now = Date.now();
    const handle = verifyState(facadeState, cfg.hmacKey, now);
    if (
      !handle ||
      handle.r !== OAUTH_STATE_HANDLE_MARKER ||
      !OAUTH_STATE_NONCE_PATTERN.test(handle.cs)
    ) {
      logEvent("oauth.callback.bad_state", {});
      return json(400, {
        error: "invalid_state",
        error_description: "state HMAC failed or token expired",
      });
    }
    const clearStateCookie = stateCookie(OAUTH_STATE_COOKIE_NAME, "", 0);
    const transaction = readCookie(event, OAUTH_STATE_COOKIE_NAME);
    const signedTransaction = transaction
      ? verifyOAuthTransaction(transaction, cfg.hmacKey, now)
      : null;
    if (!signedTransaction) {
      logEvent("oauth.callback.bad_state_cookie", {});
      const response = json(400, {
        error: "invalid_state",
        error_description: "OAuth state cookie is missing, invalid, or expired",
      });
      response.cookies = [clearStateCookie];
      return response;
    }
    if (signedTransaction.nonce !== handle.cs) {
      // A newer authorization may have replaced the single transaction slot.
      // Do not let a stale callback clear that newer, otherwise valid cookie.
      logEvent("oauth.callback.stale_state_cookie", {});
      return json(400, {
        error: "invalid_state",
        error_description: "OAuth state cookie does not match this request",
      });
    }
    const clientState = signedTransaction.clientState;
    const clientRedirect = signedTransaction.redirectUri;
    // Defense-in-depth: re-enforce the current allowlist at the redirect step.
    if (
      !isAllowedClientRedirect(clientRedirect, cfg.allowedClientRedirectUris)
    ) {
      logEvent("oauth.callback.disallowed_redirect", {});
      const response = json(400, {
        error: "invalid_state",
        error_description: "decoded redirect_uri is not allowed",
      });
      response.cookies = [clearStateCookie];
      return response;
    }

    const out = new URLSearchParams();
    if (code) {
      out.set(
        "code",
        signAuthorizationCode(
          { code, redirectUri: clientRedirect },
          cfg.hmacKey,
          now,
        ),
      );
    }
    if (error) {
      out.set("error", error);
      const errDesc = params.get("error_description");
      if (errDesc) out.set("error_description", errDesc);
    }
    out.set("state", clientState);

    logEvent("oauth.callback", { ok: !error, error: error ?? null });
    const redirectUrl = new URL(clientRedirect);
    for (const key of ["code", "error", "error_description", "state"]) {
      redirectUrl.searchParams.delete(key);
    }
    for (const [key, value] of out) redirectUrl.searchParams.set(key, value);
    return redirect(redirectUrl.toString(), [clearStateCookie]);
  }

  // POST /oauth/token — replace the client redirect_uri with the façade's so
  // Cognito's redirect_uri-replay check matches the single registered URL.
  // Public-client support: when no Authorization header AND no client_secret in
  // the form body, the façade injects the Cognito confidential-client secret
  // server-side — so PKCE-only clients (Codex) work without holding a secret.
  if (path === "/oauth/token" && method === "POST") {
    const rawBody = event.isBase64Encoded
      ? Buffer.from(event.body ?? "", "base64").toString("utf8")
      : (event.body ?? "");
    const inForm = new URLSearchParams(rawBody);

    const grantType = inForm.get("grant_type");
    const clientRedirect = inForm.get("redirect_uri");
    if (grantType === "authorization_code") {
      const misconfigured = ensureHmacConfigured(cfg);
      if (misconfigured) return misconfigured;
      if (!clientRedirect) {
        return json(400, {
          error: "invalid_request",
          error_description:
            "redirect_uri is required for authorization_code exchange",
        });
      }
      if (
        !isAllowedClientRedirect(
          clientRedirect,
          cfg.allowedClientRedirectUris,
        )
      ) {
        return json(400, {
          error: "invalid_request",
          error_description: "redirect_uri must be an allowed callback URL",
        });
      }

      const clientCode = inForm.get("code");
      if (!clientCode) {
        return json(400, {
          error: "invalid_request",
          error_description: "code is required for authorization_code exchange",
        });
      }
      const codePayload = verifyAuthorizationCode(
        clientCode,
        cfg.hmacKey,
        Date.now(),
      );
      if (!codePayload || codePayload.r !== clientRedirect) {
        return json(400, {
          error: "invalid_grant",
          error_description:
            "authorization code is invalid or redirect_uri does not match",
        });
      }
      inForm.set("code", codePayload.c);
    } else if (
      clientRedirect &&
      !isAllowedClientRedirect(
        clientRedirect,
        cfg.allowedClientRedirectUris,
      )
    ) {
      return json(400, {
        error: "invalid_request",
        error_description: "redirect_uri must be an allowed callback URL",
      });
    }

    if (inForm.has("redirect_uri") || grantType === "authorization_code") {
      inForm.set("redirect_uri", `${base}/oauth/callback`);
    }

    const fwdHeaders: Record<string, string> = {
      "content-type": "application/x-www-form-urlencoded",
    };
    const incomingAuth =
      event.headers?.authorization ?? event.headers?.Authorization;
    if (incomingAuth) fwdHeaders["authorization"] = incomingAuth;

    // Classify how the CLIENT authenticated, read before any server-side
    // mutation. The public-client injection below sets client_secret, so
    // deriving this afterward would mislabel a secretless client as "post".
    let clientAuth: "basic" | "post" | "none";
    if (incomingAuth) clientAuth = "basic";
    else if (inForm.has("client_secret")) clientAuth = "post";
    else clientAuth = "none";

    // Public-client secret injection: when the client sent no authentication at
    // all (clientAuth === "none"), verify its client_id matches the known reader
    // client and inject the Cognito confidential-client secret so Cognito's token
    // endpoint accepts the request — PKCE-only clients (Codex) never hold it.
    let injectedSecret = false;
    if (clientAuth === "none") {
      const formClientId = inForm.get("client_id");
      if (formClientId !== cfg.userClientId) {
        logEvent("oauth.token.public_client_rejected", {
          client_id: formClientId ?? null,
        });
        return json(401, {
          error: "invalid_client",
          error_description:
            "Unknown client_id for unauthenticated token request.",
        });
      }
      inForm.set("client_secret", cfg.userClientSecret);
      injectedSecret = true;
    }

    let upstream: Response;
    try {
      upstream = await fetch(cfg.token, {
        method: "POST",
        headers: fwdHeaders,
        body: inForm.toString(),
      });
    } catch (err) {
      logEvent("oauth.token.upstream_error", {
        error: err instanceof Error ? err.message : String(err),
      });
      return json(502, {
        error: "upstream_unreachable",
        error_description: "Failed to reach Cognito token endpoint",
      });
    }
    const respBody = await upstream.text();
    const respHeaders: Record<string, string> = {};
    upstream.headers.forEach((v, k) => {
      const lk = k.toLowerCase();
      if (lk === "content-length" || lk === "transfer-encoding") return;
      respHeaders[k] = v;
    });

    logEvent("oauth.token", {
      grant_type: inForm.get("grant_type") ?? null,
      client_auth: clientAuth,
      secret_injected: injectedSecret,
      status: upstream.status,
    });

    return { statusCode: upstream.status, headers: respHeaders, body: respBody };
  }

  // Cognito Hosted-UI sign-out landing.
  if (path === "/oauth/logout" && method === "GET") {
    logEvent("oauth.logout", {});
    return {
      statusCode: 200,
      headers: { "content-type": "text/plain", "cache-control": "no-store" },
      body: "Signed out.",
    };
  }

  // RFC 7591 — Dynamic Client Registration. The façade presents a PUBLIC
  // client: no secret is returned, auth method is "none". The Cognito
  // confidential-client secret is held server-side and injected at /oauth/token
  // for secretless requests — clients (Codex) that can't durably hold secrets
  // work with PKCE + refresh_token alone.
  if (path === "/register" && method === "POST") {
    let req: { redirect_uris?: string[]; token_endpoint_auth_method?: string } =
      {};
    try {
      req = JSON.parse(event.body ?? "{}");
    } catch {
      // minimal payloads are fine
    }
    // Reject requests that explicitly ask for secret-based authentication:
    // this endpoint only issues public-client registrations.
    if (
      req.token_endpoint_auth_method &&
      req.token_endpoint_auth_method !== "none"
    ) {
      return json(400, {
        error: "invalid_client_metadata",
        error_description:
          "Only token_endpoint_auth_method 'none' is supported (public client).",
      });
    }
    const redirectUris = req.redirect_uris ?? [
      "http://localhost:8080/callback",
    ];
    if (
      !Array.isArray(redirectUris) ||
      redirectUris.length === 0 ||
      redirectUris.some(
        (uri) =>
          typeof uri !== "string" ||
          !isAllowedClientRedirect(uri, cfg.allowedClientRedirectUris) ||
          !canFitTransactionCookie(uri),
      )
    ) {
      return json(400, {
        error: "invalid_redirect_uri",
        error_description:
          "redirect_uris must contain only allowed callback URLs",
      });
    }
    return json(201, {
      client_id: cfg.userClientId,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      redirect_uris: redirectUris,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      scope: ["openid", "email", ...cfg.resourceScopes].join(" "),
    });
  }

  // Catch-all proxy to the upstream AgentCore Gateway (`/mcp` + the rest).
  const upstreamUrl = new URL(cfg.upstream);
  upstreamUrl.pathname = path;
  if (event.rawQueryString) upstreamUrl.search = `?${event.rawQueryString}`;

  const fwdHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(event.headers ?? {})) {
    const lk = k.toLowerCase();
    if (lk === "host" || lk === "content-length" || lk === "x-forwarded-for")
      continue;
    fwdHeaders[k] = v;
  }

  const reqBody = event.isBase64Encoded
    ? Buffer.from(event.body ?? "", "base64")
    : event.body;

  const upstreamResp = await fetch(upstreamUrl.toString(), {
    method,
    headers: fwdHeaders,
    body: method === "GET" || method === "HEAD" ? undefined : reqBody,
  });

  const respHeaders: Record<string, string> = {};
  upstreamResp.headers.forEach((value, key) => {
    respHeaders[key] = value;
  });
  const respBody = await upstreamResp.text();

  // Rewrite WWW-Authenticate so resource_metadata points back at the façade.
  if (respHeaders["www-authenticate"]) {
    respHeaders["www-authenticate"] =
      `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource"`;
  }

  return {
    statusCode: upstreamResp.status,
    headers: respHeaders,
    body: respBody,
  };
}

/** Lambda handler — resolve config (env + SSM) once per cold start, then route. */
let configPromise: Promise<FacadeConfig> | undefined;

function getConfig(): Promise<FacadeConfig> {
  if (!configPromise) {
    configPromise = loadConfig().catch((err) => {
      configPromise = undefined;
      throw err;
    });
  }
  return configPromise;
}

export async function handler(event: ApiGwEvent): Promise<ApiGwResponse> {
  return route(event, await getConfig());
}

/** Test-only: drop the cold-start config singleton between cases. */
export function __resetForTests(): void {
  configPromise = undefined;
}
