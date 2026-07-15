/**
 * OAuth2 façade for the mem9 MCP surface (§6).
 *
 * Adapted from a proven OAuth2-façade router. One adaptation:
 *
 *   - Config is injected (`route(event, cfg)`) and resolved at runtime from
 *     env + SSM (`./config.ts`) — see that file for the SSM-at-runtime config.
 *     The routing logic below is unchanged and fully unit-testable without AWS.
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
 * - Claude Code's local callback listener picks a random ephemeral port;
 *   Cognito requires exact-match `callbackUrls`. The façade is the single
 *   registered redirect target and 302-redirects to the client's loopback
 *   port. State + the original client redirect_uri ride through Cognito as an
 *   HMAC-signed opaque blob so the proxy stays stateless.
 *
 * Routes: `/.well-known/*` metadata, `/oauth/authorize|callback|token|logout`,
 * `/register`, and a catch-all proxy to the AgentCore Gateway (`/mcp`).
 */

import { loadConfig, type FacadeConfig } from "./config.js";
import { signState, verifyState } from "./state.js";

interface ApiGwEvent {
  rawPath?: string;
  path?: string;
  rawQueryString?: string;
  headers?: Record<string, string>;
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
}

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

function redirect(location: string): ApiGwResponse {
  return {
    statusCode: 302,
    headers: { location, "cache-control": "no-store" },
    body: "",
  };
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
 * Native-app loopback redirect_uri validation (RFC 8252 §7.3). Without this
 * the façade would be an open redirector leaking auth codes to attacker URLs.
 * Claude Code's MCP transport uses a loopback address with an arbitrary port.
 */
export function isAllowedClientRedirect(uri: string): boolean {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  if (url.protocol !== "http:") return false;
  return (
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "[::1]" ||
    url.hostname === "::1"
  );
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

  // RFC 9728 — Protected Resource Metadata.
  if (path === "/.well-known/oauth-protected-resource") {
    return json(200, {
      resource: `${base}/mcp`,
      authorization_servers: [base],
      scopes_supported: cfg.resourceScopes,
      bearer_methods_supported: ["header"],
    });
  }

  // RFC 8414 — Authorization Server Metadata. authorize/token point at the
  // façade so clients hit the redirect proxy; the rest pass through to Cognito.
  if (path === "/.well-known/oauth-authorization-server") {
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
  if (path === "/.well-known/openid-configuration") {
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

  // GET /oauth/authorize — wrap state + client redirect_uri into an
  // HMAC-signed token, then 302 to Cognito Hosted UI.
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
    if (!isAllowedClientRedirect(clientRedirect)) {
      return json(400, {
        error: "invalid_request",
        error_description:
          "redirect_uri must be a loopback (http://localhost or http://127.0.0.1) URL",
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

    const facadeState = signState(
      { cs: clientState, r: clientRedirect },
      cfg.hmacKey,
      Date.now(),
    );

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
    return redirect(`${cfg.authorize}?${out.toString()}`);
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

    const decoded = verifyState(facadeState, cfg.hmacKey, Date.now());
    if (!decoded) {
      logEvent("oauth.callback.bad_state", {});
      return json(400, {
        error: "invalid_state",
        error_description: "state HMAC failed or token expired",
      });
    }
    // Defense-in-depth: re-enforce loopback at the redirect step.
    if (!isAllowedClientRedirect(decoded.r)) {
      logEvent("oauth.callback.non_loopback_redirect", {});
      return json(400, {
        error: "invalid_state",
        error_description: "decoded redirect_uri is not a loopback URL",
      });
    }

    const out = new URLSearchParams();
    if (code) out.set("code", code);
    if (error) {
      out.set("error", error);
      const errDesc = params.get("error_description");
      if (errDesc) out.set("error_description", errDesc);
    }
    out.set("state", decoded.cs);

    logEvent("oauth.callback", { ok: !error, error: error ?? null });
    return redirect(`${decoded.r}?${out.toString()}`);
  }

  // POST /oauth/token — replace the client redirect_uri with the façade's so
  // Cognito's redirect_uri-replay check matches the single registered URL.
  if (path === "/oauth/token" && method === "POST") {
    const rawBody = event.isBase64Encoded
      ? Buffer.from(event.body ?? "", "base64").toString("utf8")
      : (event.body ?? "");
    const inForm = new URLSearchParams(rawBody);

    const clientRedirect = inForm.get("redirect_uri");
    if (clientRedirect && !isAllowedClientRedirect(clientRedirect)) {
      return json(400, {
        error: "invalid_request",
        error_description: "redirect_uri must be a loopback URL",
      });
    }

    if (
      inForm.has("redirect_uri") ||
      inForm.get("grant_type") === "authorization_code"
    ) {
      inForm.set("redirect_uri", `${base}/oauth/callback`);
    }

    const fwdHeaders: Record<string, string> = {
      "content-type": "application/x-www-form-urlencoded",
    };
    const incomingAuth =
      event.headers?.authorization ?? event.headers?.Authorization;
    if (incomingAuth) fwdHeaders["authorization"] = incomingAuth;

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

    const clientAuth = incomingAuth
      ? "basic"
      : inForm.has("client_secret")
        ? "post"
        : "none";
    logEvent("oauth.token", {
      grant_type: inForm.get("grant_type") ?? null,
      client_auth: clientAuth,
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

  // RFC 7591 — Dynamic Client Registration (returns the pre-provisioned
  // reader client to every caller).
  if (path === "/register" && method === "POST") {
    let req: { redirect_uris?: string[] } = {};
    try {
      req = JSON.parse(event.body ?? "{}");
    } catch {
      // minimal payloads are fine
    }
    return json(201, {
      client_id: cfg.userClientId,
      client_secret: cfg.userClientSecret,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_secret_expires_at: 0,
      redirect_uris: req.redirect_uris ?? ["http://localhost:8080/callback"],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_post",
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
