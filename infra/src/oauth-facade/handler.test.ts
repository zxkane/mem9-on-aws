/**
 * Unit tests for the façade routing (TC-MCPGW-060..078).
 * Exercised through the injected `route(event, cfg)` seam — no AWS/SSM.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { isAllowedClientRedirect, route } from "./handler.js";
import {
  signAuthorizationCode,
  signOAuthTransaction,
  verifyAuthorizationCode,
  verifyOAuthTransaction,
  verifyState,
} from "./state.js";
import type { FacadeConfig } from "./config.js";

const HOST = "abc123.lambda-url.ap-northeast-1.on.aws";
const BASE = `https://${HOST}`;
const HMAC = "unit-test-hmac-key";
const REMOTE_CALLBACK = "https://oauth.example.com/callback/app";

function cfg(overrides: Partial<FacadeConfig> = {}): FacadeConfig {
  return {
    upstream: "https://gateway.example/mcp-prefix",
    issuer: "https://cognito-idp.ap-northeast-1.amazonaws.com/pool",
    authorize: "https://auth.example.com/oauth2/authorize",
    token: "https://auth.example.com/oauth2/token",
    userinfo: "https://auth.example.com/oauth2/userInfo",
    revocation: "https://auth.example.com/oauth2/revoke",
    jwks: "https://cognito-idp.ap-northeast-1.amazonaws.com/pool/.well-known/jwks.json",
    // Reader-client-aligned: openid + email + read only (no write).
    resourceScopes: ["example-mcp/query/read"],
    userClientId: "reader-client-id",
    userClientSecret: "reader-client-secret",
    allowedClientRedirectUris: [],
    hmacKey: HMAC,
    ...overrides,
  };
}

function ev(
  path: string,
  method = "GET",
  opts: {
    query?: string;
    body?: string;
    headers?: Record<string, string>;
    cookies?: string[];
  } = {},
) {
  return {
    rawPath: path,
    rawQueryString: opts.query ?? "",
    headers: { host: HOST, ...(opts.headers ?? {}) },
    cookies: opts.cookies,
    body: opts.body,
    requestContext: { http: { method }, domainName: HOST },
  };
}

function requestCookies(
  response: { cookies?: string[] },
): string[] {
  return (response.cookies ?? []).map((cookie) => cookie.split(";", 1)[0]!);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("façade routing (TC-MCPGW-060..073)", () => {
  it("TC-MCPGW-060: protected-resource metadata points at <base>/mcp", async () => {
    const res = await route(ev("/.well-known/oauth-protected-resource"), cfg());
    expect(res.statusCode).toBe(200);
    const b = JSON.parse(res.body);
    expect(b.resource).toBe(`${BASE}/mcp`);
    expect(b.authorization_servers).toEqual([BASE]);
  });

  it("TC-MCPGW-061: AS metadata advertises the façade endpoints + S256", async () => {
    const res = await route(
      ev("/.well-known/oauth-authorization-server"),
      cfg(),
    );
    const b = JSON.parse(res.body);
    expect(b.authorization_endpoint).toBe(`${BASE}/oauth/authorize`);
    expect(b.token_endpoint).toBe(`${BASE}/oauth/token`);
    expect(b.code_challenge_methods_supported).toContain("S256");
    // Public-client support ("none") plus the legacy secret methods during
    // migration — clients that registered before the public-client change
    // still authenticate with Basic/Post.
    expect(b.token_endpoint_auth_methods_supported).toEqual([
      "none",
      "client_secret_basic",
      "client_secret_post",
    ]);
    // Advertised scopes must match the reader client's allowed scopes exactly
    // — no `profile`, no `write`.
    expect(b.scopes_supported).toEqual(["openid", "email", "example-mcp/query/read"]);
    expect(b.scopes_supported).not.toContain("profile");
    expect(b.scopes_supported).not.toContain("example-mcp/query/write");
  });

  it("TC-MCPGW-061b: OIDC discovery metadata advertises reader-aligned scopes (no profile/write)", async () => {
    const res = await route(ev("/.well-known/openid-configuration"), cfg());
    const b = JSON.parse(res.body);
    expect(b.scopes_supported).toEqual(["openid", "email", "example-mcp/query/read"]);
    expect(b.scopes_supported).not.toContain("profile");
    expect(b.scopes_supported).not.toContain("example-mcp/query/write");
  });

  it("TC-MCPGW-061c: resource-suffixed well-known paths (/.well-known/<doc>/mcp) return the FAÇADE metadata, not the raw Gateway", async () => {
    // A spec-compliant MCP client (RFC 9728/8414) queries the resource-suffixed
    // path first. Without normalization these fell through to the catch-all proxy
    // and returned the raw AgentCore Gateway's Cognito metadata (no /register DCR),
    // breaking discovery. All three must resolve to the façade's own metadata.
    const pr = JSON.parse(
      (await route(ev("/.well-known/oauth-protected-resource/mcp"), cfg())).body,
    );
    expect(pr.resource).toBe(`${BASE}/mcp`);
    expect(pr.authorization_servers).toEqual([BASE]);

    const as = JSON.parse(
      (await route(ev("/.well-known/oauth-authorization-server/mcp"), cfg())).body,
    );
    expect(as.authorization_endpoint).toBe(`${BASE}/oauth/authorize`);
    expect(as.registration_endpoint).toBe(`${BASE}/register`);

    const oidc = JSON.parse(
      (await route(ev("/.well-known/openid-configuration/mcp"), cfg())).body,
    );
    expect(oidc.registration_endpoint).toBe(`${BASE}/register`);
  });

  it("TC-MCPGW-062: /oauth/authorize sends Cognito a short signed handle and stores client state in a signed cookie", async () => {
    const q = new URLSearchParams({
      client_id: "c",
      redirect_uri: "http://127.0.0.1:5000/callback",
      state: "orig-state",
      code_challenge: "abc",
      code_challenge_method: "S256",
      response_type: "code",
    }).toString();
    const res = await route(ev("/oauth/authorize", "GET", { query: q }), cfg());
    expect(res.statusCode).toBe(302);
    const loc = new URL(res.headers.location);
    expect(loc.origin + loc.pathname).toBe(cfg().authorize);
    expect(loc.searchParams.get("redirect_uri")).toBe(`${BASE}/oauth/callback`);
    const decoded = verifyState(
      loc.searchParams.get("state")!,
      HMAC,
      Date.now(),
    );
    expect(decoded).not.toBeNull();
    expect(decoded!.r).not.toBe("http://127.0.0.1:5000/callback");
    expect(decoded!.cs).not.toBe("orig-state");

    const setCookie = (res as typeof res & { cookies: string[] }).cookies[0]!;
    expect(setCookie).toContain("Path=/oauth/callback");
    expect(setCookie).toContain("Secure");
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("SameSite=Lax");
    const transaction = verifyOAuthTransaction(
      setCookie.split(";", 1)[0]!.split("=", 2)[1]!,
      HMAC,
      Date.now(),
    );
    expect(transaction).toMatchObject({
      nonce: decoded!.cs,
      redirectUri: "http://127.0.0.1:5000/callback",
      clientState: "orig-state",
    });
  });

  it("TC-MCPGW-063: /oauth/authorize without redirect_uri → 400", async () => {
    const res = await route(
      ev("/oauth/authorize", "GET", { query: "code_challenge=x" }),
      cfg(),
    );
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toBe("invalid_request");
  });

  it("TC-MCPGW-064: /oauth/authorize with non-loopback redirect_uri → 400", async () => {
    const q = new URLSearchParams({
      redirect_uri: "https://evil.example/callback",
      code_challenge: "x",
    }).toString();
    const res = await route(ev("/oauth/authorize", "GET", { query: q }), cfg());
    expect(res.statusCode).toBe(400);
  });

  it("TC-MCPGW-065: /oauth/authorize without code_challenge (no PKCE) → 400", async () => {
    const q = new URLSearchParams({
      redirect_uri: "http://localhost:5000/cb",
    }).toString();
    const res = await route(ev("/oauth/authorize", "GET", { query: q }), cfg());
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error_description).toMatch(/code_challenge/);
  });

  it("TC-MCPGW-066: /oauth/authorize with plain PKCE → 400", async () => {
    const q = new URLSearchParams({
      redirect_uri: "http://localhost:5000/cb",
      code_challenge: "x",
      code_challenge_method: "plain",
    }).toString();
    const res = await route(ev("/oauth/authorize", "GET", { query: q }), cfg());
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error_description).toMatch(/S256/);
  });

  it("TC-MCPGW-066b: /oauth/authorize with code_challenge but no method → 400 (no silent plain fallback)", async () => {
    // RFC 7636 §4.3: an omitted code_challenge_method defaults to `plain`.
    // The façade must reject it rather than silently downgrade from S256.
    const q = new URLSearchParams({
      redirect_uri: "http://localhost:5000/cb",
      code_challenge: "x",
    }).toString();
    const res = await route(ev("/oauth/authorize", "GET", { query: q }), cfg());
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toBe("invalid_request");
    expect(JSON.parse(res.body).error_description).toMatch(/S256/);
  });

  it("TC-OAUTH-CALLBACK-012: preserves a hosted client's long opaque state without exceeding Cognito's limit", async () => {
    const clientState = "g".repeat(2200);
    const q = new URLSearchParams({
      redirect_uri: REMOTE_CALLBACK,
      state: clientState,
      code_challenge: "x",
      code_challenge_method: "S256",
    }).toString();
    const config = cfg({ allowedClientRedirectUris: [REMOTE_CALLBACK] });
    const authRes = await route(
      ev("/oauth/authorize", "GET", { query: q }),
      config,
    );
    expect(authRes.statusCode).toBe(302);
    const cognitoState = new URL(
      authRes.headers.location,
    ).searchParams.get("state");
    expect(cognitoState).toBeTruthy();
    expect(cognitoState!.length).toBeLessThanOrEqual(1024);

    const cookies = (authRes as typeof authRes & { cookies: string[] }).cookies;
    expect(cookies).toHaveLength(1);
    expect(Buffer.byteLength(cookies[0]!, "utf8")).toBeLessThanOrEqual(4096);
    expect(cookies[0]).toContain("HttpOnly");
    expect(cookies[0]).toContain("SameSite=Lax");

    const callbackQ = new URLSearchParams({
      code: "auth-code-xyz",
      state: cognitoState!,
    }).toString();
    const callbackRes = await route(
      ev("/oauth/callback", "GET", {
        query: callbackQ,
        cookies: requestCookies({ cookies }),
      }),
      config,
    );
    expect(callbackRes.statusCode).toBe(302);
    const clientLocation = new URL(callbackRes.headers.location);
    expect(clientLocation.origin + clientLocation.pathname).toBe(
      REMOTE_CALLBACK,
    );
    expect(clientLocation.searchParams.get("state")).toBe(clientState);
    expect(
      (callbackRes as typeof callbackRes & { cookies: string[] }).cookies[0],
    ).toContain("Max-Age=0");
  });

  it("TC-MCPGW-067: /oauth/callback 302s back to the client loopback with code + orig state", async () => {
    // Sign a state the way /oauth/authorize would.
    const authQ = new URLSearchParams({
      redirect_uri: "http://127.0.0.1:5000/callback",
      state: "orig-state",
      code_challenge: "x",
      code_challenge_method: "S256",
    }).toString();
    const authRes = await route(
      ev("/oauth/authorize", "GET", { query: authQ }),
      cfg(),
    );
    const facadeState = new URL(authRes.headers.location).searchParams.get(
      "state",
    )!;

    const cbQ = new URLSearchParams({
      code: "auth-code-xyz",
      state: facadeState,
    }).toString();
    const res = await route(
      ev("/oauth/callback", "GET", {
        query: cbQ,
        cookies: requestCookies(authRes),
      }),
      cfg(),
    );
    expect(res.statusCode).toBe(302);
    const loc = new URL(res.headers.location);
    expect(loc.origin + loc.pathname).toBe("http://127.0.0.1:5000/callback");
    expect(
      verifyAuthorizationCode(loc.searchParams.get("code")!, HMAC, Date.now()),
    ).toMatchObject({
      c: "auth-code-xyz",
      r: "http://127.0.0.1:5000/callback",
    });
    expect(loc.searchParams.get("state")).toBe("orig-state");
  });

  it("TC-MCPGW-068: /oauth/callback with a bad state → 400 invalid_state", async () => {
    const q = new URLSearchParams({
      code: "c",
      state: "garbage.state",
    }).toString();
    const res = await route(ev("/oauth/callback", "GET", { query: q }), cfg());
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toBe("invalid_state");
  });

  it("TC-OAUTH-CALLBACK-013: rejects a valid Cognito state handle when its transaction cookie is missing", async () => {
    const authQ = new URLSearchParams({
      redirect_uri: "http://127.0.0.1:5000/callback",
      state: "orig-state",
      code_challenge: "x",
      code_challenge_method: "S256",
    }).toString();
    const authRes = await route(
      ev("/oauth/authorize", "GET", { query: authQ }),
      cfg(),
    );
    const state = new URL(authRes.headers.location).searchParams.get("state")!;

    const res = await route(
      ev("/oauth/callback", "GET", {
        query: new URLSearchParams({ code: "c", state }).toString(),
      }),
      cfg(),
    );
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toBe("invalid_state");
    expect((res as typeof res & { cookies: string[] }).cookies[0]).toContain(
      "Max-Age=0",
    );
  });

  it("TC-OAUTH-CALLBACK-013: rejects tampered or duplicate transaction cookies", async () => {
    const authQ = new URLSearchParams({
      redirect_uri: "http://127.0.0.1:5000/callback",
      state: "orig-state",
      code_challenge: "x",
      code_challenge_method: "S256",
    }).toString();
    const authRes = await route(
      ev("/oauth/authorize", "GET", { query: authQ }),
      cfg(),
    );
    const state = new URL(authRes.headers.location).searchParams.get("state")!;
    const cookie = requestCookies(authRes)[0]!;
    const query = new URLSearchParams({ code: "c", state }).toString();

    const tampered = await route(
      ev("/oauth/callback", "GET", {
        query,
        cookies: [`${cookie}x`],
      }),
      cfg(),
    );
    expect(tampered.statusCode).toBe(400);
    expect(JSON.parse(tampered.body).error).toBe("invalid_state");

    const duplicate = await route(
      ev("/oauth/callback", "GET", {
        query,
        cookies: [cookie, cookie],
      }),
      cfg(),
    );
    expect(duplicate.statusCode).toBe(400);
    expect(JSON.parse(duplicate.body).error).toBe("invalid_state");
  });

  it("TC-OAUTH-CALLBACK-013: rejects an expired transaction cookie", async () => {
    const authQ = new URLSearchParams({
      redirect_uri: "http://127.0.0.1:5000/callback",
      state: "orig-state",
      code_challenge: "x",
      code_challenge_method: "S256",
    }).toString();
    const authRes = await route(
      ev("/oauth/authorize", "GET", { query: authQ }),
      cfg(),
    );
    const state = new URL(authRes.headers.location).searchParams.get("state")!;
    const handle = verifyState(state, HMAC, Date.now())!;
    const cookie = requestCookies(authRes)[0]!;
    const cookieName = cookie.slice(0, cookie.indexOf("="));
    const expiredTransaction = signOAuthTransaction(
      {
        nonce: handle.cs,
        clientState: "orig-state",
        redirectUri: "http://127.0.0.1:5000/callback",
      },
      HMAC,
      Date.now() - 11 * 60 * 1000,
    );

    const res = await route(
      ev("/oauth/callback", "GET", {
        query: new URLSearchParams({ code: "c", state }).toString(),
        cookies: [`${cookieName}=${expiredTransaction}`],
      }),
      cfg(),
    );
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toBe("invalid_state");
  });

  it("binds one fixed transaction-cookie slot and preserves a newer transaction from a stale callback", async () => {
    const authorize = async (clientState: string) => {
      const query = new URLSearchParams({
        redirect_uri: "http://127.0.0.1:5000/callback",
        state: clientState,
        code_challenge: "x",
        code_challenge_method: "S256",
      }).toString();
      return route(ev("/oauth/authorize", "GET", { query }), cfg());
    };
    const first = await authorize("first-state");
    const second = await authorize("second-state");
    const firstCookie = requestCookies(first)[0]!;
    const secondCookie = requestCookies(second)[0]!;
    const firstCookieName = firstCookie.slice(0, firstCookie.indexOf("="));
    const secondCookieName = secondCookie.slice(0, secondCookie.indexOf("="));
    expect(secondCookieName).toBe(firstCookieName);
    const firstState = new URL(first.headers.location).searchParams.get("state")!;
    const secondState = new URL(second.headers.location).searchParams.get(
      "state",
    )!;

    const stale = await route(
      ev("/oauth/callback", "GET", {
        query: new URLSearchParams({
          code: "c",
          state: firstState,
        }).toString(),
        cookies: [secondCookie],
      }),
      cfg(),
    );
    expect(stale.statusCode).toBe(400);
    expect(JSON.parse(stale.body).error).toBe("invalid_state");
    expect(stale.cookies).toBeUndefined();

    const current = await route(
      ev("/oauth/callback", "GET", {
        query: new URLSearchParams({
          code: "c",
          state: secondState,
        }).toString(),
        cookies: [secondCookie],
      }),
      cfg(),
    );
    expect(current.statusCode).toBe(302);
    expect(new URL(current.headers.location).searchParams.get("state")).toBe(
      "second-state",
    );
  });

  it("TC-MCPGW-069: /oauth/token replaces redirect_uri before forwarding to Cognito", async () => {
    let captured: { url: string; body: string } | undefined;
    vi.spyOn(globalThis, "fetch").mockImplementation(
      async (url: string | URL | Request, init?: RequestInit) => {
        captured = { url: String(url), body: String(init?.body ?? "") };
        return new Response(JSON.stringify({ access_token: "tok" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    );
    const form = new URLSearchParams({
      grant_type: "authorization_code",
      code: signAuthorizationCode(
        {
          code: "c",
          redirectUri: "http://127.0.0.1:5000/callback",
        },
        HMAC,
        Date.now(),
      ),
      redirect_uri: "http://127.0.0.1:5000/callback",
      code_verifier: "v",
      client_id: "reader-client-id",
    }).toString();
    const res = await route(
      ev("/oauth/token", "POST", {
        body: form,
        headers: { "content-type": "application/x-www-form-urlencoded" },
      }),
      cfg(),
    );
    expect(res.statusCode).toBe(200);
    expect(captured!.url).toBe(cfg().token);
    const fwd = new URLSearchParams(captured!.body);
    expect(fwd.get("redirect_uri")).toBe(`${BASE}/oauth/callback`);
    expect(fwd.get("code")).toBe("c");
  });

  // --- Public-client secret injection at /oauth/token (TC-MCPGW-074..078) ---
  // Codex-style public clients authenticate with `none`: client_id only, no
  // Authorization header, no client_secret. The façade injects the Cognito
  // reader secret before forwarding — the secret must never be required from,
  // nor returned to, the MCP client.

  function mockTokenUpstream() {
    const captured: { headers?: Record<string, string>; body?: string } = {};
    vi.spyOn(globalThis, "fetch").mockImplementation(
      async (_url: string | URL | Request, init?: RequestInit) => {
        captured.headers = (init?.headers ?? {}) as Record<string, string>;
        captured.body = String(init?.body ?? "");
        return new Response(JSON.stringify({ access_token: "tok" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    );
    return captured;
  }

  it("TC-MCPGW-074: secretless refresh with the known client_id → façade injects the Cognito secret", async () => {
    const captured = mockTokenUpstream();
    const form = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: "rt",
      client_id: "reader-client-id",
    }).toString();
    const res = await route(
      ev("/oauth/token", "POST", { body: form }),
      cfg(),
    );
    expect(res.statusCode).toBe(200);
    const fwd = new URLSearchParams(captured.body!);
    expect(fwd.get("client_secret")).toBe("reader-client-secret");
    expect(fwd.get("client_id")).toBe("reader-client-id");
    expect(fwd.get("refresh_token")).toBe("rt");
  });

  it("TC-MCPGW-075: secretless request with an UNKNOWN client_id → 401, no injection", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const form = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: "rt",
      client_id: "attacker-client-id",
    }).toString();
    const res = await route(
      ev("/oauth/token", "POST", { body: form }),
      cfg(),
    );
    expect(res.statusCode).toBe(401);
    expect(JSON.parse(res.body).error).toBe("invalid_client");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("TC-MCPGW-076: secretless request with NO client_id → 401, no injection", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const form = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: "rt",
    }).toString();
    const res = await route(
      ev("/oauth/token", "POST", { body: form }),
      cfg(),
    );
    expect(res.statusCode).toBe(401);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("TC-MCPGW-077: Basic-auth refresh (legacy Claude Code) passes through untouched — no injection", async () => {
    const captured = mockTokenUpstream();
    const basic = "Basic " + Buffer.from("reader-client-id:reader-client-secret").toString("base64");
    const form = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: "rt",
    }).toString();
    const res = await route(
      ev("/oauth/token", "POST", { body: form, headers: { authorization: basic } }),
      cfg(),
    );
    expect(res.statusCode).toBe(200);
    expect(captured.headers!["authorization"]).toBe(basic);
    const fwd = new URLSearchParams(captured.body!);
    expect(fwd.get("client_secret")).toBeNull();
  });

  it("TC-MCPGW-078: client_secret_post refresh (legacy) passes through untouched — no overwrite", async () => {
    const captured = mockTokenUpstream();
    const form = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: "rt",
      client_id: "reader-client-id",
      client_secret: "caller-supplied-secret",
    }).toString();
    const res = await route(
      ev("/oauth/token", "POST", { body: form }),
      cfg(),
    );
    expect(res.statusCode).toBe(200);
    const fwd = new URLSearchParams(captured.body!);
    expect(fwd.get("client_secret")).toBe("caller-supplied-secret");
  });

  it("TC-MCPGW-078b: secretless authorization_code exchange also gets the injected secret (PKCE public client)", async () => {
    const captured = mockTokenUpstream();
    const form = new URLSearchParams({
      grant_type: "authorization_code",
      code: signAuthorizationCode(
        {
          code: "c",
          redirectUri: "http://127.0.0.1:5000/callback",
        },
        HMAC,
        Date.now(),
      ),
      redirect_uri: "http://127.0.0.1:5000/callback",
      code_verifier: "v",
      client_id: "reader-client-id",
    }).toString();
    const res = await route(
      ev("/oauth/token", "POST", { body: form }),
      cfg(),
    );
    expect(res.statusCode).toBe(200);
    const fwd = new URLSearchParams(captured.body!);
    expect(fwd.get("client_secret")).toBe("reader-client-secret");
    expect(fwd.get("redirect_uri")).toBe(`${BASE}/oauth/callback`);
  });

  it("TC-MCPGW-070: empty HMAC key → /oauth/authorize 503", async () => {
    const q = new URLSearchParams({
      redirect_uri: "http://localhost:5000/cb",
      code_challenge: "x",
    }).toString();
    const res = await route(
      ev("/oauth/authorize", "GET", { query: q }),
      cfg({ hmacKey: "" }),
    );
    expect(res.statusCode).toBe(503);
    expect(JSON.parse(res.body).error).toBe("server_misconfigured");
  });

  it("TC-MCPGW-071: empty HMAC key → /oauth/callback 503", async () => {
    const res = await route(
      ev("/oauth/callback", "GET", { query: "state=x" }),
      cfg({ hmacKey: "" }),
    );
    expect(res.statusCode).toBe(503);
    expect(JSON.parse(res.body).error).toBe("server_misconfigured");
  });

  it("TC-MCPGW-072: /register returns a PUBLIC client — no secret, auth method none (RFC 7591 DCR)", async () => {
    const res = await route(
      ev("/register", "POST", { body: JSON.stringify({ redirect_uris: ["http://127.0.0.1:9/cb"] }) }),
      cfg(),
    );
    expect(res.statusCode).toBe(201);
    const b = JSON.parse(res.body);
    expect(b.client_id).toBe("reader-client-id");
    // The Cognito client secret must NEVER leave the façade: a public MCP
    // client (Codex) can't durably hold it, and handing it out means any
    // registrant gets a confidential credential.
    expect(b.client_secret).toBeUndefined();
    expect(b.client_secret_expires_at).toBeUndefined();
    expect(b.token_endpoint_auth_method).toBe("none");
    expect(b.redirect_uris).toEqual(["http://127.0.0.1:9/cb"]);
    // DCR scope must match the reader client (no profile/write).
    expect(b.scope).toBe("openid email example-mcp/query/read");
    expect(b.scope).not.toMatch(/profile/);
    expect(b.scope).not.toMatch(/write/);
  });

  it("TC-MCPGW-072b: /register rejects a request for a secret-based auth method", async () => {
    const res = await route(
      ev("/register", "POST", {
        body: JSON.stringify({
          redirect_uris: ["http://127.0.0.1:9/cb"],
          token_endpoint_auth_method: "client_secret_basic",
        }),
      }),
      cfg(),
    );
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toBe("invalid_client_metadata");
  });

  it("TC-MCPGW-073: isAllowedClientRedirect only accepts loopback http URLs", () => {
    expect(isAllowedClientRedirect("http://localhost:1/cb")).toBe(true);
    expect(isAllowedClientRedirect("http://127.0.0.1:65535/cb")).toBe(true);
    expect(isAllowedClientRedirect("http://[::1]:54321/cb")).toBe(true);
    expect(isAllowedClientRedirect("https://localhost/cb")).toBe(false);
    expect(isAllowedClientRedirect("http://evil.example/cb")).toBe(false);
    expect(isAllowedClientRedirect("not a url")).toBe(false);
  });

  it("TC-OAUTH-CALLBACK-004/005: accepts an exact configured HTTPS callback through authorize and callback", async () => {
    const configuredCallback =
      `${REMOTE_CALLBACK}?tenant=example&code=stale&error=stale`;
    const config = cfg({ allowedClientRedirectUris: [configuredCallback] });
    const authQ = new URLSearchParams({
      redirect_uri: configuredCallback,
      state: "remote-state",
      code_challenge: "challenge",
      code_challenge_method: "S256",
    }).toString();
    const authRes = await route(
      ev("/oauth/authorize", "GET", { query: authQ }),
      config,
    );
    expect(authRes.statusCode).toBe(302);
    const cognitoRedirect = new URL(authRes.headers.location);
    expect(cognitoRedirect.searchParams.get("redirect_uri")).toBe(
      `${BASE}/oauth/callback`,
    );

    const callbackQ = new URLSearchParams({
      code: "remote-code",
      state: cognitoRedirect.searchParams.get("state")!,
    }).toString();
    const callbackRes = await route(
      ev("/oauth/callback", "GET", {
        query: callbackQ,
        cookies: requestCookies(authRes),
      }),
      config,
    );
    expect(callbackRes.statusCode).toBe(302);
    const clientRedirect = new URL(callbackRes.headers.location);
    expect(clientRedirect.origin + clientRedirect.pathname).toBe(
      REMOTE_CALLBACK,
    );
    expect(clientRedirect.searchParams.get("tenant")).toBe("example");
    expect(
      verifyAuthorizationCode(
        clientRedirect.searchParams.get("code")!,
        HMAC,
        Date.now(),
      ),
    ).toMatchObject({ c: "remote-code", r: configuredCallback });
    expect(clientRedirect.searchParams.get("error")).toBeNull();
    expect(clientRedirect.searchParams.get("state")).toBe("remote-state");
  });

  it.each([
    "https://oauth.example.com/callback/other",
    "https://sub.oauth.example.com/callback/app",
  ])(
    "TC-OAUTH-CALLBACK-006: rejects an unconfigured sibling redirect %s",
    async (redirectUri) => {
      const q = new URLSearchParams({
        redirect_uri: redirectUri,
        code_challenge: "challenge",
        code_challenge_method: "S256",
      }).toString();
      const res = await route(
        ev("/oauth/authorize", "GET", { query: q }),
        cfg({ allowedClientRedirectUris: [REMOTE_CALLBACK] }),
      );
      expect(res.statusCode).toBe(400);
    },
  );

  it("TC-OAUTH-CALLBACK-006: rechecks the allowlist before redirecting from callback", async () => {
    const authQ = new URLSearchParams({
      redirect_uri: REMOTE_CALLBACK,
      code_challenge: "challenge",
      code_challenge_method: "S256",
    }).toString();
    const authRes = await route(
      ev("/oauth/authorize", "GET", { query: authQ }),
      cfg({ allowedClientRedirectUris: [REMOTE_CALLBACK] }),
    );
    const state = new URL(authRes.headers.location).searchParams.get("state")!;

    const res = await route(
      ev("/oauth/callback", "GET", {
        query: new URLSearchParams({ code: "c", state }).toString(),
        cookies: requestCookies(authRes),
      }),
      cfg(),
    );
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toBe("invalid_state");
  });

  it("TC-OAUTH-CALLBACK-007: accepts the configured callback during code exchange", async () => {
    const captured = mockTokenUpstream();
    const form = new URLSearchParams({
      grant_type: "authorization_code",
      code: signAuthorizationCode(
        { code: "c", redirectUri: REMOTE_CALLBACK },
        HMAC,
        Date.now(),
      ),
      redirect_uri: REMOTE_CALLBACK,
      code_verifier: "v",
      client_id: "reader-client-id",
    }).toString();
    const res = await route(
      ev("/oauth/token", "POST", { body: form }),
      cfg({ allowedClientRedirectUris: [REMOTE_CALLBACK] }),
    );
    expect(res.statusCode).toBe(200);
    const forwarded = new URLSearchParams(captured.body!);
    expect(forwarded.get("redirect_uri")).toBe(`${BASE}/oauth/callback`);
    expect(forwarded.get("code")).toBe("c");
  });

  it.each([
    ["omitted", undefined],
    ["empty", ""],
  ])(
    "rejects an authorization-code exchange with an %s redirect_uri",
    async (_case, redirectUri) => {
      const form = new URLSearchParams({
        grant_type: "authorization_code",
        code: signAuthorizationCode(
          { code: "c", redirectUri: REMOTE_CALLBACK },
          HMAC,
          Date.now(),
        ),
        code_verifier: "v",
        client_id: "reader-client-id",
      });
      if (redirectUri !== undefined) form.set("redirect_uri", redirectUri);
      const res = await route(
        ev("/oauth/token", "POST", { body: form.toString() }),
        cfg({ allowedClientRedirectUris: [REMOTE_CALLBACK] }),
      );
      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body).error).toBe("invalid_request");
    },
  );

  it("rejects a code exchange using a different allowlisted redirect_uri", async () => {
    const otherCallback = "https://oauth.example.com/callback/other";
    const res = await route(
      ev("/oauth/token", "POST", {
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: signAuthorizationCode(
            { code: "c", redirectUri: REMOTE_CALLBACK },
            HMAC,
            Date.now(),
          ),
          redirect_uri: otherCallback,
          code_verifier: "v",
          client_id: "reader-client-id",
        }).toString(),
      }),
      cfg({
        allowedClientRedirectUris: [REMOTE_CALLBACK, otherCallback],
      }),
    );
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toBe("invalid_grant");
  });

  it("TC-OAUTH-CALLBACK-006: rejects an unconfigured callback during code exchange", async () => {
    const res = await route(
      ev("/oauth/token", "POST", {
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: "c",
          redirect_uri: "https://oauth.example.com/callback/other",
          code_verifier: "v",
          client_id: "reader-client-id",
        }).toString(),
      }),
      cfg({ allowedClientRedirectUris: [REMOTE_CALLBACK] }),
    );
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toBe("invalid_request");
  });

  it("TC-OAUTH-CALLBACK-008: registers configured HTTPS and loopback callbacks", async () => {
    const redirects = [REMOTE_CALLBACK, "http://127.0.0.1:54321/callback"];
    const res = await route(
      ev("/register", "POST", {
        body: JSON.stringify({ redirect_uris: redirects }),
      }),
      cfg({ allowedClientRedirectUris: [REMOTE_CALLBACK] }),
    );
    expect(res.statusCode).toBe(201);
    expect(JSON.parse(res.body).redirect_uris).toEqual(redirects);
  });

  it("TC-OAUTH-CALLBACK-009: rejects the entire registration when one redirect is unsupported", async () => {
    const res = await route(
      ev("/register", "POST", {
        body: JSON.stringify({
          redirect_uris: [
            REMOTE_CALLBACK,
            "https://oauth.example.com/callback/other",
          ],
        }),
      }),
      cfg({ allowedClientRedirectUris: [REMOTE_CALLBACK] }),
    );
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toBe("invalid_redirect_uri");
  });

  it("accepts registration of a callback that fits the transaction cookie", async () => {
    const redirectUri = `http://localhost:8080/${"x".repeat(800)}`;
    const res = await route(
      ev("/register", "POST", {
        body: JSON.stringify({
          redirect_uris: [redirectUri],
        }),
      }),
      cfg(),
    );
    expect(res.statusCode).toBe(201);
    expect(JSON.parse(res.body).redirect_uris).toEqual([redirectUri]);
  });

  it("rejects registration of a callback that cannot fit in the transaction cookie", async () => {
    const res = await route(
      ev("/register", "POST", {
        body: JSON.stringify({
          redirect_uris: [
            `http://localhost:8080/${"x".repeat(4000)}`,
          ],
        }),
      }),
      cfg(),
    );
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toBe("invalid_redirect_uri");
  });
});
