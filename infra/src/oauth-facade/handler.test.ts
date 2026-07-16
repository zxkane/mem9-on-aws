/**
 * Unit tests for the façade routing (TC-MCPGW-060..073).
 * Exercised through the injected `route(event, cfg)` seam — no AWS/SSM.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { isAllowedClientRedirect, route } from "./handler.js";
import { verifyState } from "./state.js";
import type { FacadeConfig } from "./config.js";

const HOST = "abc123.lambda-url.ap-northeast-1.on.aws";
const BASE = `https://${HOST}`;
const HMAC = "unit-test-hmac-key";

function cfg(overrides: Partial<FacadeConfig> = {}): FacadeConfig {
  return {
    upstream: "https://gateway.example/mcp-prefix",
    issuer: "https://cognito-idp.ap-northeast-1.amazonaws.com/pool",
    authorize: "https://dom.auth.ap-northeast-1.amazoncognito.com/oauth2/authorize",
    token: "https://dom.auth.ap-northeast-1.amazoncognito.com/oauth2/token",
    userinfo: "https://dom.auth.ap-northeast-1.amazoncognito.com/oauth2/userInfo",
    revocation: "https://dom.auth.ap-northeast-1.amazoncognito.com/oauth2/revoke",
    jwks: "https://cognito-idp.ap-northeast-1.amazonaws.com/pool/.well-known/jwks.json",
    // Reader-client-aligned: openid + email + read only (no write).
    resourceScopes: ["a sibling project/query/read"],
    userClientId: "reader-client-id",
    userClientSecret: "reader-client-secret",
    hmacKey: HMAC,
    ...overrides,
  };
}

function ev(
  path: string,
  method = "GET",
  opts: { query?: string; body?: string; headers?: Record<string, string> } = {},
) {
  return {
    rawPath: path,
    rawQueryString: opts.query ?? "",
    headers: { host: HOST, ...(opts.headers ?? {}) },
    body: opts.body,
    requestContext: { http: { method }, domainName: HOST },
  };
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
    // Advertised scopes must match the reader client's allowed scopes exactly
    // — no `profile`, no `write`.
    expect(b.scopes_supported).toEqual(["openid", "email", "a sibling project/query/read"]);
    expect(b.scopes_supported).not.toContain("profile");
    expect(b.scopes_supported).not.toContain("a sibling project/query/write");
  });

  it("TC-MCPGW-061b: OIDC discovery metadata advertises reader-aligned scopes (no profile/write)", async () => {
    const res = await route(ev("/.well-known/openid-configuration"), cfg());
    const b = JSON.parse(res.body);
    expect(b.scopes_supported).toEqual(["openid", "email", "a sibling project/query/read"]);
    expect(b.scopes_supported).not.toContain("profile");
    expect(b.scopes_supported).not.toContain("a sibling project/query/write");
  });

  it("TC-MCPGW-062: /oauth/authorize 302s to Cognito with replaced redirect_uri + HMAC state", async () => {
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
    expect(decoded!.r).toBe("http://127.0.0.1:5000/callback");
    expect(decoded!.cs).toBe("orig-state");
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
    const res = await route(ev("/oauth/callback", "GET", { query: cbQ }), cfg());
    expect(res.statusCode).toBe(302);
    const loc = new URL(res.headers.location);
    expect(loc.origin + loc.pathname).toBe("http://127.0.0.1:5000/callback");
    expect(loc.searchParams.get("code")).toBe("auth-code-xyz");
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
      code: "c",
      redirect_uri: "http://127.0.0.1:5000/callback",
      code_verifier: "v",
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

  it("TC-MCPGW-072: /register returns the reader client creds (RFC 7591 DCR)", async () => {
    const res = await route(
      ev("/register", "POST", { body: JSON.stringify({ redirect_uris: ["http://127.0.0.1:9/cb"] }) }),
      cfg(),
    );
    expect(res.statusCode).toBe(201);
    const b = JSON.parse(res.body);
    expect(b.client_id).toBe("reader-client-id");
    expect(b.client_secret).toBe("reader-client-secret");
    expect(b.redirect_uris).toEqual(["http://127.0.0.1:9/cb"]);
    // DCR scope must match the reader client (no profile/write).
    expect(b.scope).toBe("openid email a sibling project/query/read");
    expect(b.scope).not.toMatch(/profile/);
    expect(b.scope).not.toMatch(/write/);
  });

  it("TC-MCPGW-073: isAllowedClientRedirect only accepts loopback http URLs", () => {
    expect(isAllowedClientRedirect("http://localhost:1/cb")).toBe(true);
    expect(isAllowedClientRedirect("http://127.0.0.1:65535/cb")).toBe(true);
    expect(isAllowedClientRedirect("https://localhost/cb")).toBe(false);
    expect(isAllowedClientRedirect("http://evil.example/cb")).toBe(false);
    expect(isAllowedClientRedirect("not a url")).toBe(false);
  });
});
