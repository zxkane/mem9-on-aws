/**
 * Unit tests for the façade routing (TC-MCPGW-060..081).
 * Exercised through the injected `route(event, cfg)` seam — no AWS/SSM.
 */

import { createHmac } from "node:crypto";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  buildSlackDeps,
  handler,
  isAllowedClientRedirect,
  route,
} from "./handler.js";
import type { SlackDeps } from "./slack-interactions.js";
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
/**
 * The upstream Cognito issuer. Cognito still mints and signs every token, but the
 * façade must never advertise this as the `issuer` of its OWN metadata documents
 * (RFC 8414 §3.3) — see TC-MCPGW-079.
 */
const UPSTREAM_ISSUER = "https://cognito-idp.ap-northeast-1.amazonaws.com/pool";

function cfg(overrides: Partial<FacadeConfig> = {}): FacadeConfig {
  return {
    upstream: "https://gateway.example/mcp-prefix",
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
    // Empty by default: the OAuth cases must not depend on a Slack app existing,
    // and the Slack cases inject their own deps rather than reading this.
    slackSigningSecret: "",
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

describe("façade routing (TC-MCPGW-060..081)", () => {
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

  // TC-MCPGW-080. The OIDC document is a full peer of the RFC 8414 one — some
  // clients only know this path — but only its scopes and `registration_endpoint`
  // were ever asserted, while TC-MCPGW-061 pins the AS document's endpoints. That
  // asymmetry (one document tested, its twin trusted) is exactly what let #143
  // ship, so the same fields are pinned on both. Verified by mutation: pointing
  // either OIDC endpoint at the upstream Cognito value passed all 57 cases before
  // this was added.
  it.each([
    ["/.well-known/oauth-authorization-server", "RFC 8414"],
    ["/.well-known/openid-configuration", "OIDC discovery"],
  ])(
    "TC-MCPGW-080: %s metadata routes authorize/token through the façade and passes the rest through to Cognito",
    async (path) => {
      const b = JSON.parse((await route(ev(path), cfg())).body);
      // Must be OURS: these are the redirect-proxy routes. Sending a client
      // straight to Cognito's own endpoints skips the state/PKCE proxy and the
      // secret injection at /oauth/token.
      expect(b.authorization_endpoint).toBe(`${BASE}/oauth/authorize`);
      expect(b.token_endpoint).toBe(`${BASE}/oauth/token`);
      // Must be OURS: Cognito publishes no registration_endpoint, so DCR only
      // works through the façade.
      expect(b.registration_endpoint).toBe(`${BASE}/register`);
      // Must be COGNITO'S: the façade proxies none of these, and a client that
      // fetches JWKS itself validates tokens against this URL. Untested until
      // now — replacing jwks_uri with a garbage value passed all 57 cases.
      expect(b.jwks_uri).toBe(cfg().jwks);
      expect(b.userinfo_endpoint).toBe(cfg().userinfo);
      expect(b.revocation_endpoint).toBe(cfg().revocation);
    },
  );

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

  // TC-MCPGW-081. The 401's `WWW-Authenticate` is the RFC 9728 discovery ENTRY
  // POINT: it is how a client learns where the protected-resource document lives,
  // so if this URL is wrong discovery never starts and no metadata test can see
  // the breakage. It embeds `base` under the same host-agreement invariant as the
  // metadata `issuer` this PR fixes, and had no coverage at all — pointing it at
  // an unrelated host passed all 57 cases.
  it("TC-MCPGW-081: a 401 from upstream advertises the FAÇADE's resource metadata, not the Gateway's", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(
      async () =>
        new Response("unauthorized", {
          status: 401,
          // The raw Gateway points at its own Cognito-backed metadata, which has
          // no /register — the value that must NOT survive the rewrite.
          headers: {
            "www-authenticate": `Bearer resource_metadata="${UPSTREAM_ISSUER}/.well-known/oauth-protected-resource"`,
          },
        }),
    );
    const res = await route(ev("/mcp", "POST", { body: "{}" }), cfg());
    expect(res.statusCode).toBe(401);
    expect(res.headers["www-authenticate"]).toBe(
      `Bearer resource_metadata="${BASE}/.well-known/oauth-protected-resource"`,
    );
    // The advertised document must be the one the façade actually serves, so a
    // client that follows this header reaches metadata naming us as the AS.
    const pr = JSON.parse(
      (await route(ev("/.well-known/oauth-protected-resource"), cfg())).body,
    );
    expect(res.headers["www-authenticate"]).toContain(
      pr.authorization_servers[0],
    );
  });

  // TC-MCPGW-079. RFC 8414 §3.3: the `issuer` a metadata document returns MUST be
  // identical to the issuer identifier the client inserted the well-known string
  // into to build the URL it fetched. We publish ourselves as the authorization
  // server (`authorization_servers: [base]`), so that identifier is our own base —
  // NOT Cognito's issuer, even though Cognito mints the tokens. Advertising
  // Cognito's issuer here made rmcp >= 3.0.0 clients discard the document and fail
  // MCP startup outright.
  //
  // Asserted BOTH ways, because either alone is insufficient. The relationship
  // (`as.issuer === pr.authorization_servers[0]`) is what §3.3 actually requires
  // and survives a host/stage change. The absolute anchor (`advertisedAs === BASE`)
  // is what rules out COORDINATED drift: three documents that agree on the upstream
  // issuer satisfy §3.3 while sending clients to Cognito, which serves no
  // `/register` — reproducing #143's symptom by another route.
  //
  // The suffix is the only thing that varies — `wellKnown` strips a trailing
  // `/mcp` before matching, so both variants must hold the same property.
  it.each([
    ["bare", ""],
    ["resource-suffixed", "/mcp"],
  ])(
    "TC-MCPGW-079: advertised issuer is identical to authorization_servers[0] on %s well-known paths",
    async (_label, suffix) => {
      const doc = async (name: string) =>
        JSON.parse((await route(ev(`/.well-known/${name}${suffix}`), cfg())).body);
      const pr = await doc("oauth-protected-resource");
      const as = await doc("oauth-authorization-server");
      const oidc = await doc("openid-configuration");

      const advertisedAs = pr.authorization_servers[0];
      expect(advertisedAs).toBe(BASE);
      // Both documents self-identify as the AS the client was pointed at.
      expect(as.issuer).toBe(advertisedAs);
      expect(oidc.issuer).toBe(advertisedAs);

      // Guards a partial fix that changes only one of the two handlers: neither
      // document may leak the upstream issuer.
      expect(as.issuer).not.toBe(UPSTREAM_ISSUER);
      expect(oidc.issuer).not.toBe(UPSTREAM_ISSUER);
    },
  );

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

const SLACK_SECRET = "unit-test-signing-secret";
const SLACK_STAGE = "test";
const SLACK_HASH = "sha256:deadbeef";

/**
 * The Slack side of the façade, injected the same way `cfg` is. The Slack branch
 * is reachable ONLY when these deps are present, which is what makes "the
 * feature flag is unset" a structural state rather than a runtime string check.
 */
function slackDeps(overrides: Partial<SlackDeps> = {}): SlackDeps {
  return {
    signingSecret: SLACK_SECRET,
    stage: SLACK_STAGE,
    ssmPrefix: "/mem9-on-aws/test",
    now: () => Date.now(),
    getParameter: vi.fn(async () =>
      JSON.stringify({ stage: SLACK_STAGE, hash: SLACK_HASH, ids: ["m-1"] }),
    ),
    putParameter: vi.fn(async () => {}),
    runTask: vi.fn(async () => "arn:aws:ecs:region:account:task/cluster/abc"),
    log: vi.fn(),
    ...overrides,
  };
}

/** Slack's scheme, computed here rather than by calling the production signer. */
function slackEvent(
  method = "POST",
  opts: { secret?: string; now?: number } = {},
) {
  const body = `payload=${encodeURIComponent(
    JSON.stringify({
      type: "block_actions",
      actions: [{ action_id: "cleanup_approve", value: SLACK_HASH }],
    }),
  )}`;
  const ts = Math.floor((opts.now ?? Date.now()) / 1000);
  const mac = createHmac("sha256", opts.secret ?? SLACK_SECRET)
    .update(`v0:${ts}:${body}`)
    .digest("hex");
  return ev("/slack/interactions", method, {
    body,
    headers: {
      "x-slack-request-timestamp": String(ts),
      "x-slack-signature": `v0=${mac}`,
      "content-type": "application/x-www-form-urlencoded",
    },
  });
}

describe("Slack callback routing on the shared façade (TC-SLACKAPP-040..043)", () => {
  it("TC-SLACKAPP-040 POST /slack/interactions is matched explicitly, never proxied upstream", async () => {
    // The façade proxies EVERY unmatched path to the AgentCore Gateway, so the
    // failure this pins is not a 404 — it is a Slack payload arriving at the
    // Gateway and the Gateway's error shape being returned to Slack. Asserted by
    // watching `fetch`, because a route that returned 200 from the Slack handler
    // AND forwarded upstream would still pass a status-only assertion.
    // Stubbed rather than merely spied: an un-stubbed spy calls through, so a
    // fallthrough would fail with ENOTFOUND and make the test depend on DNS
    // resolution failing for `gateway.example`.
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async () => new Response("upstream", { status: 200 }));
    const slack = slackDeps();
    const res = await route(slackEvent(), cfg(), slack);

    expect(res.statusCode).toBe(200);
    expect(slack.runTask).toHaveBeenCalledTimes(1);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("TC-SLACKAPP-041 with the feature unconfigured the path is 404, not proxied", async () => {
    // 404 rather than a fallthrough: forwarding would send operator-approval data
    // to a component with no business seeing it. 404 rather than 401 because
    // without deps there is no secret any request to this path could be
    // authenticated against — the endpoint genuinely is not here.
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async () => new Response("upstream", { status: 200 }));
    const res = await route(slackEvent(), cfg());

    expect(res.statusCode).toBe(404);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("TC-SLACKAPP-042 GET /slack/interactions is 405 and the OAuth routes are unchanged", async () => {
    const slack = slackDeps();
    const get = await route(slackEvent("GET"), cfg(), slack);
    expect(get.statusCode).toBe(405);
    expect(slack.runTask).not.toHaveBeenCalled();

    // The Slack branch is additive. A regression in the OAuth flow would break
    // every MCP client, so the metadata documents are re-asserted WITH the Slack
    // deps present rather than trusted to be unaffected.
    const prm = await route(
      ev("/.well-known/oauth-protected-resource"),
      cfg(),
      slack,
    );
    expect(prm.statusCode).toBe(200);
    expect(JSON.parse(prm.body).resource).toBe(`${BASE}/mcp`);

    const asm = await route(
      ev("/.well-known/oauth-authorization-server"),
      cfg(),
      slack,
    );
    expect(asm.statusCode).toBe(200);
    expect(JSON.parse(asm.body).registration_endpoint).toBe(`${BASE}/register`);

    const reg = await route(
      ev("/register", "POST", { body: JSON.stringify({}) }),
      cfg(),
      slack,
    );
    expect(reg.statusCode).toBe(201);
  });

  it("TC-SLACKAPP-043 the two concerns do not share a failure mode", async () => {
    // OAuth misconfigured, Slack fine: the redirect proxy 503s while an approval
    // click still applies. They share a Lambda, not a fate.
    const slack = slackDeps();
    const broken = cfg({ hmacKey: "" });
    const oauth = await route(ev("/oauth/authorize", "GET", { query: "state=x" }), broken, slack);
    expect(oauth.statusCode).toBe(503);

    const click = await route(slackEvent(), broken, slack);
    expect(click.statusCode).toBe(200);
    expect(slack.runTask).toHaveBeenCalledTimes(1);

    // And the converse: an unconfigured SLACK secret fails the Slack route closed
    // (401, from the handler's own fail-closed branch — NOT 404, which would
    // wrongly say the endpoint is absent) while OAuth keeps working.
    const noSecret = slackDeps({ signingSecret: "" });
    const closed = await route(slackEvent(), cfg(), noSecret);
    expect(closed.statusCode).toBe(401);
    expect(noSecret.runTask).not.toHaveBeenCalled();

    const stillFine = await route(ev("/.well-known/oauth-protected-resource"), cfg(), noSecret);
    expect(stillFine.statusCode).toBe(200);
  });
});

describe("Slack deps at the Lambda entrypoint (TC-SLACKAPP-047..049)", () => {
  it("TC-SLACKAPP-047 deps are built when the stage has a signing secret", () => {
    // The routing cases above prove `route` dispatches when deps are PASSED. This
    // proves the deployed Lambda actually builds them — without it the whole
    // feature is unreachable in production while every routing test stays green.
    const deps = buildSlackDeps(
      cfg({ slackSigningSecret: "shhh" }),
      { SSM_PREFIX: "/mem9-on-aws/pr-7", STAGE: "pr-7" },
    );
    expect(deps).not.toBeUndefined();
    expect(deps!.signingSecret).toBe("shhh");
    expect(deps!.stage).toBe("pr-7");
    expect(deps!.ssmPrefix).toBe("/mem9-on-aws/pr-7");
  });

  it("TC-SLACKAPP-048 no secret means no deps, which is what makes the route 404", () => {
    expect(
      buildSlackDeps(cfg({ slackSigningSecret: "" }), {
        SSM_PREFIX: "/mem9-on-aws/pr-7",
        STAGE: "pr-7",
      }),
    ).toBeUndefined();
  });

  it("TC-SLACKAPP-047b runTask reads its ECS inputs from the stage's SSM tree", async () => {
    // The apply-task inputs live in SSM exactly as `scripts/run-consolidation-task.sh`
    // reads them, so this dep does NOT need the apply task to exist yet in infra —
    // it needs the names to be right. Asserted through the injected client seam so
    // the case touches no AWS.
    const sent: unknown[] = [];
    const deps = buildSlackDeps(
      cfg({ slackSigningSecret: "shhh" }),
      { SSM_PREFIX: "/mem9-on-aws/pr-7", STAGE: "pr-7" },
      {
        ssm: {
          send: async (cmd: { input: Record<string, unknown> }) => {
            sent.push(cmd.input);
            const names = cmd.input.Names as string[] | undefined;
            if (!names) return {};
            return {
              Parameters: names.map((Name) => ({
                Name,
                Value: Name.endsWith("/subnet-ids")
                  ? "subnet-a,subnet-b"
                  : `value-for${Name.slice(Name.lastIndexOf("/"))}`,
              })),
            };
          },
        },
        ecs: {
          send: async (cmd: { input: Record<string, unknown> }) => {
            sent.push(cmd.input);
            return { tasks: [{ taskArn: "arn:aws:ecs:r:a:task/c/t1" }], failures: [] };
          },
        },
      },
    );
    const arn = await deps!.runTask({ ids: ["m-1"], hash: "sha256:x", stage: "pr-7" });
    expect(arn).toBe("arn:aws:ecs:r:a:task/c/t1");

    const read = sent.find((i) => (i as { Names?: string[] }).Names) as { Names: string[] };
    for (const suffix of ["cluster-name", "task-def-arn", "task-sg-id", "subnet-ids"]) {
      expect(read.Names).toContain(`/mem9-on-aws/pr-7/cleanup/${suffix}`);
    }

    const run = sent.find((i) => (i as { taskDefinition?: string }).taskDefinition) as Record<
      string,
      unknown
    >;
    // Each parameter must land in the field NAMED for it, not merely be read. The
    // fake echoes the name into the value so a swap is visible here: reading four
    // names and asserting only that all four were read passes even if `cluster`
    // receives the task-def ARN, because both are non-empty strings and the
    // required-value check cannot tell them apart. The mistake would surface only
    // from ECS, as an opaque validation error, after the approval was claimed.
    expect(run.cluster).toBe("value-for/cluster-name");
    expect(run.taskDefinition).toBe("value-for/task-def-arn");
    // Private subnets with no public IP: the argument that chose ECS over a
    // VPC-attached Lambda was "no new network surface", and `assignPublicIp:
    // ENABLED` would quietly add one.
    const net = (run.networkConfiguration as {
      awsvpcConfiguration: { subnets: string[]; assignPublicIp: string };
    }).awsvpcConfiguration;
    expect(net.subnets).toEqual(["subnet-a", "subnet-b"]);
    expect(net.assignPublicIp).toBe("DISABLED");

    // The override carries the HASH ONLY. Memory ids must not ride it: an override
    // is echoed back in `DescribeTasks` and recorded in the CloudTrail event, so
    // ids there would put memory identifiers in an audit log the privacy rules keep
    // them out of — and the task must read the ids from the approved SSM record
    // anyway, not from anything a caller supplied.
    const overrides = JSON.stringify(run.overrides);
    expect(overrides).toContain("sha256:x");
    expect(overrides).not.toContain("m-1");
  });

  it("TC-SLACKAPP-047c a RunTask that starts nothing is an error, not a silent success", async () => {
    // ECS returns HTTP 200 with an empty `tasks[]` and a populated `failures[]`
    // when placement fails, so a dep that returned `tasks[0].taskArn` without
    // checking would resolve to `undefined` — and the handler would stamp the claim
    // and tell the operator an apply started that never did. This is the same trap
    // `run-bootstrap-task.sh` calls out for the CLI path.
    const deps = buildSlackDeps(
      cfg({ slackSigningSecret: "shhh" }),
      { SSM_PREFIX: "/mem9-on-aws/pr-7", STAGE: "pr-7" },
      {
        ssm: {
          send: async (cmd: { input: Record<string, unknown> }) => ({
            Parameters: ((cmd.input.Names as string[] | undefined) ?? []).map((Name) => ({
              Name,
              Value: Name.endsWith("/subnet-ids") ? "subnet-a" : "v",
            })),
          }),
        },
        ecs: {
          send: async () => ({
            tasks: [],
            failures: [{ reason: "RESOURCE:MEMORY", arn: "arn:aws:ecs:r:a:container-instance/x" }],
          }),
        },
      },
    );
    await expect(
      deps!.runTask({ ids: ["m-1"], hash: "sha256:x", stage: "pr-7" }),
    ).rejects.toThrow(/RESOURCE:MEMORY/u);
  });

  it("TC-SLACKAPP-047d an incomplete SSM input set fails before RunTask", async () => {
    // A missing `task-def-arn` would otherwise reach `RunTask` as `undefined` and
    // come back as an opaque validation error, after the claim was already written.
    let ranTask = false;
    const deps = buildSlackDeps(
      cfg({ slackSigningSecret: "shhh" }),
      { SSM_PREFIX: "/mem9-on-aws/pr-7", STAGE: "pr-7" },
      {
        ssm: {
          send: async (cmd: { input: Record<string, unknown> }) => ({
            // `task-def-arn` deliberately absent, mirroring how `GetParameters`
            // reports unknown names rather than failing the call.
            Parameters: ((cmd.input.Names as string[] | undefined) ?? [])
              .filter((n) => !n.endsWith("/task-def-arn"))
              .map((Name) => ({ Name, Value: "v" })),
          }),
        },
        ecs: {
          send: async () => {
            ranTask = true;
            return { tasks: [{ taskArn: "arn" }], failures: [] };
          },
        },
      },
    );
    await expect(
      deps!.runTask({ ids: ["m-1"], hash: "sha256:x", stage: "pr-7" }),
    ).rejects.toThrow(/task-def-arn/u);
    expect(ranTask).toBe(false);
  });

  it("TC-SLACKAPP-047e the entrypoint passes the built deps to the router", async () => {
    // The gap the isolated `buildSlackDeps` cases cannot see: deleting
    // `buildSlackDeps(cfg)` from `handler` leaves every other case green while the
    // deployed Lambda 404s every click. Exercised through `handler`, so the wiring
    // itself is the thing under test.
    const res = await handler(slackEvent(), {
      loadConfig: async () => cfg({ slackSigningSecret: SLACK_SECRET }),
      env: { SSM_PREFIX: "/mem9-on-aws/test", STAGE: SLACK_STAGE },
      clients: {
        ssm: {
          send: async (cmd) => {
            // Both reads are `GetParameters` — the only read the action ceiling
            // admits (TC-047g) — so they are told apart by NAME, not by command
            // shape. The approval read has to answer the offered record or this
            // case stops at the offered-list check and never reaches RunTask.
            const names = ((cmd as { input: { Names?: string[] } }).input.Names) ?? [];
            return {
              Parameters: names.map((Name) => ({
                Name,
                Value: Name.endsWith("/approvals/offered")
                  ? JSON.stringify({
                      stage: SLACK_STAGE,
                      hash: SLACK_HASH,
                      ids: ["m-1"],
                    })
                  : Name.endsWith("/subnet-ids")
                    ? "subnet-a"
                    : "v",
              })),
            };
          },
        },
        ecs: {
          send: async () => ({ tasks: [{ taskArn: "arn:aws:ecs:r:a:task/c/t9" }], failures: [] }),
        },
      },
    });

    // A 200 whose body reports the apply started — NOT merely a 200, which the 404
    // branch and every refusal reply also produce.
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).text).toMatch(/Apply started/u);
  });

  it("TC-SLACKAPP-047g every parameter read uses GetParameters, the only read the boundary admits", async () => {
    // `ssm:GetParameter` and `ssm:GetParameters` are DISTINCT IAM actions, and the
    // workload permissions boundary's action ceiling admits only the plural (the
    // whole project reads through `GetParameters`, so nothing needed the singular
    // until this handler). A `GetParameterCommand` is therefore an AccessDenied on
    // the first real Slack click — a runtime-only failure, invisible to every test
    // that injects a client, because an injected fake answers any command shape.
    //
    // Asserted on the command CLASS rather than the response, since the two commands
    // are interchangeable from the caller's side: same parameter, same value back,
    // and only IAM can tell them apart.
    const { GetParametersCommand } = await import("@aws-sdk/client-ssm");
    const sent: unknown[] = [];
    const deps = buildSlackDeps(
      cfg({ slackSigningSecret: "shhh" }),
      { SSM_PREFIX: "/mem9-on-aws/pr-7", STAGE: "pr-7" },
      {
        ssm: {
          send: async (cmd) => {
            sent.push(cmd);
            return {
              Parameters: [
                { Name: "/mem9-on-aws/pr-7/approvals/offered", Value: '{"ids":[]}' },
              ],
            };
          },
        },
      },
    );
    const value = await deps!.getParameter("/mem9-on-aws/pr-7/approvals/offered");

    expect(value).toBe('{"ids":[]}');
    expect(sent).toHaveLength(1);
    expect(sent[0]).toBeInstanceOf(GetParametersCommand);
    // And an absent parameter is null, not the literal string "undefined": SSM
    // reports a missing name in `InvalidParameters`, omitting it from `Parameters`
    // entirely rather than returning an empty value.
    const missing = await deps!.getParameter("/mem9-on-aws/pr-7/approvals/approved-x");
    expect(missing).toBeNull();
  });

  it("TC-SLACKAPP-047f the approval record is a plain String written without overwrite", async () => {
    // Two runtime-only failures that no handler-level test can see, because the
    // handler asks for `{ overwrite: false }` and trusts this closure to send it:
    //
    //  - `SecureString` would be DENIED by the workload permissions boundary,
    //    which admits neither `kms:Encrypt` nor `kms:GenerateDataKey`. The failure
    //    would be an AccessDenied on the first real click, long after CI is green.
    //  - `Overwrite: true` silently destroys the atomic claim: `Overwrite: false`
    //    failing with `ParameterAlreadyExists` is the ONLY thing that makes Slack's
    //    3-second redelivery safe, so this mutation double-applies instead of ACKing.
    const puts: Array<Record<string, unknown>> = [];
    const deps = buildSlackDeps(
      cfg({ slackSigningSecret: "shhh" }),
      { SSM_PREFIX: "/mem9-on-aws/pr-7", STAGE: "pr-7" },
      {
        ssm: {
          send: async (cmd) => (puts.push(cmd.input as Record<string, unknown>), {}),
        },
      },
    );
    await deps!.putParameter("/mem9-on-aws/pr-7/approvals/approved-x", "{}", {
      overwrite: false,
    });
    expect(puts[0]!.Type).toBe("String");
    expect(puts[0]!.Overwrite).toBe(false);

    // And the stamp-after-RunTask path must be able to overwrite the same record.
    await deps!.putParameter("/mem9-on-aws/pr-7/approvals/approved-x", "{}", {
      overwrite: true,
    });
    expect(puts[1]!.Overwrite).toBe(true);
  });

  it("TC-SLACKAPP-049 a secret without the stage config is refused, not half-built", () => {
    // A dep set with an empty `stage` would make the stage guard in `loadOffered`
    // compare against "" and refuse every click — a feature that looks deployed,
    // authenticates correctly, and then rejects every approval with a message about
    // the wrong stage. Failing to build is louder and cheaper to diagnose.
    for (const env of [
      { SSM_PREFIX: "/mem9-on-aws/pr-7" },
      { STAGE: "pr-7" },
      { SSM_PREFIX: "/mem9-on-aws/pr-7", STAGE: "" },
    ]) {
      expect(() => buildSlackDeps(cfg({ slackSigningSecret: "shhh" }), env)).toThrow(
        /SLACK|STAGE|SSM_PREFIX/u,
      );
    }
  });
});
