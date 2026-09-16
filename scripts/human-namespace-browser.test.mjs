import { describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { request as httpRequest } from "node:http";
import {
  checkOAuthCallback,
  HumanMcpClient,
  HumanOAuthBrowser,
  parseRpcResponse,
} from "./lib/human-namespace-browser.mjs";

const token = () => {
  const now = Math.floor(Date.now() / 1000);
  return `head.${Buffer.from(JSON.stringify({ iat: now, exp: now + 900, token_use: "access", sub: "fixture", client_id: "fixture-client", scope: "mem9-mcp/read mem9-mcp/write" })).toString("base64url")}.sig`;
};
describe("human OAuth/MCP client guards", () => {
  it("rejects registration for a different client before opening a login context", async () => {
    const browser = { newContext: vi.fn() };
    let callback;
    const client = new HumanOAuthBrowser({
      browser,
      facadeUrl: "https://facade.example.com",
      providerOrigin: "https://login.example.com",
      issuer: "fixture-issuer",
      expectedClientId: "expected-client",
      fetchImpl: async (_url, options) => {
        callback = JSON.parse(options.body).redirect_uris[0];
        return { status: 201, json: async () => ({ client_id: "different-client" }) };
      },
    });
    await expect(client.login({ username: "fixture-user", password: "fixture-password", subject: "fixture" })).rejects.toThrow("oauth_registration_client_mismatch");
    expect(browser.newContext).not.toHaveBeenCalled();
    await expect(fetch(callback)).rejects.toThrow();
  });
  it.each([false, true])(
    "receives loopback redirects and closes the listener (context-close failure=%s)",
    async (closeFails) => {
      let callback, authorize;
      const page = {
        setDefaultTimeout() {},
        async goto(url) {
          authorize = new URL(url);
        },
        url: () => "https://login.example.com/login",
        locator: () => ({
          first: () => ({
            fill: async () => {},
            isVisible: async () => true,
            locator: () => ({ locator: () => page.submit }),
          }),
        }),
        getByRole: () => {
          throw new Error("classic_form_has_submit_aria_label");
        },
        submit: {
          count: async () => 1,
          click: async () => {
            const malformed = await new Promise((resolve, reject) => {
              const request = httpRequest(
                {
                  hostname: "127.0.0.1",
                  port: new URL(callback).port,
                  path: "//",
                  method: "GET",
                },
                (response) => {
                  response.resume();
                  response.on("end", () => resolve(response.statusCode));
                },
              );
              request.on("error", reject);
              request.end();
            });
            expect(malformed).toBe(400);
            const invalid = new URL(callback);
            invalid.searchParams.set("state", "wrong");
            invalid.searchParams.set("code", "invalid");
            expect((await fetch(invalid)).status).toBe(400);
            const valid = new URL(callback);
            valid.searchParams.set(
              "state",
              authorize.searchParams.get("state"),
            );
            valid.searchParams.set("code", "opaque-code");
            expect((await fetch(valid)).status).toBe(200);
          },
        },
      };
      const close = vi.fn(async () => {
          if (closeFails) throw new Error("injected_context_close_failure");
        }),
        browser = {
          newContext: async () => ({
            route: async () => {},
            newPage: async () => page,
            close,
          }),
        };
      const fetchImpl = async (url, options) => {
        if (url.endsWith("/register")) {
          callback = JSON.parse(options.body).redirect_uris[0];
          return {
            status: 201,
            json: async () => ({ client_id: "fixture-client" }),
          };
        }
        const form = new URLSearchParams(options.body);
        expect(form.get("code")).toBe("opaque-code");
        expect(
          createHash("sha256")
            .update(form.get("code_verifier"))
            .digest("base64url"),
        ).toBe(authorize.searchParams.get("code_challenge"));
        const now = Math.floor(Date.now() / 1000),
          claims = {
            iss: "fixture-issuer",
            sub: "fixture",
            client_id: "fixture-client",
            token_use: "access",
            scope: "mem9-mcp/read mem9-mcp/write",
            iat: now,
            exp: now + 900,
          };
        return {
          ok: true,
          json: async () => ({
            access_token: `header.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.signature`,
          }),
        };
      };
      const client = new HumanOAuthBrowser({
        browser,
        facadeUrl: "https://facade.example.com",
        providerOrigin: "https://login.example.com",
        issuer: "fixture-issuer",
        expectedClientId: "fixture-client",
        fetchImpl,
      });
      const login = client.login({
        username: "fixture-user",
        password: "fixture-password",
        subject: "fixture",
      });
      if (closeFails)
        await expect(login).rejects.toThrow("injected_context_close_failure");
      else await login;
      expect(close).toHaveBeenCalledTimes(1);
      await expect(fetch(callback)).rejects.toThrow();
    },
  );
  it.each(["rate_limit", "protocol", "backend_failure", "missing_proof"])(
    "does not accept %s as a namespace denial",
    async (mode) => {
      const fetchImpl = async () => ({
        status: mode === "rate_limit" ? 429 : 200,
        ok: mode !== "rate_limit",
        headers: new Headers(),
        text: async () =>
          JSON.stringify(
            mode === "protocol"
              ? {
                  id: 1,
                  error: { code: -32602, message: "invalid parameters" },
                }
              : {
                  id: 1,
                  result: {
                    isError: true,
                    content: [
                      { type: "text", text: "An internal error occurred" },
                    ],
                  },
                },
          ),
      });
      const client = new HumanMcpClient({
        url: "https://gateway.example.com/mcp",
        token: token(),
        fetchImpl,
        readDenialStatus:
          mode === "missing_proof" ? undefined : async () => 500,
      });
      client.tools = { search_memories: "target___search_memories" };
      await expect(
        client.call("search_memories", { q: "unique" }, { denied: true }),
      ).rejects.toThrow();
    },
  );
  it("binds callback state and exact loopback route", () => {
    const expected = {
      callback: "http://127.0.0.1:43891/callback/fixture",
      state: "nonce",
    };
    expect(
      checkOAuthCallback(
        expected.callback + "?state=nonce&code=opaque",
        expected,
      ),
    ).toBe("opaque");
    for (const url of [
      expected.callback + "?state=other&code=opaque",
      expected.callback + "?state=nonce",
      expected.callback + "?state=nonce&code=opaque&error=denied",
      expected.callback + "?state=nonce&code=opaque#fragment",
      "https://other.example.com/callback/fixture?state=nonce&code=opaque",
    ])
      expect(() => checkOAuthCallback(url, expected)).toThrow();
  });
  it("parses JSON and SSE responses without logging bodies", () => {
    expect(parseRpcResponse('{"result":{}}')).toEqual({ result: {} });
    expect(
      parseRpcResponse('event: message\ndata: {"id":1}\n\ndata: [DONE]\n'),
    ).toEqual({ id: 1 });
    expect(() => parseRpcResponse("not-json")).toThrow("invalid_gateway_json");
  });
  it("separates expected authorization denials from unavailable transport", async () => {
    const response = (status, payload) => ({
      status,
      ok: status >= 200 && status < 300,
      headers: new Headers(),
      text: async () => JSON.stringify(payload),
    });
    const fetchImpl = vi.fn(async () =>
      response(200, {
        id: 1,
        result: { isError: true, content: [{ type: "text", text: "denied" }] },
      }),
    );
    const client = new HumanMcpClient({
      url: "https://gateway.example.com/mcp",
      token: token(),
      fetchImpl,
      readDenialStatus: async () => 403,
    });
    client.tools = { search_memories: "target___search_memories" };
    await expect(
      client.call("search_memories", { q: "fixture" }, { denied: true }),
    ).resolves.toBeUndefined();
    fetchImpl.mockResolvedValue(response(503, { error: "unavailable" }));
    await expect(
      client.call("search_memories", { q: "fixture" }, { denied: true }),
    ).rejects.toThrow("gateway_transport_unavailable");
  });
  it("rejects mismatched JSON-RPC IDs even for negative tests", async () => {
    const client = new HumanMcpClient({
      url: "https://gateway.example.com/mcp",
      token: token(),
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        headers: new Headers(),
        text: async () => JSON.stringify({ id: 99, result: { isError: true } }),
      }),
    });
    client.tools = { search_memories: "target___search_memories" };
    await expect(
      client.call("search_memories", {}, { denied: true }),
    ).rejects.toThrow("gateway_response_id_mismatch");
  });
});
