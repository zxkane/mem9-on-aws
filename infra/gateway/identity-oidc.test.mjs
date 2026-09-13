import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
beforeEach(() => {
  vi.resetModules();
  vi.stubEnv(
    "MEM9_CLIENT_REGISTRY",
    JSON.stringify({
      human: ["human"],
      m2m: ["machine"],
      issuer: "https://issuer.example.com",
      groupClaim: "groups",
      requiredGroup: "team-a",
    }),
  );
  vi.stubEnv(
    "MEM9_TOOL_SCOPES",
    JSON.stringify({ search_memories: "mem9-mcp/read" }),
  );
  vi.stubEnv(
    "MEM9_IDENTITY_SIGNING_KEYS",
    JSON.stringify({ current: "k".repeat(64) }),
  );
});
afterEach(() => vi.unstubAllEnvs());
function event(method, claims = {}) {
  const payload = {
    iss: "https://issuer.example.com",
    sub: "subject",
    client_id: "human",
    token_use: "access",
    groups: ["team-a"],
    scope: "mem9-mcp/read",
    ...claims,
  };
  const token = `eyJhbGciOiJSUzI1NiJ9.${Buffer.from(
    JSON.stringify(payload),
  ).toString("base64url")}.signature`;
  return {
    interceptorInputVersion: "1.0",
    mcp: {
      gatewayRequest: {
        headers: { Authorization: `Bearer ${token}` },
        body: {
          jsonrpc: "2.0",
          id: 1,
          method,
          params: {
            name: "target___search_memories",
            arguments: { q: "test" },
          },
        },
      },
    },
  };
}
describe("external group admission covers every MCP request", () => {
  it.each(["initialize", "tools/list", "tools/call"])(
    "denies wrong, missing or malformed groups for %s",
    async (method) => {
      const { handler } = await import("./identity-interceptor.mjs");
      for (const groups of [
        undefined,
        [],
        ["team-b"],
        "team-a",
        ["team-a", 1],
      ]) {
        expect(
          (await handler(event(method, { groups }))).mcp
            .transformedGatewayResponse.statusCode,
        ).toBe(403);
      }
      expect(
        (await handler(event(method))).mcp.transformedGatewayRequest,
      ).toBeDefined();
    },
  );
  it("permits only the registered machine without granting a human group bypass", async () => {
    const { handler } = await import("./identity-interceptor.mjs");
    expect(
      (
        await handler(
          event("tools/call", { client_id: "machine", groups: undefined }),
        )
      ).mcp.transformedGatewayRequest,
    ).toBeDefined();
    for (const claims of [
      { client_id: "unknown", groups: undefined },
      { iss: "https://old.example.com" },
      { token_use: "id" },
    ])
      expect(
        (await handler(event("tools/list", claims))).mcp
          .transformedGatewayResponse.statusCode,
      ).toBe(403);
  });
  it("applies group denial before returning tools/list responses", async () => {
    const { handler } = await import("./identity-interceptor.mjs");
    const request = event("tools/list", { groups: [] });
    request.mcp.gatewayResponse = {
      statusCode: 200,
      body: { jsonrpc: "2.0", id: 1, result: { tools: [] } },
    };
    expect(
      (await handler(request)).mcp.transformedGatewayResponse.statusCode,
    ).toBe(403);
  });
  it("supports audience-bound JWT access tokens with a nonstandard client claim", async () => {
    const { parseClientRegistry, classifyAccessToken } = await import(
      "./namespace-auth.mjs"
    );
    const registry = parseClientRegistry(
      JSON.stringify({
        human: ["human"],
        m2m: [],
        issuer: "https://issuer.example.com",
        clientIdClaim: "cid",
        groupClaim: "groups",
        audience: "https://api.example.com",
      }),
    );
    const request = event("tools/call", {
      token_use: undefined,
      cid: "human",
      aud: "https://api.example.com",
    });
    const token = request.mcp.gatewayRequest.headers.Authorization.slice(7);
    expect(classifyAccessToken(token, registry).principalType).toBe("human");
    expect(() =>
      classifyAccessToken(
        event("tools/call", {
          token_use: undefined,
          cid: "human",
          aud: "human",
        }).mcp.gatewayRequest.headers.Authorization.slice(7),
        registry,
      ),
    ).toThrow(/audience/);
  });
});
