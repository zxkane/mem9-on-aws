import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { generateKeyPairSync, sign } from "node:crypto";

const signingPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const JWKS_URI = "https://keys.example.com/external-jwks";

beforeEach(() => {
  vi.resetModules();
  vi.stubEnv("MEM9_IDENTITY_JWKS_URI", JWKS_URI);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (uri) => {
      expect(uri).toBe(JWKS_URI);
      return new Response(
        JSON.stringify({
          keys: [
            {
              ...signingPair.publicKey.export({ format: "jwk" }),
              kid: "external-signing",
              alg: "RS256",
              use: "sig",
            },
          ],
        }),
      );
    }),
  );
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
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});
function event(method, claims = {}) {
  const payload = {
    iss: "https://issuer.example.com",
    sub: "subject",
    client_id: "human",
    token_use: "access",
    groups: ["team-a"],
    scope: "mem9-mcp/read",
    exp: Math.floor(Date.now() / 1000) + 900,
    ...claims,
  };
  const encode = (value) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  const body = `${encode({ alg: "RS256", kid: "external-signing" })}.${encode(payload)}`;
  const token = `${body}.${sign("RSA-SHA256", Buffer.from(body), signingPair.privateKey).toString("base64url")}`;
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
  it("verifies generic OIDC signatures and audience through the handler", async () => {
    vi.stubEnv(
      "MEM9_CLIENT_REGISTRY",
      JSON.stringify({
        human: ["human"],
        m2m: [],
        issuer: "https://issuer.example.com",
        clientIdClaim: "cid",
        groupClaim: "groups",
        requiredGroup: "team-a",
        audience: "https://api.example.com",
      }),
    );
    const { handler } = await import("./identity-interceptor.mjs");
    const claims = {
      token_use: undefined,
      client_id: undefined,
      cid: "human",
      aud: "https://api.example.com",
    };
    expect(
      (await handler(event("tools/call", claims))).mcp
        .transformedGatewayRequest,
    ).toBeDefined();
    for (const overrides of [
      { aud: "wrong" },
      { aud: undefined },
      { cid: "unknown" },
    ]) {
      expect(
        (await handler(event("tools/call", { ...claims, ...overrides }))).mcp
          .transformedGatewayResponse.statusCode,
      ).toBe(403);
    }
  });
  it("rejects array-valued scopes in a signed token", async () => {
    const { handler } = await import("./identity-interceptor.mjs");
    const output = await handler(event("tools/call", { scope: ["mem9-mcp/read"] }));
    expect(output.mcp.transformedGatewayResponse.statusCode).toBe(403);
    expect(output.mcp).not.toHaveProperty("transformedGatewayRequest");
  });
});
