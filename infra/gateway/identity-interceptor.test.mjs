import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { generateKeyPairSync, sign } from "node:crypto";

import {
  INTERNAL_AUTH_FIELD,
  deriveClientKey,
  derivePrincipalKey,
} from "./namespace-auth.mjs";

const ISSUER = "https://cognito-idp.example.invalid/pool";
const HUMAN_CLIENT = "reader-client";
const signingPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const JWKS_URI = "https://keys.example.com/identity-jwks";

process.env.MEM9_TOOL_SCOPES = JSON.stringify({
  add_memory: "mem9-mcp/write",
  search_memories: "mem9-mcp/read",
  ingest_messages: "mem9-mcp/write",
  get_ingest_job_status: "mem9-mcp/read",
});
process.env.MEM9_CLIENT_REGISTRY = JSON.stringify({
  issuer: ISSUER,
  human: [HUMAN_CLIENT],
  m2m: ["m2m-client"],
});
process.env.MEM9_IDENTITY_JWKS_URI = JWKS_URI;
process.env.MEM9_IDENTITY_SIGNING_KEYS = JSON.stringify({
  current: Buffer.alloc(32, 3).toString("base64url"),
});

let handler;
beforeAll(async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (uri) => {
      expect(uri).toBe(JWKS_URI);
      return new Response(
        JSON.stringify({
          keys: [
            {
              ...signingPair.publicKey.export({ format: "jwk" }),
              kid: "test-signing",
              alg: "RS256",
              use: "sig",
            },
          ],
        }),
      );
    }),
  );
  ({ handler } = await import("./identity-interceptor.mjs"));
});
afterAll(() => vi.unstubAllGlobals());

function token(claims) {
  const encode = (value) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  const body = `${encode({ alg: "RS256", kid: "test-signing" })}.${encode({ exp: Math.floor(Date.now() / 1000) + 900, ...claims })}`;
  return `${body}.${sign("RSA-SHA256", Buffer.from(body), signingPair.privateKey).toString("base64url")}`;
}

function event(args = {}, overrides = {}) {
  const claims = {
    iss: ISSUER,
    sub: "human-subject",
    client_id: HUMAN_CLIENT,
    token_use: "access",
    scope: "mem9-mcp/read",
    "cognito:groups": ["team-a"],
    ...overrides,
  };
  return {
    interceptorInputVersion: "1.0",
    mcp: {
      gatewayRequest: {
        headers: { Authorization: `Bearer ${token(claims)}` },
        body: {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "test-target___search_memories",
            arguments: args,
          },
        },
      },
    },
  };
}

describe("identity interceptor", () => {
  it("authenticates a mixed batch and signs only its tool invocations", async () => {
    const request = event({ nested: { values: ["Unicode-测试", 3] } });
    const tool = request.mcp.gatewayRequest.body;
    const initialize = { jsonrpc: "2.0", id: 2, method: "initialize" };
    request.mcp.gatewayRequest.body = [initialize, tool];
    const output = await handler(request);
    const body = output.mcp.transformedGatewayRequest.body;
    expect(body[0]).toEqual(initialize);
    expect(body[1].params.arguments[INTERNAL_AUTH_FIELD].principal_type).toBe(
      "human",
    );
  });
  it("retains scope denial after a valid signature", async () => {
    const output = await handler(event({}, { scope: "mem9-mcp/write" }));
    expect(output.mcp.transformedGatewayResponse.body.error.code).toBe(-32003);
    expect(output.mcp).not.toHaveProperty("transformedGatewayRequest");
  });
  it("authenticates and filters a tools-list response without minting context", async () => {
    const request = event();
    request.mcp.gatewayRequest.body = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
    };
    request.mcp.gatewayResponse = {
      statusCode: 200,
      body: {
        jsonrpc: "2.0",
        id: 1,
        result: {
          tools: [
            { name: "test-target___search_memories" },
            { name: "test-target___add_memory" },
          ],
        },
      },
    };
    const output = await handler(request);
    expect(output.mcp.transformedGatewayResponse.body.result.tools).toEqual([
      { name: "test-target___search_memories" },
    ]);
    expect(JSON.stringify(output)).not.toContain(INTERNAL_AUTH_FIELD);
  });
  it.each([undefined, {}, "not-an-object", { Authorization: "Basic PRIVATE" }])(
    "rejects missing or malformed authorization without disclosure (%#)",
    async (headers) => {
      const request = event();
      request.mcp.gatewayRequest.headers = headers;
      const output = await handler(request);
      expect(output.mcp.transformedGatewayResponse.statusCode).toBe(403);
      expect(JSON.stringify(output)).not.toContain("PRIVATE");
    },
  );
  it("preserves a valid machine identity after signature verification", async () => {
    const output = await handler(
      event(
        {},
        {
          client_id: "m2m-client",
          sub: "m2m-client",
          "cognito:groups": undefined,
        },
      ),
    );
    expect(
      output.mcp.transformedGatewayRequest.body.params.arguments[
        INTERNAL_AUTH_FIELD
      ],
    ).toMatchObject({ principal_type: "m2m", group_keys: [] });
  });
  it("does not mint trusted context from an invoke-only caller's fabricated JWT", async () => {
    const request = event();
    const parts =
      request.mcp.gatewayRequest.headers.Authorization.slice(7).split(".");
    parts[2] = Buffer.from("fabricated-signature").toString("base64url");
    request.mcp.gatewayRequest.headers.Authorization = `Bearer ${parts.join(".")}`;
    const output = await handler(request);
    expect(output.mcp.transformedGatewayResponse.statusCode).toBe(403);
    expect(output.mcp).not.toHaveProperty("transformedGatewayRequest");
    expect(JSON.stringify(output)).not.toMatch(
      /fabricated-signature|human-subject|__mem9_auth_v2/,
    );
  });
  it("TC-GROUPNS-027: overwrites caller context and strips ownership fields", async () => {
    const output = await handler(
      event({
        q: "arm64",
        namespace_id: "attacker",
        principal_id: "attacker",
        [INTERNAL_AUTH_FIELD]: { mac: "attacker" },
      }),
    );
    const args = output.mcp.transformedGatewayRequest.body.params.arguments;
    expect(args.q).toBe("arm64");
    expect(args).not.toHaveProperty("namespace_id");
    expect(args).not.toHaveProperty("principal_id");
    expect(args[INTERNAL_AUTH_FIELD]).toMatchObject({
      v: 2,
      principal_type: "human",
      tool: "search_memories",
    });
    expect(args[INTERNAL_AUTH_FIELD].mac).toMatch(/^[0-9a-f]{64}$/u);
  });

  it("TC-GROUPNS-013/017: fails closed for unknown clients and ID tokens", async () => {
    for (const claims of [
      { client_id: "unknown-client" },
      { token_use: "id" },
    ]) {
      const output = await handler(event({}, claims));
      expect(output.mcp.transformedGatewayResponse.statusCode).toBe(403);
      expect(JSON.stringify(output)).not.toContain("unknown-client");
      expect(JSON.stringify(output)).not.toContain("human-subject");
    }
  });

  it("classifies Cognito client-credentials tokens that include sub", async () => {
    const output = await handler(
      event(
        { content: "team fact" },
        {
          client_id: "m2m-client",
          sub: "machine-token-subject",
          scope: "mem9-mcp/read",
          "cognito:groups": undefined,
        },
      ),
    );
    const context =
      output.mcp.transformedGatewayRequest.body.params.arguments[
        INTERNAL_AUTH_FIELD
      ];
    expect(context).toMatchObject({
      principal_type: "m2m",
      principal_key: derivePrincipalKey(ISSUER, "m2m", "m2m-client"),
      client_key: deriveClientKey(ISSUER, "m2m-client"),
      group_keys: [],
    });
    expect(context.principal_key).not.toBe(
      derivePrincipalKey(ISSUER, "m2m", "machine-token-subject"),
    );
  });

  it("does not attach internal identity to non-tool protocol requests", async () => {
    const request = event();
    request.mcp.gatewayRequest.body = {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
    };
    const output = await handler(request);
    expect(output.mcp.transformedGatewayRequest.body).toEqual(
      request.mcp.gatewayRequest.body,
    );
  });
});
