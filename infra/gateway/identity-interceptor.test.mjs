import { beforeAll, describe, expect, it } from "vitest";

import {
  INTERNAL_AUTH_FIELD,
  deriveClientKey,
  derivePrincipalKey,
} from "./namespace-auth.mjs";

const ISSUER = "https://cognito-idp.example.invalid/pool";
const HUMAN_CLIENT = "reader-client";

process.env.MEM9_TOOL_SCOPES = JSON.stringify({
  add_memory: "mem9-mcp/write",
  search_memories: "mem9-mcp/read",
  ingest_messages: "mem9-mcp/write",
  get_ingest_job_status: "mem9-mcp/read",
});
process.env.MEM9_CLIENT_REGISTRY = JSON.stringify({
  human: [HUMAN_CLIENT],
  m2m: ["m2m-client"],
});
process.env.MEM9_IDENTITY_SIGNING_KEYS = JSON.stringify({
  current: Buffer.alloc(32, 3).toString("base64url"),
});

let handler;
beforeAll(async () => {
  ({ handler } = await import("./identity-interceptor.mjs"));
});

function token(claims) {
  const encode = (value) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "RS256" })}.${encode(claims)}.signature`;
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
  it("TC-GROUPNS-027: overwrites caller context and strips ownership fields", async () => {
    const output = await handler(
      event({
        q: "arm64",
        namespace_id: "attacker",
        principal_id: "attacker",
        [INTERNAL_AUTH_FIELD]: { mac: "attacker" },
      }),
    );
    const args =
      output.mcp.transformedGatewayRequest.body.params.arguments;
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
