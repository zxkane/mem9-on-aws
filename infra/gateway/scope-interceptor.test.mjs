import { describe, expect, it } from "vitest";

import {
  interceptScopes,
  isScopeInterceptorEvent,
  parseToolScopes,
} from "./scope-interceptor.mjs";

process.env.MEM9_TOOL_SCOPES = JSON.stringify({
  add_memory: "mem9-mcp/write",
  search_memories: "mem9-mcp/read",
  ingest_messages: "mem9-mcp/write",
  get_ingest_job_status: "mem9-mcp/read",
});

const prefixed = (tool) => `test-mem9-rest___${tool}`;
const toolCall = (tool) => ({
  jsonrpc: "2.0",
  id: 7,
  method: "tools/call",
  params: { name: prefixed(tool), arguments: {} },
});

function token(scope) {
  const encode = (value) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "none" })}.${encode({ scope })}.signature`;
}

function requestEvent(body, scope, authorization) {
  const headers = {};
  if (authorization !== undefined) {
    headers.Authorization = authorization;
  } else if (scope !== undefined) {
    headers.Authorization = `Bearer ${token(scope)}`;
  }
  return {
    interceptorInputVersion: "1.0",
    mcp: {
      gatewayRequest: {
        path: "/mcp",
        httpMethod: "POST",
        headers,
        body,
      },
    },
  };
}

function responseEvent(requestBody, responseBody, scope) {
  const event = requestEvent(requestBody, scope);
  event.mcp.gatewayResponse = {
    statusCode: 200,
    headers: { "Mcp-Session-Id": "session-1" },
    body: responseBody,
  };
  return event;
}

function denied(output, requiredScope) {
  const response = output.mcp.transformedGatewayResponse;
  expect(response.statusCode).toBe(403);
  expect(response.headers["WWW-Authenticate"]).toContain(
    'Bearer error="insufficient_scope"',
  );
  const error = response.body.error;
  expect(error.code).toBe(-32003);
  if (requiredScope) {
    expect(error.data.required_scope).toBe(requiredScope);
    expect(response.headers["WWW-Authenticate"]).toContain(
      `scope="${requiredScope}"`,
    );
  }
}

describe("AgentCore scope interceptor requests", () => {
  it("validates the injected tool-to-scope policy", () => {
    expect(
      parseToolScopes('{"search_memories":"mem9-mcp/read"}'),
    ).toEqual({ search_memories: "mem9-mcp/read" });
    expect(() => parseToolScopes()).toThrow(/missing required env/u);
    expect(() => parseToolScopes("{")).toThrow(/must be a JSON object/u);
    for (const invalid of [
      "{}",
      "[]",
      '{"search_memories":""}',
      '{"search_memories":"scope with spaces"}',
      '{"search_memories":"scope\\\"quote"}',
    ]) {
      expect(() => parseToolScopes(invalid)).toThrow(
        /must map tool names to OAuth scopes/u,
      );
    }
  });

  it.each(["search_memories", "get_ingest_job_status"])(
    "allows read scope to call %s",
    (tool) => {
      const body = toolCall(tool);
      expect(interceptScopes(requestEvent(body, "mem9-mcp/read"))).toEqual({
        interceptorOutputVersion: "1.0",
        mcp: { transformedGatewayRequest: { body } },
      });
    },
  );

  it.each(["add_memory", "ingest_messages"])(
    "allows write scope to call %s",
    (tool) => {
      const body = toolCall(tool);
      expect(interceptScopes(requestEvent(body, "mem9-mcp/write"))).toEqual({
        interceptorOutputVersion: "1.0",
        mcp: { transformedGatewayRequest: { body } },
      });
    },
  );

  it("keeps read and write independent unless both scopes are present", () => {
    denied(
      interceptScopes(requestEvent(toolCall("add_memory"), "mem9-mcp/read")),
      "mem9-mcp/write",
    );
    denied(
      interceptScopes(
        requestEvent(toolCall("search_memories"), "mem9-mcp/write"),
      ),
      "mem9-mcp/read",
    );

    for (const tool of [
      "add_memory",
      "search_memories",
      "ingest_messages",
      "get_ingest_job_status",
    ]) {
      expect(
        interceptScopes(
          requestEvent(
            toolCall(tool),
            "mem9-mcp/read mem9-mcp/write",
          ),
        ).mcp.transformedGatewayRequest,
      ).toBeDefined();
    }
  });

  it("accepts the array form of the scope claim", () => {
    const body = toolCall("search_memories");
    expect(
      interceptScopes(requestEvent(body, ["mem9-mcp/read"])).mcp
        .transformedGatewayRequest,
    ).toEqual({ body });
  });

  it("checks every tools/call in a JSON-RPC batch", () => {
    const allowedBatch = [
      { jsonrpc: "2.0", id: 1, method: "initialize" },
      { ...toolCall("search_memories"), id: 2 },
      { ...toolCall("get_ingest_job_status"), id: 3 },
    ];
    expect(
      interceptScopes(requestEvent(allowedBatch, "mem9-mcp/read")).mcp
        .transformedGatewayRequest,
    ).toEqual({ body: allowedBatch });

    const deniedBatch = [
      { ...toolCall("search_memories"), id: 4 },
      { ...toolCall("add_memory"), id: 5 },
    ];
    const output = interceptScopes(
      requestEvent(deniedBatch, "mem9-mcp/read"),
    );
    denied(output, "mem9-mcp/write");
    expect(output.mcp.transformedGatewayResponse.body.id).toBe(5);

    const reverseOutput = interceptScopes(
      requestEvent(
        [
          { ...toolCall("add_memory"), id: 6 },
          { ...toolCall("search_memories"), id: 7 },
        ],
        "mem9-mcp/write",
      ),
    );
    denied(reverseOutput, "mem9-mcp/read");
    expect(reverseOutput.mcp.transformedGatewayResponse.body.id).toBe(7);
  });

  it.each([
    ["missing token", undefined],
    ["malformed bearer", "Bearer not-a-jwt"],
    ["malformed payload", ["Bearer", "e30.bm90LWpzb24.signature"].join(" ")],
  ])("fails closed for a %s", (_label, authorization) => {
    denied(
      interceptScopes(
        requestEvent(
          toolCall("search_memories"),
          undefined,
          authorization,
        ),
      ),
      "mem9-mcp/read",
    );
  });

  it("fails closed for unknown tools", () => {
    const output = interceptScopes(
      requestEvent(toolCall("delete_everything"), "mem9-mcp/write"),
    );
    denied(output);
    expect(output.mcp.transformedGatewayResponse.body.error.data.tool).toBe(
      prefixed("delete_everything"),
    );
  });

  it("passes non-tool-call requests through unchanged", () => {
    const body = { jsonrpc: "2.0", id: 1, method: "initialize" };
    expect(interceptScopes(requestEvent(body))).toEqual({
      interceptorOutputVersion: "1.0",
      mcp: { transformedGatewayRequest: { body } },
    });
  });

  it("recognizes only versioned MCP interceptor events", () => {
    expect(isScopeInterceptorEvent(requestEvent({}, "mem9-mcp/read"))).toBe(
      true,
    );
    expect(isScopeInterceptorEvent({ content: "target invocation" })).toBe(
      false,
    );
    expect(() => interceptScopes({})).toThrow(
      /invalid AgentCore interceptor event/u,
    );
  });
});

describe("AgentCore scope interceptor responses", () => {
  const tools = [
    { name: prefixed("add_memory") },
    { name: prefixed("search_memories") },
    { name: prefixed("ingest_messages") },
    { name: prefixed("get_ingest_job_status") },
    { name: prefixed("unknown_tool") },
  ];

  it.each([
    ["mem9-mcp/read", ["search_memories", "get_ingest_job_status"]],
    ["mem9-mcp/write", ["add_memory", "ingest_messages"]],
    [
      "mem9-mcp/read mem9-mcp/write",
      [
        "add_memory",
        "search_memories",
        "ingest_messages",
        "get_ingest_job_status",
      ],
    ],
  ])("filters tools/list for %s", (scope, expectedTools) => {
    const output = interceptScopes(
      responseEvent(
        { jsonrpc: "2.0", id: 2, method: "tools/list" },
        {
          jsonrpc: "2.0",
          id: 2,
          result: { tools, nextCursor: "cursor-1" },
        },
        scope,
      ),
    );
    const response = output.mcp.transformedGatewayResponse;
    expect(response.statusCode).toBe(200);
    expect(response.headers).toEqual({ "Mcp-Session-Id": "session-1" });
    expect(response.body.result.nextCursor).toBe("cursor-1");
    expect(response.body.result.tools.map(({ name }) => name)).toEqual(
      expectedTools.map(prefixed),
    );
  });

  it("fails closed when tools/list has no usable scope claim", () => {
    denied(
      interceptScopes(
        responseEvent(
          { jsonrpc: "2.0", id: 2, method: "tools/list" },
          { jsonrpc: "2.0", id: 2, result: { tools } },
          undefined,
        ),
      ),
    );
  });

  it("filters tools/list inside a mixed JSON-RPC batch", () => {
    const requestBody = [
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      toolCall("search_memories"),
    ];
    const responseBody = [
      { jsonrpc: "2.0", id: 7, result: { content: [] } },
      {
        jsonrpc: "2.0",
        id: 2,
        result: { tools, nextCursor: "cursor-1" },
      },
    ];
    const response = interceptScopes(
      responseEvent(requestBody, responseBody, "mem9-mcp/write"),
    ).mcp.transformedGatewayResponse;
    expect(response.body[0]).toEqual(responseBody[0]);
    expect(response.body[1].result.nextCursor).toBe("cursor-1");
    expect(response.body[1].result.tools.map(({ name }) => name)).toEqual(
      ["add_memory", "ingest_messages"].map(prefixed),
    );
  });

  it("fails closed when a mixed batch reuses the tools/list request id", () => {
    const requestBody = [
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      { jsonrpc: "2.0", id: 2, method: "ping" },
    ];
    const responseBody = [
      {
        jsonrpc: "2.0",
        id: 2,
        error: { code: -32601, message: "Method not found" },
      },
      { jsonrpc: "2.0", id: 2, result: { tools } },
    ];
    denied(
      interceptScopes(
        responseEvent(requestBody, responseBody, "mem9-mcp/read"),
      ),
    );
  });

  it("fails closed when a batch reuses the tools/list response id", () => {
    const requestBody = [
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      { jsonrpc: "2.0", id: 7, method: "ping" },
    ];
    const responseBody = [
      {
        jsonrpc: "2.0",
        id: 2,
        error: { code: -32601, message: "Method not found" },
      },
      { jsonrpc: "2.0", id: 2, result: { tools } },
    ];
    denied(
      interceptScopes(
        responseEvent(requestBody, responseBody, "mem9-mcp/read"),
      ),
    );
  });

  it("fails closed when a batch response id was not requested", () => {
    const requestBody = [
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      { jsonrpc: "2.0", id: 7, method: "ping" },
    ];
    const responseBody = [
      { jsonrpc: "2.0", id: 2, result: { tools } },
      { jsonrpc: "2.0", id: 99, result: { tools } },
    ];
    denied(
      interceptScopes(
        responseEvent(requestBody, responseBody, "mem9-mcp/read"),
      ),
    );
  });

  it("filters structured tool discovery responses", () => {
    const response = interceptScopes(
      responseEvent(
        { jsonrpc: "2.0", id: 2, method: "tools/list" },
        {
          jsonrpc: "2.0",
          id: 2,
          result: { structuredContent: { tools, format: "tool-search-v1" } },
        },
        "mem9-mcp/read",
      ),
    ).mcp.transformedGatewayResponse;
    expect(
      response.body.result.structuredContent.tools.map(({ name }) => name),
    ).toEqual(["search_memories", "get_ingest_job_status"].map(prefixed));
    expect(response.body.result.structuredContent.format).toBe(
      "tool-search-v1",
    );
  });

  it("fails closed for malformed tools/list responses", () => {
    denied(
      interceptScopes(
        responseEvent(
          { jsonrpc: "2.0", id: 2, method: "tools/list" },
          { jsonrpc: "2.0", id: 2, result: { unexpected: tools } },
          "mem9-mcp/read",
        ),
      ),
    );
  });

  it("preserves a valid tools/list error response", () => {
    const responseBody = {
      jsonrpc: "2.0",
      id: 2,
      error: { code: -32601, message: "Method not found" },
    };
    expect(
      interceptScopes(
        responseEvent(
          { jsonrpc: "2.0", id: 2, method: "tools/list" },
          responseBody,
          "mem9-mcp/read",
        ),
      ).mcp.transformedGatewayResponse.body,
    ).toEqual(responseBody);
  });

  it("rejects a singleton tools/list response with error and result", () => {
    const output = interceptScopes(
      responseEvent(
        { jsonrpc: "2.0", id: 2, method: "tools/list" },
        {
          jsonrpc: "2.0",
          id: 2,
          error: { code: -32601, message: "Method not found" },
          result: { tools },
        },
        "mem9-mcp/read",
      ),
    );
    denied(output);
    expect(output.mcp.transformedGatewayResponse.body.error.message).toBe(
      "Gateway tools response is unavailable",
    );
  });

  it("passes tool-call responses through, including request short-circuits", () => {
    const body = {
      jsonrpc: "2.0",
      id: 7,
      error: { code: -32003, message: "Insufficient OAuth scope" },
    };
    const event = responseEvent(toolCall("add_memory"), body, "mem9-mcp/read");
    event.mcp.gatewayResponse.statusCode = 403;
    expect(interceptScopes(event).mcp.transformedGatewayResponse).toEqual({
      statusCode: 403,
      headers: { "Mcp-Session-Id": "session-1" },
      body,
    });
  });

  it("preserves a request short-circuit for a mixed tools/list batch", () => {
    const requestBody = [
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      toolCall("add_memory"),
    ];
    const shortCircuit = interceptScopes(
      requestEvent(requestBody, "mem9-mcp/read"),
    ).mcp.transformedGatewayResponse;
    const event = responseEvent(
      requestBody,
      shortCircuit.body,
      "mem9-mcp/read",
    );
    event.mcp.gatewayResponse.statusCode = shortCircuit.statusCode;
    event.mcp.gatewayResponse.headers = shortCircuit.headers;

    expect(interceptScopes(event).mcp.transformedGatewayResponse).toEqual(
      shortCircuit,
    );
    denied(
      { mcp: { transformedGatewayResponse: shortCircuit } },
      "mem9-mcp/write",
    );
  });

  it("rejects a batched tools/list response with error and result", () => {
    const requestBody = [
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      toolCall("search_memories"),
    ];
    const event = responseEvent(
      requestBody,
      [
        {
          jsonrpc: "2.0",
          id: 2,
          error: { code: -32601, message: "Method not found" },
          result: { tools },
        },
        { jsonrpc: "2.0", id: 7, result: { content: [] } },
      ],
      "mem9-mcp/read",
    );

    const output = interceptScopes(event);
    denied(output);
    expect(output.mcp.transformedGatewayResponse.body.error.message).toBe(
      "Gateway tools response is unavailable",
    );
  });

  it("does not preserve a non-403 scope-shaped response", () => {
    const requestBody = [
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      toolCall("search_memories"),
    ];
    const event = responseEvent(
      requestBody,
      {
        jsonrpc: "2.0",
        id: 2,
        error: { code: -32003, message: "Insufficient OAuth scope" },
      },
      "mem9-mcp/read",
    );
    event.mcp.gatewayResponse.headers = {
      "WWW-Authenticate": 'Bearer error="insufficient_scope"',
    };

    const output = interceptScopes(event);
    denied(output);
    expect(output.mcp.transformedGatewayResponse.body.error.message).toBe(
      "Gateway tools response is unavailable",
    );
  });
});
