import { describe, expect, it, vi } from "vitest";
import {
  checkOAuthCallback,
  HumanMcpClient,
  parseRpcResponse,
} from "./lib/human-namespace-browser.mjs";

const token = () => {
  const now = Math.floor(Date.now() / 1000);
  return `head.${Buffer.from(JSON.stringify({ iat: now, exp: now + 900, token_use: "access", sub: "fixture", client_id: "fixture-client", scope: "mem9-mcp/read mem9-mcp/write" })).toString("base64url")}.sig`;
};
describe("human OAuth/MCP client guards", () => {
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
