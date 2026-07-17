// Unit tests for the AgentCore Gateway → mnemo-server proxy Lambda handler.
//
// The handler reads MEM9_SERVER_BASE_URL / MEM9_API_KEY at module load, so we set
// them before a dynamic import, then drive the exported `handler` with a mocked
// global `fetch` and a fake Lambda context (clientContext.Custom carries the
// AgentCore `${target}___${tool}` name). We assert the outbound request shape for
// each tool WITHOUT touching AWS, DNS, or a live mnemo-server.

import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

process.env.MEM9_SERVER_BASE_URL = "http://mnemo.mem9-test.local:8080";
process.env.MEM9_API_KEY = "test-tenant-id";

let handler;
beforeAll(async () => {
  ({ handler } = await import("./proxy-handler.mjs"));
});

// Capture the single fetch call and return an OK JSON response.
function mockFetchOk(body = { status: "accepted" }) {
  const spy = vi.fn(async () => ({
    ok: true,
    status: 200,
    text: async () => JSON.stringify(body),
  }));
  vi.stubGlobal("fetch", spy);
  return spy;
}

// Build a fake Lambda context naming the tool the way AgentCore does.
const ctx = (tool) => ({
  clientContext: { Custom: { bedrockAgentCoreToolName: `test-mem9-rest___${tool}` } },
});

afterEach(() => vi.unstubAllGlobals());

describe("proxy-handler ingest_messages", () => {
  it("POSTs a smart-ingest body (mode defaults to smart, messages passed through)", async () => {
    const spy = mockFetchOk();
    const messages = [
      { role: "user", content: "remember I prefer arm64" },
      { role: "assistant", content: "noted" },
    ];
    const res = await handler(
      { messages, session_id: "sess-1", agent_id: "claude-code-x" },
      ctx("ingest_messages"),
    );

    expect(res).toEqual({ status: "accepted" });
    expect(spy).toHaveBeenCalledTimes(1);
    const [url, init] = spy.mock.calls[0];
    expect(url).toBe("http://mnemo.mem9-test.local:8080/v1alpha2/mem9s/memories");
    expect(init.method).toBe("POST");
    expect(init.headers["X-API-Key"]).toBe("test-tenant-id");
    expect(init.headers["X-Mnemo-Agent-Id"]).toBe("claude-code-x");
    const sent = JSON.parse(init.body);
    expect(sent).toEqual({
      mode: "smart",
      messages,
      session_id: "sess-1",
      agent_id: "claude-code-x",
    });
  });

  it("honors an explicit mode and omits absent optional fields", async () => {
    const spy = mockFetchOk();
    await handler(
      { messages: [{ role: "user", content: "hi" }], mode: "raw" },
      ctx("ingest_messages"),
    );
    const sent = JSON.parse(spy.mock.calls[0][1].body);
    expect(sent.mode).toBe("raw");
    expect(sent).not.toHaveProperty("session_id");
    expect(sent).not.toHaveProperty("agent_id");
    // No agent_id → no per-agent header.
    expect(spy.mock.calls[0][1].headers).not.toHaveProperty("X-Mnemo-Agent-Id");
  });

  it("rejects an empty or missing messages array without calling the backend", async () => {
    const spy = mockFetchOk();
    await expect(handler({ messages: [] }, ctx("ingest_messages"))).rejects.toThrow(
      /non-empty 'messages'/,
    );
    await expect(handler({}, ctx("ingest_messages"))).rejects.toThrow(/non-empty 'messages'/);
    expect(spy).not.toHaveBeenCalled();
  });
});

describe("proxy-handler routing (regression)", () => {
  it("add_memory still POSTs a single content body", async () => {
    const spy = mockFetchOk();
    await handler({ content: "one fact", agent_id: "a" }, ctx("add_memory"));
    const [url, init] = spy.mock.calls[0];
    expect(url).toBe("http://mnemo.mem9-test.local:8080/v1alpha2/mem9s/memories");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toEqual({ content: "one fact", agent_id: "a" });
  });

  it("search_memories GETs with the query string", async () => {
    const spy = mockFetchOk({ memories: [], total: 0 });
    await handler({ q: "arm64", limit: 5 }, ctx("search_memories"));
    const [url, init] = spy.mock.calls[0];
    expect(init.method).toBe("GET");
    expect(url).toContain("/v1alpha2/mem9s/memories?");
    expect(url).toContain("q=arm64");
    expect(url).toContain("limit=5");
  });

  it("throws on an unknown tool", async () => {
    mockFetchOk();
    await expect(handler({}, ctx("delete_everything"))).rejects.toThrow(/unknown tool/);
  });
});
