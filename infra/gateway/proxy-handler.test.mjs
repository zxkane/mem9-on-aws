// Unit tests for the AgentCore Gateway → mnemo-server proxy Lambda handler.
//
// The handler reads MEM9_SERVER_BASE_URL / MEM9_API_KEY at module load, so we set
// them before a dynamic import, then drive the exported `handler` with a mocked
// global `fetch` and a fake Lambda context (clientContext.Custom carries the
// AgentCore `${target}___${tool}` name). We assert the outbound request shape for
// each tool WITHOUT touching AWS, DNS, or a live mnemo-server.

import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import {
  INTERNAL_AUTH_FIELD,
  createInternalContext,
  parseSigningKeys,
} from "./namespace-auth.mjs";

process.env.MEM9_SERVER_BASE_URL = "http://mnemo.mem9-test.local:8080";
process.env.MEM9_API_KEY = "test-tenant-id";
process.env.MEM9_IDENTITY_SIGNING_KEYS = JSON.stringify({
  current: Buffer.alloc(32, 4).toString("base64url"),
});
process.env.MEM9_TRANSPORT_SIGNING_KEYS = JSON.stringify({
  current: Buffer.alloc(32, 5).toString("base64url"),
});
process.env.MEM9_TRANSPORT_ISSUER = "gateway-target";

const identityKeys = parseSigningKeys(process.env.MEM9_IDENTITY_SIGNING_KEYS);
let rawHandler;
let handler;
beforeAll(async () => {
  ({ handler: rawHandler } = await import("./proxy-handler.mjs"));
  handler = (input, context) => {
    const rawTool =
      context?.clientContext?.Custom?.bedrockAgentCoreToolName ?? "";
    const tool = rawTool.includes("___")
      ? rawTool.slice(rawTool.lastIndexOf("___") + 3)
      : rawTool;
    const args = { ...(input ?? {}) };
    delete args[INTERNAL_AUTH_FIELD];
    return rawHandler(
      {
        ...args,
        [INTERNAL_AUTH_FIELD]: createInternalContext({
          invocation: { tool, arguments: args },
          identity: {
            issuer: "https://cognito-idp.example.invalid/pool",
            principalType: "human",
            subject: "human-subject",
            clientId: "reader-client",
            groups: ["team-a"],
          },
          keys: identityKeys,
        }),
      },
      context,
    );
  };
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
    expect(init.headers["X-Mem9-Transport"]).toMatch(/^[^.]+\.[0-9a-f]{64}$/u);
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
  it("rejects interceptor events because identity and target Lambdas are split", async () => {
    const spy = mockFetchOk();
    await expect(
      rawHandler(
        { interceptorInputVersion: "1.0", mcp: {} },
        ctx("search_memories"),
      ),
    ).rejects.toThrow(/internal context/u);
    expect(spy).not.toHaveBeenCalled();
  });

  it("add_memory still POSTs a single content body", async () => {
    const spy = mockFetchOk();
    await handler({ content: "one fact", agent_id: "a" }, ctx("add_memory"));
    const [url, init] = spy.mock.calls[0];
    expect(url).toBe("http://mnemo.mem9-test.local:8080/v1alpha2/mem9s/memories");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toEqual({ content: "one fact", agent_id: "a" });
    expect(init.body).not.toContain(INTERNAL_AUTH_FIELD);
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

  it("TC-GROUPNS-030/034: rejects a tampered context before fetch", async () => {
    const spy = mockFetchOk();
    const tool = "search_memories";
    const args = { q: "arm64" };
    const context = structuredClone(createInternalContext({
      invocation: { tool, arguments: args },
      identity: {
        issuer: "https://cognito-idp.example.invalid/pool",
        principalType: "human",
        subject: "human-subject",
        clientId: "reader-client",
        groups: ["team-a"],
      },
      keys: identityKeys,
    }));
    context.request_hash = "0".repeat(64);
    await expect(
      rawHandler(
        { ...args, [INTERNAL_AUTH_FIELD]: context },
        ctx(tool),
      ),
    ).rejects.toThrow(/request hash|signature/u);
    expect(spy).not.toHaveBeenCalled();
  });
});

describe("proxy-handler get_ingest_job_status", () => {
  it("GETs status with the configured tenant key and accepts only job_id", async () => {
    const status = {
      job_id: "job-54",
      state: "succeeded",
      attempts: 1,
      warning_class: "facts_truncated",
      created_at: "2026-07-26T12:00:00Z",
      updated_at: "2026-07-26T12:01:00Z",
      completed_at: "2026-07-26T12:01:00Z",
      canonical_payload: "payload-leak",
      plan_payload: "plan-leak",
      lease_owner: "owner-leak",
    };
    const spy = mockFetchOk(status);
    const result = await handler(
      { job_id: "job-54", tenant_id: "attacker", api_key: "attacker" },
      ctx("get_ingest_job_status"),
    );
    expect(result).toEqual({
      job_id: "job-54",
      state: "succeeded",
      attempts: 1,
      warning_class: "facts_truncated",
      created_at: "2026-07-26T12:00:00Z",
      updated_at: "2026-07-26T12:01:00Z",
      completed_at: "2026-07-26T12:01:00Z",
    });
    expect(JSON.stringify(result)).not.toMatch(/payload-leak|plan-leak|owner-leak/);
    const [url, init] = spy.mock.calls[0];
    expect(url).toBe(
      "http://mnemo.mem9-test.local:8080/v1alpha2/mem9s/ingest-jobs/job-54",
    );
    expect(init.method).toBe("GET");
    expect(init.headers["X-API-Key"]).toBe("test-tenant-id");
    expect(url).not.toContain("attacker");
    expect(JSON.stringify(init)).not.toContain("attacker");
  });

  it("preserves not-found without retries, response-body leakage, or logging", async () => {
    const fetchSpy = vi.fn(async () => ({
      ok: false,
      status: 404,
      text: async () => '{"error":"not found","private":"payload-leak"}',
    }));
    const logSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    vi.stubGlobal("fetch", fetchSpy);

    let message = "";
    try {
      await handler({ job_id: "job-other" }, ctx("get_ingest_job_status"));
    } catch (error) {
      message = String(error);
    }
    expect(message).toContain("returned 404");
    expect(message).not.toContain("payload-leak");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(logSpy).not.toHaveBeenCalled();
  });

  it("requires a non-empty job_id", async () => {
    const spy = mockFetchOk();
    await expect(handler({}, ctx("get_ingest_job_status"))).rejects.toThrow(/requires 'job_id'/);
    expect(spy).not.toHaveBeenCalled();
  });
});
