// Unit tests for the llm-proxy sidecar (docker/llm-proxy/server.mjs).
//
// Exercises the REAL HTTP server built by createProxyServer() over a loopback
// socket, with the token minter + upstream fetch injected — so we assert the
// actual routing, per-request header injection (fresh Bearer + OpenAI-Project),
// health gating, and error mapping without touching AWS or Bedrock Mantle.

import { afterEach, describe, expect, it, vi } from "vitest";
import { createProxyServer, makeDefaultMintToken, readConfig } from "./server.mjs";

// Start `server` on an ephemeral port; return {url, close}.
async function listen(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

const baseCfg = {
  port: 0,
  region: "ap-northeast-1",
  upstreamBase: "https://mantle.test/v1",
  openaiProject: "proj-abc",
  tokenTtlSeconds: 43200,
  refreshIntervalMs: 60 * 60 * 1000,
  upstreamTimeoutMs: 120_000,
};

const openInstances = [];
afterEach(async () => {
  while (openInstances.length) {
    const c = openInstances.pop();
    await c.close();
  }
  vi.restoreAllMocks();
});

async function boot(cfg, deps) {
  const { server, start, state } = createProxyServer(cfg, deps);
  const inst = await listen(server);
  openInstances.push(inst);
  return { ...inst, start, state };
}

describe("readConfig", () => {
  it("derives the Mantle upstream from the region", () => {
    const c = readConfig({ LLM_PROXY_REGION: "us-west-2" });
    expect(c.upstreamBase).toBe("https://bedrock-mantle.us-west-2.api.aws/v1");
    expect(c.region).toBe("us-west-2");
  });

  it("defaults the token TTL to 12h and refresh to 1h", () => {
    const c = readConfig({});
    expect(c.tokenTtlSeconds).toBe(43200); // getToken max/default
    expect(c.refreshIntervalMs).toBe(3_600_000);
  });

  it("honors an explicit upstream override + project", () => {
    const c = readConfig({ LLM_PROXY_UPSTREAM_BASE: "https://x/v1", LLM_PROXY_OPENAI_PROJECT: "p1" });
    expect(c.upstreamBase).toBe("https://x/v1");
    expect(c.openaiProject).toBe("p1");
  });
});

describe("createProxyServer", () => {
  it("throws without a mintToken dep", () => {
    expect(() => createProxyServer(baseCfg, {})).toThrow(/mintToken/);
  });

  it("injects a fresh Bearer + OpenAI-Project and forwards to Mantle /chat/completions", async () => {
    const mintToken = vi.fn().mockResolvedValue("bedrock-api-key-XYZ");
    let captured;
    const fetchImpl = vi.fn(async (targetUrl, opts) => {
      captured = { targetUrl, opts };
      return new Response(JSON.stringify({ choices: [{ message: { content: "PONG" } }] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    const { url, start } = await boot(baseCfg, { mintToken, fetchImpl });
    await start();

    const res = await fetch(`${url}/v1/chat/completions`, {
      method: "POST",
      headers: { Authorization: "Bearer dummy-static-key", "Content-Type": "application/json" },
      body: JSON.stringify({ model: "zai.glm-5", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(200);
    expect((await res.json()).choices[0].message.content).toBe("PONG");

    // Forwarded to the right upstream URL.
    expect(captured.targetUrl).toBe("https://mantle.test/v1/chat/completions");
    // The dummy inbound key is REPLACED with the minted bearer.
    expect(captured.opts.headers.Authorization).toBe("Bearer bedrock-api-key-XYZ");
    // Cost-attribution header injected.
    expect(captured.opts.headers["OpenAI-Project"]).toBe("proj-abc");
    // The minter was called exactly once (first mint), then cached.
    expect(mintToken).toHaveBeenCalledTimes(1);
  });

  it("accepts the /chat/completions path without the /v1 prefix", async () => {
    const fetchImpl = vi.fn(
      async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }),
    );
    const { url, start } = await boot(baseCfg, { mintToken: async () => "t", fetchImpl });
    await start();
    const res = await fetch(`${url}/chat/completions`, { method: "POST", body: "{}" });
    expect(res.status).toBe(200);
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("omits OpenAI-Project when no project is configured", async () => {
    let captured;
    const fetchImpl = vi.fn(async (_u, opts) => {
      captured = opts;
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    });
    const { url, start } = await boot({ ...baseCfg, openaiProject: "" }, { mintToken: async () => "t", fetchImpl });
    await start();
    await fetch(`${url}/v1/chat/completions`, { method: "POST", body: "{}" });
    expect(captured.headers["OpenAI-Project"]).toBeUndefined();
  });

  // 401-reactive re-mint (issue #24, TC-PROXY401-001…006): a bearer presigned
  // from expired task-role session credentials 401s until the hourly refresh
  // tick — the proxy must re-mint + retry once instead of serving the dead
  // bearer for up to an hour (2026-07-22 incident: 32 ingests lost).
  describe("401-reactive re-mint", () => {
    const authFailure = (status) =>
      new Response(JSON.stringify({ error: { code: "invalid_api_key", message: "The security token included in the request is invalid" } }), {
        status,
        headers: { "content-type": "application/json" },
      });
    const ok = () =>
      new Response(JSON.stringify({ choices: [{ message: { content: "PONG" } }] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });

    it("TC-PROXY401-001: re-mints once and retries with the fresh bearer on upstream 401", async () => {
      const mintToken = vi
        .fn()
        .mockResolvedValueOnce("stale-bearer")
        .mockResolvedValueOnce("fresh-bearer");
      const seenAuth = [];
      const fetchImpl = vi.fn(async (_u, opts) => {
        seenAuth.push(opts.headers.Authorization);
        return seenAuth.length === 1 ? authFailure(401) : ok();
      });
      const { url, start } = await boot(baseCfg, { mintToken, fetchImpl });
      await start();

      const res = await fetch(`${url}/v1/chat/completions`, { method: "POST", body: "{}" });
      expect(res.status).toBe(200);
      expect((await res.json()).choices[0].message.content).toBe("PONG");
      expect(mintToken).toHaveBeenCalledTimes(2); // initial + 401-triggered re-mint
      expect(seenAuth).toEqual(["Bearer stale-bearer", "Bearer fresh-bearer"]);
    });

    it("TC-PROXY401-002: a 401 on the retry passes through — no retry loop", async () => {
      const mintToken = vi.fn().mockResolvedValue("t");
      const fetchImpl = vi.fn(async () => authFailure(401));
      const { url, start } = await boot(baseCfg, { mintToken, fetchImpl });
      await start();

      const res = await fetch(`${url}/v1/chat/completions`, { method: "POST", body: "{}" });
      expect(res.status).toBe(401); // mem9 sees the real upstream status
      expect((await res.json()).error.code).toBe("invalid_api_key");
      expect(fetchImpl).toHaveBeenCalledTimes(2); // original + exactly one retry
      expect(mintToken).toHaveBeenCalledTimes(2); // initial + one re-mint
    });

    it("TC-PROXY401-003: 403 takes the same re-mint+retry path", async () => {
      const mintToken = vi.fn().mockResolvedValue("t");
      const fetchImpl = vi
        .fn()
        .mockResolvedValueOnce(authFailure(403))
        .mockResolvedValueOnce(ok());
      const { url, start } = await boot(baseCfg, { mintToken, fetchImpl });
      await start();

      const res = await fetch(`${url}/v1/chat/completions`, { method: "POST", body: "{}" });
      expect(res.status).toBe(200);
      expect(mintToken).toHaveBeenCalledTimes(2);
    });

    it("TC-PROXY401-004: non-auth statuses (400/429/500) do NOT re-mint", async () => {
      for (const status of [400, 429, 500]) {
        const mintToken = vi.fn().mockResolvedValue("t");
        const fetchImpl = vi.fn(
          async () => new Response("{}", { status, headers: { "content-type": "application/json" } }),
        );
        const { url, start } = await boot(baseCfg, { mintToken, fetchImpl });
        await start();

        const res = await fetch(`${url}/v1/chat/completions`, { method: "POST", body: "{}" });
        expect(res.status).toBe(status);
        expect(fetchImpl).toHaveBeenCalledTimes(1); // no retry
        expect(mintToken).toHaveBeenCalledTimes(1); // no re-mint
      }
    });

    it("TC-PROXY401-005: a re-mint failure maps to the existing 502 shape", async () => {
      const mintToken = vi
        .fn()
        .mockResolvedValueOnce("stale-bearer")
        .mockRejectedValueOnce(new Error("provider chain empty"));
      const fetchImpl = vi.fn(async () => authFailure(401));
      const { url, start } = await boot(baseCfg, { mintToken, fetchImpl });
      await start();

      const res = await fetch(`${url}/v1/chat/completions`, { method: "POST", body: "{}" });
      expect(res.status).toBe(502);
      expect((await res.json()).error.type).toBe("server_error");
    });

    it("TC-PROXY401-006: logs a distinct, countable line on the re-mint path", async () => {
      const logSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const mintToken = vi.fn().mockResolvedValue("t");
      const fetchImpl = vi
        .fn()
        .mockResolvedValueOnce(authFailure(401))
        .mockResolvedValueOnce(ok());
      const { url, start } = await boot(baseCfg, { mintToken, fetchImpl });
      await start();

      await fetch(`${url}/v1/chat/completions`, { method: "POST", body: "{}" });
      // The full prefix is a stable contract — the #26 CloudWatch metric
      // filter matches it verbatim. Do not loosen this assertion.
      const line = logSpy.mock.calls.map((c) => c.join(" ")).find((m) => /re-mint/.test(m));
      expect(line).toBe("llm-proxy re-minted bearer after upstream 401");
    });
  });

  // TC-PROXY401-007: the default minter must resolve credentials FRESH per
  // mint. A shared fromNodeProviderChain() memoizes; a bearer re-signed from
  // the same dead session after a 401 would 401 again (the incident's root
  // cause). The factory takes injectable deps so this is testable without AWS.
  it("TC-PROXY401-007: default minter resolves fresh credentials on every mint", async () => {
    const resolved = [];
    const createProvider = vi.fn(() => {
      const creds = { accessKeyId: `AK${createProvider.mock.calls.length}`, secretAccessKey: "s" };
      return async () => {
        resolved.push(creds.accessKeyId);
        return creds;
      };
    });
    const getToken = vi.fn(async ({ credentials }) => `bearer-for-${credentials.accessKeyId}`);
    const mintToken = makeDefaultMintToken(
      { region: "ap-northeast-1", tokenTtlSeconds: 43200 },
      { createProvider, getToken },
    );

    expect(await mintToken()).toBe("bearer-for-AK1");
    expect(await mintToken()).toBe("bearer-for-AK2");
    // A NEW provider chain per mint — never a memoized instance.
    expect(createProvider).toHaveBeenCalledTimes(2);
    expect(resolved).toEqual(["AK1", "AK2"]);
  });

  it("passes the upstream status + body straight through on a Mantle 4xx", async () => {
    const fetchImpl = vi.fn(
      async () =>
        new Response(JSON.stringify({ error: { message: "bad model" } }), {
          status: 400,
          headers: { "content-type": "application/json" },
        }),
    );
    const { url, start } = await boot(baseCfg, { mintToken: async () => "t", fetchImpl });
    await start();
    const res = await fetch(`${url}/v1/chat/completions`, { method: "POST", body: "{}" });
    expect(res.status).toBe(400); // mem9 relies on seeing the real upstream status
    expect((await res.json()).error.message).toBe("bad model");
  });

  it("returns 502 when the upstream fetch throws (Mantle unreachable)", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("ECONNREFUSED");
    });
    const { url, start } = await boot(baseCfg, { mintToken: async () => "t", fetchImpl });
    await start();
    const res = await fetch(`${url}/v1/chat/completions`, { method: "POST", body: "{}" });
    expect(res.status).toBe(502);
    expect((await res.json()).error.type).toBe("server_error");
  });

  it("returns 504 when the upstream fetch aborts (timeout)", async () => {
    const fetchImpl = vi.fn(async () => {
      const e = new Error("aborted");
      e.name = "AbortError";
      throw e;
    });
    const { url, start } = await boot(baseCfg, { mintToken: async () => "t", fetchImpl });
    await start();
    const res = await fetch(`${url}/v1/chat/completions`, { method: "POST", body: "{}" });
    expect(res.status).toBe(504);
  });

  it("404s unknown routes", async () => {
    const { url, start } = await boot(baseCfg, { mintToken: async () => "t", fetchImpl: vi.fn() });
    await start();
    const res = await fetch(`${url}/nope`);
    expect(res.status).toBe(404);
    expect((await res.json()).error.type).toBe("not_found");
  });

  describe("/health readiness gating", () => {
    it("is 503 before the first mint completes, 200 after", async () => {
      let release;
      const gate = new Promise((r) => {
        release = r;
      });
      const mintToken = vi.fn(async () => {
        await gate;
        return "bedrock-api-key-ready";
      });
      const { url, start } = await boot(baseCfg, { mintToken, fetchImpl: vi.fn() });
      const startPromise = start(); // kicks off the (blocked) first mint

      const before = await fetch(`${url}/health`);
      expect(before.status).toBe(503);
      expect((await before.json()).status).toBe("starting");

      release();
      await startPromise;

      const after = await fetch(`${url}/health`);
      expect(after.status).toBe(200);
      expect((await after.json()).status).toBe("ok");
    });

    it("stays 503 when the first mint fails (creds missing at cold start)", async () => {
      const mintToken = vi.fn().mockRejectedValue(new Error("no credentials"));
      const { url, start } = await boot(baseCfg, { mintToken, fetchImpl: vi.fn() });
      await start().catch(() => {}); // start surfaces the failure; swallow here
      const res = await fetch(`${url}/health`);
      expect(res.status).toBe(503);
    });
  });

  it("recovers on a later request after the first mint rejected (no permanently-cached rejection)", async () => {
    // First mint fails, second succeeds — the proxy must NOT pin the rejected
    // first-mint promise forever, or it could never self-heal a transient
    // cold-start credential hiccup via the request path.
    const mintToken = vi
      .fn()
      .mockRejectedValueOnce(new Error("transient creds hiccup"))
      .mockResolvedValue("bedrock-api-key-recovered");
    const fetchImpl = vi.fn(
      async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }),
    );
    const { url } = await boot(baseCfg, { mintToken, fetchImpl });

    // First request: the mint rejects → proxy returns 502.
    const first = await fetch(`${url}/v1/chat/completions`, { method: "POST", body: "{}" });
    expect(first.status).toBe(502);

    // Second request: mint now succeeds → the proxy self-heals and forwards.
    const second = await fetch(`${url}/v1/chat/completions`, { method: "POST", body: "{}" });
    expect(second.status).toBe(200);
    expect(mintToken).toHaveBeenCalledTimes(2); // retried, not cached-rejected
  });
});
