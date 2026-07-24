import { createServer, request as httpRequest } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createProxyServer } from "./server.mjs";

const body = JSON.stringify({
  model: "zai.glm-5",
  messages: [{ role: "user", content: "integration request" }],
});

const shortCfg = {
  port: 0,
  region: "ap-northeast-1",
  upstreamBase: "",
  openaiProject: "project-test",
  maxBodyBytes: 1_048_576,
  maxTokens: 4096,
  tokenTtlSeconds: 43_200,
  refreshIntervalMs: 3_600_000,
  overallDeadlineMs: 180,
  maxCallMs: 160,
  responseReserveMs: 20,
  retryMinCallBudgetMs: 50,
  backoffBaseMs: 20,
  backoffCapMs: 20,
};

const closers = [];

async function listen(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  closers.push(() => new Promise((resolve) => server.close(resolve)));
  return `http://127.0.0.1:${port}`;
}

async function bootProxy(cfg, deps = {}) {
  const proxy = createProxyServer(cfg, {
    mintToken: vi.fn().mockResolvedValue("fake-bearer"),
    log: () => {},
    ...deps,
  });
  const url = await listen(proxy.server);
  await proxy.start();
  return { ...proxy, url };
}

async function post(url) {
  const response = await fetch(`${url}/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
  return { status: response.status, body: await response.text() };
}

afterEach(async () => {
  while (closers.length) await closers.pop()();
  vi.restoreAllMocks();
});

describe("llm-proxy HTTP deadline integration", () => {
  it("TC-GLM-RETRY-024: fake Mantle fast 503 then 200 preserves final status/body", async () => {
    let calls = 0;
    const mantleUrl = await listen(
      createServer(async (req, res) => {
        for await (const _chunk of req) {
          // Drain the real forwarded request body.
        }
        calls += 1;
        if (calls === 1) {
          res.writeHead(503, { "content-type": "application/json" });
          return res.end('{"error":"retry"}');
        }
        res.writeHead(200, { "content-type": "application/json" });
        return res.end('{"choices":[{"message":{"content":"PONG"}}]}');
      }),
    );
    const logs = [];
    const proxy = await bootProxy(
      { ...shortCfg, upstreamBase: `${mantleUrl}/v1` },
      {
        random: () => 1,
        requestId: () => "e2e-retry",
        log: (record) => logs.push(record),
      },
    );

    const started = performance.now();
    const result = await post(proxy.url);
    const elapsed = performance.now() - started;
    expect(result).toEqual({
      status: 200,
      body: '{"choices":[{"message":{"content":"PONG"}}]}',
    });
    expect(calls).toBe(2);
    expect(elapsed).toBeGreaterThanOrEqual(15);
    expect(elapsed).toBeLessThan(shortCfg.overallDeadlineMs);
    expect(logs.map((record) => record.attempt)).toEqual([1, 2]);
  });

  it("TC-GLM-RETRY-025: fake Mantle over call budget returns bounded 504", async () => {
    let aborted = false;
    const mantleUrl = await listen(
      createServer((req, res) => {
        req.on("aborted", () => {
          aborted = true;
        });
        setTimeout(() => {
          if (!res.destroyed) {
            res.writeHead(200, { "content-type": "application/json" });
            res.end("{}");
          }
        }, 500);
      }),
    );
    const proxy = await bootProxy({
      ...shortCfg,
      upstreamBase: `${mantleUrl}/v1`,
      overallDeadlineMs: 120,
      maxCallMs: 100,
    });

    const started = performance.now();
    const result = await post(proxy.url);
    const elapsed = performance.now() - started;
    expect(result.status).toBe(504);
    expect(JSON.parse(result.body).error.code).toBe("upstream_timeout");
    expect(elapsed).toBeGreaterThanOrEqual(80);
    expect(elapsed).toBeLessThan(160);
    await vi.waitFor(() => expect(aborted).toBe(true));
  });

  it("TC-GLM-RETRY-028: keeps the overall deadline active while writing the response", async () => {
    const mantleUrl = await listen(
      createServer((_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end("{}");
      }),
    );
    let releaseWrite;
    const writeBlocked = new Promise((resolve) => {
      releaseWrite = resolve;
    });
    const logs = [];
    const proxy = await bootProxy(
      {
        ...shortCfg,
        upstreamBase: `${mantleUrl}/v1`,
        overallDeadlineMs: 80,
        maxCallMs: 60,
      },
      {
        requestId: () => "response-write-timeout",
        log: (record) => logs.push(record),
        writeResponse: async () => writeBlocked,
      },
    );

    const started = performance.now();
    await expect(post(proxy.url)).rejects.toThrow();
    expect(performance.now() - started).toBeLessThan(130);
    await vi.waitFor(() =>
      expect(logs.at(-1)).toMatchObject({
        request_id: "response-write-timeout",
        attempt: 1,
        reason: "overall_deadline",
        outcome_class: "deadline",
      }),
    );
    releaseWrite();
  });

  it("TC-GLM-RETRY-029: logs downstream cancellation while reading the body", async () => {
    const logs = [];
    const proxy = await bootProxy(
      {
        ...shortCfg,
        upstreamBase: "http://127.0.0.1:1/v1",
        overallDeadlineMs: 500,
        maxCallMs: 480,
      },
      {
        requestId: () => "body-read-cancel",
        log: (record) => logs.push(record),
      },
    );

    const client = httpRequest(`${proxy.url}/v1/chat/completions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(body) + 100,
      },
    });
    client.on("error", () => {});
    client.write(body.slice(0, 20));
    await new Promise((resolve) => setTimeout(resolve, 10));
    client.destroy();

    await vi.waitFor(() =>
      expect(logs.at(-1)).toMatchObject({
        request_id: "body-read-cancel",
        attempt: 0,
        reason: "downstream_disconnect",
        outcome_class: "deadline",
      }),
    );
  });

  it("TC-GLM-RETRY-026: downstream disconnect cancels the active Mantle call", async () => {
    let calls = 0;
    let upstreamAborted = false;
    let releaseMantle;
    const mantleStarted = new Promise((resolve) => {
      releaseMantle = resolve;
    });
    const mantleUrl = await listen(
      createServer((req) => {
        calls += 1;
        releaseMantle();
        req.on("aborted", () => {
          upstreamAborted = true;
        });
      }),
    );
    const proxy = await bootProxy({
      ...shortCfg,
      upstreamBase: `${mantleUrl}/v1`,
      overallDeadlineMs: 500,
      maxCallMs: 480,
    });

    const client = httpRequest(`${proxy.url}/v1/chat/completions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(body),
      },
    });
    client.on("error", () => {});
    client.end(body);
    await mantleStarted;
    client.destroy();

    await vi.waitFor(() => expect(upstreamAborted).toBe(true));
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(calls).toBe(1);
  });

  it("TC-GLM-RETRY-027: provider-400 fallback receives a fresh request budget", async () => {
    let calls = 0;
    const mantleUrl = await listen(
      createServer(async (req, res) => {
        for await (const _chunk of req) {
          // Drain the request before delaying the scripted provider result.
        }
        calls += 1;
        await new Promise((resolve) => setTimeout(resolve, 70));
        res.writeHead(calls === 1 ? 400 : 200, { "content-type": "application/json" });
        res.end(calls === 1 ? "provider rejected flag" : '{"ok":true}');
      }),
    );
    const ids = ["fallback-original", "fallback-retry"];
    const logs = [];
    const proxy = await bootProxy(
      {
        ...shortCfg,
        upstreamBase: `${mantleUrl}/v1`,
        overallDeadlineMs: 120,
        maxCallMs: 100,
      },
      {
        requestId: () => ids.shift(),
        log: (record) => logs.push(record),
      },
    );

    const first = await post(proxy.url);
    const second = await post(proxy.url);
    expect(first).toEqual({ status: 400, body: "provider rejected flag" });
    expect(second).toEqual({ status: 200, body: '{"ok":true}' });
    expect(calls).toBe(2);
    expect(logs.map((record) => record.request_id)).toEqual([
      "fallback-original",
      "fallback-retry",
    ]);
    expect(logs[0].remaining_budget_ms).toBeGreaterThan(20);
    expect(logs[1].remaining_budget_ms).toBeGreaterThan(20);
  });
});
