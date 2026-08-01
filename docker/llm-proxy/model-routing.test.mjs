// Unit tests for llm-proxy multi-model routing (docs/test-cases/llm-proxy-multi-model.md).
//
// Route resolution + both API translations are tested directly; the routing
// behavior of the real HTTP server is tested over loopback with injected fetch
// and a region-aware token minter — no AWS, no Mantle.

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createProxyServer,
  readConfig,
  resolveRoute,
  translateChatToResponses,
  translateResponsesToChat,
} from "./server.mjs";

async function listen(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

const openInstances = [];
afterEach(async () => {
  while (openInstances.length) await openInstances.pop().close();
  vi.restoreAllMocks();
});

async function boot(cfg, deps) {
  const { server, start, state } = createProxyServer(cfg, { log: () => {}, ...deps });
  const inst = await listen(server);
  openInstances.push(inst);
  return { ...inst, start, state };
}

// Full config with both routes wired to fake endpoints.
const cfg = {
  port: 0,
  region: "ap-northeast-1",
  upstreamBase: "https://mantle-tokyo.test/v1",
  openaiProject: "proj-tokyo",
  maxBodyBytes: 1_048_576,
  maxTokens: 4096,
  tokenTtlSeconds: 43200,
  refreshIntervalMs: 60 * 60 * 1000,
  responsesModelPrefixes: ["openai.gpt-5.6-"],
  responsesRegion: "us-west-2",
  responsesBase: "https://mantle-west.test/openai/v1",
  reasoningEffort: "high",
  responsesMaxOutputTokens: 16384,
  responsesOpenaiProject: "proj-west",
};

const terraChat = {
  model: "openai.gpt-5.6-terra",
  messages: [
    { role: "system", content: "you judge memories" },
    { role: "user", content: "classify this" },
  ],
};

function responsesReply(overrides = {}) {
  return {
    id: "resp_1",
    status: "completed",
    output: [
      { type: "reasoning", content: [] },
      { type: "message", content: [{ type: "output_text", text: '{"verdicts":[]}' }] },
    ],
    usage: { input_tokens: 100, output_tokens: 40 },
    ...overrides,
  };
}

describe("readConfig responses-route fields", () => {
  it("defaults: gpt-5.6 prefix, us-west-2, derived base, high effort, 16384 cap", () => {
    const c = readConfig({});
    expect(c.responsesModelPrefixes).toEqual(["openai.gpt-5.6-"]);
    expect(c.responsesRegion).toBe("us-west-2");
    expect(c.responsesBase).toBe("https://bedrock-mantle.us-west-2.api.aws/openai/v1");
    expect(c.reasoningEffort).toBe("high");
    expect(c.responsesMaxOutputTokens).toBe(16384);
    expect(c.responsesOpenaiProject).toBe("");
  });

  it("honors overrides and comma-separated prefixes with empties ignored (TC-MMROUTE-002)", () => {
    const c = readConfig({
      LLM_PROXY_RESPONSES_MODEL_PREFIXES: "openai., ,custom.reasoner-",
      LLM_PROXY_RESPONSES_REGION: "us-east-1",
      LLM_PROXY_REASONING_EFFORT: "medium",
      LLM_PROXY_RESPONSES_MAX_OUTPUT_TOKENS: "8000",
      LLM_PROXY_RESPONSES_OPENAI_PROJECT: "proj-east",
    });
    expect(c.responsesModelPrefixes).toEqual(["openai.", "custom.reasoner-"]);
    expect(c.responsesRegion).toBe("us-east-1");
    expect(c.responsesBase).toBe("https://bedrock-mantle.us-east-1.api.aws/openai/v1");
    expect(c.reasoningEffort).toBe("medium");
    expect(c.responsesMaxOutputTokens).toBe(8000);
    expect(c.responsesOpenaiProject).toBe("proj-east");
  });

  it("rejects an invalid reasoning effort at startup", () => {
    expect(() => readConfig({ LLM_PROXY_REASONING_EFFORT: "max" })).toThrow(/effort/i);
  });
});

describe("resolveRoute (TC-MMROUTE-001)", () => {
  it("routes unmatched models to chat with the regional base", () => {
    const r = resolveRoute("zai.glm-5", cfg);
    expect(r).toMatchObject({
      kind: "chat",
      region: "ap-northeast-1",
      openaiProject: "proj-tokyo",
    });
    expect(r.url).toBe("https://mantle-tokyo.test/v1/chat/completions");
  });

  it.each(["openai.gpt-5.6-terra", "openai.gpt-5.6-luna"])(
    "routes %s to the responses route in the responses region",
    (model) => {
      const r = resolveRoute(model, cfg);
      expect(r).toMatchObject({
        kind: "responses",
        region: "us-west-2",
        openaiProject: "proj-west",
      });
      expect(r.url).toBe("https://mantle-west.test/openai/v1/responses");
    },
  );
});

describe("translateChatToResponses", () => {
  it("TC-MMROUTE-010: system → instructions, other messages → input, model preserved", () => {
    const out = translateChatToResponses(terraChat, cfg);
    expect(out.model).toBe("openai.gpt-5.6-terra");
    expect(out.instructions).toBe("you judge memories");
    expect(out.input).toEqual([{ role: "user", content: "classify this" }]);
    expect(out.reasoning).toEqual({ effort: "high" });
    expect(out.max_output_tokens).toBe(16384);
  });

  it("joins multiple system messages with newlines", () => {
    const out = translateChatToResponses(
      {
        model: "openai.gpt-5.6-terra",
        messages: [
          { role: "system", content: "a" },
          { role: "system", content: "b" },
          { role: "user", content: "c" },
        ],
      },
      cfg,
    );
    expect(out.instructions).toBe("a\nb");
    expect(out.input).toEqual([{ role: "user", content: "c" }]);
  });

  it("TC-MMROUTE-011: max_tokens maps to max_output_tokens within the responses cap", () => {
    const ok = translateChatToResponses({ ...terraChat, max_tokens: 9000 }, cfg);
    expect(ok.max_output_tokens).toBe(9000);
    for (const bad of [0, -1, 1.5, "x", 16385]) {
      expect(() => translateChatToResponses({ ...terraChat, max_tokens: bad }, cfg)).toThrow(
        /max_tokens/,
      );
    }
  });

  it("TC-MMROUTE-012: request reasoning_effort wins; invalid values 400", () => {
    const out = translateChatToResponses({ ...terraChat, reasoning_effort: "low" }, cfg);
    expect(out.reasoning).toEqual({ effort: "low" });
    expect(() =>
      translateChatToResponses({ ...terraChat, reasoning_effort: "ultra" }, cfg),
    ).toThrow(/reasoning_effort/);
  });

  it("rejects array-of-parts message content (Responses names part types differently)", () => {
    expect(() =>
      translateChatToResponses(
        {
          model: "openai.gpt-5.6-terra",
          messages: [{ role: "user", content: [{ type: "text", text: "hi" }] }],
        },
        cfg,
      ),
    ).toThrow(/string content/);
  });

  it("TC-MMROUTE-013: unknown chat fields are not forwarded", () => {
    const out = translateChatToResponses(
      { ...terraChat, temperature: 0.5, tools: [{ a: 1 }], stream: true },
      cfg,
    );
    expect(out).not.toHaveProperty("temperature");
    expect(out).not.toHaveProperty("tools");
    expect(out).not.toHaveProperty("stream");
    expect(out).not.toHaveProperty("messages");
  });
});

describe("translateResponsesToChat", () => {
  it("TC-MMROUTE-020: joins output_text, maps usage, finish_reason stop", () => {
    const chat = translateResponsesToChat(responsesReply(), "openai.gpt-5.6-terra");
    expect(chat.object).toBe("chat.completion");
    expect(chat.model).toBe("openai.gpt-5.6-terra");
    expect(chat.choices).toEqual([
      {
        index: 0,
        message: { role: "assistant", content: '{"verdicts":[]}' },
        finish_reason: "stop",
      },
    ]);
    expect(chat.usage).toEqual({ prompt_tokens: 100, completion_tokens: 40, total_tokens: 140 });
  });

  it("TC-MMROUTE-021: incomplete → partial text with finish_reason length", () => {
    const chat = translateResponsesToChat(
      responsesReply({ status: "incomplete", incomplete_details: { reason: "max_output_tokens" } }),
      "m",
    );
    expect(chat.choices[0].finish_reason).toBe("length");
    expect(chat.choices[0].message.content).toBe('{"verdicts":[]}');
  });
});

describe("translation edge cases", () => {
  it("TC-MMROUTE-025: failed/cancelled/unknown statuses throw — never an empty 'stop' completion", () => {
    for (const status of ["failed", "cancelled", "queued", "in_progress", undefined]) {
      expect(() =>
        translateResponsesToChat(
          { id: "r", status, output: [], error: { message: "model exploded" } },
          "m",
        ),
      ).toThrow(/responses status/);
    }
  });

  it("TC-MMROUTE-026: a completed reply with no output_text is a contract breach", () => {
    expect(() =>
      translateResponsesToChat(
        { id: "r", status: "completed", output: [{ type: "reasoning", content: [] }] },
        "m",
      ),
    ).toThrow(/no output_text/);
  });

  it("TC-MMROUTE-023 detail: schema-shaped garbage throws instead of translating to empty", () => {
    for (const bad of [{}, { output: {} }, { status: "completed" }]) {
      expect(() => translateResponsesToChat(bad, "m")).toThrow();
    }
  });

  it("reasoning items never leak into message content (filter is part-type-based)", () => {
    const chat = translateResponsesToChat(
      {
        id: "resp_r",
        status: "completed",
        output: [
          {
            type: "reasoning",
            content: [{ type: "reasoning_text", text: "SECRET chain of thought" }],
            summary: [{ type: "summary_text", text: "thinking summary" }],
          },
          { type: "message", content: [{ type: "output_text", text: "visible" }] },
        ],
        usage: { input_tokens: 1, output_tokens: 1 },
      },
      "m",
    );
    expect(chat.choices[0].message.content).toBe("visible");
    expect(chat.choices[0].message.content).not.toContain("SECRET");
  });
});

describe("server routing integration", () => {
  it("routes a terra request via the responses base with translation both ways", async () => {
    const mintToken = vi.fn(async (region) => `bearer-${region}`);
    let captured;
    const fetchImpl = vi.fn(async (targetUrl, opts) => {
      captured = { targetUrl, opts };
      return new Response(JSON.stringify(responsesReply()), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    const { url, start } = await boot(cfg, { mintToken, fetchImpl });
    await start();

    const res = await fetch(`${url}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(terraChat),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.choices[0].message.content).toBe('{"verdicts":[]}');

    expect(captured.targetUrl).toBe("https://mantle-west.test/openai/v1/responses");
    const sent = JSON.parse(Buffer.from(captured.opts.body).toString());
    expect(sent.instructions).toBe("you judge memories");
    expect(sent.reasoning).toEqual({ effort: "high" });
    // TC-MMROUTE-040: the responses-region project header, not Tokyo's.
    expect(captured.opts.headers["OpenAI-Project"]).toBe("proj-west");
    // TC-MMROUTE-030: bearer minted for the responses region.
    expect(captured.opts.headers.Authorization).toBe("Bearer bearer-us-west-2");
  });

  it("TC-MMROUTE-030/033: responses region mints lazily; health keys on default region", async () => {
    const mintToken = vi.fn(async (region) => `bearer-${region}`);
    const fetchImpl = vi.fn(
      async () =>
        new Response(JSON.stringify(responsesReply()), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    const { url, start } = await boot(cfg, { mintToken, fetchImpl });
    await start();
    // Only the default region minted at start.
    expect(mintToken.mock.calls.map((c) => c[0] ?? cfg.region)).toEqual(["ap-northeast-1"]);
    expect((await fetch(`${url}/healthz`)).status).toBe(200);

    await fetch(`${url}/v1/chat/completions`, {
      method: "POST",
      body: JSON.stringify(terraChat),
    });
    expect(mintToken.mock.calls.map((c) => c[0] ?? cfg.region)).toEqual([
      "ap-northeast-1",
      "us-west-2",
    ]);

    // Second terra request reuses the cached responses-region bearer.
    await fetch(`${url}/v1/chat/completions`, {
      method: "POST",
      body: JSON.stringify(terraChat),
    });
    expect(mintToken).toHaveBeenCalledTimes(2);
  });

  it("TC-MMROUTE-032: a 401 on the responses route re-mints the responses region and retries", async () => {
    const mintToken = vi.fn(async (region) => `bearer-${region}-${mintToken.mock.calls.length}`);
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(new Response("{}", { status: 401 }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify(responsesReply()), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      );
    const { url, start } = await boot(cfg, { mintToken, fetchImpl });
    await start();

    const res = await fetch(`${url}/v1/chat/completions`, {
      method: "POST",
      body: JSON.stringify(terraChat),
    });
    expect(res.status).toBe(200);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    // start() mint (tokyo) + lazy responses mint + 401 re-mint = 3 mints; the
    // re-mint targeted the RESPONSES region.
    const regions = mintToken.mock.calls.map((c) => c[0] ?? cfg.region);
    expect(regions).toEqual(["ap-northeast-1", "us-west-2", "us-west-2"]);
    // Retry used the re-minted (3rd-mint) bearer, not the lazy first one.
    expect(fetchImpl.mock.calls[1][1].headers.Authorization).toBe("Bearer bearer-us-west-2-3");
  });

  it("TC-MMROUTE-022: upstream non-2xx passes through untranslated", async () => {
    const fetchImpl = vi.fn(
      async () =>
        new Response(JSON.stringify({ error: { message: "boom" } }), {
          status: 400,
          headers: { "content-type": "application/json" },
        }),
    );
    const { url, start } = await boot(cfg, { mintToken: async () => "t", fetchImpl });
    await start();
    const res = await fetch(`${url}/v1/chat/completions`, {
      method: "POST",
      body: JSON.stringify(terraChat),
    });
    expect(res.status).toBe(400);
    expect((await res.json()).error.message).toBe("boom");
  });

  it("TC-MMROUTE-050: a glm-5 request is byte-identical to the legacy chat path", async () => {
    let captured;
    const fetchImpl = vi.fn(async (targetUrl, opts) => {
      captured = { targetUrl, opts };
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    });
    const { url, start } = await boot(cfg, { mintToken: async () => "t", fetchImpl });
    await start();
    await fetch(`${url}/v1/chat/completions`, {
      method: "POST",
      body: JSON.stringify({ model: "zai.glm-5", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(captured.targetUrl).toBe("https://mantle-tokyo.test/v1/chat/completions");
    expect(JSON.parse(Buffer.from(captured.opts.body).toString())).toEqual({
      model: "zai.glm-5",
      messages: [{ role: "user", content: "hi" }],
      max_tokens: 4096,
    });
    expect(captured.opts.headers["OpenAI-Project"]).toBe("proj-tokyo");
  });

  it("Gap 1: a 2xx Responses body that fails translation maps to 502 translation_error", async () => {
    for (const badBody of ["not json", JSON.stringify({ output: {} })]) {
      const fetchImpl = vi.fn(
        async () =>
          new Response(badBody, { status: 200, headers: { "content-type": "application/json" } }),
      );
      const logs = [];
      const { url, start } = await boot(cfg, {
        mintToken: async () => "t",
        fetchImpl,
        log: (r) => logs.push(r),
      });
      await start();
      const res = await fetch(`${url}/v1/chat/completions`, {
        method: "POST",
        body: JSON.stringify(terraChat),
      });
      expect(res.status).toBe(502);
      const body = await res.json();
      expect(body.error.code).toBe("upstream_error");
      expect(JSON.stringify(logs)).toContain("translation_error");
    }
  });

  it("TC-MMROUTE-031: the refresh timer refreshes every minted region, never an unused one", async () => {
    vi.useFakeTimers();
    try {
      const mintToken = vi.fn(async (region) => `bearer-${region}`);
      const fetchImpl = vi.fn(
        async () =>
          new Response(JSON.stringify(responsesReply()), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
      );
      // Build the server directly (no loopback fetch — real fetch and fake
      // timers deadlock); drive the handler through injected deps instead.
      const { start } = createProxyServer(cfg, { log: () => {}, mintToken, fetchImpl });
      await start();
      expect(mintToken.mock.calls.map((c) => c[0] ?? cfg.region)).toEqual(["ap-northeast-1"]);

      // Simulate a terra request having minted the responses region lazily:
      // the tick must then refresh BOTH regions.
      // (ensureToken isn't exported; mint via the same path a request uses —
      // trigger it by advancing after registering the region through a real
      // request is not possible under fake timers, so assert the timer loop
      // by seeding the region map through a first tick + direct mint call.)
      await mintToken("us-west-2"); // not registered in state — control call
      mintToken.mockClear();

      await vi.advanceTimersByTimeAsync(cfg.refreshIntervalMs);
      // Only the default region is registered → only it refreshes.
      expect(mintToken.mock.calls.map((c) => c[0] ?? cfg.region)).toEqual(["ap-northeast-1"]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("TC-MMROUTE-031: after a responses-route request both regions refresh on the tick", async () => {
    const mintToken = vi.fn(async (region) => `bearer-${region}`);
    const fetchImpl = vi.fn(
      async () =>
        new Response(JSON.stringify(responsesReply()), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    // Short refresh interval + real timers: loopback request registers the
    // responses region, then one tick refreshes both regions.
    const shortCfg = { ...cfg, refreshIntervalMs: 50 };
    const { url, start } = await boot(shortCfg, { mintToken, fetchImpl });
    await start();
    await fetch(`${url}/v1/chat/completions`, {
      method: "POST",
      body: JSON.stringify(terraChat),
    });
    expect(mintToken).toHaveBeenCalledTimes(2); // start + lazy responses mint
    await new Promise((resolve) => setTimeout(resolve, 120));
    const regions = mintToken.mock.calls.map((c) => c[0] ?? cfg.region);
    // At least one tick fired: both regions re-minted at least once more.
    expect(regions.filter((r) => r === "ap-northeast-1").length).toBeGreaterThanOrEqual(2);
    expect(regions.filter((r) => r === "us-west-2").length).toBeGreaterThanOrEqual(2);
  });

  it("Gap 4: a failed lazy responses mint 502s terra, keeps chat working, then self-heals", async () => {
    let failResponses = true;
    const mintToken = vi.fn(async (region) => {
      if (region === "us-west-2" && failResponses) throw new Error("mint down");
      return `bearer-${region}`;
    });
    const fetchImpl = vi.fn(async (targetUrl) =>
      new Response(
        JSON.stringify(
          String(targetUrl).includes("/responses")
            ? responsesReply()
            : { choices: [{ message: { content: "ok" } }] },
        ),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );
    const { url, start } = await boot(cfg, { mintToken, fetchImpl });
    await start();

    // Terra fails on the mint; glm-5 is unaffected.
    const terra1 = await fetch(`${url}/v1/chat/completions`, {
      method: "POST",
      body: JSON.stringify(terraChat),
    });
    expect(terra1.status).toBe(502);
    const glm = await fetch(`${url}/v1/chat/completions`, {
      method: "POST",
      body: JSON.stringify({ model: "zai.glm-5", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(glm.status).toBe(200);

    // The rejected firstMint is cleared: once minting recovers, terra self-heals.
    failResponses = false;
    const terra2 = await fetch(`${url}/v1/chat/completions`, {
      method: "POST",
      body: JSON.stringify(terraChat),
    });
    expect(terra2.status).toBe(200);
  });

  it("TC-MMROUTE-013: an oversized TRANSLATED responses body 413s", async () => {
    const fetchImpl = vi.fn();
    const smallCfg = { ...cfg, maxBodyBytes: 220 };
    const { url, start } = await boot(smallCfg, { mintToken: async () => "t", fetchImpl });
    await start();
    // Inbound fits under 220 bytes, but translation adds reasoning/max_output_tokens
    // fields that push the rewritten body over.
    const res = await fetch(`${url}/v1/chat/completions`, {
      method: "POST",
      body: JSON.stringify({
        model: "openai.gpt-5.6-terra",
        messages: [{ role: "user", content: "a".repeat(120) }],
      }),
    });
    expect(res.status).toBe(413);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("TC-MMROUTE-040: responses route omits OpenAI-Project when its project is empty", async () => {
    let captured;
    const fetchImpl = vi.fn(async (_u, opts) => {
      captured = opts;
      return new Response(JSON.stringify(responsesReply()), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    const { url, start } = await boot(
      { ...cfg, responsesOpenaiProject: "" },
      { mintToken: async () => "t", fetchImpl },
    );
    await start();
    await fetch(`${url}/v1/chat/completions`, {
      method: "POST",
      body: JSON.stringify(terraChat),
    });
    expect(captured.headers["OpenAI-Project"]).toBeUndefined();
  });
});
