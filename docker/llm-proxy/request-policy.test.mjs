import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { forwardWithPolicy, readConfig } from "./server.mjs";

const policyCfg = {
  upstreamBase: "https://mantle.test/v1",
  openaiProject: "project-test",
  overallDeadlineMs: 110_000,
  maxCallMs: 108_000,
  responseReserveMs: 2_000,
  retryMinCallBudgetMs: 20_000,
  backoffBaseMs: 500,
  backoffCapMs: 2_000,
};

const body = Buffer.from(
  JSON.stringify({
    model: "zai.glm-5",
    messages: [{ role: "user", content: "SECRET-REQUEST-CONTENT" }],
  }),
);

function response(status, responseBody = `status-${status}`, headers = {}) {
  return new Response(responseBody, {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function abortError() {
  const error = new Error("aborted");
  error.name = "AbortError";
  return error;
}

function makeCredentialMinter(tokens = ["initial-bearer", "fresh-bearer"]) {
  const resolveCredentials = vi.fn(async () => ({
    accessKeyId: "FAKE",
    secretAccessKey: "FAKE",
  }));
  const signBearer = vi.fn(async (_credentials, index) => tokens[index] ?? `bearer-${index}`);
  const mintToken = vi.fn(async () => {
    const credentials = await resolveCredentials();
    return signBearer(credentials, mintToken.mock.calls.length - 1);
  });
  return { mintToken, resolveCredentials, signBearer };
}

async function runScript(
  script,
  {
    cfg = policyCfg,
    random = 0.5,
    requestId = "request-test",
    sleep,
    mint = makeCredentialMinter(),
  } = {},
) {
  const initialToken = await mint.mintToken();
  const fetchImpl = vi.fn(async (_url, options) => {
    const step = script[fetchImpl.mock.calls.length - 1];
    if (!step) throw new Error("unexpected Mantle call");
    if (step.durationMs) vi.setSystemTime(Date.now() + step.durationMs);
    if (step.error) throw step.error;
    return response(step.status, step.body, step.headers);
  });
  const logs = [];
  const backoff =
    sleep ??
    vi.fn(async (delayMs, signal) => {
      if (signal.aborted) throw abortError();
      vi.setSystemTime(Date.now() + delayMs);
    });
  const controller = new AbortController();
  const result = await forwardWithPolicy({
    body,
    token: initialToken,
    cfg,
    request: {
      id: requestId,
      deadlineAt: Date.now() + cfg.overallDeadlineMs,
      signal: controller.signal,
    },
    deps: {
      fetchImpl,
      refreshToken: mint.mintToken,
      now: Date.now,
      random: () => random,
      sleep: backoff,
      log: (record) => logs.push(record),
    },
  });
  return { result, fetchImpl, logs, sleep: backoff, ...mint };
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(0);
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("GLM request policy", () => {
  it("TC-GLM-RETRY-001: uses the bounded production defaults", () => {
    const cfg = readConfig({ AWS_REGION: "ap-southeast-1" });
    expect(cfg).toMatchObject({
      overallDeadlineMs: 110_000,
      maxCallMs: 108_000,
      responseReserveMs: 2_000,
      retryMinCallBudgetMs: 20_000,
      backoffBaseMs: 500,
      backoffCapMs: 2_000,
    });
  });

  it("TC-GLM-RETRY-002: allows a long success within one 108-second call budget", async () => {
    const run = await runScript([{ status: 200, durationMs: 107_999 }]);
    expect(run.result.status).toBe(200);
    expect(run.fetchImpl).toHaveBeenCalledOnce();
    expect(run.fetchImpl.mock.calls[0][1].signal).toBeInstanceOf(AbortSignal);
    expect(Date.now()).toBe(107_999);
    expect(run.logs.at(-1)).toMatchObject({
      request_id: "request-test",
      attempt: 1,
      status: 200,
      duration_ms: 107_999,
      remaining_budget_ms: 2_001,
    });
  });

  it("TC-GLM-RETRY-003/020: fast 503 then 200 makes two calls and one mint", async () => {
    const run = await runScript([
      { status: 503, durationMs: 100 },
      { status: 200, durationMs: 200 },
    ]);
    expect(run.result.status).toBe(200);
    expect(run.fetchImpl).toHaveBeenCalledTimes(2);
    expect(run.mintToken).toHaveBeenCalledTimes(1);
    expect(run.sleep).toHaveBeenCalledWith(250, expect.any(AbortSignal));
  });

  it("TC-GLM-RETRY-004/020: slow 503 returns directly with one call and one mint", async () => {
    const run = await runScript([{ status: 503, durationMs: 89_000 }]);
    expect(run.result.status).toBe(503);
    expect(await run.result.text()).toBe("status-503");
    expect(run.fetchImpl).toHaveBeenCalledOnce();
    expect(run.mintToken).toHaveBeenCalledOnce();
    expect(run.sleep).not.toHaveBeenCalled();
    expect(run.logs.at(-1).outcome_class).toBe("mantle_transient");
  });

  it("TC-GLM-RETRY-005: retries a fast network error once", async () => {
    const run = await runScript([
      { error: new Error("SECRET-NETWORK-FAILURE"), durationMs: 100 },
      { status: 200 },
    ]);
    expect(run.result.status).toBe(200);
    expect(run.fetchImpl).toHaveBeenCalledTimes(2);
    expect(run.mintToken).toHaveBeenCalledOnce();
  });

  it("TC-GLM-RETRY-006/020: an attempt timeout aborts and never retries", async () => {
    const mint = makeCredentialMinter();
    const initialToken = await mint.mintToken();
    const fetchImpl = vi.fn(
      async (_url, options) =>
        new Promise((_resolve, reject) => {
          options.signal.addEventListener("abort", () => reject(abortError()), { once: true });
        }),
    );
    const logs = [];
    const controller = new AbortController();
    const pending = forwardWithPolicy({
      body,
      token: initialToken,
      cfg: policyCfg,
      request: {
        id: "request-timeout",
        deadlineAt: policyCfg.overallDeadlineMs,
        signal: controller.signal,
      },
      deps: {
        fetchImpl,
        refreshToken: mint.mintToken,
        now: Date.now,
        random: () => 0,
        log: (record) => logs.push(record),
      },
    });

    const rejection = expect(pending).rejects.toMatchObject({
      httpStatus: 504,
      reason: "attempt_timeout",
      outcomeClass: "deadline",
    });
    await vi.advanceTimersByTimeAsync(108_000);
    await rejection;
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(mint.mintToken).toHaveBeenCalledOnce();
    expect(logs.at(-1)).toMatchObject({
      attempt: 1,
      reason: "attempt_timeout",
      outcome_class: "deadline",
    });
  });

  it.each([408, 429, 500, 502, 503, 504])(
    "TC-GLM-RETRY-007: retries fast status %i",
    async (status) => {
      const run = await runScript([{ status }, { status: 200 }], { random: 0 });
      expect(run.result.status).toBe(200);
      expect(run.fetchImpl).toHaveBeenCalledTimes(2);
    },
  );

  it.each([400, 404, 409, 422])(
    "TC-GLM-RETRY-008: returns permanent 4xx %i without retry",
    async (status) => {
      const run = await runScript([{ status }]);
      expect(run.result.status).toBe(status);
      expect(run.fetchImpl).toHaveBeenCalledOnce();
      expect(run.logs.at(-1).outcome_class).toBe("mantle_4xx_permanent");
    },
  );

  it("TC-GLM-RETRY-009/020: 401 then 200 re-resolves credentials and re-mints once", async () => {
    const run = await runScript([{ status: 401 }, { status: 200 }]);
    expect(run.result.status).toBe(200);
    expect(run.fetchImpl).toHaveBeenCalledTimes(2);
    expect(run.mintToken).toHaveBeenCalledTimes(2);
    expect(run.resolveCredentials).toHaveBeenCalledTimes(2);
    expect(run.fetchImpl.mock.calls[1][1].headers.Authorization).toBe("Bearer fresh-bearer");
    expect(run.sleep).not.toHaveBeenCalled();
  });

  it("TC-GLM-RETRY-010/020: 401 then 503 returns call two directly", async () => {
    const run = await runScript([{ status: 401 }, { status: 503 }]);
    expect(run.result.status).toBe(503);
    expect(run.fetchImpl).toHaveBeenCalledTimes(2);
    expect(run.mintToken).toHaveBeenCalledTimes(2);
    expect(run.sleep).not.toHaveBeenCalled();
  });

  it("TC-GLM-RETRY-011/020: 503 then 401 does not remint after call two", async () => {
    const run = await runScript([{ status: 503 }, { status: 401 }], { random: 0 });
    expect(run.result.status).toBe(401);
    expect(run.fetchImpl).toHaveBeenCalledTimes(2);
    expect(run.mintToken).toHaveBeenCalledOnce();
  });

  it("TC-GLM-RETRY-012/020: consecutive 401 responses stop after call two", async () => {
    const run = await runScript([{ status: 401 }, { status: 401 }]);
    expect(run.result.status).toBe(401);
    expect(run.fetchImpl).toHaveBeenCalledTimes(2);
    expect(run.mintToken).toHaveBeenCalledTimes(2);
  });

  it("TC-GLM-RETRY-013: honors Retry-After seconds", async () => {
    const run = await runScript([
      { status: 429, headers: { "retry-after": "5" } },
      { status: 200 },
    ]);
    expect(run.result.status).toBe(200);
    expect(run.sleep).toHaveBeenCalledWith(5_000, expect.any(AbortSignal));
    expect(Date.now()).toBe(5_000);
  });

  it.each([
    ["IMF-fixdate", new Date(7_000).toUTCString()],
    ["RFC 850", "Thursday, 01-Jan-70 00:00:07 GMT"],
    ["asctime", "Thu Jan  1 00:00:07 1970"],
  ])("TC-GLM-RETRY-014: honors Retry-After %s", async (_format, retryAfter) => {
    const run = await runScript([
      { status: 503, headers: { "retry-after": retryAfter } },
      { status: 200 },
    ]);
    expect(run.result.status).toBe(200);
    expect(run.sleep).toHaveBeenCalledWith(7_000, expect.any(AbortSignal));
  });

  it("TC-GLM-RETRY-014: applies RFC 850 rollover using the full 50-year boundary", async () => {
    vi.setSystemTime(Date.UTC(2026, 6, 24));
    const run = await runScript([
      { status: 503, headers: { "retry-after": "Friday, 31-Dec-76 00:00:00 GMT" } },
      { status: 200 },
    ]);
    expect(run.result.status).toBe(200);
    expect(run.sleep).toHaveBeenCalledWith(0, expect.any(AbortSignal));
  });

  it.each([
    "later-ish",
    "1.5",
    "2026-07-24",
    "Thursday, 31-Feb-70 00:00:07 GMT",
    "Friday, 01-Jan-70 00:00:07 GMT",
    "Fri Jan  1 00:00:07 1970",
    "Thu Feb 30 00:00:07 1970",
  ])(
    "TC-GLM-RETRY-015: invalid Retry-After %s falls back to full jitter",
    async (retryAfter) => {
      const run = await runScript(
        [
          { status: 503, headers: { "retry-after": retryAfter } },
          { status: 200 },
        ],
        { random: 0.75 },
      );
      expect(run.sleep).toHaveBeenCalledWith(375, expect.any(AbortSignal));
    },
  );

  it("TC-GLM-RETRY-016: too-long Retry-After returns the first response", async () => {
    const run = await runScript([
      {
        status: 429,
        body: "ORIGINAL-UPSTREAM-BODY",
        headers: { "retry-after": "89" },
      },
    ]);
    expect(run.result.status).toBe(429);
    expect(await run.result.text()).toBe("ORIGINAL-UPSTREAM-BODY");
    expect(run.fetchImpl).toHaveBeenCalledOnce();
    expect(run.sleep).not.toHaveBeenCalled();
  });

  it("TC-GLM-RETRY-017: retries when waiting leaves exactly 20 seconds", async () => {
    const run = await runScript([
      { status: 503, headers: { "retry-after": "88" } },
      { status: 200 },
    ]);
    expect(run.result.status).toBe(200);
    expect(run.fetchImpl).toHaveBeenCalledTimes(2);
    expect(run.sleep).toHaveBeenCalledWith(88_000, expect.any(AbortSignal));
  });

  it("TC-GLM-RETRY-018: cancellation aborts an active call", async () => {
    const mint = makeCredentialMinter();
    const initialToken = await mint.mintToken();
    const controller = new AbortController();
    const fetchImpl = vi.fn(
      async (_url, options) =>
        new Promise((_resolve, reject) => {
          options.signal.addEventListener("abort", () => reject(abortError()), { once: true });
        }),
    );
    const pending = forwardWithPolicy({
      body,
      token: initialToken,
      cfg: policyCfg,
      request: {
        id: "request-disconnect",
        deadlineAt: policyCfg.overallDeadlineMs,
        signal: controller.signal,
      },
      deps: { fetchImpl, refreshToken: mint.mintToken, now: Date.now, log: () => {} },
    });

    controller.abort({ reason: "downstream_disconnect" });
    await expect(pending).rejects.toMatchObject({ reason: "downstream_disconnect" });
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(mint.mintToken).toHaveBeenCalledOnce();
  });

  it("TC-GLM-RETRY-019: cancellation interrupts backoff", async () => {
    const controller = new AbortController();
    const mint = makeCredentialMinter();
    const initialToken = await mint.mintToken();
    const fetchImpl = vi.fn(async () => response(503));
    const sleep = vi.fn(
      async (_delay, signal) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener("abort", () => reject(abortError()), { once: true });
        }),
    );
    const pending = forwardWithPolicy({
      body,
      token: initialToken,
      cfg: policyCfg,
      request: {
        id: "request-backoff-cancel",
        deadlineAt: policyCfg.overallDeadlineMs,
        signal: controller.signal,
      },
      deps: {
        fetchImpl,
        refreshToken: mint.mintToken,
        now: Date.now,
        random: () => 1,
        sleep,
        log: () => {},
      },
    });

    await vi.waitFor(() => expect(sleep).toHaveBeenCalledOnce());
    controller.abort({ reason: "downstream_disconnect" });
    await expect(pending).rejects.toMatchObject({ reason: "downstream_disconnect" });
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("TC-GLM-RETRY-021: emits only redacted structured request metadata", async () => {
    const run = await runScript(
      [
        { status: 503, durationMs: 100, body: "SECRET-UPSTREAM-CONTENT" },
        { status: 400, durationMs: 20, body: "SECRET-TERMINAL-CONTENT" },
      ],
      { requestId: "generated-request-id" },
    );
    expect(run.result.status).toBe(400);
    expect(run.logs).toMatchInlineSnapshot(`
      [
        {
          "attempt": 1,
          "duration_ms": 100,
          "reason": "transient_retry",
          "remaining_budget_ms": 109900,
          "request_id": "generated-request-id",
          "status": 503,
        },
        {
          "attempt": 2,
          "duration_ms": 20,
          "outcome_class": "mantle_4xx_permanent",
          "remaining_budget_ms": 109630,
          "request_id": "generated-request-id",
          "status": 400,
        },
      ]
    `);
    for (const record of run.logs) {
      expect(Object.keys(record).sort()).toEqual(
        expect.arrayContaining([
          "attempt",
          "duration_ms",
          "remaining_budget_ms",
          "request_id",
        ]),
      );
      expect(Object.keys(record)).not.toEqual(
        expect.arrayContaining(["body", "error", "headers", "messages", "token"]),
      );
    }
    expect(JSON.stringify(run.logs)).not.toMatch(/SECRET-/);
  });

  it("TC-GLM-RETRY-022: terminal provider statuses use durable outcome classes", async () => {
    const permanent = await runScript([{ status: 400 }]);
    const transient = await runScript([{ status: 503, durationMs: 89_000 }]);
    expect(permanent.logs.at(-1).outcome_class).toBe("mantle_4xx_permanent");
    expect(transient.logs.at(-1).outcome_class).toBe("mantle_transient");
  });

  it("TC-GLM-RETRY-023: does not start a call without positive call budget", async () => {
    const mint = makeCredentialMinter();
    const initialToken = await mint.mintToken();
    const fetchImpl = vi.fn();
    await expect(
      forwardWithPolicy({
        body,
        token: initialToken,
        cfg: policyCfg,
        request: {
          id: "request-no-budget",
          deadlineAt: 2_000,
          signal: new AbortController().signal,
        },
        deps: { fetchImpl, refreshToken: mint.mintToken, now: Date.now, log: () => {} },
      }),
    ).rejects.toMatchObject({ reason: "overall_deadline", outcomeClass: "deadline" });
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
