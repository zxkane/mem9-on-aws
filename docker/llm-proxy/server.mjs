// OpenAI-compatible /v1/chat/completions PROXY → Amazon Bedrock Mantle.
//
// Why this sidecar exists (ARCHITECTURE.md §7, corrected 2026-07-12):
// mem9's smart-ingest LLM client (server/internal/llm/client.go @ pinned commit)
// reads MNEMO_LLM_API_KEY ONCE at startup into an immutable field — there is NO
// reload/SIGHUP/file-watch — and its hand-rolled net/http client sends ONLY
// `Authorization` + `Content-Type` (no way to add the `OpenAI-Project` header
// used for Bedrock Project attribution). Both were verified against the
// pinned mem9 source.
//
// A Bedrock bearer minted by @aws/bedrock-token-generator expires (default/max
// 12h), so a static MNEMO_LLM_API_KEY would eventually 401. And mem9 can't emit
// the OpenAI-Project header at all. This proxy resolves BOTH without a mem9 fork
// and without restarting mnemo-server on rotation:
//
//   mnemo-server ──(localhost, static dummy key)──▶ THIS PROXY ──(fresh bearer,
//   optional OpenAI-Project)──▶ Bedrock Mantle /v1/chat/completions
//
// mem9 is configured with:
//   MNEMO_LLM_BASE_URL=http://localhost:<PORT>/v1
//   MNEMO_LLM_API_KEY=<any non-empty dummy>   (mem9 needs it non-empty or it
//                                               nil's the client → raw mode)
//   MNEMO_LLM_MODEL=zai.glm-5
//   MNEMO_INGEST_MODE=smart
//
// The proxy holds the LIVE Mantle bearer, refreshing it on a timer well before
// expiry (minting is a LOCAL SigV4 presign — no network call — so refresh can't
// fail on connectivity), and injects it per forwarded request. It adds
// OpenAI-Project only when LLM_PROXY_OPENAI_PROJECT is configured.
//
// Verified live 2026-07-12: getToken({credentials,region}) → bearer;
// POST bedrock-mantle.ap-northeast-1.../v1/chat/completions {model:"zai.glm-5"}
// → HTTP 200 (see the mantle-token-12h-expiry memory).
//
// Testability: the HTTP server is built by createProxyServer(cfg), with the
// token minter + upstream fetch injectable, so unit tests exercise the real
// routing / header-injection / error paths without touching AWS or Mantle. When
// run directly (node server.mjs) the module wires the real deps + starts listening.

import { randomUUID } from "node:crypto";
import { createServer } from "node:http";

const DEFAULT_MAX_BODY_BYTES = 1_048_576;
const DEFAULT_MAX_TOKENS = 4096;
const REQUEST_POLICY_DEFAULTS = Object.freeze({
  overallDeadlineMs: 110_000,
  maxCallMs: 108_000,
  responseReserveMs: 2_000,
  retryMinCallBudgetMs: 20_000,
  backoffBaseMs: 500,
  backoffCapMs: 2_000,
});
const RETRYABLE_STATUSES = new Set([408, 429, 500, 502, 503, 504]);
const IMF_FIXDATE =
  /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/;
const RFC850_DATE =
  /^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), \d{2}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-\d{2} \d{2}:\d{2}:\d{2} GMT$/;
const ASCTIME_DATE =
  /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)( {2}\d| \d{2}) \d{2}:\d{2}:\d{2} \d{4}$/;

function positiveInteger(raw, fallback, name) {
  if (raw === undefined || raw === "") return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

// ── Config from env (read once) ──────────────────────────────────────────────
export function readConfig(env = process.env) {
  const region = env.LLM_PROXY_REGION || env.AWS_REGION || "ap-northeast-1";
  return {
    port: Number(env.LLM_PROXY_PORT || 8082),
    region,
    // Upstream Mantle base — regional. Overridable for tests.
    upstreamBase: env.LLM_PROXY_UPSTREAM_BASE || `https://bedrock-mantle.${region}.api.aws/v1`,
    // Bedrock Project id for Mantle cost attribution (the OpenAI-Project header).
    // Mantle does NOT support IAM-principal attribution, so this is how GLM-5
    // spend is tagged. Empty → header omitted (still functional, just untagged).
    openaiProject: env.LLM_PROXY_OPENAI_PROJECT || "",
    // Provider-boundary controls. The byte value is passed to both the stream
    // reader and the post-rewrite size check; do not introduce a second limit.
    maxBodyBytes: positiveInteger(
      env.LLM_PROXY_MAX_BODY_BYTES,
      DEFAULT_MAX_BODY_BYTES,
      "LLM_PROXY_MAX_BODY_BYTES",
    ),
    maxTokens: positiveInteger(
      env.LLM_PROXY_MAX_TOKENS,
      DEFAULT_MAX_TOKENS,
      "LLM_PROXY_MAX_TOKENS",
    ),
    // The bearer's lifetime. getToken's default+max is 12h (43200s); we mint at
    // max and refresh at a fraction so a fresh token is always well within expiry.
    tokenTtlSeconds: Number(env.LLM_PROXY_TOKEN_TTL_SECONDS || 43200),
    // Refresh interval. Default = 1h (well under 12h TTL); a long safety margin
    // costs nothing since minting is a local presign, not an API call.
    refreshIntervalMs: Number(env.LLM_PROXY_REFRESH_INTERVAL_MS || 60 * 60 * 1000),
    // The overall request remains below mem9's 120s timeout. Only the overall
    // deadline is configurable, and it is capped at 110s; the internal policy
    // values stay fixed so an environment change cannot weaken the reserves.
    overallDeadlineMs: Math.min(
      positiveInteger(
        env.LLM_PROXY_OVERALL_DEADLINE_MS,
        REQUEST_POLICY_DEFAULTS.overallDeadlineMs,
        "LLM_PROXY_OVERALL_DEADLINE_MS",
      ),
      REQUEST_POLICY_DEFAULTS.overallDeadlineMs,
    ),
    maxCallMs: REQUEST_POLICY_DEFAULTS.maxCallMs,
    responseReserveMs: REQUEST_POLICY_DEFAULTS.responseReserveMs,
    retryMinCallBudgetMs: REQUEST_POLICY_DEFAULTS.retryMinCallBudgetMs,
    backoffBaseMs: REQUEST_POLICY_DEFAULTS.backoffBaseMs,
    backoffCapMs: REQUEST_POLICY_DEFAULTS.backoffCapMs,
  };
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────
function writeHttpResponse(res, status, headers, body) {
  if (res.destroyed || res.writableFinished) return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => {
      res.removeListener("finish", done);
      res.removeListener("close", done);
      resolve();
    };
    res.once("finish", done);
    res.once("close", done);
    res.writeHead(status, headers);
    res.end(body);
  });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  return writeHttpResponse(
    res,
    status,
    {
      "content-type": "application/json",
      "content-length": Buffer.byteLength(body),
    },
    body,
  );
}

function sendError(
  res,
  status,
  message,
  type = "invalid_request_error",
  code = null,
  param = null,
) {
  return sendJson(res, status, { error: { message, type, param, code } });
}

class RequestValidationError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "RequestValidationError";
    this.status = status;
    this.code = code;
    this.outcomeClass = "proxy_validation_permanent";
  }
}

class ProxyRequestError extends Error {
  constructor(httpStatus, code, message, reason, outcomeClass) {
    super(message);
    this.name = "ProxyRequestError";
    this.httpStatus = httpStatus;
    this.code = code;
    this.reason = reason;
    this.outcomeClass = outcomeClass;
    this.logged = false;
  }
}

function requestAbortReason(signal) {
  return signal.reason?.reason || "overall_deadline";
}

function remainingBudget(request, now) {
  return Math.max(0, Math.floor(request.deadlineAt - now()));
}

function callBudget(cfg, request, now, at = now()) {
  return Math.max(
    0,
    Math.min(cfg.maxCallMs, Math.floor(request.deadlineAt - at - cfg.responseReserveMs)),
  );
}

function outcomeForStatus(status) {
  if (status >= 400 && status < 500) {
    return RETRYABLE_STATUSES.has(status) ? "mantle_transient" : "mantle_4xx_permanent";
  }
  if (status >= 500) return "mantle_transient";
  return undefined;
}

function requestLog(request, now, log, attempt, startedAt, fields) {
  const record = {
    request_id: request.id,
    attempt,
    ...fields,
    duration_ms: Math.max(0, Math.round(now() - startedAt)),
    remaining_budget_ms: remainingBudget(request, now),
  };
  log(record);
}

function defaultRequestLog(record) {
  console.log(JSON.stringify(record));
}

function parseRetryAfter(value, now) {
  if (value === null) return null;
  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) {
    const seconds = Number(trimmed);
    return Number.isFinite(seconds) ? seconds * 1_000 : Number.POSITIVE_INFINITY;
  }
  const isImfFixdate = IMF_FIXDATE.test(trimmed);
  if (!isImfFixdate && !RFC850_DATE.test(trimmed) && !ASCTIME_DATE.test(trimmed)) return null;
  const date = Date.parse(trimmed);
  if (Number.isNaN(date)) return null;
  if (isImfFixdate && new Date(date).toUTCString() !== trimmed) return null;
  return Math.max(0, date - now());
}

function fullJitterDelay(cfg, attempt, random) {
  const cap = Math.min(cfg.backoffBaseMs * 2 ** (attempt - 1), cfg.backoffCapMs);
  return Math.min(cap, Math.floor(random() * (cap + 1)));
}

function abortableSleep(delayMs, signal) {
  if (signal.aborted) return Promise.reject(new Error("request aborted"));
  return new Promise((resolve, reject) => {
    const timer = setTimeout(done, delayMs);
    function done() {
      signal.removeEventListener("abort", aborted);
      resolve();
    }
    function aborted() {
      clearTimeout(timer);
      reject(new Error("request aborted"));
    }
    signal.addEventListener("abort", aborted, { once: true });
  });
}

function waitForPromise(promise, signal) {
  if (signal.aborted) return Promise.reject(new Error("request aborted"));
  return new Promise((resolve, reject) => {
    function aborted() {
      reject(new Error("request aborted"));
    }
    signal.addEventListener("abort", aborted, { once: true });
    Promise.resolve(promise).then(
      (value) => {
        signal.removeEventListener("abort", aborted);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener("abort", aborted);
        reject(error);
      },
    );
  });
}

async function readBody(req, limitBytes, signal) {
  const chunks = [];
  let size = 0;
  const abort = () => req.destroy(new Error("request aborted"));
  signal.addEventListener("abort", abort, { once: true });
  try {
    for await (const chunk of req) {
      size += chunk.length;
      if (size > limitBytes) {
        throw new RequestValidationError(
          413,
          "request_too_large",
          `request body exceeds ${limitBytes} bytes`,
        );
      }
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  } finally {
    signal.removeEventListener("abort", abort);
  }
}

function rewriteChatCompletion(bodyBuf, cfg) {
  let payload;
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bodyBuf);
    payload = JSON.parse(text);
  } catch {
    throw new RequestValidationError(
      400,
      "invalid_json",
      "request body is not valid JSON",
    );
  }

  if (
    payload === null ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    typeof payload.model !== "string" ||
    payload.model.trim() === "" ||
    !Array.isArray(payload.messages)
  ) {
    throw new RequestValidationError(
      400,
      "invalid_chat_completions_request",
      "request body must be a chat-completions object with model and messages",
    );
  }

  let maxTokens = cfg.maxTokens;
  if (Object.hasOwn(payload, "max_tokens")) {
    maxTokens = payload.max_tokens;
    if (!Number.isInteger(maxTokens) || maxTokens < 1 || maxTokens > cfg.maxTokens) {
      throw new RequestValidationError(
        400,
        "invalid_max_tokens",
        `max_tokens must be an integer from 1 through ${cfg.maxTokens}`,
      );
    }
  }

  const rewritten = Buffer.from(JSON.stringify({ ...payload, max_tokens: maxTokens }));
  if (rewritten.length > cfg.maxBodyBytes) {
    throw new RequestValidationError(
      413,
      "request_too_large",
      `rewritten request body exceeds ${cfg.maxBodyBytes} bytes`,
    );
  }
  return rewritten;
}

/**
 * Execute at most two Mantle calls inside one request budget.
 *
 * This function owns retry/auth-remint decisions and is exported so unit tests
 * can inject clock, fetch, credential refresh, jitter, sleep, and log behavior.
 */
export async function forwardWithPolicy({ body, token, cfg, request, deps = {} }) {
  const fetchImpl = deps.fetchImpl || globalThis.fetch;
  const refreshToken = deps.refreshToken;
  const now = deps.now || Date.now;
  const random = deps.random || Math.random;
  const sleep = deps.sleep || abortableSleep;
  const log = deps.log || defaultRequestLog;

  function terminalError(attempt, startedAt, error, status) {
    requestLog(request, now, log, attempt, startedAt, {
      ...(status === undefined ? {} : { status }),
      reason: error.reason,
      outcome_class: error.outcomeClass,
    });
    error.logged = true;
    throw error;
  }

  async function callMantle(attempt, bearer) {
    request.attempt = attempt;
    const budgetMs = callBudget(cfg, request, now);
    const startedAt = now();
    if (budgetMs <= 0 || request.signal.aborted) {
      const error = new ProxyRequestError(
        504,
        "upstream_timeout",
        "overall request deadline reached",
        request.signal.aborted ? requestAbortReason(request.signal) : "overall_deadline",
        "deadline",
      );
      return terminalError(attempt, startedAt, error);
    }

    const headers = {
      Authorization: `Bearer ${bearer}`,
      "Content-Type": "application/json",
      "Content-Length": String(body.length),
    };
    if (cfg.openaiProject) headers["OpenAI-Project"] = cfg.openaiProject;

    const callController = new AbortController();
    const timeoutReason = { reason: "attempt_timeout" };
    const abortFromRequest = () => callController.abort(request.signal.reason);
    request.signal.addEventListener("abort", abortFromRequest, { once: true });
    const timer = setTimeout(() => callController.abort(timeoutReason), budgetMs);
    try {
      const upstream = await fetchImpl(`${cfg.upstreamBase}/chat/completions`, {
        method: "POST",
        headers,
        body,
        signal: callController.signal,
      });
      const responseBody = await upstream.arrayBuffer();
      return {
        response: new Response(responseBody, {
          status: upstream.status,
          statusText: upstream.statusText,
          headers: upstream.headers,
        }),
        startedAt,
      };
    } catch (cause) {
      if (request.signal.aborted) {
        return {
          error: new ProxyRequestError(
            504,
            "upstream_timeout",
            "request canceled",
            requestAbortReason(request.signal),
            "deadline",
          ),
          startedAt,
        };
      }
      if (callController.signal.reason === timeoutReason || cause?.name === "AbortError") {
        return {
          error: new ProxyRequestError(
            504,
            "upstream_timeout",
            "upstream Mantle request timed out",
            "attempt_timeout",
            "deadline",
          ),
          startedAt,
        };
      }
      return {
        error: new ProxyRequestError(
          502,
          "upstream_error",
          "llm-proxy failed to reach Mantle",
          "network_error",
          "mantle_transient",
        ),
        startedAt,
      };
    } finally {
      clearTimeout(timer);
      request.signal.removeEventListener("abort", abortFromRequest);
    }
  }

  async function waitBeforeRetry(delayMs, attempt, startedAt, fields) {
    requestLog(request, now, log, attempt, startedAt, fields);
    try {
      await sleep(delayMs, request.signal);
    } catch {
      const error = new ProxyRequestError(
        504,
        "upstream_timeout",
        "request canceled",
        requestAbortReason(request.signal),
        "deadline",
      );
      return terminalError(attempt, startedAt, error, fields.status);
    }
    return callBudget(cfg, request, now) >= cfg.retryMinCallBudgetMs;
  }

  async function retryIfUseful(delayMs, attempt, startedAt, fields) {
    const projected = callBudget(cfg, request, now, now() + delayMs);
    if (projected < cfg.retryMinCallBudgetMs) return false;
    return waitBeforeRetry(delayMs, attempt, startedAt, fields);
  }

  let bearer = token;
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const result = await callMantle(attempt, bearer);

    if (result.error) {
      if (attempt === 1 && result.error.reason === "network_error") {
        const delayMs = fullJitterDelay(cfg, attempt, random);
        const retry = await retryIfUseful(delayMs, attempt, result.startedAt, {
          reason: "transient_retry",
        });
        if (retry) continue;
      }
      return terminalError(attempt, result.startedAt, result.error);
    }

    const { response, startedAt } = result;
    if (attempt === 2) {
      requestLog(request, now, log, attempt, startedAt, {
        status: response.status,
        ...(outcomeForStatus(response.status)
          ? { outcome_class: outcomeForStatus(response.status) }
          : {}),
      });
      return response;
    }

    if (response.status === 401 || response.status === 403) {
      if (callBudget(cfg, request, now) <= 0 || request.signal.aborted) {
        requestLog(request, now, log, attempt, startedAt, {
          status: response.status,
          outcome_class: "mantle_4xx_permanent",
        });
        return response;
      }
      try {
        bearer = await waitForPromise(refreshToken(), request.signal);
      } catch {
        if (request.signal.aborted) {
          const error = new ProxyRequestError(
            504,
            "upstream_timeout",
            "request canceled",
            requestAbortReason(request.signal),
            "deadline",
          );
          return terminalError(attempt, startedAt, error, response.status);
        }
        const error = new ProxyRequestError(
          502,
          "upstream_error",
          "llm-proxy failed to refresh Mantle credentials",
          "credential_error",
          "mantle_transient",
        );
        return terminalError(attempt, startedAt, error, response.status);
      }
      if (callBudget(cfg, request, now) <= 0) {
        requestLog(request, now, log, attempt, startedAt, {
          status: response.status,
          outcome_class: "mantle_4xx_permanent",
        });
        return response;
      }
      requestLog(request, now, log, attempt, startedAt, {
        status: response.status,
        reason: "auth_remint",
      });
      continue;
    }

    if (RETRYABLE_STATUSES.has(response.status)) {
      const retryAfter = parseRetryAfter(response.headers.get("retry-after"), now);
      const delayMs = retryAfter === null ? fullJitterDelay(cfg, attempt, random) : retryAfter;
      const retry = await retryIfUseful(delayMs, attempt, startedAt, {
        status: response.status,
        reason: "transient_retry",
      });
      if (retry) continue;
    }

    requestLog(request, now, log, attempt, startedAt, {
      status: response.status,
      ...(outcomeForStatus(response.status)
        ? { outcome_class: outcomeForStatus(response.status) }
        : {}),
    });
    return response;
  }

  throw new Error("unreachable request policy state");
}

/**
 * Build the proxy HTTP server + its token lifecycle.
 *
 * @param cfg config from readConfig()
 * @param deps.mintToken async () => bearerString — mints a fresh Bedrock bearer
 *        (default: @aws/bedrock-token-generator over the task role).
 * @param deps.fetchImpl fetch-compatible fn (default: global fetch).
 * @returns { server, start, tokenState } — `start()` mints the first bearer +
 *          arms the refresh timer; `tokenState` exposes current token/age for tests.
 */
export function createProxyServer(cfg, deps = {}) {
  const mintToken = deps.mintToken;
  const fetchImpl = deps.fetchImpl || globalThis.fetch;
  const now = deps.now || Date.now;
  const requestId = deps.requestId || randomUUID;
  const log = deps.log || defaultRequestLog;
  const writeResponse = deps.writeResponse || writeHttpResponse;
  const requestCfg = {
    ...REQUEST_POLICY_DEFAULTS,
    ...cfg,
  };
  if (typeof mintToken !== "function") {
    throw new Error("createProxyServer requires deps.mintToken");
  }

  const state = { token: null, firstMint: null, lastMintAt: 0, refreshTimer: null };

  async function refresh() {
    const token = await mintToken();
    state.token = token;
    state.lastMintAt = now();
    return token;
  }

  // Ensure a token exists (blocking on the first mint); return the current one.
  // If the first mint REJECTS, clear the cached promise so a later request can
  // retry — otherwise `state.firstMint` would pin the rejected promise forever
  // and the proxy could never self-heal a transient cold-start credential hiccup
  // (belt-and-suspenders: the entrypoint also exits non-zero so ECS restarts).
  async function ensureToken() {
    if (state.token) return state.token;
    if (!state.firstMint) {
      state.firstMint = refresh().catch((err) => {
        state.firstMint = null;
        throw err;
      });
    }
    return state.firstMint;
  }

  const server = createServer(async (req, res) => {
    let url;
    let request;
    let cleanupRequest = () => {};
    try {
      url = new URL(req.url, `http://localhost:${cfg.port}`);

      // Readiness: 200 once the first bearer is minted. The ECS health check gates
      // the task on this so mnemo-server isn't marked healthy before the proxy can
      // auth. NON-BLOCKING: report the CURRENT token state — never await the
      // in-flight mint (that would hang the health probe until Mantle auth is up).
      if (req.method === "GET" && (url.pathname === "/health" || url.pathname === "/healthz")) {
        const ready = !!state.token;
        return sendJson(res, ready ? 200 : 503, {
          status: ready ? "ok" : "starting",
          lastMintAgeSeconds: state.lastMintAt
            ? Math.round((now() - state.lastMintAt) / 1000)
            : null,
        });
      }

      // mem9 posts to `${MNEMO_LLM_BASE_URL}/chat/completions`; base is
      // http://localhost:PORT/v1 → accept /v1/chat/completions and /chat/completions.
      if (req.method === "POST" && /\/(v1\/)?chat\/completions$/.test(url.pathname)) {
        const startedAt = now();
        const controller = new AbortController();
        request = {
          id: requestId(),
          deadlineAt: startedAt + requestCfg.overallDeadlineMs,
          signal: controller.signal,
          startedAt,
          attempt: 0,
        };
        const deadlineTimer = setTimeout(
          () => {
            controller.abort({ reason: "overall_deadline" });
            if (!res.writableFinished) res.destroy();
          },
          requestCfg.overallDeadlineMs,
        );
        const clientDisconnected = () => {
          if (!res.writableFinished) controller.abort({ reason: "downstream_disconnect" });
        };
        req.once("aborted", clientDisconnected);
        res.once("close", clientDisconnected);
        cleanupRequest = () => {
          clearTimeout(deadlineTimer);
          req.removeListener("aborted", clientDisconnected);
          res.removeListener("close", clientDisconnected);
        };

        const inboundBody = await readBody(req, cfg.maxBodyBytes, request.signal);
        const bodyBuf = rewriteChatCompletion(inboundBody, cfg);
        let token;
        try {
          token = await waitForPromise(ensureToken(), request.signal);
        } catch {
          const aborted = request.signal.aborted;
          const error = new ProxyRequestError(
            aborted ? 504 : 502,
            aborted ? "upstream_timeout" : "upstream_error",
            aborted ? "request canceled" : "llm-proxy failed to resolve Mantle credentials",
            aborted ? requestAbortReason(request.signal) : "credential_error",
            aborted ? "deadline" : "mantle_transient",
          );
          requestLog(request, now, log, 0, startedAt, {
            reason: error.reason,
            outcome_class: error.outcomeClass,
          });
          error.logged = true;
          throw error;
        }
        const upstream = await forwardWithPolicy({
          body: bodyBuf,
          token,
          cfg: requestCfg,
          request,
          deps: {
            fetchImpl,
            refreshToken: refresh,
            now,
            random: deps.random,
            sleep: deps.sleep,
            log,
          },
        });
        // Pass the upstream status + JSON body straight through. mem9 handles
        // non-2xx itself (it strips provider-specific flags on 400 and retries).
        const text = await upstream.text();
        return await waitForPromise(
          writeResponse(
            res,
            upstream.status,
            {
              "content-type": upstream.headers.get("content-type") || "application/json",
              "content-length": Buffer.byteLength(text),
            },
            text,
          ),
          request.signal,
        );
      }

      return sendError(
        res,
        404,
        `no route for ${req.method} ${url.pathname}`,
        "not_found",
        "not_found",
      );
    } catch (err) {
      if (err instanceof RequestValidationError) {
        if (request) {
          requestLog(request, now, log, 0, request.startedAt, {
            status: err.status,
            reason: err.code,
            outcome_class: err.outcomeClass,
          });
        }
        return await sendError(res, err.status, err.message, "invalid_request_error", err.code);
      }
      const failure =
        err instanceof ProxyRequestError
          ? err
          : new ProxyRequestError(
              request?.signal.aborted ? 504 : 502,
              request?.signal.aborted ? "upstream_timeout" : "upstream_error",
              request?.signal.aborted
                ? "request canceled"
                : "llm-proxy failed to reach Mantle",
              request?.signal.aborted ? requestAbortReason(request.signal) : "network_error",
              request?.signal.aborted ? "deadline" : "mantle_transient",
            );
      if (request && !failure.logged) {
        requestLog(request, now, log, request.attempt, request.startedAt, {
          reason: failure.reason,
          outcome_class: failure.outcomeClass,
        });
        failure.logged = true;
      }
      return await sendError(
        res,
        failure.httpStatus,
        failure.message,
        "server_error",
        failure.code,
      );
    } finally {
      cleanupRequest();
    }
  });

  // Mint the first bearer + arm the refresh timer. Returns the first-mint promise
  // so callers (and the health check) can await readiness.
  function start() {
    const p = ensureToken();
    p.then(() => {
      state.refreshTimer = setInterval(() => {
        refresh()
          .then(() => console.log("llm-proxy refreshed Bedrock bearer"))
          .catch((err) =>
            // A refresh failure keeps the previous (still-valid, 12h) token; log
            // and let the next tick retry. Do NOT crash — the current token works.
            console.error(
              "llm-proxy bearer refresh failed (keeping current):",
              err?.message || err,
            ),
          );
      }, cfg.refreshIntervalMs);
      state.refreshTimer.unref?.(); // don't keep the process alive on the timer alone
    }).catch(() => {
      /* surfaced to the caller via the returned promise */
    });
    return p;
  }

  return { server, start, state };
}

// ── Default minter factory ────────────────────────────────────────────────────
// Presigns a Bedrock bearer from the task role. Resolves credentials via a NEW
// provider chain on EVERY mint: a shared fromNodeProviderChain() memoizes, and
// a bearer presigned from an expired session dies with that session no matter
// the requested TTL — the mint "succeeds" but every call 401s (issue #24).
// Minting is at most hourly + rare 401 retries, so per-mint resolution is
// cheap. Deps are injectable for tests (TC-PROXY401-007).
export function makeDefaultMintToken(cfg, deps) {
  const { createProvider, getToken } = deps;
  return async () => {
    const credentials = await createProvider()();
    return getToken({ credentials, region: cfg.region, expiresInSeconds: cfg.tokenTtlSeconds });
  };
}

// ── Direct-run entrypoint (node server.mjs) ────────────────────────────────────
// Only wires the real AWS deps + listens when executed as the main module, so
// importing this file in a test does not require AWS credentials.
const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const cfg = readConfig();
  const { getToken } = await import("@aws/bedrock-token-generator");
  const { fromNodeProviderChain } = await import("@aws-sdk/credential-providers");
  const mintToken = makeDefaultMintToken(cfg, { createProvider: fromNodeProviderChain, getToken });

  const { server, start } = createProxyServer(cfg, { mintToken });
  server.listen(cfg.port, () => {
    console.log(
      `llm-proxy listening on :${cfg.port} → ${cfg.upstreamBase} (region ${cfg.region}` +
        `${cfg.openaiProject ? `, project ${cfg.openaiProject}` : ", no project"})`,
    );
    start()
      .then(() => console.log("llm-proxy minted initial Bedrock bearer, ready"))
      .catch((err) => {
        console.error("llm-proxy INITIAL bearer mint FAILED:", err?.message || err);
        // No token at all → the sidecar is useless; exit non-zero so ECS restarts
        // the task (e.g. a transient credential-provider hiccup at cold start).
        process.exit(1);
      });
  });
}
