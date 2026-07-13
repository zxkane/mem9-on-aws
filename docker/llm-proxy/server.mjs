// OpenAI-compatible /v1/chat/completions PROXY → Amazon Bedrock Mantle.
//
// Why this sidecar exists (ARCHITECTURE.md §7, corrected 2026-07-12):
// mem9's smart-ingest LLM client (server/internal/llm/client.go @ pinned commit)
// reads MNEMO_LLM_API_KEY ONCE at startup into an immutable field — there is NO
// reload/SIGHUP/file-watch — and its hand-rolled net/http client sends ONLY
// `Authorization` + `Content-Type` (no way to add the `OpenAI-Project` header
// Bedrock Mantle needs for cost attribution). Both were verified against the
// pinned mem9 source.
//
// A Bedrock bearer minted by @aws/bedrock-token-generator expires (default/max
// 12h), so a static MNEMO_LLM_API_KEY would eventually 401. And mem9 can't emit
// the OpenAI-Project header at all. This proxy resolves BOTH without a mem9 fork
// and without restarting mnemo-server on rotation:
//
//   mnemo-server ──(localhost, static dummy key)──▶ THIS PROXY ──(fresh bearer +
//   OpenAI-Project)──▶ https://bedrock-mantle.<region>.api.aws/v1/chat/completions
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
// fail on connectivity), and injects it + OpenAI-Project per forwarded request.
//
// Verified live 2026-07-12: getToken({credentials,region}) → bearer;
// POST bedrock-mantle.ap-northeast-1.../v1/chat/completions {model:"zai.glm-5"}
// → HTTP 200 (see the mantle-token-12h-expiry memory).
//
// Testability: the HTTP server is built by createProxyServer(cfg), with the
// token minter + upstream fetch injectable, so unit tests exercise the real
// routing / header-injection / error paths without touching AWS or Mantle. When
// run directly (node server.mjs) the module wires the real deps + starts listening.

import { createServer } from "node:http";

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
    // The bearer's lifetime. getToken's default+max is 12h (43200s); we mint at
    // max and refresh at a fraction so a fresh token is always well within expiry.
    tokenTtlSeconds: Number(env.LLM_PROXY_TOKEN_TTL_SECONDS || 43200),
    // Refresh interval. Default = 1h (well under 12h TTL); a long safety margin
    // costs nothing since minting is a local presign, not an API call.
    refreshIntervalMs: Number(env.LLM_PROXY_REFRESH_INTERVAL_MS || 60 * 60 * 1000),
    // Per-request upstream timeout. mem9's own client uses 120s; match it so the
    // proxy never times out before mem9 would.
    upstreamTimeoutMs: Number(env.LLM_PROXY_UPSTREAM_TIMEOUT_MS || 120_000),
  };
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────
function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
  });
  res.end(body);
}

function sendError(res, status, message, type = "invalid_request_error") {
  sendJson(res, status, { error: { message, type } });
}

async function readBody(req, limitBytes = 8 * 1024 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limitBytes) throw new Error("request body too large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
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
  if (typeof mintToken !== "function") {
    throw new Error("createProxyServer requires deps.mintToken");
  }

  const state = { token: null, firstMint: null, lastMintAt: 0, refreshTimer: null };

  async function refresh() {
    const token = await mintToken();
    state.token = token;
    state.lastMintAt = Date.now();
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

  async function forwardToMantle(bodyBuf) {
    const token = await ensureToken();
    const headers = {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    };
    if (cfg.openaiProject) headers["OpenAI-Project"] = cfg.openaiProject;

    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), cfg.upstreamTimeoutMs);
    try {
      return await fetchImpl(`${cfg.upstreamBase}/chat/completions`, {
        method: "POST",
        headers,
        body: bodyBuf,
        signal: ac.signal,
      });
    } finally {
      clearTimeout(timer);
    }
  }

  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, `http://localhost:${cfg.port}`);

      // Readiness: 200 once the first bearer is minted. The ECS health check gates
      // the task on this so mnemo-server isn't marked healthy before the proxy can
      // auth. NON-BLOCKING: report the CURRENT token state — never await the
      // in-flight mint (that would hang the health probe until Mantle auth is up).
      if (req.method === "GET" && (url.pathname === "/health" || url.pathname === "/healthz")) {
        const ready = !!state.token;
        return sendJson(res, ready ? 200 : 503, {
          status: ready ? "ok" : "starting",
          lastMintAgeSeconds: state.lastMintAt
            ? Math.round((Date.now() - state.lastMintAt) / 1000)
            : null,
        });
      }

      // mem9 posts to `${MNEMO_LLM_BASE_URL}/chat/completions`; base is
      // http://localhost:PORT/v1 → accept /v1/chat/completions and /chat/completions.
      if (req.method === "POST" && /\/(v1\/)?chat\/completions$/.test(url.pathname)) {
        const bodyBuf = await readBody(req);
        const upstream = await forwardToMantle(bodyBuf);
        // Pass the upstream status + JSON body straight through. mem9 handles
        // non-2xx itself (it strips provider-specific flags on 400 and retries).
        const text = await upstream.text();
        res.writeHead(upstream.status, {
          "content-type": upstream.headers.get("content-type") || "application/json",
          "content-length": Buffer.byteLength(text),
        });
        return res.end(text);
      }

      return sendError(res, 404, `no route for ${req.method} ${url.pathname}`, "not_found");
    } catch (err) {
      // AbortError = upstream timeout; everything else = proxy/mint failure. Never
      // leak internals; log server-side, return an OpenAI-shaped error.
      const isTimeout = err?.name === "AbortError";
      console.error("llm-proxy request error:", err?.message || err);
      return sendError(
        res,
        isTimeout ? 504 : 502,
        isTimeout ? "upstream Mantle request timed out" : "llm-proxy failed to reach Mantle",
        "server_error",
      );
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

// ── Direct-run entrypoint (node server.mjs) ────────────────────────────────────
// Only wires the real AWS deps + listens when executed as the main module, so
// importing this file in a test does not require AWS credentials.
const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const cfg = readConfig();
  // Real minter: presign a Bedrock bearer from the task role. Local (no network).
  const { getToken } = await import("@aws/bedrock-token-generator");
  const { fromNodeProviderChain } = await import("@aws-sdk/credential-providers");
  const credentialProvider = fromNodeProviderChain();
  const mintToken = async () => {
    const credentials = await credentialProvider();
    return getToken({ credentials, region: cfg.region, expiresInSeconds: cfg.tokenTtlSeconds });
  };

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
