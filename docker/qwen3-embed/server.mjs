// OpenAI-compatible /v1/embeddings service backed by Qwen3-Embedding-0.6B ONNX.
//
// mem9's embedder (server/internal/embed/embedder.go) POSTs to
// `${MNEMO_EMBED_BASE_URL}/embeddings` with an OpenAI-shaped body and expects an
// OpenAI-shaped reply. This is the mem9-on-aws embedding MaaS (ARCHITECTURE.md §7):
// it runs as an ALWAYS-WARM ECS sidecar next to mnemo-server, reached over
// localhost, so there's no cold-start / cross-service auth. The embedding code
// (model, last_token pooling, L2 normalize, 1024 dims) is a standalone ONNX
// embedder; this file is the thin HTTP wrapper around it.
//
// Non-obvious choices (see docs/mem9-facts.md "Embedding" + the qwen3 memory):
//   - ONE text per pipeline call, never a native string[] batch: with last_token
//     pooling, transformers.js pads every text to the batch's longest → one long
//     input inflates the whole batch. ORT already parallelizes a single forward
//     across vCPUs, so we loop and let ORT use the cores.
//   - DOCUMENT mode (no instruction prefix): the OpenAI /embeddings contract has
//     no query/document hint, and mem9 sends memory content. Both the stored
//     memory and mem9's own query embedding go through here in document mode —
//     symmetric, correct for cosine.
//   - dims MUST be 1024 (qwen3-0.6B native; matches the PG vector(1024) column the
//     bootstrap creates + mem9's MNEMO_EMBED_DIMS=1024). We assert it.

import { createServer } from "node:http";
import { createMaintenanceAdmission } from "./maintenance-admission.mjs";

const maintenanceAdmission = createMaintenanceAdmission();

const PORT = Number(process.env.QWEN3_EMBED_PORT || 8081);
const MODEL_REPO =
  process.env.QWEN3_EMBED_MODEL_REPO || "onnx-community/Qwen3-Embedding-0.6B-ONNX";
// The model id reported back in the OpenAI response `model` field. mem9 sends
// MNEMO_EMBED_MODEL; we echo whatever the request asked for (or this default).
const MODEL_ID = process.env.QWEN3_EMBED_MODEL_ID || "qwen3-embedding-0.6b";
const EXPECTED_DIM = 1024; // qwen3-0.6B native; NOT configurable (no Matryoshka).
// ORT thread pinning: leave unset on Fargate (cpuinfo works there). Set
// QWEN3_INTRA_OP_THREADS to the task vCPU count only if inference goes
// single-threaded (the Lambda-sandbox cpuinfo-autodetect failure mode).
const INTRA_OP_THREADS = Number(process.env.QWEN3_INTRA_OP_THREADS || 0);

// Resource-exhaustion bounds (CWE-770). Env-tunable so the ECS task definition
// owns production values, mirroring llm-proxy's LLM_PROXY_* envelope. The
// handler enforces these unconditionally -- NOT keyed off any client header.
function readPositiveInt(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0 || !Number.isInteger(n)) return fallback;
  return n;
}
// Max number of texts per request. mnemo-server's interactive path sends one.
const MAX_INPUTS = readPositiveInt("QWEN3_EMBED_MAX_INPUTS", 32);
// Max bytes per text, matching the maintenance budget (16 KiB).
const MAX_INPUT_BYTES = readPositiveInt("QWEN3_EMBED_MAX_INPUT_BYTES", 16 * 1024);
// Max concurrent inferences (interactive + maintenance share the pool).
const MAX_CONCURRENCY = readPositiveInt("QWEN3_EMBED_MAX_CONCURRENCY", 2);
// Overall per-request compute deadline. Exceeds mnemo-server's 45s maintenance
// client timeout so legitimate work completes; still bounds orphaned work.
const OVERALL_DEADLINE_MS = readPositiveInt("QWEN3_EMBED_OVERALL_DEADLINE_MS", 55_000);
// Worst-case body size: MAX_INPUTS * MAX_INPUT_BYTES plus small JSON envelope.
const DEFAULT_MAX_BODY_BYTES = MAX_INPUTS * MAX_INPUT_BYTES + 16 * 1024;
const MAX_BODY_BYTES = readPositiveInt("QWEN3_EMBED_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES);

// Global in-flight limiter. Covers interactive and maintenance paths alike so
// concurrent requests cannot blow past the task's limited headroom.
let inFlight = 0;
function tryAcquire() {
  if (inFlight >= MAX_CONCURRENCY) return null;
  inFlight += 1;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    inFlight -= 1;
  };
}

// The feature-extraction pipeline, created once at boot and reused (always-warm).
let extractorPromise = null;

async function getExtractor() {
  if (!extractorPromise) {
    extractorPromise = (async () => {
      const mod = await import("@huggingface/transformers");
      const opts = { dtype: "fp32" }; // fp16 hurts recall; int8/q8 wreck it.
      if (INTRA_OP_THREADS > 0) {
        opts.session_options = {
          intraOpNumThreads: INTRA_OP_THREADS,
          interOpNumThreads: 1,
          executionMode: "sequential",
        };
      }
      return mod.pipeline("feature-extraction", MODEL_REPO, opts);
    })();
  }
  return extractorPromise;
}

// Embed one text → a length-1024 number[]. last_token pooling + L2 normalize,
// document mode (no prefix). Throws on a dim mismatch (fail loud, never store a
// wrong-width vector).
async function embedOne(extractor, text) {
  const result = await extractor(text, { pooling: "last_token", normalize: true });
  const vec = Array.from(result.data);
  if (vec.length !== EXPECTED_DIM) {
    throw new Error(
      `embedding dim mismatch: expected ${EXPECTED_DIM}, got ${vec.length}`,
    );
  }
  return vec;
}

// Normalize the OpenAI `input` field → an array of strings. Accepts a string or
// a string[] (OpenAI also allows token-id arrays, which mem9 never sends — we
// reject those explicitly rather than silently mis-embed).
function normalizeInput(input) {
  if (typeof input === "string") return [input];
  if (Array.isArray(input) && input.every((x) => typeof x === "string")) return input;
  return null;
}

function sendJson(res, status, obj) {
  if (res.headersSent || res.writableEnded) return;
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

async function readBody(req, limitBytes = MAX_BODY_BYTES) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limitBytes) {
      const err = new Error("request body too large");
      err.statusCode = 413;
      throw err;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://localhost:${PORT}`);

    // Liveness/readiness: 200 only once the model is loaded, so an ECS/ALB health
    // check won't route traffic before the pipeline is warm.
    if (req.method === "GET" && (url.pathname === "/health" || url.pathname === "/healthz")) {
      let loaded = false;
      if (extractorPromise !== null) {
        try {
          await extractorPromise;
          loaded = true;
        } catch {
          // Load failed → stay 503 (loaded already false); the boot handler exits.
        }
      }
      return sendJson(res, loaded ? 200 : 503, { status: loaded ? "ok" : "loading" });
    }

    // OpenAI embeddings. mem9 posts to `${base}/embeddings`; base is
    // http://localhost:PORT/v1, so accept both /v1/embeddings and /embeddings.
    if (req.method === "POST" && /\/(v1\/)?embeddings$/.test(url.pathname)) {
      let raw;
      try {
        raw = await readBody(req);
      } catch (err) {
        if (err && err.statusCode === 413) {
          return sendError(res, 413, "request body too large");
        }
        throw err;
      }
      let payload;
      try {
        payload = JSON.parse(raw);
      } catch {
        return sendError(res, 400, "request body is not valid JSON");
      }
      const inputs = normalizeInput(payload?.input);
      if (!inputs) {
        return sendError(
          res,
          400,
          "`input` must be a string or an array of strings (token-id arrays are not supported)",
        );
      }
      // Unconditional input bounds. Enforced for every request; the maintenance
      // header does NOT gate them. One malformed request must not drive
      // unbounded ONNX work on the single shared embedder.
      if (inputs.length === 0) {
        return sendError(res, 400, "`input` must contain at least one string");
      }
      if (inputs.length > MAX_INPUTS) {
        return sendError(res, 400, `too many inputs (max ${MAX_INPUTS})`);
      }
      for (let i = 0; i < inputs.length; i++) {
        if (Buffer.byteLength(inputs[i]) > MAX_INPUT_BYTES) {
          return sendError(
            res,
            413,
            `input[${i}] exceeds per-text byte limit (max ${MAX_INPUT_BYTES} bytes)`,
          );
        }
      }
      const maintenance = req.headers["x-mem9-maintenance"];
      // Maintenance header is advisory: its only effect is to route through the
      // single-flight admission permit so a maintenance batch does not starve
      // the interactive path. Size and count caps are already enforced above.
      if (maintenance !== undefined && maintenance !== "1") {
        return sendError(res, 400, "invalid X-Mem9-Maintenance header value");
      }

      // Per-request compute deadline + abort-on-client-close. A disconnected
      // client cannot leave orphaned ONNX work consuming the shared vCPU.
      let aborted = false;
      let abortReason = null;
      const abort = (reason) => {
        if (aborted) return;
        aborted = true;
        abortReason = reason;
      };
      const onClientClose = () => {
        if (!res.writableEnded) abort("client_closed");
      };
      req.on("close", onClientClose);
      const deadlineTimer = setTimeout(
        () => abort("deadline_exceeded"),
        OVERALL_DEADLINE_MS,
      );
      if (typeof deadlineTimer.unref === "function") deadlineTimer.unref();

      // Global in-flight limiter. Shed load with 429 BEFORE any model call so
      // concurrent requests cannot evade the per-path admission permits.
      const release = tryAcquire();
      if (!release) {
        clearTimeout(deadlineTimer);
        req.off("close", onClientClose);
        res.setHeader("Retry-After", "1");
        return sendError(res, 429, "embedding service busy", "rate_limited");
      }

      const compute = async () => {
        const extractor = await getExtractor();
        // Single-text loop avoids padding unrelated texts to the longest input.
        const data = [];
        let totalChars = 0;
        for (let i = 0; i < inputs.length; i++) {
          if (aborted) {
            const err = new Error(`embedding aborted: ${abortReason ?? "aborted"}`);
            err.aborted = true;
            throw err;
          }
          const embedding = await embedOne(extractor, inputs[i]);
          data.push({ object: "embedding", index: i, embedding });
          totalChars += inputs[i].length;
        }
        return { data, totalChars };
      };
      let computed;
      try {
        if (maintenance === "1") {
          const admitted = await maintenanceAdmission.run(compute);
          if (!admitted.accepted) return sendError(res, 429, "maintenance embedding busy");
          res.setHeader("X-Mem9-Maintenance", "1");
          computed = admitted.value;
        } else {
          computed = await compute();
        }
      } catch (err) {
        if (err && err.aborted) {
          if (abortReason === "deadline_exceeded") {
            return sendError(res, 503, "embedding deadline exceeded", "server_error");
          }
          // Client disconnected mid-compute; drop the response.
          if (!res.writableEnded) {
            try { res.destroy(); } catch { /* ignore */ }
          }
          return;
        }
        throw err;
      } finally {
        clearTimeout(deadlineTimer);
        req.off("close", onClientClose);
        release();
      }
      const { data, totalChars } = computed;
      // usage.*_tokens are not meaningful here (no token accounting); report a
      // char-based proxy so the OpenAI shape is complete. mem9 ignores it.
      const approxTokens = Math.ceil(totalChars / 4);
      return sendJson(res, 200, {
        object: "list",
        data,
        model: typeof payload?.model === "string" && payload.model ? payload.model : MODEL_ID,
        usage: { prompt_tokens: approxTokens, total_tokens: approxTokens },
      });
    }

    return sendError(res, 404, `no route for ${req.method} ${url.pathname}`, "not_found");
  } catch (err) {
    // Never leak a stack; log server-side, return a generic 500.
    console.error("embed request error:", "EmbeddingError");
    return sendError(res, 500, "internal error computing embedding", "server_error");
  }
});

// Server-wide timeouts cap slow-header / slow-body abuse at the HTTP layer.
// The per-request handler above still owns the compute deadline.
server.headersTimeout = 15_000;
server.requestTimeout = Math.max(OVERALL_DEADLINE_MS + 5_000, 30_000);
server.keepAliveTimeout = 10_000;

server.listen(PORT, () => {
  console.log(`qwen3-embed listening on :${PORT} (model ${MODEL_REPO}, dims ${EXPECTED_DIM})`);
  // Kick off model load at boot so the sidecar is warm before the first request
  // (and /health flips to 200 only when it's done).
  getExtractor()
    .then(() => console.log("qwen3-embed model loaded, ready"))
    .catch((err) => {
      console.error("qwen3-embed model load FAILED:", err?.message || err);
      // Exit non-zero so ECS restarts the task rather than serving 503 forever.
      process.exit(1);
    });
});
