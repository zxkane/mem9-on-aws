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

async function readBody(req, limitBytes = 12 * 1024 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limitBytes) throw new Error("request body too large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

// Structured server-side log record. Emitted as a single JSON line so that
// CloudWatch metric filters on the qwen3-embed log group can key off
// `$.msg`, `$.event`, and `$.err` (see infra/observability.ts: oversized-body
// and dim-mismatch filters). Never written to the HTTP response body: the
// response wire format stays the generic shape sendError/sendJson produce.
function logEvent(fields) {
  try {
    console.error(JSON.stringify(fields));
  } catch {
    // Fallback for a circular/non-serializable payload — better than silence.
    console.error("embed log serialization failed");
  }
}

// Classify the catch-all error so the dim-mismatch integrity guard and the
// oversized-body abuse signal are distinguishable in the log stream even if
// the error class is a plain Error.
function classifyError(err) {
  const message = typeof err?.message === "string" ? err.message : "";
  if (message.startsWith("embedding dim mismatch")) return "embed_dim_mismatch";
  if (message === "request body too large") return "embed_body_too_large";
  return "embed_request_error";
}

const server = createServer(async (req, res) => {
  // These are hoisted so the catch-all can include them in the structured log
  // without re-parsing. `raw` captures the pre-JSON byte length so the
  // oversized-body abuse signal records the attempted size.
  let url;
  let raw;
  let inputs;
  let maintenance;
  try {
    url = new URL(req.url, `http://localhost:${PORT}`);

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
      raw = await readBody(req);
      let payload;
      try {
        payload = JSON.parse(raw);
      } catch {
        logEvent({
          msg: "embed request rejected",
          event: "embed_invalid_json",
          status: 400,
          method: req.method,
          path: url.pathname,
          bytes: raw?.length,
          remote: req.socket.remoteAddress,
        });
        return sendError(res, 400, "request body is not valid JSON");
      }
      inputs = normalizeInput(payload?.input);
      if (!inputs) {
        logEvent({
          msg: "embed request rejected",
          event: "embed_invalid_input",
          status: 400,
          method: req.method,
          path: url.pathname,
          bytes: raw?.length,
          remote: req.socket.remoteAddress,
        });
        return sendError(
          res,
          400,
          "`input` must be a string or an array of strings (token-id arrays are not supported)",
        );
      }
      maintenance = req.headers["x-mem9-maintenance"];
      if (maintenance !== undefined && (maintenance !== "1" || inputs.length !== 1 || Buffer.byteLength(inputs[0]) > 16384)) {
        logEvent({
          msg: "embed request rejected",
          event: "embed_invalid_maintenance",
          status: 400,
          method: req.method,
          path: url.pathname,
          inputs: inputs?.length,
          bytes: raw?.length,
          maintenance: String(maintenance),
          remote: req.socket.remoteAddress,
        });
        return sendError(res, 400, "invalid maintenance embedding request");
      }
      const compute = async () => {
        const extractor = await getExtractor();
        // Single-text loop avoids padding unrelated texts to the longest input.
        const data = [];
        let totalChars = 0;
        for (let i = 0; i < inputs.length; i++) {
          const embedding = await embedOne(extractor, inputs[i]);
          data.push({ object: "embedding", index: i, embedding });
          totalChars += inputs[i].length;
        }
        return { data, totalChars };
      };
      let computed;
      if (maintenance === "1") {
        const admitted = await maintenanceAdmission.run(compute);
        if (!admitted.accepted) {
          logEvent({
            msg: "embed request rejected",
            event: "embed_maintenance_busy",
            status: 429,
            method: req.method,
            path: url.pathname,
            inputs: inputs?.length,
            bytes: raw?.length,
            maintenance: true,
            remote: req.socket.remoteAddress,
          });
          return sendError(res, 429, "maintenance embedding busy");
        }
        res.setHeader("X-Mem9-Maintenance", "1");
        computed = admitted.value;
      } else {
        computed = await compute();
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
    // Never leak a stack to the caller; log server-side with enough context to
    // distinguish oversized-body abuse, the dim-mismatch integrity guard, and
    // any ONNX/OOM inference failure. Response body is unchanged.
    logEvent({
      msg: "embed request error",
      event: classifyError(err),
      status: 500,
      err: err?.message,
      name: err?.name,
      method: req?.method,
      path: url?.pathname,
      inputs: inputs?.length,
      bytes: raw?.length,
      maintenance: maintenance === "1",
      remote: req.socket?.remoteAddress,
    });
    return sendError(res, 500, "internal error computing embedding", "server_error");
  }
});

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
