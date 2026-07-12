// OpenAI-compatible /v1/embeddings service backed by Qwen3-Embedding-0.6B ONNX.
//
// mem9's embedder (server/internal/embed/embedder.go) POSTs to
// `${MNEMO_EMBED_BASE_URL}/embeddings` with an OpenAI-shaped body and expects an
// OpenAI-shaped reply. This is the mem9-on-aws embedding MaaS (ARCHITECTURE.md §7):
// it runs as an ALWAYS-WARM ECS sidecar next to mnemo-server, reached over
// localhost, so there's no cold-start / cross-service auth. The embedding code
// (model, last_token pooling, L2 normalize, 1024 dims) is lifted from
// zxkane/llm-wiki's ONNX embedder; this file is the thin HTTP wrapper llm-wiki
// never had (it called the embedder in-process).
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
      const raw = await readBody(req);
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
      const extractor = await getExtractor();
      // Single-text loop — NOT a native batch (padding pathology, see header).
      const data = [];
      let totalChars = 0;
      for (let i = 0; i < inputs.length; i++) {
        const embedding = await embedOne(extractor, inputs[i]);
        data.push({ object: "embedding", index: i, embedding });
        totalChars += inputs[i].length;
      }
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
    console.error("embed request error:", err?.message || err);
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
