# qwen3-embed sidecar — OpenAI /v1/embeddings backed by Qwen3-Embedding-0.6B ONNX.
#
# ARCHITECTURE.md §7: mem9's embedding MaaS, always-warm ECS sidecar next to
# mnemo-server (localhost). Embedding logic (model, last_token pooling, 1024 dims)
# lifted from zxkane/llm-wiki's ONNX embedder; server.mjs is the thin HTTP shell.
#
# The model is BAKED INTO THE IMAGE at build time (no cold-start download) so task
# startup is deterministic. @huggingface/transformers v4 ignores HF_HOME and
# caches under node_modules/@huggingface/transformers/.cache — the bake writes
# there and runtime reads the same install-relative dir, so we must NOT reinstall
# node_modules after baking.
#
# BASE = node:24-slim (Debian bookworm, **glibc**), NOT alpine. onnxruntime-node
# ships only glibc-linked prebuilt .so binaries; on alpine (musl) the model load
# dies with `__vsnprintf_chk: symbol not found` (ERR_DLOPEN_FAILED) — a glibc-only
# fortified symbol. llm-wiki runs this on Amazon Linux (glibc) for the same reason.
# node:24-slim is multi-arch → the arm64 variant is pulled for --platform=linux/arm64.
# Node 24 (@huggingface/transformers needs >=24; project standard).

FROM node:24-slim

WORKDIR /app

# curl for the ECS health check (bookworm-slim ships neither curl nor wget); the
# glibc runtime onnxruntime-node needs is already present in the Debian base.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Install deps first (layer cache); --omit=dev keeps only @huggingface/transformers
# + its transitive onnxruntime-node (~513 MB).
COPY docker/qwen3-embed/package.json ./
RUN npm install --omit=dev --no-audit --no-fund

# Bake the ONNX model into the image. This downloads Qwen3-Embedding-0.6B-ONNX
# (~1.2 GB) into node_modules/@huggingface/transformers/.cache at build time so
# the running container never hits the network. dtype fp32 must match server.mjs.
RUN node -e "import('@huggingface/transformers').then(async (m) => { \
      await m.pipeline('feature-extraction', 'onnx-community/Qwen3-Embedding-0.6B-ONNX', { dtype: 'fp32' }); \
      console.log('qwen3-0.6B ONNX model baked into image'); \
    }).catch((e) => { console.error('model bake failed:', e); process.exit(1); })"

COPY docker/qwen3-embed/server.mjs ./

# Listens on QWEN3_EMBED_PORT (default 8081); mem9 reaches it at
# http://localhost:8081/v1. Not published outside the task — localhost only.
EXPOSE 8081
ENV NODE_ENV=production
ENTRYPOINT ["node", "server.mjs"]
