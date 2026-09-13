# qwen3-embed sidecar — OpenAI /v1/embeddings backed by Qwen3-Embedding-0.6B ONNX.
#
# ARCHITECTURE.md §7: mem9's embedding MaaS, always-warm ECS sidecar next to
# mnemo-server (localhost). Embedding logic (model, last_token pooling, 1024 dims)
# is a standalone ONNX embedder; server.mjs is the thin HTTP shell.
#
# The model is BAKED INTO THE IMAGE at build time (no cold-start download) so task
# startup is deterministic. @huggingface/transformers v4 ignores HF_HOME and
# caches under node_modules/@huggingface/transformers/.cache — the bake writes
# there and runtime reads the same install-relative dir, so we must NOT reinstall
# node_modules after baking.
#
# BASE = node:24-trixie-slim (Debian, **glibc**), NOT alpine. onnxruntime-node
# ships only glibc-linked prebuilt .so binaries; on alpine (musl) the model load
# dies with `__vsnprintf_chk: symbol not found` (ERR_DLOPEN_FAILED) — a glibc-only
# fortified symbol — any glibc base (Debian/Amazon Linux) works for the same reason.
# node:24-trixie-slim is multi-arch → arm64 is pulled for --platform=linux/arm64.
# Node 24 (@huggingface/transformers needs >=24; project standard).

FROM node:24-trixie-slim AS model

WORKDIR /app

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

# Runtime upgrades run on every CI build without invalidating the model stage.
# Pulling a new base digest still rebuilds both stages to update Node/native deps.
# Copy the entire installation, including its model cache and native libraries.
FROM node:24-trixie-slim AS runtime
WORKDIR /app
RUN apt-get update \
    && apt-get dist-upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=model /app/node_modules ./node_modules
COPY docker/healthcheck.mjs ./healthcheck.mjs
COPY docker/qwen3-embed/server.mjs ./

# Listens on QWEN3_EMBED_PORT (default 8081); mem9 reaches it at
# http://localhost:8081/v1. Not published outside the task — localhost only.
EXPOSE 8081
ENV NODE_ENV=production
ENTRYPOINT ["node", "server.mjs"]
