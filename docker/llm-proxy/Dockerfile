# llm-proxy sidecar — OpenAI /v1/chat/completions proxy → Amazon Bedrock Mantle.
#
# ARCHITECTURE.md §7 (LLM smart-ingest): mem9 reads MNEMO_LLM_API_KEY once at
# startup (immutable) and its client sends only Authorization + Content-Type. This
# sidecar holds the live Mantle bearer (refreshed on a timer via
# @aws/bedrock-token-generator — a LOCAL SigV4 presign, no network), and injects
# a fresh Bearer + the OpenAI-Project header per forwarded request. So mem9 auths
# with a static dummy key to localhost and never needs a restart on rotation, and
# no mem9 source fork is required. See docker/llm-proxy/server.mjs header.
#
# Lightweight: no model, pure Node. node:24-slim (Debian bookworm) is multi-arch →
# the arm64 variant is pulled for --platform=linux/arm64 (Graviton Fargate, project
# standard). curl for the ECS health check (bookworm-slim ships none).

FROM node:24-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Deps first (layer cache). --omit=dev: only @aws/bedrock-token-generator +
# @aws-sdk/credential-providers (+ their @smithy/@aws-sdk transitive deps).
COPY docker/llm-proxy/package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY docker/llm-proxy/server.mjs ./

# Listens on LLM_PROXY_PORT (default 8082); mem9 reaches it at
# http://localhost:8082/v1. Not published outside the task — localhost only.
EXPOSE 8082
ENV NODE_ENV=production
ENTRYPOINT ["node", "server.mjs"]
