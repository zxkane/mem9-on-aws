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
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl --fail --silent --show-error \
      https://truststore.pki.rds.amazonaws.com/ap-northeast-1/ap-northeast-1-bundle.pem \
      --output /app/ap-northeast-1-bundle.pem \
    && rm -rf /var/lib/apt/lists/*

# Deps first (layer cache). The sidecar uses the token dependencies; the
# consolidation entrypoint additionally uses PostgreSQL and SNS.
COPY docker/llm-proxy/package*.json ./
RUN npm ci --omit=dev --no-audit --no-fund

# PRESERVE the repo directory layout: memory-cleanup.mjs imports the sidecar as
# `../docker/llm-proxy/server.mjs`, so flattening both into /app makes that
# resolve to /docker/llm-proxy/server.mjs and the consolidation entrypoint dies
# on its first import. The sidecar itself is still started as `server.mjs` from
# the /app workdir (see ENTRYPOINT), so it is copied to BOTH locations.
COPY docker/llm-proxy/server.mjs ./
COPY docker/llm-proxy/server.mjs /app/docker/llm-proxy/server.mjs
COPY scripts/memory-cleanup.mjs /app/scripts/memory-cleanup.mjs
COPY scripts/memory-consolidation.mjs /app/scripts/memory-consolidation.mjs

# Fail the BUILD, not the weekly run, if that import graph ever breaks again.
RUN node --input-type=module \
      -e "await import('/app/scripts/memory-consolidation.mjs')" \
    && echo "consolidation entrypoint imports OK"

# Listens on LLM_PROXY_PORT (default 8082); mem9 reaches it at
# http://localhost:8082/v1. Not published outside the task — localhost only.
EXPOSE 8082
ENV NODE_ENV=production
ENV NODE_EXTRA_CA_CERTS=/app/ap-northeast-1-bundle.pem
ENTRYPOINT ["node", "server.mjs"]
