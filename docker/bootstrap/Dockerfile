# mem9-on-aws schema-bootstrap — one-shot task image (ARCHITECTURE.md §8).
#
# A short-lived task run on each deploy that applies the pgvector + control-plane
# + memories(vector 1024) schema and seeds one active tenant, then exits. Uses
# psql (from the postgres client) + jq (to parse the Secrets Manager JSON). Kept
# separate from the mnemo-server startup migration because it applies the full
# schema and tenant seed; this is a one-shot runner, not a long-lived service.
#
# postgres:17 client matches the Aurora PostgreSQL 17.x engine (infra/db.ts).
# Runs on arm64 (task architecture) — postgres + jq are multi-arch.

FROM node:24-alpine3.24 AS runtime

RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates jq postgresql17-client \
    && mkdir -p /bootstrap

RUN node --input-type=module -e "\
      const response = await fetch('https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem', { signal: AbortSignal.timeout(30000) }); \
      if (!response.ok) throw new Error('RDS CA download failed: ' + response.status); \
      const { writeFile } = await import('node:fs/promises'); \
      await writeFile('/bootstrap/global-bundle.pem', new Uint8Array(await response.arrayBuffer()));"

ENV NODE_EXTRA_CA_CERTS=/bootstrap/global-bundle.pem

COPY docker/bootstrap/schema.sql /bootstrap/schema.sql
COPY docker/bootstrap/migrations/ /bootstrap/migrations/
COPY docker/bootstrap/entrypoint.sh /bootstrap/entrypoint.sh
COPY docker/bootstrap/operator-entrypoint.mjs /bootstrap/operator/operator-entrypoint.mjs
COPY scripts/lib/memory-namespace.mjs /bootstrap/operator/scripts/lib/memory-namespace.mjs
COPY scripts/manage-memory-access.mjs /bootstrap/operator/scripts/manage-memory-access.mjs
COPY scripts/migrate-memory-namespaces.mjs /bootstrap/operator/scripts/migrate-memory-namespaces.mjs
# The standalone operator resolves its enforcement SQL relative to scripts/,
# just as it does in a checkout. Preserve that layout alongside bootstrap's SQL.
COPY docker/bootstrap/migrations/003_enforce_memory_namespaces.sql /bootstrap/operator/docker/bootstrap/migrations/003_enforce_memory_namespaces.sql
COPY scripts/prepare-preview-memory-namespaces.mjs /bootstrap/operator/scripts/prepare-preview-memory-namespaces.mjs
COPY scripts/reconcile-memory-namespaces.mjs /bootstrap/operator/scripts/reconcile-memory-namespaces.mjs
COPY package.json package-lock.json /bootstrap/operator/
RUN cd /bootstrap/operator && npm ci --omit=dev
RUN chmod +x /bootstrap/entrypoint.sh

# One-shot: applies schema + seeds the tenant, then exits 0. Not a server.
ENTRYPOINT ["/bootstrap/entrypoint.sh"]
