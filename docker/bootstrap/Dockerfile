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
COPY docker/bootstrap/runtime-contract.sql docker/bootstrap/schema-digest.sh /bootstrap/
COPY docker/bootstrap/schema-digest.sh /bootstrap/operator/docker/bootstrap/schema-digest.sh
RUN sh /bootstrap/schema-digest.sh /bootstrap > /bootstrap/schema.sha256
COPY docker/bootstrap/entrypoint.sh /bootstrap/entrypoint.sh
COPY docker/bootstrap/operator-entrypoint.mjs /bootstrap/operator/operator-entrypoint.mjs
COPY scripts/lib/memory-namespace.mjs /bootstrap/operator/scripts/lib/memory-namespace.mjs
COPY scripts/lib/memory-ingest-cancellation.mjs /bootstrap/operator/scripts/lib/memory-ingest-cancellation.mjs
COPY scripts/manage-memory-access.mjs /bootstrap/operator/scripts/manage-memory-access.mjs
COPY scripts/manage-memory-services.mjs /bootstrap/operator/scripts/manage-memory-services.mjs
COPY infra/gateway/service-auth.mjs /bootstrap/operator/infra/gateway/service-auth.mjs
COPY scripts/migrate-memory-namespaces.mjs /bootstrap/operator/scripts/migrate-memory-namespaces.mjs
COPY scripts/benchmark-memory-namespaces.mjs /bootstrap/operator/scripts/benchmark-memory-namespaces.mjs
COPY scripts/observe-memory-namespace-connections.mjs /bootstrap/operator/scripts/observe-memory-namespace-connections.mjs
# The standalone operator resolves its enforcement SQL relative to scripts/,
# just as it does in a checkout. Preserve that layout alongside bootstrap's SQL.
COPY docker/bootstrap/migrations/003_enforce_memory_namespaces.sql /bootstrap/operator/docker/bootstrap/migrations/003_enforce_memory_namespaces.sql
COPY scripts/prepare-preview-memory-namespaces.mjs /bootstrap/operator/scripts/prepare-preview-memory-namespaces.mjs
COPY scripts/consolidation-preview-fixture.mjs /bootstrap/operator/scripts/consolidation-preview-fixture.mjs
COPY scripts/runtime-bootstrap.mjs /bootstrap/operator/scripts/runtime-bootstrap.mjs
COPY scripts/runtime-admin-probe.mjs /bootstrap/operator/scripts/runtime-admin-probe.mjs
COPY scripts/production-runtime-operator.mjs /bootstrap/operator/scripts/production-runtime-operator.mjs
COPY scripts/production-consolidation-operator.mjs /bootstrap/operator/scripts/production-consolidation-operator.mjs
COPY scripts/lib/production-canary-continuation.mjs /bootstrap/operator/scripts/lib/production-canary-continuation.mjs
COPY scripts/lib/production-canary-compatibility.mjs /bootstrap/operator/scripts/lib/production-canary-compatibility.mjs
COPY scripts/lib/production-canary-transition.mjs /bootstrap/operator/scripts/lib/production-canary-transition.mjs
COPY scripts/lib/production-image-transition.mjs /bootstrap/operator/scripts/lib/production-image-transition.mjs
COPY scripts/lib/production-canary-snapshot.mjs /bootstrap/operator/scripts/lib/production-canary-snapshot.mjs
COPY scripts/lib/production-canary-paused-audit.mjs /bootstrap/operator/scripts/lib/production-canary-paused-audit.mjs
# Runtime certificate/launch parsing is pure. Host-side proof collectors and
# source verifiers have a separate dependency closure and stay outside this image.
COPY scripts/lib/production-nonroot-contracts.mjs scripts/lib/production-nonroot-runtime.mjs scripts/lib/production-nonroot-launch.mjs /bootstrap/operator/scripts/lib/
COPY scripts/lib/nonroot-preview-source.mjs /bootstrap/operator/scripts/lib/nonroot-preview-source.mjs
COPY scripts/lib/production-canary-verification.mjs /bootstrap/operator/scripts/lib/production-canary-verification.mjs
COPY scripts/lib/production-canary-performance.mjs /bootstrap/operator/scripts/lib/production-canary-performance.mjs
COPY scripts/lib/production-canary-report.mjs /bootstrap/operator/scripts/lib/production-canary-report.mjs
COPY scripts/lib/canary-benchmark.mjs /bootstrap/operator/scripts/lib/canary-benchmark.mjs
COPY scripts/lib/production-artifacts.mjs /bootstrap/operator/scripts/lib/production-artifacts.mjs
COPY scripts/lib/production-runtime-config.mjs /bootstrap/operator/scripts/lib/production-runtime-config.mjs
COPY scripts/lib/production-runtime-state.mjs /bootstrap/operator/scripts/lib/production-runtime-state.mjs
COPY scripts/lib/production-runtime-credentials.mjs /bootstrap/operator/scripts/lib/production-runtime-credentials.mjs
COPY scripts/lib/production-runtime-ownership.mjs /bootstrap/operator/scripts/lib/production-runtime-ownership.mjs
COPY scripts/lib/production-runtime-rehearsal.mjs /bootstrap/operator/scripts/lib/production-runtime-rehearsal.mjs
COPY scripts/lib/production-runtime-cancellation.mjs /bootstrap/operator/scripts/lib/production-runtime-cancellation.mjs
COPY scripts/lib/runtime-extension-catalog.mjs /bootstrap/operator/scripts/lib/runtime-extension-catalog.mjs
COPY scripts/lib/runtime-admin-probe-config.mjs /bootstrap/operator/scripts/lib/runtime-admin-probe-config.mjs
COPY scripts/seed-tenant.mjs /bootstrap/operator/scripts/seed-tenant.mjs
COPY scripts/lib/runtime-credentials.mjs /bootstrap/operator/scripts/lib/runtime-credentials.mjs
COPY scripts/lib/consolidation-preview-config.mjs /bootstrap/operator/scripts/lib/consolidation-preview-config.mjs
COPY scripts/lib/post-runtime-preview-authority.mjs /bootstrap/operator/scripts/lib/post-runtime-preview-authority.mjs
COPY scripts/lib/post-runtime-preview-route.mjs /bootstrap/operator/scripts/lib/post-runtime-preview-route.mjs
COPY scripts/lib/consolidation-preview-secrets.mjs /bootstrap/operator/scripts/lib/consolidation-preview-secrets.mjs
COPY scripts/reconcile-memory-namespaces.mjs /bootstrap/operator/scripts/reconcile-memory-namespaces.mjs
COPY package.json package-lock.json /bootstrap/operator/
RUN cd /bootstrap/operator && npm ci --omit=dev
RUN chmod +x /bootstrap/entrypoint.sh

# The guarded launch is selected by the authenticated task plan. Keep these
# files outside the preserved application entrypoints and DATA build recipe.
COPY docker/bootstrap/nonroot-dispatch.mjs docker/bootstrap/nonroot-files.mjs docker/bootstrap/nonroot-identity.mjs /bootstrap/
COPY scripts/build-nonroot-manifest.mjs /usr/local/lib/mem9/build-nonroot-manifest.mjs
RUN chmod -R a+rX,go-w /bootstrap \
    && node /usr/local/lib/mem9/build-nonroot-manifest.mjs

# One-shot: applies schema + seeds the tenant, then exits 0. Not a server.
USER node
# Resolve the production entrypoints with the final filesystem and permissions.
# Importing a module must not execute its CLI or contact AWS/the database.
RUN --network=none /usr/local/bin/node --input-type=module -e "\
      const { readdir } = await import('node:fs/promises'); \
      for (const directory of ['/bootstrap', '/bootstrap/operator', '/bootstrap/operator/scripts', '/bootstrap/operator/scripts/lib']) { \
        for (const name of (await readdir(directory)).sort()) { \
          if (name.endsWith('.mjs')) await import(directory + '/' + name); \
        } \
      }"
ENTRYPOINT ["/bootstrap/entrypoint.sh"]
