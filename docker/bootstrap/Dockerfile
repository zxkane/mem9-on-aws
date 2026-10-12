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
COPY scripts/lib/memory-namespace.mjs scripts/lib/memory-ingest-cancellation.mjs /bootstrap/operator/scripts/lib/
COPY scripts/manage-memory-access.mjs scripts/manage-memory-services.mjs /bootstrap/operator/scripts/
COPY infra/gateway/service-auth.mjs /bootstrap/operator/infra/gateway/service-auth.mjs
COPY scripts/migrate-memory-namespaces.mjs scripts/benchmark-memory-namespaces.mjs scripts/observe-memory-namespace-connections.mjs /bootstrap/operator/scripts/
# The standalone operator resolves its enforcement SQL relative to scripts/,
# just as it does in a checkout. Preserve that layout alongside bootstrap's SQL.
COPY docker/bootstrap/migrations/003_enforce_memory_namespaces.sql /bootstrap/operator/docker/bootstrap/migrations/003_enforce_memory_namespaces.sql
COPY scripts/prepare-preview-memory-namespaces.mjs scripts/consolidation-preview-fixture.mjs scripts/runtime-bootstrap.mjs scripts/runtime-admin-probe.mjs scripts/production-runtime-operator.mjs scripts/production-consolidation-operator.mjs /bootstrap/operator/scripts/
COPY scripts/lib/production-canary-continuation.mjs scripts/lib/production-canary-compatibility.mjs scripts/lib/production-canary-transition.mjs scripts/lib/production-image-transition.mjs scripts/lib/production-canary-snapshot.mjs scripts/lib/production-canary-paused-audit.mjs /bootstrap/operator/scripts/lib/
# Runtime certificate/launch parsing is pure. Host-side proof collectors and
# source verifiers have a separate dependency closure and stay outside this image.
COPY scripts/lib/production-nonroot-contracts.mjs scripts/lib/production-nonroot-runtime.mjs scripts/lib/production-nonroot-control-current.mjs scripts/lib/production-nonroot-launch.mjs scripts/lib/nonroot-preview-source.mjs scripts/lib/production-canary-verification.mjs scripts/lib/production-canary-performance.mjs scripts/lib/production-canary-report.mjs scripts/lib/canary-benchmark.mjs scripts/lib/production-artifacts.mjs scripts/lib/production-runtime-config.mjs scripts/lib/production-runtime-state.mjs scripts/lib/production-runtime-credentials.mjs scripts/lib/production-runtime-ownership.mjs scripts/lib/production-runtime-rehearsal.mjs scripts/lib/production-runtime-cancellation.mjs scripts/lib/runtime-extension-catalog.mjs scripts/lib/runtime-admin-probe-config.mjs /bootstrap/operator/scripts/lib/
COPY scripts/seed-tenant.mjs /bootstrap/operator/scripts/seed-tenant.mjs
COPY scripts/lib/runtime-credentials.mjs scripts/lib/consolidation-preview-config.mjs scripts/lib/post-runtime-preview-authority.mjs scripts/lib/post-runtime-preview-route.mjs scripts/lib/consolidation-preview-secrets.mjs /bootstrap/operator/scripts/lib/
COPY scripts/reconcile-memory-namespaces.mjs /bootstrap/operator/scripts/reconcile-memory-namespaces.mjs
COPY package.json package-lock.json /bootstrap/operator/
RUN cd /bootstrap/operator && npm ci --omit=dev
RUN chmod +x /bootstrap/entrypoint.sh

# The guarded launch is selected by the authenticated task plan. Keep these
# files outside the preserved application entrypoints and DATA build recipe.
COPY docker/bootstrap/nonroot-dispatch.mjs docker/bootstrap/nonroot-files.mjs docker/bootstrap/nonroot-identity.mjs /bootstrap/
COPY scripts/production-continuation-inspection.mjs /bootstrap/operator/scripts/
COPY scripts/lib/production-continuation-inspection.mjs scripts/lib/production-continuation-root.mjs scripts/lib/production-continuation-publication.mjs scripts/lib/production-continuation-absence.mjs scripts/lib/production-nonroot-local-work.mjs scripts/lib/production-nonroot-archive-capacity.mjs scripts/lib/ci-smoke-acquisition-format.mjs scripts/lib/ci-smoke-evidence.mjs scripts/lib/production-nonroot-budget-revision.mjs scripts/lib/production-nonroot-observer-control-context.mjs scripts/lib/production-nonroot-observer-delivery.mjs scripts/lib/production-nonroot-observer-route-probe.mjs scripts/lib/production-nonroot-observer-runtime-provider.mjs scripts/lib/production-nonroot-observer-route-protocol.mjs scripts/lib/production-nonroot-observer-finalization-work.mjs /bootstrap/operator/scripts/lib/
COPY infra/gateway/namespace-auth.mjs /bootstrap/operator/infra/gateway/namespace-auth.mjs
COPY scripts/validate-emf-event.mjs /bootstrap/operator/scripts/validate-emf-event.mjs
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
