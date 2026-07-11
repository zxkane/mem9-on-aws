# mem9-on-aws schema-bootstrap — one-shot task image (ARCHITECTURE.md §8).
#
# A short-lived task run on each deploy that applies the pgvector + control-plane
# + memories(vector 1024) schema and seeds one active tenant, then exits. Uses
# psql (from the postgres client) + jq (to parse the Secrets Manager JSON). Kept
# separate from the mnemo-server image because that alpine image has no psql; this
# is a tiny throwaway runner, not a long-lived service.
#
# postgres:17 client matches the Aurora PostgreSQL 17.x engine (infra/db.ts).
# Runs on arm64 (task architecture) — postgres + jq are multi-arch.

FROM postgres:17-alpine

RUN apk add --no-cache jq

COPY docker/bootstrap/schema.sql /bootstrap/schema.sql
COPY docker/bootstrap/entrypoint.sh /bootstrap/entrypoint.sh
RUN chmod +x /bootstrap/entrypoint.sh

# One-shot: applies schema + seeds the tenant, then exits 0. Not a server.
ENTRYPOINT ["/bootstrap/entrypoint.sh"]
