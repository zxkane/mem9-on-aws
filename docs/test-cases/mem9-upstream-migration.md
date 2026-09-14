# mem9 upstream migration acceptance tests

Target: upstream `5af03a68c072651e9c64d1b8b1265e36b7354671` with the complete
downstream patch stack, including namespace enforcement. Assistant extraction
remains disabled. Existing database schemas and embedding dimensions are retained.

| ID | Scenario | Required result |
| --- | --- | --- |
| TC-UPSTREAM-001 | Build from the exact source pin and apply all patches in lexical order | All patches apply without fuzz/reject files; Go tests and arm64 build pass |
| TC-UPSTREAM-002 | Recall has successful and deadline-exhausted branches | Available results and upstream partial/warning fields reach the MCP caller; confidence tunables and zero-result fallback remain effective |
| TC-UPSTREAM-003 | Backend stalls, body stalls, retry backoff, or Lambda has little remaining time | One total proxy budget covers all attempts and body reads; active work is canceled before the Lambda deadline; exhausted work is not retried |
| TC-UPSTREAM-004 | Fast transient backend failure followed by success | Bounded retry succeeds within the original deadline and refreshes the signed transport envelope |
| TC-UPSTREAM-005 | Latest upstream extraction is used by the durable worker | Default remains user-only, the assistant setting reaches the separate worker constructor, and durable-only filtering/request bounds still apply |
| TC-UPSTREAM-006 | PostgreSQL tags-only/metadata-only PUT | Existing embedding survives read-modify-write; stale If-Match returns 412 without mutation; a foreign namespace cannot update the row |
| TC-UPSTREAM-007 | Content changes with and without an embedder | New content receives its new vector; without an embedder the old-content vector is cleared |
| TC-UPSTREAM-008 | Durable ingest retries, lease recovery, rollback, and worker restart | Existing queue, atomic apply, fencing, session deletion, and telemetry integration tests pass |
| TC-UPSTREAM-009 | Updated upstream repository SQL is inventoried | Every changed statement is reviewed; namespace predicates and signed authorization remain enforced; inventory matches the patched tree |
| TC-UPSTREAM-010 | Fresh and existing namespace schemas start the migrated server | Existing bootstrap/migration/startup and cross-namespace integration tests pass without a new migration or re-embedding |
| TC-UPSTREAM-011 | Preview deployment uses the migrated image | Health, authenticated MCP, namespace isolation, and OAuth smoke checks pass |
| TC-UPSTREAM-012 | Cold-cache schema check waits for a PostgreSQL connection | Recall returns its deadline response, cancels schema work, and leaves the failed service bundle uncached |
| TC-UPSTREAM-013 | Durable configuration/lessons contain operational phrases | Coding-agent durable mode preserves the useful fact while rejecting transient status and explicit operational-log classifications |
| TC-UPSTREAM-014 | Live MCP smart-write smoke uses a synthetic project's established configuration | The marked fact is retrieved and NL recall is non-empty; the harness does not bypass extraction with pinned memory and passes with `E2E_SOFT=0` |

Run the existing root/infra tests, `scripts/run-ingest-queue-integration.sh`,
`scripts/run-memory-namespace-integration.sh`, and
`scripts/run-mnemo-emf-smoke.sh`; CI also exercises the deployed preview.
