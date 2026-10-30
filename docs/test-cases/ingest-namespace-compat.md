# Durable ingest before namespace cutover

Production compatibility mode uses the additive schema and legacy tenant-wide
idempotency index. The enforced namespace index is installed by the separate
cutover; normal transcript ingestion must work before that cutover.

| ID | Scenario | Expected result |
| --- | --- | --- |
| TC-COMPAT-001 | Real PostgreSQL additive schema, no namespace on authenticated request | HTTP 202 follows a committed job; repeating the same request returns the same job |
| TC-COMPAT-002 | Compatibility worker extracts, embeds, and applies that job | Job succeeds atomically, session and one memory persist, and vector recall finds the memory |
| TC-COMPAT-003 | Read compatibility job using another tenant or namespace | Not found |
| TC-COMPAT-004 | Scoped enqueue against additive-only schema, or unscoped enqueue after enforcement | Reject without a row; never fall back to a different scope/index |
| TC-COMPAT-005 | Same idempotency key in two enforced namespaces | Existing isolation tests continue to admit two distinct jobs |
| TC-COMPAT-006 | Both indexes exist and a scoped job already owns the legacy key | Unscoped enqueue fails without returning that foreign job |
| TC-COMPAT-007 | Deployed MCP transcript ingest and repeated request | Same job ID, then succeeded; admission errors, dead jobs and changed replay IDs fail even when search smoke is soft |

The integration harness prepares separate additive and enforced database
templates and executes all Go packages against both contracts. No production
schema, namespace flag, or maintenance schedule changes are part of this fix.

## Namespace vector reconciliation retries

Smart writes must finish an exact namespace lookup before reconciling existing
memories. A transient statement timeout may be retried in this read-only phase;
it must never turn into an empty result or a keyword-only write decision.

| ID | Scenario | Expected result |
| --- | --- | --- |
| TC-COMPAT-008 | Two namespace vector timeouts followed by a matching memory | Third lookup succeeds with the same filter, limit and embedding; embedding generation runs once for the lookup |
| TC-COMPAT-009 | Every lookup times out | Stop after three attempts, return the timeout, and perform no memory mutation |
| TC-COMPAT-010 | Namespace capacity refusal | Fail immediately without retry or keyword-only reconciliation |
| TC-COMPAT-011 | Caller cancels after the first timeout | Stop before another lookup or keyword fallback and return cancellation |
| TC-COMPAT-012 | Caller deadline expires during retry backoff | Return the deadline error without a second lookup or any write |
| TC-COMPAT-013 | Lookup succeeds immediately or returns an unrelated backend error | Do not retry; retain existing successful and keyword-fallback behavior |
| TC-COMPAT-014 | Full patched-upstream integration and deployed MCP smoke | Existing namespace isolation and atomic ingest suites pass; a smart write remains searchable under the unchanged hard E2E assertions |

Use synthetic in-process repository and embedding fixtures for deterministic
fault injection. Run the service tests with the race detector, then the complete
`scripts/run-ingest-queue-integration.sh` suite before deployment.
