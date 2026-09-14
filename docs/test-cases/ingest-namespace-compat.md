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
