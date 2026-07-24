# Test cases: durable ingest queue foundation

Design: [`docs/designs/durable-ingest-queue.md`](../designs/durable-ingest-queue.md)

## Canonicalization

| ID | Scenario | Expected |
|---|---|---|
| TC-INGEST-QUEUE-001 | Same semantic metadata with different object-key order | Canonical bytes and SHA-256 hash are identical |
| TC-INGEST-QUEUE-002 | Nested metadata objects and arrays | Object keys sort recursively while array order is preserved |
| TC-INGEST-QUEUE-003 | Equivalent JSON number spellings | Numbers normalize to identical canonical bytes and hash |
| TC-INGEST-QUEUE-004 | Invalid, out-of-range, or precision-sensitive numeric metadata | Invalid/out-of-range values are rejected and distinct exact integers never collide |
| TC-INGEST-QUEUE-005 | Omitted mode, IDs, sequence, metadata, and session-save setting | Defaults are applied before hashing and every envelope field is explicit |
| TC-INGEST-QUEUE-006 | Message order or explicit sequence changes | Hash changes; overlapping nonidentical windows do not coalesce |
| TC-INGEST-QUEUE-007 | Authenticated tenant changes while app remains fixed | Hash changes and `tenant_id` remains separate from `app_id` |
| TC-INGEST-QUEUE-008 | Business app changes while tenant remains fixed | Hash changes |
| TC-INGEST-QUEUE-009 | Transport fields, credentials, headers, and request IDs differ | Canonical bytes and hash are unchanged because those fields are excluded |
| TC-INGEST-QUEUE-010 | Effective `disableSessionSave`, mode, role, content, or session changes | Hash changes |

## Repository And Migration

| ID | Scenario | Expected |
|---|---|---|
| TC-INGEST-QUEUE-011 | Apply migration twice to an empty PostgreSQL schema | Both applications succeed and all columns, constraints, and indexes exist |
| TC-INGEST-QUEUE-012 | Apply migration twice to a schema with a legacy minimal `ingest_jobs` table | Missing columns/indexes are added without destructive changes |
| TC-INGEST-QUEUE-013 | Enqueue one job | Transaction commits before `Enqueue` returns; row contains canonical payload, scope, state, counters, lease fields, and timestamps |
| TC-INGEST-QUEUE-014 | Concurrent identical enqueue calls in one tenant | Every caller receives one shared job ID and no duplicate row is created |
| TC-INGEST-QUEUE-015 | Same idempotency key in different tenants | Separate rows are returned and neither tenant can claim or update the other |
| TC-INGEST-QUEUE-016 | Semantically different requests in one scope | Distinct jobs are persisted; no window coalescing occurs |
| TC-INGEST-QUEUE-017 | Concurrent claimers race one queued job | Exactly one owner claims it and attempt count increments once |
| TC-INGEST-QUEUE-018 | Two queued jobs in one session plus one in another | Session head and cross-session job claim; later same-session job remains blocked |
| TC-INGEST-QUEUE-019 | Head job is `retry_wait` in the future or actively leased | Later jobs in that scope remain blocked |
| TC-INGEST-QUEUE-020 | Head becomes `succeeded` | Next same-scope job becomes claimable |
| TC-INGEST-QUEUE-021 | Poison head becomes `dead` | Next same-scope job becomes claimable |
| TC-INGEST-QUEUE-022 | Lease heartbeat uses matching tenant/job/owner | Lease extends; a wrong owner or tenant changes no row |
| TC-INGEST-QUEUE-023 | Processing lease expires | A new owner recovers the row with a new full-job attempt; an expired fifth attempt becomes `dead` |
| TC-INGEST-QUEUE-024 | State, plan, retry, or terminal update uses wrong owner/state/tenant | Update fails as lease-lost and persisted data is unchanged |

## Handler And Configuration

| ID | Scenario | Expected |
|---|---|---|
| TC-INGEST-QUEUE-025 | Durable route disabled | Existing asynchronous goroutine response and behavior remain unchanged |
| TC-INGEST-QUEUE-026 | Durable route enabled and enqueue commits | HTTP 202 contains `job_id` and current state only after repository return |
| TC-INGEST-QUEUE-027 | Durable enqueue returns an error or commit failure | Handler returns non-2xx and no success response |
| TC-INGEST-QUEUE-028 | Duplicate durable request | HTTP 202 returns the existing job ID and current state |
| TC-INGEST-QUEUE-029 | Two authenticated tenant DB handles | Each request constructs its repository from only its resolved `TenantDB` |
| TC-INGEST-QUEUE-030 | Application config has no durable-ingest environment variable | Durable routing and worker execution are false |
| TC-INGEST-QUEUE-031 | IaC task definition for prod or preview | `MNEMO_DURABLE_INGEST_ENABLED` is explicitly `0` in every stage |
| TC-INGEST-QUEUE-032 | Inspect production worker wiring | No processor adapter calls existing ingest/reconcile/memory mutation methods, and enabling without one fails startup |

## Worker, Retry, And Privacy

| ID | Scenario | Expected |
|---|---|---|
| TC-INGEST-QUEUE-033 | Worker config defaults | Disabled, concurrency 2, lease 90 seconds, heartbeat 30 seconds, full-job timeout 10 minutes |
| TC-INGEST-QUEUE-034 | Three claimable jobs across multiple worker instances | The process-wide semaphore permits at most two processors to overlap |
| TC-INGEST-QUEUE-035 | Plan/apply succeeds | States progress through processing/planning/applying/succeeded and plan/warning counters persist |
| TC-INGEST-QUEUE-036 | Proxy class is validation/permanent 4xx | Job becomes `dead` after one attempt |
| TC-INGEST-QUEUE-037 | Proxy class is transient/deadline on attempts 1-4 | Job enters `retry_wait` with jittered availability |
| TC-INGEST-QUEUE-038 | Transient failure reaches attempt 5 | Job becomes `dead`; no sixth full-job execution occurs |
| TC-INGEST-QUEUE-039 | Full-jitter boundary calculation | Attempt 1 caps at 5 seconds, exponential caps reach but never exceed 5 minutes, and random endpoints are exact |
| TC-INGEST-QUEUE-040 | Worker shutdown during active processor | Claims stop, active context is canceled, and unfinished row is not acknowledged |
| TC-INGEST-QUEUE-041 | New worker starts after shutdown lease expiry | Unfinished row is recovered and processed |
| TC-INGEST-QUEUE-042 | Heartbeat keeps a long-running job alive | Other claimers cannot recover it before heartbeat stops and lease expires |
| TC-INGEST-QUEUE-043 | Worker and repository errors include secret payload markers and tenant identifiers | Captured logs/metrics omit payload, plan, memory content, credentials, tenant, agent, app, and session identifiers |
| TC-INGEST-QUEUE-044 | Worker is disabled or has no atomic processor | It makes no claims; production rejects enabled startup and never invokes the existing non-atomic reconcile path |

## CI Evidence

- Go unit tests run while building the patched mnemo-server image.
- `scripts/run-ingest-queue-integration.sh` starts PostgreSQL, applies both
  migration scenarios, and runs concurrent repository/worker/handler tests.
- Root and infrastructure Vitest suites pin migration contents and the
  disabled-by-default ECS configuration.
