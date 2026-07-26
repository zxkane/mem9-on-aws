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
| TC-INGEST-QUEUE-045 | An earlier same-scope enqueue holds its transaction open while a later row is visible to a concurrent claim and the connection default is `REPEATABLE READ` | Claim explicitly uses `READ COMMITTED`, skips the contended scope without taking a row lock, and after commit claims only the earlier row; the later row remains queued |
| TC-INGEST-QUEUE-046 | A lease expires and the same worker owner recovers the job with a new attempt generation | Every stale-attempt heartbeat/state/plan/terminal write fails as lease-lost; only the recovered generation can write |
| TC-INGEST-QUEUE-047 | Worker and database clocks differ far in either direction | Claim eligibility, lease/heartbeat expiry, and retry availability remain anchored to PostgreSQL; repository calls pass durations only |
| TC-INGEST-QUEUE-048 | A heartbeat or retry write waits on the job row longer than its requested duration | The write locks and revalidates first, then derives its deadline from a fresh database statement; the persisted deadline is not already expired |
| TC-INGEST-QUEUE-049 | Multiple claimers race while an earlier same-scope enqueue holds the scope lock and a later row is visible | Claimers skip the contended scope without row locks or errors; after release exactly one claims the FIFO head |
| TC-INGEST-QUEUE-050 | A lease expires between owned-write validation and the guarded update | Guard and update both use the PostgreSQL statement clock; the update fails closed as lease-lost |
| TC-INGEST-QUEUE-051 | Same-scope enqueues race while another scope enqueues | Same-scope acceptance is serialized to establish FIFO timestamps; an unrelated scope remains independently enqueueable |
| TC-INGEST-QUEUE-052 | Claim returns PostgreSQL `40P01`, `40001`, or another repository error | The PostgreSQL repository maps contention states to a generic sentinel; the worker makes exactly three immediate retries with a payload-safe class, then polls normally |
| TC-INGEST-QUEUE-053 | Several expired fifth-attempt heads exist | One claim transaction terminalizes at most one exhausted head; later claims make bounded progress and unblock following jobs |
| TC-INGEST-QUEUE-054 | Canonical envelope is exactly 1 MiB or one byte larger | The boundary is accepted, the larger request is a permanent validation error, and no oversized repository row is written |
| TC-INGEST-QUEUE-055 | Apply the preceding foundation migration state, then the current migration twice and enqueue a real 64-hex key | The old synthetic hash and length-only constraint are replaced; `legacy:<job_id>` cannot shadow the canonical hash namespace |
| TC-INGEST-QUEUE-056 | Review enablement documentation | Cross-tenant advisory-collision liveness and deferred metering/webhook responsibilities are explicit prerequisites |
| TC-INGEST-QUEUE-057 | An owned write row-locks an expired scope head while its follower is queued | `FOR UPDATE SKIP LOCKED` targets only the exact head; claim returns no job and never skips to the follower |
| TC-INGEST-QUEUE-058 | The first candidate scope's advisory lock is held while another session is eligible | Claim uses bounded nonblocking scope-lock attempts and claims the unrelated session without consuming a slot waiting |
| TC-INGEST-QUEUE-059 | The first candidate scope's exact head is row-locked while another session is eligible | Claim does not skip to the same-scope follower, but continues the candidate page and claims the unrelated session |
| TC-INGEST-QUEUE-060 | Advisory locks hold the first 32 candidate scopes while scope 33 is eligible | Candidate pages rotate across bounded claim calls, so the later scope is claimed without waiting for the contended page |
| TC-INGEST-QUEUE-061 | New scopes arrive faster than bounded claim pages advance after an older page becomes uncontended | A fixed high-water sweep reaches its end and wraps, so sustained queue growth cannot starve the released older scope |
| TC-INGEST-QUEUE-062 | Upgrade a preceding schema containing a canonical payload larger than 1 MiB | Migration preserves the legacy row with a not-valid check, rejects every new oversized row, and validates the constraint on clean schemas |
| TC-INGEST-QUEUE-063 | Repository, worker, and handler PostgreSQL packages run in one default-parallel `go test` invocation against the same configured DSN | Every integration test uses an isolated database, no helper truncates shared state, and all packages pass without `-p 1` serialization |

## CI Evidence

- Go unit tests run while building the patched mnemo-server image.
- `scripts/run-ingest-queue-integration.sh` starts PostgreSQL, applies both
  migration scenarios, and runs repository/worker/handler integration packages
  together with Go's default package parallelism.
- Root and infrastructure Vitest suites pin migration contents and the
  disabled-by-default ECS configuration.
