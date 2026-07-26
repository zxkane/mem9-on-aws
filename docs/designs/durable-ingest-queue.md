# Design Canvas: durable ingest queue foundation

Feature: Tenant-scoped Aurora ingest jobs
Date: 2026-07-25
Status: Approved (autonomous mode)

## Problem

Asynchronous message ingest currently returns HTTP 202 before an in-process
goroutine runs extraction and reconciliation. A task restart can lose accepted
work. The durable foundation must record accepted work in the authenticated
tenant database without enabling the existing non-atomic reconcile path.

## Boundaries

- Aurora PostgreSQL is the queue and state store.
- Each request uses the `TenantDB` already resolved by authentication. The
  authenticated `tenant_id` remains distinct from the business `app_id`.
- Only asynchronous `messages[]` ingest is eligible. Synchronous ingest and
  explicit-content writes retain current behavior.
- `MNEMO_DURABLE_INGEST_ENABLED` gates both durable routing and worker execution.
  Its code default and deployed value are false.
- The worker accepts an injected plan/apply processor. Production does not wire
  the current reconcile service as that processor. The production entrypoint
  rejects an enabled flag until such a processor and worker are wired, so it
  cannot accept inert jobs or perform non-atomic memory mutation.

## Canonical Envelope

Defaults are resolved before canonicalization:

- `version`: `ingest-v1`
- `tenant_id`: authenticated tenant
- `agent_id`: request value or authenticated agent
- `app_id`: normalized request value or empty string
- `session_id`: request value or empty string
- `mode`: request value or configured ingest mode
- `disableSessionSave`: request/server effective value
- `messages`: input order, with each `seq` explicit; omitted sequence defaults
  to its zero-based input position
- `metadata`: parsed JSON, defaulting to an empty object

Credentials, headers, `sync`, request IDs, URLs, and other transport fields are
not accepted by the canonical builder. Plugin-injected memory context is removed
before canonicalization. Object keys are recursively sorted, array order is
preserved, finite JSON numbers are normalized as exact decimals without
float-rounding collisions, and invalid or out-of-range numbers are rejected.
The idempotency key is the lowercase SHA-256 hex digest of the UTF-8 canonical
bytes.

## Data Flow

```text
authenticated async messages request
  -> resolve agent/app/session/mode/defaults
  -> canonicalize ingest-v1 envelope and hash
  -> BEGIN
       acquire transaction-scoped advisory lock for the tenant/session scope
       reject canonical payloads larger than 1 MiB
       INSERT ingest_jobs
       ON CONFLICT (tenant_id, idempotency_key) return existing row
     COMMIT
  -> HTTP 202 {job_id, state}

tenant worker (only when explicitly enabled and given a processor)
  -> claim earliest eligible scope head with FOR UPDATE SKIP LOCKED
  -> processing (attempt + 1, 90-second lease)
  -> planning -> persist plan -> applying
  -> succeeded
       or transient -> retry_wait with full-jitter availability
       or permanent/exhausted -> dead
```

The handler does not hold work in memory after returning. A failed insert or
commit returns non-2xx.

## FIFO And Claiming

The scope is `(tenant_id, agent_id, app_id, session_id)`. Enqueue and claim use
the same transaction-scoped PostgreSQL advisory lock derived from that scope.
Enqueue acquires it before assigning database timestamps and inserting. Each
claim reads at most 32 candidate scopes without locking rows and advances a
process-local per-tenant cursor through a fixed high-water boundary. Repeated
bounded claims therefore wrap even while newer scopes keep arriving, and reach
eligible work behind a persistently contended page. Within the page, claim
attempts advisory locks with
`pg_try_advisory_xact_lock`. A contended scope is skipped rather than consuming a
worker slot. After a lock succeeds, claim re-reads the exact scope head and
applies `FOR UPDATE SKIP LOCKED` only to that row. A locked head cannot expose
its same-scope follower; claim continues to another scope in the page instead.
No claim path takes a row lock before an advisory lock. Enqueue, claim, and
owned writes explicitly request
`READ COMMITTED`, independent of the database or role default. A claim cannot
pass an invisible enqueue because that enqueue still owns the shared scope lock;
a later claim sees its committed row in a fresh snapshot.

The enqueue-side lock is intentional. Assigning `created_at` after acquiring it
makes accepted same-scope jobs follow the database serialization order and
prevents claim from passing an uncommitted enqueue. This adds request-path
contention for bursts in one session; replacing it requires an equivalent
database-enforced scope sequencer and is an enablement prerequisite, not a
reason to weaken FIFO. Claim holds the lock only for one head transition and
never reaps an unbounded series in one transaction. Claim-side advisory
acquisition is nonblocking, so a slow same-scope enqueue does not stall claims
for other sessions.

A candidate is claimable only when no earlier nonterminal row exists in the same
scope. Therefore a delayed retry or active lease at the head blocks later
overlapping windows. `succeeded` and `dead` are terminal and unblock the next
row. Advisory-lock hash collisions may serialize same-scope enqueues or cause a
claimer to temporarily skip an unrelated scope, but cannot relax ordering or
expose data. Because PostgreSQL advisory locks are scoped to one database,
separately resolved tenant databases cannot collide. If multiple tenant IDs
share one database, a 64-bit hash collision can affect an unrelated tenant's
progress; this is a liveness-only cross-tenant effect and must be revisited
before a shared-database multi-tenant rollout.

Candidates are ordered by creation time and job ID. Concurrent
claimers try candidate scope locks in that order. After locking one scope, the
claimer locks only its exact FIFO head; an atomic update sets `processing`,
increments the full-job attempt count, and records the lease owner/expiry. The
incremented `attempt_count` is also the lease generation. Every owned write
matches tenant, job, lease owner, eligible state, unexpired lease, and that
generation. A stale attempt is fenced even when a worker process reuses its
owner string after recovery. Different scopes remain independently claimable.

An expired scope head already at five attempts is locked and moved to `dead`.
That claim transaction then ends, bounding lock duration; the next claim can
select the newly unblocked head. It therefore cannot remain nonterminal and
block its scope forever after a worker crash.

## Worker Contract

- Process-wide semaphore shared by all worker instances: 2 jobs.
- Lease: 90 seconds.
- Heartbeat: every 30 seconds, extending the lease.
- Full-job context: 10 minutes.
- Claim eligibility, lease expiry, heartbeat extension, and retry availability
  are calculated from PostgreSQL's statement clock. Worker APIs pass durations,
  never absolute process timestamps.
- Lease validation and the guarded write both use `statement_timestamp()`.
  A lease expiring between the two statements fails closed as lease-lost.
- Owned writes first lock and validate the row, then calculate deadlines in a
  second database statement. Time spent waiting for the row lock cannot consume
  the new lease or retry duration.
- Every heartbeat, transition, plan write, retry, and terminal write matches
  tenant, job ID, eligible current state, lease owner, and lease generation.
- Shutdown stops claims, cancels active contexts, and leaves unfinished leased
  rows nonterminal. A later worker recovers them after lease expiry.
- Processor outcome classes `proxy_validation_permanent` and
  `mantle_4xx_permanent` are permanent. `mantle_transient` and `deadline` are
  transient. Unknown processor errors are permanent.
- At most five claimed full-job attempts. Transient failures before attempt 5
  enter `retry_wait`; attempt 5 becomes `dead`.
- Retry delay is full jitter from zero through
  `min(5s * 2^(attempt-1), 5m)`.
- PostgreSQL deadlock (`40P01`) and serialization (`40001`) claim failures are
  mapped by the PostgreSQL repository to a provider-neutral contention
  sentinel, logged without query or scope data, and retried immediately up to
  three times. Other claim failures, or persistent contention after that bound,
  retain the normal poll delay.

The persisted plan is opaque canonical JSON for a later atomic-apply change.
This issue supplies no production processor and does not call
`IngestService.Ingest`, extraction, reconciliation, or memory repositories from
the worker.

## Schema

Canonical envelopes are limited to 1,048,576 bytes before repository writes;
the database also enforces that bound. `ingest_jobs` stores:

- job ID, tenant-scoped idempotency key, exact canonical payload;
- tenant/agent/app/session scope and effective mode/settings;
- lifecycle state, attempts, availability, lease owner/expiry, heartbeat;
- opaque plan, plan/apply/total warning counters, error class;
- created, updated, and completed timestamps.

Migrations use `IF NOT EXISTS` plus guarded constraints and indexes so they are
repeatable on empty and previously bootstrapped tenant schemas. A row from a
pre-foundation schema receives `legacy:<job_id>` as its migration-only
idempotency value. That reserved form is distinguishable from and cannot collide
with a 64-character canonical SHA-256 key. The migration also recognizes the
preceding foundation revision's deterministic synthetic 64-hex value, rewrites
it to the reserved form, and replaces that revision's length-only constraint.
The 1 MiB database check is added `NOT VALID`, so a payload accepted by the
preceding schema is preserved while every new or changed row is constrained.
Clean schemas validate the check immediately.

## Deferred Enablement Responsibilities

The durable route returns after enqueue and therefore does not run upstream
runtime-usage leasing/metering or memory-added webhooks. This is inert in the
current deployment because durable routing is disabled and runtime-usage
metering is not configured. Atomic apply must define transactional mutation,
metering finalization, and webhook emission semantics before the flag can be
enabled; the foundation must not silently omit those side effects.

## Privacy

Payloads and plans remain inside Aurora. Queue logs contain only generated job
ID, state/outcome class, attempt, and timing. They never contain tenant IDs,
scope identifiers, messages, metadata, credentials, payloads, or plans. No
payload-derived metric labels are introduced.

## Rollback

Keep `MNEMO_DURABLE_INGEST_ENABLED=0` or revert the handler/config patch. The
production entrypoint also rejects `1` until atomic worker wiring exists.
Existing rows are inert and do not alter the current ingest path. The additive
table and indexes may remain without affecting runtime behavior.
