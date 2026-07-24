# Design Canvas: durable ingest queue foundation

Feature: Tenant-scoped Aurora ingest jobs
Date: 2026-07-24
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

The scope is `(tenant_id, agent_id, app_id, session_id)`. A candidate is
claimable only when no earlier nonterminal row exists in the same scope.
Therefore a delayed retry or active lease at the head blocks later overlapping
windows. `succeeded` and `dead` are terminal and unblock the next row.

Candidates are ordered by availability, creation time, and job ID. Concurrent
claimers lock one candidate through `FOR UPDATE SKIP LOCKED`; an atomic update
sets `processing`, increments the full-job attempt count, and records the lease
owner/expiry. Different scopes remain independently claimable.

An expired scope head already at five attempts is locked and moved to `dead`
before selecting another candidate. It therefore cannot remain nonterminal and
block its scope forever after a worker crash.

## Worker Contract

- Process-wide semaphore shared by all worker instances: 2 jobs.
- Lease: 90 seconds.
- Heartbeat: every 30 seconds, extending the lease.
- Full-job context: 10 minutes.
- Every heartbeat, transition, plan write, retry, and terminal write matches
  tenant, job ID, eligible current state, and lease owner.
- Shutdown stops claims, cancels active contexts, and leaves unfinished leased
  rows nonterminal. A later worker recovers them after lease expiry.
- Processor outcome classes `proxy_validation_permanent` and
  `mantle_4xx_permanent` are permanent. `mantle_transient` and `deadline` are
  transient. Unknown processor errors are permanent.
- At most five claimed full-job attempts. Transient failures before attempt 5
  enter `retry_wait`; attempt 5 becomes `dead`.
- Retry delay is full jitter from zero through
  `min(5s * 2^(attempt-1), 5m)`.

The persisted plan is opaque canonical JSON for a later atomic-apply change.
This issue supplies no production processor and does not call
`IngestService.Ingest`, extraction, reconciliation, or memory repositories from
the worker.

## Schema

`ingest_jobs` stores:

- job ID, tenant-scoped idempotency key, exact canonical payload;
- tenant/agent/app/session scope and effective mode/settings;
- lifecycle state, attempts, availability, lease owner/expiry, heartbeat;
- opaque plan, plan/apply/total warning counters, error class;
- created, updated, and completed timestamps.

Migrations use `IF NOT EXISTS` plus guarded constraints and indexes so they are
repeatable on empty and previously bootstrapped tenant schemas.

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
