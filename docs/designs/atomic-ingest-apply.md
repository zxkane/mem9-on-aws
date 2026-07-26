# Design Canvas: atomic durable ingest apply

Feature: Immutable ingest plans, atomic PostgreSQL apply, and tenant-scoped status
Date: 2026-07-26
Status: Approved (autonomous mode)

## Problem

The durable queue foundation commits accepted transcript jobs before returning,
but it intentionally has no production processor. The existing smart-ingest
pipeline performs raw-session writes, tag patches, memory mutations, and
completion as independent operations. Reusing that path after a worker crash
could leave partial state or duplicate accepted facts.

## Boundaries

- This change completes only asynchronous `messages[]` ingest. Synchronous
  transcript ingest and explicit-content memory writes keep their current paths.
- PostgreSQL is the only enabled durable backend and its transaction commit is
  the exactly-once boundary. No operation ledger is added.
- Extraction, reconciliation, existing-memory reads, and embedding calls happen
  while no apply transaction is open.
- Raw-session writes are added to the PostgreSQL tenant schema because the
  upstream PostgreSQL session repository is currently a no-op.
- Space-chain transcript routing is rejected on the durable asynchronous path.
  The production Gateway uses the single tenant API key and is unaffected.
- Post-commit metering and webhook enqueue are best effort. Their failures are
  logged without message, fact, plan, tenant, or memory content and cannot
  change a succeeded job.

## Schema

`ingest_jobs` gains:

- `active_plan_revision` and `active_plan_hash`;
- `truncated_fact_count`;
- `warning_class`;
- nullable runtime-usage reservation correlation: `runtime_operation_id`,
  `runtime_cluster_id`, and `runtime_agent_name`;
- `runtime_reservation_expires_at`, copied from the quota provider;
- `runtime_finalization_state` (`reserved`, `finalizing`, or `completed`) so a
  terminal reservation callback remains recoverable after process failure.

`ingest_job_plans` is immutable plan history keyed by
`(tenant_id, job_id, plan_revision)`. It stores the canonical plan bytes, hash,
attempt generation, state (`valid`, `stale`, or `applied`), truncation count,
and timestamps. Payload/hash/revision are never updated. A conflict only changes
plan state to `stale`; the replacement is a new revision.

The migration also:

- creates PostgreSQL `sessions` with the same tenant/session/content-hash
  deduplication key used by upstream;
- adds/backfills `memories.version`, makes it positive and non-null, and keeps
  the default at 1;
- adds indexes needed by status and active-plan lookup.

All migration operations are repeatable on empty and previously bootstrapped
schemas.

## Plan Shape

An `ingest-plan-v1` document contains:

- job ID, tenant ID, revision, and source attempt generation;
- raw-session upserts and message-tag patches;
- at most 50 canonically ordered memory actions;
- each action's index, kind, target ID, expected version, complete materialized
  row values, and embedding;
- exact `truncated_fact_count`, warning count, and warning class;
- a lowercase SHA-256 hash over canonical JSON with the hash field omitted.

The first 50 extracted facts are retained in model order. Reconcile output is
normalized and ordered first by numeric source/model order, then by action kind,
target ID, normalized content, and scope fields before indexes are assigned.
Invalid, pinned-target, and excess actions become warnings rather than unbounded
mutations.

Memory ADD IDs are UUID-shaped values derived from SHA-256 of
`(job_id, plan_revision, action_index)`. The same revision always produces the
same ID; a replacement revision has a disjoint ID namespace.

## Worker Flow

```text
claim tenant job + lease generation
  -> refresh an expiring runtime reservation and persist its replacement
  -> transition processing -> planning
  -> load active valid plan
       valid hash: transition planning -> applying and reuse
       missing/invalid: build next immutable revision outside a transaction
  -> persist plan only with tenant/job/owner/generation/state/lease guard
  -> apply with a 15-second context:
       BEGIN READ COMMITTED
       lock and validate tenant/job/owner/generation/applying/lease/plan
       upsert every raw session
       patch every planned message tag set
       ADD/UPDATE/DELETE each ordered memory action
       UPDATE job -> succeeded with the same ownership predicates
       UPDATE plan -> applied
       COMMIT
  -> run best-effort post-commit effects
```

UPDATE and DELETE include `state = active AND version = expected_version`.
UPDATE increments `version`; DELETE changes state and increments `version`.
Any zero-row predicate result is an optimistic conflict. The whole transaction
rolls back, the owned plan is marked stale separately, and the worker builds the
next revision. A full-job attempt may create at most three revisions. Reaching
that bound becomes a transient retry outcome.

Claim recovery preserves a valid active plan. It does not clear plan fields.
The new lease generation may reuse the plan after validating its canonical hash.

When runtime usage is enabled, enqueue persists the reserved operation on the
job with finalization state `reserved`. Retry states retain it. A successful
atomic commit or committed `dead` transition changes the state to `finalizing`
while retaining the worker lease. The worker hands the idempotent callback to
the existing runtime-usage outbox, then marks the job `completed`. If the
process exits anywhere between terminal commit and completion, another worker
reclaims the expired terminal lease and repeats the handoff. A duplicate
enqueue releases only the duplicate request's new reservation and keeps the
existing job's reservation unchanged.

The runtime provider's `expiresAt` is retained on the job. Before planning, the
worker requires enough remaining validity to cover the full configured job
deadline plus a finalization buffer. Before a delayed terminal handoff it also
requires a bounded finalization window. An insufficient or unknown lifetime
causes a replacement reservation outside the apply transaction; the worker
persists the replacement under the active lease before releasing the previous
one. Provider denial is terminal for the attempt, while provider unavailability
is retryable. A fail-open replacement clears correlation and proceeds without a
terminal callback, matching the existing runtime-usage policy.

## Failure And Commit Semantics

- Mutation errors, optimistic conflicts, deadlocks, cancellation, and the
  15-second deadline return before commit and roll back every plan mutation.
- A commit error is ambiguous. The processor rereads the tenant-scoped job using
  a fresh bounded context. `succeeded` is success; any nonterminal state is safe
  to retry because the mutations and completion shared one transaction.
- An enqueue commit error is also reread by tenant and idempotency key using a
  fresh bounded context. A found row is accepted. If the reread itself fails,
  the handler leaves the reservation for durable recovery or TTL expiry instead
  of releasing a possibly committed job's reservation.
- A process crash before commit leaves no plan mutations. A crash after commit
  leaves all mutations and `succeeded`, so recovery exits without reapplying.
- Runtime reservation finalization remains independently reclaimable after the
  job reaches either terminal state; it never reopens or changes that outcome.
- The final job update repeats tenant, eligible state, lease owner, lease
  generation, active plan revision/hash, and unexpired lease predicates. Each
  terminal reclaim replaces the owner with a claim-specific token so a stale
  callback from the same ECS worker identity cannot complete a refreshed
  reservation.

## Tenant Binding And Status

Authenticated routes:

```text
GET /v1alpha2/mem9s/ingest-jobs/{jobID}
```

The handler constructs the repository only from the authenticated tenant ID and
resolved tenant database. Missing and cross-tenant IDs both return 404.

The JSON response allow-list is:

- `job_id`, `state`, `attempts`;
- optional `warning_class` and `error_class`;
- `created_at`, `updated_at`, and optional `completed_at`.

Canonical payloads, messages, facts, embeddings, plans, plan hashes/revisions,
lease data, runtime reservation correlation, credentials, tenant IDs, and scope
IDs are never serialized.

The AgentCore `get_ingest_job_status` tool accepts only `job_id`; the proxy
injects its configured tenant API key and does not accept a caller-supplied
tenant or credential.

## Production Wiring

The stable tenant identity is created independently of the bootstrap task so the
same Secrets Manager value can be injected into both bootstrap and
`mnemo-server`. When durable ingest is enabled, startup requires:

- PostgreSQL backend;
- the injected tenant ID;
- the atomic processor and worker wiring.

The `mnemo-server` image includes the repeatable atomic migration. Its
entrypoint applies that migration before starting the server or worker. The ECS
path passes discrete libpq connection variables so the credential-bearing DSN
stays out of process arguments, and retries transient connection failures with
a bounded timeout. CI performs one rollout with
`MNEMO_DURABLE_INGEST_ENABLED=1`; its live-image smoke exercises the same
secret-derived connection contract over TLS, verifies a delayed database is
retried, and requires the atomic relations before health can pass. CI then
reconciles the healthy replacement and runs the one-shot bootstrap for the
complete base schema and tenant seed. The worker uses the existing database
handle because this deployment's control and single tenant data plane
intentionally share the Aurora database.

## Privacy

Plans and payloads remain in the operator-owned Aurora database. Worker and
post-commit logs contain only job ID, state/outcome class, attempt/revision,
counts, and timing. No payload-derived metric labels are introduced.

## Rollback

Set `MNEMO_DURABLE_INGEST_ENABLED=0` and redeploy. Existing jobs and immutable
plans remain inert. The additive schema can stay in place; synchronous and
explicit-content paths do not depend on it.
