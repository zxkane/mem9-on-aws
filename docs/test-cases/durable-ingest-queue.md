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
| TC-INGEST-QUEUE-031 | IaC task definition for prod or preview | CI explicitly supplies `MNEMO_DURABLE_INGEST_ENABLED=1`; local synthesis still fails closed to `0` unless explicitly enabled |
| TC-INGEST-QUEUE-032 | Inspect production worker wiring | The immutable-plan atomic processor is injected; enabling without PostgreSQL or tenant identity fails startup |

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
| TC-INGEST-QUEUE-044 | Worker is disabled or has no atomic processor | It makes no claims; production injects the reviewed atomic processor and never invokes the existing non-atomic reconcile path |
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
- Root and infrastructure Vitest suites pin migration contents, atomic worker
  wiring, Gateway status behavior, and enabled ECS configuration.

## Durable Ingest Telemetry

Design:
[`docs/designs/durable-ingest-telemetry.md`](../designs/durable-ingest-telemetry.md)

| ID | Scenario | Expected |
|---|---|---|
| TC-INGEST-METRIC-001 | A new asynchronous job commits | `JobsAccepted=1` with only stage and bounded result dimensions |
| TC-INGEST-METRIC-002 | An idempotent duplicate returns the existing job | No second accepted-job metric is emitted |
| TC-INGEST-METRIC-003 | First claim occurs at, before, and after the acceptance timestamp | `QueueWaitMs` is zero at/before the boundary and exact after it; later attempts do not re-emit initial queue wait |
| TC-INGEST-METRIC-004 | Planning loads, builds, saves, or rebuilds a plan | `PlanDurationMs` is application elapsed time around those operations and is never emitted in `AWS/BedrockMantle` |
| TC-INGEST-METRIC-005 | Atomic apply succeeds, conflicts, or fails | `ApplyDurationMs` includes every apply attempt and excludes post-commit effects |
| TC-INGEST-METRIC-006 | A claimed attempt commits retry, success, or dead | `TotalProcessingDurationMs` spans claim to the committed durable result and clamps negative clock movement to zero |
| TC-INGEST-METRIC-007 | Attempts one through four fail transiently | `JobsRetrying`, retry ordinal, duration, and the agreed bounded error class are emitted |
| TC-INGEST-METRIC-008 | A permanent failure, fifth-attempt transient failure, or exhausted lease becomes dead | Detailed `JobsDead` with bounded result/error dimensions, its stage-only alarm rollup, `JobsTerminated`, and retry count are emitted once |
| TC-INGEST-METRIC-009 | Atomic apply commits successfully | `JobsSucceeded` and `JobsTerminated` are emitted once with result `succeeded` |
| TC-INGEST-METRIC-010 | Smart extraction returns zero facts and apply succeeds | `ZeroFactSuccess=1`; a nonzero-fact no-op reconciliation does not increment it |
| TC-INGEST-METRIC-011 | Extraction truncates facts or planning records warnings | Exact `TruncatedFacts` and `Warnings` values are emitted on success |
| TC-INGEST-METRIC-012 | Queue contains queued/retrying rows, is empty, or its age query stalls | Database-clock `OldestQueuedAgeMs` reports the oldest age or zero without tenant dimensions; a bounded asynchronous sample cannot block claims |
| TC-INGEST-METRIC-013 | Proxy and worker errors cover every agreed class plus an unknown value | GLM/worker classes are preserved and unknown input normalizes to `other` |
| TC-INGEST-METRIC-014 | EMF fixtures carry marker values in tenant, agent, app, session, job, request, payload hash, message, fact, and embedding fields | Metric/log output contains none of the markers and dimensions remain low-cardinality |
| TC-INGEST-METRIC-015 | Production dashboard is synthesized | Provider and durable-application headings are separate; Mantle widgets use `AWS/BedrockMantle` plus `Project`; no Mantle latency metric appears; retry volume uses the additive stage-only `JobsRetrying` rollup, never a search gap or sum of retry ordinals |
| TC-INGEST-METRIC-016 | Dead-job and queue-age alarms are synthesized | Dead consumes the stage-only `JobsDead` rollup and alarms at least once in 15 minutes; queue age is greater than 10 minutes for two consecutive five-minute periods |
| TC-INGEST-METRIC-017 | Failure-ratio fixtures contain 19, 20, or more terminal jobs | The expression returns zero below 20 and alarms at or above 10 percent only from 20 onward |
| TC-INGEST-METRIC-018 | Alarm input data is absent | Every alarm explicitly uses `notBreaching`; absent queue-age data is not interpreted as proof that the age threshold was exceeded |
| TC-INGEST-METRIC-019 | Production alarms are synthesized | Every alarm action targets the existing topic; application alarms use `stage=prod` and Mantle client errors use the configured `Project` |
| TC-INGEST-METRIC-020 | Legacy observability resources are synthesized | The unalarmed `ingest_dropped` metric filter is absent |

## Atomic Plan And Apply

Design: [`docs/designs/atomic-ingest-apply.md`](../designs/atomic-ingest-apply.md)

| ID | Scenario | Expected |
|---|---|---|
| TC-INGEST-ATOMIC-001 | Build a plan twice from identical extracted/reconcile results | Canonical action order and plan hash are identical |
| TC-INGEST-ATOMIC-002 | Build replacement plans after optimistic conflicts | Revisions increase monotonically and old plan payload/hash rows remain immutable |
| TC-INGEST-ATOMIC-003 | Generate ADD IDs for repeated and replacement revisions | IDs are stable for one `(job, revision, action index)` tuple and distinct across tuples |
| TC-INGEST-ATOMIC-004 | Reconcile emits actions in different model orders | Canonical sorting produces one action order and hash |
| TC-INGEST-ATOMIC-005 | UPDATE or DELETE has a stale expected version | The predicate changes zero rows, every earlier mutation rolls back, and the plan becomes stale only after rollback |
| TC-INGEST-ATOMIC-006 | UPDATE succeeds with the expected version | Content/tags/metadata/embedding change in place and the monotonic version increments exactly once |
| TC-INGEST-ATOMIC-007 | DELETE succeeds with the expected version | State becomes deleted and the monotonic version increments exactly once |
| TC-INGEST-ATOMIC-008 | Extraction returns 67 facts | The first 50 in model order are retained, `truncated_fact_count=17`, at most 50 actions apply, and the job succeeds with a truncation warning |
| TC-INGEST-ATOMIC-009 | Reconcile returns more than 50 valid actions | The canonical first 50 actions apply and excess action count is recorded as a warning |
| TC-INGEST-ATOMIC-010 | Worker recovers an applying job with a valid persisted plan | No extraction, LLM, existing-memory read, or embedding call repeats; the same plan is applied |
| TC-INGEST-ATOMIC-011 | Persisted plan hash or envelope is invalid | The plan is not applied and a new immutable revision is built under the active lease |
| TC-INGEST-ATOMIC-012 | Four consecutive version conflicts occur in one full-job attempt | At most three new revisions are persisted; the attempt leaves via bounded transient retry |
| TC-INGEST-ATOMIC-013 | Plan save uses a wrong tenant, owner, generation, state, or expired lease | No plan row or active-plan pointer is persisted |
| TC-INGEST-ATOMIC-014 | Final apply loses tenant, owner, generation, eligible state, active plan, or lease predicate | The entire transaction rolls back |
| TC-INGEST-ATOMIC-015 | Crash after enqueue commit | The durable job remains claimable and no raw-session, tag, or memory mutation exists |
| TC-INGEST-ATOMIC-016 | Crash immediately after plan persistence | The valid plan remains reusable and no plan mutation exists |
| TC-INGEST-ATOMIC-017 | Crash immediately before apply | The valid plan remains reusable and no plan mutation exists |
| TC-INGEST-ATOMIC-018 | Crash/error after each raw-session, tag, or memory mutation | Every pre-commit mutation rolls back, including mutations earlier in the plan |
| TC-INGEST-ATOMIC-019 | Crash immediately before transaction commit | Every plan mutation and job completion rolls back |
| TC-INGEST-ATOMIC-020 | Commit succeeds but the client observes an ambiguous error/crash | Tenant-scoped reread sees `succeeded`; restart does not reapply or duplicate actions |
| TC-INGEST-ATOMIC-021 | Commit fails and reread sees a nonterminal job | No plan mutation committed and recovery safely retries |
| TC-INGEST-ATOMIC-022 | PostgreSQL injects `40P01`, transaction cancellation, or the 15-second deadline | The transaction rolls back and the worker classifies a retryable database outcome |
| TC-INGEST-ATOMIC-023 | Instrument extraction, reads, reconciliation, embeddings, webhook, and metering | Every observed network call occurs while the apply-transaction-open signal is false |
| TC-INGEST-ATOMIC-024 | Post-commit webhook or metering fails | A content-free outcome is logged and the committed job remains succeeded |
| TC-INGEST-ATOMIC-025 | Owning tenant requests an existing job status | HTTP 200 contains only job ID, state, attempts, warning/error class, and timestamps |
| TC-INGEST-ATOMIC-026 | A different authenticated tenant or an unknown ID requests status | HTTP 404 is returned with no existence or payload disclosure |
| TC-INGEST-ATOMIC-027 | Serialize a status row containing payload, plan, lease, runtime reservation, tenant, and credential markers | None of those fields or marker values appears in JSON |
| TC-INGEST-ATOMIC-028 | Gateway status tool is called with an owning job ID | Proxy sends a tenant-authenticated GET and returns the approved status fields |
| TC-INGEST-ATOMIC-029 | Gateway status tool input attempts to supply tenant/key/payload fields | Schema and proxy ignore/disallow them; only configured tenant auth is used |
| TC-INGEST-ATOMIC-030 | Gateway owning tenant requests an unknown or mismatched-tenant job | Not-found response is preserved without payload leakage |
| TC-INGEST-ATOMIC-031 | Production deployment is synthesized | The image applies the repeatable atomic migration before server startup and one rollout enables durable ingest with tenant identity and atomic worker wiring |
| TC-INGEST-ATOMIC-032 | Asynchronous `messages[]` request is accepted with durable mode enabled | Enqueue commits and returns a job; no untracked ingest goroutine is launched |
| TC-INGEST-ATOMIC-033 | Worker process restarts before and after every apply boundary | Recovery reuses/replans safely and creates no duplicate fact/action |
| TC-INGEST-ATOMIC-034 | Apply raw sessions, message tags, mixed ADD/UPDATE/DELETE, and success | One commit contains all mutations and `succeeded`; observers never see a partial subset |
| TC-INGEST-ATOMIC-035 | Apply the atomic migration twice to empty and preceding schemas | Sessions, version backfill, plan history, constraints, and indexes converge idempotently |
| TC-INGEST-ATOMIC-036 | Runtime quota reservation succeeds before enqueue | Reservation correlation is persisted on the new job and is not finalized by the request handler |
| TC-INGEST-ATOMIC-037 | Durable job retries and then succeeds or becomes dead | Retry retains the reservation; success commits it after apply; committed terminal failure releases it |
| TC-INGEST-ATOMIC-038 | Duplicate enqueue creates a second runtime reservation | Existing job keeps its original reservation and the duplicate reservation is released |
| TC-INGEST-ATOMIC-039 | ECS deploys an enabled replacement | The live-image smoke uses the ECS `MEM9_DB_*` secret contract over TLS and verifies `ingest_jobs`, `ingest_job_plans`, and `sessions` exist before the server is healthy; CI performs exactly one enabled service rollout and then the complete bootstrap |
| TC-INGEST-ATOMIC-040 | Enqueue commits but the client observes a connection error | A fresh tenant/idempotency reread returns the committed job and the handler does not release its reservation |
| TC-INGEST-ATOMIC-041 | Enqueue commit outcome is unknown and the immediate reread returns no row or an error | The request fails closed without releasing the possibly committed reservation; retry or TTL expiry resolves it |
| TC-INGEST-ATOMIC-042 | Process exits after `succeeded` commits but before runtime finalization starts | The terminal job retains a `finalizing` intent and an expired lease is reclaimed without reapplying the plan |
| TC-INGEST-ATOMIC-043 | Process exits after a `dead` transition but before reservation release starts | The terminal job retains a `finalizing` intent and another worker performs the idempotent release handoff |
| TC-INGEST-ATOMIC-044 | Runtime finalization handoff succeeds and completion write commits | State becomes `completed`, terminal lease fields clear, and the job outcome remains unchanged |
| TC-INGEST-ATOMIC-045 | Runtime finalization callback or completion write fails | The finalization remains reclaimable under its expiring lease and no terminal business mutation is retried |
| TC-INGEST-ATOMIC-046 | Quota provider returns a reservation expiry | The manager propagates it and enqueue persists it with the operation correlation |
| TC-INGEST-ATOMIC-047 | A queued or retrying job's reservation cannot cover the full job deadline | The worker reserves and lease-fences a replacement before planning, then releases the superseded reservation |
| TC-INGEST-ATOMIC-048 | A recovered terminal job's reservation has expired | The worker refreshes correlation before the idempotent terminal handoff; no plan mutation is rerun |
| TC-INGEST-ATOMIC-049 | Process exits after runtime outbox handoff but before finalization completion | Replay uses the same operation ID, memory IDs, and stable job occurrence timestamp, so the outbox payload hash remains identical |
| TC-INGEST-ATOMIC-050 | Terminal release cannot reach either the runtime outbox or quota provider | The callback reports failure and the job remains `finalizing` for lease-based recovery |
| TC-INGEST-ATOMIC-051 | Replacement reservation persistence returns an ambiguous database error | The worker does not release the replacement; a committed replacement remains valid and an uncommitted one expires by provider TTL |
| TC-INGEST-ATOMIC-052 | A terminal lease is reclaimed by the same configured worker owner while its reservation is replaced | The reclaim rotates a claim-specific lease token; the stale callback is fenced and cannot complete the replacement |
| TC-INGEST-ATOMIC-053 | A job row has only one active-plan pointer or a runtime operation without a finalization state | Two-valued database checks reject every partial invariant even when nullable expressions would otherwise evaluate to `UNKNOWN` |
| TC-INGEST-ATOMIC-054 | The enabled replacement starts before PostgreSQL accepts connections | The bounded retry budget fits inside the ECS startup grace; CI pre-pulls PostgreSQL, starts it only after a failed migration attempt, rejects plaintext DB connections, and then requires TLS migration completion and server health |
