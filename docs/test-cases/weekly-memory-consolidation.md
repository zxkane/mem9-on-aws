# Test Cases: weekly memory consolidation (issue #103)

Unit tests use mocked database, REST, LLM, and AWS resource constructors.
Preview E2E runs the deployed task in report-only mode.

## Continuous scheduling and preview rehearsal

## Runtime credential preparation

This increment exercises schema/runtime separation in numeric preview stages.
Production credential retirement and consolidation activation remain separate.

| Case | Scenario | Required result |
| --- | --- | --- |
| RUNTIME-001 | Apply production schema twice on fresh/existing databases | No runtime contract schema, role, tenant RLS or PUBLIC ACL changes |
| RUNTIME-002 | Start a preview without valid readiness | Missing digest, wrong login OID, incomplete namespace constraints or invalid indexes reject startup |
| RUNTIME-003 | Bootstrap and restart a normal preview | Server uses a non-owner login; only bootstrap can run DDL; normal MCP/ingest/JIT paths work |
| RUNTIME-004 | Exercise runtime privileges | DDL, role management, tenant credential writes, maintenance policy/table writes, owner-role assumption and grant options are denied |
| RUNTIME-005 | Write an owner credential into a tenant row | RLS hides it, readiness is invalidated, and a new privileged tenant pool is rejected |
| RUNTIME-006 | Repeat or race bootstrap | Stable credentials; one dedicated session owns a nonblocking lock; busy attempts cannot invalidate or stamp |
| RUNTIME-007 | Kill bootstrap during concurrent index creation | No readiness; retry repairs only known invalid indexes and verifies their complete definitions |
| RUNTIME-008 | Lose bootstrap launch response or cancel runner | Recorded task identity/deadline allows recovery; old service/bootstrap revisions are drained before initialization |
| RUNTIME-009 | Compare actual SST resource graphs | Production uses its existing path; preview starts with zero tasks, then resumes with runtime-only secret references |
| RUNTIME-010 | Inspect child arguments and logs | No plaintext password, verifier, API key or private row contents are emitted |
| RUNTIME-011 | Register the synthetic consolidation tenant | Exact owner-approved binding and row commit together; stale credentials are invisible; prior Scheduler/Qwen acceptance remains valid |
| RUNTIME-012 | Run all preview checks | Hard MCP search/ingest, namespace isolation/performance, OAuth/human and consolidation checks pass |
| RUNTIME-013 | Inspect running server task definitions and current IAM policies | Exact runtime secret references, verify mode, stable revision and reviewed task/execution grants are required; owner references, mixed revisions, extra grants and environment overrides fail acceptance |
| RUNTIME-014 | Run human OAuth target preflight with separated credentials | The application requires its exact runtime SSM reference and verify mode; the independently pinned owner secret is retained for fixtures. Owner-backed application references fail before credential reads, with bounded failure diagnostics |

## Continuous scheduling cases

These acceptance cases cover the next delivery. Production activation and
real-corpus semantic/drain calibration remain separate gates.

| Case | Scenario | Required result |
| --- | --- | --- |
| SCHED-001 | Synthesize production and numeric PR stages | Production creates no new continuous workers/credentials or enabled schedules; PR planner/executor schedules default DISABLED |
| SCHED-002 | Inspect Scheduler trust and invocation grants | Exact schedule-group/current-account trust; RunTask names exact scheduled revisions and PassRole names only their task/execution roles |
| SCHED-003 | Inspect worker roles and secret injection | Planner cannot read owner/executor/signing credentials; executor has no inference grant; replace SST's default wildcard secret-read inline policy with exact stage references |
| SCHED-004 | Acquire the same kind's dispatcher lease from concurrent real login sessions | One winner, bounded busy outcome for the other; session_user binding rejects wrong-kind and backend callers |
| SCHED-005 | Heartbeat, expiry, takeover and stale release | Fixed maximum job deadline cannot be extended; generations fence renew/release; old action/work receipts remain authoritative |
| SCHED-006 | Multiple namespaces, restart and one unauthorized target | Persistent rotation continues across tasks, authorized targets progress and no foreign memory access succeeds |
| SCHED-007 | Child exits, missing marker, deadline, signal and excessive output | Bounded parent/child termination and redacted counters; zero exit without an expected marker does not count as success |
| SCHED-008 | Replay preview fixture setup or detect mismatched ownership/credentials | Preserve recorded policies/counters/receipts; never drop a database, reset counters or rotate a live cached tenant implicitly |
| SCHED-009 | Preview seed login retirement and runtime DB privileges | Retired login cannot reconnect; workers cannot directly mutate memories or read the normal tenant; backend uses its dedicated fixture credential |
| SCHED-010 | Trigger one-time schedules derived from disabled recurring definitions | Real Scheduler deliveries create correlated current-revision tasks; no direct RunTask substitute or prior-run logs satisfy the gate |
| SCHED-011 | Observe planner handoff and executor batching | Baseline has zero new actions/receipts; scheduled planner queues new/cache-derived actions; a correlated executor reports more than one 100-row loop batch and more than 100 actual changed rows |
| SCHED-012 | Duplicate wake and deliberately exhausted namespace budget | Receipts/mutations occur once; subsequent tasks preserve used counters and expose budget_wait while other namespaces complete |
| SCHED-013 | Protected records, incompatible context and unclassified semantic conflicts | Protected/context-conflict cases remain unchanged/reviewed; model-disabled semantic conflicts remain explicitly deferred, never claimed as classified |
| SCHED-014 | Pre-verified synthetic semantic classification | Planner cache handoff precedes a new action; real backend/local Qwen computes the changed-content embedding and preserves facts/provenance |
| SCHED-015 | Finish or fail the rehearsal | Pause synthetic authoritative modes, remove temporary schedules, observe owned tasks quiescent, and confirm recurring schedules remain DISABLED; late delivery cannot mutate after pause |
| SCHED-016 | Inspect PostgreSQL credential handling and logs | Passwords are injected, role setup uses SCRAM verifiers and guarded parameter handling, unsafe statement/audit logging fails before credentials are submitted |

## Incremental planner and model admission cases

The planner increment keeps production activation closed. These cases cover
the next executable delivery, independently of later scheduling and calibration.

| Case | Scenario | Required result |
| --- | --- | --- |
| PLAN-001 | Install/replay migrations with existing namespaces and worker grants | No opt-in, policy, login, schedule or memory change; later scoped grants survive replay |
| PLAN-002 | Foreign namespace, unbound login, disabled capture or revoked viewer | Discovery, cache, admission and publication reject before reading protected inputs |
| PLAN-003 | More than one page of eligible neighbors, worker restart between pages | At most ten hydrated members; persisted cursor resumes with no lost overflow or reset of oldest age |
| PLAN-004 | Anchor/member changes during inference or continuation | Stale generation cannot publish; new work survives and restarts discovery |
| PLAN-005 | Late outbox commit and more reverse dependents than one page | Exact events remain until all dependent anchors are dirtied; no sequence watermark skips work |
| PLAN-006 | Repeat exact neighborhood with valid KEEP, REVIEW or MERGE | Reuse protected classification with zero provider calls and unchanged authoritative validation |
| PLAN-007 | Crash or response loss at publication/action handoff | Publication, action and cursor commit together or all roll back; receipt recovery never repeats the model |
| PLAN-008 | Missing/null-vector anchor, equal content with conflicting context, protected or oversized inputs | Deterministic safe handling; incompatible/oversized actions remain review or blocked, with no truncation |
| PLAN-009 | Concurrent workers, duplicate requests and fresh processes | Stage/namespace request and token reservations plus global slots remain within persisted policy |
| PLAN-010 | Timeout, crash, missing/excess usage, expired attempt and late settlement | Conservative maximum charge exactly once; unknown/contract breaker cannot be reset by restart or midnight |
| PLAN-011 | Policy lowering, pause, context change or membership revocation | No new provider dispatch under stale authority; used counters and outstanding reservations are retained |
| PLAN-012 | Truncated/invalid model JSON, subset IDs, override fields and unbounded result | Strict whole-neighborhood verdict only; no arbitrary replacement content or authority |
| PLAN-013 | Budget wait, failed model, fixed task deadline | Waits preserve age without burning attempts; actual failures are bounded; no new work after deadline |
| PLAN-014 | Malformed credentials, DB failure and private provider errors | CLI emits only bounded content-free counts/error classes, never secrets or memory payloads |
| PLAN-015 | Repeated paginated fingerprint audit and hard-deleted rows | Unchanged coverage causes no model work; changed/new/missing rows become durable work |
| PLAN-016 | Synthetic 17k corpus with planted pairs and a large component | Compare discovered work with ground truth, bounded hydration and restart coverage; do not claim calibrated production drain time |

Code-review regressions additionally cover same-policy embedding-context refresh;
reopening an oversized page after a real edit; large deterministic duplicates;
byte-bounded model paging without skipped neighbors; typed token bounds;
definitive dispatch rejection versus ambiguous connection loss; and unspent
reservation cancellation after revocation or expiry without releasing a
dispatched/unknown attempt. The production timing contract reserves 110 seconds
for the provider, 15 seconds for finishing, and 11 seconds for DB dispatch.

## Maintenance connectivity and failure delivery

- TC-CONSOL-103: the stage task security group permits only TCP 8080 from
  itself through a standalone rule. No CIDR or sidecar port is added; the
  separate proxy and Aurora rules retain their existing sources.
- TC-CONSOL-104: both task failure targets supply the CloudWatch Logs
  timestamp/message envelope. The message is valid JSON containing only the
  fixed event and stage, even if the source has no exit code or an unsafe
  stopped reason. Nonzero and absent exit codes match; zero and other task
  revisions do not. Verify the pattern with AWS TestEventPattern and delivery
  with a synthetic failed task after production deployment, while the weekly
  schedule remains paused. Alert resources are production-only.
- TC-CONSOL-105: apply failures preserve bounded operation and error class
  through both log boundaries, including nested connection timeouts. Arbitrary
  errors, URLs, identifiers, content and stack traces never survive formatting.
  Partial-write accounting, abort behavior and nonzero exit remain intact.
- TC-CONSOL-106: production report and apply runs check the signed REST read
  path before digest writes or corpus classification. An absent synthetic ID
  is healthy; transport and authorization failures abort without memory writes.
  Verify a health-only ECS probe fails before the network fix and succeeds
  afterward, then verify scoped synthetic writes and optimistic fences.


## Proposed continuous consolidation acceptance

These `TC-CONSOL-V2-*` cases specify the draft in
[the consolidation design](../designs/weekly-memory-consolidation.md). They are
implementation requirements, not claims that tests or production behavior already
exist. Existing legacy cases remain the current implementation contract.

The user confirmed the 24–72 hour target for the existing automatically eligible
backlog on 2026-09-28; cases requiring human judgment are excluded. Budgets and
concurrency still require calibration, and target confirmation is not evidence
of achieved throughput or production acceptance.

| ID | Scenario | Required result / evidence |
| --- | --- | --- |
| TC-CONSOL-V2-001 | A production-shaped 17k corpus produces roughly 2k automatic candidates | Real preview load replay drains all automatically eligible work inside the user-confirmed 24–72 hour target under calibrated budgets; report actual action/row costs and model calls |
| TC-CONSOL-V2-002 | A batch reaches 100 changed rows with more ready work | Worker starts another eligible batch in the same invocation; no weekly wait and no budget reset |
| TC-CONSOL-V2-003 | Restart after persisting only part of a classification pass | Previously committed classifications/actions survive and are not sent to the model again |
| TC-CONSOL-V2-004 | Repeated unchanged audit, including KEEP outcomes | Zero repeated model calls while exact inputs, policy and temporal validity remain valid |
| TC-CONSOL-V2-005 | New related memory arrives after an old KEEP result | Dirty-neighbor work invalidates the relevant window; the old KEEP never certifies the full namespace |
| TC-CONSOL-V2-006 | Staleness threshold passes without a row write | Due-time sweep reopens work independently of updated_at and outbox writes |
| TC-CONSOL-V2-007 | One transaction allocates an earlier outbox sequence but commits late | Its change is still consumed; a high-water cursor cannot skip it |
| TC-CONSOL-V2-008 | Generation G+1 arrives while G is being planned | Acknowledging G preserves G+1; repeat execution consumes the newest generation |
| TC-CONSOL-V2-009 | Direct SQL update, delete, state change, migration or backfill | Transactional capture or explicit reconciliation covers every path, including version-only changes |
| TC-CONSOL-V2-010 | A component exceeds the old cluster bound | Bounded paginated neighborhoods retain overflow and coverage; no permanent silent omission or false whole-component guarantee |
| TC-CONSOL-V2-011 | Two neighborhoods/actions overlap | Deterministic deduplication plus final all-member fences prevent conflicting double application |
| TC-CONSOL-V2-012 | Model output supplies foreign IDs, invalid graphs, confidence or budget overrides | Deterministic validation rejects authority fields and foreign scope; no memory mutation |
| TC-CONSOL-V2-013 | Survivor or any donor is edited during embedding | Entire atomic merge aborts; no survivor-only rewrite or lost donor edit; run with real PostgreSQL and concurrent ingest |
| TC-CONSOL-V2-014 | Membership/namespace/service is revoked or paused before commit | Transactional authorization blocks every memory write and receipt/budget completion |
| TC-CONSOL-V2-015 | Worker dies before commit | Transaction rolls back memories, receipt and spent budget together; reservation is recoverable |
| TC-CONSOL-V2-016 | Commit succeeds but HTTP response is lost | Retry reads the same receipt; no second embedding, mutation or budget charge |
| TC-CONSOL-V2-017 | Lease expires, another worker claims, old worker returns | Old generation cannot finalize or spend a released reservation |
| TC-CONSOL-V2-018 | Competing claims, commits and expiry recovery | Consistent lock order avoids deadlock; short transactions and real race tests prove accounting correctness |
| TC-CONSOL-V2-019 | Legacy cleanup holds the namespace mutex | New backend returns/requeues busy without holding a caller-side mutex or deadlocking itself |
| TC-CONSOL-V2-020 | Several workers, namespaces or duplicate Scheduler deliveries | Stage and namespace budgets remain exact; no multiplication per task or run ID |
| TC-CONSOL-V2-021 | Worst-case reservation exceeds actual changes because survivor is already complete | Settle actual row transitions and release the difference; merge count is not assumed to equal rewritten/deleted counts |
| TC-CONSOL-V2-022 | Budget window ends during preparation | Expired reservation cannot commit; reacquire under the next window and preserve idempotency |
| TC-CONSOL-V2-023 | Budget decreases or pause is committed while work is queued/preparing | No later uncommitted action bypasses the new policy; committed receipts remain counted |
| TC-CONSOL-V2-024 | One hot candidate repeatedly conflicts or one risk class dominates | Bounded retry and weighted fairness allow other candidates/namespaces to progress |
| TC-CONSOL-V2-025 | Model throttling, invalid response, timeout or verification failure | Bounded attempts; persisted retry/review reason; no mutation and no inference-budget reset |
| TC-CONSOL-V2-026 | Automatic DELETE or ambiguous contradiction is proposed | Remains manual review regardless of backlog age or larger execution budget |
| TC-CONSOL-V2-027 | Equal content has different material context, protection or provenance | Exact dedup does not erase those distinctions; incompatible actions are reviewed |
| TC-CONSOL-V2-028 | Semantic merge drops a qualifier, fact, timeline distinction or provenance | Preservation gate rejects it; evaluation and adversarial fixtures are required before budget promotion |
| TC-CONSOL-V2-029 | Merge requires new content embedding; metadata-only change does not | Atomic receipt agrees with committed content/vector/version; local embedding only; no opening 8081/8082 |
| TC-CONSOL-V2-030 | Undo after a later human or ingest edit | Conditional recovery refuses changed post-images; no blind restore; original receipt remains immutable |
| TC-CONSOL-V2-031 | Before-image exceeds bound or terminal payload reaches retention | No truncated recovery guarantee; oversize is review-only; expired IDs remain non-replayable without retaining unnecessary content |
| TC-CONSOL-V2-032 | Ready work waits behind budgets or a worker is idle | Distinct durable outcomes and age metrics; an increasing backlog cannot appear as healthy completed cleanup |
| TC-CONSOL-V2-033 | EMF or digest delivery fails after commit | DB receipt/budget is authoritative; notification retries never replay mutations |
| TC-CONSOL-V2-034 | Planner or executor attempts a disallowed database/API/inference operation | New restricted roles deny it; no shared owner credential is accepted as evidence of role isolation |
| TC-CONSOL-V2-035 | An old maintenance task image runs after v2 activation | Backend mode guard and removal of legacy owner-secret access block both legacy REST and direct SQL bypasses |
| TC-CONSOL-V2-036 | Roll back code or stop workers mid-run | New commits pause safely; no simultaneous legacy/v2 apply; plans/receipts survive and fences remain effective |
| TC-CONSOL-V2-037 | Maintenance runs alongside representative foreground recall/write traffic | Paired preview benchmark meets reviewed absolute deadlines and p95 regression allowance; overload pauses/reduces background work |
| TC-CONSOL-V2-038 | Logs, metrics, reports and public PR artifacts are collected | Only bounded counters/enums in ordinary output; content/IDs/credentials remain in authorized private storage |
| TC-CONSOL-V2-039 | Claim/audit/query table is added or changed | Reviewed SQL inventory includes every namespace predicate and bounded privileged operation; full PostgreSQL namespace rehearsal passes |
| TC-CONSOL-V2-040 | A budget-delayed unchanged plan needs periodic revalidation | Fresh policy/input/temporal checks can reuse its valid classification; changed/time-expired inputs require new planning and cannot inherit authority |
| TC-CONSOL-V2-041 | A model alternates paraphrases or an operator undoes/rejects a merge | Novel-donor/net-reduction and rewrite-generation fences stop churn; suppression blocks reapplication; undo advances versions |
| TC-CONSOL-V2-042 | Lock waits cross lease expiry or UTC midnight | Advancing-clock final authorization uses post-wait time; stale transaction-start clocks cannot authorize a write |
| TC-CONSOL-V2-043 | Response is lost during reservation or embedding, before a receipt | One active per-action preparation/reservation; duplicates report in-progress; generation-fenced recovery is bounded |
| TC-CONSOL-V2-044 | Old task caches owner credentials or retains SQL sessions through rollout | Pre-activation credential/session retirement blocks reconnect and existing-session writes; mode epoch serializes commits |
| TC-CONSOL-V2-045 | Tasks contend for model calls/tokens or apply-rate capacity | Durable admission includes all reservations and unknown outcomes; missing bounds block activation |
| TC-CONSOL-V2-046 | A merge arrives after another class borrowed capacity | Protected credits and next-window age priority give bounded service; spent loans are never fictitiously refunded |
| TC-CONSOL-V2-047 | Planner misses planted safe candidates or resets blocked ages | Coverage/drain targets fail against ground truth; no success by denominator shrinkage or relabeling |
| TC-CONSOL-V2-048 | An action exceeds an empty-window limit | Durable policy-blocked state exposes the missed target; other affordable work continues |

## Continuous consolidation storage foundation

The first implementation increment covers the durable planning foundation below.
The full v2 acceptance gates above remain pending until their complete scenarios
are implemented and exercised, including atomic apply and calibrated throughput.

| ID | Scenario | Required result / evidence |
| --- | --- | --- |
| TC-CONSOL-STORE-001 | Fresh and populated database; migration repeated with existing work | No memory/vector changes, state resets, or duplicate triggers; existing writes remain functional |
| TC-CONSOL-STORE-002 | Insert, version-only update, state update, hard delete, transaction rollback, namespace move | Committed changes captured without content or memory FK; rollback is invisible; both namespaces dirtied on move |
| TC-CONSOL-STORE-003 | Earlier event sequence commits after a later event is consumed | Late commit remains consumable; no high-water cursor loses it |
| TC-CONSOL-STORE-004 | New change arrives during a work lease; worker crashes or responds late | Desired generation survives acknowledgement; lease takeover increments token; stale completion rejected |
| TC-CONSOL-STORE-005 | Competing consumers/claimants and namespace membership revocation | No duplicated claim or lost event; unauthorized namespace returns no data; revocation serializes with authorized work |
| TC-CONSOL-STORE-006 | Planner inserts KEEP/review/MERGE classification then retries or alters payload | Exact retry reuses stored result; conflicting fingerprint is rejected; payload and member mapping immutable |
| TC-CONSOL-STORE-007 | Separate planner/executor connections attempt memory DML, raw reads, policy changes, or caller spoofing | Denied by database privileges and authenticated-login binding, including SET ROLE/application_name spoofing |
| TC-CONSOL-STORE-008 | Planner proposes authoritative fields, foreign/missing/changed members, DELETE, or malformed data | Storage validates a bounded exact member set, rejects authority fields, and creates no executable action |
| TC-CONSOL-STORE-009 | New model/policy context or due-time expiry | Replanning preserves unresolved age; unchanged valid KEEP reused; expired or different-context results cannot be reused |
| TC-CONSOL-STORE-010 | Baseline contains 17,236 synthetic active memories | All anchors become pending without memory changes; multiple 100-row planning batches proceed; record baseline/capture timing without claiming the full drain SLO |

## Atomic execution and persisted budgets

These execution cases complement the storage foundation. Deployment does not
enable execution: policy configuration, restricted login binding and the later
credential-cutover/quality gates remain explicit prerequisites.

| ID | Scenario | Required result / evidence |
| --- | --- | --- |
| TC-CONSOL-EXEC-001 | Additive migration repeats while legacy behavior is enabled | Execution stays disabled, no memory changes, no policy/counter/receipt reset |
| TC-CONSOL-EXEC-002 | Authenticated planner queues an immutable MERGE classification | Costs and lossless output are derived by storage; unsupported/protected/context-conflicting inputs become durable review |
| TC-CONSOL-EXEC-003 | Several executor logins claim work with shared stage/namespace budgets | Reservation is atomic, one current lease per action; task restarts cannot multiply limits |
| TC-CONSOL-EXEC-004 | Backend commits a prepared merge | Survivor, donor states, embedding, receipt, snapshots and budget settlement commit together |
| TC-CONSOL-EXEC-005 | Any participant changes after planning or during embedding | Whole operation invalidates without partial memory changes; reservation is released |
| TC-CONSOL-EXEC-006 | Commit succeeds but response is lost | Same action returns its receipt, without embedding again or charging twice |
| TC-CONSOL-EXEC-007 | Old worker finishes after lease takeover or preparation recovery | Generation/nonce checks reject the stale completion and prevent double reservations |
| TC-CONSOL-EXEC-008 | Locks cross lease expiry or UTC midnight | Advancing database time sampled after locks rejects old authorization windows |
| TC-CONSOL-EXEC-009 | Policy is paused/lowered or service membership revoked during preparation | Final transaction rechecks policy epochs and authorization; no later stale commit |
| TC-CONSOL-EXEC-010 | An action cannot fit a configured empty window | Durable policy-blocked reason remains visible; affordable work can proceed |
| TC-CONSOL-EXEC-011 | Prepared actions contend for apply-rate capacity | Persisted stage/namespace buckets bound commits; retry reuses preparation without a new embedding |
| TC-CONSOL-EXEC-012 | Operator requests undo, with or without a later user edit | Exact post-image fences; versions advance, original receipt remains, replay is suppressed |
| TC-CONSOL-EXEC-013 | Caller injects plan/budget/vector fields or uses human/analysis/cleanup transport | Private apply/status routes reject it; request carries only the action and lease generation |
| TC-CONSOL-EXEC-014 | HTTP request disconnects while maintenance embedding is running | Sidecar holds admission until actual inference completes; concurrent maintenance is refused |
| TC-CONSOL-EXEC-015 | ARCHIVE or STALE is eligible | Archive fences both timeline participants; stale marking preserves content/vector and settles actual rows |
| TC-CONSOL-EXEC-016 | Planner/executor attempts direct action, budget, receipt or undo manipulation | Database privileges deny it; backend/operator capabilities are separately bound to authenticated logins |
| TC-CONSOL-EXEC-017 | Real PostgreSQL HTTP tests and existing namespace/ingest/rollback suites run | New route works through signed service authorization without changing legacy/public API behavior |
| TC-CONSOL-EXEC-018 | CLI configuration, credential JSON or database connection fails | Actual subprocess stdout/stderr contain only the bounded error record; generated credential markers never appear |

## Model action contract

- Existing routing regressions must continue to quarantine all overlapping
  actions, including a `KEEP` that overlaps a `MERGE`, and reject unknown IDs.
- A live synthetic model probe uses only fictional, namespace-scoped memories
  and the configured Bedrock route. Verify that returned IDs come from the input,
  no ID belongs to multiple actions, and survivor/winner references belong to
  their action. The probe performs no database or memory writes.
- Synthetic samples are a smoke check, not proof of full-corpus quality. A
  complete report-only run and the existing health assessment remain required
  before automatic writes are reconsidered.

## Execution budget and progress

Diagnostics regressions run in `scripts/consolidation-progress.test.mjs` and
`scripts/dispatch-memory-consolidation.test.mjs`:

- TC-CONSOL-091: a classification request or response-parse failure emits one
  structured failure with a bounded error class and cluster count through both
  log formatters; review routing, exit status, and mutation behavior stay intact.
- TC-CONSOL-092: known review kinds, digest statuses, and error classes survive
  child and parent formatting, including child stdout/stderr forwarding.
- TC-CONSOL-093: unknown enums, invalid scalar types, and private extra fields
  are dropped at both boundaries; counts remain nonnegative safe integers.
- TC-CONSOL-101: after a scheduled apply, digest refresh queries only the
  deduplicated review IDs with a namespace-scoped `id/content` projection. It
  must not reparse the corpus embeddings; rows no longer active remain missing,
  while a query failure degrades the digest rather than becoming a missing row.
- TC-CONSOL-102: a child-reported failure and a child process that exits by
  signal both produce a content-free parent terminal outcome. It contains only
  fixed event, phase, disposition, exit-code/signal-presence, and error-class
  fields; it never contains error text, memory IDs, content, credentials, or
  stack data.

| ID | Scenario | Expected result |
| --- | --- | --- |
| TC-CONSOL-085 | A child takes longer than 30 minutes and completes within the default two-hour budget | It exits normally; progress never resets its fixed deadline |
| TC-CONSOL-086 | An execution budget is malformed, outside 60..21,600 seconds, or explicitly empty | Refuse before spawn; a valid override gets its exact deadline and TERM/KILL/close handling |
| TC-CONSOL-087 | A child is computing or awaiting a model | Parent heartbeat continues with bounded elapsed/since-progress fields; no namespace, credentials, or content is emitted |
| TC-CONSOL-088 | A phase completes, a classification advances, or work throws | Phase/count/duration events remain allowlisted, rate-limited, and truthful; errors do not create success events |
| TC-CONSOL-089 | A single-namespace report is launched while scheduled targets are configured | Only its explicit namespace runs through the shared watchdog, with report-only/model-smoke flags preserved |
| TC-CONSOL-090 | A model or SQL operation spans a phase boundary | Progress adds no authorization grant, transaction lifetime, mutation, digest write, or metric dimension |

## Consolidation Logic

| ID | Scenario | Expected result |
|---|---|---|
| TC-CONSOL-001 | Active memories include two similarity groups and one recent singleton | Cosine-connected components are deterministic; the recent singleton is not sent for staleness evaluation |
| TC-CONSOL-002 | An old environment/config singleton meets its age rule | It is included as a one-item staleness cluster |
| TC-CONSOL-003 | LLM returns malformed JSON, unknown ids, conflicting actions, or an oversized cluster | The affected cluster is skipped/reviewed with no mutation; a total classifier outage exits nonzero |
| TC-CONSOL-004 | LLM returns DELETE with high confidence and an `auto_execute` hint | DELETE appears only in the review list and never in the auto-execute list |
| TC-CONSOL-005 | LLM returns contradiction without a winner or with equal timestamps | Both ids and bounded snippets are review-only |
| TC-CONSOL-006 | LLM returns a contradiction whose winner is strictly newer by both creation and update time, with no prior consolidation stale marker on either side | The loser is archived with `superseded_by` only while both timeline sides still match the scan; no delete API is called |
| TC-CONSOL-007 | LLM returns a valid same-topic MERGE | The cleanup MERGE contract PUTs the survivor before soft-deleting version/content-unchanged absorbed fragments |
| TC-CONSOL-008 | LLM returns STALE for a memory | Only a memory satisfying its type-specific age threshold is eligible; existing tags/metadata are preserved and a bounded stale marker is PUT |
| TC-CONSOL-009 | An auto action or either side of an archive pair changes after scan | LWW fencing skips it and increments `ConsolidationSkippedLww` |
| TC-CONSOL-010 | Auto actions would cost 21 mutations | At most 20 mutations execute; the overflow action is review-deferred before its first write |
| TC-CONSOL-011 | Report-only run has MERGE/archive/stale decisions | No REST, SQL mutation, mutex, or SNS publish occurs |
| TC-CONSOL-012 | Review records are emitted | Each has kind, ids, snippets, and rationale; the list summary is always emitted |
| TC-CONSOL-013 | Run completes with mixed outcomes | EMF uses namespace `mem9-on-aws`, only the `stage` dimension, and the seven documented metric names |
| TC-CONSOL-014 | Manual cleanup and consolidation attempt apply concurrently | The shared PostgreSQL advisory mutex admits one holder and the other exits without mutation |
| TC-CONSOL-015 | SNS review summary is published | Payload contains counts/stage only and no ids, snippets, rationale, content, embeddings, or tenant key |
| TC-CONSOL-016 | Production adapters are exercised with fake DB/REST/Mantle/SNS clients | TLS DB config, bearer refresh, mutex/archive SQL, REST LWW headers, redacted SNS payload, and shutdown are verified |
| TC-CONSOL-077 | Exercise the production weekly Slack digest adapter with absent, partial, successful, and API-rejected configuration | No configuration is a silent no-op; partial configuration fails before fetch; success posts one bearer-authenticated `chat.postMessage` request with the configured channel; HTTP 200 with `ok: false` fails with the Slack error |
| TC-CONSOL-017 | A mutation throws after an earlier mutation succeeded | The run exits nonzero after releasing the mutex, emits the complete review list and EMF with applied counts, and routes the failed action to review |
| TC-CONSOL-018 | A stale candidate already has 20 non-stale tags | No write or stale metric is emitted; the item is review-only with `TAG_LIMIT_REACHED` |
| TC-CONSOL-019 | Active rows include `session` memories | Session rows are excluded from clustering, model input, mutation routing, and the scanned metric |
| TC-CONSOL-043 | The model-selected contradiction winner has a later `updated_at` but an earlier `created_at` | The contradictory chronology is review-only and no archive action is emitted |
| TC-CONSOL-044 | A contradiction side has a prior consolidation stale marker that bumped `updated_at` | The pair is review-only and no archive action is emitted |
| TC-CONSOL-038 | An ingest write lands between the MERGE survivor's guard read and its rewrite (issue #128) | The `If-Match` fence rejects the rewrite with 412: the concurrent content survives, no absorbed id is deleted, `ConsolidationSkippedLww` increments, `mutations` stays 0, and the run exits 0 without an `APPLY_FAILED` review. The fake `putMemory` enforces the version predicate — accepting a stale version would make the case vacuous |
| TC-CONSOL-039 | A MERGE survivor is rewritten with no concurrent write | `putMemory` is called with the observed version so the server can fence it, and with `content` in the body — a content-bearing PUT is the precondition for upstream re-embedding, so the survivor's embedding matches its merged content. The dep fake cannot observe an embedding; the re-embed itself is pinned server-side by the patch's `TestUpdateAcceptedByIfMatchStillReEmbedsTheNewContent` |
| TC-CONSOL-050 | An active memory carries a `version` that cannot be fenced (`null`, `0`, or a string) and the model returns a MERGE for it | The action is routed to `UNFENCEABLE_MERGE` review and never auto-applied, on either the survivor or an absorbed side. Omitting `If-Match` would drop upstream back to last-writer-wins, reintroducing issue #128's silent overwrite — and it would slip the client's own guard too, since `current.version !== action.version` is false when both are null. Defense in depth: this repo's bootstrap hardens the column to `NOT NULL` + `CHECK (version > 0)` and every upstream insert hardcodes `Version: 1` — verified against a real bootstrap, the check rejects even a hand-run `SET version = 0` — so such a row implies a partial migration or a dropped constraint. The guard still earns its keep because this task reads `version` with direct SQL, where node-pg surfaces NULL as `null` and nothing upstream fails loud first. A well-formed version still auto-merges |
| TC-CONSOL-049 | The **production** REST adapter (via `createProductionDeps`, not the dep fake) receives 412 | A versioned `putMemory` resolves to `null` so the caller skips; an unversioned write and `deleteMemories` still throw on 412, since a request with no precondition has none to lose. Covers the adapter half of the fence — the half the unattended weekly task depends on, which TC-CONSOL-038 cannot reach because its fake replaces the dep |
| TC-CONSOL-051 | Production emits the content-free metric record | `runConsolidation` routes it through a dedicated metrics dependency, and the production dependency writes exactly one JSON object followed by one LF with `stdout.write`; it does not use the ordinary `console.log` path or append CR. CloudWatch EMF requires no data before or after the root JSON object, and a production log event ending in CR produced no `Consolidation*` metric series |
| TC-CONSOL-052 | Classify every current review kind plus an unknown kind | DELETE and ambiguous CONTRADICTION are `OPERATOR_DECISION`; CAP_DEFERRED, LOCK_HELD, CLUSTER_TOO_LARGE, and TAG_LIMIT_REACHED are `DEFERRED_RETRY`; APPLY_FAILED, UNFENCEABLE_MERGE, CLASSIFICATION_FAILED, UNKNOWN_ID, CONFLICTING_ACTION, INVALID_MERGE, INVALID_STALE, INELIGIBLE_STALE, and unknown kinds are `SYSTEM_HEALTH`; `REPORT_ONLY_*` is excluded |
| TC-CONSOL-053 | A mutation fails with later auto actions still queued | One `APPLY_FAILED` record carries `abortedCount`; no per-action `APPLY_ABORTED` record is emitted |
| TC-CONSOL-054 | Build topic identity from reordered, duplicated ids and changed rationale/version/snippet fields | Topic id remains stable because it uses only schema version, kind, and sorted unique ids |
| TC-CONSOL-055 | Recompute a topic after content and metadata/version changes | Content changes alter the payload hash and classify `updated`; metadata/version-only changes keep the payload hash and classify `continuing` |
| TC-CONSOL-056 | Compare current topics with a previous snapshot | Topics classify deterministically as `new`, `updated`, `continuing`, and `resolved` |
| TC-CONSOL-057 | Run four consecutive scheduled snapshots with only continuing topics | The first three digests are suppressed; the fourth is a reminder; any new, updated, or resolved topic resets the unchanged counter |
| TC-CONSOL-058 | More than ten disposition/kind groups and more than three current records per group | Slack output contains at most ten groups and three bounded samples per group, with no action blocks or bulk controls |
| TC-CONSOL-059 | A newly observed CLUSTER_TOO_LARGE group ranks below ten other groups | The oversized-cluster group remains visible in that run |
| TC-CONSOL-060 | Evaluate health thresholds at their boundaries | APPLY_FAILED, UNFENCEABLE_MERGE, and unknown kinds alarm immediately; classification failures alarm at 10 or 20%; other system-health kinds alarm at 10 or on a consecutive run; selected deferred kinds alarm on a consecutive run; oversized affected memories alarm at 20% of scanned |
| TC-CONSOL-061 | Scheduled apply succeeds with Slack/SNS/state enabled | Required Slack and SNS notifications complete before the conditional state write |
| TC-CONSOL-062 | Slack or SNS delivery fails after confirmed mutations | The run exits nonzero, state is not committed, and confirmed mutation totals remain unchanged |
| TC-CONSOL-063 | State read is missing, denied, or otherwise fails before an ETag is available | Missing state is a valid first run; failed reads emit `dedup_unavailable`, claim neither `new` nor `resolved`, send degraded configured notifications, and may attempt only `If-None-Match: *` so a missing key is initialized while an existing unreadable snapshot cannot be overwritten |
| TC-CONSOL-064 | First snapshot, matching-ETag update, stale ETag, and generic S3 write failure | First write uses `IfNoneMatch: "*"`, updates use the read ETag in `IfMatch`, every request uses `ExpectedBucketOwner`, and failed writes never overwrite another run |
| TC-CONSOL-078 | Load a snapshot containing valid topic records, then a parseable snapshot with an invalid topic disposition | Valid topics survive normalization and deterministic sorting; the invalid snapshot returns its ETag with `status: invalid`, and scheduled processing performs no `PutObject` |
| TC-CONSOL-065 | Inspect S3 state, SNS payload, and EMF/log markers with private memory text present | S3, SNS, metrics, and public test artifacts contain no memory text, ids, snippets, rationale, embeddings, or tenant key; private review logs and bounded private Slack samples are the only content-bearing surfaces |
| TC-CONSOL-066 | Execute two fixture-driven scheduled runs containing more than 1,000 review records | Each run posts at most one bounded digest with ten groups and three samples per group, and the second run reports the expected cross-run transitions |
| TC-CONSOL-072 | The snapshot object is readable and has an ETag, but its JSON or schema is invalid | The run is degraded, sends configured degraded notifications, performs no state write, and exits nonzero until an operator pauses the schedule and deletes the exact stage key |
| TC-CONSOL-073 | The post-mutation active-memory refresh fails during a scheduled run | Confirmed mutation totals remain intact, `ConsolidationDedupUnavailable=1` is emitted in the run EMF, a content-free degraded health notification is attempted, no snapshot is committed, and the task exits nonzero |
| TC-CONSOL-074 | A health topic is unchanged from the previous snapshot but still breaches an immediate health rule | The Slack digest is posted despite unchanged-run suppression so the SNS alarm has matching private digest context |
| TC-CONSOL-075 | A manual apply run produces an immediate or current-run threshold health failure | It publishes the content-free health alarm without reading/writing digest state or posting the weekly Slack digest; report-only remains notification-free |

## Infrastructure

| ID | Scenario | Expected result |
|---|---|---|
| TC-CONSOL-020 | Enablement flag is unset | Consolidation task exists for on-demand report-only runs; schedule and scheduler role are absent |
| TC-CONSOL-021 | Enablement flag is set in preview | Schedule and scheduler role exist, but schedule state is `DISABLED` |
| TC-CONSOL-022 | Enablement flag is set in production | Weekly Sunday 03:00 UTC schedule is `ENABLED` with flexible window off and overrides the exact task container to `MEM9_CONSOLIDATION_REPORT_ONLY=0` |
| TC-CONSOL-023 | Inspect task definition | arm64 task pins the `llm-proxy` image tag, `node /app/memory-consolidation.mjs` entrypoint, and contains no secret literal |
| TC-CONSOL-024 | Inspect task role | Mantle actions, scoped SNS publish for scheduled and manual apply health, and log/EMF writes are present; no wildcard secret read is present |
| TC-CONSOL-025 | Inspect scheduler role | Trust is restricted to Scheduler; RunTask names the exact task definition; PassRole names only task/execution roles with `ecs-tasks.amazonaws.com` condition |
| TC-CONSOL-026 | Inspect workload roles | Task, execution, and scheduler roles receive the required operator-owned permissions boundary |
| TC-CONSOL-027 | Inspect task network | Existing cluster, private subnets, task security group, Fargate launch type, and no public IP are used |
| TC-CONSOL-028 | Inspect run exports | Task definition, cluster, subnets, security group, and log group are exported under the stage consolidation SSM prefix |
| TC-CONSOL-029 | Inspect production failure detector | Exact task-definition non-zero STOPPED events feed a stage metric and CloudWatch alarm; previews create no actionless alert resources |
| TC-CONSOL-030 | Inspect alarm actions | Failure alarm targets the existing SNS topic and therefore the existing Slack router |
| TC-CONSOL-031 | Inspect deploy-role template | Scheduler lifecycle/probe reads are scoped and deploy-role PassRole is conditioned on `scheduler.amazonaws.com` |
| TC-CONSOL-032 | Inspect workload boundary | ECS RunTask, constrained PassRole, SNS publish, and consolidation secret-injection role are admitted while the existing exact failure-queue scopes and DB-secret compatibility remain unchanged |
| TC-CONSOL-033 | Compare runtime emitter and docs/alarm names | EMF namespace, metric names, and `stage` dimension are identical |
| TC-CONSOL-034 | Run focused coverage gates | New runtime and infra modules exceed 80% for statements, branches, functions, and lines |
| TC-CONSOL-035 | Inspect the `llm-proxy` image build | The image installs a CA trust store before downloading the regional RDS certificate bundle over HTTPS |
| TC-CONSOL-036 | Inspect the failure-event Logs resource policy | EventBridge delivery trusts both documented service principals for CreateLogStream and PutLogEvents on only the failure log group |
| TC-CONSOL-037 | Inspect Scheduler tags and group IAM | Tags live on a dedicated schedule group, the schedule and trust policy name that group, and deploy grants separate schedule and group resource scopes |
| TC-CONSOL-067 | Inspect task defaults and Scheduler override | The task definition has no scheduled marker; only the Scheduler override sets `MEM9_CONSOLIDATION_SCHEDULED=1`; manual apply and preview report-only paths therefore cannot touch digest state or weekly Slack, while manual apply can still publish a threshold-based health alarm |
| TC-CONSOL-068 | Slack approval is disabled or enabled | Disabled consolidation injects no Slack token/channel; enabled consolidation reuses the existing bot-token parameter and private channel without duplicating secrets |
| TC-CONSOL-069 | Inspect consolidation task IAM and workload boundary | The task has only stage-scoped digest `s3:GetObject`/`s3:PutObject`, no list/delete, matching KMS context permissions, and the existing boundary admits the path |
| TC-CONSOL-070 | Inspect the operator-owned bucket lifecycle | `decisions/` retains its three-day expiry, `consolidation-digests/` has a separate expiry of at least 70 days, and both prefixes abort incomplete multipart uploads after one day |
| TC-CONSOL-076 | Inspect rollout documentation for an existing decision-artifact bucket | Before schedule enablement, the operator is told to re-run `scripts/deploy-decision-artifact-bucket.sh`, require its two-rule lifecycle read-back, and expect the first scheduled run to degrade once when a missing key is masked as 403 |
| TC-CONSOL-079 | Inspect the synthesized consolidation task definition | The exact `Mem9Consolidation` container has `pseudoTerminal: false`, leaves `interactive` unset, and preserves its `awslogs` configuration while the task transform also preserves and adds tags |

## Preview E2E

The continuous-scheduling gate additionally requires cross-stage task ARN
denials for untagged tasks, exact revision/generation/nonce correlation, a
pre-create SSM journal and cleanup after a lost CreateSchedule response. Local
fixture tests use real SCRAM logins, reject an incorrect password and reject the
retired seed login. Synthetic runs preserve existing stage-budget counters.

| ID | Scenario | Expected result |
|---|---|---|
| TC-CONSOL-040 | Run deployed consolidation task with `--report-only --check-llm` | A content-free Mantle smoke succeeds and the task reaches STOPPED with exit code 0 |
| TC-CONSOL-041 | Query that task's CloudWatch stream | At least one `CONSOLIDATION_REVIEW_LIST` line is present |
| TC-CONSOL-042 | Inspect report-only task logs and state | Summary and content-free EMF are present; no auto mutation or SNS notification is issued |
| TC-CONSOL-045 | The operator script, task definition, and Dockerfile each name the consolidation entrypoint | All three agree on `/app/scripts/memory-consolidation.mjs`, and neither the script nor the task definition still references the flattened `/app/` path (they drifted once: the image fix moved the file but the operator script kept the old path, and each file was only asserted in isolation) |
| TC-CONSOL-046 | Schedule-group name prefix for realistic stages | Every prefix stays within EventBridge Scheduler's 38-character `name_prefix` limit and keeps the `mem9-on-aws-` prefix the deploy role is scoped to; an overlong stage throws at synth rather than at deploy |
| TC-CONSOL-047 | Scheduler role name against its three intersecting constraints | The name is within IAM's 64-character limit, matches the already-deployed boundary pattern `mem9-on-a*-*Mem9ConsolidationSchedulerRole-*`, and starts with `mem9-on-aws-` for `iam:CreateRole`; an overlong stage throws |
| TC-CONSOL-071 | Run the preview report-only harness with digest configuration present | It exits zero only when `CONSOLIDATION_REVIEW_LIST` reports `digestEnabled: false`, proving the path performs no S3 digest-state, Slack, or SNS review-digest operation |
| TC-CONSOL-080 | A production-sized report-only task remains `RUNNING` for 80 minutes before stopping successfully | The default bounded observer budget tolerates the run beyond the former 1,200-second deadline, then requires exit zero and the exact task stream's content-free `CONSOLIDATION_REVIEW_LIST` marker |
| TC-CONSOL-081 | Configure the report-only observer budget at its valid boundaries or with empty, malformed, shorter, or unbounded values | Integers from 60 through 43,200 seconds are accepted; every invalid value fails before `ecs run-task` or any other AWS call |
| TC-CONSOL-082 | The exact report-only task reaches `STOPPED` with a non-zero container exit code | The harness fails with the exit code before querying or publishing any log marker |
| TC-CONSOL-083 | The default observer budget expires while the exact task remains `RUNNING`, or an AWS command returns an identifier-bearing failure | The harness polls at 43,199 seconds and fails after exactly 43,200, leaves the task running without `ecs stop-task`, queries no logs, and publishes no task id, ARN, account id, raw failure record, or stop reason |
| TC-CONSOL-084 | Inspect the PR-preview report-only workflow step | The preview smoke preserves its former 1,200-second observer budget inside the 60-minute deployment job, while direct operator runs retain the production-suitable 43,200-second default |
| TC-CONSOL-094 | Scheduled run with missing or expired digest | Authorize namespace writes, conditionally create an empty schema-versioned baseline, then validate an owner-bound read before model or memory apply; no listing permission is needed |
| TC-CONSOL-095 | Existing digest and concurrent initialization | Only HTTP 412 means already exists; preserve the winning object and read it normally; final writes retain ETag fencing |
| TC-CONSOL-096 | Initialization/read failure or invalid existing state | 403, KMS/transport failure, 409, missing-after-create, malformed JSON, schema/stage/namespace mismatch abort before model/apply; existing state is not replaced |
| TC-CONSOL-097 | Revoked/readonly service or invalid invocation scope | No initialization write is sent without active namespace write authorization; revocation between create and read aborts before model/apply |
| TC-CONSOL-098 | Manual or report-only invocation, including inherited scheduled marker | No initialization or scheduled digest writes; empty baseline produces the same first-run health, transitions, and reminder outcome as missing state |
| TC-CONSOL-099 | Namespace-enforced numeric PR preview, with scheduling disabled | Only that preview's digest prefix receives GetObject/PutObject and matching S3/KMS access; production, arbitrary stages, and pre-cutover previews gain nothing; no ListBucket or schedule |
| TC-CONSOL-100 | Explicit synthetic probe under the deployed preview task role | ListObjectsV2 is denied; actual initialization plus strict Get succeeds, a second initialization preserves state/ETag, and revoked membership blocks initialization; journal and clean up only owned preview fixtures; no model/memory apply or production-role reuse |


## Production credential cutover and historical activation

The following cases are required for the proposed production maintenance path;
they are pending until executable tests and same-account rehearsal pass.

| ID | Scenario | Expected evidence |
| --- | --- | --- |
| TC-CONS-PROD-001 | Prepare resources while production still uses the owner credential | Exact new parameter/task references; serving configuration and memory rows unchanged; new workers disabled |
| TC-CONS-PROD-002 | Inventory and transfer application ownership | Exact database/OID inventory; unknown schema/type rejected; extension and other-database ownership untouched; transactional rollback on mismatch |
| TC-CONS-PROD-003 | New administrator bootstraps through fresh connections | Schema replay, grants and namespace operations pass on local PostgreSQL and actual Aurora; no circular memberships or runtime admin privileges |
| TC-CONS-PROD-004 | Install runtime while service is drained | Tenant ID, namespace mappings, memories and ingest jobs preserved; exact runtime tuple bound; readiness stamped only after schema/ACL/index verification |
| TC-CONS-PROD-005 | Restore online runtime before retirement | MCP write/search, OAuth and durable ingest recovery pass; failed health check cannot retire old owner |
| TC-CONS-PROD-006 | Retire the real legacy database identity | Actual old OID NOLOGIN, old sessions terminated, literal old-password reconnect fails; dummy retired role rejected |
| TC-CONS-PROD-007 | Historic ECS revisions try administrator access | Exact IAM read-back and negative tests deny new admin secret to old bootstrap/server/maintenance task or execution roles, including override variants |
| TC-CONS-PROD-008 | Repeated/ambiguous cutover invocation and deadline | Durable operation nonce/phase prevents duplicate transfer or two-hour extension; premature/expired transition rejected; cancellation preserves recovery state |
| TC-CONS-PROD-009 | Failure before versus after retirement | Before/after: rehearsed runtime image and restricted credential restored with v2 and old schedules off. After retirement NOLOGIN remains; no automatic data restore |
| TC-CONS-PROD-010 | Subsequent ordinary production deployment | Correct credential references and verify-only bootstrap; each verification receives its own nonce and bounded deadline without changing the completed cutover window; changed digest/incomplete or contradictory state fails before serving revision changes |
| TC-CONS-PROD-011 | Policy and target manifest validation | Exact stage/database/namespace/version binding; both persisted budgets required; model/capture/dispatcher remain off until explicit activation |
| TC-CONS-PROD-012 | First bounded historical batch | Durable receipt count and source/post-image preservation; protected/disputed cases stay review-only; duplicate wakes produce zero repeat mutations |
| TC-CONS-PROD-013 | Canary promotion and load | Steady-state daily budget derived from measured eligible work; unchanged denominators and uncertainty accounting; foreground p95 within 10% allowance |
| TC-CONS-PROD-014 | Preview regression and log redaction | Existing synthetic preview acceptance remains green; no production data copied to reviewers/preview; no passwords, verifiers or memory contents in output |
| TC-CONS-PROD-015 | Abort after password fence before ownership transfer | Runtime role/grants/tenant/readiness were committed first; pinned runtime image restores read/write/search without runtime DDL |
| TC-CONS-PROD-016 | ECS first-restoration and subsequent rollout failure | No automatic pre-cutover task resurrection; pinned fallback ARN/digest/new runtime reference enforced; all historic roles denied replacement credentials |
| TC-CONS-PROD-017 | Old migration reconnects after watchdog recovery | Recovery epoch advances under the shared lock; old nonce/epoch cannot mutate DDL or phase; retry cannot extend original deadline |
| TC-CONS-PROD-018 | Management-plane password reset and admin-parameter recovery | Preview records master NOLOGIN behavior; live-role execution guard denies v2 if revived; restore missing admin parameter from protected backup while keeping old login disabled |
| TC-CONS-PROD-019 | Credential DDL cancelled or backend terminated | Default logging reproduces a synthetic verifier leak; hardened stderr sessions omit it after ERROR/FATAL and a log-ingestion barrier; CSV/JSON destinations and denied settings reject before credential DDL |
| TC-CONS-PROD-020 | IAM simulator aggregates resource decisions or reports unrelated missing conditions | Inspect each resource; unknown SSM conditions remain blocking; unrelated PassRole/KMS statements cannot hide or manufacture a credential grant |
| TC-CONS-PROD-021 | Hundreds of historical task definitions | Persist deterministic inventory count/digest plus exact role/family/cluster sets below the routing size limit; revalidate before starting maintenance |
| TC-CONS-PROD-022 | Preparation fails before plan, manifest or ledger creation | No maintenance begins; original login and stage lock prove absent ledger; retries inspect committed state before deployment; disposable cleanup handles partial state and always rejects production |
| TC-CONS-PROD-023 | Database backup, identity or credential rotation changes | Match actual Aurora master and cluster resource ID; require encrypted, available, recent snapshot and current PITR; never delete production recovery snapshots |
| TC-CONS-PROD-024 | OAuth facade tries replacement database credentials | Exact handler input grants retain OAuth/approval behavior and cannot read runtime, transition or administrator credentials |
| TC-CONS-PROD-025 | Preview administrator upgrades an extension created by the original owner | A separate deterministic probe database reproduces extension ownership; after real master retirement, the new administrator upgrades a supported older vector version and verifies synthetic vector operations; production and unmarked databases are rejected |
| TC-CONS-PROD-026 | Administrator parameter disappears after retirement | Trusted recovery restores only a missing primary from its exact backup, never overwrites an existing value, validates the expected administrator identity, and leaves the old master NOLOGIN |
| TC-CONS-PROD-027 | Preview primary-credential loss interrupts the rehearsal process | A durable backup remains; independent recovery can restore the primary without the interrupted process's memory; no workload receives the backup parameter |
| TC-CONS-PROD-028 | Rehearsal evidence is stale, incomplete or belongs to a different tree | Production acceptance requires all real checks plus matching schema/operator/coordinator/source-tree identities and successful source-run evidence; synthetic-only or partial runs cannot authorize production |
| TC-CONS-PROD-029 | Current engine exposes no extension upgrade target | Record maintenance-only evidence; require successful normalized ALTER command and isolated CREATE/DROP/vector-index operations; an unchanged tuple following permission denial cannot pass |
| TC-CONS-PROD-030 | Engine, owner, extension version, available versions or reachable targets drift | Read live production catalogs through a bounded read-only bootstrap operation; reject stale maintenance evidence before downtime, activation or normal deployment |
| TC-CONS-PROD-031 | Credential fencing updates existing ECS roles | Preserve their audited service trust and attach the credential deny policy; preparation requires no additional trust-policy update permission; new roles retain their scoped trust |
| TC-CONS-PROD-032 | Arm cancellation acceptance on production, stale source or wrong attempt | Reject before mutation; preview intent binds run and attempt, tree/digests, plan nonce and synthetic preservation baseline |
| TC-CONS-PROD-033 | Cancel an armed preview after committed password fencing | Source recovery and cleanup are skipped only for that armed cancellation; independent receiver advances epoch, preserves phase/deadline and restores foreground service |
| TC-CONS-PROD-034 | Inspect the interrupted preservation fixture | Phase-selected original/transition credential, exact legacy role OID, rollout lock and read-only consistent snapshot; changed/deleted records fail; only hashes/counts leave the task |
| TC-CONS-PROD-035 | Recovery receipt is a no-op, stale, forged or from another workflow attempt | Verify actual source cancellation/skipped steps and a distinct successful receiver attempt plus immutable ledger history; no-op or contradictory evidence cannot pass or erase the preview |
| TC-CONS-PROD-036 | Resume after verified cancellation takeover | Same nonce and original maintenance deadline, unchanged code/schema, full retirement/admin rehearsal; final evidence alone permits cleanup and later production admission |
| TC-CONS-PROD-037 | Raw provider IAM roles are created during preparation | Explicit project/stage names match existing deployment and runtime verification scopes; overlong names reject before credential creation; do not assume SST component naming applies to raw provider resources |
| TC-CONS-PROD-038 | Cutover infrastructure changes without an image source change | Build a matching release image for the new coordinator tree; retain exact production revision and preview merge-parent/tree validation |
| TC-CONS-PROD-039 | ECS list/describe views temporarily disagree during Scheduler acceptance | Retry a bounded complete inventory only for requested task ARNs reported MISSING; unresolved, unauthorized, unaccounted or malformed results remain fatal; ownership checks and cleanup journals are retained |
| TC-CONS-PROD-040 | Cutover deployment rebuilds maintenance target configuration | Read and validate the exact stage's deployed maintenance target parameter; preserve it for every SST cutover deployment; missing enabled targets or conflicting explicit overrides reject before deployment |
| TC-CONS-PROD-041 | Production weekly-task opt-in is enabled while preview targets are empty | Manual preview rehearsal uses the same disabled weekly scheduling as normal preview CI and accepts its empty target list; production retains its own opt-in |
| TC-CONS-PROD-042 | Aurora attributes a source-issued role grant to rdsadmin | The same legacy/transition caller uses default-grantor REVOKE with RESTRICT; effective SET and USAGE must both disappear; rollback probe restores original membership options; a committed ownership transfer is retained if the subsequent revoke fails |
| TC-CONS-PROD-043 | Ordinary bootstrap launcher targets runtime verification | The actual RunTask request adds only a fresh invocation nonce and 14-minute deadline below the verifier's 15-minute ceiling to a matching single-container verification definition, with the nonce as clientToken; wrong stage/marker/duplicate environment rejects before launch; legacy launches remain unchanged and no persisted cutover deadline is edited |
| TC-CONS-PROD-044 | Rehearse the ordinary deployment launcher against a completed preview cutover | The same generic bootstrap launcher runs against the active preview runtime after finalization and before administrator recovery and cleanup; its failure blocks the rehearsal and merge evidence |
| TC-CONS-PROD-045 | Retirement commits near the apply cutoff | The mutation remains bounded by the original 45-minute cutoff; its committed retired state is handed to finalization without launching another under-budget task; both credential rejection checks remain mandatory before active convergence and completion, inside the unchanged original maintenance window |
| TC-CONS-WORKER-001 | Provision production workers after runtime retirement | Independent planner/executor credentials; existing tenant and maintenance targets reused by reference; HTTP capability admits a SQL-controlled canary while recurring schedules remain disabled until promotion |
| TC-CONS-WORKER-002 | Production worker IAM and wake frequency | Planner cannot read executor/admin/tenant secrets; executor receives only its own credential, signing ring and tenant; role trust remains account scoped; persisted leases serialize bounded slices |
| TC-CONS-WORKER-003 | Administrative task or execution role drifts | Reject wrong stage/role ARN, foreign trust, missing boundary, extra attachment or widened inline permissions before task launch; both roles are checked |
| TC-CONS-WORKER-004 | Protected row changes during canary | Capture namespace-bound hashes before enabling execution; require original protected rows unchanged; a foreground edit leaves proof indeterminate because last-writer metadata cannot establish the intervening history |
| TC-CONS-WORKER-005 | Stage planning and capture the performance baseline | Planning can run with execution disabled; pause dispatch before capturing protected rows, then benchmark with temporary pinned writes; canary requires the saved baseline and never replaces it |
| TC-CONS-WORKER-006 | Old revision starts after pause or later activation | Stop every revision in the approved families; fresh admission nonce and release binding reject old workers before dispatcher acquisition; unrelated services remain running |
| TC-CONS-WORKER-007 | Jittered full-precision performance report exceeds an ECS override | Preserve timing values in four bounded SSM fragments; validate complete request size and assembled hash; missing/mixed fragments reject promotion without blocking emergency pause |
| TC-CONS-WORKER-008 | Benchmark POST commits but its response is lost or retried | Reconcile marker and deterministic content hashes across the approved namespaces; remove duplicates; preserve edited/unexpected rows and require zero remaining owned fixtures before promotion |
| TC-CONS-WORKER-009 | Main advances or schedule activation fails | Keep pinned worker/operator images and existing schedule targets; verify unchanged backend tasks/digests and worker revisions; pause SQL plus disable recurrence after partial updates or failed readback |
| TC-CONS-WORKER-010 | Controller restarts after promotion | Persist the original backend binding with the first database baseline; reject rebinding; compare fresh task/digest observations with the DB original and pause when evidence is missing or changed |
| TC-CONS-WORKER-011 | Admission allows one action every twenty seconds | Explicit successful rate-wait replies preserve the same lease until the slice deadline; five two-row actions complete over at least eighty seconds; transport uncertainty keeps its three-attempt ceiling, including interleaved rate waits |
| TC-CONS-WORKER-012 | Build the bootstrap image with an unresolvable production operator import | A network-disabled import of both production operator entrypoints at their actual image paths fails the image build; the reproduced missing-module error identifies the dependency, rather than accepting an unrelated build failure |
| TC-CONS-WORKER-013 | Import both production operator entrypoints in the final image as its non-root user | The complete transitive module/package graph is readable and resolves without credentials, network access, database access or CLI-main execution; existing namespace validation semantics remain unchanged |
| TC-CONS-WORKER-014 | Capture the production backend after credential retirement | Accept only the sealed runtime task family for the exact cluster/account/region and positive revision; reject the legacy task family, similar names and foreign clusters while preserving three-container digest and replay-binding checks |
| TC-CONS-WORKER-015 | Load canary authentication for managed or OIDC deployments | Read the deployed auth mode and select its existing M2M credentials; retained Cognito or browser credentials are never an OIDC fallback |
| TC-CONS-WORKER-016 | Published auth metadata is missing, unknown or malformed | Reject before reading credentials; require exact requested names, nonblank strings and positive integer versions, with sanitized errors |
| TC-CONS-WORKER-017 | Mode and selected provider metadata form a stable mixed configuration | Both managed and OIDC provider token endpoints and scopes must match the active common values before reading M2M credentials |
| TC-CONS-WORKER-018 | OIDC prefix points outside the stage or to browser credentials | Accept only the exact same-stage provider path with an opaque lowercase 64-hex suffix; reject traversal and malformed paths before credential reads |
| TC-CONS-WORKER-019 | Selected configuration changes during loading | Re-read all selected names, original values and versions and reject observed changes; no stale-data/provider fallback or atomic-snapshot claim |
| TC-CONS-WORKER-020 | Confirm managed and OIDC configuration | Final confirmation contains all eight managed or nine OIDC records; every request stays within ten names and uses a bounded timeout; secret reads are decrypted and credential bytes preserved |
| TC-CONS-WORKER-021 | Change the host-side canary authentication loader | Build matching release images and run real preview acceptance so source-tree-bound production evidence can be obtained; successful unit tests with skipped preview deployment are insufficient |
| TC-CONS-WORKER-022 | Re-admit a canary after its verification froze conservation | Reject before changing policy epochs or enabling work; an explicit continuation is required and the frozen parent remains unchanged |
| TC-CONS-WORKER-023 | Begin a continuation from a paused frozen parent | Verify all receipt chains, protected baseline, counter, source and expected parent hash; append immutable attempt evidence atomically without clearing the original proof or restoring spent budget |
| TC-CONS-WORKER-024 | Repeat or conflict with a begin-continuation request | Identical committed request is idempotent; changed body, parent or active pointer rejects without another transition |
| TC-CONS-WORKER-025 | Inspect an open continuation before another real mutation | Return fresh evidence without freezing it; final verification freezes only the active attempt and still rejects later conservation drift |
| TC-CONS-WORKER-026 | Resume candidate planning after a frozen canary | Dedicated planning admission keeps SQL execution disabled, uses canonical dispatcher fencing, and preserves all original memory receipts and counters |
| TC-CONS-WORKER-027 | Budget spans original and continued attempts | Real PostgreSQL atomic apply plus receipt trigger never exceeds the original 20-row lifetime allowance, including stale/racing tasks and retries; policy changes preserve spent counters and denominator |
| TC-CONS-WORKER-028 | Deploy the administrative-only continuation increment | Prove actual worker/serving ARM64 child-image equality and exact normalized execution/authority configuration; reject changed image content, command, environment, secret references, resources, roles or namespace targets |
| TC-CONS-WORKER-029 | Rebind a backend for a compatible new release | Retain old and new identities and the compatibility certificate; reject bare task/tag substitutions, altered parent data, changed generation or unsupported compatibility |
| TC-CONS-WORKER-030 | Refresh release witness for paused existing canary data | New explicit mode audits exact existing receipts/protection/counter under a real repeatable-read read-only lease and full new release evidence; audit works before witness publication, rejects read-write transactions, runtime ACL drift or enabled dispatch, and installs no tables; original zero-receipt/no-setup mode still rejects active setup |
| TC-CONS-WORKER-031 | Race, fail or interrupt paused-canary witness publication | Preserve original runtime plan/state and production snapshots; exact single-write/readback and independent lease/session release; ambiguity retains owned fences |
| TC-CONS-WORKER-032 | Execute fresh foreground sampling with a sparse real merge set | Predeclared identical cohorts; real planner progress covers every request; one executor is launched only after both measured windows begin; no sleeping padding, fabricated candidates, sample trimming or timestamp stitching |
| TC-CONS-WORKER-033 | Reentrant callback, wake rejection or controller crash | Persist launch intent before the canonical request; attach rejection handling immediately; do not await executor completion inside the sampling callback; never double-launch on recovery |
| TC-CONS-WORKER-034 | Executor starts or commits after the measured cohort ends | Reconcile the authorized real receipt within the unchanged lifetime cap; performance remains failed, no new launch/retry/promotion; preserve the complete failed cohort |
| TC-CONS-WORKER-035 | Abort while Schedule creation, a task or a foreground write is uncertain | Pause first, reconcile ownership and cancellation horizon, join work, repeat final drain and fresh receipt checks, remove all owned benchmarks; hold fences if evidence remains uncertain |
| TC-CONS-WORKER-036 | Reuse an archived production capacity batch | Require every original receipt/time/result plus actual task and compatible runtime evidence; no faster subset, preview substitution or cross-attempt rate; require new full performance evidence and fresh census |
| TC-CONS-WORKER-037 | Complete continued validation and promotion | Verify the active freeze, entire lifetime receipt set, two fresh full-set replays, benchmark remaining=0, calibrated budget and genuine recurring planner/executor provenance; no invented large-backlog prerequisite |
| TC-CONS-WORKER-038 | Run continuation acceptance in preview | Marked isolated synthetic database and stage-scoped resources only; real PostgreSQL lifecycle and packaged operator imports; no production data copied and no fixture receipt presented as a production mutation |
| TC-CONS-WORKER-039 | Install administrative attempt metadata under an already sealed runtime | Atomic maintenance-schema DDL and revokes preserve runtime ready_for, ordinary verification, original runtime/schema digests and existing worker denial of metadata mutation |
| TC-CONS-WORKER-040 | Encode full-precision N150 cohorts near report bounds | Lossless versioned timing encoding round-trips every sample/timestamp/latency, accepts legacy encoding, and stays within unchanged report/fragment/request limits; no truncation or rounding |
| TC-CONS-WORKER-041 | A descendant changes members or budget-policy epochs after a parent freeze | Parent re-verification uses its fixed receipt/post-image/policy projection; current verification covers the full immutable lineage and current rows without rewriting the parent |
| TC-CONS-WORKER-042 | Receipt arrives with a missing or stale attempt admission | Atomic trigger membership binds actual action control epoch to the active attempt; unbound/cross-attempt insert rejects with rollback of memory writes and counter; cached replay adds nothing |
| TC-CONS-WORKER-043 | Continuation certificate or witness payload is malformed or forged | Version/size/source/parent/digest/residual-diff checks reject; witness refresh uses only its independent read-only producer path before new operator admission |
| TC-CONS-WORKER-044 | Counter accounting spans multiple attempt states | Root phase stays canary until verified promotion; one shared counter counts each receipt once; planning, failed measurement and child creation never reset or double-charge usage |
| TC-CONS-WORKER-045 | Foreground callback is mistaken for worker activity | Only the first non-warmup foreground write acknowledgment can cause a launch; planner activity already exists; actual executor start/commit are independently observed afterward |
| TC-CONS-WORKER-046 | Apply and replay ordinary recurring work after promotion | New receipt-membership trigger no longer admits canary lineage while root phase is promote; normal steady-state budgeted apply and cached replay succeed without altering frozen attempt membership |
| TC-CONS-WORKER-047 | A failure event follows an attempt freeze | Presence of the immutable freeze still forbids new execution admission; changing latest status to failed never reopens the attempt |
| TC-CONS-WORKER-048 | Legacy verification sees a newly deployed release before continuation | Reject changed release/binding fields without overwriting the original frozen proof; prepare cannot overwrite validated or spent root setup |
| TC-CONS-WORKER-049 | Retry transport changes while semantic continuation request repeats | Persisted request/attempt identity returns the same committed outcome without resetting clocks; changed semantic body or superseded pointer rejects |
| TC-CONS-WORKER-050 | Archived tagged backend image mapping is replaced | Both old and new captures bind exact task, definition and container identities/digests; a substituted root mapping, mismatched task image or extra container rejects even when cached material hashes match |
| TC-CONS-WORKER-051 | Scheduler authority spans compatible worker revision updates | Capture all seven roles, verify exact per-snapshot RunTask/PassRole/trust/legacy-deny contract, and normalize only the two approved revision references; wrong same-family revision, extra resource, missing deny, widened trust or missing Scheduler role rejects |
| TC-CONS-WORKER-052 | Fixture evidence is missing, incomplete, from another release or expires while publishing | Require one authenticated successful preview record with the exact workflow/source identities and all nine checks; bind its hash/run/attempt into every continuation witness; recheck age before and after the single publication write, retaining fences after an uncertain or stale post-write check |
| TC-CONS-WORKER-053 | Run the packaged canonical fixture in isolated containers | Inherit production bootstrap modules without replacement, execute all 17 named PostgreSQL cases with zero skips, remove shared fixture roles, and verify zero database/role residue before shutdown; reject production stage, unexpected inputs or injected production DB credentials; only the verified AWS preview host may emit final release evidence |
| TC-CONS-WORKER-054 | Fixture launch response or ownership-journal update is lost | Preserve one deadline and one RunTask attempt; directly describe and stop every acknowledged task even when ListTasks omits it; missing known-task coverage keeps cleanup pending; retain private resource/request-hash receipts until physical deletion is verified |
| TC-CONS-WORKER-055 | Retain data images while deploying a new control release | Verify exact protected root/ARM64 pairs, separate control/data tags and actual backend/worker images; bootstrap uses the current build; an all-new preview is not retained-mode acceptance |
| TC-CONS-WORKER-056 | Environment descriptor is forged, missing, expired or replaced during predeployment checks | Read fixed same-account protected parameters, require complete responses and runtime binding, verify build evidence and unchanged readback; reject silent fallback after retention |
| TC-CONS-WORKER-057 | Retention authorization expires after execution settings are changed inside admission | The final database-time check rejects and rolls back execution, dispatcher, policy/window/history, rate admission and attempt records; pause/status still work |
| TC-CONS-WORKER-058 | Declared Docker inputs change while high-level source appears unchanged | Include Dockerfiles, all COPY/glob/directory members, lockfiles, modes, ignore files and CI builder settings; reject unsupported syntax, missing/linked inputs and changed recipes; unrelated control-only edits do not change the data recipe |
| TC-CONS-WORKER-059 | Registry returns substituted roots, platform children or manifest bytes | Authenticate exact account/repository/digest, one ARM64 child, config and layer descriptors; retain actual artifact identities without ignoring executable caches or claiming rebuild reproducibility |
| TC-CONS-WORKER-060 | Retained image scanning is stale, incomplete or contains open HIGH findings | Exhaust pages and verify timestamps, identity and complete severity counts; preserve open findings without converting inventory into risk acceptance or substituting a new-build scan |
| TC-CONS-WORKER-061 | Sampling and executor launch persist concurrently | Serialize immutable snapshots; delayed writes cannot overwrite acknowledged launch identity or the once flag; persistence failures close admission and remain failures |
| TC-CONS-WORKER-062 | An adapter silently returns N100 for declared N150 | Reject the baseline before canary admission and the loaded cohort before freezing, while preserving the shared verifier's original supported range |
| TC-CONS-WORKER-063 | A periodic task exits successfully without running a slice | Require at least one successful slice and no failed slices; an empty successful slice remains valid; use Scheduler/task identity rather than a missing one-shot invocation |
| TC-CONS-WORKER-064 | Activation drops or substitutes the stored backend binding | Compare the canonical binding before writes and pass it through the actual activation helper's final verification; never adopt a fresh observation implicitly |
| TC-CONS-WORKER-065 | Exercise retained preview data with current control code | Reject invalid production/manual inputs before AWS work, verify the historical build and actual data/control digests, run genuine preview checks, and emit one complete source-bound retained-combination record |
| TC-CONS-WORKER-066 | An expired preview descriptor remains during teardown | Remove only the stage's graph with selection explicitly disabled for removal; delete the unchanged owned descriptor before the runtime plan, and retain a concurrently changed record |
| TC-CONS-WORKER-067 | Retained acceptance follows completed runtime cutover | Reproduce the ordinary runtime verifier's missing fixture generation without writes; select a dedicated operator only for numeric preview, exact active mode and an explicit context bound to the completed runtime nonce; intermediate and production contexts reject |
| TC-CONS-WORKER-068 | An old fixture belongs to the retired administrator | Use new context-derived database, roles, tenant ID and tenant name; create under the verified replacement administrator; require actual database owner OID and context marker; preserve old data, bindings and proofs |
| TC-CONS-WORKER-069 | Dedicated fixture execution identity | Current control bootstrap image, empty task role, exact six secret references and scoped KMS key/context; no owner, backup, transition or ordinary runtime credential; ordinary bootstrap and production resource graph remain unchanged |
| TC-CONS-WORKER-070 | Route or task identity changes before launch | Validate the deploy-authored route and actual definition, roles, image, network and nonce before mutation and again immediately before RunTask; reject drift and arbitrary overrides |
| TC-CONS-WORKER-071 | Fixture setup overlaps ordinary bootstrap | Bounded fixture lock precedes the runtime bootstrap lock; CREATE DATABASE runs in autocommit outside the ordinary lock; add only the new synthetic binding and tenant in one short transaction; pre-existing tenant/binding bytes and readiness remain unchanged |
| TC-CONS-WORKER-072 | Historical route or partially created fixture remains | Recover only journal-owned tasks using historical definition/container/nonce identity, never current credentials; unknown work holds admission; markerless partial DBs are not adopted or swept by name and are removed by verified disposal of the owned preview cluster |
| TC-CONS-WORKER-073 | Complete post-runtime retained combination | Run actual current-source cancellation/recovery/resume, dedicated fixture setup, 150-row multi-slice Scheduler execution, zero-change replay, pause, MCP/OAuth and full owned-resource disposal; stage diagnostics disclose no raw secrets or child output |
| TC-CONS-WORKER-074 | Supersede an expired retained-data authorization | Preserve descriptor schema and all data/root bindings; require a fresh policy-backed successor, immutable predecessor archive and complete paused-state checks inside the existing writer fence; increment the protected parameter version exactly once |
| TC-CONS-WORKER-075 | A predecessor changes, a lineage link is missing, or an authorization ID is reused | Reject before mutation, including IDs from earlier lineage entries and reserved attempts; never delete the parameter, reset its version or edit old timestamps |
| TC-CONS-WORKER-076 | Supersession write outcome or completion receipt is lost | Recover the exact archived transition under its original owner; reconcile only the expected successor version/value, never repeat PutParameter, and retain fences for foreign or uncertain results |
| TC-CONS-WORKER-077 | Authorization, root, scans, writer coverage or pause state changes at the write boundary | Recheck the complete snapshot after fence acquisition and before/after the write; reject before mutation or retain fences after an uncertain write; preserve the original canary allowance and proof |
| TC-CONS-WORKER-078 | Deploy a superseded authorization while the old worker manifest remains | Keep workers paused until the normal deployment reconciles the new hash and exact parameter version; reject missing, predecessor and later same-byte versions during admission |
| TC-CONS-WORKER-079 | Replay verified supersession cleanup | Revalidate owned fence receipts and current parameter before release; a repeated reconciliation performs no new authorization write |
| TC-CONS-WORKER-080 | Receipt persistence overlaps root, worker, schedule or execution-state drift | Collect a new full fenced snapshot after persistence; keep the fences on drift in both issuance and recovery |
| TC-CONS-WORKER-081 | Write intent exists but the issuer fails before calling Put | Persist an authenticated archive/intent-bound no-send receipt before cleanup; recover interrupted cleanup without another Put, including after expiry |
| TC-CONS-WORKER-082 | Process stops after archiving but before acquiring resources | Prove issuer termination and absence of the mandatory durable acquisition intent, then record an abort; an uncertain acquisition remains held |
| TC-CONS-WORKER-083 | A released resource has a stored acquisition descriptor, or caller lineage is fabricated | Authenticate retained descriptors and release receipts separately from active resources; verify lineage against independently collected archive hashes |
| TC-CONS-WORKER-084 | A durable write acknowledges but its authenticated record is missing or different | Read back acquisition intent before requesting locks, write intent before Put, and verification receipt before releasing locks; reject or hold without proceeding across the affected boundary |
| TC-CONS-WORKER-085 | Create or mutate an authorization archive object | Require exact conditional creation; deny missing/wrong conditions, copy sources, replication, deletion and object/version ACL changes only under the archive prefix |
| TC-CONS-WORKER-086 | Read an ambiguous or modified archive bucket policy | Reject duplicate JSON members at every depth, escaped equivalent keys, duplicate Sids/values, extra fields or statements, Not variants and unresolved/wrong resources; accept only the exact normalized five-statement policy |
| TC-CONS-WORKER-087 | Lifecycle or intelligent-tiering configuration can affect archived evidence | Reject overlapping expiration and archival transitions, including unfiltered, tag-only, parent/descendant and ambiguous scopes; preserve disjoint decision/digest rules |
| TC-CONS-WORKER-088 | Verify the existing archive owner stack without deploying | Validate owner, region, exact policy and availability through observation; do not create, import, update or execute a stack change |
| TC-CONS-WORKER-089 | Prepare or execute an archive policy update change set | Bind account, region, stack, parameters, reviewed template and complete proposed changes; allow only the intended in-place policy modification and reject replacement, unrelated changes or drift |
| TC-CONS-WORKER-090 | Validate real archive authorization and governing identities | Keep source tests separate from provider evidence; classify API rejection versus IAM denial, retain a synthetic audit record, and block admission for incomplete writer/configuration-mutator coverage |
| TC-CONS-WORKER-091 | Deployment attempts production data-release writes, deletes, tag or version-label changes | Exact protected parameter mutations, including label reassignment/removal, are denied for every deployment role; readers retain the fixed unlabelled name and version/hash checks, and legitimate preview descriptor creation/cleanup retains its prior behavior |
| TC-CONS-WORKER-092 | Deployment mutates the archive or its bucket configuration | An unconditional Deny excludes non-Get/List actions on the exact bucket and archive objects; access-point mutation is excluded for regional/Multi-Region ARNs and creation/control APIs; reads receive no new grant, and other direct-bucket prefixes/state/locks remain unaffected |
| TC-CONS-WORKER-093 | Deployment grants archive writes to a bounded workload | Explicit boundary PutObject denial rejects the archive write despite an identity/resource allow; preserve decision/digest writes, archive reads and all prior KMS/service/network restrictions |
| TC-CONS-WORKER-094 | A project-owned indirect path can remove or bypass exclusions | Reject protected owner-stack mutation, governing-role/policy changes and unauthorized helper/delegation paths; test regional/Multi-Region access-point object writes, cross-account access-point ARNs and independent workload resource-ceiling denial |
| TC-CONS-WORKER-095 | Bucket override differs across ownership contracts | Use only metadata Get/List checks, derive one validated name and reject existing owner/boundary mismatch before upload or update; distinguish authenticated fresh-bootstrap absence from failed reads without requiring a write probe |
| TC-CONS-WORKER-096 | Compact a maximum supported boundary | Preserve the revision Sid, omit only other optional Sids, enforce the shared 3–33-character bucket limit and reject 34/63-character overrides at every entry point, prove canonical uniqueness across complete default/custom-bucket, one/two-project and maximum-revision fixtures, and enforce quota against full rendered outputs in CI/deployment preflight |
| TC-CONS-WORKER-097 | Anonymous boundary statements are reordered or represented as scalar/list equivalents | Require template/library parity and a strict bijection over complete canonical statements while retaining only the existing safe normalizations |
| TC-CONS-WORKER-098 | Boundary contains duplicate, extra, missing or modified statements | Reject actual or expected duplicates, expected statements differing only by removed Sids, a library duplicate paired with a same-count rogue actual statement, duplicate Action/Resource entries, changed fields/effects/actions/resources/conditions and a missing or changed revision marker; never deduplicate input to make it pass |
| TC-CONS-WORKER-099 | A quota fix accidentally relaxes an old boundary restriction | Differential synthetic request matrices retain prior KMS contexts, ENI/service-origin, SSM approval and PassRole decisions; only the newly excluded archive write changes |
| TC-CONS-WORKER-100 | Ownership rollout fails between source, deployment and boundary updates | Keep deployment quarantine until the deployed verifier, both contracts and live default versions agree and pass independent readback/probes; recover under the existing owner without removing exclusions or rewriting authorization history |
| TC-CONS-WORKER-101 | Updated roles run normal preview and production deployment checks | Preserve required workload provisioning, preview descriptor lifecycle, retained-image reads and deployment locks; metadata-only offline checks cannot substitute for deployed checks |
| TC-CONS-WORKER-102 | Source exclusions pass but live governance is incomplete | Keep production admission held until live target bindings, current writer/mutator controls, trust ownership and audit evidence pass; source tests never manufacture owner approval |
| TC-CONS-WORKER-103 | Runtime-role preflight inspects source-declared SSM secret references | Accept only exact prod paths for the intended secret name and container with matching account/region; reject administrator-in-service, backup/transition, foreign stage/account/region, selectors, duplicates and wrong-container references without fetching credential values |
| TC-CONS-WORKER-104 | Project-prefix inventory encounters a retained operator | Exclude only the two exact source-owned roles after complete stack/logical-resource/physical-name/IAM identity, trust and policy verification; keep ordinary workload and live-runtime coverage complete |
| TC-CONS-WORKER-105 | Operator ownership, identity, trust or permissions drift | Reject missing/wrong owner, nested/service-role owner paths without a reviewed contract, wrong region/account/stage, recreated RoleId, unexpected permissions boundary or managed/inline attachment, changed policy or trust; never attach the runtime boundary as a fallback |
| TC-CONS-WORKER-106 | CI directly modifies a retained operator | Every deployment role denies exact-role lifecycle, trust, policy, attachment, boundary and tag changes while preserving necessary metadata reads |
| TC-CONS-WORKER-107 | CI passes a retained operator role | Namespace operator passing is denied; direct preview/legacy human acceptance remains ECS-only, absent/wrong service rejects, and production CI cannot pass the preview-human role |
| TC-CONS-WORKER-108 | CI authors a bounded workload that passes an operator role | Permanent boundary denies both exact operator PassRole targets even with broad identity permissions and an existing task definition; CI's own inline deny is not used as proof for the workload |
| TC-CONS-WORKER-109 | Resource-deny actions are compacted | Require a duplicate-free literal-only unchanged ceiling and prove old/new resource-deny matching agrees for every admitted action; retain Mantle bearer and ECR authorization-token behavior and explicit denial of future non-admitted actions |
| TC-CONS-WORKER-110 | Combined deny or quota inputs change | Keep archive PutObject and operator PassRole action/resource effects distinct; full maximum-field boundary stays within 6,144 and each CI role's aggregate inline policies including quarantine stays within 10,240 |
| TC-CONS-WORKER-111 | One CI role loses its permanent inline protections | Verification fails despite valid policies on peers or installed quarantine; metadata-only and custom-policy simulations do not substitute for current attachment checks |
| TC-CONS-WORKER-112 | Operator or CI-role catalog changes during a quarantined maintenance attempt | Recheck frozen identity/policy/boundary/source ownership before and after enforcement and before release; reject extra/missing CI identities, retain quarantine and installed restrictions on late failure, and preserve the operator role rather than altering its purpose |
| TC-CONS-WORKER-113 | CI attempts CloudFormation-mediated operator mutation | Permanently deny every admitted CloudFormation mutation on all stack targets, including a synthetic unrelated stack with a privileged execution role; preserve reads/template validation and the separate operator update path; reject uncovered future mutation grants |
| TC-CONS-WORKER-114 | An existing task definition or caller location is mistaken for operator authority | Require PassRole for task roles and overrides; preserve numeric-preview target/image/commit checks and preview-scoped human-role resources, without claiming PassedToService alone proves cluster placement |
| TC-CONS-WORKER-115 | Permanent CI inline protections are updated during quarantine | Use independently named CloudFormation inline-policy resources attached to the exact deployment roles; preserve the quarantine policy separately, reject its loss, and include it in aggregate inline quota checks |
| TC-CONS-WORKER-116 | CI attempts removal of its own or peer protections | Verify the complete source and live identity-policy set grants no role mutation on the exact three deployment-role ARNs, including wildcard and NotAction grants; installed quarantine independently denies every self/peer mutation, including deletion of quarantine itself |
| TC-CONS-WORKER-117 | CLI receives SIGINT or SIGTERM during partial group release | Preserve the adapter's fresh recovery signal, restore and verify quarantine on every CI role, report uncertain release without resuming deployments, and exit with the interruption status |
| TC-CONS-WORKER-118 | Account-wide role inventory requires pagination | Request 1,000 roles per service page, retain operator verification on every page, and follow IsTruncated/Marker even when IAM returns fewer records; never treat page size as proof of completion |
| TC-CONS-WORKER-119 | An owner template is returned as flow-style YAML beginning with a brace | Accept the same verified ownership declarations in JSON, block YAML and flow YAML; retain duplicate-key, intrinsic-tag, alias and exact role/condition/policy validation |
| TC-CONS-WORKER-120 | Initial supersession times or historical time structure are invalid | Before dependent work, reject future/noninteger issued or review times; retain the inclusive five-minute initial age boundary, including independent issued/review ages; historical recovery exempts age and D only |
| TC-CONS-WORKER-121 | Five complete collections exceed five minutes in a synthetic clock | Keep one preparation collection plus exactly four public protocol collections; all snapshots are freshly collected and the unchanged envelope completes before its immutable operation deadline |
| TC-CONS-WORKER-122 | Any snapshot becomes stale, future-dated or noninteger | Retain the five-minute snapshot limit at every phase and after asynchronous ownership checks; do not substitute an earlier cached audit |
| TC-CONS-WORKER-123 | The earlier issue/review anchor or descriptor expiry reaches D | Derive the strict deadline from the earlier immutable timestamp, capped by existing expiry; block normal fence acquisition, advance intents, Put, verification and release at the boundary |
| TC-CONS-WORKER-124 | D expires before Put or after a write | Before Put, retain positive no-send proof and existing abort cleanup; after Put, hold without another write or normal-success claim; independent physical cleanup remains available within its bounded lifecycle |
| TC-CONS-WORKER-125 | Recovery has a released gate and remaining mutex | Recollect the full audit, reject stale/unavailable or changed root/permission/pause/parameter evidence, and recheck recovery ownership plus the released gate and remaining mutex before the conditional release; cover both successor and unsent-abort paths |
| TC-CONS-WORKER-126 | The mutex is absent after an interrupted release | Authenticate the original release intent and exact absence before acknowledging the missing receipt; never delete again or infer release from an unauthenticated missing response |
| TC-CONS-WORKER-127 | All acquired fences are already released | Authenticate receipts and actual released state without a new full audit or resource mutation; permit historical audit records without current production admission or another Put |
| TC-CONS-WORKER-128 | An invocation restarts or cleanup outlives normal issuance | Preserve issued/review times, deadline, envelope and fence formats; new sessions cannot restart D, and the separate physical lifecycle does not extend write authority |
| TC-CONS-WORKER-129 | V3 compares archived and current material | Validate both legacy raw snapshots without rewriting recorded hashes; preserve V1/V2 equality and reject unsupported certificate versions or fields |
| TC-CONS-WORKER-130 | Backend service metadata differs | Accept only the established compatibility-order and specified capability variants; reject changed execution configuration, required compatibility, images, environment, network or unknown semantic fields |
| TC-CONS-WORKER-131 | The approved boundary tightening is observed | Preserve distinct authority hashes; verify the exact bootstrap operation, terminal chain, source/templates/parameters and full stable role cohort against current readback |
| TC-CONS-WORKER-132 | A boundary transition broadens access or substitutes evidence | Reject Allow changes, removed/weakened Deny, expanded resource exceptions, altered conditions, role/trust/identity-policy changes, forged chains or mismatched current documents |
| TC-CONS-WORKER-133 | Proof and live observations are spliced or replayed | Bind the operation, owner/fences, proof and fresh envelope in an authenticated immutable joint record; reject wrong root, generation, account, region, image, parameter or time window |
| TC-CONS-WORKER-134 | A transition proof cannot be authenticated | Reject missing/unavailable archives, arbitrary locations, malformed records, incorrect hashes or invalid semantics before admission |
| TC-CONS-WORKER-135 | Legacy control code attempts maintenance during transition | Permit only the exact pinned read-only root command and intended deployment path; reject other old control writes, continuation, promotion and worker dispatch without disrupting foreground data access |
| TC-CONS-WORKER-136 | V2 root inspection succeeds before V3 deployment | Treat it only as current DB-root/pause evidence; require the independent transition proof and joint binding, and never use it alone to authorize new operation types |
| TC-CONS-WORKER-137 | A V3 image is deployed without its verified paused witness | Keep maintenance disabled until current image/source/parameter bindings, complete live evidence and the whole certificate commitment pass |
| TC-CONS-WORKER-138 | V3 crosses producer, consumer, calibration and transport boundaries | Preserve honest authority hashes and proof identity throughout; enforce all existing payload limits and reject legacy downgrade or truncated evidence |
| TC-CONS-WORKER-139 | The control-only transition is released | Prove data Docker/COPY inputs, worker/replay, schema and frozen runtime-operator digest members unchanged; preserve all root and cumulative-budget state and complete new-head CI/preview/live validation |
