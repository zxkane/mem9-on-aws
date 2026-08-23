# Test Cases: weekly memory consolidation (issue #103)

Unit tests use mocked database, REST, LLM, and AWS resource constructors.
Preview E2E runs the deployed task in report-only mode.

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
| TC-CONSOL-013 | Run completes with mixed outcomes | EMF uses namespace `mem9-on-aws`, only the `stage` dimension, and the six documented metric names |
| TC-CONSOL-014 | Manual cleanup and consolidation attempt apply concurrently | The shared PostgreSQL advisory mutex admits one holder and the other exits without mutation |
| TC-CONSOL-015 | SNS review summary is published | Payload contains counts/stage only and no ids, snippets, rationale, content, embeddings, or tenant key |
| TC-CONSOL-016 | Production adapters are exercised with fake DB/REST/Mantle/SNS clients | TLS DB config, bearer refresh, mutex/archive SQL, REST LWW headers, redacted SNS payload, and shutdown are verified |
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
| TC-CONSOL-063 | State read is missing, corrupt, denied, or otherwise fails | Missing state is a valid first run; corrupt/failed reads emit `dedup_unavailable`, claim neither `new` nor `resolved`, send degraded configured notifications, and may attempt only `If-None-Match: *` so a missing key is initialized while an existing unreadable snapshot cannot be overwritten |
| TC-CONSOL-064 | First snapshot, matching-ETag update, stale ETag, and generic S3 write failure | First write uses `IfNoneMatch: "*"`, updates use the read ETag in `IfMatch`, every request uses `ExpectedBucketOwner`, and failed writes never overwrite another run |
| TC-CONSOL-065 | Inspect S3 state, SNS payload, and EMF/log markers with private memory text present | S3, SNS, metrics, and public test artifacts contain no memory text, ids, snippets, rationale, embeddings, or tenant key; private review logs and bounded private Slack samples are the only content-bearing surfaces |
| TC-CONSOL-066 | Execute two fixture-driven scheduled runs containing more than 1,000 review records | Each run posts at most one bounded digest with ten groups and three samples per group, and the second run reports the expected cross-run transitions |

## Infrastructure

| ID | Scenario | Expected result |
|---|---|---|
| TC-CONSOL-020 | Enablement flag is unset | Consolidation task exists for on-demand report-only runs; schedule and scheduler role are absent |
| TC-CONSOL-021 | Enablement flag is set in preview | Schedule and scheduler role exist, but schedule state is `DISABLED` |
| TC-CONSOL-022 | Enablement flag is set in production | Weekly Sunday 03:00 UTC schedule is `ENABLED` with flexible window off and overrides the exact task container to `MEM9_CONSOLIDATION_REPORT_ONLY=0` |
| TC-CONSOL-023 | Inspect task definition | arm64 task pins the `llm-proxy` image tag, `node /app/memory-consolidation.mjs` entrypoint, and contains no secret literal |
| TC-CONSOL-024 | Inspect task role | Mantle actions, scoped SNS publish, and log/EMF writes are present; no wildcard secret read is present |
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
| TC-CONSOL-067 | Inspect task defaults and Scheduler override | The task definition has no scheduled marker; only the Scheduler override sets `MEM9_CONSOLIDATION_SCHEDULED=1`; manual apply and preview report-only paths therefore cannot touch digest state or Slack |
| TC-CONSOL-068 | Slack approval is disabled or enabled | Disabled consolidation injects no Slack token/channel; enabled consolidation reuses the existing bot-token parameter and private channel without duplicating secrets |
| TC-CONSOL-069 | Inspect consolidation task IAM and workload boundary | The task has only stage-scoped digest `s3:GetObject`/`s3:PutObject`, no list/delete, matching KMS context permissions, and the existing boundary admits the path |
| TC-CONSOL-070 | Inspect the operator-owned bucket lifecycle | `decisions/` retains its three-day expiry and `consolidation-digests/` has a separate expiry of at least 70 days |

## Preview E2E

| ID | Scenario | Expected result |
|---|---|---|
| TC-CONSOL-040 | Run deployed consolidation task with `--report-only --check-llm` | A content-free Mantle smoke succeeds and the task reaches STOPPED with exit code 0 |
| TC-CONSOL-041 | Query that task's CloudWatch stream | At least one `CONSOLIDATION_REVIEW_LIST` line is present |
| TC-CONSOL-042 | Inspect report-only task logs and state | Summary and content-free EMF are present; no auto mutation or SNS notification is issued |
| TC-CONSOL-045 | The operator script, task definition, and Dockerfile each name the consolidation entrypoint | All three agree on `/app/scripts/memory-consolidation.mjs`, and neither the script nor the task definition still references the flattened `/app/` path (they drifted once: the image fix moved the file but the operator script kept the old path, and each file was only asserted in isolation) |
| TC-CONSOL-046 | Schedule-group name prefix for realistic stages | Every prefix stays within EventBridge Scheduler's 38-character `name_prefix` limit and keeps the `mem9-on-aws-` prefix the deploy role is scoped to; an overlong stage throws at synth rather than at deploy |
| TC-CONSOL-047 | Scheduler role name against its three intersecting constraints | The name is within IAM's 64-character limit, matches the already-deployed boundary pattern `mem9-on-a*-*Mem9ConsolidationSchedulerRole-*`, and starts with `mem9-on-aws-` for `iam:CreateRole`; an overlong stage throws |
| TC-CONSOL-071 | Run the preview report-only harness with digest configuration present | It exits zero only when `CONSOLIDATION_REVIEW_LIST` reports `digestEnabled: false`, proving the path performs no S3 digest-state, Slack, or SNS review-digest operation |
