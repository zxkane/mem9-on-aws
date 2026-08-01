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
| TC-CONSOL-006 | LLM returns a contradiction with a strictly newer winner | The loser is archived with `superseded_by` only while both timeline sides still match the scan; no delete API is called |
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
| TC-CONSOL-032 | Inspect workload boundary | ECS RunTask, constrained PassRole, SNS publish, and consolidation secret-injection role are admitted without weakening unrelated denies |
| TC-CONSOL-033 | Compare runtime emitter and docs/alarm names | EMF namespace, metric names, and `stage` dimension are identical |
| TC-CONSOL-034 | Run focused coverage gates | New runtime and infra modules exceed 80% for statements, branches, functions, and lines |
| TC-CONSOL-035 | Inspect the `llm-proxy` image build | The image installs a CA trust store before downloading the regional RDS certificate bundle over HTTPS |

## Preview E2E

| ID | Scenario | Expected result |
|---|---|---|
| TC-CONSOL-040 | Run deployed consolidation task with `--report-only --check-llm` | A content-free Mantle smoke succeeds and the task reaches STOPPED with exit code 0 |
| TC-CONSOL-041 | Query that task's CloudWatch stream | At least one `CONSOLIDATION_REVIEW_LIST` line is present |
| TC-CONSOL-042 | Inspect report-only task logs and state | Summary and content-free EMF are present; no auto mutation or SNS notification is issued |
