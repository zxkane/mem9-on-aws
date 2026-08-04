# Design Canvas: weekly memory consolidation

Feature: weekly contradiction, fragment, and staleness consolidation (issue #103)
Date: 2026-08-01
Status: Approved (autonomous mode)

## Problem

Ingest reconciliation compares new facts only with similar existing memories.
It does not compare existing memories with each other, so contradictions,
same-topic fragments, and facts made stale by time can remain active forever.

The consolidation task is not a second durability filter. The one-shot cleanup
tool owns old ingest noise. This task periodically evaluates relationships among
active memories while preserving a review boundary for low-confidence actions.

## Runtime Architecture

```text
EventBridge Scheduler group + schedule (weekly, explicit enablement only)
  -> scheduler execution role
  -> ECS RunTask in the existing private cluster
  -> consolidation container (llm-proxy image, dedicated entrypoint)
       -> Aurora: advisory mutex + active ids/content/embeddings
       -> GLM-5 on Bedrock Mantle: cluster decisions
       -> mnemo-server REST:
            PUT survivor content (MERGE)
            batch-delete absorbed fragments (MERGE contract)
            PUT stale tags/metadata
       -> Aurora optimistic state='archived' update for a timeline loser
       -> stdout: review records + content-free EMF
       -> SNS topic: content-free review summary -> existing Slack router
```

The task reuses the `llm-proxy` image because that image already contains the
Node 24 Mantle authentication dependencies. Its task definition overrides the
entrypoint to `node /app/memory-consolidation.mjs`; the normal service keeps its
existing `server.mjs` entrypoint.

## Enablement

- `MEM9_CONSOLIDATION_SCHEDULE_ENABLED=1` is the only synthesis gate.
- Without the flag, the schedule group, schedule, and scheduler execution role
  do not exist.
  The task definition still exists so an operator and preview CI can run a
  report-only pass.
- With the flag in a preview, the schedule resource exists but its state is
  `DISABLED`. This proves synthesis without allowing unattended preview writes.
- With the flag in production, the schedule is `ENABLED` and runs at a fixed
  Sunday 03:00 UTC low-traffic window.
- Production enablement remains an operator decision after initial cleanup and
  a useful report-only run. No code path flips the flag automatically.

AWS documents that Scheduler uses an execution role to invoke a target and that
an ECS target role needs `ecs:RunTask` plus `iam:PassRole` for each task and
execution role:

- https://docs.aws.amazon.com/eventbridge/latest/userguide/using-eventbridge-scheduler.html
- https://docs.aws.amazon.com/AmazonECS/latest/developerguide/CWE_IAM_role.html

## Discovery And Clustering

The REST representation intentionally omits embeddings. The task therefore
reads active memory ids, content, metadata, timestamps, versions, and embeddings
from the operator-owned Aurora database. It does not send embeddings or memory
content outside the AWS account.

Embeddings are normalized and compared with cosine similarity. Connected
components above the configured threshold form clusters. Singletons old enough
for their memory-type staleness rule are retained as one-item clusters so GLM-5
can classify staleness without inventing contradictory evidence.

GLM-5 receives only one bounded cluster at a time. A component above 50
memories or 200,000 content characters is deferred to review before inference.
It returns structured actions:

- `MERGE`: survivor id, absorbed ids, canonical content, rationale.
- `CONTRADICTION`: the two ids, optional winner id, rationale.
- `STALE`: one id and rationale.
- `DELETE`: one or more ids and rationale.
- `KEEP`: no mutation.

Unknown ids, malformed responses, conflicting actions (including KEEP versus a
mutation), and invalid merge graphs degrade to review or skip. They never
become mutations. If every attempted cluster classification fails, the task
still emits review/EMF records but exits nonzero.

## Action Tiers

### Auto-execute

At most 20 logical mutations are issued in one run:

- MERGE uses the cleanup tool's hash-anchored contract. The survivor is PUT
  first and each unchanged absorbed fragment is then soft-deleted. Cost is one
  for the PUT plus one per absorbed id.
- A contradiction is archived only when the LLM-selected winner is strictly
  newer than the loser and an atomic SQL predicate confirms both sides still
  match their scanned versions/content.
  The database update is `state='archived'`, never `state='deleted'`, and records
  `superseded_by`.
- Staleness marking first enforces the memory type's age threshold, then
  preserves content and existing metadata/tags while adding the bounded `stale`
  tag and consolidation metadata through PUT.

The full cost of an action must fit before its first mutation. Once the cap is
reached, remaining otherwise-safe actions become review items for a later run.

### Review-only

The following are always review records and never enter the mutation dispatcher:

- every `DELETE`, regardless of model confidence or other fields;
- a contradiction without a unique winner whose `created_at` and `updated_at`
  are both strictly newer, or whose pair carries a prior consolidation stale
  marker;
- malformed or conflicting decisions that name real memories;
- safe actions deferred by the cap.

Each review line is a single structured stdout record prefixed
`CONSOLIDATION_REVIEW`. It contains ids, bounded snippets, and rationale, so the
records persist in CloudWatch Logs. Review content is never written to task
ephemeral storage, repository artifacts, issues, PRs, or metrics.

The SNS message contains counts only. It uses the existing alarm-shaped payload
accepted by the SNS-to-Slack alert router. Approved DELETE ids remain a manual
`memory-cleanup.mjs --apply --ids` operation.

## Concurrency And LWW

Manual cleanup and scheduled consolidation use the same PostgreSQL advisory-lock
key, `mem9-cleanup:<stage>`, held on a dedicated connection for the entire apply
phase. PostgreSQL releases the lock if a process or task dies. Report-only runs
do not take the apply mutex.

Every mutation re-reads or atomically predicates current state:

- REST mutations compare version and SHA-256 content anchors before PUT/delete.
- Archive uses one optimistic SQL statement constrained by id, active state,
  version, and original content.

This preserves the cleanup tool's last-writer-wins guard while closing its
previous cross-host mutex gap.

### The MERGE survivor rewrite is fenced (issue #128)

Both legs of a MERGE are now version-predicated, by different mechanisms:

- **Absorbed deletes** are guarded client-side. Each id is re-read and dropped
  from the delete set unless its version AND content hash still match the plan
  (`applyMergeDecision`), so a concurrently-edited absorbed memory is never
  deleted. Unchanged by #128.
- **The survivor rewrite** is fenced server-side. It sends
  `If-Match: <version>`, and patch 0008 makes that header **authoritative**:
  the service passes it to `UpdateOptimistic` as the expected version, so the
  predicate rides in the SAME `UPDATE ... WHERE id = $ AND version = $N` that
  writes the content. A mismatch returns **412** and writes nothing.

Because the predicate and the write are one statement, no interleaving can make
the rewrite clobber a newer row: either the merged content lands, or the caller
gets a 412 and nothing was written. That closes the race rather than narrowing
it. Previously the header was advisory — a mismatch only logged a server-side
warning, and an ingest write landing between the survivor's GET and its PUT was
silently overwritten by the merged content.

To be precise about where the safety comes from, since it is not the pre-read:
upstream's `Update` does a pre-read, compares the version, embeds, then issues
the predicated `UPDATE`. A write can still land between the compare and the
`UPDATE`, and it is the predicate — not the compare — that catches it (see
`TestUpdateLosingTheVersionPredicateRaceReportsConflict`). The compare only
saves a wasted embedding call on the common case.

On a 412 both callers (`scripts/memory-cleanup.mjs` from the CLI and
`scripts/memory-consolidation.mjs` from the scheduled task, which share
`applyMergeDecision`) abandon the **whole** merge: `skippedLww` increments, the
absorbed ids are left active, and the run continues. Abandoning both legs is the
point — absorbing the fragments after a rejected rewrite would delete content
the survivor never received. A 412 is not a failure; any other non-2xx still
propagates and aborts the run.

A fence only works if a version is available to send. `restAdapter` omits
`If-Match` when the version is falsy, and upstream's column is
`version INT DEFAULT 1` — **nullable**; this repo's bootstrap hardening
(`NOT NULL` + `CHECK (version > 0)`) is conditional on the table already
existing, so it is skipped when the migration runs before mnemo-server creates
it. An unfenceable version would therefore send no precondition and silently
fall back to last-writer-wins, and it would slip the client-side guard too,
because `current.version !== action.version` is false when both sides are null.

This guard is **defense in depth, not the only barrier**, and it is worth being
precise about what is actually reachable. Every upstream insert hardcodes
`Version: 1`, so a NULL row requires out-of-band SQL; and because upstream scans
`version` into a plain Go `int`, a true NULL fails loud on any REST read
(`converting NULL to int is unsupported`) rather than arriving as a null. This
task is the one that could still see it, because it reads the column with direct
SQL, where node-pg surfaces NULL as `null`. The cases that degrade *silently* —
and so genuinely need the guard — are a non-positive or non-integer version,
such as a hand-run `UPDATE ... SET version = 0`. So
`routeActions` disqualifies any MERGE whose survivor or absorbed side lacks a
positive integer version, routing it to `UNFENCEABLE_MERGE` review instead of
auto-applying it (TC-CONSOL-050). The SQL-based archive and stale-marking legs
need no equivalent guard: they carry the version in a `WHERE` clause, so a null
matches no row and already fails closed into `skippedLww`.

The cleanup tool needs the same guard in two places, because it has two ways to
obtain a decision. On the replay path `validateDecisions` refuses a loaded file
whose MERGE lacks a version anchor (TC-MEMCLEAN-048). On the fresh-scan path
`planDecisions` builds the anchors itself, so it degrades an unfenceable memory
to `SKIP` (TC-MEMCLEAN-051) — a `SKIP`, not a throw, so one bad row cannot abort
an otherwise-valid audit. Without it the run would send `If-Match: "null"` and
take patch 0008's 400 mid-apply, possibly after earlier decisions had already
deleted rows.

The survivor's embedding stays correct because the rewrite remains a
content-bearing REST PUT, which is what makes upstream re-embed. A direct-SQL
rewrite (the alternative considered) would have stranded a stale embedding: on
postgres, mem9 re-embeds only when a PUT changes content, the repository writes
`embedding` unconditionally, and the postgres scanner never populates
`m.Embedding`. Computing the embedding in the consolidation task instead would
have required reaching the embedder on `:8081` inside the mnemo-server task,
which the task security group does not permit — so it would have meant a new SG
ingress rule widening the data-plane surface. This design needs none.

Residual risk, unchanged: the advisory mutex (`mem9-cleanup:<stage>`) excludes
other cleanup/consolidation runs but NOT live ingest, so a concurrent ingest
edit still *skips* a merge. That is now a safe, observable outcome rather than
silent data loss. The weekly schedule still targets the lowest-ingest hour
(Sunday 03:00 UTC), the auto tier is still capped at 20 mutations per run, and a
rising `skippedLww` remains the signal to look at.

## Metrics And Failure Detection

One content-free EMF line is emitted per run in namespace `mem9-on-aws` with
only the `stage` dimension:

- `ConsolidationScanned`
- `ConsolidationMerged`
- `ConsolidationArchived`
- `ConsolidationFlaggedStale`
- `ConsolidationReviewItems`
- `ConsolidationSkippedLww`

In production, an ECS task-state EventBridge rule captures STOPPED events for the exact
consolidation task definition when any container exit code is non-zero. It
writes a redacted event projection to a dedicated CloudWatch log group. A metric
filter emits a stage-scoped failure metric, and a CloudWatch alarm targets the
existing SNS/Slack topic. The log resource policy follows AWS's documented
EventBridge target contract by granting `logs:CreateLogStream` and
`logs:PutLogEvents` to both `events.amazonaws.com` and
`delivery.logs.amazonaws.com` on only that log group. Preview CI checks the task
exit directly and does not consume an account-level Logs resource policy. AWS
documents the ECS task state-change event and its container exit-code fields:

https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs_task_events.html

## IAM

- Consolidation task role: Mantle inference, content-free log/EMF writes, and
  scoped SNS publish to the existing alert topic.
- Consolidation execution role: ECR/log startup permissions from SST plus the
  two Secrets Manager references injected by ECS.
- Scheduler role: `ecs:RunTask` on the exact task definition and `iam:PassRole`
  on only the consolidation task/execution roles, conditioned on
  `iam:PassedToService=ecs-tasks.amazonaws.com`. Its trust policy accepts only
  the deploying account's dedicated consolidation schedule group.
- Deploy role: separately scoped schedule and tagged schedule-group lifecycle
  actions, plus `iam:PassRole` for the scheduler role conditioned on
  `scheduler.amazonaws.com`.
- Every new role receives the retained workload permissions boundary. The
  boundary adds only the actions/resources needed by these exact paths.

## E2E

Preview CI creates a disabled schedule and runs the task once with a
`--report-only --check-llm` container command override. The content-free smoke
proves live Mantle bearer, IAM, and model connectivity even when no preview
memory forms a cluster. The harness waits for STOPPED, requires exit code zero,
then queries the task log stream for the mandatory `CONSOLIDATION_REVIEW_LIST`
summary line. Report-only suppresses MERGE, archive, stale, and notification
writes.
