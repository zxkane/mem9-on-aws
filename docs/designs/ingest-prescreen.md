# Design: durable-ingest pre-screen evaluation

Feature: evaluate possible zero-fact durable-ingest pre-screens
Status: shadow scoring; active skipping is not enabled by this design

## Decision

Keep extraction behavior unchanged. The `msg-count-le-1-v1` shadow policy
evaluates whether `message_count <= 1`, then compares that decision with the
actual extraction outcome. A shadow match never suppresses extraction.

A future active policy needs a separately reviewed proposal, a fresh temporal
holdout, zero observed false skips, a cluster-aware one-sided 95% upper bound
no greater than 0.5%, and a skip rate of at least 10%. Offline candidate
selection is evidence for review, not an activation switch.

## Evaluation protocol

- **Scope:** one explicit namespace. Both jobs and retained plans compare to
  the supplied namespace, and the plan lookup also matches its parent job.
- **Population:** succeeded smart-ingest jobs with applied plans inside an
  operator-selected time window. Use plan application time for label validity.
- **Label boundary:** the operator supplies the earliest time at which the
  persisted `zero_fact` label is authoritative. The field uses `omitempty`;
  absence in an older plan cannot establish that extraction produced facts.
- **Ground truth:** count a fact-producing result as a false skip even when
  reconciliation later finds the fact already present.
- **Partitioning:** hash tenant/agent/app/session scope inside PostgreSQL,
  falling back to the job ID when no session exists. Modulo-five assignment
  puts repeated windows from one transcript into the same partition.
- **Candidate selection:** choose on tuning data before evaluating held-out
  labels. The query orders eligible rules by skipped-session rate, skipped-rune
  share, and rule name. Do not tune again against the held-out outcomes.
- **Uncertainty:** the query's Wilson calculation is an offline summary.
  Repeated windows can be correlated; future activation must account for
  transcript-session clustering and use a new holdout after policy selection.

The public implementation is
[`scripts/analyze-ingest-prescreen.sql`](../../scripts/analyze-ingest-prescreen.sql).
It requires `namespace_id`, `analysis_cutoff`, and `label_start`; none is
inherited from an operator deployment. Missing inputs fail before source-table
reads. `window_days` defaults to 30.

## Operator execution and privacy

Run from an authorized private database path with a read-only database role
that can create session-local temporary objects. Configure database connection
settings and an owner-only `PGPASSFILE` outside source control. For example:

```bash
: "${NAMESPACE_ID:?Select the authorized namespace}"
: "${ANALYSIS_CUTOFF:?Set the exclusive analysis cutoff}"
: "${LABEL_START:?Set the label-validity boundary}"
: "${PGPASSFILE:?Set an owner-only password-file path}"

psql --set=namespace_id="$NAMESPACE_ID" \
  --set=analysis_cutoff="$ANALYSIS_CUTOFF" \
  --set=label_start="$LABEL_START" \
  --set=window_days=30 \
  --file scripts/analyze-ingest-prescreen.sql
```

The query creates empty temporary structures before reading source tables in
a read-only transaction. Message and action text stays in temporary feature
queries. Its bounded JSONL output excludes content, source identifiers, and
hashes, but aggregates and renamed real records still belong to the operator.
They are not synthetic evidence and must not be posted in public issues or PRs.

Public verification must use constructed fixtures with documented generation
parameters. Cover empty inputs, mixed outcomes, repeated-session grouping,
label boundaries, invalid/missing parameters, and foreign-namespace rows.
Do not copy an operator's cohort sizes, dates, token usage, outcome tables,
or false-skip examples into the fixture.

## Placement

The durable ingest worker is the intended location for any future active
policy. It has canonical messages, durable job ownership, and extraction
outcomes, so it can preserve namespace scope and atomic job semantics.
The existing shadow implementation is downstream patch
`0008-ingest-prescreen-shadow`; upstream updates must apply the entire current
patch stack and run the patched Go and PostgreSQL suites.

Client-side filtering cannot provide one authoritative outcome across all
callers. The LLM proxy sees formatted model requests rather than canonical
job ownership and cannot atomically complete an ingest job. Neither is an
activation path in this design. Deferring/coalescing sessions is a separate
queueing proposal with its own freshness and idempotency requirements.

## Shadow observability

Keep extraction unchanged and emit bounded metrics after the outcome is known:

- `PrescreenEvaluated`: an eligible smart-ingest plan was evaluated.
- `PrescreenWouldSkip`: the shadow rule matched.
- `PrescreenFalseSkip`: the rule matched and extraction produced facts.

Dimensions contain only stage and a bounded policy version. Do not use content,
identifiers, hashes, measured lengths, or lexical matches as dimensions.
Would-skip and false-skip rates are separate from `ZeroFactSuccess`; shadow
matches do not imply realized token or cost savings.

A future active implementation additionally needs an explicit persisted skip
reason, an `IngestSkippedPrescreen` metric, a rollback flag defaulting to
pass-through, and review of affected quality dashboards. This document contains
the reusable protocol, not deployment-specific evaluation results.
