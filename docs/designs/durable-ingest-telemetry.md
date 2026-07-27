# Design Canvas: durable ingest telemetry

Feature: Durable worker metrics, dashboard, and production alarms
Date: 2026-07-27
Status: Approved (autonomous mode)

## Problem

Bedrock Mantle inference completion does not prove that an accepted memory job
reached an Aurora-backed terminal state. Operators need separate provider and
application signals without exposing memory content or unbounded identifiers.

## Metric Path

`mnemo-server` writes one-line CloudWatch Embedded Metric Format (EMF) records to
its existing `awslogs` stream. EMF records use the
`mem9-on-aws/DurableIngest` namespace. They contain metric values and only these
dimensions:

- `stage`;
- bounded `result_class`: `accepted`, `succeeded`, `retrying`, or `dead`;
- bounded `error_class`, normalized to the worker outcome allow-list or `other`.

CloudWatch Logs auto-detection in the production path extracts these records
only when `_aws` is the first root member. The emitter therefore serializes an
explicit Go envelope whose first declared JSON field is `_aws`; typed optional
fields retain required zero-valued metrics without returning to a top-level
map. `encoding/json` produces the complete line, and a mutex covers each encode,
so the implementation does not hand-build JSON and concurrent records cannot
interleave. Regression tests check the raw prefix before decoding the same lines
for schema, value, unit, dimension, bounded-cardinality, and privacy assertions.

Tenant, agent, app, session, job, request, plan, payload, fact, message, and
embedding identifiers or content are absent. Existing durable-worker log lines
also drop job IDs.

The worker outcome allow-list preserves the proxy classes
`proxy_validation_permanent`, `mantle_4xx_permanent`, `mantle_transient`, and
`deadline`, plus bounded worker/database/runtime classes. Unknown classes become
`other`.

## Application Metrics

| Metric | Unit | Emission and dimensions |
|---|---|---|
| `JobsAccepted` | Count | A newly committed job, not an idempotent duplicate; `stage,result_class` |
| `JobsSucceeded` | Count | Atomic apply committed; `stage,result_class` |
| `JobsRetrying` | Count | A retry transition committed; detailed `stage,result_class,error_class` plus a stage-only dashboard rollup |
| `JobsDead` | Count | A dead transition committed; detailed `stage,result_class,error_class` plus a separate stage-only rollup consumed by the dead-job alarm |
| `JobsTerminated` | Count | Every succeeded or dead job; `stage` |
| `DeadlineTransientTerminalFailures` | Count | `1` only for dead `deadline` or `mantle_transient`, otherwise `0`; `stage` |
| `QueueWaitMs` | Milliseconds | Acceptance to first claim only; `stage,result_class` |
| `PlanDurationMs` | Milliseconds | Application elapsed time around planning/load/save work; `stage,result_class` |
| `ApplyDurationMs` | Milliseconds | Application elapsed time around atomic apply attempts; `stage,result_class` |
| `TotalProcessingDurationMs` | Milliseconds | Claim to committed retry/success/dead transition; `stage,result_class` |
| `RetryCount` | Count | Retry ordinal on retry, or completed retry count on terminal result; `stage,result_class` |
| `OldestQueuedAgeMs` | Milliseconds | Database-clock age of the oldest `queued` or `retry_wait` row, or zero; `stage` |
| `Warnings` | Count | Persisted plan warning count on success; `stage` |
| `TruncatedFacts` | Count | Persisted truncation count on success; `stage` |
| `ZeroFactSuccess` | Count | One when smart extraction produced zero facts and apply succeeded; `stage` |

Durations clamp negative clock differences to zero. Replanning accumulates plan
time; failed/conflicting apply attempts accumulate apply time. Post-commit
webhooks and metering are outside durable processing duration.

`PlanDurationMs` is application elapsed time. It is not a Mantle or provider
latency metric.

The dashboard graphs retry volume from the additive `JobsRetrying` transition
counter's stage-only rollup. This remains a stable zero-or-value time series
after a quiet period instead of depending on a CloudWatch metric search that
forgets inactive detailed series after two weeks. `RetryCount` is an ordinal
attached to each result and must not be summed across jobs.

The queue sampler runs asynchronously, uses PostgreSQL `statement_timestamp()`,
and emits immediately at worker start and once per minute. Each query has a
five-second timeout so observability cannot block job claims. This avoids
worker/database clock skew and provides multiple samples in each five-minute
alarm period.

Application EMF is enabled only for production. Preview stages exercise the
same durable queue and worker path with an empty metric-stage setting so each
short-lived `pr-N` stage does not create permanently retained custom-metric
dimension values.

## Provider Metrics

The AWS
[Bedrock Mantle CloudWatch metrics documentation](https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-mantle-metrics.html),
verified on 2026-07-27, defines these Project-dimension metrics in
`AWS/BedrockMantle`:

- `Inferences`;
- `TotalInputTokens`;
- `TotalOutputTokens`;
- `InferenceClientErrors`.

The production dashboard places them under a "Bedrock Mantle provider" heading.
It does not reference a Mantle latency metric because AWS explicitly does not
publish `InvocationLatency` or `TimeToFirstToken` equivalents for Mantle.

Application metrics appear in a separate "Durable ingest application" section.
Production synthesis requires the out-of-band Mantle Project ID so provider
widgets and the client-error alarm cannot silently target an empty dimension.
The out-of-band GitHub Actions role must be updated with
`scripts/deploy-github-role.sh` before the first deployment that creates the
dashboard; application deployment does not update that role.

## Alarms

Every alarm targets the existing production SNS alarm topic and declares
missing-data behavior:

- `JobsDead >= 1` in one 15-minute period, missing data not breaching.
- `OldestQueuedAgeMs > 600000` for two of two consecutive five-minute periods,
  missing data not breaching. A missing sample does not prove excessive queue
  age and can occur during deploys, a disabled-worker rollback, or a transient
  database read failure.
- `DeadlineTransientTerminalFailures / JobsTerminated >= 0.10` in 15 minutes,
  gated with `IF(JobsTerminated >= 20, ratio, 0)`, missing data not breaching.
- `AWS/BedrockMantle InferenceClientErrors >= 1` in 15 minutes for the configured
  `Project`, missing data not breaching.

The obsolete `ingest_dropped` filter is removed because durable jobs now have
explicit retry and dead outcomes.

## Failure Modes And Rollback

Lifecycle EMF is emitted after the corresponding database commit and is
best-effort, not an accounting ledger. A process crash or log-write failure in
that post-commit window can omit a transition metric, so Aurora `ingest_jobs`
and the tenant-scoped job-status API remain the authoritative job state.
Serialization failures do not alter job state, and missing telemetry cannot
break ingest. Queue-age alarms only on sampled values over the threshold; it is
not a worker-liveness signal. Set `MNEMO_DURABLE_INGEST_ENABLED=0` to stop the
worker; dashboard and alarms may remain deployed without creating a false
queue-age page.
