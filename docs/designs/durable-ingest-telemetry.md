# Design Canvas: durable ingest telemetry

Feature: Durable worker metrics, telemetry liveness, dashboard, and production alarms
Date: 2026-07-27
Status: Approved (autonomous mode)

## Problem

Bedrock Mantle inference completion does not prove that an accepted memory job
reached an Aurora-backed terminal state. Operators need separate provider and
application signals without exposing memory content or unbounded identifiers.
Queue-age samples also cannot distinguish an empty or healthy queue from a
broken ECS-to-CloudWatch EMF path when every sample disappears. Telemetry
liveness therefore needs its own continuously emitted signal and alarm.

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

The synthesized `mnemo-server` container explicitly sets
`pseudoTerminal=false`. The service is non-interactive, and omitting the TTY
keeps the emitter's LF record boundary from being translated to CRLF before the
`awslogs` driver splits events. The two sidecar terminal settings are unchanged.
A named arm64 image smoke captures one real sampler record through Docker with
the same non-TTY setting and validates its exact local bytes. This smoke covers
the container stdout contract only; post-deploy CloudWatch extraction remains a
separate production verification.

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
| `SamplerHeartbeat` | Count | Exactly one before each once-per-minute queue sampler query, including failed queries; `stage` |
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

The queue sampler runs asynchronously, emits immediately at worker start and
once per minute, and extends the existing EMF emitter with a dedicated
`SamplerHeartbeat()` operation. Each tick writes a separate
`SamplerHeartbeat=1` record before querying PostgreSQL. The heartbeat therefore
proves that the worker sampler and its ECS `awslogs` EMF path are live even when
the queue-age query fails. A successful query separately emits
`OldestQueuedAgeMs`, using PostgreSQL `statement_timestamp()`. Each query has a
five-second timeout so observability cannot block job claims. Both records are
content-free and carry only the fixed production `stage` dimension.

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
dashboard or composite liveness alarm; application deployment does not update
that role.

## Alarms

Every action-bearing alarm targets the existing production SNS alarm topic, and
every metric alarm declares missing-data behavior:

- `JobsDead >= 1` in one 15-minute period, missing data not breaching.
- `OldestQueuedAgeMs > 600000` for two of two consecutive five-minute periods,
  missing data not breaching. A missing sample does not prove excessive queue
  age and can occur during deploys, a disabled-worker rollback, or a transient
  database read failure.
- `FILL(SamplerHeartbeat, 0) < 1` for five of five consecutive one-minute
  periods, with missing data also configured as breaching. A value of one is
  healthy; five sustained missing samples or malformed zero-valued samples
  make the raw liveness alarm enter `ALARM`. This raw alarm has no actions.
- `DeadlineTransientTerminalFailures / JobsTerminated >= 0.10` in 15 minutes,
  gated with `IF(JobsTerminated >= 20, ratio, 0)`, missing data not breaching.
- `AWS/BedrockMantle InferenceClientErrors >= 1` in 15 minutes for the configured
  `Project`, missing data not breaching.

The obsolete `ingest_dropped` filter is removed because durable jobs now have
explicit retry and dead outcomes.

CloudWatch sliding alarms retrieve a wider evaluation range and can substitute
older real datapoints before applying `treatMissingData`. The heartbeat alarm
uses metric math to turn every current missing period into an explicit zero, so
older healthy heartbeats cannot silently extend the five-minute evaluation
bound. Requiring all five periods to breach means one normally delayed latest
sample does not alarm while the preceding four heartbeats are present.

### Bounded action enablement

The action-bearing telemetry-liveness alarm is a composite over the raw
heartbeat alarm. CloudWatch composite action suppression requires a suppressor
alarm, so a stage-scoped action-delay guard observes the same fixed heartbeat
with an impossible healthy-domain threshold (`SamplerHeartbeat < 0`) and treats
missing data as non-breaching. The fixed emitter value is one, so the guard
remains `OK`; it exists only to activate the composite alarm's documented
`ActionsSuppressorWaitPeriod`.

The composite waits at most 300 seconds for that guard to enter `ALARM`. If it
remains in `ALARM`, the wait expires and its ALARM action runs. CloudWatch
discards that wait and starts another when the composite returns to `OK`; the
composite deliberately has no OK action, so recovery during the grace period
cannot produce a notification without a preceding page. The extension period
is zero. This gives both deployment modes a bounded contract:

- On initial enablement, historical heartbeat periods are absent and the raw
  alarm can immediately enter `ALARM`. The composite withholds notification for
  five minutes. One real ECS-origin sampler heartbeat makes the five-of-five raw
  alarm non-breaching before the wait expires and no action runs. If no sampler
  heartbeat is extracted, notification is released after the fixed wait.
- During a routine rolling deployment, fewer than five missed one-minute
  samples do not change the raw alarm to `ALARM`. A longer interruption starts
  the same fixed composite wait, and a resumed ECS-origin sample clears the raw
  alarm. Current missing periods are explicit zeroes, so older pre-deploy
  heartbeats cannot defer the transition. Sustained loss becomes actionable
  after at most five evaluation minutes plus the five-minute action wait.

There is no manual actions-disabled mode, deployment marker, or successful
direct `PutLogEvents` probe in this contract. Such a probe can validate an AWS
API shape, but it is not evidence that the once-per-minute ECS sampler path is
live. `AWS/Logs` EMF parsing and validation error metrics remain useful
diagnostics but are not inputs to the liveness alarm.

## Failure Modes And Rollback

Lifecycle EMF is emitted after the corresponding database commit and is
best-effort, not an accounting ledger. A process crash or log-write failure in
that post-commit window can omit a transition metric, so Aurora `ingest_jobs`
and the tenant-scoped job-status API remain the authoritative job state.
Serialization failures do not alter job state, and missing telemetry cannot
break ingest. Queue-age alarms only on sampled values over the threshold; it is
not a worker-liveness signal. The independent heartbeat alarm intentionally
pages after its bounded window when telemetry is disabled or lost. Set
`MNEMO_DURABLE_INGEST_ENABLED=0` only with an operator-approved alarm
maintenance window; leaving the liveness alarm enabled correctly reports that
the production sampler contract is absent.
