# Alarming on a scan that offers zero ids (#154)

A scheduled cleanup scan whose consensus DELETE set is empty writes the offered
record, posts nothing, exits 0, and nothing reports it. That is correct for a
genuinely quiet week and indistinguishable from a classifier that degraded far
enough to collapse the consensus without tripping `classifierBroken` — which
needs **every** batch to fail. The measured basis: one pass reproduced only 66%
of its own DELETE set on re-run, so a *partial* degradation can empty the
intersection while every batch still "succeeds".

## The constraint that shapes everything below

A CloudWatch alarm's total evaluation window is capped at 604,800 s — seven days
— for `Period` × `EvaluationPeriods` ([PutMetricAlarm][putmetricalarm]). The scan
is weekly (`CLEANUP_SCAN_CRON`), so consecutive runs are seven days apart, and a
window that is *guaranteed* to contain two of them has to be longer than seven
days. `period=604800, evaluationPeriods=2` is 1,209,600 s and is rejected;
`period=86400, evaluationPeriods=7, datapointsToAlarm=2` is a seven-day window
that holds one weekly run, so the second breaching datapoint never exists. So no
single alarm can be relied on to see both runs, and ">= 2 consecutive zero-offer
weeks" is not expressible in one by any combination of `period`,
`evaluationPeriods`, `datapointsToAlarm`, or metric math; latching flips on the
first quiet week, and a composite alarm combines instantaneous child states
(`ALARM(A) AND ALARM(A)` is `A`) with no accumulator.

So memory spanning two runs — more than the seven days an alarm can see — has to
be persisted somewhere. This design puts the smallest possible amount of it in
SSM and keeps the alarm dumb.

[putmetricalarm]: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html

## Shape

```
scan run ──► offered record  (approvals/offered, unchanged)
        ├──► week record     (approvals/scan-outcome-<iso-week>, new)
        ├──► reads the last 4 week records ──► quietWeeks (pure function)
        └──► one JSON log line {event, stage, isoWeek, offered, quietWeeks, scanRan:1}
                    │
                    ├─ LogMetricFilter → QuietScanWeeks ─► alarm: >= 2
                    └─ LogMetricFilter → ScanRan ────────► alarm: FILL(...,0) < 1
```

### Per-week record, not a counter

Key: `{prefix}/approvals/scan-outcome-<iso-week>`, value
`{"stage","isoWeek","offered","at"}`. One key per ISO week means a same-week
retry is an idempotent rewrite rather than a read-modify-write, so there is no
double-increment race to defend, and a corrupted or deleted key costs one week
of history instead of the series. It also needs **no new IAM**: the scan task
role already holds `ssm:GetParameters` + `ssm:PutParameter` on
`{prefix}/approvals/*`, and the workload permissions boundary — which renders
near IAM's non-adjustable 6144-character ceiling — is untouched.

These records are the alarm's only memory. Deleting them as "stale" silently
resets the streak; they are not pruned by this change (~52 small parameters per
year per stage, far inside the SSM quota).

### The streak is derived, never incremented

`quietWeekStreak` is a pure function over the last N (4) week records, newest
first, recomputed from scratch every run: count contiguous **present**
zero-offer records ending at the current week. An **absent** record does not
extend the streak — the semantics are asserted rather than left implicit,
because the natural mistake (skip the gap and keep counting) would *invent*
contiguity: a week whose record was never written would then be treated as quiet,
and two real quiet weeks either side of it would page as a streak of three. That
is a false **positive**, and the issue text called it a false negative; the
direction matters, because it is the reason absence breaks the streak rather than
being tolerated.

One `isoWeek` function serves both the writer and the reader. A W52/W53
disagreement between two implementations would produce a *permanent* false
negative — the alarm would never fire again — so the ISO week-numbering year is
derived the ISO-8601 way (from the Thursday of the week) and the year-boundary
cases are asserted directly.

### A read failure is loud and never rounds down

The scan computes the number its own alarm reads, so the failure mode to design
against is a read that silently yields a *lower* count. Absence and error are
distinguished: an absent parameter comes back in `InvalidParameters` and
legitimately breaks the streak, while a thrown read — or a record whose value
will not parse, which is corruption rather than legitimate absence — emits its
own log line, publishes **no** streak value at all, and exits non-zero so the
existing task-exit alarm fires. A failed *write* of this week's record is
reported the same way, for the same reason: next week would read this week as
absent. A zero-id scan still exits 0 — a quiet week is not a failure, and
exiting non-zero there would page every quiet week.

### Bookkeeping runs last and never throws

The week record and the streak are handled **after** the offered record is
written and, when non-empty, after the message is posted; `recordScanOutcome`
returns its failures instead of throwing. Both properties exist to keep one
ordering true: an alarm's input must never be able to stop an operator's review
list from being offered. Running earlier would let a failed parameter write
block the post, and throwing would surface a telemetry fault through
`runCleanup`'s offer-failure branch as "failed to offer the review list to
Slack".

### Why a JSON line in addition to the existing lines

The existing `offered N id(s) …` and `no deletions to offer; posted nothing to
Slack` lines survive verbatim; other consumers parse that format. A metric
filter cannot use the `{ $.field = ... }` form on them, because
`[memory-cleanup <iso>] <message>` is not JSON. The new line is emitted
unprefixed, on its own, carrying both metrics the two alarms need — which is
also why neither alarm costs the task any IAM: a log-filter metric needs no
`cloudwatch:PutMetricData`, and the scan role must not acquire one.

### Two alarms, and why the second one exists

| Alarm | Metric | Shape |
|---|---|---|
| streak | `QuietScanWeeks` (`$.quietWeeks`) | `>= 2`, `period=604800`, `evaluationPeriods=1` (exactly at the cap, therefore legal), `treatMissingData: notBreaching` |
| liveness | `ScanRan` (`$.scanRan`) | `FILL(scan_ran, 0) < 1`, `period=604800`, `evaluationPeriods=1`, armed only where the schedule is `ENABLED` |

The streak alarm alone fails open: if the scan never runs — schedule flipped to
`DISABLED`, broken task definition, scheduler misconfiguration — no metric is
published and `notBreaching` keeps it green forever. That is the same
"silence reads as health" defect one layer up, and the ECS task-exit alarm
cannot see a task that never started. `FILL` turns a missing datapoint into a
concrete breaching value, which `treatMissingData` cannot do
(`DurableIngestTelemetryLivenessAlarm` in `infra/observability.ts` is the
precedent). It arms only on stages whose schedule state is `ENABLED` — today
`prod` — or every other stage would page continuously.

**No volume guard, deliberately.** A volume guard protects a *rate's*
denominator; `quietWeeks` is a count of consecutive discrete runs with exactly
one run per period by construction, so the "high zero rate on low volume"
failure the ingest precedent guards against cannot arise. A guard here would
*suppress* genuine signal. The omission is documented at the alarm declaration
so it is not "restored" by analogy.

## Rejected

- **A single alarm whose window spans two runs** — it would have to exceed seven
  days, which is over the hard cap.
- **A counter parameter** — read-modify-write on a path with retries.
- **An independent scheduled evaluator** reading metrics instead of the scan
  deriving its own count. It would decouple watcher from watched, but costs a
  new principal, `cloudwatch:GetMetricData`, and a second scheduled resource,
  to buy independence against SSM read failure — a failure mode that barely
  overlaps the classifier degradation this targets, and one the loud read-error
  path already covers. Revisit only if the coupling bites.
- **Separating "consensus collapsed" from "nothing to delete"** at the
  classifier level. Still the same observable event here; splitting it is a
  larger change to `consensusDecisions` than this needs.
