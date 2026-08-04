# Design: durable-ingest pre-screen evaluation

Feature: Pre-screen zero-fact durable ingest calls
Date: 2026-07-31
Status: Approved (autonomous mode)

## Decision

Do not implement an active heuristic pre-screen. The tuning-selected rule,
`message_count <= 1`, skipped 10.25% of held-out jobs but falsely skipped
3 fact-producing jobs. Its held-out false-skip rate was 0.4392%, with a
one-sided 95% Wilson upper bound of 1.0939%. This fails the explicit
acceptance requirement of zero false skips and an upper bound no greater than
0.5%.

Active expected token savings are therefore **0%**. The counterfactual rule
would remove 10.25% of extraction calls and 9.74% of transcript runes, but it
would lose extraction output for 3 of 74 held-out fact-producing jobs
(4.05%). The provider token metric includes extraction, reconciliation, and
other project calls, so it cannot turn this counterfactual into an exact
project-level token or cost reduction.

The follow-up is
[shadow-only scoring and audit metrics](https://github.com/zxkane/mem9-on-aws/issues/106).
It must score the selected rule without suppressing extraction. A future
active proposal requires a fresh temporal holdout, zero observed false skips,
and a cluster-aware one-sided 95% upper bound no greater than 0.5%; shadow
disagreement data may support a more selective rule or lightweight classifier.

## Evaluation Protocol

The population, cutoff, label derivation, original candidate thresholds, and
decision gate were fixed before the initial selection. Review then identified
three protocol defects: the per-job split could leak repeated windows, empty
message arrays needed explicit preservation, and user-message share had not
been evaluated separately. The final query corrects those defects and reruns
the complete analysis with a scope-grouped split.

Because those corrections were made after earlier outcomes had been inspected,
the final held-out table is a **post-hoc sensitivity analysis**, not a
confirmatory holdout. It is sufficient to reject active skipping because the
corrected rule has observed false skips. It must not be used to approve a rule;
future activation requires a fresh temporal holdout whose split and policy are
frozen before labels are read.

- **Population:** all production `smart` ingest jobs with a succeeded,
  applied plan in the trailing 30 days before
  `2026-07-31T10:00:00Z`, restricted to the period in which the persisted
  `zero_fact` label is authoritative. The fixed lower bound is
  `2026-07-27T06:00:00Z`, the coarsened interval after the patched ECS
  deployment reached steady state. The filter uses plan application time, not
  job creation time. This yields every label-valid job in the window, 1,052
  jobs, and exceeds the minimum of 500.
- **Source:** canonical `messages` payloads in Aurora `ingest_jobs` joined to
  the latest applied plan in `ingest_job_plans`. The temporary feature rows
  retain both tenant and job keys because plans use the composite
  `(tenant_id, job_id, plan_revision)` primary key. Neither key is emitted.
- **Ground truth:** the applied plan JSON's `zero_fact=true` is zero-fact.
  `zero_fact` uses `omitempty`, so its absence after the label boundary means
  extraction produced at least one fact. Older plans are excluded because an
  absent field cannot distinguish their outcomes. A fact-producing result is
  conservatively counted as a false skip even when reconciliation would have
  found the fact already present.
- **Split:** MD5 of the tenant/agent/app/session scope modulo five, computed
  inside PostgreSQL; jobs without a session use their job ID as a fallback.
  Remainder zero is tuning and remainders one through four are held out. This
  keeps repeated windows from one transcript session in one partition. Uneven
  scope sizes produce 369 tuning jobs and 683 held-out jobs rather than an
  exact 20/80 job split. IDs and hashes are never emitted.
- **Selection:** among the fixed candidate rules, choose the highest tuning
  skip rate with zero tuning false skips. Ties use skipped-rune share and then
  rule name.
- **Decision gate:** on held-out data, zero false skips, one-sided 95% Wilson
  upper confidence bound for false skips per held-out job no greater than
  0.5%, and skip rate at least 10%.

The Wilson interval treats jobs as Bernoulli observations. Grouping the split
prevents direct transcript-session leakage but does not remove correlation
among repeated windows. The interval may therefore be optimistic. That
limitation cannot reverse this decision because the rule already fails both
the observed-error and upper-bound criteria. A future activation study must
use a fresh temporal holdout and compute its one-sided bound with transcript
session as the resampling cluster, while retaining the zero-observed-error and
10% usefulness requirements.

The committed query is
[`scripts/analyze-ingest-prescreen.sql`](../../scripts/analyze-ingest-prescreen.sql).
An authorized operator runs it from a private network path with a database role
that has `SELECT` on the two source tables and `TEMP` on the database, but no
source-table write grants. The invocation also works when the role has
`default_transaction_read_only=on`:

```bash
export PGHOST="<database-host>"
export PGPORT="5432"
export PGDATABASE="mem9"
export PGUSER="<read-only-database-user>"
umask 077
export PGPASSFILE="$(mktemp)"
chmod 600 "$PGPASSFILE"
trap 'rm -f "$PGPASSFILE"' EXIT
# Populate PGPASSFILE from the approved secret without printing the password.

psql -X --quiet --tuples-only --no-align \
  --set=analysis_cutoff=2026-07-31T10:00:00Z \
  --set=label_start=2026-07-27T06:00:00Z \
  --set=window_days=30 \
  --file scripts/analyze-ingest-prescreen.sql \
  > /tmp/ingest-prescreen-report.local.jsonl

jq -e -s '
  (map(.section) | last == "complete")
  and (map(select(.section == "protocol")) | length == 1)
  and (map(select(.section == "baseline")) | length == 1)
  and (map(select(.section == "selected")) | length == 1)
  and (map(select(.section == "complete")) | length == 1)
  and (map(select(.section == "complete"))[0].data.consistent == true)
  and (
    (map(select(.section == "false_skip_item")) | length)
    == (map(select(.section == "selected"))[0].data.false_skips // 0)
  )
' /tmp/ingest-prescreen-report.local.jsonl
```

The production run used a one-off private Fargate task based on the existing
bootstrap image and task-injected database configuration. The task definition
was deregistered after the query. To support roles whose session default is
read-only, the script uses one explicit `TRANSACTION READ WRITE` only to create
empty session-local objects. Committing it automatically restores the role
default before the explicit `TRANSACTION READ ONLY`. All source reads,
temporary rows, and reports occur inside that read-only transaction. Message
and persisted-action text is decoded only in database-local feature queries.
Output is bounded JSONL containing aggregate counts, buckets, rates, and
synthetic false-skip labels. No content, fact text, tenant/session/job
identifier, hash, credential, or environment identifier leaves PostgreSQL.
The result reports zero empty-message jobs, proving the left join did not
silently exclude any eligible row. A final `complete` record proves the
itemized false-skip count matches the selected rule's aggregate count, so
truncated output fails validation. No new production telemetry was needed.

## Baseline

Aurora is authoritative for job outcomes. Of 1,052 evaluated jobs, 955
(90.78%) were zero-fact and 97 (9.22%) were fact-producing. The deterministic
scope-grouped split contains 369 tuning jobs and 683 held-out jobs; 74 held-out
jobs were fact-producing.

CloudWatch provides the operational trend below. Application EMF is
post-commit best effort, while Aurora is the accounting source, so metric sums
are not used as dataset labels. The final day is partial at the fixed cutoff.
`AWS/BedrockMantle` `TotalInputTokens` is scoped to the production project and
is not extraction-only.

| UTC day | `JobsAccepted` | `ZeroFactSuccess` | Zero-fact share | Project input tokens |
|---|---:|---:|---:|---:|
| 2026-07-27 | 1 | 1 | 100.0% | 1,449,580 |
| 2026-07-28 | 101 | 97 | 96.0% | 334,481 |
| 2026-07-29 | 176 | 144 | 81.8% | 1,112,934 |
| 2026-07-30 | 377 | 342 | 90.7% | 1,310,050 |
| 2026-07-31, partial | 182 | 171 | 94.0% | 676,932 |

The daily inputs are reproducible with fixed UTC boundaries. Each command
returns daily `Sum` datapoints; sort `Datapoints` by `Timestamp` before joining
the three series:

```bash
export AWS_REGION="ap-northeast-1"
export START_TIME="2026-07-27T00:00:00Z"
export END_TIME="2026-07-31T10:00:00Z"
export MEM9_BEDROCK_PROJECT="<production-project-id>"

aws cloudwatch get-metric-statistics \
  --region "$AWS_REGION" \
  --namespace "mem9-on-aws/DurableIngest" \
  --metric-name JobsAccepted \
  --dimensions Name=stage,Value=prod Name=result_class,Value=accepted \
  --start-time "$START_TIME" --end-time "$END_TIME" \
  --period 86400 --statistics Sum

aws cloudwatch get-metric-statistics \
  --region "$AWS_REGION" \
  --namespace "mem9-on-aws/DurableIngest" \
  --metric-name ZeroFactSuccess \
  --dimensions Name=stage,Value=prod \
  --start-time "$START_TIME" --end-time "$END_TIME" \
  --period 86400 --statistics Sum

aws cloudwatch get-metric-statistics \
  --region "$AWS_REGION" \
  --namespace "AWS/BedrockMantle" \
  --metric-name TotalInputTokens \
  --dimensions Name=Project,Value="$MEM9_BEDROCK_PROJECT" \
  --start-time "$START_TIME" --end-time "$END_TIME" \
  --period 86400 --statistics Sum
```

The table contains 837 accepted EMF events versus 1,052 authoritative Aurora
rows, or 79.6% coverage. That gap is consistent with the documented
post-commit, best-effort metric contract and is why CloudWatch is used for the
trend only, not labels or denominators.

### Size and shape

| Outcome | Jobs | Messages p25 / p50 / p75 | Runes p25 / p50 / p75 | Mean user-message share | Mean user-rune share |
|---|---:|---:|---:|---:|---:|
| Zero-fact | 955 | 2 / 2 / 4 | 223 / 628 / 3,143 | 42.32% | 33.40% |
| Fact-producing | 97 | 2 / 2 / 4 | 333 / 1,623 / 3,933 | 47.40% | 36.90% |

The medians separate somewhat by content size, but the interquartile ranges
and buckets overlap. Message count is not monotonic with outcome:

| Message count | Zero-fact / fact-producing | Zero-fact share |
|---|---:|---:|
| 1 | 98 / 3 | 97.0% |
| 2 | 447 / 57 | 88.7% |
| 3-4 | 231 / 14 | 94.3% |
| 5-8 | 24 / 4 | 85.7% |
| 9+ | 155 / 19 | 89.1% |

| Total runes | Zero-fact / fact-producing | Zero-fact share |
|---|---:|---:|
| 0-80 | 81 / 4 | 95.3% |
| 81-160 | 32 / 3 | 91.4% |
| 161-320 | 215 / 16 | 93.1% |
| 321-1,000 | 231 / 18 | 92.8% |
| 1,001-5,000 | 242 / 41 | 85.5% |
| 5,001+ | 154 / 15 | 91.1% |

Tool-role ratio is zero in both outcome groups. The current shared transcript
hooks for Claude Code, Codex, and Kiro upload only user/assistant text and strip
tool calls and results. Tool-call ratio is therefore unavailable to every
server-side or proxy-side policy for this traffic; a client-side implementation
would need a new pre-filter signal contract.

## Why Zero Facts Occur

The query uses deliberately broad lexical cues for decision, preference,
constraint, and environment language. These are not semantic labels and are
not used as ground truth. They divide zero-fact jobs into privacy-safe
operational categories:

| Category | Jobs | Share of zero-fact | Interpretation |
|---|---:|---:|---|
| Borderline durable-language cue rejected | 543 | 56.9% | Durable-looking words were present, but the extraction prompt correctly found no durable fact. Cheap lexical rejection cannot safely identify these. |
| Assistant-heavy, no cue | 172 | 18.0% | User content was at most 20% of runes; the answer dominated the window. |
| Routine, no cue | 139 | 14.6% | More substantial exchange, but no broad durable-language cue. |
| Minimal exchange, no cue | 101 | 10.6% | At most 160 runes. |

The coarse low-signal proxy covers 412 zero-fact jobs
(43.1% of zero-fact outcomes), while the other 543 are borderline. Even that
43.1% is not safely skippable: each structural group overlaps fact-producing
jobs. The dataset therefore contains no structurally defined bucket that can
be called objectively information-free. Durable-language cues are also poor
positive separators: they appear in 56.9% of zero-fact jobs and 46.4% of
fact-producing jobs. The
durable-only extractor is making a semantic decision that message shape and a
small keyword list do not reproduce.

No content was manually reviewed or exported. For the selected false skips,
the query privately classifies persisted memory actions into a fixed
durable-fact taxonomy and emits only the category. It distinguishes no memory
mutation and actions without content text before applying lexical categories.
The corrected production rerun found content text for all three false skips;
all three fell into `other_durable_fact`. This preserves instance privacy. The
zero-fact cause categories remain measurable proxies rather than a subjective
content taxonomy, and their overlap with fact-producing jobs is itself the
limiting result.

## Candidate Signals

The evaluated candidates combine message count, total runes, user-message
share, user-rune share, tool-role ratio, and the broad language cues. Adding
language absence did not remove false skips.

| Held-out rule | Skipped | Skip rate | False skips | Fact loss |
|---|---:|---:|---:|---:|
| Messages <= 1 | 70 | 10.25% | 3 | 4.05% |
| Messages <= 2 | 437 | 63.98% | 50 | 67.57% |
| Runes <= 80 | 64 | 9.37% | 4 | 5.41% |
| Runes <= 160 | 94 | 13.76% | 7 | 9.46% |
| Runes <= 320 | 275 | 40.26% | 20 | 27.03% |
| Runes <= 80 and no cue | 62 | 9.08% | 4 | 5.41% |
| Runes <= 160 and no cue | 82 | 12.01% | 7 | 9.46% |
| Runes <= 320 and no cue | 226 | 33.09% | 11 | 14.86% |
| User runes <= 10% and no cue | 96 | 14.06% | 7 | 9.46% |
| User messages <= 25% and no cue | 59 | 8.64% | 2 | 2.70% |
| Tool-role ratio >= 80% and no cue | 0 | 0.00% | 0 | 0.00% |
| Conservative size/user-share union, no cue | 168 | 24.60% | 12 | 16.22% |

On tuning data, `message_count <= 1` skipped 31 of 369 jobs (8.40%) with
zero false skips, the highest skip rate among zero-error candidates. The held
out result invalidated it.

### Held-out false skips

All would-be false skips from the selected rule are itemized below. Synthetic
labels are stable only within this report and reveal no source identifier or
content.

| Item | Category | Shape | Durable-language cues |
|---|---|---|---|
| H-0001 | `other_durable_fact` | 1 message, 0-80 runes | None |
| H-0002 | `other_durable_fact` | 1 message, 0-80 runes | None |
| H-0003 | `other_durable_fact` | 1 message, 0-80 runes | None |

The point estimate, 3/683 or 0.4392%, is below 0.5%, but the explicit
criterion also requires zero observed false skips. Its one-sided 95% Wilson
upper bound is 1.0939%, also above 0.5%. The rule loses 3/74 fact-producing
held-out outcomes. The required conclusion is **do not implement**.

## Placement Options

### 1. Durable ingest worker

This is the only acceptable placement if a future policy passes. The worker
sees the canonical structured messages before extraction, covers all clients,
can compare a shadow decision with the real extraction result, and can emit
bounded lifecycle telemetry in the existing application namespace.

The issue anticipated patch `0007`, but that number is now occupied by
PostgreSQL session deletion. A new implementation would be patch `0008`.
The current downstream stack is seven patch files and 15,192 patch lines, so an
eighth patch increases patch-file count by 14.3%. Every upstream pin bump must:

1. Apply all eight patches in order.
2. Run the Docker builder's four Go package groups: server command, handler,
   service, and LLM.
3. Run the PostgreSQL integration suite's seven package groups: repository,
   PostgreSQL repository, ingest queue, handler, service, config, and server
   command.
4. Re-verify the downstream facts recorded in `docs/mem9-facts.md`.

That cost is acceptable for shadow scoring but not evidence to activate a rule
that failed recall protection.

### 2. Transcript-ingestion clients

The shared hook implementation serves three clients through six event
bindings. One shared change could cover today's clients without another mem9
patch, and a client could inspect tool activity before the current filter
removes it.

The drawbacks are policy drift across bindings and future clients, bypass by
direct API callers, no authoritative extraction outcome for shadow comparison,
and permanent loss before durable job acceptance. This placement also makes
central rollback and observability harder. It is rejected.

### 3. LLM proxy sidecar

The proxy covers current model calls without a mem9 patch or client change.
However, it sees a formatted chat-completions request, not the original
canonical message structure or durable job metadata. Parsing message count and
roles back out of the extraction prompt would couple the proxy to upstream
prompt formatting. It must also distinguish extraction from reconciliation and
cannot commit a skipped durable-job outcome atomically. It is rejected.

### 4. Defer and coalesce

Coalescing small sessions avoids permanent false skips and can reduce fixed
prompt overhead and call count. It is the only option that preserves every
session for semantic extraction.

It is a different queueing design: facts are delayed until a batch closes;
session boundaries and source attribution must survive one extraction;
idempotency, retries, token bounds, reconciliation, and atomic per-job
completion need new semantics. It changes freshness, while a pre-screen changes
cost only. This may be investigated independently, but it is not a substitute
for activating the failed heuristic and does not alter the value basis of the
staleness work in #103.

## Shadow Observability

The follow-up must keep extraction behavior unchanged and emit content-free,
bounded metrics after the real outcome is known:

- `PrescreenEvaluated`: every eligible smart-ingest plan;
- `PrescreenWouldSkip`: shadow rule matched;
- `PrescreenFalseSkip`: shadow rule matched and extraction produced facts.

Dimensions are limited to the existing fixed stage and a bounded policy
version. No identifier, content, hash, measured length, or lexical match is a
dimension. A dashboard should show would-skip rate and false-skip rate next to
`ZeroFactSuccess`. Shadow mode leaves the current zero-fact dashboard and alarm
baselines unchanged.

Any future active implementation additionally needs an
`IngestSkippedPrescreen` metric, an explicit persisted terminal reason, and a
rollback flag defaulting to pass-through. Its implementation issue must review
the `ZeroFactSuccess` dashboard baseline because actively skipped sessions no
longer reach extraction. The durable-only prompt, reconciliation, and recall
scoring remain unchanged.
