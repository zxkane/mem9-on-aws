# Design Canvas: reasoning-model route for cleanup + zero-fact quality alarm

Feature: `scripts/memory-cleanup.mjs` responses route, `ZeroFactSuccess` alarm
Date: 2026-08-01
Status: Approved (interactive session)

## Problem

Two gaps left open after the model comparison (GLM-5 vs terra vs luna):

1. **The cleanup script cannot reach a reasoning model.** `productionDeps`
   hard-codes Bedrock Mantle's `/v1/chat/completions` with `max_tokens: 4096`.
   The `openai.gpt-5.6-*` models are Responses-API-only and live in a different
   region, so the only way to run cleanup on terra was a gitignored operator
   wrapper. That wrapper is the thing that produced the current prod decision
   list — an unreviewable, untested path for a destructive tool.

   Measured on the same 2271-memory corpus: GLM-5 left **740 memories (33%)
   unclassified** (32 of 117 batches failed JSON twice, root cause `max_tokens:
   4096` truncation); terra had **zero** classification failures. The batch
   ceiling, not the prompt, is the limiting factor.

2. **Nothing watches smart-ingest extraction quality.** A model swap that
   silently degrades extraction is invisible: `ZeroFactSuccess` counts a
   *successful* job that produced no facts, so a wholly broken extractor still
   reports `JobsSucceeded` and pages nobody.

## Part 1: responses route in the cleanup script

Reuse the sidecar's already-reviewed translation instead of re-deriving it.
`docker/llm-proxy/server.mjs` exports `resolveRoute`,
`translateChatToResponses`, and `translateResponsesToChat`; those are pure
functions with no server or AWS dependency, and the cleanup script already runs
from a repo checkout with `node_modules` present. Importing them means the
fail-loud contract (`status: "failed"` → throw, `completed` with no
`output_text` → throw) is enforced identically on both paths, and one test suite
covers both callers.

Route selection is by model prefix, exactly as the sidecar does it — so
`--model openai.gpt-5.6-terra` picks the Responses API in the responses region,
and `zai.glm-5` keeps the existing chat-completions request byte for byte. Its
*reply* handling gains one guard: a `finish_reason: "length"` response now fails
the batch instead of forwarding partial text. On the chat route that previously
reached `parseVerdicts` and almost always failed JSON parse anyway (the measured
GLM-5 mode); in the rare case the partial text parsed, it produced actionable
verdicts from an unfinished reply, so failing is strictly safer.

### Why the token cap differs per route

`max_tokens: 4096` is correct for GLM-5 and *catastrophic* for a reasoning
model: reasoning tokens are billed and consumed as output tokens before any
visible text is produced, so a 4096 cap truncates the JSON mid-object. That is
precisely the GLM-5 failure mode, and it would recur on terra at the same cap.
The responses route therefore defaults to a much larger output budget
(`RESPONSES_MAX_OUTPUT_TOKENS = 24_000`, the value that ran the corpus clean)
and the chat route keeps 4096.

A truncated reply is rejected outright rather than parsed: at a 24k budget,
truncation is the *expected* failure mode, and it can land on syntactically
valid JSON (a partial verdict list, or a MERGE whose `merged_content` is cut
mid-sentence). Classifying that would delete memories the model never finished
judging and overwrite a survivor with half a fact, so `finish_reason: "length"`
fails the batch and the existing retry→SKIP machinery takes over.

`LLM_TIMEOUT_MS` also rises to 300s on the responses route only: observed p50
was ~3.4s but max 29.5s, and a high-effort batch legitimately runs longer than
the 120s the chat route allows.

### Non-goals

- Not routing cleanup through the sidecar over the network. The sidecar is a
  localhost-only container inside the task; an operator host cannot reach it.
  Sharing the *translation code* gets the contract without the network path.
- Not changing `MNEMO_LLM_MODEL` (what smart-ingest uses). Cleanup's model is
  an operator choice per run; ingest's is a deployed setting.

## Part 2: `ZeroFactSuccess` quality alarm

### The measurement that shaped this

`ZeroFactSuccess` is emitted **once per succeeded job** (verified against prod:
a 6h bucket has `Sum=105`, `SampleCount=133`, and `JobsSucceeded=133` for the
same window). So `Average` of `ZeroFactSuccess` *is* the zero-fact rate
directly, with no second metric needed — the metric is a 0/1 gauge per job, not
a sparse counter.

The naive alarm ("rate too high") is **not viable**, and the baseline says why:

| Window (prod, healthy) | zero-fact rate |
|---|---|
| Jul 28 | 96% |
| Jul 29 | 82% |
| Jul 30 | 91% |
| Jul 31 | 90% |
| Aug 1 | 77% |
| Jul 30 17:00–23:00 (hourly) | **100%, 100%, 100%, 100%, 100%, 100%** |

Six consecutive fully-zero-fact hours occur in a **healthy** baseline — most
agent sessions genuinely carry no durable takeaway, which is the documented
correct outcome of rule D4. Any threshold that would catch a broken extractor
within hours also fires constantly on normal traffic. This is why the alarm is
scoped as below, and why the earlier framing of "watch that the rate stays in
the 82–98% band" cannot be implemented as an hourly alarm.

### What the alarm actually asserts

A **daily** window (`period: 86400`) at a threshold **above the observed
maximum**, alarming only on a *sustained, total* extraction blackout:

- `Average(ZeroFactSuccess) >= 1.0` over 24h, with `Sum(JobsSucceeded) > 50`
  guarding against a low-traffic day trivially reading 100%. The threshold is
  **exactly** 1.0, not a fraction: 0.995 looks like a comfortable margin over
  the 96% worst healthy day but is not one — at 200 jobs it pages on a day that
  extracted a single real fact. "Not one extraction succeeded" is the honest
  line for a blackout detector and cannot false-positive while memories are
  still being written.
- Daily is the shortest window where the healthy signal separates from the
  broken one at all (windows are 24h and sliding, not calendar-aligned — see
  Known limits). The six healthy 100% hours above total 134 succeeded jobs
  with zero facts — past the traffic guard and a breach at any threshold — so
  an hourly (or any sub-day) window would page on that stretch. Aggregated over
  its real day, the same traffic extracted 35 facts from 377 jobs.
- `treatMissingData: notBreaching` — no ingest traffic is not a quality
  regression (and the liveness alarm already owns "telemetry stopped").

This is deliberately a **backstop, not a sensitive detector**. It catches "the
extractor returns nothing, ever" (a bad model swap, a broken prompt, a
translation regression returning empty content) within a day. It does *not*
catch subtle quality drift — that is genuinely not detectable from this metric,
and #104/#106's shadow scoring is the right instrument for it. Stating that
limit here so the alarm is not mistaken for coverage it does not provide.

## Classification-failure visibility

`classifierBroken` (exit 5) fires only when **every** batch fails. A partial
outage therefore exits 0, and its SKIPs land in the same bucket as legitimate
planner SKIPs — so the measured GLM-5 run, which failed 27% of batches, reported
success. Every terminal summary now states how many memories went unclassified
and what share of batches failed, because on a destructive tool "we did not look
at 740 memories" must not read the same as "those 740 are fine".

Relatedly, a request the translator rejects is a deterministic defect thrown
before any network call: it fails identically on all batches, so it aborts the
run instead of degrading it to a clean-looking audit of an unexamined corpus.

## Known limits of the alarm

Stated so it is not mistaken for coverage it lacks:

- **Dilution.** `ZeroFactSuccess` is dimensioned only by `stage`, so extraction
  that still works for one session type keeps the aggregate off 1.0 while it is
  broken for everything else.
- **Traffic-guard silence.** A break that also pushes jobs to `dead` instead of
  `succeeded` drops volume below 51/day, and the guard returns 0. The dead-job
  alarm owns that failure; no single alarm owns "extraction is broken".
- **`notBreaching` conflates "no data" with "all good."** A total emitter stop
  reads healthy here; the telemetry-liveness alarm owns it.
- **The 24h window slides.** CloudWatch advances the evaluation window by a
  minute and does not align it to the wall clock, and `@pulumi/aws` at the
  pinned version exposes no `evaluationWindow` for wall-clock alignment. The
  baseline figures above are calendar-day aggregates, so "daily" means "a 24h
  window", not "midnight to midnight". Accepted: at a threshold of exactly 1.0
  a single fact-producing job anywhere in the window clears the alarm.
- **A single surviving extraction silences it.** By construction — see the
  threshold rationale. This is a blackout detector, not a degradation detector.

## Verification

Pre-merge, in CI: unit tests for route selection, per-route token/timeout
budgets, the shared fail-loud contract, and the synthesized alarm's semantics
(namespace, statistic, period, threshold, comparison, missing-data policy,
traffic guard). The alarm's *live* behavior against real prod traffic is
observable only post-deploy and is not gated on.
