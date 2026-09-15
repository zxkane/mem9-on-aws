# Design Canvas: reasoning-model route for cleanup + zero-fact quality alarm

Feature: `scripts/memory-cleanup.mjs` responses route, `ZeroFactSuccess` alarm
Date: 2026-08-01
Status: Approved (interactive session)

## Problem

Two gaps in cleanup model support and extraction monitoring:

1. **The cleanup script needs a configurable reasoning-model route.** The
   original `productionDeps` path used Chat Completions with a 4096-token cap.
   Cleanup needs the same configurable Responses route and bounded output
   handling as the local proxy. Route selection and truncation handling must
   be tested with synthetic fixtures; operator model comparisons remain private.

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
the batch instead of forwarding partial text. A truncated reply could previously reach `parseVerdicts` on the chat route.
Even syntactically valid partial JSON must not produce actionable verdicts.

### Why the token cap differs per route

The routes have separate output-budget settings: the Responses route defaults
to `RESPONSES_MAX_OUTPUT_TOKENS = 24_000`, while the chat route keeps 4096.
Validate budget and batch size with synthetic fixtures for the selected model;
these defaults do not guarantee complete classification for every workload.

A truncated reply can contain syntactically valid but incomplete decisions.
Reject it before classification so that incomplete DELETE or MERGE decisions
cannot change memory. The existing retry and SKIP handling covers failed batches.

`LLM_TIMEOUT_MS` is 300s on the Responses route and 120s on the chat route.
Keep workload-specific latency measurements in private operator records.

### Non-goals

- Not routing cleanup through the sidecar over the network. The sidecar is a
  localhost-only container inside the task; an operator host cannot reach it.
  Sharing the *translation code* gets the contract without the network path.
- Not changing `MNEMO_LLM_MODEL` (what smart-ingest uses). Cleanup's model is
  an operator choice per run; ingest's is a deployed setting.

## Part 2: `ZeroFactSuccess` quality alarm

### Metric contract

`ZeroFactSuccess` is emitted **once per succeeded job** as a 0/1 value.
Its `Average` is therefore the zero-fact rate. A high zero-fact rate alone
does not prove failure: sessions without durable facts may legitimately produce
no extraction. Public verification uses synthetic all-zero, mixed-outcome,
and traffic-boundary fixtures; operator traffic baselines remain private.

### What the alarm actually asserts

A **daily** window (`period: 86400`) detects a total extraction blackout:

- `Average(ZeroFactSuccess) >= 1.0` over 24h, with `Sum(JobsSucceeded) > 50`
  guarding against low traffic. Any successful extraction within the evaluation
  window keeps this alarm quiet; partial degradation is a separate concern.
- The 24-hour window is sliding, not calendar-aligned. An all-zero short
  interval can sit inside a mixed-outcome day; synthetic tests cover this
  aggregation behavior without replaying operator traffic.
- `treatMissingData: notBreaching` treats missing traffic as non-breaching;
  telemetry liveness is monitored separately.

This is deliberately a **backstop, not a sensitive detector**. It catches "the
extractor returns nothing, ever" (a bad model swap, a broken prompt, a
translation regression returning empty content) within a day. It does *not*
catch subtle quality drift — that is genuinely not detectable from this metric,
and #104/#106's shadow scoring is the right instrument for it. Stating that
limit here so the alarm is not mistaken for coverage it does not provide.

## Classification-failure visibility

`classifierBroken` (exit 5) fires only when **every** batch fails. A partial
outage can exit 0, with its SKIPs in the same category as planner SKIPs.
Every terminal summary therefore states how many memories went unclassified
and what share of batches failed. Unclassified memories have not passed the audit.

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
  pinned version exposes no `evaluationWindow` for wall-clock alignment. Here "daily" means "a 24h window", not "midnight to midnight". Accepted: at a threshold of exactly 1.0
  a single fact-producing job anywhere in the window clears the alarm.
- **A single surviving extraction silences it.** By construction — see the
  threshold rationale. This is a blackout detector, not a degradation detector.

## Verification

Pre-merge, in CI: unit tests for route selection, per-route token/timeout
budgets, the shared fail-loud contract, and the synthesized alarm's semantics
(namespace, statistic, period, threshold, comparison, missing-data policy,
traffic guard). The alarm's *live* behavior against real prod traffic is
observable only post-deploy and is not gated on.
