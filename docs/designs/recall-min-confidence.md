# Design: recall min_confidence tunables + zero-result fallback (issue #23)

## Problem

Production recall is effectively broken: over 2026-07-16 → 2026-07-23, 88% of
`search_memories` calls (117/133) returned **zero results**. Every zero-result
search had candidates (avg ~37 insight candidates); all were rejected by the
selection stage with `cutoff_reason: "min_confidence"`. Long natural-language
queries (≥25 chars, what the recall hooks tell every agent to send) averaged
0.11 results vs 5.5 for short keyword queries.

Root cause: the upstream selection thresholds are **hard-coded consts** in
`server/internal/handler/recall.go` at the pinned commit:

| const | value | used by |
|---|---|---|
| `defaultPinnedMinConfidence` | 70 | pinned pool + single-pool pinned |
| `defaultMixedMinConfidence` | 65 | balanced/top selection (the main path) |
| `enumerationMinConfidence` | 55 | enumeration-shape queries |

The confidence score (`buildRecallConfidence`) is dominated by
`0.55*rrfNorm + 0.20*vecNorm + bonuses`. Long natural-language queries dilute
RRF/vector agreement, so real hits routinely score below 65 and the whole
result set is cut off.

## Decision

Patch the vendored upstream build (we already build from a pinned commit —
`docker/mnemo-server/Dockerfile`) with two orthogonal changes, both
behavior-neutral by default:

1. **Env-tunable thresholds.** A new `recall_config.go` in the handler package
   reads at process start:
   - `MNEMO_RECALL_MIN_CONFIDENCE` (default 65 — upstream value)
   - `MNEMO_RECALL_PINNED_MIN_CONFIDENCE` (default 70)
   - `MNEMO_RECALL_ENUM_MIN_CONFIDENCE` (default 55)
   The three const references in `recall.go` switch to these vars.
   Invalid/empty values fall back to defaults (never crash the server).

2. **Zero-result fallback.** Gated by `MNEMO_RECALL_ZERO_RESULT_FALLBACK`
   (default off). When the normal selection returns 0 memories but candidates
   exist, return the top-`budget` candidates by confidence that clear a low
   floor (`MNEMO_RECALL_FALLBACK_MIN_CONFIDENCE`, default 25), and log
   `cutoff_reason: "zero_result_fallback"` so occurrences are countable
   (feeds the #26 metric work). Applied at the tail of BOTH search entry
   points (`defaultConfidenceRecallSearch`, `singlePoolConfidenceRecallSearch`).

Deployment config (`infra/ecs.ts`, same values on prod and previews):

```
MNEMO_RECALL_MIN_CONFIDENCE:        "40"
MNEMO_RECALL_ZERO_RESULT_FALLBACK:  "1"
```

Belt and suspenders: even if 40 is still too high for some query shapes, the
fallback guarantees a non-empty best-effort answer whenever candidates exist.

## Patch mechanism

`docker/mnemo-server/patches/*.patch` (git `diff` format), applied in the
Dockerfile builder stage right after the pinned checkout:

```dockerfile
COPY docker/mnemo-server/patches/ /tmp/mem9-patches/
RUN git apply --verbose /tmp/mem9-patches/*.patch
```

`git apply` hard-fails the image build if the pinned tree drifts (e.g. a
future `MEM9_REF` bump), forcing a conscious re-verify of the patch — exactly
the failure mode we want. The patch includes its own Go unit tests
(the new `recall_config_test.go`, covering both the config parsing and the
fallback) so upstream's `go test ./internal/handler/` exercises the new paths;
CI's docker build runs `go test` for the handler package in the builder stage.

## Alternatives considered

- **Config-only (no fallback):** smaller patch, but the confidence
  distribution of real NL queries is unknown; if mass sits below 40 the
  zero-hit behavior persists and needs a second PR. Rejected as sole fix.
- **Fallback-only:** normal path keeps rejecting; every NL query rides the
  fallback, losing the gap-cutoff/coverage logic of the primary selection.
  Rejected as sole fix.
- **Fork upstream:** heavyweight; the patch-in-Dockerfile approach keeps the
  pin + reproducibility story intact.

## Observability

No new log lines; the existing `confidence recall search` /
`single-pool confidence recall` lines carry the new
`cutoff_reason=zero_result_fallback` value. Alarming on zero-hit rate is
issue #26 (out of scope here).

## Rollback

Unset the two env vars in `infra/ecs.ts` (defaults are upstream behavior) or
drop the patch files; no data migration involved.
