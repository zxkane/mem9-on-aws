# Test cases: recall min_confidence tunables + zero-result fallback (issue #23)

Design: [`docs/designs/recall-min-confidence.md`](../designs/recall-min-confidence.md)

## Go unit tests (inside the patched upstream tree; run by the Docker builder stage)

| ID | Scenario | Expected |
|---|---|---|
| TC-RECALL-001 | No `MNEMO_RECALL_*` env set | Thresholds equal upstream defaults (65/70/55); fallback disabled — behavior identical to unpatched upstream |
| TC-RECALL-002 | `MNEMO_RECALL_MIN_CONFIDENCE=40` | Mixed selection admits candidates with confidence ≥40 that upstream (65) rejected |
| TC-RECALL-003 | Invalid values (`abc`, `-5`, `150`, empty) | Fall back to defaults; no panic |
| TC-RECALL-004 | **Regression (fails before fix):** all candidates score below the mixed threshold, fallback enabled | Non-empty result: top-budget candidates ≥ fallback floor, `cutoff_reason="zero_result_fallback"`; upstream behavior returns 0 |
| TC-RECALL-005 | Fallback enabled, zero candidates at all | Empty result, cutoff_reason unchanged (`no_candidates`) — fallback never fabricates |
| TC-RECALL-006 | Fallback enabled, all candidates below fallback floor (25) | Empty result — the floor holds |
| TC-RECALL-007 | Fallback disabled (default), all candidates below threshold | Empty result with `cutoff_reason="min_confidence"` (upstream behavior preserved) |
| TC-RECALL-008 | Normal selection returns ≥1 result, fallback enabled | Fallback does NOT trigger; results and cutoff_reason are those of the primary selection |
| TC-RECALL-009 | Fallback respects budget | With budget=3 and 10 eligible candidates, exactly 3 returned, ordered by confidence desc |

## Infra unit tests (`infra/ecs.test.ts`)

| ID | Scenario | Expected |
|---|---|---|
| TC-RECALL-020 | mnemo-server container env | `MNEMO_RECALL_MIN_CONFIDENCE="40"` and `MNEMO_RECALL_ZERO_RESULT_FALLBACK="1"` present |

## E2E (`scripts/run-mcp-e2e.sh`, preview soft / prod hard)

| ID | Scenario | Expected |
|---|---|---|
| TC-RECALL-030 | Existing keyword probe (marker string) | Unchanged; still passes |
| TC-RECALL-031 | **Natural-language probe:** after the keyword search finds the marker, search with a ≥25-char natural-language query describing the marker fact (not containing the raw marker token verbatim-only) | ≥1 result containing the marker within the retry window |

## Build-time guards

| ID | Scenario | Expected |
|---|---|---|
| TC-RECALL-040 | `git apply` of patches against the pinned `MEM9_REF` | Applies cleanly; a future pin bump that breaks the patch fails the image build loudly |
| TC-RECALL-041 | Builder-stage `go test ./internal/handler/` in the patched tree | Passes (includes TC-RECALL-001…009) |
