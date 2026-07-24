# Test cases: durable-facts-only ingest extraction (issue #25)

Design: [`docs/designs/ingest-durable-only.md`](../designs/ingest-durable-only.md)

## Go unit tests (inside the patched upstream tree; run by Docker builder)

| ID | Scenario | Expected |
|---|---|---|
| TC-INGEST-001 | `MNEMO_INGEST_DURABLE_ONLY` not set | `durableOnlyPromptSection()` returns `""` — prompts byte-identical to upstream |
| TC-INGEST-002 | Enabled | Section contains all load-bearing rules: "Durability filter", "future sessions", "REJECT session-state", "Rules 12-14 above do NOT apply", "empty facts array is the CORRECT output" |
| TC-INGEST-003 | Env parsing | Only "1"/"true"/"yes"/"on" activate; "0"/"false"/""/etc. → off |
| TC-INGEST-005 | Probe exception (D5): section contains EXCEPTION+probe+marker so deploy probes are never rejected | Present |
| TC-INGEST-004 | Integration — durability section reaches the LLM extraction prompt | A mock LLM server captures the system prompt; `ExtractPhase1` with durability on includes "Durability filter" + "REJECT session-state observations" |

## Infra unit tests (`infra/ecs.test.ts`)

| ID | Scenario | Expected |
|---|---|---|
| TC-INGEST-020 | mnemo-server container env | `MNEMO_INGEST_DURABLE_ONLY="1"` present |

## Build-time guards

| ID | Scenario | Expected |
|---|---|---|
| TC-INGEST-030 | Patch 0002 applies after patch 0001 against the pinned MEM9_REF | `git apply` succeeds; no hunk drift |
| TC-INGEST-031 | Builder-stage `go test ./internal/handler/ && go test ./internal/service/` | Both pass (handler tests from #23 + service tests from #25) |

## E2E (qualitative; no automated assertion)

The extraction quality change is LLM-behavioral: the same ingest window may or
may not produce facts depending on the model's interpretation of the durability
rules. A hard automated E2E assertion ("ingest this window, assert exactly 0
facts") would be flaky. Instead:

- **Spot-check post-deploy:** after a few days on prod, query
  `search_memories` for recently-created memories and verify the transient
  noise observed pre-fix is no longer appearing (manual).
- The existing E2E (`run-mcp-e2e.sh`) still writes a probe fact via
  `add_memory` (not `ingest_messages`), so it bypasses the extraction prompt
  and is unaffected by this change.
