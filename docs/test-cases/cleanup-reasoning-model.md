# Test Cases: reasoning-model route for cleanup + zero-fact quality alarm

Feature: `scripts/memory-cleanup.mjs` responses route, `ZeroFactSuccess` alarm
Design: [cleanup-reasoning-model.md](../designs/cleanup-reasoning-model.md)

## Cleanup LLM route (`scripts/memory-cleanup.test.mjs`)

| ID | Scenario | Expected |
|---|---|---|
| TC-MEMCLEAN-070 | `buildCompleteChat` with `zai.glm-5` | Posts to `/v1/chat/completions` in the app region with `max_tokens: 4096`; body has `messages` (no `input`/`reasoning`); returns `choices[0].message.content` |
| TC-MEMCLEAN-071 | `buildCompleteChat` with `openai.gpt-5.6-terra` | Posts to `openai/v1/responses` in the **responses** region with `max_output_tokens: 24000` and `reasoning.effort`; system prompt becomes `instructions`, memories become `input` |
| TC-MEMCLEAN-072 | Responses reply `status: "completed"` with `output_text` parts | Returns the concatenated text, so `parseVerdicts` sees exactly what the chat route would produce |
| TC-MEMCLEAN-073 | Responses reply `status: "failed"` (HTTP 200, empty output) | Throws — never returns `""`. An empty string would parse as "no verdicts" and mark a whole batch SKIP on an authoritative-looking non-answer |
| TC-MEMCLEAN-074 | Responses reply `status: "incomplete"` (output-token exhaustion), whose partial text is **valid** JSON | Throws. Truncation at the 24k budget can land on parseable JSON — a partial verdict list, or a MERGE with `merged_content` cut mid-sentence — so `finish_reason: "length"` fails the batch (→ retry → SKIP) instead of classifying a reply the upstream told us was incomplete |
| TC-MEMCLEAN-074b | A truncated MERGE reply driven through `runCleanup --apply` with the real `buildCompleteChat` | Both memories SKIP, `writeCalls === 0`, the survivor's content is unchanged and the absorbed memory stays `active` — no delete, no half-written overwrite |
| TC-MEMCLEAN-074c | A near-miss model id (`openai.gpt-5.6terra`, `openai.gpt-6-terra`, uppercase) | Documents that prefix matching is exact, so these fall to the chat route's 4096 cap; pins current behavior so a prefix change is a visible test change rather than a silent capability regression |
| TC-MEMCLEAN-075 | 401 on either route | Re-mints the bearer once and retries; a second 401 throws. Responses route mints for the responses region, chat route for the app region |
| TC-MEMCLEAN-076 | `--model` / `--effort` / `--llm-region` flags | Parsed by `parseArgs`; `--effort` rejects a value outside `low|medium|high`; `--model` defaults to `MEM9_LLM_MODEL` then `zai.glm-5` |
| TC-MEMCLEAN-077 | Responses route timeout budget | Uses the 300s responses budget, not the 120s chat budget |
| TC-MEMCLEAN-078 | `OpenAI-Project` header per route | Each route sends its own regional project id; the app-region project is never sent to the responses region (Mantle projects are regional) |
| TC-MEMCLEAN-080 | 1 of 3 classification batches fails both attempts | Exit 0 (a partial outage is not "classifier broken"), but the summary reports `UNCLASSIFIED=20 of 60 memories (1/3 batches failed, 33%)` and says the run did not audit them. Without this the outage is indistinguishable from a legitimate planner `SKIP:20` |
| TC-MEMCLEAN-081 | The request translator rejects the payload (deterministic config defect, thrown before any network call) | The run aborts instead of retrying and degrading every batch to SKIP — an invocation bug must not read as a clean audit of an unexamined corpus |
| TC-MEMCLEAN-079 | Ambient `LLM_PROXY_*` sidecar env is exported in the operator's shell | Route, output budget, and effort are unchanged. The proxy config is built from a closed object, so a stray `LLM_PROXY_RESPONSES_MODEL_PREFIXES` cannot silently downgrade terra to the 4096-cap chat route, and a limit cleanup never reads (`LLM_PROXY_MAX_BODY_BYTES=0`) cannot abort the run |

## Zero-fact quality alarm (`infra/observability.test.ts`)

| ID | Scenario | Expected |
|---|---|---|
| TC-INGEST-METRIC-030 | Prod synthesis | A `DurableIngestZeroFactRateAlarm` exists on `mem9-on-aws/DurableIngest`, using `Average` of `ZeroFactSuccess` over `period: 86400`, `threshold: 1`, `GreaterThanOrEqualToThreshold`, `treatMissingData: notBreaching`, dimensioned `stage`. The rate expression is asserted as a **literal** string (not compared to its own constant), so a mutation of the traffic-guard value or the branch order fails the suite |
| TC-INGEST-METRIC-031 | Low-traffic day | The alarm expression requires `JobsSucceeded > 50` in the window, so a day with a handful of legitimately zero-fact jobs cannot breach |
| TC-INGEST-METRIC-032 | Healthy baseline replay + boundary | The measured healthy daily rates (96/82/91/90/77%) stay quiet. The six consecutive 100% *hours* (Jul 30 17:00-23:00) aggregate to 134 all-zero-fact jobs and **do** breach — the concrete reason the window must be a full day, since over their real day that traffic extracted 35 facts from 377 jobs and stays quiet. Boundary: at the smallest healthy daily volume (101 jobs) a single successful extraction keeps it quiet, and 51 all-zero-fact jobs is the first breach past the guard |
| TC-INGEST-METRIC-033 | Alarm actions | Wired to the prod alert topic for both ALARM and OK, consistent with the other action-bearing alarms |
| TC-INGEST-METRIC-034 | Non-prod synthesis | No alarm resources outside prod (existing contract preserved) |
| TC-INGEST-METRIC-035 | Emitter producer contract | `ZeroFactSuccess` and `JobsSucceeded` are pinned in the emitter-metric assertion. Dropping either from the mnemo-server patch makes the metric vanish from CloudWatch, leaving the alarm `INSUFFICIENT_DATA` → `notBreaching` → healthy forever; verified by mutation |
