# Test Cases: llm-proxy multi-model routing (issue: GLM-5 + OpenAI terra/luna)

Unit tests live in `docker/llm-proxy/model-routing.test.mjs`; the untouched
`server.test.mjs`/`request-policy.test.mjs` suites double as the chat-route
regression net (their configs carry no responses-route fields). All network
I/O is faked via injected deps.

## Route resolution

- **TC-MMROUTE-001** — `zai.glm-5` (and any unmatched model) resolves to the
  `chat` route with the Tokyo base; `openai.gpt-5.6-terra` and
  `openai.gpt-5.6-luna` resolve to the `responses` route with the
  `openai/v1` base in the responses region.
- **TC-MMROUTE-002** — `LLM_PROXY_RESPONSES_MODEL_PREFIXES` accepts a comma
  list; a custom prefix routes accordingly; empty entries are ignored.
- **TC-MMROUTE-003** — route resolution happens before any upstream call and
  an invalid body (no model) still 400s exactly as today.

## Request translation (chat → Responses)

- **TC-MMROUTE-010** — system messages join into `instructions`; user and
  assistant messages become `input` items in order; `model` is preserved.
- **TC-MMROUTE-011** — `max_tokens` maps to `max_output_tokens` with the
  responses cap (default 16384): omitted → cap; 1..cap accepted; 0, negative,
  non-integer, > cap → 400 `invalid_max_tokens`.
- **TC-MMROUTE-012** — `reasoning_effort` in the request wins over the env
  default; invalid values → 400; result lands as `reasoning.effort`.
- **TC-MMROUTE-013** — unknown chat-completions fields are NOT forwarded;
  the translated body stays within `maxBodyBytes` (413 otherwise).

## Response translation (Responses → chat)

- **TC-MMROUTE-020** — `output[].content[].output_text` joins into
  `choices[0].message.content`; usage maps input/output→prompt/completion;
  `finish_reason: "stop"` on complete.
- **TC-MMROUTE-021** — `status: "incomplete"` yields the partial text with
  `finish_reason: "length"` and still HTTP 200 (mem9's retry-on-bad-JSON
  handles truncation).
- **TC-MMROUTE-022** — upstream non-2xx passes through as-is (status + body),
  same as the chat route.
- **TC-MMROUTE-023** — a 2xx upstream body that fails translation (invalid
  JSON, non-array `output`) maps to 502 `upstream_error` with a
  `translation_error` log record — never a hung or mislabeled response.
- **TC-MMROUTE-024** — reasoning items (including non-empty reasoning_text
  parts) never leak into `choices[0].message.content`; only `output_text`
  parts of message items are joined.
- **TC-MMROUTE-025** — `failed`/`cancelled`/`queued`/unknown statuses (which
  arrive as HTTP 200 with empty output) throw and surface as 502 — never a
  well-formed empty "stop" completion (the silent-skip failure this route
  exists to eliminate). Mantle's `error.message` is carried into the proxy
  error, bounded.
- **TC-MMROUTE-026** — a `completed` reply with no `output_text` (e.g. a
  refusal) is a contract breach → 502, not an empty completion. Translation
  failures are classified `proxy_translation_permanent` (deterministic;
  retrying re-bills reasoning tokens for the same failure).

## Per-region token lifecycle

- **TC-MMROUTE-030** — first responses-route request lazily mints a bearer
  for the responses region; the chat route keeps using the default-region
  bearer; mintToken receives the correct region each time.
- **TC-MMROUTE-031** — the refresh timer refreshes every region minted so
  far; a region never used is never minted.
- **TC-MMROUTE-032** — 401 on the responses route re-mints the RESPONSES
  region bearer (not Tokyo's) and retries once (policy unchanged).
- **TC-MMROUTE-033** — health/readiness still keys on the default-region
  token only (startup semantics unchanged).
- **TC-MMROUTE-034** — a failed lazy responses-region mint 502s that request,
  leaves the chat route working, and self-heals on the next request once
  minting recovers (the rejected first-mint promise is not pinned).

## Route-scoped headers

- **TC-MMROUTE-040** — chat route sends `OpenAI-Project` from
  `LLM_PROXY_OPENAI_PROJECT` (unchanged); responses route sends it from
  `LLM_PROXY_RESPONSES_OPENAI_PROJECT`; each omits the header when its value
  is empty (never cross-applied — projects are regional).

## Chat-route regression

- **TC-MMROUTE-050** — with no responses-route env at all, a `zai.glm-5`
  request produces a byte-identical upstream call to today's behavior
  (URL, headers, rewritten body, max_tokens=4096 policy).

## Infra

- **TC-MMROUTE-060** — infra/ecs.ts: with `MEM9_BEDROCK_PROJECT_OPENAI` set,
  the task role gains a second CreateInference resource ARN in the responses
  region and the container env carries `LLM_PROXY_RESPONSES_OPENAI_PROJECT`;
  unset → no new ARN, no new env (existing tests stay green).
- **TC-MMROUTE-061** — workload boundary template: `OpenAiBedrockProjectArn`
  parameter present; cfn-lint passes; empty parameter keeps the NotResource
  list unchanged (condition test via template rendering in the existing
  boundary test suite).

## Live verification (operator)

- **TC-MMROUTE-070** — not a CI gate (VPC-internal): after deploy with
  `MNEMO_LLM_MODEL=openai.gpt-5.6-terra` on a preview stage, one smart-ingest
  round-trip succeeds and the llm-proxy log shows the responses route. Run
  per runbook when enabling the model.
