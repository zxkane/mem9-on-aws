# Design Canvas: llm-proxy multi-model routing (GLM-5 + OpenAI terra/luna)

Feature: model-based routing in `docker/llm-proxy`
Date: 2026-08-01
Status: Approved (interactive session)

## Problem

Before this change, the proxy spoke exactly one dialect: chat-completions
against the application-region Mantle endpoint (Tokyo in the 2026-08-01
deployment). The OpenAI reasoning models
(`openai.gpt-5.6-terra`, `openai.gpt-5.6-luna`) are only available in
us-west-2 / us-east-1 and ONLY via the **Responses API** at the
`openai/v1/responses` path (probed live 2026-08-01: `/v1/chat/completions`,
`/v1/responses`, and `openai/v1/chat/completions` all 400 with "does not
support"; `openai/v1/responses` returns 200). mem9's LLM client is immutable
chat-completions — so model switching must happen in the proxy: translate the
API surface and hop regions, keyed on the requested `model`.

Evidence this matters: the prod memory-cleanup dry-run had 33% classification
SKIPs under GLM-5 (JSON truncation at max_tokens=4096); the terra-high rerun
had zero.

## Routing model

The `model` field of each incoming chat-completions request selects a route:

| Route | Match | Upstream | API |
|---|---|---|---|
| `chat` (default) | everything else (e.g. `zai.glm-5`) | `https://bedrock-mantle.<region>.api.aws/v1` (application region) | chat-completions passthrough (current behavior, byte-identical) |
| `responses` | model starts with a configured prefix (default `openai.gpt-5.6-`) | `https://bedrock-mantle.<responsesRegion>.api.aws/openai/v1` (default us-west-2) | chat-completions ⇄ Responses translation |

Switching models = change `MNEMO_LLM_MODEL` (env, task-def) or send a
different `model` per request. No proxy restart semantics change.

## Config (env, read once — consistent with the existing pattern)

| Env | Default | Meaning |
|---|---|---|
| `LLM_PROXY_RESPONSES_MODEL_PREFIXES` | `openai.gpt-5.6-` | Comma list of model-id prefixes routed via Responses |
| `LLM_PROXY_RESPONSES_REGION` | `us-west-2` | Region for the responses route (bearer + endpoint) |
| `LLM_PROXY_RESPONSES_BASE` | derived from region | Override for tests |
| `LLM_PROXY_REASONING_EFFORT` | `high` | `reasoning.effort` when the request doesn't carry `reasoning_effort` (mem9 can't) |
| `LLM_PROXY_RESPONSES_MAX_OUTPUT_TOKENS` | `16384` | Cap/default for `max_output_tokens` — reasoning burns output tokens first, so the chat route's 4096 cap would truncate JSON (the GLM failure mode) |
| `LLM_PROXY_RESPONSES_OPENAI_PROJECT` | empty | `OpenAI-Project` for the responses region (projects are regional; the application-region id is not reused). Empty → header omitted (untagged) |

Existing chat-route config is untouched; issue #46's provider-boundary
controls (4096 cap, byte limit, deadlines) still govern the chat route.
The responses route enforces the same `maxBodyBytes` and its own token cap.

## Request translation (chat-completions → Responses)

- `messages[role=system]` → `instructions` (joined by newline).
- Remaining messages → `input` array (Responses accepts role/content items).
- `max_tokens` → `max_output_tokens`, validated 1..cap, default = cap.
- `reasoning_effort` (request) or env default → `reasoning: { effort }`;
  validated `low|medium|high`.
- Unknown chat-completions fields are dropped (not forwarded blind — the
  Responses API rejects unknown fields with 400s that mem9 would retry raw).

## Response translation (Responses → chat-completions)

mem9 reads `choices[0].message.content`, so:

```json
{ "id": "<resp id>", "object": "chat.completion", "model": "<model>",
  "choices": [{ "index": 0,
                "message": { "role": "assistant", "content": "<joined output_text>" },
                "finish_reason": "stop" | "length" }],
  "usage": { "prompt_tokens": input_tokens, "completion_tokens": output_tokens,
             "total_tokens": sum } }
```

- `status: "incomplete"` (ran out of output tokens) → whatever text exists
  with `finish_reason: "length"` — mem9's JSON-parse-retry handles a
  truncated body the same way it does today.
- Non-2xx upstream → passed through as-is (status + body), matching the chat
  route's contract ("mem9 handles non-2xx itself").

## Token lifecycle (two regions)

Bearers are region-scoped presigns, so the responses route needs its own.
`state.tokens` becomes a per-region map: the default region minted at start
(unchanged health/readiness semantics), the responses region minted lazily on
first use, and the shared refresh timer refreshes every region minted so far.
`makeDefaultMintToken` gains a region parameter (defaults to cfg.region).
401/403 re-mint inside `forwardWithPolicy` refreshes the route's own region.

## Retry policy

`forwardWithPolicy` is route-parameterized (URL, headers, token region) but
the policy itself — one transient retry, one auth re-mint, deadline budget,
Retry-After — is shared verbatim. No second policy implementation.

## IAM / boundary (prod enablement is OPTIONAL and gated)

Cross-region calls authorize against the **requesting region's** project
resource, and Mantle projects are regional (different ids per region):

- **Task role (infra/ecs.ts)**: when `MEM9_BEDROCK_PROJECT_OPENAI` (the
  Responses-region project id) is set, add a second
  `bedrock-mantle:CreateInference`
  resource `arn:aws:bedrock-mantle:<responsesRegion>:<acct>:project/<id>` and
  inject `LLM_PROXY_RESPONSES_OPENAI_PROJECT`. Unset → no new grant; prod
  calls to the responses route would 403 (documented, fail-loud).
- **Workload boundary (operator-owned)**: new optional parameter
  `OpenAiBedrockProjectArn`; when non-empty it joins the `Resources` statement's
  NotResource list via `Fn::If`.
  Rollout = operator re-runs `deploy-workload-permissions-boundary.sh`
  (same out-of-band ownership as today).
- **Mantle project in the Responses region**: created with the existing
  out-of-band script (for the default,
  `PROJECT_REGION=us-west-2 scripts/deploy-bedrock-mantle-project.sh`).
- `bedrock-mantle:CallWithBearerToken` is already `Resource: "*"` in both the
  task role and the boundary ceiling — no change.

The checked-in default posture remains GLM-5 in the `sst.config.ts` application
region. No fallback-region grant is exercised until an operator both configures
the OpenAI project and selects the GPT model.

## Out of scope

- Streaming (neither consumer streams).
- The Anthropic Messages surface.
- memory-cleanup script routing through the proxy (it runs outside the task;
  its own Responses wrapper already exists for operator use).
- Automatic model downgrade after a failed Responses call. Region fallback is
  deterministic model-prefix routing; an upstream failure does not silently
  switch the request to GLM.

## Test hooks

Same injected-deps style: `mintToken(region)`, `fetchImpl`, clock/random/
sleep fakes. Route resolution, both translators, and per-region token
lifecycle are exported for direct unit testing.
