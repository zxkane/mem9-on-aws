# Test cases: bounded GLM-5 requests (issue #46)

Design: [`docs/designs/glm-request-bounds.md`](../designs/glm-request-bounds.md)

## Proxy tests (`docker/llm-proxy/server.test.mjs`)

| ID | Scenario | Expected |
|---|---|---|
| TC-GLM-BOUND-001 | Default and explicit proxy configuration | Defaults are 1,048,576 bytes and 4096 tokens; explicit values are parsed once into `cfg` |
| TC-GLM-BOUND-002 | Valid ASCII chat request is exactly N bytes | Request is accepted and forwarded in full |
| TC-GLM-BOUND-003 | Valid ASCII chat request is N+1 bytes | OpenAI-shaped 413; no Mantle call and no truncated prefix is forwarded |
| TC-GLM-BOUND-004 | N/N+1 boundary contains four-byte UTF-8 characters | Actual encoded bytes, not JavaScript character count, decide acceptance |
| TC-GLM-BOUND-005 | Malformed JSON | OpenAI-shaped 400 with `invalid_json`; no Mantle call |
| TC-GLM-BOUND-006 | JSON is not a chat-completions object | Arrays, null, missing/invalid model, and missing/invalid messages return OpenAI-shaped 400 |
| TC-GLM-BOUND-007 | `max_tokens` is missing | Forwarded JSON contains `max_tokens: 4096` |
| TC-GLM-BOUND-008 | Explicit smaller integer `max_tokens` | Values 1 and 1024 are preserved |
| TC-GLM-BOUND-009 | Explicit maximum `max_tokens` | 4096 is preserved |
| TC-GLM-BOUND-010 | Non-integer `max_tokens` | String, null, boolean, and fractional values return 400; no clamping or Mantle call |
| TC-GLM-BOUND-011 | Integer `max_tokens` is out of range | Zero, negative, and 4097 return 400; no clamping or Mantle call |
| TC-GLM-BOUND-012 | Normal mem9 request carries supported and provider-extension fields | Model, messages, temperature, response format, and unknown extensions are unchanged; only missing `max_tokens` is added |
| TC-GLM-BOUND-013 | Forwarded request metadata | `Content-Length` equals the rewritten body's byte length |
| TC-GLM-BOUND-014 | Input fits N but the rewritten body exceeds N | The semantic size check uses the same `cfg.maxBodyBytes` and returns 413 |
| TC-GLM-BOUND-015 | Validation logging | Snapshot contains request ID, attempt 0, status/reason, duration, remaining budget, and outcome class only; request/message markers are absent |
| TC-GLM-BOUND-016 | Validation status classification | HTTP 400 and 413 classify as `proxy_validation_permanent` for the durable-worker contract |

## Patched upstream Go tests (Docker builder)

| ID | Scenario | Expected |
|---|---|---|
| TC-GLM-BOUND-017 | Rune-cap configuration default and override | Default is 200,000; a valid `MNEMO_MAX_EXTRACTION_CONVERSATION_RUNES` value is honored and invalid values use the default |
| TC-GLM-BOUND-018 | Four-byte worst-case serialization | Real formatter + current fixed prompts + real LLM request serializer at 200,000 runes, with `max_tokens:4096`, remains below 1,048,576 bytes |
| TC-GLM-BOUND-019 | Formatter truncation | Formatted conversation never exceeds the configured rune cap and remains valid UTF-8 |

## IaC tests (`infra/ecs.test.ts`)

| ID | Scenario | Expected |
|---|---|---|
| TC-GLM-BOUND-020 | mnemo-server production environment | `MNEMO_MAX_EXTRACTION_CONVERSATION_RUNES="200000"` is explicit |
| TC-GLM-BOUND-021 | llm-proxy production environment | `LLM_PROXY_MAX_BODY_BYTES="1048576"` and `LLM_PROXY_MAX_TOKENS="4096"` are explicit |

## Verification

- Root Node 24 typecheck and proxy tests.
- Infra Node 24 typecheck and unit tests.
- Patched upstream `go test ./internal/handler/ ./internal/service/` plus
  `./internal/llm/` in the Docker builder.
- Build the mnemo-server builder stage to prove all patches apply to the pinned
  upstream commit.
