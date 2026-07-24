# Design: bounded GLM-5 requests (issue #46)

## Problem

The local LLM proxy accepts up to 8 MiB without parsing the request, while the
patched mnemo-server can format 1,000,000 runes and omits `max_tokens`. A request
can therefore consume excessive output tokens or fail only after mnemo-server
has built a large prompt.

## Data flow

```text
mnemo-server
  format conversation (maximum 200,000 runes)
    -> llm-proxy body reader (maximum 1,048,576 bytes)
      -> parse and validate chat-completions JSON
        -> preserve all fields and default max_tokens to 4096
          -> reject if rewritten JSON exceeds the same byte maximum
            -> Bedrock Mantle GLM-5
```

## Decisions

### Proxy boundary

`readConfig()` owns the two proxy limits:

- `LLM_PROXY_MAX_BODY_BYTES`, default `1048576`
- `LLM_PROXY_MAX_TOKENS`, default `4096`

The body reader and post-rewrite semantic size check both receive
`cfg.maxBodyBytes`; there is no second byte-limit constant. The body reader
fails as soon as observed bytes exceed the limit and never forwards a truncated
prefix.

The proxy parses JSON before minting a token or calling Mantle. A valid
chat-completions payload is a JSON object with a non-empty string `model` and an
array `messages`. It preserves the object and every supported/provider-specific
field. It changes only `max_tokens`: missing becomes the configured maximum;
explicit JSON integers in `[1, maxTokens]` remain unchanged; all other values
fail without clamping.

Validation responses use the OpenAI error envelope with `message`, `type`,
`param`, and `code`. Malformed/invalid payloads and invalid `max_tokens` return
400. Byte-limit failures return 413. The validation-status contract classifies
400 and 413 as permanent so a durable worker must not retry them.

Validation logs are structured metadata only: event, status, error code,
outcome class, method, path, declared content length, and observed byte count.
Bodies, prompts, messages, and response content are never logged.

### Upstream formatter

A build-time patch makes the formatted-conversation cap configurable through
`MNEMO_MAX_EXTRACTION_CONVERSATION_RUNES`, defaulting to 200,000. ECS injects
the same value explicitly. A Go regression test runs the real conversation
formatter, fixed extraction prompts, and LLM request serializer with 200,000
four-byte Unicode runes, then applies the proxy's `max_tokens` rewrite shape and
asserts the final request remains below 1,048,576 bytes.

### ECS configuration

The task definition explicitly injects all three production values. These are
non-sensitive controls, so normal ECS environment variables are appropriate;
secrets remain in the existing `ssm` mapping.

## Failure modes

- Inbound body exceeds the cap: 413, permanent, no Mantle call.
- Rewritten body exceeds the cap: 413, permanent, no Mantle call.
- Malformed JSON or wrong payload shape: 400, permanent, no Mantle call.
- Invalid explicit `max_tokens`: 400, permanent, no Mantle call.
- Provider/network failures after validation: existing passthrough and 502/504
  behavior remains unchanged.

## Rollback

Revert the proxy validation/rewrite, upstream patch, and ECS values together.
The prior behavior accepts 8 MiB, omits `max_tokens`, and caps at 1,000,000
runes.
