# Test cases: bounded GLM-5 deadlines and retries

Design: [`docs/designs/glm-request-deadlines.md`](../designs/glm-request-deadlines.md)

## Unit tests (`docker/llm-proxy/request-policy.test.mjs`)

The policy tests use Vitest's fake clock, scripted fake fetch, a fake ECS
credential resolver/token signer, deterministic jitter, and an injected log
sink. Call and mint counts include the initial bearer mint performed before the
request.

| ID | Scenario | Expected |
|---|---|---|
| TC-GLM-RETRY-001 | Default deadline configuration | Overall deadline is 110 seconds, call maximum is 108 seconds, response reserve is 2 seconds, minimum retry call budget is 20 seconds, and jitter is 500 ms base/2 seconds cap |
| TC-GLM-RETRY-002 | First call succeeds after a long useful run | Call receives a 108-second deadline and the request remains within the 110-second overall deadline |
| TC-GLM-RETRY-003 | Fast 503 then 200 | Full-jitter backoff runs; client sees 200; exactly two Mantle calls and one bearer mint |
| TC-GLM-RETRY-004 | Slow 503 leaves less than 20 seconds | First 503 is returned directly; one call and one mint |
| TC-GLM-RETRY-005 | Fast network error then 200 | One bounded jitter wait and one retry; client sees 200 |
| TC-GLM-RETRY-006 | First attempt reaches its call deadline | Active fetch is aborted, client receives 504/deadline, and no retry occurs |
| TC-GLM-RETRY-007 | Retryable status matrix: 408/429/500/502/503/504 | Every fast first failure retries once; no other status gains this policy |
| TC-GLM-RETRY-008 | Other 4xx matrix | 400/404/409/422 return immediately as `mantle_4xx_permanent` |
| TC-GLM-RETRY-009 | 401 then 200 | Fresh credentials are resolved and a new bearer is minted; two calls/two mints; client sees 200 |
| TC-GLM-RETRY-010 | 401 then 503 | Auth retry consumes call two and returns 503 directly; two calls/two mints |
| TC-GLM-RETRY-011 | 503 then 401 | Transient retry consumes call two and returns 401 without remint; two calls/one mint |
| TC-GLM-RETRY-012 | Consecutive 401 responses | Second 401 is returned; two calls/two mints and no third call |
| TC-GLM-RETRY-013 | `Retry-After` seconds | Valid delay is honored and retry begins with at least 20 seconds of call budget |
| TC-GLM-RETRY-014 | `Retry-After` HTTP-date | Valid future date is honored using the injected clock |
| TC-GLM-RETRY-015 | Invalid `Retry-After` | Header is ignored and deterministic full jitter is used |
| TC-GLM-RETRY-016 | Too-long `Retry-After` | First upstream status/body is returned without waiting or retrying |
| TC-GLM-RETRY-017 | Retry budget equality | A wait leaving exactly 20 seconds of call budget is eligible |
| TC-GLM-RETRY-018 | Cancellation during active call | Downstream/context abort cancels fetch and performs no later call |
| TC-GLM-RETRY-019 | Cancellation during backoff | Pending wait is canceled and performs no second call |
| TC-GLM-RETRY-020 | Exact call/mint matrix | 401->200, 401->503, 503->401, 401->401, 503->200, slow 503, and timeout match the required counts |
| TC-GLM-RETRY-021 | Structured request logs | Snapshot exposes only request ID, attempt, status/reason, duration, remaining budget, and terminal outcome class; secret request/response/error markers are absent |
| TC-GLM-RETRY-022 | Terminal classifications | Validation, permanent 4xx, transient provider/network failure, and timeout map to the four durable-worker classes |
| TC-GLM-RETRY-023 | Overall cancellation before another call | No call starts with a non-positive call budget |

## HTTP integration tests (`docker/llm-proxy/server.e2e.test.mjs`)

These tests run the real proxy HTTP server against a controllable loopback
Mantle server. Test-only short budgets keep the suite fast while exercising the
same calculations.

| ID | Scenario | Expected |
|---|---|---|
| TC-GLM-RETRY-024 | Fake Mantle returns fast 503 then 200 | External proxy response preserves the final 200 body, exactly two upstream requests arrive, and elapsed time includes bounded backoff |
| TC-GLM-RETRY-025 | Fake Mantle exceeds the call budget | Upstream socket is canceled, external response is OpenAI-shaped 504, and elapsed time remains within the overall deadline |
| TC-GLM-RETRY-026 | HTTP client disconnects during Mantle call | Active upstream request is canceled and no retry arrives |
| TC-GLM-RETRY-027 | Provider-400 fallback is a second proxy request | A slow 400 request followed by a slow successful request gets two independent request IDs/deadlines; the second does not inherit elapsed budget from the first |
| TC-GLM-RETRY-028 | Response write reaches the overall deadline | The downstream socket is closed by the still-active overall timer; response flushing cannot extend the request past its deadline |

## Existing integration coverage

- `docker/llm-proxy/server.test.mjs` keeps request validation, bearer lifecycle,
  health, route, header injection, and response passthrough coverage.
- `infra/ecs.test.ts` pins `LLM_PROXY_OVERALL_DEADLINE_MS="110000"` in the
  production task definition.
- Root CI runs all proxy unit/integration tests under Node.js 24.
