# Design Canvas: bounded GLM-5 deadlines and retries

Feature: GLM-5 request deadline and retry policy
Date: 2026-07-24
Status: Approved (autonomous mode)

## Problem

The LLM proxy currently gives each Mantle call an independent timeout and only
retries authentication failures. A request can therefore outlive mem9's
120-second client timeout, and adding transient retries without a shared budget
could duplicate token spend after useful processing time is gone.

## Request Flow

```text
incoming POST
  -> create request id and 110-second request context
  -> read and validate the body within that context
  -> obtain the current bearer
  -> attempt 1 with min(108 seconds, remaining - 2 seconds)
       -> 2xx/non-retryable response: return it
       -> 401/403: resolve ECS credentials, re-mint, attempt 2 immediately
       -> network/retryable status: wait full-jitter/Retry-After only if
          at least 20 seconds of call budget remains, then attempt 2
       -> attempt timeout: return deadline without retry
  -> attempt 2: return its response or mapped transport outcome directly
  -> reserve the final 2 seconds for writing the downstream response
```

The downstream connection, overall deadline, active Mantle call, and pending
backoff share one abort path. At most two calls are created for a request.

## Budget Model

- Overall deadline: 110,000 ms from entry into the HTTP request handler.
- Response reserve: 2,000 ms.
- Maximum call duration: 108,000 ms.
- Call budget before each attempt:
  `min(108000, overallDeadline - now - 2000)`.
- A transient retry is useful only when its wait completes with at least
  20,000 ms of call budget. Equality is allowed.
- Attempt timeout is terminal. With the first call allowed to consume its full
  budget, it cannot leave the 20-second minimum required by a transient retry.
- Authentication retry is different: the first 401/403 re-resolves ECS task
  credentials, re-mints once, and uses attempt 2 without backoff whenever the
  computed call budget is positive.

The clock, timers, sleep, random source, fetch implementation, token minter, and
request-id generator are dependencies. Production uses platform implementations;
tests use a fake clock, deterministic jitter, fake fetch, and fake credential
resolver.

## Retry State Machine

Only attempt 1 can schedule another Mantle call.

| Attempt 1 result | Attempt 2 policy |
|---|---|
| 401 or 403 | Fresh credential resolution and bearer mint, no backoff |
| Network error | Full-jitter backoff if 20 seconds remains afterward |
| 408, 429, 500, 502, 503, 504 | `Retry-After` or full-jitter if 20 seconds remains afterward |
| Attempt timeout | No retry |
| Other 4xx or any other response | No retry |

Full-jitter delay is uniformly selected from zero through
`min(500 * 2^(attempt - 1), 2000)` milliseconds. With only one transient retry,
the first retry cap is 500 ms. A valid non-negative integer seconds or HTTP-date
`Retry-After` replaces jitter. Invalid values fall back to jitter.
A wait that would leave less than 20 seconds of call budget suppresses retry and
returns the first upstream response; for a network error it returns the mapped
transient failure.

Attempt 2 is always terminal, including 401/403 or a retryable status. A
503-then-401 path therefore does not re-mint, and a 401-then-503 path does not
perform a transient retry.

## Cancellation

The handler creates an overall `AbortController` and aborts it when:

- the 110-second timer fires;
- the downstream response closes before completion;
- the incoming request is aborted.

Each Mantle call has a child controller canceled by either the request signal or
its own call-budget timer. Backoff listens to the request signal. Cancellation
prevents all later calls and avoids writing to a closed response.

## Outcome And Logging Contract

Terminal classes are:

- `proxy_validation_permanent`
- `mantle_4xx_permanent`
- `mantle_transient`
- `deadline`

Each request/attempt log is one JSON object containing only:

- generated `request_id`
- `attempt`
- `status` or `reason`
- `duration_ms`
- `remaining_budget_ms`
- `outcome_class` when terminal

No URL, method, body size, prompt, message, bearer, credential, upstream body,
or error text is logged. Existing validation logs move to this schema. The
401-remint metric should match structured reason/status fields instead of a
free-form line.

## E2E Strategy

The real proxy server runs against a loopback fake Mantle HTTP server. Short,
test-only budget values verify status/body passthrough, elapsed retry behavior,
and fresh request budgets. Two sequential proxy requests model mem9's
invalid-JSON/provider-400 fallback: each receives a distinct request id and a
new deadline rather than sharing the first request context.

## Rollback

Revert the request-policy module and restore the prior single-call timeout plus
401/403 remint path. No persisted data or infrastructure migration is involved.
