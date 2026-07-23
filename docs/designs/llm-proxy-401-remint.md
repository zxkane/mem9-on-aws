# Design: llm-proxy 401-reactive bearer re-mint (issue #24)

## Problem

On 2026-07-22 ~14:59–15:04 UTC, Bedrock Mantle returned `401 invalid_api_key`
("The security token included in the request is ...") for ~5 minutes; 32
smart-ingest extractions failed permanently (mnemo-server's ingest is
fire-and-forget). The proxy only re-mints its bearer on a fixed 1h timer, so a
bearer invalidated mid-interval keeps being served until the next tick.

Root cause is twofold (`docker/llm-proxy/server.mjs`):

1. **Stale session credentials in the mint.** The direct-run entrypoint
   creates `fromNodeProviderChain()` once and calls it per mint. That provider
   memoizes; a bearer presigned from an expired ECS task-role session dies
   with the session regardless of the requested 12h TTL — and the mint
   "succeeds", so the proxy believes it holds a good token.
2. **No 401 reaction.** `forwardToMantle` passes any upstream status straight
   through. A 401 is treated like a business response, not an auth failure.

## Decision

Two changes, both inside the proxy (no mnemo-server / upstream change):

1. **401/403-reactive re-mint + single retry.** In the request path: if the
   upstream responds 401 or 403, re-mint the bearer once (minting is a local
   SigV4 presign — cheap, no network), retry the request with the fresh
   bearer, and pass through whatever the retry returns. No retry loop: a
   second auth failure passes through (mem9 already handles non-2xx). Log a
   distinct line — exactly `llm-proxy re-minted bearer after upstream <status>`
   — so occurrences are countable; the #26 metric filter matches this prefix
   verbatim and TC-PROXY401-006 pins it as a contract.
2. **Fresh credentials per mint.** The default minter resolves credentials
   via a NEW `fromNodeProviderChain()` per mint call instead of a shared
   memoized provider. Mint happens at most hourly (plus rare 401 retries), so
   the extra provider-chain resolution cost is negligible against the
   guarantee that a re-mint after 401 can't re-sign with the same dead
   session. The minter stays injectable for tests.

The refresh timer, health semantics, non-auth status passthrough, and error
mapping (502/504) are unchanged.

## Alternatives considered

- **Shorter refresh interval:** narrows but doesn't close the window; the
  memoized-credentials bug would persist (re-mint with dead session).
- **Ingest retry/DLQ in mnemo-server:** requires forking upstream; the proxy
  fix removes the failure class at its source.
- **expireTime-aware provider cache:** subtler and still trusts the provider's
  view of expiry; per-mint resolution is simpler and provably fresh.

## Concurrency note

Concurrent requests hitting 401 may each trigger a re-mint; mints are cheap,
local, and idempotent (last writer wins on `state.token`), so no locking is
added — matching the existing refresh-timer behavior.

## Rollback

Revert the commit; behavior returns to timer-only refresh.
