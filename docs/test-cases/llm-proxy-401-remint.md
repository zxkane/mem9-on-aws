# Test cases: llm-proxy 401-reactive re-mint (issue #24)

Design: [`docs/designs/llm-proxy-401-remint.md`](../designs/llm-proxy-401-remint.md)

All run in `docker/llm-proxy/server.test.mjs` (vitest, injected minter+fetch,
real HTTP server on loopback).

| ID | Scenario | Expected |
|---|---|---|
| TC-PROXY401-001 | **Regression (fails before fix):** upstream returns 401 once, then 200 | Proxy re-mints (mintToken called 2×), retries with the NEW bearer, client sees 200; retry request carries `Bearer <new-token>` |
| TC-PROXY401-002 | Upstream returns 401 on the original AND the retry | Client sees the 401 body passed through; mintToken called exactly 2× (initial + one re-mint — no loop) |
| TC-PROXY401-003 | Upstream returns 403 | Same re-mint+retry path as 401 |
| TC-PROXY401-004 | Upstream returns non-auth, non-retry status 400/404/501 | NO re-mint (mintToken called 1x), status passes straight through |
| TC-PROXY401-005 | Re-mint itself throws | Mapped to the existing 502 error shape; no crash |
| TC-PROXY401-006 | Distinct structured log on the re-mint path | Redacted record contains request ID, attempt 1, status 401, and reason `auth_remint` |
| TC-PROXY401-007 | Fresh credentials per mint (direct-run minter) | The default minter constructs a new provider chain per call — asserted via the exported `makeDefaultMintToken` factory taking an injectable `createProvider`, called once per mint |
| TC-PROXY401-008 | Existing suite | All pre-existing tests still pass unchanged (timer refresh keep-old-token-on-failure, health gating, header injection, 404 routing, timeout→504) |
