# Test cases: OAuth refresh-token rotation

The OAuth facade's Cognito reader client rotates refresh tokens so MCP clients
that replace their stored token response can refresh repeatedly without another
browser login. The facade never logs or diagnoses with token values.

| ID | Scenario | Expected result |
| --- | --- | --- |
| TC-OAUTH-REFRESH-001 | Synthesize the reader user-pool client | Refresh-token rotation is `ENABLED` with a 10-second retry grace period, and `ALLOW_REFRESH_TOKEN_AUTH` is absent from `explicitAuthFlows` |
| TC-OAUTH-REFRESH-002 | Exchange an authorization code through the facade | The client receives access, ID, and initial refresh tokens while the facade injects its confidential-client secret only into the upstream request |
| TC-OAUTH-REFRESH-003 | Submit the initial refresh token | The first refresh succeeds and returns a non-empty replacement refresh token |
| TC-OAUTH-REFRESH-004 | Submit the replacement refresh token | A second consecutive refresh succeeds and returns another non-empty replacement refresh token |
| TC-OAUTH-REFRESH-005 | Inspect the synthesized and deployed rotation configuration | The retry grace period is exactly 10 seconds, allowing a client to retry briefly before Cognito invalidates the rotated-out token |
| TC-OAUTH-REFRESH-006 | Cognito returns a successful refresh response with a missing or empty refresh token | The facade returns a content-free `502 invalid_upstream_response` diagnostic instead of exposing an unusable successful credential |
| TC-OAUTH-REFRESH-007 | Inspect logs and diagnostics for the authorization-code and refresh sequence | Access, ID, refresh, and confidential-client secret values are absent |
| TC-OAUTH-REFRESH-008 | Run the preview OAuth smoke against the deployed reader client | `DescribeUserPoolClient` reports rotation enabled with the expected grace period and no `ALLOW_REFRESH_TOKEN_AUTH`; the check is non-interactive and prints no credential values |
