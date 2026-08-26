# Test cases: OAuth facade compliance authorizer

The facade authorizer is a mandatory compliance shim on both internet-reachable
API Gateway routes. It preserves anonymous access to discovery, `/oauth/*`, and
`/register`; the facade handler remains responsible for the real `/mcp`
bearer-token check.

## Unit tests

| ID | Scenario | Expected |
|---|---|---|
| TC-FACADEAUTH-001 | Synthesize the OAuth facade | One payload-v2 simple-response Lambda authorizer is always created with no identity sources and zero cache TTL; its arm64 function and execution role receive stable project-prefixed names |
| TC-FACADEAUTH-002 | Inspect both facade routes | The root and catch-all routes both bind the allow-all authorizer ID; neither route can synthesize with `authorizationType: NONE` |
| TC-FACADEAUTH-003 | Allow-all authorizer invocation | The handler resolves to `{ isAuthorized: true }` |
| TC-FACADEAUTH-004 | Synthesize the full SST graph across optional scheduler/Slack configurations | The facade-authorizer role is always present with the exact permissions boundary; the Lambda keeps its stable name and Node 24/arm64 settings; the authorizer emits payload v2, simple responses, empty identity sources, and zero TTL; both routes emit `CUSTOM` authorization |
| TC-FACADEAUTH-005 | Verify deployment IAM and production runtime bindings | The authorizer Lambda and role are required as the fourth Lambda binding, remain Lambda-only, are covered by the boundary's cold-start KMS context, and cannot be passed to another service |
