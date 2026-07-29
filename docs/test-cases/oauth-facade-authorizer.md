# Test cases: OAuth facade compliance authorizer

The facade authorizer is an optional compliance shim. It must preserve anonymous
access to discovery, `/oauth/*`, and `/register`; the facade handler remains
responsible for the real `/mcp` bearer-token check.

## Unit tests

| ID | Scenario | Expected |
|---|---|---|
| TC-FACADEAUTH-001 | `MEM9_FACADE_AUTHORIZER_ENABLED` is unset or not exactly `"1"` | No authorizer is created, and both facade routes retain an undefined third argument |
| TC-FACADEAUTH-002 | `MEM9_FACADE_AUTHORIZER_ENABLED="1"` | One payload-v2 simple-response Lambda authorizer is created with no identity sources and zero cache TTL; its arm64 function and execution role receive stable project-prefixed names, and both routes bind its ID |
| TC-FACADEAUTH-003 | Allow-all authorizer invocation | The handler resolves to `{ isAuthorized: true }` |
| TC-FACADEAUTH-004 | Synthesize the full SST graph with the switch off and on | Off: the original eight workload roles retain the exact permissions boundary, no authorizer is emitted, and both routes remain `NONE`. On: the ninth role keeps an allowed project prefix and the exact boundary; the authorizer Lambda keeps its project-prefixed name and Node 24/arm64 settings; the authorizer emits payload v2, simple responses, empty identity sources, and zero TTL; both routes emit `CUSTOM` authorization |
| TC-FACADEAUTH-005 | Verify deployment IAM with the optional authorizer present | The authorizer role is accepted only as an optional fourth Lambda binding, remains Lambda-only, is covered by the boundary's cold-start KMS context, and cannot be passed to another service |
