# Test cases: OAuth facade compliance authorizer

The facade authorizer is an optional compliance shim. It must preserve anonymous
access to discovery, `/oauth/*`, and `/register`; the facade handler remains
responsible for the real `/mcp` bearer-token check.

## Unit tests

| ID | Scenario | Expected |
|---|---|---|
| TC-FACADEAUTH-001 | `MEM9_FACADE_AUTHORIZER_ENABLED` is unset or not exactly `"1"` | No authorizer is created, and both facade routes retain an undefined third argument |
| TC-FACADEAUTH-002 | `MEM9_FACADE_AUTHORIZER_ENABLED="1"` | One payload-v2 simple-response Lambda authorizer is created with no identity sources and zero cache TTL; both routes bind its ID |
| TC-FACADEAUTH-003 | Allow-all authorizer invocation | The handler resolves to `{ isAuthorized: true }` |
