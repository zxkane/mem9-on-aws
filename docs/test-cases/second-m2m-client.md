# Test cases: second M2M client

The Cognito stack provisions a second confidential client for independent
machine-to-machine access. Both M2M clients use the same resource server and
remain explicitly trusted by the AgentCore Gateway.

| ID | Scenario | Expected |
|---|---|---|
| TC-M2M2-001 | Synthesize the Cognito stack | Two confidential user-pool clients are created with generated secrets, `client_credentials` as their only OAuth flow, and the existing read/write scopes |
| TC-M2M2-002 | Inspect the second client's SSM exports | The client ID is a `String` at `cognito/client2/client-id`, and the secret is a `SecureString` at `cognito/client2/client-secret` |
| TC-M2M2-003 | Synthesize the AgentCore Gateway | `allowedClients` contains both M2M client IDs and the browser-login reader client ID |
