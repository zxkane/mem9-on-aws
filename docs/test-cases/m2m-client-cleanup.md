# Test cases: M2M client cleanup

The Cognito stack retains the original confidential machine-to-machine client
and removes the unused second client. The browser OAuth reader remains a
separate client managed by the facade.

| ID | Scenario | Expected |
|---|---|---|
| TC-M2M-CLEANUP-001 | Synthesize the Cognito stack | Exactly one confidential M2M user-pool client is created with `client_credentials` and the existing read/write scopes |
| TC-M2M-CLEANUP-002 | Inspect Cognito SSM exports | The original client ID and secret remain exported, and no parameter is created below `cognito/client2/` |
| TC-M2M-CLEANUP-003 | Synthesize the AgentCore Gateway | `allowedClients` contains the remaining M2M client ID and the browser-login reader client ID |
