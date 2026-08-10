# Test cases: OAuth façade metadata issuer (RFC 8414 §3.3)

The façade publishes itself as the authorization server in its RFC 9728
protected-resource document (`authorization_servers: [<base>]`). RFC 8414 §3.3
therefore requires the `issuer` in the metadata it serves at its own well-known
paths to be **identical** to that same base URL:

> The `issuer` value returned MUST be identical to the authorization server's
> issuer identifier value into which the well-known URI string was inserted to
> create the URL used to retrieve the metadata. If these values are not
> identical, the data contained in the response MUST NOT be used.

Before #143 both documents returned the **upstream Cognito** issuer instead. A
client that enforces §3.3 (`rmcp >= 3.0.0`, e.g. Codex `0.147.0`) discards the
whole document and fails MCP startup with `Authorization server issuer mismatch`.
Clients that skip the check were unaffected, which is why the defect survived from
the façade's first commit.

Cognito remains the token issuer: minted JWTs still carry the Cognito `iss` claim,
and the AgentCore Gateway's JWT authorizer still validates against Cognito's own
discovery URL. Only the metadata *self-identifier* is the façade's.

## Unit tests

`infra/src/oauth-facade/handler.test.ts`

| ID | Scenario | Expected |
|---|---|---|
| TC-MCPGW-079 | Fetch the protected-resource, AS-metadata, and OIDC-discovery documents on the **bare** well-known paths | `issuer` in both the AS and OIDC documents is identical to `authorization_servers[0]`, and neither equals the upstream Cognito issuer |
| TC-MCPGW-079 | Same three documents on the **resource-suffixed** paths (`/.well-known/<doc>/mcp`) | Identical result — this is the path a spec-compliant client queries first (see TC-MCPGW-061c) |

Both cases assert the **relationship between the two live documents** rather than a
hardcoded hostname. A test pinning the literal expected host would keep passing if
the two documents later drifted apart again, which is precisely the defect. The
`not.toBe(UPSTREAM_ISSUER)` assertions additionally catch a partial fix that
updates only one of the two handlers.

## E2E / preview tests

`scripts/run-oauth-facade-smoke.sh` (run by the `deploy-preview` job's
"OAuth façade smoke (preview)" step)

| ID | Scenario | Expected |
|---|---|---|
| TC-MCPGW-079 | Against the **deployed** façade, compare `.issuer` from `/.well-known/oauth-authorization-server` with `.authorization_servers[0]` from `/.well-known/oauth-protected-resource` | Identical; otherwise `::error::` and a non-zero exit |
| TC-MCPGW-079 | Same comparison for `/.well-known/openid-configuration` | Identical; otherwise `::error::` and a non-zero exit |

The script already validated `authorization_endpoint`, `token_endpoint`, S256,
`registration_endpoint`, and the public-client auth method — but never `issuer`,
so it could not have caught this. Verified by running the assertion block against
two mock façades: one advertising its own base (passes, exit 0) and one
reproducing the pre-fix shape (fails with the `::error::` line, exit 1).

## Config

`infra/src/oauth-facade/config.test.ts`

| ID | Scenario | Expected |
|---|---|---|
| — | `loadConfig` with a required env var absent | Still throws `missing env <NAME>`. The case previously used the upstream-issuer env var; #143 removed that variable (nothing consumed it once the façade stopped advertising the upstream issuer), so the case was **re-pointed** to another required var rather than deleted |
