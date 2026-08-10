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

Both cases assert **two things, because either alone is insufficient**:

1. the **relationship** between the live documents (`issuer` ===
   `authorization_servers[0]`) — this is what §3.3 actually requires, and it holds
   on any host or stage; and
2. an **absolute anchor** (`authorization_servers[0]` === the façade's own base) —
   this is what rules out *coordinated* drift.

Relationship-only would be strictly weaker: three documents that all agree on the
**upstream** issuer satisfy §3.3 while sending clients to Cognito, which publishes
no `registration_endpoint` — so DCR fails and #143's symptom returns by another
route. Verified against a mock serving exactly that shape.

The `not.toBe(UPSTREAM_ISSUER)` assertions additionally catch a partial fix that
updates only one of the two handlers (verified by mutation: reverting either handler
alone fails both cases).

## Related asymmetry closed at the same time

The defect shipped because one document was asserted and its twin was trusted. The
same asymmetry existed two fields over, so `TC-MCPGW-080` now pins
`authorization_endpoint`, `token_endpoint`, `registration_endpoint` (must be the
façade's) and `jwks_uri`, `userinfo_endpoint`, `revocation_endpoint` (must be
Cognito's) on **both** documents. Before it, pointing the OIDC document's
`authorization_endpoint` or `token_endpoint` at upstream Cognito — or replacing
`jwks_uri` with a garbage value — passed all 57 handler cases.

`TC-MCPGW-081` covers the `WWW-Authenticate` rewrite on a 401 from upstream. That
header is the RFC 9728 discovery *entry point* — it tells the client where the
protected-resource document lives — and it embeds the same host-derived base under
the same invariant, yet had no coverage: pointing it at an unrelated host also
passed all 57 cases. Because discovery never starts if this URL is wrong, no
metadata test can observe that failure.

## E2E / preview tests

`scripts/run-oauth-facade-smoke.sh` (run by the `deploy-preview` job's
"OAuth façade smoke (preview)" step)

| ID | Scenario | Expected |
|---|---|---|
| TC-MCPGW-079 | Against the **deployed** façade, assert `.authorization_servers[0]` is the façade URL read from SSM (the absolute anchor; trailing slash normalized) | Identical; otherwise `::error::` and a non-zero exit |
| TC-MCPGW-079 | Compare `.issuer` from `/.well-known/oauth-authorization-server` with `.authorization_servers[0]` | Identical; otherwise `::error::` and a non-zero exit |
| TC-MCPGW-079 | Same comparison for `/.well-known/openid-configuration` | Identical; otherwise `::error::` and a non-zero exit |
| TC-MCPGW-079 | Any of those fields **missing, null, or empty** in the live documents | `::error::` naming the field, then a non-zero exit |
| TC-MCPGW-079 | `authorization_servers[0]` differs from the AS `issuer` only by a **trailing slash** | Fails the §3.3 comparison. The anchor check normalizes the trailing slash (SSM is deployment ground truth for the façade's own URL); the document-to-document comparison is byte-exact, because §3.3 requires *identical*, and a compliant client rejects on the byte difference |

The script already validated `authorization_endpoint`, `token_endpoint`, S256,
`registration_endpoint`, and the public-client auth method — but never `issuer`,
so it could not have caught this. Verified by running the assertion block against
mock façades: one advertising its own base (passes, exit 0), one reproducing the
pre-fix shape (fails with the `::error::` line, exit 1), and one where all three
documents agree on the upstream issuer — §3.3-clean but functionally broken, which
the anchor is what catches.

The missing-field row is why each field is presence-checked on its own line before it
is read. Two shorter forms were tried against a mock serving a null `.issuer` and both
exit non-zero with **no `::error::` and no field named**, leaving an operator with
truncated output and no cause: a bare `jq -er` inside the assignment lets `set -e` kill
the script *at the assignment*, and hoisting the diagnostic into a helper invoked as
`$(field ...)` only redirects that diagnostic into the captured stdout — the same
silent failure, one level less obvious. The mock is also what caught it; the first two
attempts read as correct.

The mock harness asserts its extracted block contains every `::error::` string before
it runs a single mode. An earlier run of it reported two spurious passes because the
extraction had silently truncated at the first `fi`, so the checks under test were
never in the file being exercised — a green result from a harness that isn't running
the code is worse than a red one.

## Config

`infra/src/oauth-facade/config.test.ts`

| ID | Scenario | Expected |
|---|---|---|
| — | `loadConfig` with a required env var absent | Still throws `missing env <NAME>`. The case previously used the upstream-issuer env var; #143 removed that variable (nothing consumed it once the façade stopped advertising the upstream issuer), so the case was **re-pointed** to another required var rather than deleted |
