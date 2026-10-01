# Cloudflare account resolution test cases

## Scope

Both normal production deployment and guarded production runtime cutover resolve
the Cloudflare account that owns the configured zone before SST initializes its
Cloudflare provider. Both paths use the same Node.js helper. Pull-request preview
deployments and runtime rehearsals remain independent of production Cloudflare
credentials.

## Cases

### TC-CF-ACCOUNT-001: Resolve the account before production deployment

- Given the production custom-domain secrets are configured
- When the production deployment job runs
- Then it queries the configured Cloudflare zone before `sst deploy`
- And exports the owning account as `CLOUDFLARE_DEFAULT_ACCOUNT_ID`
- And masks the resolved account ID before writing it to the GitHub Actions
  environment

### TC-CF-ACCOUNT-002: Keep Cloudflare credentials production-only

- Given a pull-request preview deployment
- When its SST deployment step runs
- Then it receives no custom-domain, Cloudflare token, zone, or account
  configuration

### TC-CF-ACCOUNT-003: Fail closed on an unusable zone response

- Given Cloudflare rejects the request or omits a valid account ID
- When the account-resolution step runs
- Then the step fails before SST deployment
- And it does not export an empty or malformed account ID

### TC-CF-ACCOUNT-004: Preserve deployments without a custom domain

- Given no production custom domain is configured
- When the account-resolution step runs
- Then it succeeds without calling Cloudflare
- And it exports no Cloudflare account ID

### TC-CF-ACCOUNT-005: Resolve before guarded production cutover

- Given production custom-domain configuration
- When the runtime-cutover production job runs
- Then the shared resolver completes before the guarded runtime action
- And resolution failure prevents any SST or credential-migration action
- And the preview runtime job receives no production Cloudflare configuration

### TC-CF-ACCOUNT-006: Keep credentials out of command arguments and diagnostics

- Given a token and a provider error containing that token
- When the shared Node.js resolver runs
- Then the token is read from environment and used only in the request header
- And no token or response body appears in process arguments or output
- And failure diagnostics contain only controlled reason/status/code fields
- And a valid account is masked before the GitHub environment is written

### TC-CF-ACCOUNT-007: Validate the configured zone and returned account

- Given a malformed zone ID, mismatched returned zone, missing account, or invalid account ID
- When resolution runs
- Then it fails closed and exports nothing
- And malformed configuration makes no HTTP request
- And resolution only queries the configured zone, never the account-list endpoint

### TC-CF-ACCOUNT-008: Bound transient retries and response handling

- Given network failures, rate limiting, or server errors
- When resolution runs
- Then it attempts at most four requests, each with a 15-second timeout
- And backoff is bounded to 1, 2, and 4 seconds, for a nominal maximum of 67 seconds
- And permanent denial or malformed provider data fails without further retry
- And failed response bodies are consumed or cancelled without being logged

### TC-CF-ACCOUNT-009: Bind the resolver to rollout evidence

- Given a change to the shared resolver
- When the production coordinator digest is calculated
- Then the resolver is included among its source dependencies
- And prior source-tree-bound rehearsal evidence cannot authorize the changed revision
- And the new revision requires full preview and actual cancellation/recovery/resume validation
