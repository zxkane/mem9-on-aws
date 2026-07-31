# Cloudflare account resolution test cases

## Scope

The production deployment resolves the Cloudflare account that owns the
configured zone before SST initializes its Cloudflare provider. Pull-request
preview deployments remain independent of Cloudflare credentials.

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
