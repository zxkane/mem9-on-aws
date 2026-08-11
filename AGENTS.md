# AGENTS.md — repo conventions for AI agents

Conventions and hard rules for AI agents (Claude Code, and any tool that reads
`AGENTS.md`) working in this repo. For the project overview and architecture, see
[`README.md`](README.md); for the authoritative decisions and upstream mem9
constraints, see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and
[`docs/mem9-facts.md`](docs/mem9-facts.md).

## Read first

Before designing, changing infra, or answering mem9/AWS questions, read
[`docs/mem9-facts.md`](docs/mem9-facts.md) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
They hold facts that are expensive to re-derive (probed from mem9 source + verified
against AWS docs). Treat them as authoritative; if code or AWS behavior contradicts
them, update the file rather than silently diverging.

## Hard rules

- **AWS compliance**: known constraints to honor here — **no Lambda Function URL**
  (use API Gateway / AgentCore Gateway), **Lambda runtime `nodejs24.x`**,
  least-privilege IAM, and **no hardcoded account IDs / ARNs in committed files**
  (use `<aws-account-id>` placeholders).
- **Node.js 24 LTS** everywhere (`.nvmrc` = 24, `engines.node >= 24`, CI + Lambda
  `nodejs24.x`). The Go build for mnemo-server targets **arm64**
  (`CGO_ENABLED=0 GOARCH=arm64`).
- **Never commit secrets**: no real account IDs, ARNs with account numbers,
  Cognito pool IDs, gateway URLs, API keys, client secrets, or memory content —
  use placeholders (e.g. `<aws-account-id>`). Environment-specific values go in a
  gitignored `.env` (see `.env.example`), never in tracked files. Scan before every
  commit that touches tracked files:

  ```bash
  grep -niE '[0-9]{12}|arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}|X-API-Key' <files>
  # the placeholder 123456789012 used in tests is fine.
  ```

- **Data ownership is the whole point**: any change that sends memory content or
  embeddings to a third party (e.g. OpenAI direct, a mem9 SaaS) violates the
  project's reason to exist — flag it, don't silently adopt it.
- **CI runners**: workflows select their runner via the `RUNNER_LABEL` repo
  variable with a lazy ternary so an unset variable falls back to GitHub-hosted:

  ```yaml
  runs-on: ${{ vars.RUNNER_LABEL && fromJSON(vars.RUNNER_LABEL) || 'ubuntu-latest' }}
  ```

  Keep `fromJSON` — `${{ vars.RUNNER_LABEL || 'ubuntu-latest' }}` passes the literal
  JSON string as a single label and never matches.

## Region topology

- This deployment is region-heterogeneous. Never treat the application region,
  `us-west-2`, or one ambient `AWS_REGION` as a universal region for every
  component.
- The application plane (SST resources, ECR images, primary Mantle route, and
  VPC) uses `providers.aws.region` in `sst.config.ts` as its single source of
  truth. Changing that value retargets all application-plane consumers together
  for a fresh deployment; it does not relocate existing regional resources.
- An existing IAM ownership stack records its application region. A mismatch
  with `sst.config.ts` must fail before mutation. Live relocation requires a
  dedicated dual-region migration after every old-region preview is removed;
  never update the boundary or deploy role in place to force the move.
- The account-global IAM ownership stacks are intentionally hosted in
  `us-west-2`. The optional Mantle Responses route has its own independently
  configured region and regional Project (default `us-west-2`). OpenAI GPT
  models selected by the configured prefix use that route when unavailable in
  the application region. Do not "normalize" either plane to the application
  region.
- For operator commands, identify the component first and pass its specific
  region variable. Preserve service-specific region settings when editing
  examples or automation.

## OAuth operator memory

- The Cognito resource server defines `mem9-mcp/read` and `mem9-mcp/write`.
  M2M clients may request both. The browser/hosted-client OAuth facade is
  intentionally read-only and advertises only `openid`, `email`, and
  `mem9-mcp/read`; do not assume a facade token can call write tools.
- Hosted callback URLs come from the stage-scoped SST secret
  `OauthAllowedCallbackUrls`. This is not a GitHub Actions environment/repository
  secret, and external URLs must not be added to the Cognito reader client's
  callback list. Cognito redirects only to the facade's own `/oauth/callback`.
- A hosted callback may itself run in any region; its exact public HTTPS URL is
  allowlisted independently of the AWS region hosting the OAuth facade.
- The secret is one complete JSON array, so `sst secret set` replaces the entire
  allowlist. Read the current stage value and preserve existing entries when
  adding one. Values are exact HTTPS URLs (no wildcard, credentials, or
  fragment), with at most 20 unique entries and 1 KiB of serialized JSON.
- After changing the secret, redeploy the same stage so SST updates SSM and
  refreshes the facade Lambda. For production:

  ```bash
  pnpm -C infra exec sst secret set OauthAllowedCallbackUrls \
    '["https://existing.example.com/callback","https://new.example.com/callback"]' \
    --stage prod
  gh workflow run "Infra CI" --ref main
  ```

  Monitor the production workflow through its OAuth facade smoke test. Do not
  print unrelated SST secrets while inspecting the current callback allowlist.

## Out-of-band bootstrap scripts

`scripts/deploy-*.sh` create resources the SST app references read-only (the
GitHub Actions IAM role, four ECR repositories, and the Bedrock Mantle Project)
so that a `sst remove --stage pr-N` can never wipe shared/prod state. They are NOT
part of the CI deploy — run them once per AWS account. Each reads its config from a
gitignored `.env` (copy `.env.example` and fill in your own AWS profile). See each
script's header comment for what it provisions and when to re-run it.
