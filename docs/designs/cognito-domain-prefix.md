# Design: Cognito domain prefix

Date: 2026-08-13
Status: Approved

## Problem

Amazon Cognito requires an explicit prefix for its hosted domain. Prefixes are
shared across AWS accounts in a Region, so a stage-only name such as
`prod-mem9-mcp` lets only the first account in that Region deploy the stage.

The prefix is part of every OAuth endpoint. It must remain stable across normal
deployments and must not expose the AWS account ID.

## Decision

`MEM9_COGNITO_DOMAIN_PREFIX` remains the highest-priority input. A non-blank
override is trimmed and validated before any resource is created.

Without an override, derive the prefix from a versioned SHA-256 input tuple:

```text
["mem9-cognito-domain-v1", account-id, application-region, stage]
```

The emitted prefix is `mem9-` plus the first 20 hexadecimal digest characters.
This gives each account, Region, and stage a stable 80-bit namespace while
keeping the account ID out of the public hostname. The version marker makes any
future algorithm change explicit and testable.

The application Region comes from the active AWS provider and the account ID
comes from the deploy credentials. Both are Pulumi outputs resolved by the
resource graph, not copied configuration.

## Existing Production Deployment

The repository variable `MEM9_COGNITO_DOMAIN_PREFIX` is seeded with the current
production prefix before the workflow starts consuming it. Infra CI passes that
variable only to the production deploy, preserving the existing OAuth hostname.

Preview deploys intentionally do not receive the repository-wide production
override. They use the derived account/Region/stage default so concurrent stages
do not claim one shared prefix.

New repositories may omit the variable and use the derived default for every
stage. Operators adopting this change after a successful legacy deployment must
set the variable to that stage's existing prefix before redeploying it.

## Validation

Overrides must be 1-63 lowercase letters, digits, or hyphens, without a leading
or trailing hyphen. Values containing Cognito's reserved `aws`, `amazon`, or
`cognito` keywords are rejected at synthesis.

The generated prefix uses only the fixed `mem9-` label and hexadecimal output,
so it satisfies those constraints by construction.

## Rollback

Keep the repository variable set to the existing production prefix. Reverting
the code then restores the previous stage-only fallback without changing the
live production domain.
