# Cognito domain prefix

## Derived Default

| ID | Scenario | Expected result |
| --- | --- | --- |
| TC-COGDOMAIN-001 | Resolve the same account, application Region, and stage repeatedly without an override | The exact versioned `mem9-<20 hex>` prefix is stable |
| TC-COGDOMAIN-002 | Change only the AWS account | The derived prefix changes without exposing the account ID |
| TC-COGDOMAIN-003 | Change only the application Region | The derived prefix changes |
| TC-COGDOMAIN-004 | Change only the stage | The derived prefix changes |
| TC-COGDOMAIN-005 | Construct the Cognito stack from Pulumi account and Region outputs | `UserPoolDomain.domain` receives the resolved derived prefix |

## Override

| ID | Scenario | Expected result |
| --- | --- | --- |
| TC-COGDOMAIN-010 | Supply `MEM9_COGNITO_DOMAIN_PREFIX` explicitly or through the process environment | The trimmed override wins over the derived default |
| TC-COGDOMAIN-011 | Leave the override absent or blank | The account/Region/stage default is used |
| TC-COGDOMAIN-012 | Supply invalid characters, invalid length, edge hyphens, or an AWS-reserved keyword | Synthesis fails before resource creation |
| TC-COGDOMAIN-013 | Supply valid one- and 63-character boundaries | The override is accepted |
| TC-COGDOMAIN-014 | Construct the production stack with the environment override | `UserPoolDomain.domain` receives the exact existing prefix |

## CI And Documentation

| ID | Scenario | Expected result |
| --- | --- | --- |
| TC-COGDOMAIN-020 | Run the production deploy through Infra CI | The deploy receives `${{ vars.MEM9_COGNITO_DOMAIN_PREFIX }}` so this repository retains its existing hostname |
| TC-COGDOMAIN-021 | Run a PR preview through Infra CI | The production repository override is absent and the stage uses its derived default |
| TC-COGDOMAIN-022 | Read operator guidance | Existing deployments are told to preserve their current prefix before redeploying; new deployments may omit the variable |
