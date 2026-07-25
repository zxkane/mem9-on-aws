# Design Canvas - ECR registry scan-on-push

Feature: Out-of-band ECR registry scanning ownership
Date: 2026-07-24
Status: Approved (autonomous mode)

## Component Architecture

```text
deploy-ecr-registry-scanning.sh
  |
  +-- ECR GetRegistryScanningConfiguration (complete account/region state)
  +-- CloudFormation DescribeStacks/DescribeStackResources (ownership only)
  +-- ecr-registry-scanning-preflight.mjs (pure decision)
        |
        +-- adopt          -> validate + create dedicated stack
        +-- verify-owned   -> exit without mutation
        +-- update-owned   -> validate + update from complete declaration
        +-- verify-only    -> exit without adopting external rules
        +-- fail-closed    -> exit before every mutation command

Dedicated CloudFormation stack
  `-- AWS::ECR::RegistryScanningConfiguration
        ScanType: BASIC
        Rules:
          - ScanFrequency: SCAN_ON_PUSH
            RepositoryFilters:
              - Filter: mem9-on-aws/*
                FilterType: WILDCARD
```

The existing retained `AWS::ECR::Repository` resources remain in their current
out-of-band stack. The registry singleton is deliberately separate.

## Data Flow

1. Read the complete registry scanning configuration before any CloudFormation
   mutation.
2. Read whether the dedicated stack exists and owns the singleton resource.
3. Evaluate the current configuration, stack ownership, the four project
   repositories, and the complete declared configuration as pure data.
4. Repeat the complete registry and ownership read immediately before mutation.
5. Require the account owner to acknowledge an exclusive account/region writer
   window because ECR has no conditional registry-configuration write.
6. Permit a mutation only when the registry is default/unconfigured or the
   dedicated stack already owns the singleton.
7. Never merge external filters into the project template. Externally managed
   BASIC scan-on-push rules are accepted only when they cover all four project
   repositories; every other external state fails closed.

## Design Notes

- `${ProjectName}/*` is narrower than `${ProjectName}*`: it covers only
  repositories below the project's namespace separator.
- A filter without `*` uses ECR substring semantics, so matching is implemented
  according to the documented wildcard rules instead of as a prefix shortcut.
- Stack-owned drift can be replaced because the dedicated template is the
  complete declaration for the singleton. External drift is never replaced.
- The project prefix is constrained to a wildcard-free ECR repository-prefix
  pattern in both the wrapper and CloudFormation parameter.
- Missing registry fields or stack status are errors, never evidence of a
  default or stable configuration.
- The operator's `AWS_PROFILE` identity owns the registry get/put and findings
  permissions. The pull-request-capable GitHub Actions role intentionally has no
  registry-singleton mutation or findings access because CI never runs this
  wrapper.
- `DeletionPolicy: Retain` preserves the registry configuration if ownership is
  relinquished. An external owner can then install a complete account-level
  ruleset without this stack deleting it.
- The wrapper normally updates through CloudFormation. If an unchanged template
  cannot repair stack-owned drift, it reapplies the exact complete declaration
  through the registry-level API and verifies convergence. Before that direct
  write it saves the prior complete configuration to a mode-`0600`, gitignored
  local rollback file and prints the exact restore command on any subsequent
  write or verification failure, including the selected AWS profile when one is
  configured. It never calls ECR's repository-level scanning API.
- Fixture tests record every mocked AWS command so all conflict paths can prove
  that no mutation command was reached.
