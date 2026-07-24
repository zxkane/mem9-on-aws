# Test cases: ECR registry scan-on-push

Design: [`docs/designs/ecr-registry-scanning.md`](../designs/ecr-registry-scanning.md)

## Preflight unit tests

| ID | Scenario | Expected |
|---|---|---|
| TC-ECR-SCAN-001 | Registry has the default BASIC configuration with no rules and the dedicated stack does not exist | Decision is `adopt` |
| TC-ECR-SCAN-002 | Dedicated stack owns a configuration equivalent to the complete declaration | Decision is `verify-owned`; no mutation |
| TC-ECR-SCAN-003 | Dedicated stack owns the singleton but current rules differ | Decision is `update-owned`; update uses the complete template |
| TC-ECR-SCAN-004 | External BASIC `SCAN_ON_PUSH` rules cover all four project repositories | Decision is `verify-only`; no adoption or mutation |
| TC-ECR-SCAN-005 | External BASIC rules cover sibling repositories but not this project | Decision is `fail-closed` |
| TC-ECR-SCAN-006 | External configuration uses `ENHANCED`, even with scan-on-push coverage | Decision is `fail-closed` because the required scan type is BASIC |
| TC-ECR-SCAN-007 | External BASIC rules cover only some project repositories | Decision is `fail-closed` and identifies incomplete coverage |
| TC-ECR-SCAN-008 | Repository filter matching | `mem9-on-aws/*` covers exactly the four project repositories and excludes sibling prefixes; AWS substring and wildcard semantics are preserved |
| TC-ECR-SCAN-009 | Dedicated stack name exists but does not own the singleton | Decision is `fail-closed` |

## Template and wrapper E2E tests

| ID | Scenario | Expected |
|---|---|---|
| TC-ECR-SCAN-010 | Parse the dedicated CloudFormation template | Exactly one `AWS::ECR::RegistryScanningConfiguration` declares BASIC, `SCAN_ON_PUSH`, and `${ProjectName}/*` |
| TC-ECR-SCAN-011 | Parse the retained repository template | It still contains exactly four `AWS::ECR::Repository` resources and no registry singleton |
| TC-ECR-SCAN-012 | Run wrapper with default-registry fixture and missing stack | Reads ECR first, validates the template, then creates and waits for the dedicated stack |
| TC-ECR-SCAN-013 | Run wrapper with externally compliant fixture | Exits successfully after verification with no mutation command |
| TC-ECR-SCAN-014 | Run wrapper with stack-owned drift fixture | Validates and updates the dedicated stack from the complete template |
| TC-ECR-SCAN-015 | Run wrapper with stack-owned equivalent fixture | Exits successfully with no mutation command |
| TC-ECR-SCAN-016 | Run wrapper with sibling, conflicting scan type, partial coverage, or stack-name conflict | Every path exits nonzero before create, update, delete, or direct registry mutation |
| TC-ECR-SCAN-017 | Inspect wrapper and both ECR templates | No repository-level scan-on-push API or repository property is used |
| TC-ECR-SCAN-018 | Parse deploy-role IAM | Registry operations are exactly `GetRegistryScanningConfiguration`, `PutRegistryScanningConfiguration`, and `DescribeImageScanFindings` |
| TC-ECR-SCAN-019 | Scan changed documentation and examples | No account ID, live ARN, API key, private repository reference, or comment permalink is present |
| TC-ECR-SCAN-020 | Stack-owned drift but CloudFormation reports no template update | Reapply the complete declared registry configuration directly; never treat unresolved drift as success |
| TC-ECR-SCAN-021 | Registry state changes between initial preflight and mutation | Read and decide again immediately before mutation; external sibling rules fail closed |
| TC-ECR-SCAN-022 | Parse deploy-role singleton IAM condition | Registry get/put is limited to `ap-northeast-1` with `aws:RequestedRegion` |
| TC-ECR-SCAN-023 | CI CloudFormation validation | `cfn-lint` performs schema validation on the dedicated template before unit tests |
| TC-ECR-SCAN-024 | Registry still differs after a successful owned update | Read-back verification exits nonzero instead of reporting convergence |
| TC-ECR-SCAN-025 | Dedicated stack loses ownership after adoption | Read-back verification exits nonzero instead of accepting external state |

## Operator verification

| ID | Scenario | Expected |
|---|---|---|
| TC-ECR-SCAN-026 | Query findings for a project image after a push-triggered BASIC scan completes | `describe-image-scan-findings` returns scan status and findings without mutating the image or registry |
