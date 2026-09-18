# Test cases: deploy role isolation

| ID | Scenario | Expected |
|---|---|---|
| TC-DEPLOYROLE-001 | Inspect preview trust | Only `preview-ci` and `preview-maintenance` can assume it |
| TC-DEPLOYROLE-002 | Inspect production trust | Only the protected `prod` Environment subject can assume it |
| TC-DEPLOYROLE-003 | Simulate preview access to production resources | Explicit deny for representative SSM, secret, ECS, Lambda, RDS, IAM, and state resources |
| TC-DEPLOYROLE-004 | Simulate production access to preview resources | Explicit deny for representative `pr-*` resources |
| TC-DEPLOYROLE-005 | Main change touches only role/workflow/docs/tests | Tests run; ECR build and SST production deployment skip |
| TC-DEPLOYROLE-006 | Main change touches application IaC only | Production deploy reuses the current deployed image tag |
| TC-DEPLOYROLE-007 | Change touches any workload image input | All four images build under one shared release tag |
| TC-DEPLOYROLE-008 | Production mutation is ready | Job waits for `prod` Environment approval before AWS credentials |
| TC-DEPLOYROLE-009 | Fork pull request runs | No repository role secret and no AWS mutation path |
| TC-DEPLOYROLE-010 | Pull request closes | Preview cleanup still uses the preview role |
| TC-DEPLOYROLE-011 | Scheduled preview reconciliation runs | Dedicated preview-maintenance subject uses the preview role |
| TC-DEPLOYROLE-012 | Additive owner-stack rollout | New roles exist while legacy role remains usable |
| TC-DEPLOYROLE-013 | Legacy retirement | Old role trust is disabled and its repository secret removed only after both paths pass |
| TC-DEPLOYROLE-014 | Rollback is invoked | Legacy role can be conditionally restored without widening fork trust |
| TC-DEPLOYROLE-015 | Preview workload images are built | All four `pr-*` tags are written only below `mem9-on-aws/preview/*` and the preview task definitions reference that namespace |
| TC-DEPLOYROLE-016 | Production image publication is attempted against preview repositories | Production role receives an explicit deny |
