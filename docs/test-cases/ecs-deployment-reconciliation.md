# Test cases: ECS deployment reconciliation (issue #45)

Design:
[`docs/designs/ecs-deployment-reconciliation.md`](../designs/ecs-deployment-reconciliation.md)

| ID | Scenario | Expected |
|---|---|---|
| TC-DEPLOY-001 | Push to `main` at SHA `abcdef012...` | Tags are exactly `mem9-abcdef0` and `latest`; authoritative release tag is `mem9-abcdef0` |
| TC-DEPLOY-002 | Manual `workflow_dispatch` at SHA `abcdef012...` | Tags are exactly `mem9-abcdef0` and `latest`; no preview tag is generated |
| TC-DEPLOY-003 | Pull-request build at SHA `abcdef012...` | The only tag is `pr-abcdef0` |
| TC-DEPLOY-004 | SST ECS stack export | SSM receives the current task-definition ARN and exact `MEM9_IMAGE_TAG` under the stage's `/ecs/` prefix |
| TC-DEPLOY-005 | Stable service with one PRIMARY deployment; every running task uses the desired task definition and all three images use the desired tag | Reconciliation exits 0 and reports a normalized, ARN-redacted match |
| TC-DEPLOY-006 | SSM exports a new task definition but ECS PRIMARY and running task still use the old definition | Reconciliation exits nonzero with task-definition mismatch diagnostics |
| TC-DEPLOY-007 | One or more application containers use a different release tag | Reconciliation exits nonzero and reports mixed/image-tag mismatch |
| TC-DEPLOY-008 | ECS lists no running task for the service | Reconciliation exits nonzero with `no_running_tasks` |
| TC-DEPLOY-009 | ECS service still exposes multiple deployments after the bounded poll | Reconciliation exits nonzero with `multiple_deployments` |
| TC-DEPLOY-010 | ECS stability polling exhausts its bounded window | Reconciliation exits nonzero with `stabilization_timeout` and performs only safe read-only state inspection for diagnostics |
| TC-DEPLOY-011 | Running tasks use more than one task definition | Reconciliation exits nonzero with `mixed_task_definitions` |
| TC-DEPLOY-012 | AWS responses contain account IDs, task ARNs, service ARNs, and task-definition ARNs | Logs contain stage, normalized `family:revision`, and image tag, but no 12-digit account ID or `arn:` string |
| TC-DEPLOY-013 | IAM reconciliation policy is inspected | Its action set is exactly `ssm:GetParameters`, `ecs:DescribeServices`, `ecs:ListTasks`, and `ecs:DescribeTasks` |
| TC-DEPLOY-014 | Match and drift fixtures execute through the fake AWS CLI | Match exits 0; drift exits nonzero; calls are recorded in deterministic order |
| TC-DEPLOY-015 | Recorded reconciliation commands and source are inspected | No `UpdateService`, task-definition listing, or other ECS mutation is called |
| TC-DEPLOY-016 | Reconciliation fails in the production job | The independent `always()` reporter observes `needs.deploy-prod.result` and creates the failure issue |
| TC-DEPLOY-017 | The single desired PRIMARY rollout is initially `IN_PROGRESS`, then reports `COMPLETED` with zero pending tasks and the desired running count | Reconciliation waits within the bounded window and succeeds |
| TC-DEPLOY-018 | The single PRIMARY rollout remains `IN_PROGRESS` through the bounded window | Reconciliation exits nonzero with `stabilization_timeout` and `primary_not_completed`; it does not mutate ECS or wait indefinitely |
| TC-DEPLOY-019 | The desired PRIMARY deployment circuit breaker reports `FAILED` | Reconciliation stops polling immediately and exits nonzero with `primary_failed` |
| TC-DEPLOY-020 | A historical `ACTIVE` deployment is `FAILED` while the desired PRIMARY is `IN_PROGRESS` | Reconciliation ignores the historical failure, keeps polling, and succeeds when the desired PRIMARY settles |
| TC-DEPLOY-021 | Preview deploy fails or exhausts its job timeout after producing a validated `pr-N` stage | An independent 70-minute cleanup job removes stale Pulumi runtimes, then runs a bounded 15-minute remove, 22-minute ENI wait, and 15-minute retry with each `kill-after` allowance covered; same-PR workflows are serialized without cancellation |
| TC-DEPLOY-022 | Production deploy fails or exhausts its 75-minute timeout | An independent `always()` reporter job creates the failure issue from `needs.deploy-prod.result`; explicit whole-workflow cancellation is not claimed |
