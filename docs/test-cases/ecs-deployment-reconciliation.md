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
| TC-DEPLOY-009 | ECS service still exposes multiple deployments after the waiter | Reconciliation exits nonzero with `multiple_deployments` |
| TC-DEPLOY-010 | ECS stability waiter times out | Reconciliation exits nonzero with `stabilization_timeout`; no state-inspection call is guessed or retried as remediation |
| TC-DEPLOY-011 | Running tasks use more than one task definition | Reconciliation exits nonzero with `mixed_task_definitions` |
| TC-DEPLOY-012 | AWS responses contain account IDs, task ARNs, service ARNs, and task-definition ARNs | Logs contain stage, normalized `family:revision`, and image tag, but no 12-digit account ID or `arn:` string |
| TC-DEPLOY-013 | IAM reconciliation policy is inspected | Its action set is exactly `ssm:GetParameters`, `ecs:DescribeServices`, `ecs:ListTasks`, and `ecs:DescribeTasks` |
| TC-DEPLOY-014 | Match and drift fixtures execute through the fake AWS CLI | Match exits 0; drift exits nonzero; calls are recorded in deterministic order |
| TC-DEPLOY-015 | Recorded reconciliation commands and source are inspected | No `UpdateService`, task-definition listing, or other ECS mutation is called |
| TC-DEPLOY-016 | Reconciliation fails in the production job | The existing `failure()` deployment-reporting step runs; no separate remediation path is introduced |
