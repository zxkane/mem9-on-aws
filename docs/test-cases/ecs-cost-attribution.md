# ECS cost attribution test cases

These cases protect the task-level tags required to attribute Fargate charges in
Cost Explorer.

## Service tag propagation

### TC-ECS-COST-001: Propagate service tags to new tasks

- Given the SST ECS Service transform
- When the underlying `aws.ecs.Service` arguments are produced
- Then `propagateTags` is `SERVICE`

### TC-ECS-COST-002: Enable ECS-managed task tags

- Given the SST ECS Service transform
- When the underlying `aws.ecs.Service` arguments are produced
- Then `enableEcsManagedTags` is `true`

### TC-ECS-COST-003: Preserve existing service behavior

- Given the tag-attribution settings
- When the Service transform also configures Cloud Map
- Then the service registry and deployment dependency remain configured

### TC-ECS-COST-004: Replace tasks when propagation is enabled

- Given an existing Service whose running tasks predate tag propagation
- When SST updates the Service with the attribution settings
- Then a versioned deployment trigger forces replacement of the existing tasks
- And the replacement tasks receive the propagated tags

## Bootstrap task tag propagation

### TC-ECS-COST-005: Propagate task-definition tags to the one-shot task

- Given the tagged bootstrap task definition
- When the deployment script invokes `aws ecs run-task`
- Then the task definition carries `Project`, `Stage`, and `ManagedBy`
- And it sets `--propagate-tags TASK_DEFINITION`
- And it enables ECS-managed tags
