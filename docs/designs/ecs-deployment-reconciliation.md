# Design: ECS deployment reconciliation (issue #45)

Date: 2026-07-24
Status: Approved

## Problem

The image workflow treats every event other than `push` as a pull request. A
manual `workflow_dispatch` therefore publishes `pr-<sha7>` instead of the
production `mem9-<sha7>` and `latest` tags.

The production job also trusts a successful SST command and the existing image
SSM export. If deployment stops after SST exports new desired values but before
ECS finishes replacing the service tasks, CI can report success while ECS still
runs an older task definition or a mixture of image tags.

## Decision

Use two small Node.js 24 command modules:

1. `scripts/image-tags.mjs` is the single event-to-tag function used by the
   workflow. `push` and `workflow_dispatch` return `mem9-<sha7>, latest`;
   `pull_request` returns only `pr-<sha7>`.
2. `scripts/reconcile-ecs-deployment.mjs` is a detection-only verifier. It reads
   the exact task-definition ARN and release tag exported by the current SST
   deployment, waits for ECS service stability, then inspects the service
   deployments and every running task.

SST exports two new String parameters:

```text
/mem9-on-aws/<stage>/ecs/task-definition
/mem9-on-aws/<stage>/ecs/image-tag
```

These parameters are the only desired deployment identity used by the verifier.
It never lists task-definition revisions, chooses a revision, calls
`UpdateService`, or performs remediation.

## Data Flow

```text
GitHub event + commit SHA
  -> image-tags.mjs
  -> build and push all images under one release tag
  -> MEM9_IMAGE_TAG
  -> SST creates task definition and exports task-definition ARN + image tag
  -> reconcile-ecs-deployment.mjs
       -> SSM GetParameters
       -> ECS services-stable waiter
       -> ECS DescribeServices (one PRIMARY deployment)
       -> ECS ListTasks (RUNNING for this service)
       -> ECS DescribeTasks (task-definition ARN + three container images)
       -> match: continue deployment job
       -> mismatch: exit nonzero into the existing deployment-failure path
```

## Match Contract

A deployment matches only when all of these are true:

- ECS stabilization succeeds.
- The service has exactly one resolved deployment and one PRIMARY deployment.
- The PRIMARY deployment task definition exactly equals the exported ARN.
- At least one running task exists.
- Every listed task is running and uses the exported task definition.
- Every task contains `mnemo-server`, `qwen3-embed`, and `llm-proxy`.
- Every application container image uses the exported release tag.

Mixed task definitions, mixed tags, missing tasks or containers, AWS lookup
failures, and waiter timeout are mismatches.

## Diagnostics And IAM

Diagnostics include only the stage, `family:revision` task-definition identity,
release tag, task count, and normalized mismatch reasons. AWS CLI stderr,
account IDs, task ARNs, service ARNs, and full task-definition ARNs are never
printed.

The verifier exercises exactly these IAM actions:

- `ssm:GetParameters`
- `ecs:DescribeServices`
- `ecs:ListTasks`
- `ecs:DescribeTasks`

The existing deployment role retains its separate provisioning permissions,
but these four reads are grouped and asserted as the reconciliation surface.

## Testing

- Pure function tests pin event-to-tag behavior and workflow use of the module.
- Mock-response tests pin reconciliation parsing and redacted diagnostics.
- Deterministic fake AWS CLI fixtures execute the command for match and
  mismatch paths and record every API call.
- IAM tests assert the reconciliation action set exactly matches command use.
- Workflow tests assert a mismatch exits through the existing failure-reporting
  step.

## Rollback

Revert the workflow verifier steps and the two SSM exports. No ECS state is
changed by reconciliation, so rollback requires no cloud-side remediation.
