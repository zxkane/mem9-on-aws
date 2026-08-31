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
   deployment, polls `DescribeServices` until the desired deployment is stable,
   then inspects every running task. The poll is just under 30 minutes because
   the AWS `services-stable` waiter is fixed at 15-second checks and 40 attempts
   (about 10 minutes), which is shorter than a measured fresh preview cold start.

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
       -> bounded ECS DescribeServices polling
          -> one desired PRIMARY deployment
          -> rolloutState COMPLETED
          -> pendingCount 0 and runningCount == desiredCount
       -> ECS ListTasks (RUNNING for this service)
       -> ECS DescribeTasks (task-definition ARN + three container images)
       -> match: continue deployment job
       -> mismatch: exit nonzero into the existing deployment-failure path
```

## Match Contract

A deployment matches only when all of these are true:

- ECS reaches the desired stable state within the bounded poll window.
- The service has exactly one resolved deployment and one PRIMARY deployment.
- The PRIMARY rollout reaches `COMPLETED` within the bounded follow-up window.
- The PRIMARY deployment task definition exactly equals the exported ARN.
- At least one running task exists.
- Every listed task is running and uses the exported task definition.
- Every task contains `mnemo-server`, `qwen3-embed`, and `llm-proxy`.
- Every application container image uses the exported release tag.

Mixed task definitions, mixed tags, missing tasks or containers, AWS lookup
failures, poll timeout, a failed deployment circuit breaker, and an incomplete
PRIMARY rollout are mismatches. A timeout still performs the safe read-only
service/task inspection so diagnostics distinguish a slow rollout from drift.
Only a failed PRIMARY for the desired task definition terminates polling;
historical `ACTIVE/FAILED` deployments are ignored while a newer PRIMARY
continues.

Preview failure cleanup runs in a separate 70-minute dependent job keyed by the
validated `pr-N` stage output. It runs after a failed deploy job or job timeout,
using the same bounded 15-minute remove, ENI-detach wait, and 15-minute retry as
PR-close cleanup. The three commands can consume 55 minutes including their
`kill-after` allowances; the remaining 15 minutes cover runner setup, Pulumi
cache cleanup, OIDC, unlock, and process startup. PR workflow runs for the same
stage are serialized without `cancel-in-progress`, so a newer commit waits for
the prior deployment or cleanup instead of cancelling teardown or racing the
same SST state. Production failure reporting likewise runs in a separate
`always()` job based on `needs.deploy-prod.result`; it can create the failure
issue when the 75-minute production deploy job fails or times out. Explicit
cancellation of the whole workflow is operator-controlled and is not claimed
to run downstream jobs.

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
- Budget tests keep the stability window between 25 and 35 minutes and keep the
  preview cleanup and production failure reporting independent from deployment
  job failure or timeout.
- Deterministic fake AWS CLI fixtures execute the command for match and
  mismatch paths and record every API call.
- IAM tests assert the reconciliation action set exactly matches command use.
- Workflow tests assert a mismatch is reported by the independent failure job.

## Rollback

Revert the workflow verifier steps and the two SSM exports. No ECS state is
changed by reconciliation, so rollback requires no cloud-side remediation.
