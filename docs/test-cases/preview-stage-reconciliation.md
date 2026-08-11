# Test cases: Preview stage reconciliation (issue #49)

Design: [`docs/designs/preview-stage-reconciliation.md`](../designs/preview-stage-reconciliation.md)

## Planner fixtures

| ID | Scenario | Expected |
|---|---|---|
| TC-PREVIEW-RECON-001 | Strict `pr-N` stage with an open pull request | Retained with `pr-open`; never a candidate |
| TC-PREVIEW-RECON-002 | Closed pull request whose grace anchor is less than 24 hours old | Retained with `grace-period` |
| TC-PREVIEW-RECON-003 | Closed pull request, no active deploy, state present, and grace elapsed | State-present cleanup candidate |
| TC-PREVIEW-RECON-004 | Pull request absent, matching completed deploy older than 24 hours, tagged resources present | State-missing operator candidate |
| TC-PREVIEW-RECON-005 | Pull request absent and no close/deploy/state timestamp | Retained with `grace-anchor-missing` |
| TC-PREVIEW-RECON-006 | Close time is later than deploy completion and state modification | Close time is the grace anchor |
| TC-PREVIEW-RECON-007 | Deploy completion is later than close time and state modification | Deploy completion is the grace anchor |
| TC-PREVIEW-RECON-008 | SST state modification is later than close and deploy completion | State modification is the grace anchor |
| TC-PREVIEW-RECON-009 | Closed pull request has a queued/in-progress matching deploy | Retained with `deploy-active` |
| TC-PREVIEW-RECON-010 | Candidate has an SST state object | Classified `remove-with-sst` |
| TC-PREVIEW-RECON-011 | Candidate has tagged resources but no SST state object | Classified `operator-review`; no delete action |
| TC-PREVIEW-RECON-012 | `prod`, `main`, `production`, `pr-x`, `pr-1-extra`, and other non-preview stages | Protected; none become candidates |
| TC-PREVIEW-RECON-013 | Out-of-band IAM, ECR, and Mantle fixtures use `ManagedBy=cli` | Excluded from stage inventory |
| TC-PREVIEW-RECON-014 | Planner result includes reasons and observation timestamps | Result and nested values are deeply immutable |

## Apply and reporting

| ID | Scenario | Expected |
|---|---|---|
| TC-PREVIEW-RECON-015 | Report inputs originated from account-bearing ARNs, URLs, and resource values | Output contains only safe stage, decision, timestamp, resource type, and count fields |
| TC-PREVIEW-RECON-016 | State-missing inventory is applied twice with an existing marker issue | First call creates or updates one issue; later calls update the same open issue |
| TC-PREVIEW-RECON-017 | Pull request reopens between plan and apply | Recheck cancels cleanup |
| TC-PREVIEW-RECON-018 | New active or completed preview deployment appears between plan and apply | Recheck resets safety predicates and cancels cleanup |
| TC-PREVIEW-RECON-019 | SST state disappears between plan and apply | No `sst remove`; stage is prepared for operator review |
| TC-PREVIEW-RECON-020 | Revalidated state-present candidate | Exactly `pnpm -C infra exec sst remove --stage pr-N` is invoked |

## Workflow and mocked E2E

| ID | Scenario | Expected |
|---|---|---|
| TC-PREVIEW-RECON-021 | Scheduled workflow | Runs report job only; apply job condition cannot match and report job has no write permission |
| TC-PREVIEW-RECON-022 | Manual dispatch with no input override | Input resolves to `dry-run` |
| TC-PREVIEW-RECON-023 | Manual dispatch with explicit `apply` | Apply job receives issue-write permission and invokes the apply CLI |
| TC-PREVIEW-RECON-024 | Scheduled and manual dry-run through mocked adapters | No removal, issue create, or issue update call |
| TC-PREVIEW-RECON-025 | Manual apply through mocked adapters | `sst remove` occurs only after a second observation still classifies the stage as state-present and eligible |
| TC-PREVIEW-RECON-026 | Manual apply with state-missing resources | Redacted issue draft is created/updated; no AWS delete adapter exists or is called |

## Security and CI guards

| ID | Scenario | Expected |
|---|---|---|
| TC-PREVIEW-RECON-027 | Workflow and adapter source scan | No direct AWS delete API is present; only the SST removal adapter can mutate infrastructure |
| TC-PREVIEW-RECON-028 | Rendered report and issue snapshot scan | No 12-digit account id, full ARN, endpoint URL, or resource content appears |
| TC-PREVIEW-RECON-029 | Deploy-role policy | Adds only read-only tag and IAM inventory actions |
| TC-PREVIEW-RECON-030 | Active workflow has no PR association and cannot be correlated by head metadata/API | Every preview stage is retained while the run remains active |
| TC-PREVIEW-RECON-031 | State-missing stage has only an SST-managed IAM role | IAM-native tag discovery includes `iam:role` in the operator inventory |
| TC-PREVIEW-RECON-032 | A state-missing candidate and a failing state-present SST removal share one apply | Operator issue is persisted before the removal failure propagates |
| TC-PREVIEW-RECON-033 | Candidate becomes active/reopened after preflight but before removal | Immediate second recheck cancels `sst remove` |
| TC-PREVIEW-RECON-034 | Recent completed run remains uncorrelated after head matching | It does not change another stage's matching grace anchor |
| TC-PREVIEW-RECON-035 | SST state disappears after its timestamp supplied the advisory plan's only grace anchor | Tagged resources are reported from the still-eligible advisory evidence; no removal occurs |
| TC-PREVIEW-RECON-036 | Multiple stages lose SST state during the final apply recheck | One cumulative operator-issue update contains every late state-missing stage |

## Orphaned network sweep and bounded ENI wait (issue #146)

The sweep is the only path that issues an AWS delete outside SST, so each of its
refusals is proven by a mutation probe rather than by inspection: breaking any one
guard below must turn a listed test red.

| ID | Scenario | Expected |
|---|---|---|
| TC-PREVIEW-RECON-037 | Deploy-role policy vs. the four EC2 actions the sweep issues | `DescribeSecurityGroups`, `DescribeNetworkInterfaces`, `DeleteSecurityGroup`, and `DeleteNetworkInterface` are already granted; the sweep needs no new IAM |
| TC-PREVIEW-RECON-038 | `cleanup-preview` inner bounds vs. the job `timeout-minutes` | First remove + ENI wait + retry sum strictly below the job timeout, and the wait sits between the two removes |
| TC-PREVIEW-RECON-039 | State-missing stage whose whole owned inventory is one SG plus its ENIs | Classified `sweep-orphaned-network` with `network-scaffolding-only`, not `operator-review` |
| TC-PREVIEW-RECON-040 | State-missing stage holding any non-SG/ENI type (Aurora, S3, Cognito, IAM role) | Stays `operator-review`; a mixed inventory is never swept |
| TC-PREVIEW-RECON-041 | Apply over a sweepable stage | Sweep adapter runs; no operator issue is filed for that stage |
| TC-PREVIEW-RECON-042 | Stage stops being sweepable between plan and the apply recheck | Sweep is cancelled with the recheck's reason; nothing is deleted |
| TC-PREVIEW-RECON-043 | `prod`, `main`, and other non-preview stages | Never swept, at both the plan and the sweep layer |
| TC-PREVIEW-RECON-044 | Sweepable stage still inside the 24-hour grace period | Retained; the sweep does not shorten the grace period |
| TC-PREVIEW-RECON-045 | Dry-run report over a sweepable stage | Report names the planned sweep, so the plan is reviewable before apply |
| TC-PREVIEW-RECON-046 | `security-group` and `network-interface` EC2 ARNs | Map to `ec2:security-group` and `ec2:network-interface` |
| TC-PREVIEW-RECON-047 | End-to-end apply through the real CLI over an SG+ENI-only stage | Exact AWS call sequence deletes every ENI before its security group |
| TC-PREVIEW-RECON-048 | `sweepOrphanedNetwork` over a detached ENI and its group | `delete-network-interface` precedes `delete-security-group`; SG-first would raise `DependencyViolation` and leak both |
| TC-PREVIEW-RECON-049 | ENI is `in-use`, `detaching`, or requester-managed | Refuses with a reason and deletes nothing — a refusal, not a throw, so one drifted stage cannot abort the run |
| TC-PREVIEW-RECON-050 | `sweepOrphanedNetwork` called with a non-preview stage | Refuses `stage-protected` without issuing even a describe |
| TC-PREVIEW-RECON-051 | No security group carries this stage's `Project`/`ManagedBy`/`Stage` tags | Refuses; tags are re-derived locally so a server-side filter typo cannot widen blast radius |
| TC-PREVIEW-RECON-052 | Owned security group with no remaining interfaces | Deletes the group alone |
| TC-PREVIEW-RECON-053 | Empty owned inventory | Never sweepable — asserted on the predicate directly, since `[].every()` is vacuously true |
| TC-PREVIEW-RECON-054 | A redeploy re-creates SST state between the advisory pass and the pre-sweep re-plan | Sweep cancels `no-longer-sweepable`; the stage returns to `sst remove` instead of losing a live security group |

| ID | Scenario | Expected |
|---|---|---|
| TC-PREVIEW-ENI-001 | Interfaces detach partway through the budget | Returns `detached` with the poll count |
| TC-PREVIEW-ENI-002 | Interfaces never detach | Times out at exactly the budget and names the blocking interface ids |
| TC-PREVIEW-ENI-003 | Wait expires during cleanup | Emits `::warning::`, exits 0, and defers to the reconciler sweep — failing the step would recreate the original leak |
| TC-PREVIEW-ENI-004 | Zero or already-expired budget | Still polls once, so the diagnostic reports what is actually attached |
| TC-PREVIEW-ENI-005 | Stage owns no security group | Returns immediately; nothing to wait for |
| TC-PREVIEW-ENI-006 | A security group tagged for a different stage | Ignored; the wait is scoped to this stage's groups |
| TC-PREVIEW-ENI-007 | Non-preview stage | Throws rather than waiting on protected infrastructure |
| TC-PREVIEW-ENI-008 | Stage owns several security groups | Every group is polled before the wait concludes |
