# Design Canvas - Preview Stage Reconciliation

Feature: Stale pull-request preview reconciliation
Date: 2026-07-24
Status: Approved (autonomous mode)

## Operator Surface

The reconciler is an operational GitHub Actions workflow, not an application UI.
Its only controls are a recurring schedule and a manual choice:

```text
schedule --------------------------> report job (read-only permissions)

workflow_dispatch(mode=dry-run) ---> report job (read-only permissions)

workflow_dispatch(mode=apply) ------> report job
                                  \-> apply job (write issue permission)
                                      |
                                      +-- fresh safety observations
                                      +-- sst remove for state-present stages
                                      +-- network sweep for SG+ENI-only stages
                                      `-- operator issue for state-missing stages
```

The manual input defaults to `dry-run`. The apply job has a job-level condition
requiring both `workflow_dispatch` and `mode == apply`; scheduled runs therefore
cannot enter the mutation branch or receive its issue-write permission.

## Component Architecture

```text
scripts/preview-reconciler.mts
  +-- collectObservation()
  |    +-- GitHub pull requests
  |    +-- Infra CI workflow runs
  |    +-- SST S3 state objects
  |    +-- Resource Groups Tagging API
  |    `-- IAM role tags
  +-- buildReconciliationPlan()       pure, deterministic, deeply frozen
  +-- renderPlanReport()              redacted stage/type/count output
  +-- applyReconciliationPlan()
  |    +-- collectObservation() again before each removal
  |    +-- buildReconciliationPlan() again
  |    +-- runSstRemove(stage)
  |    +-- sweepOrphanedNetwork(stage)  ENI-then-SG, allowlisted types only
  |    `-- upsertOperatorIssue()
  `-- CLI
       +-- plan
       `-- apply
```

The planner accepts normalized values only. AWS resource ARNs are consumed by the
adapter solely to derive a service/resource type and are discarded before data
reaches the planner, reports, plan artifacts, errors, or operator issues.

## Data Flow

1. Read all pull requests and matching `Infra CI` workflow runs.
2. Read `/sst/bootstrap`, then list `app/mem9-on-aws/*.json` state objects from
   the configured SST state bucket.
3. Read resources tagged `Project=mem9-on-aws` and `ManagedBy=sst`. IAM roles
   use `ListRoles` plus `ListRoleTags` because the Resource Groups Tagging API
   does not return them.
4. Group observations only by stage. The accepted mutation format is exactly
   `pr-[0-9]+`; protected and malformed names never become candidates.
5. For each observed preview stage, calculate the grace anchor as the latest of:
   pull-request close time, matching completed preview workflow time, and SST
   state-object modification time.
6. A candidate requires a closed or absent pull request, no active matching
   workflow, a known grace anchor, and at least 24 elapsed hours.
7. Persist a redacted advisory plan artifact and print a redacted report.
8. In manual apply mode, refresh all observations to classify every advisory
   candidate, write any state-missing operator inventory, then refresh the same
   stage again immediately before `sst remove`. Any reopened pull request,
   active/new workflow, changed state timestamp, missing state, or renewed grace
   period cancels removal.
9. A state-missing candidate whose ENTIRE owned inventory is orphaned network
   scaffolding is classified `sweep-orphaned-network` and finished automatically
   (#146). Every other state-missing candidate is never sent to an AWS delete API:
   manual apply creates or updates one marker-bearing operator issue containing
   only stage, resource type, and count.

## Design Notes

- The stage universe comes from SST state objects and tagged AWS resources, not
  pull requests alone. An old closed pull request with no deployed footprint
  therefore does not generate a false orphan report.
- Pull-request absence is allowed only when another timestamp supplies a grace
  anchor. An absent pull request with no trustworthy age remains protected.
- Workflow runs first correlate through GitHub's PR association, then exact head
  SHA/branch metadata, then the commit-to-pull-request API for active runs. An
  active run that remains uncorrelated protects every preview stage; it is never
  interpreted as inactivity. Uncorrelated completed runs do not alter another
  stage's matching grace timestamp.
- Shared out-of-band IAM, ECR, and Mantle resources are excluded by the
  `ManagedBy=sst` and strict-stage ownership predicates. Their `ManagedBy=cli`
  tags never enter an SST stage inventory.
- The only cleanup adapter invokes `pnpm -C infra exec sst remove --stage pr-N`.
  Command output is captured, not streamed, because provider logs can contain
  account identifiers, ARNs, endpoints, or resource values.
- The operator issue uses a stable title and hidden marker. Exact matching
  updates the existing open issue instead of creating duplicates.
- Collection failures fail closed. The reconciler never interprets an AWS or
  GitHub read error as an empty result.
- The deploy role gains only read inventory actions: `tag:GetResources`,
  `iam:ListRoles`, and role-scoped `iam:ListRoleTags`. Existing SSM and S3 read
  permissions cover SST state.

## Orphaned Network Sweep (issue #146)

The cleanup job's 30-minute `timeout-minutes` cancelled `sst remove` mid-flight
while it waited on a security group whose Lambda VPC hyperplane ENIs had not yet
detached. By then SST had already deleted the state object, so the stranded
`Mem9TaskSg` plus its ENIs became invisible to a state-anchored reconciler and
leaked with nothing left tying them to a closed PR. Two independent changes:

**A bounded wait between two removes.** `scripts/await-eni-detach.mts` polls until
no ENI references the stage's groups. Placement is load-bearing: AWS detaches
those ENIs only *after* the function is deleted, and `sst remove` is what deletes
it, so a wait placed before the first remove would poll a still-`in-use` interface
for its whole budget. The job therefore runs `remove` → on failure `wait` →
`remove` again, and the job timeout stays strictly above the sum of the inner
bounds. Expiry is a `::warning::`, never a failure — failing the step is precisely
what leaked the resources, and the sweep below is the designed backstop.

**A narrow sweep for what already leaked.** Only two resource types may be deleted
without SST state: `ec2:security-group` and `ec2:network-interface`. Both are
recreated from scratch by the next deploy and hold no data. A stage is swept only
when *every* owned resource it has is in that set; one Aurora cluster in the
inventory sends the whole stage back to `operator-review`, because a partial sweep
would leave a half-torn stage behind a stale issue. Widening that allowlist is the
entire risk of the feature.

Within a sweep, ENIs are deleted before their group. This ordering is not
cosmetic: `DeleteSecurityGroup` returns `DependencyViolation` while any ENI still
references the group, so SG-first leaves *both* behind — the leak itself. The
sweep refuses (rather than throws) on an `in-use`, `detaching`, or
requester-managed interface, so one drifted stage cannot abort the run, and it
re-derives `Project`/`ManagedBy`/`Stage` from each resource's own tags so a
server-side filter typo cannot widen the blast radius. The four EC2 actions it
needs were already granted to the deploy role and scoped to the account default
VPC, so no IAM change accompanies this feature.

Every refusal above is proven by a mutation probe: breaking one guard must turn a
named test red. A guard no test kills is not a guard.

## Failure Modes

- Missing AWS role or unreadable bootstrap state: fail the report; do not apply.
- Malformed plan artifact: reject before any mutation.
- SST state disappears during recheck: cancel removal and report the stage as
  state-missing if tagged resources remain. If that state timestamp was the only
  grace anchor, retain the already-eligible advisory timestamp for reporting only;
  it never restores removal eligibility.
- Multiple stages that lose state during final rechecks are accumulated into one
  redacted issue update so later inventory cannot overwrite an earlier stage.
- One removal fails: state-missing inventory has already been written, so the
  failing SST command cannot suppress operator reporting for another stage.
- `sst remove` failure: report only the stage and a generic failure; suppress
  command output.
- GitHub operator-issue write failure: fail apply after all deletion decisions
  remain independently protected by their own rechecks.
- ENI detach outlasts the bounded wait: warn with the blocking interface ids and
  remove anyway. The stage may leak a security group for one reconciler cycle; the
  sweep then finishes it.
- Stage stops being sweepable between plan and sweep: cancel with the recheck's
  reason. The sweep runs independently of removal failures, because an SST failure
  on one stage says nothing about another stage's orphaned security group.
