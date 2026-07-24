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
