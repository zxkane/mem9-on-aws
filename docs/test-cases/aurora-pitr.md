# Test cases: Aurora point-in-time recovery (issue #48)

## IaC unit tests (`infra/db.test.ts`, `infra/config.test.ts`)

| ID | Scenario | Expected |
|---|---|---|
| TC-PITR-001 | Production Aurora cluster configuration | `backupRetentionPeriod` is exactly 14 days |
| TC-PITR-002 | Preview stage Aurora cluster configuration | `backupRetentionPeriod` is exactly 1 day |
| TC-PITR-003 | Development stage Aurora cluster configuration | `backupRetentionPeriod` is exactly 1 day |
| TC-PITR-004 | Any other non-production stage | `backupRetentionPeriod` is exactly 1 day |
| TC-PITR-005 | Retention source inspection | The cluster transform derives retention directly from `$app.stage` and has no `process.env` path |
| TC-PITR-006 | Production removal safeguards | RDS deletion protection and SST retain/protect remain enabled; the existing SST `skipFinalSnapshot: true` default is unchanged |
| TC-PITR-007 | Preview and development teardown | RDS deletion protection remains disabled, the final snapshot is skipped, and SST state remains removable and unprotected |

## Runbook and infrastructure verification

| ID | Scenario | Expected |
|---|---|---|
| TC-PITR-008 | Production infrastructure preview | Only `backupRetentionPeriod` changes on the existing Aurora cluster; no delete, replacement, endpoint, secret, encryption, protection, or removal-policy change is planned |
| TC-PITR-009 | Recovery timestamp selection | Operator records a UTC timestamp inside `EarliestRestorableTime` and `LatestRestorableTime`, before the damaging event |
| TC-PITR-010 | Restore operation | PITR creates a separately named encrypted cluster and an explicit writer instance; the source cluster remains untouched |
| TC-PITR-011 | Restored schema validation | `vector` is installed, required tables/indexes exist, and `memories.embedding` is exactly `vector(1024)` without reading memory content |
| TC-PITR-012 | Write fence and pre-cutover backup | Headless writers are paused, normal interactive clients are removed from the Gateway allowlist, the proxy Lambda reports zero invocations for the quiet window, and a manual snapshot of the active source cluster completes before IaC cutover |
| TC-PITR-013 | IaC cutover and synthetic verification | A reviewed IaC change updates the endpoint/secret wiring, deploys it, and the existing synthetic write/search test passes |
| TC-PITR-014 | Rollback | With the write fence still active, unsetting the lookup-only recovery inputs points the same IaC path back to the source cluster and the synthetic write/search test passes again |
| TC-PITR-015 | Runbook command validation | Shell blocks pass `bash -n`; AWS mutating commands pass AWS CLI skeleton validation or are paired with read-only inspection commands, without executing a restore |
