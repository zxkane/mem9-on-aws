# Test Cases: Cognito group-routed memory namespaces

Design:
[`docs/designs/cognito-group-memory-namespaces.md`](../designs/cognito-group-memory-namespaces.md)

All criteria are pre-merge verifiable unless explicitly marked otherwise.
Surfaces are the existing `Typecheck & Unit Tests` CI job, PostgreSQL integration
tests, PR-preview deployment, or a real AgentCore Gateway smoke test in the PR
stage.

Implementation status: local unit, infrastructure, fresh-upstream Go, additive
schema, migration, and PostgreSQL isolation coverage is present. Rows whose
surface is a real Gateway smoke, PR-preview E2E, fault injection, benchmark, or
post-deploy exercise remain release gates and are not claimed complete by the
source implementation alone. The PR workflow now creates two synthetic
namespaces and temporary M2M clients in one preview database, switches that
stage to namespace-required mode, and hard-fails if either fixture client cannot
recall its own marker, if the default client cannot recall alpha's marker
through their shared namespace binding, or if either namespace can observe the
other marker. This proves the deployed M2M sharing and isolation path; it does
not substitute for the human `cognito:groups` Gateway smokes named below.

## Product And Group Routing

| ID             | Scenario                                                                   | Expected                                                                | Surface                |
| -------------- | -------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ---------------------- |
| TC-GROUPNS-001 | Two humans have the same configured namespace group                        | Both resolve the same namespace and can recall each other's team memory | PR-preview E2E         |
| TC-GROUPNS-002 | Two humans have different configured namespace groups                      | Each sees only its namespace corpus                                     | PR-preview E2E         |
| TC-GROUPNS-003 | Human token has no recognized namespace group                              | Request returns 403 before content SQL                                  | Real Gateway smoke     |
| TC-GROUPNS-004 | Human token has two recognized namespace groups                            | Request returns the content-free ambiguous-namespace error              | Real Gateway smoke     |
| TC-GROUPNS-005 | Human token has unrelated groups plus one recognized group                 | Unrelated groups are ignored and the configured namespace resolves      | Unit + Gateway smoke   |
| TC-GROUPNS-006 | Human token has two group keys mapping to the same namespace               | Request is denied as ambiguous in version 1                             | Unit                   |
| TC-GROUPNS-007 | Client submits a namespace ID or namespace slug                            | Input never influences the resolved namespace                           | Unit + E2E             |
| TC-GROUPNS-008 | User changes optional `agent_id`                                           | Attribution/filtering changes only inside the resolved namespace        | PostgreSQL integration |
| TC-GROUPNS-009 | Namespace is disabled                                                      | New reads, writes, and job applies are denied                           | PostgreSQL integration |
| TC-GROUPNS-010 | User belongs to a configured group with JIT disabled and has no membership | Access is denied and no membership is inserted                          | PostgreSQL integration |

## Cognito Token And Client Classification

| ID             | Scenario                                                                                                       | Expected                                                                        | Surface              |
| -------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | -------------------- |
| TC-GROUPNS-011 | Reader-client access token contains valid `iss`, `sub`, `client_id`, `token_use`, scopes, and `cognito:groups` | Token is classified as human by the client registry                             | Unit + Gateway smoke |
| TC-GROUPNS-012 | M2M access token is issued to a configured client                                                              | Token is classified as M2M by the client registry regardless of optional claims | Unit + Gateway smoke |
| TC-GROUPNS-013 | Client ID is absent from the registry                                                                          | Request fails closed                                                            | Unit                 |
| TC-GROUPNS-014 | Client ID is configured as both human and M2M                                                                  | Deployment or cold start fails before serving requests                          | Infra unit           |
| TC-GROUPNS-015 | Human client token lacks `sub`                                                                                 | Request fails closed and is not reclassified as M2M                             | Unit                 |
| TC-GROUPNS-016 | M2M token has an unexpected human-only shape                                                                   | Request fails closed and is not reclassified as human                           | Unit                 |
| TC-GROUPNS-017 | `token_use` is missing or not `access`                                                                         | Request fails before target invocation                                          | Unit + Gateway smoke |
| TC-GROUPNS-018 | Group claim is not an array of bounded strings                                                                 | Request fails closed                                                            | Unit                 |
| TC-GROUPNS-019 | Group claim contains more than 32 entries                                                                      | Request fails before context construction                                       | Unit                 |
| TC-GROUPNS-020 | Reader app client infrastructure is synthesized                                                                | Access-token validity is exactly 15 minutes with explicit units                 | Infra unit           |

## Derived Keys And Privacy

| ID             | Scenario                                                                       | Expected                                                                                                      | Surface     |
| -------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- | ----------- |
| TC-GROUPNS-021 | Same issuer/type/subject is processed twice                                    | The same principal key is produced                                                                            | Unit        |
| TC-GROUPNS-022 | Principal type changes with the same subject                                   | Principal keys differ                                                                                         | Unit        |
| TC-GROUPNS-023 | Same group name exists in two issuers                                          | Group keys differ                                                                                             | Unit        |
| TC-GROUPNS-024 | Group name differs only by case                                                | Group keys differ because Cognito names use exact equality                                                    | Unit        |
| TC-GROUPNS-025 | Logs are captured with marker subject, email, client, group, and bearer values | None of the marker values appears in interceptor, target, or server logs                                      | Integration |
| TC-GROUPNS-026 | Public artifact scan runs over changed files and issue bodies                  | No real user identifier, group name, account ID, ARN, pool ID, domain, secret, or memory content is published | CI scan     |

## Internal Gateway Context

| ID             | Scenario                                                                             | Expected                                                                                                           | Surface              |
| -------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ | -------------------- |
| TC-GROUPNS-027 | Caller supplies `__mem9_auth_v2`                                                     | Interceptor removes and overwrites it                                                                              | Real Gateway smoke   |
| TC-GROUPNS-028 | Interceptor injects context into a declared reserved tool property                   | Context reaches the target unchanged through real Gateway schema processing                                        | Real Gateway smoke   |
| TC-GROUPNS-029 | Context MAC is valid and bound to the request/tool/time                              | Target accepts it for the bound invocation                                                                         | Unit + Gateway smoke |
| TC-GROUPNS-030 | Principal, client, group, tool, request hash, time, or version changes after signing | Target rejects the context                                                                                         | Unit                 |
| TC-GROUPNS-031 | Context is older than 30 seconds                                                     | Target rejects it                                                                                                  | Unit                 |
| TC-GROUPNS-032 | Context uses unknown `kid`                                                           | Target rejects it                                                                                                  | Unit                 |
| TC-GROUPNS-033 | Context group keys are duplicated, unsorted, malformed, or more than 32              | Target rejects it                                                                                                  | Unit                 |
| TC-GROUPNS-034 | Target constructs mnemo request                                                      | Bearer and reserved argument are absent; fixed tenant and identity are carried only in a signed transport envelope | Unit                 |
| TC-GROUPNS-035 | Interceptor and target IAM/resource settings are inspected                           | Interceptor has no VPC/DB/tenant-key access and target is invokable only by the exact Gateway role                 | Infra unit           |
| TC-GROUPNS-036 | Public or unrelated IAM principal attempts target invocation                         | Invocation is denied                                                                                               | PR-preview IAM smoke |

## Control Plane And Membership

| ID             | Scenario                                                   | Expected                                                                        | Surface                |
| -------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------- | ---------------------- |
| TC-GROUPNS-037 | First valid request from an eligible human                 | Principal and membership are created atomically with the binding's default role | PostgreSQL integration |
| TC-GROUPNS-038 | Two first requests race for one human                      | One principal and one membership remain                                         | PostgreSQL integration |
| TC-GROUPNS-039 | Existing active membership role differs from group default | Persisted membership role is used                                               | PostgreSQL integration |
| TC-GROUPNS-040 | Membership is revoked while group remains present          | Later requests are denied and JIT does not reactivate it                        | PostgreSQL integration |
| TC-GROUPNS-041 | Principal is disabled while membership remains active      | Principal status denies access                                                  | PostgreSQL integration |
| TC-GROUPNS-042 | Group binding is disabled                                  | Human requests using that group are denied                                      | PostgreSQL integration |
| TC-GROUPNS-043 | Membership namespace and group binding namespace differ    | Request fails as an internal consistency error without content reads            | PostgreSQL integration |
| TC-GROUPNS-044 | Viewer has read and write OAuth scopes                     | Reads work; writes fail by membership role                                      | E2E                    |
| TC-GROUPNS-045 | Member has read scope only                                 | Reads work; writes fail by OAuth scope                                          | E2E                    |
| TC-GROUPNS-046 | Configured M2M client has one active binding               | M2M resolves the binding's principal, matching namespace, and membership        | PostgreSQL integration |
| TC-GROUPNS-047 | Gateway-allowed M2M client has no active binding           | Request is denied                                                               | E2E                    |
| TC-GROUPNS-048 | M2M binding or membership is disabled/revoked              | Request remains denied while Gateway still accepts the client                   | PostgreSQL integration |

## Access Management

| ID             | Scenario                                                                   | Expected                                                                                                         | Surface                     |
| -------------- | -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | --------------------------- |
| TC-GROUPNS-049 | Desired-state file contains duplicate group, slug, or client bindings      | Reconciler exits before AWS or database mutation                                                                 | Unit                        |
| TC-GROUPNS-050 | Desired-state file contains malformed roles/statuses or secret-like fields | Reconciler rejects it                                                                                            | Unit                        |
| TC-GROUPNS-051 | Reconciliation runs twice                                                  | Cognito groups and Aurora bindings converge without duplicates                                                   | PR-preview integration      |
| TC-GROUPNS-052 | Desired state omits an existing group or namespace in normal mode          | Existing resources are reported as drift and not deleted                                                         | Unit + integration          |
| TC-GROUPNS-053 | `assign-user` targets an unknown namespace                                 | No group or database mutation occurs                                                                             | Unit                        |
| TC-GROUPNS-054 | `move-user` succeeds                                                       | Old memberships are revoked, exactly one new group remains, and the operator-granted target membership is active | PR-preview integration      |
| TC-GROUPNS-055 | `move-user` fails after new group add but before target membership grant   | User has no memory access because the target membership remains absent or revoked                                | Fault-injection integration |
| TC-GROUPNS-056 | `move-user` is retried after any partial failure                           | It converges to exactly one requested group and one operator-granted active target membership                    | Fault-injection integration |
| TC-GROUPNS-057 | `revoke-user` completes                                                    | Active database memberships are revoked before managed groups are removed                                        | PR-preview integration      |
| TC-GROUPNS-058 | Command output is captured with marker username                            | Normal output and logs do not print the username                                                                 | Unit                        |

## Additive Schema And Migration

| ID             | Scenario                                                                                 | Expected                                                                                                                | Surface                    |
| -------------- | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| TC-GROUPNS-059 | Additive migration runs twice on an empty database                                       | Both runs converge to identical schema                                                                                  | PostgreSQL integration     |
| TC-GROUPNS-060 | Additive migration runs on current production-shaped schema                              | Existing rows and indexes remain; nullable columns and control tables are added                                         | PostgreSQL integration     |
| TC-GROUPNS-061 | Backfill starts without shared-history acknowledgement                                   | It exits before mutation                                                                                                | Integration                |
| TC-GROUPNS-062 | A REST, worker, maintenance, or direct-script write is attempted during the frozen phase | The writer is stopped or rejected and no null-namespace row is created                                                  | Integration                |
| TC-GROUPNS-063 | Direct-SQL backfill completes                                                            | Every scoped legacy row receives the selected namespace                                                                 | PostgreSQL integration     |
| TC-GROUPNS-064 | Historical jobs are backfilled                                                           | They reference the seeded legacy service principal, not an invented human                                               | PostgreSQL integration     |
| TC-GROUPNS-065 | Every embedding is included in a deterministic ordered digest before/after backfill      | Digest, null count, and zero-vector count are unchanged with zero allowed mismatches                                    | PostgreSQL integration     |
| TC-GROUPNS-066 | Migration attempts to use REST memory update for namespace backfill                      | Test or migration guard rejects the path                                                                                | Unit/static inventory      |
| TC-GROUPNS-067 | Composite job key and plan foreign key are validated                                     | Every plan references a job in the same tenant and namespace                                                            | PostgreSQL integration     |
| TC-GROUPNS-068 | Same idempotency key exists in two namespaces                                            | Both jobs can exist                                                                                                     | PostgreSQL integration     |
| TC-GROUPNS-069 | Same session content hash exists in two namespaces                                       | Both session rows can exist                                                                                             | PostgreSQL integration     |
| TC-GROUPNS-070 | Constraint validation exceeds lock budget and the migration is rerun                     | Writes stay closed; the verified checkpoint is retained and rerun completes without duplicate constraints               | PostgreSQL fault injection |
| TC-GROUPNS-071 | Compatibility startup sees null namespaces or unsupported schema phase                   | It fails closed                                                                                                         | Integration                |
| TC-GROUPNS-072 | A migration phase fails or a later phase is manually dispatched                          | Later phases reject the unexpected database checkpoint; the four CI operations cannot be bypassed by job ordering alone | Workflow unit              |

## Memory, Session, And Search Isolation

| ID             | Scenario                                                          | Expected                                                                                                                                   | Surface                |
| -------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------- |
| TC-GROUPNS-073 | Namespace A searches content present only in B                    | Vector, FTS, count, and fallback outputs contain no B data                                                                                 | PostgreSQL integration |
| TC-GROUPNS-074 | A knows a B memory ID and calls get                               | Response matches a random unknown ID                                                                                                       | Integration            |
| TC-GROUPNS-075 | A updates or deletes a B memory ID                                | Zero B rows change and response matches not found                                                                                          | Integration            |
| TC-GROUPNS-076 | Bulk delete mixes A and B IDs                                     | Only A rows change and count excludes B                                                                                                    | Integration            |
| TC-GROUPNS-077 | Merge names objects from different namespaces                     | Transaction fails and neither namespace changes                                                                                            | Integration            |
| TC-GROUPNS-078 | Session list/delete/upsert runs in A                              | Every query and unique key remains in A                                                                                                    | PostgreSQL integration |
| TC-GROUPNS-079 | FTS runs on representative two-namespace data                     | Correct rows return and plan uses namespace plus GIN without tenant-wide result leakage                                                    | PostgreSQL integration |
| TC-GROUPNS-080 | Exact vector search runs below the configured row ceiling         | IDs and ordering equal an application brute-force namespace-local top-K baseline; `EXPLAIN` does not use tenant-wide HNSW result selection | PostgreSQL benchmark   |
| TC-GROUPNS-081 | Namespace exceeds exact-vector row ceiling                        | Search returns stable non-retryable `namespace_vector_capacity` and emits the bounded capacity metric                                      | PostgreSQL integration |
| TC-GROUPNS-082 | Exact vector statement times out                                  | Search returns retryable `namespace_vector_timeout` and never uses tenant-wide HNSW fallback                                               | PostgreSQL integration |
| TC-GROUPNS-083 | Documented two-namespace benchmark runs at the configured ceiling | Search p95 is no more than 120 percent of the approved exact-scan baseline, excluding embedding time                                       | PR benchmark           |

## Durable Ingest

| ID             | Scenario                                                      | Expected                                                                                                                      | Surface                   |
| -------------- | ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| TC-GROUPNS-084 | Eligible principal enqueues ingest                            | Job persists tenant, namespace, principal, payload, and state before accepted response                                        | PostgreSQL integration    |
| TC-GROUPNS-085 | Identical request is submitted in two namespaces              | Canonical bytes/idempotency differ and jobs do not coalesce                                                                   | Unit + integration        |
| TC-GROUPNS-086 | Worker claims jobs across namespaces                          | Each claimed row carries immutable namespace and constructs bound repositories                                                | PostgreSQL integration    |
| TC-GROUPNS-087 | Claim SQL runs on the documented representative queue         | JSON plan uses the approved index, has no sequential scan, and stays within recorded candidate-row, lock-wait, and p95 bounds | PostgreSQL `EXPLAIN` test |
| TC-GROUPNS-088 | Job payload or plan attempts namespace override               | Validation rejects it before apply                                                                                            | Unit + integration        |
| TC-GROUPNS-089 | Reconciliation for A runs while B has closer vectors          | Only A candidates reach reconciliation or the model                                                                           | Integration               |
| TC-GROUPNS-090 | Plan references a B memory from an A job                      | Composite checks or scoped mutation roll back the transaction                                                                 | PostgreSQL integration    |
| TC-GROUPNS-091 | Job/plan/lease/action namespace differs                       | Job fails without content mutation or false success                                                                           | PostgreSQL integration    |
| TC-GROUPNS-092 | A requests status for a B job                                 | Response matches unknown job 404                                                                                              | E2E                       |
| TC-GROUPNS-093 | Another A member requests A job status                        | Status is visible because the job is team-owned                                                                               | E2E                       |
| TC-GROUPNS-094 | Submitter membership is normally revoked after job acceptance | Existing job finishes in A, retains submitter audit attribution, and new requests are denied                                  | PostgreSQL integration    |
| TC-GROUPNS-095 | Namespace is disabled before apply                            | No memory/session mutation commits and non-terminal namespace jobs become terminally cancelled                                | PostgreSQL integration    |

## Background And Maintenance Paths

| ID             | Scenario                                                                                                  | Expected                                                                                                                       | Surface                                                |
| -------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------ |
| TC-GROUPNS-096 | Query inventory expands pinned upstream, applies patches, and scans compiled/source/operator SQL surfaces | Every scoped statement is in the version-controlled manifest; an added unclassified statement fails CI                         | Static/unit                                            |
| TC-GROUPNS-097 | Cleanup/restore is requested in namespace v1                                                              | No deployed task exists; the retained direct CLI exits before SQL, REST, model, S3, SSM, or Slack calls                        | Infra/workflow static + CLI process                    |
| TC-GROUPNS-098 | A cleanup request attempts to name a foreign ID                                                           | Cleanup is disabled in v1, so the CLI exits before row lookup, existence disclosure, or mutation                               | Infra/workflow static + CLI process                    |
| TC-GROUPNS-099 | Consolidation is requested for any namespace                                                              | No task, schedule, model input, digest, or mutation path is synthesized, and the retained CLI exits before production adapters | Infra/workflow static + CLI process                    |
| TC-GROUPNS-100 | Two consolidation launches are attempted                                                                  | No launchable task definition or schedule exists in the namespace v1 graph                                                     | Infra/workflow static                                  |
| TC-GROUPNS-101 | Scheduled cleanup scan or Slack approval is enabled without namespace contract                            | Startup/configuration fails closed                                                                                             | Infra unit                                             |
| TC-GROUPNS-102 | A future namespace-aware Slack offer/claim/artifact/apply capability is enabled                           | Each tuple contains exactly one namespace and an approved destination before apply                                             | Capability-specific integration; not a v1 release gate |
| TC-GROUPNS-103 | Upload worker is enabled without namespace task support                                                   | Startup/configuration fails closed                                                                                             | Infra unit                                             |
| TC-GROUPNS-104 | Webhook or Space Chain path is enabled                                                                    | Startup/configuration fails closed until separately designed                                                                   | Infra unit                                             |
| TC-GROUPNS-105 | Analysis/sampler/service REST path reads scoped tables                                                    | Explicit namespace binding is required                                                                                         | Static + integration                                   |

## Rollout, Rollback, And Operations

| ID             | Scenario                                                                                                 | Expected                                                                                            | Surface                                      |
| -------------- | -------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| TC-GROUPNS-106 | Preflight finds queued/running jobs, active writes/tasks, imports, unsupported paths, or user onboarding | Migration does not start                                                                            | Integration                                  |
| TC-GROUPNS-107 | Manual snapshot and latest restorable time are recorded                                                  | Evidence is stored privately and the public-artifact scan finds no identifier                       | Post-deploy operator follow-up; non-blocking |
| TC-GROUPNS-108 | Two namespaces contain data and old namespace-unaware app starts                                         | Startup refuses the rollback                                                                        | Integration                                  |
| TC-GROUPNS-109 | Database membership is revoked during traffic                                                            | Requests after commit are denied without restart                                                    | E2E                                          |
| TC-GROUPNS-110 | Cognito group is changed directly without database revoke                                                | Reader-client configuration bounds token lifetime to 15 minutes and drift report flags the mismatch | Infra unit + PR-preview integration          |
| TC-GROUPNS-111 | Ten users and five namespaces are configured                                                             | No per-user/namespace DB, schema, cluster, ECS service, or embedder is created                      | Infra unit                                   |
| TC-GROUPNS-112 | Namespace resolution load test runs                                                                      | p95 is below 20 ms in the application VPC                                                           | PR-preview benchmark                         |
| TC-GROUPNS-113 | Gateway traffic is compared before/after                                                                 | No Lambda-originated Aurora pool or per-user connection growth appears                              | PR-preview observation                       |
| TC-GROUPNS-114 | Snapshot/PITR restore is tested in isolation                                                             | Namespace, membership, memory, session, job, and plan constraints remain consistent                 | Post-deploy operator follow-up; non-blocking |

## Team-Review Hardening

| ID             | Scenario                                                                                                 | Expected                                                                                                                                                          | Surface                     |
| -------------- | -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- |
| TC-GROUPNS-115 | Human token has 17-31 unrelated groups plus one recognized group                                         | Context remains within the common 32-key limit and the recognized namespace resolves                                                                              | Unit + Gateway smoke        |
| TC-GROUPNS-116 | Interceptor and target canonicalize a nested invocation delivered through real Gateway                   | Both derive the same request hash; reordered keys, caller context, or changed values fail verification                                                            | Real Gateway smoke          |
| TC-GROUPNS-117 | Caller reaches mnemo with a bare tenant key, forged identity headers, or invalid target/service envelope | Namespace-aware endpoints reject before content SQL                                                                                                               | Integration                 |
| TC-GROUPNS-118 | Human already has an active membership in B and a new group-A token triggers JIT                         | No A membership is created; request fails as an internal consistency error                                                                                        | PostgreSQL integration      |
| TC-GROUPNS-119 | M2M reconciliation runs                                                                                  | One M2M principal, one binding referencing that principal, and one matching membership are created atomically                                                     | PostgreSQL integration      |
| TC-GROUPNS-120 | User moves A to B and later back to A                                                                    | Operator reactivates the revoked A row only after Cognito re-read; access to B stays revoked                                                                      | PR-preview integration      |
| TC-GROUPNS-121 | Two access-management commands race for one human                                                        | Per-principal serialization permits one final requested state without mixed groups or memberships                                                                 | Fault-injection integration |
| TC-GROUPNS-122 | `revoke-user --emergency` runs with queued and processing jobs                                           | Principal and memberships are disabled first; each racing apply linearizes before revoke or is terminally cancelled, and no mutation commits after revoke returns | PostgreSQL integration      |
| TC-GROUPNS-123 | Migration preflight sees any pending or processing legacy ingest job                                     | Freeze does not start until the queue is zero                                                                                                                     | PostgreSQL integration      |
| TC-GROUPNS-124 | Phase 3 fails after one or more checkpoints                                                              | Read-back identifies the last verified checkpoint and rerun resumes idempotently                                                                                  | PostgreSQL fault injection  |
| TC-GROUPNS-125 | Application-switch CI operation is dispatched before the required migration phase                        | Operation exits before deployment and reports the observed/required phase without environment identifiers                                                         | Workflow unit               |
| TC-GROUPNS-126 | Target and approved service issuers rotate their transport keys                                          | Current and previous keys verify during the window; unknown issuer or `kid` fails                                                                                 | Unit + integration          |
| TC-GROUPNS-127 | Existing tenant-wide HNSW index remains after migration                                                  | Namespace exact-search plan regression test proves it is never selected; otherwise migration removes it                                                           | PostgreSQL benchmark        |
| TC-GROUPNS-128 | Principal is emergency-disabled while apply is racing                                                    | Fault injection proves the job-row lock yields exactly one legal order: apply commits before revoke, or revoke wins and apply commits no content                  | PostgreSQL fault injection  |
| TC-GROUPNS-129 | Legacy namespace seed and backfill receive different IDs                                                 | Migration rejects the mismatch before row mutation                                                                                                                | PostgreSQL integration      |
| TC-GROUPNS-130 | A single-namespace database runs the latest namespace-aware compatible rollback build                    | Build starts successfully; a namespace-unaware build remains rejected                                                                                             | Integration                 |

## Release Gates

The feature cannot be enabled until:

1. Every unit, infra, workflow, static, PostgreSQL integration, and benchmark AC
   above passes on its named pre-merge surface, excluding capability-specific
   TC-GROUPNS-102 and non-blocking TC-GROUPNS-107/114.
   Disabled-path TC-GROUPNS-097..104 pass only when executable/static checks
   prove those capabilities are absent or fail closed; a verification path in
   the coverage map does not authorize the legacy implementations or claim an
   AC result.
2. Real Cognito/AgentCore PR-stage smoke tests pass for the rows explicitly
   marked `Gateway smoke`, including TC-GROUPNS-027 through 029, 036, 115, and 116.
3. The automated PR-preview hard E2E passes with two synthetic namespaces in
   one Aurora database, and the separately named human-group and fault-injection
   suites also pass.
4. The database contains zero null namespace values in enforced tables.
5. Every memory-enabled human is in exactly one managed namespace group and has
   no other active human namespace membership.
6. Every enabled M2M client has exactly one active binding, referenced active
   principal, and matching active membership.
7. Unsupported upload, webhook, Space Chain, cleanup-scan, and Slack-approval
   paths are disabled by configuration validation.
8. The pre-merge migration rehearsal records count, orphan, full
   embedding-preservation, checkpoint, lock, and rollback evidence.
9. No namespace-unaware application version is available as an automated
   rollback target.
10. TC-GROUPNS-107 and 114 remain tracked as a non-blocking, non-autonomous
    post-deploy operator follow-up.
