# mem9-on-AWS architecture

This document describes the runtime implemented in this repository. It separates
that current state from planned reliability work and rejected alternatives.

Status: **implemented current state, reviewed 2026-07-24**. The deployed-resource
definitions in `sst.config.ts`, `infra/`, and `docker/` are authoritative. The
upstream mem9 observations in [`mem9-facts.md`](mem9-facts.md) are empirical
against the pinned source commit and carry their verification date.

## Goal and constraints

- Run one operator-owned memory backend shared by multiple devices and agents.
- Keep memory content and embeddings inside the operator's AWS account.
- Use the upstream `mnemo-server` API and PostgreSQL backend where possible.
- Keep `mnemo-server` private. Remote clients use an authenticated MCP surface.
- Use Node.js 24 for Lambda and arm64 for the Fargate workload.

The data-ownership requirement rejects mem9 SaaS and third-party embedding APIs
for this deployment. The PostgreSQL backend is required because mem9's TiDB
backend depends on TiDB-specific vector functions that Aurora MySQL does not
provide.

## Current implementation

### Runtime summary

The current request paths are:

```text
MCP client
  -> Cognito M2M or OAuth2 PKCE facade
  -> Amazon Bedrock AgentCore Gateway
  -> VPC-attached proxy Lambda
  -> AWS Cloud Map private DNS
  -> mnemo-server:8080

mnemo-server
  -> qwen3-embed:8081 for /v1/embeddings
  -> llm-proxy:8082 for /v1/chat/completions
       -> Amazon Bedrock Mantle
  -> Aurora PostgreSQL cluster writer endpoint:5432
```

AWS documents the Lambda target configuration used here:
[AgentCore Lambda target configuration](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-add-target-api-target-config.html).
The proxy function uses Lambda VPC access to reach private resources:
[Lambda VPC connectivity](https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html).
AWS separately requires `lambda:InvokeFunction` on the target in the AgentCore
Gateway service role:
[AgentCore Gateway permissions](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-prerequisites-permissions.html).
AWS Cloud Map documents that a private DNS namespace automatically creates the
associated Route 53 private hosted zone:
[CreatePrivateDnsNamespace](https://docs.aws.amazon.com/cloud-map/latest/api/API_CreatePrivateDnsNamespace.html).

### ECS task

`infra/ecs.ts` defines one arm64 Fargate service with `desiredCount=1`, 2 vCPU,
6 GB of memory, and **three containers**:

1. `mnemo-server` exposes the private memory REST API on port 8080.
2. `qwen3-embed` exposes an OpenAI-compatible `/v1/embeddings` endpoint on
   localhost port 8081. It produces 1024-dimensional vectors.
3. `llm-proxy` exposes an OpenAI-compatible `/v1/chat/completions` endpoint on
   localhost port 8082. It is the only task component that calls Mantle.

`mnemo-server` uses:

```text
MNEMO_EMBED_BASE_URL=http://localhost:8081/v1
MNEMO_EMBED_DIMS=1024
MNEMO_LLM_BASE_URL=http://localhost:8082/v1
MNEMO_LLM_API_KEY=local
MNEMO_INGEST_MODE=smart
```

The non-empty LLM key is a local dummy value. It prevents upstream mem9 from
silently disabling its LLM client; it is not a Bedrock credential.

AWS distinguishes the
[ECS task role](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html),
whose credentials are available to application containers, from the
[ECS task execution role](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_execution_IAM_role.html),
which the ECS agent uses to start the task. This repository follows that split:

- The task role is used by `llm-proxy` for Mantle inference.
- The task execution role retrieves the referenced Secrets Manager value while
  starting `mnemo-server`. AWS documents
  `secretsmanager:GetSecretValue` on the execution role for task-definition
  secret references.

### LLM request path and IAM

`mnemo-server` does **not** call Mantle directly. Its immutable LLM configuration
points to `http://localhost:8082/v1`. The local `llm-proxy`:

1. Resolves the ECS task-role credentials.
2. Mints and refreshes a short-term Mantle bearer with
   `@aws/bedrock-token-generator`.
3. Re-mints once immediately after an upstream 401 or 403.
4. Replaces the local dummy authorization value with the live bearer.
5. Injects `OpenAI-Project` when `MEM9_BEDROCK_PROJECT` is configured.
6. Forwards the request to Mantle and returns the OpenAI-shaped response.

Each proxy chat-completions request has one 110-second wall-clock deadline.
Each Mantle call receives `min(108s, remaining - 2s)`, and no request makes more
than two calls. The first 401 or 403 re-resolves ECS credentials and re-mints
without backoff. Only fast network, 408, 429, 500, 502, 503, and 504 failures
retry, using full jitter or a valid `Retry-After` when at least 20 seconds of
call budget remains. Attempt timeout and downstream disconnect are terminal and
cancel active work.

AWS documents API-key or AWS-credential authentication for the
[Mantle Chat Completions endpoint](https://docs.aws.amazon.com/bedrock/latest/userguide/inference-chat-completions-mantle.html).
The official
[Bedrock API key documentation](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html)
documents the token generator and 12-hour maximum for short-term keys.
AWS also documents `OpenAI-Project` as the project header for OpenAI-compatible
APIs:
[Bedrock workspaces and projects](https://docs.aws.amazon.com/bedrock/latest/userguide/workspaces.html).

The SST `permissions` block attaches the implemented Mantle permissions to the
ECS task role:

- `bedrock-mantle:CreateInference`
- `bedrock-mantle:CallWithBearerToken`
- `bedrock-mantle:GetProject`
- `bedrock-mantle:ListProjects`
- `bedrock-mantle:ListTagsForResource`

These use the `bedrock-mantle` service namespace, not `bedrock`. The official
[service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_bedrock-mantle.html)
defines `CallWithBearerToken` for Mantle bearer authentication, and the
[Bedrock tagging documentation](https://docs.aws.amazon.com/bedrock/latest/userguide/tagging.html)
defines the singular `ListTagsForResource` action.

Repository-specific empirical observation, 2026-07-12: a bearer minted from
task-equivalent AWS credentials successfully invoked the configured Mantle Chat
Completions model in the application region. This observation supports the
selected model and endpoint; it is not a general AWS availability claim.

### Database path

`infra/db.ts` provisions Aurora PostgreSQL Serverless v2 with pgvector support.
`mnemo-server` and the one-shot bootstrap task connect **directly to the Aurora
cluster writer endpoint**. **RDS Proxy is not deployed.**

Automated backup retention is fixed in IaC at **14 days for production** and
**1 day for every non-production stage**. Recovery restores a separate cluster;
the operator procedure is in the
[Aurora PITR runbook](../README.md#aurora-backup-and-point-in-time-recovery).

AWS documents that the Aurora cluster endpoint follows the current primary and
should be used for write operations:
[Aurora cluster endpoints](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Aurora.Endpoints.Cluster.html).

The database credential is generated by `sst.aws.Aurora`, stored in Secrets
Manager, and referenced from the ECS task definition. The task definition does
not contain the password literal. At container startup:

- ECS injects the secret into `MEM9_DB_SECRET`.
- `docker/mnemo-server/entrypoint.sh` assembles the static `MNEMO_DSN`.
- `docker/bootstrap/entrypoint.sh` uses the same host and secret contract.
- Both paths require TLS with `sslmode=require`.

The control-plane and per-tenant connections both target the same writer
endpoint. The bootstrap task writes the working database user and password into
the single tenant row because upstream mem9 opens memory repositories from those
per-tenant fields on each request.

Native IAM database authentication is not part of the current implementation.
AWS states that an Aurora IAM database authentication token is valid for 15
minutes:
[Aurora IAM database authentication](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/UsingWithRDS.IAMDBAuth.Connecting.html).
Empirical source observation, rechecked 2026-07-24 against the pinned mem9
commit: mem9 reads a static DSN once and has no credential refresh hook. A token
inserted into that DSN would therefore expire for future pool connections.

Repository deployment observation, empirical 2026-07-12: the former RDS Proxy
target remained `PENDING_PROXY_CAPACITY` for more than 40 minutes at the chosen
0.5 ACU floor in two regions. The repository removed that proxy and now uses the
writer endpoint. This document does not generalize the observed behavior into an
AWS service guarantee or root-cause claim.

Automatic database credential rotation is not configured. Rotation would also
require a task restart because ECS injects task-definition secrets only when the
container starts.

### Gateway and private networking

The current inbound path is:

```text
Cognito-authenticated MCP request
  -> AgentCore Gateway Lambda target
  -> proxy Lambda with nodejs24.x and VPC access
  -> http://mnemo.mem9-<stage>.local:8080
  -> mnemo-server
```

`infra/gateway.ts` grants the gateway service role
`lambda:InvokeFunction` on the one proxy Lambda. The Lambda maps
`add_memory`, `search_memories`, `ingest_messages`, and
`get_ingest_job_status` to the mem9 REST API and injects the tenant
`X-API-Key`.

`infra/ecs.ts` creates an AWS Cloud Map private DNS namespace and service. The
proxy Lambda and ECS task share the task security group, whose self-referencing
port 8080 rule permits the private hop. There is no ALB, ACM certificate, VPC
Lattice target, public Route 53 zone, or public mnemo-server endpoint.

The gateway trusts both implemented Cognito clients:

- M2M `client_credentials` for CI and headless clients.
- Authorization code with PKCE through the API Gateway v2 OAuth facade for
  interactive clients.

### Schema bootstrap and data

`infra/bootstrap.ts` defines a separate one-shot arm64 ECS task. CI invokes it
after deployment with `scripts/run-bootstrap-task.sh`. It:

1. Enables pgvector and applies the control-plane and tenant runtime schema.
2. Creates `vector(1024)`, FTS, `idx_app`, and HNSW indexes.
3. Seeds one stable tenant whose id is the `X-API-Key`.

The task is idempotent and connects directly to the Aurora writer endpoint. It is
not one of the three long-running application containers.

The `mnemo-server` image contains the additive `ingest_jobs` migration and its
entrypoint applies it before starting the server or worker. CI therefore uses
one rollout with durable routing enabled, reconciles that healthy deployment,
and then runs the bootstrap task for the complete schema and tenant seed. The
bootstrap repeats the same migration after creating the memory schema, which
also guarantees the memory-version backfill on a fresh environment.
Asynchronous `messages[]` ingest commits a canonical job before returning
instead of launching the upstream untracked goroutine. Scope-level advisory
locks serialize enqueue and claim, each claim attempt is a write-fencing
generation, and PostgreSQL supplies lease and retry timestamps.
Claim traverses finite high-water sweeps in bounded candidate pages,
nonblockingly tries advisory locks before taking any row lock, locks only the
exact FIFO head, limits new canonical envelopes to 1 MiB, and terminalizes only
one exhausted head per transaction. Terminal reclaims rotate a claim-specific
owner token so a stale callback is fenced even when workers share a configured
identity.
The worker performs extraction, existing-memory reads, reconciliation, and
embedding before persisting an immutable deterministic plan. It retains at most
50 facts and actions, uses monotonic memory versions for optimistic
UPDATE/DELETE predicates, and replans at most three times per attempt. A
15-second tenant-database transaction applies every raw session, message-tag
patch, memory mutation, plan completion, and `job=succeeded`. A conflict,
deadlock, cancellation, timeout, or mutation error rolls back the whole apply.
Valid plans survive lease recovery, and ambiguous commits are resolved by
rereading the tenant-scoped job.

Authenticated REST and AgentCore `get_ingest_job_status` lookups expose only the
job ID, state, attempts, warning/error class, and timestamps. Unknown and
cross-tenant jobs are both not found. Runtime-usage reservations are correlated
on the durable job with provider expiry. Expiring reservations are replaced
under the active lease before plan/apply work. Terminal commits preserve a
reclaimable finalization state until the existing runtime-usage outbox has
accepted the idempotent commit or release handoff. Other post-commit metering
and webhooks are best effort and cannot change a committed job outcome.

Production durable-ingest lifecycle EMF is emitted after its database
transition and is best-effort. Preview workers use the same durable processing
path without EMF so short-lived `pr-N` stages do not create unbounded custom
metric dimensions. These metrics are operational signals rather than an
accounting ledger: a process crash or log-write failure can omit a committed
transition metric. Aurora `ingest_jobs` and the tenant-scoped status API are the
authoritative job state.

The same production emitter writes a content-free, stage-only
`SamplerHeartbeat=1` before every queue-age query: immediately at worker start
and once per minute thereafter, including when the query fails. Queue age and
telemetry health are separate contracts. The queue-age alarm uses only sampled
values over the threshold and keeps missing data non-breaching. The raw
heartbeat alarm fills each current missing period with zero and requires five
of five one-minute values below one. Older healthy points from CloudWatch's
wider sliding evaluation range therefore cannot extend the five-minute bound;
one delayed latest sample after four healthy samples remains non-alarming.

The raw heartbeat alarm has no actions. Its action-bearing composite uses a
fixed five-minute CloudWatch action-suppression wait backed by an always-OK
guard alarm. This absorbs absent historical datapoints at initial enablement
and brief rolling-deploy gaps. If no real ECS-origin heartbeat arrives, the
wait expires and the composite notifies; sustained loss is therefore actionable
after at most five evaluation minutes plus five action-wait minutes. Direct log
probes and `AWS/Logs` parser-error metrics are diagnostic only and do not enable
or suppress this contract. The composite has no OK action because CloudWatch
starts a new suppression wait after a state change; recovery during the wait
must clear silently rather than produce a notification without a preceding
ALARM action.

Memory rows and embeddings are durable in Aurora. The Fargate task uses `/tmp`
only for mem9's batch-import implementation; normal add, search, and CRUD paths
do not require persistent task storage.

### ECR registry scanning

The four retained repositories remain in
`infra/cloudformation/ecr-repositories.yaml`. Registry scanning is a separate
account/region singleton, so the dedicated
`infra/cloudformation/ecr-registry-scanning.yaml` stack owns the complete
registry configuration. No `AWS::ECR::Repository` has repository-level scanning
configuration.

The complete declaration uses BASIC scanning with one `SCAN_ON_PUSH` filter,
`mem9-on-aws/*`. The namespace separator keeps the rule narrow: it covers the
four project repositories without matching a sibling such as
`mem9-on-aws-other/*`.

Before first adoption from this revision, apply the reviewed deploy-role policy
update once with `scripts/deploy-github-role.sh`. This out-of-band step
activates `DenyEcrRegistryScanningOwnershipStackMutation`; merging or deploying
the SST application does not update that role.

Run `scripts/deploy-ecr-registry-scanning.sh` once per account/region. Its first
AWS call reads the complete registry scanning configuration. It then reads
CloudFormation ownership and applies this policy:

| Current state                                                                    | Wrapper result                                    |
| -------------------------------------------------------------------------------- | ------------------------------------------------- |
| Default BASIC configuration with no rules; dedicated stack absent                | Adopt by creating the dedicated stack             |
| Dedicated stack owns an equivalent complete declaration                          | Verify and exit without mutation                  |
| Dedicated stack owns different current rules                                     | Update from the stack's complete declared ruleset |
| External BASIC `SCAN_ON_PUSH` rules cover all four project repositories          | Verify and exit without adopting or mutating them |
| Any external scan type conflict, sibling-only rules, or partial project coverage | Fail closed before mutation                       |

The wrapper never merges or infers external rules. It repeats the complete
registry and ownership preflight immediately before mutation. A stack-name
collision without ownership also fails closed. This prevents a project-local
deployment from replacing sibling repositories' account-level rules.

ECR exposes no conditional or versioned registry-configuration write. Before an
adopt or owned update, the account owner must pause every other writer for that
account/region and set `ECR_SCAN_EXCLUSIVE_WRITER_ACK=true`. The acknowledgement
is intentionally unnecessary for verify-only paths. The repeated read narrows
the service-level time-of-check/time-of-write window; the exclusive writer
window closes it operationally.

CloudFormation does not reconcile resource drift when the submitted template is
unchanged. On that specific stack-owned path, the wrapper reapplies the exact
complete declaration through the registry-level API, reads it back, and requires
an owned-equivalent result. It never uses the deprecated repository-level
scanning API. Immediately before that direct write, it saves the prior complete
configuration to a mode-`0600`, gitignored
`ecr-registry-scanning-rollback-<timestamp>.local.json`. If the direct write or
read-back fails, keep the exclusive-writer window active and restore that file
with the command printed by the wrapper before investigating further. The
command includes the `AWS_PROFILE` selected from `.env`, when configured, so
the restore targets the same account.

CloudFormation update rollback restores the stack's previous complete
declaration. The singleton has `DeletionPolicy: Retain`, so deleting the stack
relinquishes ownership without deleting the active configuration. After
deletion, the account-level owner may apply a reviewed complete ruleset,
including the default state if that is the intended rollback. The project
wrapper intentionally does not perform that account-wide handoff. Stack deletion
also does not replace the direct-write rollback procedure above: retained state
remains active after CloudFormation relinquishes ownership.

For conflicts, export the current state with
`aws ecr get-registry-scanning-configuration --region ap-northeast-1`, have the
account-level owner update the complete ruleset, and rerun the wrapper. Do not
copy sibling filters into this project's template.

After an image push and scan completion, an operator can inspect findings
without starting or changing a scan:

```bash
aws ecr describe-image-scan-findings \
  --region ap-northeast-1 \
  --repository-name mem9-on-aws/mnemo-server \
  --image-id imageTag=<image-tag> \
  --query '{status:imageScanStatus.status,counts:imageScanFindings.findingSeverityCounts,findings:imageScanFindings.findings}'
```

The operator identity selected by `AWS_PROFILE` must have
`ecr:GetRegistryScanningConfiguration` and
`ecr:PutRegistryScanningConfiguration` in `ap-northeast-1`; the read-only
findings query additionally needs `ecr:DescribeImageScanFindings` on the four
project repository ARNs. These account-level mutation permissions are
intentionally absent from the GitHub Actions deploy role: its OIDC trust includes
pull-request jobs, while the guarded wrapper is operator-run and is never invoked
by CI. An explicit deny prevents that role from directly using its broad
application-stack CloudFormation permissions to create, update, refactor, tag,
or delete the dedicated ownership stack in any region. The operator wrapper
derives its canonical `ecr-registry-scanning-mem9-on-aws` stack name without an
override, so it cannot move the ownership record outside that deny.

The application now defines a retained, operator-owned
`mem9-on-aws-workload-boundary` and applies it to every non-production Pulumi IAM
role through a global transform. Production registration requires an explicit
`false` before migration and is changed to `true` only by the guarded migration;
a missing or malformed value fails synthesis. The deploy-role policy
requires that exact boundary for role creation, boundary attachment, and
subsequent policy writes; it denies boundary removal and mutation of the
boundary policy or operator-owned stacks.
A global `sst.aws.Function` component transform, registered before any stack
module is imported, gives every application Function an exact execution-role
trust containing only `lambda.amazonaws.com`. The pinned SST version otherwise
emits the same-account root principal because it evaluates a Pulumi
development-mode output as a plain boolean.
The boundary uses one broad identity allow plus an explicit
`Deny`/`NotAction` ceiling for the current Lambda, ECS, AgentCore, alert-router,
OAuth, and Mantle runtime actions. This is deliberate: same-account resource
policies can grant directly to assumed-role sessions without an explicit
boundary allow, but
[explicit boundary denies still apply](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html).
Resource and condition denies constrain project resources, KMS use, short-term
Mantle bearer use, and Lambda VPC ENI access. KMS decrypt is limited to either
the project SSM parameter context or Lambda cold-start environment decryption
with a project function ARN encryption context; a decrypt without either
context remains denied. The boundary deliberately does not duplicate a
`kms:ViaService` condition because Lambda's default environment-key grant does
not expose it consistently during permissions-boundary evaluation. A separate
deny requires either SSM mediation or a project Lambda context. A second deny
uses `lambda:SourceFunctionArn` to block a direct KMS call from function code
that forges that Lambda context. A third deny allows the Lambda context only
from the three reviewed project Lambda execution-role types, preventing a
non-Lambda workload role from forging the exception. The OAuth facade identity
policy also pins both the SSM service and project parameter context. The ENI
exception requires both a generated proxy-role name and
`iam:PassedToService` restricted to Lambda; `lambda:SourceFunctionArn`
explicitly denies the same actions to function code. The name match is
therefore not the sole authorization check. The deploy role likewise denies
passing any of the three allowlisted Lambda role-name patterns to a non-Lambda
service, preventing a PR from creating an ECS-assumable lookalike. This
`PassRole` deny does not constrain a role trust policy supplied to `CreateRole`;
the accepted trusted-writer model therefore remains load-bearing for direct
assumption, as described below.

The live role migration is intentionally separate from application deployment.
`scripts/rollout-workload-permissions-boundary.sh` requires a maintenance
acknowledgement plus `DEPLOYMENT_MAINTENANCE_PAUSED=true`. Both Infra CI and
preview reconciliation stop before assuming the deploy role, and the rollout
requires a clean checkout at the current default-branch commit, verifies the
exact reviewed workflow blobs, and waits for queued or active runs from either
workflow to finish, including disabled workflows. It then installs and verifies
a temporary deploy-role quarantine before discovery. Verification reads back
the exact inline deny and custom-simulates every cross-service probe against its
default `*` resource, then re-reads the exact deny before mutation. Permanent
verification separately requires the fixed deny managed policy in the role's
attached-policy inventory, custom-simulates that policy alone, and rechecks its
attachment, default version, and the complete live policy aggregate. The
temporary quarantine therefore cannot satisfy the permanent check.
This avoids principal-simulator Organizations decisions that do not represent
live authorization in a management account, where SCPs do not apply. The
rollout then expands the deployed `iam:PassRole` scope with full pagination and
validates the alert-router, OAuth-facade, and VPC-proxy Lambda role trusts.
During initial discovery only, it repairs the single exact legacy shape
containing Lambda plus current-account root: the complete inventory must first
contain no other unexpected trust, and each repair is guarded by an immediate
pre-write read plus an exact post-write read-back. Retries skip already repaired
roles. All later frozen-state checks are validation-only.
The rollout then verifies all current production service deployment,
RUNNING/PENDING, and bootstrap task definitions still carry the two required
current-account/current-region project secret references before the first
boundary attachment. It also lists the production project Lambdas,
reads the production AgentCore Gateway, and requires every ECS task/execution,
Lambda execution, and Gateway service role to belong to the migration inventory.
That live binding set is re-read at every frozen-state verification. It attaches
and reads back every role boundary, repairs and re-verifies the exact active
boundary default policy version, activates and reads back the production
transform variable. Immediately before quarantine deletion it requires the
default branch to remain at the reviewed commit, both reviewed workflow blobs
to remain exact, the pause variable to remain `true`, both workflows to remain
manually disabled, and every nonterminal run count to remain zero. It then
re-verifies trust, role bindings, boundaries, and permanent enforcement,
rechecks quarantine, and only then deletes it. It then enables
and reads back both deployment workflows before unpausing; a partial resume
restores the pause and disables workflows enabled by that attempt, while a
failed restoration is reported as unsafe. IAM/ECS/Lambda pagination has page
and item ceilings;
AWS, GitHub, and deploy subprocesses have explicit timeouts; the overall rollout
deadline is 60 minutes so retained preview-role inventories can complete every
required read-back pass. Existing-stack
updates change a semantics-neutral policy revision so CloudFormation reconciles
direct managed-policy drift; nonterminal or rollback stack states fail closed.
A failure retains quarantine and is recovered by re-running the same command.
Normal preview and production deployment preflights use the read-only
`--verify-only` path, so a permissive policy drift at the same stable ARN blocks
deployment rather than satisfying an ARN-only check. That path also
custom-simulates the live boundary's KMS behavior: project Lambda and SSM
contexts must be allowed, while direct SSM-context use, direct function-code KMS
use, a non-Lambda role forging the Lambda context, an out-of-project Lambda
context, and a missing context must be explicit denies. It then confirms that
the simulated policy version remains the default.
The cold-start Lambda probe intentionally omits
`kms:ViaService`, matching the cold-start authorization path that a warm
end-to-end smoke can temporarily hide. This simulation verifies policy semantics;
a forced cold-start smoke separately verifies the AWS integration path.
Before migration, GitHub preview AWS jobs intentionally skip while
`WORKLOAD_BOUNDARY_PROD_ENABLED=false`; policy preparation is required for a
manual non-production deployment and for the first post-migration GitHub
preview, not for a pre-migration implementation preview.
Workflow gates and repository variables are trusted-writer maintenance
interlocks, not authorization against a repository writer who can edit them.
GitHub and IAM provide no cross-system atomic transaction, so the final
revalidation narrows rather than eliminates the interval between observing
GitHub state and deleting the IAM quarantine. The trusted-writer maintenance
window requires no concurrent workflow or repository-settings changes in that
interval. An untrusted-PR model requires removing the OIDC `pull_request`
subject out of band until permanent enforcement is verified.
Any rollback must preserve the transform, production activation, future
`CreateRole` boundary enforcement, and the boundary-removal deny. Production
execution and redacted evidence belong to the release-verification procedure.

#### Operator IAM

In addition to its existing CloudFormation stack-management permissions, the
operator identity needs only these ECR permissions for this workflow. Replace
the account placeholder before attaching the policy; do not grant these actions
to the GitHub Actions deploy role.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EcrRegistryScanning",
      "Effect": "Allow",
      "Action": [
        "ecr:GetRegistryScanningConfiguration",
        "ecr:PutRegistryScanningConfiguration"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": "ap-northeast-1"
        }
      }
    },
    {
      "Sid": "EcrImageScanFindings",
      "Effect": "Allow",
      "Action": "ecr:DescribeImageScanFindings",
      "Resource": [
        "arn:aws:ecr:ap-northeast-1:<aws-account-id>:repository/mem9-on-aws/mnemo-server",
        "arn:aws:ecr:ap-northeast-1:<aws-account-id>:repository/mem9-on-aws/qwen3-embed",
        "arn:aws:ecr:ap-northeast-1:<aws-account-id>:repository/mem9-on-aws/bootstrap",
        "arn:aws:ecr:ap-northeast-1:<aws-account-id>:repository/mem9-on-aws/llm-proxy"
      ]
    }
  ]
}
```

### Component map

| Layer                  | Current resource or component                                                                        | Source                                                                                                        |
| ---------------------- | ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Container registry     | Four retained ECR repositories plus guarded registry-level BASIC scan-on-push                        | `infra/cloudformation/ecr-repositories.yaml`, `infra/cloudformation/ecr-registry-scanning.yaml`               |
| Compute                | ECS Fargate, arm64, one task, three containers                                                       | `infra/ecs.ts`                                                                                                |
| Database               | Aurora PostgreSQL Serverless v2, direct writer endpoint; PITR retention prod=14 days, non-prod=1 day | `infra/db.ts`                                                                                                 |
| Database credential    | Secrets Manager task-definition secret                                                               | `infra/db.ts`, `docker/mnemo-server/entrypoint.sh`                                                            |
| Workload IAM ceiling   | Retained operator-owned permissions boundary; guarded live migration                                 | `infra/cloudformation/workload-permissions-boundary.yaml`, `scripts/rollout-workload-permissions-boundary.sh` |
| Embedding              | Local qwen3 sidecar, 1024 dimensions                                                                 | `docker/qwen3-embed/`                                                                                         |
| Smart-ingest LLM       | Local proxy to Bedrock Mantle                                                                        | `docker/llm-proxy/`                                                                                           |
| Mantle attribution     | `OpenAI-Project` added by `llm-proxy` when a project is configured                                   | `docker/llm-proxy/server.mjs`                                                                                 |
| Ingest observability   | Content-free EMF metrics, CloudWatch dashboard, and production alarms                                | `docker/mnemo-server/patches/0006-durable-ingest-telemetry.patch`, `infra/observability.ts`                   |
| MCP surface            | AgentCore Gateway Lambda target                                                                      | `infra/gateway.ts`                                                                                            |
| Private service lookup | AWS Cloud Map                                                                                        | `infra/ecs.ts`                                                                                                |
| Inbound auth           | Cognito M2M plus OAuth2 PKCE facade                                                                  | `infra/cognito.ts`, `infra/oauth-facade.ts`                                                                   |
| Schema setup           | Startup atomic-ingest migration plus one-shot ECS bootstrap for the complete schema and tenant seed  | `docker/mnemo-server/entrypoint.sh`, `infra/bootstrap.ts`, `docker/bootstrap/migrations/`                     |

## Locked decisions

- Aurora PostgreSQL plus pgvector is the database engine.
- Aurora automated backup retention is 14 days in production and 1 day in every
  non-production stage; PITR restores to a separate cluster.
- `mnemo-server` and bootstrap connect directly to the Aurora writer endpoint.
- Database authentication uses a Secrets Manager password over TLS, not native
  IAM database authentication.
- RDS Proxy is absent.
- The service runs one arm64 Fargate task with the three containers listed above.
- qwen3 embedding is local, 1024-dimensional, and not sent to a third party.
- Smart ingest is enabled and reaches Mantle only through `llm-proxy`.
- Each `llm-proxy` request has one 110-second deadline and makes at most two
  Mantle calls.
- Mantle application permissions use `bedrock-mantle:*` actions on the task role.
- The AgentCore Gateway uses a Lambda target and Cloud Map private DNS.
- The public OAuth facade uses API Gateway v2 plus Lambda, never a Lambda
  Function URL.
- Schema bootstrap is a separate one-shot ECS task.
- ECR scan-on-push is a guarded out-of-band registry singleton, separate from
  the retained repository stack.
- Every application IAM role is synthesized with the fixed operator-owned
  workload permissions boundary; live adoption uses the guarded migration.
- Durable transcript ingest uses immutable plans and atomic PostgreSQL apply.
- Durable ingest emits job lifecycle, queue-age, sampler-heartbeat,
  phase-duration, retry, warning, truncation, and zero-fact metrics in
  `mem9-on-aws/DurableIngest`. Metric dimensions are limited to stage and
  bounded result/error classes.
- The production ingest dashboard keeps application metrics separate from
  documented `AWS/BedrockMantle` Project metrics. Planning duration is
  application elapsed time; no Mantle latency metric is synthesized.

## Planned changes

The open reliability program covers future work in these areas:

- Release image tag selection and read-only ECS actual-state reconciliation.
- Mandatory alert delivery with separate transport and execution failure queues.
- Safe preview-stage reconciliation and a separately reviewed one-time cleanup.
- A post-deployment production reliability verification exercise.

The current async `messages[]` path is a durable queue and atomic job processor.
Regular explicit-content memory operations remain on their existing path.

## Open decisions

There is no unresolved architecture choice that changes the current runtime
described above. The planned reliability work has its own accepted scope and is
not an architecture decision awaiting resolution.

The following ideas remain deferred and would require a new design decision:

- End-to-end IAM database authentication through a mem9 credential-refresh
  patch or another compatible connection mechanism.
- More than one long-running ECS task, which would require resolving mem9's
  local batch-import filesystem assumption.
- Per-tool or per-agent authorization beyond the current single-tenant model.

## Rejected alternatives

### Direct Mantle calls from mnemo-server

Rejected. Upstream mem9 reads its LLM API key once and cannot add
`OpenAI-Project`. A static direct bearer expires, and a token-file writer would
not be observed. The local request proxy solves both constraints.

### Two-container task

Rejected. Smart ingest requires the third `llm-proxy` container. The implemented
task contains `mnemo-server`, `qwen3-embed`, and `llm-proxy`.

### RDS Proxy

Rejected after the empirical 2026-07-12 deployment behavior described above.
The current single-task workload connects directly to the writer endpoint.

### Native IAM database auth without a mem9 change

Rejected. The current static DSN cannot refresh 15-minute IAM authentication
tokens.

### AgentCore OpenAPI private endpoint through VPC Lattice and ALB

Rejected after repeated empirical deployment failures on 2026-07-14. The
implemented Lambda target is smaller and uses the gateway service role plus
`lambda:InvokeFunction`.

### Mantle or a third-party embedding API

Rejected. This repository computes embeddings in the local qwen3 sidecar. The
current Bedrock Mantle OpenAI-compatible documentation covers inference APIs,
not this deployment's required local embedding contract:
[Bedrock Mantle OpenAI-compatible APIs](https://docs.aws.amazon.com/bedrock/latest/userguide/bedrock-mantle.html).
