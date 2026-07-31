# mem9-on-aws

Self-hosted deployment of **mem9** (`mnemo-server`, the open-source agent-memory
server by [`mem9-ai/mem9`](https://github.com/mem9-ai/mem9), Apache-2.0) on AWS —
a single-operator, multi-device, multi-agent shared memory layer with **full data
ownership** (no third-party SaaS). Your agents' memories live 100% in your own AWS
account and are exportable at any time.

## What this is / is NOT

- **IS**: an [SST v4](https://sst.dev) app that runs `mnemo-server` (upstream
  mem9, unmodified where possible) on ECS Fargate against Aurora PostgreSQL,
  fronted by an Amazon Bedrock AgentCore Gateway MCP surface with Cognito auth.
- **IS NOT**: a fork of mem9's application code. We vendor/pin the upstream
  container and drive it entirely through env vars + a bootstrapped Postgres
  schema. Any source change to mem9 is a last resort and must be recorded in
  [`docs/mem9-facts.md`](docs/mem9-facts.md) with the upstream commit it forks from.

## Read first (ground truth)

Two files describe the implemented runtime, the upstream constraints, and the
rationale for locked decisions. Treat the deployed-resource definitions in
`sst.config.ts`, `infra/`, and `docker/` as authoritative current state. If code
or current AWS documentation contradicts these files, update the documentation
rather than silently diverging.

- **[`docs/mem9-facts.md`](docs/mem9-facts.md)** — the non-obvious mem9
  constraints, e.g.:
  - Aurora **MySQL cannot run mem9** (mem9's MySQL/tidb path needs TiDB-only
    `VECTOR`/`VEC_COSINE`/`EMBED_TEXT`) → we use the **postgres backend + pgvector**.
  - **Bedrock Mantle has no `/embeddings`** (Chat Completions / Responses only) →
    embedding can't go through Mantle; we self-host qwen3.
  - mem9 reads `MNEMO_LLM_API_KEY` **once at startup (immutable)** and sends no
    custom headers → the Mantle bearer and, when a Bedrock Project is configured,
    its `OpenAI-Project` cost header are bridged by a **local LLM proxy sidecar**
    (`docker/llm-proxy/`), not a token file-writer.
  - mem9 schema **`idx_app` gap**: control-plane `schema_pg.sql` ≠ the tenant
    runtime schema the server validates → bootstrap must apply the runtime schema.
  - AgentCore Gateway reaches the private mnemo-server via a **Lambda-proxy target**
    (out-of-the-box private path): a VPC-attached proxy Lambda reaches the server
    over **AWS Cloud Map** DNS with an `X-API-Key`.
- **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)** — the current request paths,
  component map, locked decisions, planned changes, and rejected alternatives.

## Current implementation

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for rationale and official AWS
citations.

| Dimension          | Decision                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| IaC                | **SST v4**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Region             | **ap-northeast-1 (Tokyo)**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Container registry | Four retained ECR repositories plus guarded registry-level BASIC scan-on-push for `mem9-on-aws/*`, both managed out of band                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Compute            | **ECS Fargate**, **arm64**, single task (`desiredCount=1`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Database           | **Aurora PostgreSQL Serverless v2** + `pgvector` (mem9 `postgres` backend). `mnemo-server` and bootstrap connect directly to the cluster writer endpoint with a Secrets Manager credential. **RDS Proxy is not deployed.**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| VPC                | **Reuse the account default VPC** (private subnets with NAT egress)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| MCP surface        | **AgentCore Gateway** (MCP → mnemo-server REST API)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Gateway → server   | **Private** (a [Lambda-proxy GatewayTarget](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-add-target-api-target-config.html)): AgentCore invokes a VPC-attached proxy Lambda with [`lambda:InvokeFunction`](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-prerequisites-permissions.html). The Lambda uses [VPC connectivity](https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html) and [AWS Cloud Map private DNS](https://docs.aws.amazon.com/cloud-map/latest/api/API_CreatePrivateDnsNamespace.html) (`mnemo.mem9-<stage>.local:8080`) to reach mnemo-server with the `X-API-Key` (= tenant id). No ALB, VPC Lattice, or public server endpoint is deployed; the optional OAuth façade custom domain is a separate API Gateway concern. |
| Auth (inbound)     | **Cognito M2M** (`client_credentials`) + an OAuth2 browser-login façade (`authorization_code` + PKCE) for interactive MCP clients                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| LLM (smart-ingest) | `mnemo-server` calls the **local `llm-proxy` sidecar** at `http://localhost:8082/v1`. The proxy refreshes a short-term Mantle bearer, injects `OpenAI-Project` when `MEM9_BEDROCK_PROJECT` is configured, and calls Bedrock Mantle. Each request has one 110-second deadline and at most two Mantle calls. The task role uses `bedrock-mantle:CreateInference` and `bedrock-mantle:CallWithBearerToken`; `mnemo-server` never calls Mantle directly.                                                                                                                                                                                                                                                                                                                   |
| Embedding          | qwen3 OpenAI-compatible `/embeddings` as an **ECS sidecar** (localhost, always warm), **dims 1024**. Not Mantle, not a third-party API.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ECS task           | **3 containers**: mnemo-server + qwen3-embed sidecar + llm-proxy sidecar                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Schema bootstrap   | **startup atomic-ingest migration** before `mnemo-server`, plus a **one-shot ECS task** on deploy (pgvector + tenant runtime schema incl. `idx_app`/FTS/`vector(1024)` + seed 1 tenant)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Durable ingest     | Transcript `messages[]` requests enqueue durable Aurora jobs. Immutable, materialized plans apply raw sessions, tags, memory actions, and job success in one PostgreSQL transaction; authenticated REST and Gateway status lookups are tenant-scoped.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Tenancy            | **single tenant** (one `X-API-Key`); writes carry **`X-Mnemo-Agent-Id`** to reserve per-agent scoping                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Replicas           | **Single** (`desiredCount=1`) — single-writer, sidesteps mem9's local-disk import dir                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |

## Planned reliability work

The remaining open reliability program covers deployment reconciliation, alert
failure queues, preview cleanup, job-level telemetry, and post-deployment
verification. Current atomic durable processing is recorded in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#planned-changes).

## MCP tools exposed

The AgentCore Gateway exposes four tools over MCP (Cognito-authenticated):

- `add_memory` — store one raw memory (`content`, optional `agent_id`).
- `search_memories` — semantic search (`q`, optional `limit`/`agent_id`).
- `ingest_messages` — smart-ingest a conversation window (`messages[]`, optional
  `session_id`/`agent_id`/`mode`) for LLM extraction into memories.
- `get_ingest_job_status` — read the tenant-scoped state and approved outcome
  metadata for a durable ingest job.

## Layout

- `infra/` — the SST/Pulumi app (VPC lookup, Aurora, ECS, Cognito, gateway,
  OAuth façade, bootstrap) + unit tests.
- `docker/` — the four container images: `mnemo-server` (pinned upstream build),
  `qwen3-embed` (embedding sidecar), `llm-proxy` (Mantle bearer/project bridge),
  `bootstrap` (schema + tenant seed).
- `scripts/` — out-of-band bootstrap scripts (GitHub Actions IAM role, workload
  permissions boundary, four ECR repositories, guarded registry scan-on-push,
  and Bedrock Mantle Project) that the SST app references read-only. See each
  script's header and `.env.example` for the environment it expects.
- `docs/` — `ARCHITECTURE.md` (decisions) and `mem9-facts.md` (upstream constraints).

## Development

- **Node.js 24 LTS** everywhere (`.nvmrc` = 24, `engines.node >= 24`, CI +
  Lambda `nodejs24.x`). The Go build for mnemo-server targets **arm64**.
- Copy `.env.example` to `.env` and fill in your AWS profile before running the
  `scripts/deploy-*.sh` bootstrap scripts.
- Set `MEM9_FACADE_AUTHORIZER_ENABLED=1` at deploy time to attach the optional
  allow-all OAuth facade compliance authorizer; it is disabled by default.
  Roll out the reviewed workload-boundary update before enabling it.
- `scripts/deploy-github-role.sh` always owns its account-global IAM stack in
  `us-west-2` and ignores ambient `AWS_REGION`. Set `PROJECT_REGION` only when
  application VPC discovery must target a region other than its documented
  default.
- Agent contributors: see [`AGENTS.md`](AGENTS.md) for repo conventions and hard rules.

### Optional production custom domain

The OAuth façade can use a production-only custom hostname. Leave
`MEM9_FACADE_CUSTOM_DOMAIN` unset to keep the generated API Gateway
`execute-api` URL. When configured, SST creates a Regional API Gateway domain
and mapping, requests and DNS-validates an ACM certificate in
`ap-northeast-1`, and writes alias records into an existing public Route 53
hosted zone in the same AWS account. Preview stages never receive this setting.

Before enabling it, update the out-of-band deploy role, then store the hostname
as a GitHub secret:

```bash
scripts/deploy-github-role.sh
gh secret set MEM9_FACADE_CUSTOM_DOMAIN --body "memory.example.com"
```

Use a hostname only, without `https://`, a port, or a path. The secret prevents
the repository and workflow definition from carrying the operator's domain,
but the hostname is inherently public in DNS and appears in the deployed AWS
resources. One hostname maps to the production stage; use no production
hostname for PR previews.

## Workload permissions-boundary rollout

The application applies the fixed, operator-owned workload permissions boundary
to every non-production Pulumi `aws.iam.Role`. Set the repository variable
`WORKLOAD_BOUNDARY_PROD_ENABLED=false` before merging the implementation; the
guarded migration later sets and verifies it as `true`. A missing or malformed
value fails production synthesis instead of silently omitting the transform.
The boundary stack and its migration remain out-of-band so a pull-request-capable
deploy role cannot modify its own ceiling. Merging the implementation does not
migrate the live account.

Before migration, pull-request AWS jobs intentionally skip while
`WORKLOAD_BOUNDARY_PROD_ENABLED=false`; only the non-AWS validation job runs.
There is therefore no pre-migration GitHub preview of this implementation.

Prepare the unattached policy before either a manual non-production deployment
or the first GitHub preview after migration:

```bash
scripts/deploy-workload-permissions-boundary.sh
gh variable set WORKLOAD_BOUNDARY_PROD_ENABLED --body false
```

This preparation creates or verifies only the retained managed policy. It does
not attach a boundary, update the deploy role, activate pre-migration GitHub AWS
jobs, or remove the maintenance gate. A drifted existing stack can be updated
only by the guarded rollout, which changes a semantics-neutral policy revision
so CloudFormation rewrites the managed policy even when the submitted template
is otherwise unchanged. Both boundary operator commands require Node.js 24.

Merge the gate-bearing implementation before migration. Then run the migration
only in an approved maintenance window after setting
`DEPLOYMENT_MAINTENANCE_PAUSED=true`. The rollout requires a clean checkout at
the current default-branch commit, verifies the exact reviewed workflow blobs,
checks every nonterminal workflow status twice (including disabled workflows),
requires the exact-head push run's non-AWS `Typecheck & Unit Tests` job to have
succeeded, and refuses to start until Infra CI and preview reconciliation are
idle. It passes that reviewed commit explicitly into the migration state
machine for one final comparison before quarantine removal. The gated AWS jobs
are expected to fail or skip before migration:

```bash
WORKLOAD_BOUNDARY_MAINTENANCE_ACK=true \
  scripts/rollout-workload-permissions-boundary.sh
```

The command requires Node.js 24 before its first AWS mutation. It first installs
an exact temporary deny on the GitHub Actions deploy role, reads it back, and
custom-simulates every quarantine action against the policy's default `*`
resource. It reads the exact quarantine again after simulation before any
boundary mutation. It then deploys or verifies the retained boundary stack,
derives the complete migration set from the deployed `iam:PassRole` policies,
classifies the three required Lambda execution-role types plus the optional
facade authorizer role, and repairs only the exact legacy trust containing
Lambda plus the current-account root. It validates the complete inventory before
any trust write, then re-reads immediately before each update and reads back the
exact Lambda-only result. Any unknown principal, extra field, or later trust
drift fails closed; frozen-state checks never repair.
The command then checks all production service deployments, RUNNING/PENDING
tasks, and the bootstrap task definition before the first boundary mutation.
Every task definition
must carry `MEM9_DB_SECRET` and `MEM9_TENANT_ID` references to current-account,
Tokyo-region
`mem9-on-aws-*` secrets. It also reads every production project Lambda and the
AgentCore Gateway, then proves that all ECS task/execution, Lambda execution,
and Gateway service roles are in the migration inventory. That binding set is
re-read before quarantine removal. The command then attaches and reads back every
boundary and deploys the permanent policy conditions. Before removing quarantine
it repairs and verifies the exact active boundary policy, sets and reads back
`WORKLOAD_BOUNDARY_PROD_ENABLED=true`, then requires the default branch to
remain at the reviewed commit, both reviewed
workflow blobs to remain exact, the pause to remain `true`, both workflows to
remain `disabled_manually`, and all `queued`, `in_progress`, `requested`,
`waiting`, and `pending` run counts to remain zero. It repeats the frozen-state
checks after that GitHub interlock, so trust, bindings, boundaries, and
permanent enforcement are the last substantive reads before another quarantine
verification and deletion. It then enables and reads
back both workflows before unpausing deployments. A partial resume restores and
reads back the pause, disables workflows enabled by that attempt, and reports
any failed rollback without claiming success. That rollback uses a fresh signal
and the reserved shutdown window even when the operational signal or deadline
already fired.

Normal AWS deployment preflights call the boundary script with `--verify-only`.
They compare the current default policy version with the repository contract and
then custom-simulate 17 KMS boundary cases. The allowed paths are project Lambda
contexts for the required and optional role types, an SSM-mediated project
parameter, and Secrets Manager-mediated project DB/tenant secrets from the
server or bootstrap ECS execution-role type. Direct service-context use,
foreign/cross-region service paths, task/Lambda roles presenting a secret
context, mismatched SSM/Secrets Manager context pairs, forged Lambda contexts,
and missing contexts must be explicit denies.
The verifier also confirms that the simulated version remains the active
default. Any structural or semantic drift at the stable ARN fails without
creating or updating anything. This deterministic policy check does not prove
the live AWS service context: a forced Lambda cold start, ECS service
replacement, and bootstrap task separately verify the integration paths. The
deploy role therefore has the
resource-agnostic `iam:SimulateCustomPolicy` read/evaluation action; apply that
out-of-band role update with `scripts/deploy-github-role.sh` before this
preflight revision runs.
AWS and GitHub CLI calls, deploy subprocesses, pagination, and the complete
rollout all have bounded execution limits; exceeding one leaves quarantine in
place.

Use an operator identity, never the GitHub Actions deploy role. In addition to
the existing out-of-band CloudFormation permissions, it needs IAM role/policy
read access, inline-policy put/get/delete on the deploy role,
`iam:SimulateCustomPolicy`, role inventory reads, and
`iam:UpdateAssumeRolePolicy` plus `iam:PutRolePermissionsBoundary` on the
discovered project roles.
The permanent-enforcement phase invokes `scripts/deploy-github-role.sh`, so the
operator also needs that script's existing OIDC-provider, STS, VPC/subnet, and
template-upload reads/writes. Because the role template exceeds the inline
CloudFormation size limit, configure `MEM9_TEMPLATE_BUCKET` or ensure the
operator can discover and write the account's SST state bucket.

If the command is interrupted or fails after the quarantine attempt, keep
deployments paused and run the exact `Resume:` command it prints. Before the
first IAM mutation the wrapper writes the effective non-secret AWS profile and
region settings, VPC/template-bucket selectors, and expected account and
partition to the gitignored, mode-`0600`
`.env.workload-boundary-resume` file. The printed command explicitly reloads
that file even if the caller previously set `WORKLOAD_BOUNDARY_SKIP_DOTENV`.
A retry refuses a different AWS identity instead of targeting another account.
If retained recovery state already exists, an initial command is rejected before
any GitHub or AWS call; only the printed `Resume:` command may reload that state.
The wrapper takes a checkout-local nonblocking lock so another rollout cannot
overwrite or remove that recovery state. During the IAM phase it forwards
`SIGINT` and `SIGTERM` to the bounded Node process, waits for its recovery path,
and exits with 130 or 143. The file is removed after a successful rollout. The
migration is idempotent and treats quarantine as installed until proven
otherwise. Never manually remove
`mem9-on-aws-workload-boundary-quarantine` during recovery.

An ownership stack in `UPDATE_ROLLBACK_COMPLETE` is repaired only by the guarded
rollout; read-only verification rejects it even if the current policy happens to
match. For `UPDATE_ROLLBACK_FAILED`, first use CloudFormation's reviewed
`continue-update-rollback` recovery to return the stack to
`UPDATE_ROLLBACK_COMPLETE`, then rerun the printed guarded command.

A rollback is forward-fix only. It may correct or narrow the explicit runtime
action ceiling, but it must retain the transform, the production activation
variable, the fixed boundary, the `CreateRole`/policy-write boundary conditions,
and the explicit boundary-removal deny. Never deploy an older revision that
omits `permissionsBoundary`, and never unset
`WORKLOAD_BOUNDARY_PROD_ENABLED`: either action asks Pulumi to remove the
boundary, which permanent enforcement denies and can leave a partial deployment.
If such a deployment was attempted, keep maintenance paused, restore the
boundary-aware exact head, verify every role boundary, and redeploy that head.
Removing future-role enforcement would reopen the privilege-escalation path even
if existing roles remain bounded.
Live migration and production smoke evidence are recorded by the production
release-verification procedure, not by CI for this change.

The maintenance variables and workflow checks are operational interlocks for
this private, trusted-writer repository. They cannot stop a repository writer
from editing the workflow itself, and GitHub state plus IAM state cannot be
validated and changed in one atomic transaction. The final GitHub revalidation
narrows that cross-system window; the trusted-writer rule and prohibition on
concurrent repository-settings changes close it operationally. Before accepting
untrusted pull requests, remove the `pull_request` subject from the deploy role
trust out of band and restore it only after the guarded migration has verified
permanent enforcement.

## Production alert runbook

Production deployment requires the `SLACK_WEBHOOK_URL` GitHub secret. SST
synthesis fails when it is absent so production alarms cannot be deployed
without an IaC-managed sink. Preview and development stages do not create the
alerting stack.

Production synthesis also requires the out-of-band Bedrock Mantle Project ID.
The `mem9-on-aws-prod-ingest` dashboard separates documented Project-scoped
Mantle inference/token/client-error metrics from durable application outcomes,
queue age, phase durations, retries, and warnings. It does not present
application planning time as provider latency. Lifecycle EMF is a post-commit,
best-effort operational signal; Aurora job rows and the tenant-scoped status API
remain authoritative. EMF is production-only so preview stage identifiers do
not accumulate as permanent custom-metric dimensions.

Queue health and telemetry health are independent. Missing
`OldestQueuedAgeMs` remains non-breaching because it is not evidence of a
backlog. The sampler emits stage-only `SamplerHeartbeat=1` immediately and once
per minute. The raw liveness alarm fills each current missing period with zero
and requires five of five one-minute periods below one. This prevents older
healthy points in CloudWatch's wider sliding evaluation range from extending
the five-minute bound, while one delayed latest sample after four healthy
samples remains non-alarming. That raw alarm has no actions. Its composite
notification waits exactly five more minutes on every ALARM transition, which
bounds both initial enablement and rolling-deploy suppression without a manual
actions-disabled mode. A real ECS-origin heartbeat clears the raw alarm during
that wait; otherwise the notification is released. A direct `PutLogEvents`
probe or zero `AWS/Logs` parser errors can aid diagnosis but does not establish
sampler liveness.

Before the first deployment from this revision, run
`scripts/deploy-github-role.sh` to grant the out-of-band GitHub Actions role the
CloudWatch composite-alarm and dashboard APIs. Merging the PR or running SST
does not update that role.

All action-bearing production alarms target one SNS topic. The raw telemetry
liveness alarm and its action-delay guard are intentionally actionless. The
liveness composite has only an ALARM action: CloudWatch restarts its suppression
wait after a state change, so an OK action could otherwise send a recovery
without a preceding notification. Delivery failures are separated by the AWS
boundary at which they occurred:

| Alarm                                       | Queue meaning                                                                                          | Queue body                                                                                                  |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| `AlertTransportFailureQueueVisibleMessages` | SNS exhausted attempts to invoke the alert Lambda                                                      | Original SNS notification envelope with `Type`, `MessageId`, `TopicArn`, and `Message`                      |
| `AlertExecutionFailureQueueVisibleMessages` | Lambda accepted the SNS event, but the handler exhausted two retries or reached the two-hour event age | Lambda destination record with `requestContext`, `requestPayload`, `responseContext`, and `responsePayload` |

Both queues use SSE-SQS encryption and retain messages for 14 days. The
queue-depth alarms use the same alert path, so the CloudWatch alarm state and
SQS queue depth remain the ground truth when Slack delivery is impaired.

For a **transport failure**:

1. Verify the SNS subscription still targets the alert Lambda and its redrive
   policy names the transport queue.
2. Verify the Lambda resource permission allows `sns.amazonaws.com` from only
   the project alarm topic, and check for deleted, disabled, or throttled Lambda
   resources.
3. After restoring SNS-to-Lambda delivery, republish only the envelope's
   `Message` value to the alarm topic through controlled tooling.

For an **execution failure**:

1. Inspect the destination record's `requestContext.condition` and
   `approximateInvokeCount`. `RetriesExhausted` with count `3` means the initial
   attempt plus two retries failed.
2. Verify the webhook secret is configured and Slack is reachable. Lambda logs
   intentionally contain only generic operation messages and HTTP status codes.
3. After fixing the handler dependency, asynchronously invoke the alert Lambda
   with only `requestPayload`. Do not invoke it with the destination envelope.

Use the shape-specific parsers in
[`infra/src/alert-router/failure-records.ts`](infra/src/alert-router/failure-records.ts)
for automation. Each parser rejects the other queue's record shape and returns
only routing/failure metadata. Never print, log, or paste `Message`,
`requestPayload`, `responsePayload`, webhook values, or formatted alarm fields.
Delete a queued record only after the replay succeeds and the notification is
confirmed.

## Aurora backup and point-in-time recovery

Aurora automated backup retention is fixed in IaC: **14 days for `prod`** and
**1 day for every non-production stage**. There is no environment override.
Changing `BackupRetentionPeriod` updates the existing cluster rather than
replacing it, although AWS classifies the update as **some interruptions**.
Schedule the production change in an approved maintenance window.

This runbook restores to a **new cluster**. It never rewinds or overwrites the
source cluster. Do not run a production restore from CI or as a pre-merge test.
Use a gitignored `.env.recovery` for real operator values; the placeholders
below must never be committed.

### 1. Select and record the restore point

```bash
export AWS_PROFILE="<aws-profile>"
export AWS_REGION="<aws-region>"
export SOURCE_CLUSTER="<source-db-cluster-identifier>"
export RESTORED_CLUSTER="<new-db-cluster-identifier>"
export RESTORED_INSTANCE="<new-db-instance-identifier>"
export RESTORE_TIME="<yyyy-mm-ddThh:mm:ssZ>"
export DB_SUBNET_GROUP="<db-subnet-group-name>"
export DB_SECURITY_GROUP="<db-security-group-id>"
export DB_CLUSTER_PARAMETER_GROUP="<db-cluster-parameter-group-name>"
export SOURCE_WRITER="<source-writer-db-instance-identifier>"
export DB_INSTANCE_PARAMETER_GROUP="<db-instance-parameter-group-name>"
export PRE_CUTOVER_SNAPSHOT="<pre-cutover-snapshot-identifier>"

aws rds describe-db-clusters \
  --db-cluster-identifier "$SOURCE_CLUSTER" \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --query 'DBClusters[0].{Earliest:EarliestRestorableTime,Latest:LatestRestorableTime,Retention:BackupRetentionPeriod,Engine:Engine,EngineVersion:EngineVersion,SubnetGroup:DBSubnetGroup,ParameterGroup:DBClusterParameterGroup,SecurityGroups:VpcSecurityGroups[*].VpcSecurityGroupId,Encrypted:StorageEncrypted,KmsKeyId:KmsKeyId,Scaling:ServerlessV2ScalingConfiguration}'

aws rds describe-db-instances \
  --db-instance-identifier "$SOURCE_WRITER" \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --query 'DBInstances[0].{ParameterGroups:DBParameterGroups[*].DBParameterGroupName,AutoMinorVersionUpgrade:AutoMinorVersionUpgrade}'
```

Choose a UTC `RESTORE_TIME` inside the returned earliest/latest interval and
immediately before the damaging event. Record the evidence and timestamp in the
approved operational record. Do not use `--use-latest-restorable-time` unless
latest-state recovery is explicitly the incident objective.

### 2. Restore a separate cluster and writer

The restore explicitly reuses the production network controls, keeps 14-day
retention and deletion protection, and uses the existing Serverless v2 bounds.
Omitting `--kms-key-id` makes an encrypted restore inherit the source KMS key.

```bash
aws rds restore-db-cluster-to-point-in-time \
  --source-db-cluster-identifier "$SOURCE_CLUSTER" \
  --db-cluster-identifier "$RESTORED_CLUSTER" \
  --restore-to-time "$RESTORE_TIME" \
  --db-subnet-group-name "$DB_SUBNET_GROUP" \
  --vpc-security-group-ids "$DB_SECURITY_GROUP" \
  --db-cluster-parameter-group-name "$DB_CLUSTER_PARAMETER_GROUP" \
  --serverless-v2-scaling-configuration MinCapacity=0.5,MaxCapacity=4 \
  --backup-retention-period 14 \
  --deletion-protection \
  --copy-tags-to-snapshot \
  --tags Key=Project,Value=mem9-on-aws Key=Stage,Value=prod Key=ManagedBy,Value=recovery \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION"

aws rds wait db-cluster-available \
  --db-cluster-identifier "$RESTORED_CLUSTER" \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION"

aws rds create-db-instance \
  --db-instance-identifier "$RESTORED_INSTANCE" \
  --db-cluster-identifier "$RESTORED_CLUSTER" \
  --engine aurora-postgresql \
  --db-instance-class db.serverless \
  --db-parameter-group-name "$DB_INSTANCE_PARAMETER_GROUP" \
  --no-auto-minor-version-upgrade \
  --no-publicly-accessible \
  --promotion-tier 0 \
  --tags Key=Project,Value=mem9-on-aws Key=Stage,Value=prod Key=ManagedBy,Value=recovery \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION"

aws rds wait db-instance-available \
  --db-instance-identifier "$RESTORED_INSTANCE" \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION"
```

Verify the restored cluster before connecting. `Encrypted` must be `true`,
`Retention` must be `14`, the KMS key must match the approved source key, and
the endpoint must differ from the source endpoint.

```bash
aws rds describe-db-clusters \
  --db-cluster-identifier "$RESTORED_CLUSTER" \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --query 'DBClusters[0].{Status:Status,Endpoint:Endpoint,Retention:BackupRetentionPeriod,DeletionProtection:DeletionProtection,Encrypted:StorageEncrypted,KmsKeyId:KmsKeyId,Scaling:ServerlessV2ScalingConfiguration}'
```

### 3. Validate schema without reading memory content

From an approved PostgreSQL client inside the VPC, supply the restored endpoint,
database user, and password through a temporary `PGPASSFILE`. Never put a
password in the command line, shell history, committed files, or logs.

```bash
export PGHOST="<restored-cluster-endpoint>"
export PGPORT="5432"
export PGDATABASE="mem9"
export PGUSER="<database-user>"
umask 077
export PGPASSFILE="$(mktemp)"
chmod 600 "$PGPASSFILE"
trap 'rm -f "$PGPASSFILE"' EXIT

# Populate PGPASSFILE from the approved secret without printing the password.
# Escape any "\" or ":" characters according to the PostgreSQL .pgpass format.

psql -X -v ON_ERROR_STOP=1 <<'SQL'
SELECT extname FROM pg_extension WHERE extname = 'vector';
SELECT to_regclass('public.tenants') AS tenants_table,
       to_regclass('public.memories') AS memories_table;
SELECT format_type(a.atttypid, a.atttypmod) AS embedding_type
FROM pg_attribute AS a
WHERE a.attrelid = 'public.memories'::regclass
  AND a.attname = 'embedding'
  AND NOT a.attisdropped;
SELECT indexname
FROM pg_indexes
WHERE schemaname = 'public'
  AND tablename = 'memories'
  AND indexname IN ('idx_app', 'idx_memories_embedding', 'idx_memories_fts')
ORDER BY indexname;
SQL
```

Require `vector`, both tables, `embedding_type = vector(1024)`, and all
bootstrap-required indexes. Compare aggregate row counts only if needed; do not
select or log memory content.

### 4. Take the pre-cutover backup

Establish a write fence under the incident change window:

1. Pause scheduled CI and every headless process that holds the normal M2M
   client credentials.
2. Through a reviewed IaC change, create a temporary recovery-only Cognito M2M
   client with the existing read/write scopes. Store its generated ID and secret
   in `/mem9-on-aws/prod/recovery/cognito/{client-id,client-secret}` and make it
   the Gateway's **only** `allowedClients` entry for `prod`.
3. Deploy the fence, verify both a normal M2M client and normal interactive
   client are rejected, and use
   the proxy Lambda's CloudWatch `Invocations` metric to confirm zero backend
   calls during twice the maximum request timeout.

Then snapshot the still-active source cluster. Keep the fence in place through
cutover, synthetic verification, and any rollback; only the operator's synthetic
probe may write after cutover. Do not proceed until the snapshot is available.

```bash
aws rds create-db-cluster-snapshot \
  --db-cluster-identifier "$SOURCE_CLUSTER" \
  --db-cluster-snapshot-identifier "$PRE_CUTOVER_SNAPSHOT" \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION"

aws rds wait db-cluster-snapshot-available \
  --db-cluster-snapshot-identifier "$PRE_CUTOVER_SNAPSHOT" \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION"
```

### 5. Cut over through IaC

Do not edit SSM parameters or ECS task definitions manually, and do not import
the restored cluster during incident cutover. Prepare a reviewed, lookup-only
recovery change in `infra/db.ts` that:

- leaves the original `sst.aws.Aurora` declaration state-managed and retained;
- for `prod` only, resolves `MEM9_RECOVERY_DB_CLUSTER_IDENTIFIER` with
  `aws.rds.getClusterOutput`;
- uses `MEM9_RECOVERY_DB_SECRET_ARN` only after that secret has authenticated
  successfully to the restored cluster;
- feeds the selected writer endpoint and secret ARN through the existing
  `DbOutputs` contract; and
- leaves the stage-derived retention transform unchanged.

Keep the database values in `.env.recovery`, never in tracked files:

```bash
export MEM9_RECOVERY_DB_CLUSTER_IDENTIFIER="$RESTORED_CLUSTER"
export MEM9_RECOVERY_DB_SECRET_ARN="<approved-secret-arn>"
```

Source that file into the deploy shell before preview and deployment. This
lookup-only approach leaves source-cluster ownership unchanged, making rollback
a connection-selection change rather than another state import.

Run `sst diff --stage prod` and require:

- the restored endpoint and approved secret are the only database connection
  inputs propagated to ECS and bootstrap;
- neither cluster is deleted or replaced;
- encryption, security groups, Serverless v2 bounds, production retention,
  deletion protection, and SST `removal: "retain"` / `protect: true` remain;
- no plaintext credential or full DSN appears in the plan.

After approval, deploy the recovery change:

```bash
set -a
source .env.recovery
set +a
sst diff --stage prod
sst deploy --stage prod
STAGE=prod AWS_REGION="$AWS_REGION" bash scripts/run-bootstrap-task.sh
```

Replacing the ECS task is required because database credentials are injected at
task start. The bootstrap task is also required: it idempotently updates the
tenant row's per-request `db_host` and credentials to the selected endpoint.
Do not probe until both the ECS service and bootstrap task are on the recovery
configuration. Adopt the restored cluster into long-term IaC ownership only in
a separate reviewed change after recovery is stable. Restore the normal M2M and
reader client IDs to the Gateway allowlist, remove the temporary recovery client,
and resume paused jobs only after the cutover or rollback probe passes.

### 6. Verify and roll back

Keep normal clients behind the write fence and run the existing hard-fail
synthetic write/search probe after cutover. It writes only a generated marker
and does not inspect existing memory content. The script first waits for ECS
service stability, verifies every running task uses the active task definition,
and verifies that task definition targets the restored cluster.

```bash
STAGE=prod \
AWS_REGION="$AWS_REGION" \
E2E_SOFT=0 \
E2E_COGNITO_CLIENT_PREFIX="/mem9-on-aws/prod/recovery/cognito" \
E2E_EXPECTED_DB_CLUSTER_IDENTIFIER="$RESTORED_CLUSTER" \
bash scripts/run-mcp-e2e.sh
```

If deployment or verification fails, keep the write fence in place, unset the
two recovery variables, and deploy the same IaC change so `DbOutputs` selects
the untouched source endpoint and original secret again. Rerun the same probe;
remove the write fence only after either the cutover probe or rollback probe
passes. Keep the restored cluster for investigation and the pre-cutover snapshot
until the incident owner closes the recovery. Do not delete either cluster or
rotate credentials as part of rollback.

```bash
unset MEM9_RECOVERY_DB_CLUSTER_IDENTIFIER MEM9_RECOVERY_DB_SECRET_ARN
sst diff --stage prod
sst deploy --stage prod
STAGE=prod AWS_REGION="$AWS_REGION" bash scripts/run-bootstrap-task.sh
STAGE=prod \
AWS_REGION="$AWS_REGION" \
E2E_SOFT=0 \
E2E_COGNITO_CLIENT_PREFIX="/mem9-on-aws/prod/recovery/cognito" \
E2E_EXPECTED_DB_CLUSTER_IDENTIFIER="$SOURCE_CLUSTER" \
bash scripts/run-mcp-e2e.sh
```

### Command preflight

`--generate-cli-skeleton output` validates AWS CLI arguments locally and does
not call AWS. Use it with non-production dummy identifiers before an incident;
also run `bash -n scripts/run-mcp-e2e.sh`. These checks validate command shape
only and never replace a reviewed recovery drill.

AWS references:
[Aurora backup and restore](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Aurora.Managing.Backups.html),
[point-in-time restore](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-pitr.html),
and [`restore-db-cluster-to-point-in-time`](https://docs.aws.amazon.com/cli/latest/reference/rds/restore-db-cluster-to-point-in-time.html).

## Preview reconciliation

The `Reconcile preview stages` workflow runs daily in report-only mode. Manual
dispatch also defaults to `dry-run`; selecting `apply` explicitly rechecks every
candidate before invoking `sst remove` for a strict `pr-N` stage with SST state.
Tagged resources without SST state are never deleted. They are summarized by
stage and resource type in one deduplicated operator issue.

After deploying a revision that introduces this workflow, re-run
`scripts/deploy-github-role.sh` once so the out-of-band CI role receives the
read-only `tag:GetResources`, `iam:ListRoles`, and scoped `iam:ListRoleTags`
grants used for inventory discovery.

## License

The mem9 server (`mnemo-server`) is Apache-2.0 (upstream `mem9-ai/mem9`). See that
project for its license; this repo's own IaC/config is provided as-is.
