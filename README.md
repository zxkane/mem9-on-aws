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

| Dimension          | Decision                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| IaC                | **SST v4**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Region topology    | **Region-heterogeneous**: `sst.config.ts` selects the application plane and retained ECR repository region; account-global IAM ownership stacks are hosted in `us-west-2`; the optional Mantle Responses route uses its own configured region (default `us-west-2`) and regional Project.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Container registry | Four retained ECR repositories plus guarded registry-level BASIC scan-on-push for `mem9-on-aws/*`, both managed out of band                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Compute            | **ECS Fargate**, **arm64**, single task (`desiredCount=1`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Database           | **Aurora PostgreSQL Serverless v2** + `pgvector` (mem9 `postgres` backend). `mnemo-server` and bootstrap connect directly to the cluster writer endpoint with a Secrets Manager credential. **RDS Proxy is not deployed.**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| VPC                | **Reuse the account default VPC** (private subnets with NAT egress)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| MCP surface        | **AgentCore Gateway** (MCP → mnemo-server REST API)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Gateway → server   | **Private** (a [Lambda-proxy GatewayTarget](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-add-target-api-target-config.html)): AgentCore invokes a VPC-attached proxy Lambda with [`lambda:InvokeFunction`](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-prerequisites-permissions.html). The Lambda uses [VPC connectivity](https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html) and [AWS Cloud Map private DNS](https://docs.aws.amazon.com/cloud-map/latest/api/API_CreatePrivateDnsNamespace.html) (`mnemo.mem9-<stage>.local:8080`) to reach mnemo-server with the `X-API-Key` (= tenant id). No ALB, VPC Lattice, or public server endpoint is deployed; the optional OAuth façade custom domain is a separate API Gateway concern. |
| Auth (inbound)     | **Cognito M2M** (`client_credentials`) + an OAuth2 browser-login façade (`authorization_code` + PKCE) for interactive MCP clients                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| LLM (smart-ingest) | `mnemo-server` calls the **local `llm-proxy` sidecar** at `http://localhost:8082/v1`. The proxy refreshes a short-term Mantle bearer, injects `OpenAI-Project` when `MEM9_BEDROCK_PROJECT` is configured, and calls Bedrock Mantle. Each request has one 110-second deadline and at most two Mantle calls. The task role uses `bedrock-mantle:CreateInference` and `bedrock-mantle:CallWithBearerToken`; `mnemo-server` never calls Mantle directly.                                                                                                                                                                                                                                                                                                                                                       |
| Embedding          | qwen3 OpenAI-compatible `/embeddings` as an **ECS sidecar** (localhost, always warm), **dims 1024**. Not Mantle, not a third-party API.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ECS task           | **3 containers**: mnemo-server + qwen3-embed sidecar + llm-proxy sidecar                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Schema bootstrap   | **startup atomic-ingest migration** before `mnemo-server`, plus a **one-shot ECS task** on deploy (pgvector + tenant runtime schema incl. `idx_app`/FTS/`vector(1024)` + seed 1 tenant)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Durable ingest     | Transcript `messages[]` requests enqueue durable Aurora jobs. Immutable, materialized plans apply raw sessions, tags, memory actions, and job success in one PostgreSQL transaction; authenticated REST and Gateway status lookups are tenant-scoped.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Maintenance        | **Service-scoped cleanup and consolidation.** Every invocation requires one namespace and an active service membership. Tasks default to report-only; scheduling is opt-in. Slack digests, approval, and cleanup scans remain disabled. |
| Tenancy            | **single tenant** (one `X-API-Key`); writes carry **`X-Mnemo-Agent-Id`** to reserve per-agent scoping                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Replicas           | **Single** (`desiredCount=1`) — single-writer, sidesteps mem9's local-disk import dir                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |

### Region topology

This is not a single-region deployment where one `AWS_REGION` applies to every
resource. Treat each plane independently:

- **Application plane:** SST resources, VPC, ECR images, and the primary Mantle
  route use `providers.aws.region` in `sst.config.ts` as their single source of
  truth. Changing that value retargets every application consumer for a fresh
  deployment. An ambient environment override does not move the application.
- **IAM ownership plane:** the GitHub Actions role and workload-boundary
  CloudFormation stacks are intentionally hosted in `us-west-2`. IAM is
  account-global, while the fixed stack region prevents duplicate ownership.
- **Optional Responses plane:** the Responses model route, its task-role grant,
  workload-boundary Project ARN, Mantle bearer, and `OpenAI-Project` value use
  their own region. The default is `us-west-2`, independently of the application
  region. Selecting a configured OpenAI GPT model routes it here when that model
  is unavailable in the application region.

Operator commands must use the region of the component they address. Do not
replace these service-specific regions with one global value. A hosted OAuth
callback may run in any region; only its exact public HTTPS URL is allowlisted.

Changing the provider region does not relocate an existing live deployment:
AWS regional resources remain in their original region. The retained workload
boundary and GitHub Actions role record the application region and fail before
mutation when it differs from `sst.config.ts`. Remove all old-region previews
first, then use a separately reviewed dual-region data/resource migration.
Region-changing PRs are blocked before AWS deployment, and closed-PR cleanup
uses the base region so an earlier preview is not orphaned. There is
intentionally no one-command in-place production region switch.

## Cost attribution and monthly estimate

The billing model has three attribution scopes. Keep them separate rather than
forcing every charge through one `Stage=prod` filter:

| Scope            | Cost Explorer attribution                                                                                         | Included resources                                                                                                  |
| ---------------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Production       | `Project=mem9-on-aws` **and** `Stage=prod`                                                                        | SST-managed Aurora, ECS, Lambda, API Gateway, AgentCore Gateway, CloudWatch, Secrets Manager, and related resources |
| Mantle inference | Service `Amazon Bedrock` **and** `Project=mem9-on-aws`                                                            | Chat Completions requests associated with the retained Bedrock Project                                              |
| Shared           | `Project=mem9-on-aws`, excluding service `Amazon Bedrock`; group by `Stage` and retain only the no-`Stage` bucket | Retained ECR repositories, the Bedrock Project resource, and other intentionally stage-neutral resources            |

SST applies `Project`, `Stage`, and `ManagedBy` as default tags. The retained
Bedrock Project is different: it intentionally has no `Stage`, and `llm-proxy`
associates each Mantle Chat Completions request with it through
`OpenAI-Project`. AWS documents that a Project's tags flow to Cost Explorer and
CUR 2.0. Do not add `Stage=prod` to the Mantle query or its inference cost will
be omitted. See [Bedrock Projects cost
attribution](https://docs.aws.amazon.com/bedrock/latest/userguide/cost-mgmt-projects.html).

AgentCore Gateway is not the model charge. It bills Gateway operations such as
tool listing, invocation, and health checks at approximately **$0.005 per 1,000
API invocations**. Semantic search is approximately **$0.025 per 1,000
queries**, tool indexing is **$0.02 per 100 indexed tools per month**, and data
egress to a customer VPC adds **$0.006 per GB**. The target Lambda invocation
and Mantle inference are separate charges. See [AgentCore
pricing](https://aws.amazon.com/bedrock/agentcore/pricing/).

### ECS/Fargate attribution requirement

Fargate vCPU and memory charges belong to the running ECS **task**, not merely
to the tagged ECS Service. The Service must propagate its user tags when tasks
are created:

```text
propagateTags = SERVICE
```

This repository sets both `propagateTags=SERVICE` and
`enableEcsManagedTags=true`. The latter adds AWS-managed cluster and
service-name tags, but it does not replace propagation of `Project` and
`Stage`. Tag changes apply only to newly created tasks, so the Service sets
`forceNewDeployment=true` with a versioned deployment trigger; the update that
enables propagation replaces tasks that predate the setting even when the image
tag is unchanged. The one-shot bootstrap run separately propagates
`TASK_DEFINITION` tags and enables ECS-managed tags. The `Project` and `Stage`
keys must also be activated as cost-allocation tags before the resulting
charges appear in Cost Explorer.

Without task tag propagation, a `Project + Stage` report excludes Fargate even
when the ECS Service itself has both tags. Those charges appear in the
untagged ECS bucket, where they cannot be reliably separated from other
untagged workloads. Task tag propagation is not retroactive: it cannot add tags
to historical task usage. Cost-allocation tag activation is different; AWS can
backfill the current activation status to a prior billing month, but that does
not reconstruct tags that were absent from a resource or task. See
[tagging ECS resources](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-using-tags.html)
and [cost-allocation tag
backfill](https://docs.aws.amazon.com/cli/latest/reference/ce/start-cost-allocation-tag-backfill.html).

### Reporting procedure and considerations

1. Use `UnblendedCost` for a single account, and exclude `Credit` and `Refund`
   record types. Use amortized cost instead if commitments must be allocated.
2. Produce the production, Mantle, and shared scopes above as separate reports,
   then sum them. Keep the scopes mutually exclusive by excluding `Amazon
Bedrock` and retaining only the no-`Stage` bucket in the shared scope. Group
   each scope by AWS service and usage type.
3. Reconcile every service total against its tagged total. Investigate the
   no-tag bucket, especially for Fargate tasks, model calls without a Project,
   restored resources, and tasks that ran before tag propagation.
4. Treat the current day as incomplete. Cost data, newly activated tags, and
   new tag values can take roughly 24 hours to appear. Request a cost-allocation
   tag backfill when prior-month activation status is needed. AWS limits the
   start date to the previous 12 months and accepts one request every 24 hours
   after the prior request completes.
5. Use CUR 2.0 when invoice-level line items or task-level allocation are
   required. ECS Split Cost Allocation Data adds task CPU and memory usage
   detail; it is not a substitute for propagating cost-allocation tags.
6. Report preview stages separately. Each live preview can duplicate the two
   largest fixed lines, Aurora and Fargate, until reconciliation removes it.
7. Allocate shared NAT Gateway hourly cost only if this application owns the
   gateway. For a pre-existing shared NAT, attribute incremental processing and
   transfer where CUR supports it, and leave the shared hourly charge in a
   documented shared-cost pool.
8. Set budgets on the combined project view and separate alerts for Fargate,
   RDS, and Bedrock so a missing tag cannot hide a service-level increase.

### Approximate monthly cost

These are architecture estimates, not a quote or a snapshot of any AWS
account. They assume one continuously running production task, near-idle
database capacity, low API traffic, and 730.5 hours per average month. Prices
vary by Region and can change.

| Cost driver                                         | Assumption                                                                                                                     | Approximate monthly cost |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------ |
| ECS Fargate                                         | One arm64 task, 2 vCPU and 6 GB, running continuously                                                                          | **$78**                  |
| Aurora PostgreSQL Serverless v2 capacity            | Production 1 ACU floor; Tokyo Standard capacity example at $0.15/ACU-hour                                                     | **$110**                 |
| Aurora storage, I/O, and backup                     | Depends on retained data and request volume                                                                                  | **Variable**             |
| Supporting services                                 | CloudWatch dashboard/alarms/logs, Secrets Manager, ECR storage, Lambda, API Gateway, Cognito, and low-volume AgentCore Gateway | **$5-20**                |
| Core total before variable storage/I/O, model usage and shared networking | Production compute and supporting-service baseline                                                               | **$193-208**             |
| Bedrock Mantle                                      | Input and output tokens for the selected model                                                                                 | **Variable**             |

The Fargate estimate uses representative regional arm64 rates:
`2 x 730.5 x $0.04045` for vCPU plus
`6 x 730.5 x $0.00442` for memory, or approximately **$78/month**.

The Aurora capacity example uses the Tokyo Standard on-demand rate returned by
the AWS Price List API on 2026-09-15: `1 x 730.5 x $0.15`, or **$109.58/month**.
Development and preview stages retain the 0.5 ACU floor, about **$54.79/month**
at that rate. Raising the production minimum from 0.5 to 1 increases the
capacity-cost floor by at most about **$55/month**; the actual difference depends
on time already spent above 0.5 ACU and any storage/I/O savings from caching.
These figures exclude discounts and taxes and are not universal regional rates.

The Fargate task and Aurora floor dominate the fixed cost. The qwen3 embedding
model drives the 2 vCPU/6 GB task size; reduce it only after CPU and memory
measurements prove a smaller valid Fargate size is safe. A Compute Savings Plan
can help a stable 24/7 task, while Fargate Spot is a poor default for the only
replica unless interruptions are acceptable.

The conservative smaller candidate is **1 vCPU/6 GB**, approximately
**$49/month** at the same rates. It preserves memory headroom but halves burst
CPU, so validate embedding latency, ingest deadlines, and startup health before
adopting it. Reducing memory from 6 GB to 5 GB saves only about **$3/month**;
4 GB leaves too little headroom for the embedding model, application, and proxy
sidecars to be a safe production target.

Aurora auto-pause is unlikely to help while the long-lived service polls the
durable ingest queue and retains database connections. A single-AZ burstable
RDS PostgreSQL instance can reduce the database estimate to roughly
**$20-40/month** plus storage, but gives up Aurora Serverless scaling and
requires a planned database migration. Mantle remains usage-based; bound prompt
size and output tokens, and review token usage by Bedrock Project rather than
estimating it from Gateway calls.

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
  metadata for a durable ingest job inside the caller's team namespace.

## Layout

- `infra/` — the SST/Pulumi app (VPC lookup, Aurora, ECS, Cognito, gateway,
  OAuth façade, bootstrap, consolidation) + unit tests.
- `docker/` — the four container images: `mnemo-server` (pinned upstream build),
  `qwen3-embed` (embedding sidecar), `llm-proxy` (Mantle bearer/project bridge),
  `bootstrap` (schema + tenant seed).
- `scripts/` — out-of-band bootstrap scripts (GitHub Actions IAM role, workload
  permissions boundary, four ECR repositories, guarded registry scan-on-push,
  Bedrock Mantle Project, and the decision-artifact bucket) that the SST app
  references read-only. See each script's header and `.env.example` for the
  environment it expects.
- `docs/` — `ARCHITECTURE.md` (decisions) and `mem9-facts.md` (upstream constraints).

## Development

- **Node.js 24 LTS** everywhere (`.nvmrc` = 24, `engines.node >= 24`, CI +
  Lambda `nodejs24.x`). The Go build for mnemo-server targets **arm64**.
- Container security updates cover all three service images and the bootstrap
  image. Node sidecars use `node:24-trixie-slim`; mnemo-server uses Alpine 3.24
  and Go 1.27; bootstrap uses Node 24 and the PostgreSQL 17 client on Alpine
  3.24. Every image build
  pulls the current base and bypasses the `runtime` stage cache to run
  `apt-get dist-upgrade` or `apk upgrade`; the Go builder is refreshed too.
  The separate Qwen `model` stage retains its dependency/model cache while its
  base digest is unchanged; a new base digest rebuilds it as well.
  Node health checks replace curl, avoiding its libssh2 dependency. BusyBox,
  musl, and PCRE2 remain where required and receive distribution updates.
  For equivalent local builds, pass `--pull --no-cache-filter runtime` to
  `docker buildx build` (`--no-cache-filter builder,runtime` for mnemo-server).
  Publish and deploy the rebuilt release tag, then re-scan its image digest;
  existing images and running tasks are not patched by a Dockerfile edit.
- Copy `.env.example` to `.env` and fill in your AWS profile before running the
  `scripts/deploy-*.sh` bootstrap scripts.
- The public OAuth facade always attaches its allow-all Lambda request
  authorizer to both API Gateway routes. It has no identity sources or cache, so
  anonymous protocol endpoints remain reachable; the facade handler still
  enforces the real `/mcp` bearer check.
- Cognito hosted-UI prefixes share a namespace across AWS accounts in each
  Region. New stages default to a stable `mem9-<hash>` prefix derived from the
  AWS account, application Region, and stage; the account ID is not exposed.
  `MEM9_COGNITO_DOMAIN_PREFIX` remains an explicit override. Before adopting
  this change for an existing stage, preserve its current prefix so the OAuth
  hostname is not replaced:

  ```bash
  gh variable set MEM9_COGNITO_DOMAIN_PREFIX --body "<existing-prefix>"
  ```

  Infra CI passes this repository variable only to the production deploy;
  previews use their derived stage-specific defaults. A new repository may
  leave it unset. Treat either choice as permanent for the stage because the
  prefix is the OAuth token/authorize hostname.

- `scripts/deploy-github-role.sh` always owns its account-global IAM stack in
  `us-west-2` and ignores ambient `AWS_REGION`. Application VPC discovery and
  regional bootstrap resources resolve `providers.aws.region` from
  `sst.config.ts`. `PROJECT_REGION` is only an explicit selector when creating a
  separate regional Mantle Project, such as the OpenAI Responses fallback.
- Agent contributors: see [`AGENTS.md`](AGENTS.md) for repo conventions and hard rules.

### Team memory namespaces and production cutover

One Aurora database is shared by all teams. A managed Cognito group routes a
human to one internal namespace, while Aurora memberships remain the
authorization, role, revocation, and audit source of truth. Users in the same
managed group share memory; users in different managed groups cannot read or
mutate each other's memories, sessions, jobs, or plans. Clients never submit a
namespace ID. M2M clients use explicit database bindings instead of Cognito
groups.

A deployment can use one registered namespace. Additional business groups and
namespaces are optional; the application does not require a second one. In
namespace-required mode, each human must match exactly one registered namespace
group and have an active membership. `mem9-<team-slug>` is an example naming
convention, not an enforced prefix or an instruction to create a namespace.
Bindings use exact configured group names.

For an external Cognito pool, keep the application admission group (the value
of the optional `MEM9_AUTH_REQUIRED_GROUP`) separate from namespace groups.
Omitting that admission check does not bypass namespace authorization. For example:

| Human | Provider groups | Memory namespace |
| --- | --- | --- |
| First and second team members | `mem9-access`, `mem9-team-a` | `team-a`, shared |
| Another team member | `mem9-access`, `mem9-team-b` | `team-b`, isolated |

The admission group `mem9-access` is not a namespace binding. Bind only
`mem9-team-a` and `mem9-team-b` in desired state; unrelated groups are ignored.
Two namespace groups cause rejection, regardless of Cognito group precedence.
Use `MEM9_AUTH_GROUP_CLAIM=cognito:groups` for an external Cognito pool.
Creating groups alone does not isolate compatibility-mode data: complete the
backfill and required-mode cutover below before onboarding another team.

The implementation is additive and defaults to compatibility mode:

```text
MEM9_NAMESPACE_REQUIRED=0  server starts only while database is additive_ready
MEM9_NAMESPACE_REQUIRED=1  server requires constraints_complete
```

Production consumes the repository variable. A fresh `pr-N` preview uses an
automated synthetic cutover instead: its first deployment forces `0`, bootstrap creates
`preview-alpha` and `preview-beta` in that preview's one Aurora database,
reconciles two managed Cognito groups plus temporary M2M bindings, completes the
empty-database migration, and a second deployment forces `1`. CI then performs
a live-Gateway test in which each temporary client recalls its own marker, the
stage's default M2M client recalls the alpha marker through the same shared
namespace, and neither fixture returns the other namespace's marker. No
production namespace, user, or memory value is needed for this preview gate,
and all fixture resources are removed with the PR stage. On a later run for the
same PR, CI first reruns the existing idempotent bootstrap task, then deploys
directly with `1`; this recovers a run cancelled during cutover and never
restarts a completed database in compatibility mode.

The two synthetic preview namespaces are required to test cross-namespace
isolation. They do not impose a second namespace on a deployment. Public test
reports use fixture data only; real identity mappings, corpus measurements, and
rollout records remain private to the operator.

Transport signing uses stable A/B key slots. GitHub repository variables
`MEM9_TRANSPORT_SIGNING_ACTIVE_SLOT`,
`MEM9_TRANSPORT_SIGNING_SLOT_A_REVISION`, and
`MEM9_TRANSPORT_SIGNING_SLOT_B_REVISION` default to `a`, `v1`, and `v1` when
unset. To rotate, increment only the inactive slot revision and deploy; after
the rollout is healthy, switch the active slot and deploy again. Never rotate
both slots or switch active slots in the same deployment that changes a
revision. The keyring digest changes the ECS task definition, so the rolling
tasks consume the new SSM SecureString instead of retaining the value injected
at their previous start.

Do not set the repository variable to `1` on an existing stage until the
following guarded cutover is complete. The migration commands operate inside a
private bootstrap Fargate task; they do not stop ECS, disable traffic, create a
snapshot, or prevent Cognito administration on their own.

1. Deploy the reviewed release with `MEM9_NAMESPACE_REQUIRED` unset or `0`, then
   run the normal bootstrap. This installs the additive schema while the current
   corpus remains available.
2. Deploy the retained operator task role after the compatible release exports
   the stage's user-pool ID:

   ```bash
   MEM9_NAMESPACE_OPERATOR_STAGE=prod \
     scripts/deploy-memory-namespace-operator-role.sh
   ```

   For external authentication, also pass `MEM9_AUTH_MODE=oidc`; the retained
   role then has no Cognito administration grants. Use the application account
   credentials for this role and the private task, and the provider account's
   credentials and region only for provider group administration.

   The account has one fixed `memory-namespace-operator-mem9-on-aws` ownership
   stack in `us-west-2`. Its first deployment binds it to the selected stage
   and application region. Later runs may refresh that stage's user-pool ID,
   but cannot retarget the retained role to another stage or application
   region. The script verifies the final CloudFormation parameters even when
   the update is a no-op.

3. Create a manual Aurora snapshot and record the latest restorable time in a
   private operator record. Pause user/group onboarding, disable write-capable
   event sources, drain durable jobs, scale the mnemo-server ECS service to zero,
   and wait for no running or pending application task.
4. Run `preflight`; it must report zero non-terminal jobs and active uploads.
   Then freeze database writers. Do not run `freeze` while the application
   service is still running. `freeze` waits for existing DML transactions under
   bounded table locks, rechecks durable jobs and uploads in the same
   transaction, and changes the phase only when both remain drained.

   ```bash
   STAGE=prod scripts/run-memory-namespace-task.sh preflight
   STAGE=prod scripts/run-memory-namespace-task.sh freeze
   ```

5. Backfill all historical data into one explicitly approved legacy team
   namespace. Use new random UUIDs for the namespace and unattributed service
   principal; never reuse IDs from another stage. The first backfill invocation
   permanently binds the migration state to those IDs and the supplied
   namespace metadata. A retry must use the exact same values.

   ```bash
   STAGE=prod scripts/run-memory-namespace-task.sh backfill \
     --legacy-namespace-id <legacy-namespace-uuid> \
     --legacy-service-principal-id <legacy-service-principal-uuid> \
     --namespace <legacy-team-slug> \
     --display-name "<legacy-team-display-name>" \
     --acknowledge-shared-history \
       I_ACKNOWLEDGE_EXISTING_MEMORY_IS_SHARED_TEAM_HISTORY

   STAGE=prod scripts/run-memory-namespace-task.sh enforce
   ```

6. Prepare a gitignored desired-state JSON file from
   `scripts/memory-namespaces.example.json`, set its mode to `600`, reconcile
   the Cognito groups and Aurora bindings, then assign each enabled user to
   exactly one namespace. Supply usernames through an owner-only file or stdin;
   do not put them in tracked files or command arguments.

   ```bash
   cp scripts/memory-namespaces.example.json namespace-config.local.json
   chmod 600 namespace-config.local.json

   STAGE=prod scripts/run-memory-namespace-task.sh reconcile \
     --config namespace-config.local.json

   STAGE=prod scripts/run-memory-namespace-task.sh assign-user \
     --config namespace-config.local.json \
     --username-file <username.local.txt> \
     --namespace <team-slug>
   ```

   In external mode, reconciliation writes Aurora bindings without changing
   provider groups. Create the namespace groups and assign users at the
   provider. The `cognito_group` configuration field still contains the exact
   group name even though its lifecycle is external. Keep the same legacy
   namespace slug used by backfill; reconciliation preserves its internal ID.

   Use an owner-only `identity.local.json` containing exactly the current
   provider's issuer and immutable `sub`, obtained from its administration
   records. An email, display name, or old-pool username is not a substitute:

   ```json
   {"issuer":"https://id.example.com/pool","sub":"provider-subject"}
   ```

   ```bash
   chmod 600 identity.local.json
   STAGE=prod scripts/run-memory-namespace-task.sh assign-user \
     --config namespace-config.local.json \
     --identity-file identity.local.json --namespace <team-slug>

   STAGE=prod scripts/run-memory-namespace-task.sh show-user \
     --config namespace-config.local.json --identity-file identity.local.json
   ```

   These commands change only Aurora authorization and verify the file's
   issuer against the deployed task. For an external user move, first run
   `revoke-user --identity-file ...`, update the provider to exactly one target
   namespace group, then run `assign-user --identity-file ... --namespace ...`
   and obtain a fresh token. Normal revoke blocks JIT even before first login
   and allows accepted jobs to finish. `revoke-user --emergency` also disables
   the principal and cancels nonterminal jobs. A subsequent normal revoke
   preserves the disabled state; explicit assignment is required to restore it.
   `show-user` reports status/counts and does not create users or memberships.

   Bind each enabled M2M client to one namespace in `m2m_bindings`; human groups
   do not authorize machine clients. Derive its `client_key` and `principal_key`
   with `deriveClientKey(activeIssuer, clientId)` and
   `deriveM2MPrincipalKey(activeIssuer, clientId)` from
   `scripts/lib/memory-namespace.mjs`. Keep provider values and generated
   bindings in mode-600 gitignored files. A shared machine client cannot route
   to multiple namespaces.

7. Verify the database phase is `constraints_complete`, every human has exactly
   one managed group and active membership, and every enabled M2M client has one
   binding. Set the repository variable and deploy. When the variable is `1`,
   CI first launches the existing private operator task with
   `assert-phase constraints_complete`; a mismatch fails before SST deployment
   and reports only the observed and required phase:

   ```bash
   gh variable set MEM9_NAMESPACE_REQUIRED --body "1"
   gh workflow run "Infra CI" --ref main
   ```

8. Restore the service's desired count, reopen traffic, require fresh user
   tokens, and run same-group sharing plus cross-group denial smoke tests.
   Grant maintenance services access separately before running scoped cleanup,
   restore, or consolidation. Scheduling remains opt-in. Slack digests/approval,
   cleanup scans, upload processing, webhooks, and Space Chains remain disabled.

The caller of `scripts/run-memory-namespace-task.sh` needs constrained
`ecs:RunTask`, `ecs:ListTasks`, `ecs:DescribeTasks`, and `ecs:StopTask`
permissions for the stage bootstrap task plus `iam:PassRole` only for
`mem9-on-aws-namespace-operator`. The runner identifies active work with a
content-free operation fingerprint. It reattaches only to the same invocation,
refuses a different concurrent invocation, and on timeout, interruption, or
local failure stops the task before deleting short-lived SecureString inputs.
If ECS does not confirm `STOPPED`, the command fails and retains those inputs
for recovery instead of deleting data that a task may still need. The container
forwards termination to its child and uses a bounded kill watchdog. The task
uses the existing private database network path.

The authoritative design and acceptance criteria are
[`docs/designs/cognito-group-memory-namespaces.md`](docs/designs/cognito-group-memory-namespaces.md)
and
[`docs/test-cases/cognito-group-memory-namespaces.md`](docs/test-cases/cognito-group-memory-namespaces.md).

CI also verifies the version-controlled scoped-SQL manifest at
`scripts/memory-namespace-query-inventory.json` against the complete patched
upstream source and its exact trusted-exception policy. It also checks
`scripts/memory-namespace-release-gates.json` as a coverage ownership map so
every `TC-GROUPNS-001..137` criterion has exactly one owning capability and a
named verification surface. The map is not an AC execution result. The deployed
PR namespace check is implemented by
`scripts/run-memory-namespace-e2e.sh`.

#### Operator-run human OAuth acceptance

`scripts/run-human-namespace-e2e.mjs` exercises real human authorization-code +
PKCE login through the deployed facade and Cognito, followed by Gateway memory
requests and the existing access-management functions. Run a reviewed, clean
candidate checkout against its own `pr-N` preview from a trusted operator host
with private database access. This does not add user-administration permissions
to CI or application workloads. Automated human release gating remains follow-up
work alongside preview/production deployment-role separation.

Create a mode-600 `deployment.local.json` containing operator-verified targets.
Names and tags are consistency checks; independently pin the actual preview
pool, database resource ID, secret reference, account, deployed commit, and proxy
log group from its Lambda `LoggingConfig.LogGroup` (which SST may customize).
Never publish this file or derive authorization from PR-controlled tags alone.
For GitHub pull-request builds, `commit` is the deployed synthetic merge commit
(`refs/pull/<number>/merge`), not just the source branch head. Run the clean
checkout of that same commit; its `pr-<sha7>` image tag is checked before mutation.

```json
{
  "version": 1,
  "stage": "pr-<number>",
  "commit": "<full-reviewed-commit-sha>",
  "accountId": "<aws-account-id>",
  "region": "<application-region>",
  "userPoolId": "<preview-user-pool-id>",
  "facadeUrl": "https://facade.example.com",
  "gatewayUrl": "https://gateway.example.com/mcp",
  "proxyFunctionArn": "arn:aws:lambda:<application-region>:<aws-account-id>:function:<preview-proxy-function-name>",
  "proxyLogGroup": "<exact-preview-proxy-log-group>",
  "database": {
    "host": "database.example.com",
    "port": 5432,
    "name": "<database-name>",
    "clusterId": "<preview-cluster-identifier>",
    "resourceId": "<immutable-cluster-resource-id>",
    "secretArn": "arn:aws:secretsmanager:<application-region>:<aws-account-id>:secret:<preview-db-secret-name>",
    "caFile": "/absolute/path/to/rds-ca.pem"
  },
  "namespaces": [
    {"slug":"preview-alpha","display_name":"PR isolation fixture preview-alpha","cognito_group":"memory-preview-alpha","default_role":"member","jit_enabled":true,"status":"active"},
    {"slug":"preview-beta","display_name":"PR isolation fixture preview-beta","cognito_group":"memory-preview-beta","default_role":"member","jit_enabled":true,"status":"active"}
  ]
}
```

The operator needs metadata/secret reads for those targets and user/group
administration on that preview pool. Use the application's configured region.
Preflight verifies that the exact reader client has a 15-minute access-token
setting with explicit units, and browser registration must return that client.
Issued tokens may be one second shorter (899 seconds); lifetimes above 900 or
below 899 seconds, expired tokens, and excessive future issuance are rejected.
Database TLS verification is mandatory; supply the RDS CA bundle. An existing
authorized tunnel can use `MEM9_HUMAN_E2E_TUNNEL_PORT` with loopback while retaining
the pinned database hostname for TLS. The runner does not change network access.

```bash
npm ci
npx playwright install --with-deps chromium
node scripts/run-human-namespace-e2e.mjs \
  --deployment-file deployment.local.json \
  --fixtures-file human-fixtures.local.json \
  --evidence-file human-acceptance.json > human-output.local.log 2>&1
node scripts/run-human-namespace-e2e.mjs \
  --verify-output-file human-output.local.log
```

The fixture file is created exclusively with mode 600 and contains generated
credentials, captured subjects, and an immutable target fingerprint. Updates use
atomic replacement. Invitations are suppressed. No browser trace
or screenshot is saved. Evidence contains only the commit, named cases, and
completion flags. The matrix covers sharing/denial, first-login JIT, stale-token
revocation before first use, role checks, group drift, move failures/retries,
A-to-B-to-A, concurrent commands, and accepted-work revoke semantics. The output
verifier accepts only the complete fixed case vocabulary; unexpected SDK output,
identities, or lookup keys fail it.

Gateway masks Lambda errors. Each negative case therefore requires a matching
PR-only proxy diagnostic containing its invocation hash and exact backend
403/409 status; an arbitrary tool error, 429, or backend outage fails the test.
These diagnostics contain no arguments or identity values and are disabled in
production. The operator reads only the explicitly pinned proxy log group;
preflight rejects a configured log destination that differs from the manifest.

Successful cleanup disables fixture principals before deleting owned users and
removes the credential file. If cleanup is incomplete, retain that file and use
the recovery command; its target checks do not require a healthy app deployment:

```bash
node scripts/run-human-namespace-e2e.mjs \
  --deployment-file deployment.local.json \
  --fixtures-file human-fixtures.local.json \
  --evidence-file human-cleanup.json --cleanup-only
```

Private failure details stay beside the fixture file in a `*.failure.local.json`
record. A token-time failure records only integer checks and relative timing
differences from the validation clock, without tokens or identity claims.
Evidence paths must be new: cleanup cannot overwrite failed acceptance
evidence and produces a distinct `kind: cleanup` record. Publish only acceptance
evidence after both `success` and `cleanup_complete` are true. Ordinary revoke leaves tombstones for managed and
external identities even before their first memory request, so stale group
claims cannot recreate access through JIT.

### Decision-artifact bucket bootstrap

Scheduled consolidation stores private, memory-content-free state at
`consolidation-digests/<stage>/<namespace-id>/current-v1.json` in the retained
account-level decision-artifact bucket. Every SST stage shares the bucket;
provision it before enabling scheduled consolidation. Application stages do
not create or delete it. Existing `decisions/` artifacts belong to the disabled
Slack approval capability and are not an enablement path for that feature.

For the default `mem9-audit-<aws-account-id>` name:

```bash
# If .env does not already exist, copy .env.example and set AWS_PROFILE.
scripts/deploy-decision-artifact-bucket.sh
```

To choose a different name, set one value everywhere before the first bootstrap:

```bash
# In the gitignored .env used by operator scripts:
MEM9_DECISION_ARTIFACT_BUCKET=example-mem9-decision-artifacts

scripts/deploy-decision-artifact-bucket.sh
gh variable set MEM9_DECISION_ARTIFACT_BUCKET \
  --body "example-mem9-decision-artifacts"
```

If the workload boundary stack is new and unattached, create it with the same
environment:

```bash
scripts/deploy-workload-permissions-boundary.sh
```

If the boundary already exists, update it only through the guarded
[workload permissions-boundary rollout](#workload-permissions-boundary-rollout).
That procedure requires the deployment maintenance pause, a clean merged
default-branch checkout, and `WORKLOAD_BOUNDARY_MAINTENANCE_ACK=true`; do not run
the rollout as an unguarded bootstrap command.

The name must be 3–33 lowercase letters, digits, or hyphens, beginning and
ending with a letter or digit, and cannot use an S3-reserved prefix or suffix.
The 33-character ceiling preserves the workload boundary's 6144-byte
managed-policy quota because the exact name appears three times. The same value
scopes the bucket stack, SST task grants, workload boundary, preview E2E, and CI
deploys. Leave both `.env` and the repository variable unset to use the default.
Do not change the value after the stack owns a bucket: the script refuses that
replacement because it would split the audit trail and the boundary. A rename
needs a dedicated data and IAM migration.

On a fresh account the script creates the full stack. If the old stage-owned
deployment left the bucket behind, the script automatically imports only that
bucket with `decision-artifact-bucket-import.yaml`, waits for
`stack-import-complete`, then applies the full template. This second update is
required because CloudFormation import records properties but does not reconcile
public-access block, encryption, lifecycle, tags, or create the TLS-only policy.
Every path finishes by reading those controls back and requiring CloudFormation
drift status `IN_SYNC`. Re-running the script updates and verifies the existing
owner stack. If a full update rolls back, rerun after fixing the cause;
`UPDATE_ROLLBACK_COMPLETE` is recoverable after the script re-verifies the
physical bucket, while `UPDATE_ROLLBACK_FAILED` first requires
`continue-update-rollback`.

Cleanup and consolidation use the service-scoped tasks documented below.
Scheduling additionally requires the private namespace target list and the new
repository variable `MEM9_NAMESPACE_CONSOLIDATION_SCHEDULE_ENABLED`; old
repository enablement variables do not activate the CI deployment path.

Existing buckets from before consolidation digests still have the old
bucket-wide three-day lifecycle. Before setting
`MEM9_NAMESPACE_CONSOLIDATION_SCHEDULE_ENABLED=1`, re-run
`scripts/deploy-decision-artifact-bucket.sh` and require its two-rule lifecycle
read-back to pass: `decisions/` expires after three days and
`consolidation-digests/` after at least 70 days, with incomplete multipart
uploads aborted after one day on both prefixes.

The adoption phase is rerunnable after interruption. A pending
`REVIEW_IN_PROGRESS` stack resumes only when the fixed import change set reads
back exactly, and `IMPORT_IN_PROGRESS` resumes only its waiter. An
`IMPORT_ROLLBACK_COMPLETE` stack is recreated only after the script confirms its
stack shell owns no resources. `IMPORT_ROLLBACK_FAILED`, an unrecognized change
set, or any rollback stack that still owns a resource is left untouched for
explicit CloudFormation recovery.

### Optional hosted OAuth callback URLs

Native MCP clients continue to use RFC 8252 loopback callbacks without any
configuration. For a hosted OAuth client, set the stage-scoped SST secret to a
JSON array of complete callback URLs, then redeploy so SST propagates the value
to the stage's OAuth configuration in SSM and refreshes the façade Lambda:

`OauthAllowedCallbackUrls` is not a GitHub Actions environment or repository
secret. `sst secret set` replaces the complete JSON array, so inspect only the
current callback setting, preserve every existing URL, and append the new URL.
Do not print unrelated SST secrets while doing so.

```bash
pnpm -C infra exec sst secret set OauthAllowedCallbackUrls \
  '["https://existing.example.com/callback","https://new.example.com/callback"]' \
  --stage prod
gh workflow run "Infra CI" --ref main
```

The array supports at most 20 unique HTTPS URLs and its serialized JSON must
not exceed 1 KiB. Each URL must be an exact match and cannot contain credentials
or a fragment; host and path wildcards are intentionally unsupported. Use `[]`
to remove all hosted callbacks. The façade validates the same list during
dynamic registration, authorization, callback, and token exchange. The hosted
client may run in any region; callback authorization is based on the exact URL,
not regional co-location with the façade.

Do not add hosted-client URLs to the Cognito reader app client's callback list.
Cognito always redirects to the façade's own `/oauth/callback`; the façade
sends Cognito only a compact HMAC-signed nonce. The original client URL and
opaque client state stay in a nonce-bound, HMAC-signed cookie with
`Secure`, `HttpOnly`, `SameSite=Lax`, a 10-minute lifetime, and
`Path=/oauth/callback`; the callback clears it after use. This supports hosted
clients whose state is too large for Cognito's state parameter without adding
server-side session storage. The complete cookie is limited to 4 KiB. One fixed
cookie slot prevents pending authorization attempts from accumulating beyond
API Gateway's
[10,240-byte request-line and header quota](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-quotas.html);
starting a new authorization in the same browser replaces an older unfinished
transaction.

After exact allowlist validation, the façade redirects to the client URL. It
also wraps the Cognito authorization code in a short-lived signature so token
exchange must present the same client redirect URL. The interactive OAuth
client advertises both `mem9-mcp/read` and `mem9-mcp/write`; clients may request
either scope or both. The Gateway accepts tokens carrying at least one of those
scopes, filters tool discovery, and requires `read` for searches and ingest
status or `write` for memory and transcript ingestion.

### Optional production custom domain

The OAuth façade can use a production-only custom hostname. Leave
`MEM9_FACADE_CUSTOM_DOMAIN` unset to keep the generated API Gateway
`execute-api` URL. When configured, SST creates a Regional API Gateway domain
and mapping, requests and DNS-validates an ACM certificate in the application
region, and creates DNS-only validation and API-target CNAME records in an
existing Cloudflare zone. Preview stages never receive these settings.

Before enabling it, update the out-of-band deploy role. Create a
[Cloudflare API token](https://developers.cloudflare.com/dns/manage-dns-records/how-to/api-tokens/)
scoped to the target zone with `Zone:Read` and `DNS:Edit`, then configure the
hostname, token, and zone ID as GitHub repository secrets:

```bash
scripts/deploy-github-role.sh
gh secret set MEM9_FACADE_CUSTOM_DOMAIN --body "memory.example.com"
gh secret set CLOUDFLARE_API_TOKEN
gh secret set CLOUDFLARE_ZONE_ID
```

Use a hostname only, without `https://`, a port, or a path. The secret prevents
the repository and workflow definition from carrying the operator's domain,
but the hostname is inherently public in DNS and appears in the deployed AWS
resources. One hostname maps to the production stage; use no production
hostname for PR previews. Keep Cloudflare proxying disabled for these managed
records.

No certificate-renewal issue is required. ACM automatically renews a
DNS-validated certificate while it remains attached to API Gateway and every
ACM validation CNAME remains publicly resolvable. Do not manually remove that
CNAME while the custom domain is in use; ACM reports renewal failures through
AWS Health and EventBridge. See
[ACM DNS renewal](https://docs.aws.amazon.com/acm/latest/userguide/dns-renewal-validation.html).

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
classifies the four currently required Lambda execution-role types plus the
pre-authorized namespace identity-interceptor role, and repairs only the exact
legacy trust containing
Lambda plus the current-account root. It validates the complete inventory before
any trust write, then re-reads immediately before each update and reads back the
exact Lambda-only result. Any unknown principal, extra field, or later trust
drift fails closed; frozen-state checks never repair. The interceptor remains
optional until the namespace feature has created it, but is accepted only with
its exact reviewed function/role binding when present.
The command then checks all production service deployments, RUNNING/PENDING
tasks, and the bootstrap task definition before the first boundary mutation.
Every task definition
must carry `MEM9_DB_SECRET` and `MEM9_TENANT_ID` references to current-account,
application-region
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
then custom-simulate 18 KMS boundary cases. The allowed paths are project Lambda
contexts for the four required role types plus the pre-authorized namespace
identity-interceptor role, an SSM-mediated project
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
trusted repository writers. They cannot stop a writer from editing the workflow
itself, and GitHub state plus IAM state cannot be validated and changed in one
atomic transaction. This public repository also accepts fork pull requests.
GitHub withholds repository secrets and reduces write permissions on
fork-triggered `pull_request` runs; because `id-token` supports only `write` or
`none`, those runs cannot request an OIDC token. The missing
`secrets.AWS_ROLE_ARN` also makes the checked-in AWS steps skip, but the role ARN
is an identifier, not an authorization boundary. The deploy role still trusts
the repository's `pull_request` subject for same-repository preview runs.
Before any workflow can give untrusted pull-request code `id-token: write` (for
example through `pull_request_target`), identify the subject that workflow
emits and remove every matching subject from the deploy-role trust out of band.
Restore trust only after the guarded migration has verified permanent
enforcement. The final GitHub revalidation narrows the cross-system window; the
trusted-writer rule and prohibition on concurrent repository-settings changes
close it operationally.

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
backlog. The sampler publishes an age only after every authorized namespace
sample succeeds. Compatibility or incomplete migration suppresses the aggregate,
because legacy NULL-namespace jobs could otherwise look like an empty queue;
logs report the bounded `namespace_not_enforced` error. Failed or partial samples
also suppress the aggregate. The sampler still emits stage-only
`SamplerHeartbeat=1` immediately and once per minute, so a heartbeat alone does
not prove that queue-age sampling succeeded. The raw liveness alarm fills each
current missing period with zero
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
export AWS_REGION="$(node scripts/resolve-application-region.mjs)"
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
3. Deploy the fence, verify the normal M2M client and normal interactive
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
a separate reviewed change after recovery is stable. Restore the normal M2M
client ID and reader client ID to the Gateway allowlist, remove the
temporary recovery client, and resume paused jobs only after the cutover or
rollback probe passes.

### 6. Verify and roll back

Keep normal clients behind the write fence and run the existing hard-fail
synthetic write/search probe after cutover. It writes only a generated marker
and does not inspect existing memory content. The script first waits for ECS
service stability, verifies every running task uses the active task definition,
verifies that task definition targets the restored cluster, then proves that
read-only and write-only tokens see only their tools and cannot cross scopes.

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

## Namespace-scoped memory maintenance

Cleanup, restore, consolidation, and analysis use fixed service identities and
one explicit lowercase namespace UUID per invocation. A namespace ID alone is
not authorization: the namespace, service principal, and service membership must
all be active. Foreign memory IDs are treated as absent. There is no implicit
all-namespace mode or service JIT enrollment.

The fixed capabilities are `cleanup`, `consolidation`, and `analysis`, with
issuers `maintenance:cleanup`, `maintenance:consolidation`, and
`maintenance:analysis`. Each has its own signing keyring, separate from the
Gateway and other services. Tasks receive only their own service credential.
Service REST envelopes bind the namespace, method, URI, and body; direct SQL
authenticates through the trusted database connection and checks the fixed
service membership in the same transaction as the operation.

Service credentials approve only these canonical private REST paths:

| Method | Path | Operation |
| --- | --- | --- |
| `GET` | `/v1alpha2/mem9s/memories` | List/search memories |
| `GET` | `/v1alpha2/mem9s/memories/{memory-id}` | Read an existing memory |
| `PUT` | `/v1alpha2/mem9s/memories/{memory-id}` | Update an existing memory |
| `DELETE` | `/v1alpha2/mem9s/memories/{memory-id}` | Soft-delete a memory |
| `POST` | `/v1alpha2/mem9s/memories/batch-delete` | Soft-delete selected memories |

Membership roles still apply: a viewer cannot write. All other service routes
and methods are denied, including `POST /v1alpha2/mem9s/memories` for creation
or transcript ingestion, ingest-job endpoints, and session APIs. Memory routes
cannot fall back to reading or mutating raw session records. This restriction
does not change the human/M2M ingestion contract.

### Grant a service access to one namespace

Create an owner-only, gitignored `service-binding.local.json`:

```json
{"namespace_id":"<namespace-uuid>","service":"cleanup"}
```

Use the existing private operator task for `prod` or `dev`:

```bash
chmod 600 service-binding.local.json
STAGE=prod scripts/run-memory-namespace-task.sh service-enable \
  --config service-binding.local.json
STAGE=prod scripts/run-memory-namespace-task.sh service-show \
  --config service-binding.local.json
```

Use `service-disable` with the same file to revoke that membership. Set `service`
to `consolidation` or `analysis` to administer those capabilities separately.
Cleanup and consolidation receive member access; analysis receives viewer
access. A disabled namespace or principal cannot be enabled through a membership
grant. The configuration cannot choose a principal ID or another issuer.

The internal queue sampler is not a public service-management choice and has no
REST signing key. Startup and namespace reconciliation initialize only missing
sampler viewer memberships; existing revocations and disabled principals remain
intact.

### Start with a report-only task

After deploying the task definitions and granting the corresponding service:

```bash
STAGE=prod MEM9_NAMESPACE_ID="<namespace-uuid>" \
  scripts/run-cleanup-task.sh
STAGE=prod MEM9_NAMESPACE_ID="<namespace-uuid>" \
  scripts/run-consolidation-task.sh
```

Both launchers run the deployed report-only command and verify a bounded summary
from that exact task. They do not enable a schedule or apply mutations.
Consolidation also checks the configured model route. Their default observation
budget is twelve hours; use `CLEANUP_TASK_WAIT_SECONDS` or
`CONSOLIDATION_TASK_WAIT_SECONDS` to shorten it. A timeout ends observation,
leaving the task running; inspect it before launching another report.

Consolidation reports and scheduled runs share a parent-process watchdog.
`MEM9_CONSOLIDATION_TIMEOUT_SECONDS` sets each namespace's execution budget:
7,200 seconds (two hours) by default, with a validated 60..21,600 second range.
Set the repository variable of that name and redeploy to change the task's
configuration. The report launcher uses `dispatcher --single --report-only
--check-llm`; single mode ignores scheduled targets and clears inherited apply
and scheduled flags. The observer budget and execution budget are independent:
choose enough observation time for task startup, execution, and log delivery.

Task logs include `consolidation_phase` records with allowlisted phase names,
counts, total elapsed time, and phase elapsed time. Classification updates are
rate-limited. A separate `maintenance_heartbeat` appears every minute while a
child runs, including during CPU-bound work; `sinceProgressMs` shows time since
the last phase update. Heartbeats do not prove useful progress, renew execution
deadlines, or count as report success. `maintenance_timeout` triggers TERM and
then KILL after five seconds if necessary. The dispatcher waits for the child
and its pipes to close before advancing. A sequential namespace list may take
the sum of its per-namespace budgets; this is not an overlap-prevention guarantee.

Each failed cluster classification emits `consolidation_classification_failed`
with a bounded `errorClass` and `count` (memories in that cluster). Both child
and dispatcher logs preserve only known review `kind`, digest `status`, and
error-class values; unknown values and private extra fields are dropped.
Error messages, stacks, and model responses are never forwarded. These events
add diagnostics without changing review routing, retries, or run success rules.

The model instructions assign each supplied memory ID to at most one action,
including `KEEP`, and permit unchanged memories to be omitted. Runtime validation
still isolates every overlapping action and rejects unknown IDs; prompt guidance
does not replace these checks.

Console and task-log output contains bounded kinds and counters, without memory
IDs, namespace/principal IDs, snippets, or model rationale. Content-bearing
decisions, ID selections, and detailed operator reports belong only in mode-600
private files, under mode-700 directories. Never attach them to issues or PRs.
Cleanup writes its private files under
`~/.mem9-cleanup/<stage>/<namespace-id>/`. Task-local files are ephemeral; use
the direct operator CLI with a persistent private output directory when keeping
decisions for review and later apply.

### Maintenance preview acceptance

Use `scripts/run-maintenance-namespace-e2e.mjs` from a clean checkout of the
reviewed deployed commit against its own `pr-N` preview. Reuse the mode-600
`deployment.local.json` from [human OAuth acceptance](#operator-run-human-oauth-acceptance),
including its pinned resources and `preview-alpha`/`preview-beta` bindings.
The operator host needs existing private database and REST access; the runner
does not open network access or accept production targets. Cleanup and
consolidation must already have their preview memberships and deployed credentials.

```bash
node scripts/run-maintenance-namespace-e2e.mjs \
  --deployment-file deployment.local.json \
  --fixtures-file maintenance-fixtures.local.json \
  --evidence-file maintenance-acceptance.json
```

The nine scenarios cover own-memory GET/PUT, foreign HTTP absence, wrong service
key, wrong issuer, wrong principal, namespace tampering, isolated membership
revocation, unchanged foreign SQL records, and verified owned-fixture cleanup.
This acceptance runner seeds synthetic memories through authorized SQL and
tests mutations; the ECS cleanup/consolidation launchers above remain report-only.

Cleanup removes only the journal's fixture IDs with its run marker in the pinned
namespaces. It restores the temporarily revoked membership only when the current
row still matches the journal-owned change, refusing concurrent external edits.
The private fixture journal remains available after success or failure; detailed
failures are saved beside it. Evidence contains only the commit, case names, and
completion flags. All nine cases, `success`, and `cleanup_complete` are required
for acceptance.

For interrupted cleanup, retain the journal and use a new evidence path:

```bash
node scripts/run-maintenance-namespace-e2e.mjs \
  --deployment-file deployment.local.json \
  --fixtures-file maintenance-fixtures.local.json \
  --evidence-file maintenance-cleanup.json --cleanup-only
```

Recovery rechecks the pinned target and journal ownership without requiring a
healthy app deployment or service credentials. Cleanup-only evidence records
recovery and never turns a failed acceptance run into success. Use new fixture
and evidence paths for each acceptance run; recovery reuses the journal and
writes a new evidence file.

## Memory cleanup

`scripts/memory-cleanup.mjs` audits active memories in one namespace against the
D1–D4 durability rules used by smart ingest. It defaults to dry-run. Direct CLI
use requires private network access, the deployed cleanup service keyring in
`MEM9_SERVICE_TRANSPORT_SIGNING_KEYS`, stage/namespace configuration, and the
database, tenant, and model access appropriate to the selected mode. Keep those
values in an owner-only `maintenance.local.env` or inherited environment; never
put credential values in arguments. The deployed task supplies its configuration
by reference.

1. **Audit and review** in the selected namespace:

   ```bash
   node --env-file maintenance.local.env scripts/memory-cleanup.mjs \
     --stage prod --namespace-id "<namespace-uuid>"
   ```

   Use `--model` and `--effort` to select the classifier. Keep the application
   region and the independently configured Responses route region distinct.
   Validate model changes with synthetic classification fixtures; truncated
   responses fail their batch. Review the private decision file, including its
   stage/namespace binding, protection decisions, and `UNCLASSIFIED` count.
   Partial classifier failure can still exit zero; unclassified memories have
   not passed the audit and must be retried before calling it complete.

2. **Select decisions** in a private file when applying only a subset. Prefer
   the bound JSON form:

   ```json
   {"stage":"prod","namespaceId":"<namespace-uuid>","ids":["<memory-id>"]}
   ```

   Decision and JSON selection files for another stage or namespace are
   rejected. Plain one-ID-per-line selections remain supported, but every read
   and mutation still uses the invocation's authorized namespace.

3. **Apply the reviewed decisions**:

   ```bash
   node --env-file maintenance.local.env scripts/memory-cleanup.mjs \
     --stage prod --namespace-id "<namespace-uuid>" --apply \
     --decisions "<private-decision-file>" --ids approved.local.json --cap 50
   ```

   Apply re-reads records, checks content/version anchors, and uses soft
   deletion. DELETE and merge writes share a per-run mutation cap, default 50.
   The PostgreSQL apply mutex includes both stage and namespace and is shared
   with restore and consolidation; different namespaces do not share that
   mutex. A namespace-specific local lockfile is an additional safeguard.

Exit codes are `0` success, `1` unexpected failure, `2` discovery failure,
`3` lock held, `4` mutation cap reached, and `5` every classification batch
failed. A failure after partial application does not imply rollback of earlier
completed mutations. Inspect the private report and scoped records before retry.

Audit uses the private mem9 REST endpoint, Aurora, and the configured model
route. The recovery modes below use Aurora directly and do not require REST,
tenant-key discovery, or model calls. Both paths still require the configured
cleanup identity and active membership. Preserve the application's database TLS
verification and its specific region when using an operator host.

### Recovering a soft-deleted or archived memory

Inactive rows are read directly from the database because normal REST reads
return only active memories. Listing is read-only and does not acquire the
apply mutex; restore is also dry-run unless `--apply` is supplied:

```bash
node --env-file maintenance.local.env scripts/memory-cleanup.mjs \
  --stage prod --namespace-id "<namespace-uuid>" --list-inactive \
  --state deleted --limit 100

node --env-file maintenance.local.env scripts/memory-cleanup.mjs \
  --stage prod --namespace-id "<namespace-uuid>" --restore --ids recover.local.json

node --env-file maintenance.local.env scripts/memory-cleanup.mjs \
  --stage prod --namespace-id "<namespace-uuid>" --restore --ids recover.local.json \
  --apply --cap 50
```

Use the same stage/namespace-bound JSON selection format shown above. Unknown
and foreign IDs are absent. A stored successor outside the namespace is redacted;
it cannot disclose a foreign winner's ID or bypass the contradiction safeguard.

`deleted` and `archived` have different meanings. Soft deletion reverses a
cleanup decision; an archived row lost a contradiction to another memory.
Restoring it can return both sides of that contradiction to search. An archived
row, or a deleted row retaining a successor link, therefore requires an explicit
`--force`. Review that decision in the private report. Restore preserves
`superseded_by`, the memory version, and the stored embedding, so it does not
re-embed or erase the contradiction's audit link.

`--since` filters `updated_at`, not insertion time; there is no dedicated
deletion timestamp. Restore advances `updated_at` through the database trigger,
records the authenticated restoring principal, and saves the prior timestamp in
the private namespace-bound restore report. Each write fences namespace, ID,
prior state, and version, skipping a record changed since review.

Restore also uses exit `6` when some requested IDs were absent, refused, or
fenced out. An already-active local record is an idempotent no-op. Failure to
persist the restore report exits nonzero even if writes completed; IDs are not
printed to console as a fallback. `--state`, `--since`, and `--limit` apply only
to listing, while `--apply` is rejected for a listing.

## Weekly memory consolidation

Consolidation compares active memories within one namespace. The deployed task
defaults to report-only. Apply can merge fragments, archive a strictly older
contradiction loser, or mark an eligible fact stale, capped at 20 mutations per
run. Archive checks both loser and winner in the same namespace; all mutations
recheck service authorization and record the acting principal. Consolidation
does not execute DELETE actions. Any approved deletion is reviewed and applied
through cleanup using private namespace-bound files.

Direct operator use of `scripts/memory-consolidation.mjs` accepts `--stage`,
`--namespace-id`, `--report-only`, and explicit `--apply`, with the consolidation
service's own environment and credentials. The report-only launcher above
remains the first verification step. Normal console output is content-free;
there is no Slack digest or approval delivery.

### Scheduling and digest state

Scheduling is off by default. Grant consolidation access and run a report for
each intended namespace first. Store the complete target list as the
stage-scoped SST secret `MaintenanceNamespaceIds`: a JSON array of at most 32
unique lowercase namespace UUIDs, nonempty when scheduling is enabled. This is
an SST secret, not a GitHub Actions secret or repository variable.

For file-based loading, put only the target-list entry in the owner-only,
gitignored `maintenance-secrets.local.env`:

```dotenv
MaintenanceNamespaceIds='["<namespace-uuid>"]'
```

```bash
chmod 600 maintenance-secrets.local.env
pnpm -C infra exec sst secret load --stage prod ../maintenance-secrets.local.env
```

Updating the value replaces the entire list. Preserve existing intended targets
and redeploy the same stage. Before the first Scheduler deployment, complete
the deploy-role and decision-bucket bootstrap prerequisites described above.
Then opt in with the **new repository variable**:

```bash
gh variable set MEM9_NAMESPACE_CONSOLIDATION_SCHEDULE_ENABLED --body 1
gh workflow run "Infra CI" --ref main
```

Infra CI maps this variable to the internal
`MEM9_CONSOLIDATION_SCHEDULE_ENABLED` deployment environment value. Setting only
the old repository variable does not activate the schedule. Production runs
Sunday at 03:00 UTC; enabling this schedule enables scoped apply, not another
report-only run. The dispatcher starts one isolated child per configured
namespace and reports partial failure while continuing independent targets.

Scheduled apply maintains a private, memory-content-free snapshot at
`consolidation-digests/<stage>/<namespace-id>/current-v1.json`. Its serialized
stage/namespace binding, hashes, kinds, counts, and timestamps are checked on
read, and updates use conditional writes. It contains no memory IDs or content.
Before any model call or memory apply, a scheduled run authorizes namespace
writes and attempts to create an empty versioned baseline with `If-None-Match:
*`. Only HTTP 412 is accepted as an existing snapshot; the task then reads and
validates the snapshot normally. This initializes new or expired state without
bucket listing permission. The baseline has no topics or kind counts and an
unchanged-run count of zero; it records no completed consolidation run.
Read, write, authorization, and validation failures abort startup. Existing
snapshots are never replaced by initialization, and final updates retain ETag
fencing. Initialization does not lock the whole run or roll back later failures.
Manual/report-only runs do not update scheduled digest state. Health failures
remain visible in bounded output; Slack delivery stays disabled.

After namespace cutover, numeric `pr-N` previews receive digest GetObject and
PutObject access only under their own stage prefix, plus the matching
S3-mediated KMS permission. This permits an explicitly invoked synthetic
bootstrap probe without ListBucket, production-role reuse, or a schedule.
Task defaults remain report-only; normal preview reports do not initialize
metadata. The probe must use an owned preview namespace, preserve a private
journal of its exact object key, and remove only its fixture after verification.

If a snapshot is invalid, the task preserves it. Pause scheduling, ensure no
run for that namespace is active, and inspect the private object before an
operator removes or restores that exact stage/namespace key. Never reset a
different namespace's snapshot or use a stage-wide deletion. Set the new
repository variable to `0` and redeploy to remove the schedule.

## Slack approval and cleanup scans

Slack digests, deletion approval, scheduled cleanup scans, and their replay
artifacts are not enabled by this maintenance release. Their enablement flags
or inputs fail configuration validation; they do not turn the ordinary cleanup
task into an approval or scan task. Do not use the old Slack or scan rollout
commands. Those capabilities require a separately reviewed namespace and
destination contract; retained design/test files describe that deferred work.

## External OIDC authentication

By default, a stage creates its own Cognito pool and separate human/M2M
clients. Set `MEM9_AUTH_MODE=oidc` to use an existing provider instead. External
mode does not create or manage that provider's pool, users, groups, clients or
scopes. The provider must support Authorization Code with S256 PKCE and signed
JWT access tokens carrying `mem9-mcp/read` and/or `mem9-mcp/write`. Opaque access
tokens are not supported. Cognito's public-client flow is supported even though
its discovery document omits some PKCE/public-client capabilities.

The production job reads the following GitHub Actions Secrets. Unset settings
preserve managed authentication. Preview jobs do not receive these settings and
continue to create isolated managed pools and namespace fixtures.

| Secret | Value / behavior |
| --- | --- |
| `MEM9_AUTH_MODE` | `managed` (default) or `oidc` |
| `MEM9_OIDC_ISSUER` | Exact HTTPS issuer, preserving any trailing slash |
| `MEM9_OIDC_CLIENT_ID` | Dedicated browser/facade client |
| `MEM9_OIDC_CLIENT_SECRET` | Optional; omit for a public client |
| `MEM9_OIDC_TOKEN_AUTH_METHOD` | `none`, `client_secret_basic`, or `client_secret_post`; defaults according to secret presence |
| `MEM9_OIDC_M2M_CLIENT_ID` | Dedicated machine client; paired with its secret |
| `MEM9_OIDC_M2M_CLIENT_SECRET` | Machine secret; required for production M2M smoke tests |
| `MEM9_OIDC_AUDIENCE` | Optional API audience, distinct from client IDs |
| `MEM9_OIDC_CLIENT_ID_CLAIM` | Defaults to `client_id`; another claim such as `cid` requires an API audience |
| `MEM9_AUTH_REQUIRED_GROUP` | Optional exact human group; unset adds no group restriction |
| `MEM9_AUTH_GROUP_CLAIM` | Defaults to `cognito:groups` in managed mode and `groups` in external mode; select `cognito:groups` for an external Cognito pool |
| `MEM9_RETAIN_MANAGED_AUTH` | Set to `1` when switching an existing managed stage, keeping its old pool and clients under SST ownership for recovery |

Client secrets enter SST through `SST_SECRET_OidcClientSecret` and
`SST_SECRET_OidcM2mClientSecret`, become secret Outputs, and are stored in
stage-scoped SSM SecureString parameters. For local commands use those SST
environment names in a machine-local, gitignored file. Never paste secret
values into command arguments or output them. Provider-specific credential paths bind each Lambda version to its issuer,
client and token endpoint. Old paths are retained across provider changes so
a cold start cannot send a new provider secret to an old endpoint; remove
retained paths only after the recovery window. For a public upstream client the
facade neither requires nor forwards a client secret, including any retained
legacy secret. The public MCP registration remains secretless in either mode.

Discovery is checked before resource registration, including an exact issuer
match and HTTPS endpoints. Gateway validates the signature, issuer, client or
audience, expiry and resource scopes. The identity interceptor independently
verifies the token signature using the configured issuer and trusted JWKS URI,
then classifies the registered human/machine client, checks the configured human
group on every MCP method, and retains the signed namespace context. Missing
groups do not confer machine access. A non-Cognito JWT without `token_use`
requires a distinct configured API audience; an explicit ID token is rejected.
The provider's own token lifetime bounds stale group claims. Group validation
protects direct Gateway calls as well as calls through the facade.

The interceptor accepts only the explicit asymmetric algorithm set and requires
a finite, unexpired `exp`. The JWT `scope` claim must be a space-separated string;
array-valued scopes are rejected. JWKS requests have a 2.5-second deadline, a 64 KiB
response ceiling, and no redirects or bearer headers. Keys are cached for up to
five minutes, with bounded refresh for unknown key IDs. Token-supplied key URLs
are ignored. Invalid tokens cannot cause the interceptor to mint signed identity
contexts, including through a direct Lambda invocation. This application check
does not establish IAM-exclusive invocation; managed deployment/workload-role
isolation remains a separate control.

Register exactly `<facade-origin>/oauth/callback` at the external provider,
with the existing facade HTTPS origin. The application's region and provider's
region can differ. Hosted MCP client callbacks remain in the existing
`OauthAllowedCallbackUrls` allowlist, not the provider's client registration.
Only the provider owns login branding, membership and refresh-token policy.

### Existing-stage cutover

This change preserves the tenant ID, memories, embeddings, sessions and ingest
jobs. Admitted human group members and the registered dedicated M2M client
share the existing data, subject to scopes and any already-enabled namespace
authorization. This release does not introduce personal ownership mapping,
copy data, or turn off namespace enforcement.

1. Verify the external client, callback and read/write scopes, along with an
   allowed and a denied human account and the dedicated M2M client. Confirm a
   restorable backup and record content-free pre-cutover data counts.
2. Check the stage's `MEM9_NAMESPACE_REQUIRED` setting. Compatibility mode
   preserves shared access. An already-enforced namespace deployment needs
   explicit bindings for the new issuer, group, human principals and M2M
   identity before switching; old issuer hashes will not match. Do not change
   the namespace gate to bypass authorization. External group lifecycle is
   administered at the provider; the bootstrap task does not receive an external
   user-pool ID for group-management commands. Namespace phase checks and
   database migration remain available; namespace reconciliation writes database
   bindings without managing external groups. Access commands use an
   issuer-bound `--identity-file` for Aurora membership administration as
   described in the namespace cutover runbook. Provision the namespace operator
   role with `MEM9_AUTH_MODE=oidc` to omit Cognito grants while preserving its
   existing stage/region ownership checks.
3. Configure production secrets, including `MEM9_RETAIN_MANAGED_AUTH=1` for an
   existing pool, and review the SST diff. Reject deletion/replacement of the
   existing tenant, database or retained authentication resources. Coordinate
   a short authentication maintenance window while facade and Gateway update.
4. Deploy the same stage. The external-mode smoke checks the active provider
   contract without using Cognito administration APIs in the application region.
   MCP E2E obtains external machine tokens from the active SSM configuration and
   verifies read/write restrictions. Complete a real browser code/refresh flow,
   allowed/denied group checks and direct-Gateway denial checks before reopening.
5. Reauthenticate MCP clients; their registered client ID and provider change.
   In-flight state/code wrappers are invalidated by provider/client binding.
   Verify both admitted users recall the same pre-existing data, the machine
   can access it, and old-provider tokens fail at the new Gateway.

Rollback restores a reviewed complete auth configuration using the retained
pool, including its client registry, group policy and any namespace bindings.
It never disables group/namespace authorization or restores old data over new
writes. Keep the old pool until the recovery window closes; its removal is a
separate change. Empty or inconsistent external settings fail closed, and
switching secrets alone does not update deployed resources.

## License

This repository is licensed under the
[Apache License 2.0](LICENSE), matching the upstream `mem9-ai/mem9` project.
