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
`add_memory`, `search_memories`, and `ingest_messages` to the mem9 REST API and
injects the tenant `X-API-Key`.

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

Memory rows and embeddings are durable in Aurora. The Fargate task uses `/tmp`
only for mem9's batch-import implementation; normal add, search, and CRUD paths
do not require persistent task storage.

### Component map

| Layer | Current resource or component | Source |
|---|---|---|
| Compute | ECS Fargate, arm64, one task, three containers | `infra/ecs.ts` |
| Database | Aurora PostgreSQL Serverless v2, direct writer endpoint; PITR retention prod=14 days, non-prod=1 day | `infra/db.ts` |
| Database credential | Secrets Manager task-definition secret | `infra/db.ts`, `docker/mnemo-server/entrypoint.sh` |
| Embedding | Local qwen3 sidecar, 1024 dimensions | `docker/qwen3-embed/` |
| Smart-ingest LLM | Local proxy to Bedrock Mantle | `docker/llm-proxy/` |
| Mantle attribution | `OpenAI-Project` added by `llm-proxy` when a project is configured | `docker/llm-proxy/server.mjs` |
| MCP surface | AgentCore Gateway Lambda target | `infra/gateway.ts` |
| Private service lookup | AWS Cloud Map | `infra/ecs.ts` |
| Inbound auth | Cognito M2M plus OAuth2 PKCE facade | `infra/cognito.ts`, `infra/oauth-facade.ts` |
| Schema setup | One-shot ECS bootstrap task | `infra/bootstrap.ts` |

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

## Planned changes

The open reliability program covers future work in these areas:

- Release image tag selection and read-only ECS actual-state reconciliation.
- Mandatory alert delivery with separate transport and execution failure queues.
- Safe preview-stage reconciliation and a separately reviewed one-time cleanup.
- Registry-level ECR scan-on-push coverage.
- A disabled-by-default durable ingest job foundation, atomic plan application,
  tenant-scoped job status, and job-level telemetry.
- A post-deployment production reliability verification exercise.

**None of this planned work is part of the current implementation.** Each change
must update this document only after its implementation, tests, and deployment
definition land. The current async smart-ingest path must not be described as a
durable queue or atomic job processor.

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
