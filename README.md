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

| Dimension | Decision |
|---|---|
| IaC | **SST v4** |
| Region | **ap-northeast-1 (Tokyo)** |
| Compute | **ECS Fargate**, **arm64**, single task (`desiredCount=1`) |
| Database | **Aurora PostgreSQL Serverless v2** + `pgvector` (mem9 `postgres` backend). `mnemo-server` and bootstrap connect directly to the cluster writer endpoint with a Secrets Manager credential. **RDS Proxy is not deployed.** |
| VPC | **Reuse the account default VPC** (private subnets with NAT egress) |
| MCP surface | **AgentCore Gateway** (MCP → mnemo-server REST API) |
| Gateway → server | **Private** (a [Lambda-proxy GatewayTarget](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-add-target-api-target-config.html)): AgentCore invokes a VPC-attached proxy Lambda with [`lambda:InvokeFunction`](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-prerequisites-permissions.html). The Lambda uses [VPC connectivity](https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html) and [AWS Cloud Map private DNS](https://docs.aws.amazon.com/cloud-map/latest/api/API_CreatePrivateDnsNamespace.html) (`mnemo.mem9-<stage>.local:8080`) to reach mnemo-server with the `X-API-Key` (= tenant id). No ALB, ACM certificate, VPC Lattice, public Route 53 zone, or public server endpoint is deployed. |
| Auth (inbound) | **Cognito M2M** (`client_credentials`) + an OAuth2 browser-login façade (`authorization_code` + PKCE) for interactive MCP clients |
| LLM (smart-ingest) | `mnemo-server` calls the **local `llm-proxy` sidecar** at `http://localhost:8082/v1`. The proxy refreshes a short-term Mantle bearer, injects `OpenAI-Project` when `MEM9_BEDROCK_PROJECT` is configured, and calls Bedrock Mantle. Each request has one 110-second deadline and at most two Mantle calls. The task role uses `bedrock-mantle:CreateInference` and `bedrock-mantle:CallWithBearerToken`; `mnemo-server` never calls Mantle directly. |
| Embedding | qwen3 OpenAI-compatible `/embeddings` as an **ECS sidecar** (localhost, always warm), **dims 1024**. Not Mantle, not a third-party API. |
| ECS task | **3 containers**: mnemo-server + qwen3-embed sidecar + llm-proxy sidecar |
| Schema bootstrap | **one-shot ECS task** on deploy (pgvector + tenant runtime schema incl. `idx_app`/FTS/`vector(1024)` + seed 1 tenant) |
| Tenancy | **single tenant** (one `X-API-Key`); writes carry **`X-Mnemo-Agent-Id`** to reserve per-agent scoping |
| Replicas | **Single** (`desiredCount=1`) — single-writer, sidesteps mem9's local-disk import dir |

## Planned reliability work

The remaining open reliability program covers deployment reconciliation, alert
failure queues, Aurora retention, preview cleanup, ECR scanning, durable ingest
jobs, atomic apply, telemetry, and post-deployment verification. **None of that
planned work is part of the current implementation.** The exact boundary is
recorded in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#planned-changes).

## MCP tools exposed

The AgentCore Gateway exposes three tools over MCP (Cognito-authenticated):

- `add_memory` — store one raw memory (`content`, optional `agent_id`).
- `search_memories` — semantic search (`q`, optional `limit`/`agent_id`).
- `ingest_messages` — smart-ingest a conversation window (`messages[]`, optional
  `session_id`/`agent_id`/`mode`) for LLM extraction into memories.

## Layout

- `infra/` — the SST/Pulumi app (VPC lookup, Aurora, ECS, Cognito, gateway,
  OAuth façade, bootstrap) + unit tests.
- `docker/` — the four container images: `mnemo-server` (pinned upstream build),
  `qwen3-embed` (embedding sidecar), `llm-proxy` (Mantle bearer/project bridge),
  `bootstrap` (schema + tenant seed).
- `scripts/` — out-of-band bootstrap scripts (GitHub Actions IAM role, four ECR
  repositories, and Bedrock Mantle Project) that the SST app references
  read-only. See each script's header and `.env.example` for the environment it
  expects.
- `docs/` — `ARCHITECTURE.md` (decisions) and `mem9-facts.md` (upstream constraints).

## Development

- **Node.js 24 LTS** everywhere (`.nvmrc` = 24, `engines.node >= 24`, CI +
  Lambda `nodejs24.x`). The Go build for mnemo-server targets **arm64**.
- Copy `.env.example` to `.env` and fill in your AWS profile before running the
  `scripts/deploy-*.sh` bootstrap scripts.
- Agent contributors: see [`AGENTS.md`](AGENTS.md) for repo conventions and hard rules.

## Production alert runbook

Production deployment requires the `SLACK_WEBHOOK_URL` GitHub secret. SST
synthesis fails when it is absent so production alarms cannot be deployed
without an IaC-managed sink. Preview and development stages do not create the
alerting stack.

All production alarms target one SNS topic. Delivery failures are separated by
the AWS boundary at which they occurred:

| Alarm | Queue meaning | Queue body |
|---|---|---|
| `AlertTransportFailureQueueVisibleMessages` | SNS exhausted attempts to invoke the alert Lambda | Original SNS notification envelope with `Type`, `MessageId`, `TopicArn`, and `Message` |
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

## License

The mem9 server (`mnemo-server`) is Apache-2.0 (upstream `mem9-ai/mem9`). See that
project for its license; this repo's own IaC/config is provided as-is.
