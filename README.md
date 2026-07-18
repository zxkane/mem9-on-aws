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

## Read first (ground-truth — do not re-derive)

Two files hold the facts that shaped this design (probed from mem9 source +
verified against AWS docs) and the rationale for every locked decision. Treat
them as authoritative; if code/AWS contradicts them, update the file rather than
silently diverging.

- **[`docs/mem9-facts.md`](docs/mem9-facts.md)** — the non-obvious mem9
  constraints, e.g.:
  - Aurora **MySQL cannot run mem9** (mem9's MySQL/tidb path needs TiDB-only
    `VECTOR`/`VEC_COSINE`/`EMBED_TEXT`) → we use the **postgres backend + pgvector**.
  - **Bedrock Mantle has no `/embeddings`** (Chat Completions / Responses only) →
    embedding can't go through Mantle; we self-host qwen3.
  - mem9 reads `MNEMO_LLM_API_KEY` **once at startup (immutable)** and sends no
    custom headers → the Mantle bearer + `OpenAI-Project` cost header are bridged
    by a **local LLM proxy sidecar** (`docker/llm-proxy/`), not a token file-writer.
  - mem9 schema **`idx_app` gap**: control-plane `schema_pg.sql` ≠ the tenant
    runtime schema the server validates → bootstrap must apply the runtime schema.
  - AgentCore Gateway reaches the private mnemo-server via a **Lambda-proxy target**
    (out-of-the-box private path): a VPC-attached proxy Lambda reaches the server
    over **AWS Cloud Map** DNS with an `X-API-Key`.
- **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)** — the full component
  selection plus the authoritative **Locked decisions** and **Open decisions**
  lists (the table below is a summary; ARCHITECTURE.md wins if they disagree).

## Locked decisions (see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for rationale)

| Dimension | Decision |
|---|---|
| IaC | **SST v4** |
| Region | **ap-northeast-1 (Tokyo)** |
| Compute | **ECS Fargate**, **arm64**, single task (`desiredCount=1`) |
| Database | **Aurora PostgreSQL Serverless v2** + `pgvector` (mem9 `postgres` backend) |
| VPC | **Reuse the account default VPC** (private subnets with NAT egress) |
| MCP surface | **AgentCore Gateway** (MCP → mnemo-server REST API) |
| Gateway → server | **Private** (a **Lambda-proxy GatewayTarget**): AgentCore invokes a VPC-attached proxy Lambda (`lambda:InvokeFunction`), which reaches mnemo-server over **AWS Cloud Map** private DNS (`mnemo.mem9-<stage>.local:8080`) with the `X-API-Key` (= tenant id) injected by the Lambda. No ALB, no ACM cert, no VPC Lattice, no Route 53 public zone. No public exposure of the server. |
| Auth (inbound) | **Cognito M2M** (`client_credentials`) + an OAuth2 browser-login façade (`authorization_code` + PKCE) for interactive MCP clients |
| LLM (smart-ingest) | **Bedrock Mantle** direct, **GLM-5**, on at launch. Auth via a short-term bearer from the task IAM role (`@aws/bedrock-token-generator`) + a Bedrock Project for cost attribution + a **local LLM proxy sidecar** (`docker/llm-proxy/`) that holds the live bearer and injects the `OpenAI-Project` header (mem9 reads its LLM key once and sends no custom headers). |
| Embedding | qwen3 OpenAI-compatible `/embeddings` as an **ECS sidecar** (localhost, always warm), **dims 1024**. Not Mantle, not a third-party API. |
| ECS task | **3 containers**: mnemo-server + qwen3-embed sidecar + llm-proxy sidecar |
| Schema bootstrap | **one-shot ECS task** on deploy (pgvector + tenant runtime schema incl. `idx_app`/FTS/`vector(1024)` + seed 1 tenant) |
| Tenancy | **single tenant** (one `X-API-Key`); writes carry **`X-Mnemo-Agent-Id`** to reserve per-agent scoping |
| Replicas | **Single** (`desiredCount=1`) — single-writer, sidesteps mem9's local-disk import dir |

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
- `scripts/` — out-of-band bootstrap scripts (GitHub Actions IAM role, ECR repo,
  Bedrock Mantle Project) that the SST app references read-only. See each script's
  header and `.env.example` for the environment it expects.
- `docs/` — `ARCHITECTURE.md` (decisions) and `mem9-facts.md` (upstream constraints).

## Development

- **Node.js 24 LTS** everywhere (`.nvmrc` = 24, `engines.node >= 24`, CI +
  Lambda `nodejs24.x`). The Go build for mnemo-server targets **arm64**.
- Copy `.env.example` to `.env` and fill in your AWS profile before running the
  `scripts/deploy-*.sh` bootstrap scripts.
- Agent contributors: see [`AGENTS.md`](AGENTS.md) for repo conventions and hard rules.

## License

The mem9 server (`mnemo-server`) is Apache-2.0 (upstream `mem9-ai/mem9`). See that
project for its license; this repo's own IaC/config is provided as-is.
