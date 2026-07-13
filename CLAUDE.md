# mem9-on-aws

Self-hosted deployment of **mem9** (`mnemo-server`, the open-source agent-memory
server by `mem9-ai/mem9`, Apache-2.0) on AWS — a single-operator, multi-device,
multi-agent shared memory layer with **full data ownership** (no third-party SaaS).

> Status: **architecture / design phase**. No IaC implemented yet.

## Read first (ground-truth — do not re-derive)

Before designing, changing infra, or answering mem9/AWS questions in this repo,
read these two files. They hold facts that are expensive to re-derive (probed
from mem9 source + verified against AWS docs) and the rationale for every locked
decision. Treat them as authoritative; if code/AWS contradicts them, update the
file rather than silently diverging.

- **[`docs/mem9-facts.md`](docs/mem9-facts.md)** — the non-obvious constraints
  that shaped this whole design, e.g.:
  - Aurora **MySQL cannot run mem9** (mem9's MySQL/tidb path needs TiDB-only
    `VECTOR`/`VEC_COSINE`/`EMBED_TEXT`) → we use the **postgres backend + pgvector**.
  - **Bedrock Mantle has no `/embeddings`** (Chat Completions / Responses only) →
    embedding can't go through Mantle; we self-host qwen3.
  - mem9 reads `MNEMO_LLM_API_KEY` **once at startup (immutable)** and sends no
    custom headers → the Mantle bearer (12h TTL, refreshable) + `OpenAI-Project`
    cost header are bridged by a **local LLM proxy sidecar** (`docker/llm-proxy/`),
    NOT a token file-writer.
  - mem9 schema **`idx_app` gap**: control-plane `schema_pg.sql` ≠ the tenant
    runtime schema the server validates → bootstrap must apply the runtime schema.
  - AgentCore Gateway reaches a private VPC target via **managed VPC Lattice +
    `privateEndpoint`** (no public exposure); ALB needs a **public** ACM cert for
    Lattice TLS trust; SigV4 outbound is NOT compatible with ALB → use API key.
- **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)** — full selection + the
  authoritative **Locked decisions** and **Open decisions** lists (this file's
  table is a summary; ARCHITECTURE.md wins if they ever disagree).

## What this is / is NOT

- **IS**: an SST v4 app that runs `mnemo-server` (upstream mem9, unmodified where
  possible) on ECS Fargate against Aurora PostgreSQL, fronted by an AgentCore
  Gateway MCP surface with Cognito auth. Data lives 100% in the operator's AWS
  account and is exportable at any time.
- **IS NOT**: a fork of mem9's application code. We vendor/pin the upstream
  container and drive it entirely through env vars + a bootstrapped Postgres
  schema. Any source change to mem9 is a last resort and must be recorded in
  `docs/mem9-facts.md` with the upstream commit it forks from.

## Locked decisions (see ARCHITECTURE.md for rationale)

| Dimension | Decision |
|---|---|
| IaC | **SST v4**, mirroring `zxkane/podcast-curation` + `zxkane/llm-wiki` structure |
| Region | **ap-northeast-1 (Tokyo)** |
| Compute | **ECS Fargate**, **arm64**, single task (`desiredCount=1`) |
| Database | **Aurora PostgreSQL Serverless v2** + `pgvector` (mem9 `postgres` backend) |
| VPC | **Reuse the account default VPC** (private subnets w/ NAT), per podcast-curation pattern |
| MCP surface | **AgentCore Gateway** (OpenAPI target → mnemo-server REST API) |
| Gateway → server | **private** (IMPLEMENTED): `privateEndpoint` (managed VPC Lattice, `routingDomain`=ALB DNS) → **internal ALB** (public ACM cert `mem9.aws.kane.mx` — an existing R53 public zone; name-only for Lattice TLS SNI) → HTTP:8080. Outbound auth = API key (`X-API-Key`=tenant id, `AgentcoreApiKeyCredentialProvider`). No public exposure |
| Auth (inbound) | **Cognito M2M**, reusing the podcast-curation / llm-wiki gateway pattern |
| LLM (smart-ingest) | **Bedrock Mantle direct**, **GLM-5**, **ON at launch**. Auth via **`@aws/bedrock-token-generator`** (short-term bearer from task IAM role, same as llm-wiki) + **Bedrock Project** cost attribution + a **local LLM proxy sidecar** (`docker/llm-proxy/` — mem9 reads `MNEMO_LLM_API_KEY` once & sends no custom headers, so a request-proxy holds the live bearer + injects `OpenAI-Project`; NOT a token file-writer). GPT-5.4/5.5 excluded (Responses-only) |
| Embedding | qwen3 OpenAI `/embeddings` as an **ECS sidecar** (localhost, always warm), **code lifted from llm-wiki qwen3 ONNX**, **dims 1024**. NOT Mantle, NOT 3P API |
| ECS task | **3 containers**: mnemo-server + qwen3-embed sidecar + llm-proxy sidecar (Mantle GLM-5). TLS at the ALB, not in task |
| Schema bootstrap | **one-shot ECS task** on deploy (pgvector + tenant runtime schema incl. `idx_app`/FTS/`vector(1024)` + seed 1 tenant) |
| Tenancy | **single tenant** (one `X-API-Key`); writes carry **`X-Mnemo-Agent-Id`** to reserve per-agent scoping |
| Replicas | **Single** (`desiredCount=1`) — single-writer, sidesteps mem9's local-disk import dir |

## Reference projects (read these before writing IaC)

- `zxkane/podcast-curation` — the closest template. Copy from `infra/`:
  `ecs.ts` (Fargate + default-VPC lookup + arm64 task), `gateway.ts`
  (AgentCore Gateway REST target + interceptor), `cognito.ts` (M2M pool),
  `api.ts` (JWT authorizer). ECR repo owned out-of-band via a CloudFormation
  template + `scripts/deploy-*.sh`, referenced read-only by every SST stage.
- `zxkane/llm-wiki` — `sst.config.ts` shape (Tokyo region, Node 24 `$transform`,
  `docker-build`/`command` providers), and the **qwen3 embedding** supply
  (`infra/wiki-query.ts`, `infra/wiki-embed-batch.ts`) that this project reuses
  as its embedding MaaS.

## Hard rules

- **AWS work MUST comply with `~/.claude/CLAUDE-AWS.md`** — verify design AND
  deployed resources against it. Known constraints to honor here: **no Lambda
  Function URL** (use API Gateway / AgentCore Gateway), **Lambda runtime
  nodejs24.x**, least-privilege IAM, no hardcoded account IDs / ARNs in committed
  files (use `<aws-account-id>` placeholders).
- **Node.js 24 LTS** everywhere (`.nvmrc` = 24, `engines.node >=24`, CI + Lambda
  `nodejs24.x`). Go build for mnemo-server targets **arm64** (`CGO_ENABLED=0
  GOARCH=arm64`).
- **This is a PRIVATE repo** (`zxkane/*`, kept private). It MAY reference the
  operator's private sister repos (`zxkane/podcast-curation`, `zxkane/llm-wiki`)
  and their concrete `infra/*.ts` file paths — that's the whole point of the
  reference pointers. **Do NOT flip it public** without first scrubbing those
  private-repo slugs + file paths. Regardless of visibility, **never commit real
  secrets**: no real account IDs, ARNs with account numbers, Cognito pool IDs,
  gateway URLs, API keys, or the operator's real memory content — use
  placeholders (`<aws-account-id>`). Scan before commit:
  `grep -niE '[0-9]{12}|arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}|X-API-Key' <files>`.
- **Self-hosted CI runners**: this is a personal `zxkane/*` repo → use the
  `RUNNER_LABEL` ternary pattern (`runs-on: ${{ vars.RUNNER_LABEL && fromJSON(...) || 'ubuntu-latest' }}`).
- **Data ownership is the whole point**: any design change that sends memory
  content or embeddings to a third party (OpenAI direct, mem9 SaaS) violates the
  project's reason to exist — flag it, don't silently adopt it.

## Open decisions

**Authoritative list lives in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
§"Open decisions"** — keep it there, not here, to avoid drift. All are
engineering detail now (no architecture-level choices remain): OpenAPI schema
mapping, token-refresh sidecar mechanism, mem9 pin + arm64 image build, Aurora
backup/PITR, CI/deploy (RUNNER_LABEL + arm64 build), secrets (DB creds in
Secrets Manager). Everything architectural is in **Locked decisions** above and
in ARCHITECTURE.md.
