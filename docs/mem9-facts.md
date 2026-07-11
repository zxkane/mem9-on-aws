# mem9 (`mnemo-server`) — Ground-truth facts

Probed directly from the `mem9-ai/mem9` source (server is Go, under `server/`).
These are the facts the AWS design in [`ARCHITECTURE.md`](ARCHITECTURE.md) relies
on. Re-verify against the pinned upstream commit before implementing IaC.

## Identity & license

- Repo: `mem9-ai/mem9`. Server binary: `mnemo-server` (Go, `server/cmd/mnemo-server`).
- License: **Apache-2.0** (self-host, modify, commercial — all allowed).
- SaaS (`api.mem9.ai`) and self-host run the **same server code**; migration
  between them is a base-URL + DSN change (no lock-in). SaaS billing (for
  reference): per Add/Retrieve request, Free = 13k add + 1.3k retrieval/mo.

## Runtime shape

- HTTP server on `MNEMO_PORT` (default **8080**). Preferred API surface
  `v1alpha2` with `X-API-Key` header; legacy `v1alpha1` puts tenant id in the URL.
- **`X-API-Key` value == tenant `id`** (server does `tenants.GetByID(apiKey)`).
  Provision a tenant via `POST /v1alpha1/mem9s` (no auth) → returns `{"id": ...}`.
  That id is the API key.
- Endpoints: `POST/GET/GET{id}/PUT{id}/DELETE{id} /v1alpha2/mem9s/memories`,
  batch-delete, `/imports`, `/session-messages`, `/status`, webhooks, space-chains.
- Search query param is `q` (`GET /v1alpha2/mem9s/memories?q=...`).
- Writes return `{"status":"accepted"}` and are processed **asynchronously** —
  list/search may return empty for a few seconds/minutes after write until the
  ingest+index pipeline completes. (Observed on both self-host POC and SaaS.)

## Statefulness / filesystem

- **Effectively stateless for add/search/CRUD** — all durable state is in the DB.
- **Local filesystem is used ONLY for batch import**: `MNEMO_UPLOAD_DIR`
  (default `./uploads`), files at `{UploadDir}/{tenantID}/{agentID}/{filename}`,
  50 MB max multipart. An async upload worker reads them back and requeues
  "if file not found locally" → **assumes single-node local disk**. Multi-replica
  breaks import unless the upload dir is shared or moved to S3 (source change).
  → **For single-task deploy, `MNEMO_UPLOAD_DIR=/tmp` is fine; no EFS needed.**
- No other required disk state.

## Database backends

`MNEMO_DB_BACKEND` ∈ `{tidb, postgres, db9}` (default `tidb`). Repos under
`server/internal/repository/{tidb,postgres}`. Multi-tenant "control plane +
per-tenant DB" architecture (a `tenants` row carries db_host/user/pass/name per
tenant); for a single operator you run one active tenant.

### DB connection mechanism (probed — decisive for IAM-auth question)
Verified from `server/internal/config/config.go` + `server/internal/repository/postgres/postgres.go`:
- The **control-plane** connection is a **single static DSN env var `MNEMO_DSN`**
  (required; `os.Getenv("MNEMO_DSN")`). mem9 does **NOT** assemble the DSN from
  separate host/user/pass/dbname/sslmode env vars — there are no such vars.
- `NewDB(dsn)` = `sql.Open("pgx", dsn)` via the **pgx v5 stdlib driver**
  (`_ "github.com/jackc/pgx/v5/stdlib"`), pool sized `SetMaxOpenConns(25)` /
  `SetMaxIdleConns(5)` / `SetConnMaxLifetime(5m)`, `db.Ping()` at startup.
- **Credential is read ONCE at startup and never refreshed** — no `BeforeConnect`
  hook, no credential callback, no password-returning function (the stdlib pgx
  path doesn't expose pgxpool's `BeforeConnect`). Rotating the credential requires
  a process restart.
- **Consequence for IAM DB auth**: an RDS/Aurora **IAM auth token expires in
  ~15 min**, but `MNEMO_DSN` is static → new pool connections after ~15 min would
  fail with auth error. So **native (end-to-end) IAM database auth is NOT viable
  for mem9 unmodified**, whether direct to Aurora OR client-side-IAM through RDS
  Proxy (mem9 is the IAM client either way). **Chosen (LOCKED): RDS Proxy +
  Secrets Manager** (ARCHITECTURE.md §3a). The Aurora password lives ONLY in a
  Secrets Manager secret (a **static `RandomPassword`** created by
  `sst.aws.Aurora` — ⚠️ SST's `proxy:true` does NOT use `manageMasterUserPassword`
  and attaches **no rotation Lambda**, so it is NOT auto-rotated; rotation is
  ARCHITECTURE.md Open #6). RDS Proxy pulls the secret and pools/multiplexes; mem9
  connects to the **proxy endpoint** with a user+password delivered to the
  container via an ECS `secrets: valueFrom` (Secrets Manager → env at task start)
  — never a literal in the task def or git. Not literally passwordless at the
  mem9 hop, but the password is never committed or human-handled. A future
  token-refresh sidecar (like the Mantle one) or a mem9 source patch (pgx
  `BeforeConnect` + AWS auth-token generator) could enable true end-to-end IAM
  later — recorded as an Open decision, not adopted now.
- The per-tenant `tenants` rows ALSO carry db_host/user/pass; `MNEMO_ENCRYPT_TYPE`
  (`plain`|`kms`) + `MNEMO_ENCRYPT_KEY` encrypt those stored tenant DB passwords.
  For a single operator with one tenant pointed at the same Aurora, the tenant
  row's creds and the control-plane DSN target the same cluster.

### postgres backend (the one we use)
- Uses **`github.com/pgvector/pgvector-go`**. Column `embedding vector(N)`.
- **VectorSearch** = pgvector cosine: `... embedding <=> $q AS distance ORDER BY
  embedding <=> $q`. Requires **pre-computed query embedding** (mnemo-server
  calls the embedding MaaS, then queries).
- **FTSSearch** = PostgreSQL `to_tsvector('english', ...)` + `plainto_tsquery` +
  `ts_rank`. (English analyzer — note for CJK content, same class of issue
  a sibling project hit; may need config.)
- **`AutoVectorSearch` is NOT supported on PG** — explicit source fallback:
  "auto vector search not supported with PostgreSQL; use VectorSearch with
  pre-computed embeddings." (Auto-embed via `EMBED_TEXT` is TiDB-only.)
- Default schema (`server/schema_pg.sql`) ships `embedding vector(1536)` and
  `CREATE EXTENSION IF NOT EXISTS vector;`.

### tidb backend (NOT viable on Aurora)
- Uses TiDB `VECTOR(N)` type, `VEC_COSINE_DISTANCE`, and optionally
  `EMBED_TEXT("tidbcloud_free/...", content)` GENERATED column for **server-side
  auto-embedding** (TiDB Cloud Serverless only). Vector index needs TiFlash.
- **None of `VECTOR`/`VEC_COSINE`/`EMBED_TEXT` exist in Aurora MySQL** → mem9's
  MySQL/tidb path cannot run on Aurora MySQL. This is why PG is chosen.

### Schema bootstrap gotcha (observed in POC)
- Control-plane schema file `server/schema_pg.sql` ≠ the **tenant runtime schema**
  in `server/internal/tenant/schema.go`. In the self-host POC, list/search
  returned empty and logs showed `validate schema: memories app_id index:
  memories.idx_app is missing` — the control-plane file did not create the
  `idx_app` index the runtime validator requires. **Bootstrap must apply the
  tenant runtime schema (idx_app, FTS, vector column at the right dims), not just
  the control-plane file.** Verify exact DDL from `tenant/schema.go` at build time.

## Embedding (MaaS)

- OpenAI-compatible only. `server/internal/embed/embedder.go` POSTs to
  `{MNEMO_EMBED_BASE_URL}/embeddings`, `EncodingFormat: "float"`.
- Env: `MNEMO_EMBED_BASE_URL` (default `https://api.openai.com/v1`),
  `MNEMO_EMBED_MODEL` (default `text-embedding-3-small`), `MNEMO_EMBED_API_KEY`
  (`""`/`local` for Ollama-style), `MNEMO_EMBED_DIMS` (default 1536).
- **No native Bedrock.** Bedrock requires an OpenAI→Bedrock proxy exposing
  `/embeddings`. Ollama/LM Studio/TEI/any OpenAI-compatible server works via
  `MNEMO_EMBED_BASE_URL`.
- Design decision: reuse a sibling project's **qwen3** embedding (dims 1024) or a Bedrock
  Cohere/Titan proxy. **Pin model + dims before first ingest** — the vector
  column type and all stored vectors depend on it; changing dims = reindex.

## LLM (smart-ingest / MaaS)

- OpenAI-compatible `/chat/completions`. Env: `MNEMO_LLM_BASE_URL`,
  `MNEMO_LLM_MODEL` (default `gpt-4o-mini`), `MNEMO_LLM_API_KEY`.
- `MNEMO_INGEST_MODE` = `smart` (default, LLM extraction/reconciliation) or
  `raw`. **If no LLM key/base-url, smart falls back to raw** (server logs
  "no LLM configured, ingest will use raw mode"). Raw = store as-is (no extraction).
- Startup also logs "no embedding configured, keyword-only search active" when no
  embedder is set → **without an embedding endpoint, PG backend does keyword-only
  (FTS), NO vector search.** So the embedding MaaS is required for semantic recall.

## Bedrock Mantle facts (for the LLM/embedding decision)

Verified against AWS docs + the operator's a sibling project prod usage:

- **Mantle IS OpenAI-compatible.** Endpoint `https://bedrock-mantle.{region}.api.aws/v1`;
  surfaces = **Chat Completions** + **Responses** (OpenAI-compatible) + **Messages**
  (Anthropic). "Bring OpenAI SDK code by changing only base URL + API key."
- **mem9 speaks `/chat/completions` only** → the smart-ingest LLM must be a
  **Chat-Completions** model on Mantle: **GLM-5** (a sibling project runs GLM-5 on
  Mantle in prod), Claude Sonnet/Fable 5, DeepSeek, Gemma, etc. **GPT-5.4 / 5.5
  are Responses-API only → NOT usable by mem9** without a source change.
- **Mantle has NO `/embeddings`.** All Bedrock embedding models (Titan Text V2,
  Cohere embed-v4, Nova MM) are **`bedrock-runtime` ONLY**, and bedrock-runtime is
  **not** OpenAI-compatible for embeddings (it's InvokeModel). → embedding must be
  our own OpenAI-shaped `/embeddings` service (decided: qwen3, dims 1024).
- **Auth**: Bedrock API key (bearer) works with the OpenAI SDK; SigV4 also works.
  Cost attribution on Mantle = **Bedrock Projects** via the `OpenAI-Project`
  header — **IAM-principal / session-tag attribution does NOT work on Mantle**
  (a sibling project verified prod GLM-5 spend tagged ~$0 via the runtime path).
  Reuse a sibling project `infra/bedrock-mantle.ts` (CloudControl
  `AWS::BedrockMantle::Project`, gated behind a provision env flag) +
  `bedrock-mantle-auth.ts` + `src/shared/llm/providers/bedrock-mantle.ts`.
- Pricing identical to bedrock-runtime per-token. VPC PrivateLink interface
  endpoint avoids NAT egress cost if calling from in-VPC.

## Other integrations

- **S3**: only `server/internal/metering` (usage metering PutObject) — disableable,
  not needed.
- **KMS**: only when `MNEMO_ENCRYPT_TYPE=kms` (encrypts tenant DB passwords);
  default `plain`. Uses AWS SDK default cred chain (`AWS_REGION` etc.).
- **TiDB Cloud API**: `MNEMO_TIDBCLOUD_*` for auto-provisioning tenants on TiDB
  Cloud — irrelevant for the postgres backend (manual-bootstrap tenants).

## Build / architecture

- `server/Dockerfile` as shipped **assumes a pre-built binary** (the golang
  builder stage is commented out) → for a self-contained build, restore a
  multi-stage Dockerfile (golang:<ver>-alpine builder → alpine runtime). go.mod
  requires **Go 1.24**.
- Makefile builds `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`. **Pure Go, no CGO** →
  switch to `GOARCH=arm64` + `docker build --platform=linux/arm64` for Graviton.
  No source change needed.

## Concurrency model

- Server is the single process fronting the DB; concurrency is handled at the DB
  (Aurora PG) transaction level, not in-process file locks (unlike TAM's SQLite).
  With `desiredCount=1` there is one writer process → no cross-process contention.
  Multi-replica writes would rely on Aurora's MVCC (fine for the DB) but hit the
  local-disk import limitation above.

## Verified AWS facts (for the design)

- Aurora **PostgreSQL Serverless v2** available in **ap-northeast-1 (Tokyo)**,
  PG 16 & 17. `pgvector` is a standard extension (`CREATE EXTENSION vector`).
- Amazon S3 Files (2026-04 GA) exists as a writable POSIX/NFS mount but is NOT
  used here (no filesystem state to host; single-task `/tmp` covers import).
- a sibling project's ECS stack consumes the **account default VPC** via
  `aws.ec2.getVpc({ default: true })`, filtered to NAT-routed private subnets —
  the pattern reused here.
- **Tokyo default VPC is customized + NAT-routed (verified 2026-07-11).** The
  account's `ap-northeast-1` default VPC (172.31.0.0/16) is NOT a stock default:
  it has `private-1a/1c/1d` subnets across 3 AZs (172.31.96/112/128.0/20,
  `MapPublicIpOnLaunch=false`), **each routing `0.0.0.0/0` through a NAT gateway**,
  plus `public-1a/1c/1d` via the IGW. The scaffold's `infra/vpc.ts` selects the
  three private subnets by the `private-1*` Name tag (excluding the secondary
  `172.32.x` private subnets added out-of-band). So ECS Fargate + Aurora can live
  in the default VPC with outbound internet (Bedrock Mantle) via NAT — no
  dedicated VPC needed, confirming the ARCHITECTURE.md assumption. Concrete
  resource ids are intentionally NOT recorded here (they'd leak account topology);
  the design's own `docs/superpowers/specs/` note verified them at authoring time.

### AgentCore Gateway private egress to VPC (verified — resolves the #6 unknown)

- AgentCore Gateway **OpenAPI and MCP-server targets support a `privateEndpoint`**
  block that routes to an in-VPC endpoint over **Amazon VPC Lattice**, **without
  public internet exposure**. Shape:
  `privateEndpoint.managedVpcResource = { vpcIdentifier, subnetIds[],
  endpointIpAddressType, securityGroupIds[] }`.
- **Two Lattice modes**: **managed** (AgentCore creates/manages the Lattice
  resource gateway + resource config; needs only EC2 perms + a service-linked
  role, no VPC Lattice IAM/SCP/approval) vs **self-managed** (cross-account /
  governance). → use **managed**.
- **TLS**: Lattice targets are HTTPS. For a plain-HTTP backend (mnemo-server:8080),
  the documented workaround is an **internal ALB with a public ACM cert** in front.
- **Outbound auth for OpenAPI targets**: OAuth / API key / IAM(SigV4). **SigV4 is
  NOT compatible with ALB or EC2 backends** (only API Gateway / Lambda URL /
  AgentCore natively verify SigV4). → for the ALB-fronted mnemo-server use an
  **API-key credential provider** carrying `X-API-Key` (= mem9 tenant id).
- Caveat: `privateEndpoint` applies to **one domain** in the OpenAPI schema; if the
  schema references multiple server domains, need `privateEndpointOverrides` (AWS
  Support request). mnemo-server = single domain → fine.
- NOT the same limitation as "API Gateway *private endpoint type* not supported"
  or "AWS DevOps Agent needs public HTTPS" — those are different integration points.
  Gateway's own private target egress via Lattice is a first-class documented feature.
