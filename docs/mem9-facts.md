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
  `sst.aws.Aurora`, **consumed ONLY by RDS Proxy** — password blast-radius is the
  proxy↔Aurora hop). ⚠️ SST's `proxy:true` owns a minimal `{username,password}`
  secret (no `host`/`engine`, no transform hook), and the AWS RDS rotation Lambda
  requires `host`+`engine`; enabling rotation would force replacing the SST-owned
  proxy → **rotation is intentionally NOT configured (DECIDED, ARCHITECTURE.md
  §3a / #6)**, revisit when the ECS stack re-owns the secret/proxy. RDS Proxy
  pulls the secret and pools/multiplexes; mem9
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
  llm-wiki hit; may need config.)
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
- On the PG backend mem9 does NOT create the `memories` table at runtime — the
  `TenantMemorySchemaPostgres` constant has NO call site (only webhooks/usage get
  `EnsureSchema`); startup only *validates* `app_id`+`idx_app`. **So our bootstrap
  creates the full memories schema** (with `vector(1024)`, GIN FTS, HNSW).

### DB connection per request = PER-TENANT creds from the `tenants` row (decisive)
Verified from `server/internal/middleware/auth.go` + `service/tenant.go` +
`service/upload.go` + `domain/types.go` (`DSNForBackend`) + `tenant/pool.go`:
- On **every** memory request, mem9's auth middleware loads the tenant row, calls
  `enc.Decrypt(t.DBPassword)` (with `MNEMO_ENCRYPT_TYPE=plain` default → the stored
  value is used **literally**), then `pool.Get(id, t.DSNForBackend(backend))` and
  builds the `MemoryRepo` on THAT per-tenant `*sql.DB`. The memory add/search path
  does NOT reuse the control-plane `MNEMO_DSN` pool.
- `DSNForBackend` (postgres) =
  `postgres://<db_user>:<db_password>@<db_host>:<db_port>/<db_name>?sslmode=<disable|require>`
  (`require` iff `db_tls=true`). It does **NOT URL-encode** the password — a DSN-
  reserved char in the password could malform mem9's own DSN (mem9 limitation;
  the RDS `RandomPassword` can contain such chars — a risk to watch, not ours to
  fix without a mem9 patch).
- **Consequence for bootstrap:** the seeded `tenants` row MUST carry the REAL
  `db_user`+`db_password` (the RDS Proxy creds from `MEM9_DB_SECRET`), NOT a
  placeholder — else every add/search fails auth at query time even though the
  server boots and passes `idx_app` validation. The bootstrap entrypoint seeds
  them via psql `--set` variables (password never in argv/SQL text). `db_tls=TRUE`
  → mem9 builds `sslmode=require`. This puts the DB password in a `tenants` table
  column (mem9's plain-mode design; the operator's own DB). `MNEMO_ENCRYPT_TYPE=kms`
  could encrypt it at rest later.

## Embedding (MaaS)

- OpenAI-compatible only. `server/internal/embed/embedder.go` POSTs to
  `{MNEMO_EMBED_BASE_URL}/embeddings`, `EncodingFormat: "float"`.
- Env: `MNEMO_EMBED_BASE_URL` (default `https://api.openai.com/v1`),
  `MNEMO_EMBED_MODEL` (default `text-embedding-3-small`), `MNEMO_EMBED_API_KEY`
  (`""`/`local` for Ollama-style), `MNEMO_EMBED_DIMS` (default 1536).
- **No native Bedrock.** Bedrock requires an OpenAI→Bedrock proxy exposing
  `/embeddings`. Ollama/LM Studio/TEI/any OpenAI-compatible server works via
  `MNEMO_EMBED_BASE_URL`.
- Design decision: reuse llm-wiki's **qwen3** embedding (dims 1024) or a Bedrock
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

Verified against AWS docs + the operator's podcast-curation prod usage:

- **Mantle IS OpenAI-compatible.** Endpoint `https://bedrock-mantle.{region}.api.aws/v1`;
  surfaces = **Chat Completions** + **Responses** (OpenAI-compatible) + **Messages**
  (Anthropic). "Bring OpenAI SDK code by changing only base URL + API key."
- **mem9 speaks `/chat/completions` only** → the smart-ingest LLM must be a
  **Chat-Completions** model on Mantle: **GLM-5** (podcast-curation runs GLM-5 on
  Mantle in prod), Claude Sonnet/Fable 5, DeepSeek, Gemma, etc. **GPT-5.4 / 5.5
  are Responses-API only → NOT usable by mem9** without a source change.
- **Mantle has NO `/embeddings`.** All Bedrock embedding models (Titan Text V2,
  Cohere embed-v4, Nova MM) are **`bedrock-runtime` ONLY**, and bedrock-runtime is
  **not** OpenAI-compatible for embeddings (it's InvokeModel). → embedding must be
  our own OpenAI-shaped `/embeddings` service (decided: qwen3, dims 1024).
- **Auth**: Bedrock API key (bearer) works with the OpenAI SDK; SigV4 also works.
  Cost attribution on Mantle = **Bedrock Projects** via the `OpenAI-Project`
  header — **IAM-principal / session-tag attribution does NOT work on Mantle**
  (podcast-curation verified prod GLM-5 spend tagged ~$0 via the runtime path).
  Reuse podcast-curation `infra/bedrock-mantle.ts` (CloudControl
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

### Packaging: no release/tag/public image → we PIN a source SHA (verified 2026-07-11)

- **mem9-ai/mem9 publishes NO GitHub release, NO tag, and NO public image.**
  `gh api repos/mem9-ai/mem9/{releases,tags}` both return empty. Their own CI
  (`.github/workflows/deploy-dev.yml` / `deploy-prod.yml`) builds
  `<branch>-<sha7>` and pushes to the **maintainers' PRIVATE ECR** (a different
  AWS account) + deploys to their EKS — **unusable for us**. So self-hosting
  REQUIRES pinning an upstream commit and building our own image.
- Upstream's build model: the Makefile's `build-linux` compiles the binary on
  the CI host (`CGO_ENABLED=0 GOOS=linux GOARCH=amd64`), then `docker build`
  merely `COPY`s the prebuilt binary into `alpine:3.19` (the Dockerfile's golang
  builder stage is commented out). Module path is
  **`github.com/qiffang/mnemos/server`**; the server module lives under `server/`
  (`server/{go.mod,go.sum,cmd/mnemo-server/main.go,internal,schema_pg.sql}`).
- **Our build (this repo, `docker/mnemo-server/Dockerfile`):** a self-contained
  **multi-stage** build — `golang:1.24-alpine` builder git-fetches the pinned
  commit, `CGO_ENABLED=0 GOARCH=arm64 go build ./cmd/mnemo-server`, into
  `alpine:3.19` — so CI needs only Docker (no host Go, no separate mem9
  checkout). Built for **arm64** (Graviton Fargate) via `docker buildx
  --platform=linux/arm64`.
- **Vendored pin (LOCKED): `mem9-ai/mem9` @ `d4638c8458abeb209a1b3a20472a1328c4acd149`**
  (main tip, committed 2026-07-10). It is the `MEM9_REF` build-arg default in the
  Dockerfile. **Bumping the pin = change `MEM9_REF` + re-verify every fact in
  this file against the new tree** (schema, config env vars, DB driver path).
- **Entrypoint (`docker/mnemo-server/entrypoint.sh`)** bridges the static-DSN
  constraint (see "DB connection mechanism"): mem9 reads one static `MNEMO_DSN`
  and can't compose it from parts, and the DB password is a runtime secret
  (Secrets Manager → ECS `secrets: valueFrom`), so the entrypoint assembles
  `MNEMO_DSN=postgres://<user>:<url-encoded-pw>@<host>:<port>/<db>?sslmode=require`
  at container start from the injected `MEM9_DB_HOST/PORT/NAME` env + the
  `MEM9_DB_SECRET` JSON (`{username,password}`), URL-encoding the password (RDS
  RandomPassword can contain `@ / : ? #`) via `jq @uri`. It respects a pre-set
  `MNEMO_DSN` and fails loud on any missing/null field. **No mem9 source change.**

## Concurrency model

- Server is the single process fronting the DB; concurrency is handled at the DB
  (Aurora PG) transaction level, not in-process file locks (unlike TAM's SQLite).
  With `desiredCount=1` there is one writer process → no cross-process contention.
  Multi-replica writes would rely on Aurora's MVCC (fine for the DB) but hit the
  local-disk import limitation above.

## Verified AWS facts (for the design)

- Aurora **PostgreSQL Serverless v2** available in **ap-southeast-1 (Singapore)**,
  PG 16 & 17. `pgvector` is a standard extension (`CREATE EXTENSION vector`).
  (Project moved Tokyo→Singapore 2026-07-12 — see the RDS-Proxy warmup note below.)
- Amazon S3 Files (2026-04 GA) exists as a writable POSIX/NFS mount but is NOT
  used here (no filesystem state to host; single-task `/tmp` covers import).
- podcast-curation's ECS stack consumes the **account default VPC** via
  `aws.ec2.getVpc({ default: true })`, filtered to NAT-routed private subnets —
  the pattern reused here.
- **Singapore default VPC is customized + NAT-routed (verified 2026-07-12).** The
  account's `ap-southeast-1` default VPC (172.31.0.0/16) has three
  `private-subnet-1a/1b/1c` subnets across 3 AZs (`MapPublicIpOnLaunch=false`),
  **each routing `0.0.0.0/0` through a single NAT gateway**, plus three public
  subnets via the IGW. The scaffold's `infra/vpc.ts` selects the three private
  subnets by the **region-agnostic `map-public-ip-on-launch=false` filter** (NOT a
  Name tag). So ECS Fargate + Aurora can live in the default VPC with outbound
  internet via NAT — no dedicated VPC needed, confirming the ARCHITECTURE.md
  assumption. Concrete resource ids are intentionally NOT recorded here (they'd
  leak account topology).
- **RDS Proxy `PENDING_PROXY_CAPACITY` was pathological in ap-northeast-1
  (2026-07-12) — the reason for the Tokyo→Singapore move.** A freshly-created RDS
  Proxy (SST `Aurora({proxy:true})`) sat in `TargetHealth.State=UNAVAILABLE /
  Reason=PENDING_PROXY_CAPACITY` for 40+ min and NEVER became AVAILABLE, even
  though the Aurora cluster+instance were both `available` and the proxy's own
  config (SG, subnets, target group, pool) was verified healthy. Reproduced on two
  independent proxies. SST's deploy returns once the CLUSTER is available but does
  NOT wait for the proxy target to be healthy, so `run-bootstrap-task.sh` gates on
  `describe-db-proxy-targets` TargetHealth.State==AVAILABLE (up to ~35 min) before
  running the bootstrap task. Normal warmup is 1–3 min; Tokyo's indefinite wedge
  was region-level. Watch for the same signature in Singapore.

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
