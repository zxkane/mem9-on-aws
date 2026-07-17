# mem9-on-AWS — Architecture & Selection

Design doc for self-hosting **mem9** (`mnemo-server`) on AWS as a single-operator,
multi-device, multi-agent shared memory layer with full data ownership.

Status: **design only, not implemented.** All mem9 behavior below is probed from
source (see [`mem9-facts.md`](mem9-facts.md)); all AWS capability claims are
verified against AWS docs (Tokyo availability, pgvector, Aurora Serverless v2).

---

## 1. Goal & constraints

- **Goal**: one cloud-hosted memory backend; every device/agent (Claude Code,
  Codex, others) reads & writes the *same* pool via MCP over the network. Memory
  data 100% in the operator's own AWS account, exportable anytime.
- **Why not the alternatives** (established in prior evaluation):
  - *mem9 SaaS* — zero-ops and Free tier covers the operator's volume (~174
    memories/mo vs 13k quota), but data is hosted by a third party. Rejected on
    **data ownership**.
  - *TAM (total-agent-memory)* — best local retrieval in testing, but SQLite is
    hard-coupled (949 raw SQL statements, no storage abstraction), WAL
    single-writer breaks under multi-process/multi-device writes, and it has no
    AWS deployment story. Rejected as the AWS backend.
  - *mem9 self-hosted* — Apache-2.0, stateless server, MySQL/PG-compatible
    backends, SaaS↔self-host is a base-URL change (no lock-in). **Chosen.**

## 2. What mem9 actually needs (probed — full detail in mem9-facts.md)

| Dependency | Required? | Consequence for AWS |
|---|---|---|
| Database (PG / MySQL / TiDB) | ✅ all state | Aurora PostgreSQL + pgvector |
| Embedding MaaS (OpenAI-compatible `/embeddings`) | ✅ on PG backend | mnemo-server computes embeddings itself → needs an endpoint |
| LLM MaaS (OpenAI-compatible `/chat/completions`) | ⚠️ smart-ingest only | optional at launch; raw mode works without it |
| Local filesystem (`MNEMO_UPLOAD_DIR`) | ⚠️ **batch import only** |普通 add/search/CRUD 不碰磁盘 → **no EFS needed**; single task → `/tmp` is fine |
| S3 | ❌ metering only (disableable) | none |
| KMS | ❌ only if `MNEMO_ENCRYPT_TYPE=kms` | none at launch |

**Net**: `mnemo-server` is effectively **stateless** for our usage (逐条 add, no
batch import) — all durable state is in Aurora. This is what makes ECS Fargate a
clean fit and lets us avoid EFS entirely.

## 3. Database: **Aurora PostgreSQL + pgvector** (decisive)

The PG-vs-MySQL choice is forced by how mem9 implements vectors:

- mem9 `postgres` backend uses **pgvector** (`embedding vector(N)`, cosine via
  `embedding <=> $q`, FTS via `to_tsvector`). Standard, portable, self-controllable.
- mem9 `tidb` backend uses **TiDB's `VECTOR` type + `VEC_COSINE` + `EMBED_TEXT`**
  — these are **TiDB-Cloud-specific** and **do NOT exist in Aurora MySQL**. So
  "Aurora MySQL" cannot actually run mem9's MySQL/tidb path. Not viable.
- **`AutoVectorSearch` is TiDB-only** (server-side auto-embedding via
  `EMBED_TEXT` generated column). On PG, mem9 explicitly falls back to
  `VectorSearch` with **pre-computed embeddings** → **mnemo-server calls the
  embedding MaaS itself**. This is more moving parts but keeps embeddings under
  our control (fits "own the data").

**Chosen: Aurora PostgreSQL Serverless v2**, `pgvector` extension.
- Tokyo availability verified: Aurora PostgreSQL 16 / 17 on Serverless v2 in
  ap-northeast-1. `CREATE EXTENSION vector;` is standard.
- Serverless v2 scales 0.5 ACU → N; single-operator load sits near the floor.
- Embedding dims: mem9 PG schema ships `vector(1536)` by default but the tenant
  runtime schema is parameterized by client dims — **must match the chosen
  embedding model's dims** (e.g. qwen3-0.6B = 1024, Cohere embed-v4 = 1024,
  OpenAI text-embedding-3-small = 1536). Pin dims once; changing later requires a
  reindex.

### 3a. DB auth: **direct-to-Aurora + Secrets Manager** (no RDS Proxy; no committed password; NOT native IAM)

The operator asked to avoid a password / use IAM-role auth. **Probed, verified,
and decided (public-AWS only):**

- **mem9 cannot do IAM database auth unmodified.** `server/internal/config/config.go`
  reads a **single static `MNEMO_DSN`** env var (no separate host/user/pass vars);
  `postgres.go` does `sql.Open("pgx", dsn)` (pgx v5 stdlib) and reads the
  credential **once at startup** — no `BeforeConnect`/credential-refresh hook. An
  Aurora **IAM auth token expires in ~15 min**, but the DSN is static, so pool
  connections would start failing after the token expires. Verified against mem9
  source + public AWS Aurora docs.
- **Chosen: mem9 connects DIRECTLY to the Aurora cluster writer endpoint; the DB
  password lives ONLY in AWS Secrets Manager.** Flow:
  ```
  mnemo-server  --(static user+password from ECS `secrets: valueFrom`, TLS)-->  Aurora PG (writer endpoint)
  ```
  - The Aurora credential is generated (a static `RandomPassword`) + stored in a
    **Secrets Manager** secret by `sst.aws.Aurora` (the value never appears in
    git, the SST code, or the ECS task def as a literal). mem9 + the bootstrap
    task read it via ECS `secrets: valueFrom` and connect to the cluster writer
    endpoint. The ECS/bootstrap task role gets `secretsmanager:GetSecretValue` on
    that one secret ARN.
  - **NO RDS PROXY (DECIDED 2026-07-12).** We originally fronted Aurora with an
    RDS Proxy (`sst.aws.Aurora({proxy:true})`) for connection pooling. It proved
    **unusable at our 0.5-ACU floor**: an RDS Proxy provisions its backend capacity
    at a rate PROPORTIONAL to the Aurora Serverless v2 current ACU (AWS: "scale-up
    rate is proportional to current capacity"; the RDS Proxy team: "our capacity is
    based on underlying registered database capacity"). At 0.5 ACU the provisioning
    is the slowest possible, so the proxy target sat in
    `TargetHealth.State=UNAVAILABLE / Reason=PENDING_PROXY_CAPACITY` for 40+ min and
    effectively never became AVAILABLE — blocking every first connection. Reproduced
    in **two regions (Tokyo + Singapore)** → systemic to the 0.5-ACU + proxy combo,
    NOT regional (root cause confirmed against internal AWS knowledge). A
    single-writer, single-task self-host does **not** need proxy pooling, so the
    proxy was removed. (Raising min ACU to 2+ would also have fixed the proxy per
    AWS docs, but at ~4× the idle cost; dropping the proxy keeps the locked 0.5-ACU
    floor.) This removes the whole PENDING_PROXY_CAPACITY failure mode.
  - **Rotation: intentionally NOT configured (DECIDED — see #6).** Static
    Secrets-Manager password, blast-radius-confined; the master credential is only
    read by mem9/bootstrap via `secrets: valueFrom`. Revisit only if zero-static-
    secret becomes a hard requirement (would need the deferred token-refresh sidecar
    or a mem9 source patch).
  - mem9's `MNEMO_DSN` points at the **Aurora cluster writer endpoint** and carries
    a user + password injected via ECS **`secrets: valueFrom`** at task start —
    resolved to an env var by ECS, **never a plaintext literal in the committed
    task def or repo.**
- **Deferred (Open decision, not adopted):** true end-to-end IAM (no password at
  all) via either (a) a **token-refresh sidecar** minting a fresh RDS IAM token
  <15 min and reloading mem9, or (b) a **mem9 source patch** (pgx `BeforeConnect`
  + AWS auth-token generator). Both are more moving parts / a fork; revisit if the
  operator wants zero password even in Secrets Manager.
- **TLS**: the mnemo-server → Aurora hop uses password auth over TLS (Aurora
  presents a managed RDS cert; no cert to manage on our side). Set
  `sslmode=require` in `MNEMO_DSN`.

> **Customer-facing / public-AWS-only note.** This deployment is intended for
> customers and must use **only public AWS services**. Aurora +
> Secrets Manager are all public — compliant. ⚠️ The LLM smart-ingest path
> (§7) currently targets **Bedrock *Mantle***, which is an internal/preview
> surface — for a customer-facing build that must be revisited to the **public**
> `bedrock-runtime` Converse API (or an OpenAI-compatible public gateway). Tracked
> in Open decisions; does not affect the DB-auth decision here.

## 4. Compute: **ECS Fargate, arm64, single task**

- mnemo-server is a Go HTTP server (`:8080`), stateless for our usage → ECS
  Fargate long-lived service is the AWS-recommended host for a "sessionful/
  streaming" MCP-style server (vs Lambda for stateless bursts). Matches
  podcast-curation's `ecs.ts` pattern.
- **arm64**: mem9's Makefile currently hardcodes `GOARCH=amd64`, but the build is
  `CGO_ENABLED=0` pure Go → rebuild with `GOARCH=arm64` + Docker
  `--platform=linux/arm64`. Zero code change. (Recorded in mem9-facts.md.)
- **`desiredCount=1`** (locked): single-operator, 逐条 add → single writer, no
  concurrent-write contention, and it sidesteps mem9's local-disk import dir
  (which assumes files live on one task's filesystem). If HA/multi-AZ is ever
  needed, revisit (drop batch-import, or move upload dir to S3 — source change).
- Task size start: 256 CPU / 512 MB (mnemo-server is light; Aurora does the work).
- ECR: own the repo **out-of-band** via a CloudFormation template +
  `scripts/deploy-ecr-repositories.sh` (podcast-curation pattern) so
  `sst remove --stage pr-N` never wipes image history.

## 5. Networking: **reuse account default VPC** (Tokyo)

Per podcast-curation `ecs.ts`: `aws.ec2.getVpc({ default: true })`, then filter to
**private subnets with a NAT route** for the Fargate task + Aurora. No dedicated
VPC (a V2 concern). Aurora in the same private subnets; SG allows 5432 from the
Fargate task SG only. mnemo-server reaches the embedding MaaS via NAT (or via a
VPC-internal endpoint if the embedding shim is in-VPC).

## 6. MCP surface + auth: **AgentCore Gateway + Cognito** (reuse the pattern)

> **IMPLEMENTED** (PR "feat(mcp)", 2026-07-14) — **Lambda-proxy target** (see §6a
> for why the original ALB+Lattice path was abandoned). `infra/{cognito,gateway}.ts`
> + `infra/gateway/{proxy-handler.mjs,provision-target.mjs}`. Adaptations vs
> podcast-curation, all intentional:
> - **Target = a VPC-attached proxy Lambda** (nodejs24.x), NOT a public API URL. The
>   Lambda GatewayTarget carries `targetConfiguration.mcp.lambda.{lambdaArn,toolSchema}`
>   — AgentCore's out-of-the-box private path. NO ALB, NO ACM cert, NO VPC Lattice,
>   NO Route53 zone.
> - **Outbound auth = API key injected BY THE LAMBDA** (X-API-Key = tenant id), NOT a
>   credential provider — the proxy Lambda adds the header itself when it calls
>   mnemo-server, so there's no `AgentcoreApiKeyCredentialProvider`.
> - **Private reach = AWS Cloud Map**: mnemo-server registers under
>   `mnemo.mem9-<stage>.local`; the Lambda (in the same private subnets + task SG)
>   resolves it and calls HTTP :8080.
> - **v1 has NO interceptor Lambda** (single-operator, single-tenant → per-tool
>   scoping deferred). Tools exposed: `add_memory`, `search_memories`,
>   `ingest_messages` (transcript smart-ingest — same mnemo-server
>   `POST /memories` endpoint as `add_memory`, but a `messages[]` body triggers
>   LLM extraction; used by the Claude Code ingest hooks).

Mirror podcast-curation `gateway.ts` + `cognito.ts` + `api.ts`:

- **AgentCore Gateway** (MCP protocol) with an **OpenAPI target** whose schema
  maps MCP tools → mnemo-server's REST API (`/v1alpha2/mem9s/memories` add/
  search/get/update/delete). mnemo-server is already a REST server, so this is a
  schema-mapping job, not a Lambda rewrite. The target reaches mnemo-server
  **privately** (§6a) — no Lambda adapter needed.
- **Cognito M2M** user pool + resource server + app client(s); Gateway uses a
  Cognito OAuth credential provider. Inbound authorizer = JWT (Cognito issuer).
- **REQUEST interceptor Lambda** (scope ↔ tool authorization), as podcast-curation
  does, if per-tool scoping is wanted (e.g. read-only vs write clients across
  devices).
- Clients (Claude Code on any machine) point at the Gateway URL with OAuth →
  globally reachable, no SSH tunnel, no exposed mnemo-server port.
- SSM parameter exports for Gateway URL / Cognito endpoints / client IDs
  (podcast-curation convention: `/mem9-on-aws/${stage}/...`).

### 6b. Inbound auth — **two coexisting modes** (the gateway trusts both clients)

The MCP surface now accepts **two** inbound-auth flows against the same Cognito
pool; the AgentCore Gateway's JWT authorizer trusts both app clients:

1. **Cognito M2M (`client_credentials`)** — for CI / headless callers
   (`scripts/run-mcp-e2e.sh`). Unchanged from §6.
2. **OAuth2 authorization-code + PKCE (browser login)** — for humans (Claude Code
   desktop). Served by the **OAuth façade** (`infra/oauth-facade.ts`, an
   ApiGatewayV2 + Lambda surface — see the façade unit tests in
   `infra/src/oauth-facade/`) that bridges the PKCE authorization-code flow to the
   Cognito Hosted UI, so a human logs in via the browser instead of a client
   secret.

One-time setup per stage (never committed; run by the operator):
- Seed the state-signing HMAC key:
  `sst secret set OauthStateHmacKey "$(openssl rand -base64 32)" --stage <stage>`
  (empty default → the façade returns 503 until seeded).
- Create the operator user: `aws cognito-idp admin-create-user ...`.

The operator then points Claude Code at the façade MCP endpoint published in SSM
at `/mem9-on-aws/<stage>/facade/mcp-endpoint` and logs in via the browser. Full
design + flow: [`docs/superpowers/specs/2026-07-15-oauth2-mcp-browser-login-design.md`](superpowers/specs/2026-07-15-oauth2-mcp-browser-login-design.md).

### 6a. Gateway → mnemo-server network path (Lambda-proxy — the ALB/Lattice path was abandoned)

**mnemo-server stays fully private; the Gateway reaches it via a VPC-attached proxy
Lambda, no public exposure.** AgentCore Gateway supports a **Lambda target** as an
out-of-the-box private path: *"the gateway can immediately invoke Lambda functions
configured with VPC access to reach your internal resources"* (AWS docs). The Lambda
runs in our private subnets and reaches mnemo-server over **AWS Cloud Map** DNS.

Path (all private, zero public):
```
Claude Code (any device)
  → AgentCore Gateway  [inbound: Cognito M2M JWT (CUSTOM_JWT)]
    → GatewayTarget (mcp.lambda) → proxy Lambda (VPC, nodejs24.x)   [gateway role: lambda:InvokeFunction]
      → http://mnemo.mem9-<stage>.local:8080  (AWS Cloud Map)       [outbound auth: X-API-Key = tenant id, added by the Lambda]
        → ECS Fargate mnemo-server (HTTP :8080, private subnet)
          → Aurora PG (private subnet)
```

Design rules:
- **Lambda target** (`targetConfiguration.mcp.lambda.{lambdaArn, toolSchema}`) — no
  `privateEndpoint`, no VPC Lattice, no ALB, no ACM cert, no Route53 public zone.
  AgentCore invokes the Lambda AS THE GATEWAY SERVICE ROLE, so that role needs only
  `lambda:InvokeFunction` on the one function (least privilege).
- **The proxy Lambda** (`infra/gateway/proxy-handler.mjs`) receives the tool name in
  `context.clientContext.Custom.bedrockAgentCoreToolName` (`${target}___${tool}`) and
  the tool inputs as a flat event map; it maps `add_memory`/`search_memories`/
  `ingest_messages` to mnemo-server's REST (`POST`/`GET /v1alpha2/mem9s/memories`;
  `ingest_messages` POSTs a `messages[]` body for smart-ingest), injecting
  `X-API-Key` (= tenant id). It's VPC-attached (private subnets + the task SG, so a self-ingress
  :8080 rule lets it reach the server) and nodejs24.x. The tool inputSchemas live
  inline in `infra/gateway.ts`.
- **Cloud Map** (`infra/ecs.ts`): a `PrivateDnsNamespace` (`mem9-<stage>.local`) + a
  `Service` (`mnemo`) registered on the ECS service; ECS keeps the A record pointed
  at the running task's private IP. (A PrivateDnsNamespace creates a managed Route53
  private hosted zone — the only remaining Route53 dependency.)
- **WHY NOT the original ALB + self-managed-VPC-Lattice `privateEndpoint`**: that
  target failed to stabilize **100% of the time** in the full CI deploy — an AgentCore
  control-plane internal error (*"The server encountered an internal error … Retry the
  request later."*) on the self-managed-Lattice privateEndpoint target in
  ap-northeast-1. The IDENTICAL config reached READY in isolated direct-API tests but
  never in a full-stack deploy (ruled out: CloudControl-vs-SDK, CUSTOM_JWT-vs-IAM,
  RC-not-ACTIVE, domain-verification, retries + spacing). It's an AWS-side defect on
  that combination; the Lambda target sidesteps it entirely.

## 7. LLM + embedding supply (all LOCKED)

mem9 (PG backend) needs an OpenAI-compatible `/chat/completions` (smart-ingest LLM)
and an OpenAI-compatible `/embeddings`. Both are resolved below.

### LLM (smart-ingest) → **Bedrock Mantle, GLM-5, enabled at launch**

**Key finding (verified against AWS docs + podcast-curation prod usage):** Amazon
**Bedrock Mantle** (`https://bedrock-mantle.{region}.api.aws/v1`) is a *native
OpenAI-compatible* endpoint. mem9's LLM client POSTs to `/chat/completions`, so:

- **smart-ingest = ON at launch, Mantle direct, NO LiteLLM/proxy.** Set
  `MNEMO_LLM_BASE_URL=https://bedrock-mantle.ap-northeast-1.api.aws/v1`,
  `MNEMO_LLM_MODEL=<GLM-5 model id>`, `MNEMO_INGEST_MODE=smart`, and
  `MNEMO_LLM_API_KEY=<a Bedrock bearer token>` (see auth below).
  → **First deploy must bring up Mantle auth + Bedrock Project together** (not a
  later add-on), since smart-ingest is on from day one.
- **Model = GLM-5** (Chat-Completions; verified in podcast-curation prod on Mantle).
  **GPT-5.4 / 5.5 are Responses-API only → NOT usable by mem9.**
- **Auth = `@aws/bedrock-token-generator` (same as llm-wiki), NOT a static key.**
  llm-wiki uses `@aws/bedrock-token-generator@^1.1.0` to mint a **short-term
  Bedrock bearer token** from the task's IAM credentials (no long-lived API key to
  manage). Cost attribution = a **Bedrock Project** (`AWS::BedrockMantle::Project`,
  out-of-band CFN — this repo's `infra/cloudformation/bedrock-mantle-project.yaml` +
  `scripts/deploy-bedrock-mantle-project.sh`, modeled on llm-wiki's), passed as the
  `OpenAI-Project` header. Mantle does NOT support IAM-principal attribution
  (podcast-curation verified), so the Project is how GLM-5 spend gets tagged.
- **Token-lifetime + header bridge (LOCKED; mechanism corrected 2026-07-12):** the
  Mantle bearer expires (**12h TTL**, verified live), but mem9 reads
  `MNEMO_LLM_API_KEY` **once at startup into an immutable field — NO reload** (no
  SIGHUP/watch/re-read, verified in mem9 source), and its hand-rolled client sends
  **only** `Authorization` (no hook to add the `OpenAI-Project` cost header). So the
  originally-sketched "sidecar rewrites a file mem9 re-reads" **cannot work**. The
  LOCKED mechanism is a **local LLM proxy sidecar** (`docker/llm-proxy/`): mem9
  points `MNEMO_LLM_BASE_URL=http://localhost:8082/v1` with a **static dummy**
  `MNEMO_LLM_API_KEY` (must be non-empty, else mem9 nils the LLM client → silent
  raw); the proxy holds the live bearer (minted by `@aws/bedrock-token-generator` —
  a **local SigV4 presign**, refreshed on a ~hourly timer well under the 12h TTL)
  and injects a fresh `Authorization: Bearer` + the `OpenAI-Project` header per
  forwarded request. Solves BOTH the read-once-key and no-custom-header limits —
  **no mem9 source change, no restart on rotation.** Task-role IAM:
  `bedrock:CallWithBearerToken` (mint) + `bedrock:InvokeModel` on the `zai.glm-5`
  FM ARN. See `docs/mem9-facts.md` "LLM key is read ONCE" + `docker/llm-proxy/server.mjs`.

### Embedding → **NOT Mantle** (Mantle has no `/embeddings`)

**Critical (verified):** Mantle only serves Chat Completions / Responses / Messages
— **there is NO `/embeddings` on Mantle.** Every Bedrock embedding model
(Titan V2, Cohere embed-v4, Nova MM) is available **only on `bedrock-runtime`**,
which is **not** OpenAI-compatible (it's InvokeModel). So embedding cannot come
from Mantle, and Bedrock's own embed models aren't OpenAI-shaped either.

**Decision (locked): write our own OpenAI-compatible `/embeddings` service running
qwen3.** mem9 points `MNEMO_EMBED_BASE_URL` at this service; it exposes the OpenAI
`POST /v1/embeddings` contract and computes vectors with **qwen3** (the same
open-weight embedding model llm-wiki runs as ONNX). Rationale:

- Full data ownership — embeddings computed on our own code/infra, nothing leaves
  to OpenAI or a 3P embed API.
- **Code source (LOCKED): lift llm-wiki's qwen3 ONNX embed code** into this repo
  (the ONNX model, eager-INIT, CJK handling; ref llm-wiki memory
  `s3vectors-query-coldstart-onnx-timeout`), wrapped in a tiny OpenAI
  `/v1/embeddings` shell: accept `{input, model}`, return `{data:[{embedding:[...]}]}`.
  qwen3-0.6B = **1024 dims**.

**Placement (LOCKED): ECS sidecar in the same task.** The qwen3 embed server runs
as a sidecar container next to mnemo-server; mem9 calls it over
`MNEMO_EMBED_BASE_URL=http://localhost:<port>/v1`. Always warm (no Lambda
cold-start, no keep-warm ping, no API Gateway, no cross-service auth) — the right
call for `desiredCount=1` + low volume. Cost: the qwen3 ONNX model rides the task's
memory → size the task up for it (main swing in the Fargate cost row).

**Pin dims = 1024 before first ingest** — align mem9's `MNEMO_EMBED_DIMS`, the
qwen3 output, and the PG `vector(1024)` column. Changing later = full reindex.

### ECS task container composition (result of the sidecar decisions)

The single Fargate task (`desiredCount=1`, arm64) runs **three containers**:
1. **mnemo-server** (upstream mem9, HTTP :8080) — the memory server.
2. **qwen3-embed sidecar** — OpenAI `/v1/embeddings` on localhost:8081 (§7 embedding).
3. **llm-proxy sidecar** — OpenAI `/v1/chat/completions` proxy on localhost:8082 →
   Bedrock Mantle GLM-5 (§7 LLM). Holds + refreshes the Mantle bearer and injects
   `OpenAI-Project`, so mnemo-server auths with a static dummy key locally. (This
   replaces the originally-named "token-refresh sidecar" — mem9's read-once key +
   no-custom-header limits require a request proxy, not a token file-writer.)

(TLS is NOT in the task — the internal ALB terminates it, §6a. So no nginx/TLS
sidecar needed.) Task memory must fit mnemo-server + the qwen3 ONNX model; the
token-refresh helper is negligible. Size at IaC stage.

## 8. Schema bootstrap (must-not-forget)

mem9 PG needs, before first use:
1. `CREATE EXTENSION vector;`
2. apply **control-plane** schema (`server/schema_pg.sql`) — note the probed gap:
   the runtime tenant schema validation expects an `idx_app` index that the
   shipped `schema_pg.sql` did not create in our POC; the tenant runtime schema
   (`server/internal/tenant/schema.go`) differs from the control-plane file.
   Bootstrap must apply the **tenant runtime schema**, not just the control-plane
   file. (Full detail in mem9-facts.md.)
3. Insert an active `tenants` row (single-tenant for a single operator); the
   tenant `id` is the `X-API-Key` (probed).

Mechanism — **IMPLEMENTED (one-shot ECS task).** `infra/bootstrap.ts` defines an
`sst.aws.Task` (arm64, image `docker/bootstrap/`, psql + jq) wired to the DB
Outputs + a **stable tenant-id secret** (a `random.RandomId` stored in Secrets
Manager, so re-runs reuse the same `X-API-Key` rather than minting a new one).
The task runs `docker/bootstrap/schema.sql` (all IF NOT EXISTS) then upserts the
one active tenant (ON CONFLICT). SST only *defines* the task; **CI runs it via
`aws ecs run-task` after `sst deploy`** (`scripts/run-bootstrap-task.sh`, reading
the run inputs SST exports to `/mem9-on-aws/${stage}/bootstrap/*` SSM) and waits
for exit 0 — kept out of the Pulumi graph (no local-exec provider) and observable
in CI logs. Idempotent, so it re-runs safely on every deploy.

**Embedding-dims decision baked in here:** the `memories.embedding` column is
`vector(1024)` (NOT mem9's hardcoded `vector(1536)`), matching the qwen3-embed
sidecar + `MNEMO_EMBED_DIMS=1024`. The FTS index is a GIN on
`to_tsvector('english', content)` (matches mem9's FTSSearch), plus an HNSW
`vector_cosine_ops` index for the `embedding <=> $q` cosine search.

## 9. Cost sketch (Tokyo, order-of-magnitude, verify at build)

| Component | Rough monthly |
|---|---|
| Aurora PG **Serverless v2** @ ~0.5 ACU floor (LOCKED) | ~$40–50 (largest line; scales with idle floor) |
| Fargate arm64 1 task (size depends on embed placement — see below) | ~$8–20 |
| qwen3 embedding: Lambda (b1) low volume ~$0–2, OR folded into the Fargate task (b2, sidecar) → task memory ↑ | see Fargate row |
| Bedrock Mantle (GLM-5 smart-ingest) | per-token, tiny at single-operator volume |
| **Internal ALB** (TLS termination for Lattice) | ~$16–20 (fixed; the price of the private Gateway→ECS path) |
| ACM public cert (`mem9.aws.kane.mx`) | **$0** (public ACM certs are free) |
| AgentCore Gateway + Cognito + managed VPC Lattice | low / mostly free at this scale (managed Lattice has no separate charge surfaced) |
| NAT (if not already present in default VPC) | ~$32 + data — check whether default VPC already has one |

vs mem9 SaaS Free ($0). The delta buys full data ownership + no third-party.
**Database is locked to Aurora Serverless v2** (operator decision) — the ~0.5 ACU
idle floor is accepted; the earlier RDS `t4g` alternative is dropped. If the embed
model runs as a sidecar (b2), size the Fargate task memory for qwen3 (the ONNX
model is the heavy tenant), which is the main swing in the Fargate cost row.

## 10. Data ownership / exit

- All memory + embeddings in the operator's Aurora PG. Export = `pg_dump` or
  mem9's `GET /v1alpha2/mem9s/memories` paginate; import into any PG/mem9 via
  `POST /v1alpha2/mem9s/imports`. mem9 self-host↔SaaS↔another-PG is a base-URL +
  DSN change (upstream: "migration is a base-URL and credential change").
- Sensitive-content note: the operator's real engineering memories contain
  account IDs / role ARNs / internal paths. Those go into **Aurora (private,
  owned)** — fine. They must NOT be echoed into this repo's committed docs.

---

## Component summary (for IaC mapping)

| Layer | AWS resource | Source pattern |
|---|---|---|
| Container registry | ECR (out-of-band CFN) | podcast-curation `cloudformation/ecr-repositories.yaml` |
| Compute | ECS Fargate service, arm64, count=1 | podcast-curation `infra/ecs.ts` |
| Database | Aurora PostgreSQL Serverless v2 + pgvector | new (`infra/db.ts`) |
| Networking | default VPC private subnets + SGs | podcast-curation `infra/ecs.ts` default-VPC lookup |
| MCP gateway | AgentCore Gateway (OpenAPI target + `privateEndpoint` managed Lattice, API-key outbound) | podcast-curation `infra/gateway.ts` (adapt: private endpoint is new) |
| Private egress | AgentCore managed VPC Lattice (auto) + **internal ALB** (HTTPS→HTTP:8080, host-header transform) | new (`infra/gateway-egress.ts`) — no direct template (podcast fronts Lambda, not ECS) |
| TLS cert | **public ACM cert** `mem9.aws.kane.mx` (R53 DNS-validated; name-only, no public A record) | new (`infra/certs.ts`) |
| Auth | Cognito M2M pool + resource server | podcast-curation `infra/cognito.ts` |
| Tool authz | REQUEST interceptor Lambda | podcast-curation `infra/functions.ts` |
| Embedding | qwen3 OpenAI `/embeddings` as an **ECS sidecar** (lifted from llm-wiki qwen3 ONNX), localhost, dims 1024 | llm-wiki qwen3 ONNX code |
| LLM (smart-ingest) | **Bedrock Mantle direct**, **GLM-5**, ON at launch; auth via **`@aws/bedrock-token-generator`** + **token-refresh sidecar** + Bedrock Project | llm-wiki (`@aws/bedrock-token-generator`, `bedrock-mantle-project.yaml`) + podcast-curation `bedrock-mantle.ts` |
| Bedrock Project | `AWS::BedrockMantle::Project` for GLM-5 cost attribution (out-of-band CFN) | this repo: `infra/cloudformation/bedrock-mantle-project.yaml` + `scripts/deploy-bedrock-mantle-project.sh` (modeled on llm-wiki) |
| Config | SST v4 `sst.config.ts` (Tokyo, Node 24) | llm-wiki `sst.config.ts` |
| Cross-module wiring | SSM Parameter Store `/mem9-on-aws/${stage}/...` | both |

## Locked decisions (no longer open)

- **DB engine**: Aurora **PostgreSQL Serverless v2** + pgvector (not MySQL, not
  RDS t4g). Backend = mem9 `postgres`.
- **DB auth (§3a)**: **direct-to-Aurora + Secrets Manager**, NOT native IAM (mem9's
  static `MNEMO_DSN` / pgx-stdlib / no credential refresh can't handle the ~15-min
  IAM token). **NO RDS Proxy** — it was dropped (DECIDED 2026-07-12) because at the
  0.5-ACU floor the proxy's `PENDING_PROXY_CAPACITY` provisioning was starved and
  the target never became AVAILABLE (reproduced Tokyo + Singapore → systemic to the
  0.5-ACU + proxy combo, not regional; root cause confirmed vs internal AWS
  knowledge — proxy capacity provisions ∝ current ACU). A single-writer self-host
  needs no pooling, so mem9 + the bootstrap task connect to the Aurora **cluster
  writer endpoint** directly. Aurora password lives only in Secrets Manager (static
  `RandomPassword` from `sst.aws.Aurora`; **rotation intentionally NOT configured —
  see §3a / #6, DECIDED**), injected via ECS `secrets: valueFrom` (never committed /
  human-handled). Task role gets `secretsmanager:GetSecretValue` on the one secret
  ARN. True end-to-end IAM deferred (sidecar or source patch) — see Open decisions.
- **Public-AWS-only (customer-facing)**: this deployment targets customers, so it
  must use **only public AWS services**. Aurora / Secrets Manager are public ✅.
  The **Bedrock Mantle** LLM path (§7) is internal/preview → flagged for revisit to
  public `bedrock-runtime` Converse before a customer build (Open #7).
- **Region**: **ap-northeast-1 (Tokyo)**. (Briefly moved to Singapore 2026-07-12
  while diagnosing the RDS Proxy `PENDING_PROXY_CAPACITY` hang, but that turned out
  to be the 0.5-ACU + proxy combo, not regional — so we dropped the proxy and moved
  back to Tokyo.) **Compute**: ECS Fargate, arm64, `desiredCount=1`. **VPC**: reuse
  the account default VPC's NAT-routed private subnets (selected by the `private-1*`
  Name tag — the Tokyo default VPC also has no-NAT `secondary-private-subnet-*` ones
  that a generic public-ip filter would wrongly include; see infra/vpc.ts).
- **MCP + auth**: AgentCore Gateway + Cognito (podcast-curation pattern). **Two
  coexisting inbound modes** (§6b): **Cognito M2M** (`client_credentials`, for
  CI / headless callers) **and** **OAuth2 authorization-code + PKCE** browser
  login for humans (Claude Code desktop) via the **OAuth façade**
  (`infra/oauth-facade.ts`, ApiGatewayV2 → Cognito Hosted UI). One-time per-stage
  setup: seed `OauthStateHmacKey` + `admin-create-user`; the operator points
  Claude Code at `/mem9-on-aws/<stage>/facade/mcp-endpoint`.
- **Gateway → mnemo-server**: **private** via AgentCore `privateEndpoint` +
  **managed VPC Lattice** → **internal ALB (public ACM cert, TLS terminated here)**
  → mnemo-server over HTTP:8080. Outbound auth = **API key** (`X-API-Key` = tenant
  id). ACM cert domain = a **kane.mx subdomain** (`mem9.aws.kane.mx`,
  name-only / no public DNS needed, R53-validated). No public exposure. (See §6a.)
- **LLM (smart-ingest)**: **Bedrock Mantle direct**, **GLM-5**, **ON at launch**
  (`MNEMO_INGEST_MODE=smart`). No proxy. GPT-5.4/5.5 (Responses-only) excluded.
  → first deploy must wire Mantle auth + Bedrock Project together.
- **Mantle auth**: **`@aws/bedrock-token-generator`** (same as llm-wiki) mints a
  short-term bearer from the task IAM role; **Bedrock Project** for cost
  attribution. A **token-refresh sidecar** keeps `MNEMO_LLM_API_KEY` fresh (mem9
  reads static env; bearer expires) — no mem9 source change.
- **Embedding**: qwen3 OpenAI `/embeddings` as an **ECS sidecar** (localhost,
  always warm), **code lifted from llm-wiki's qwen3 ONNX**, **dims 1024**. Not
  Mantle (no `/embeddings`), not a 3P embed API.
- **ECS task = 3 containers**: mnemo-server + qwen3-embed sidecar + token-refresh
  sidecar. TLS terminated at the ALB (not in the task).
- **Schema bootstrap**: **one-shot ECS task** on deploy (applies pgvector + the
  tenant runtime schema incl. `idx_app` + FTS + `vector(1024)`, seeds one tenant).
- **Tenancy**: **single tenant** (one `X-API-Key`), but writes carry
  **`X-Mnemo-Agent-Id`** so memories are tagged per device/agent — reserves
  future per-agent scoping/filtering without a migration.

## Open decisions (STILL TO DECIDE — all engineering detail, none architecture-level)

1. **OpenAPI schema mapping** — how to express mnemo-server's REST API as the
   Gateway OpenAPI target schema: which endpoints become MCP tools
   (add/search/get/update/delete), tool names/filters, and whether an interceptor
   Lambda is needed for per-device read/write scoping. Pure schema work.
2. **Token-refresh sidecar mechanism** — exact refresh cadence + how mnemo-server
   picks up the new bearer without restart (shared file it re-reads each call vs.
   a rolling env refresh). Approach locked (sidecar); mechanism is impl detail.
3. **mem9 pinning + image build** — which upstream commit/tag of `mem9-ai/mem9` to
   vendor; own arm64 Dockerfile derived from `server/Dockerfile` (restore the
   commented-out golang builder stage; `GOARCH=arm64`).
4. **Backup / DR** — Aurora automated backups + snapshot cadence; is
   point-in-time recovery wanted? (Data-ownership project → likely yes.)
5. **CI / deploy** — GHA with the `RUNNER_LABEL` self-hosted pattern; how the
   arm64 image builds & pushes to ECR (docker-build provider vs. CodeBuild arm).
6. **Secrets + rotation — DECIDED: storage resolved (§3a), rotation intentionally
   deferred.** Aurora creds live in an `sst.aws.Aurora` static `RandomPassword`
   Secrets Manager secret, injected into Fargate via ECS `secrets: valueFrom`, and
   mem9 connects to the Aurora cluster writer endpoint DIRECTLY (no RDS Proxy — see
   §3a). **Automatic rotation is NOT configured, on purpose** (static, blast-radius-
   confined password is acceptable for a single-operator self-host). Note: dropping
   the RDS Proxy actually REMOVED the old blocker to rotation (SST's `proxy:true`
   owned a minimal `{username,password}`-only secret with no way to add
   `host`+`engine` for the RDS rotation Lambda). If rotation is pursued later: the
   secret would need `engine=aurora-postgresql`+`host`=cluster writer endpoint, the
   SAR `SecretsManagerRDSPostgreSQLRotationSingleUser` Lambda in the DB private
   subnets, and the deploy role would need
   `iam:CreateRole`+`AttachRolePolicy`+`serverlessrepo`+`lambda`+
   `secretsmanager:RotateSecret`. (Mantle bearer is minted at runtime by the token
   sidecar, not a stored secret.)
7. **Public-AWS LLM path (customer-facing)** — the solution must use only public
   AWS services. §7's **Bedrock Mantle** smart-ingest is internal/preview → for a
   customer build, migrate the OpenAI-compatible `/chat/completions` LLM to the
   **public `bedrock-runtime` Converse API** (or a public OpenAI-compatible
   gateway) + a `bedrock:InvokeModel`-based auth. Does not affect DB/Aurora.
8. **True end-to-end IAM DB auth (deferred)** — reach zero-password by either a
   token-refresh sidecar (mints an RDS IAM token <15 min, reloads mem9) or a mem9
   source patch (pgx `BeforeConnect` + AWS auth-token generator). Not adopted;
   §3a's Secrets-Manager-rotation path is the launch choice.
