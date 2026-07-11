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

### 3a. DB auth: **RDS Proxy + Secrets Manager rotation** (no committed password; NOT native IAM)

The operator asked to avoid a password / use IAM-role auth. **Probed, verified,
and decided (public-AWS only):**

- **mem9 cannot do IAM database auth unmodified.** `server/internal/config/config.go`
  reads a **single static `MNEMO_DSN`** env var (no separate host/user/pass vars);
  `postgres.go` does `sql.Open("pgx", dsn)` (pgx v5 stdlib) and reads the
  credential **once at startup** — no `BeforeConnect`/credential-refresh hook. An
  Aurora **IAM auth token expires in ~15 min**, but the DSN is static, so pool
  connections would start failing after the token expires. This is true whether
  connecting **directly** to Aurora or via **RDS Proxy with client-side IAM**
  (mem9 is the IAM token client either way). Verified against mem9 source +
  public AWS Aurora docs (`rds-proxy-connecting.html`).
- **Chosen: RDS Proxy in front of Aurora; the DB password lives ONLY in AWS
  Secrets Manager with automatic rotation.** Flow:
  ```
  mnemo-server  --(static user+password from ECS `secrets: valueFrom`)-->  RDS Proxy
                                          RDS Proxy  --(Secrets Manager creds, TLS)-->  Aurora PG
  ```
  - The Aurora credential is generated (a static `RandomPassword`) + stored in a
    **Secrets Manager** secret by `sst.aws.Aurora` (the value never appears in
    git, the SST code, or the ECS task def as a literal). ⚠️ SST's `proxy: true`
    does **NOT** configure rotation (no `manageMasterUserPassword`, no rotation
    Lambda) → **automatic rotation is an Open item (#6)**. Launch posture =
    "secret not committed / not human-handled," not "auto-rotated."
  - RDS Proxy targets Aurora and reads that secret to authenticate; it also pools
    + multiplexes connections (good for `desiredCount=1` reconnpressure).
  - mem9's `MNEMO_DSN` points at the **proxy endpoint** and carries a user +
    password injected into the container via an ECS **`secrets: valueFrom`** (from
    Secrets Manager / SSM SecureString) at task start — resolved to an env var by
    ECS, **never a plaintext literal in the committed task def or repo.**
  - Not *literally* passwordless at the mem9 hop, but: the password is never
    committed, never human-handled, and rotates automatically — which satisfies
    the real intent (no static secret in code, IAM-governed access to the secret).
    The ECS task role gets `secretsmanager:GetSecretValue` on that one secret ARN.
- **Deferred (Open decision, not adopted):** true end-to-end IAM (no password at
  all) via either (a) a **token-refresh sidecar** minting a fresh RDS IAM token
  <15 min and reloading mem9, or (b) a **mem9 source patch** (pgx `BeforeConnect`
  + AWS auth-token generator). Both are more moving parts / a fork; revisit if the
  operator wants zero password even in Secrets Manager.
- **TLS**: RDS Proxy requires TLS for IAM client connections and uses ACM certs
  itself; the mnemo-server → proxy hop uses password auth over TLS (proxy has a
  managed cert; no cert to manage on our side). Set `sslmode=require` in `MNEMO_DSN`.

> **Customer-facing / public-AWS-only note.** This deployment is intended for
> customers and must use **only public AWS services**. Aurora + RDS Proxy +
> Secrets Manager are all public — compliant. ⚠️ The LLM smart-ingest path
> (§7) currently targets **Bedrock *Mantle***, which is an internal/preview
> surface — for a customer-facing build that must be revisited to the **public**
> `bedrock-runtime` Converse API (or an OpenAI-compatible public gateway). Tracked
> in Open decisions; does not affect the DB-auth decision here.

## 4. Compute: **ECS Fargate, arm64, single task**

- mnemo-server is a Go HTTP server (`:8080`), stateless for our usage → ECS
  Fargate long-lived service is the AWS-recommended host for a "sessionful/
  streaming" MCP-style server (vs Lambda for stateless bursts). Matches
  a sibling project's `ecs.ts` pattern.
- **arm64**: mem9's Makefile currently hardcodes `GOARCH=amd64`, but the build is
  `CGO_ENABLED=0` pure Go → rebuild with `GOARCH=arm64` + Docker
  `--platform=linux/arm64`. Zero code change. (Recorded in mem9-facts.md.)
- **`desiredCount=1`** (locked): single-operator, 逐条 add → single writer, no
  concurrent-write contention, and it sidesteps mem9's local-disk import dir
  (which assumes files live on one task's filesystem). If HA/multi-AZ is ever
  needed, revisit (drop batch-import, or move upload dir to S3 — source change).
- Task size start: 256 CPU / 512 MB (mnemo-server is light; Aurora does the work).
- ECR: own the repo **out-of-band** via a CloudFormation template +
  `scripts/deploy-ecr-repositories.sh` (a sibling project pattern) so
  `sst remove --stage pr-N` never wipes image history.

## 5. Networking: **reuse account default VPC** (Tokyo)

Per a sibling project `ecs.ts`: `aws.ec2.getVpc({ default: true })`, then filter to
**private subnets with a NAT route** for the Fargate task + Aurora. No dedicated
VPC (a V2 concern). Aurora in the same private subnets; SG allows 5432 from the
Fargate task SG only. mnemo-server reaches the embedding MaaS via NAT (or via a
VPC-internal endpoint if the embedding shim is in-VPC).

## 6. MCP surface + auth: **AgentCore Gateway + Cognito** (reuse the pattern)

Mirror a sibling project `gateway.ts` + `cognito.ts` + `api.ts`:

- **AgentCore Gateway** (MCP protocol) with an **OpenAPI target** whose schema
  maps MCP tools → mnemo-server's REST API (`/v1alpha2/mem9s/memories` add/
  search/get/update/delete). mnemo-server is already a REST server, so this is a
  schema-mapping job, not a Lambda rewrite. The target reaches mnemo-server
  **privately** (§6a) — no Lambda adapter needed.
- **Cognito M2M** user pool + resource server + app client(s); Gateway uses a
  Cognito OAuth credential provider. Inbound authorizer = JWT (Cognito issuer).
- **REQUEST interceptor Lambda** (scope ↔ tool authorization), as a sibling project
  does, if per-tool scoping is wanted (e.g. read-only vs write clients across
  devices).
- Clients (Claude Code on any machine) point at the Gateway URL with OAuth →
  globally reachable, no SSH tunnel, no exposed mnemo-server port.
- SSM parameter exports for Gateway URL / Cognito endpoints / client IDs
  (a sibling project convention: `/mem9-on-aws/${stage}/...`).

### 6a. Gateway → mnemo-server network path (RESOLVED — this was the one unknown)

**mnemo-server stays fully private; the Gateway reaches it over VPC Lattice, no
public exposure.** Verified against AWS docs — AgentCore Gateway OpenAPI/MCP
targets support a **`privateEndpoint` (managed VPC Lattice)** config that routes to
an in-VPC endpoint without the public internet. This is a **first-class,
documented** capability — the earlier worry ("must be public HTTPS") applies only
to certain integration points (e.g. AWS DevOps Agent, API Gateway *private
endpoint type*), NOT to Gateway's own private target egress.

Resolved path (all private, zero public):
```
Claude Code (any device)
  → AgentCore Gateway  [inbound: Cognito M2M JWT]
    → privateEndpoint { managedVpcResource: default-VPC, private subnets, SG }  (VPC Lattice)
      → internal ALB (HTTPS, PUBLIC ACM cert)     [outbound auth: API key = X-API-Key]
        → ECS Fargate mnemo-server (HTTP :8080, private subnet)
          → Aurora PG (private subnet)
```

Design rules pinned from the docs:
- **Managed Lattice** (`privateEndpoint.managedVpcResource`) — AgentCore creates &
  manages the Lattice resource gateway/config on our behalf; **no VPC Lattice IAM,
  SCP, or approval needed**, only standard EC2 perms + a service-linked role.
  Simplest for a single operator. (Self-managed Lattice = cross-account/governance,
  not needed.)
- **Internal ALB in front of mnemo-server** — required because *"VPC egress
  requires your target endpoint to have a publicly trusted TLS certificate"* (docs,
  verbatim). Lattice's TLS handshake to the target must trust the cert, and a
  private CA won't do → the ALB carries a **public ACM cert** and terminates TLS.
  The ALB is `internal` (not internet-facing); the public cert is only for TLS
  trust, not for public reachability.
- **Certificate + domain (LOCKED)**:
  - Public ACM cert for a **example.com subdomain**, e.g. `mem9.internal.example.com`.
  - The domain is **name-only**: it is the ACM cert subject and the Lattice
    request **TLS SNI** — it does **NOT** need public DNS resolution and does
    **NOT** point at the ALB. Actual routing uses Lattice `routingDomain` = the
    ALB's internal AWS DNS name (`internal-xxx.<region>.elb.amazonaws.com`). SNI
    (your domain) and routing (ALB AWS DNS) are decoupled — this is the documented
    flow.
  - **Route53 assumed** for `example.com` → ACM does automatic DNS validation
    (`sst.aws.Dns` / one CNAME). If the zone isn't in R53, add the ACM validation
    CNAME manually at the registrar (one-time).
- **ALB → mnemo-server = plain HTTP (LOCKED)**: the ALB terminates TLS with the
  public ACM cert, then forwards to mnemo-server over **HTTP :8080** inside the
  private subnets. mnemo-server needs **no cert of its own**. (The docs' HTTPS
  backend step assumes a backend that already has a private cert; ours is bare
  HTTP, which is fine intra-VPC.) The ALB HTTPS listener applies a host-header
  transform (`mem9.internal.example.com` → mnemo-server's internal host) per the docs.
- **Outbound auth = API key**, NOT SigV4. Docs: IAM/SigV4 outbound auth is only
  compatible with API Gateway / Lambda URL / AgentCore — **NOT ALB/EC2**. So the
  Gateway target uses an **API-key credential provider** carrying mnemo-server's
  `X-API-Key` (= the tenant id). Fits mem9's native auth exactly. (OAuth is the
  alternative if we ever front with something OAuth-capable.)

## 7. LLM + embedding supply (all LOCKED)

mem9 (PG backend) needs an OpenAI-compatible `/chat/completions` (smart-ingest LLM)
and an OpenAI-compatible `/embeddings`. Both are resolved below.

### LLM (smart-ingest) → **Bedrock Mantle, GLM-5, enabled at launch**

**Key finding (verified against AWS docs + a sibling project prod usage):** Amazon
**Bedrock Mantle** (`https://bedrock-mantle.{region}.api.aws/v1`) is a *native
OpenAI-compatible* endpoint. mem9's LLM client POSTs to `/chat/completions`, so:

- **smart-ingest = ON at launch, Mantle direct, NO LiteLLM/proxy.** Set
  `MNEMO_LLM_BASE_URL=https://bedrock-mantle.ap-northeast-1.api.aws/v1`,
  `MNEMO_LLM_MODEL=<GLM-5 model id>`, `MNEMO_INGEST_MODE=smart`, and
  `MNEMO_LLM_API_KEY=<a Bedrock bearer token>` (see auth below).
  → **First deploy must bring up Mantle auth + Bedrock Project together** (not a
  later add-on), since smart-ingest is on from day one.
- **Model = GLM-5** (Chat-Completions; verified in a sibling project prod on Mantle).
  **GPT-5.4 / 5.5 are Responses-API only → NOT usable by mem9.**
- **Auth = `@aws/bedrock-token-generator` (same as a sibling project), NOT a static key.**
  a sibling project uses `@aws/bedrock-token-generator@^1.1.0` to mint a **short-term
  Bedrock bearer token** from the task's IAM credentials (no long-lived API key to
  manage). Cost attribution = a **Bedrock Project** (`AWS::BedrockMantle::Project`,
  out-of-band CFN like a sibling project's `bedrock-mantle-project.yaml` +
  `deploy-mantle-project.sh`), passed as the `OpenAI-Project` header. Mantle does
  NOT support IAM-principal attribution (a sibling project verified), so the Project
  is how GLM-5 spend gets tagged.
- **Token-lifetime bridge (LOCKED — this is the one non-obvious wiring):** the
  bearer token from the generator is **short-lived and expires**, but mem9 reads a
  **static** `MNEMO_LLM_API_KEY` env var. So a **token-refresh sidecar** in the ECS
  task periodically mints a fresh bearer via `@aws/bedrock-token-generator` and
  writes it where mnemo-server reads it (a shared file the container re-reads, or a
  restart-free refresh mechanism), refreshing before expiry. **No mem9 source
  change.** (Detail + the exact refresh mechanism = an IaC-stage item; the approach
  is locked.)

### Embedding → **NOT Mantle** (Mantle has no `/embeddings`)

**Critical (verified):** Mantle only serves Chat Completions / Responses / Messages
— **there is NO `/embeddings` on Mantle.** Every Bedrock embedding model
(Titan V2, Cohere embed-v4, Nova MM) is available **only on `bedrock-runtime`**,
which is **not** OpenAI-compatible (it's InvokeModel). So embedding cannot come
from Mantle, and Bedrock's own embed models aren't OpenAI-shaped either.

**Decision (locked): write our own OpenAI-compatible `/embeddings` service running
qwen3.** mem9 points `MNEMO_EMBED_BASE_URL` at this service; it exposes the OpenAI
`POST /v1/embeddings` contract and computes vectors with **qwen3** (the same
open-weight embedding model a sibling project runs as ONNX). Rationale:

- Full data ownership — embeddings computed on our own code/infra, nothing leaves
  to OpenAI or a 3P embed API.
- **Code source (LOCKED): lift a sibling project's qwen3 ONNX embed code** into this repo
  (the ONNX model, eager-INIT, CJK handling; ref a sibling project memory
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
2. **qwen3-embed sidecar** — OpenAI `/v1/embeddings` on localhost (§7 embedding).
3. **token-refresh sidecar** — mints/refreshes the Bedrock bearer for Mantle
   (§7 LLM auth) so mnemo-server's `MNEMO_LLM_API_KEY` stays valid.

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

Mechanism — Open decision #3: one-shot ECS task on deploy vs. an init Lambda vs.
a documented manual step. Leaning one-shot ECS task run against Aurora.

## 9. Cost sketch (Tokyo, order-of-magnitude, verify at build)

| Component | Rough monthly |
|---|---|
| Aurora PG **Serverless v2** @ ~0.5 ACU floor (LOCKED) | ~$40–50 (largest line; scales with idle floor) |
| Fargate arm64 1 task (size depends on embed placement — see below) | ~$8–20 |
| qwen3 embedding: Lambda (b1) low volume ~$0–2, OR folded into the Fargate task (b2, sidecar) → task memory ↑ | see Fargate row |
| Bedrock Mantle (GLM-5 smart-ingest) | per-token, tiny at single-operator volume |
| **Internal ALB** (TLS termination for Lattice) | ~$16–20 (fixed; the price of the private Gateway→ECS path) |
| ACM public cert (`mem9.internal.example.com`) | **$0** (public ACM certs are free) |
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
| Container registry | ECR (out-of-band CFN) | a sibling project `cloudformation/ecr-repositories.yaml` |
| Compute | ECS Fargate service, arm64, count=1 | a sibling project `infra/ecs.ts` |
| Database | Aurora PostgreSQL Serverless v2 + pgvector | new (`infra/db.ts`) |
| Networking | default VPC private subnets + SGs | a sibling project `infra/ecs.ts` default-VPC lookup |
| MCP gateway | AgentCore Gateway (OpenAPI target + `privateEndpoint` managed Lattice, API-key outbound) | a sibling project `infra/gateway.ts` (adapt: private endpoint is new) |
| Private egress | AgentCore managed VPC Lattice (auto) + **internal ALB** (HTTPS→HTTP:8080, host-header transform) | new (`infra/gateway-egress.ts`) — no direct template (podcast fronts Lambda, not ECS) |
| TLS cert | **public ACM cert** `mem9.internal.example.com` (R53 DNS-validated; name-only, no public A record) | new (`infra/certs.ts`) |
| Auth | Cognito M2M pool + resource server | a sibling project `infra/cognito.ts` |
| Tool authz | REQUEST interceptor Lambda | a sibling project `infra/functions.ts` |
| Embedding | qwen3 OpenAI `/embeddings` as an **ECS sidecar** (lifted from a sibling project qwen3 ONNX), localhost, dims 1024 | a sibling project qwen3 ONNX code |
| LLM (smart-ingest) | **Bedrock Mantle direct**, **GLM-5**, ON at launch; auth via **`@aws/bedrock-token-generator`** + **token-refresh sidecar** + Bedrock Project | a sibling project (`@aws/bedrock-token-generator`, `bedrock-mantle-project.yaml`) + a sibling project `bedrock-mantle.ts` |
| Bedrock Project | `AWS::BedrockMantle::Project` for GLM-5 cost attribution (out-of-band CFN) | a sibling project `cloudformation/bedrock-mantle-project.yaml` + `deploy-mantle-project.sh` |
| Config | SST v4 `sst.config.ts` (Tokyo, Node 24) | a sibling project `sst.config.ts` |
| Cross-module wiring | SSM Parameter Store `/mem9-on-aws/${stage}/...` | both |

## Locked decisions (no longer open)

- **DB engine**: Aurora **PostgreSQL Serverless v2** + pgvector (not MySQL, not
  RDS t4g). Backend = mem9 `postgres`.
- **DB auth (§3a)**: **RDS Proxy + Secrets Manager**, NOT native IAM (mem9's
  static `MNEMO_DSN` / pgx-stdlib / no credential refresh can't handle the ~15-min
  IAM token). Aurora password lives only in Secrets Manager (static
  `RandomPassword` from `sst.aws.Aurora`; **rotation NOT configured by default —
  Open #6**); RDS Proxy fronts Aurora; mem9's `MNEMO_DSN` → proxy endpoint with a
  user+password injected via ECS `secrets: valueFrom` (never committed /
  human-handled). Task role gets `secretsmanager:GetSecretValue` on the one secret
  ARN. True end-to-end IAM deferred (sidecar or source patch) — see Open decisions.
- **Public-AWS-only (customer-facing)**: this deployment targets customers, so it
  must use **only public AWS services**. Aurora / RDS Proxy / Secrets Manager are
  public ✅. The **Bedrock Mantle** LLM path (§7) is internal/preview → flagged for
  revisit to public `bedrock-runtime` Converse before a customer build (Open #7).
- **Region**: ap-northeast-1 (Tokyo). **Compute**: ECS Fargate, arm64,
  `desiredCount=1`. **VPC**: reuse default VPC private subnets.
- **MCP + auth**: AgentCore Gateway + Cognito M2M (a sibling project pattern).
- **Gateway → mnemo-server**: **private** via AgentCore `privateEndpoint` +
  **managed VPC Lattice** → **internal ALB (public ACM cert, TLS terminated here)**
  → mnemo-server over HTTP:8080. Outbound auth = **API key** (`X-API-Key` = tenant
  id). ACM cert domain = a **example.com subdomain** (`mem9.internal.example.com`,
  name-only / no public DNS needed, R53-validated). No public exposure. (See §6a.)
- **LLM (smart-ingest)**: **Bedrock Mantle direct**, **GLM-5**, **ON at launch**
  (`MNEMO_INGEST_MODE=smart`). No proxy. GPT-5.4/5.5 (Responses-only) excluded.
  → first deploy must wire Mantle auth + Bedrock Project together.
- **Mantle auth**: **`@aws/bedrock-token-generator`** (same as a sibling project) mints a
  short-term bearer from the task IAM role; **Bedrock Project** for cost
  attribution. A **token-refresh sidecar** keeps `MNEMO_LLM_API_KEY` fresh (mem9
  reads static env; bearer expires) — no mem9 source change.
- **Embedding**: qwen3 OpenAI `/embeddings` as an **ECS sidecar** (localhost,
  always warm), **code lifted from a sibling project's qwen3 ONNX**, **dims 1024**. Not
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
6. **Secrets + rotation** — storage RESOLVED into the DB-auth lock (§3a): Aurora
   creds in a Secrets Manager secret (`sst.aws.Aurora` static `RandomPassword`),
   consumed by RDS Proxy + injected into the Fargate task via ECS `secrets:
   valueFrom`. **STILL OPEN: automatic rotation** — SST's `proxy: true` does NOT
   attach a rotation Lambda, so add a Secrets Manager rotation schedule + the RDS
   rotation Lambda (+ grant `secretsmanager:RotateSecret`) if rotation is wanted.
   (Mantle bearer is minted at runtime by the token sidecar, not a stored secret.)
   Also remaining: RDS Proxy `MaxConnectionsPercent` / pinning tuning for
   `desiredCount=1`.
7. **Public-AWS LLM path (customer-facing)** — the solution must use only public
   AWS services. §7's **Bedrock Mantle** smart-ingest is internal/preview → for a
   customer build, migrate the OpenAI-compatible `/chat/completions` LLM to the
   **public `bedrock-runtime` Converse API** (or a public OpenAI-compatible
   gateway) + a `bedrock:InvokeModel`-based auth. Does not affect DB/Aurora.
8. **True end-to-end IAM DB auth (deferred)** — reach zero-password by either a
   token-refresh sidecar (mints an RDS IAM token <15 min, reloads mem9) or a mem9
   source patch (pgx `BeforeConnect` + AWS auth-token generator). Not adopted;
   §3a's Secrets-Manager-rotation path is the launch choice.
