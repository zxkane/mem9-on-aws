# mem9 (`mnemo-server`) — Ground-truth facts

Probed directly from the `mem9-ai/mem9` source (server is Go, under `server/`).
Unless a different date is stated, source-level observations are **empirical
against upstream `5af03a6` plus the downstream patches and were rechecked 2026-09-15**. These are the
facts the current runtime in [`ARCHITECTURE.md`](ARCHITECTURE.md) relies on.
Re-verify them whenever the pinned commit changes.

## Identity & license

- Repo: `mem9-ai/mem9`. Server binary: `mnemo-server` (Go, `server/cmd/mnemo-server`).
- License: **Apache-2.0** (self-host, modify, commercial — all allowed).
- This deployment builds upstream source with downstream durability and namespace
  extensions. Its data remains in the operator-owned PostgreSQL database; hosted
  SaaS is not part of the request path.

## Runtime shape

- HTTP server on `MNEMO_PORT` (default **8080**). Preferred API surface
  `v1alpha2` with `X-API-Key` header; legacy `v1alpha1` puts tenant id in the URL.
- **`X-API-Key` value == tenant `id`** (server does `tenants.GetByID(apiKey)`).
  Provision a tenant via `POST /v1alpha1/mem9s` (no auth) → returns `{"id": ...}`.
  That id is the API key.
- Endpoints: `POST/GET/GET{id}/PUT{id}/DELETE{id} /v1alpha2/mem9s/memories`,
  batch-delete, `/imports`, `/session-messages`, `/status`, webhooks, space-chains.
- **Unauthenticated health/liveness (registered BEFORE the auth middleware,
  verified in `handler.go` at the current pin):** `GET /healthz` → 200 `{"status":"ok"}`
  and `GET /versionz` → 200 `{go_version,started_at}`. `/healthz` is **process
  liveness only**: it does not query the database, embedding sidecar, LLM proxy,
  or an end-to-end memory path, and must not be treated as dependency readiness.
  It is reachable unauthenticated for the ECS container health check.
- Search query param is `q` (`GET /v1alpha2/mem9s/memories?q=...`).
- Writes return `{"status":"accepted"}` and are processed **asynchronously** —
  list/search may remain empty until the ingest and index pipeline completes.

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
- **Consequence for IAM DB auth**: an RDS/Aurora IAM authentication token is
  [valid for 15 minutes](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/UsingWithRDS.IAMDBAuth.Connecting.html),
  but `MNEMO_DSN` is static. New pool connections would fail after the token
  expires, so native end-to-end IAM database auth is not viable for unmodified
  mem9.
- **Current implementation:** `mnemo-server` and the bootstrap task connect
  directly to the Aurora cluster writer endpoint with a static
  Secrets Manager password over TLS. **RDS Proxy is not deployed.** ECS injects
  the secret through a task-definition `secrets: valueFrom` reference at task
  startup; the literal does not appear in the task definition or repository.
  Per the
  [ECS execution-role documentation](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_execution_IAM_role.html),
  `secretsmanager:GetSecretValue` for that startup injection belongs to the task
  execution role, not the application task role.
- Automatic database credential rotation is not configured. Because both mem9
  and ECS consume startup-time values, a changed credential also requires a new
  task. End-to-end IAM auth remains a deferred alternative that would require a
  mem9 credential-refresh change.
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
  `ts_rank`. (English analyzer — note for CJK content, a known class of issue;
  may need config.)
- **`AutoVectorSearch` is NOT supported on PG** — explicit source fallback:
  "auto vector search not supported with PostgreSQL; use VectorSearch with
  pre-computed embeddings." (Auto-embed via `EMBED_TEXT` is TiDB-only.)
- Default schema (`server/schema_pg.sql`) ships `embedding vector(1536)` and
  `CREATE EXTENSION IF NOT EXISTS vector;`.

#### Metadata-only updates preserve embeddings (downstream patch 0012)

The unpatched upstream still discards the vector in `GetByID` and unconditionally
writes it in `UpdateOptimistic`. A tags/metadata-only PUT can therefore clear a
stored embedding. The PostgreSQL HTTP integration test reproduces this behavior
against the new pin before the fix.
Upstream PR #470 remains unmerged as of 2026-09-14.

`0012-preserve-postgres-update-embedding.patch` backports the PostgreSQL fix:
`scanMemory` hydrates the vector used by read-modify-write. Tags-only and
metadata-only PUTs preserve it without an embedding call. A content-bearing PUT
still re-embeds when an embedder is configured; without an embedder it clears the
old-content vector. `MNEMO_EMBED_AUTO_MODEL` remains unset for this PostgreSQL
deployment. Patch 0009 still enforces `If-Match`, including a raced write, and
namespace predicates still fence every update.

The real PostgreSQL HTTP test checks stored vectors, semantic recall after each
metadata update, 412 for a stale version, 404 for a foreign namespace, and content
updates with/without an embedder. This prevents new vector loss; it does not
repair vectors previously cleared. Cleanup/consolidation now use authorized,
namespace-bound SQL for state transitions and inactive records. REST mutations
use separately signed service identities and recheck membership inside the
actual mutation transaction.

### tidb backend (NOT viable on Aurora)

- Uses TiDB `VECTOR(N)` type, `VEC_COSINE_DISTANCE`, and optionally
  `EMBED_TEXT("tidbcloud_free/...", content)` GENERATED column for **server-side
  auto-embedding** (TiDB Cloud Serverless only). Vector index needs TiFlash.
- **None of `VECTOR`/`VEC_COSINE`/`EMBED_TEXT` exist in Aurora MySQL** → mem9's
  MySQL/tidb path cannot run on Aurora MySQL. This is why PG is chosen.

### Schema bootstrap contract

- Control-plane schema file `server/schema_pg.sql` ≠ the **tenant runtime schema**
  in `server/internal/tenant/schema.go`. The runtime validator requires `idx_app`;
  applying only the control-plane file is insufficient. **Bootstrap must apply the
  tenant runtime schema (idx_app, FTS, vector column at the right dims), not just
  the control-plane file.** Verify exact DDL from `tenant/schema.go` at build time.
- On the PG backend mem9 does NOT create the `memories` table at runtime — the
  `TenantMemorySchemaPostgres` constant has NO call site (only webhooks/usage get
  `EnsureSchema`); startup only _validates_ `app_id`+`idx_app`. **So our bootstrap
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
  `db_user`+`db_password` (the Aurora credentials from `MEM9_DB_SECRET`), NOT a
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
- Current implementation: a self-hosted **qwen3** sidecar produces 1024
  dimensions. **Pin model + dims before first ingest** — the vector column type
  and all stored vectors depend on it; changing dims = reindex.

## LLM (smart-ingest / MaaS)

- OpenAI-compatible `/chat/completions`. Env: `MNEMO_LLM_BASE_URL`,
  `MNEMO_LLM_MODEL` (default `gpt-4o-mini`), `MNEMO_LLM_API_KEY`.
- `MNEMO_INGEST_MODE` = `smart` (default, LLM extraction/reconciliation) or
  `raw`. **The nil-client downgrade is keyed on the API KEY, not the mode:**
  `llm.New()` returns `nil` iff `MNEMO_LLM_API_KEY == ""` (base-url alone defaults
  to `api.openai.com/v1`), and the ingest pipeline silently does raw whenever the
  client is nil — regardless of `MNEMO_INGEST_MODE`. So `smart` needs a **non-empty**
  `MNEMO_LLM_API_KEY` or it logs "no LLM configured, ingest will use raw mode" and
  downgrades. (Verified in `server/internal/llm/client.go` + `service/ingest.go`.)
- Startup also logs "no embedding configured, keyword-only search active" when no
  embedder is set → **without an embedding endpoint, PG backend does keyword-only
  (FTS), NO vector search.** So the embedding MaaS is required for semantic recall.

### Upstream refresh and request contracts (2026-09-14)

- The source pin advances from `d4638c8` to `5af03a6` (2026-08-25), 44 upstream
  commits including Recall budgets/partial responses (#445, #449), bounded list
  behavior, durable fact filtering (#370), and optional assistant extraction
  (#451). PostgreSQL schema, module dependencies, and the embedding/LLM clients
  are unchanged across these pins. Existing vectors stay 1024-dimensional and
  this refresh adds no database migration.
- Recall runs with a 20-second total server budget and a 2-second response
  reserve. The proxy has one 25-second deadline across all attempts, body reads,
  and backoff, shortened to Lambda remaining time minus one second when needed.
  The Lambda timeout remains 30 seconds. Terminal server 504s are not retried;
  successful `partial` and `warnings` fields pass through unchanged.
- `MNEMO_FACT_EXTRACTION_INCLUDE_ASSISTANT=false` is explicit in ECS. Patch 0013
  shares the constructor for the global durable worker and namespace-specific
  replacements, so both honor this setting. Enabling it requires a separate
  extraction-quality evaluation; the upgrade keeps user-only extraction.
- Upstream's durable-fact guards complement the coding-agent durability override
  in patch 0002. Patch 0014 preserves explicitly durable configuration and causal
  lessons containing operational phrases when durable-only mode is enabled;
  explicit transient fact types and plain session status are still rejected.
  The bounded formatter in patch 0003 remains active.
- The MCP smart-write smoke uses established configuration for an explicitly
  synthetic fixture project. The old one-off "e2e secret marker" input produced
  zero extracted facts despite a successful provider response under the new
  extraction policy. The smoke still sends only `content` (not `memory_type:
  pinned`) so it exercises the real LLM path, and its natural-language query
  remains free of the unique run marker.
- Patch 0014 threads request/branch contexts through cold-cache schema checks.
  A blocked connection acquisition cannot outlive the Recall deadline or caller
  cancellation; failed schema checks remain uncached.
- The upstream Agent9 external-provenance envelope is supported only on the
  existing synchronous ingest path. Durable `ingest-v1` does not serialize that
  contract, so async requests carrying it return 400 before reservation/enqueue
  rather than acknowledge and discard it. The MCP tools do not expose that field.
- `ListAllTypes` delegates to the namespace-scoped PostgreSQL list implementation;
  TiDB-specific list/FTS optimizations do not add a PostgreSQL search path. The
  reviewed SQL inventory is regenerated for the new source pin without new
  namespace exceptions.

### Enabled atomic durable ingest (downstream patches)

`0015-ingest-namespace-compatibility.patch` keeps admission compatible with the
database migration phase. An unscoped authenticated request uses the legacy
`(tenant_id, idempotency_key)` conflict target while the additive schema is
active. A scoped request uses `(tenant_id, namespace_id, idempotency_key)`;
neither path falls back when its matching index is absent. Both immutable SQL
variants appear in the reviewed query inventory. The integration suite exercises
additive, enforced, and partially indexed schemas, and the deployed MCP smoke
requires transcript enqueue, idempotent replay, and a succeeded job even when
ordinary search checks are configured soft. Existing migration procedures must
still keep writers stopped through namespace cutover.

- The ordered downstream stack is
  `0001-recall-min-confidence-tunables-and-zero-result-fallback`,
  `0002-ingest-durable-only-extraction-filter`, `0003-glm-request-bounds`,
  `0004-durable-ingest-queue`, `0005-atomic-ingest-apply`,
  `0006-durable-ingest-telemetry`, `0007-postgres-session-delete`,
  `0008-ingest-prescreen-shadow`, `0009-if-match-precondition-fence`,
  `0010-group-memory-namespaces`, `0011-stabilize-ingest-deadline-test`,
  `0012-preserve-postgres-update-embedding`, and
  `0013-upstream-durable-compatibility`, and
  `0014-recall-schema-budget-and-durable-facts`, and
  `0015-ingest-namespace-compatibility`, and
  `0016-namespace-vector-late-hydration`, and
  `0017-namespace-lifecycle-fencing`,
  `0018-service-maintenance-namespaces`, and
  `0019-namespace-sampler`, `0020-namespace-performance-gates`, and
  `0021-namespace-connection-attribution`. The Docker build applies the complete stack to
  the pinned upstream commit in lexical order.
- Patch `0021` adds the fixed low-cardinality
  `application_name=mem9-server-tenant` parameter to PostgreSQL per-tenant
  DSNs. The container entrypoint independently labels the control-plane pool
  `mem9-server-control`. These labels are for bounded connection attribution;
  they contain no user, namespace, memory, or request identifier.
- Upstream asynchronous `messages[]` ingest returns 202 before starting an
  untracked goroutine. Downstream patch
  `docker/mnemo-server/patches/0004-durable-ingest-queue.patch` adds a
  tenant-database queue repository, canonical `ingest-v1` envelopes, leases,
  retries, and an injected plan/apply worker contract.
- Patch `docker/mnemo-server/patches/0005-atomic-ingest-apply.patch` supplies the
  PostgreSQL processor and worker, immutable plan revisions, explicit memory
  versions, one-transaction apply, and tenant-scoped job status. The server
  entrypoint applies the repeatable migration before process startup, so CI uses
  one enabled rollout and runs the complete bootstrap afterward. ECS injects
  the stable tenant identity. The old untracked transcript goroutine is no
  longer used when durable routing is enabled.
- Patch `docker/mnemo-server/patches/0006-durable-ingest-telemetry.patch` emits
  content-free CloudWatch EMF for committed accepted, retry, success, and dead
  transitions plus queue age, sampler heartbeat, and phase durations. The
  heartbeat is written before each immediate/once-per-minute queue-age query,
  including failed queries, and uses only the stage dimension. Other metrics
  use only stage and bounded result/error dimensions; plan duration measures
  application work and is not a Mantle/provider latency. Lifecycle EMF is
  post-commit best effort, not an accounting ledger; Aurora and the
  tenant-scoped status API remain authoritative if a crash or log-write failure
  omits a metric. Queue-age absence remains non-breaching, while five
  current missing one-minute heartbeats, filled as zero by metric math, breach
  the actionless raw liveness alarm without reuse of older healthy samples. A
  composite releases its ALARM notification after a fixed five-minute
  initial/rollout wait if real ECS-origin heartbeat extraction does not recover;
  it omits an OK action so recovery during suppression cannot notify alone.
- Patch `docker/mnemo-server/patches/0008-ingest-prescreen-shadow.patch` scores
  each smart-ingest candidate immediately before planning with the pure,
  versioned `msg-count-le-1-v1` policy. Exactly one message is `would-skip`;
  two or more messages are pass-through. The decision is persisted in the
  immutable plan only when a configured LLM runs the smart extraction path;
  raw mode and the existing nil-LLM raw fallback are not eligible samples. The
  decision never controls planning, extraction, reconciliation, embedding, or
  apply. Recovery reuses the persisted decision.
- After a successful real extraction/apply outcome, patch `0008` emits
  `PrescreenEvaluated`, `PrescreenWouldSkip`, and `PrescreenFalseSkip` through
  the existing best-effort EMF stream. A false skip means `would-skip` and the
  real plan produced facts. These counters use only `stage` and the bounded
  `policy_version`; they contain no content, identifier, hash, measured length,
  or lexical match. The dashboard divides would-skip and false-skip by evaluated
  beside `ZeroFactSuccess`. No alarm or `ZeroFactSuccess` definition changes.
- Startup and bootstrap apply the repeatable `ingest_jobs` migration inside the
  same operator-owned Aurora database. Canonical payloads and plans are not sent
  to logs, metrics, or another service. Canonical envelopes are rejected above
  1,048,576 bytes before enqueue, with a matching database constraint.
- Enqueue and claim serialize each tenant/agent/app/session scope with a
  transaction advisory lock. Claim traverses a fixed high-water boundary in
  bounded candidate pages, nonblockingly tries scope locks before any row lock,
  locks only the exact FIFO head, and terminalizes at most one exhausted head
  per transaction. A row-locked head cannot expose its follower or block an
  eligible scope later in the page. The claim attempt count fences every
  processing write; each terminal reclaim rotates a claim-specific owner token
  to fence stale callbacks even when ECS workers share one configured identity.
  Lease/retry decisions use PostgreSQL's statement clock rather than the worker
  process clock.
- Advisory-key collisions can only serialize unrelated scopes in the same
  tenant database; they cannot weaken FIFO or expose rows. If multiple tenant
  IDs ever share one database, this becomes a liveness-only cross-tenant risk
  that must be revisited before enablement.
- Extraction, reconciliation, existing-memory reads, and embedding calls happen
  before the 15-second apply transaction. Raw-session upserts, tag patches,
  memory actions, plan completion, and job success commit or roll back together.
  Runtime-usage reservation correlation is stored on the job, retained across
  retries, and refreshed before processing when provider expiry cannot cover
  the full attempt. Terminal success/failure retains a recoverable finalization
  lease until the idempotent runtime-usage outbox handoff completes. Other
  metering and webhook work runs after commit as best effort and cannot move a
  succeeded job back to failed.
- At most the first 50 extracted facts and 50 deterministic actions are retained.
  ADD IDs derive from the job, plan revision, and action index; UPDATE/DELETE use
  monotonic memory-version predicates. Recovery reuses a valid persisted plan or
  creates a bounded replacement revision after an optimistic conflict.

### Enabled Cognito group-routed team namespaces (downstream patch 0010)

- One PostgreSQL database and one mem9 tenant are shared by all small teams.
  Isolation is a required `namespace_id` data-plane key, not a per-user
  database, schema, server, or embedding service.
- Gateway identity is split across two Lambdas. A non-VPC interceptor validates
  JWT signatures independently against configured issuer/JWKS metadata, then checks
  the deployed human/M2M client registry, access-token shape, OAuth scope, and
  bounded Cognito groups, then signs derived lookup keys. The VPC target verifies
  that request-bound context and creates a different signed transport envelope
  for mnemo-server. Neither caller-supplied namespace IDs nor bare derived
  headers are trusted.
- Interceptor verification uses a pinned asymmetric algorithm allowlist and
  requires token expiry. JWKS retrieval is HTTPS-only, has a 2.5-second deadline
  and 64 KiB ceiling, never follows token key URLs, and refreshes its cache at
  least every five minutes of use. Unknown-key refreshes are rate-limited.
  Failures return a generic denial before an internal context can be minted.
  Signature verification does not replace separate IAM invocation confinement.
- For humans, Cognito group claims establish eligibility only. Aurora
  `memory_namespace_memberships` remains the active role/revocation source. A
  request must match exactly one configured group binding; unrelated groups are
  ignored, multiple recognized groups fail closed, and JIT never reactivates a
  revoked membership or creates a second active human namespace.
- M2M access uses an explicit client-key binding, principal, and matching active
  membership. Gateway `allowedClients` admission alone grants no memory access.
- Patch 0010 carries namespace and actor identity through memory CRUD, exact
  vector/FTS search, sessions, ingest canonicalization, queue rows, plans,
  claims, status, reconciliation, and atomic apply. Foreign object/job IDs are
  scoped to the caller namespace and appear not found.
- Namespace vector recall does not post-filter tenant-wide HNSW candidates.
  Patch 0016 materializes namespace-local IDs/distances, selects top-K, then
  hydrates full records with the same namespace/filter predicates. This keeps
  ordinary B-tree hydration available without approximate candidate selection.
  One read-only repeatable-read transaction still enforces
  `MNEMO_NAMESPACE_EXACT_VECTOR_MAX_ROWS`, applies a local statement timeout,
  and exactly orders cosine distance. Enforcement drops the old tenant-wide
  HNSW index.
- Startup with `MNEMO_NAMESPACE_REQUIRED=1` requires database phase
  `constraints_complete`; unset/`0` is compatibility mode for the initial
  additive deployment. There is no fallback to a default namespace in required
  mode.
- The mnemo entrypoint applies the complete base schema before additive
  migrations `001` and `002`, so a fresh empty database has its base tables
  before namespace columns are added. Bootstrap repeats the idempotent schema
  and seeds the tenant. Namespace data-plane indexes are not built at startup.
- The private operator task runs guarded preflight, freeze, catalog-verified
  concurrent index creation, embedding-preserving direct-SQL backfill, and
  `003_enforce_memory_namespaces.sql`. Backfill stores an immutable legacy seed
  binding and compares a bounded database-side ordered digest plus
  null/zero-vector counts before and after; any mismatch fails.
- A fresh `pr-N` preview needs no production namespace or user input. Bootstrap
  creates two synthetic namespace/group definitions and temporary M2M bindings
  in that stage's shared database, completes the empty-database migration, and
  CI redeploys with required mode before running a hard cross-namespace Gateway
  test. This validates the deployed M2M path; human group-token routing remains
  a separate Gateway-smoke surface.
- A later run whose deployed task carries the namespace-bootstrap version
  marker invokes that task before deployment and then uses required mode
  directly. A legacy preview task without the marker receives one compatibility
  deployment first. This is necessary because compatibility startup accepts only
  `additive_ready`, while a completed preview database remains
  `constraints_complete`.
- The migration command does not drain or scale ECS. Production cutover must
  stop write-capable traffic and scale mnemo-server to zero before `freeze`.
  Cleanup approval, upload processing, webhooks, and Space Chains remain disabled.
  Scoped cleanup/consolidation require explicit service membership and one
  namespace; scheduling additionally requires an explicit private target list.

### Scoped maintenance and service capabilities (patches 0018 and 0019)

- Consolidation reports and scheduled children use the same process watchdog.
  Single mode always reports without applying or writing digest state. Each
  namespace has a configurable fixed execution budget (two hours by default,
  60 seconds to six hours), distinct from the operator's twelve-hour observation
  default. Allowlisted phase/count/time records and a parent heartbeat expose
  activity without identifiers or content; progress does not extend the budget.

- Patch `0018-service-maintenance-namespaces` adds separately signed service
  transport for the fixed `maintenance:cleanup`, `maintenance:consolidation`,
  and `maintenance:analysis` capabilities. Their principal keys are derived
  from `sha256("mem9-service-principal-v1\0" + service)`. Credentials are
  separate from Gateway credentials and from one another. An envelope binds one
  explicit namespace, method, URI, and body; it cannot select a human/M2M
  principal or another service. There is no service JIT enrollment.
- The approved service REST subset is exactly `GET /v1alpha2/mem9s/memories`,
  `GET`, `PUT`, or `DELETE /v1alpha2/mem9s/memories/{memory-id}`, and
  `POST /v1alpha2/mem9s/memories/batch-delete`, subject to the active membership's
  role. Collection POST for memory creation or transcript ingestion is denied,
  including its synchronous variant. Session APIs, ingest-job routes, legacy
  API paths, and raw-session fallback through memory IDs are also denied.
  Maintenance credentials cannot submit work through the ingestion/session
  paths; human/M2M ingestion remains a separate authorization contract.
- The namespace, service principal, and service membership must be active.
  REST mutations recheck authorization inside the mutation transaction.
  Direct database adapters authenticate through trusted operator/task database
  credentials and authorize their fixed service in the same transaction as
  the query. Cleanup/consolidation writes use member access; analysis is a
  viewer. Namespace selection does not itself grant access.
- `scripts/manage-memory-services.mjs` manages only cleanup, consolidation,
  and analysis. The existing private namespace task exposes `service-enable`,
  `service-disable`, and `service-show` for an owner-only JSON file containing
  exactly `namespace_id` and `service`. Operators cannot choose a principal
  ID. Membership enablement does not revive a disabled principal or namespace.
- Cleanup lists and restores only the selected namespace. Its successor
  projection binds both the memory and winner aliases and redacts a foreign
  successor ID. Archive/restore contradiction safeguards remain: an archived
  row or retained successor link requires explicit force, and restore preserves
  the link, version, and embedding. Consolidation fences both loser and winner
  aliases, and its archive/stale transitions record the authenticated actor.
- Decision and report artifacts carry stage/namespace identity and belong in
  owner-only files. JSON ID selections are checked against that binding; plain
  ID lists remain limited to the invocation's authorized namespace. Apply
  mutexes and digest keys include both stage and
  namespace. Scheduled digest state uses
  `consolidation-digests/<stage>/<namespace-id>/current-v1.json`; console events
  contain bounded kinds and counters, without memory IDs or snippets. Slack
  digest delivery, approval, and cleanup scans remain disabled, as do upload
  processing, webhooks, and Space Chains without their own namespace contract.
- The shared cleanup/consolidation tasks default to report-only. Scheduling
  needs a nonempty private target list in the stage-scoped SST secret
  `MaintenanceNamespaceIds` and an explicit production opt-in through repository
  variable `MEM9_NAMESPACE_CONSOLIDATION_SCHEDULE_ENABLED`. Infra CI maps that
  variable to its internal consolidation schedule environment setting; the
  old repository flag alone does not activate it. The dispatcher runs one
  namespace per child and reports independent failures without sharing scope.
- Patch `0019-namespace-sampler` binds every queue-age read to an explicit
  namespace and the fixed internal sampler principal, derived from
  `sha256("mem9-service-principal-v1\0sampler")`. It requires an active service
  membership and has no REST signing capability. Startup initializes missing
  sampler viewer grants only after phase validation; Node reconciliation does
  the same for new namespaces. Both use `ON CONFLICT DO NOTHING` and preserve
  revoked memberships and disabled principals.
- The sampler coordinator enumerates active namespace metadata and publishes
  only the maximum of a complete successful sample set, with stage as its sole
  metric dimension. Any partial failure suppresses the aggregate. Until the
  database phase is `constraints_complete`, it fails sampling with bounded
  `namespace_not_enforced` output rather than publishing a false healthy zero
  over a legacy NULL-namespace queue. Heartbeat continues independently; no
  tenant-wide age query or compatibility authorization bypass is introduced.
- Prescreen analysis uses the fixed analysis service key and checks its active
  namespace membership before any payload query. Authorization and evaluation
  share a repeatable-read, read-only snapshot. A supplied principal ID cannot
  substitute for that service; all output remains bounded and content-free.
- The reviewed SQL inventory includes full statically resolved JavaScript
  projections and each scoped alias. Its AST extractor never evaluates source
  code, and unresolved relations fail closed. Cleanup/consolidation have no
  owner-wide disabled-capability exemption. PostgreSQL fixtures exercise
  foreign winner/restore IDs, disabled services, and populated A/B analysis;
  sampler fixtures also cover legacy NULL-namespace backlog before cutover.
- The operator-only maintenance preview runner reuses the human deployment
  manifest and runs nine named cases over owned synthetic memories: own GET/PUT,
  foreign HTTP absence, wrong key/issuer/principal, namespace tampering,
  isolated membership revocation, foreign SQL invariance, and owned cleanup.
  Its private journal pins fixture ownership and the exact membership change;
  cleanup-only recovery cannot claim acceptance. These mutation tests are
  separate from the report-only ECS cleanup/consolidation launchers.

### `If-Match` is a FENCE, not a warning (downstream patch 0009, issue #128)

**Upstream at the pinned commit:** `PUT /v1alpha2/mem9s/memories/{id}` read
`If-Match` as an HTTP **header** (`r.Header.Get("If-Match")`, not a body field),
discarded the `strconv.Atoi` error, and on a version mismatch only logged
`"version conflict, applying LWW"` before applying the write anyway.
`service/memory.go Update` then called `UpdateOptimistic(ctx, current, 0)` —
hardcoding `0`, which **disabled** the `AND version = $N` predicate the
postgres/tidb/db9 repositories already implemented.

**Downstream patch `docker/mnemo-server/patches/0009-if-match-precondition-fence.patch`:**

- `ifMatch` is threaded into `UpdateOptimistic` as the expected version, so the
  predicate rides in the **same** `UPDATE ... WHERE id = $ AND version = $N`
  statement that writes the content. Being one statement, it cannot silently
  overwrite: either the content lands or the caller gets 412.
  Precisely: `Update` is pre-read → cheap version compare → embed → predicated
  `UPDATE`. There are two checks, and the window between them is real — that is
  why the `ErrNotFound`→412 remap below has to exist. The pre-read compare is
  only an optimisation that saves an embedding call; the _predicate_ is what
  makes the write safe. So the race is closed with respect to silent overwrite,
  which is the guarantee issue #128 needed, and it is closed rather than
  narrowed because no interleaving can make the `UPDATE` clobber a newer row.
- A mismatch detected on the pre-read returns the new sentinel
  `domain.ErrPreconditionFailed` → HTTP **412**, before the embedder runs, so a
  rejected write costs no embedding call. It is deliberately distinct from
  `ErrConflict` (→ 409, "the LLM merge replaced LWW") so a fenced caller can
  tell "not applied" from "applied differently".
- Losing the predicate race surfaces from the repository as `ErrNotFound` (zero
  affected rows). With `ifMatch > 0` that is reported as 412, never as 404 — the
  row existed at read time.
- An unparsable or non-positive `If-Match` is now a **400**, not a silent `0`.
  Discarding the parse error would disable the fence at exactly the moment a
  client believed it was fenced.
- **Blast radius:** requests that send no `If-Match` keep last-writer-wins
  semantics (`ifMatch = 0` → no predicate), pinned by
  `TestUpdateWithoutIfMatchRemainsLastWriterWins`. There are four
  `MemoryService.Update` callers post-patch, and they split two ways:
  - The two ingest-internal ones (`handler/memory.go:727` metadata merge in
    `ingestMessages`, `:775` tag merge in `createSmartContentWithRouting`) pass a
    literal `0`, so smart-ingest is unaffected. The MCP surface is this repo's
    own proxy Lambda (`infra/gateway/`), not an upstream Go package — it issues
    only POST/GET and never sends `If-Match`, so it is unaffected too.
  - Both PUT handler branches pass the parsed `ifMatch` and are therefore fenced
    identically: the normal one (`:1430`) and the **Space Chain** branch
    (`:1379`, `auth.IsChain()`, routed through `target.svc.memory`). A chain
    client sending `If-Match` now gets 412 on a mismatch and 400 on a malformed
    header. That is intended — the whole point is that the header means what it
    says for every caller — but note the chain routing itself is not covered by
    the patch's tests, which exercise the service layer and the non-chain handler.
- The rewrite stays a content-bearing REST PUT, so upstream still re-embeds and
  the survivor's embedding matches its new content. This is why the fix went
  upstream instead of into a direct-SQL rewrite — see the content-free-`PUT`
  section above for the stale-embedding trap that alternative would have hit,
  and it needs no security-group change for the embedder port.
- Callers: `scripts/memory-cleanup.mjs` (CLI) and
  `scripts/memory-consolidation.mjs` (scheduled task) share
  `applyMergeDecision`; both treat 412 as "skip this merge, increment
  `skippedLww`, leave the absorbed ids active" and let any other non-2xx abort.
  The 412→null translation lives in each script's own REST adapter, so both are
  tested: TC-MEMCLEAN-042/043 through a fake HTTP layer, TC-CONSOL-049 through
  `createProductionDeps`.
- **Known divergence from upstream's own e2e suite:** upstream
  `e2e/api-smoke-test-round2.sh` test 6 asserts that a stale `If-Match` returns
  **200** ("LWW semantics"), and `e2e/AGENTS.md` documents that contract. Against
  a 0009-patched server it returns 412. The script is not applied, copied into
  the image, or in the Dockerfile's gating test set, so nothing here runs it —
  left unpatched deliberately, since a hunk against a file we never execute would
  only add drift risk at the next `MEM9_REF` bump. Expect that test to fail if
  the upstream suite is ever pointed at our image.
- Upstream's dashboard also sends the header
  (`dashboard/app/src/api/provider-http.ts:325`,
  `if (version !== undefined) headers["If-Match"] = String(version)`), so it
  would see 412s against a patched server. This repo does not build or deploy
  the dashboard, so nothing changes today — noted for whoever bumps `MEM9_REF`
  or ever serves that dashboard from this image.

### LLM key is read ONCE at startup, immutable — decisive for the sidecar (verified 2026-07-12)

Probed at the pinned commit (`server/internal/config/config.go` + `llm/client.go`):

- `MNEMO_LLM_API_KEY` / `_BASE_URL` / `_MODEL` are read **once** in `config.Load()`
  (called once in `main`) and copied into an **immutable `Client` struct field**
  (`apiKey`/`baseURL`/`model`). **NO reload path** — no SIGHUP handler (only
  SIGINT/SIGTERM for shutdown), no file watch, no periodic re-read, no setter.
  Rotating the key requires a **process restart**.
- The LLM client is **hand-rolled `net/http`** (NOT go-openai/sashabaranov). Its
  `doRequest` sets **only** `Content-Type` + `Authorization: Bearer <apiKey>` and
  POSTs to `{baseURL}/chat/completions`. There is **no hook to add extra headers**
  → mem9 **cannot** emit the `OpenAI-Project` header Bedrock Mantle needs for cost
  attribution.
- **Consequence (design pivot from the original §7):** a token-refresh sidecar that
  rewrites a shared file/env for mem9 to re-read **cannot work** (mem9 never
  re-reads), and mem9 can't tag Mantle spend. Both are solved WITHOUT a mem9 fork by
  a **local LLM proxy sidecar** (`docker/llm-proxy/`): mem9 points
  `MNEMO_LLM_BASE_URL=http://localhost:8082/v1` with a **static dummy**
  `MNEMO_LLM_API_KEY`; the proxy holds the live Mantle bearer (minted by
  `@aws/bedrock-token-generator` — a **local SigV4 presign, 12h TTL**, refreshed on
  a timer) and injects a fresh `Authorization` per request. It adds
  `OpenAI-Project` when `MEM9_BEDROCK_PROJECT` is configured. See
  [`ARCHITECTURE.md`](ARCHITECTURE.md) and `docker/llm-proxy/server.mjs`.
- **Provider-boundary limits (patched locally):** the proxy reads at most
  **1,048,576 bytes**, validates chat-completions JSON before forwarding, defaults
  missing `max_tokens` to **4096**, and rejects invalid or larger explicit values.
  The patched formatter caps the conversation at **200,000 runes** through
  `MNEMO_MAX_EXTRACTION_CONVERSATION_RUNES`; a real-formatter regression test uses
  four-byte Unicode to prove the final serialized request remains below the byte
  cap. ECS injects all three values explicitly.

## Bedrock Mantle facts (for the LLM/embedding decision)

These notes describe AWS documentation and the repository integration.
Model/region smoke tests must use synthetic requests; operator invocation
records and workload measurements remain private.
- **Mantle IS OpenAI-compatible.** Endpoint `https://bedrock-mantle.{region}.api.aws/v1`;
  surfaces = **Chat Completions** + **Responses** (OpenAI-compatible) + **Messages**
  (Anthropic). "Bring OpenAI SDK code by changing only base URL + API key."
- **mem9 speaks `/chat/completions`** to the local proxy. The proxy can translate
  configured model prefixes to the Responses API. Verify model availability
  for the selected route and region using the AWS documentation.
- **Mantle has NO `/embeddings`.** All Bedrock embedding models (Titan Text V2,
  Cohere embed-v4, Nova MM) are **`bedrock-runtime` ONLY**, and bedrock-runtime is
  **not** OpenAI-compatible for embeddings (it's InvokeModel). → embedding must be
  our own OpenAI-shaped `/embeddings` service (decided: qwen3, dims 1024).
- **Auth**: AWS documents API-key or AWS-credential authentication for
  [Mantle Chat Completions](https://docs.aws.amazon.com/bedrock/latest/userguide/inference-chat-completions-mantle.html).
  Its
  [API key documentation](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html)
  documents the 12-hour maximum and token generator for short-term keys.
- **Project attribution**: when `MEM9_BEDROCK_PROJECT` is configured, `llm-proxy`
  sends its value in `OpenAI-Project`, the header AWS documents for
  OpenAI-compatible project requests. Without that setting, the proxy omits the
  header and inference remains untagged:
  [Bedrock projects and workspaces](https://docs.aws.amazon.com/bedrock/latest/userguide/workspaces.html).
- **CloudWatch metrics**: AWS documents `Inferences`,
  `InferenceClientErrors`, `TotalInputTokens`, and `TotalOutputTokens` in the
  `AWS/BedrockMantle` namespace at Project granularity. It also explicitly
  states that Mantle does not yet publish `InvocationLatency` or
  `TimeToFirstToken` equivalents:
  [Bedrock Mantle CloudWatch metrics](https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-mantle-metrics.html).
- **IAM namespace**: current task-role permissions are
  `bedrock-mantle:CreateInference`, `bedrock-mantle:CallWithBearerToken`,
  `bedrock-mantle:GetProject`, `bedrock-mantle:ListProjects`, and
  `bedrock-mantle:ListTagsForResource`. Mantle inference does not use the
  `bedrock:*` action namespace. See the
  [Mantle service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_bedrock-mantle.html)
  and the
  [Bedrock tagging documentation](https://docs.aws.amazon.com/bedrock/latest/userguide/tagging.html).

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

### Packaging: no release/tag/public image → we PIN a source SHA (rechecked 2026-09-14)

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
  **multi-stage** build — `golang:1.27-alpine3.24` builder git-fetches the pinned
  commit, `CGO_ENABLED=0 GOARCH=arm64 go build ./cmd/mnemo-server`, into
  `alpine:3.24` — so CI needs only Docker (no host Go, no separate mem9
  checkout). Built for **arm64** (Graviton Fargate) via `docker buildx
--platform=linux/arm64`.
- **Vendored pin (LOCKED): `mem9-ai/mem9` @ `5af03a68c072651e9c64d1b8b1265e36b7354671`**
  (main tip as checked 2026-09-14, committed 2026-08-25). It is the `MEM9_REF` build-arg default in the
  Dockerfile. **Bumping the pin = change `MEM9_REF` + re-verify every fact in
  this file against the new tree** (schema, config env vars, DB driver path).
- **Entrypoint (`docker/mnemo-server/entrypoint.sh`)** bridges the static-DSN
  constraint (see "DB connection mechanism"): mem9 reads one static `MNEMO_DSN`
  and can't compose it from parts, and the DB password is a runtime secret
  (Secrets Manager → ECS `secrets: valueFrom`), so the entrypoint assembles
  `MNEMO_DSN=postgres://<user>:<url-encoded-pw>@<host>:<port>/<db>?sslmode=require&application_name=mem9-server-control`
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

## AWS facts and infrastructure configuration

- The current IaC provisions Aurora PostgreSQL 17.4 Serverless v2 and applies
  `CREATE EXTENSION vector` in the bootstrap task.
- AWS documents the Aurora cluster endpoint as the endpoint for the current
  primary and recommends it for writes:
  [Aurora cluster endpoints](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Aurora.Endpoints.Cluster.html).
- The ECS stack consumes the account default VPC through
  `aws.ec2.getVpc({ default: true })` and selects the NAT-routed private subnets.
- `infra/vpc.ts` selects private subnets by the `private-1*` Name tag. Operators
  must provide the required networking in their chosen application region;
  actual subnet inventories remain private.
- RDS Proxy is absent from the current architecture. mem9 and bootstrap connect
  directly to the Aurora cluster writer endpoint.

### AgentCore Gateway private egress to VPC — Lambda-proxy (the VPC-Lattice path was abandoned)

**Current implementation:** a **Lambda target**. AgentCore invokes a VPC-attached
proxy Lambda (`targetConfiguration.mcp.lambda.{lambdaArn, toolSchema}`) that reaches
mnemo-server over **AWS Cloud Map** private DNS (`mnemo.mem9-<stage>.local:8080`),
injecting `X-API-Key` (= tenant id). This private backend path has no ALB, ACM
certificate, VPC Lattice, public Route 53 zone, or public server endpoint. The
optional ACM certificate and DNS-only Cloudflare records for the public OAuth
facade custom domain are separate from this path. The Cloud Map private DNS
namespace creates a VPC-associated Route 53 private hosted zone, as documented
by [CreatePrivateDnsNamespace](https://docs.aws.amazon.com/cloud-map/latest/api/API_CreatePrivateDnsNamespace.html).
The target shape follows the
[AgentCore Lambda target documentation](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-add-target-api-target-config.html).
The gateway service role grants only `lambda:InvokeFunction` on that target, as
specified by the
[AgentCore Gateway permissions documentation](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-prerequisites-permissions.html).
The function uses
[Lambda VPC connectivity](https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html)
to reach Cloud Map and mnemo-server.

**Alternative — OpenAPI/MCP target with `privateEndpoint` (VPC Lattice):**
this is outside the current implementation. The repository uses the Lambda
target and private Cloud Map path described above. Keep operator-specific
deployment experiments and diagnostics in private records.
