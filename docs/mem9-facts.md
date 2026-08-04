# mem9 (`mnemo-server`) — Ground-truth facts

Probed directly from the `mem9-ai/mem9` source (server is Go, under `server/`).
Unless a different date is stated, source-level observations are **empirical
against the pinned upstream commit and were rechecked 2026-07-24**. These are the
facts the current runtime in [`ARCHITECTURE.md`](ARCHITECTURE.md) relies on.
Re-verify them whenever the pinned commit changes.

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
- **Unauthenticated health/liveness (registered BEFORE the auth middleware,
  verified handler.go:205 @ pinned SHA):** `GET /healthz` → 200 `{"status":"ok"}`
  and `GET /versionz` → 200 `{go_version,started_at}`. `/healthz` is **process
  liveness only**: it does not query the database, embedding sidecar, LLM proxy,
  or an end-to-end memory path, and must not be treated as dependency readiness.
  It is reachable unauthenticated for the ECS container health check.
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

#### A content-free `PUT` NULLS the embedding on postgres (probed in prod 2026-08-03)
**Decisive for any tool that updates tags/metadata without changing content.**

`PUT /v1alpha2/mem9s/memories/{id}` is not a partial update at the storage layer:

- `service/memory.go` re-embeds **only** when the request changes `content`, and
  the full guard is `contentChanged && s.autoModel == "" && s.embedder != nil`.
  We rely on `autoModel` being empty: `MNEMO_EMBED_AUTO_MODEL` is never set in
  `infra/ecs.ts`, so the condition holds in production. Setting it would silently
  stop re-embedding on content change, which is what makes the content-bearing
  MERGE rewrite safe — treat it as load-bearing config, not a tuning knob.
- `repository/postgres/memory.go` `UpdateOptimistic` writes `embedding = $4`
  **unconditionally**, from the in-memory row.
- `scanMemory`/`scanMemoryRows` on the **postgres** path scan the embedding column
  into a discarded local and **never assign `m.Embedding`** (the TiDB path does).
  So the read-modify-write round-trips `nil` → `embedding = NULL`.

Verified against prod: a probe memory that ranked **first** for its own topic
became permanently unfindable by semantic search after a tags-only `PUT`, while
`GET` still returned it `state=active` with the new tag and `version` bumped.
`VectorSearch` filters `embedding IS NOT NULL`, so the row survives in
list/get and silently leaves recall — unrecoverable without recomputing the
vector.

**Consequence:** a tags/metadata-only mutation must go **direct to Aurora**
(`UPDATE ... SET tags=…, metadata=… WHERE id=… AND version=… AND content=…`),
not through the REST `PUT`. `scripts/memory-consolidation.mjs`'s
`markMemoryStale` adapter does exactly this; `executeStale` documents why. If a
future path must use REST, it has to send the unchanged `content` too so
`contentChanged` triggers a re-embed, and pay the embedding cost.

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

### Enabled atomic durable ingest (downstream patches)

- The ordered downstream stack is
  `0001-recall-min-confidence-tunables-and-zero-result-fallback`,
  `0002-ingest-durable-only-extraction-filter`, `0003-glm-request-bounds`,
  `0004-durable-ingest-queue`, `0005-atomic-ingest-apply`,
  `0006-durable-ingest-telemetry`, `0007-postgres-session-delete`,
  `0008-ingest-prescreen-shadow`, then `0009-if-match-precondition-fence`. The
  Docker build applies the complete stack to the pinned upstream commit in
  lexical order.
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
  only an optimisation that saves an embedding call; the *predicate* is what
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
  a 0008-patched server it returns 412. The script is not applied, copied into
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

Verified against AWS docs + production usage, and — for
this repo — **empirically live 2026-07-12** (ap-northeast-1):

- **Live proof:** `getToken({credentials, region})` (from `@aws/bedrock-token-generator`)
  → a `bedrock-api-key-…` bearer; `POST https://bedrock-mantle.ap-northeast-1.api.aws/v1/chat/completions`
  with `{model:"zai.glm-5", messages:[…]}` + `Authorization: Bearer <bearer>` →
  **HTTP 200**, OpenAI-shaped body (`choices[0].message.content`). The bearer's
  default+max TTL is **12h** (`token.js`: `DEFAULT/MAX_TOKEN_EXPIRES_IN_SECONDS = 43200`),
  and minting is a **pure local SigV4 presign** (no network call) → the token-refresh
  cadence is ~hourly, not the 15-min figure that was the *RDS IAM* token, not this one.
- **Mantle IS OpenAI-compatible.** Endpoint `https://bedrock-mantle.{region}.api.aws/v1`;
  surfaces = **Chat Completions** + **Responses** (OpenAI-compatible) + **Messages**
  (Anthropic). "Bring OpenAI SDK code by changing only base URL + API key."
- **mem9 speaks `/chat/completions` only** → the smart-ingest LLM must be a
  **Chat-Completions** model on Mantle: **GLM-5** (GLM-5 runs on Mantle in
  production), Claude Sonnet/Fable 5, DeepSeek, Gemma, etc. **GPT-5.4 / 5.5
  are Responses-API only → NOT usable by mem9** without a source change.
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

## AWS facts and empirical deployment observations

- The current IaC provisions Aurora PostgreSQL 17.4 Serverless v2 and applies
  `CREATE EXTENSION vector` in the bootstrap task.
- AWS documents the Aurora cluster endpoint as the endpoint for the current
  primary and recommends it for writes:
  [Aurora cluster endpoints](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Aurora.Endpoints.Cluster.html).
- The ECS stack consumes the account default VPC through
  `aws.ec2.getVpc({ default: true })` and selects the NAT-routed private subnets.
- **Empirical account observation, 2026-07-12:** the default VPC contains both
  NAT-routed and no-NAT private subnets. `infra/vpc.ts` selects the intended
  group by its `private-1*` Name tag. Concrete resource ids are intentionally not
  recorded.
- **Empirical deployment observation, 2026-07-12:** the former RDS Proxy target
  remained `PENDING_PROXY_CAPACITY` for more than 40 minutes at the selected
  0.5 ACU floor in two regions. The repository removed the proxy. mem9 and the
  bootstrap task now connect directly to the Aurora cluster writer endpoint.
  This observation is not presented as a general AWS root-cause or capacity
  guarantee.

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

**REJECTED alternative — OpenAPI/MCP target with `privateEndpoint` (VPC Lattice):**
this was the original design and it is a real, documented feature, BUT the
self-managed-VPC-Lattice `privateEndpoint` GatewayTarget **failed to stabilize 100%
of the time in the full CI deploy** — an AgentCore control-plane internal error on
that combination in ap-northeast-1 (the identical config reached READY in isolated
direct-API tests but never in a full-stack deploy). We could not resolve it from IaC
(ruled out CloudControl-vs-SDK, CUSTOM_JWT-vs-IAM, RC-not-ACTIVE, domain-verification,
spaced retries), so we pivoted to the Lambda target. For the record, the rejected
path's shape was: `privateEndpoint.managedVpcResource`/`selfManagedLatticeResource`
→ an **internal ALB with a public ACM cert** (Lattice targets are HTTPS; a plain-HTTP
backend needs the ALB+cert in front) → mnemo-server:8080, with an **API-key credential
provider** for outbound auth (SigV4 is NOT compatible with ALB/EC2 backends).
