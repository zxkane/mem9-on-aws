-- mem9-on-aws schema bootstrap (ARCHITECTURE.md §8) — applied ONCE per deploy by
-- the one-shot bootstrap task (docker/bootstrap/), idempotent (IF NOT EXISTS).
--
-- WHY we apply this ourselves (docs/mem9-facts.md "Schema bootstrap gotcha"):
-- on the postgres backend, mnemo-server does NOT create the `memories` table —
-- it only VALIDATES `memories.app_id` + the `idx_app` index at startup and errors
-- if missing (`validate schema: memories.idx_app is missing`). The shipped
-- server/schema_pg.sql builds only the CONTROL-PLANE tables (tenants, ...), not
-- the tenant runtime `memories` schema. So we create the full memories schema
-- here, with our chosen embedding width.
--
-- CRITICAL: `embedding vector(1024)` — mem9's TenantMemorySchemaPostgres constant
-- hardcodes vector(1536), but we run qwen3-0.6B = 1024 dims and set
-- MNEMO_EMBED_DIMS=1024. The DB column width, mem9's dims env, and the embedder
-- MUST all agree; changing later = full reindex. See docs/mem9-facts.md.

-- 1) pgvector extension (idempotent).
CREATE EXTENSION IF NOT EXISTS vector;

-- 2) Control-plane `tenants` table. X-API-Key == tenants.id (the server does
--    tenants.GetByID(apiKey)), so a row must exist for auth to resolve. Mirrors
--    server/schema_pg.sql (only the columns the server reads).
CREATE TABLE IF NOT EXISTS tenants (
    id               VARCHAR(36)   PRIMARY KEY,
    name             VARCHAR(255)  NOT NULL,
    db_host          VARCHAR(255)  NOT NULL,
    db_port          INT           NOT NULL,
    db_user          VARCHAR(255)  NOT NULL,
    db_password      VARCHAR(255)  NOT NULL,
    db_name          VARCHAR(255)  NOT NULL,
    db_tls           BOOLEAN       NOT NULL DEFAULT FALSE,
    provider         VARCHAR(50)   NOT NULL,
    cluster_id       VARCHAR(255)  NULL,
    claim_url        TEXT          NULL,
    claim_expires_at TIMESTAMPTZ   NULL,
    status           VARCHAR(20)   NOT NULL DEFAULT 'provisioning',
    schema_version   INT           NOT NULL DEFAULT 1,
    created_at       TIMESTAMPTZ   DEFAULT NOW(),
    updated_at       TIMESTAMPTZ   DEFAULT NOW(),
    deleted_at       TIMESTAMPTZ   NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_name ON tenants(name);
CREATE INDEX IF NOT EXISTS idx_tenant_status ON tenants(status);
CREATE INDEX IF NOT EXISTS idx_tenant_provider ON tenants(provider);

-- 2b) `tenant_activity` — the server's ActivityTracker.RecordMemoryStats upserts
--     into this on EVERY memory write (hot path). Like upload_tasks it lives in the
--     control-plane schema_pg.sql we don't run, so without it every write logs
--     `record tenant memory stats failed ... relation "tenant_activity" does not
--     exist (SQLSTATE 42P01)`. Non-fatal (a WARN — the write/ingest still succeeds)
--     but noisy. FK → tenants(id), so it must follow the tenants table above. DDL
--     verbatim from schema_pg.sql @ d4638c8458abeb209a1b3a20472a1328c4acd149.
CREATE TABLE IF NOT EXISTS tenant_activity (
    tenant_id                  VARCHAR(36) PRIMARY KEY,
    last_activity_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active_memory_total        BIGINT      NOT NULL DEFAULT 0,
    active_memory_7d_total     BIGINT      NOT NULL DEFAULT 0,
    memory_stats_observed_at   TIMESTAMPTZ NULL,
    CONSTRAINT fk_tenant_activity FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_tenant_activity_last_activity ON tenant_activity(last_activity_at);

-- 3) Tenant runtime `memories` schema — the table + indexes the server validates
--    and uses. Derived from mem9's TenantMemorySchemaPostgres constant, with:
--      * embedding vector(1024)  (qwen3 dims, NOT the default 1536)
--      * idx_app                 (the index the runtime validator requires)
--      * a GIN FTS index on to_tsvector('english', content) — FTSSearch runs
--        `to_tsvector('english', content) @@ plainto_tsquery(...)`, so this index
--        makes keyword search use the index instead of a seq scan.
CREATE TABLE IF NOT EXISTS memories (
    id             VARCHAR(36)     PRIMARY KEY,
    content        TEXT            NOT NULL,
    source         VARCHAR(100),
    tags           JSONB,
    metadata       JSONB,
    embedding      vector(1024)    NULL,
    memory_type    VARCHAR(20)     NOT NULL DEFAULT 'pinned',
    agent_id       VARCHAR(100)    NULL,
    session_id     VARCHAR(100)    NULL,
    app_id         VARCHAR(100)    NOT NULL DEFAULT '',
    state          VARCHAR(20)     NOT NULL DEFAULT 'active',
    version        INT             DEFAULT 1,
    updated_by     VARCHAR(100),
    superseded_by  VARCHAR(36)     NULL,
    created_at     TIMESTAMPTZ     DEFAULT NOW(),
    updated_at     TIMESTAMPTZ     DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_memory_type ON memories(memory_type);
CREATE INDEX IF NOT EXISTS idx_source ON memories(source);
CREATE INDEX IF NOT EXISTS idx_state ON memories(state);
CREATE INDEX IF NOT EXISTS idx_agent ON memories(agent_id);
CREATE INDEX IF NOT EXISTS idx_session ON memories(session_id);
CREATE INDEX IF NOT EXISTS idx_app ON memories(app_id);
CREATE INDEX IF NOT EXISTS idx_updated ON memories(updated_at);
-- FTS: matches FTSSearch's to_tsvector('english', content) expression exactly.
CREATE INDEX IF NOT EXISTS idx_memories_fts
    ON memories USING GIN (to_tsvector('english', content));
-- pgvector ANN index for compatibility mode. Namespace enforcement drops this
-- tenant-wide index because post-filtered ANN candidates are not a valid
-- isolation boundary. A later idempotent bootstrap must not recreate it after
-- constraints_complete.
DO $$
DECLARE
    namespace_enforced BOOLEAN := FALSE;
BEGIN
    IF to_regclass('public.memory_namespace_migration_state') IS NOT NULL THEN
        EXECUTE
            'SELECT EXISTS (
                 SELECT 1
                 FROM memory_namespace_migration_state
                 WHERE singleton_id
                   AND phase = ''constraints_complete''
             )'
        INTO namespace_enforced;
    END IF;
    IF NOT namespace_enforced THEN
        CREATE INDEX IF NOT EXISTS idx_memories_embedding
            ON memories USING hnsw (embedding vector_cosine_ops);
    END IF;
END
$$;

-- mem9's updated_at auto-touch trigger (from TenantMemorySchemaPostgres).
CREATE OR REPLACE FUNCTION update_updated_at() RETURNS TRIGGER AS $$
BEGIN
    IF current_setting(
        'mem9.namespace_migration_actor',
        TRUE
    ) = 'backfill' THEN
        RETURN NEW;
    END IF;
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_memories_updated ON memories;
CREATE TRIGGER trg_memories_updated BEFORE UPDATE ON memories
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- 4) `upload_tasks` — the mnemo-server "upload worker" starts UNCONDITIONALLY at
--    boot (cmd/mnemo-server/main.go: uploadWorker.Run) and immediately runs
--    `reset processing tasks` against this table. Unlike the webhook tables
--    (which the server creates itself via webhookStore.EnsureSchema), the upload
--    worker has NO EnsureSchema — it assumes upload_tasks already exists (it lives
--    in the CONTROL-PLANE server/schema_pg.sql we do not run). Without it the
--    worker logs, every startup: `upload worker error ... reset upload task
--    processing: ERROR: relation "upload_tasks" does not exist (SQLSTATE 42P01)`.
--    DDL copied verbatim from the pinned mem9 source (schema_pg.sql @
--    d4638c8458abeb209a1b3a20472a1328c4acd149). We do not use the file-upload path
--    (writes go through the memory content API), but the worker must find the table.
CREATE TABLE IF NOT EXISTS upload_tasks (
    task_id       VARCHAR(36)   PRIMARY KEY,
    tenant_id     VARCHAR(36)   NOT NULL,
    file_name     VARCHAR(255)  NOT NULL,
    file_path     TEXT          NOT NULL,
    agent_id      VARCHAR(100)  NULL,
    session_id    VARCHAR(100)  NULL,
    file_type     VARCHAR(20)   NOT NULL,
    total_chunks  INT           NOT NULL DEFAULT 0,
    done_chunks   INT           NOT NULL DEFAULT 0,
    status        VARCHAR(20)   NOT NULL DEFAULT 'pending',
    error_msg     TEXT          NULL,
    created_at    TIMESTAMPTZ   DEFAULT NOW(),
    updated_at    TIMESTAMPTZ   DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_upload_tenant ON upload_tasks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_upload_poll ON upload_tasks(status, created_at);
-- upload_tasks' updated_at auto-touch trigger (also from schema_pg.sql). Reuses
-- the update_updated_at() function defined above for `memories`.
DROP TRIGGER IF EXISTS trg_upload_tasks_updated ON upload_tasks;
CREATE TRIGGER trg_upload_tasks_updated BEFORE UPDATE ON upload_tasks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- 5) Tenant-local durable ingest queue (disabled by default at runtime).
\ir migrations/001_ingest_jobs.sql

-- 6) Additive team-memory namespace control and data-plane columns.
\ir migrations/002_memory_namespaces.sql
