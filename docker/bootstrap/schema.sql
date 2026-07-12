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
-- pgvector ANN index for cosine (embedding <=> $q). HNSW is the pgvector default
-- for good recall/latency; vector_cosine_ops matches mem9's `<=>` cosine operator.
-- Built even while empty; pgvector fills it as rows arrive.
CREATE INDEX IF NOT EXISTS idx_memories_embedding
    ON memories USING hnsw (embedding vector_cosine_ops);

-- mem9's updated_at auto-touch trigger (from TenantMemorySchemaPostgres).
CREATE OR REPLACE FUNCTION update_updated_at() RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_memories_updated ON memories;
CREATE TRIGGER trg_memories_updated BEFORE UPDATE ON memories
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
