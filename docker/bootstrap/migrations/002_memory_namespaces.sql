-- Additive foundation for Cognito group-routed team memory namespaces.
-- This migration is repeatable and deliberately does not assign legacy rows.
-- Enforcement and NOT NULL transitions happen only after the explicit
-- embedding-preserving backfill records application_ready.

CREATE TABLE IF NOT EXISTS memory_namespaces (
    namespace_id VARCHAR(36) PRIMARY KEY,
    slug VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    kind VARCHAR(20) NOT NULL DEFAULT 'team',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_memory_namespaces_kind CHECK (kind = 'team'),
    CONSTRAINT ck_memory_namespaces_status
        CHECK (status IN ('active', 'disabled'))
);

CREATE TABLE IF NOT EXISTS memory_principals (
    principal_id VARCHAR(36) PRIMARY KEY,
    principal_key VARCHAR(64) NOT NULL UNIQUE,
    principal_type VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_memory_principals_key
        CHECK (principal_key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_memory_principals_type
        CHECK (principal_type IN ('human', 'm2m', 'service')),
    CONSTRAINT ck_memory_principals_status
        CHECK (status IN ('active', 'disabled'))
);

CREATE TABLE IF NOT EXISTS memory_cognito_group_bindings (
    group_key VARCHAR(64) PRIMARY KEY,
    namespace_id VARCHAR(36) NOT NULL,
    default_role VARCHAR(20) NOT NULL DEFAULT 'member',
    jit_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_memory_group_bindings_key
        CHECK (group_key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_memory_group_bindings_role
        CHECK (default_role IN ('viewer', 'member')),
    CONSTRAINT ck_memory_group_bindings_status
        CHECK (status IN ('active', 'disabled')),
    CONSTRAINT fk_memory_group_bindings_namespace
        FOREIGN KEY (namespace_id)
        REFERENCES memory_namespaces(namespace_id)
);

CREATE TABLE IF NOT EXISTS memory_namespace_memberships (
    namespace_id VARCHAR(36) NOT NULL,
    principal_id VARCHAR(36) NOT NULL,
    role VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    source_type VARCHAR(20) NOT NULL,
    source_key VARCHAR(64) NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ NULL,
    PRIMARY KEY (namespace_id, principal_id),
    CONSTRAINT ck_memory_memberships_role
        CHECK (role IN ('viewer', 'member', 'owner')),
    CONSTRAINT ck_memory_memberships_status
        CHECK (status IN ('active', 'revoked')),
    CONSTRAINT ck_memory_memberships_source
        CHECK (source_type IN (
            'cognito_group',
            'm2m_binding',
            'operator',
            'service'
        )),
    CONSTRAINT ck_memory_memberships_source_key
        CHECK (source_key IS NULL OR source_key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT fk_memory_memberships_namespace
        FOREIGN KEY (namespace_id)
        REFERENCES memory_namespaces(namespace_id),
    CONSTRAINT fk_memory_memberships_principal
        FOREIGN KEY (principal_id)
        REFERENCES memory_principals(principal_id)
);

CREATE TABLE IF NOT EXISTS memory_m2m_namespace_bindings (
    client_key VARCHAR(64) PRIMARY KEY,
    principal_id VARCHAR(36) NOT NULL UNIQUE,
    namespace_id VARCHAR(36) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'member',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_memory_m2m_bindings_key
        CHECK (client_key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_memory_m2m_bindings_role
        CHECK (role IN ('viewer', 'member')),
    CONSTRAINT ck_memory_m2m_bindings_status
        CHECK (status IN ('active', 'disabled')),
    CONSTRAINT fk_memory_m2m_bindings_principal
        FOREIGN KEY (principal_id)
        REFERENCES memory_principals(principal_id),
    CONSTRAINT fk_memory_m2m_bindings_namespace
        FOREIGN KEY (namespace_id)
        REFERENCES memory_namespaces(namespace_id)
);

CREATE TABLE IF NOT EXISTS memory_namespace_migration_state (
    singleton_id BOOLEAN PRIMARY KEY DEFAULT TRUE,
    phase VARCHAR(40) NOT NULL,
    checkpoint VARCHAR(80) NULL,
    legacy_namespace_id VARCHAR(36) NULL,
    legacy_principal_id VARCHAR(36) NULL,
    legacy_namespace_slug VARCHAR(100) NULL,
    legacy_namespace_display_name VARCHAR(255) NULL,
    legacy_principal_key VARCHAR(64) NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_memory_namespace_migration_singleton CHECK (singleton_id),
    CONSTRAINT ck_memory_namespace_migration_phase CHECK (
        phase IN (
            'additive_ready',
            'frozen',
            'backfilling',
            'application_ready',
            'constraints_complete'
        )
    )
);

ALTER TABLE memory_namespace_migration_state
    ADD COLUMN IF NOT EXISTS legacy_namespace_id VARCHAR(36);
ALTER TABLE memory_namespace_migration_state
    ADD COLUMN IF NOT EXISTS legacy_principal_id VARCHAR(36);
ALTER TABLE memory_namespace_migration_state
    ADD COLUMN IF NOT EXISTS legacy_namespace_slug VARCHAR(100);
ALTER TABLE memory_namespace_migration_state
    ADD COLUMN IF NOT EXISTS legacy_namespace_display_name VARCHAR(255);
ALTER TABLE memory_namespace_migration_state
    ADD COLUMN IF NOT EXISTS legacy_principal_key VARCHAR(64);

ALTER TABLE memory_namespace_migration_state
    DROP CONSTRAINT IF EXISTS ck_memory_namespace_migration_legacy_binding;
ALTER TABLE memory_namespace_migration_state
    ADD CONSTRAINT ck_memory_namespace_migration_legacy_binding
    CHECK (
        (
            phase IN ('additive_ready', 'frozen')
            AND legacy_namespace_id IS NULL
            AND legacy_principal_id IS NULL
            AND legacy_namespace_slug IS NULL
            AND legacy_namespace_display_name IS NULL
            AND legacy_principal_key IS NULL
        )
        OR
        (
            phase IN (
                'backfilling',
                'application_ready',
                'constraints_complete'
            )
            AND legacy_namespace_id IS NOT NULL
            AND legacy_principal_id IS NOT NULL
            AND legacy_namespace_slug IS NOT NULL
            AND legacy_namespace_display_name IS NOT NULL
            AND legacy_principal_key IS NOT NULL
        )
    )
    NOT VALID;

ALTER TABLE memory_namespace_migration_state
    VALIDATE CONSTRAINT ck_memory_namespace_migration_legacy_binding;

INSERT INTO memory_namespace_migration_state (
    singleton_id,
    phase,
    checkpoint
) VALUES (
    TRUE,
    'additive_ready',
    NULL
)
ON CONFLICT (singleton_id) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_memory_group_bindings_namespace
    ON memory_cognito_group_bindings (namespace_id, status);
CREATE INDEX IF NOT EXISTS idx_memory_memberships_principal
    ON memory_namespace_memberships (principal_id, status, namespace_id);
CREATE INDEX IF NOT EXISTS idx_memory_memberships_namespace
    ON memory_namespace_memberships (namespace_id, status, principal_id);
CREATE INDEX IF NOT EXISTS idx_memory_principals_status
    ON memory_principals (status, principal_type);
CREATE INDEX IF NOT EXISTS idx_memory_m2m_bindings_namespace
    ON memory_m2m_namespace_bindings (namespace_id, status);

ALTER TABLE memories
    ADD COLUMN IF NOT EXISTS namespace_id VARCHAR(36);
ALTER TABLE memories
    ADD COLUMN IF NOT EXISTS created_by_principal_id VARCHAR(36);
ALTER TABLE memories
    ADD COLUMN IF NOT EXISTS updated_by_principal_id VARCHAR(36);

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS namespace_id VARCHAR(36);
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS principal_id VARCHAR(36);
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS updated_by_principal_id VARCHAR(36);

ALTER TABLE ingest_jobs
    ADD COLUMN IF NOT EXISTS namespace_id VARCHAR(36);
ALTER TABLE ingest_jobs
    ADD COLUMN IF NOT EXISTS principal_id VARCHAR(36);

ALTER TABLE ingest_job_plans
    ADD COLUMN IF NOT EXISTS namespace_id VARCHAR(36);
ALTER TABLE ingest_job_plans
    ADD COLUMN IF NOT EXISTS principal_id VARCHAR(36);

ALTER TABLE upload_tasks
    ADD COLUMN IF NOT EXISTS namespace_id VARCHAR(36);

DO $$
BEGIN
    IF to_regclass('session_edits') IS NOT NULL THEN
        ALTER TABLE session_edits
            ADD COLUMN IF NOT EXISTS namespace_id VARCHAR(36);
        ALTER TABLE session_edits
            ADD COLUMN IF NOT EXISTS principal_id VARCHAR(36);
    END IF;
END
$$;

-- Namespace data-plane indexes are intentionally not built during compatible
-- application startup. The guarded operator creates them concurrently after
-- writers are frozen, validates their catalog definitions, and repairs any
-- invalid artifact left by an interrupted concurrent build.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'memories'::regclass
          AND conname = 'fk_memories_namespace'
    ) THEN
        ALTER TABLE memories
            ADD CONSTRAINT fk_memories_namespace
            FOREIGN KEY (namespace_id)
            REFERENCES memory_namespaces(namespace_id)
            NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'sessions'::regclass
          AND conname = 'fk_sessions_principal'
    ) THEN
        ALTER TABLE sessions
            ADD CONSTRAINT fk_sessions_principal
            FOREIGN KEY (principal_id)
            REFERENCES memory_principals(principal_id)
            NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'sessions'::regclass
          AND conname = 'fk_sessions_updated_principal'
    ) THEN
        ALTER TABLE sessions
            ADD CONSTRAINT fk_sessions_updated_principal
            FOREIGN KEY (updated_by_principal_id)
            REFERENCES memory_principals(principal_id)
            NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'memories'::regclass
          AND conname = 'fk_memories_created_principal'
    ) THEN
        ALTER TABLE memories
            ADD CONSTRAINT fk_memories_created_principal
            FOREIGN KEY (created_by_principal_id)
            REFERENCES memory_principals(principal_id)
            NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'ingest_job_plans'::regclass
          AND conname = 'fk_ingest_job_plans_principal'
    ) THEN
        ALTER TABLE ingest_job_plans
            ADD CONSTRAINT fk_ingest_job_plans_principal
            FOREIGN KEY (principal_id)
            REFERENCES memory_principals(principal_id)
            NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'memories'::regclass
          AND conname = 'fk_memories_updated_principal'
    ) THEN
        ALTER TABLE memories
            ADD CONSTRAINT fk_memories_updated_principal
            FOREIGN KEY (updated_by_principal_id)
            REFERENCES memory_principals(principal_id)
            NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'sessions'::regclass
          AND conname = 'fk_sessions_namespace'
    ) THEN
        ALTER TABLE sessions
            ADD CONSTRAINT fk_sessions_namespace
            FOREIGN KEY (namespace_id)
            REFERENCES memory_namespaces(namespace_id)
            NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'ingest_jobs'::regclass
          AND conname = 'fk_ingest_jobs_namespace'
    ) THEN
        ALTER TABLE ingest_jobs
            ADD CONSTRAINT fk_ingest_jobs_namespace
            FOREIGN KEY (namespace_id)
            REFERENCES memory_namespaces(namespace_id)
            NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'ingest_jobs'::regclass
          AND conname = 'fk_ingest_jobs_principal'
    ) THEN
        ALTER TABLE ingest_jobs
            ADD CONSTRAINT fk_ingest_jobs_principal
            FOREIGN KEY (principal_id)
            REFERENCES memory_principals(principal_id)
            NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'ingest_job_plans'::regclass
          AND conname = 'fk_ingest_job_plans_namespace'
    ) THEN
        ALTER TABLE ingest_job_plans
            ADD CONSTRAINT fk_ingest_job_plans_namespace
            FOREIGN KEY (namespace_id)
            REFERENCES memory_namespaces(namespace_id)
            NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'upload_tasks'::regclass
          AND conname = 'fk_upload_tasks_namespace'
    ) THEN
        ALTER TABLE upload_tasks
            ADD CONSTRAINT fk_upload_tasks_namespace
            FOREIGN KEY (namespace_id)
            REFERENCES memory_namespaces(namespace_id)
            NOT VALID;
    END IF;
END
$$;

-- The operator changes the migration phase to frozen only after application
-- writers have been scaled down. These triggers make that operational freeze
-- database-enforced, closing the race between the drain check and backfill.
-- The migration process opts into a narrowly named session-local bypass.
CREATE OR REPLACE FUNCTION enforce_memory_namespace_writer_freeze()
RETURNS TRIGGER AS $$
DECLARE
    observed_phase VARCHAR(40);
BEGIN
    IF current_setting(
        'mem9.namespace_migration_actor',
        TRUE
    ) = 'backfill' THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;

    SELECT phase
    INTO observed_phase
    FROM memory_namespace_migration_state
    WHERE singleton_id;

    IF observed_phase IN ('frozen', 'backfilling') THEN
        RAISE EXCEPTION
            'memory namespace migration writer freeze is active'
            USING ERRCODE = '55000';
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_memories_namespace_writer_freeze ON memories;
CREATE TRIGGER trg_memories_namespace_writer_freeze
    BEFORE INSERT OR UPDATE OR DELETE ON memories
    FOR EACH STATEMENT
    EXECUTE FUNCTION enforce_memory_namespace_writer_freeze();

DROP TRIGGER IF EXISTS trg_sessions_namespace_writer_freeze ON sessions;
CREATE TRIGGER trg_sessions_namespace_writer_freeze
    BEFORE INSERT OR UPDATE OR DELETE ON sessions
    FOR EACH STATEMENT
    EXECUTE FUNCTION enforce_memory_namespace_writer_freeze();

DROP TRIGGER IF EXISTS trg_ingest_jobs_namespace_writer_freeze ON ingest_jobs;
CREATE TRIGGER trg_ingest_jobs_namespace_writer_freeze
    BEFORE INSERT OR UPDATE OR DELETE ON ingest_jobs
    FOR EACH STATEMENT
    EXECUTE FUNCTION enforce_memory_namespace_writer_freeze();

DROP TRIGGER IF EXISTS trg_ingest_job_plans_namespace_writer_freeze
    ON ingest_job_plans;
CREATE TRIGGER trg_ingest_job_plans_namespace_writer_freeze
    BEFORE INSERT OR UPDATE OR DELETE ON ingest_job_plans
    FOR EACH STATEMENT
    EXECUTE FUNCTION enforce_memory_namespace_writer_freeze();

DROP TRIGGER IF EXISTS trg_upload_tasks_namespace_writer_freeze
    ON upload_tasks;
CREATE TRIGGER trg_upload_tasks_namespace_writer_freeze
    BEFORE INSERT OR UPDATE OR DELETE ON upload_tasks
    FOR EACH STATEMENT
    EXECUTE FUNCTION enforce_memory_namespace_writer_freeze();
