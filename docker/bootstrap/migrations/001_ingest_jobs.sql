-- Tenant-local durable ingest queue. This migration is additive and repeatable
-- so the bootstrap task can run it on every deployment.

CREATE TABLE IF NOT EXISTS ingest_jobs (
    job_id                VARCHAR(36)  PRIMARY KEY,
    tenant_id             VARCHAR(36)  NOT NULL,
    idempotency_key       VARCHAR(64)  NOT NULL,
    canonical_payload     BYTEA        NOT NULL DEFAULT '\x7b7d'::bytea,
    agent_id              VARCHAR(100) NOT NULL DEFAULT '',
    app_id                VARCHAR(100) NOT NULL DEFAULT '',
    session_id            VARCHAR(100) NOT NULL DEFAULT '',
    mode                  VARCHAR(20)  NOT NULL DEFAULT 'smart',
    disable_session_save  BOOLEAN      NOT NULL DEFAULT FALSE,
    runtime_operation_id  VARCHAR(36)  NULL,
    runtime_cluster_id    VARCHAR(255) NULL,
    runtime_agent_name    VARCHAR(100) NULL,
    runtime_reservation_expires_at TIMESTAMPTZ NULL,
    runtime_finalization_state VARCHAR(20) NULL,
    state                 VARCHAR(20)  NOT NULL DEFAULT 'queued',
    attempt_count         INT          NOT NULL DEFAULT 0,
    available_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    lease_owner           VARCHAR(255) NULL,
    lease_expires_at      TIMESTAMPTZ  NULL,
    heartbeat_at          TIMESTAMPTZ  NULL,
    plan_payload          BYTEA        NULL,
    active_plan_revision  INT          NULL,
    active_plan_hash      VARCHAR(64)  NULL,
    plan_warning_count    INT          NOT NULL DEFAULT 0,
    apply_warning_count   INT          NOT NULL DEFAULT 0,
    warning_count         INT          NOT NULL DEFAULT 0,
    warning_class         VARCHAR(64)  NULL,
    truncated_fact_count  INT          NOT NULL DEFAULT 0,
    error_class           VARCHAR(64)  NULL,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at          TIMESTAMPTZ  NULL
);

-- Upgrade a minimal pre-foundation table without dropping existing rows.
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36) NOT NULL DEFAULT '';
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS idempotency_key VARCHAR(64);
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS canonical_payload BYTEA NOT NULL DEFAULT '\x7b7d'::bytea;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS agent_id VARCHAR(100) NOT NULL DEFAULT '';
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS app_id VARCHAR(100) NOT NULL DEFAULT '';
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS session_id VARCHAR(100) NOT NULL DEFAULT '';
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS mode VARCHAR(20) NOT NULL DEFAULT 'smart';
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS disable_session_save BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS runtime_operation_id VARCHAR(36) NULL;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS runtime_cluster_id VARCHAR(255) NULL;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS runtime_agent_name VARCHAR(100) NULL;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS runtime_reservation_expires_at TIMESTAMPTZ NULL;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS runtime_finalization_state VARCHAR(20) NULL;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS state VARCHAR(20) NOT NULL DEFAULT 'queued';
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS attempt_count INT NOT NULL DEFAULT 0;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS available_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS lease_owner VARCHAR(255) NULL;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ NULL;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ NULL;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS plan_payload BYTEA NULL;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS active_plan_revision INT NULL;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS active_plan_hash VARCHAR(64) NULL;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS plan_warning_count INT NOT NULL DEFAULT 0;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS apply_warning_count INT NOT NULL DEFAULT 0;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS warning_count INT NOT NULL DEFAULT 0;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS warning_class VARCHAR(64) NULL;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS truncated_fact_count INT NOT NULL DEFAULT 0;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS error_class VARCHAR(64) NULL;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ NULL;

-- The first foundation revision used an indistinguishable 64-hex synthetic key
-- for upgraded rows. Remove its length-only constraint before moving those keys
-- into a reserved namespace. Keep the current constraint untouched on repeats.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'ingest_jobs'::regclass
          AND conname = 'ck_ingest_jobs_idempotency_key'
          AND position(
              'legacy:' IN pg_get_constraintdef(oid)
          ) = 0
    ) THEN
        ALTER TABLE ingest_jobs DROP CONSTRAINT ck_ingest_jobs_idempotency_key;
    END IF;
END
$$;

UPDATE ingest_jobs
SET idempotency_key = 'legacy:' || job_id
WHERE idempotency_key IS NULL
   OR idempotency_key = md5(job_id) || md5('ingest-v1:' || job_id);
ALTER TABLE ingest_jobs ALTER COLUMN idempotency_key SET NOT NULL;

-- A terminal job from the preceding rollout may have committed before its
-- reservation callback ran. Make that callback reclaimable on upgrade.
UPDATE ingest_jobs
SET runtime_finalization_state = CASE
    WHEN state IN ('succeeded', 'dead') THEN 'finalizing'
    ELSE 'reserved'
END
WHERE runtime_operation_id IS NOT NULL
  AND runtime_finalization_state IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'ingest_jobs'::regclass
          AND conname = 'ck_ingest_jobs_state'
    ) THEN
        ALTER TABLE ingest_jobs ADD CONSTRAINT ck_ingest_jobs_state CHECK (
            state IN (
                'queued',
                'processing',
                'planning',
                'applying',
                'retry_wait',
                'succeeded',
                'dead'
            )
        );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'ingest_jobs'::regclass
          AND conname = 'ck_ingest_jobs_idempotency_key'
    ) THEN
        ALTER TABLE ingest_jobs ADD CONSTRAINT ck_ingest_jobs_idempotency_key
            CHECK (
                idempotency_key ~ '^[0-9a-f]{64}$'
                OR idempotency_key = 'legacy:' || job_id
            );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'ingest_jobs'::regclass
          AND conname = 'ck_ingest_jobs_payload_size'
    ) THEN
        ALTER TABLE ingest_jobs ADD CONSTRAINT ck_ingest_jobs_payload_size
            CHECK (octet_length(canonical_payload) <= 1048576) NOT VALID;
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'ingest_jobs'::regclass
          AND conname = 'ck_ingest_jobs_payload_size'
          AND NOT convalidated
    ) AND NOT EXISTS (
        SELECT 1 FROM ingest_jobs
        WHERE octet_length(canonical_payload) > 1048576
    ) THEN
        ALTER TABLE ingest_jobs
            VALIDATE CONSTRAINT ck_ingest_jobs_payload_size;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'ingest_jobs'::regclass
          AND conname = 'ck_ingest_jobs_counters'
    ) THEN
        ALTER TABLE ingest_jobs ADD CONSTRAINT ck_ingest_jobs_counters CHECK (
            attempt_count >= 0
            AND plan_warning_count >= 0
            AND apply_warning_count >= 0
            AND warning_count >= 0
        );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'ingest_jobs'::regclass
          AND conname = 'ck_ingest_jobs_active_plan_v2'
    ) THEN
        ALTER TABLE ingest_jobs ADD CONSTRAINT ck_ingest_jobs_active_plan_v2 CHECK (
            (active_plan_revision IS NULL AND active_plan_hash IS NULL)
            OR (
                active_plan_revision IS NOT NULL
                AND active_plan_hash IS NOT NULL
                AND active_plan_revision > 0
                AND active_plan_hash ~ '^[0-9a-f]{64}$'
            )
        );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'ingest_jobs'::regclass
          AND conname = 'ck_ingest_jobs_truncated_fact_count'
    ) THEN
        ALTER TABLE ingest_jobs
            ADD CONSTRAINT ck_ingest_jobs_truncated_fact_count
            CHECK (truncated_fact_count >= 0);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'ingest_jobs'::regclass
          AND conname = 'ck_ingest_jobs_runtime_finalization_v2'
    ) THEN
        ALTER TABLE ingest_jobs
            ADD CONSTRAINT ck_ingest_jobs_runtime_finalization_v2 CHECK (
                (
                    runtime_operation_id IS NULL
                    AND runtime_finalization_state IS NULL
                )
                OR (
                    runtime_operation_id IS NOT NULL
                    AND runtime_finalization_state IS NOT NULL
                    AND (
                        (
                            runtime_finalization_state = 'reserved'
                            AND state NOT IN ('succeeded', 'dead')
                        )
                        OR (
                            runtime_finalization_state IN ('finalizing', 'completed')
                            AND state IN ('succeeded', 'dead')
                        )
                    )
                )
            );
    END IF;
END
$$;

-- Immutable plan payloads are retained by revision. Only lifecycle metadata
-- (valid -> stale/applied) changes after insert.
CREATE TABLE IF NOT EXISTS ingest_job_plans (
    tenant_id             VARCHAR(36) NOT NULL,
    job_id                VARCHAR(36) NOT NULL,
    plan_revision         INT         NOT NULL,
    attempt_generation    INT         NOT NULL,
    plan_hash             VARCHAR(64) NOT NULL,
    plan_payload          BYTEA       NOT NULL,
    state                 VARCHAR(20) NOT NULL DEFAULT 'valid',
    truncated_fact_count  INT         NOT NULL DEFAULT 0,
    warning_count         INT         NOT NULL DEFAULT 0,
    warning_class         VARCHAR(64) NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    stale_at              TIMESTAMPTZ NULL,
    applied_at            TIMESTAMPTZ NULL,
    PRIMARY KEY (tenant_id, job_id, plan_revision),
    CONSTRAINT ck_ingest_job_plans_revision CHECK (
        plan_revision > 0
        AND attempt_generation > 0
        AND truncated_fact_count >= 0
        AND warning_count >= 0
    ),
    CONSTRAINT ck_ingest_job_plans_hash CHECK (
        plan_hash ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_ingest_job_plans_state CHECK (
        state IN ('valid', 'stale', 'applied')
    )
);

DO $$
DECLARE
    namespace_enforced BOOLEAN := FALSE;
BEGIN
    IF to_regclass('memory_namespace_migration_state') IS NOT NULL THEN
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
        CREATE UNIQUE INDEX IF NOT EXISTS uq_ingest_job_plans_hash
            ON ingest_job_plans (tenant_id, job_id, plan_hash);
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_ingest_job_plans_active
    ON ingest_job_plans (tenant_id, job_id, plan_revision DESC)
    WHERE state = 'valid';

-- The PostgreSQL backend historically no-oped raw-session writes. Durable
-- transcript ingest materializes these rows in the same transaction as memory
-- actions and job completion.
CREATE TABLE IF NOT EXISTS sessions (
    id            VARCHAR(36)  PRIMARY KEY,
    session_id    VARCHAR(100) NOT NULL,
    agent_id      VARCHAR(100) NULL,
    app_id        VARCHAR(100) NOT NULL DEFAULT '',
    source        VARCHAR(100) NULL,
    seq           INT          NOT NULL DEFAULT 0,
    role          VARCHAR(32)  NOT NULL,
    content       TEXT         NOT NULL,
    content_type  VARCHAR(32)  NOT NULL DEFAULT 'text',
    content_hash  VARCHAR(64)  NOT NULL,
    tags          JSONB        NOT NULL DEFAULT '[]'::jsonb,
    state         VARCHAR(20)  NOT NULL DEFAULT 'active',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_sessions_content_hash CHECK (
        content_hash ~ '^[0-9a-f]{64}$'
    )
);

DO $$
DECLARE
    namespace_enforced BOOLEAN := FALSE;
BEGIN
    IF to_regclass('memory_namespace_migration_state') IS NOT NULL THEN
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
        CREATE UNIQUE INDEX IF NOT EXISTS uq_sessions_message
            ON sessions (app_id, session_id, content_hash);
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_sessions_scope
    ON sessions (app_id, session_id, seq, id)
    WHERE state = 'active';

-- The migration is also exercised against the queue tables in isolation. Apply
-- the memory version upgrade only when the full bootstrap has already created
-- the runtime memories table.
DO $$
BEGIN
    IF to_regclass('memories') IS NOT NULL THEN
        ALTER TABLE memories ADD COLUMN IF NOT EXISTS version INT;
        UPDATE memories
        SET version = 1
        WHERE version IS NULL;
        ALTER TABLE memories ALTER COLUMN version SET DEFAULT 1;
        ALTER TABLE memories ALTER COLUMN version SET NOT NULL;
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'memories'::regclass
              AND conname = 'ck_memories_version'
        ) THEN
            ALTER TABLE memories ADD CONSTRAINT ck_memories_version
                CHECK (version > 0);
        END IF;
    END IF;
END
$$;

DO $$
DECLARE
    namespace_enforced BOOLEAN := FALSE;
BEGIN
    IF to_regclass('memory_namespace_migration_state') IS NOT NULL THEN
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
        CREATE UNIQUE INDEX IF NOT EXISTS uq_ingest_jobs_tenant_idempotency
            ON ingest_jobs (tenant_id, idempotency_key);
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_ingest_jobs_fifo
    ON ingest_jobs (tenant_id, agent_id, app_id, session_id, created_at, job_id)
    WHERE state NOT IN ('succeeded', 'dead');

CREATE INDEX IF NOT EXISTS idx_ingest_jobs_claim
    ON ingest_jobs (tenant_id, available_at, created_at, job_id)
    WHERE state IN ('queued', 'retry_wait', 'processing', 'planning', 'applying');

CREATE INDEX IF NOT EXISTS idx_ingest_jobs_claim_cursor
    ON ingest_jobs (tenant_id, created_at, job_id)
    WHERE state NOT IN ('succeeded', 'dead');

CREATE INDEX IF NOT EXISTS idx_ingest_jobs_lease
    ON ingest_jobs (tenant_id, lease_expires_at)
    WHERE state IN ('processing', 'planning', 'applying');

CREATE INDEX IF NOT EXISTS idx_ingest_jobs_runtime_finalization
    ON ingest_jobs (tenant_id, completed_at, job_id)
    WHERE runtime_finalization_state = 'finalizing'
      AND state IN ('succeeded', 'dead');

CREATE INDEX IF NOT EXISTS idx_ingest_jobs_status
    ON ingest_jobs (tenant_id, state, updated_at DESC);
