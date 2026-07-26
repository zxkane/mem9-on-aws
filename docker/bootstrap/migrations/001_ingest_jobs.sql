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
    state                 VARCHAR(20)  NOT NULL DEFAULT 'queued',
    attempt_count         INT          NOT NULL DEFAULT 0,
    available_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    lease_owner           VARCHAR(255) NULL,
    lease_expires_at      TIMESTAMPTZ  NULL,
    heartbeat_at          TIMESTAMPTZ  NULL,
    plan_payload          BYTEA        NULL,
    plan_warning_count    INT          NOT NULL DEFAULT 0,
    apply_warning_count   INT          NOT NULL DEFAULT 0,
    warning_count         INT          NOT NULL DEFAULT 0,
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
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS state VARCHAR(20) NOT NULL DEFAULT 'queued';
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS attempt_count INT NOT NULL DEFAULT 0;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS available_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS lease_owner VARCHAR(255) NULL;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ NULL;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ NULL;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS plan_payload BYTEA NULL;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS plan_warning_count INT NOT NULL DEFAULT 0;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS apply_warning_count INT NOT NULL DEFAULT 0;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS warning_count INT NOT NULL DEFAULT 0;
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
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_ingest_jobs_tenant_idempotency
    ON ingest_jobs (tenant_id, idempotency_key);

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

CREATE INDEX IF NOT EXISTS idx_ingest_jobs_status
    ON ingest_jobs (tenant_id, state, updated_at DESC);
