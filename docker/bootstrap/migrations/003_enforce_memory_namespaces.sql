-- Explicit namespace cutover. Do not run this migration until the writer
-- freeze and embedding-preserving backfill have recorded application_ready.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '25min';

SELECT pg_advisory_xact_lock(hashtext('mem9-memory-namespace-cutover-v1'));

DO $$
DECLARE
    observed_phase VARCHAR(40);
BEGIN
    SELECT phase
    INTO observed_phase
    FROM memory_namespace_migration_state
    WHERE singleton_id
    FOR UPDATE;

    IF observed_phase NOT IN ('application_ready', 'constraints_complete') THEN
        RAISE EXCEPTION
            'namespace cutover requires application_ready, observed %',
            COALESCE(observed_phase, '<missing>');
    END IF;

    IF EXISTS (SELECT 1 FROM memories WHERE namespace_id IS NULL)
       OR EXISTS (SELECT 1 FROM sessions WHERE namespace_id IS NULL)
       OR EXISTS (
            SELECT 1
            FROM ingest_jobs
            WHERE namespace_id IS NULL OR principal_id IS NULL
       )
       OR EXISTS (
            SELECT 1
            FROM ingest_job_plans
            WHERE namespace_id IS NULL OR principal_id IS NULL
       )
       OR EXISTS (SELECT 1 FROM upload_tasks WHERE namespace_id IS NULL)
    THEN
        RAISE EXCEPTION 'namespace cutover found unassigned data-plane rows';
    END IF;
END
$$;

DROP INDEX IF EXISTS uq_ingest_jobs_tenant_idempotency;
DROP INDEX IF EXISTS uq_ingest_job_plans_hash;
DROP INDEX IF EXISTS uq_sessions_message;

DO $$
DECLARE
    primary_key_columns NAME[];
BEGIN
    SELECT array_agg(attribute.attname ORDER BY key_column.ordinality)
    INTO primary_key_columns
    FROM pg_constraint AS constraint_state
    CROSS JOIN LATERAL unnest(constraint_state.conkey)
        WITH ORDINALITY AS key_column(attnum, ordinality)
    JOIN pg_attribute AS attribute
      ON attribute.attrelid = constraint_state.conrelid
     AND attribute.attnum = key_column.attnum
    WHERE constraint_state.conrelid = 'ingest_job_plans'::regclass
      AND constraint_state.contype = 'p';

    IF primary_key_columns IS NOT NULL
       AND primary_key_columns <> ARRAY[
            'tenant_id',
            'namespace_id',
            'job_id',
            'plan_revision'
       ]::NAME[]
    THEN
        ALTER TABLE ingest_job_plans
            DROP CONSTRAINT ingest_job_plans_pkey;
    END IF;
END
$$;

ALTER TABLE memories
    ALTER COLUMN namespace_id SET NOT NULL;
ALTER TABLE sessions
    ALTER COLUMN namespace_id SET NOT NULL,
    ALTER COLUMN principal_id SET NOT NULL;
ALTER TABLE ingest_jobs
    ALTER COLUMN namespace_id SET NOT NULL,
    ALTER COLUMN principal_id SET NOT NULL;
ALTER TABLE ingest_job_plans
    ALTER COLUMN namespace_id SET NOT NULL,
    ALTER COLUMN principal_id SET NOT NULL;
ALTER TABLE upload_tasks
    ALTER COLUMN namespace_id SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'ingest_job_plans'::regclass
          AND contype = 'p'
    ) THEN
        ALTER TABLE ingest_job_plans
            ADD CONSTRAINT ingest_job_plans_pkey
            PRIMARY KEY USING INDEX
                uq_ingest_job_plans_namespace_revision;
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'ingest_job_plans'::regclass
          AND conname = 'fk_ingest_job_plans_job_namespace'
    ) THEN
        ALTER TABLE ingest_job_plans
            ADD CONSTRAINT fk_ingest_job_plans_job_namespace
            FOREIGN KEY (tenant_id, namespace_id, job_id)
            REFERENCES ingest_jobs (tenant_id, namespace_id, job_id)
            NOT VALID;
    END IF;
END
$$;

ALTER TABLE memories VALIDATE CONSTRAINT fk_memories_namespace;
ALTER TABLE memories VALIDATE CONSTRAINT fk_memories_created_principal;
ALTER TABLE memories VALIDATE CONSTRAINT fk_memories_updated_principal;
ALTER TABLE sessions VALIDATE CONSTRAINT fk_sessions_namespace;
ALTER TABLE sessions VALIDATE CONSTRAINT fk_sessions_principal;
ALTER TABLE sessions VALIDATE CONSTRAINT fk_sessions_updated_principal;
ALTER TABLE ingest_jobs VALIDATE CONSTRAINT fk_ingest_jobs_namespace;
ALTER TABLE ingest_jobs VALIDATE CONSTRAINT fk_ingest_jobs_principal;
ALTER TABLE ingest_job_plans VALIDATE CONSTRAINT fk_ingest_job_plans_namespace;
ALTER TABLE ingest_job_plans VALIDATE CONSTRAINT fk_ingest_job_plans_principal;
ALTER TABLE ingest_job_plans
    VALIDATE CONSTRAINT fk_ingest_job_plans_job_namespace;
ALTER TABLE upload_tasks VALIDATE CONSTRAINT fk_upload_tasks_namespace;

-- Namespace-scoped vector search is exact in v1. A tenant-wide HNSW index can
-- return a post-filtered approximation and is therefore not a supported path.
DROP INDEX IF EXISTS idx_memories_embedding;

UPDATE memory_namespace_migration_state
SET phase = 'constraints_complete',
    checkpoint = 'constraints_validated',
    updated_at = statement_timestamp()
WHERE singleton_id;

COMMIT;
