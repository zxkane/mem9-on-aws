-- Durable ingest queue retention and payload purge.
--
-- The ingest queue admits each ingest_messages request as an ingest_jobs row
-- that holds a verbatim copy of the submitted transcript in canonical_payload
-- (plus the derived plan_payload) and up to a few revisions in
-- ingest_job_plans. Nothing in the runtime previously deleted these rows, so
-- succeeded/dead jobs retained plaintext transcripts indefinitely and the
-- queue could grow Aurora storage without bound. This migration adds:
--   * A completed_at index that makes a terminal-row retention sweep cheap.
--   * purge_terminal_ingest_payloads(interval, batch): the maintenance-plane
--     retention sweep. For terminal rows (state IN ('succeeded','dead')) whose
--     completed_at is older than the retention window it NULLs out
--     canonical_payload / plan_payload on ingest_jobs and ingest_job_plans so
--     the deletion of derived data (sessions / memories) also stops leaving a
--     plaintext copy behind in the queue. Payloads are nulled rather than rows
--     deleted so lifecycle metadata (attempt counts, warnings, idempotency
--     keys for client retries) stays available for observability; the storage
--     and confidentiality defects are resolved by removing the content, not
--     the row.
--   * purge_ingest_payloads_for_scope(tenant, agent, app, session): invoked by
--     session / memory deletion to purge the queue copies of that content
--     immediately for terminal rows in the same scope, independent of the
--     retention window.
--
-- The migration is additive and repeatable so the bootstrap task can run it on
-- every deployment.

CREATE INDEX IF NOT EXISTS idx_ingest_jobs_retention_terminal
    ON ingest_jobs (completed_at)
    WHERE state IN ('succeeded', 'dead')
      AND completed_at IS NOT NULL;

-- Null out canonical_payload and the active plan_payload on ingest_jobs, and
-- plan_payload on ingest_job_plans, for terminal rows whose completed_at is
-- older than retention_window. Caps the number of ingest_jobs rows touched per
-- call at max_rows to keep the sweep bounded on crowded tables; the caller is
-- expected to loop until the function returns zero.
--
-- Returns the number of ingest_jobs rows whose payload was nulled on this call
-- (an ingest_job_plans fan-out is purged in the same statement).
CREATE OR REPLACE FUNCTION purge_terminal_ingest_payloads(
    retention_window INTERVAL,
    max_rows INT DEFAULT 1000
) RETURNS INT
LANGUAGE plpgsql
AS $$
DECLARE
    purged_rows INT := 0;
BEGIN
    IF retention_window IS NULL OR retention_window <= INTERVAL '0' THEN
        RAISE EXCEPTION 'purge_terminal_ingest_payloads: retention_window must be positive';
    END IF;
    IF max_rows IS NULL OR max_rows <= 0 THEN
        max_rows := 1000;
    END IF;

    WITH candidates AS (
        SELECT tenant_id, job_id
        FROM ingest_jobs
        WHERE state IN ('succeeded', 'dead')
          AND completed_at IS NOT NULL
          AND completed_at < NOW() - retention_window
          AND (
              octet_length(canonical_payload) > 0
              OR plan_payload IS NOT NULL
          )
        ORDER BY completed_at
        LIMIT max_rows
        FOR UPDATE SKIP LOCKED
    ),
    purge_plans AS (
        UPDATE ingest_job_plans p
        SET plan_payload = '\x'::bytea
        FROM candidates c
        WHERE p.tenant_id = c.tenant_id
          AND p.job_id = c.job_id
          AND octet_length(p.plan_payload) > 0
        RETURNING p.job_id
    ),
    purge_jobs AS (
        UPDATE ingest_jobs j
        SET canonical_payload = '\x'::bytea,
            plan_payload = NULL,
            updated_at = NOW()
        FROM candidates c
        WHERE j.tenant_id = c.tenant_id
          AND j.job_id = c.job_id
        RETURNING j.job_id
    )
    SELECT (SELECT COUNT(*) FROM purge_jobs)
         + 0 * (SELECT COUNT(*) FROM purge_plans)
    INTO purged_rows;

    RETURN purged_rows;
END
$$;

-- Immediately null out canonical_payload / plan_payload on all terminal queue
-- copies matching a (tenant, namespace, principal, agent, app, session) scope.
-- Called by session or memory deletion so the user-visible delete also purges
-- the content from the durable queue, instead of waiting for the retention
-- window.
--
-- Non-terminal rows are left intact so in-flight ingest keeps running; those
-- rows transition to terminal naturally and are then eligible for the normal
-- retention sweep.
--
-- NULL arguments act as wildcards for the corresponding scope column; the
-- tenant_id argument is required and must match exactly to prevent a caller
-- from purging another tenant's rows.
CREATE OR REPLACE FUNCTION purge_ingest_payloads_for_scope(
    p_tenant_id VARCHAR,
    p_namespace_id VARCHAR DEFAULT NULL,
    p_principal_id VARCHAR DEFAULT NULL,
    p_agent_id VARCHAR DEFAULT NULL,
    p_app_id VARCHAR DEFAULT NULL,
    p_session_id VARCHAR DEFAULT NULL
) RETURNS INT
LANGUAGE plpgsql
AS $$
DECLARE
    purged_rows INT := 0;
BEGIN
    IF p_tenant_id IS NULL OR p_tenant_id = '' THEN
        RAISE EXCEPTION 'purge_ingest_payloads_for_scope: tenant_id is required';
    END IF;

    WITH candidates AS (
        SELECT tenant_id, job_id
        FROM ingest_jobs
        WHERE tenant_id = p_tenant_id
          AND state IN ('succeeded', 'dead')
          AND (p_namespace_id IS NULL OR namespace_id = p_namespace_id)
          AND (p_principal_id IS NULL OR principal_id = p_principal_id)
          AND (p_agent_id     IS NULL OR agent_id     = p_agent_id)
          AND (p_app_id       IS NULL OR app_id       = p_app_id)
          AND (p_session_id   IS NULL OR session_id   = p_session_id)
          AND (
              octet_length(canonical_payload) > 0
              OR plan_payload IS NOT NULL
          )
        FOR UPDATE SKIP LOCKED
    ),
    purge_plans AS (
        UPDATE ingest_job_plans p
        SET plan_payload = '\x'::bytea
        FROM candidates c
        WHERE p.tenant_id = c.tenant_id
          AND p.job_id = c.job_id
          AND octet_length(p.plan_payload) > 0
        RETURNING p.job_id
    ),
    purge_jobs AS (
        UPDATE ingest_jobs j
        SET canonical_payload = '\x'::bytea,
            plan_payload = NULL,
            updated_at = NOW()
        FROM candidates c
        WHERE j.tenant_id = c.tenant_id
          AND j.job_id = c.job_id
        RETURNING j.job_id
    )
    SELECT (SELECT COUNT(*) FROM purge_jobs)
         + 0 * (SELECT COUNT(*) FROM purge_plans)
    INTO purged_rows;

    RETURN purged_rows;
END
$$;
