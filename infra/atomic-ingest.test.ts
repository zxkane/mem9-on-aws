import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

describe("atomic durable ingest wiring", () => {
  it("pins the repeatable plan/session/version migration contract", () => {
    const migration = readFileSync(
      resolve(root, "docker/bootstrap/migrations/001_ingest_jobs.sql"),
      "utf8",
    );
    expect(migration).toContain("CREATE TABLE IF NOT EXISTS ingest_job_plans");
    expect(migration).toContain("CREATE TABLE IF NOT EXISTS sessions");
    expect(migration).toContain("active_plan_revision");
    expect(migration).toContain("active_plan_hash");
    expect(migration).toContain("truncated_fact_count");
    expect(migration).toContain("warning_class");
    expect(migration).toContain("runtime_operation_id");
    expect(migration).toContain("runtime_cluster_id");
    expect(migration).toContain("runtime_agent_name");
    expect(migration).toContain("runtime_reservation_expires_at");
    expect(migration).toContain("runtime_finalization_state");
    expect(migration).toContain("idx_ingest_jobs_runtime_finalization");
    expect(migration).toMatch(
      /state IN \('succeeded', 'dead'\) THEN 'finalizing'/,
    );
    expect(migration).toMatch(
      /ALTER TABLE memories ADD COLUMN IF NOT EXISTS version/,
    );
    expect(migration).toMatch(
      /UPDATE memories\s+SET version = 1\s+WHERE version IS NULL/,
    );
    expect(migration).toMatch(/ALTER COLUMN version SET NOT NULL/);
    expect(migration.toLowerCase()).not.toContain("operation_ledger");
  });

  it("enables production in one rollout after startup migration", () => {
    const ecs = readFileSync(resolve(root, "infra/ecs.ts"), "utf8");
    const config = readFileSync(resolve(root, "sst.config.ts"), "utf8");
    const workflow = readFileSync(
      resolve(root, ".github/workflows/infra-ci.yml"),
      "utf8",
    );
    const dockerfile = readFileSync(
      resolve(root, "docker/mnemo-server/Dockerfile"),
      "utf8",
    );
    const entrypoint = readFileSync(
      resolve(root, "docker/mnemo-server/entrypoint.sh"),
      "utf8",
    );
    const schema = readFileSync(
      resolve(root, "docker/bootstrap/schema.sql"),
      "utf8",
    );
    const patch = readFileSync(
      resolve(
        root,
        "docker/mnemo-server/patches/0005-atomic-ingest-apply.patch",
      ),
      "utf8",
    );
    expect(ecs).toContain("process.env.MEM9_DURABLE_INGEST_ENABLED");
    expect(workflow.match(/MEM9_DURABLE_INGEST_ENABLED: "1"/g)).toHaveLength(3);
    expect(workflow).not.toContain('MEM9_DURABLE_INGEST_ENABLED: "0"');
    expect(workflow).not.toContain("Enable durable ingest after bootstrap");
    expect(dockerfile).toContain("postgresql-client");
    expect(dockerfile).toContain(
      "COPY docker/bootstrap/schema.sql /usr/local/share/mem9/schema.sql",
    );
    expect(dockerfile).toContain(
      "COPY docker/bootstrap/migrations/ /usr/local/share/mem9/migrations/",
    );
    expect(entrypoint).not.toContain('PGDATABASE="$MNEMO_DSN" psql');
    expect(entrypoint).toContain('psql --dbname="$MNEMO_DSN"');
    expect(entrypoint).toContain("-f /usr/local/share/mem9/schema.sql");
    expect(schema.indexOf("\\ir migrations/001_ingest_jobs.sql")).toBeLessThan(
      schema.indexOf("\\ir migrations/002_memory_namespaces.sql"),
    );
    expect(entrypoint).toContain('PGDATABASE="$MEM9_DB_NAME"');
    expect(entrypoint).toContain('PGPASSWORD="$DB_PASS"');
    expect(entrypoint).toContain("PGCONNECT_TIMEOUT");
    expect(entrypoint).toContain(
      'while [ "$i" -le "$MIGRATION_MAX_ATTEMPTS" ]',
    );
    expect(entrypoint).toContain("MIGRATION_RETRY_DELAY_SECONDS");
    expect(entrypoint).toContain("MIGRATION_SUCCEEDED=false");
    expect(entrypoint).toContain('if [ "$MIGRATION_SUCCEEDED" != true ]');
    expect(entrypoint).toContain(
      'if [ "$MIGRATION_RETRY_BUDGET_SECONDS" -ge 300 ]',
    );
    expect(entrypoint.indexOf('psql --dbname="$MNEMO_DSN"')).toBeLessThan(
      entrypoint.indexOf("exec /usr/local/bin/mnemo-server"),
    );
    const attempts = Number(
      entrypoint.match(/MNEMO_MIGRATION_MAX_ATTEMPTS:-([0-9]+)/)?.[1],
    );
    const connectTimeout = Number(
      entrypoint.match(/PGCONNECT_TIMEOUT:-([0-9]+)/)?.[1],
    );
    const retryDelay = Number(
      entrypoint.match(/MNEMO_MIGRATION_RETRY_DELAY_SECONDS:-([0-9]+)/)?.[1],
    );
    const startupGrace = Number(
      ecs.match(/startPeriod: "([0-9]+) seconds"/)?.[1],
    );
    const worstCaseRetryBudget =
      attempts * connectTimeout + (attempts - 1) * retryDelay;
    expect(worstCaseRetryBudget).toBeLessThan(startupGrace);
    expect(ecs).toContain("MEM9_TENANT_ID");
    expect(config).toContain("tenantIdentity");
    expect(patch).toContain("NewWorker");
    expect(patch).toContain("NewDurableProcessor");
    expect(patch).not.toMatch(
      /^\+\s*go func\(lease \*runtimeusage\.OperationLease\)/m,
    );
  });
});
