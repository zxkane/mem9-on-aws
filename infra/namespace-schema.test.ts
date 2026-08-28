import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const migrationPath = resolve(
  root,
  "docker/bootstrap/migrations/002_memory_namespaces.sql",
);

describe("memory namespace additive migration", () => {
  it("TC-GROUPNS-059/060: creates the complete control plane repeatably", () => {
    const sql = readFileSync(migrationPath, "utf8");
    for (const table of [
      "memory_namespaces",
      "memory_principals",
      "memory_cognito_group_bindings",
      "memory_namespace_memberships",
      "memory_m2m_namespace_bindings",
      "memory_namespace_migration_state",
    ]) {
      expect(sql).toMatch(
        new RegExp(`CREATE TABLE IF NOT EXISTS ${table}\\b`, "u"),
      );
    }
    expect(sql).toContain("ON CONFLICT (singleton_id) DO NOTHING");
    expect(sql).toContain("'additive_ready'");
  });

  it("adds nullable namespace and actor columns without inventing a default", () => {
    const sql = readFileSync(migrationPath, "utf8");
    for (const table of [
      "memories",
      "sessions",
      "ingest_jobs",
      "ingest_job_plans",
      "upload_tasks",
    ]) {
      expect(sql).toMatch(
        new RegExp(
          `ALTER TABLE ${table}\\s+ADD COLUMN IF NOT EXISTS namespace_id VARCHAR\\(36\\)`,
          "u",
        ),
      );
    }
    expect(sql).not.toMatch(
      /ADD COLUMN IF NOT EXISTS namespace_id[^;]*DEFAULT/iu,
    );
    expect(sql).toContain("created_by_principal_id");
    expect(sql).toContain("updated_by_principal_id");
    expect(sql).toContain("principal_id");
  });

  it("wires additive namespace migration before mnemo-server starts", () => {
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
    expect(dockerfile).toContain("docker/bootstrap/schema.sql");
    expect(dockerfile).toContain("docker/bootstrap/migrations/");
    expect(entrypoint).toContain("/usr/local/share/mem9/schema.sql");
    expect(entrypoint).not.toContain(
      "-f /usr/local/share/mem9/002_memory_namespaces.sql",
    );
    expect(schema).toContain("\\ir migrations/002_memory_namespaces.sql");
  });

  it("builds namespace data-plane indexes only in the guarded operator", () => {
    const sql = readFileSync(migrationPath, "utf8");
    const operator = readFileSync(
      resolve(root, "scripts/migrate-memory-namespaces.mjs"),
      "utf8",
    );
    expect(sql).not.toMatch(
      /CREATE (?:UNIQUE )?INDEX IF NOT EXISTS idx_memories_namespace/iu,
    );
    expect(sql).not.toMatch(
      /CREATE (?:UNIQUE )?INDEX IF NOT EXISTS uq_ingest_jobs_namespace/iu,
    );
    expect(operator).toContain(
      "CREATE INDEX CONCURRENTLY idx_memories_namespace_state",
    );
    expect(operator).toContain(
      "CREATE UNIQUE INDEX CONCURRENTLY uq_ingest_jobs_namespace_job",
    );
    expect(operator).toContain("indisvalid");
    expect(operator).toContain("DROP INDEX CONCURRENTLY IF EXISTS");
  });
});
