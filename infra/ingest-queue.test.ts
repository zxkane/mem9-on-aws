import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

describe("durable ingest migration", () => {
  it("is included by bootstrap and defines the complete idempotent tenant job schema", () => {
    const migration = readFileSync(
      resolve(root, "docker/bootstrap/migrations/001_ingest_jobs.sql"),
      "utf8",
    );
    const schema = readFileSync(resolve(root, "docker/bootstrap/schema.sql"), "utf8");
    const dockerfile = readFileSync(resolve(root, "docker/bootstrap/Dockerfile"), "utf8");

    expect(schema).toContain("\\ir migrations/001_ingest_jobs.sql");
    expect(dockerfile).toContain("docker/bootstrap/migrations/");
    expect(migration).toMatch(/CREATE TABLE IF NOT EXISTS ingest_jobs\b/);
    for (const column of [
      "job_id",
      "tenant_id",
      "idempotency_key",
      "canonical_payload",
      "agent_id",
      "app_id",
      "session_id",
      "state",
      "attempt_count",
      "available_at",
      "lease_owner",
      "lease_expires_at",
      "heartbeat_at",
      "plan_payload",
      "plan_warning_count",
      "apply_warning_count",
      "warning_count",
      "error_class",
      "created_at",
      "updated_at",
      "completed_at",
    ]) {
      expect(migration).toMatch(new RegExp(`\\b${column}\\b`));
    }
    for (const state of [
      "queued",
      "processing",
      "planning",
      "applying",
      "retry_wait",
      "succeeded",
      "dead",
    ]) {
      expect(migration).toContain(`'${state}'`);
    }
    for (const index of [
      "uq_ingest_jobs_tenant_idempotency",
      "idx_ingest_jobs_fifo",
      "idx_ingest_jobs_claim",
      "idx_ingest_jobs_lease",
      "idx_ingest_jobs_status",
    ]) {
      expect(migration).toContain(index);
    }
    expect(migration).toMatch(/ADD COLUMN IF NOT EXISTS/);
    expect(migration.toLowerCase()).not.toMatch(
      /\b(api_key|authorization|credential|password|secret|access_token)\b/,
    );
  });
});
