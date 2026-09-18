import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const entrypoint = join(import.meta.dirname, "entrypoint.sh");
const flags = [
  "MNEMO_UPLOAD_WORKER_ENABLED",
  "MNEMO_WEBHOOKS_ENABLED",
  "MNEMO_SPACE_CHAINS_ENABLED",
];
let directory;
let trace;

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "mem9-entrypoint-guard-"));
  trace = join(directory, "calls");
  for (const [name, status] of [["jq", 41], ["psql", 42]]) {
    writeFileSync(
      join(directory, name),
      `#!/bin/sh\nprintf '%s\\n' '${name}' >> "$ENTRYPOINT_TRACE"\nexit ${status}\n`,
      { mode: 0o700 },
    );
  }
});

afterEach(() => rmSync(directory, { recursive: true, force: true }));

function run(extra = {}) {
  return spawnSync("/bin/sh", [entrypoint], {
    env: {
      PATH: directory,
      ENTRYPOINT_TRACE: trace,
      MNEMO_NAMESPACE_REQUIRED: "1",
      MNEMO_MIGRATION_MAX_ATTEMPTS: "1",
      MNEMO_MIGRATION_RETRY_DELAY_SECONDS: "0",
      PGCONNECT_TIMEOUT: "1",
      ...extra,
    },
    encoding: "utf8",
    timeout: 2_000,
  });
}

describe("namespace capability guards at the container entrypoint", () => {
  it.each(flags)("TC-GROUPNS-103/104: rejects %s before credentials or schema SQL", (flag) => {
    for (const required of ["0", "1"]) {
      for (const value of ["1", " true ", "INVALID-PRIVATE-MARKER"]) {
        for (const credentials of [
          {},
          { MNEMO_DSN: "postgres://fixture" },
          {
            MEM9_DB_HOST: "db.example.com",
            MEM9_DB_PORT: "5432",
            MEM9_DB_NAME: "fixture",
            MEM9_DB_SECRET: '{"username":"fixture","password":"PRIVATE-SECRET-MARKER"}',
          },
        ]) {
          const result = run({ ...credentials, MNEMO_NAMESPACE_REQUIRED: required, [flag]: value });
          expect(result.error).toBeUndefined();
          expect(result.status).toBe(1);
          expect(result.stderr).toContain(flag);
          expect(result.stderr).not.toContain("required to assemble");
          expect(result.stderr).not.toContain("PRIVATE-MARKER");
          expect(result.stdout + result.stderr).not.toContain("PRIVATE-SECRET-MARKER");
          expect(result.stdout).not.toContain("applying atomic-ingest migration");
          expect(existsSync(trace)).toBe(false);
        }
      }
    }
  });

  it.each(["", "0", "f", "F", "false", "False", "FALSE", " \tfalse\r\n"])(
    "accepts Go-compatible disabled values (%j) and reaches the migration boundary",
    (value) => {
      const result = run({ MNEMO_DSN: "postgres://fixture", ...Object.fromEntries(flags.map(flag => [flag, value])) });
      expect(result.error).toBeUndefined();
      expect(result.status).toBe(42);
      expect(readFileSync(trace, "utf8")).toBe("psql\n");
    },
  );

  it("preserves normal bootstrap when capability flags are absent", () => {
    const result = run({ MNEMO_DSN: "postgres://fixture" });
    expect(result.status).toBe(42);
    expect(readFileSync(trace, "utf8")).toBe("psql\n");
  });

  it("TC-GROUPNS-113: labels the control-plane PostgreSQL pool", () => {
    writeFileSync(
      join(directory, "jq"),
      '#!/bin/sh\nexec /usr/bin/jq "$@"\n',
      { mode: 0o700 },
    );
    const result = run({
      MEM9_DB_HOST: "db.example.com",
      MEM9_DB_PORT: "5432",
      MEM9_DB_NAME: "fixture",
      MEM9_DB_SECRET: '{"username":"fixture","password":"fixture"}',
    });
    expect(result.status).toBe(42);
    expect(result.stdout).toContain(
      "application_name=mem9-server-control",
    );
  });
});
