import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  buildManifest,
  classifyStatement,
  compareManifests,
  extractSqlStatements,
  statementHash,
  validateManifest,
} from "./lib/memory-namespace-query-inventory.mjs";

const root = resolve(import.meta.dirname, "..");

describe("memory namespace query inventory", () => {
  it("TC-GROUPNS-096: extracts scoped statements without matching comments", () => {
    const candidates = extractSqlStatements({
      kind: "javascript",
      owner: "scripts/example.mjs",
      source: `
        // SELECT * FROM memories
        await db.query(
          \`SELECT id FROM memories
             WHERE namespace_id = $1 AND id = $2\`,
          [namespaceID, id],
        );
        const unrelated = "memories are useful";
      `,
    });

    expect(candidates).toHaveLength(1);
    expect(candidates[0]).toMatchObject({
      owner: "scripts/example.mjs",
      line: 4,
      tables: ["memories"],
    });
  });

  it("TC-GROUPNS-096: reconstructs interpolated templates before relation analysis", () => {
    const candidates = extractSqlStatements({
      kind: "javascript",
      owner: "scripts/example.mjs",
      source: `
        const query = \`SELECT \${columns}
                         FROM memories
                        WHERE namespace_id = \${namespaceID}\`;
      `,
    });

    expect(candidates).toHaveLength(1);
    expect(candidates[0]).toMatchObject({
      owner: "scripts/example.mjs",
      line: 2,
      tables: ["memories"],
    });
    expect(candidates[0].text).toContain("SELECT {{dynamic}} FROM memories");
    expect(candidates[0].text).toContain("namespace_id = {{dynamic}}");
  });

  it("TC-GROUPNS-096: fails closed on JavaScript string-concatenated relations", () => {
    const candidates = extractSqlStatements({
      kind: "javascript",
      owner: "scripts/example.mjs",
      source: `
        const query =
          "SELECT " + columns + " FROM " + table +
          " WHERE namespace_id = $1";
      `,
    });

    expect(candidates).toHaveLength(1);
    expect(candidates[0]).toMatchObject({
      owner: "scripts/example.mjs",
      line: 3,
      tables: ["<dynamic-relation>"],
    });
    expect(candidates[0].text).toBe(
      "SELECT {{dynamic}} FROM {{dynamic}} WHERE namespace_id = $1",
    );
    expect(classifyStatement(candidates[0])).toMatchObject({
      classification: "unclassified",
    });
  });

  it("TC-GROUPNS-096: inventories the existing legacy cleanup SQL", () => {
    const source = readFileSync(
      resolve(root, "scripts/memory-cleanup.mjs"),
      "utf8",
    );
    const candidates = extractSqlStatements({
      kind: "javascript",
      owner: "scripts/memory-cleanup.mjs",
      source,
    });

    expect(candidates.length).toBeGreaterThan(0);
    expect(candidates.some(({ tables }) => tables.includes("memories"))).toBe(
      true,
    );
  });

  it("TC-GROUPNS-096: reconstructs Go string concatenation around dynamic columns", () => {
    const directory = mkdtempSync(join(tmpdir(), "mem9-go-sql-inventory-"));
    const server = resolve(directory, "server");
    try {
      mkdirSync(server);
      writeFileSync(
        resolve(server, "repository.go"),
        `package repository

const allColumns = "id, content"

func query() string {
	return \`SELECT \` + allColumns + \` FROM memories WHERE namespace_id = $1\`
}
`,
      );

      const candidates = JSON.parse(
        execFileSync(
          "go",
          ["run", resolve(root, "scripts/extract-go-sql.go"), server],
          { encoding: "utf8" },
        ),
      );

      expect(candidates).toEqual([
        expect.objectContaining({
          owner: "upstream/server/repository.go",
          tables: ["memories"],
        }),
      ]);
      expect(candidates[0].text).toContain(
        "SELECT id, content FROM memories WHERE namespace_id = $1",
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }, 20_000);

  it("TC-GROUPNS-096: classifies an explicit namespace predicate", () => {
    expect(
      classifyStatement({
        owner: "scripts/example.mjs",
        text: "SELECT id FROM memories WHERE namespace_id = $1",
        tables: ["memories"],
      }),
    ).toMatchObject({
      classification: "namespace_bound",
      namespace_evidence: "namespace_id = $1",
    });
  });

  it("TC-GROUPNS-096: accepts only named trusted exceptions", () => {
    expect(
      classifyStatement({
        owner: "docker/bootstrap/migrations/002_memory_namespaces.sql",
        text: "ALTER TABLE memories ADD COLUMN namespace_id varchar(36)",
        tables: ["memories"],
      }),
    ).toMatchObject({ classification: "schema_migration" });

    expect(
      classifyStatement({
        owner: "upstream/server/internal/repository/postgres/upload_task.go",
        text: "SELECT task_id FROM upload_tasks WHERE status = 'pending'",
        tables: ["upload_tasks"],
      }),
    ).toMatchObject({ classification: "disabled_capability" });

    expect(
      classifyStatement({
        owner: "scripts/unknown.mjs",
        text: "SELECT id FROM memories WHERE id = $1",
        tables: ["memories"],
      }),
    ).toMatchObject({ classification: "unclassified" });

    const statement = {
      owner: "upstream/server/internal/repository/postgres/memory.go",
      text: "SELECT id FROM memories WHERE id = $1",
      tables: ["memories"],
    };
    expect(classifyStatement(statement)).toMatchObject({
      classification: "unclassified",
    });
    expect(
      classifyStatement(statement, [
        {
          owner: statement.owner,
          statement_sha256: statementHash(statement.text),
          classification: "namespace_composed_or_compatibility",
          rationale: "Reviewed additive compatibility branch.",
          coverage: [
            "upstream/server/internal/repository/postgres/namespace_integration_test.go",
          ],
        },
      ]),
    ).toMatchObject({
      classification: "namespace_composed_or_compatibility",
    });
    expect(
      classifyStatement({ ...statement, text: `${statement.text} LIMIT 1` }, [
        {
          owner: statement.owner,
          statement_sha256: statementHash(statement.text),
          classification: "namespace_composed_or_compatibility",
          rationale: "Reviewed additive compatibility branch.",
          coverage: [
            "upstream/server/internal/repository/postgres/namespace_integration_test.go",
          ],
        },
      ]),
    ).toMatchObject({ classification: "unclassified" });
  });

  it("TC-GROUPNS-096: rejects a changed or newly added statement", () => {
    const reviewed = buildManifest([
      {
        owner: "scripts/example.mjs",
        line: 1,
        text: "SELECT id FROM memories WHERE namespace_id = $1",
        tables: ["memories"],
      },
    ]);
    const changed = buildManifest([
      {
        owner: "scripts/example.mjs",
        line: 1,
        text: "SELECT id, content FROM memories WHERE namespace_id = $1",
        tables: ["memories"],
      },
    ]);

    expect(compareManifests(reviewed, reviewed)).toEqual([]);
    expect(compareManifests(reviewed, changed)).toEqual([
      "query inventory differs from the reviewed manifest",
    ]);
  });

  it("TC-GROUPNS-096: rejects stale or malformed trusted exceptions", () => {
    const manifest = buildManifest([]);
    expect(
      validateManifest(manifest, [
        {
          owner: "upstream/server/internal/repository/postgres/memory.go",
          statement_sha256: "0".repeat(64),
          classification: "namespace_composed_or_compatibility",
          rationale: "Reviewed additive compatibility branch.",
          coverage: [
            "upstream/server/internal/repository/postgres/namespace_integration_test.go",
          ],
        },
      ]),
    ).toEqual([
      `upstream/server/internal/repository/postgres/memory.go:${"0".repeat(64)}: unused trusted exception`,
    ]);
  });

  it("TC-GROUPNS-096: prescreen analysis requires and binds one namespace", () => {
    const sql = readFileSync(
      resolve(root, "scripts/analyze-ingest-prescreen.sql"),
      "utf8",
    );

    expect(sql).toContain("--set=namespace_id=<namespace-uuid>");
    expect(sql).toMatch(/\\if :\{\?namespace_id\}[\s\S]*\\else[\s\S]*\\quit/);
    expect(sql).toMatch(
      /FROM ingest_jobs AS job[\s\S]*WHERE job\.namespace_id = :'namespace_id'/,
    );
    expect(sql).toMatch(
      /FROM ingest_job_plans AS retained[\s\S]*retained\.namespace_id = :'namespace_id'[\s\S]*retained\.namespace_id = job\.namespace_id/,
    );
    expect(sql).toMatch(
      /FROM ingest_job_plans AS retained[\s\S]*retained\.namespace_id = :'namespace_id'/,
    );
  });

  it("TC-GROUPNS-096: CI inventories the fully patched upstream source", () => {
    const integration = readFileSync(
      resolve(root, "scripts/run-ingest-queue-integration.sh"),
      "utf8",
    );
    const applyIndex = integration.indexOf(
      'git -C "$TMP_DIR/upstream" apply "$ROOT"/docker/mnemo-server/patches/*.patch',
    );
    const verifyIndex = integration.indexOf(
      "verify-memory-namespace-query-inventory.mjs",
    );

    expect(applyIndex).toBeGreaterThanOrEqual(0);
    expect(verifyIndex).toBeGreaterThan(applyIndex);
  });
});
