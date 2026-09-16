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
  extractRepositoryStatements,
  extractSqlStatements,
  assertDirectory,
  statementHash,
  validateManifest,
} from "./lib/memory-namespace-query-inventory.mjs";

const root = resolve(import.meta.dirname, "..");
const javascript = (source, owner = "scripts/example.mjs") =>
  extractSqlStatements({ kind: "javascript", owner, source });

describe("memory namespace query inventory", () => {
  it("TC-GROUPNS-096: parses a regex character class before SQL without hanging", () => {
    const source = String.raw`const valid = /[A-Za-z0-9./_#-]{1,512}/;
      db.query(\`SELECT id FROM memories WHERE namespace_id=$1\`);`.replaceAll("\\`", "`");
    const script = `import {extractSqlStatements} from './scripts/lib/memory-namespace-query-inventory.mjs';
      console.log(JSON.stringify(extractSqlStatements({kind:'javascript',owner:'example.mjs',source:${JSON.stringify(source)}})));`;
    const found = JSON.parse(execFileSync(process.execPath, ["--input-type=module", "-e", script], {
      cwd: root, encoding: "utf8", timeout: 3000,
    }));
    expect(found).toHaveLength(1);
    expect(found[0].text).toBe("SELECT id FROM memories WHERE namespace_id=$1");
  }, 5000);

  it("TC-GROUPNS-096: resolves nested const projections into the full query digest", () => {
    const source = (limit) => `
      const relation = "mem" + "ories";
      const projection = "CASE WHEN EXISTS (SELECT 1 FROM " + relation + " WHERE version > ${limit}) THEN 1 ELSE 0 END";
      const columns = \`id, \${projection} AS present\`;
      const query = \`SELECT \${columns} FROM memories WHERE namespace_id=$1\`;
    `;
    const before = javascript(source(1));
    const after = javascript(source(2));
    expect(before).toHaveLength(1);
    expect(before[0].text).toContain("EXISTS (SELECT 1 FROM memories WHERE version > 1)");
    expect(before[0].text).not.toContain("{{dynamic}}");
    expect(buildManifest(before).statements[0].statement_sha256)
      .not.toBe(buildManifest(after).statements[0].statement_sha256);
  });

  it("TC-GROUPNS-096: resolves bindings at their declaration's lexical scope", () => {
    const found = javascript(`
      const table = "memories";
      const base = "SELECT id FROM " + table;
      function outer(table) {
        const query = base + " WHERE namespace_id=$1";
        { const table = "sessions"; db.query(\`SELECT id FROM \${table} WHERE namespace_id=$1\`); }
        db.query(\`SELECT id FROM \${table} WHERE namespace_id=$1\`);
      }
    `);
    expect(found.map(({ text }) => text)).toEqual([
      "SELECT id FROM memories WHERE namespace_id=$1",
      "SELECT id FROM sessions WHERE namespace_id=$1",
      "SELECT id FROM {{dynamic}} WHERE namespace_id=$1",
    ]);
    expect(classifyStatement(found.at(-1)).classification).toBe("unclassified");
  });

  it("TC-GROUPNS-096: captures complete concatenations without partial statements", () => {
    const found = javascript(`
      db.query("SELECT id FROM memories" + (" WHERE namespace_id=" + "$1") + " AND state='active'");
    `);
    expect(found).toHaveLength(1);
    expect(found[0].text).toBe("SELECT id FROM memories WHERE namespace_id=$1 AND state='active'");
    const aliased = javascript('const base="SELECT id FROM memories"; const alias=base; const query=alias+" WHERE namespace_id=$1";');
    expect(aliased).toHaveLength(1);
    expect(aliased[0].text).toBe("SELECT id FROM memories WHERE namespace_id=$1");
    for (const use of ['db.query(base);', 'const mutable=base;', 'const text=`log ${base}`;', 'const query=tag`${base}`;']) {
      const withDirectUse = javascript(`const base="SELECT id FROM memories"; ${use}`);
      expect(withDirectUse.some(({text}) => text === "SELECT id FROM memories")).toBe(true);
    }
  });

  it("TC-GROUPNS-096: leaves calls, mutable bindings, cycles and dynamic relations unresolved", () => {
    for (const binding of [
      'let table = "memories";',
      'const table = arbitraryCode();',
      'const table = config.table;',
      'const table = table;',
      'const table = other; const other = table;',
      'import { table } from "external-package";',
    ]) {
      const found = javascript(`${binding}\nconst query = \`SELECT id FROM \${table} WHERE namespace_id=$1\`;`);
      expect(found).toHaveLength(1);
      expect(classifyStatement(found[0]).classification).toBe("unclassified");
    }
  });

  it.each(["scripts/memory-cleanup.mjs", "scripts/memory-consolidation.mjs", "infra/consolidation.ts"])(
    "TC-GROUPNS-096: enabled maintenance owner %s has no disabled exemption", (owner) => {
      expect(classifyStatement({ owner, text: "SELECT id FROM memories" }).classification).toBe("unclassified");
      expect(classifyStatement({ owner, text: "SELECT id FROM memories WHERE namespace_id=$1" }).classification).toBe("namespace_bound");
    },
  );

  it("TC-GROUPNS-096: resolves String.raw and rejects shadowed or arbitrary tags", () => {
    const source = [
      'const table = "memories";',
      'const query = String.raw`SELECT id FROM ${table} WHERE namespace_id=$1 AND value=\\n`;',
    ].join("\n");
    const found = javascript(source);
    expect(found).toHaveLength(1);
    expect(found[0].text).toContain(String.raw`value=\n`);
    expect(classifyStatement(found[0]).classification).toBe("namespace_bound");
    for (const source of [
      'function f(String) { return String.raw`SELECT id FROM memories WHERE namespace_id=$1`; }',
      'const raw = String.raw; const query = raw`SELECT id FROM memories WHERE namespace_id=$1`;',
      'const query = unknown.raw`SELECT id FROM memories WHERE namespace_id=$1`;',
      'const query = String["raw"]`SELECT id FROM memories WHERE namespace_id=$1`;',
      'const query = String.other`SELECT id FROM memories WHERE namespace_id=$1`;',
      String.raw`const query = custom\`SELECT id FROM memories WHERE namespace_id=$1 AND id=\unicode\`;`.replaceAll("\\`", "`"),
    ]) {
      const candidates = javascript(source);
      expect(candidates).toHaveLength(1);
      expect(classifyStatement(candidates[0]).classification).toBe("unclassified");
    }
  });

  it("TC-GROUPNS-096: does not execute source code or resolve mutable/destructured aliases", () => {
    const marker = globalThis.__inventoryMustNotExecute;
    for (const binding of [
      'var table = "memories";',
      'const { table } = objectWithGetters;',
      'const table = "memories"; table = "sessions";',
      'const table = String("memories");',
      'const table = 17;',
      'const table = true ? "memories" : "sessions";',
      'const table = (() => { globalThis.__inventoryMustNotExecute = true; throw new Error("must not execute"); })();',
    ]) {
      const found = javascript(`${binding}\nconst q = \`SELECT id FROM \${table} WHERE namespace_id=$1\`;`);
      expect(found).toHaveLength(1);
      expect(classifyStatement(found[0]).classification).toBe("unclassified");
    }
    expect(globalThis.__inventoryMustNotExecute).toBe(marker);
  });

  it("TC-GROUPNS-096: dynamic qualified, quoted and nested relations cannot borrow another predicate", () => {
    for (const sql of [
      'SELECT id FROM "${table}" WHERE namespace_id=$1',
      'SELECT id FROM public.${table} WHERE namespace_id=$1',
      'SELECT id FROM memories_${table} WHERE namespace_id=$1',
      'SELECT id FROM /* relation */ ${table} WHERE namespace_id=$1',
      'SELECT id FROM memories WHERE namespace_id=$1 AND EXISTS(SELECT 1 FROM ${table})',
      'SELECT m.id FROM memories AS m JOIN ${table} AS other ON other.id=m.id WHERE m.namespace_id=$1',
    ]) {
      const found = javascript(`const table = attackerControlled(); const query = \`${sql}\`;`, "scripts/memory-cleanup.mjs");
      expect(found).toHaveLength(1);
      expect(classifyStatement(found[0]).classification).toBe("unclassified");
    }
  });

  it("TC-GROUPNS-096: handles TypeScript wrappers, ambient bindings and JSX", () => {
    const found = javascript(`
      declare const unknownTable: string;
      const table = "memories" as const;
      const projection = (<string> "id")! satisfies string;
      const query = \`SELECT \${projection} FROM \${table} WHERE namespace_id=$1\`;
      const unknown = \`SELECT id FROM \${unknownTable} WHERE namespace_id=$1\`;
    `, "scripts/example.ts");
    expect(found.map(({text}) => text)).toEqual([
      "SELECT id FROM memories WHERE namespace_id=$1",
      "SELECT id FROM {{dynamic}} WHERE namespace_id=$1",
    ]);
    expect(javascript('export const view = <div>{"SELECT id FROM memories WHERE namespace_id=$1"}</div>;', "view.jsx")).toHaveLength(1);
    expect(javascript('const table: string; export {};', "types.d.ts")).toEqual([]);
  });

  it("TC-GROUPNS-096: parse errors and excessive expansion fail closed", () => {
    expect(() => javascript('const query = `SELECT id FROM memories')).toThrow(/example.mjs:1: cannot parse inventory source/);
    const deep = ['const a0 = a1;'];
    for (let n = 1; n < 80; n++) deep.push(`const a${n}=a${n+1};`);
    deep.push('const a80="memories"; const q=`SELECT id FROM ${a0}`;');
    expect(() => javascript(deep.join("\n"))).toThrow(/depth limit/);
    const large = ['const a0="memories";'];
    for (let n = 1; n <= 19; n++) large.push(`const a${n}=a${n-1}+a${n-1};`);
    expect(() => javascript(large.join("\n"))).toThrow(/size limit/);
  });

  it("TC-GROUPNS-096: deduplicates same-line SQL conservatively", () => {
    const found = javascript('const a="SELECT id FROM memories"; const b="SELECT id FROM memories"; const c=tag`SELECT id FROM memories`;');
    expect(found).toHaveLength(1);
    expect(classifyStatement(found[0]).classification).toBe("unclassified");
  });

  it("TC-GROUPNS-096: splits SQL outside quotes, dollar bodies and comments", () => {
    const found = extractSqlStatements({ kind: "sql", owner: "fixture.sql", source: `
      -- a comment with ; and SELECT * FROM sessions
      SELECT 'a;''b', "q;""uoted", $$body;$$, $tag$other;body$tag$, $1 FROM memories WHERE namespace_id=$1;
      /* SELECT * FROM sessions; ignored */
      SELECT id FROM sessions WHERE namespace_id = ?;
      SELECT 1;
      SELECT id FROM ingest_jobs WHERE namespace_id IS NOT DISTINCT FROM $1
    ` });
    expect(found).toHaveLength(3);
    expect(found.map(({ tables }) => tables)).toEqual([["memories"], ["sessions"], ["ingest_jobs"]]);
    expect(found[0].text).toContain("'a;''b'");
    expect(found.every(candidate => classifyStatement(candidate).classification === "namespace_bound")).toBe(true);
    expect(() => extractSqlStatements({kind:"unknown",owner:"x",source:""})).toThrow(/unsupported query inventory source kind/);
  });

  it("TC-GROUPNS-096: scans constant-built SQL without a source keyword shortcut", () => {
    const directory = mkdtempSync(join(tmpdir(), "mem9-js-inventory-"));
    try {
      for (const name of ["scripts/nested", "infra", "docker/bootstrap/migrations", "scripts/node_modules", "scripts/dist", "scripts/coverage", "scripts/.sst", "scripts/.git"]) mkdirSync(join(directory, name), {recursive:true});
      writeFileSync(join(directory,"docker/bootstrap/schema.sql"), "CREATE TABLE memories(id text);");
      writeFileSync(join(directory,"docker/bootstrap/migrations/001.sql"), "ALTER TABLE memories ADD COLUMN namespace_id text;");
      writeFileSync(join(directory,"scripts/analyze-ingest-prescreen.sql"), "SELECT id FROM sessions WHERE namespace_id=:'namespace_id';");
      writeFileSync(join(directory,"scripts/nested/query.js"), 'const table="mem"+"ories"; const query="SELECT id FROM "+table+" WHERE namespace_id=$1";');
      writeFileSync(join(directory,"infra/dynamic.ts"), 'declare const relation: string; const prefix="SELECT id FROM "; const query=prefix+relation+" WHERE namespace_id=$1";');
      for (const name of ["scripts/node_modules/skip.mjs", "scripts/dist/skip.mjs", "scripts/coverage/skip.mjs", "scripts/.sst/skip.mjs", "scripts/.git/skip.mjs", "scripts/skip.test.mjs", "scripts/memory-namespace-query-inventory.mjs", "scripts/verify-memory-namespace-query-inventory.mjs"]) writeFileSync(join(directory,name), "not valid JS");
      writeFileSync(join(directory,"scripts/readme.md"), "not valid JS");
      assertDirectory(directory);
      expect(() => assertDirectory(join(directory,"scripts/readme.md"))).toThrow(/not a directory/);
      const found = extractRepositoryStatements(directory);
      expect(found).toHaveLength(5);
      expect(found.find(({owner}) => owner.endsWith("query.js")).text).toBe("SELECT id FROM memories WHERE namespace_id=$1");
      expect(classifyStatement(found.find(({owner}) => owner.endsWith("dynamic.ts"))).classification).toBe("unclassified");
    } finally { rmSync(directory, {recursive:true,force:true}); }
  });

  it("TC-GROUPNS-096: psql guards and gset cannot hide subsequent payload queries", () => {
    const owner = "scripts/analyze-ingest-prescreen.sql";
    const found = extractSqlStatements({kind:"sql",owner,source:readFileSync(resolve(root,owner),"utf8")});
    expect(found).toHaveLength(2);
    expect(found.find(({text}) => text.startsWith("INSERT INTO ingest_prescreen_features")).tables)
      .toEqual(["ingest_job_plans", "ingest_jobs"]);
    const directives = extractSqlStatements({kind:"sql",owner:"fixture.sql",source:String.raw`
      \set flag true
      SELECT id FROM memories WHERE namespace_id=$1 \gset
      \if :flag
      SELECT '\endif' FROM sessions WHERE namespace_id=$1;
      \else
      SELECT id FROM ingest_jobs WHERE namespace_id=$1;
      \endif
      SELECT id
      \set label ignored
      FROM memories WHERE namespace_id=$1;
      SELECT id FROM memories WHERE namespace_id=$1 \g
    `});
    expect(directives).toHaveLength(5);
    expect(directives[1].text).toContain(String.raw`'\endif'`);
    expect(directives[3].text).toBe("SELECT id FROM memories WHERE namespace_id=$1");
    expect(extractSqlStatements({kind:"sql",owner:"x.sql",source:"SELECT id FROM memories WHERE namespace_id=$1 \\gset"})).toHaveLength(1);
    for (const command of ["copy", "gexec", "unknown", "!"])
      expect(() => extractSqlStatements({kind:"sql",owner:"x.sql",source:`\\${command} SELECT id FROM memories`})).toThrow(/unsupported SQL-producing psql command/);
  });

  it("TC-GROUPNS-096: maintenance inventory preserves every archive/winner/restore predicate", () => {
    const cleanupOwner = "scripts/memory-cleanup.mjs";
    const consolidationOwner = "scripts/memory-consolidation.mjs";
    const cleanupSource = readFileSync(resolve(root, cleanupOwner), "utf8");
    const cleanup = javascript(cleanupSource, cleanupOwner);
    const consolidation = javascript(readFileSync(resolve(root, consolidationOwner), "utf8"), consolidationOwner);
    const projections = cleanup.filter(({text}) => text.startsWith("SELECT memory.id"));
    expect(projections).toHaveLength(2);
    for (const {text} of projections) {
      expect(text).toContain("winner.namespace_id = $1");
      expect(text).toContain("memory.namespace_id = $1");
      expect(text).toContain("ELSE NULL END AS superseded_by");
    }
    expect(cleanup.find(({text}) => text.startsWith("UPDATE memories")).text)
      .toContain("WHERE namespace_id = $1 AND id = $2 AND state = $3 AND version = $4");
    const archive = consolidation.find(({text}) => text.startsWith("UPDATE memories AS loser"));
    expect(archive.text).toContain("loser.namespace_id = $7");
    expect(archive.text).toContain("winner.namespace_id = $7");
    const changed = javascript(cleanupSource.replace("winner.namespace_id = $1 AND ", ""), cleanupOwner);
    expect(compareManifests(buildManifest(cleanup), buildManifest(changed))).not.toEqual([]);
    for (const candidate of [...cleanup, ...consolidation]) {
      expect(classifyStatement(candidate).classification).toBe("namespace_bound");
      expect(classifyStatement(candidate).coverage).toContain("scripts/maintenance-postgres.test.mjs");
    }
    expect(classifyStatement({owner:"upstream/server/internal/repository/postgres/namespace_sampler.go",text:"SELECT min(created_at) FROM ingest_jobs WHERE namespace_id=$1"}).coverage)
      .toContain("upstream/server/internal/repository/postgres/namespace_sampler_test.go");
    expect(classifyStatement({owner:"scripts/analyze-ingest-prescreen.sql",text:"SELECT id FROM ingest_jobs WHERE namespace_id=:'namespace_id'"}).coverage)
      .toContain("scripts/run-analysis-namespace-integration.sh");
  });

  it("TC-GROUPNS-096: keeps explicit migration, backend, startup and emergency policies", () => {
    for (const [owner, text, expected] of [
      ["docker/bootstrap/schema.sql", "CREATE TABLE memories(id text)", "schema_migration"],
      ["scripts/migrate-memory-namespaces.mjs", "UPDATE memories SET namespace_id=$1", "migration_operator"],
      ["upstream/server/internal/repository/tidb/memory.go", "SELECT id FROM memories", "unsupported_backend"],
      ["upstream/server/internal/repository/db9/memory.go", "SELECT id FROM memories", "unsupported_backend"],
      ["scripts/manage-memory-access.mjs", "UPDATE ingest_jobs SET state='dead' WHERE principal_id=$1", "emergency_control_plane"],
      ["upstream/server/cmd/mnemo-server/main.go", "SELECT count(*) FROM memories WHERE namespace_id IS NULL", "startup_gate"],
      ["scripts/analyze-ingest-prescreen.sql", "SELECT id FROM ingest_jobs WHERE namespace_id=:'namespace_id'", "namespace_bound"],
      ["example.sql", "INSERT INTO memories (namespace_id, id) VALUES ($1,$2)", "namespace_bound"],
      ["example.sql", "ALTER TABLE memories ADD FOREIGN KEY (namespace_id) REFERENCES namespaces(id)", "namespace_bound"],
      ["infra/slack-approval/example.ts", "SELECT id FROM memories", "disabled_capability"],
    ]) expect(classifyStatement({owner,text}).classification).toBe(expected);
  });

  it("TC-GROUPNS-096: validation rejects duplicate IDs, duplicate policies and malformed policies", () => {
    const candidate = {owner:"scripts/example.mjs",line:1,text:"SELECT id FROM memories",tables:["memories"]};
    expect(validateManifest(buildManifest([candidate]))[0]).toContain("unclassified scoped SQL");
    expect(validateManifest(buildManifest([candidate, candidate])).some(error => error.includes("duplicate inventory ids"))).toBe(true);
    const policy = {owner:candidate.owner,statement_sha256:statementHash(candidate.text),classification:"namespace_composed_or_compatibility",rationale:"Reviewed fixture",coverage:["fixture.test.mjs"],namespace_evidence:"reviewed fixture scope"};
    const manifest = buildManifest([candidate], {}, [policy]);
    expect(validateManifest(manifest,[policy])).toEqual([]);
    expect(validateManifest(manifest,[policy,policy])[0]).toContain("duplicate trusted exceptions");
    expect(manifest.statements[0].namespace_evidence).toBe("reviewed fixture scope");
    for (const bad of [{classification:"anything"},{rationale:0},{rationale:""},{coverage:null},{coverage:[]}])
      expect(validateManifest(manifest,[{...policy,...bad}])[0]).toContain("invalid trusted exception");
    expect(buildManifest([candidate,{...candidate,line:1,text:"SELECT content FROM memories"}]).statements).toHaveLength(2);
  });

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
          // A cold Go toolchain build can exceed 20s on a shared runner.
          // Bound the subprocess separately from the enclosing test budget.
          { encoding: "utf8", timeout: 45_000 },
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
  }, 60_000);

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
    for (const name of ["namespace_id", "analysis_cutoff", "label_start"]) {
      const start = sql.indexOf(`\\if :{?${name}}`);
      const end = sql.indexOf("\\endif", start);
      expect(start).toBeGreaterThan(-1);
      expect(sql.slice(start, end)).toContain(`RAISE EXCEPTION '${name} is required'`);
      expect(end).toBeLessThan(sql.indexOf("BEGIN TRANSACTION READ WRITE"));
    }
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
