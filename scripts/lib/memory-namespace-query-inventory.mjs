import { createHash } from "node:crypto";
import {
  readdirSync,
  readFileSync,
  statSync,
} from "node:fs";
import { relative, resolve } from "node:path";

import { parse } from "@babel/parser";
import traverseModule from "@babel/traverse";

const traverse = traverseModule.default ?? traverseModule;

export const SCOPED_TABLES = [
  "ingest_job_plans",
  "ingest_jobs",
  "upload_tasks",
  "memories",
  "sessions",
];

const SQL_PREFIX =
  /^\s*(?:SELECT|INSERT|UPDATE|DELETE|MERGE|WITH|CREATE|ALTER|DROP|TRUNCATE)\b/i;
const TABLE_PATTERN = new RegExp(
  String.raw`\b(?:FROM|JOIN|INTO|UPDATE|TABLE|REFERENCES|ON)\s+` +
    String.raw`(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(?:ONLY\s+)?` +
    String.raw`(?:(?:"?[A-Za-z_][A-Za-z_0-9]*"?)\.)?` +
    String.raw`"?(${SCOPED_TABLES.join("|")})"?\b`,
  "gi",
);
const DYNAMIC_RELATION_PATTERN =
  /\b(?:FROM|JOIN|INTO|UPDATE|TABLE|REFERENCES|ON)\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(?:ONLY\s+)?[^\s(),;]*\{\{dynamic\}\}/i;

function normalizeSql(text) {
  return text
    .replace(/--[^\n]*/g, " ")
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/;$/, "");
}

function tablesIn(text) {
  return [
    ...new Set(
      [...text.matchAll(TABLE_PATTERN)].map((match) =>
        match[1].toLowerCase(),
      ),
    ),
  ].sort();
}

function isScopedSql(text) {
  return (
    SQL_PREFIX.test(text) &&
    (tablesIn(text).length > 0 || DYNAMIC_RELATION_PATTERN.test(text))
  );
}

const DYNAMIC_SQL = "{{dynamic}}";
const MAX_STATIC_SQL_LENGTH = 1_048_576;
const MAX_STATIC_SQL_DEPTH = 64;
const TRANSPARENT_EXPRESSIONS = new Set([
  "ParenthesizedExpression", "TSAsExpression", "TSTypeAssertion",
  "TSNonNullExpression", "TSSatisfiesExpression",
]);

function isStringExpression(path) {
  return path.isStringLiteral() || path.isTemplateLiteral() ||
    path.isBinaryExpression({ operator: "+" }) || path.isTaggedTemplateExpression() ||
    TRANSPARENT_EXPRESSIONS.has(path.node.type);
}

function extractJavaScript({ owner, source }) {
  let ast;
  try {
    ast = parse(source, {
      sourceType: "unambiguous",
      allowAwaitOutsideFunction: true,
      plugins: [
        ...(/\.(?:[cm]?ts|tsx)$/.test(owner) ? [["typescript", { dts: /\.d\.[cm]?ts$/.test(owner) }]] : []),
        ...(/\.[jt]sx$/.test(owner) ? ["jsx"] : []),
      ],
    });
  } catch (error) {
    throw new Error(`${owner}:${error.loc?.line ?? "?"}: cannot parse inventory source (${error.reasonCode ?? "syntax error"})`);
  }
  const candidates = new Map();
  const cache = new WeakMap();
  const resolving = new Set();
  const unknown = () => ({ text: DYNAMIC_SQL, unsupported: false });
  const combine = (parts, unsupported = false) => {
    const text = parts.map(part => part.text).join("");
    if (text.length > MAX_STATIC_SQL_LENGTH) {
      throw new Error(`${owner}: static SQL expansion exceeds size limit`);
    }
    return { text, unsupported: unsupported || parts.some(part => part.unsupported) };
  };
  const template = (path, raw, depth) => {
    const expressions = path.get("expressions");
    const parts = [];
    path.node.quasis.forEach((quasi, index) => {
      const text = raw ? quasi.value.raw : quasi.value.cooked;
      parts.push(text == null ? unknown() : { text, unsupported: false });
      if (index < expressions.length) parts.push(expand(expressions[index], depth + 1));
    });
    return combine(parts);
  };
  // Interpret only immutable lexical string syntax. Never call Babel's
  // evaluator or execute source calls, imports, getters, or arbitrary tags.
  const expand = (path, depth = 0) => {
    if (depth > MAX_STATIC_SQL_DEPTH) {
      throw new Error(`${owner}: static SQL expansion exceeds depth limit`);
    }
    if (cache.has(path.node)) return cache.get(path.node);
    if (resolving.has(path.node)) return unknown();
    resolving.add(path.node);
    let result;
    if (path.isStringLiteral()) {
      result = { text: path.node.value, unsupported: false };
    } else if (path.isTemplateLiteral()) {
      result = template(path, false, depth);
    } else if (path.isBinaryExpression({ operator: "+" })) {
      result = combine([expand(path.get("left"), depth + 1), expand(path.get("right"), depth + 1)]);
    } else if (path.isIdentifier()) {
      const binding = path.scope.getBinding(path.node.name);
      result = binding?.kind === "const" && binding.constant &&
        binding.path.isVariableDeclarator() && binding.path.get("id").isIdentifier() &&
        binding.path.node.init
        ? expand(binding.path.get("init"), depth + 1)
        : unknown();
    } else if (path.isTaggedTemplateExpression()) {
      const tag = path.get("tag");
      const raw = tag.isMemberExpression({ computed: false }) &&
        tag.get("object").isIdentifier({ name: "String" }) &&
        !tag.scope.getBinding("String") && tag.get("property").isIdentifier({ name: "raw" });
      // Unknown tags are never executed. Retain their raw source for an
      // unclassified candidate even when a cooked escape would be invalid.
      result = combine([template(path.get("quasi"), true, depth)], !raw);
    } else if (TRANSPARENT_EXPRESSIONS.has(path.node.type)) {
      result = expand(path.get("expression"), depth + 1);
    } else {
      result = unknown();
    }
    resolving.delete(path.node);
    cache.set(path.node, result);
    return result;
  };

  // A const SQL prefix used only to build larger, inspectable queries is not
  // another statement. Keep definitions with direct/unknown uses so this
  // reduction never hides a query whose enclosing expression is opaque.
  const onlyComposedUses = (binding, seen = new Set()) => {
    if (!binding || binding.kind !== "const" || !binding.constant ||
      !binding.referencePaths.length || seen.has(binding)) return false;
    const next = new Set(seen).add(binding);
    return binding.referencePaths.every(reference => {
      let enclosing = reference;
      while (enclosing.parentPath && isStringExpression(enclosing.parentPath))
        enclosing = enclosing.parentPath;
      if (enclosing !== reference) {
        const value = expand(enclosing);
        return !value.unsupported && isScopedSql(normalizeSql(value.text));
      }
      const parent = reference.parentPath;
      return parent.isVariableDeclarator() && parent.get("id").isIdentifier() &&
        parent.node.init === reference.node &&
        onlyComposedUses(parent.scope.getBinding(parent.node.id.name), next);
    });
  };

  traverse(ast, {
    enter(path) {
      if (!isStringExpression(path)) return;
      // A concatenation/template is one candidate. Its literal children are
      // incomplete projections/predicates, not additional SQL statements.
      if (path.parentPath && isStringExpression(path.parentPath)) return;
      const resolved = expand(path);
      const text = normalizeSql(resolved.text);
      if (!isScopedSql(text)) return;
      const declaration = path.parentPath;
      if (declaration?.isVariableDeclarator() && declaration.get("id").isIdentifier() &&
        onlyComposedUses(declaration.scope.getBinding(declaration.node.id.name))) return;
      const tables = tablesIn(text);
      const candidate = {
        owner,
        line: path.node.loc.start.line,
        text,
        tables: tables.length ? tables : ["<dynamic-relation>"],
      };
      const key = `${candidate.line}\n${candidate.text}`;
      if (resolved.unsupported) candidate.unsupported_expression = true;
      const previous = candidates.get(key);
      if (!previous || resolved.unsupported) candidates.set(key, candidate);
    },
  });
  return [...candidates.values()];
}

function splitSql(source) {
  const statements = [];
  let start = 0;
  let startLine = 1;
  let line = 1;
  let state = "plain";
  let dollarTag = "";

  const push = (end) => {
    const text = normalizeSql(source.slice(start, end));
    if (isScopedSql(text)) {
      statements.push({ line: startLine, text });
    }
    start = end + 1;
    startLine = line;
  };

  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    const next = source[index + 1];
    if (char === "\n") line += 1;

    if (state === "line-comment") {
      if (char === "\n") state = "plain";
      continue;
    }
    if (state === "block-comment") {
      if (char === "*" && next === "/") {
        state = "plain";
        index += 1;
      }
      continue;
    }
    if (state === "single") {
      if (char === "'" && next === "'") {
        index += 1;
      } else if (char === "'") {
        state = "plain";
      }
      continue;
    }
    if (state === "double") {
      if (char === '"' && next === '"') {
        index += 1;
      } else if (char === '"') {
        state = "plain";
      }
      continue;
    }
    if (state === "dollar") {
      if (source.startsWith(dollarTag, index)) {
        index += dollarTag.length - 1;
        state = "plain";
      }
      continue;
    }

    if (char === "\\") {
      const command = source.slice(index).match(/^\\([A-Za-z_]+)/)?.[1];
      const execute = ["g", "gset", "gx", "watch"].includes(command);
      const control = ["set", "unset", "pset", "if", "elif", "else", "endif",
        "echo", "warn", "q", "quit", "i", "ir", "include", "include_relative",
        "encoding", "conninfo", "timing"].includes(command);
      if (!execute && !control) {
        throw new Error("unsupported SQL-producing psql command in query inventory");
      }
      // psql controls are not SQL. Blank them while preserving offsets and
      // line numbers; g/gset terminate the current SQL buffer without ';'.
      if (execute) push(index);
      const newline = source.indexOf("\n", index);
      const end = newline < 0 ? source.length : newline;
      source = source.slice(0, index) + " ".repeat(end - index) + source.slice(end);
      index = end - 1;
      continue;
    }

    if (char === "-" && next === "-") {
      state = "line-comment";
      index += 1;
    } else if (char === "/" && next === "*") {
      state = "block-comment";
      index += 1;
    } else if (char === "'") {
      state = "single";
    } else if (char === '"') {
      state = "double";
    } else if (char === "$") {
      const match = source.slice(index).match(/^\$[A-Za-z_0-9]*\$/);
      if (match) {
        dollarTag = match[0];
        state = "dollar";
        index += dollarTag.length - 1;
      }
    } else if (char === ";") {
      push(index);
    }
  }

  if (start < source.length) push(source.length);
  return statements;
}

export function extractSqlStatements({ kind, owner, source }) {
  if (kind === "javascript") {
    return extractJavaScript({ owner, source });
  }
  if (kind === "sql") {
    return splitSql(source).map((statement) => ({
      owner,
      ...statement,
      tables: tablesIn(statement.text),
    }));
  }
  throw new Error(`unsupported query inventory source kind: ${kind}`);
}

function namespaceEvidence(text) {
  const equality = text.match(
    /\bnamespace_id\b\s*=\s*(\$[0-9]+|\?|:'?namespace_id'?|:[A-Za-z_][A-Za-z_0-9]*|\{\{dynamic\}\})/i,
  );
  if (equality) return equality[0].replace(/\s+/g, " ");
  const nullSafeEquality = text.match(
    /\bnamespace_id\b\s+IS\s+NOT\s+DISTINCT\s+FROM\s+(\$[0-9]+|\?|:'?namespace_id'?|:[A-Za-z_][A-Za-z_0-9]*|\{\{dynamic\}\})/i,
  );
  if (nullSafeEquality) {
    return nullSafeEquality[0].replace(/\s+/g, " ");
  }
  if (
    /\bINSERT\s+INTO\b[\s\S]*\([^)]*\bnamespace_id\b[^)]*\)[\s\S]*\bVALUES\b/i.test(
      text,
    )
  ) {
    return "INSERT column namespace_id";
  }
  if (
    /\b(?:PRIMARY|FOREIGN|UNIQUE)\s+KEY\b[\s\S]*\bnamespace_id\b/i.test(text)
  ) {
    return "namespace_id key";
  }
  return null;
}

function classification(
  name,
  rationale,
  coverage,
  namespace_evidence = null,
) {
  return {
    classification: name,
    rationale,
    coverage,
    namespace_evidence,
  };
}

function hash(text) {
  return createHash("sha256").update(text).digest("hex");
}

export function statementHash(text) {
  return hash(normalizeSql(text));
}

const SCOPED_COVERAGE = new Map([
  ["scripts/memory-cleanup.mjs", [
    "scripts/memory-cleanup-namespace.test.mjs",
    "scripts/maintenance-postgres.test.mjs",
    "scripts/memory-namespace-query-inventory.test.mjs",
  ]],
  ["scripts/memory-consolidation.mjs", [
    "scripts/consolidation-namespace.test.mjs",
    "scripts/maintenance-postgres.test.mjs",
    "scripts/memory-namespace-query-inventory.test.mjs",
  ]],
  ["scripts/analyze-ingest-prescreen.sql", [
    "scripts/run-analysis-namespace-integration.sh",
    "scripts/memory-namespace-query-inventory.test.mjs",
  ]],
  ["scripts/run-maintenance-namespace-e2e.mjs", [
    "scripts/run-maintenance-namespace-e2e.test.mjs",
    "scripts/run-maintenance-namespace-e2e.mjs",
  ]],
  ["upstream/server/internal/repository/postgres/namespace_sampler.go", [
    "upstream/server/internal/repository/postgres/namespace_sampler_test.go",
    "upstream/server/internal/ingestqueue/namespace_sampler_test.go",
  ]],
]);

export function classifyStatement(statement, trustedExceptions = []) {
  const { owner, text } = statement;
  const evidence = namespaceEvidence(text);
  if (statement.unsupported_expression) {
    return classification("unclassified", "An unsupported string expression cannot prove the resulting SQL.", []);
  }

  if (
    owner === "docker/bootstrap/schema.sql" ||
    owner.startsWith("docker/bootstrap/migrations/")
  ) {
    return classification(
      "schema_migration",
      "Bootstrap and versioned migrations are run only by the guarded schema operator.",
      ["infra/namespace-schema.test.ts", "scripts/run-memory-namespace-integration.sh"],
      evidence,
    );
  }

  if (owner === "scripts/migrate-memory-namespaces.mjs") {
    return classification(
      "migration_operator",
      "The phased writer-fenced migration intentionally inventories and backfills legacy rows.",
      ["scripts/memory-namespace.test.mjs", "scripts/run-memory-namespace-integration.sh"],
      evidence,
    );
  }

  if (
    owner.startsWith("upstream/server/internal/repository/db9/") ||
    owner.startsWith("upstream/server/internal/repository/tidb/")
  ) {
    return classification(
      "unsupported_backend",
      "The AWS image is pinned to PostgreSQL; DB9 and TiDB repositories are not selectable in this deployment.",
      ["infra/ecs.test.ts", "docker/mnemo-server/Dockerfile"],
      evidence,
    );
  }

  if (
    owner.includes("/upload_task.go") ||
    owner === "upstream/server/internal/service/upload.go" ||
    owner === "upstream/server/internal/service/tenant.go" ||
    owner === "upstream/server/internal/tenant/schema.go" ||
    owner.startsWith("infra/slack-approval")
  ) {
    return classification(
      "disabled_capability",
      "This capability or provisioning path is excluded from the namespace-required AWS application until its full contract is namespace-bound.",
      ["sst.config.ts", "infra/ecs.test.ts", "infra/consolidation.test.ts"],
      evidence,
    );
  }

  if (
    owner === "scripts/manage-memory-access.mjs" &&
    /\bUPDATE\s+ingest_jobs\b/i.test(text)
  ) {
    return classification(
      "emergency_control_plane",
      "Emergency revocation intentionally cancels every non-terminal job owned by the disabled principal.",
      ["scripts/memory-namespace.test.mjs", "docker/mnemo-server/patches/0010-group-memory-namespaces.patch"],
      evidence,
    );
  }

  if (
    owner === "upstream/server/cmd/mnemo-server/main.go" &&
    /\bnamespace_id\s+IS\s+NULL\b/i.test(text)
  ) {
    return classification(
      "startup_gate",
      "Startup checks all scoped tables for incomplete migration before accepting traffic.",
      ["upstream/server/cmd/mnemo-server/namespace_startup_integration_test.go"],
      evidence,
    );
  }

  if (DYNAMIC_RELATION_PATTERN.test(text)) {
    return classification(
      "unclassified",
      "A dynamic relation cannot prove that every scoped table is namespace-bound.",
      [],
    );
  }

  if (evidence) {
    return classification(
      "namespace_bound",
      "The statement carries an explicit namespace column, predicate, or key.",
      SCOPED_COVERAGE.get(owner) ?? ["docker/mnemo-server/patches/0010-group-memory-namespaces.patch"],
      evidence,
    );
  }

  const reviewed = trustedExceptions.find(
    (exception) =>
      exception.owner === owner &&
      exception.statement_sha256 === statementHash(text),
  );
  if (reviewed) {
    return classification(
      reviewed.classification,
      reviewed.rationale,
      reviewed.coverage,
      reviewed.namespace_evidence ?? null,
    );
  }

  return classification(
    "unclassified",
    "No reviewed namespace predicate or trusted exception applies.",
    [],
  );
}

export function buildManifest(
  candidates,
  metadata = {},
  trustedExceptions = [],
) {
  const statements = candidates
    .map((candidate) => {
      const text = normalizeSql(candidate.text);
      const policy = classifyStatement(
        { ...candidate, text },
        trustedExceptions,
      );
      return {
        id: hash(`${candidate.owner}\n${candidate.line}\n${text}`).slice(0, 20),
        owner: candidate.owner,
        line: candidate.line,
        tables: [...candidate.tables].sort(),
        statement_sha256: hash(text),
        statement: text,
        ...policy,
      };
    })
    .sort((left, right) =>
      left.owner.localeCompare(right.owner) ||
      left.line - right.line ||
      left.statement.localeCompare(right.statement),
    );

  return {
    version: 1,
    scoped_tables: SCOPED_TABLES,
    ...metadata,
    statements,
  };
}

export function compareManifests(reviewed, generated) {
  return JSON.stringify(reviewed) === JSON.stringify(generated)
    ? []
    : ["query inventory differs from the reviewed manifest"];
}

function walkFiles(root, predicate) {
  const files = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = resolve(root, entry.name);
    if (entry.isDirectory()) {
      if (
        ["node_modules", ".git", ".sst", "coverage", "dist"].includes(
          entry.name,
        )
      ) {
        continue;
      }
      files.push(...walkFiles(path, predicate));
    } else if (entry.isFile() && predicate(path)) {
      files.push(path);
    }
  }
  return files.sort();
}

export function extractRepositoryStatements(repoRoot) {
  const candidates = [];
  const sqlFiles = [
    resolve(repoRoot, "docker/bootstrap/schema.sql"),
    ...walkFiles(
      resolve(repoRoot, "docker/bootstrap/migrations"),
      (path) => path.endsWith(".sql"),
    ),
    resolve(repoRoot, "scripts/analyze-ingest-prescreen.sql"),
  ];
  for (const path of sqlFiles) {
    candidates.push(
      ...extractSqlStatements({
        kind: "sql",
        owner: relative(repoRoot, path),
        source: readFileSync(path, "utf8"),
      }),
    );
  }

  const codeRoots = [
    resolve(repoRoot, "scripts"),
    resolve(repoRoot, "infra"),
    resolve(repoRoot, "docker"),
  ];
  for (const codeRoot of codeRoots) {
    for (const path of walkFiles(
      codeRoot,
      (candidate) =>
        /\.(?:[cm]?js|[cm]?ts|jsx|tsx)$/.test(candidate) &&
        !/\.test\.(?:[cm]?js|[cm]?ts|jsx|tsx)$/.test(candidate) &&
        !candidate.endsWith("memory-namespace-query-inventory.mjs") &&
        !candidate.endsWith("verify-memory-namespace-query-inventory.mjs"),
    )) {
      const source = readFileSync(path, "utf8");
      candidates.push(
        ...extractSqlStatements({
          kind: "javascript",
          owner: relative(repoRoot, path),
          source,
        }),
      );
    }
  }
  return candidates;
}

export function validateManifest(manifest, trustedExceptions = []) {
  const errors = [];
  const unclassified = manifest.statements.filter(
    ({ classification: value }) => value === "unclassified",
  );
  if (unclassified.length > 0) {
    errors.push(
      ...unclassified.map(
        ({ owner, line, statement_sha256, statement }) =>
          `${owner}:${line}: unclassified scoped SQL ${statement_sha256}: ${statement}`,
      ),
    );
  }
  const duplicateIDs = manifest.statements
    .map(({ id }) => id)
    .filter((id, index, ids) => ids.indexOf(id) !== index);
  if (duplicateIDs.length > 0) {
    errors.push(`duplicate inventory ids: ${[...new Set(duplicateIDs)].join(", ")}`);
  }

  const exceptionKeys = trustedExceptions.map(
    ({ owner, statement_sha256 }) => `${owner}\n${statement_sha256}`,
  );
  const duplicateExceptions = exceptionKeys.filter(
    (key, index, keys) => keys.indexOf(key) !== index,
  );
  if (duplicateExceptions.length > 0) {
    errors.push(
      `duplicate trusted exceptions: ${[
        ...new Set(duplicateExceptions),
      ].join(", ")}`,
    );
  }
  for (const exception of trustedExceptions) {
    if (
      exception.classification !== "namespace_composed_or_compatibility" ||
      typeof exception.rationale !== "string" ||
      exception.rationale.length === 0 ||
      !Array.isArray(exception.coverage) ||
      exception.coverage.length === 0
    ) {
      errors.push(
        `${exception.owner}:${exception.statement_sha256}: invalid trusted exception`,
      );
      continue;
    }
    const used = manifest.statements.some(
      (statement) =>
        statement.owner === exception.owner &&
        statement.statement_sha256 === exception.statement_sha256 &&
        statement.classification === exception.classification,
    );
    if (!used) {
      errors.push(
        `${exception.owner}:${exception.statement_sha256}: unused trusted exception`,
      );
    }
  }
  return errors;
}

export function assertDirectory(path) {
  if (!statSync(path).isDirectory()) {
    throw new Error(`${path} is not a directory`);
  }
}
