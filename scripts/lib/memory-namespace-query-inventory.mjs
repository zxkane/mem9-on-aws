import { createHash } from "node:crypto";
import {
  readdirSync,
  readFileSync,
  statSync,
} from "node:fs";
import { relative, resolve } from "node:path";

import {
  computeLineStarts,
  createScanner,
  LanguageVariant,
  SyntaxKind,
} from "typescript/unstable/ast";

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
  /\b(?:FROM|JOIN|INTO|UPDATE|TABLE|REFERENCES|ON)\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(?:ONLY\s+)?\{\{dynamic\}\}/i;
const SCOPED_TABLE_SOURCE_PATTERN = new RegExp(
  String.raw`\b(?:${SCOPED_TABLES.join("|")})\b`,
  "i",
);
const DYNAMIC_RELATION_SOURCE_PATTERN =
  /\b(?:FROM|JOIN|INTO|UPDATE|TABLE|REFERENCES|ON)\s*(?:\$\{|["'`]\s*\+)/i;

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

function extractJavaScript({ owner, source }) {
  const scanner = createScanner(true, LanguageVariant.Standard, source);
  const lineStarts = computeLineStarts(source);
  const candidates = [];
  const candidateKeys = new Set();

  const lineAt = (position) => {
    let low = 0;
    let high = lineStarts.length;
    while (low + 1 < high) {
      const middle = Math.floor((low + high) / 2);
      if (lineStarts[middle] <= position) low = middle;
      else high = middle;
    }
    return low + 1;
  };
  const add = (text, start) => {
    if (isScopedSql(text)) {
      const tables = tablesIn(text);
      const candidate = {
        owner,
        line: lineAt(start),
        text: normalizeSql(text),
        tables:
          tables.length > 0
            ? tables
            : ["<dynamic-relation>"],
      };
      const key = `${candidate.line}\n${candidate.text}`;
      if (!candidateKeys.has(key)) {
        candidateKeys.add(key);
        candidates.push(candidate);
      }
    }
  };

  const readTemplate = (templateScanner, start, head) => {
    let text = head;
    let braceDepth = 0;
    for (;;) {
      const token = templateScanner.scan();
      if (token === SyntaxKind.EndOfFile) {
        return { start, text };
      }
      if (token === SyntaxKind.TemplateHead) {
        readTemplate(
          templateScanner,
          templateScanner.getTokenStart(),
          templateScanner.getTokenValue(),
        );
        continue;
      }
      if (token === SyntaxKind.OpenBraceToken) {
        braceDepth += 1;
        continue;
      }
      if (token !== SyntaxKind.CloseBraceToken) {
        continue;
      }
      if (braceDepth > 0) {
        braceDepth -= 1;
        continue;
      }

      text += "{{dynamic}}";
      const continuation = templateScanner.reScanTemplateToken(false);
      if (
        continuation !== SyntaxKind.TemplateMiddle &&
        continuation !== SyntaxKind.TemplateTail
      ) {
        return { start, text };
      }
      text += templateScanner.getTokenValue();
      if (continuation === SyntaxKind.TemplateTail) {
        return { start, text };
      }
    }
  };

  for (;;) {
    const token = scanner.scan();
    if (token === SyntaxKind.EndOfFile) break;
    if (
      token === SyntaxKind.StringLiteral ||
      token === SyntaxKind.NoSubstitutionTemplateLiteral
    ) {
      add(scanner.getTokenValue(), scanner.getTokenStart());
    } else if (token === SyntaxKind.TemplateHead) {
      const template = readTemplate(
        scanner,
        scanner.getTokenStart(),
        scanner.getTokenValue(),
      );
      add(template.text, template.start);
    }
  }

  const concatScanner = createScanner(
    true,
    LanguageVariant.Standard,
    source,
  );
  const tokens = [];
  for (;;) {
    const kind = concatScanner.scan();
    if (kind === SyntaxKind.TemplateHead) {
      const template = readTemplate(
        concatScanner,
        concatScanner.getTokenStart(),
        concatScanner.getTokenValue(),
      );
      tokens.push({
        kind: SyntaxKind.NoSubstitutionTemplateLiteral,
        start: template.start,
        value: template.text,
      });
      continue;
    }
    tokens.push({
      kind,
      start: concatScanner.getTokenStart(),
      value:
        kind === SyntaxKind.StringLiteral ||
        kind === SyntaxKind.NoSubstitutionTemplateLiteral
          ? concatScanner.getTokenValue()
          : null,
    });
    if (kind === SyntaxKind.EndOfFile) break;
  }

  const openingTokens = new Set([
    SyntaxKind.OpenParenToken,
    SyntaxKind.OpenBracketToken,
    SyntaxKind.OpenBraceToken,
  ]);
  const closingTokens = new Set([
    SyntaxKind.CloseParenToken,
    SyntaxKind.CloseBracketToken,
    SyntaxKind.CloseBraceToken,
  ]);
  const boundaryTokens = new Set([
    SyntaxKind.CommaToken,
    SyntaxKind.SemicolonToken,
    SyntaxKind.EndOfFile,
  ]);
  const stringTokens = new Set([
    SyntaxKind.StringLiteral,
    SyntaxKind.NoSubstitutionTemplateLiteral,
  ]);

  for (let startIndex = 0; startIndex < tokens.length; startIndex += 1) {
    const startToken = tokens[startIndex];
    if (
      !stringTokens.has(startToken.kind) ||
      !SQL_PREFIX.test(startToken.value)
    ) {
      continue;
    }

    let text = startToken.value;
    let index = startIndex + 1;
    let concatenated = false;
    while (tokens[index]?.kind === SyntaxKind.PlusToken) {
      concatenated = true;
      index += 1;
      const operandStart = index;
      let depth = 0;
      while (index < tokens.length) {
        const kind = tokens[index].kind;
        if (openingTokens.has(kind)) {
          depth += 1;
          index += 1;
          continue;
        }
        if (closingTokens.has(kind)) {
          if (depth === 0) break;
          depth -= 1;
          index += 1;
          continue;
        }
        if (
          depth === 0 &&
          (kind === SyntaxKind.PlusToken || boundaryTokens.has(kind))
        ) {
          break;
        }
        index += 1;
      }

      const operand = tokens.slice(operandStart, index);
      text +=
        operand.length === 1 && stringTokens.has(operand[0].kind)
          ? operand[0].value
          : "{{dynamic}}";
    }
    if (concatenated) {
      add(text, startToken.start);
    }
  }

  return candidates;
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

export function classifyStatement(statement, trustedExceptions = []) {
  const { owner, text } = statement;
  const evidence = namespaceEvidence(text);

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
    owner === "scripts/memory-cleanup.mjs" ||
    owner === "scripts/memory-consolidation.mjs" ||
    owner.startsWith("infra/consolidation") ||
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
      owner === "scripts/analyze-ingest-prescreen.sql"
        ? ["scripts/memory-namespace-query-inventory.test.mjs"]
        : ["docker/mnemo-server/patches/0010-group-memory-namespaces.patch"],
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
        /\.(?:mjs|ts)$/.test(candidate) &&
        !/\.test\.(?:mjs|ts)$/.test(candidate) &&
        !candidate.endsWith("memory-namespace-query-inventory.mjs") &&
        !candidate.endsWith("verify-memory-namespace-query-inventory.mjs"),
    )) {
      const source = readFileSync(path, "utf8");
      if (
        !SCOPED_TABLE_SOURCE_PATTERN.test(source) &&
        !DYNAMIC_RELATION_SOURCE_PATTERN.test(source)
      ) {
        continue;
      }
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
