#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertDirectory,
  buildManifest,
  compareManifests,
  extractRepositoryStatements,
  validateManifest,
} from "./lib/memory-namespace-query-inventory.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const manifestPath = resolve(
  root,
  "scripts/memory-namespace-query-inventory.json",
);
const exceptionPath = resolve(
  root,
  "scripts/memory-namespace-query-exceptions.json",
);

function usage() {
  console.error(
    "usage: node scripts/verify-memory-namespace-query-inventory.mjs " +
      "--upstream <patched-upstream-root> [--write]",
  );
}

const args = process.argv.slice(2);
let upstreamRoot;
let write = false;
for (let index = 0; index < args.length; index += 1) {
  if (args[index] === "--upstream") {
    upstreamRoot = args[index + 1];
    index += 1;
  } else if (args[index] === "--write") {
    write = true;
  } else {
    usage();
    process.exit(2);
  }
}
if (!upstreamRoot) {
  usage();
  process.exit(2);
}
upstreamRoot = resolve(upstreamRoot);
assertDirectory(upstreamRoot);

const goCandidates = JSON.parse(
  execFileSync(
    "go",
    [
      "run",
      resolve(root, "scripts/extract-go-sql.go"),
      resolve(upstreamRoot, "server"),
    ],
    { encoding: "utf8" },
  ),
);
const exceptionPolicy = JSON.parse(readFileSync(exceptionPath, "utf8"));
if (
  exceptionPolicy.version !== 1 ||
  !Array.isArray(exceptionPolicy.exceptions)
) {
  throw new Error("invalid memory namespace query exception policy");
}
const trustedExceptions = exceptionPolicy.exceptions;
const manifest = buildManifest(
  [...extractRepositoryStatements(root), ...goCandidates],
  {
    upstream_ref: readFileSync(
      resolve(root, "docker/mnemo-server/Dockerfile"),
      "utf8",
    ).match(/^ARG MEM9_REF=(.+)$/m)?.[1],
    trusted_exception_policy:
      "scripts/memory-namespace-query-exceptions.json",
  },
  trustedExceptions,
);
const errors = validateManifest(manifest, trustedExceptions);
if (errors.length > 0) {
  console.error(errors.join("\n"));
  process.exit(1);
}

if (write) {
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(
    `wrote ${manifest.statements.length} reviewed scoped SQL statements`,
  );
  process.exit(0);
}

const reviewed = JSON.parse(readFileSync(manifestPath, "utf8"));
const drift = compareManifests(reviewed, manifest);
if (drift.length > 0) {
  console.error(drift.join("\n"));
  console.error(
    "run with --write, review every changed entry, and commit the manifest",
  );
  process.exit(1);
}
console.log(
  `verified ${manifest.statements.length} reviewed scoped SQL statements`,
);
