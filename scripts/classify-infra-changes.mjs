#!/usr/bin/env node

import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import process from "node:process";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const DOCKERFILES = [
  "docker/bootstrap/Dockerfile",
  "docker/llm-proxy/Dockerfile",
  "docker/mnemo-server/Dockerfile",
  "docker/qwen3-embed/Dockerfile",
];

export function discoverWorkloadCopyInputs() {
  const inputs = new Set();
  for (const dockerfile of DOCKERFILES) {
    if (!existsSync(resolve(root, dockerfile))) continue;
    for (const line of readFileSync(resolve(root, dockerfile), "utf8").split("\n")) {
      const tokens = line.trim().split(/\s+/u);
      if (tokens[0] !== "COPY" || tokens.some((token) => token.startsWith("--from="))) {
        continue;
      }
      const operands = tokens.slice(1).filter((token) => !token.startsWith("--"));
      for (const source of operands.slice(0, -1)) inputs.add(source);
    }
  }
  return inputs;
}

export const WORKLOAD_COPY_INPUTS = discoverWorkloadCopyInputs();

function matchesCopyInput(path, input) {
  if (input.endsWith("/")) return path.startsWith(input);
  const pattern = new RegExp(
    `^${input
      .replace(/[.+?^${}()|[\]\\]/gu, "\\$&")
      .replaceAll("*", "[^/]*")}$`,
    "u",
  );
  return pattern.test(path);
}

function isTestPath(path) {
  return /(?:^|\/)(?:test-cases|tests?)\//u.test(path) ||
    /\.(?:test|spec)\.[cm]?[jt]sx?$/u.test(path);
}

export function classifyChangedPaths(paths) {
  const normalized = [...new Set(paths.filter(Boolean))];
  const workloadChanged = normalized.some(
    (path) =>
      path.startsWith("docker/") ||
      [...WORKLOAD_COPY_INPUTS].some((input) => matchesCopyInput(path, input)),
  );
  const applicationInfrastructureChanged = normalized.some((path) => {
    if (path === "sst.config.ts") return true;
    if (!path.startsWith("infra/")) return false;
    if (path.startsWith("infra/cloudformation/")) return false;
    return !isTestPath(path);
  });
  return {
    workloadChanged,
    applicationInfrastructureChanged,
    awsMutationRequired:
      workloadChanged || applicationInfrastructureChanged,
  };
}

function parseArgs(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--force-production") {
      result.forceProduction = true;
      continue;
    }
    if (argument === "--merge-base") {
      result.mergeBase = true;
      continue;
    }
    if (!["--base", "--head"].includes(argument)) {
      throw new Error(`unsupported argument ${argument}`);
    }
    const value = argv[index + 1];
    if (!value) throw new Error(`${argument} requires a value`);
    result[argument.slice(2)] = value;
    index += 1;
  }
  return result;
}

function writeOutputs(path, classification) {
  appendFileSync(
    path,
    [
      `workload_changed=${classification.workloadChanged}`,
      `app_infra_changed=${classification.applicationInfrastructureChanged}`,
      `aws_mutation_required=${classification.awsMutationRequired}`,
      "",
    ].join("\n"),
  );
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  let classification;
  if (args.forceProduction) {
    classification = {
      workloadChanged: true,
      applicationInfrastructureChanged: true,
      awsMutationRequired: true,
    };
  } else {
    if (!args.base || !args.head) {
      throw new Error("--base and --head are required");
    }
    const output = execFileSync(
      "git",
      [
        "diff",
        "--no-renames",
        "--name-only",
        "--diff-filter=ACDMRT",
        ...(args.mergeBase ? ["--merge-base"] : []),
        args.base,
        args.head,
      ],
      { encoding: "utf8" },
    );
    classification = classifyChangedPaths(output.trim().split("\n"));
  }
  if (!process.env.GITHUB_OUTPUT) {
    process.stdout.write(`${JSON.stringify(classification)}\n`);
    return;
  }
  writeOutputs(process.env.GITHUB_OUTPUT, classification);
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`change classification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
