import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const PROJECT_REPOSITORY_SUFFIXES = [
  "mnemo-server",
  "qwen3-embed",
  "bootstrap",
  "llm-proxy",
];

const STABLE_STACK_STATUSES = new Set([
  "CREATE_COMPLETE",
  "IMPORT_COMPLETE",
  "UPDATE_COMPLETE",
  "UPDATE_ROLLBACK_COMPLETE",
]);

export function projectRepositories(projectName) {
  return PROJECT_REPOSITORY_SUFFIXES.map((suffix) => `${projectName}/${suffix}`);
}

export function declaredConfiguration(projectName) {
  return {
    scanType: "BASIC",
    rules: [
      {
        scanFrequency: "SCAN_ON_PUSH",
        repositoryFilters: [
          {
            filter: `${projectName}/*`,
            filterType: "WILDCARD",
          },
        ],
      },
    ],
  };
}

function scanningConfiguration(value) {
  return value?.scanningConfiguration ?? value ?? {};
}

function canonicalConfiguration(value) {
  const configuration = scanningConfiguration(value);
  return {
    scanType: configuration.scanType ?? null,
    rules: (configuration.rules ?? [])
      .map((rule) => ({
        scanFrequency: rule.scanFrequency,
        repositoryFilters: (rule.repositoryFilters ?? [])
          .map((filter) => ({
            filter: filter.filter,
            filterType: filter.filterType,
          }))
          .sort((a, b) =>
            `${a.filterType}:${a.filter}`.localeCompare(`${b.filterType}:${b.filter}`),
          ),
      }))
      .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
  };
}

function equivalentConfiguration(left, right) {
  return JSON.stringify(canonicalConfiguration(left)) === JSON.stringify(canonicalConfiguration(right));
}

function defaultConfiguration(value) {
  const configuration = scanningConfiguration(value);
  const rules = configuration.rules ?? [];
  return rules.length === 0 && (!configuration.scanType || configuration.scanType === "BASIC");
}

function escapeRegex(value) {
  return value.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
}

export function repositoryMatchesFilter(repositoryName, filter) {
  if (!filter.includes("*")) {
    return repositoryName.includes(filter);
  }

  const expression = filter.split("*").map(escapeRegex).join(".*");
  return new RegExp(`^${expression}$`).test(repositoryName);
}

function uncoveredProjectRepositories(configuration, projectName) {
  const scanOnPushFilters = (configuration.rules ?? [])
    .filter((rule) => rule.scanFrequency === "SCAN_ON_PUSH")
    .flatMap((rule) => rule.repositoryFilters ?? [])
    .filter((filter) => filter.filterType === "WILDCARD")
    .map((filter) => filter.filter);

  return projectRepositories(projectName).filter(
    (repository) =>
      !scanOnPushFilters.some((filter) => repositoryMatchesFilter(repository, filter)),
  );
}

export function decideRegistryScanningAction({ current, ownership, projectName }) {
  const configuration = scanningConfiguration(current);
  const declared = declaredConfiguration(projectName);

  if (ownership.ownsResource && !ownership.stackExists) {
    return {
      action: "fail-closed",
      reason: "CloudFormation ownership data is inconsistent.",
    };
  }

  if (ownership.stackExists && !ownership.ownsResource) {
    return {
      action: "fail-closed",
      reason: "The dedicated stack name exists but does not own the registry singleton.",
    };
  }

  if (ownership.ownsResource) {
    if (
      ownership.stackStatus &&
      !STABLE_STACK_STATUSES.has(ownership.stackStatus)
    ) {
      return {
        action: "fail-closed",
        reason: `The owning stack is not stable (${ownership.stackStatus}).`,
      };
    }

    if (equivalentConfiguration(configuration, declared)) {
      return {
        action: "verify-owned",
        reason: "The dedicated stack owns an equivalent complete configuration.",
      };
    }

    return {
      action: "update-owned",
      reason: "The dedicated stack owns the singleton and may restore its complete declaration.",
    };
  }

  if (defaultConfiguration(configuration)) {
    return {
      action: "adopt",
      reason: "The registry has no non-default scanning configuration.",
    };
  }

  if (configuration.scanType !== "BASIC") {
    return {
      action: "fail-closed",
      reason: `External registry scan type ${configuration.scanType ?? "unknown"} is not BASIC.`,
    };
  }

  const uncoveredRepositories = uncoveredProjectRepositories(configuration, projectName);
  if (uncoveredRepositories.length === 0) {
    return {
      action: "verify-only",
      reason: "External BASIC scan-on-push rules cover every project repository.",
    };
  }

  return {
    action: "fail-closed",
    reason: "External rules do not provide complete BASIC scan-on-push coverage.",
    uncoveredRepositories,
  };
}

function argumentValue(args, name, fallback = undefined) {
  const index = args.indexOf(name);
  return index === -1 ? fallback : args[index + 1];
}

async function main() {
  const args = process.argv.slice(2);
  const inputFile = argumentValue(args, "--input");
  const projectName = argumentValue(args, "--project-name");
  if (!inputFile || !projectName) {
    throw new Error("--input and --project-name are required");
  }

  const current = JSON.parse(await readFile(inputFile, "utf8"));
  const stackExists = argumentValue(args, "--stack-exists") === "true";
  const ownsResource = argumentValue(args, "--owns-resource") === "true";
  const stackStatus = argumentValue(args, "--stack-status", "") || null;
  const format = argumentValue(args, "--format", "json");
  const decision = decideRegistryScanningAction({
    current,
    ownership: { stackExists, ownsResource, stackStatus },
    projectName,
  });

  if (format === "tsv") {
    const uncovered = decision.uncoveredRepositories?.join(", ") ?? "";
    process.stdout.write(`${decision.action}\t${decision.reason}\t${uncovered}\n`);
    return;
  }
  if (format !== "json") {
    throw new Error(`unsupported --format: ${format}`);
  }
  process.stdout.write(`${JSON.stringify(decision)}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error) => {
    console.error(`Preflight input error: ${error.message}`);
    process.exitCode = 2;
  });
}
