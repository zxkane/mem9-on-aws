import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

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
const PROJECT_NAME_PATTERN = /^[a-z0-9]+(?:[._/-][a-z0-9]+)*$/;
const SCAN_TYPES = new Set(["BASIC", "ENHANCED"]);
const SCAN_FREQUENCIES = new Set([
  "SCAN_ON_PUSH",
  "CONTINUOUS_SCAN",
  "MANUAL",
]);

export function validProjectName(projectName) {
  return (
    typeof projectName === "string" &&
    projectName.length >= 2 &&
    projectName.length <= 243 &&
    PROJECT_NAME_PATTERN.test(projectName)
  );
}

function assertProjectName(projectName) {
  if (!validProjectName(projectName)) {
    throw new Error(
      "project name must be 2-243 lowercase repository-prefix characters without wildcards",
    );
  }
}

export function projectRepositories(projectName) {
  assertProjectName(projectName);
  return PROJECT_REPOSITORY_SUFFIXES.map((suffix) => `${projectName}/${suffix}`);
}

export function declaredConfiguration(projectName) {
  assertProjectName(projectName);
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

function invalidConfigurationReason(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return "Registry scanning response is missing.";
  }
  if (!/^[0-9]{12}$/.test(value.registryId ?? "")) {
    return "Registry scanning response has no valid registry ID.";
  }

  const configuration = value.scanningConfiguration;
  if (!configuration || typeof configuration !== "object") {
    return "Registry scanning response has no configuration.";
  }
  if (!SCAN_TYPES.has(configuration.scanType)) {
    return "Registry scanning response has an invalid scan type.";
  }
  if (!Array.isArray(configuration.rules)) {
    return "Registry scanning response has no complete rules array.";
  }

  for (const rule of configuration.rules) {
    if (
      !rule ||
      typeof rule !== "object" ||
      !SCAN_FREQUENCIES.has(rule.scanFrequency) ||
      !Array.isArray(rule.repositoryFilters)
    ) {
      return "Registry scanning response contains an incomplete rule.";
    }
    for (const filter of rule.repositoryFilters) {
      if (
        !filter ||
        typeof filter !== "object" ||
        filter.filterType !== "WILDCARD" ||
        typeof filter.filter !== "string" ||
        filter.filter.length === 0
      ) {
        return "Registry scanning response contains an incomplete repository filter.";
      }
    }
  }

  return null;
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

export function uncoveredProjectRepositories(configuration, projectName) {
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
  if (!validProjectName(projectName)) {
    return {
      action: "fail-closed",
      reason: "The project name is not a safe ECR repository prefix.",
    };
  }
  if (
    !ownership ||
    typeof ownership.stackExists !== "boolean" ||
    typeof ownership.ownsResource !== "boolean"
  ) {
    return {
      action: "fail-closed",
      reason: "CloudFormation ownership data is incomplete.",
    };
  }

  const invalidReason = invalidConfigurationReason(current);
  if (invalidReason) {
    return {
      action: "fail-closed",
      reason: invalidReason,
    };
  }

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
      !ownership.stackStatus ||
      !STABLE_STACK_STATUSES.has(ownership.stackStatus)
    ) {
      return {
        action: "fail-closed",
        reason: `The owning stack is not stable (${ownership.stackStatus ?? "unknown"}).`,
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

async function main() {
  const args = process.argv.slice(2);
  const parsed = parseArgs({
    args,
    options: {
      input: { type: "string" },
      "project-name": { type: "string" },
      "stack-exists": { type: "string" },
      "owns-resource": { type: "string" },
      "stack-status": { type: "string" },
      format: { type: "string", default: "json" },
    },
    strict: true,
    allowPositionals: false,
    tokens: true,
  });

  const optionCounts = new Map();
  for (const token of parsed.tokens) {
    if (token.kind === "option") {
      optionCounts.set(token.name, (optionCounts.get(token.name) ?? 0) + 1);
    }
  }
  for (const [name, count] of optionCounts) {
    if (count > 1) throw new Error(`--${name} must be provided at most once`);
  }

  const projectName = parsed.values["project-name"];
  const format = parsed.values.format;
  if (!projectName) throw new Error("--project-name is required");
  if (!["json", "tsv", "configuration"].includes(format)) {
    throw new Error(`unsupported --format: ${format}`);
  }
  if (format === "configuration") {
    process.stdout.write(`${JSON.stringify(declaredConfiguration(projectName))}\n`);
    return;
  }

  for (const name of ["input", "stack-exists", "owns-resource"]) {
    if (!parsed.values[name]) throw new Error(`--${name} is required`);
  }
  for (const name of ["stack-exists", "owns-resource"]) {
    if (!["true", "false"].includes(parsed.values[name])) {
      throw new Error(`--${name} must be true or false`);
    }
  }

  const inputFile = parsed.values.input;
  const current = JSON.parse(await readFile(inputFile, "utf8"));
  const stackExists = parsed.values["stack-exists"] === "true";
  const ownsResource = parsed.values["owns-resource"] === "true";
  const stackStatus = parsed.values["stack-status"] || null;
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
  process.stdout.write(`${JSON.stringify(decision)}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error) => {
    console.error(`Preflight input error: ${error.message}`);
    process.exitCode = 2;
  });
}
