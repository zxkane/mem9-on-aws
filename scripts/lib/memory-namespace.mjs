import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";

const HASH_RE = /^[0-9a-f]{64}$/u;
const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$/u;
const ROLE_SET = new Set(["viewer", "member"]);
const STATUS_SET = new Set(["active", "disabled"]);
const SECRET_KEY_RE = /(password|secret|token|api[_-]?key|private[_-]?key)/iu;

export const LEGACY_MAINTENANCE_DISABLED_CODE =
  "NAMESPACE_V1_LEGACY_MAINTENANCE_DISABLED";

export function assertNamespaceV1LegacyMaintenanceDisabled(capability) {
  const error = new Error(
    `${capability}: legacy maintenance is disabled in memory namespace v1; ` +
      "a namespace-bound replacement is required before this entry point can run",
  );
  error.code = LEGACY_MAINTENANCE_DISABLED_CODE;
  throw error;
}

export function deriveLookupKey(namespace, issuer, value) {
  if (!namespace || !issuer || !value) {
    throw new Error("lookup key inputs are required");
  }
  const hash = createHash("sha256");
  hash.update(namespace);
  hash.update("\0");
  hash.update(issuer);
  hash.update("\0");
  hash.update(value);
  return hash.digest("hex");
}

export function deriveHumanPrincipalKey(issuer, subject) {
  return deriveLookupKey("mem9-principal-v2", issuer, `human\0${subject}`);
}

export function deriveM2MPrincipalKey(issuer, clientId) {
  return deriveLookupKey("mem9-principal-v2", issuer, `m2m\0${clientId}`);
}

export function deriveClientKey(issuer, clientId) {
  return deriveLookupKey("mem9-client-v1", issuer, clientId);
}

export function deriveGroupKey(issuer, groupName) {
  return deriveLookupKey("mem9-cognito-group-v1", issuer, groupName);
}

function rejectSecretFields(value, path = "$") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => rejectSecretFields(item, `${path}[${index}]`));
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (SECRET_KEY_RE.test(key)) {
      throw new Error(`${path}.${key} is not allowed in desired state`);
    }
    rejectSecretFields(child, `${path}.${key}`);
  }
}

function exactKeys(value, allowed, path) {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new Error(`${path}.${key} is not supported`);
    }
  }
}

export function validateDesiredState(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("desired state must be an object");
  }
  rejectSecretFields(value);
  exactKeys(value, new Set(["namespaces", "m2m_bindings"]), "$");
  if (!Array.isArray(value.namespaces) || value.namespaces.length === 0) {
    throw new Error("desired state requires at least one namespace");
  }
  if (!Array.isArray(value.m2m_bindings ?? [])) {
    throw new Error("m2m_bindings must be an array");
  }

  const slugs = new Set();
  const groups = new Set();
  const namespaces = value.namespaces.map((item, index) => {
    const path = `$.namespaces[${index}]`;
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error(`${path} must be an object`);
    }
    exactKeys(
      item,
      new Set([
        "slug",
        "display_name",
        "cognito_group",
        "default_role",
        "jit_enabled",
        "status",
      ]),
      path,
    );
    if (!SLUG_RE.test(item.slug ?? "")) {
      throw new Error(`${path}.slug is invalid`);
    }
    if (
      typeof item.display_name !== "string" ||
      item.display_name.length < 1 ||
      item.display_name.length > 255
    ) {
      throw new Error(`${path}.display_name is invalid`);
    }
    if (
      typeof item.cognito_group !== "string" ||
      item.cognito_group.length < 1 ||
      item.cognito_group.length > 128
    ) {
      throw new Error(`${path}.cognito_group is invalid`);
    }
    const role = item.default_role ?? "member";
    const status = item.status ?? "active";
    if (!ROLE_SET.has(role)) throw new Error(`${path}.default_role is invalid`);
    if (!STATUS_SET.has(status)) throw new Error(`${path}.status is invalid`);
    if (typeof item.jit_enabled !== "boolean") {
      throw new Error(`${path}.jit_enabled must be boolean`);
    }
    if (slugs.has(item.slug)) throw new Error("duplicate namespace slug");
    if (groups.has(item.cognito_group)) throw new Error("duplicate Cognito group");
    slugs.add(item.slug);
    groups.add(item.cognito_group);
    return {
      ...item,
      default_role: role,
      status,
    };
  });

  const clientKeys = new Set();
  const principalKeys = new Set();
  const m2mBindings = (value.m2m_bindings ?? []).map((item, index) => {
    const path = `$.m2m_bindings[${index}]`;
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error(`${path} must be an object`);
    }
    exactKeys(
      item,
      new Set([
        "client_key",
        "principal_key",
        "namespace_slug",
        "role",
        "status",
      ]),
      path,
    );
    if (!HASH_RE.test(item.client_key ?? "")) {
      throw new Error(`${path}.client_key is invalid`);
    }
    if (!HASH_RE.test(item.principal_key ?? "")) {
      throw new Error(`${path}.principal_key is invalid`);
    }
    if (!slugs.has(item.namespace_slug)) {
      throw new Error(`${path}.namespace_slug is unknown`);
    }
    const role = item.role ?? "member";
    const status = item.status ?? "active";
    if (!ROLE_SET.has(role)) throw new Error(`${path}.role is invalid`);
    if (!STATUS_SET.has(status)) throw new Error(`${path}.status is invalid`);
    if (clientKeys.has(item.client_key)) throw new Error("duplicate client binding");
    if (principalKeys.has(item.principal_key)) {
      throw new Error("duplicate M2M principal binding");
    }
    clientKeys.add(item.client_key);
    principalKeys.add(item.principal_key);
    return { ...item, role, status };
  });

  return { namespaces, m2m_bindings: m2mBindings };
}

export async function readDesiredState(path) {
  const metadata = await stat(path);
  if ((metadata.mode & 0o077) !== 0) {
    throw new Error("desired-state file must be owner-only (mode 600)");
  }
  const parsed = JSON.parse(await readFile(path, "utf8"));
  return validateDesiredState(parsed);
}

export async function readUsername({ file, stdin = process.stdin } = {}) {
  let value;
  if (file) {
    const metadata = await stat(file);
    if ((metadata.mode & 0o077) !== 0) {
      throw new Error("username file must be owner-only (mode 600)");
    }
    value = await readFile(file, "utf8");
  } else {
    const chunks = [];
    for await (const chunk of stdin) chunks.push(chunk);
    value = Buffer.concat(chunks).toString("utf8");
  }
  const username = value.trim();
  if (!username || username.length > 128 || /[\r\n\0]/u.test(username)) {
    throw new Error("username input is invalid");
  }
  return username;
}

export function parseOperatorArgs(argv) {
  if (argv[0] === "--help" || argv[0] === "-h") {
    return { help: true };
  }
  const args = { command: argv[0] };
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--help" || token === "-h") {
      args.help = true;
      continue;
    }
    if (token === "--emergency") {
      args.emergency = true;
      continue;
    }
    if (!token.startsWith("--") || index + 1 >= argv.length) {
      throw new Error("invalid command arguments");
    }
    const key = token.slice(2).replaceAll("-", "_");
    args[key] = argv[index + 1];
    index += 1;
  }
  return args;
}
