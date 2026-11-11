import { createHash } from "node:crypto";

function requireThat(value, message) {
  if (!value) throw new Error(message);
}

function exactKeys(value, keys, label) {
  requireThat(value && typeof value === "object" && !Array.isArray(value), `Invalid ${label}`);
  requireThat(Object.keys(value).sort().join() === [...keys].sort().join(), `Unexpected ${label} fields`);
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  return value;
}

function digest(value) {
  return createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");
}

export function validateInputs(desired, binding) {
  exactKeys(desired, ["name", "repository", "defaultBranch", "scanFrequency", "patchCreationPolicy", "allowedDomains"], "declaration");
  exactKeys(binding, ["accountId", "region", "integrationId"], "binding");
  requireThat(typeof binding.accountId === "string" && /^\d{12}$/u.test(binding.accountId), "Invalid account ID");
  requireThat(["us-east-1", "us-west-2"].includes(binding.region), "Unsupported Continuum region");
  requireThat(typeof binding.integrationId === "string" && /^[a-z0-9]{1,64}$/u.test(binding.integrationId), "Invalid integration ID");
  requireThat(typeof desired.name === "string" && /^[A-Za-z][A-Za-z0-9]{0,63}$/u.test(desired.name), "Invalid environment name");
  requireThat(typeof desired.repository === "string" && /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/u.test(desired.repository), "Invalid repository");
  requireThat(desired.defaultBranch === "main", "Only the main branch may be scanned");
  requireThat(["P1D", "P2D", "P7D", "PT0H"].includes(desired.scanFrequency), "Unsupported scan interval");
  requireThat(["ENABLED", "DISABLED"].includes(desired.patchCreationPolicy), "Unsupported patch policy");
  requireThat(Array.isArray(desired.allowedDomains) && desired.allowedDomains.length >= 1 && desired.allowedDomains.length <= 20, "Invalid dependency domains");
  for (const domain of desired.allowedDomains) {
    requireThat(typeof domain === "string" && domain.length <= 253 && /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/u.test(domain), "Invalid dependency domain");
  }
  requireThat(new Set(desired.allowedDomains).size === desired.allowedDomains.length, "Duplicate dependency domains");
}

export function configuration(desired, binding) {
  return {
    codeConfiguration: {
      sourceConfiguration: { repositorySources: [{ integrationId: binding.integrationId, repository: desired.repository, defaultBranch: desired.defaultBranch }] },
      environmentConfiguration: {
        scanFrequency: desired.scanFrequency,
        patchCreationPolicy: desired.patchCreationPolicy,
        network: { allowedDomains: [...desired.allowedDomains].sort() },
      },
    },
  };
}

function resourceArn(binding, type, id) {
  return `arn:aws:continuum:${binding.region}:${binding.accountId}:${type}/${id}`;
}

function validateState(state, desired, binding) {
  if (!state) return;
  requireThat(state.version === 1 && state.phase === "bound", "Ambiguous creation journal: reconcile the environment manually before retrying");
  requireThat(digest(state.binding) === digest(binding) && state.name === desired.name && state.repository === desired.repository && state.defaultBranch === desired.defaultBranch, "State identity does not match this declaration and binding");
  requireThat(typeof state.environmentId === "string" && /^[a-z0-9]{1,64}$/u.test(state.environmentId), "Invalid state environment ID");
}

async function preflight(api, desired, binding, state) {
  validateInputs(desired, binding);
  validateState(state, desired, binding);
  const identity = await api.identity();
  requireThat(identity.Account === binding.accountId, "AWS caller account does not match binding");
  const integration = await api.integration(binding.integrationId);
  requireThat(integration.integrationId === binding.integrationId && integration.integrationType === "GITHUB" && integration.integrationArn === resourceArn(binding, "integrations", binding.integrationId), "GitHub integration identity does not match binding");
}

function observedConfiguration(current, state, desired, binding) {
  requireThat(current.environmentId === state.environmentId && current.environmentArn === resourceArn(binding, "environments", state.environmentId) && current.name === desired.name && current.status === "ACTIVE", "Environment identity or status mismatch");
  const code = current.configuration?.codeConfiguration;
  requireThat(!code?.collectorDetails || Object.keys(code.collectorDetails).length === 0, "Collector access is outside this repository-only deployment");
  const sources = code?.sourceConfiguration;
  const expected = configuration(desired, binding).codeConfiguration.sourceConfiguration;
  requireThat(sources && (sources.s3Sources ?? []).length === 0 && digest(sources.repositorySources) === digest(expected.repositorySources) && Object.keys(sources).every((key) => ["repositorySources", "s3Sources"].includes(key)), "Environment source drift; refusing to overwrite another source");
  const settings = code.environmentConfiguration;
  requireThat(settings && Object.keys(settings).every((key) => ["network", "scanFrequency", "patchCreationPolicy"].includes(key)), "Unknown environment policy");
  requireThat(!settings.network || Object.keys(settings.network).every((key) => key === "allowedDomains"), "Unknown network policy");
  return {
    codeConfiguration: {
      sourceConfiguration: expected,
      environmentConfiguration: {
        scanFrequency: settings.scanFrequency,
        patchCreationPolicy: settings.patchCreationPolicy,
        network: { allowedDomains: [...(settings.network?.allowedDomains ?? [])].sort() },
      },
    },
  };
}

async function verifyNoCollectors(api, environmentId) {
  const collectors = await api.collectors(environmentId);
  requireThat(Array.isArray(collectors) && collectors.length === 0, "Collector associations are outside this repository-only deployment");
}

export async function makePlan({ api, desired, binding, state, now = Date.now() }) {
  await preflight(api, desired, binding, state);
  let observed = null;
  if (state) {
    observed = observedConfiguration(await api.environment(state.environmentId), state, desired, binding);
    await verifyNoCollectors(api, state.environmentId);
  } else {
    const environments = await api.environments();
    requireThat(!environments.some((item) => item.name === desired.name), "Environment name already exists without owned state; explicit recovery is required");
  }
  const target = configuration(desired, binding);
  return {
    version: 1, createdAt: now,
    action: !state ? "create" : digest(observed) === digest(target) ? "noop" : "update",
    binding, name: desired.name, environmentId: state?.environmentId ?? null,
    desired: target, observed,
    inputDigest: digest({ desired, binding, state }),
  };
}

export async function applyPlan({ api, desired, binding, state, plan, journal, now = Date.now() }) {
  requireThat(plan?.version === 1 && Number.isSafeInteger(plan.createdAt) && now >= plan.createdAt && now - plan.createdAt <= 30 * 60 * 1000, "Plan expired or invalid; generate a fresh plan");
  const fresh = await makePlan({ api, desired, binding, state, now: plan.createdAt });
  requireThat(digest(fresh) === digest(plan), "Plan input or live configuration changed; generate a fresh plan");
  if (plan.action === "create") {
    const base = { version: 1, binding, name: desired.name, repository: desired.repository, defaultBranch: desired.defaultBranch };
    // CreateEnvironment has no client token. Persist ambiguity BEFORE sending,
    // and never automatically retry a request that might have reached AWS.
    await journal({ ...base, phase: "creating" });
    const created = await api.create({ name: desired.name, configuration: fresh.desired });
    requireThat(typeof created.environmentId === "string" && /^[a-z0-9]{1,64}$/u.test(created.environmentId), "Invalid created environment ID; reconcile the creation journal");
    state = { ...base, phase: "bound", environmentId: created.environmentId };
    await journal(state);
  } else if (plan.action === "update") {
    await api.update(state.environmentId, fresh.desired);
  }
  const live = observedConfiguration(await api.environment(state.environmentId), state, desired, binding);
  await verifyNoCollectors(api, state.environmentId);
  requireThat(digest(live) === digest(fresh.desired), "Deployment verification failed; state retained for inspection");
  return state;
}

export async function inspectEnvironment({ api, desired, binding, state }) {
  await preflight(api, desired, binding, state);
  requireThat(state, "No environment state; deploy the reviewed plan first");
  const current = await api.environment(state.environmentId);
  const observed = observedConfiguration(current, state, desired, binding);
  await verifyNoCollectors(api, state.environmentId);
  const scan = current.configuration?.codeConfiguration?.latestScan;
  return {
    environmentId: state.environmentId,
    configurationMatches: digest(observed) === digest(configuration(desired, binding)),
    latestScan: scan ? { status: scan.status, scanRunId: scan.scanRunId, origin: scan.origin, createdAt: scan.createdAt, completedAt: scan.completedAt } : null,
  };
}
