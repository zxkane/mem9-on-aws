#!/usr/bin/env node
import { createHash, createHmac, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { lstat, open, readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual, promisify } from "node:util";
import { readDeploymentManifest, HumanAcceptanceError } from "./lib/human-namespace-acceptance.mjs";
import { awsJson, verifyHumanPreviewTarget } from "./lib/human-namespace-target.mjs";
import { humanTargetFingerprint, writePrivateRecord } from "./lib/human-namespace-records.mjs";
import { deriveGroupKey } from "./lib/memory-namespace.mjs";
import { createMaintenanceIdentity, requireMaintenanceConfig, requireNamespaceId, createServiceFetch, createScopedDatabase } from "./lib/maintenance-scope.mjs";
import { createConsolidationDatabase } from "./memory-consolidation.mjs";

export const MAINTENANCE_CASES = Object.freeze([
  "maintenance_own_get_put", "maintenance_foreign_http_absent",
  "maintenance_wrong_service_key_denied", "maintenance_wrong_issuer_denied",
  "maintenance_wrong_principal_denied", "maintenance_namespace_tamper_denied",
  "maintenance_membership_revoke_isolated", "maintenance_foreign_sql_unchanged",
  "maintenance_owned_fixture_cleanup_complete",
]);
const SERVICES = ["consolidation", "cleanup"];
const ALIASES = ["alpha", "beta"];
const API = "/v1alpha2/mem9s/memories/";
const check = (condition, code) => { if (!condition) throw new HumanAcceptanceError(code); };
const markerFor = (runId) => `maintenance-e2e-${runId}`;
const changeKey = (runId) => createHash("sha256").update(markerFor(runId)).digest("hex");

async function exclusiveRecord(path, value) {
  const file = await open(path, "wx", 0o600);
  try { await file.writeFile(JSON.stringify(value)); await file.sync(); }
  finally { await file.close(); }
}

function parameterValues(response, names) {
  check(Array.isArray(response.Parameters) && !(response.InvalidParameters?.length) &&
    response.Parameters.length === names.length &&
    names.every((name) => response.Parameters.filter((p) => p.Name === name && typeof p.Value === "string" && p.Value).length === 1), "maintenance_parameters_mismatch");
  return Object.fromEntries(response.Parameters.map((p) => [p.Name, p.Value]));
}

// Recheck the running service after the shared account/pool/database/commit gate.
// No endpoint override, secret enumeration, bundled keyring read, or SG mutation.
export async function discoverMaintenanceService(manifest, aws) {
  const prefix = `/mem9-on-aws/${manifest.stage}`;
  const names = ["ecs/cluster-name", "ecs/service-name", "tenant/secret-arn"].map((suffix) => `${prefix}/${suffix}`);
  const values = parameterValues(await aws("ssm", "get-parameters", "--names", ...names), names);
  const cluster = values[names[0]], serviceName = values[names[1]];
  const response = await aws("ecs", "describe-services", "--cluster", cluster, "--services", serviceName);
  check(!response.failures?.length && response.services?.length === 1, "maintenance_service_missing");
  const service = response.services[0];
  check(service.desiredCount === 1 && service.runningCount === 1 && service.pendingCount === 0 &&
    service.deployments?.length === 1 && service.deployments[0].rolloutState === "COMPLETED", "maintenance_service_not_stable");
  const definition = (await aws("ecs", "describe-task-definition", "--task-definition", service.taskDefinition)).taskDefinition;
  check(definition?.taskDefinitionArn === service.taskDefinition && definition.containerDefinitions?.length === 3 &&
    definition.containerDefinitions.every((c) => c.image.endsWith(`:pr-${manifest.commit.slice(0, 7)}`)), "maintenance_deployed_commit_mismatch");
  const server = definition.containerDefinitions.find((c) => c.name === "mnemo-server");
  const environment = Object.fromEntries((server?.environment ?? []).map((e) => [e.name, e.value]));
  const secrets = Object.fromEntries((server?.secrets ?? []).map((e) => [e.name, e.valueFrom]));
  const tenantRef = values[names[2]];
  check(environment.MNEMO_NAMESPACE_REQUIRED === "1" && environment.MEM9_DB_HOST === manifest.database.host &&
    environment.MEM9_DB_NAME === manifest.database.name && secrets.MEM9_DB_SECRET === manifest.database.secretArn &&
    secrets.MEM9_TENANT_ID === tenantRef && tenantRef.startsWith(`arn:aws:secretsmanager:${manifest.region}:${manifest.accountId}:secret:mem9-on-aws-${manifest.stage}-tenant-api-key-`), "maintenance_runtime_binding_mismatch");
  const listed = await aws("ecs", "list-tasks", "--cluster", cluster, "--service-name", serviceName, "--desired-status", "RUNNING");
  check(listed.taskArns?.length === 1, "maintenance_running_task_ambiguous");
  const tasks = await aws("ecs", "describe-tasks", "--cluster", cluster, "--tasks", listed.taskArns[0]);
  const task = tasks.tasks?.[0];
  check(!tasks.failures?.length && tasks.tasks?.length === 1 && task.taskArn === listed.taskArns[0] &&
    task.taskDefinitionArn === service.taskDefinition && task.group === `service:${serviceName}` && task.lastStatus === "RUNNING", "maintenance_running_task_mismatch");
  const runningServer = task.containers?.find((c) => c.name === "mnemo-server");
  check(runningServer?.lastStatus === "RUNNING", "maintenance_server_not_running");
  const addresses = [...new Set((runningServer.networkInterfaces ?? []).map((n) => n.privateIpv4Address))];
  const ip = addresses[0], octets = String(ip).split(".").map(Number);
  check(addresses.length === 1 && isIP(ip) === 4 && (octets[0] === 10 ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168)), "maintenance_private_endpoint_required");
  const secret = await aws("secretsmanager", "describe-secret", "--secret-id", tenantRef);
  const tags = Object.fromEntries((secret.Tags ?? []).map((t) => [t.Key, t.Value]));
  check(secret.ARN === tenantRef && tags.Stage === manifest.stage && tags.Project === "mem9-on-aws", "maintenance_tenant_secret_mismatch");
  const tenantId = (await aws("secretsmanager", "get-secret-value", "--secret-id", tenantRef)).SecretString;
  check(typeof tenantId === "string" && /^[a-f0-9]{32}$/.test(tenantId), "maintenance_tenant_value_invalid");
  const signingNames = SERVICES.map((service) => `${prefix}/namespace/service-${service}-signing-keys`);
  const signing = parameterValues(await aws("ssm", "get-parameters", "--names", ...signingNames, "--with-decryption"), signingNames);
  return { baseUrl: `http://${ip}:8080`, tenantId,
    keyrings: Object.fromEntries(SERVICES.map((service, i) => [service, signing[signingNames[i]]])) };
}

async function namespacesFor(manifest, target, db, cleanupOnly = false) {
  check(isDeepStrictEqual(manifest.namespaces.map((n) => n.slug).sort(), ["preview-alpha", "preview-beta"]), "maintenance_preview_bindings_required");
  const ids = {};
  for (const alias of ALIASES) {
    const entry = manifest.namespaces.find((n) => n.slug === `preview-${alias}`);
    const result = cleanupOnly
      ? await db.query("SELECT namespace_id FROM memory_namespaces WHERE slug=$1", [entry.slug])
      : await db.query(`SELECT n.namespace_id FROM memory_cognito_group_bindings b
        JOIN memory_namespaces n USING(namespace_id) WHERE n.slug=$1 AND b.group_key=$2
        AND n.status='active' AND b.status='active' AND b.jit_enabled`, [entry.slug, deriveGroupKey(target.issuer, entry.cognito_group)]);
    check(result.rowCount === 1, "maintenance_preview_binding_mismatch");
    ids[alias] = requireNamespaceId(result.rows[0].namespace_id);
  }
  const ordered = manifest.namespaces.map((n) => ids[n.slug.slice("preview-".length)]);
  check(humanTargetFingerprint(manifest, ordered) === target.targetFingerprint, "maintenance_target_changed");
  return ids;
}

export function validateMaintenanceJournal(journal, fingerprint, namespaces) {
  check(journal?.version === 1 && journal.targetFingerprint === fingerprint &&
    journal.agentMarker === markerFor(journal.runId) &&
    isDeepStrictEqual(journal.namespaces, namespaces), "maintenance_journal_target_mismatch");
  requireNamespaceId(journal.runId);
  check(journal.ids && isDeepStrictEqual(Object.keys(journal.ids).sort(), ALIASES), "maintenance_journal_ids_invalid");
  const ids = ALIASES.flatMap((alias) => journal.ids?.[alias] ?? []);
  check(ids.length === 4 && new Set(ids).size === 4 && ALIASES.every((alias) => journal.ids[alias]?.length === 2), "maintenance_journal_ids_invalid");
  ids.forEach(requireNamespaceId);
  const change = journal.membership;
  if (change) check(change.before?.namespace_id === namespaces.alpha && change.before.status === "active" &&
    change.before.source_type === "service" && ["member", "owner"].includes(change.before.role) &&
    (!change.after || (change.after.namespace_id === namespaces.alpha && change.after.principal_id === change.before.principal_id &&
      change.after.status === "revoked" && change.after.source_key === changeKey(journal.runId))), "maintenance_journal_membership_invalid");
  return journal;
}

async function transaction(db, work) {
  await db.query("BEGIN");
  try {
    await db.query("SET LOCAL lock_timeout='5s'");
    await db.query("SET LOCAL statement_timeout='30s'");
    await db.query("SET LOCAL idle_in_transaction_session_timeout='35s'");
    const result = await work(); await db.query("COMMIT"); return result;
  } catch (error) { await db.query("ROLLBACK").catch(() => {}); throw error; }
}

async function restoreMembership(db, journal) {
  if (!journal.membership) return;
  await transaction(db, async () => {
    await db.query("SELECT namespace_id FROM memory_namespaces WHERE namespace_id=$1 FOR SHARE", [journal.namespaces.alpha]);
    const principal = await db.query("SELECT principal_id FROM memory_principals WHERE principal_key=$1 AND principal_type='service' FOR SHARE", [createMaintenanceIdentity("consolidation").principalKey]);
    const { before, after } = journal.membership;
    check(principal.rowCount === 1 && principal.rows[0].principal_id === before.principal_id, "maintenance_cleanup_principal_mismatch");
    const current = (await db.query("SELECT to_jsonb(m) AS record FROM memory_namespace_memberships m WHERE namespace_id=$1 AND principal_id=$2 FOR UPDATE", [before.namespace_id, before.principal_id])).rows[0]?.record;
    if (isDeepStrictEqual(current, before)) return;
    check(after && isDeepStrictEqual(current, after), "maintenance_membership_changed_externally");
    const result = await db.query(`UPDATE memory_namespace_memberships m SET status=$3,source_key=$4,revoked_at=$5::timestamptz
      WHERE namespace_id=$1 AND principal_id=$2 AND to_jsonb(m)=$6::jsonb RETURNING to_jsonb(m) AS record`,
    [before.namespace_id, before.principal_id, before.status, before.source_key, before.revoked_at, JSON.stringify(after)]);
    check(result.rowCount === 1 && isDeepStrictEqual(result.rows[0].record, before), "maintenance_membership_restore_unverified");
  });
}

export async function cleanupMaintenanceFixtures(connect, journal) {
  const db = await connect();
  try {
    // Attempt both cleanup operations even if restoring a concurrently changed
    // membership must be refused. Never widen either ownership predicate.
    let problem;
    try { await restoreMembership(db, journal); } catch (error) { problem = error; }
    try {
      await transaction(db, async () => {
        for (const alias of ALIASES) {
          const namespaceId = journal.namespaces[alias], ids = journal.ids[alias];
          await db.query("DELETE FROM memories WHERE namespace_id=$1 AND agent_id=$2 AND id=ANY($3)", [namespaceId, journal.agentMarker, ids]);
          const left = await db.query("SELECT count(*)::int AS remaining FROM memories WHERE namespace_id=$1 AND id=ANY($2)", [namespaceId, ids]);
          check(left.rows[0]?.remaining === 0, "maintenance_fixture_cleanup_unverified");
        }
      });
    } catch (error) { problem ??= error; }
    if (problem) throw problem;
  } finally { await db.end(); }
}

async function snapshot(db, journal) {
  const records = [];
  for (const alias of ALIASES) {
    const result = await db.query(`SELECT to_jsonb(m) AS record FROM memories m
      WHERE namespace_id=$1 AND agent_id=$2 AND id=ANY($3) ORDER BY id`,
    [journal.namespaces[alias], journal.agentMarker, journal.ids[alias]]);
    records.push(...result.rows.map((r) => r.record));
  }
  return records.sort((left, right) => left.id.localeCompare(right.id));
}

async function boundedHttpBody(response) {
  if (!response.body) return "";
  const reader = response.body.getReader(), chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return Buffer.concat(chunks, size).toString("utf8");
      size += value.byteLength;
      if (size > 65536) {
        await reader.cancel().catch(() => {});
        throw new HumanAcceptanceError("maintenance_http_body_too_large");
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
}

export async function runMaintenanceScenarios({ manifest, target, endpoint, journal, persist, report, fetchImpl = fetch, signal }) {
  const scopes = Object.fromEntries(SERVICES.map((service) => [service, Object.fromEntries(ALIASES.map((alias) => [alias,
    requireMaintenanceConfig({ stage: manifest.stage, namespaceId: journal.namespaces[alias] }, { MEM9_SERVICE_TRANSPORT_SIGNING_KEYS: endpoint.keyrings[service] }, service),
  ]))]));
  const request = async (scope, id, method, expected, intercept) => {
    signal?.throwIfAborted();
    const transport = createServiceFetch(scope, async (url, options) => fetchImpl(url, intercept ? intercept(options) : options));
    const headers = new Headers({ "content-type": "application/json" });
    headers.set("X-API-Key", endpoint.tenantId);
    const response = await transport(`${endpoint.baseUrl}${API}${encodeURIComponent(id)}`, {
      method, headers,
      ...(method === "PUT" ? { body: JSON.stringify({ tags: ["maintenance-e2e"] }) } : {}),
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(15000)]) : AbortSignal.timeout(15000),
    });
    const body = await boundedHttpBody(response);
    if (response.status !== expected) {
      const error = new HumanAcceptanceError("maintenance_unexpected_http_status");
      error.http = { method, expectedStatus: expected, actualStatus: response.status, body: body.slice(0, 65536) };
      throw error;
    }
    if (expected === 200) {
      const value = JSON.parse(body);
      check(value.id === id, "maintenance_response_identity_mismatch");
    }
  };
  const tamper = (scope, changes, resign) => (options) => {
    const headers = new Headers(options.headers), [encoded, mac] = headers.get("X-Mem9-Transport").split(".");
    const payload = { ...JSON.parse(Buffer.from(encoded, "base64url")), ...changes };
    const bytes = Buffer.from(JSON.stringify(payload));
    const signature = resign ? createHmac("sha256", scope.keys.keys.get(payload.kid)).update(bytes).digest("hex") : mac;
    headers.set("X-Mem9-Transport", `${bytes.toString("base64url")}.${signature}`);
    return { ...options, headers };
  };
  const db = await target.connect();
  try {
    for (const alias of ALIASES) {
      await createScopedDatabase(db, scopes.consolidation[alias]).write(async (tx, actor) => {
        for (const id of journal.ids[alias]) await tx.query(`INSERT INTO memories
          (id,namespace_id,created_by_principal_id,updated_by_principal_id,agent_id,content,memory_type,state,version,embedding)
          VALUES($1,$2,$3,$3,$4,'Synthetic maintenance verification fixture','pinned','active',1,
          (ARRAY[1::real] || array_fill(0::real,ARRAY[1023]))::vector)`, [id, actor.namespaceId, actor.principalId, journal.agentMarker]);
      });
    }
    for (const service of SERVICES) for (const alias of ALIASES) {
      await request(scopes[service][alias], journal.ids[alias][0], "GET", 200);
      await request(scopes[service][alias], journal.ids[alias][0], "PUT", 200);
    }
    report(MAINTENANCE_CASES[0]);
    const before = await snapshot(db, journal);
    check(before.length === 4, "maintenance_seed_count_mismatch");
    for (const service of SERVICES) for (const alias of ALIASES) for (const method of ["GET", "PUT"])
      await request(scopes[service][alias], journal.ids[alias === "alpha" ? "beta" : "alpha"][0], method, 404);
    check(isDeepStrictEqual(await snapshot(db, journal), before), "maintenance_foreign_http_mutated");
    report(MAINTENANCE_CASES[1]);
    const scope = scopes.consolidation.alpha, id = journal.ids.alpha[0];
    await request({ ...scope, keys: scopes.cleanup.alpha.keys }, id, "PUT", 403);
    report(MAINTENANCE_CASES[2]);
    await request(scope, id, "PUT", 403, tamper(scope, { issuer: "maintenance:unknown" }, true));
    report(MAINTENANCE_CASES[3]);
    await request(scope, id, "PUT", 403, tamper(scope, { principal_key: "f".repeat(64), client_key: "f".repeat(64) }, true));
    report(MAINTENANCE_CASES[4]);
    await request(scope, id, "PUT", 403, tamper(scope, { namespace_id: journal.namespaces.beta }, false));
    check(isDeepStrictEqual(await snapshot(db, journal), before), "maintenance_denied_http_mutated");
    report(MAINTENANCE_CASES[5]);
    await createScopedDatabase(db, scope).write(async (tx, actor) => {
      const original = (await tx.query("SELECT to_jsonb(m) AS record FROM memory_namespace_memberships m WHERE namespace_id=$1 AND principal_id=$2 FOR UPDATE", [actor.namespaceId, actor.principalId])).rows[0]?.record;
      check(original?.status === "active" && original.source_type === "service", "maintenance_membership_baseline_invalid");
      journal.membership = { before: original, after: null };
      await persist(); // Write-ahead ownership record, before touching the row.
      const changed = await tx.query(`UPDATE memory_namespace_memberships m SET status='revoked',source_key=$3,revoked_at=clock_timestamp()
        WHERE namespace_id=$1 AND principal_id=$2 AND to_jsonb(m)=$4::jsonb RETURNING to_jsonb(m) AS record`,
      [actor.namespaceId, actor.principalId, changeKey(journal.runId), JSON.stringify(original)]);
      check(changed.rowCount === 1, "maintenance_membership_revoke_failed");
      journal.membership.after = changed.rows[0].record;
      await persist(); // Persist the exact after-image before COMMIT can succeed.
    });
    await request(scope, id, "PUT", 403);
    await request(scopes.consolidation.beta, journal.ids.beta[0], "PUT", 200);
    await restoreMembership(db, journal);
    report(MAINTENANCE_CASES[6]);
    const rows = await snapshot(db, journal), own = rows.find((r) => r.id === id), foreign = rows.find((r) => r.id === journal.ids.beta[0]);
    const adapter = createConsolidationDatabase(db, scope);
    for (const [loser, winner] of [[foreign, own], [own, foreign]]) check(await adapter.archiveMemory({
      id: loser.id, supersededBy: winner.id, version: loser.version, content: loser.content,
      winnerVersion: winner.version, winnerContent: winner.content,
    }) === false, "maintenance_foreign_archive_accepted");
    check(await adapter.markMemoryStale({ id: foreign.id, tags: ["stale"], metadata: {}, version: foreign.version, content: foreign.content }) === false, "maintenance_foreign_stale_accepted");
    check(isDeepStrictEqual(await snapshot(db, journal), rows), "maintenance_foreign_sql_mutated");
    report(MAINTENANCE_CASES[7]);
  } finally { await db.end(); }
}

async function checkCheckout(commit) {
  const git = promisify(execFile), cwd = fileURLToPath(new URL("..", import.meta.url));
  const head = await git("git", ["rev-parse", "HEAD"], { cwd });
  const status = await git("git", ["status", "--porcelain", "--untracked-files=normal"], { cwd });
  check(head.stdout.trim() === commit && !status.stdout.trim(), "maintenance_clean_exact_checkout_required");
}

export async function main(args = process.argv.slice(2), runtime = {}) {
  const emit = runtime.emit ?? ((line) => process.stdout.write(line + "\n"));
  if (args.length === 1 && args[0] === "--help") {
    emit("usage: run-maintenance-namespace-e2e.mjs --deployment-file <owner.local.json> --fixtures-file <new.local.json> --evidence-file <new.json> [--cleanup-only]"); return;
  }
  const options = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--cleanup-only") options.cleanupOnly = true;
    else if (["--deployment-file", "--fixtures-file", "--evidence-file"].includes(args[i]) && args[i + 1]) {
      check(!options[args[i]], "maintenance_duplicate_argument"); options[args[i]] = resolve(args[++i]);
    } else check(false, "maintenance_invalid_arguments");
  }
  const deployment = options["--deployment-file"], fixtures = options["--fixtures-file"], evidenceFile = options["--evidence-file"];
  check(deployment?.endsWith(".local.json") && fixtures?.endsWith(".local.json") && evidenceFile &&
    new Set([deployment, fixtures, evidenceFile, fixtures + ".failure.local.json"]).size === 4, "maintenance_private_paths_required");
  const manifest = await readDeploymentManifest(deployment);
  // Recovery may use repaired local code after a failed deployment. Its safety
  // comes from the pinned target and journal, not application/checkout readiness.
  if (!options.cleanupOnly) await (runtime.checkCheckout ?? checkCheckout)(manifest.commit);
  let journal;
  if (options.cleanupOnly) {
    const stat = await lstat(fixtures);
    check(stat.isFile() && stat.uid === process.getuid() && (stat.mode & 0o077) === 0, "maintenance_journal_must_be_private");
    journal = JSON.parse(await readFile(fixtures, "utf8"));
  } else {
    try { await lstat(fixtures); check(false, "maintenance_journal_already_exists"); } catch (error) { if (error.code !== "ENOENT") throw error; }
  }
  const evidence = { version: 1, commit: manifest.commit, kind: options.cleanupOnly ? "cleanup" : "acceptance", success: false, cleanup_complete: false, cases: [] };
  await exclusiveRecord(evidenceFile, evidence);
  const controller = new AbortController(), stop = () => controller.abort();
  process.once("SIGINT", stop); process.once("SIGTERM", stop);
  let problem, target, journalOwned = false;
  const report = (label) => {
    check(MAINTENANCE_CASES.includes(label) && !evidence.cases.includes(label), "maintenance_case_label_invalid");
    evidence.cases.push(label); emit(`PASS ${label}`);
  };
  try {
    target = await (runtime.verifyTarget ?? verifyHumanPreviewTarget)(manifest, { cleanupOnly: Boolean(options.cleanupOnly) });
    const db = await target.connect();
    let namespaces;
    try { namespaces = await namespacesFor(manifest, target, db, Boolean(options.cleanupOnly)); } finally { await db.end(); }
    if (options.cleanupOnly) validateMaintenanceJournal(journal, target.targetFingerprint, namespaces);
    else {
      const runId = randomUUID();
      journal = { version: 1, commit: manifest.commit, targetFingerprint: target.targetFingerprint, namespaces,
        runId, agentMarker: markerFor(runId), ids: Object.fromEntries(ALIASES.map((alias) => [alias, [randomUUID(), randomUUID()]])) };
      await exclusiveRecord(fixtures, journal);
    }
    journalOwned = true;
    const persist = () => writePrivateRecord(fixtures, journal);
    controller.signal.throwIfAborted();
    if (!options.cleanupOnly) {
      const endpoint = await discoverMaintenanceService(manifest, runtime.aws ?? ((...args) => awsJson(manifest.region, args)));
      await runMaintenanceScenarios({ manifest, target, endpoint, journal, persist, report,
        fetchImpl: runtime.fetchImpl ?? fetch, signal: controller.signal });
    }
  } catch (error) { problem = error; }
  finally {
    if (journalOwned) {
      try {
        await cleanupMaintenanceFixtures(target.connect, journal);
        evidence.cleanup_complete = true; report(MAINTENANCE_CASES[8]);
      } catch (error) { problem ??= error; }
    }
    process.off("SIGINT", stop); process.off("SIGTERM", stop);
  }
  if (!options.cleanupOnly && !MAINTENANCE_CASES.every((label) => evidence.cases.includes(label))) problem ??= new HumanAcceptanceError("maintenance_cases_incomplete");
  if (controller.signal.aborted) problem ??= new HumanAcceptanceError("maintenance_interrupted");
  evidence.success = !options.cleanupOnly && !problem && evidence.cleanup_complete;
  // Journals remain private on both success and failure; their flags never
  // substitute for a fresh cleanup verification or acceptance case execution.
  if (journalOwned) await writePrivateRecord(fixtures, { ...journal, cleanup_complete: evidence.cleanup_complete });
  if (problem) await writePrivateRecord(fixtures + ".failure.local.json", { name: problem.name, message: problem.message, stack: problem.stack, http: problem.http, stdout: problem.stdout, stderr: problem.stderr });
  await writePrivateRecord(evidenceFile, evidence);
  emit(JSON.stringify({ acceptance_complete: evidence.success, cleanup_complete: evidence.cleanup_complete }));
  if (problem) throw new HumanAcceptanceError("maintenance_acceptance_incomplete");
  return evidence;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(() => {
  process.stderr.write("maintenance namespace verification incomplete; inspect private operator records\n");
  process.exitCode = 1;
});
