import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { afterEach, describe, expect, it, vi } from "vitest";
import { main, MAINTENANCE_CASES, runMaintenanceScenarios, validateMaintenanceJournal } from "./run-maintenance-namespace-e2e.mjs";
import { humanTargetFingerprint } from "./lib/human-namespace-records.mjs";
import { createMaintenanceIdentity } from "./lib/maintenance-scope.mjs";
import { parseSigningKeys, verifyTransportEnvelope } from "../infra/gateway/namespace-auth.mjs";
import { validateServiceIdentity } from "../infra/gateway/service-auth.mjs";

const NS = { alpha: "60000000-0000-4000-8000-000000000101", beta: "60000000-0000-4000-8000-000000000102" };
const SERVICES = ["consolidation", "cleanup"];
const PRINCIPALS = { consolidation: "70000000-0000-4000-8000-000000000101", cleanup: "70000000-0000-4000-8000-000000000102" };
const paths = [];
afterEach(async () => { for (const path of paths.splice(0)) await rm(path, { recursive: true, force: true }); });

async function fixture(options = {}) {
  const directory = await mkdtemp(join(tmpdir(), "maintenance-live-gate-")); paths.push(directory);
  const files = { deployment: join(directory, "deployment.local.json"), journal: join(directory, "fixtures.local.json"), evidence: join(directory, "evidence.json") };
  const manifest = {
    version: 1, stage: options.production ? "prod" : "pr-42", commit: "a".repeat(40), accountId: "123456789012", region: "ap-northeast-1",
    userPoolId: ["ap-northeast-1", "fixture"].join("_"), facadeUrl: "https://facade.example.com", gatewayUrl: "https://gateway.example.com/mcp",
    proxyFunctionArn: "arn:aws:lambda:ap-northeast-1:123456789012:function:mem9-on-aws-pr-42-proxy",
    proxyLogGroup: "/sst/fixture/proxy",
    database: { host: "database.example.com", port: 5432, name: "mem9", resourceId: "cluster-fixture", clusterId: "mem9-on-aws-pr-42-db",
      secretArn: "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:mem9-on-aws-pr-42-db-fixture", caFile: "/tmp/fixture.pem" },
    namespaces: Object.keys(NS).map((alias) => ({ slug: `preview-${alias}`, display_name: alias, cognito_group: `mem9-${alias}`, default_role: "member", jit_enabled: true, status: "active" })),
  };
  await writeFile(files.deployment, JSON.stringify(manifest), { mode: options.publicManifest ? 0o644 : 0o600 });
  const keyrings = Object.fromEntries(SERVICES.map((name, index) => [name, JSON.stringify({ active: "a", a: Buffer.alloc(32, index + 1).toString("base64url"), b: Buffer.alloc(32, index + 3).toString("base64url") })]));
  const membershipKey = (ns, principal) => `${ns}/${principal}`;
  const memberships = new Map(SERVICES.flatMap((service) => Object.values(NS).map((namespace_id) => [membershipKey(namespace_id, PRINCIPALS[service]), {
    namespace_id, principal_id: PRINCIPALS[service], role: "member", status: "active", source_type: "service", source_key: null,
    granted_at: "2026-01-01T00:00:00+00:00", revoked_at: null,
  }])));
  const originalMembership = structuredClone(memberships.get(membershipKey(NS.alpha, PRINCIPALS.consolidation)));
  const rows = new Map([["unowned", { id: "unowned", namespace_id: NS.alpha, agent_id: "someone-else", content: "preexisting private content" }]]);
  const queries = [], requests = [], output = [];
  let commitFaulted = false, cleanupFaulted = false;
  const connect = vi.fn(async () => {
    let before;
    return { end: vi.fn(async () => {}), query: vi.fn(async (sql, values = []) => {
      queries.push({ sql, values });
      const result = (records) => ({ rowCount: records.length, rows: structuredClone(records) });
      if (sql === "BEGIN") { before = { rows: structuredClone(rows), memberships: structuredClone(memberships) }; return result([]); }
      if (sql === "COMMIT") {
        before = undefined;
        if (options.lostCommit && !commitFaulted && memberships.get(membershipKey(NS.alpha, PRINCIPALS.consolidation)).status === "revoked") { commitFaulted = true; throw new Error("private lost commit acknowledgement"); }
        return result([]);
      }
      if (sql === "ROLLBACK") {
        if (before) { rows.clear(); memberships.clear(); for (const [k,v] of before.rows) rows.set(k,v); for (const [k,v] of before.memberships) memberships.set(k,v); before = undefined; }
        return result([]);
      }
      if (sql.startsWith("SET LOCAL")) return result([]);
      if (sql.includes("FROM memory_namespace_migration_state")) return result([{ phase: "constraints_complete" }]);
      if (sql.includes("memory_cognito_group_bindings")) {
        if (options.bindingsUnavailable) throw new Error("group binding no longer ready");
        return result([{ namespace_id: NS[values[0].replace("preview-", "")] }]);
      }
      if (sql.includes("FROM memory_namespaces")) {
        const id = sql.includes("WHERE slug=") ? NS[values[0].replace("preview-", "")] : values[0];
        return result(Object.values(NS).includes(id) ? [{ namespace_id: id }] : []);
      }
      if (sql.includes("FROM memory_principals")) {
        const service = SERVICES.find((name) => createMaintenanceIdentity(name).principalKey === values[0]);
        return result(service ? [{ principal_id: PRINCIPALS[service] }] : []);
      }
      if (sql.includes("SELECT role FROM memory_namespace_memberships")) {
        const row = memberships.get(membershipKey(values[0], values[1]));
        return result(row?.status === "active" ? [{ role: row.role }] : []);
      }
      if (sql.includes("SELECT to_jsonb(m) AS record FROM memory_namespace_memberships")) {
        const row = memberships.get(membershipKey(values[0], values[1])); return result(row ? [{ record: row }] : []);
      }
      if (sql.startsWith("UPDATE memory_namespace_memberships")) {
        const row = memberships.get(membershipKey(values[0], values[1]));
        if (sql.includes("status='revoked'")) {
          if (!isDeepStrictEqual(row, JSON.parse(values[3]))) return result([]);
          Object.assign(row, { status: "revoked", source_key: values[2], revoked_at: "2026-09-16T00:00:00+00:00" });
        } else {
          if (options.restoreFailure) throw new Error("private membership restore failure");
          if (!isDeepStrictEqual(row, JSON.parse(values[5]))) return result([]);
          Object.assign(row, { status: values[2], source_key: values[3], revoked_at: values[4] });
        }
        return result([{ record: row }]);
      }
      if (sql.startsWith("INSERT INTO memories")) {
        if (rows.has(values[0])) throw new Error("duplicate fixture ID");
        rows.set(values[0], { id: values[0], namespace_id: values[1], agent_id: values[3], content: "Synthetic maintenance verification fixture", version: 1,
          state: "active", embedding: "[1,0]", tags: [], metadata: {}, superseded_by: null, updated_by_principal_id: values[2] });
        return result([]);
      }
      if (sql.includes("SELECT to_jsonb(m) AS record FROM memories")) return result([...rows.values()].filter((r) => r.namespace_id === values[0] && r.agent_id === values[1] && values[2].includes(r.id)).sort((a,b) => a.id.localeCompare(b.id)).map((record) => ({ record })));
      if (sql.startsWith("UPDATE memories AS loser")) {
        const row = rows.get(values[0]), winner = rows.get(values[1]);
        if (row?.namespace_id !== values[6] || winner?.namespace_id !== values[6]) return result([]);
        row.state = "archived"; row.superseded_by = values[1]; return { rowCount: 1, rows: [] };
      }
      if (sql.startsWith("UPDATE memories")) {
        const row = rows.get(values[0]); if (row?.namespace_id !== values[5]) return result([]);
        row.tags = JSON.parse(values[1]); return { rowCount: 1, rows: [] };
      }
      if (sql.startsWith("DELETE FROM memories")) {
        if (options.cleanupFailure && !cleanupFaulted) { cleanupFaulted = true; throw new Error("private cleanup failure"); }
        for (const [id,row] of rows) if (row.namespace_id === values[0] && row.agent_id === values[1] && values[2].includes(id)) rows.delete(id);
        return result([]);
      }
      if (sql.startsWith("SELECT count(*)::int AS remaining")) return result([{ remaining: [...rows.values()].filter((r) => r.namespace_id === values[0] && values[1].includes(r.id)).length }]);
      throw new Error("unexpected fixture query: " + sql);
    }) };
  });
  const taskDef = "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/fixture:1", taskArn = "arn:aws:ecs:ap-northeast-1:123456789012:task/fixture/task";
  const tenantRef = "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:mem9-on-aws-pr-42-tenant-api-key-fixture";
  const prefix = "/mem9-on-aws/pr-42";
  const aws = vi.fn(async (...args) => {
    const op = args.slice(0,2).join(" ");
    if (op === "ssm get-parameters") {
      const names = args.slice(args.indexOf("--names") + 1).filter((s) => !s.startsWith("--"));
      const table = { [`${prefix}/ecs/cluster-name`]: "fixture-cluster", [`${prefix}/ecs/service-name`]: "fixture-service", [`${prefix}/tenant/secret-arn`]: tenantRef,
        ...Object.fromEntries(SERVICES.map((name) => [`${prefix}/namespace/service-${name}-signing-keys`, keyrings[name]])) };
      checkNames(names, Object.keys(table)); return { InvalidParameters: [], Parameters: names.map((Name) => ({ Name, Value: table[Name] })) };
    }
    if (op === "ecs describe-services") return { services: [{ desiredCount: 1, runningCount: 1, pendingCount: 0, deployments: [{ rolloutState: "COMPLETED" }], taskDefinition: taskDef }] };
    if (op === "ecs describe-task-definition") return { taskDefinition: { taskDefinitionArn: taskDef, containerDefinitions: ["mnemo-server", "qwen3-embed", "llm-proxy"].map((name) => ({ name,
      image: `example.com/${name}:pr-${options.wrongCommit ? "bbbbbbb" : "aaaaaaa"}`,
      environment: [{ name: "MNEMO_NAMESPACE_REQUIRED", value: "1" }, { name: "MEM9_DB_HOST", value: manifest.database.host }, { name: "MEM9_DB_NAME", value: manifest.database.name }],
      secrets: [{ name: "MEM9_DB_SECRET", valueFrom: manifest.database.secretArn }, { name: "MEM9_TENANT_ID", valueFrom: tenantRef }],
    })) } };
    if (op === "ecs list-tasks") return { taskArns: [taskArn] };
    if (op === "ecs describe-tasks") return { tasks: [{ taskArn, taskDefinitionArn: taskDef, group: "service:fixture-service", lastStatus: "RUNNING", containers: [{ name: "mnemo-server", lastStatus: "RUNNING", networkInterfaces: [{ privateIpv4Address: options.publicIp ? "8.8.8.8" : "10.0.1.24" }] }] }] };
    if (op === "secretsmanager describe-secret") return { ARN: tenantRef, Tags: [{ Key: "Stage", Value: "pr-42" }, { Key: "Project", Value: "mem9-on-aws" }] };
    if (op === "secretsmanager get-secret-value") return { SecretString: "d".repeat(32) };
    throw new Error("unexpected AWS operation");
  });
  const fetchImpl = vi.fn(async (url, init) => {
    requests.push({ url, init });
    if (options.oversizeResponse) return new Response("private-body".repeat(65536));
    const headers = new Headers(init.headers), path = new URL(url).pathname, id = decodeURIComponent(path.split("/").at(-1));
    const response = (status, body = status === 404 ? { error: "not found" } : status === 403 ? { error: "memory namespace authorization failed" } : {}) => {
      if ((status === 403 || status === 404) && options.denialFault && (!options.denialStatus || options.denialStatus === status)) {
        const faults = {
          fixture: { error: "Synthetic maintenance verification fixture" },
          foreign_id: { error: id }, namespace: { error: NS.alpha },
          service: { error: "maintenance:consolidation" },
          principal: { error: createMaintenanceIdentity("consolidation").principalKey },
          extra_fields: { error: "not found", memory: { id, content: "private content" } },
          empty: {}, object: { error: { message: "not found" } }, oversize: { error: "x".repeat(1024) },
        };
        body = faults[options.denialFault];
      }
      return new Response(JSON.stringify(body), { status });
    };
    const publicMemory = (row) => Object.fromEntries(Object.entries(row).filter(([key]) => !["embedding", "namespace_id", "created_by_principal_id", "updated_by_principal_id"].includes(key)));
    let identity, service;
    try {
      const envelope = headers.get("X-Mem9-Transport"), payload = JSON.parse(Buffer.from(envelope.split(".")[0], "base64url"));
      service = SERVICES.find((name) => payload.issuer === `maintenance:${name}`);
      identity = verifyTransportEnvelope({ envelope, issuer: `maintenance:${service}`, method: init.method, path, body: init.body ?? "", keys: parseSigningKeys(keyrings[service]) });
      validateServiceIdentity(identity);
    } catch { return response(403); }
    const membership = memberships.get(membershipKey(identity.namespace_id, PRINCIPALS[service]));
    if (membership?.status !== "active") {
      if (options.externalMembershipChange) membership.role = "viewer";
      return response(403, { error: "namespace membership required" });
    }
    const row = rows.get(id);
    if (!row || row.namespace_id !== identity.namespace_id) return response(options.foreignStatus ?? 404);
    if (init.method === "PUT") {
      const body = JSON.parse(init.body); expect(Object.keys(body)).toEqual(["tags"]);
      const prior = structuredClone(row);
      const updated = { ...prior, tags: body.tags, version: prior.version + 1, updated_by_principal_id: PRINCIPALS[service] };
      if (options.putFault === "no_op") return response(200, publicMemory(prior));
      if (options.putFault === "response_only") return response(200, publicMemory(updated));
      Object.assign(row, updated);
      if (options.changeMarker) row.agent_id = "changed-by-other-writer";
      const returned = structuredClone(row);
      if (options.putFault === "returned_tags") returned.tags = ["ignored"];
      if (options.putFault === "returned_version") returned.version = prior.version;
      if (options.putFault === "stored_tags") row.tags = ["ignored"];
      if (options.putFault === "stored_version") row.version = prior.version;
      if (options.putFault === "stored_actor") row.updated_by_principal_id = PRINCIPALS[service === "cleanup" ? "consolidation" : "cleanup"];
      return response(200, publicMemory(returned));
    }
    return response(200, publicMemory(row));
  });
  const runtime = {
    checkCheckout: vi.fn(async (commit) => { expect(commit).toBe(manifest.commit); if (options.dirty) throw new Error("maintenance_clean_exact_checkout_required"); }),
    verifyTarget: vi.fn(async () => { if (options.targetFailure) throw new Error("private target diagnostic"); return { connect, issuer: `https://cognito-idp.${manifest.region}.amazonaws.com/${manifest.userPoolId}`, targetFingerprint: humanTargetFingerprint(manifest, Object.values(NS)) }; }),
    aws, fetchImpl, emit: (line) => output.push(line),
  };
  const args = ["--deployment-file", files.deployment, "--fixtures-file", files.journal, "--evidence-file", files.evidence];
  return { directory, files, manifest, rows, memberships, originalMembership, membershipKey, queries, requests, output, runtime, args, keyrings };
}
function checkNames(actual, expected) { for (const name of actual) if (!expected.includes(name)) throw new Error("unexpected parameter read"); }
function safeOutput(f) {
  for (const value of [...Object.values(NS), ...Object.values(PRINCIPALS), ...Object.values(f.keyrings), "123456789012", "arn:", "private", "Synthetic", "d".repeat(32)])
    expect(f.output.join("\n")).not.toContain(value);
  for (const line of f.output) {
    if (line.startsWith("PASS ")) expect(MAINTENANCE_CASES).toContain(line.slice(5));
    else expect(Object.keys(JSON.parse(line)).sort()).toEqual(["acceptance_complete", "cleanup_complete"]);
  }
}

describe("operator-only maintenance preview gate", () => {
  it("validates keyrings before opening a database connection", async () => {
    const f = await fixture();
    const db = { end: vi.fn() }, target = { connect: vi.fn(async () => db) };
    await expect(runMaintenanceScenarios({
      manifest: f.manifest, target, journal: { namespaces: NS },
      endpoint: { keyrings: { ...f.keyrings, consolidation: "malformed" } },
      persist: vi.fn(), report: vi.fn(), fetchImpl: vi.fn(),
    })).rejects.toThrow(/signing keys/);
    expect(target.connect).not.toHaveBeenCalled();
  });
  it("uses verified service transport and the real SQL adapter, then proves cleanup", async () => {
    const f = await fixture(); const evidence = await main(f.args, f.runtime);
    expect(evidence).toMatchObject({ kind: "acceptance", success: true, cleanup_complete: true, cases: [...MAINTENANCE_CASES] });
    expect([...f.rows.keys()]).toEqual(["unowned"]);
    expect(f.memberships.get(f.membershipKey(NS.alpha, PRINCIPALS.consolidation))).toEqual(f.originalMembership);
    expect(f.queries.filter(({ sql }) => sql.startsWith("UPDATE memories AS loser"))).toHaveLength(2);
    expect(f.queries.some(({ sql }) => sql.includes("AND namespace_id = $6"))).toBe(true);
    const signing = f.runtime.aws.mock.calls.filter((args) => args.includes("--with-decryption"));
    expect(signing).toHaveLength(1);
    expect(signing[0]).not.toContain("/mem9-on-aws/pr-42/namespace/service-transport-signing-keys");
    expect((await stat(f.files.journal)).mode & 0o777).toBe(0o600);
    expect((await stat(f.files.evidence)).mode & 0o777).toBe(0o600);
    const journal = JSON.parse(await readFile(f.files.journal, "utf8"));
    const fixtureQueries = f.queries.filter(({ sql }) => sql.startsWith("DELETE FROM memories") || sql.includes("SELECT to_jsonb(m) AS record FROM memories") || sql.startsWith("SELECT count(*)::int AS remaining"));
    for (const { sql, values } of fixtureQueries) {
      expect(sql).toMatch(/namespace_id\s*=\s*\$1\b/);
      const alias = Object.keys(NS).find((name) => NS[name] === values[0]);
      expect(alias).toBeDefined();
      expect(values[sql.startsWith("SELECT count") ? 1 : 2]).toEqual(journal.ids[alias]);
    }
    safeOutput(f);
  });
  it.each(["no_op", "response_only", "returned_tags", "returned_version", "stored_tags", "stored_version", "stored_actor"])("requires returned and persisted mutation proof: %s", async (putFault) => {
    const f = await fixture({ putFault });
    await expect(main(f.args, f.runtime)).rejects.toThrow(/incomplete/);
    const evidence = JSON.parse(await readFile(f.files.evidence, "utf8"));
    expect(evidence).toMatchObject({ success: false, cleanup_complete: true });
    expect(evidence.cases).not.toContain("maintenance_own_get_put");
    expect([...f.rows.keys()]).toEqual(["unowned"]); safeOutput(f);
  });
  it.each(["fixture", "foreign_id", "namespace", "service", "principal", "extra_fields", "empty", "object", "oversize"])("rejects non-generic denial bodies: %s", async (denialFault) => {
    const f = await fixture({ denialFault });
    await expect(main(f.args, f.runtime)).rejects.toThrow(/incomplete/);
    const evidence = JSON.parse(await readFile(f.files.evidence, "utf8"));
    expect(evidence).toMatchObject({ success: false, cleanup_complete: true });
    expect(evidence.cases).not.toContain("maintenance_foreign_http_absent");
    expect([...f.rows.keys()]).toEqual(["unowned"]); safeOutput(f);
  });
  it("checks 403 bodies after valid generic foreign-ID 404 responses", async () => {
    const f = await fixture({ denialFault: "service", denialStatus: 403 });
    await expect(main(f.args, f.runtime)).rejects.toThrow(/incomplete/);
    const evidence = JSON.parse(await readFile(f.files.evidence, "utf8"));
    expect(evidence).toMatchObject({ success: false, cleanup_complete: true });
    expect(evidence.cases).toContain("maintenance_foreign_http_absent");
    expect(evidence.cases).not.toContain("maintenance_wrong_service_key_denied");
    safeOutput(f);
  });
  it.each(["production", "publicManifest", "dirty"])("rejects %s before target/AWS work", async (key) => {
    const f = await fixture({ [key]: true }); await expect(main(f.args, f.runtime)).rejects.toThrow();
    expect(f.runtime.verifyTarget).not.toHaveBeenCalled(); expect(f.runtime.aws).not.toHaveBeenCalled();
  });
  it("requires a new evidence file before invoking the target guard", async () => {
    const f = await fixture(); await writeFile(f.files.evidence, "existing evidence");
    await expect(main(f.args, f.runtime)).rejects.toThrow();
    expect(await readFile(f.files.evidence, "utf8")).toBe("existing evidence");
    expect(f.runtime.verifyTarget).not.toHaveBeenCalled();
  });
  it.each(["targetFailure", "wrongCommit", "publicIp"])("does not seed fixtures after %s", async (key) => {
    const f = await fixture({ [key]: true }); await expect(main(f.args, f.runtime)).rejects.toThrow();
    expect(f.queries.some(({ sql }) => sql.startsWith("INSERT INTO memories"))).toBe(false);
    expect(JSON.parse(await readFile(f.files.evidence, "utf8")).success).toBe(false); safeOutput(f);
  });
  it.each([{ foreignStatus: 403 }, { lostCommit: true }])("fails unexpected status/commit outcome and restores the original membership", async (options) => {
    const f = await fixture(options); await expect(main(f.args, f.runtime)).rejects.toThrow(/incomplete/);
    const evidence = JSON.parse(await readFile(f.files.evidence, "utf8"));
    expect(evidence.success).toBe(false); expect(evidence.cleanup_complete).toBe(true);
    expect([...f.rows.keys()]).toEqual(["unowned"]);
    expect(f.memberships.get(f.membershipKey(NS.alpha, PRINCIPALS.consolidation))).toEqual(f.originalMembership);
    expect((await stat(f.files.journal)).mode & 0o777).toBe(0o600);
    expect((await stat(f.files.journal + ".failure.local.json")).mode & 0o777).toBe(0o600); safeOutput(f);
  });
  it.each(["cleanupFailure", "restoreFailure", "changeMarker"])("never claims acceptance when %s prevents verified cleanup", async (key) => {
    const f = await fixture({ [key]: true }); await expect(main(f.args, f.runtime)).rejects.toThrow();
    const evidence = JSON.parse(await readFile(f.files.evidence, "utf8"));
    expect(evidence.success).toBe(false); expect(evidence.cleanup_complete).toBe(false);
    expect(evidence.cases).not.toContain("maintenance_owned_fixture_cleanup_complete");
    expect(f.rows.has("unowned")).toBe(true); safeOutput(f);
  });
  it("does not overwrite a membership changed by another operator during the test", async () => {
    const f = await fixture({ externalMembershipChange: true }); await expect(main(f.args, f.runtime)).rejects.toThrow();
    expect(f.memberships.get(f.membershipKey(NS.alpha, PRINCIPALS.consolidation))).toMatchObject({ role: "viewer", status: "revoked" });
    expect(JSON.parse(await readFile(f.files.evidence, "utf8"))).toMatchObject({ success: false, cleanup_complete: false });
    expect([...f.rows.keys()]).toEqual(["unowned"]);
    expect((await stat(f.files.journal)).mode & 0o777).toBe(0o600); safeOutput(f);
  });
  it("cleanup-only rechecks resources and cannot turn failed acceptance into success", async () => {
    const f = await fixture({ cleanupFailure: true }); await expect(main(f.args, f.runtime)).rejects.toThrow();
    const cleanupEvidence = join(f.directory, "cleanup-evidence.json"), args = [...f.args]; args[args.indexOf("--evidence-file") + 1] = cleanupEvidence;
    const result = await main([...args, "--cleanup-only"], f.runtime);
    expect(result).toMatchObject({ kind: "cleanup", success: false, cleanup_complete: true, cases: ["maintenance_owned_fixture_cleanup_complete"] });
    expect([...f.rows.keys()]).toEqual(["unowned"]); safeOutput(f);
    expect((await readdir(f.directory)).some((name) => name.endsWith(".failure.local.json"))).toBe(true);
  });
  it("cleanup-only needs no checkout, active group, ECS readiness, or service credentials", async () => {
    const options = { cleanupFailure: true };
    const f = await fixture(options); await expect(main(f.args, f.runtime)).rejects.toThrow();
    options.bindingsUnavailable = true;
    const target = await f.runtime.verifyTarget(f.manifest);
    f.runtime.checkCheckout.mockImplementation(async () => { throw new Error("checkout no longer ready"); });
    f.runtime.verifyTarget.mockImplementation(async (manifest, mode) => {
      expect(manifest).toEqual(f.manifest); expect(mode).toEqual({ cleanupOnly: true }); return target;
    });
    f.runtime.aws.mockClear().mockImplementation(async () => { throw new Error("unused service credentials unavailable"); });
    f.runtime.fetchImpl.mockClear().mockImplementation(async () => { throw new Error("service is stopped"); });
    const checkedBefore = f.runtime.checkCheckout.mock.calls.length;
    const args = [...f.args]; args[args.indexOf("--evidence-file") + 1] = join(f.directory, "recovery-evidence.json");
    const result = await main([...args, "--cleanup-only"], f.runtime);
    expect(result).toMatchObject({ kind: "cleanup", success: false, cleanup_complete: true });
    expect(f.runtime.checkCheckout).toHaveBeenCalledTimes(checkedBefore);
    expect(f.runtime.aws).not.toHaveBeenCalled(); expect(f.runtime.fetchImpl).not.toHaveBeenCalled();
    expect([...f.rows.keys()]).toEqual(["unowned"]); safeOutput(f);
  });
  it("cleanup-only still refuses a journal with a different target fingerprint", async () => {
    const f = await fixture({ cleanupFailure: true }); await expect(main(f.args, f.runtime)).rejects.toThrow();
    const journal = JSON.parse(await readFile(f.files.journal, "utf8")); journal.targetFingerprint = "f".repeat(64);
    await writeFile(f.files.journal, JSON.stringify(journal));
    const args = [...f.args]; args[args.indexOf("--evidence-file") + 1] = join(f.directory, "wrong-target-evidence.json");
    const deletes = f.queries.filter(({ sql }) => sql.startsWith("DELETE FROM memories")).length;
    await expect(main([...args, "--cleanup-only"], f.runtime)).rejects.toThrow();
    expect(f.queries.filter(({ sql }) => sql.startsWith("DELETE FROM memories"))).toHaveLength(deletes);
    const evidence = JSON.parse(await readFile(args.at(-1), "utf8"));
    expect(evidence).toMatchObject({ kind: "cleanup", success: false, cleanup_complete: false });
  });
  it("bounds HTTP response bytes and retains failed acceptance evidence", async () => {
    const f = await fixture({ oversizeResponse: true }); await expect(main(f.args, f.runtime)).rejects.toThrow();
    const failure = JSON.parse(await readFile(f.files.journal + ".failure.local.json", "utf8"));
    expect(failure.message).toBe("maintenance_http_body_too_large");
    expect(JSON.stringify(failure)).not.toContain("private-body");
    expect(JSON.parse(await readFile(f.files.evidence, "utf8"))).toMatchObject({ success: false, cleanup_complete: true });
    expect([...f.rows.keys()]).toEqual(["unowned"]); safeOutput(f);
  });
  it("rejects a forged target journal even when its cleanup flag is true", async () => {
    const f = await fixture(); await main(f.args, f.runtime);
    const journal = JSON.parse(await readFile(f.files.journal, "utf8"));
    journal.namespaces.alpha = NS.beta; journal.cleanup_complete = true;
    expect(() => validateMaintenanceJournal(journal, journal.targetFingerprint, NS)).toThrow();
  });
  it("rejects extra cleanup ID collections and malformed run ownership", async () => {
    const f = await fixture(); await main(f.args, f.runtime);
    const journal = JSON.parse(await readFile(f.files.journal, "utf8"));
    expect(() => validateMaintenanceJournal({ ...journal, ids: { ...journal.ids, other: ["unowned"] } }, journal.targetFingerprint, NS)).toThrow();
    expect(() => validateMaintenanceJournal({ ...journal, runId: "-".repeat(36), agentMarker: "maintenance-e2e-" + "-".repeat(36) }, journal.targetFingerprint, NS)).toThrow();
  });
  it("records unexpected HTTP details only in the private diagnostic file", async () => {
    const f = await fixture({ foreignStatus: 403 }); await expect(main(f.args, f.runtime)).rejects.toThrow();
    const failure = JSON.parse(await readFile(f.files.journal + ".failure.local.json", "utf8"));
    expect(failure.http).toMatchObject({ expectedStatus: 404, actualStatus: 403 });
    expect((await stat(f.files.journal + ".failure.local.json")).mode & 0o777).toBe(0o600);
    safeOutput(f);
  });
});
