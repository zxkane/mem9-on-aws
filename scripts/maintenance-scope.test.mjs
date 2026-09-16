import { describe, expect, it, vi } from "vitest";
import { createMaintenanceIdentity, requireNamespaceId, requireMaintenanceConfig, createScopedDatabase, createServiceFetch } from "./lib/maintenance-scope.mjs";
import { verifyTransportEnvelope, parseSigningKeys } from "../infra/gateway/namespace-auth.mjs";

const namespaceId = "60000000-0000-4000-8000-000000000001";
const principalId = "70000000-0000-4000-8000-000000000001";
const keys = { active: "a", a: "A".repeat(43), b: "B".repeat(43) };
const config = () => requireMaintenanceConfig({ stage: "pr-42", namespaceId }, { MEM9_SERVICE_TRANSPORT_SIGNING_KEYS: JSON.stringify(keys) }, "consolidation");
describe("maintenance scope boundaries", () => {
  it.each([undefined, "", "all", "*", "../other", [namespaceId], namespaceId + ",other"])("rejects missing or ambiguous namespace", value => {
    expect(() => requireNamespaceId(value)).toThrow();
  });
  it("binds identity to the service and refuses mismatched configuration", () => {
    expect(createMaintenanceIdentity("cleanup").principalKey).not.toBe(createMaintenanceIdentity("consolidation").principalKey);
    expect(() => requireMaintenanceConfig({ stage: "prod", namespaceId }, {}, "cleanup")).toThrow();
    expect(() => requireMaintenanceConfig({ stage: "prod", namespaceId }, { MEM9_SERVICE_TRANSPORT_SIGNING_KEYS: JSON.stringify(keys), MEM9_SERVICE_PRINCIPAL_KEY: "f".repeat(64) }, "cleanup")).toThrow();
  });
  it("signs namespace, service, method, URI and body and refuses redirect following", async () => {
    const scope = config(), fetchImpl = vi.fn(async () => new Response("{}"));
    await createServiceFetch(scope, fetchImpl)("http://service.example.com/v1alpha2/mem9s/memories?limit=1", { method: "POST", body: '{"content":"fixture"}' });
    const [url, init] = fetchImpl.mock.calls[0];
    const claims = verifyTransportEnvelope({ envelope: new Headers(init.headers).get("X-Mem9-Transport"), issuer: scope.issuer, method: "POST", path: "/v1alpha2/mem9s/memories?limit=1", body: init.body, keys: parseSigningKeys(JSON.stringify(keys)) });
    expect(claims.namespace_id).toBe(namespaceId);
    expect(claims.principal_type).toBe("service");
    expect(claims.principal_key).toBe(scope.principalKey);
    expect(init.redirect).toBe("error");
    expect(String(url)).toContain("service.example.com");
  });
  it("authorizes inside each data transaction and rolls back before callbacks on denial", async () => {
    const events = [];
    let role = "member";
    const db = { query: vi.fn(async (sql) => {
      events.push(sql);
      if (sql.includes("FROM memory_namespace_migration_state")) return { rows: [{phase:"constraints_complete"}] };
      if (sql.includes("FROM memory_namespaces")) return { rowCount: 1, rows: [{ namespace_id: namespaceId }] };
      if (sql.includes("FROM memory_principals")) return { rowCount: 1, rows: [{ principal_id: principalId }] };
      if (sql.includes("FROM memory_namespace_memberships")) return { rowCount: 1, rows: [{ role }] };
      return { rows: [] };
    }) };
    const scoped = createScopedDatabase(db, config());
    const work = vi.fn(async (tx, actor) => { expect(actor.principalId).toBe(principalId); await tx.query("DATA_OPERATION"); return 7; });
    expect(await scoped.write(work)).toBe(7);
    expect(events[0]).toBe("BEGIN");
    expect(events.at(-2)).toBe("DATA_OPERATION");
    expect(events.at(-1)).toBe("COMMIT");
    role = "viewer";
    await expect(scoped.write(work)).rejects.toThrow();
    expect(work).toHaveBeenCalledTimes(1);
    expect(events.at(-1)).toBe("ROLLBACK");
    expect(await scoped.read(work)).toBe(7);
  });
});
