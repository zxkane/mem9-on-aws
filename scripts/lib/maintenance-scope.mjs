import { createTransportEnvelope, parseSigningKeys } from "../../infra/gateway/namespace-auth.mjs";
import { serviceIdentity, requireServiceNamespace } from "../../infra/gateway/service-auth.mjs";

export const requireNamespaceId = requireServiceNamespace;
export const createMaintenanceIdentity = serviceIdentity;

export function requireMaintenanceConfig(options, env = process.env, service) {
  const namespaceId = requireNamespaceId(options.namespaceId ?? env.MEM9_NAMESPACE_ID);
  const stage = options.stage ?? env.MEM9_STAGE;
  if (typeof stage !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9-]{0,63}$/.test(stage))
    throw new Error("maintenance stage is required");
  const identity = serviceIdentity(service);
  if (service === "sampler" ||
    (env.MEM9_SERVICE_PRINCIPAL_KEY !== undefined && env.MEM9_SERVICE_PRINCIPAL_KEY !== identity.principalKey) ||
    (env.MEM9_SERVICE_TRANSPORT_ISSUER !== undefined && env.MEM9_SERVICE_TRANSPORT_ISSUER !== identity.issuer))
    throw new Error("maintenance service configuration mismatch");
  if (!env.MEM9_SERVICE_TRANSPORT_SIGNING_KEYS)
    throw new Error("maintenance service signing credentials are required");
  const keys = parseSigningKeys(env.MEM9_SERVICE_TRANSPORT_SIGNING_KEYS);
  return Object.freeze({ ...identity, namespaceId, stage, keys });
}

export function createServiceFetch(scope, fetchImpl = fetch) {
  requireNamespaceId(scope.namespaceId);
  const identity = serviceIdentity(scope.service);
  if (scope.principalKey !== identity.principalKey || scope.issuer !== identity.issuer || !scope.keys)
    throw new Error("maintenance service configuration mismatch");
  return async (input, options = {}) => {
    const url = new URL(input);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.hash)
      throw new Error("invalid maintenance service endpoint");
    const body = options.body ?? "";
    if (typeof body !== "string") throw new Error("maintenance request body must be serialized");
    const method = (options.method ?? "GET").toUpperCase();
    const headers = new Headers(options.headers);
    headers.set("X-Mem9-Transport", createTransportEnvelope({
      issuer: scope.issuer, method, path: url.pathname + url.search, body, keys: scope.keys,
      identity: { principal_type: "service", principal_key: scope.principalKey,
        client_key: scope.principalKey, group_keys: [], namespace_id: scope.namespaceId },
    }));
    return fetchImpl(input, { ...options, method, headers, redirect: "error" });
  };
}

export function createScopedDatabase(db, scope) {
  const namespaceId = requireNamespaceId(scope.namespaceId);
  const identity = serviceIdentity(scope.service);
  if (scope.principalKey !== identity.principalKey) throw new Error("maintenance service identity mismatch");
  // One Client, never a Pool: transaction and session-lock affinity are required.
  let queue = Promise.resolve();
  const operation = (write, work) => {
    const pending = queue.then(async () => {
      await db.query("BEGIN");
      try {
        await db.query("SET LOCAL lock_timeout = '5s'");
        await db.query("SET LOCAL statement_timeout = '30s'");
        await db.query("SET LOCAL idle_in_transaction_session_timeout = '35s'");
        const phase = await db.query(
          "SELECT phase FROM memory_namespace_migration_state WHERE singleton_id",
        );
        if (phase.rows[0]?.phase !== "constraints_complete")
          throw new Error("maintenance requires namespace enforcement");
        const namespace = await db.query(
          "SELECT namespace_id FROM memory_namespaces WHERE namespace_id=$1 AND status='active' FOR SHARE",
          [namespaceId],
        );
        if (namespace.rowCount !== 1) throw new Error("maintenance namespace denied");
        const principal = await db.query(
          "SELECT principal_id FROM memory_principals WHERE principal_key=$1 AND principal_type='service' AND status='active' FOR SHARE",
          [identity.principalKey],
        );
        if (principal.rowCount !== 1) throw new Error("maintenance service denied");
        const principalId = principal.rows[0].principal_id;
        const membership = await db.query(
          "SELECT role FROM memory_namespace_memberships WHERE namespace_id=$1 AND principal_id=$2 AND status='active' AND source_type='service' FOR SHARE",
          [namespaceId, principalId],
        );
        const role = membership.rows[0]?.role;
        if (membership.rowCount !== 1 || !["viewer", "member", "owner"].includes(role) ||
          (write && role === "viewer")) throw new Error("maintenance membership denied");
        const value = await work(db, Object.freeze({ namespaceId, principalId, role }));
        await db.query("COMMIT");
        return value;
      } catch (error) {
        await db.query("ROLLBACK");
        throw error;
      }
    });
    queue = pending.catch(() => {});
    return pending;
  };
  return Object.freeze({
    namespaceId,
    read: work => operation(false, work),
    write: work => operation(true, work),
    authorize: (write = false) => operation(write, async (_db, actor) => actor),
  });
}
