#!/usr/bin/env node
import { randomUUID } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { serviceIdentity, MAINTENANCE_SERVICES, requireServiceNamespace } from "../infra/gateway/service-auth.mjs";
import { lockNamespaceLifecycle } from "./lib/memory-ingest-cancellation.mjs";

export function validateServiceBinding(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
    Object.keys(value).some(k => !["namespace_id", "service"].includes(k)) ||
    !MAINTENANCE_SERVICES.includes(value.service))
    throw new Error("invalid service binding configuration");
  requireServiceNamespace(value.namespace_id);
  return value;
}
export async function readServiceBinding(path) {
  const info = await stat(path);
  if (!info.isFile() || (info.mode & 0o077) !== 0) throw new Error("service binding file must be owner-only");
  return validateServiceBinding(JSON.parse(await readFile(path, "utf8")));
}

async function principal(db, service) {
  const { principalKey } = serviceIdentity(service);
  await db.query(
    `INSERT INTO memory_principals(principal_id,principal_key,principal_type,status)
     VALUES($1,$2,'service','active') ON CONFLICT(principal_key) DO NOTHING`,
    [randomUUID(), principalKey],
  );
  const result = await db.query(
    "SELECT principal_id,principal_type,status FROM memory_principals WHERE principal_key=$1 FOR NO KEY UPDATE",
    [principalKey],
  );
  if (result.rowCount !== 1 || result.rows[0].principal_type !== "service") throw new Error("service principal type mismatch");
  return result.rows[0];
}

// Caller holds the lifecycle/namespace transaction. New grants are explicit
// per-namespace rows; boot/reconciliation never reactivate revoked membership.
export async function initializeServiceMemberships(db, namespaceIds, services = ["sampler"]) {
  namespaceIds.forEach(requireServiceNamespace);
  for (const service of services) {
    const actor = await principal(db, service);
    if (actor.status !== "active") continue;
    const role = ["sampler", "analysis"].includes(service) ? "viewer" : "member";
    for (const id of [...new Set(namespaceIds)].sort())
      await db.query(
        `INSERT INTO memory_namespace_memberships(namespace_id,principal_id,role,status,source_type)
         SELECT namespace_id,$2,$3,'active','service' FROM memory_namespaces WHERE namespace_id=$1 AND status='active'
         ON CONFLICT(namespace_id,principal_id) DO NOTHING`,
        [id, actor.principal_id, role],
      );
  }
}

export async function manageMemoryService({ db, command, binding }) {
  validateServiceBinding(binding);
  if (!["enable", "disable", "show"].includes(command)) throw new Error("invalid service operation");
  await db.query("BEGIN");
  try {
    await db.query("SET LOCAL lock_timeout = '5s'");
    await db.query("SET LOCAL statement_timeout = '30s'");
    await lockNamespaceLifecycle(db);
    const ns = await db.query(
      "SELECT namespace_id,status FROM memory_namespaces WHERE namespace_id=$1 FOR NO KEY UPDATE",
      [binding.namespace_id],
    );
    if (ns.rowCount !== 1) throw new Error("service namespace unavailable");
    const { principalKey } = serviceIdentity(binding.service);
    if (command === "show") {
      const result = await db.query(
        `SELECT p.status AS principal_status,m.status AS membership_status,m.role
         FROM memory_principals p LEFT JOIN memory_namespace_memberships m
           ON m.principal_id=p.principal_id AND m.namespace_id=$1 AND m.source_type='service'
         WHERE p.principal_key=$2 AND p.principal_type='service'`,
        [binding.namespace_id, principalKey],
      );
      await db.query("COMMIT");
      return { namespace_status: ns.rows[0].status, ...(result.rows[0] ?? { principal_status: "absent" }) };
    }
    const actor = await principal(db, binding.service);
    if (command === "enable" && (ns.rows[0].status !== "active" || actor.status !== "active"))
      throw new Error("service or namespace is disabled");
    const existing = await db.query(
      "SELECT source_type FROM memory_namespace_memberships WHERE namespace_id=$1 AND principal_id=$2 FOR UPDATE",
      [binding.namespace_id, actor.principal_id],
    );
    if (existing.rows.some(row => row.source_type !== "service")) throw new Error("service membership ownership mismatch");
    const enabled = command === "enable";
    await db.query(
      `INSERT INTO memory_namespace_memberships(namespace_id,principal_id,role,status,source_type,revoked_at)
       VALUES($1,$2,$3,$4::varchar,'service',CASE WHEN $4::varchar='revoked' THEN statement_timestamp() END)
       ON CONFLICT(namespace_id,principal_id) DO UPDATE SET
       role=EXCLUDED.role,status=EXCLUDED.status,source_type='service',source_key=NULL,
       granted_at=CASE WHEN EXCLUDED.status='active' THEN statement_timestamp() ELSE memory_namespace_memberships.granted_at END,
       revoked_at=EXCLUDED.revoked_at`,
      [binding.namespace_id, actor.principal_id, binding.service === "analysis" ? "viewer" : "member", enabled ? "active" : "revoked"],
    );
    await db.query("COMMIT");
    return { status: enabled ? "enabled" : "disabled" };
  } catch (error) {
    await db.query("ROLLBACK");
    throw error;
  }
}

async function main() {
  const [command, flag, file, ...extra] = process.argv.slice(2);
  if (flag !== "--config" || !file || extra.length || !["enable", "disable", "show"].includes(command))
    throw new Error("usage: manage-memory-services.mjs enable|disable|show --config <owner-only.local.json>");
  const binding = await readServiceBinding(file);
  if (!process.env.MNEMO_DSN) throw new Error("database configuration required");
  const db = new pg.Client({ connectionString: process.env.MNEMO_DSN, statement_timeout: 30000 });
  await db.connect();
  try { console.log(JSON.stringify(await manageMemoryService({ db, command, binding }))); }
  finally { await db.end(); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main().catch(() => { console.error("memory service operation failed"); process.exitCode = 1; });
