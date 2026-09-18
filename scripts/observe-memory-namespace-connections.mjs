#!/usr/bin/env node

import process from "node:process";

const APPLICATIONS = Object.freeze({
  control: "mem9-server-control",
  tenant: "mem9-server-tenant",
  observer: "mem9-connection-observer",
});
const MAX_IDLE_CONNECTIONS_PER_POOL = 5;

export async function observeConnections(db) {
  const result = await db.query(`
    SELECT application_name,
           count(*) FILTER (WHERE state = 'idle')::text AS idle_connections,
           count(*) FILTER (WHERE state <> 'idle')::text AS active_connections
    FROM pg_stat_activity
    WHERE datname = current_database()
      AND backend_type = 'client backend'
    GROUP BY application_name
  `);
  const counts = new Map(
    result.rows.map(({ application_name, idle_connections, active_connections }) => [
      application_name ?? "",
      {
        idle: Number(idle_connections),
        active: Number(active_connections),
      },
    ]),
  );
  const known = new Set(Object.values(APPLICATIONS));
  return {
    version: 1,
    control_connections: counts.get(APPLICATIONS.control)?.idle ?? 0,
    tenant_connections: counts.get(APPLICATIONS.tenant)?.idle ?? 0,
    active_connections: [...counts.entries()]
      .filter(([name]) => name !== APPLICATIONS.observer)
      .reduce((total, [, count]) => total + count.active, 0),
    unknown_connections: [...counts.entries()]
      .filter(([name]) => !known.has(name))
      .reduce((total, [, count]) => total + count.idle + count.active, 0),
  };
}

export function compareConnectionSnapshots(before, after) {
  if (before.unknown_connections !== 0 || after.unknown_connections !== 0) {
    throw new Error("unknown database application connections observed");
  }
  if (
    before.control_connections < 1 ||
    before.tenant_connections < 1 ||
    after.control_connections < 1 ||
    after.tenant_connections < 1
  ) {
    throw new Error("attributed control and tenant pools must be observed");
  }
  if (before.active_connections !== 0 || after.active_connections !== 0) {
    throw new Error("connection snapshot was not stable");
  }
  if (
    after.control_connections > MAX_IDLE_CONNECTIONS_PER_POOL ||
    after.control_connections > before.control_connections
  ) {
    throw new Error("control pool grew after sequential principal probes");
  }
  if (
    after.tenant_connections > MAX_IDLE_CONNECTIONS_PER_POOL ||
    after.tenant_connections > before.tenant_connections
  ) {
    throw new Error("tenant pool grew after sequential namespace probes");
  }
  return {
    version: 1,
    before_control: before.control_connections,
    before_tenant: before.tenant_connections,
    after_control: after.control_connections,
    after_tenant: after.tenant_connections,
    max_idle_per_pool: MAX_IDLE_CONNECTIONS_PER_POOL,
  };
}

async function main() {
  if (!/^pr-[1-9][0-9]*$/u.test(process.env.MEM9_STAGE ?? "")) {
    throw new Error("connection observation is restricted to pr-N stages");
  }
  const dsn = process.env.MNEMO_DSN;
  if (!dsn) throw new Error("MNEMO_DSN is required");
  const { default: pg } = await import("pg");
  const observerDsn = new URL(dsn);
  observerDsn.searchParams.set("application_name", APPLICATIONS.observer);
  const db = new pg.Client({
    connectionString: observerDsn.toString(),
    statement_timeout: 30_000,
  });
  await db.connect();
  try {
    let result = await observeConnections(db);
    for (
      let attempt = 1;
      result.active_connections !== 0 && attempt < 20;
      attempt += 1
    ) {
      await new Promise((resolve) => setTimeout(resolve, 250));
      result = await observeConnections(db);
    }
    if (result.active_connections !== 0) {
      throw new Error("database connections did not reach an idle snapshot");
    }
    process.stdout.write(
      `${JSON.stringify({
        event: "namespace_connection_snapshot",
        ...result,
      })}\n`,
    );
  } finally {
    await db.end();
  }
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  main().catch((error) => {
    process.stderr.write(
      `namespace connection observation failed: ${error.message}\n`,
    );
    process.exitCode = 1;
  });
}
