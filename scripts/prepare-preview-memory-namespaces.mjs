#!/usr/bin/env node

import process from "node:process";
import {
  CognitoIdentityProviderClient,
} from "@aws-sdk/client-cognito-identity-provider";
import pg from "pg";

import {
  deriveClientKey,
  deriveM2MPrincipalKey,
  validateDesiredState,
} from "./lib/memory-namespace.mjs";
import {
  SHARED_HISTORY_ACKNOWLEDGEMENT,
  backfillNamespaces,
  enforceNamespaces,
  freezeNamespaceWriters,
} from "./migrate-memory-namespaces.mjs";
import { reconcileNamespaces } from "./reconcile-memory-namespaces.mjs";

const PREVIEW_SERVICE_PRINCIPAL_ID =
  "70000000-0000-4000-8000-000000000201";

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`missing required env ${name}`);
  return value;
}

function databaseDsn() {
  const secret = JSON.parse(requireEnv("MEM9_DB_SECRET"));
  if (
    typeof secret.username !== "string" ||
    typeof secret.password !== "string"
  ) {
    throw new Error("MEM9_DB_SECRET must contain username and password");
  }
  const url = new URL("postgres://placeholder");
  url.username = secret.username;
  url.password = secret.password;
  url.hostname = requireEnv("MEM9_DB_HOST");
  url.port = requireEnv("MEM9_DB_PORT");
  url.pathname = `/${encodeURIComponent(requireEnv("MEM9_DB_NAME"))}`;
  url.searchParams.set("sslmode", "require");
  return url.toString();
}

export function previewNamespaceDesiredState({
  issuer,
  defaultClientId,
  alpha,
  beta,
}) {
  const namespaces = [alpha, beta].map((fixture) => ({
    slug: fixture.slug,
    display_name: `PR isolation fixture ${fixture.slug}`,
    cognito_group: fixture.group,
    default_role: "member",
    jit_enabled: true,
    status: "active",
  }));
  const m2mBindings = [
    { clientId: defaultClientId, namespaceSlug: alpha.slug },
    { clientId: alpha.clientId, namespaceSlug: alpha.slug },
    { clientId: beta.clientId, namespaceSlug: beta.slug },
  ].map(({ clientId, namespaceSlug }) => ({
    client_key: deriveClientKey(issuer, clientId),
    principal_key: deriveM2MPrincipalKey(issuer, clientId),
    namespace_slug: namespaceSlug,
    role: "member",
    status: "active",
  }));
  return validateDesiredState({
    namespaces,
    m2m_bindings: m2mBindings,
  });
}

async function migrationPhase(db) {
  const result = await db.query(
    `SELECT phase
     FROM memory_namespace_migration_state
     WHERE singleton_id`,
  );
  if (result.rowCount !== 1) {
    throw new Error("namespace migration state is missing");
  }
  return result.rows[0].phase;
}

export async function preparePreviewMemoryNamespaces({
  db,
  cognito,
  issuer,
  userPoolId,
  stage,
  desired,
  migrationPath,
}) {
  const reconciliation = await reconcileNamespaces({
    desired,
    issuer,
    userPoolId,
    cognito,
    db,
    authoritativeM2MNamespaceSlugs: desired.namespaces.map(
      ({ slug }) => slug,
    ),
  });
  if (reconciliation.drift.total !== 0) {
    throw new Error(
      `preview namespace reconciliation did not converge: ${reconciliation.drift.total} drift items`,
    );
  }
  let phase = await migrationPhase(db);
  if (phase === "constraints_complete") {
    return { phase, reconciliation };
  }
  if (phase === "additive_ready" || phase === "frozen") {
    await freezeNamespaceWriters(db);
    phase = "frozen";
  }
  if (phase === "frozen" || phase === "backfilling") {
    const legacyNamespace = await db.query(
      `SELECT namespace_id
       FROM memory_namespaces
       WHERE slug = $1 AND status = 'active'`,
      [desired.namespaces[0].slug],
    );
    if (legacyNamespace.rowCount !== 1) {
      throw new Error("preview legacy namespace is unavailable");
    }
    await backfillNamespaces({
      db,
      stage,
      namespaceID: legacyNamespace.rows[0].namespace_id,
      namespaceSlug: desired.namespaces[0].slug,
      namespaceDisplayName: desired.namespaces[0].display_name,
      principalID: PREVIEW_SERVICE_PRINCIPAL_ID,
      acknowledgement: SHARED_HISTORY_ACKNOWLEDGEMENT,
    });
    phase = "application_ready";
  }
  if (phase === "application_ready") {
    await enforceNamespaces(db, migrationPath);
    phase = "constraints_complete";
  }
  if (phase !== "constraints_complete") {
    throw new Error(`unsupported preview namespace migration phase ${phase}`);
  }
  return { phase, reconciliation };
}

async function main() {
  const stage = requireEnv("MEM9_STAGE");
  if (!/^pr-[1-9][0-9]*$/u.test(stage)) {
    throw new Error("preview namespace fixtures require a pr-N stage");
  }
  const issuer = requireEnv("MEM9_COGNITO_ISSUER");
  const userPoolId = requireEnv("MEM9_COGNITO_USER_POOL_ID");
  const desired = previewNamespaceDesiredState({
    issuer,
    defaultClientId: requireEnv(
      "MEM9_PREVIEW_NAMESPACE_DEFAULT_CLIENT_ID",
    ),
    alpha: {
      clientId: requireEnv("MEM9_PREVIEW_NAMESPACE_ALPHA_CLIENT_ID"),
      slug: requireEnv("MEM9_PREVIEW_NAMESPACE_ALPHA_SLUG"),
      group: requireEnv("MEM9_PREVIEW_NAMESPACE_ALPHA_GROUP"),
    },
    beta: {
      clientId: requireEnv("MEM9_PREVIEW_NAMESPACE_BETA_CLIENT_ID"),
      slug: requireEnv("MEM9_PREVIEW_NAMESPACE_BETA_SLUG"),
      group: requireEnv("MEM9_PREVIEW_NAMESPACE_BETA_GROUP"),
    },
  });
  const cognito = new CognitoIdentityProviderClient({
    region: requireEnv("AWS_REGION"),
  });
  const db = new pg.Client({ connectionString: databaseDsn() });
  await db.connect();
  try {
    const result = await preparePreviewMemoryNamespaces({
      db,
      cognito,
      issuer,
      userPoolId,
      stage,
      desired,
      migrationPath:
        "/bootstrap/migrations/003_enforce_memory_namespaces.sql",
    });
    process.stdout.write(
      `${JSON.stringify({
        phase: result.phase,
        namespace_count: result.reconciliation.namespace_count,
        m2m_binding_count: result.reconciliation.m2m_binding_count,
        drift_total: result.reconciliation.drift.total,
      })}\n`,
    );
  } finally {
    cognito.destroy();
    await db.end();
  }
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  main().catch((error) => {
    process.stderr.write(
      `preview namespace preparation failed: ${error.message}\n`,
    );
    process.exitCode = 1;
  });
}
