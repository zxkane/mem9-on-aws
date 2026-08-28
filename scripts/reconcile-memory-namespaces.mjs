#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import process from "node:process";
import {
  CognitoIdentityProviderClient,
  CreateGroupCommand,
  ListGroupsCommand,
  UpdateGroupCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import pg from "pg";

import {
  deriveGroupKey,
  parseOperatorArgs,
  readDesiredState,
} from "./lib/memory-namespace.mjs";

const USAGE = `usage:
  node scripts/reconcile-memory-namespaces.mjs reconcile --config <file> [--region <region>]

required environment:
  MEM9_COGNITO_ISSUER MEM9_COGNITO_USER_POOL_ID MNEMO_DSN
`;

async function listGroups(client, userPoolId) {
  const groups = new Map();
  let nextToken;
  do {
    const response = await client.send(
      new ListGroupsCommand({ UserPoolId: userPoolId, NextToken: nextToken }),
    );
    for (const group of response.Groups ?? []) {
      if (group.GroupName) groups.set(group.GroupName, group);
    }
    nextToken = response.NextToken;
  } while (nextToken);
  return groups;
}

function countMapDrift(expected, actual) {
  let missing = 0;
  let mismatched = 0;
  for (const [key, value] of expected) {
    if (!actual.has(key)) missing += 1;
    else if (JSON.stringify(actual.get(key)) !== JSON.stringify(value)) {
      mismatched += 1;
    }
  }
  let extra = 0;
  for (const key of actual.keys()) {
    if (!expected.has(key)) extra += 1;
  }
  return { missing, mismatched, extra };
}

async function readDatabaseState(db) {
  const [namespaces, groupBindings, m2mBindings] = await Promise.all([
    db.query(
      `SELECT slug, display_name, status
       FROM memory_namespaces`,
    ),
    db.query(
      `SELECT binding.group_key, namespace.slug AS namespace_slug,
              binding.default_role, binding.jit_enabled, binding.status
       FROM memory_cognito_group_bindings AS binding
       JOIN memory_namespaces AS namespace
         ON namespace.namespace_id = binding.namespace_id`,
    ),
    db.query(
      `SELECT binding.client_key, principal.principal_key,
              namespace.slug AS namespace_slug, binding.role, binding.status,
              principal.status AS principal_status,
              membership.role AS membership_role,
              membership.status AS membership_status
       FROM memory_m2m_namespace_bindings AS binding
       JOIN memory_principals AS principal
         ON principal.principal_id = binding.principal_id
       JOIN memory_namespaces AS namespace
         ON namespace.namespace_id = binding.namespace_id
       LEFT JOIN memory_namespace_memberships AS membership
         ON membership.namespace_id = binding.namespace_id
        AND membership.principal_id = binding.principal_id`,
    ),
  ]);
  return {
    namespaces: new Map(
      namespaces.rows.map((row) => [
        row.slug,
        {
          display_name: row.display_name,
          status: row.status,
        },
      ]),
    ),
    groupBindings: new Map(
      groupBindings.rows.map((row) => [
        row.group_key,
        {
          namespace_slug: row.namespace_slug,
          default_role: row.default_role,
          jit_enabled: row.jit_enabled,
          status: row.status,
        },
      ]),
    ),
    m2mBindings: new Map(
      m2mBindings.rows.map((row) => [
        row.client_key,
        {
          principal_key: row.principal_key,
          namespace_slug: row.namespace_slug,
          role: row.role,
          status: row.status,
          principal_status: row.principal_status,
          membership_role: row.membership_role,
          membership_status: row.membership_status,
        },
      ]),
    ),
  };
}

async function readDrift({ desired, issuer, userPoolId, cognito, db }) {
  const [groups, database] = await Promise.all([
    listGroups(cognito, userPoolId),
    readDatabaseState(db),
  ]);
  const managedDescription = "Managed team memory namespace";
  const desiredGroupNames = new Set(
    desired.namespaces.map((item) => item.cognito_group),
  );
  const cognitoDrift = {
    missing: [...desiredGroupNames].filter((name) => !groups.has(name)).length,
    extra: [...groups.values()].filter(
      (group) =>
        group.Description === managedDescription &&
        !desiredGroupNames.has(group.GroupName),
    ).length,
  };
  const expectedNamespaces = new Map(
    desired.namespaces.map((item) => [
      item.slug,
      {
        display_name: item.display_name,
        status: item.status,
      },
    ]),
  );
  const expectedGroups = new Map(
    desired.namespaces.map((item) => [
      deriveGroupKey(issuer, item.cognito_group),
      {
        namespace_slug: item.slug,
        default_role: item.default_role,
        jit_enabled: item.jit_enabled,
        status: item.status,
      },
    ]),
  );
  const expectedM2M = new Map(
    desired.m2m_bindings.map((item) => [
      item.client_key,
      {
        principal_key: item.principal_key,
        namespace_slug: item.namespace_slug,
        role: item.role,
        status: item.status,
        principal_status: item.status,
        membership_role: item.role,
        membership_status: item.status === "active" ? "active" : "revoked",
      },
    ]),
  );
  const namespaces = countMapDrift(expectedNamespaces, database.namespaces);
  const group_bindings = countMapDrift(
    expectedGroups,
    database.groupBindings,
  );
  const m2m_bindings = countMapDrift(expectedM2M, database.m2mBindings);
  return {
    cognito: cognitoDrift,
    namespaces,
    group_bindings,
    m2m_bindings,
    total:
      cognitoDrift.missing +
      cognitoDrift.extra +
      Object.values(namespaces).reduce((sum, value) => sum + value, 0) +
      Object.values(group_bindings).reduce((sum, value) => sum + value, 0) +
      Object.values(m2m_bindings).reduce((sum, value) => sum + value, 0),
  };
}

export async function reconcileNamespaces({
  desired,
  issuer,
  userPoolId,
  cognito,
  db,
  authoritativeM2MNamespaceSlugs = [],
}) {
  if (!Array.isArray(authoritativeM2MNamespaceSlugs)) {
    throw new Error("authoritative M2M namespace slugs must be an array");
  }
  const desiredNamespaceSlugs = new Set(
    desired.namespaces.map(({ slug }) => slug),
  );
  const authoritativeM2MNamespaces = new Set(
    authoritativeM2MNamespaceSlugs,
  );
  if (
    authoritativeM2MNamespaces.size !==
      authoritativeM2MNamespaceSlugs.length ||
    [...authoritativeM2MNamespaces].some(
      (slug) => !desiredNamespaceSlugs.has(slug),
    )
  ) {
    throw new Error(
      "authoritative M2M namespace slugs must be unique desired namespaces",
    );
  }
  const existingGroups = await listGroups(cognito, userPoolId);
  for (const item of desired.namespaces) {
    const description = "Managed team memory namespace";
    const existing = existingGroups.get(item.cognito_group);
    if (!existing) {
      await cognito.send(
        new CreateGroupCommand({
          UserPoolId: userPoolId,
          GroupName: item.cognito_group,
          Description: description,
        }),
      );
    } else if (existing.Description !== description) {
      await cognito.send(
        new UpdateGroupCommand({
          UserPoolId: userPoolId,
          GroupName: item.cognito_group,
          Description: description,
        }),
      );
    }
  }

  await db.query("BEGIN");
  try {
    const namespaceIDs = new Map();
    for (const item of desired.namespaces) {
      const result = await db.query(
        `INSERT INTO memory_namespaces (
           namespace_id, slug, display_name, status, updated_at
         ) VALUES ($1, $2, $3, $4, statement_timestamp())
         ON CONFLICT (slug) DO UPDATE
         SET display_name = EXCLUDED.display_name,
             status = EXCLUDED.status,
             updated_at = statement_timestamp()
         RETURNING namespace_id`,
        [randomUUID(), item.slug, item.display_name, item.status],
      );
      const namespaceID = result.rows[0].namespace_id;
      namespaceIDs.set(item.slug, namespaceID);
      await db.query(
        `INSERT INTO memory_cognito_group_bindings (
           group_key, namespace_id, default_role, jit_enabled, status, updated_at
         ) VALUES ($1, $2, $3, $4, $5, statement_timestamp())
         ON CONFLICT (group_key) DO UPDATE
         SET namespace_id = EXCLUDED.namespace_id,
             default_role = EXCLUDED.default_role,
             jit_enabled = EXCLUDED.jit_enabled,
             status = EXCLUDED.status,
             updated_at = statement_timestamp()`,
        [
          deriveGroupKey(issuer, item.cognito_group),
          namespaceID,
          item.default_role,
          item.jit_enabled,
          item.status,
        ],
      );
    }

    for (const binding of desired.m2m_bindings) {
      const principalResult = await db.query(
        `INSERT INTO memory_principals (
           principal_id, principal_key, principal_type, status, last_seen_at
         ) VALUES ($1, $2, 'm2m', $3, statement_timestamp())
         ON CONFLICT (principal_key) DO UPDATE
         SET status = EXCLUDED.status,
             last_seen_at = statement_timestamp()
         WHERE memory_principals.principal_type = 'm2m'
         RETURNING principal_id`,
        [randomUUID(), binding.principal_key, binding.status],
      );
      if (principalResult.rowCount !== 1) {
        throw new Error("M2M principal type conflict");
      }
      const principalID = principalResult.rows[0].principal_id;
      const namespaceID = namespaceIDs.get(binding.namespace_slug);
      const existingBinding = await db.query(
        `SELECT principal_id
         FROM memory_m2m_namespace_bindings
         WHERE client_key = $1
         FOR UPDATE`,
        [binding.client_key],
      );
      const previousPrincipalID = existingBinding.rows[0]?.principal_id;
      if (previousPrincipalID && previousPrincipalID !== principalID) {
        await db.query(
          `UPDATE memory_namespace_memberships
           SET status = 'revoked',
               revoked_at = statement_timestamp()
           WHERE principal_id = $1 AND status = 'active'`,
          [previousPrincipalID],
        );
        await db.query(
          `UPDATE memory_principals
           SET status = 'disabled'
           WHERE principal_id = $1`,
          [previousPrincipalID],
        );
      }
      await db.query(
        `INSERT INTO memory_m2m_namespace_bindings (
           client_key, principal_id, namespace_id, role, status, updated_at
         ) VALUES ($1, $2, $3, $4, $5, statement_timestamp())
         ON CONFLICT (client_key) DO UPDATE
         SET principal_id = EXCLUDED.principal_id,
             namespace_id = EXCLUDED.namespace_id,
             role = EXCLUDED.role,
             status = EXCLUDED.status,
             updated_at = statement_timestamp()`,
        [
          binding.client_key,
          principalID,
          namespaceID,
          binding.role,
          binding.status,
        ],
      );
      await db.query(
        `UPDATE memory_namespace_memberships
         SET status = 'revoked',
             revoked_at = statement_timestamp()
         WHERE principal_id = $1
           AND namespace_id <> $2
           AND status = 'active'`,
        [principalID, namespaceID],
      );
      await db.query(
        `INSERT INTO memory_namespace_memberships (
           namespace_id, principal_id, role, status, source_type, source_key,
           revoked_at
         ) VALUES ($1, $2, $3, $4, 'm2m_binding', $5,
           CASE WHEN $4 = 'active' THEN NULL ELSE statement_timestamp() END)
         ON CONFLICT (namespace_id, principal_id) DO UPDATE
         SET role = EXCLUDED.role,
             status = EXCLUDED.status,
             source_type = EXCLUDED.source_type,
             source_key = EXCLUDED.source_key,
             revoked_at = EXCLUDED.revoked_at`,
        [
          namespaceID,
          principalID,
          binding.role,
          binding.status === "active" ? "active" : "revoked",
          binding.client_key,
        ],
      );
    }

    if (authoritativeM2MNamespaces.size > 0) {
      const authoritativeNamespaceIDs = [
        ...authoritativeM2MNamespaces,
      ].map((slug) => namespaceIDs.get(slug));
      const desiredClientKeys = desired.m2m_bindings
        .filter(({ namespace_slug }) =>
          authoritativeM2MNamespaces.has(namespace_slug),
        )
        .map(({ client_key }) => client_key);
      const staleBindings = await db.query(
        `SELECT binding.client_key, binding.principal_id
         FROM memory_m2m_namespace_bindings AS binding
         WHERE binding.namespace_id = ANY($1::varchar[])
           AND NOT (binding.client_key = ANY($2::varchar[]))
         ORDER BY binding.client_key
         FOR UPDATE`,
        [authoritativeNamespaceIDs, desiredClientKeys],
      );
      if (staleBindings.rowCount > 0) {
        const staleClientKeys = staleBindings.rows.map(
          ({ client_key }) => client_key,
        );
        const stalePrincipalIDs = [
          ...new Set(
            staleBindings.rows.map(({ principal_id }) => principal_id),
          ),
        ];
        await db.query(
          `UPDATE memory_namespace_memberships
           SET status = 'revoked',
               revoked_at = statement_timestamp()
           WHERE principal_id = ANY($1::varchar[])
             AND status = 'active'`,
          [stalePrincipalIDs],
        );
        await db.query(
          `UPDATE memory_principals
           SET status = 'disabled'
           WHERE principal_id = ANY($1::varchar[])
             AND principal_type = 'm2m'`,
          [stalePrincipalIDs],
        );
        await db.query(
          `DELETE FROM memory_m2m_namespace_bindings
           WHERE client_key = ANY($1::varchar[])`,
          [staleClientKeys],
        );
      }
    }
    await db.query("COMMIT");
    return {
      namespace_count: desired.namespaces.length,
      m2m_binding_count: desired.m2m_bindings.length,
      drift: await readDrift({
        desired,
        issuer,
        userPoolId,
        cognito,
        db,
      }),
    };
  } catch (error) {
    await db.query("ROLLBACK");
    throw error;
  }
}

async function main() {
  const args = parseOperatorArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(USAGE);
    return;
  }
  if (args.command && args.command !== "reconcile") {
    throw new Error("supported command: reconcile");
  }
  const configPath = args.config ?? process.env.MEM9_NAMESPACE_CONFIG;
  const issuer = process.env.MEM9_COGNITO_ISSUER;
  const userPoolId = process.env.MEM9_COGNITO_USER_POOL_ID;
  const dsn = process.env.MNEMO_DSN;
  if (!configPath || !issuer || !userPoolId || !dsn) {
    throw new Error(
      "MEM9_NAMESPACE_CONFIG, MEM9_COGNITO_ISSUER, " +
        "MEM9_COGNITO_USER_POOL_ID, and MNEMO_DSN are required",
    );
  }
  const desired = await readDesiredState(configPath);
  const region = args.region ?? process.env.AWS_REGION;
  const cognito = new CognitoIdentityProviderClient({ region });
  const db = new pg.Client({ connectionString: dsn });
  await db.connect();
  try {
    const result = await reconcileNamespaces({
      desired,
      issuer,
      userPoolId,
      cognito,
      db,
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } finally {
    cognito.destroy();
    await db.end();
  }
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  main().catch((error) => {
    process.stderr.write(`namespace reconciliation failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
