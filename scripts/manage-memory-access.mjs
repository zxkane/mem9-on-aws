#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import process from "node:process";
import {
  AdminAddUserToGroupCommand,
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
  AdminRemoveUserFromGroupCommand,
  CognitoIdentityProviderClient,
} from "@aws-sdk/client-cognito-identity-provider";
import pg from "pg";

import {
  deriveHumanPrincipalKey,
  parseOperatorArgs,
  readDesiredState,
  readUsername,
} from "./lib/memory-namespace.mjs";

const USAGE = `usage:
  node scripts/manage-memory-access.mjs <command> [options]

commands:
  assign-user  --config <file> --username-file <file> --namespace <slug>
  move-user    --config <file> --username-file <file> --namespace <slug>
  revoke-user  --config <file> --username-file <file> [--emergency]
  show-user    --config <file> --username-file <file>

required environment:
  MEM9_COGNITO_ISSUER MEM9_COGNITO_USER_POOL_ID MNEMO_DSN
`;

function userSubject(response) {
  const subject = (response.UserAttributes ?? []).find(
    (attribute) => attribute.Name === "sub",
  )?.Value;
  if (!subject) throw new Error("Cognito user has no subject");
  return subject;
}

async function userGroups(client, userPoolId, username) {
  const names = [];
  let nextToken;
  do {
    const response = await client.send(
      new AdminListGroupsForUserCommand({
        UserPoolId: userPoolId,
        Username: username,
        NextToken: nextToken,
      }),
    );
    for (const group of response.Groups ?? []) {
      if (group.GroupName) names.push(group.GroupName);
    }
    nextToken = response.NextToken;
  } while (nextToken);
  return names;
}

export async function manageAccess({
  command,
  emergency,
  namespaceSlug,
  username,
  desired,
  issuer,
  userPoolId,
  cognito,
  db,
}) {
  if (!["assign-user", "move-user", "revoke-user", "show-user"].includes(command)) {
    throw new Error("unsupported access command");
  }
  const target = namespaceSlug
    ? desired.namespaces.find((item) => item.slug === namespaceSlug)
    : undefined;
  if (
    (command === "assign-user" || command === "move-user") &&
    (!target || target.status !== "active")
  ) {
    throw new Error("target namespace is unknown or disabled");
  }

  const user = await cognito.send(
    new AdminGetUserCommand({ UserPoolId: userPoolId, Username: username }),
  );
  const principalKey = deriveHumanPrincipalKey(issuer, userSubject(user));
  await db.query(`SELECT pg_advisory_lock(hashtext($1))`, [principalKey]);
  try {
    const principalResult = await db.query(
      `INSERT INTO memory_principals (
         principal_id, principal_key, principal_type, status, last_seen_at
       ) VALUES ($1, $2, 'human', 'active', statement_timestamp())
       ON CONFLICT (principal_key) DO UPDATE
       SET last_seen_at = statement_timestamp()
       WHERE memory_principals.principal_type = 'human'
       RETURNING principal_id, status`,
      [randomUUID(), principalKey],
    );
    if (principalResult.rowCount !== 1) {
      throw new Error("human principal type conflict");
    }
    const principalID = principalResult.rows[0].principal_id;
    if (command === "show-user") {
      const result = await db.query(
        `SELECT COUNT(*) FILTER (WHERE status = 'active')::int AS active,
                COUNT(*) FILTER (WHERE status = 'revoked')::int AS revoked
         FROM memory_namespace_memberships
         WHERE principal_id = $1`,
        [principalID],
      );
      return {
        principal_status: principalResult.rows[0].status,
        active_memberships: result.rows[0].active,
        revoked_memberships: result.rows[0].revoked,
      };
    }

    let targetNamespaceID;
    await db.query("BEGIN");
    try {
      await db.query(
        `UPDATE memory_namespace_memberships
         SET status = 'revoked', revoked_at = statement_timestamp()
         WHERE principal_id = $1 AND status = 'active'`,
        [principalID],
      );
      if (emergency) {
        await db.query(
          `UPDATE memory_principals
           SET status = 'disabled'
           WHERE principal_id = $1`,
          [principalID],
        );
        await db.query(
          `UPDATE ingest_jobs
           SET state = 'dead',
               error_class = 'principal_emergency_revoked',
               lease_owner = NULL,
               lease_expires_at = NULL,
               completed_at = statement_timestamp(),
               updated_at = statement_timestamp()
           WHERE principal_id = $1
             AND state NOT IN ('succeeded', 'dead')`,
          [principalID],
        );
      } else {
        await db.query(
          `UPDATE memory_principals
           SET status = 'active'
           WHERE principal_id = $1`,
          [principalID],
        );
      }
      if (target) {
        const namespace = await db.query(
          `SELECT namespace_id
           FROM memory_namespaces
           WHERE slug = $1 AND status = 'active'
           FOR UPDATE`,
          [target.slug],
        );
        if (namespace.rowCount !== 1) {
          throw new Error("target namespace is unavailable");
        }
        targetNamespaceID = namespace.rows[0].namespace_id;
        // A revoked target row is a fail-closed tombstone. If Cognito succeeds
        // but the final operator grant fails, runtime JIT sees this row and
        // refuses to reactivate it.
        await db.query(
          `INSERT INTO memory_namespace_memberships (
             namespace_id, principal_id, role, status, source_type,
             source_key, granted_at, revoked_at
           ) VALUES ($1, $2, $3, 'revoked', 'operator', NULL,
             statement_timestamp(), statement_timestamp())
           ON CONFLICT (namespace_id, principal_id) DO UPDATE
           SET role = EXCLUDED.role,
               status = 'revoked',
               source_type = 'operator',
               source_key = NULL,
               revoked_at = statement_timestamp()`,
          [targetNamespaceID, principalID, target.default_role],
        );
      }
      await db.query("COMMIT");
    } catch (error) {
      await db.query("ROLLBACK");
      throw error;
    }

    const managedGroups = new Set(
      desired.namespaces.map((item) => item.cognito_group),
    );
    for (const groupName of await userGroups(cognito, userPoolId, username)) {
      if (managedGroups.has(groupName)) {
        await cognito.send(
          new AdminRemoveUserFromGroupCommand({
            UserPoolId: userPoolId,
            Username: username,
            GroupName: groupName,
          }),
        );
      }
    }

    if (target) {
      await cognito.send(
        new AdminAddUserToGroupCommand({
          UserPoolId: userPoolId,
          Username: username,
          GroupName: target.cognito_group,
        }),
      );
      const recognized = (await userGroups(cognito, userPoolId, username)).filter(
        (groupName) => managedGroups.has(groupName),
      );
      if (
        recognized.length !== 1 ||
        recognized[0] !== target.cognito_group
      ) {
        throw new Error("Cognito group verification failed");
      }
      await db.query("BEGIN");
      try {
        const namespace = await db.query(
          `SELECT namespace_id
           FROM memory_namespaces
           WHERE slug = $1 AND status = 'active'
           FOR UPDATE`,
          [target.slug],
        );
        if (namespace.rowCount !== 1) {
          throw new Error("target namespace is unavailable");
        }
        if (namespace.rows[0].namespace_id !== targetNamespaceID) {
          throw new Error("target namespace changed during assignment");
        }
        await db.query(
          `INSERT INTO memory_namespace_memberships (
             namespace_id, principal_id, role, status, source_type,
             source_key, granted_at, revoked_at
           ) VALUES ($1, $2, $3, 'active', 'operator', NULL,
             statement_timestamp(), NULL)
           ON CONFLICT (namespace_id, principal_id) DO UPDATE
           SET role = EXCLUDED.role,
               status = 'active',
               source_type = 'operator',
               source_key = NULL,
               granted_at = statement_timestamp(),
               revoked_at = NULL`,
          [namespace.rows[0].namespace_id, principalID, target.default_role],
        );
        await db.query("COMMIT");
      } catch (error) {
        await db.query("ROLLBACK");
        throw error;
      }
    }
    return {
      status: target ? "assigned" : emergency ? "emergency_revoked" : "revoked",
    };
  } finally {
    await db.query(`SELECT pg_advisory_unlock(hashtext($1))`, [principalKey]);
  }
}

async function main() {
  const args = parseOperatorArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(USAGE);
    return;
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
  if (args.username) {
    throw new Error("pass username through stdin or --username-file, not argv");
  }
  const desired = await readDesiredState(configPath);
  const username = await readUsername({ file: args.username_file });
  const cognito = new CognitoIdentityProviderClient({
    region: args.region ?? process.env.AWS_REGION,
  });
  const db = new pg.Client({ connectionString: dsn });
  await db.connect();
  try {
    const result = await manageAccess({
      command: args.command,
      emergency: args.emergency === true,
      namespaceSlug: args.namespace,
      username,
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
    process.stderr.write(`memory access command failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
