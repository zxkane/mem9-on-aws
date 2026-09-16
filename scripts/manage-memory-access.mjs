#!/usr/bin/env node
import {
  cancelPrincipalIngestJobs,
  lockNamespaceLifecycle,
} from "./lib/memory-ingest-cancellation.mjs";

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
  readExternalIdentity,
  readUsername,
  validateExternalIdentity,
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

external provider mode (MEM9_AUTH_MODE=oidc):
  Use --identity-file <owner-only-json> instead of --username-file.
  The file contains exactly {"issuer":"https://id.example.com","sub":"provider-subject"}.
  Only Aurora access changes; manage groups at the identity provider.
  MEM9_COGNITO_USER_POOL_ID is not required.
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

function validateAccessInput({
  command,
  emergency,
  namespaceSlug,
  username,
  desired,
  issuer,
  authMode = "managed",
  externalIdentity,
}) {
  if (
    !["assign-user", "move-user", "revoke-user", "show-user"].includes(command)
  ) {
    throw new Error("unsupported access command");
  }
  if (!["managed", "oidc"].includes(authMode))
    throw new Error("unsupported auth mode");
  const external = authMode === "oidc";
  if (external ? username !== undefined : externalIdentity !== undefined) {
    throw new Error("identity input does not match authentication mode");
  }
  const subject = external
    ? validateExternalIdentity(externalIdentity, issuer).sub
    : undefined;
  const assigning = command === "assign-user" || command === "move-user";
  if (
    (emergency && command !== "revoke-user") ||
    (!assigning && namespaceSlug)
  ) {
    throw new Error("invalid access command options");
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

  return { external, subject, target };
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
  authMode = "managed",
  externalIdentity,
}) {
  const { external, subject, target } = validateAccessInput({
    command,
    emergency,
    namespaceSlug,
    username,
    desired,
    issuer,
    authMode,
    externalIdentity,
  });

  const principalKey = deriveHumanPrincipalKey(
    issuer,
    external
      ? subject
      : userSubject(
          await cognito.send(
            new AdminGetUserCommand({
              UserPoolId: userPoolId,
              Username: username,
            }),
          ),
        ),
  );
  if (command === "show-user") {
    const result = await db.query(
      `SELECT principal.status AS principal_status,
              COUNT(*) FILTER (WHERE membership.status = 'active')::int AS active_memberships,
              COUNT(*) FILTER (WHERE membership.status = 'revoked')::int AS revoked_memberships
       FROM memory_principals AS principal
       LEFT JOIN memory_namespace_memberships AS membership USING (principal_id)
       WHERE principal.principal_key = $1 AND principal.principal_type = 'human'
       GROUP BY principal.principal_id, principal.status`,
      [principalKey],
    );
    return (
      result.rows[0] ?? {
        principal_status: "absent",
        active_memberships: 0,
        revoked_memberships: 0,
      }
    );
  }
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
    let targetNamespaceID;
    await db.query("BEGIN");
    try {
      if (emergency) {
        // Serialize overlapping namespace and principal cancellations.
        await lockNamespaceLifecycle(db);
      }
      if (target) {
        const namespace = await db.query(
          `SELECT namespace_id
           FROM memory_namespaces
           WHERE slug = $1 AND status = 'active'
           FOR SHARE`,
          [target.slug],
        );
        if (namespace.rowCount !== 1) {
          throw new Error("target namespace is unavailable");
        }
        targetNamespaceID = namespace.rows[0].namespace_id;
      }
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
        await cancelPrincipalIngestJobs(
          db,
          [principalID],
          "principal_emergency_revoked",
        );
      } else if (target) {
        await db.query(
          `UPDATE memory_principals
           SET status = 'active'
           WHERE principal_id = $1`,
          [principalID],
        );
      }
      if (command === "revoke-user") {
        // Provider tokens can predate first use. Tombstones also block JIT for
        // an existing namespace in which this human never had a membership.
        await db.query(
          `INSERT INTO memory_namespace_memberships (
             namespace_id, principal_id, role, status, source_type,
             source_key, granted_at, revoked_at
           ) SELECT namespace_id, $1, 'member', 'revoked', 'operator', NULL,
                    statement_timestamp(), statement_timestamp()
             FROM memory_namespaces
           ON CONFLICT (namespace_id, principal_id) DO UPDATE
           SET status = 'revoked', revoked_at = statement_timestamp()`,
          [principalID],
        );
      }
      if (target) {
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

    if (!external) {
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
        const recognized = (
          await userGroups(cognito, userPoolId, username)
        ).filter((groupName) => managedGroups.has(groupName));
        if (recognized.length !== 1 || recognized[0] !== target.cognito_group) {
          throw new Error("Cognito group verification failed");
        }
      }
    }

    if (target) {
      await db.query("BEGIN");
      try {
        const namespace = await db.query(
          `SELECT namespace_id
           FROM memory_namespaces
           WHERE slug = $1 AND status = 'active'
           FOR SHARE`,
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
  const authMode = process.env.MEM9_AUTH_MODE ?? "managed";
  if (!["managed", "oidc"].includes(authMode))
    throw new Error("unsupported auth mode");
  const external = authMode === "oidc";
  if (!configPath || !issuer || (!external && !userPoolId) || !dsn) {
    throw new Error(
      "MEM9_NAMESPACE_CONFIG, MEM9_COGNITO_ISSUER, " +
        "MEM9_COGNITO_USER_POOL_ID, and MNEMO_DSN are required",
    );
  }
  if (
    args.username ||
    args.sub ||
    args.subject ||
    args.identity ||
    (external ? args.username_file : args.identity_file)
  ) {
    throw new Error(
      "use the authentication mode's identity file; never pass identity values in argv",
    );
  }
  const desired = await readDesiredState(configPath);
  const externalIdentity = external
    ? await readExternalIdentity(args.identity_file, issuer)
    : undefined;
  const username = external
    ? undefined
    : await readUsername({ file: args.username_file });
  const request = {
    command: args.command,
    emergency: args.emergency === true,
    namespaceSlug: args.namespace,
    username,
    desired,
    issuer,
    authMode,
    externalIdentity,
  };
  validateAccessInput(request);
  const cognito = external
    ? undefined
    : new CognitoIdentityProviderClient({
        region: args.region ?? process.env.AWS_REGION,
      });
  const db = new pg.Client({ connectionString: dsn });
  await db.connect();
  try {
    const result = await manageAccess({ ...request, userPoolId, cognito, db });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } finally {
    cognito?.destroy();
    await db.end();
  }
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  main().catch((error) => {
    process.stderr.write(`memory access command failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
