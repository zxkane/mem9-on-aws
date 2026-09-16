import { randomBytes, createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import {
  AdminCreateUserCommand,
  AdminDeleteUserCommand,
  AdminGetUserCommand,
  AdminSetUserPasswordCommand,
  AdminAddUserToGroupCommand,
  AdminRemoveUserFromGroupCommand,
  AdminListGroupsForUserCommand,
  CreateGroupCommand,
  DeleteGroupCommand,
  GetGroupCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import { manageAccess } from "../manage-memory-access.mjs";
import { reconcileNamespaces } from "../reconcile-memory-namespaces.mjs";
import {
  deriveHumanPrincipalKey,
  validateDesiredState,
} from "./memory-namespace.mjs";

export const ACTORS = [
  "writer",
  "peer",
  "other",
  "none",
  "multi",
  "mover",
  "revoked",
  "never_used",
  "emergency",
  "concurrent",
  "viewer",
];
export const MOVE_FAULTS = [
  "revoke_commit",
  "group_remove",
  "group_add",
  "group_verify",
  "target_grant",
  "grant_commit",
];
export const HUMAN_CASES = [
  "reconciliation_twice_and_omission_drift",
  "owned_synthetic_users_ready_without_jit",
  "real_human_oauth_pkce_and_15_minute_tokens",
  "same_group_sharing_cross_group_denial_and_caller_context_replacement",
  "jit_single_membership_and_denial_order",
  "zero_multiple_unrelated_groups_and_concurrent_first_use",
  "managed_revoke_before_first_use_blocks_stale_token_jit",
  "membership_role_and_token_scope_intersection",
  "direct_group_drift_fails_closed",
  "failed_move_tombstone",
  "failed_grant_retry_a_b_a_and_original_team_data_ownership",
  ...MOVE_FAULTS.map((fault) => `move_retry_${fault}`),
  "observed_concurrent_command_serialization",
  "normal_revocation_preserves_accepted_team_work",
  "emergency_revocation_cancels_queued_work",
  "owned_fixture_cleanup_complete",
];

export function verifyHumanOperatorOutput(output) {
  const cases = [];
  const lines = output.trim().split(/\r?\n/);
  for (const line of lines) {
    if (line === "human namespace acceptance: complete") continue;
    const label = line.startsWith("PASS ") ? line.slice(5) : "";
    if (!HUMAN_CASES.includes(label))
      throw new HumanAcceptanceError("unexpected_or_sensitive_operator_output");
    cases.push(label);
  }
  if (lines.at(-1) !== "human namespace acceptance: complete")
    throw new HumanAcceptanceError("operator_output_not_complete");
  if (!HUMAN_CASES.every((label) => cases.includes(label)))
    throw new HumanAcceptanceError("operator_output_cases_incomplete");
  return { output_redacted: true, case_count: cases.length };
}
const own = (object, keys) =>
  object &&
  typeof object === "object" &&
  !Array.isArray(object) &&
  Object.keys(object).every((key) => keys.includes(key));
export class HumanAcceptanceError extends Error {
  constructor(message) {
    super(message);
    this.name = "HumanAcceptanceError";
  }
}
const requireCase = (condition, name) => {
  if (!condition) throw new HumanAcceptanceError(name);
};

export function validateDeploymentManifest(value) {
  requireCase(
    own(value, [
      "version",
      "stage",
      "commit",
      "accountId",
      "region",
      "userPoolId",
      "facadeUrl",
      "gatewayUrl",
      "proxyFunctionArn",
      "proxyLogGroup",
      "database",
      "namespaces",
    ]),
    "invalid deployment manifest fields",
  );
  requireCase(
    value.version === 1 &&
      /^pr-[1-9][0-9]*$/.test(value.stage) &&
      /^[a-f0-9]{40}$/.test(value.commit),
    "exact preview stage and commit required",
  );
  requireCase(
    /^[0-9]{12}$/.test(value.accountId) &&
      /^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$/.test(value.region),
    "invalid deployment account or region",
  );
  requireCase(
    typeof value.userPoolId === "string" &&
      value.userPoolId.startsWith(value.region + "_") &&
      /^[a-z0-9-]+_[A-Za-z0-9]+$/.test(value.userPoolId),
    "pool must match application region",
  );
  for (const key of ["facadeUrl", "gatewayUrl"]) {
    const url = new URL(value[key]);
    requireCase(
      url.protocol === "https:" &&
        !url.username &&
        !url.password &&
        !url.hash &&
        !url.search,
      "invalid deployment endpoint",
    );
  }
  requireCase(
    typeof value.proxyFunctionArn === "string" &&
      value.proxyFunctionArn.startsWith(
        `arn:aws:lambda:${value.region}:${value.accountId}:function:mem9-on-aws-${value.stage}-`,
      ),
    "pinned_preview_proxy_required",
  );
  requireCase(
    typeof value.proxyLogGroup === "string" &&
      new RegExp("^[A-Za-z0-9./_#-]{1,512}$").test(value.proxyLogGroup) &&
      !value.proxyLogGroup.startsWith("aws/"),
    "pinned_proxy_log_group_required",
  );
  const db = value.database;
  requireCase(
    own(db, [
      "host",
      "port",
      "name",
      "resourceId",
      "clusterId",
      "secretArn",
      "caFile",
    ]),
    "invalid database manifest fields",
  );
  requireCase(
    typeof db.host === "string" &&
      /^[a-zA-Z0-9.-]+$/.test(db.host) &&
      Number.isInteger(db.port) &&
      db.port > 0 &&
      db.port < 65536 &&
      typeof db.name === "string" &&
      /^[a-zA-Z0-9_-]+$/.test(db.name),
    "invalid database target",
  );
  requireCase(
    typeof db.resourceId === "string" &&
      db.resourceId.startsWith("cluster-") &&
      typeof db.clusterId === "string" &&
      db.clusterId.includes(`-${value.stage}-`),
    "exact preview database resource required",
  );
  requireCase(
    typeof db.secretArn === "string" &&
      db.secretArn.startsWith(
        `arn:aws:secretsmanager:${value.region}:${value.accountId}:secret:mem9-on-aws-${value.stage}-`,
      ) &&
      typeof db.caFile === "string" &&
      db.caFile.startsWith("/"),
    "preview secret reference and TLS CA required",
  );
  const desired = validateDesiredState({
    namespaces: value.namespaces,
    m2m_bindings: [],
  });
  requireCase(
    desired.namespaces.length === 2,
    "two registered preview namespaces required",
  );
  requireCase(
    value.namespaces.every(
      (n) =>
        n.status === "active" &&
        n.jit_enabled === true &&
        n.default_role === "member",
    ),
    "active_jit_member_fixtures_required",
  );
  return value;
}

export async function readDeploymentManifest(path) {
  const stat = await lstat(path);
  requireCase(
    stat.isFile() && (stat.mode & 0o077) === 0 && stat.uid === process.getuid(),
    "deployment manifest must be an owner-only regular file",
  );
  let value;
  try {
    value = JSON.parse(await readFile(path, "utf8"));
  } catch {
    throw new HumanAcceptanceError("Invalid deployment manifest JSON");
  }
  return validateDeploymentManifest(value);
}

export function createFixturePlan(targetFingerprint) {
  requireCase(
    /^[a-f0-9]{64}$/.test(targetFingerprint),
    "fixture_target_fingerprint_required",
  );
  const runId = randomBytes(16).toString("hex");
  return {
    version: 1,
    targetFingerprint,
    runId,
    users: Object.fromEntries(
      ACTORS.map((alias) => [
        alias,
        {
          username: `namespace-e2e-${runId}-${alias}`,
          password: randomBytes(24).toString("base64url") + "Aa0!",
        },
      ]),
    ),
  };
}

export function validateFixturePlan(plan) {
  requireCase(
    own(plan, ["version", "runId", "users", "targetFingerprint"]) &&
      plan.version === 1 &&
      /^[a-f0-9]{64}$/.test(plan.targetFingerprint) &&
      /^[a-f0-9]{32}$/.test(plan.runId),
    "invalid fixture plan",
  );
  requireCase(
    own(plan.users, ACTORS) && Object.keys(plan.users).length === ACTORS.length,
    "all fixture actors required",
  );
  for (const alias of ACTORS) {
    const user = plan.users[alias];
    requireCase(
      own(user, ["username", "password", "subject"]) &&
        user.username === `namespace-e2e-${plan.runId}-${alias}` &&
        /^[A-Za-z0-9_-]{32}Aa0!$/.test(user.password) &&
        (user.subject === undefined || /^[a-f0-9-]{36}$/.test(user.subject)),
      "fixture identity is not owned by this run",
    );
  }
  return plan;
}

// Shape/lifetime checks supplement, rather than replace, the real Gateway's
// signature verification. Never emit the token or its identity claims.
export function validateHumanAccessToken(
  token,
  now = Math.floor(Date.now() / 1000),
) {
  let claims;
  try {
    claims = JSON.parse(
      Buffer.from(token.split(".")[1], "base64url").toString("utf8"),
    );
  } catch {
    throw new HumanAcceptanceError("invalid human access token");
  }
  requireCase(
    claims.token_use === "access" &&
      typeof claims.sub === "string" &&
      claims.sub.length > 0 &&
      typeof claims.client_id === "string" &&
      claims.client_id.length > 0,
    "human access token claims required",
  );
  const integerTimes =
    Number.isInteger(claims.iat) && Number.isInteger(claims.exp);
  // The pinned reader configuration is checked as exactly 15 minutes.
  // Permit the observed one-second shorter token, never a longer lifetime.
  if (!(integerTimes &&
    claims.exp - claims.iat >= 899 && claims.exp - claims.iat <= 900 &&
    claims.exp > now + 15 && claims.iat <= now + 5)) {
    const error = new HumanAcceptanceError(
      "human token must have a live 15-minute lifetime",
    );
    error.tokenTiming = {
      integer_times: integerTimes,
      lifetime_seconds: integerTimes ? claims.exp - claims.iat : null,
      remaining_seconds: integerTimes ? claims.exp - now : null,
      issued_offset_seconds: integerTimes ? claims.iat - now : null,
    };
    throw error;
  }
  const scopes = new Set(String(claims.scope ?? "").split(/\s+/));
  requireCase(
    scopes.has("mem9-mcp/read") && scopes.has("mem9-mcp/write"),
    "human resource scopes required",
  );
  return claims;
}

export class HumanNamespaceFixture {
  constructor({
    manifest,
    plan,
    cognito,
    connect,
    report = () => {},
    persist = async () => {},
    signal,
    targetFingerprint,
  }) {
    this.manifest = validateDeploymentManifest(manifest);
    this.plan = validateFixturePlan(plan);
    requireCase(
      plan.targetFingerprint === targetFingerprint,
      "fixture_deployment_mismatch",
    );
    this.cognito = cognito;
    this.connect = connect;
    this.report = report;
    this.persist = persist;
    this.signal = signal;
    this.issuer = `https://cognito-idp.${manifest.region}.amazonaws.com/${manifest.userPoolId}`;
    this.desired = { namespaces: manifest.namespaces, m2m_bindings: [] };
    this.unrelatedGroup = `namespace-unrelated-${plan.runId}`;
    this.subjects = new Map();
    this.guards = new Map();
    this.agentId = `human-namespace-${plan.runId}`;
  }
  identity(alias) {
    requireCase(ACTORS.includes(alias), "unknown fixture actor");
    return this.plan.users[alias];
  }
  input(alias) {
    return {
      UserPoolId: this.manifest.userPoolId,
      Username: this.identity(alias).username,
    };
  }
  async withDb(work) {
    const db = await this.connect();
    try {
      return await work(db);
    } finally {
      await db.end();
    }
  }
  async user(alias, optional = false) {
    try {
      const value = await this.cognito.send(
        new AdminGetUserCommand(this.input(alias)),
      );
      requireCase(
        value.UserAttributes?.some(
          (x) =>
            x.Name === "preferred_username" &&
            x.Value === `${this.plan.runId}:${alias}`,
        ),
        "fixture ownership mismatch",
      );
      const subject = value.UserAttributes.find((x) => x.Name === "sub")?.Value;
      requireCase(
        typeof subject === "string" && subject.length > 0,
        "fixture subject missing",
      );
      const identity = this.identity(alias);
      requireCase(
        !identity.subject || identity.subject === subject,
        "fixture_subject_changed",
      );
      this.subjects.set(alias, subject);
      if (!identity.subject) {
        identity.subject = subject;
        await this.persist(this.plan);
      }
      return value;
    } catch (error) {
      if (optional && error.name === "UserNotFoundException") return null;
      throw error;
    }
  }
  async groups(alias) {
    const names = [];
    let NextToken;
    do {
      const result = await this.cognito.send(
        new AdminListGroupsForUserCommand({ ...this.input(alias), NextToken }),
      );
      names.push(...(result.Groups ?? []).map((x) => x.GroupName));
      NextToken = result.NextToken;
    } while (NextToken);
    return names;
  }
  async changeGroup(alias, index, add) {
    const GroupName =
      index === "unrelated"
        ? this.unrelatedGroup
        : this.desired.namespaces[index].cognito_group;
    const Command = add
      ? AdminAddUserToGroupCommand
      : AdminRemoveUserFromGroupCommand;
    await this.cognito.send(new Command({ ...this.input(alias), GroupName }));
  }
  async access(alias, command, { target = 0, fault, db, role } = {}) {
    const operation = async (connection) => {
      let commits = 0,
        groupReads = 0,
        injected = false;
      const fail = (point) => {
        if (!injected && fault === point) {
          injected = true;
          throw new HumanAcceptanceError(`injected_${point}`);
        }
      };
      const adapter = {
        query: async (sql, args) => {
          if (
            sql.includes("INSERT INTO memory_namespace_memberships") &&
            sql.includes("'active', 'operator'")
          )
            fail("target_grant");
          const value = await connection.query(sql, args);
          if (sql === "COMMIT")
            fail(++commits === 1 ? "revoke_commit" : "grant_commit");
          return value;
        },
      };
      const provider = {
        send: async (request) => {
          const value = await this.cognito.send(request);
          switch (request.constructor.name) {
            case "AdminRemoveUserFromGroupCommand":
              fail("group_remove");
              break;
            case "AdminAddUserToGroupCommand":
              fail("group_add");
              break;
            case "AdminListGroupsForUserCommand":
              if (++groupReads === 2) fail("group_verify");
              break;
          }
          return value;
        },
      };
      const desired = role
        ? {
            ...this.desired,
            namespaces: this.desired.namespaces.map((n, i) =>
              i === target ? { ...n, default_role: role } : n,
            ),
          }
        : this.desired;
      const request = {
        command: command === "emergency" ? "revoke-user" : command,
        emergency: command === "emergency",
        username: this.identity(alias).username,
        issuer: this.issuer,
        userPoolId: this.manifest.userPoolId,
        desired,
        db: adapter,
        cognito: provider,
      };
      if (command === "assign-user" || command === "move-user")
        request.namespaceSlug = desired.namespaces[target].slug;
      return manageAccess(request);
    };
    return db ? operation(db) : this.withDb(operation);
  }
  async placement(alias) {
    await this.user(alias);
    const key = deriveHumanPrincipalKey(this.issuer, this.subjects.get(alias));
    return this.withDb(
      async (db) =>
        (
          await db.query(
            `SELECT p.status AS principal_status, n.slug, m.status, m.role, m.source_type
      FROM memory_principals p LEFT JOIN memory_namespace_memberships m USING(principal_id)
      LEFT JOIN memory_namespaces n USING(namespace_id) WHERE p.principal_key=$1`,
            [key],
          )
        ).rows,
    );
  }
  async assertPlacement(alias, target, { disabled = false } = {}) {
    const rows = await this.placement(alias);
    const active = rows.filter((x) => x.status === "active");
    requireCase(
      active.length === (target === null ? 0 : 1),
      "active_membership_count",
    );
    if (target !== null)
      requireCase(
        active[0].slug === this.desired.namespaces[target].slug,
        "active_membership_namespace",
      );
    if (disabled)
      requireCase(
        rows.length > 0 && rows.every((x) => x.principal_status === "disabled"),
        "principal_not_disabled",
      );
    const managed = (await this.groups(alias)).filter((group) =>
      this.desired.namespaces.some((n) => n.cognito_group === group),
    );
    requireCase(
      managed.length === (target === null ? 0 : 1) &&
        (target === null ||
          managed[0] === this.desired.namespaces[target].cognito_group),
      "provider_membership_mismatch",
    );
  }
  async prepare() {
    await this.withDb(async (db) => {
      const before = (
        await db.query(
          "SELECT client_key,principal_id,namespace_id,role,status FROM memory_m2m_namespace_bindings ORDER BY client_key",
        )
      ).rows;
      const options = {
        desired: this.desired,
        issuer: this.issuer,
        userPoolId: this.manifest.userPoolId,
        cognito: this.cognito,
        db,
      };
      const first = await reconcileNamespaces(options),
        second = await reconcileNamespaces(options);
      requireCase(
        JSON.stringify(first.drift) === JSON.stringify(second.drift),
        "reconciliation_not_idempotent",
      );
      for (const key of ["namespaces", "group_bindings", "m2m_bindings"])
        requireCase(
          second.drift[key].missing === 0 && second.drift[key].mismatched === 0,
          "reconciliation_not_converged",
        );
      const after = (
        await db.query(
          "SELECT client_key,principal_id,namespace_id,role,status FROM memory_m2m_namespace_bindings ORDER BY client_key",
        )
      ).rows;
      requireCase(
        JSON.stringify(before) === JSON.stringify(after),
        "reconciliation_pruned_omissions",
      );
    });
    this.report("reconciliation_twice_and_omission_drift");
    try {
      await this.cognito.send(
        new CreateGroupCommand({
          UserPoolId: this.manifest.userPoolId,
          GroupName: this.unrelatedGroup,
          Description: this.plan.runId,
        }),
      );
    } catch (error) {
      if (error.name !== "GroupExistsException") throw error;
    }
    const ownedGroup = await this.cognito.send(
      new GetGroupCommand({
        UserPoolId: this.manifest.userPoolId,
        GroupName: this.unrelatedGroup,
      }),
    );
    requireCase(
      ownedGroup.Group?.Description === this.plan.runId,
      "unrelated_group_ownership_mismatch",
    );
    for (const alias of ACTORS) {
      if (!(await this.user(alias, true))) {
        await this.cognito.send(
          new AdminCreateUserCommand({
            ...this.input(alias),
            MessageAction: "SUPPRESS",
            UserAttributes: [
              {
                Name: "preferred_username",
                Value: `${this.plan.runId}:${alias}`,
              },
            ],
          }),
        );
        await this.user(alias);
      }
      await this.cognito.send(
        new AdminSetUserPasswordCommand({
          ...this.input(alias),
          Password: this.identity(alias).password,
          Permanent: true,
        }),
      );
      for (const group of await this.groups(alias))
        requireCase(
          [
            this.unrelatedGroup,
            ...this.desired.namespaces.map((n) => n.cognito_group),
          ].includes(group),
          "unexpected_fixture_group",
        );
      if (alias !== "none")
        await this.changeGroup(
          alias,
          alias === "other" || alias === "viewer" ? 1 : 0,
          true,
        );
      if (alias === "multi") await this.changeGroup(alias, 1, true);
      if (["writer", "none", "mover"].includes(alias))
        await this.changeGroup(alias, "unrelated", true);
      const status = await this.access(alias, "show-user");
      requireCase(
        status.principal_status === "absent",
        "fresh_fixture_already_enrolled",
      );
    }
    this.report("owned_synthetic_users_ready_without_jit");
  }
  async assertInitialJit() {
    for (const alias of [
      "writer",
      "peer",
      "other",
      "mover",
      "revoked",
      "emergency",
      "concurrent",
    ]) {
      const status = await this.access(alias, "show-user");
      requireCase(
        status.principal_status === "active" && status.active_memberships === 1,
        "jit_not_single_membership",
      );
    }
    for (const alias of ["none", "multi"])
      requireCase(
        (await this.access(alias, "show-user")).principal_status === "absent",
        "denied_identity_created_principal",
      );
    this.report("jit_single_membership_and_denial_order");
  }
  async failedMove() {
    let failed = false;
    try {
      await this.access("mover", "move-user", {
        target: 1,
        fault: "target_grant",
      });
    } catch (error) {
      failed = error.message === "injected_target_grant";
    }
    requireCase(
      failed &&
        (await this.access("mover", "show-user")).active_memberships === 0,
      "failed_move_not_closed",
    );
    this.report("failed_move_tombstone");
  }
  async faultMatrix() {
    for (const fault of MOVE_FAULTS) {
      await this.access("mover", "move-user", { target: 0 });
      let failed = false;
      try {
        await this.access("mover", "move-user", { target: 1, fault });
      } catch (error) {
        failed = error.message === `injected_${fault}`;
      }
      requireCase(failed, "fault_not_reached");
      const status = await this.access("mover", "show-user");
      requireCase(
        status.active_memberships === (fault === "grant_commit" ? 1 : 0),
        "fault_not_fail_closed",
      );
      await this.access("mover", "move-user", { target: 1 });
      await this.assertPlacement("mover", 1);
      await this.access("mover", "move-user", { target: 0 });
      await this.assertPlacement("mover", 0);
      requireCase(
        (await this.groups("mover")).includes(this.unrelatedGroup),
        "move_removed_unrelated_group",
      );
      this.report(`move_retry_${fault}`);
    }
  }
  async concurrentMoves() {
    await this.user("mover");
    const key = deriveHumanPrincipalKey(
      this.issuer,
      this.subjects.get("mover"),
    );
    const connections = [];
    try {
      for (let i = 0; i < 3; i++) connections.push(await this.connect());
      const [barrier, left, right] = connections;
      await barrier.query("SELECT pg_advisory_lock(hashtext($1))", [key]);
      const pending = Promise.allSettled([
        this.access("mover", "move-user", { target: 0, db: left }),
        this.access("mover", "move-user", { target: 1, db: right }),
      ]);
      let waiting = false;
      try {
        for (let i = 0; i < 200; i++) {
          this.signal?.throwIfAborted();
          const result = await barrier.query(
            "SELECT count(*)::int AS waiting FROM pg_locks WHERE pid=ANY($1::int[]) AND locktype='advisory' AND NOT granted",
            [[left.processID, right.processID]],
          );
          if (result.rows[0].waiting === 2) {
            waiting = true;
            break;
          }
          await delay(25);
        }
      } finally {
        await barrier.query("SELECT pg_advisory_unlock(hashtext($1))", [key]);
      }
      const results = await pending;
      requireCase(
        waiting && results.every((x) => x.status === "fulfilled"),
        "concurrent_commands_did_not_serialize",
      );
      const rows = (await this.placement("mover")).filter(
        (x) => x.status === "active",
      );
      requireCase(rows.length === 1, "concurrent_active_memberships");
      await this.assertPlacement(
        "mover",
        this.desired.namespaces.findIndex((n) => n.slug === rows[0].slug),
      );
      await this.access("mover", "move-user", { target: 0 });
      this.report("observed_concurrent_command_serialization");
    } finally {
      await Promise.all(connections.map((db) => db.end()));
    }
  }
  async ids(db, alias, target = 0) {
    await this.user(alias);
    return this.idsForSubject(db, this.subjects.get(alias), target);
  }
  async idsForSubject(db, subject, target = 0) {
    const key = deriveHumanPrincipalKey(this.issuer, subject);
    const result = await db.query(
      `SELECT n.namespace_id,p.principal_id
      FROM memory_namespaces n CROSS JOIN memory_principals p
      WHERE n.slug=$1 AND p.principal_key=$2 AND p.principal_type='human'`,
      [this.desired.namespaces[target].slug, key],
    );
    requireCase(result.rowCount === 1, "fixture_identity_not_enrolled");
    return result.rows[0];
  }
  async observeJobScope(alias, jobId) {
    await this.withDb(async (db) => {
      const ids = await this.ids(db, alias);
      const result = await db.query(
        `SELECT tenant_id,app_id FROM ingest_jobs
        WHERE job_id=$1 AND namespace_id=$2 AND principal_id=$3`,
        [jobId, ids.namespace_id, ids.principal_id],
      );
      requireCase(result.rowCount === 1, "owned_probe_job_missing");
      this.jobScope = result.rows[0];
    });
  }
  async blockSession(alias, sessionId) {
    requireCase(
      this.jobScope && !this.guards.has(alias),
      "job_scope_not_ready",
    );
    const guard = { id: this.guardId(alias), sessionId };
    await this.withDb(async (db) => {
      Object.assign(guard, await this.ids(db, alias));
      const payload = Buffer.from(
        JSON.stringify({
          version: "ingest-v1",
          tenant_id: this.jobScope.tenant_id,
          namespace_id: guard.namespace_id,
          principal_id: guard.principal_id,
          messages: [],
        }),
      );
      // A leased, content-free FIFO predecessor holds only this synthetic
      // session. If an interrupted test leaves it behind, its invalid empty
      // transcript fails planning after lease expiry; it cannot write memory.
      await db.query(
        `INSERT INTO ingest_jobs(job_id,tenant_id,namespace_id,principal_id,
        idempotency_key,canonical_payload,agent_id,app_id,session_id,state,attempt_count,
        lease_owner,lease_expires_at,created_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'processing',1,$10,
          statement_timestamp()+interval '10 minutes',statement_timestamp()-interval '1 minute')`,
        [
          guard.id,
          this.jobScope.tenant_id,
          guard.namespace_id,
          guard.principal_id,
          createHash("sha256").update(guard.id).digest("hex"),
          payload,
          this.agentId,
          this.jobScope.app_id,
          sessionId,
          `fixture-${this.plan.runId}`,
        ],
      );
    });
    this.guards.set(alias, guard);
  }
  guardId(alias) {
    this.identity(alias);
    const hash = createHash("sha256")
      .update(`${this.plan.runId}\0${alias}\0fifo`)
      .digest("hex");
    return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-4${hash.slice(13, 16)}-8${hash.slice(17, 20)}-${hash.slice(20, 32)}`;
  }
  async releaseSession(alias) {
    const guard = this.guards.get(alias);
    if (!guard) return;
    await this.withDb((db) =>
      db.query(
        `DELETE FROM ingest_jobs
      WHERE job_id=$1 AND namespace_id=$2 AND principal_id=$3`,
        [guard.id, guard.namespace_id, guard.principal_id],
      ),
    );
    this.guards.delete(alias);
  }
  async jobState(alias, jobId) {
    return this.withDb(async (db) => {
      const ids = await this.ids(db, alias);
      const result = await db.query(
        `SELECT state FROM ingest_jobs
        WHERE job_id=$1 AND namespace_id=$2 AND principal_id=$3`,
        [jobId, ids.namespace_id, ids.principal_id],
      );
      requireCase(result.rowCount === 1, "owned_job_missing");
      return result.rows[0].state;
    });
  }
  async cleanup() {
    const failures = [];
    for (const alias of ACTORS) {
      try {
        const existing = await this.user(alias, true);
        if (existing) {
          await this.access(alias, "emergency");
          await this.cognito.send(
            new AdminDeleteUserCommand(this.input(alias)),
          );
        } else if (this.identity(alias).subject) {
          // The provider user can already be gone after an interrupted cleanup.
          // Its captured immutable subject still permits DB-side cancellation.
          await this.withDb((db) =>
            manageAccess({
              command: "revoke-user",
              emergency: true,
              authMode: "oidc",
              externalIdentity: {
                issuer: this.issuer,
                sub: this.identity(alias).subject,
              },
              issuer: this.issuer,
              desired: this.desired,
              db,
            }),
          );
        }
        const subject = this.identity(alias).subject;
        if (subject)
          await this.withDb(async (db) => {
            const ids = await this.idsForSubject(db, subject);
            await db.query(
              `DELETE FROM ingest_jobs
            WHERE job_id=$1 AND namespace_id=$2 AND principal_id=$3 AND agent_id=$4`,
              [
                this.guardId(alias),
                ids.namespace_id,
                ids.principal_id,
                this.agentId,
              ],
            );
          });
        this.guards.delete(alias);
      } catch {
        failures.push(alias);
      }
    }
    try {
      const group = await this.cognito.send(
        new GetGroupCommand({
          UserPoolId: this.manifest.userPoolId,
          GroupName: this.unrelatedGroup,
        }),
      );
      requireCase(
        group.Group?.Description === this.plan.runId,
        "unrelated_group_ownership_mismatch",
      );
      await this.cognito.send(
        new DeleteGroupCommand({
          UserPoolId: this.manifest.userPoolId,
          GroupName: this.unrelatedGroup,
        }),
      );
    } catch (error) {
      if (error.name !== "ResourceNotFoundException")
        failures.push("unrelated");
    }
    requireCase(failures.length === 0, "fixture_cleanup_incomplete");
    this.report("owned_fixture_cleanup_complete");
  }
}
