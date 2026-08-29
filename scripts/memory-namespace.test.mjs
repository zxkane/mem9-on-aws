import { spawnSync } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  deriveClientKey,
  deriveGroupKey,
  deriveHumanPrincipalKey,
  deriveM2MPrincipalKey,
  readDesiredState,
  validateDesiredState,
} from "./lib/memory-namespace.mjs";
import { manageAccess } from "./manage-memory-access.mjs";
import { assertMigrationPhase } from "./migrate-memory-namespaces.mjs";
import {
  preparePreviewMemoryNamespaces,
  previewNamespaceDesiredState,
} from "./prepare-preview-memory-namespaces.mjs";
import { reconcileNamespaces } from "./reconcile-memory-namespaces.mjs";

function desired() {
  return {
    namespaces: [
      {
        slug: "team-a",
        display_name: "Team A",
        cognito_group: "mem9-team-a",
        default_role: "member",
        jit_enabled: true,
        status: "active",
      },
    ],
    m2m_bindings: [],
  };
}

async function runNamespaceE2EFixture(failure = "") {
  const directory = await mkdtemp(join(tmpdir(), "mem9-namespace-e2e-"));
  const bin = join(directory, "bin");
  const curlLog = join(directory, "curl-argv.jsonl");
  await mkdir(bin);
  await writeFile(
    join(bin, "aws"),
    `#!/usr/bin/env node
const args = process.argv.slice(2);
const name = args[args.indexOf("--name") + 1];
const values = {
  "/mem9-on-aws/pr-42/cognito/token-endpoint": "https://token.example",
  "/mem9-on-aws/pr-42/cognito/scope": "mem9-mcp/read mem9-mcp/write",
  "/mem9-on-aws/pr-42/gateway/url": "https://gateway.example/mcp",
  "/mem9-on-aws/pr-42/cognito/client-id": "default-client",
  "/mem9-on-aws/pr-42/cognito/client-secret": "default-secret",
  "/mem9-on-aws/pr-42/cognito/namespace-e2e-alpha/client-id": "alpha-client",
  "/mem9-on-aws/pr-42/cognito/namespace-e2e-alpha/client-secret": "alpha-secret",
  "/mem9-on-aws/pr-42/cognito/namespace-e2e-beta/client-id": "beta-client",
  "/mem9-on-aws/pr-42/cognito/namespace-e2e-beta/client-secret": "beta-secret"
};
if (!(name in values)) process.exit(2);
process.stdout.write(values[name] + "\\n");
`,
    { mode: 0o755 },
  );
  await writeFile(
    join(bin, "curl"),
    `#!/usr/bin/env node
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";

const args = process.argv.slice(2);
appendFileSync(process.env.MCP_CURL_LOG, JSON.stringify(args) + "\\n");
const option = (name) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
const config = readFileSync(option("--config"), "utf8");
if (args.includes("https://token.example")) {
  const token = config.includes("alpha-client")
    ? "fixture.alpha.token"
    : config.includes("beta-client")
      ? "fixture.beta.token"
      : "fixture.default.token";
  process.stdout.write(JSON.stringify({ access_token: token }));
  process.exit(0);
}

const auth = config.includes("fixture.alpha.token")
  ? "alpha"
  : config.includes("fixture.beta.token")
    ? "beta"
    : "default";
const request = JSON.parse(option("-d"));
const headers = option("-D");
const output = option("-o");
let status = "200";
let body;
if (request.method === "initialize") {
  body = { jsonrpc: "2.0", id: 1, result: { protocolVersion: "2025-03-26" } };
} else if (request.method === "tools/list") {
  body = {
    jsonrpc: "2.0",
    id: 1,
    result: {
      tools: [
        {
          name: "fixture___add_memory",
          inputSchema: {
            type: "object",
            properties: {
              memory_type: {
                type: "string",
                description:
                  "Optional explicit memory type. Only pinned is supported."
              }
            }
          }
        },
        {
          name: "fixture___search_memories",
          inputSchema: {
            type: "object",
            properties: {
              search_mode: {
                type: "string",
                description:
                  "Optional search mode. Defaults to semantic; keyword performs exact substring matching."
              }
            }
          }
        }
      ]
    }
  };
} else {
  const tool = request.params.name;
  const input = request.params.arguments;
  if (tool.endsWith("add_memory")) {
    if (input.memory_type !== "pinned") {
      process.exit(3);
    }
    if (
      auth === "alpha" &&
      (input.namespace_id !== "forged-beta-namespace" ||
        input.namespace_slug !== "preview-beta")
    ) {
      process.exit(3);
    }
    body = {
      jsonrpc: "2.0",
      id: 1,
      result: { content: [{ text: JSON.stringify({ status: "accepted" }) }] }
    };
  } else {
    if (input.search_mode !== "keyword") {
      process.exit(3);
    }
    const ownPrefix = auth === "beta" ? "namespace-beta" : "namespace-alpha";
    const ownID = auth === "beta" ? "memory-beta-id" : "memory-alpha-id";
    const foreign = !input.q.includes(ownPrefix);
    if (foreign && process.env.MCP_FAKE_FAILURE === "cross-http") {
      status = "500";
      body = { error: "simulated" };
    } else if (foreign && process.env.MCP_FAKE_FAILURE === "cross-json") {
      body = {
        jsonrpc: "2.0",
        id: 1,
        error: { code: -32000, message: "simulated" }
      };
    } else {
      const memories = foreign
        ? []
        : [{
            id: ownID,
            content: "PR namespace isolation marker " + input.q
          }];
      body = {
        jsonrpc: "2.0",
        id: 1,
        result: {
          content: [{
            text: JSON.stringify({
              limit: input.limit,
              offset: 0,
              total: memories.length,
              memories
            })
          }]
        }
      };
    }
  }
}
writeFileSync(headers, "mcp-session-id: fixture-" + auth + "\\r\\n");
writeFileSync(output, JSON.stringify(body));
process.stdout.write(status);
`,
    { mode: 0o755 },
  );

  try {
    const result = spawnSync(
      "bash",
      [resolve(import.meta.dirname, "run-memory-namespace-e2e.sh")],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: `${bin}${delimiter}${process.env.PATH}`,
          AWS_REGION: "ap-northeast-1",
          STAGE: "pr-42",
          GITHUB_RUN_ID: "123",
          GITHUB_RUN_ATTEMPT: "1",
          MCP_CURL_LOG: curlLog,
          MCP_FAKE_FAILURE: failure,
        },
      },
    );
    return {
      result,
      curlArgv: await readFile(curlLog, "utf8"),
    };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe("memory namespace operator config", () => {
  it("TC-GROUPNS-021/023/024: derives domain-separated exact keys", () => {
    expect(deriveHumanPrincipalKey("issuer-a", "subject")).not.toBe(
      deriveHumanPrincipalKey("issuer-b", "subject"),
    );
    expect(deriveGroupKey("issuer-a", "Team")).not.toBe(
      deriveGroupKey("issuer-a", "team"),
    );
    expect(deriveGroupKey("issuer-a", "Team")).toMatch(/^[0-9a-f]{64}$/u);
  });

  it("TC-GROUPNS-049/050: rejects duplicates and secret-shaped fields", () => {
    const duplicate = desired();
    duplicate.namespaces.push({ ...duplicate.namespaces[0] });
    expect(() => validateDesiredState(duplicate)).toThrow(/duplicate/u);
    expect(() =>
      validateDesiredState({
        ...desired(),
        api_token: "forbidden",
      }),
    ).toThrow(/not allowed/u);
  });

  it("requires an owner-only desired-state file", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mem9-namespace-"));
    const path = join(directory, "config.json");
    await writeFile(path, JSON.stringify(desired()), { mode: 0o644 });
    await expect(readDesiredState(path)).rejects.toThrow(/owner-only/u);
    await chmod(path, 0o600);
    await expect(readDesiredState(path)).resolves.toEqual(desired());
  });

  it("ships a valid public desired-state example", async () => {
    const example = JSON.parse(
      await readFile(
        resolve(import.meta.dirname, "memory-namespaces.example.json"),
        "utf8",
      ),
    );
    expect(validateDesiredState(example)).toEqual(example);
  });

  it("builds two isolated PR namespaces and binds the default client to alpha", () => {
    const issuer = "https://cognito-idp.example.com/pool";
    const state = previewNamespaceDesiredState({
      issuer,
      defaultClientId: "default-client",
      alpha: {
        clientId: "alpha-client",
        slug: "preview-alpha",
        group: "memory-preview-alpha",
      },
      beta: {
        clientId: "beta-client",
        slug: "preview-beta",
        group: "memory-preview-beta",
      },
    });
    expect(state.namespaces.map(({ slug }) => slug)).toEqual([
      "preview-alpha",
      "preview-beta",
    ]);
    expect(state.m2m_bindings).toHaveLength(3);
    expect(
      state.m2m_bindings.filter(
        ({ namespace_slug }) => namespace_slug === "preview-alpha",
      ),
    ).toHaveLength(2);
    expect(
      state.m2m_bindings.filter(
        ({ namespace_slug }) => namespace_slug === "preview-beta",
      ),
    ).toHaveLength(1);
    expect(
      new Set(state.m2m_bindings.map(({ principal_key }) => principal_key))
        .size,
    ).toBe(3);
  });

  it("TC-GROUPNS-132: converges replaced PR fixture clients to the current A/B slots", async () => {
    const issuer = "https://cognito-idp.example.com/pool";
    const state = previewNamespaceDesiredState({
      issuer,
      defaultClientId: "default-client",
      alpha: {
        clientId: "alpha-client",
        slug: "preview-alpha",
        group: "memory-preview-alpha",
      },
      beta: {
        clientId: "beta-client",
        slug: "preview-beta",
        group: "memory-preview-beta",
      },
    });
    const namespaceIDs = new Map([
      ["preview-alpha", "namespace-alpha"],
      ["preview-beta", "namespace-beta"],
    ]);
    const principalIDs = new Map(
      state.m2m_bindings.map(({ principal_key }, index) => [
        principal_key,
        `principal-${index + 1}`,
      ]),
    );
    const queries = [];
    let cognitoCalls = 0;
    const cognito = {
      async send(command) {
        cognitoCalls += 1;
        throw new Error(
          `preview bootstrap must not call Cognito: ${command.constructor.name}`,
        );
      },
    };
    const db = {
      async query(sql, values = []) {
        const text = String(sql);
        queries.push({ text, values });
        if (text.includes("INSERT INTO memory_namespaces")) {
          return {
            rowCount: 1,
            rows: [{ namespace_id: namespaceIDs.get(values[1]) }],
          };
        }
        if (text.includes("INSERT INTO memory_principals")) {
          return {
            rowCount: 1,
            rows: [{ principal_id: principalIDs.get(values[1]) }],
          };
        }
        if (
          text.includes("FROM memory_m2m_namespace_bindings") &&
          text.includes("WHERE client_key = $1")
        ) {
          return { rowCount: 0, rows: [] };
        }
        if (text.includes("NOT (binding.client_key = ANY")) {
          return {
            rowCount: 2,
            rows: [
              {
                client_key: "a".repeat(64),
                principal_id: "principal-stale-alpha",
              },
              {
                client_key: "b".repeat(64),
                principal_id: "principal-stale-beta",
              },
            ],
          };
        }
        if (text.includes("SELECT slug, display_name, status")) {
          return {
            rows: state.namespaces.map(
              ({ slug, display_name, status }) => ({
                slug,
                display_name,
                status,
              }),
            ),
          };
        }
        if (text.includes("binding.group_key")) {
          return {
            rows: state.namespaces.map(
              ({
                slug,
                cognito_group,
                default_role,
                jit_enabled,
                status,
              }) => ({
                group_key: deriveGroupKey(issuer, cognito_group),
                namespace_slug: slug,
                default_role,
                jit_enabled,
                status,
              }),
            ),
          };
        }
        if (
          text.includes("binding.client_key") &&
          text.includes("principal.principal_key")
        ) {
          return {
            rows: state.m2m_bindings.map(
              ({
                client_key,
                principal_key,
                namespace_slug,
                role,
                status,
              }) => ({
                client_key,
                principal_key,
                namespace_slug,
                role,
                status,
                principal_status: status,
                membership_role: role,
                membership_status:
                  status === "active" ? "active" : "revoked",
              }),
            ),
          };
        }
        if (text.includes("FROM memory_namespace_migration_state")) {
          return {
            rowCount: 1,
            rows: [{ phase: "constraints_complete" }],
          };
        }
        return { rowCount: 1, rows: [] };
      },
    };

    const result = await preparePreviewMemoryNamespaces({
      db,
      cognito,
      issuer,
      userPoolId: "pool",
      stage: "pr-42",
      desired: state,
      migrationPath: "/unused.sql",
    });

    expect(cognitoCalls).toBe(0);
    const staleLock = queries.find(({ text }) =>
      text.includes("NOT (binding.client_key = ANY"),
    );
    expect(staleLock.values[0]).toEqual([
      "namespace-alpha",
      "namespace-beta",
    ]);
    expect(staleLock.values[1].toSorted()).toEqual(
      [
        deriveClientKey(issuer, "default-client"),
        deriveClientKey(issuer, "alpha-client"),
        deriveClientKey(issuer, "beta-client"),
      ].toSorted(),
    );
    for (const fragment of [
      "UPDATE memory_namespace_memberships",
      "UPDATE memory_principals",
      "DELETE FROM memory_m2m_namespace_bindings",
    ]) {
      const query = queries.find(
        ({ text }) =>
          text.includes(fragment) &&
          text.includes("ANY($1::varchar[])"),
      );
      expect(query.values[0]).toEqual(
        fragment.startsWith("DELETE")
          ? ["a".repeat(64), "b".repeat(64)]
          : ["principal-stale-alpha", "principal-stale-beta"],
      );
    }
    expect(result.reconciliation.drift.total).toBe(0);
    expect(
      new Set(
        state.m2m_bindings.map(({ principal_key }) => principal_key),
      ),
    ).toEqual(
      new Set([
        deriveM2MPrincipalKey(issuer, "default-client"),
        deriveM2MPrincipalKey(issuer, "alpha-client"),
        deriveM2MPrincipalKey(issuer, "beta-client"),
      ]),
    );
  });

  it("runs the live namespace gate without putting secrets or bearers in curl argv", async () => {
    const { result, curlArgv } = await runNamespaceE2EFixture();
    const curlCalls = curlArgv
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    const headers = curlCalls.flatMap((args) =>
      args.flatMap((arg, index) => (args[index - 1] === "-H" ? [arg] : [])),
    );
    expect(result.status).toBe(0);
    expect(result.stdout).toContain(
      "shared memory ID matched; cross-namespace keyword results absent",
    );
    expect(curlArgv).toContain('\\"search_mode\\":\\"keyword\\"');
    expect(curlArgv).toContain('\\"memory_type\\":\\"pinned\\"');
    expect(headers).toContain("Mcp-Session-Id: fixture-default");
    expect(headers).toContain("Mcp-Session-Id: fixture-alpha");
    expect(headers).toContain("Mcp-Session-Id: fixture-beta");
    expect(curlArgv).not.toContain("default-secret");
    expect(curlArgv).not.toContain("alpha-secret");
    expect(curlArgv).not.toContain("beta-secret");
    expect(curlArgv).not.toContain("fixture.default.token");
    expect(curlArgv).not.toContain("fixture.alpha.token");
    expect(curlArgv).not.toContain("fixture.beta.token");
  });

  it.each(["cross-http", "cross-json"])(
    "fails closed when a foreign-marker query returns %s",
    async (failure) => {
      const { result } = await runNamespaceE2EFixture(failure);
      expect(result.status).not.toBe(0);
    },
  );

  it("prints operator help without configuration, AWS, or database access", () => {
    const env = {
      HOME: process.env.HOME,
      PATH: process.env.PATH,
    };
    const commands = [
      [
        process.execPath,
        [resolve(import.meta.dirname, "manage-memory-access.mjs"), "--help"],
      ],
      [
        process.execPath,
        [
          resolve(import.meta.dirname, "migrate-memory-namespaces.mjs"),
          "--help",
        ],
      ],
      [
        process.execPath,
        [
          resolve(import.meta.dirname, "reconcile-memory-namespaces.mjs"),
          "--help",
        ],
      ],
      [
        "bash",
        [
          resolve(import.meta.dirname, "run-memory-namespace-task.sh"),
          "--help",
        ],
      ],
      [
        "bash",
        [
          resolve(
            import.meta.dirname,
            "deploy-memory-namespace-operator-role.sh",
          ),
          "--help",
        ],
      ],
    ];

    for (const [command, args] of commands) {
      const result = spawnSync(command, args, {
        encoding: "utf8",
        env,
      });
      expect(result.status).toBe(0);
      expect(result.stdout).toContain("usage:");
      expect(result.stderr).toBe("");
    }
  });

  it("rejects partial SSM parameter deletion responses", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mem9-namespace-delete-"));
    const response = join(directory, "response.json");
    const verifier = resolve(
      import.meta.dirname,
      "lib/memory-namespace-operator.sh",
    );
    const verify = () =>
      spawnSync(
        "bash",
        [
          "-c",
          'source "$1"; verify_ssm_delete_response "$2" "$3" "$4"',
          "verify-delete",
          verifier,
          response,
          "/namespace/config",
          "/namespace/username",
        ],
        { encoding: "utf8" },
      );

    try {
      await writeFile(
        response,
        JSON.stringify({
          DeletedParameters: ["/namespace/username", "/namespace/config"],
          InvalidParameters: [],
        }),
      );
      expect(verify().status).toBe(0);

      await writeFile(
        response,
        JSON.stringify({
          DeletedParameters: ["/namespace/config"],
          InvalidParameters: ["/namespace/username"],
        }),
      );
      expect(verify().status).not.toBe(0);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("keeps the retained operator role out of PR preview stages", () => {
    const env = {
      HOME: process.env.HOME,
      PATH: process.env.PATH,
      AWS_REGION: "ap-northeast-1",
    };
    const runResult = spawnSync(
      "bash",
      [
        resolve(import.meta.dirname, "run-memory-namespace-task.sh"),
        "preflight",
      ],
      {
        encoding: "utf8",
        env: { ...env, STAGE: "pr-42" },
      },
    );
    expect(runResult.status).toBe(2);
    expect(runResult.stderr).toContain("supports only prod or dev");

    const deployResult = spawnSync(
      "bash",
      [
        resolve(
          import.meta.dirname,
          "deploy-memory-namespace-operator-role.sh",
        ),
      ],
      {
        encoding: "utf8",
        env: { ...env, MEM9_NAMESPACE_OPERATOR_STAGE: "pr-42" },
      },
    );
    expect(deployResult.status).toBe(2);
    expect(deployResult.stderr).toContain("expected prod or dev");
  });

  it("reattaches or stops the single stage operator task safely", async () => {
    const runner = await readFile(
      resolve(import.meta.dirname, "run-memory-namespace-task.sh"),
      "utf8",
    );
    const containerRunner = await readFile(
      resolve(
        import.meta.dirname,
        "../docker/bootstrap/operator-entrypoint.mjs",
      ),
      "utf8",
    );
    expect(runner).toContain('--started-by "$STARTED_BY"');
    expect(runner).toContain("aws ecs list-tasks");
    expect(runner).not.toContain("--desired-status RUNNING");
    expect(runner).toContain('.lastStatus != "STOPPED"');
    expect(runner).toContain("MEM9_NAMESPACE_OPERATION_KEY");
    expect(runner).toContain("another namespace operator invocation is active");
    expect(runner).toContain("aws ecs stop-task");
    expect(runner).toContain("if ! stop_operator_task; then");
    expect(runner).toContain(
      "operator inputs retained because the task may still be running",
    );
    expect(runner).toContain(
      "error: failed to delete short-lived namespace operator inputs",
    );
    expect(runner).toContain("cleanup_status=1");
    expect(runner).toContain("trap 'exit 143' TERM");
    expect(runner.indexOf("if ! stop_operator_task; then")).toBeLessThan(
      runner.indexOf("aws ssm delete-parameters"),
    );
    expect(containerRunner).toContain("CHILD_STOP_TIMEOUT_MS = 25_000");
    expect(containerRunner).toContain("activeChild.kill(signal)");
    expect(containerRunner).toContain('activeChild?.kill("SIGKILL")');
  });
});

describe("memory namespace migration gates", () => {
  it("TC-GROUPNS-125: requires the exact database phase before cutover", async () => {
    const db = {
      async query() {
        return {
          rowCount: 1,
          rows: [
            { phase: "application_ready", checkpoint: "backfill_complete" },
          ],
        };
      },
    };

    await expect(
      assertMigrationPhase(db, "application_ready"),
    ).resolves.toEqual({ phase: "application_ready" });

    const mismatch = await assertMigrationPhase(
      db,
      "constraints_complete",
    ).catch((error) => error);
    expect(mismatch).toMatchObject({
      message:
        "namespace migration phase is application_ready; required constraints_complete",
      exitCode: 34,
    });
    await expect(assertMigrationPhase(db, "invalid")).rejects.toThrow(
      "expected namespace migration phase is invalid",
    );
  });
});

describe("memory namespace access state machines", () => {
  it("TC-GROUPNS-122: commits emergency database revocation before Cognito removal", async () => {
    const groups = new Set(["mem9-team-a"]);
    let databaseCommitted = false;
    let principalDisabled = false;
    let jobsCancelled = false;
    const cognito = {
      async send(command) {
        switch (command.constructor.name) {
          case "AdminGetUserCommand":
            return {
              UserAttributes: [{ Name: "sub", Value: "subject-a" }],
            };
          case "AdminListGroupsForUserCommand":
            return {
              Groups: [...groups].map((GroupName) => ({ GroupName })),
            };
          case "AdminRemoveUserFromGroupCommand":
            expect(databaseCommitted).toBe(true);
            expect(principalDisabled).toBe(true);
            expect(jobsCancelled).toBe(true);
            groups.delete(command.input.GroupName);
            return {};
          default:
            throw new Error(
              `unexpected Cognito command ${command.constructor.name}`,
            );
        }
      },
    };
    const db = {
      async query(sql) {
        const text = String(sql);
        if (text.includes("RETURNING principal_id, status")) {
          return {
            rowCount: 1,
            rows: [{ principal_id: "principal-a", status: "active" }],
          };
        }
        if (
          text.includes("UPDATE memory_principals") &&
          text.includes("status = 'disabled'")
        ) {
          principalDisabled = true;
        }
        if (
          text.includes("UPDATE ingest_jobs") &&
          text.includes("principal_emergency_revoked")
        ) {
          jobsCancelled = true;
        }
        if (text === "COMMIT") {
          databaseCommitted = true;
        }
        return { rowCount: 1, rows: [] };
      },
    };

    await expect(
      manageAccess({
        command: "revoke-user",
        emergency: true,
        namespaceSlug: undefined,
        username: "private-user",
        desired: desired(),
        issuer: "issuer-a",
        userPoolId: "pool-a",
        cognito,
        db,
      }),
    ).resolves.toEqual({ status: "emergency_revoked" });

    expect(groups).toEqual(new Set());
  });

  it("TC-GROUPNS-055: leaves a revoked tombstone when the final operator grant fails", async () => {
    const groups = new Set();
    const cognito = {
      async send(command) {
        switch (command.constructor.name) {
          case "AdminGetUserCommand":
            return {
              UserAttributes: [{ Name: "sub", Value: "subject-a" }],
            };
          case "AdminListGroupsForUserCommand":
            return {
              Groups: [...groups].map((GroupName) => ({ GroupName })),
            };
          case "AdminAddUserToGroupCommand":
            groups.add(command.input.GroupName);
            return {};
          case "AdminRemoveUserFromGroupCommand":
            groups.delete(command.input.GroupName);
            return {};
          default:
            throw new Error(
              `unexpected Cognito command ${command.constructor.name}`,
            );
        }
      },
    };
    let membershipStatus;
    let activeGrantAttempts = 0;
    const db = {
      async query(sql) {
        const text = String(sql);
        if (text.includes("RETURNING principal_id, status")) {
          return {
            rowCount: 1,
            rows: [{ principal_id: "principal-a", status: "active" }],
          };
        }
        if (
          text.includes("FROM memory_namespaces") &&
          text.includes("FOR UPDATE")
        ) {
          return {
            rowCount: 1,
            rows: [{ namespace_id: "namespace-a" }],
          };
        }
        if (
          text.includes("INSERT INTO memory_namespace_memberships") &&
          text.includes("'revoked'")
        ) {
          membershipStatus = "revoked";
          return { rowCount: 1, rows: [] };
        }
        if (
          text.includes("INSERT INTO memory_namespace_memberships") &&
          text.includes("'active'")
        ) {
          activeGrantAttempts += 1;
          throw new Error("simulated final grant failure");
        }
        return { rowCount: 1, rows: [] };
      },
    };

    await expect(
      manageAccess({
        command: "move-user",
        emergency: false,
        namespaceSlug: "team-a",
        username: "private-user",
        desired: desired(),
        issuer: "issuer-a",
        userPoolId: "pool-a",
        cognito,
        db,
      }),
    ).rejects.toThrow(/simulated final grant failure/u);

    expect(groups).toEqual(new Set(["mem9-team-a"]));
    expect(activeGrantAttempts).toBe(1);
    expect(membershipStatus).toBe("revoked");
  });

  it("TC-GROUPNS-119: M2M reconciliation revokes stale principal and namespace memberships", async () => {
    const queries = [];
    const cognito = {
      async send(command) {
        if (command.constructor.name === "ListGroupsCommand") {
          return {
            Groups: [
              {
                GroupName: "mem9-team-a",
                Description: "Managed team memory namespace",
              },
            ],
          };
        }
        throw new Error(
          `unexpected Cognito command ${command.constructor.name}`,
        );
      },
    };
    const db = {
      async query(sql, values = []) {
        const text = String(sql);
        queries.push({ text, values });
        if (text.includes("SELECT slug, display_name, status")) {
          return {
            rows: [
              {
                slug: "team-a",
                display_name: "Team A",
                status: "active",
              },
            ],
          };
        }
        if (text.includes("binding.group_key")) {
          return {
            rows: [
              {
                group_key: deriveGroupKey("issuer-a", "mem9-team-a"),
                namespace_slug: "team-a",
                default_role: "member",
                jit_enabled: true,
                status: "active",
              },
            ],
          };
        }
        if (text.includes("binding.client_key")) {
          return {
            rows: [
              {
                client_key: "a".repeat(64),
                principal_key: "b".repeat(64),
                namespace_slug: "team-a",
                role: "member",
                status: "active",
                principal_status: "active",
                membership_role: "member",
                membership_status: "active",
              },
            ],
          };
        }
        if (text.includes("RETURNING namespace_id")) {
          return {
            rowCount: 1,
            rows: [{ namespace_id: "namespace-a" }],
          };
        }
        if (text.includes("RETURNING principal_id")) {
          return {
            rowCount: 1,
            rows: [{ principal_id: "principal-new" }],
          };
        }
        if (
          text.includes("FROM memory_m2m_namespace_bindings") &&
          text.includes("FOR UPDATE")
        ) {
          return {
            rowCount: 1,
            rows: [{ principal_id: "principal-old" }],
          };
        }
        return { rowCount: 1, rows: [] };
      },
    };
    const state = desired();
    state.m2m_bindings.push({
      client_key: "a".repeat(64),
      principal_key: "b".repeat(64),
      namespace_slug: "team-a",
      role: "member",
      status: "active",
    });

    const result = await reconcileNamespaces({
      desired: validateDesiredState(state),
      issuer: "issuer-a",
      userPoolId: "pool-a",
      cognito,
      db,
    });

    expect(
      queries.some(
        ({ text, values }) =>
          text.includes("WHERE principal_id = $1 AND status = 'active'") &&
          values[0] === "principal-old",
      ),
    ).toBe(true);
    expect(
      queries.some(
        ({ text, values }) =>
          text.includes("AND namespace_id <> $2") &&
          values[0] === "principal-new" &&
          values[1] === "namespace-a",
      ),
    ).toBe(true);
    expect(result.drift.total).toBe(0);
  });

  it("TC-GROUPNS-052/110: reports omitted managed state without deleting it", async () => {
    const cognito = {
      async send(command) {
        if (command.constructor.name === "ListGroupsCommand") {
          return {
            Groups: [
              {
                GroupName: "mem9-team-a",
                Description: "Managed team memory namespace",
              },
              {
                GroupName: "mem9-old-team",
                Description: "Managed team memory namespace",
              },
            ],
          };
        }
        throw new Error(
          `unexpected Cognito command ${command.constructor.name}`,
        );
      },
    };
    const db = {
      async query(sql) {
        const text = String(sql);
        if (text.includes("RETURNING namespace_id")) {
          return { rowCount: 1, rows: [{ namespace_id: "namespace-a" }] };
        }
        if (text.includes("SELECT slug, display_name, status")) {
          return {
            rows: [
              {
                slug: "team-a",
                display_name: "Team A",
                status: "active",
              },
              {
                slug: "old-team",
                display_name: "Old Team",
                status: "disabled",
              },
            ],
          };
        }
        if (text.includes("binding.group_key")) {
          return {
            rows: [
              {
                group_key: deriveGroupKey("issuer-a", "mem9-team-a"),
                namespace_slug: "team-a",
                default_role: "member",
                jit_enabled: true,
                status: "active",
              },
              {
                group_key: "c".repeat(64),
                namespace_slug: "old-team",
                default_role: "member",
                jit_enabled: false,
                status: "disabled",
              },
            ],
          };
        }
        if (text.includes("binding.client_key")) return { rows: [] };
        return { rowCount: 1, rows: [] };
      },
    };

    const result = await reconcileNamespaces({
      desired: validateDesiredState(desired()),
      issuer: "issuer-a",
      userPoolId: "pool-a",
      cognito,
      db,
    });

    expect(result.drift).toMatchObject({
      cognito: { missing: 0, extra: 1 },
      namespaces: { missing: 0, mismatched: 0, extra: 1 },
      group_bindings: { missing: 0, mismatched: 0, extra: 1 },
      m2m_bindings: { missing: 0, mismatched: 0, extra: 0 },
      total: 3,
    });
  });
});
