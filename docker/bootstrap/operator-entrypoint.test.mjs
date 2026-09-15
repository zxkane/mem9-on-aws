import { EventEmitter } from "node:events";
import { existsSync, readFileSync, statSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
const spawned = vi.hoisted(() => vi.fn());
const ssmSend = vi.hoisted(() => vi.fn());
vi.mock("node:child_process", () => ({ spawn: spawned }));
vi.mock("@aws-sdk/client-ssm", async (original) => ({
  ...(await original()),
  SSMClient: class {
    send = ssmSend;
    destroy() {}
  },
}));
import { main } from "./operator-entrypoint.mjs";
beforeEach(() => {
  spawned.mockReset();
  ssmSend.mockReset();
  spawned.mockImplementation(() => {
    const child = new EventEmitter();
    child.kill = vi.fn();
    queueMicrotask(() => child.emit("exit", 0, null));
    return child;
  });
  for (const [name, value] of Object.entries({
    MEM9_DB_SECRET: '{"username":"test","password":"fixture"}',
    MEM9_DB_HOST: "db.example.com",
    MEM9_DB_PORT: "5432",
    MEM9_DB_NAME: "mem9",
    MEM9_STAGE: "test",
    MEM9_COGNITO_ISSUER: "https://id.example.com",
    MEM9_COGNITO_USER_POOL_ID: "",
    MEM9_AUTH_MODE: "oidc",
    MEM9_EXPECTED_NAMESPACE_PHASE: "constraints_complete",
    MEM9_NAMESPACE_CONFIG_PARAMETER: "",
    MEM9_NAMESPACE_USERNAME_PARAMETER: "",
    MEM9_NAMESPACE_IDENTITY_PARAMETER: "",
    AWS_REGION: "ap-northeast-1",
  }))
    vi.stubEnv(name, value);
});
afterEach(() => vi.unstubAllEnvs());
describe("namespace operator with an external identity provider", () => {
  it.each(["assert-phase", "preflight", "freeze", "enforce"])(
    "runs database-only %s without a Cognito pool",
    async (operation) => {
      vi.stubEnv("MEM9_BOOTSTRAP_OPERATION", operation);
      await main();
      expect(spawned.mock.calls[0][1][1]).toBe(operation);
      expect(spawned.mock.calls[0][2].env.MEM9_COGNITO_USER_POOL_ID).toBe("");
    },
  );
  it.each(["assign-user", "move-user", "revoke-user", "show-user"])(
    "TC-GROUPNS-143: requires explicit external identity for %s",
    async (operation) => {
      vi.stubEnv("MEM9_BOOTSTRAP_OPERATION", operation);
      await expect(main()).rejects.toThrow(
        "identity input does not match authentication mode",
      );
      expect(spawned).not.toHaveBeenCalled();
      expect(ssmSend).not.toHaveBeenCalled();
    },
  );

  it.each(["assign-user", "move-user", "revoke-user", "show-user"])(
    "TC-GROUPNS-143: sends %s an owner-only identity file and removes it afterwards",
    async (operation) => {
      vi.stubEnv("MEM9_BOOTSTRAP_OPERATION", operation);
      vi.stubEnv("MEM9_NAMESPACE_CONFIG_PARAMETER", "/inputs/config");
      vi.stubEnv("MEM9_NAMESPACE_IDENTITY_PARAMETER", "/inputs/identity");
      const identity = JSON.stringify({
        issuer: "https://id.example.com",
        sub: "private-subject",
      });
      ssmSend.mockImplementation(async (command) => ({
        Parameters: command.input.Names.map((Name) => ({
          Name,
          Value: Name.endsWith("identity") ? identity : '{"namespaces":[]}',
        })),
      }));
      let privateFile;
      const spawnDefault = spawned.getMockImplementation();
      spawned.mockImplementation((executable, args, options) => {
        privateFile = args[args.indexOf("--identity-file") + 1];
        expect(readFileSync(privateFile, "utf8")).toBe(identity);
        expect(statSync(privateFile).mode & 0o777).toBe(0o600);
        expect(JSON.stringify(args)).not.toContain("private-subject");
        expect(args).not.toContain("--username-file");
        expect(options.env.MEM9_COGNITO_USER_POOL_ID).toBe("");
        return spawnDefault(executable, args, options);
      });
      await main();
      expect(existsSync(privateFile)).toBe(false);
      expect(ssmSend.mock.calls[0][0].input.WithDecryption).toBe(true);
    },
  );

  it.each(["managed", "oidc"])(
    "rejects %s mixed identity inputs before SSM",
    async (mode) => {
      vi.stubEnv("MEM9_AUTH_MODE", mode);
      vi.stubEnv("MEM9_BOOTSTRAP_OPERATION", "assign-user");
      vi.stubEnv("MEM9_NAMESPACE_USERNAME_PARAMETER", "/inputs/username");
      vi.stubEnv("MEM9_NAMESPACE_IDENTITY_PARAMETER", "/inputs/identity");
      await expect(main()).rejects.toThrow("identity input does not match");
      expect(ssmSend).not.toHaveBeenCalled();
      expect(spawned).not.toHaveBeenCalled();
    },
  );
});
