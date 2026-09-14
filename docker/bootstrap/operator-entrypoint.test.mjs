import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
const spawned = vi.hoisted(() => vi.fn());
vi.mock("node:child_process", () => ({ spawn: spawned }));
import { main } from "./operator-entrypoint.mjs";
beforeEach(() => {
  spawned.mockReset();
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
    "fails closed for provider-owned %s",
    async (operation) => {
      vi.stubEnv("MEM9_BOOTSTRAP_OPERATION", operation);
      await expect(main()).rejects.toThrow(
        "Manage external users at the identity provider",
      );
      expect(spawned).not.toHaveBeenCalled();
    },
  );
});
