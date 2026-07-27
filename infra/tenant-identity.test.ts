import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

function out<T>(value: T): { value: T; apply: (fn: (v: T) => unknown) => unknown } {
  return {
    value,
    apply: (fn) => {
      const result = fn(value);
      return result && typeof result === "object" && "apply" in result
        ? result
        : out(result as never);
    },
  };
}

let secrets: Record<string, unknown>[];
let versions: Record<string, unknown>[];
let randomIds: Record<string, unknown>[];

function installGlobals(stage: string) {
  (globalThis as Record<string, unknown>).$app = { name: "mem9-on-aws", stage };
  (globalThis as Record<string, unknown>).aws = {
    secretsmanager: {
      Secret: class {
        id = out("secret-id");
        arn = out("arn:aws:secretsmanager:x:y:secret:tenant");
        constructor(_name: string, args: Record<string, unknown>) {
          secrets.push(args);
        }
      },
      SecretVersion: class {
        arn = out("arn:aws:secretsmanager:x:y:secret:tenant:version");
        constructor(_name: string, args: Record<string, unknown>) {
          versions.push(args);
        }
      },
    },
  };
  (globalThis as Record<string, unknown>).random = {
    RandomId: class {
      hex = out("0123456789abcdef0123456789abcdef");
      constructor(_name: string, args: Record<string, unknown>) {
        randomIds.push(args);
      }
    },
  };
}

beforeEach(() => {
  secrets = [];
  versions = [];
  randomIds = [];
});

afterEach(() => {
  for (const key of ["$app", "aws", "random"]) {
    delete (globalThis as Record<string, unknown>)[key];
  }
  vi.resetModules();
});

describe("tenant identity", () => {
  it("creates one stable secret value and exports shared outputs", async () => {
    installGlobals("prod");
    const { tenantIdentity } = await import("./tenant-identity");
    const outputs = tenantIdentity();
    expect(secrets).toHaveLength(1);
    expect(versions).toHaveLength(1);
    expect(randomIds).toEqual([{ byteLength: 16 }]);
    expect(secrets[0].recoveryWindowInDays).toBe(7);
    expect(outputs.tenantSecretArn).toBeDefined();
    expect(outputs.tenantId).toBeDefined();
  });

  it("allows clean non-production teardown", async () => {
    installGlobals("pr-9");
    const { tenantIdentity } = await import("./tenant-identity");
    tenantIdentity();
    expect(secrets[0].recoveryWindowInDays).toBe(0);
  });
});
