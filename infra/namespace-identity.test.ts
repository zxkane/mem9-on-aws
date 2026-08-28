import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

function out<T>(value: T): {
  value: T;
  apply: (fn: (value: T) => unknown) => unknown;
} {
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
let passwords: Record<string, unknown>[];

beforeEach(() => {
  secrets = [];
  versions = [];
  passwords = [];
  (globalThis as Record<string, unknown>).$app = {
    name: "mem9-on-aws",
    stage: "prod",
  };
  (globalThis as Record<string, unknown>).aws = {
    secretsmanager: {
      Secret: class {
        id = out("secret-id");
        arn = out("arn:secret");
        constructor(_name: string, args: Record<string, unknown>) {
          secrets.push(args);
        }
      },
      SecretVersion: class {
        arn = out("arn:secret:version");
        constructor(_name: string, args: Record<string, unknown>) {
          versions.push(args);
        }
      },
    },
  };
  (globalThis as Record<string, unknown>).random = {
    RandomPassword: class {
      result = out(Buffer.alloc(48, 8).toString("base64url"));
      constructor(_name: string, args: Record<string, unknown>) {
        passwords.push(args);
      }
    },
  };
});

afterEach(() => {
  for (const key of ["$app", "aws", "random"]) {
    delete (globalThis as Record<string, unknown>)[key];
  }
  vi.resetModules();
});

describe("namespace signing identity", () => {
  it("creates separate stable identity and transport secrets", async () => {
    const { namespaceIdentity } = await import("./namespace-identity");
    const outputs = namespaceIdentity();
    expect(secrets).toHaveLength(2);
    expect(versions).toHaveLength(2);
    expect(passwords).toEqual([
      { length: 64, special: false },
      { length: 64, special: false },
    ]);
    expect(outputs.identitySigningKeys).toBeDefined();
    expect(outputs.transportSigningKeys).toBeDefined();
    expect(outputs.transportSigningSecretArn).toBeDefined();
  });
});
