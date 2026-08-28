import { createHash } from "node:crypto";
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
let passwords: {
  name: string;
  args: Record<string, unknown>;
}[];
let parameters: Record<string, unknown>[];

function materialize<T>(value: unknown): T {
  if (value && typeof value === "object" && "value" in value) {
    return (value as { value: T }).value;
  }
  return value as T;
}

function passwordValue(
  name: string,
  args: Record<string, unknown>,
): string {
  const keepers = args.keepers as
    | Record<string, string>
    | undefined;
  return createHash("sha384")
    .update(`${name}:${keepers?.revision ?? "stable"}`)
    .digest("base64url");
}

beforeEach(() => {
  for (const key of [
    "MEM9_TRANSPORT_SIGNING_ACTIVE_SLOT",
    "MEM9_TRANSPORT_SIGNING_SLOT_A_REVISION",
    "MEM9_TRANSPORT_SIGNING_SLOT_B_REVISION",
  ]) {
    delete process.env[key];
  }
  secrets = [];
  versions = [];
  passwords = [];
  parameters = [];
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
    ssm: {
      Parameter: class {
        arn = out("arn:ssm:parameter");
        constructor(_name: string, args: Record<string, unknown>) {
          parameters.push(args);
        }
      },
    },
  };
  (globalThis as Record<string, unknown>).random = {
    RandomPassword: class {
      result: ReturnType<typeof out<string>>;
      constructor(name: string, args: Record<string, unknown>) {
        passwords.push({ name, args });
        this.result = out(passwordValue(name, args));
      }
    },
  };
});

afterEach(() => {
  for (const key of [
    "MEM9_TRANSPORT_SIGNING_ACTIVE_SLOT",
    "MEM9_TRANSPORT_SIGNING_SLOT_A_REVISION",
    "MEM9_TRANSPORT_SIGNING_SLOT_B_REVISION",
  ]) {
    delete process.env[key];
  }
  for (const key of ["$app", "aws", "random"]) {
    delete (globalThis as Record<string, unknown>)[key];
  }
  vi.resetModules();
});

describe("namespace signing identity", () => {
  it("creates a stable identity secret and transport SecureString", async () => {
    const { namespaceIdentity } = await import("./namespace-identity");
    const outputs = namespaceIdentity();
    expect(secrets).toHaveLength(1);
    expect(versions).toHaveLength(1);
    expect(passwords).toEqual([
      {
        name: "Mem9IdentitySigningKeysValue",
        args: { length: 64, special: false },
      },
      {
        name: "Mem9TransportSigningKeySlotA",
        args: {
          length: 64,
          special: false,
          keepers: { revision: "v1" },
        },
      },
      {
        name: "Mem9TransportSigningKeySlotB",
        args: {
          length: 64,
          special: false,
          keepers: { revision: "v1" },
        },
      },
    ]);
    expect(parameters).toHaveLength(1);
    expect(parameters[0]).toMatchObject({
      name: "/mem9-on-aws/prod/namespace/transport-signing-keys",
      type: "SecureString",
    });
    expect(parameters[0]).not.toHaveProperty("keyId");
    const keyring = materialize<string>(outputs.transportSigningKeys);
    expect(JSON.parse(keyring)).toEqual({
      active: "a",
      a: passwordValue("Mem9TransportSigningKeySlotA", {
        keepers: { revision: "v1" },
      }),
      b: passwordValue("Mem9TransportSigningKeySlotB", {
        keepers: { revision: "v1" },
      }),
    });
    expect(materialize(outputs.transportSigningRevision)).toBe(
      createHash("sha256").update(keyring).digest("hex"),
    );
    expect(outputs.identitySigningKeys).toBeDefined();
    expect(outputs.transportSigningParameterArn).toBeDefined();
  });

  it("switches the active slot without discarding the previous key", async () => {
    process.env.MEM9_TRANSPORT_SIGNING_ACTIVE_SLOT = "b";
    process.env.MEM9_TRANSPORT_SIGNING_SLOT_A_REVISION = "2026-08-a2";
    process.env.MEM9_TRANSPORT_SIGNING_SLOT_B_REVISION = "2026-08-b3";
    const { namespaceIdentity } = await import("./namespace-identity");
    const outputs = namespaceIdentity();

    expect(passwords.slice(1)).toEqual([
      {
        name: "Mem9TransportSigningKeySlotA",
        args: {
          length: 64,
          special: false,
          keepers: { revision: "2026-08-a2" },
        },
      },
      {
        name: "Mem9TransportSigningKeySlotB",
        args: {
          length: 64,
          special: false,
          keepers: { revision: "2026-08-b3" },
        },
      },
    ]);
    expect(JSON.parse(materialize(outputs.transportSigningKeys))).toEqual({
      active: "b",
      a: passwordValue("Mem9TransportSigningKeySlotA", {
        keepers: { revision: "2026-08-a2" },
      }),
      b: passwordValue("Mem9TransportSigningKeySlotB", {
        keepers: { revision: "2026-08-b3" },
      }),
    });
  });

  it("TC-GROUPNS-133: rotates the inactive slot before switching active", async () => {
    const { namespaceIdentity } = await import("./namespace-identity");
    const initial = namespaceIdentity();
    const initialKeyring = JSON.parse(
      materialize<string>(initial.transportSigningKeys),
    );
    const initialRevision = materialize<string>(
      initial.transportSigningRevision,
    );

    process.env.MEM9_TRANSPORT_SIGNING_SLOT_B_REVISION = "v2";
    const prepared = namespaceIdentity();
    const preparedKeyring = JSON.parse(
      materialize<string>(prepared.transportSigningKeys),
    );
    const preparedRevision = materialize<string>(
      prepared.transportSigningRevision,
    );
    expect(preparedKeyring.active).toBe("a");
    expect(preparedKeyring.a).toBe(initialKeyring.a);
    expect(preparedKeyring.b).not.toBe(initialKeyring.b);
    expect(preparedRevision).not.toBe(initialRevision);

    process.env.MEM9_TRANSPORT_SIGNING_ACTIVE_SLOT = "b";
    const activated = namespaceIdentity();
    const activatedKeyring = JSON.parse(
      materialize<string>(activated.transportSigningKeys),
    );
    expect(activatedKeyring).toEqual({
      active: "b",
      a: preparedKeyring.a,
      b: preparedKeyring.b,
    });
    expect(
      materialize(activated.transportSigningRevision),
    ).not.toBe(preparedRevision);
  });

  it.each([
    [
      "MEM9_TRANSPORT_SIGNING_ACTIVE_SLOT",
      "c",
      "MEM9_TRANSPORT_SIGNING_ACTIVE_SLOT must be a or b",
    ],
    [
      "MEM9_TRANSPORT_SIGNING_SLOT_A_REVISION",
      "bad revision",
      "MEM9_TRANSPORT_SIGNING_SLOT_A_REVISION must be",
    ],
    [
      "MEM9_TRANSPORT_SIGNING_SLOT_B_REVISION",
      "bad/revision",
      "MEM9_TRANSPORT_SIGNING_SLOT_B_REVISION must be",
    ],
  ])("rejects invalid %s", async (name, value, message) => {
    const { transportSigningKeyConfig } = await import("./namespace-identity");
    expect(() =>
      transportSigningKeyConfig({ [name]: value }),
    ).toThrow(message);
  });
});
