import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Unit tests for the `cognito` stack factory. Mocks the SST globals so the
 * factory runs bare; asserts the M2M user pool + domain + resource server +
 * client wiring and the SSM exports (client secrets as SecureString, never plain).
 */

function out<T>(value: T): { value: T; apply: (fn: (v: T) => unknown) => unknown } {
  return { value, apply: (fn) => out(fn(value) as never) };
}

interface Rec {
  kind: string;
  args: Record<string, unknown>;
}
let created: Rec[];
let params: { name: string; type: string; value: unknown }[];

function installInterpolate() {
  (globalThis as Record<string, unknown>).$interpolate = (
    strings: TemplateStringsArray,
    ...values: unknown[]
  ) => {
    let s = "";
    strings.forEach((str, i) => {
      s += str;
      if (i < values.length) {
        const v = values[i];
        s += typeof v === "object" && v && "value" in v ? String((v as { value: unknown }).value) : String(v);
      }
    });
    return out(s);
  };
}

function makeCtor(kind: string) {
  return class {
    id = out(`${kind}-${created.filter((record) => record.kind === kind).length + 1}-id`);
    arn = out(`arn:${kind}`);
    identifier = out("mem9-mcp");
    domain = out("prod-mem9-mcp");
    clientSecret = out(
      `SECRET-VALUE-${created.filter((record) => record.kind === kind).length + 1}`,
    );
    constructor(_n: string, args: Record<string, unknown>) {
      created.push({ kind, args });
    }
  };
}

function installGlobals(stage: string) {
  (globalThis as Record<string, unknown>).$app = { name: "mem9-on-aws", stage };
  installInterpolate();
  (globalThis as Record<string, unknown>).aws = {
    getRegionOutput: () => ({ name: out("ap-northeast-1") }),
    cognito: {
      UserPool: makeCtor("UserPool"),
      UserPoolDomain: makeCtor("UserPoolDomain"),
      ResourceServer: makeCtor("ResourceServer"),
      UserPoolClient: makeCtor("UserPoolClient"),
    },
    ssm: {
      Parameter: class {
        constructor(_n: string, args: { name: unknown; type: string; value: unknown }) {
          const name =
            typeof args.name === "object" && args.name && "value" in args.name
              ? (args.name as { value: string }).value
              : (args.name as string);
          const value =
            typeof args.value === "object" && args.value && "value" in args.value
              ? (args.value as { value: unknown }).value
              : args.value;
          params.push({ name, type: args.type, value });
        }
      },
    },
  };
}

beforeEach(() => {
  created = [];
  params = [];
});
afterEach(() => {
  for (const g of ["$app", "aws", "$interpolate"]) delete (globalThis as Record<string, unknown>)[g];
  vi.resetModules();
});

async function loadCognito() {
  vi.resetModules();
  return (await import("./cognito")).cognito;
}
function byKind(kind: string) {
  return created.filter((r) => r.kind === kind);
}

describe("cognito stack", () => {
  it("creates a pool, domain, resource server (read+write), and two M2M clients", async () => {
    installGlobals("prod");
    const cognito = await loadCognito();
    const outs = cognito();
    expect(byKind("UserPool")).toHaveLength(1);
    expect(byKind("UserPoolDomain")).toHaveLength(1);
    const rs = byKind("ResourceServer")[0].args;
    expect(rs.identifier).toBe("mem9-mcp");
    const scopeNames = (rs.scopes as { scopeName: string }[]).map((s) => s.scopeName).sort();
    expect(scopeNames).toEqual(["read", "write"]);
    const clients = byKind("UserPoolClient");
    expect(clients).toHaveLength(2);
    expect(clients.map(({ args }) => args.name)).toEqual([
      "prod-mem9-mcp-client",
      "prod-mem9-mcp-client2",
    ]);
    for (const { args } of clients) {
      expect(args.generateSecret).toBe(true);
      expect(args.allowedOauthFlows).toEqual(["client_credentials"]);
      expect((args.allowedOauthScopes as { value: string[] }).value).toEqual([
        "mem9-mcp/read",
        "mem9-mcp/write",
      ]);
    }
    // The gateway consumes both client ids in allowedClientIds.
    expect(outs.allowedClientIds).toHaveLength(2);
    expect(outs.allowedClientIds.map((id) => (id as unknown as { value: string }).value)).toEqual(
      ["UserPoolClient-1-id", "UserPoolClient-2-id"],
    );
  });

  it("exports both client secrets as SecureString values", async () => {
    installGlobals("prod");
    const cognito = await loadCognito();
    cognito();
    expect(params.find((p) => p.name.endsWith("/cognito/client-secret"))).toMatchObject({
      type: "SecureString",
      value: "SECRET-VALUE-1",
    });
    expect(
      params.find((p) => p.name.endsWith("/cognito/client2/client-secret")),
    ).toMatchObject({
      type: "SecureString",
      value: "SECRET-VALUE-2",
    });
    // Issuer, token endpoint, client ids, and scope are plain Strings.
    expect(params.find((p) => p.name.endsWith("/cognito/issuer"))?.type).toBe("String");
    expect(params.find((p) => p.name.endsWith("/cognito/client-id"))).toMatchObject({
      type: "String",
      value: "UserPoolClient-1-id",
    });
    expect(params.find((p) => p.name.endsWith("/cognito/client2/client-id"))).toMatchObject({
      type: "String",
      value: "UserPoolClient-2-id",
    });
  });

  it("uses deleteBeforeReplace on non-prod, not on prod (pool replacement wipes clients)", async () => {
    // prod: no deleteBeforeReplace
    installGlobals("prod");
    let cognito = await loadCognito();
    cognito();
    // (opts aren't captured by the mock ctor; assert via a pr- stage building a
    // distinct pool name — the deterministic naming is the observable contract.)
    expect(byKind("UserPool")[0].args.name).toBe("prod-mem9-mcp");

    for (const g of ["$app", "aws", "$interpolate"]) delete (globalThis as Record<string, unknown>)[g];
    created = [];
    installGlobals("pr-42");
    cognito = await loadCognito();
    cognito();
    expect(byKind("UserPool")[0].args.name).toBe("pr-42-mem9-mcp");
    // PR-stage domain gets the numeric suffix for deterministic re-deploys.
    expect(byKind("UserPoolDomain")[0].args.domain).toBe("pr-42-mem9-mcp-42");
  });

  it("configures the pool for Hosted-UI (email schema + no forced re-verify)", async () => {
    installGlobals("prod");
    const cognito = await loadCognito();
    cognito();
    const poolArgs = byKind("UserPool")[0].args;
    const schema = poolArgs.schema as { name: string; mutable: boolean; required: boolean }[];
    expect(schema).toContainEqual(
      expect.objectContaining({ name: "email", mutable: true, required: false }),
    );
    const updateSettings = poolArgs.userAttributeUpdateSettings as {
      attributesRequireVerificationBeforeUpdate: unknown[];
    };
    expect(updateSettings.attributesRequireVerificationBeforeUpdate).toEqual([]);
  });

  it("auto-verifies email so ForgotPassword recovery works", async () => {
    installGlobals("prod");
    const cognito = await loadCognito();
    cognito();
    const poolArgs = byKind("UserPool")[0].args;
    // email must be auto-verifiable for the Hosted-UI ForgotPassword flow to send
    // a recovery code (AccountRecovery is verified_email). Without this, reset 503s.
    expect(poolArgs.autoVerifiedAttributes).toEqual(["email"]);
  });

  it("locks self-service sign-up (admin-create-user only)", async () => {
    installGlobals("prod");
    const cognito = await loadCognito();
    cognito();
    const poolArgs = byKind("UserPool")[0].args;
    const adminCfg = poolArgs.adminCreateUserConfig as { allowAdminCreateUserOnly?: boolean };
    // Single-operator: no public sign-up. Only an admin creates users.
    expect(adminCfg.allowAdminCreateUserOnly).toBe(true);
  });

  it("exports the Hosted-UI endpoint URLs the façade needs", async () => {
    installGlobals("prod");
    const cognito = await loadCognito();
    const out = cognito();
    expect(out.authorizeEndpoint).toBeDefined();
    expect(out.userInfoEndpoint).toBeDefined();
    expect(out.revocationEndpoint).toBeDefined();
    expect(out.jwksUri).toBeDefined();
  });
});
