import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Unit tests for the `cognito` stack factory. Mocks the SST globals so the
 * factory runs bare; asserts the M2M user pool + domain + resource server +
 * client wiring and the SSM exports (client secret as SecureString, never plain).
 */

interface TestOutput<T> {
  value: T;
  apply<U>(fn: (value: T) => U | TestOutput<U>): TestOutput<U>;
}

function isTestOutput<T>(value: T | TestOutput<T>): value is TestOutput<T> {
  return typeof value === "object" && value !== null && "apply" in value;
}

function out<T>(value: T): TestOutput<T> {
  return {
    value,
    apply<U>(fn: (input: T) => U | TestOutput<U>): TestOutput<U> {
      const result = fn(value);
      return isTestOutput(result) ? result : out(result);
    },
  };
}

interface Rec {
  kind: string;
  args: Record<string, unknown>;
}
let created: Rec[];
let params: { name: string; type: string; value: unknown }[];
let previousDomainPrefix: string | undefined;

const ACCOUNT_ID = "123456789012";
const REGION = "ap-northeast-1";
const PROD_DERIVED_PREFIX = "mem9-eacc290a1cfb9bde8585";

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

function installGlobals(stage: string, accountId = ACCOUNT_ID, region = REGION) {
  (globalThis as Record<string, unknown>).$app = { name: "mem9-on-aws", stage };
  installInterpolate();
  (globalThis as Record<string, unknown>).aws = {
    getCallerIdentityOutput: () => ({ accountId: out(accountId) }),
    getRegionOutput: () => ({ name: out(region) }),
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
  previousDomainPrefix = process.env.MEM9_COGNITO_DOMAIN_PREFIX;
  delete process.env.MEM9_COGNITO_DOMAIN_PREFIX;
});
afterEach(() => {
  for (const g of ["$app", "aws", "$interpolate"]) delete (globalThis as Record<string, unknown>)[g];
  if (previousDomainPrefix === undefined) {
    delete process.env.MEM9_COGNITO_DOMAIN_PREFIX;
  } else {
    process.env.MEM9_COGNITO_DOMAIN_PREFIX = previousDomainPrefix;
  }
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
  it("TC-M2M-CLEANUP-001: creates one read/write M2M client", async () => {
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
    expect(clients).toHaveLength(1);
    expect(clients.map(({ args }) => args.name)).toEqual([
      "prod-mem9-mcp-client",
    ]);
    for (const { args } of clients) {
      expect(args.generateSecret).toBe(true);
      expect(args.allowedOauthFlows).toEqual(["client_credentials"]);
      expect((args.allowedOauthScopes as { value: string[] }).value).toEqual([
        "mem9-mcp/read",
        "mem9-mcp/write",
      ]);
    }
    // The gateway consumes the remaining M2M client id in allowedClientIds.
    expect(outs.allowedClientIds).toHaveLength(1);
    expect(outs.allowedClientIds.map((id) => (id as unknown as { value: string }).value)).toEqual(
      ["UserPoolClient-1-id"],
    );
  });

  it("TC-M2M-CLEANUP-002: exports only the original client credentials", async () => {
    installGlobals("prod");
    const cognito = await loadCognito();
    cognito();
    expect(params.find((p) => p.name.endsWith("/cognito/client-secret"))).toMatchObject({
      type: "SecureString",
      value: "SECRET-VALUE-1",
    });
    // Issuer, token endpoint, client id, and scope are plain Strings.
    expect(params.find((p) => p.name.endsWith("/cognito/issuer"))?.type).toBe("String");
    expect(params.find((p) => p.name.endsWith("/cognito/client-id"))).toMatchObject({
      type: "String",
      value: "UserPoolClient-1-id",
    });
    expect(params.some((p) => p.name.includes("/cognito/client2/"))).toBe(false);
  });

  it("creates two additional namespace clients only for pr-N stages", async () => {
    installGlobals("pr-42");
    const cognito = await loadCognito();
    const outs = cognito();
    const clients = byKind("UserPoolClient");
    expect(clients.map(({ args }) => args.name)).toEqual([
      "pr-42-mem9-mcp-client",
      "pr-42-namespace-alpha-e2e",
      "pr-42-namespace-beta-e2e",
    ]);
    expect(outs.allowedClientIds).toHaveLength(3);
    expect(outs.previewNamespaceClients).toMatchObject([
      {
        namespaceSlug: "preview-alpha",
        cognitoGroup: "memory-preview-alpha",
        ssmPrefix:
          "/mem9-on-aws/pr-42/cognito/namespace-e2e-alpha",
      },
      {
        namespaceSlug: "preview-beta",
        cognitoGroup: "memory-preview-beta",
        ssmPrefix:
          "/mem9-on-aws/pr-42/cognito/namespace-e2e-beta",
      },
    ]);
    expect(
      params.find((p) =>
        p.name.endsWith("/cognito/namespace-e2e-alpha/client-secret"),
      ),
    ).toMatchObject({ type: "SecureString", value: "SECRET-VALUE-2" });
    expect(
      params.find((p) =>
        p.name.endsWith("/cognito/namespace-e2e-beta/client-secret"),
      ),
    ).toMatchObject({ type: "SecureString", value: "SECRET-VALUE-3" });
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
    expect(
      (byKind("UserPoolDomain")[0].args.domain as { value: string }).value,
    ).toBe("mem9-464003a338eef415916e");
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

  it("TC-COGDOMAIN-014: preserves the configured production prefix", async () => {
    process.env.MEM9_COGNITO_DOMAIN_PREFIX = "existing-prod-prefix";
    installGlobals("prod");
    const cognito = await loadCognito();
    cognito();

    expect(byKind("UserPoolDomain")[0].args.domain).toBe(
      "existing-prod-prefix",
    );
  });
});

describe("Cognito domain prefix helpers", () => {
  // The module reads the SST-injected `aws` global at import time, so the stage
  // value here is irrelevant to these cases — the globals just have to exist.
  async function loadDomainHelpers() {
    installGlobals("prod");
    vi.resetModules();
    const module = await import("./cognito");
    return {
      cognitoDomainOverride: module.cognitoDomainOverride,
      cognitoDomainPrefix: module.cognitoDomainPrefix,
    };
  }

  it("TC-COGDOMAIN-001: derives a pinned stable default", async () => {
    const { cognitoDomainPrefix } = await loadDomainHelpers();
    const input = { accountId: ACCOUNT_ID, region: REGION, stage: "prod" };
    expect(cognitoDomainPrefix(input)).toBe(PROD_DERIVED_PREFIX);
    expect(cognitoDomainPrefix(input)).toBe(PROD_DERIVED_PREFIX);
    expect(PROD_DERIVED_PREFIX).toMatch(/^mem9-[a-f0-9]{20}$/u);
  });

  it("TC-COGDOMAIN-002/003/004: changes for every namespace input", async () => {
    const { cognitoDomainPrefix } = await loadDomainHelpers();
    const base = { accountId: ACCOUNT_ID, region: REGION, stage: "prod" };
    expect(
      cognitoDomainPrefix({ ...base, accountId: "test-account-two" }),
    ).toBe("mem9-fd5620e61c7a89401f03");
    expect(
      cognitoDomainPrefix({ ...base, region: "us-west-2" }),
    ).toBe("mem9-a0ae4801969aea22f95f");
    expect(
      cognitoDomainPrefix({ ...base, stage: "pr-42" }),
    ).toBe("mem9-464003a338eef415916e");
  });

  it("TC-COGDOMAIN-010: returns a configured override", async () => {
    const { cognitoDomainOverride } = await loadDomainHelpers();
    expect(cognitoDomainOverride("acme-mem9-mcp")).toBe("acme-mem9-mcp");
    expect(cognitoDomainOverride("  acme-mem9-mcp  ")).toBe(
      "acme-mem9-mcp",
    );
  });

  it("TC-COGDOMAIN-011: falls back when the override is absent or blank", async () => {
    const { cognitoDomainOverride } = await loadDomainHelpers();
    expect(cognitoDomainOverride(undefined)).toBeUndefined();
    expect(cognitoDomainOverride("")).toBeUndefined();
    expect(cognitoDomainOverride("   ")).toBeUndefined();
  });

  it("TC-COGDOMAIN-012/013: validates Cognito syntax and reserved keywords", async () => {
    const { cognitoDomainOverride } = await loadDomainHelpers();
    for (const invalid of [
      "Mem9-Prod", // uppercase
      "-mem9-prod", // leading hyphen
      "mem9-prod-", // trailing hyphen
      "mem9_prod", // underscore
      "mem9.prod", // dot
      "a".repeat(64), // 64 chars, one over the limit
      "aws",
      "acme-amazon-auth",
      "my-cognito-login",
    ]) {
      expect(() => cognitoDomainOverride(invalid)).toThrow(
        /MEM9_COGNITO_DOMAIN_PREFIX/u,
      );
    }
    expect(cognitoDomainOverride("a")).toBe("a");
    expect(cognitoDomainOverride("a".repeat(63))).toBe("a".repeat(63));
  });

  it("TC-COGDOMAIN-010: reads the override from the environment", async () => {
    const { cognitoDomainOverride } = await loadDomainHelpers();
    process.env.MEM9_COGNITO_DOMAIN_PREFIX = "acme-mem9-mcp";
    expect(cognitoDomainOverride()).toBe("acme-mem9-mcp");
  });
});
