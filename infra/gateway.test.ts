import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CognitoOutputs } from "./cognito";
import type { EcsOutputs } from "./ecs";
import type { TenantIdentityOutputs } from "./tenant-identity";
import type { NamespaceIdentityOutputs } from "./namespace-identity";

/**
 * Unit tests for the `gateway` stack (Lambda-proxy target): the CUSTOM_JWT
 * AgentCore Gateway, the VPC-attached proxy Lambda (nodejs24.x) + its exec role,
 * the gateway service role (lambda:InvokeFunction only), and the Lambda
 * GatewayTarget provisioned via a command.local.Command.
 */

function out<T>(value: T): { value: T; apply: (fn: (v: T) => unknown) => unknown } {
  return { value, apply: (fn) => out(fn(value) as never) };
}

interface Rec {
  kind: string;
  args: Record<string, unknown>;
  opts?: Record<string, unknown>;
}
let created: Rec[];
let params: { name: string }[];

// Unwrap the loose out<T> mock (and plain values) recursively — the target
// Command's `create`/`delete`/`environment` come through the out<T> mock.
function unwrap(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(unwrap);
  if (v && typeof v === "object") {
    if ("value" in v) return unwrap((v as { value: unknown }).value);
    const o: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v)) o[k] = unwrap(val);
    return o;
  }
  return v;
}

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
    name = out(`${kind}-name`);
    arn = { value: `arn:${kind}`, apply: (fn: (v: string) => unknown) => out(fn(`arn:${kind}`) as never) };
    id = out(`${kind}-id`);
    gatewayId = out("gw-123");
    gatewayUrl = out("https://gateway.example.com/mcp");
    constructor(_n: string, args: Record<string, unknown>, opts?: Record<string, unknown>) {
      created.push({ kind, args, opts });
    }
  };
}

function installGlobals(stage: string) {
  (globalThis as Record<string, unknown>).$app = { name: "mem9-on-aws", stage };
  installInterpolate();
  (globalThis as Record<string, unknown>).$jsonStringify = (value: unknown) =>
    out(JSON.stringify(unwrap(value)));
  (globalThis as Record<string, unknown>).aws = {
    getRegionOutput: () => ({ name: out("ap-northeast-1") }),
    ec2: {
      getVpcOutput: () => ({ id: out("vpc-test") }),
      getSubnetsOutput: () => ({ ids: out(["subnet-a", "subnet-b", "subnet-c"]) }),
    },
    iam: { Role: makeCtor("Role"), RolePolicy: makeCtor("RolePolicy") },
    bedrock: {
      AgentcoreGateway: makeCtor("AgentcoreGateway"),
    },
    ssm: {
      Parameter: class {
        constructor(_n: string, args: { name: unknown }) {
          const name =
            typeof args.name === "object" && args.name && "value" in args.name
              ? (args.name as { value: string }).value
              : (args.name as string);
          params.push({ name });
        }
      },
    },
  };
  // The proxy Lambda is an `sst.aws.Function` (SST zips it + makes the exec role).
  (globalThis as Record<string, unknown>).sst = {
    aws: { Function: makeCtor("SstFunction") },
  };
  // The GatewayTarget is provisioned via a command.local.Command running the
  // direct bedrock-agentcore-control API. `command` is a separate SST global.
  (globalThis as Record<string, unknown>).command = {
    local: { Command: makeCtor("LocalCommand") },
  };
  (globalThis as Record<string, unknown>).random = {
    RandomPassword: class {
      result = out(Buffer.alloc(48, 7).toString("base64url"));
      constructor(_name: string, args: Record<string, unknown>) {
        created.push({ kind: "RandomPassword", args });
      }
    },
  };
}

beforeEach(() => {
  created = [];
  params = [];
});
afterEach(() => {
  for (const g of ["$app", "aws", "sst", "command", "random", "$interpolate", "$jsonStringify"]) delete (globalThis as Record<string, unknown>)[g];
  vi.resetModules();
});

async function loadGateway() {
  vi.resetModules();
  return (await import("./gateway")).gateway;
}

function fakeCognito(): CognitoOutputs {
  return {
    issuer: out("https://cognito-idp.ap-northeast-1.amazonaws.com/pool-1"),
    allowedClientIds: [out("client-1")],
  } as unknown as CognitoOutputs;
}
function fakeEcs(): EcsOutputs {
  return {
    serviceDnsName: out("mnemo.mem9-prod.local"),
    taskSecurityGroupId: out("sg-task"),
  } as unknown as EcsOutputs;
}
function fakeIdentity(): TenantIdentityOutputs {
  return {
    tenantId: out("deadbeefTENANTID"),
    tenantSecretArn: out("arn:secret"),
  } as unknown as TenantIdentityOutputs;
}
function fakeNamespaceIdentity(): NamespaceIdentityOutputs {
  return {
    identitySigningKeys: out(
      JSON.stringify({ current: Buffer.alloc(32, 4).toString("base64url") }),
    ),
    transportSigningKeys: out(
      JSON.stringify({
        active: "a",
        a: Buffer.alloc(32, 5).toString("base64url"),
        b: Buffer.alloc(32, 6).toString("base64url"),
      }),
    ),
    transportSigningParameterArn: out("arn:transport-parameter"),
    transportSigningRevision: out("transport-revision"),
  } as unknown as NamespaceIdentityOutputs;
}
function only(kind: string) {
  const rs = created.filter((r) => r.kind === kind);
  expect(rs).toHaveLength(1);
  return rs[0].args;
}

function all(kind: string) {
  return created.filter((r) => r.kind === kind).map((r) => r.args);
}

describe("gateway stack", () => {
  it("creates a CUSTOM_JWT MCP gateway matching on allowedClients (not aud)", async () => {
    installGlobals("prod");
    const gateway = await loadGateway();
    gateway(fakeCognito(), fakeEcs(), fakeIdentity(), out("reader-client-id-test") as unknown as Output<string>, fakeNamespaceIdentity());
    const gw = only("AgentcoreGateway");
    expect(gw.protocolType).toBe("MCP");
    expect(gw.authorizerType).toBe("CUSTOM_JWT");
    const jwt = (gw.authorizerConfiguration as any).customJwtAuthorizer;
    expect(String((jwt.discoveryUrl as { value?: string }).value)).toContain("/.well-known/openid-configuration");
    // The M2M client plus the browser-login reader client.
    expect(jwt.allowedClients).toHaveLength(2);
    expect(jwt.allowedScopes).toEqual([
      "mem9-mcp/read",
      "mem9-mcp/write",
    ]);
    expect(unwrap(gw.interceptorConfigurations)).toEqual([
      {
        interceptionPoints: ["REQUEST", "RESPONSE"],
        interceptor: { lambda: { arn: "arn:SstFunction" } },
        inputConfiguration: { passRequestHeaders: true },
      },
    ]);
  });

  it("TC-M2M-CLEANUP-003: trusts the M2M and reader clients", async () => {
    installGlobals("prod");
    const gateway = await loadGateway();
    gateway(fakeCognito(), fakeEcs(), fakeIdentity(), out("reader-client-id-test") as unknown as Output<string>, fakeNamespaceIdentity());
    const gw = only("AgentcoreGateway");
    const jwt = (gw.authorizerConfiguration as any).customJwtAuthorizer;
    // The list is [...cognitoOut.allowedClientIds, readerClientId]; each entry is an
    // out<string> wrapper, so unwrap to compare the underlying client ids.
    const clients = (unwrap(jwt.allowedClients) as string[]);
    // The M2M client from fakeCognito().allowedClientIds.
    expect(clients).toContain("client-1");
    // The browser-login reader client passed as the 4th arg.
    expect(clients).toContain("reader-client-id-test");
  });

  it("TC-GROUPNS-035: splits a non-VPC identity interceptor from the VPC target", async () => {
    installGlobals("prod");
    const gateway = await loadGateway();
    gateway(fakeCognito(), fakeEcs(), fakeIdentity(), out("reader-client-id-test") as unknown as Output<string>, fakeNamespaceIdentity());
    const functions = all("SstFunction");
    expect(functions).toHaveLength(2);
    const interceptorFn = functions.find((fn) =>
      String(fn.handler).includes("identity-interceptor.handler"),
    );
    const targetFn = functions.find((fn) =>
      String(fn.handler).includes("proxy-handler.handler"),
    );
    expect(interceptorFn).toBeDefined();
    expect(targetFn).toBeDefined();
    expect(interceptorFn?.runtime).toBe("nodejs24.x");
    expect(interceptorFn?.vpc).toBeUndefined();
    expect(
      (interceptorFn?.environment as Record<string, unknown>).MEM9_API_KEY,
    ).toBeUndefined();

    expect(targetFn?.runtime).toBe("nodejs24.x");
    const vpc = targetFn?.vpc as Record<string, unknown>;
    expect(vpc.privateSubnets).toBeDefined();
    expect(vpc.securityGroups).toBeDefined();
    // Env (flat on sst.aws.Function): the Cloud Map base URL + the tenant key.
    const env = targetFn?.environment as Record<string, any>;
    expect(String((env.MEM9_SERVER_BASE_URL as { value?: string }).value)).toContain("mnemo.mem9-prod.local");
    expect(String((env.MEM9_SERVER_BASE_URL as { value?: string }).value)).toContain(":8080");
    expect(String((env.MEM9_API_KEY as { value?: string }).value)).toBe("deadbeefTENANTID");
    expect(
      JSON.parse(
        String(
          (interceptorFn?.environment as Record<string, unknown>)
            .MEM9_TOOL_SCOPES,
        ),
      ),
    ).toEqual({
      add_memory: "mem9-mcp/write",
      search_memories: "mem9-mcp/read",
      ingest_messages: "mem9-mcp/write",
      get_ingest_job_status: "mem9-mcp/read",
    });

    const gw = only("AgentcoreGateway");
    const interceptor = (
      unwrap(gw.interceptorConfigurations) as Array<{
        interceptor: { lambda: { arn: string } };
      }>
    )[0];
    expect(interceptor.interceptor.lambda.arn).toBe("arn:SstFunction");
  });

  it("gateway service role grants ONLY lambda:InvokeFunction (no workload-identity/secret/ENI)", async () => {
    installGlobals("prod");
    const gateway = await loadGateway();
    gateway(fakeCognito(), fakeEcs(), fakeIdentity(), out("reader-client-id-test") as unknown as Output<string>, fakeNamespaceIdentity());
    // Two roles are created: the Lambda exec role + the gateway service role. Find
    // the gateway-invoke RolePolicy (its doc is an apply()'d Output over the ARN).
    const rolePolicies = created.filter((r) => r.kind === "RolePolicy");
    const docs = rolePolicies.map((r) => JSON.stringify(unwrap(r.args.policy)));
    const invokeDoc = docs.find((d) => d.includes("lambda:InvokeFunction"));
    expect(invokeDoc).toBeDefined();
    // None of the removed API-key/managed-Lattice grants remain anywhere.
    for (const d of docs) {
      expect(d).not.toContain("GetWorkloadAccessToken");
      expect(d).not.toContain("bedrock-agentcore-identity!");
      expect(d).not.toContain("CreateNetworkInterfacePermission");
    }
  });

  it("provisions the target via a command.local.Command driving a mcp.lambda CreateGatewayTarget", async () => {
    installGlobals("prod");
    const gateway = await loadGateway();
    gateway(fakeCognito(), fakeEcs(), fakeIdentity(), out("reader-client-id-test") as unknown as Output<string>, fakeNamespaceIdentity());
    const cmd = only("LocalCommand");
    expect(String(unwrap(cmd.create))).toContain("MEM9_TGT_OP=create");
    expect(String(unwrap(cmd.create))).toContain("provision-target.mjs");
    expect(String(unwrap(cmd.delete))).toContain("MEM9_TGT_OP=delete");
    const env = unwrap(cmd.environment) as Record<string, unknown>;
    // Lambda target inputs: the proxy Lambda ARN + the inline tool schema (both tools).
    expect(env.MEM9_TGT_LAMBDA_ARN).toBeDefined();
    expect(String(env.MEM9_TGT_TOOL_SCHEMA)).toContain("add_memory");
    expect(String(env.MEM9_TGT_TOOL_SCHEMA)).toContain("search_memories");
    expect(String(env.MEM9_TGT_TOOL_SCHEMA)).toContain("ingest_messages");
    expect(String(env.MEM9_TGT_TOOL_SCHEMA)).toContain("get_ingest_job_status");
    const toolNames = JSON.parse(String(env.MEM9_TGT_TOOL_SCHEMA))
      .map(({ name }: { name: string }) => name)
      .sort();
    const identityFn = all("SstFunction").find((fn) =>
      String(fn.handler).includes("identity-interceptor.handler"),
    );
    const scopePolicy = JSON.parse(
      String(
        (unwrap(identityFn?.environment) as Record<string, unknown>)
          .MEM9_TOOL_SCOPES,
      ),
    );
    expect(Object.keys(scopePolicy).sort()).toEqual(toolNames);
    // The removed privateEndpoint/API-key/OpenAPI-schema inputs are gone.
    expect(env.MEM9_TGT_SCHEMA).toBeUndefined();
    expect(env.MEM9_TGT_APIKEY_PROVIDER_ARN).toBeUndefined();
    expect(env.MEM9_TGT_LATTICE_RC_ARN).toBeUndefined();
    expect(env.MEM9_TGT_GATEWAY_ID).toBeDefined();
    expect(env.MEM9_TGT_NAME).toBe("prod-mem9-rest");
    // No API-key credential provider resource is created for a Lambda target.
    expect(created.filter((r) => r.kind === "AgentcoreApiKeyCredentialProvider")).toHaveLength(0);
    // Gateway url/id exported to SSM.
    expect(params.map((p) => p.name)).toContain("/mem9-on-aws/prod/gateway/url");
    // deleteBeforeReplace guards against the create-then-delete replace order that
    // wiped the target on a tool-schema change (PR #16 prod outage).
    const cmdRec = created.find((r) => r.kind === "LocalCommand");
    expect(cmdRec?.opts?.deleteBeforeReplace).toBe(true);
  });
});
