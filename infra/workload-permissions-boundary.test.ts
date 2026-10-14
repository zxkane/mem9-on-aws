import { readFileSync } from "node:fs";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as pulumi from "@pulumi/pulumi";
import {
  WORKLOAD_BOUNDARY_POLICY_NAME,
  registerWorkloadRoleBoundary,
  shouldRegisterWorkloadRoleBoundary,
} from "./workload-permissions-boundary";

function out<T>(value: T): {
  value: T;
  apply: (fn: (v: T) => unknown) => unknown;
} {
  return {
    value,
    apply: (fn) => out(fn(value)),
  };
}

function materialize(value: unknown): unknown {
  if (typeof value === "object" && value && "value" in value) {
    return materialize((value as { value: unknown }).value);
  }
  if (Array.isArray(value)) return value.map(materialize);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, materialize(entry)]));
  return value;
}

describe("workload role boundary transform", () => {
  type RoleTransform = (args: Record<string, unknown>, opts: Record<string, unknown>, name: string) => void;
  let roleTransform: RoleTransform | undefined;

  beforeEach(() => {
    vi.resetModules();
    roleTransform = undefined;
    (globalThis as Record<string, unknown>).$app = { stage: "pr-7" };
    (globalThis as Record<string, unknown>).$jsonStringify = (value: unknown) => out(JSON.stringify(materialize(value)));
    (globalThis as Record<string, unknown>).aws = {
      getCallerIdentityOutput: () => ({ accountId: out("123456789012") }),
      getPartitionOutput: () => ({ partition: out("aws") }),
      iam: { Role: class {} },
    };
    (globalThis as Record<string, unknown>).$interpolate = (
      strings: TemplateStringsArray,
      ...values: unknown[]
    ) =>
      out(
        strings.reduce(
          (result, text, index) =>
            result +
            text +
            (index < values.length ? String(materialize(values[index])) : ""),
          "",
        ),
      );
    (globalThis as Record<string, unknown>).$transform = (
      resource: unknown,
      transform: RoleTransform,
    ) => {
      const aws = (globalThis as Record<string, any>).aws as Record<
        string,
        any
      >;
      if (resource === aws.iam.Role) {
        roleTransform = transform;
      } else {
        throw new Error("unexpected transformed resource");
      }
    };
  });

  it("sets the exact partition/account-derived workload ARN on other role inputs", () => {
    registerWorkloadRoleBoundary();
    expect(roleTransform).toBeTypeOf("function");

    const implicitRole: Record<string, unknown> = {
      permissionsBoundary: "arn:aws:iam::123456789012:policy/wrong-implicit",
    };
    const explicitRole: Record<string, unknown> = {
      name: "mem9-on-aws-prod-gateway-service-role",
      permissionsBoundary: "arn:aws:iam::123456789012:policy/wrong-explicit",
    };
    roleTransform?.(implicitRole, {}, "Mem9ServerTaskRole");
    roleTransform?.(explicitRole, {}, "Mem9GatewayServiceRole");

    const expected = `arn:aws:iam::123456789012:policy/${WORKLOAD_BOUNDARY_POLICY_NAME}`;
    expect(materialize(implicitRole.permissionsBoundary)).toBe(expected);
    expect(materialize(explicitRole.permissionsBoundary)).toBe(expected);
  });

  it.each(["Mem9ProxyFnRole", "Mem9IdentityInterceptorFnRole"])(
    "assigns the existing Gateway boundary to logical role %s without changing its permissions or trust",
    (name) => {
      registerWorkloadRoleBoundary();
      const args: Record<string, unknown> = {
        permissionsBoundary: "wrong",
        assumeRolePolicy: "unchanged-trust",
        inlinePolicies: [{ name: "unchanged", policy: "unchanged-permissions" }],
        name: "provider-generated-name",
        tags: out({ Project: "wrong", Stage: "wrong", Retained: out("unchanged") }),
      };
      const expected = { ...args, permissionsBoundary: "arn:aws:iam::123456789012:policy/mem9-on-aws-gateway-boundary",
        tags: { Project: "mem9-on-aws", Stage: "pr-7", Retained: "unchanged" } };
      roleTransform?.(args, {}, name);
      expect(materialize(args)).toEqual(expected);
    },
  );

  it.each(["Mem9GatewayServiceRole", "Mem9OauthFacadeFnRole", "Mem9ServerTaskRole",
    "Mem9ProxyFnRoleLookalike", "Mem9ProxyFnRole-extra", "OtherMem9IdentityInterceptorFnRole",
    "mem9-on-aws-pr-7-Mem9ProxyFnRole-example"])(
    "does not assign the Gateway boundary to %s",
    (name) => {
      registerWorkloadRoleBoundary();
      const tags = out({ Stage: "unchanged", Project: "unchanged" });
      const args: Record<string, unknown> = { permissionsBoundary: "arn:aws:iam::123456789012:policy/mem9-on-aws-gateway-boundary", tags };
      roleTransform?.(args, {}, name);
      expect(materialize(args.permissionsBoundary)).toBe(`arn:aws:iam::123456789012:policy/${WORKLOAD_BOUNDARY_POLICY_NAME}`);
      expect(args.tags).toBe(tags);
    },
  );

  it.each(["prod", "pr-7"])("sets required Gateway tags from the registered %s stage when none were supplied", stage => {
    (globalThis as Record<string, unknown>).$app = { stage };
    registerWorkloadRoleBoundary();
    const args: Record<string, unknown> = {};
    roleTransform?.(args, {}, "Mem9ProxyFnRole");
    expect(materialize(args.tags)).toEqual({ Project: "mem9-on-aws", Stage: stage });
  });

  it.each(["prod", "pr-7"])("selects Gateway only by fixed logical role and binds stage %s", stage => {
    (globalThis as Record<string, unknown>).$app = {stage};
    registerWorkloadRoleBoundary();
    for (const name of ["Mem9ProxyFnRole", "Mem9IdentityInterceptorFnRole"]) {
      const args:Record<string,unknown> = {permissionsBoundary:"wrong", tags:{Project:"wrong",Stage:"wrong",Existing:"kept"}};
      roleTransform?.(args, {}, name);
      expect(materialize(args.permissionsBoundary)).toBe("arn:aws:iam::123456789012:policy/mem9-on-aws-gateway-boundary");
      expect(materialize(args.tags)).toEqual({Project:"mem9-on-aws",Stage:stage,Existing:"kept"});
    }
    for (const name of ["Mem9ServerExecutionRole", "Mem9ProxyFnRoleSuffix", "OtherMem9ProxyFnRole"]) {
      const args:Record<string,unknown> = {name:`mem9-on-aws-${stage}-Mem9ProxyFnRole-fixture`,permissionsBoundary:"wrong"};
      roleTransform?.(args, {}, name);
      expect(materialize(args.permissionsBoundary)).toBe(`arn:aws:iam::123456789012:policy/${WORKLOAD_BOUNDARY_POLICY_NAME}`);
    }
  });

  it("registers the role transform before any stack module is imported", () => {
    const config = readFileSync(
      new URL("../sst.config.ts", import.meta.url),
      "utf8",
    );
    const registration = config.indexOf("registerWorkloadRoleBoundary();");
    const firstStackImport = config.indexOf('await import("./infra/meta")');
    expect(registration).toBeGreaterThan(-1);
    expect(firstStackImport).toBeGreaterThan(registration);
    expect(config).not.toContain("registerBoundaryCompatibleSecretNames");
    expect(config).not.toContain("applyBoundaryCompatibleSecretName");
  });

  it.each([
    ["true", true, /stop after global transforms/u],
    ["false", false, /stop after global transforms/u],
    ["malformed", false, /must be explicitly true or false/u],
  ])(
    "executes the prod config branch with flag %s",
    async (prodEnabled, shouldRegister, expectedError) => {
      vi.resetModules();
      const previousFlag = process.env.WORKLOAD_BOUNDARY_PROD_ENABLED;
      let configuredRoleTransform:
        | ((args: Record<string, unknown>) => void)
        | undefined;
      let configuredFunctionTransform:
        | ((args: Record<string, unknown>) => void)
        | undefined;
      const roleResource = class {};
      const lambdaResource = class {};
      const functionComponent = class {};

      (globalThis as Record<string, unknown>).$config = (value: unknown) =>
        value;
      (globalThis as Record<string, unknown>).$app = { stage: "prod" };
      (globalThis as Record<string, unknown>).$cli = { command: "deploy" };
      (globalThis as Record<string, unknown>).$util = pulumi;
      (globalThis as Record<string, unknown>).aws = {
        ec2: {
          getVpcOutput: () => {
            throw new Error("stop after global transforms");
          },
        },
        getCallerIdentityOutput: () => ({ accountId: out("123456789012") }),
        getPartitionOutput: () => ({ partition: out("aws") }),
        iam: { Role: roleResource },
        lambda: { Function: lambdaResource },
      };
      (globalThis as Record<string, unknown>).sst = {
        aws: { Function: functionComponent },
      };
      (globalThis as Record<string, unknown>).$interpolate = (
        strings: TemplateStringsArray,
        ...values: unknown[]
      ) =>
        out(
          strings.reduce(
            (result, text, index) =>
              result +
              text +
              (index < values.length ? String(materialize(values[index])) : ""),
            "",
          ),
        );
      (globalThis as Record<string, unknown>).$transform = (
        resource: unknown,
        transform: (args: Record<string, unknown>) => void,
      ) => {
        if (resource === roleResource) configuredRoleTransform = transform;
        if (resource === functionComponent) {
          configuredFunctionTransform = transform;
        }
      };
      process.env.WORKLOAD_BOUNDARY_PROD_ENABLED = prodEnabled;

      try {
        const configUrl = new URL("../sst.config.ts", import.meta.url).href;
        const configModule = (await import(/* @vite-ignore */ configUrl)) as {
          default: { run(): Promise<unknown> };
        };
        await expect(configModule.default.run()).rejects.toThrow(expectedError);
        expect(configuredFunctionTransform).toBeTypeOf("function");
        const functionArgs: Record<string, any> = {
          handler: "handler.main",
          transform: {
            role: { assumeRolePolicy: "wrong" },
          },
        };
        configuredFunctionTransform?.(functionArgs);
        const roleArgs = { assumeRolePolicy: "still-wrong" };
        functionArgs.transform.role(roleArgs, {}, "TestFunctionRole");
        expect(JSON.parse(roleArgs.assumeRolePolicy)).toEqual({
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Action: "sts:AssumeRole",
              Principal: { Service: "lambda.amazonaws.com" },
            },
          ],
        });
        if (shouldRegister) {
          expect(configuredRoleTransform).toBeTypeOf("function");
          const args = {
            permissionsBoundary: "arn:aws:iam::123456789012:policy/wrong",
          };
          configuredRoleTransform?.(args);
          expect(materialize(args.permissionsBoundary)).toBe(
            `arn:aws:iam::123456789012:policy/${WORKLOAD_BOUNDARY_POLICY_NAME}`,
          );
        } else {
          expect(configuredRoleTransform).toBeUndefined();
        }
      } finally {
        if (previousFlag === undefined) {
          delete process.env.WORKLOAD_BOUNDARY_PROD_ENABLED;
        } else {
          process.env.WORKLOAD_BOUNDARY_PROD_ENABLED = previousFlag;
        }
        for (const name of [
          "$app",
          "$cli",
          "$util",
          "$config",
          "aws",
          "sst",
          "$interpolate",
          "$transform",
        ]) {
          delete (globalThis as Record<string, unknown>)[name];
        }
      }
    },
  );

  it.each([
    ["pr-70", undefined, true],
    ["prod", "false", false],
    ["prod", "true", true],
    ["dev", undefined, true],
    ["dev", "false", true],
  ])(
    "gates transform registration for stage %s with prod flag %s",
    (stage, prodEnabled, expected) => {
      expect(shouldRegisterWorkloadRoleBoundary({ stage, prodEnabled })).toBe(
        expected,
      );
    },
  );

  it.each([undefined, "", "yes", "TRUE"])(
    "fails closed for a prod deployment with flag %s",
    (prodEnabled) => {
      expect(() =>
        shouldRegisterWorkloadRoleBoundary({
          stage: "prod",
          prodEnabled,
        }),
      ).toThrow(/must be explicitly true or false/u);
    },
  );
});
