import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import * as pulumi from "@pulumi/pulumi";
import { LocalWorkspace } from "@pulumi/pulumi/automation";
import * as dynamic from "@pulumi/pulumi/dynamic";
import { afterEach, describe, expect, it } from "vitest";
import { WORKLOAD_BOUNDARY_POLICY_NAME } from "./workload-permissions-boundary";
import { EXPECTED_WORKLOAD_ROLE_NAMES } from "./workload-permissions-boundary.test-fixtures";

const PULUMI_OPERATION_TIMEOUT_MS = 30_000;

interface RoleInputs {
  assumeRolePolicy: string;
  permissionsBoundary: string;
  revision: string;
  roleKind: string;
}

interface ExportedResource {
  inputs?: Record<string, unknown>;
  outputs?: Record<string, unknown>;
  type: string;
  urn: string;
}

class MockRoleProvider implements dynamic.ResourceProvider {
  constructor(private readonly expectedBoundaryArn: string) {}

  private assertExactBoundary(inputs: RoleInputs): void {
    if (inputs.permissionsBoundary !== this.expectedBoundaryArn) {
      throw new Error("mock role operation received an unexpected boundary");
    }
  }

  async create(inputs: RoleInputs): Promise<dynamic.CreateResult> {
    this.assertExactBoundary(inputs);
    return {
      id: `mock-${inputs.roleKind}`,
      outs: inputs,
    };
  }

  async diff(
    _id: string,
    olds: RoleInputs,
    news: RoleInputs,
  ): Promise<dynamic.DiffResult> {
    this.assertExactBoundary(olds);
    this.assertExactBoundary(news);
    return { changes: olds.revision !== news.revision };
  }

  async update(
    _id: string,
    _olds: RoleInputs,
    news: RoleInputs,
  ): Promise<dynamic.UpdateResult> {
    this.assertExactBoundary(news);
    return { outs: news };
  }

  async delete(_id: string, props: RoleInputs): Promise<void> {
    this.assertExactBoundary(props);
  }
}

class MockRole extends dynamic.Resource {
  constructor(name: string, inputs: RoleInputs, expectedBoundaryArn: string) {
    super(new MockRoleProvider(expectedBoundaryArn), name, inputs);
  }
}

describe("workload role boundary Pulumi lifecycle", () => {
  const temporaryPaths: string[] = [];

  afterEach(async () => {
    await Promise.all(
      temporaryPaths
        .splice(0)
        .map((path) => rm(path, { force: true, recursive: true })),
    );
  });

  it("retains the exact boundary through update and role deletion", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mem9-pulumi-boundary-"));
    temporaryPaths.push(directory);
    const backendPath = join(directory, "backend");
    const pulumiHome = join(directory, "pulumi-home");
    await Promise.all([
      mkdir(backendPath, { recursive: true }),
      mkdir(pulumiHome, { recursive: true }),
    ]);
    const sstBin = join(homedir(), ".config", "sst", "bin");
    const previousPath = process.env.PATH ?? "";
    process.env.PATH = `${sstBin}${delimiter}${previousPath}`;

    const boundaryArn = `arn:aws:iam::123456789012:policy/${WORKLOAD_BOUNDARY_POLICY_NAME}`;
    try {
      const stack = await LocalWorkspace.createOrSelectStack(
        {
          projectName: "mem9-workload-boundary-lifecycle",
          stackName: "test",
          program: async () => {
            const revision = new pulumi.Config().require("revision");
            for (const roleKind of EXPECTED_WORKLOAD_ROLE_NAMES) {
              const args: RoleInputs = {
                assumeRolePolicy: "{}",
                permissionsBoundary: boundaryArn,
                revision,
                roleKind,
              };
              new MockRole(`${roleKind}-role`, args, boundaryArn);
            }
          },
        },
        {
          envVars: {
            PULUMI_BACKEND_URL: `file://${backendPath}`,
            PULUMI_CONFIG_PASSPHRASE: "local-test-only",
          },
          pulumiHome,
        },
      );

      try {
        await stack.setConfig("revision", { value: "1" });
        const createResult = await stack.up({
          onOutput: () => {},
          signal: AbortSignal.timeout(PULUMI_OPERATION_TIMEOUT_MS),
        });
        expect(createResult.summary.resourceChanges?.create).toBe(
          EXPECTED_WORKLOAD_ROLE_NAMES.length + 1,
        );

        await stack.setConfig("revision", { value: "2" });
        const updateResult = await stack.up({
          onOutput: () => {},
          signal: AbortSignal.timeout(PULUMI_OPERATION_TIMEOUT_MS),
        });
        expect(updateResult.summary.resourceChanges?.update).toBe(
          EXPECTED_WORKLOAD_ROLE_NAMES.length,
        );

        const state = await stack.exportStack();
        const resources = state.deployment.resources as ExportedResource[];
        const roles = resources.filter(
          ({ type }) => type === "pulumi-nodejs:dynamic:Resource",
        );
        expect(roles).toHaveLength(EXPECTED_WORKLOAD_ROLE_NAMES.length);
        expect(
          roles.every(
            ({ inputs, outputs }) =>
              inputs?.permissionsBoundary === boundaryArn &&
              outputs?.permissionsBoundary === boundaryArn,
          ),
        ).toBe(true);

        const destroyResult = await stack.destroy({
          onOutput: () => {},
          signal: AbortSignal.timeout(PULUMI_OPERATION_TIMEOUT_MS),
        });
        expect(destroyResult.summary.resourceChanges?.delete).toBe(
          EXPECTED_WORKLOAD_ROLE_NAMES.length + 1,
        );
      } finally {
        await stack.workspace.removeStack(stack.name);
      }
    } finally {
      process.env.PATH = previousPath;
    }
  }, 120_000);
});
