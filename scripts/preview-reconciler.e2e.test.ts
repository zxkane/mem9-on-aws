import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  runCli,
  type CommandRunner,
  type CommandResult,
} from "./preview-reconciler.mts";

const REPOSITORY = "example/mem9-on-aws";
const OLD = "2026-07-22T10:00:00.000Z";

type MockCommands = Readonly<{
  runner: CommandRunner;
  calls: Array<Readonly<{ file: string; args: readonly string[] }>>;
}>;

function json(value: unknown): CommandResult {
  return { stdout: JSON.stringify(value), stderr: "" };
}

const SG_ID = "sg-0123456789abcdef0";
const ENI_ID = "eni-0123456789abcdef0";

type MockOptions = Readonly<{
  statePresent?: boolean;
  uncorrelatedActive?: boolean;
  malformedAfterRemoval?: "state" | "tagging" | "iam";
  s3TwoPages?: boolean;
  /**
   * When true the stage's only tagged resources are the sweepable SG + ENI, i.e.
   * the shape a cleanup job cancelled mid-`sst remove` leaves behind (#146).
   */
  networkOnly?: boolean;
}>;

function mockCommands({
  statePresent = true,
  uncorrelatedActive = false,
  malformedAfterRemoval,
  s3TwoPages = false,
  networkOnly = false,
}: MockOptions = {}): MockCommands {
  const calls: Array<{ file: string; args: readonly string[] }> = [];
  let removed = false;
  const runner: CommandRunner = vi.fn(
    async (file: string, args: readonly string[]) => {
      calls.push({ file, args: [...args] });
      const endpoint = args.find((arg) => arg.startsWith(`repos/${REPOSITORY}/`));

      if (file === "aws" && args[1] === "describe-security-groups") {
        return json({
          SecurityGroups: [
            {
              GroupId: SG_ID,
              Tags: [
                { Key: "Project", Value: "mem9-on-aws" },
                { Key: "ManagedBy", Value: "sst" },
                { Key: "Stage", Value: "pr-7" },
              ],
            },
          ],
        });
      }
      if (file === "aws" && args[1] === "describe-network-interfaces") {
        return json({
          NetworkInterfaces: [
            {
              NetworkInterfaceId: ENI_ID,
              Status: "available",
              RequesterManaged: false,
              Tags: [
                { Key: "Project", Value: "mem9-on-aws" },
                { Key: "ManagedBy", Value: "sst" },
                { Key: "Stage", Value: "pr-7" },
              ],
            },
          ],
        });
      }
      if (
        file === "aws" &&
        (args[1] === "delete-network-interface" || args[1] === "delete-security-group")
      ) {
        return { stdout: "", stderr: "" };
      }

      if (file === "gh" && endpoint === `repos/${REPOSITORY}/pulls`) {
        return json([
          [
            {
              number: 7,
              state: "closed",
              closed_at: OLD,
              head: { sha: "preview-sha-7", ref: "preview-branch-7" },
            },
          ],
        ]);
      }
      if (
        file === "gh" &&
        endpoint === `repos/${REPOSITORY}/actions/workflows/infra-ci.yml/runs`
      ) {
        return json([
          {
            workflow_runs: [
              {
                id: 700,
                status: uncorrelatedActive ? "in_progress" : "completed",
                updated_at: uncorrelatedActive ? null : OLD,
                head_sha: uncorrelatedActive
                  ? "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                  : "preview-sha-7",
                head_branch: uncorrelatedActive
                  ? "unknown-branch"
                  : "preview-branch-7",
                pull_requests: [],
              },
            ],
          },
        ]);
      }
      if (
        file === "gh" &&
        endpoint ===
          `repos/${REPOSITORY}/commits/deadbeefdeadbeefdeadbeefdeadbeefdeadbeef/pulls`
      ) {
        return json([]);
      }
      if (
        file === "gh" &&
        endpoint === `repos/${REPOSITORY}/issues` &&
        args.includes("GET")
      ) {
        return json([[]]);
      }
      if (
        file === "gh" &&
        endpoint === `repos/${REPOSITORY}/issues` &&
        args.includes("POST")
      ) {
        return json({ number: 77 });
      }
      if (file === "aws" && args[0] === "ssm") {
        return json({ Parameter: { Value: JSON.stringify({ state: "state-bucket" }) } });
      }
      if (file === "aws" && args[0] === "s3api") {
        if (removed) {
          return json(malformedAfterRemoval === "state" ? {} : { KeyCount: 0, IsTruncated: false });
        }
        if (s3TwoPages && !args.includes("--continuation-token")) {
          return json({ KeyCount: 0, IsTruncated: true, NextContinuationToken: "second-page" });
        }
        if (!statePresent) return json({ KeyCount: 0, IsTruncated: false });
        return json({
          Contents: [{ Key: "app/mem9-on-aws/pr-7.json", LastModified: OLD }],
          KeyCount: 1,
          IsTruncated: false,
        });
      }
      if (file === "aws" && args[0] === "s3" && args[1] === "cp") {
        return json({
          checkpoint: {
            latest: statePresent ? { resources: [{ urn: "fixture" }] } : {},
            stack: "fixture",
          },
          version: 3,
        });
      }
      if (file === "aws" && args[0] === "resourcegroupstaggingapi") {
        if (removed && malformedAfterRemoval === "tagging") return json({});
        const stageTags = [
          { Key: "Project", Value: "mem9-on-aws" },
          { Key: "ManagedBy", Value: "sst" },
          { Key: "Stage", Value: "pr-7" },
        ];
        return json({
          ResourceTagMappingList: removed ? [] : networkOnly
            ? [
                {
                  ResourceARN: `arn:aws:ec2:ap-northeast-1:123456789012:security-group/${SG_ID}`,
                  Tags: stageTags,
                },
                {
                  ResourceARN: `arn:aws:ec2:ap-northeast-1:123456789012:network-interface/${ENI_ID}`,
                  Tags: stageTags,
                },
              ]
            : [
                {
                  ResourceARN:
                    "arn:aws:ecs:ap-northeast-1:123456789012:service/private-name",
                  Tags: stageTags,
                },
              ],
        });
      }
      if (file === "aws" && args[0] === "ecs" && args[1] === "describe-services") {
        const serviceArn = args[args.indexOf("--services") + 1];
        return json({
          failures: [],
          services: [{ serviceArn, status: "ACTIVE" }],
        });
      }
      if (file === "aws" && args[0] === "iam" && args[1] === "list-roles") {
        if (removed && malformedAfterRemoval === "iam") return json({});
        return json({
          Roles: removed || networkOnly
            ? [{ RoleName: "github-actions-mem9-on-aws" }]
            : [
                { RoleName: "github-actions-mem9-on-aws" },
                { RoleName: "mem9-on-aws-pr-7-task-role" },
              ],
        });
      }
      if (file === "aws" && args[0] === "iam" && args[1] === "list-role-tags") {
        return json({
          Tags: [
            { Key: "Project", Value: "mem9-on-aws" },
            { Key: "ManagedBy", Value: "sst" },
            { Key: "Stage", Value: "pr-7" },
          ],
        });
      }
      if (file === "pnpm") {
        removed = true;
        return { stdout: "", stderr: "" };
      }
      throw new Error(`Unexpected mock command: ${file} ${args.join(" ")}`);
    },
  );
  return { runner, calls };
}

async function withPlan(
  callback: (planPath: string) => Promise<void>,
): Promise<void> {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "preview-reconciler-e2e-"),
  );
  try {
    await callback(path.join(directory, "plan.json"));
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("preview reconciler CLI with mocked GitHub/AWS commands", () => {
  it("TC-PREVIEW-RECON-088 reads a preview state on the second S3 API page", async () => {
    await withPlan(async (planPath) => {
      const commands = mockCommands({ s3TwoPages: true });
      vi.spyOn(console, "log").mockImplementation(() => undefined);
      await runCli([
        "plan", "--repository", REPOSITORY,
        "--event", "schedule", "--plan", planPath,
      ], commands.runner);
      const plan = JSON.parse(await fs.readFile(planPath, "utf8"));
      expect(plan.stages.map((stage: { stage: string }) => stage.stage)).toContain("pr-7");
      const lists = commands.calls.filter(({ file, args }) => file === "aws" && args[1] === "list-objects-v2");
      expect(lists).toHaveLength(2);
      expect(lists[0].args).toContain("--no-paginate");
      expect(lists[1].args).toContain("second-page");
    });
  });

  it.each([
    { name: "missing Contents", page: { KeyCount: 1, IsTruncated: false }, error: "Invalid SST state listing" },
    { name: "wrong KeyCount", page: { KeyCount: 1, Contents: [], IsTruncated: false }, error: "Invalid SST state page count" },
    { name: "repeated token", page: { KeyCount: 0, IsTruncated: true, NextContinuationToken: "same" }, error: "Invalid SST state continuation token" },
  ])("TC-PREVIEW-RECON-089 rejects S3 pagination with $name", async ({ page, error }) => {
    await withPlan(async (planPath) => {
      const commands = mockCommands();
      const runner: CommandRunner = (file, args, label, allowedFailure) =>
        file === "aws" && args[1] === "list-objects-v2"
          ? Promise.resolve(json(page))
          : commands.runner(file, args, label, allowedFailure);
      await expect(runCli([
        "plan", "--repository", REPOSITORY,
        "--event", "schedule", "--plan", planPath,
      ], runner)).rejects.toThrow(error);
      expect(commands.calls.some(({ file }) => file === "pnpm")).toBe(false);
    });
  });

  it.each(["schedule", "workflow_dispatch"] as const)(
    "TC-PREVIEW-RECON-024 %s report makes no mutating call",
    async (eventName) => {
      await withPlan(async (planPath) => {
        const commands = mockCommands();
        vi.spyOn(console, "log").mockImplementation(() => undefined);

        await runCli(
          [
            "plan",
            "--repository",
            REPOSITORY,
            "--event",
            eventName,
            "--plan",
            planPath,
          ],
          commands.runner,
        );

        expect(commands.calls).not.toContainEqual(
          expect.objectContaining({ file: "pnpm" }),
        );
        expect(
          commands.calls.some(
            ({ file, args }) =>
              file === "gh" && (args.includes("POST") || args.includes("PATCH")),
          ),
        ).toBe(false);
      });
    },
  );

  it("TC-PREVIEW-RECON-025 apply invokes SST only after CLI revalidation", async () => {
    await withPlan(async (planPath) => {
      const commands = mockCommands();
      vi.spyOn(console, "log").mockImplementation(() => undefined);

      await runCli(
        [
          "plan",
          "--repository",
          REPOSITORY,
          "--event",
          "workflow_dispatch",
          "--plan",
          planPath,
        ],
        commands.runner,
      );
      await runCli(
        [
          "apply",
          "--repository",
          REPOSITORY,
          "--event",
          "workflow_dispatch",
          "--mode",
          "apply",
          "--plan",
          planPath,
        ],
        commands.runner,
      );

      expect(
        commands.calls.filter(({ file }) => file === "pnpm").map(({ args }) => args),
      ).toEqual([
        ["-C", "infra", "exec", "sst", "remove", "--stage", "pr-7"],
      ]);
      expect(
        commands.calls.filter(
          ({ file, args }) =>
            file === "gh" &&
            args.includes(`repos/${REPOSITORY}/actions/workflows/infra-ci.yml/runs`),
        ),
      ).toHaveLength(3);
    });
  });

  it("fails closed when an active workflow remains uncorrelated", async () => {
    await withPlan(async (planPath) => {
      const commands = mockCommands({ uncorrelatedActive: true });
      vi.spyOn(console, "log").mockImplementation(() => undefined);

      await runCli(
        [
          "plan",
          "--repository",
          REPOSITORY,
          "--event",
          "schedule",
          "--plan",
          planPath,
        ],
        commands.runner,
      );

      const plan = JSON.parse(await fs.readFile(planPath, "utf8")) as {
        stages: Array<{ decision: string; reasons: string[] }>;
      };
      expect(plan.stages[0]).toMatchObject({
        decision: "retain",
        reasons: expect.arrayContaining(["deploy-active"]),
      });
      expect(
        commands.calls.some(
          ({ file, args }) =>
            file === "gh" &&
            args.includes(
              `repos/${REPOSITORY}/commits/deadbeefdeadbeefdeadbeefdeadbeefdeadbeef/pulls`,
            ),
        ),
      ).toBe(true);
    });
  });

  it("TC-PREVIEW-RECON-026 state-missing apply creates an issue, never removes", async () => {
    await withPlan(async (planPath) => {
      const commands = mockCommands({ statePresent: false });
      vi.spyOn(console, "log").mockImplementation(() => undefined);

      await runCli(
        [
          "plan",
          "--repository",
          REPOSITORY,
          "--event",
          "workflow_dispatch",
          "--plan",
          planPath,
        ],
        commands.runner,
      );
      await runCli(
        [
          "apply",
          "--repository",
          REPOSITORY,
          "--event",
          "workflow_dispatch",
          "--mode",
          "apply",
          "--plan",
          planPath,
        ],
        commands.runner,
      );

      expect(commands.calls.some(({ file }) => file === "pnpm")).toBe(false);
      const create = commands.calls.find(
        ({ file, args }) =>
          file === "gh" &&
          args.includes(`repos/${REPOSITORY}/issues`) &&
          args.includes("POST"),
      );
      expect(create?.args.join("\n")).toMatch(
        /\|\s*pr-7\s*\|\s*(ecs:service|iam:role)\s*\|\s*1\s*\|/,
      );
      expect(create?.args.join("\n")).not.toMatch(
        /\barn:|https?:\/\/|\b[0-9]{12}\b/i,
      );
      expect(
        commands.calls.some(
          ({ file, args }) =>
            file === "aws" && args[0] === "iam" && args[1] === "list-role-tags",
        ),
      ).toBe(true);
    });
  });

  it("TC-PREVIEW-RECON-085 auto CLI uses a fresh plan and confirms SST removal", async () => {
    const commands = mockCommands();
    const logged: string[] = [];
    const previous = process.env.PREVIEW_AUTO_CLEANUP_ENABLED;
    process.env.PREVIEW_AUTO_CLEANUP_ENABLED = "true";
    vi.spyOn(console, "log").mockImplementation((message: unknown) => {
      logged.push(String(message));
    });
    try {
      await runCli([
        "auto", "--repository", REPOSITORY,
        "--event", "schedule", "--mode", "auto",
      ], commands.runner);
    } finally {
      if (previous === undefined) delete process.env.PREVIEW_AUTO_CLEANUP_ENABLED;
      else process.env.PREVIEW_AUTO_CLEANUP_ENABLED = previous;
    }

    const removals = commands.calls.filter(({ file }) => file === "pnpm");
    expect(removals).toHaveLength(1);
    expect(removals[0].args).toEqual(["-C", "infra", "exec", "sst", "remove", "--stage", "pr-7"]);
    expect(logged).toContain("Automatic preview cleanup selected pr-7");
    expect(logged).toContain("Removed preview stage pr-7");
    expect(commands.calls.filter(({ file, args }) => file === "aws" && args[1] === "list-objects-v2"))
      .toHaveLength(4);
    expect(commands.calls.some(({ file, args }) => file === "gh" && args.includes("POST")))
      .toBe(false);
  });

  it.each([
    { source: "state", message: "Invalid SST state page metadata" },
    { source: "tagging", message: "Invalid AWS tagged-resource list" },
    { source: "iam", message: "Invalid IAM role list" },
  ] as const)("TC-PREVIEW-RECON-086 rejects a malformed $source post-removal inventory", async ({ source, message }) => {
    const commands = mockCommands({ malformedAfterRemoval: source });
    const previous = process.env.PREVIEW_AUTO_CLEANUP_ENABLED;
    process.env.PREVIEW_AUTO_CLEANUP_ENABLED = "true";
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    try {
      await expect(runCli([
        "auto", "--repository", REPOSITORY,
        "--event", "schedule", "--mode", "auto",
      ], commands.runner)).rejects.toThrow(message);
    } finally {
      if (previous === undefined) delete process.env.PREVIEW_AUTO_CLEANUP_ENABLED;
      else process.env.PREVIEW_AUTO_CLEANUP_ENABLED = previous;
    }
    expect(commands.calls.filter(({ file }) => file === "pnpm")).toHaveLength(1);
  });

  it("TC-PREVIEW-RECON-087 rejects malformed workflow and IAM tag pages before removal", async () => {
    const commands = mockCommands();
    const previous = process.env.PREVIEW_AUTO_CLEANUP_ENABLED;
    process.env.PREVIEW_AUTO_CLEANUP_ENABLED = "true";
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    try {
      for (const malformed of ["workflow", "iam-tags"] as const) {
        const runner: CommandRunner = async (file, args, label, allowedFailure) => {
          if (malformed === "workflow" && file === "gh" &&
              args.includes(`repos/${REPOSITORY}/actions/workflows/infra-ci.yml/runs`)) {
            return json([{}]);
          }
          if (malformed === "iam-tags" && file === "aws" && args[1] === "list-role-tags") {
            return json({});
          }
          return commands.runner(file, args, label, allowedFailure);
        };
        await expect(runCli([
          "auto", "--repository", REPOSITORY,
          "--event", "schedule", "--mode", "auto",
        ], runner)).rejects.toThrow(
          malformed === "workflow" ? "Invalid GitHub workflow-run page" : "Invalid IAM role tag list",
        );
      }
    } finally {
      if (previous === undefined) delete process.env.PREVIEW_AUTO_CLEANUP_ENABLED;
      else process.env.PREVIEW_AUTO_CLEANUP_ENABLED = previous;
    }
    expect(commands.calls.some(({ file }) => file === "pnpm")).toBe(false);
  });

  it("TC-PREVIEW-RECON-090 refuses cleanup when SST bootstrap cannot be read", async () => {
    const commands = mockCommands({ statePresent: false, networkOnly: true });
    const previous = process.env.PREVIEW_AUTO_CLEANUP_ENABLED;
    process.env.PREVIEW_AUTO_CLEANUP_ENABLED = "true";
    const runner: CommandRunner = (file, args, label, allowedFailure) =>
      file === "aws" && args[0] === "ssm" && args[1] === "get-parameter"
        ? Promise.resolve(null)
        : commands.runner(file, args, label, allowedFailure);
    try {
      await expect(runCli([
        "auto", "--repository", REPOSITORY,
        "--event", "schedule", "--mode", "auto",
      ], runner)).rejects.toThrow("SST bootstrap parameter is missing");
    } finally {
      if (previous === undefined) delete process.env.PREVIEW_AUTO_CLEANUP_ENABLED;
      else process.env.PREVIEW_AUTO_CLEANUP_ENABLED = previous;
    }
    expect(commands.calls.some(({ file, args }) => file === "aws" && args[1]?.startsWith("delete-")))
      .toBe(false);
  });

  // #146. The end-to-end shape of the leak: state gone, only the SG + its detached
  // ENIs left. This must now finish the stage instead of filing an issue about it.
  it("TC-PREVIEW-RECON-047 sweeps SG-and-ENI-only leftovers, ENI before SG", async () => {
    await withPlan(async (planPath) => {
      const commands = mockCommands({ statePresent: false, networkOnly: true });
      const logged: string[] = [];
      vi.spyOn(console, "log").mockImplementation((message: unknown) => {
        logged.push(String(message));
      });

      for (const command of ["plan", "apply"] as const) {
        await runCli(
          [
            command,
            "--repository",
            REPOSITORY,
            "--event",
            "workflow_dispatch",
            ...(command === "apply" ? ["--mode", "apply"] : []),
            "--plan",
            planPath,
          ],
          commands.runner,
        );
      }

      const deleteOrder = commands.calls
        .filter(({ file, args }) => file === "aws" && args[1]?.startsWith("delete-"))
        .map(({ args }) => args[1]);
      // ORDER IS THE WHOLE POINT: DeleteSecurityGroup returns DependencyViolation
      // while an ENI still references the group, so SG-first leaves BOTH behind —
      // the leak itself. Asserted as an exact sequence, not a set.
      expect(deleteOrder).toEqual(["delete-network-interface", "delete-security-group"]);

      // No SST removal (state is gone — it would fail) and no operator issue.
      expect(commands.calls.some(({ file }) => file === "pnpm")).toBe(false);
      expect(
        commands.calls.some(
          ({ file, args }) =>
            file === "gh" &&
            args.includes(`repos/${REPOSITORY}/issues`) &&
            args.includes("POST"),
        ),
      ).toBe(false);
      expect(logged.join("\n")).toContain("Swept orphaned network scaffolding");
    });
  });
});
