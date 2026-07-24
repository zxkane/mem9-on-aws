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

function mockCommands(
  statePresent = true,
  uncorrelatedActive = false,
): MockCommands {
  const calls: Array<{ file: string; args: readonly string[] }> = [];
  const runner: CommandRunner = vi.fn(
    async (file: string, args: readonly string[]) => {
    calls.push({ file, args: [...args] });
    const endpoint = args.find((arg) => arg.startsWith(`repos/${REPOSITORY}/`));

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
      return json({
        Contents: statePresent
          ? [
              {
                Key: "app/mem9-on-aws/pr-7.json",
                LastModified: OLD,
              },
            ]
          : [],
      });
    }
    if (file === "aws" && args[0] === "resourcegroupstaggingapi") {
      return json({
        ResourceTagMappingList: [
          {
            ResourceARN:
              "arn:aws:ecs:ap-northeast-1:123456789012:service/private-name",
            Tags: [
              { Key: "Project", Value: "mem9-on-aws" },
              { Key: "ManagedBy", Value: "sst" },
              { Key: "Stage", Value: "pr-7" },
            ],
          },
        ],
      });
    }
    if (file === "aws" && args[0] === "iam" && args[1] === "list-roles") {
      return json({
        Roles: [
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
    if (file === "pnpm") return { stdout: "", stderr: "" };
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
      const commands = mockCommands(true, true);
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
      const commands = mockCommands(false);
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
});
