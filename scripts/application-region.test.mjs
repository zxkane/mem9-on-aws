import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";
import { parse } from "yaml";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const resolverPath = resolve(here, "resolve-application-region.mjs");
const tempDirs = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function fixtureConfig(regionExpression, { preamble = [] } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "mem9-app-region-"));
  tempDirs.push(dir);
  const path = join(dir, "sst.config.ts");
  writeFileSync(
    path,
    [
      ...preamble,
      "export default $config({",
      "  app() {",
      "    return {",
      "      providers: { aws: {",
      `        region: ${regionExpression},`,
      "      } },",
      "    };",
      "  },",
      "  run() {},",
      "});",
      "",
    ].join("\n"),
  );
  return path;
}

async function loadResolver() {
  return import(
    pathToFileURL(resolve(here, "lib/application-region.mjs")).href
  );
}

describe("application region resolver", () => {
  it("TC-APPREGION-001: reads the checked-in SST AWS provider", async () => {
    const { resolveApplicationRegion } = await loadResolver();
    const region = await resolveApplicationRegion();
    expect(region).toMatch(/^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$/u);

    const cli = spawnSync(process.execPath, [resolverPath], {
      cwd: root,
      encoding: "utf8",
    });
    expect(cli.status, cli.stderr).toBe(0);
    expect(cli.stdout).toBe(`${region}\n`);
  });

  it("TC-APPREGION-002: follows a non-Tokyo SST provider region", async () => {
    const { resolveApplicationRegion } = await loadResolver();
    const configPath = fixtureConfig('"ap-southeast-1"');

    await expect(resolveApplicationRegion({ configPath })).resolves.toBe(
      "ap-southeast-1",
    );

    const cli = spawnSync(
      process.execPath,
      [resolverPath, "--config", configPath],
      { cwd: root, encoding: "utf8" },
    );
    expect(cli.status, cli.stderr).toBe(0);
    expect(cli.stdout).toBe("ap-southeast-1\n");
  });

  it.each([
    ["missing", "undefined"],
    ["non-string", "42"],
    ["malformed", '"tokyo"'],
  ])("TC-APPREGION-003: rejects a %s provider region", async (_name, value) => {
    const { resolveApplicationRegion } = await loadResolver();
    const configPath = fixtureConfig(value);

    await expect(resolveApplicationRegion({ configPath })).rejects.toThrow(
      /AWS provider region/u,
    );
  });

  it("TC-APPREGION-004: serializes concurrent imports and restores $config", async () => {
    const { resolveApplicationRegion } = await loadResolver();
    let releaseFirst;
    let releaseSecond;
    const firstRelease = new Promise((resolvePromise) => {
      releaseFirst = resolvePromise;
    });
    const secondRelease = new Promise((resolvePromise) => {
      releaseSecond = resolvePromise;
    });
    const firstPath = fixtureConfig('"eu-west-1"', {
      preamble: [
        "globalThis.__applicationRegionFirstEntered = true;",
        "await globalThis.__applicationRegionFirstRelease;",
      ],
    });
    const secondPath = fixtureConfig('"ap-southeast-1"', {
      preamble: ["await globalThis.__applicationRegionSecondRelease;"],
    });
    const previousConfig = globalThis.$config;
    const sentinel = () => {
      throw new Error("test sentinel must never evaluate an SST config");
    };
    globalThis.$config = sentinel;
    globalThis.__applicationRegionFirstRelease = firstRelease;
    globalThis.__applicationRegionSecondRelease = secondRelease;

    try {
      const first = resolveApplicationRegion({ configPath: firstPath });
      while (globalThis.__applicationRegionFirstEntered !== true) {
        await new Promise((resolvePromise) => setImmediate(resolvePromise));
      }
      const second = resolveApplicationRegion({ configPath: secondPath });
      releaseFirst();
      await expect(first).resolves.toBe("eu-west-1");
      releaseSecond();
      await expect(second).resolves.toBe("ap-southeast-1");
      expect(globalThis.$config).toBe(sentinel);
    } finally {
      releaseFirst();
      releaseSecond();
      delete globalThis.__applicationRegionFirstEntered;
      delete globalThis.__applicationRegionFirstRelease;
      delete globalThis.__applicationRegionSecondRelease;
      if (previousConfig === undefined) delete globalThis.$config;
      else globalThis.$config = previousConfig;
    }
  });
});

describe("application region consumers", () => {
  it("TC-APPREGION-010/011: removes copied application-region literals", () => {
    const literalFreeFiles = [
      ".env.example",
      ".github/workflows/infra-ci.yml",
      ".github/workflows/reconcile-previews.yml",
      "infra/ecr.ts",
      "infra/ecs.ts",
      "infra/cloudformation/bedrock-mantle-project.yaml",
      "infra/cloudformation/ecr-repositories.yaml",
      "infra/cloudformation/github-actions-role.yaml",
      "infra/cloudformation/workload-permissions-boundary.yaml",
      "scripts/deploy-bedrock-mantle-project.sh",
      "scripts/deploy-ecr-registry-scanning.sh",
      "scripts/deploy-ecr-repositories.sh",
      "scripts/deploy-github-role.sh",
      "scripts/deploy-workload-permissions-boundary.sh",
      "scripts/rollout-workload-permissions-boundary.sh",
      "scripts/run-bootstrap-task.sh",
      "scripts/run-consolidation-task.sh",
      "scripts/run-mcp-e2e.sh",
      "scripts/run-oauth-facade-smoke.sh",
      "scripts/run-slack-approval-e2e.sh",
    ];

    for (const relativePath of literalFreeFiles) {
      expect(
        readFileSync(resolve(root, relativePath), "utf8"),
        relativePath,
      ).not.toContain("ap-northeast-1");
    }
  });

  it("TC-APPREGION-012: passes the resolved region to every AWS workflow job", () => {
    for (const workflowName of ["infra-ci.yml", "reconcile-previews.yml"]) {
      const workflow = parse(
        readFileSync(resolve(root, ".github/workflows", workflowName), "utf8"),
      );
      const regionJob = workflow.jobs?.["application-region"];
      expect(regionJob, workflowName).toBeDefined();
      expect(JSON.stringify(regionJob)).toContain(
        "node scripts/resolve-application-region.mjs",
      );
      if (workflowName === "infra-ci.yml") {
        expect(regionJob.steps[0].with?.ref).toContain(
          "github.event.pull_request.head.sha",
        );
        expect(regionJob.outputs.cleanup_region).toContain(
          "steps.resolve.outputs.cleanup_region",
        );
        expect(JSON.stringify(regionJob)).toContain(
          ".application-region-base/sst.config.ts",
        );
        expect(JSON.stringify(regionJob)).toContain(
          "Application region changes cannot deploy PR previews",
        );
      }

      for (const [jobName, job] of Object.entries(workflow.jobs ?? {})) {
        const configuresAws = (job.steps ?? []).some(
          ({ uses }) =>
            typeof uses === "string" &&
            uses.startsWith("aws-actions/configure-aws-credentials@"),
        );
        if (!configuresAws) continue;
        expect(job.needs, `${workflowName}:${jobName}`).toContain(
          "application-region",
        );
        const regionOutput =
          jobName === "cleanup-preview" ? "cleanup_region" : "region";
        expect(job.env?.AWS_REGION, `${workflowName}:${jobName}`).toContain(
          `needs.application-region.outputs.${regionOutput}`,
        );
      }
    }
  });

  it("TC-APPREGION-013: operator scripts resolve their application default", () => {
    for (const relativePath of [
      "scripts/deploy-bedrock-mantle-project.sh",
      "scripts/deploy-ecr-registry-scanning.sh",
      "scripts/deploy-ecr-repositories.sh",
      "scripts/deploy-github-role.sh",
      "scripts/deploy-workload-permissions-boundary.sh",
      "scripts/memory-cleanup.mjs",
      "scripts/memory-consolidation.mjs",
      "scripts/rollout-workload-permissions-boundary.sh",
      "scripts/run-bootstrap-task.sh",
      "scripts/run-consolidation-task.sh",
      "scripts/run-mcp-e2e.sh",
      "scripts/run-oauth-facade-smoke.sh",
      "scripts/run-slack-approval-e2e.sh",
    ]) {
      expect(
        readFileSync(resolve(root, relativePath), "utf8"),
        relativePath,
      ).toContain("application-region.mjs");
    }
  });

  it("TC-APPREGION-014: never gives the runtime proxy a Tokyo fallback", () => {
    const server = readFileSync(
      resolve(root, "docker/llm-proxy/server.mjs"),
      "utf8",
    );
    expect(server).not.toMatch(
      /LLM_PROXY_REGION\s*\|\|\s*env\.AWS_REGION\s*\|\|\s*["']ap-northeast-1/u,
    );
  });

  it("TC-APPREGION-015: uses the commercial-region RDS CA bundle", () => {
    const dockerfile = readFileSync(
      resolve(root, "docker/llm-proxy/Dockerfile"),
      "utf8",
    );
    expect(dockerfile).toContain(
      "https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem",
    );
    expect(dockerfile).toContain("NODE_EXTRA_CA_CERTS=/app/global-bundle.pem");
    expect(dockerfile).toContain(
      "COPY scripts/lib/application-region.mjs /app/scripts/lib/application-region.mjs",
    );
  });

  it("TC-APPREGION-020/021: keeps the Responses fallback independent", () => {
    for (const relativePath of [
      "infra/ecs.ts",
      "infra/consolidation.ts",
      "infra/slack-approval.ts",
      "docker/llm-proxy/server.mjs",
    ]) {
      const source = readFileSync(resolve(root, relativePath), "utf8");
      expect(source, relativePath).toMatch(
        /RESPONSES_REGION[\s\S]{0,120}us-west-2/u,
      );
    }
  });

  it("TC-APPREGION-023: passes a custom Responses region through CI", () => {
    const workflow = parse(
      readFileSync(
        resolve(root, ".github/workflows/infra-ci.yml"),
        "utf8",
      ),
    );
    for (const jobName of ["deploy-preview", "deploy-prod"]) {
      const job = workflow.jobs[jobName];
      expect(
        job.env?.MEM9_LLM_RESPONSES_REGION,
        `${jobName}:runtime region`,
      ).toContain("vars.MEM9_LLM_RESPONSES_REGION");
    }
    const boundaryScript = readFileSync(
      resolve(root, "scripts/deploy-workload-permissions-boundary.sh"),
      "utf8",
    );
    expect(boundaryScript).toContain(
      'openai_project_region="${MEM9_LLM_RESPONSES_REGION:-',
    );
    const projectScript = readFileSync(
      resolve(root, "scripts/deploy-bedrock-mantle-project.sh"),
      "utf8",
    );
    expect(projectScript).toContain(
      'PROJECT_VARIABLE="MEM9_BEDROCK_PROJECT_OPENAI"',
    );
    expect(projectScript).toContain(
      'PROJECT_VARIABLE="MEM9_BEDROCK_PROJECT"',
    );
  });

  it("TC-APPREGION-016: closes previews in the PR base region", () => {
    const workflow = parse(
      readFileSync(
        resolve(root, ".github/workflows/infra-ci.yml"),
        "utf8",
      ),
    );
    const cleanup = workflow.jobs["cleanup-preview"];
    expect(cleanup.env.AWS_REGION).toContain(
      "needs.application-region.outputs.cleanup_region",
    );
    const checkout = cleanup.steps.find(
      ({ uses }) => uses === "actions/checkout@v7",
    );
    expect(checkout.with.ref).toContain("github.event.pull_request.base.sha");
  });

  it("TC-APPREGION-030/031: separates current guidance from historical facts", () => {
    for (const relativePath of [
      "README.md",
      "AGENTS.md",
      "docs/ARCHITECTURE.md",
    ]) {
      const source = readFileSync(resolve(root, relativePath), "utf8");
      expect(source, relativePath).toContain("sst.config.ts");
      expect(source, relativePath).not.toContain(
        "PROJECT_REGION selects the application region",
      );
      expect(source, relativePath).not.toContain(
        "pins that plane to `ap-northeast-1`",
      );
      expect(source, relativePath).not.toContain(
        "--region ap-northeast-1",
      );
    }

    const facts = readFileSync(
      resolve(root, "docs/mem9-facts.md"),
      "utf8",
    );
    expect(facts).toContain("empirically live 2026-07-12");
    expect(facts).toContain("bedrock-mantle.ap-northeast-1.api.aws");
  });
});
