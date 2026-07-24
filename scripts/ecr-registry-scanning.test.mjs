import { chmod, copyFile, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";
import { parse } from "yaml";
import {
  decideRegistryScanningAction,
  projectRepositories,
  repositoryMatchesFilter,
} from "./lib/ecr-registry-scanning-preflight.mjs";

const scriptsDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = dirname(scriptsDir);
const fixtureDir = join(scriptsDir, "test-fixtures", "ecr-registry-scanning");
const wrapper = join(scriptsDir, "deploy-ecr-registry-scanning.sh");
const tempDirs = [];
const cloudFormationTags = [
  ...["!Ref", "!Sub", "!GetAtt"].map((tag) => ({ tag, resolve: (value) => value })),
  ...["!If", "!Equals"].map((tag) => ({
    tag,
    collection: "seq",
    resolve: (value) => value,
  })),
];

const missingStack = {
  stackExists: false,
  ownsResource: false,
  stackStatus: null,
};
const ownedStack = {
  stackExists: true,
  ownsResource: true,
  stackStatus: "UPDATE_COMPLETE",
};

async function fixture(name) {
  return JSON.parse(await readFile(join(fixtureDir, name), "utf8"));
}

function parseCloudFormation(source) {
  return parse(source, { customTags: cloudFormationTags });
}

async function runWrapper(fixture, stackState) {
  const dir = await mkdtemp(join(tmpdir(), "ecr-scan-wrapper-"));
  tempDirs.push(dir);
  const mockAws = join(dir, "aws");
  const log = join(dir, "aws.log");
  await copyFile(join(fixtureDir, "mock-aws.sh"), mockAws);
  await chmod(mockAws, 0o755);

  const result = spawnSync("bash", [wrapper], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${dir}${delimiter}${process.env.PATH}`,
      MOCK_AWS_LOG: log,
      MOCK_CURRENT_CONFIG: join(fixtureDir, fixture),
      MOCK_STACK_STATE: stackState,
    },
  });

  return {
    ...result,
    calls: await readFile(log, "utf8"),
  };
}

function mutationCalls(calls) {
  return calls
    .split("\n")
    .filter((line) =>
      /cloudformation (create-stack|update-stack|delete-stack)|ecr put-/.test(line),
    );
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("registry scanning preflight decision", () => {
  it("TC-ECR-SCAN-001: allows adoption only from the default BASIC configuration", async () => {
    expect(
      decideRegistryScanningAction({
        current: {},
        ownership: missingStack,
        projectName: "mem9-on-aws",
      }).action,
    ).toBe("adopt");
    expect(
      decideRegistryScanningAction({
        current: await fixture("default.json"),
        ownership: missingStack,
        projectName: "mem9-on-aws",
      }).action,
    ).toBe("adopt");
  });

  it("TC-ECR-SCAN-002: verifies an equivalent stack-owned declaration", async () => {
    expect(
      decideRegistryScanningAction({
        current: await fixture("declared.json"),
        ownership: ownedStack,
        projectName: "mem9-on-aws",
      }).action,
    ).toBe("verify-owned");
  });

  it("TC-ECR-SCAN-003: updates stack-owned drift from the complete declaration", async () => {
    expect(
      decideRegistryScanningAction({
        current: await fixture("owned-drift.json"),
        ownership: ownedStack,
        projectName: "mem9-on-aws",
      }).action,
    ).toBe("update-owned");
  });

  it("TC-ECR-SCAN-004: treats complete external BASIC scan-on-push coverage as verify-only", async () => {
    expect(
      decideRegistryScanningAction({
        current: await fixture("external-compliant.json"),
        ownership: missingStack,
        projectName: "mem9-on-aws",
      }).action,
    ).toBe("verify-only");
  });

  it("TC-ECR-SCAN-005: fails closed on external sibling-only rules", async () => {
    expect(
      decideRegistryScanningAction({
        current: await fixture("external-sibling.json"),
        ownership: missingStack,
        projectName: "mem9-on-aws",
      }).action,
    ).toBe("fail-closed");
  });

  it("TC-ECR-SCAN-006: fails closed on externally managed ENHANCED scanning", async () => {
    expect(
      decideRegistryScanningAction({
        current: await fixture("enhanced.json"),
        ownership: missingStack,
        projectName: "mem9-on-aws",
      }).action,
    ).toBe("fail-closed");
  });

  it("TC-ECR-SCAN-007: reports incomplete external project coverage", async () => {
    const decision = decideRegistryScanningAction({
      current: await fixture("partial.json"),
      ownership: missingStack,
      projectName: "mem9-on-aws",
    });

    expect(decision.action).toBe("fail-closed");
    expect(decision.uncoveredRepositories).toEqual([
      "mem9-on-aws/bootstrap",
      "mem9-on-aws/llm-proxy",
    ]);
  });

  it("TC-ECR-SCAN-008: implements exact ECR filter semantics and complete repository inventory", () => {
    const repositories = projectRepositories("mem9-on-aws");
    expect(repositories).toEqual([
      "mem9-on-aws/mnemo-server",
      "mem9-on-aws/qwen3-embed",
      "mem9-on-aws/bootstrap",
      "mem9-on-aws/llm-proxy",
    ]);
    for (const repository of repositories) {
      expect(repositoryMatchesFilter(repository, "mem9-on-aws/*")).toBe(true);
    }
    expect(repositoryMatchesFilter("mem9-on-aws-other/image", "mem9-on-aws/*")).toBe(false);
    expect(repositoryMatchesFilter("other/mem9-on-aws/image", "mem9-on-aws/*")).toBe(false);
    expect(repositoryMatchesFilter("mem9-on-aws", "mem9-on-aws/*")).toBe(false);
    expect(repositoryMatchesFilter("mem9-on-aws-other/image", "mem9-on-aws*")).toBe(true);
    expect(repositoryMatchesFilter("other/mem9-on-aws/image", "mem9-on-aws")).toBe(true);
  });

  it("TC-ECR-SCAN-009: fails closed when the stack name exists without ownership", async () => {
    expect(
      decideRegistryScanningAction({
        current: await fixture("default.json"),
        ownership: {
          stackExists: true,
          ownsResource: false,
          stackStatus: "UPDATE_COMPLETE",
        },
        projectName: "mem9-on-aws",
      }).action,
    ).toBe("fail-closed");
  });
});

describe("CloudFormation declarations", () => {
  it("TC-ECR-SCAN-010: declares only the narrow BASIC scan-on-push singleton", async () => {
    const source = await readFile(
      join(repoRoot, "infra", "cloudformation", "ecr-registry-scanning.yaml"),
      "utf8",
    );
    const template = parseCloudFormation(source);
    const resources = Object.values(template.Resources);
    expect(resources).toHaveLength(1);
    expect(resources[0]).toMatchObject({
      Type: "AWS::ECR::RegistryScanningConfiguration",
      DeletionPolicy: "Retain",
      UpdateReplacePolicy: "Retain",
      Properties: {
        ScanType: "BASIC",
        Rules: [
          {
            ScanFrequency: "SCAN_ON_PUSH",
            RepositoryFilters: [
              {
                Filter: "${ProjectName}/*",
                FilterType: "WILDCARD",
              },
            ],
          },
        ],
      },
    });
  });

  it("TC-ECR-SCAN-011: leaves all four retained repositories in their existing stack", async () => {
    const source = await readFile(
      join(repoRoot, "infra", "cloudformation", "ecr-repositories.yaml"),
      "utf8",
    );
    const repositoryCount = (source.match(/Type: AWS::ECR::Repository$/gm) ?? []).length;
    expect(repositoryCount).toBe(4);
    expect(source).not.toContain("AWS::ECR::RegistryScanningConfiguration");
  });

  it("TC-ECR-SCAN-018: grants exactly the required ECR registry and findings actions", async () => {
    const source = await readFile(
      join(repoRoot, "infra", "cloudformation", "github-actions-role.yaml"),
      "utf8",
    );
    const template = parseCloudFormation(source);
    const statements =
      template.Resources.ImageBuildPolicy.Properties.PolicyDocument.Statement;
    const registryStatement = statements.find(
      (statement) => statement.Sid === "EcrRegistryScanning",
    );
    const findingsStatement = statements.find(
      (statement) => statement.Sid === "EcrImageScanFindings",
    );

    expect(registryStatement).toMatchObject({
      Effect: "Allow",
      Action: [
        "ecr:GetRegistryScanningConfiguration",
        "ecr:PutRegistryScanningConfiguration",
      ],
      Resource: "*",
    });
    expect(findingsStatement?.Action).toEqual(["ecr:DescribeImageScanFindings"]);
    expect([...registryStatement.Action, ...findingsStatement.Action]).toEqual([
      "ecr:GetRegistryScanningConfiguration",
      "ecr:PutRegistryScanningConfiguration",
      "ecr:DescribeImageScanFindings",
    ]);
    expect(findingsStatement?.Resource).toHaveLength(4);
    expect(
      findingsStatement?.Resource.every((resource) =>
        resource.includes("repository/${ProjectName}/"),
      ),
    ).toBe(true);
  });

  it("TC-ECR-SCAN-019: keeps new public artifacts free of live identifiers", async () => {
    const artifactPaths = [
      "README.md",
      "docs/ARCHITECTURE.md",
      "docs/designs/ecr-registry-scanning.md",
      "docs/test-cases/ecr-registry-scanning.md",
      "infra/cloudformation/ecr-registry-scanning.yaml",
      "scripts/deploy-ecr-registry-scanning.sh",
    ];
    const artifacts = await Promise.all(
      artifactPaths.map(async (path) => ({
        path,
        source: await readFile(join(repoRoot, path), "utf8"),
      })),
    );
    const prohibited = [
      /\b(?!123456789012\b)[0-9]{12}\b/i,
      /arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}/i,
      /quant-scorer|vidsyllabus|issuecomment-[0-9]+/i,
      /[a-z0-9_.-]+\/[a-z0-9_.-]+#[0-9]+/i,
    ];

    for (const artifact of artifacts) {
      for (const pattern of prohibited) {
        expect(artifact.source, `${artifact.path} matched ${pattern}`).not.toMatch(pattern);
      }
    }
  });
});

describe("deployment wrapper fixture adapter", () => {
  it("TC-ECR-SCAN-012: adopts only after reading and validating", async () => {
    const result = await runWrapper("default.json", "missing");
    expect(result.status, result.stderr).toBe(0);
    const lines = result.calls.trim().split("\n");
    expect(lines[0]).toContain("ecr get-registry-scanning-configuration");
    expect(lines).toContainEqual(expect.stringContaining("cloudformation validate-template"));
    expect(lines).toContainEqual(expect.stringContaining("cloudformation create-stack"));
    expect(lines).toContainEqual(expect.stringContaining("cloudformation wait stack-create-complete"));
    expect(lines.findIndex((line) => line.includes("create-stack"))).toBeGreaterThan(
      lines.findIndex((line) => line.includes("get-registry-scanning-configuration")),
    );
  });

  it("TC-ECR-SCAN-013: verifies compliant external coverage without mutation", async () => {
    const result = await runWrapper("external-compliant.json", "missing");
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("verify-only");
    expect(mutationCalls(result.calls)).toEqual([]);
  });

  it("TC-ECR-SCAN-014: updates stack-owned drift from the template", async () => {
    const result = await runWrapper("owned-drift.json", "owned");
    expect(result.status, result.stderr).toBe(0);
    expect(result.calls).toContain("cloudformation validate-template");
    expect(result.calls).toContain("cloudformation update-stack");
    expect(result.calls).toContain("cloudformation wait stack-update-complete");
  });

  it("TC-ECR-SCAN-015: verifies equivalent stack-owned state without mutation", async () => {
    const result = await runWrapper("declared.json", "owned");
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("verify-owned");
    expect(mutationCalls(result.calls)).toEqual([]);
  });

  it.each([
    ["external-sibling.json", "missing"],
    ["enhanced.json", "missing"],
    ["partial.json", "missing"],
    ["default.json", "unowned"],
  ])(
    "TC-ECR-SCAN-016: %s/%s fails before mutation",
    async (fixture, stackState) => {
      const result = await runWrapper(fixture, stackState);
      expect(result.status).not.toBe(0);
      expect(mutationCalls(result.calls)).toEqual([]);
    },
  );

  it("TC-ECR-SCAN-017: never uses repository-level scanning configuration", async () => {
    const [wrapperSource, repositoryTemplate, registryTemplate] = await Promise.all([
      readFile(wrapper, "utf8"),
      readFile(join(repoRoot, "infra", "cloudformation", "ecr-repositories.yaml"), "utf8"),
      readFile(
        join(repoRoot, "infra", "cloudformation", "ecr-registry-scanning.yaml"),
        "utf8",
      ),
    ]);
    const repositoryApi = ["put", "image", "scanning", "configuration"].join("-");
    const repositoryProperty = ["Image", "Scanning", "Configuration"].join("");
    for (const source of [wrapperSource, repositoryTemplate, registryTemplate]) {
      expect(source).not.toContain(repositoryApi);
      expect(source).not.toContain(repositoryProperty);
    }
  });
});
