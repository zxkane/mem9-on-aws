import { createHash } from "node:crypto";
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";
import { parse } from "yaml";
import {
  declaredConfiguration,
  decideRegistryScanningAction,
  projectRepositories,
  repositoryMatchesFilter,
} from "./lib/ecr-registry-scanning-preflight.mjs";

const scriptsDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = dirname(scriptsDir);
const fixtureDir = join(scriptsDir, "test-fixtures", "ecr-registry-scanning");
const wrapper = join(scriptsDir, "deploy-ecr-registry-scanning.sh");
const preflight = join(scriptsDir, "lib", "ecr-registry-scanning-preflight.mjs");
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

function actionPatternMatches(pattern, action) {
  const expression = pattern
    .split(/([*?])/u)
    .map((part) => {
      if (part === "*") return ".*";
      if (part === "?") return ".";
      return RegExp.escape(part);
    })
    .join("");
  return new RegExp(`^${expression}$`, "i").test(action);
}

function statementAllowsAction(statement, action) {
  if (statement.Effect !== "Allow") return false;
  if (statement.Action !== undefined) {
    const actions = Array.isArray(statement.Action)
      ? statement.Action
      : [statement.Action];
    return actions.some((pattern) => actionPatternMatches(pattern, action));
  }
  if (statement.NotAction !== undefined) {
    const excludedActions = Array.isArray(statement.NotAction)
      ? statement.NotAction
      : [statement.NotAction];
    return !excludedActions.some((pattern) => actionPatternMatches(pattern, action));
  }
  return false;
}

function rolePolicyStatements(template, roleId) {
  const role = template.Resources[roleId];
  const attachedStatements = role.Properties.ManagedPolicyArns.flatMap(
    (policyId) => {
      const policy = template.Resources[policyId];
      if (!policy) throw new Error(`Unknown attached policy: ${policyId}`);
      return policy.Properties.PolicyDocument.Statement;
    },
  );
  const inlineStatements = (role.Properties.Policies ?? []).flatMap(
    (policy) => policy.PolicyDocument.Statement,
  );
  return [...attachedStatements, ...inlineStatements];
}

async function runWrapper(fixture, stackState, options = {}) {
  const dir = await mkdtemp(join(tmpdir(), "ecr-scan-wrapper-"));
  tempDirs.push(dir);
  const mockAws = join(dir, "aws");
  const log = join(dir, "aws.log");
  const rollbackFile = join(
    dir,
    options.rollbackFileName ?? "rollback.local.json",
  );
  const putInputFile = join(dir, "put-input.json");
  let wrapperUnderTest = wrapper;
  let operatorBackupFile = null;
  await copyFile(join(fixtureDir, "mock-aws.sh"), mockAws);
  await chmod(mockAws, 0o755);
  if (options.existingRollback) {
    await writeFile(rollbackFile, "existing rollback\n", { mode: 0o600 });
  }
  if (options.repoEnv) {
    const isolatedRepo = join(dir, "repo");
    const isolatedScripts = join(isolatedRepo, "scripts");
    await Promise.all([
      mkdir(join(isolatedScripts, "lib"), { recursive: true }),
      mkdir(join(isolatedRepo, "infra", "cloudformation"), { recursive: true }),
    ]);
    wrapperUnderTest = join(isolatedScripts, "deploy-ecr-registry-scanning.sh");
    operatorBackupFile = join(dir, "operator-backup.local.json");
    await Promise.all([
      copyFile(wrapper, wrapperUnderTest),
      copyFile(
        preflight,
        join(isolatedScripts, "lib", "ecr-registry-scanning-preflight.mjs"),
      ),
      copyFile(
        join(repoRoot, "infra", "cloudformation", "ecr-registry-scanning.yaml"),
        join(
          isolatedRepo,
          "infra",
          "cloudformation",
          "ecr-registry-scanning.yaml",
        ),
      ),
      writeFile(
        join(isolatedRepo, ".env"),
        [
          "AWS_PROFILE=operator-real-profile",
          "ECR_REGION=us-east-1",
          `ECR_SCAN_BACKUP_FILE=${operatorBackupFile}`,
          "",
        ].join("\n"),
      ),
    ]);
  }

  const result = spawnSync("bash", [wrapperUnderTest], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${dir}${delimiter}${process.env.PATH}`,
      MOCK_AWS_LOG: log,
      MOCK_AWS_STATE: join(dir, "aws.state"),
      MOCK_PUT_INPUT: putInputFile,
      MOCK_CURRENT_CONFIG: join(fixtureDir, fixture),
      MOCK_DECLARED_CONFIG: join(fixtureDir, "declared.json"),
      MOCK_SECOND_CURRENT_CONFIG: options.secondFixture
        ? join(fixtureDir, options.secondFixture)
        : "",
      MOCK_THIRD_CURRENT_CONFIG: options.thirdFixture
        ? join(fixtureDir, options.thirdFixture)
        : "",
      MOCK_STACK_STATE: stackState,
      MOCK_SECOND_STACK_STATE: options.secondStackState ?? "",
      MOCK_THIRD_STACK_STATE: options.thirdStackState ?? "",
      MOCK_UPDATE_RESULT: options.updateResult ?? "success",
      MOCK_PUT_RESULT: options.putResult ?? "success",
      MOCK_MUTATION_CONVERGES: String(options.mutationConverges ?? true),
      MOCK_POST_MUTATION_STACK_STATE: options.postMutationStackState ?? "",
      ECR_SCAN_SKIP_DOTENV: String(options.skipDotenv ?? true),
      ECR_SCAN_EXCLUSIVE_WRITER_ACK: options.exclusiveWriterAck ?? "true",
      ECR_SCAN_BACKUP_FILE: rollbackFile,
      ECR_SCAN_STACK_NAME: options.stackName ?? "",
      ECR_REGION: options.ecrRegion ?? "ap-northeast-1",
      AWS_PROFILE: options.awsProfile ?? "test-operator",
      PROJECT_NAME: options.projectName ?? "mem9-on-aws",
    },
  });

  let calls = "";
  let rollback = "";
  let rollbackMode = null;
  let putInput = null;
  let operatorBackup = null;
  try {
    calls = await readFile(log, "utf8");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  try {
    rollback = await readFile(rollbackFile, "utf8");
    rollbackMode = (await stat(rollbackFile)).mode & 0o777;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  try {
    putInput = JSON.parse(await readFile(putInputFile, "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (operatorBackupFile) {
    try {
      operatorBackup = await readFile(operatorBackupFile, "utf8");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }

  return {
    ...result,
    rollback,
    rollbackFile,
    rollbackMode,
    calls,
    operatorBackup,
    operatorBackupFile,
    putInput,
  };
}

function mutationCalls(calls) {
  return calls
    .split("\n")
    .filter((line) =>
      /cloudformation (create-stack|update-stack|delete-stack)|ecr put-/.test(line),
    );
}

function repositoryTokenDigest(token) {
  const normalized = token.toLowerCase().replace(/\.+$/, "").replace(/\.git$/, "");
  return createHash("sha256").update(normalized).digest("hex");
}

function expectRollback(
  result,
  expectedConfiguration,
  { guidance = false, profile = "test-operator" } = {},
) {
  expect(JSON.parse(result.rollback)).toEqual(expectedConfiguration);
  expect(result.rollbackMode).toBe(0o600);

  if (guidance) {
    const profileArgument = profile ? ` --profile ${profile}` : "";
    expect(result.stderr).toContain(
      "Restore the captured baseline while the exclusive-writer window remains active:",
    );
    expect(result.stderr).toContain(
      `aws${profileArgument} ecr put-registry-scanning-configuration --region ap-northeast-1 --cli-input-json file://${result.rollbackFile}`,
    );
  }
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("registry scanning preflight decision", () => {
  it("TC-ECR-SCAN-001: allows adoption only from the default BASIC configuration", async () => {
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

  it("TC-ECR-SCAN-037: external MANUAL coverage is not scan-on-push compliance", async () => {
    const decision = decideRegistryScanningAction({
      current: await fixture("manual.json"),
      ownership: missingStack,
      projectName: "mem9-on-aws",
    });
    expect(decision.action).toBe("fail-closed");
    expect(decision.uncoveredRepositories).toEqual(projectRepositories("mem9-on-aws"));
  });

  it("TC-ECR-SCAN-038: wildcard filters escape regex metacharacters", () => {
    expect(repositoryMatchesFilter("a.c-thing", "a.c*")).toBe(true);
    expect(repositoryMatchesFilter("abc-thing", "a.c*")).toBe(false);
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

  it("TC-ECR-SCAN-027: fails closed on incomplete AWS responses and ownership", () => {
    expect(
      decideRegistryScanningAction({
        current: {},
        ownership: missingStack,
        projectName: "mem9-on-aws",
      }).action,
    ).toBe("fail-closed");
    expect(
      decideRegistryScanningAction({
        current: {
          registryId: "123456789012",
          scanningConfiguration: { scanType: "BASIC" },
        },
        ownership: missingStack,
        projectName: "mem9-on-aws",
      }).action,
    ).toBe("fail-closed");
    expect(
      decideRegistryScanningAction({
        current: {
          registryId: "123456789012",
          scanningConfiguration: { scanType: "BASIC", rules: [] },
        },
        ownership: { ...ownedStack, stackStatus: null },
        projectName: "mem9-on-aws",
      }).action,
    ).toBe("fail-closed");
  });

  it("TC-ECR-SCAN-039: pins registry identity and ownership stability guards", async () => {
    const ownedDrift = await fixture("owned-drift.json");
    for (const stackStatus of ["UPDATE_IN_PROGRESS", "UPDATE_ROLLBACK_FAILED"]) {
      expect(
        decideRegistryScanningAction({
          current: ownedDrift,
          ownership: { ...ownedStack, stackStatus },
          projectName: "mem9-on-aws",
        }).action,
      ).toBe("fail-closed");
    }

    const defaultConfiguration = await fixture("default.json");
    for (const registryId of [undefined, "not-an-account-id"]) {
      expect(
        decideRegistryScanningAction({
          current: {
            ...defaultConfiguration,
            registryId,
          },
          ownership: missingStack,
          projectName: "mem9-on-aws",
        }).action,
      ).toBe("fail-closed");
    }

    expect(
      decideRegistryScanningAction({
        current: defaultConfiguration,
        ownership: {
          stackExists: false,
          ownsResource: true,
          stackStatus: "UPDATE_COMPLETE",
        },
        projectName: "mem9-on-aws",
      }).action,
    ).toBe("fail-closed");
  });

  it("TC-ECR-SCAN-028: rejects project names that could broaden the filter", async () => {
    expect(
      decideRegistryScanningAction({
        current: await fixture("default.json"),
        ownership: missingStack,
        projectName: "mem9-on-aws*",
      }).action,
    ).toBe("fail-closed");
    expect(() => declaredConfiguration("mem9-on-aws*")).toThrow(/project name/i);

    const maximumPrefix = "a".repeat(243);
    expect(projectRepositories(maximumPrefix)[0]).toHaveLength(256);
    expect(declaredConfiguration(maximumPrefix).rules[0].repositoryFilters[0].filter)
      .toHaveLength(245);
    expect(() => declaredConfiguration("a".repeat(244))).toThrow(/project name/i);
  });
});

describe("CloudFormation declarations", () => {
  it("TC-ECR-SCAN-010: declares only the narrow BASIC scan-on-push singleton", async () => {
    const source = await readFile(
      join(repoRoot, "infra", "cloudformation", "ecr-registry-scanning.yaml"),
      "utf8",
    );
    const template = parseCloudFormation(source);
    expect(template.Parameters.ProjectName).toMatchObject({
      MinLength: 2,
      MaxLength: 243,
      AllowedPattern: "^[a-z0-9]+([._/-][a-z0-9]+)*$",
    });
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
    expect(declaredConfiguration("mem9-on-aws")).toEqual({
      scanType: resources[0].Properties.ScanType,
      rules: resources[0].Properties.Rules.map((rule) => ({
        scanFrequency: rule.ScanFrequency,
        repositoryFilters: rule.RepositoryFilters.map((filter) => ({
          filter: filter.Filter.replace("${ProjectName}", "mem9-on-aws"),
          filterType: filter.FilterType,
        })),
      })),
    });
  });

  it("TC-ECR-SCAN-011: leaves all four retained repositories in their existing stack", async () => {
    const source = await readFile(
      join(repoRoot, "infra", "cloudformation", "ecr-repositories.yaml"),
      "utf8",
    );
    const template = parseCloudFormation(source);
    const repositoryNames = Object.values(template.Resources)
      .filter((resource) => resource.Type === "AWS::ECR::Repository")
      .map((resource) =>
        resource.Properties.RepositoryName.replace("${ProjectName}", "mem9-on-aws"),
      )
      .sort();
    const repositoryCount = (source.match(/Type: AWS::ECR::Repository$/gm) ?? []).length;
    expect(repositoryCount).toBe(4);
    expect(repositoryNames).toEqual(projectRepositories("mem9-on-aws").sort());
    expect(source).not.toContain("AWS::ECR::RegistryScanningConfiguration");
  });

  it("TC-ECR-SCAN-018/022: keeps singleton permissions on the operator identity", async () => {
    const [
      source,
      roleBootstrapSource,
      wrapperSource,
      architecture,
    ] = await Promise.all([
      readFile(
        join(repoRoot, "infra", "cloudformation", "github-actions-role.yaml"),
        "utf8",
      ),
      readFile(join(repoRoot, "scripts", "deploy-github-role.sh"), "utf8"),
      readFile(wrapper, "utf8"),
      readFile(join(repoRoot, "docs", "ARCHITECTURE.md"), "utf8"),
    ]);
    const template = parseCloudFormation(source);
    expect(template.Parameters.ProjectName.Default).toBe("mem9-on-aws");
    expect(roleBootstrapSource).not.toContain("ParameterKey=ProjectName");
    expect(architecture).toContain(
      "update once with `scripts/deploy-github-role.sh`",
    );
    expect(architecture).toContain(
      "DenyEcrRegistryScanningOwnershipStackMutation",
    );
    const roleStatements = rolePolicyStatements(template, "GitHubActionsRole");
    const operatorPolicy = [...architecture.matchAll(/```json\n([\s\S]*?)\n```/g)]
      .map((match) => JSON.parse(match[1]))
      .find((document) =>
        document.Statement?.some(
          (statement) => statement.Sid === "EcrRegistryScanning",
        ),
      );
    expect(operatorPolicy).toBeDefined();
    const targetActions = [
      "ecr:GetRegistryScanningConfiguration",
      "ecr:PutRegistryScanningConfiguration",
      "ecr:DescribeImageScanFindings",
    ];
    expect(
      statementAllowsAction(
        { Effect: "Allow", Action: "ecr:*RegistryScanningConfiguration" },
        targetActions[0],
      ),
    ).toBe(true);
    expect(
      actionPatternMatches(
        "ecr:GetRegistryScanningConfiguratio?",
        "ecr:GetRegistryScanningConfiguration",
      ),
    ).toBe(true);
    expect(
      actionPatternMatches(
        "ecr:GetRegistryScanningConfiguratio",
        "ecr:GetRegistryScanningConfiguration",
      ),
    ).toBe(false);
    const inlineNotActionGrant = {
      Effect: "Allow",
      NotAction: "ecr:Delete*",
      Resource: "*",
    };
    const templateWithInlinePolicy = structuredClone(template);
    templateWithInlinePolicy.Resources.GitHubActionsRole.Properties.Policies = [
      {
        PolicyName: "SyntheticRegressionPolicy",
        PolicyDocument: {
          Version: "2012-10-17",
          Statement: [inlineNotActionGrant],
        },
      },
    ];
    expect(
      rolePolicyStatements(
        templateWithInlinePolicy,
        "GitHubActionsRole",
      ),
    ).toContainEqual(inlineNotActionGrant);
    expect(statementAllowsAction(inlineNotActionGrant, targetActions[0])).toBe(
      true,
    );
    expect(
      statementAllowsAction(
        { Effect: "Allow", NotAction: "ecr:Get*" },
        targetActions[0],
      ),
    ).toBe(false);

    for (const action of targetActions) {
      expect(
        roleStatements.some((statement) => statementAllowsAction(statement, action)),
        action,
      ).toBe(false);
    }

    const protectedStackArn =
      "arn:${AWS::Partition}:cloudformation:*:${AWS::AccountId}:stack/ecr-registry-scanning-${ProjectName}/*";
    const ownershipMutationActions = [
      "cloudformation:CancelUpdateStack",
      "cloudformation:ContinueUpdateRollback",
      "cloudformation:CreateChangeSet",
      "cloudformation:CreateStack",
      "cloudformation:CreateStackRefactor",
      "cloudformation:DeleteChangeSet",
      "cloudformation:DeleteStack",
      "cloudformation:ExecuteChangeSet",
      "cloudformation:ExecuteStackRefactor",
      "cloudformation:RecordHandlerProgress",
      "cloudformation:RollbackStack",
      "cloudformation:SetStackPolicy",
      "cloudformation:SignalResource",
      "cloudformation:TagResource",
      "cloudformation:UntagResource",
      "cloudformation:UpdateStack",
      "cloudformation:UpdateTerminationProtection",
    ];
    const ownershipStackDeny = roleStatements.find(
      (statement) =>
        statement.Sid === "DenyEcrRegistryScanningOwnershipStackMutation",
    );
    expect({
      ...ownershipStackDeny,
      Action: [...ownershipStackDeny.Action].sort(),
    }).toEqual({
      Sid: "DenyEcrRegistryScanningOwnershipStackMutation",
      Effect: "Deny",
      Action: ownershipMutationActions.sort(),
      Resource: protectedStackArn,
    });
    expect(wrapperSource).not.toContain("ECR_SCAN_STACK_NAME");
    expect(wrapperSource).toContain('project_name="mem9-on-aws"');
    expect(wrapperSource).toContain(
      'stack_name="ecr-registry-scanning-${project_name}"',
    );

    const registryStatement = operatorPolicy.Statement.find(
      (statement) => statement.Sid === "EcrRegistryScanning",
    );
    const findingsStatement = operatorPolicy.Statement.find(
      (statement) => statement.Sid === "EcrImageScanFindings",
    );
    expect({
      ...registryStatement,
      Action: [...registryStatement.Action].sort(),
    }).toEqual({
      Sid: "EcrRegistryScanning",
      Effect: "Allow",
      Action: targetActions.slice(0, 2).sort(),
      Resource: "*",
      Condition: {
        StringEquals: {
          "aws:RequestedRegion": "ap-northeast-1",
        },
      },
    });
    expect({
      ...findingsStatement,
      Resource: [...findingsStatement.Resource].sort(),
    }).toEqual({
      Sid: "EcrImageScanFindings",
      Effect: "Allow",
      Action: targetActions[2],
      Resource: projectRepositories("mem9-on-aws")
        .map(
          (repository) =>
            `arn:aws:ecr:ap-northeast-1:<aws-account-id>:repository/${repository}`,
        )
        .sort(),
    });
    expect(
      operatorPolicy.Statement.flatMap((statement) =>
        Array.isArray(statement.Action) ? statement.Action : [statement.Action],
      ),
    ).toEqual(expect.arrayContaining(targetActions));
    expect(
      operatorPolicy.Statement.flatMap((statement) =>
        Array.isArray(statement.Action) ? statement.Action : [statement.Action],
      ),
    ).toHaveLength(targetActions.length);
  });

  it("TC-ECR-SCAN-019: keeps new public artifacts free of live identifiers", async () => {
    const artifactPaths = [
      ".env.example",
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
      /issuecomment-[0-9]+/i,
      /[a-z0-9_.-]+\/[a-z0-9_.-]+#[0-9]+/i,
    ];
    const prohibitedSlugDigests = new Set([
      "af2d37eee16a88a81c6dd8d96a9025555355cda174e6f4b48f7fbdf8fca985fd",
      "a36eed16dd93c459d32152e438418f179d3a2f6cc1860bcdaea12bfc0b0996f9",
    ]);
    const referenceDigest = repositoryTokenDigest("example");
    for (const suffix of [".", ".git", ".git."]) {
      expect(repositoryTokenDigest(`example${suffix}`)).toBe(referenceDigest);
    }

    for (const artifact of artifacts) {
      for (const pattern of prohibited) {
        expect(artifact.source, `${artifact.path} matched ${pattern}`).not.toMatch(pattern);
      }
      for (const token of artifact.source.match(/[a-z0-9][a-z0-9._-]*/gi) ?? []) {
        const digest = repositoryTokenDigest(token);
        expect(
          prohibitedSlugDigests,
          `${artifact.path} contains a prohibited private repository reference`,
        ).not.toContain(digest);
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

  it("TC-ECR-SCAN-020: repairs owned drift when CloudFormation has no template update", async () => {
    const result = await runWrapper("owned-drift.json", "owned", {
      updateResult: "no-updates",
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.calls).toContain("cloudformation update-stack");
    expect(result.calls).toContain("ecr put-registry-scanning-configuration");
    expect(result.putInput).toEqual(declaredConfiguration("mem9-on-aws"));
    const driftedConfiguration = (await fixture("owned-drift.json"))
      .scanningConfiguration;
    expectRollback(result, driftedConfiguration);

    const failed = await runWrapper("owned-drift.json", "owned", {
      updateResult: "no-updates",
      mutationConverges: false,
    });
    expect(failed.status).toBe(4);
    expectRollback(failed, driftedConfiguration, { guidance: true });

    const writeFailed = await runWrapper("owned-drift.json", "owned", {
      updateResult: "no-updates",
      putResult: "failure",
    });
    expect(writeFailed.status).not.toBe(0);
    expectRollback(writeFailed, driftedConfiguration, { guidance: true });

    const noProfileFailure = await runWrapper("owned-drift.json", "owned", {
      updateResult: "no-updates",
      mutationConverges: false,
      awsProfile: "",
    });
    expect(noProfileFailure.status).toBe(4);
    expectRollback(noProfileFailure, driftedConfiguration, {
      guidance: true,
      profile: "",
    });
    expect(noProfileFailure.stderr).not.toContain("--profile");

    const quotedGuidance = await runWrapper("owned-drift.json", "owned", {
      awsProfile: "test operator;false",
      mutationConverges: false,
      rollbackFileName: "rollback path;false.local.json",
      updateResult: "no-updates",
    });
    expect(quotedGuidance.status).toBe(4);
    expect(quotedGuidance.stderr).toContain(
      "aws --profile test\\ operator\\;false ecr",
    );
    expect(quotedGuidance.stderr).toContain(
      `file://${quotedGuidance.rollbackFile.replaceAll(" ", "\\ ").replaceAll(";", "\\;")}`,
    );

    const backupCollision = await runWrapper("owned-drift.json", "owned", {
      updateResult: "no-updates",
      existingRollback: true,
    });
    expect(backupCollision.status).not.toBe(0);
    expect(backupCollision.rollback).toBe("existing rollback\n");
    expect(backupCollision.calls).not.toContain(
      "ecr put-registry-scanning-configuration",
    );
  });

  it("TC-ECR-SCAN-024: fails when an owned update does not converge", async () => {
    const result = await runWrapper("owned-drift.json", "owned", {
      mutationConverges: false,
    });
    expect(result.status).toBe(4);
    expect(result.stderr).toContain("did not converge");
  });

  it("TC-ECR-SCAN-025: fails when ownership is lost after adoption", async () => {
    const result = await runWrapper("default.json", "missing", {
      postMutationStackState: "missing",
    });
    expect(result.status).toBe(4);
    expect(result.stderr).toContain("did not converge");
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

  it("TC-ECR-SCAN-021: a conflicting second read fails before mutation", async () => {
    const result = await runWrapper("default.json", "missing", {
      secondFixture: "external-sibling.json",
    });
    expect(result.status).not.toBe(0);
    expect(
      result.calls.match(/ecr get-registry-scanning-configuration/g),
    ).toHaveLength(2);
    expect(mutationCalls(result.calls)).toEqual([]);
  });

  it("TC-ECR-SCAN-033: fixture tests ignore an operator repo-root .env", async () => {
    const driftedConfiguration = (await fixture("owned-drift.json"))
      .scanningConfiguration;
    const originalRegion = process.env.ECR_REGION;
    process.env.ECR_REGION = "us-east-1";
    let isolated;
    try {
      isolated = await runWrapper("owned-drift.json", "owned", {
        mutationConverges: false,
        repoEnv: true,
        updateResult: "no-updates",
      });
    } finally {
      if (originalRegion === undefined) delete process.env.ECR_REGION;
      else process.env.ECR_REGION = originalRegion;
    }
    expect(isolated.status).toBe(4);
    expectRollback(isolated, driftedConfiguration, { guidance: true });
    expect(isolated.operatorBackup).toBeNull();
    expect(isolated.stderr).not.toContain("operator-real-profile");
    expect(isolated.stderr).not.toContain("us-east-1");

    const loaded = await runWrapper("owned-drift.json", "owned", {
      mutationConverges: false,
      repoEnv: true,
      skipDotenv: false,
      updateResult: "no-updates",
    });
    expect(loaded.status).toBe(4);
    expect(JSON.parse(loaded.operatorBackup)).toEqual(driftedConfiguration);
    expect(loaded.rollback).toBe("");
    expect(loaded.stderr).toContain("--profile operator-real-profile");
    expect(loaded.stderr).toContain("--region us-east-1");
    expect(loaded.stderr).toContain(`file://${loaded.operatorBackupFile}`);
  });

  it.each([
    ["error", "Could not determine CloudFormation ownership"],
    ["resource-error", "AccessDeniedException"],
    ["invalid", "Could not determine whether the stack owns"],
  ])(
    "TC-ECR-SCAN-034: %s ownership response fails before mutation",
    async (stackState, expectedError) => {
      const result = await runWrapper("default.json", stackState);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain(expectedError);
      expect(mutationCalls(result.calls)).toEqual([]);
    },
  );

  it("TC-ECR-SCAN-035: an ownership change cannot switch mutation paths", async () => {
    const result = await runWrapper("default.json", "missing", {
      secondStackState: "owned",
    });
    expect(result.status).toBe(3);
    expect(result.stderr).toContain(
      "Ownership changed during preflight; refusing to switch mutation paths.",
    );
    expect(mutationCalls(result.calls)).toEqual([]);
  });

  it("TC-ECR-SCAN-036: ownership loss before drift repair refuses a direct write", async () => {
    const result = await runWrapper("owned-drift.json", "owned", {
      thirdFixture: "default.json",
      thirdStackState: "missing",
      updateResult: "no-updates",
    });
    expect(result.status).toBe(3);
    expect(result.stderr).toContain(
      "Ownership changed before drift repair; refusing direct registry mutation.",
    );
    expect(
      result.calls.match(/ecr get-registry-scanning-configuration/g),
    ).toHaveLength(3);
    expect(mutationCalls(result.calls)).toEqual([
      expect.stringMatching(/^cloudformation update-stack /),
    ]);
    expect(result.rollback).toBe("");
    expect(result.putInput).toBeNull();
  });

  it("TC-ECR-SCAN-029: mutations require an exclusive-writer acknowledgement", async () => {
    const result = await runWrapper("default.json", "missing", {
      exclusiveWriterAck: "",
    });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("exclusive");
    expect(mutationCalls(result.calls)).toEqual([]);
  });

  it("TC-ECR-SCAN-030: malformed configuration never mutates", async () => {
    const malformed = await runWrapper("malformed.json", "missing");
    expect(malformed.status).not.toBe(0);
    expect(mutationCalls(malformed.calls)).toEqual([]);
  });

  it("TC-ECR-SCAN-032: ambient variables cannot redirect the ownership stack", async () => {
    const result = await runWrapper("default.json", "missing", {
      projectName: "alternate-project",
      stackName: "alternate-ownership-stack",
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.calls).not.toContain("alternate-project");
    expect(result.calls).not.toContain("alternate-ownership-stack");
    for (const call of result.calls
      .split("\n")
      .filter((line) =>
        /^cloudformation (describe-stacks|describe-stack-resources|create-stack|update-stack|wait) /.test(
          line,
        ),
      )) {
      expect(call).toContain(
        "--stack-name ecr-registry-scanning-mem9-on-aws",
      );
    }
    expect(result.calls).toContain(
      "ParameterKey=ProjectName,ParameterValue=mem9-on-aws",
    );
  });

  it("TC-ECR-SCAN-031: rejects unknown preflight CLI options", async () => {
    const result = spawnSync(
      process.execPath,
      [
        preflight,
        "--input",
        join(fixtureDir, "default.json"),
        "--project-name",
        "mem9-on-aws",
        "--unknown-option",
        "value",
      ],
      { encoding: "utf8" },
    );
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("unknown-option");

    const declaration = spawnSync(
      process.execPath,
      [
        preflight,
        "--project-name",
        "mem9-on-aws",
        "--format",
        "configuration",
      ],
      { encoding: "utf8" },
    );
    expect(declaration.status, declaration.stderr).toBe(0);
    expect(JSON.parse(declaration.stdout)).toEqual(
      declaredConfiguration("mem9-on-aws"),
    );
  });

  it("TC-ECR-SCAN-040: rejects duplicate preflight CLI options", () => {
    const result = spawnSync(
      process.execPath,
      [
        preflight,
        "--project-name",
        "mem9-on-aws",
        "--project-name",
        "alternate-project",
        "--format",
        "configuration",
      ],
      { encoding: "utf8" },
    );
    expect(result.status).toBe(2);
    expect(result.stderr).toContain(
      "--project-name must be provided at most once",
    );
  });

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

describe("CI validation", () => {
  it("TC-ECR-SCAN-023: runs genuine cfn-lint schema validation", async () => {
    const workflow = await readFile(
      join(repoRoot, ".github", "workflows", "infra-ci.yml"),
      "utf8",
    );
    const coreChecks = [
      "Type check (infra)",
      "Unit tests (infra)",
      "Type check (root)",
      "Unit tests (root)",
    ];
    const setupPython = workflow.indexOf("uses: actions/setup-python@v6");
    const templateValidation = workflow.indexOf(
      "name: Validate ECR registry scanning template",
    );

    expect(workflow).toContain("cfn-lint");
    expect(workflow).toContain("infra/cloudformation/ecr-registry-scanning.yaml");
    expect(workflow).toContain("python-version: \"3.x\"");
    for (const name of coreChecks) {
      const coreCheck = workflow.indexOf(`name: ${name}`);
      expect(coreCheck).toBeGreaterThanOrEqual(0);
      expect(setupPython).toBeGreaterThan(coreCheck);
    }
    expect(templateValidation).toBeGreaterThan(setupPython);
  });
});
