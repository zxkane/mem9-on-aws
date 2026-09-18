import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

import {
  classifyChangedPaths,
  WORKLOAD_COPY_INPUTS,
} from "./classify-infra-changes.mjs";

const root = resolve(import.meta.dirname, "..");
const roleSource = readFileSync(
  resolve(root, "infra/cloudformation/github-actions-role.yaml"),
  "utf8",
);
const deployScript = readFileSync(
  resolve(root, "scripts/deploy-github-role.sh"),
  "utf8",
);
const workflow = parse(
  readFileSync(resolve(root, ".github/workflows/infra-ci.yml"), "utf8"),
);
const reconciliation = parse(
  readFileSync(
    resolve(root, ".github/workflows/reconcile-previews.yml"),
    "utf8",
  ),
);
const cloudFormationTags = [
  ...["!Ref", "!Sub", "!GetAtt"].map((tag) => ({
    tag,
    resolve: (value) => value,
  })),
  ...["!If", "!Equals", "!Not"].map((tag) => ({
    tag,
    collection: "seq",
    resolve: (value) => value,
  })),
];
const roleTemplate = parse(roleSource, { customTags: cloudFormationTags });

function role(logicalId) {
  return roleTemplate.Resources[logicalId].Properties;
}

function synthetic(value) {
  return value
    .replaceAll("${AWS::Partition}", "aws")
    .replaceAll("${AWS::AccountId}", "123456789012")
    .replaceAll("${ApplicationRegion}", "ap-northeast-1")
    .replaceAll("${ProjectName}", "mem9-on-aws")
    .replaceAll("${GitHubOrg}", "zxkane")
    .replaceAll("${GitHubRepo}", "mem9-on-aws");
}

function wildcardMatch(pattern, value) {
  const expression = synthetic(pattern)
    .replace(/[.+?^${}()|[\]\\]/gu, "\\$&")
    .replaceAll("*", ".*");
  return new RegExp(`^${expression}$`, "u").test(value);
}

function conditionMatches(condition = {}, context = {}) {
  return Object.entries(condition).every(([operator, entries]) =>
    Object.entries(entries).every(([key, expected]) => {
      const actual = context[key];
      if (actual === undefined) return false;
      const expectedValues = Array.isArray(expected) ? expected : [expected];
      if (operator === "StringEquals") {
        return expectedValues.some((value) => synthetic(value) === actual);
      }
      if (operator === "StringLike" || operator === "ArnLike") {
        return expectedValues.some((value) => wildcardMatch(value, actual));
      }
      return false;
    }),
  );
}

function explicitlyDenies(policy, action, resource, context = {}) {
  return policy.Statement.some((statement) => {
    if (
      Array.isArray(statement) ||
      statement.Effect !== "Deny" ||
      !conditionMatches(statement.Condition, context)
    ) {
      return false;
    }
    const actions = Array.isArray(statement.Action)
      ? statement.Action
      : [statement.Action];
    const resources = Array.isArray(statement.Resource)
      ? statement.Resource
      : [statement.Resource];
    return actions.some((candidate) => wildcardMatch(candidate, action)) &&
      resources.some((candidate) => wildcardMatch(candidate, resource));
  });
}

describe("split GitHub OIDC deployment roles", () => {
  it("TC-DEPLOYROLE-001/002/012/014: defines exact trusts and conditional legacy rollback", () => {
    expect(roleSource).toContain("GitHubPreviewActionsRole:");
    expect(roleSource).toContain("GitHubProductionActionsRole:");
    expect(roleSource).toContain("LegacyRoleEnabled:");
    expect(roleSource).toContain("KeepLegacyRole:");
    expect(roleSource).toContain(
      "repo:${GitHubOrg}/${GitHubRepo}:pull_request",
    );
    expect(roleSource).toContain(
      "repo:${GitHubOrg}/${GitHubRepo}:environment:preview-maintenance",
    );
    expect(roleSource).toContain(
      "repo:${GitHubOrg}/${GitHubRepo}:environment:preview-ci",
    );
    expect(roleSource).toContain(
      "repo:${GitHubOrg}/${GitHubRepo}:environment:prod",
    );
    expect(roleSource).toContain("PreviewRoleArn:");
    expect(roleSource).toContain("ProductionRoleArn:");
    expect(roleSource).toContain("LegacyRoleArn:");
    expect(deployScript).toContain("--retire-legacy");
    expect(deployScript).toContain("--enable-legacy");
    expect(deployScript).toContain("read_existing_legacy_role_enabled");
    expect(deployScript).toContain("AWS_PREVIEW_ROLE_ARN");
    expect(deployScript).toContain("AWS_PROD_ROLE_ARN");
    const previewTrust = role("GitHubPreviewActionsRole")
      .AssumeRolePolicyDocument.Statement[0].Condition.StringEquals;
    const productionTrust = role("GitHubProductionActionsRole")
      .AssumeRolePolicyDocument.Statement[0].Condition.StringEquals;
    expect(previewTrust).toEqual({
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": [
        "repo:${GitHubOrg}/${GitHubRepo}:environment:preview-ci",
        "repo:${GitHubOrg}/${GitHubRepo}:environment:preview-maintenance",
      ],
    });
    expect(productionTrust).toEqual({
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub":
        "repo:${GitHubOrg}/${GitHubRepo}:environment:prod",
    });
  });

  it("TC-DEPLOYROLE-003/004: carries opposite-stage explicit denies", () => {
    for (const sid of [
      "DenyTaggedProductionResources",
      "DenyNamedProductionResources",
      "DenyProductionState",
      "DenyTaggedPreviewResources",
      "DenyNamedPreviewResources",
      "DenyPreviewState",
    ]) {
      expect(roleSource).toContain(`Sid: ${sid}`);
    }
    expect(roleSource).toContain("parameter/${ProjectName}/prod/*");
    expect(roleSource).toContain("parameter/${ProjectName}/pr-*");
    expect(roleSource).toContain("secret:${ProjectName}-prod-*");
    expect(roleSource).toContain("secret:${ProjectName}-pr-*");
    const previewPolicy = role("GitHubPreviewActionsRole").Policies[0]
      .PolicyDocument;
    const productionPolicy = role("GitHubProductionActionsRole").Policies[0]
      .PolicyDocument;
    const prodParameter =
      "arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/prod/ecs/image-tag";
    const previewParameter =
      "arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/pr-42/ecs/image-tag";
    expect(
      explicitlyDenies(previewPolicy, "ssm:GetParameter", prodParameter),
    ).toBe(true);
    expect(
      explicitlyDenies(previewPolicy, "ssm:GetParameter", previewParameter),
    ).toBe(false);
    expect(
      explicitlyDenies(productionPolicy, "ssm:GetParameter", previewParameter),
    ).toBe(true);
    expect(
      explicitlyDenies(productionPolicy, "ssm:GetParameter", prodParameter),
    ).toBe(false);
    const representative = [
      [
        "secretsmanager:GetSecretValue",
        "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:mem9-on-aws-prod-fixture",
        "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:mem9-on-aws-pr-42-fixture",
      ],
      [
        "lambda:UpdateFunctionCode",
        "arn:aws:lambda:ap-northeast-1:123456789012:function:mem9-on-aws-prod-fixture",
        "arn:aws:lambda:ap-northeast-1:123456789012:function:mem9-on-aws-pr-42-fixture",
      ],
      [
        "ecs:UpdateService",
        "arn:aws:ecs:ap-northeast-1:123456789012:service/mem9-on-aws-prod-cluster/service",
        "arn:aws:ecs:ap-northeast-1:123456789012:service/mem9-on-aws-pr-42-cluster/service",
      ],
      [
        "rds:ModifyDBCluster",
        "arn:aws:rds:ap-northeast-1:123456789012:cluster:mem9-on-aws-prod-fixture",
        "arn:aws:rds:ap-northeast-1:123456789012:cluster:mem9-on-aws-pr-42-fixture",
      ],
      [
        "iam:PutRolePolicy",
        "arn:aws:iam::123456789012:role/mem9-on-aws-prod-fixture",
        "arn:aws:iam::123456789012:role/mem9-on-aws-pr-42-fixture",
      ],
    ];
    for (const [action, prodResource, previewResource] of representative) {
      expect(
        explicitlyDenies(previewPolicy, action, prodResource),
        `${action} preview-to-prod`,
      ).toBe(true);
      expect(
        explicitlyDenies(productionPolicy, action, previewResource),
        `${action} prod-to-preview`,
      ).toBe(true);
    }
    expect(
      explicitlyDenies(
        previewPolicy,
        "s3:GetObject",
        ["arn:", "aws:s3:::fixture/app/mem9-on-aws/prod.json"].join(""),
      ),
    ).toBe(true);
    expect(
      explicitlyDenies(
        previewPolicy,
        "bedrock-agentcore:UpdateGateway",
        "arn:aws:bedrock-agentcore:ap-northeast-1:123456789012:gateway/prod",
        { "aws:ResourceTag/Stage": "prod" },
      ),
    ).toBe(true);
    expect(
      explicitlyDenies(
        productionPolicy,
        "bedrock-agentcore:UpdateGateway",
        "arn:aws:bedrock-agentcore:ap-northeast-1:123456789012:gateway/preview",
        { "aws:ResourceTag/Stage": "pr-42" },
      ),
    ).toBe(true);
    expect(
      explicitlyDenies(
        previewPolicy,
        "kms:Decrypt",
        "arn:aws:kms:ap-northeast-1:123456789012:key/fixture",
        {
          "kms:EncryptionContext:SecretARN":
            "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:mem9-on-aws-prod-fixture",
        },
      ),
    ).toBe(true);
    expect(
      explicitlyDenies(
        productionPolicy,
        "s3:GetObject",
        ["arn:", "aws:s3:::fixture/app/mem9-on-aws/pr-42.json"].join(""),
      ),
    ).toBe(true);
  });

  it("TC-DEPLOYROLE-005/006/007: classifies mutation paths", () => {
    expect(
      classifyChangedPaths([
        ".github/workflows/infra-ci.yml",
        "infra/cloudformation/github-actions-role.yaml",
        "scripts/deploy-github-role.sh",
        "docs/ARCHITECTURE.md",
        "scripts/deploy-role-isolation.test.mjs",
      ]),
    ).toEqual({
      workloadChanged: false,
      applicationInfrastructureChanged: false,
      awsMutationRequired: false,
    });
    expect(classifyChangedPaths(["infra/ecs.ts"])).toMatchObject({
      workloadChanged: false,
      applicationInfrastructureChanged: true,
      awsMutationRequired: true,
    });
    expect(classifyChangedPaths(["docker/mnemo-server/entrypoint.sh"])).toEqual({
      workloadChanged: true,
      applicationInfrastructureChanged: false,
      awsMutationRequired: true,
    });
    expect(
      classifyChangedPaths(["scripts/observe-memory-namespace-connections.mjs"]),
    ).toMatchObject({ workloadChanged: true, awsMutationRequired: true });
    expect(
      classifyChangedPaths(["infra/gateway/service-auth.mjs"]),
    ).toMatchObject({ workloadChanged: true, awsMutationRequired: true });
    expect(classifyChangedPaths(["package-lock.json"])).toMatchObject({
      workloadChanged: true,
      awsMutationRequired: true,
    });
  });

  it("keeps workload-script classification aligned with Dockerfile COPY inputs", () => {
    const copiedScripts = new Set();
    for (const dockerfile of [
      "docker/bootstrap/Dockerfile",
      "docker/llm-proxy/Dockerfile",
      "docker/mnemo-server/Dockerfile",
      "docker/qwen3-embed/Dockerfile",
    ]) {
      for (const line of readFileSync(resolve(root, dockerfile), "utf8").split("\n")) {
        const match = line.match(/^COPY (scripts\/\S+) \S+$/u);
        if (match) copiedScripts.add(match[1]);
      }
    }
    expect([...WORKLOAD_COPY_INPUTS].filter((path) => path.startsWith("scripts/")).toSorted()).toEqual(
      [...copiedScripts].toSorted(),
    );
    const classifierSource = readFileSync(
      resolve(root, "scripts/classify-infra-changes.mjs"),
      "utf8",
    );
    expect(classifierSource).toContain("--diff-filter=ACDMRT");
    expect(classifierSource).toContain('"--no-renames"');
    expect(classifierSource).toContain('"--merge-base"');
    expect(classifyChangedPaths(["docker/bootstrap/Dockerfile"])).toMatchObject({
      workloadChanged: true,
      awsMutationRequired: true,
    });
  });

  it("TC-DEPLOYROLE-005..010: gates workflow mutations and removes the legacy secret", () => {
    expect(JSON.stringify(workflow)).not.toContain("secrets.AWS_ROLE_ARN");
    expect(workflow.jobs.changes).toBeDefined();
    for (const jobName of [
      "build-and-push-image",
      "deploy-preview",
      "deploy-prod",
    ]) {
      expect(workflow.jobs[jobName].if).toContain(
        "needs.application-region.result == 'success'",
      );
    }
    const previewCredentials = workflow.jobs["deploy-preview"].steps.find(
      ({ uses }) =>
        typeof uses === "string" &&
        uses.startsWith("aws-actions/configure-aws-credentials@"),
    );
    const prodCredentials = workflow.jobs["deploy-prod"].steps.find(
      ({ uses }) =>
        typeof uses === "string" &&
        uses.startsWith("aws-actions/configure-aws-credentials@"),
    );
    expect(previewCredentials.with["role-to-assume"]).toBe(
      "${{ secrets.AWS_PREVIEW_ROLE_ARN }}",
    );
    expect(prodCredentials.with["role-to-assume"]).toBe(
      "${{ secrets.AWS_PROD_ROLE_ARN }}",
    );
    expect(workflow.jobs["build-and-push-image"].environment).toContain("prod");
    expect(workflow.jobs["deploy-prod"].environment).toBe("prod");
    for (const jobName of [
      "build-and-push-image",
      "deploy-preview",
      "cleanup-failed-preview",
      "cleanup-preview",
    ]) {
      expect(workflow.jobs[jobName].environment).toContain("preview-ci");
    }
    expect(workflow.jobs["deploy-prod"].steps.some(
      ({ name }) => name === "Resolve deployed image tag",
    )).toBe(true);
    expect(workflow.jobs["report-prod-failure"].if).toContain(
      "needs.deploy-prod.result != 'success'",
    );
    expect(workflow.jobs["report-prod-failure"].if).toContain(
      "needs.changes.outputs.aws_mutation_required == 'true'",
    );
    expect(workflow.jobs["report-prod-failure"].if).toContain(
      "needs.changes.result != 'success'",
    );
  });


  it("TC-DEPLOYROLE-011: uses preview role for scheduled reconciliation", () => {
    for (const jobName of ["report", "apply"]) {
      const job = reconciliation.jobs[jobName];
      expect(job.environment).toBe("preview-maintenance");
      const credentials = job.steps.find(
        ({ uses }) =>
          typeof uses === "string" &&
          uses.startsWith("aws-actions/configure-aws-credentials@"),
      );
      expect(credentials.with["role-to-assume"]).toBe(
        "${{ secrets.AWS_PREVIEW_ROLE_ARN }}",
      );
    }
  });
});
