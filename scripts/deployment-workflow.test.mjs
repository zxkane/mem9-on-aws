import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";
import { parse, parseDocument } from "yaml";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const workflowsDirectory = resolve(root, ".github/workflows");
const workflowPath = resolve(root, ".github/workflows/infra-ci.yml");
const rolePath = resolve(root, "infra/cloudformation/github-actions-role.yaml");
const deployRolePath = resolve(here, "deploy-github-role.sh");
const deployRoleFixturePath = resolve(
  here,
  "test-fixtures/deploy-github-role/mock-aws.mjs",
);
const reconcilePath = resolve(here, "reconcile-ecs-deployment.mjs");
const bootstrapTaskPath = resolve(here, "run-bootstrap-task.sh");
const emfSmokePath = resolve(here, "run-mnemo-emf-smoke.sh");
const healthSmokePath = resolve(here, "run-mnemo-health-smoke.sh");
const fakeAwsPath = resolve(here, "fixtures/fake-aws.mjs");
const tempDirs = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function runFixture(name) {
  const dir = mkdtempSync(join(tmpdir(), "mem9-reconcile-"));
  tempDirs.push(dir);
  const calls = join(dir, "calls.jsonl");
  const result = spawnSync(process.execPath, [reconcilePath, "--stage", "prod"], {
    encoding: "utf8",
    env: {
      ...process.env,
      AWS_CLI: fakeAwsPath,
      AWS_FIXTURE_FILE: resolve(here, `fixtures/reconciliation/${name}.json`),
      AWS_CALL_LOG: calls,
    },
  });
  const callRecords = readFileSync(calls, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  return { result, callRecords };
}

function runDeployRoleFixture(args = []) {
  const dir = mkdtempSync(join(tmpdir(), "mem9-deploy-role-"));
  tempDirs.push(dir);
  const isolatedRoot = join(dir, "repo");
  const isolatedScripts = join(isolatedRoot, "scripts");
  const mockAws = join(dir, "aws");
  const wrapperUnderTest = join(isolatedScripts, "deploy-github-role.sh");
  const calls = join(dir, "calls.jsonl");
  mkdirSync(isolatedScripts, { recursive: true });
  mkdirSync(join(isolatedRoot, "infra", "cloudformation"), {
    recursive: true,
  });
  copyFileSync(deployRoleFixturePath, mockAws);
  copyFileSync(deployRolePath, wrapperUnderTest);
  copyFileSync(
    rolePath,
    join(isolatedRoot, "infra", "cloudformation", "github-actions-role.yaml"),
  );
  chmodSync(mockAws, 0o755);

  const result = spawnSync("bash", [wrapperUnderTest, ...args], {
    cwd: isolatedRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${dir}${delimiter}${process.env.PATH}`,
      AWS_CALL_LOG: calls,
      AWS_PROFILE: "fixture-operator",
      AWS_REGION: "us-east-2",
      PROJECT_REGION: "eu-west-1",
      MEM9_TEMPLATE_BUCKET: "fixture-template-bucket",
    },
  });
  const callRecords = readFileSync(calls, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  return { result, callRecords };
}

function runCloudflareResolver({
  customDomain = "memory.example.com",
  curlExit = 0,
  zoneResponse = "",
} = {}) {
  const workflow = parse(readFileSync(workflowPath, "utf8"));
  const resolver = workflow.jobs["deploy-prod"].steps.find(
    ({ name }) => name === "Resolve Cloudflare account ID",
  );
  const dir = mkdtempSync(join(tmpdir(), "mem9-cloudflare-account-"));
  tempDirs.push(dir);
  const bin = join(dir, "bin");
  const githubEnv = join(dir, "github-env");
  mkdirSync(bin);
  writeFileSync(
    join(bin, "curl"),
    [
      "#!/usr/bin/env bash",
      'if [[ "${MOCK_CURL_EXIT:-0}" != "0" ]]; then exit "$MOCK_CURL_EXIT"; fi',
      "printf '%s' \"$MOCK_ZONE_RESPONSE\"",
      "",
    ].join("\n"),
    { mode: 0o755 },
  );
  writeFileSync(githubEnv, "");

  const result = spawnSync("bash", ["-c", resolver.run], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${bin}${delimiter}${process.env.PATH}`,
      GITHUB_ENV: githubEnv,
      MEM9_FACADE_CUSTOM_DOMAIN: customDomain,
      CLOUDFLARE_API_TOKEN: customDomain ? "fixture-token" : "",
      CLOUDFLARE_ZONE_ID: customDomain ? "a".repeat(32) : "",
      MOCK_CURL_EXIT: String(curlExit),
      MOCK_ZONE_RESPONSE: zoneResponse,
    },
  });

  return { result, githubEnv: readFileSync(githubEnv, "utf8") };
}

function optionValue(args, option) {
  const index = args.indexOf(option);
  return index >= 0 ? args[index + 1] : undefined;
}

function blockForSid(source, sid) {
  const start = source.indexOf(`- Sid: ${sid}`);
  expect(start, `missing IAM Sid ${sid}`).toBeGreaterThanOrEqual(0);
  const tail = source.slice(start);
  const next = tail.slice(1).search(/\n\s+- Sid: /);
  return next >= 0 ? tail.slice(0, next + 1) : tail;
}

function actionSetForSid(source, sid) {
  return [
    ...blockForSid(source, sid).matchAll(
      /^\s+- ([a-z0-9-]+:[A-Za-z*]+)$/gm,
    ),
  ].map(
    (m) => m[1],
  );
}

describe("workflow integration", () => {
  it("masks the AWS account ID in every credential configuration", () => {
    const workflowFiles = readdirSync(workflowsDirectory).filter((name) =>
      /\.ya?ml$/u.test(name),
    );
    const credentialJobs = [];

    for (const workflowFile of workflowFiles) {
      const workflow = parse(
        readFileSync(resolve(workflowsDirectory, workflowFile), "utf8"),
      );
      for (const [jobName, job] of Object.entries(workflow.jobs ?? {})) {
        for (const step of job.steps ?? []) {
          if (
            typeof step.uses !== "string" ||
            !step.uses.startsWith("aws-actions/configure-aws-credentials@")
          ) {
            continue;
          }
          credentialJobs.push(`${workflowFile}:${jobName}`);
          expect(
            step.with?.["mask-aws-account-id"],
            `${workflowFile}:${jobName}:${step.name ?? step.uses}`,
          ).toBe(true);
        }
      }
    }

    expect(credentialJobs.sort()).toEqual(
      [
        "infra-ci.yml:build-and-push-image",
        "infra-ci.yml:cleanup-preview",
        "infra-ci.yml:deploy-preview",
        "infra-ci.yml:deploy-prod",
        "reconcile-previews.yml:apply",
        "reconcile-previews.yml:report",
      ].sort(),
    );
  });

  it("runs IAM regression tests when the GitHub Actions role template changes", () => {
    const workflow = parse(readFileSync(workflowPath, "utf8"));

    for (const trigger of ["pull_request", "push"]) {
      const paths = workflow.on[trigger].paths;
      const exclusion = paths.indexOf("!infra/cloudformation/**");
      const roleTemplate = paths.indexOf(
        "infra/cloudformation/github-actions-role.yaml",
      );

      expect(exclusion).toBeGreaterThanOrEqual(0);
      expect(roleTemplate).toBeGreaterThan(exclusion);
    }
  });

  it("runs the PostgreSQL durable-ingest integration suite in CI", () => {
    const workflow = readFileSync(workflowPath, "utf8");
    expect(workflow).toContain("bash scripts/run-ingest-queue-integration.sh");
  });

  it("TC-CF-ACCOUNT-001/002/003: resolves the Cloudflare account only for prod", () => {
    const workflow = parse(readFileSync(workflowPath, "utf8"));
    const previewSteps = workflow.jobs["deploy-preview"].steps;
    const prodSteps = workflow.jobs["deploy-prod"].steps;
    const preview = previewSteps.find(
      ({ name }) => name === "Deploy PR stage",
    );
    const resolverIndex = prodSteps.findIndex(
      ({ name }) => name === "Resolve Cloudflare account ID",
    );
    const deployIndex = prodSteps.findIndex(
      ({ name }) => name === "Deploy prod stage",
    );
    const resolver = prodSteps[resolverIndex];
    const prod = prodSteps[deployIndex];

    expect(resolverIndex).toBeGreaterThanOrEqual(0);
    expect(resolverIndex).toBeLessThan(deployIndex);
    expect(resolver.env.MEM9_FACADE_CUSTOM_DOMAIN).toBe(
      "${{ secrets.MEM9_FACADE_CUSTOM_DOMAIN }}",
    );
    expect(resolver.env.CLOUDFLARE_API_TOKEN).toBe(
      "${{ secrets.CLOUDFLARE_API_TOKEN }}",
    );
    expect(resolver.env.CLOUDFLARE_ZONE_ID).toBe(
      "${{ secrets.CLOUDFLARE_ZONE_ID }}",
    );
    expect(resolver.run).toContain(
      "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}",
    );
    expect(resolver.run).toContain("curl --fail");
    expect(resolver.run).toContain('data.get("success") is True');
    expect(resolver.run).toContain('re.fullmatch(r"[0-9a-f]{32}", value)');
    expect(resolver.run).toContain("::add-mask::$ACCOUNT_ID");
    expect(resolver.run).toContain(
      "CLOUDFLARE_DEFAULT_ACCOUNT_ID=%s\\n",
    );
    expect(resolver.run).toContain('>> "$GITHUB_ENV"');
    expect(prod.env.MEM9_FACADE_CUSTOM_DOMAIN).toBe(
      "${{ secrets.MEM9_FACADE_CUSTOM_DOMAIN }}",
    );
    expect(prod.env.CLOUDFLARE_API_TOKEN).toBe(
      "${{ secrets.CLOUDFLARE_API_TOKEN }}",
    );
    expect(prod.env.CLOUDFLARE_ZONE_ID).toBe(
      "${{ secrets.CLOUDFLARE_ZONE_ID }}",
    );
    for (const name of [
      "MEM9_FACADE_CUSTOM_DOMAIN",
      "CLOUDFLARE_API_TOKEN",
      "CLOUDFLARE_ZONE_ID",
      "CLOUDFLARE_DEFAULT_ACCOUNT_ID",
    ]) {
      expect(preview.env[name]).toBeUndefined();
    }
    expect(
      previewSteps.some(({ name }) => name === "Resolve Cloudflare account ID"),
    ).toBe(false);
  });

  it("TC-CF-ACCOUNT-003/004: exports only a valid account and skips an unset domain", () => {
    const accountId = "b".repeat(32);
    const success = runCloudflareResolver({
      zoneResponse: JSON.stringify({
        success: true,
        result: { account: { id: accountId } },
      }),
    });
    expect(success.result.status).toBe(0);
    expect(success.result.stdout).toContain(`::add-mask::${accountId}`);
    expect(success.githubEnv).toBe(
      `CLOUDFLARE_DEFAULT_ACCOUNT_ID=${accountId}\n`,
    );

    const noDomain = runCloudflareResolver({ customDomain: "" });
    expect(noDomain.result.status).toBe(0);
    expect(noDomain.result.stdout).toContain(
      "skipping Cloudflare account resolution",
    );
    expect(noDomain.githubEnv).toBe("");

    for (const failure of [
      runCloudflareResolver({ curlExit: 22 }),
      runCloudflareResolver({ zoneResponse: "not-json" }),
      runCloudflareResolver({
        zoneResponse: JSON.stringify({ success: true, result: {} }),
      }),
    ]) {
      expect(failure.result.status).not.toBe(0);
      expect(failure.githubEnv).toBe("");
    }
  });

  it("TC-EMF-011: smokes non-TTY EMF bytes from the built arm64 image", () => {
    const workflow = parse(readFileSync(workflowPath, "utf8"));
    const steps = workflow.jobs["build-and-push-image"].steps;
    const buildIndex = steps.findIndex(
      ({ name }) => name === "Build & push mnemo-server (arm64)",
    );
    const smokeIndex = steps.findIndex(
      ({ name }) => name === "Smoke test mnemo-server EMF framing (non-TTY)",
    );

    expect(buildIndex).toBeGreaterThanOrEqual(0);
    expect(smokeIndex).toBeGreaterThanOrEqual(0);
    expect(smokeIndex).toBeGreaterThan(buildIndex);
    expect(steps[smokeIndex]).toMatchObject({
      env: {
        MNEMO_IMAGE:
          "${{ steps.ecr-login.outputs.registry }}/${{ env.ECR_NS }}/mnemo-server:${{ steps.tag.outputs.image_tag }}",
      },
      run: "bash scripts/run-mnemo-emf-smoke.sh",
    });
    expect(readFileSync(emfSmokePath, "utf8")).toContain(
      "MNEMO_VALIDATE_EMF=true",
    );
    const healthSmoke = readFileSync(healthSmokePath, "utf8");
    expect(healthSmoke).toContain("--tty=false");
    expect(healthSmoke).toContain("validate-emf-event.mjs --docker-stream");
  });

  it("uses one enabled rollout after baking the repeatable migration into startup", () => {
    const workflow = readFileSync(workflowPath, "utf8");
    for (const stage of ["preview", "prod"]) {
      const bootstrap = workflow.indexOf(`name: Run schema-bootstrap task (${stage})`);
      const reconcile = workflow.indexOf(
        `name: Reconcile ${stage === "preview" ? "preview ECS deployment" : "prod ECS deployment"}`,
      );
      expect(bootstrap).toBeGreaterThanOrEqual(0);
      expect(reconcile).toBeGreaterThanOrEqual(0);
      expect(bootstrap).toBeGreaterThan(reconcile);
    }
    expect(workflow.match(/MEM9_DURABLE_INGEST_ENABLED: "1"/g)).toHaveLength(2);
    expect(workflow).not.toContain('MEM9_DURABLE_INGEST_ENABLED: "0"');
    expect(workflow).not.toContain("Enable durable ingest after bootstrap");
    expect(workflow.match(/pnpm -C infra exec sst deploy/g)).toHaveLength(2);
  });

  it("uses the tested tag selector and reconciles preview and prod deployments", () => {
    const workflow = readFileSync(workflowPath, "utf8");

    expect(workflow).toContain("node scripts/image-tags.mjs");
    expect(workflow.match(/node scripts\/reconcile-ecs-deployment\.mjs/g)).toHaveLength(2);
  });

  it("TC-ECS-COST-005: propagates bootstrap task tags at task creation", () => {
    const script = readFileSync(bootstrapTaskPath, "utf8");
    const start = script.indexOf("RUN_OUT=$(aws ecs run-task");
    const end = script.indexOf("TASK_ARN=", start);
    const runTask = script.slice(start, end);

    expect(start).toBeGreaterThanOrEqual(0);
    expect(end).toBeGreaterThan(start);
    expect(runTask).toContain("--propagate-tags TASK_DEFINITION");
    expect(runTask).toContain("--enable-ecs-managed-tags");
  });

  it("routes a reconciliation failure through the existing prod failure reporter", () => {
    const workflow = readFileSync(workflowPath, "utf8");
    const reconcile = workflow.indexOf("name: Reconcile prod ECS deployment");
    const failureReporter = workflow.indexOf("name: Create issue on prod deploy failure");

    expect(reconcile).toBeGreaterThanOrEqual(0);
    expect(failureReporter).toBeGreaterThan(reconcile);
    const reporterBlock = workflow.slice(failureReporter, failureReporter + 500);
    expect(reporterBlock).toContain("if: failure()");
  });

  it("reports preview reconciliation failures using the overall job status", () => {
    const workflow = readFileSync(workflowPath, "utf8");
    const statusComment = workflow.indexOf("name: Comment deploy status");
    const commentBlock = workflow.slice(statusComment, statusComment + 500);

    expect(statusComment).toBeGreaterThanOrEqual(0);
    expect(commentBlock).toContain("DEPLOY_STATUS: ${{ job.status }}");
    expect(commentBlock).not.toContain("steps.deploy.outcome");
  });
});

describe("reconciliation IAM", () => {
  it("grants exactly the read actions exercised by the command", () => {
    const role = readFileSync(rolePath, "utf8");
    const actions = [
      ...actionSetForSid(role, "EcsDeploymentReconciliationRead"),
      ...actionSetForSid(role, "SsmDeploymentReconciliationRead"),
    ].sort();

    expect(actions).toEqual(
      [
        "ecs:DescribeServices",
        "ecs:DescribeTasks",
        "ecs:ListTasks",
        "ssm:GetParameters",
      ].sort(),
    );
  });
});

describe("OAuth2 facade IAM", () => {
  it("grants the documented CloudWatch Logs delivery lifecycle actions", () => {
    const role = readFileSync(rolePath, "utf8");
    const actions = actionSetForSid(role, "ApiGatewayV2AccessLogs");

    expect(actions).toEqual(
      expect.arrayContaining([
        "logs:CreateLogDelivery",
        "logs:PutResourcePolicy",
        "logs:UpdateLogDelivery",
        "logs:DeleteLogDelivery",
        "logs:CreateLogGroup",
        "logs:DescribeResourcePolicies",
        "logs:GetLogDelivery",
        "logs:ListLogDeliveries",
      ]),
    );
  });

  it("grants the optional custom-domain lifecycle without creating a public zone", () => {
    const role = readFileSync(rolePath, "utf8");

    expect(actionSetForSid(role, "ApiGatewayV2")).toEqual(
      expect.arrayContaining([
        "apigateway:POST",
        "apigateway:GET",
        "apigateway:PATCH",
        "apigateway:PUT",
        "apigateway:DELETE",
      ]),
    );
    expect(blockForSid(role, "ApiGatewayV2")).toContain(
      "arn:aws:apigateway:*::/domainnames/*",
    );
    expect(actionSetForSid(role, "AcmFacadeCertificateCreate")).toEqual([
      "acm:RequestCertificate",
      "acm:AddTagsToCertificate",
    ]);
    expect(actionSetForSid(role, "AcmFacadeCertificateManage")).toEqual(
      expect.arrayContaining([
        "acm:DeleteCertificate",
        "acm:DescribeCertificate",
        "acm:ListTagsForCertificate",
      ]),
    );
    expect(actionSetForSid(role, "ApiGatewayServiceLinkedRole")).toEqual([
      "iam:CreateServiceLinkedRole",
    ]);
    expect(blockForSid(role, "ApiGatewayServiceLinkedRole")).toContain(
      "iam:AWSServiceName: ops.apigateway.amazonaws.com",
    );

    const route53 = blockForSid(role, "Route53ForCloudMap");
    expect(route53).toContain("route53:ChangeResourceRecordSets");
    expect(route53).toContain("route53:ListHostedZonesByName");
    expect(route53).toContain("This is the only");
    expect(route53).toContain("uses Cloudflare for public DNS");
  });
});

describe("Lambda VPC IAM", () => {
  it("discovers the same application VPC and private subnets used by SST", () => {
    const script = readFileSync(deployRolePath, "utf8");

    expect(script).toContain(
      'APPLICATION_REGION="${PROJECT_REGION:-ap-northeast-1}"',
    );
    expect(script).toContain('APPLICATION_VPC_ID="${MEM9_VPC_ID:-}"');
    expect(script).toContain('"Name=tag:Name,Values=private-1*"');
    for (const parameter of [
      "OIDCProviderArn",
      "ApplicationRegion",
      "ApplicationVpcArn",
      "ApplicationPrivateSubnetArns",
    ]) {
      expect(script).toContain(`"ParameterKey":"${parameter}"`);
    }
  });

  it("scopes ENI cleanup to the application account, region, VPC, and subnets", () => {
    const document = parseDocument(readFileSync(rolePath, "utf8"));
    expect(document.errors).toEqual([]);
    const template = document.toJS();
    const statement =
      template.Resources.LambdaProxyPolicy.Properties.PolicyDocument.Statement.find(
        ({ Sid }) => Sid === "LambdaVpcEniCleanup",
      );

    expect(statement).toEqual({
      Sid: "LambdaVpcEniCleanup",
      Effect: "Allow",
      Action: ["ec2:DeleteNetworkInterface"],
      Resource: [
        "arn:${AWS::Partition}:ec2:${ApplicationRegion}:${AWS::AccountId}:network-interface/*",
      ],
      Condition: {
        ArnEquals: {
          "ec2:Vpc": "ApplicationVpcArn",
          "ec2:Subnet": "ApplicationPrivateSubnetArns",
        },
      },
    });
  });
});

describe("deploy-role stack region", () => {
  it("auto-detects the owner stack without coupling its application region", () => {
    const { result, callRecords } = runDeployRoleFixture();
    const cloudFormationCalls = callRecords.filter(
      ({ args }) => args[0] === "cloudformation",
    );
    const ec2Calls = callRecords.filter(({ args }) => args[0] === "ec2");
    const updateCall = cloudFormationCalls.find(
      ({ args }) => args[1] === "update-stack",
    );
    const parameters = JSON.parse(
      optionValue(updateCall.args, "--parameters"),
    );

    expect(result.status, result.stderr).toBe(0);
    expect(
      cloudFormationCalls.map(({ args }) => args.slice(0, 2).join(" ")),
    ).toEqual([
      "cloudformation describe-stacks",
      "cloudformation update-stack",
      "cloudformation wait",
      "cloudformation describe-stacks",
    ]);
    expect(
      cloudFormationCalls.every(
        ({ args }) => optionValue(args, "--region") === "us-west-2",
      ),
    ).toBe(true);
    expect(ec2Calls).not.toHaveLength(0);
    expect(
      ec2Calls.every(
        ({ args }) => optionValue(args, "--region") === "eu-west-1",
      ),
    ).toBe(true);
    expect(parameters).toContainEqual({
      ParameterKey: "ApplicationRegion",
      ParameterValue: "eu-west-1",
    });
  });

  it.each([
    ["create", "--create", "cloudformation create-stack"],
    ["update", "--update", "cloudformation update-stack"],
  ])("pins forced %s operations to the owner region", (_, mode, operation) => {
    const { result, callRecords } = runDeployRoleFixture([mode]);
    const cloudFormationCalls = callRecords.filter(
      ({ args }) => args[0] === "cloudformation",
    );

    expect(result.status, result.stderr).toBe(0);
    expect(
      cloudFormationCalls.map(({ args }) => args.slice(0, 2).join(" ")),
    ).toContain(operation);
    expect(
      cloudFormationCalls.every(
        ({ args }) => optionValue(args, "--region") === "us-west-2",
      ),
    ).toBe(true);
  });
});

describe("reconciliation command fixtures", () => {
  it("succeeds on an exact match and calls only the expected read commands", () => {
    const { result, callRecords } = runFixture("match");
    const calls = callRecords.map(({ args }) => args.slice(0, 2).join(" "));

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("status=match");
    expect(calls).toEqual([
      "ssm get-parameters",
      "ecs wait",
      "ecs describe-services",
      "ecs list-tasks",
      "ecs describe-tasks",
    ]);
    expect(JSON.stringify(callRecords)).not.toMatch(
      /update-service|register-task-definition|deregister-task-definition/i,
    );
  });

  it("fails on drift, remains redacted, and makes no mutating ECS call", () => {
    const { result, callRecords } = runFixture("exported-new-ecs-old");
    const diagnostic = `${result.stdout}\n${result.stderr}`;

    expect(result.status).not.toBe(0);
    expect(diagnostic).toContain("status=mismatch");
    expect(diagnostic).toContain("task_definition=mem9-on-aws-prod-Mem9Server:42");
    expect(diagnostic).not.toMatch(/\d{12}/);
    expect(diagnostic).not.toContain("arn:");
    expect(JSON.stringify(callRecords)).not.toMatch(
      /update-service|register-task-definition|deregister-task-definition|list-task-definitions/i,
    );
  });
});
