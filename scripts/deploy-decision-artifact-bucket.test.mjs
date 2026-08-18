import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { parse } from "yaml";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const script = resolve(root, "scripts/deploy-decision-artifact-bucket.sh");
const fullTemplate = resolve(
  root,
  "infra/cloudformation/decision-artifact-bucket.yaml",
);
const importTemplate = resolve(
  root,
  "infra/cloudformation/decision-artifact-bucket-import.yaml",
);
const temporaryPaths = [];

function parseCloudFormation(path) {
  return parse(readFileSync(path, "utf8"), {
    customTags: [
      { tag: "!Ref", resolve: (value) => ({ Ref: value }) },
      { tag: "!Sub", resolve: (value) => ({ "Fn::Sub": value }) },
      {
        tag: "!GetAtt",
        resolve: (value) => ({ "Fn::GetAtt": value.split(".") }),
      },
    ],
  });
}

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) {
    rmSync(path, { force: true, recursive: true });
  }
});

function runFixture({
  bucket = "absent",
  bucketName = "",
  changeSetMismatch = false,
  drift = "IN_SYNC",
  recoveryHasResource = false,
  stack = "absent",
  stackBucketName = "",
  stackHasBucketParameter = true,
  stackPolicyOwned = true,
  stackStatus = "UPDATE_COMPLETE",
  updateNoop = false,
  verificationFailure = "",
} = {}) {
  const directory = mkdtempSync(join(tmpdir(), "mem9-artifact-bucket-"));
  temporaryPaths.push(directory);
  const aws = join(directory, "aws");
  const calls = join(directory, "calls.jsonl");

  writeFileSync(
    aws,
    `#!${process.execPath}
import { appendFileSync, existsSync, rmSync, writeFileSync } from "node:fs";

const args = process.argv.slice(2);
appendFileSync(process.env.MOCK_CALLS, JSON.stringify(args) + "\\n");
const command = args.slice(0, 2).join(" ");
const option = (name) => {
  const index = args.indexOf(name);
  return index === -1 ? "" : args[index + 1];
};
const stackNowExists = () =>
  !existsSync(process.env.MOCK_STACK_DELETED) &&
  (
    process.env.MOCK_STACK === "present" ||
    existsSync(process.env.MOCK_STACK_CREATED) ||
    existsSync(process.env.MOCK_FULL_STACK_CREATED)
  );
if (command === process.env.MOCK_VERIFICATION_FAILURE) {
  console.error("AccessDenied: simulated verification failure");
  process.exit(254);
}

switch (command) {
  case "sts get-caller-identity":
    console.log("123456789012");
    break;
  case "cloudformation validate-template":
    console.log("{}");
    break;
  case "cloudformation describe-stacks":
    if (process.env.MOCK_STACK === "denied") {
      console.error("AccessDenied: denied");
      process.exit(254);
    }
    if (!stackNowExists()) {
      console.error("ValidationError: Stack with id decision-artifact-bucket-mem9-on-aws does not exist");
      process.exit(255);
    }
    console.log(JSON.stringify({
      Stacks: [{
        StackStatus: existsSync(process.env.MOCK_UPDATED)
          ? "UPDATE_COMPLETE"
          : existsSync(process.env.MOCK_IMPORTED)
            ? "IMPORT_COMPLETE"
            : existsSync(process.env.MOCK_FULL_STACK_CREATED)
              ? "CREATE_COMPLETE"
          : process.env.MOCK_STACK_STATUS,
        Parameters:
          process.env.MOCK_STACK_HAS_BUCKET_PARAMETER === "false"
            ? []
            : [{
                ParameterKey: "DecisionArtifactBucketName",
                ParameterValue:
                  process.env.MOCK_STACK_BUCKET_NAME ||
                  process.env.MEM9_DECISION_ARTIFACT_BUCKET ||
                  "mem9-audit-123456789012",
              }],
      }],
    }));
    break;
  case "s3api head-bucket":
    if (process.env.MOCK_BUCKET === "denied") {
      console.error("An error occurred (403) when calling the HeadBucket operation: Forbidden");
      process.exit(254);
    }
    if (process.env.MOCK_BUCKET === "wrong-region") {
      console.error("An error occurred (301) when calling the HeadBucket operation: Moved Permanently");
      process.exit(254);
    }
    if (process.env.MOCK_BUCKET === "absent") {
      console.error("An error occurred (404) when calling the HeadBucket operation: Not Found");
      process.exit(254);
    }
    break;
  case "cloudformation create-change-set":
    rmSync(process.env.MOCK_STACK_DELETED, { force: true });
    writeFileSync(process.env.MOCK_STACK_CREATED, "1");
    break;
  case "cloudformation create-stack":
    rmSync(process.env.MOCK_STACK_DELETED, { force: true });
    writeFileSync(process.env.MOCK_FULL_STACK_CREATED, "1");
    break;
  case "cloudformation describe-change-set":
    console.log(JSON.stringify({
      Description:
        process.env.MOCK_CHANGE_SET_MISMATCH === "true"
          ? "unrecognized import"
          : "mem9 decision-artifact bucket adoption",
      Status: "CREATE_COMPLETE",
      ExecutionStatus: "AVAILABLE",
      Parameters: [{
        ParameterKey: "DecisionArtifactBucketName",
        ParameterValue:
          process.env.MOCK_STACK_BUCKET_NAME ||
          process.env.MEM9_DECISION_ARTIFACT_BUCKET ||
          "mem9-audit-123456789012",
      }],
      Changes: [{
        Type: "Resource",
        ResourceChange: {
          Action: "Import",
          LogicalResourceId: "DecisionArtifactBucket",
          ResourceType: "AWS::S3::Bucket",
        },
      }],
    }));
    break;
  case "cloudformation execute-change-set":
    writeFileSync(process.env.MOCK_IMPORTED, "1");
    break;
  case "cloudformation delete-stack":
    writeFileSync(process.env.MOCK_STACK_DELETED, "1");
    break;
  case "cloudformation update-stack":
    if (process.env.MOCK_UPDATE_NOOP === "true") {
      console.error("ValidationError: No updates are to be performed.");
      process.exit(255);
    }
    writeFileSync(process.env.MOCK_UPDATED, "1");
    break;
  case "cloudformation detect-stack-drift":
    if (command === "cloudformation detect-stack-drift") {
      console.log("drift-detection-id");
    }
    break;
  case "cloudformation wait":
    if (args[2] === "stack-import-complete") {
      writeFileSync(process.env.MOCK_IMPORTED, "1");
    }
    break;
  case "cloudformation describe-stack-resources":
    {
      const initialRecovery =
        ["REVIEW_IN_PROGRESS", "IMPORT_IN_PROGRESS", "IMPORT_ROLLBACK_COMPLETE"]
          .includes(process.env.MOCK_STACK_STATUS) &&
        !existsSync(process.env.MOCK_IMPORTED) &&
        !existsSync(process.env.MOCK_UPDATED) &&
        !existsSync(process.env.MOCK_FULL_STACK_CREATED);
      if (
        initialRecovery &&
        process.env.MOCK_RECOVERY_HAS_RESOURCE !== "true"
      ) {
        console.log(JSON.stringify({ StackResources: [] }));
        break;
      }
      const policyOwned =
        existsSync(process.env.MOCK_UPDATED) ||
        existsSync(process.env.MOCK_FULL_STACK_CREATED) ||
        (
          !existsSync(process.env.MOCK_IMPORTED) &&
          process.env.MOCK_STACK_POLICY_OWNED === "true"
        );
      console.log(JSON.stringify({
        StackResources: [
          {
            LogicalResourceId: "DecisionArtifactBucket",
            PhysicalResourceId:
              process.env.MOCK_STACK_BUCKET_NAME ||
              process.env.MEM9_DECISION_ARTIFACT_BUCKET ||
              "mem9-audit-123456789012",
            ResourceStatus: "UPDATE_COMPLETE",
            ResourceType: "AWS::S3::Bucket",
          },
          ...(policyOwned
            ? [{
                LogicalResourceId: "DecisionArtifactBucketPolicy",
                PhysicalResourceId:
                  process.env.MOCK_STACK_BUCKET_NAME ||
                  process.env.MEM9_DECISION_ARTIFACT_BUCKET ||
                  "mem9-audit-123456789012",
                ResourceStatus: "UPDATE_COMPLETE",
                ResourceType: "AWS::S3::BucketPolicy",
              }]
            : []),
        ],
      }));
      break;
    }
  case "s3api get-bucket-location":
    console.log(JSON.stringify({ LocationConstraint: "ap-northeast-1" }));
    break;
  case "s3api get-public-access-block":
    console.log(JSON.stringify({
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        IgnorePublicAcls: true,
        RestrictPublicBuckets: true,
      },
    }));
    break;
  case "s3api get-bucket-encryption":
    console.log(JSON.stringify({
      ServerSideEncryptionConfiguration: {
        Rules: [{
          ApplyServerSideEncryptionByDefault: {
            SSEAlgorithm: "aws:kms",
            KMSMasterKeyID: "alias/aws/s3",
          },
          BucketKeyEnabled: true,
        }],
      },
    }));
    break;
  case "s3api get-bucket-lifecycle-configuration":
    console.log(JSON.stringify({
      Rules: [{
        ID: "expire-decision-artifacts",
        Status: "Enabled",
        Filter: { Prefix: "" },
        Expiration: { Days: 3 },
        AbortIncompleteMultipartUpload: { DaysAfterInitiation: 1 },
      }],
    }));
    break;
  case "s3api get-bucket-policy":
    console.log(JSON.stringify({
      Policy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{
          Sid: "DenyInsecureTransport",
          Effect: "Deny",
          Principal: "*",
          Action: "s3:*",
          Resource: [
            \`arn:aws:s3:::\${option("--bucket")}\`,
            \`arn:aws:s3:::\${option("--bucket")}/*\`,
          ],
          Condition: { Bool: { "aws:SecureTransport": "false" } },
        }],
      }),
    }));
    break;
  case "s3api get-bucket-tagging":
    console.log(JSON.stringify({
      TagSet: [
        { Key: "ManagedBy", Value: "cloudformation" },
        { Key: "Project", Value: "mem9-on-aws" },
      ],
    }));
    break;
  case "cloudformation describe-stack-drift-detection-status":
    console.log(JSON.stringify({
      DetectionStatus: "DETECTION_COMPLETE",
      StackDriftStatus: process.env.MOCK_DRIFT,
    }));
    break;
  default:
    console.error("unexpected aws command:", command, args.join(" "));
    process.exit(2);
}
`,
  );
  chmodSync(aws, 0o755);

  const result = spawnSync("bash", [script], {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      AWS_PROFILE: "",
      MEM9_DECISION_ARTIFACT_BUCKET: bucketName,
      MOCK_BUCKET: bucket,
      MOCK_CALLS: calls,
      MOCK_CHANGE_SET_MISMATCH: String(changeSetMismatch),
      MOCK_DRIFT: drift,
      MOCK_FULL_STACK_CREATED: join(directory, "full-stack-created"),
      MOCK_IMPORTED: join(directory, "imported"),
      MOCK_RECOVERY_HAS_RESOURCE: String(recoveryHasResource),
      MOCK_STACK: stack,
      MOCK_STACK_BUCKET_NAME: stackBucketName,
      MOCK_STACK_DELETED: join(directory, "stack-deleted"),
      MOCK_STACK_HAS_BUCKET_PARAMETER: String(stackHasBucketParameter),
      MOCK_STACK_POLICY_OWNED: String(stackPolicyOwned),
      MOCK_STACK_STATUS: stackStatus,
      MOCK_UPDATE_NOOP: String(updateNoop),
      MOCK_STACK_CREATED: join(directory, "stack-created"),
      MOCK_UPDATED: join(directory, "updated"),
      MOCK_VERIFICATION_FAILURE: verificationFailure,
      PATH: `${directory}:${process.env.PATH}`,
    },
  });
  const callRecords = (existsSync(calls) ? readFileSync(calls, "utf8") : "")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  return {
    calls: callRecords,
    output: `${result.stdout}${result.stderr}`,
    result,
  };
}

const hasMutation = (calls) =>
  calls.some(
    ([service, operation]) =>
      service === "cloudformation" &&
      [
        "create-change-set",
        "create-stack",
        "execute-change-set",
        "update-stack",
      ].includes(operation),
  );

describe("decision-artifact bucket bootstrap", () => {
  it("TC-SLACKAPP-220 keeps import limited to the retained bucket", () => {
    const template = parseCloudFormation(importTemplate);
    expect(Object.keys(template.Resources)).toEqual(["DecisionArtifactBucket"]);
    expect(template.Resources.DecisionArtifactBucket).toMatchObject({
      Type: "AWS::S3::Bucket",
      DeletionPolicy: "Retain",
      UpdateReplacePolicy: "Retain",
      Properties: {
        BucketName: { Ref: "DecisionArtifactBucketName" },
      },
    });
    expect(template.Outputs).toBeUndefined();
    expect(
      parseCloudFormation(fullTemplate).Parameters.DecisionArtifactBucketName,
    ).toEqual(template.Parameters.DecisionArtifactBucketName);
  });

  it("TC-SLACKAPP-220 imports an existing bucket before applying the full template", () => {
    const { calls, output, result } = runFixture({ bucket: "present" });
    expect(result.status, output).toBe(0);
    const importCall = calls.find(
      ([service, operation]) =>
        service === "cloudformation" && operation === "create-change-set",
    );
    expect(importCall).toBeDefined();
    expect(importCall.join(" ")).toContain(
      "infra/cloudformation/decision-artifact-bucket-import.yaml",
    );
    const resources = JSON.parse(
      importCall[importCall.indexOf("--resources-to-import") + 1],
    );
    expect(resources).toEqual([
      {
        ResourceType: "AWS::S3::Bucket",
        LogicalResourceId: "DecisionArtifactBucket",
        ResourceIdentifier: { BucketName: "mem9-audit-123456789012" },
      },
    ]);
    const imported = calls.findIndex(
      (call) =>
        call[0] === "cloudformation" &&
        call[1] === "wait" &&
        call[2] === "stack-import-complete",
    );
    const updated = calls.findIndex(
      ([service, operation]) =>
        service === "cloudformation" && operation === "update-stack",
    );
    expect(imported).toBeGreaterThanOrEqual(0);
    expect(updated).toBeGreaterThan(imported);
    expect(calls[updated].join(" ")).toContain(
      "infra/cloudformation/decision-artifact-bucket.yaml",
    );
  });

  it("TC-SLACKAPP-219 passes a validated override through create and verification", () => {
    const override = "example-mem9-decision-artifacts";
    const { calls, output, result } = runFixture({ bucketName: override });
    expect(result.status, output).toBe(0);
    const create = calls.find(
      ([service, operation]) =>
        service === "cloudformation" && operation === "create-stack",
    );
    expect(create.join(" ")).toContain(
      `ParameterKey=DecisionArtifactBucketName,ParameterValue=${override}`,
    );
    for (const call of calls.filter(([service]) => service === "s3api")) {
      expect(call[call.indexOf("--bucket") + 1]).toBe(override);
    }
  });

  it.each([
    "UPPERCASE",
    "ab",
    "192.0.2.1",
    "bad..name",
    "bad_name",
    "xn--reserved",
    "sthree-reserved",
    "amzn-s3-demo-reserved",
    "reserved-s3alias",
    "reserved--ol-s3",
    "reserved--x-s3",
    "reserved--table-s3",
    "reserved-an",
    "a".repeat(34),
  ])(
    "TC-SLACKAPP-219 rejects invalid override %s before AWS",
    (bucketName) => {
      const { calls, output, result } = runFixture({ bucketName });
      expect(result.status).toBe(2);
      expect(output).toMatch(/invalid.*bucket name/iu);
      expect(calls).toEqual([]);
    },
  );

  it.each([
    ["stack discovery", { stack: "denied" }],
    ["bucket discovery", { bucket: "denied" }],
    ["wrong-region bucket", { bucket: "wrong-region" }],
  ])("TC-SLACKAPP-221 fails closed on %s", (_name, options) => {
    const { calls, output, result } = runFixture(options);
    expect(result.status, output).not.toBe(0);
    expect(hasMutation(calls)).toBe(false);
  });

  it("TC-SLACKAPP-221 resumes its verified REVIEW_IN_PROGRESS import", () => {
    const { calls, output, result } = runFixture({
      bucket: "present",
      stack: "present",
      stackStatus: "REVIEW_IN_PROGRESS",
    });
    expect(result.status, output).toBe(0);
    expect(
      calls.some(
        ([service, operation]) =>
          service === "cloudformation" && operation === "create-change-set",
      ),
    ).toBe(false);
    const described = calls.findIndex(
      ([service, operation]) =>
        service === "cloudformation" && operation === "describe-change-set",
    );
    const executed = calls.findIndex(
      ([service, operation]) =>
        service === "cloudformation" && operation === "execute-change-set",
    );
    expect(described).toBeGreaterThanOrEqual(0);
    expect(executed).toBeGreaterThan(described);
  });

  it("TC-SLACKAPP-221 refuses an unrecognized REVIEW_IN_PROGRESS change set", () => {
    const { calls, output, result } = runFixture({
      bucket: "present",
      changeSetMismatch: true,
      stack: "present",
      stackStatus: "REVIEW_IN_PROGRESS",
    });
    expect(result.status, output).not.toBe(0);
    expect(output).toMatch(/change set read-back mismatch/iu);
    expect(
      calls.some(
        ([service, operation]) =>
          service === "cloudformation" && operation === "execute-change-set",
      ),
    ).toBe(false);
  });

  it("TC-SLACKAPP-221 resumes waiting for an IMPORT_IN_PROGRESS stack", () => {
    const { calls, output, result } = runFixture({
      bucket: "present",
      stack: "present",
      stackStatus: "IMPORT_IN_PROGRESS",
    });
    expect(result.status, output).toBe(0);
    const importWait = calls.findIndex(
      (call) =>
        call[0] === "cloudformation" &&
        call[1] === "wait" &&
        call[2] === "stack-import-complete",
    );
    const updated = calls.findIndex(
      ([service, operation]) =>
        service === "cloudformation" && operation === "update-stack",
    );
    expect(importWait).toBeGreaterThanOrEqual(0);
    expect(updated).toBeGreaterThan(importWait);
  });

  it("TC-SLACKAPP-221 recreates a verified empty IMPORT_ROLLBACK_COMPLETE shell", () => {
    const { calls, output, result } = runFixture({
      bucket: "present",
      stack: "present",
      stackStatus: "IMPORT_ROLLBACK_COMPLETE",
    });
    expect(result.status, output).toBe(0);
    const deleted = calls.findIndex(
      ([service, operation]) =>
        service === "cloudformation" && operation === "delete-stack",
    );
    const recreated = calls.findIndex(
      ([service, operation]) =>
        service === "cloudformation" && operation === "create-change-set",
    );
    expect(deleted).toBeGreaterThanOrEqual(0);
    expect(recreated).toBeGreaterThan(deleted);
  });

  it("TC-SLACKAPP-221 never deletes an import-rollback stack with resources", () => {
    const { calls, output, result } = runFixture({
      bucket: "present",
      recoveryHasResource: true,
      stack: "present",
      stackStatus: "IMPORT_ROLLBACK_COMPLETE",
    });
    expect(result.status, output).not.toBe(0);
    expect(output).toMatch(/unexpectedly owns resources/iu);
    expect(
      calls.some(
        ([service, operation]) =>
          service === "cloudformation" && operation === "delete-stack",
      ),
    ).toBe(false);
  });

  it("TC-SLACKAPP-222 rejects CloudFormation drift after live read-back", () => {
    const { calls, output, result } = runFixture({ drift: "DRIFTED" });
    expect(result.status, output).not.toBe(0);
    expect(output).toMatch(/drift/iu);
    expect(
      calls.some(
        ([service, operation]) =>
          service === "cloudformation" && operation === "detect-stack-drift",
      ),
    ).toBe(true);
    for (const operation of [
      "get-public-access-block",
      "get-bucket-encryption",
      "get-bucket-lifecycle-configuration",
      "get-bucket-policy",
    ]) {
      expect(
        calls.some(
          ([service, candidate]) =>
            service === "s3api" && candidate === operation,
        ),
      ).toBe(true);
    }
  });

  it("TC-SLACKAPP-222 requires CloudFormation to own the TLS bucket policy", () => {
    const { calls, output, result } = runFixture({
      stack: "present",
      stackPolicyOwned: false,
      updateNoop: true,
    });
    expect(result.status, output).not.toBe(0);
    expect(output).toMatch(/policy ownership/iu);
    expect(
      calls.some(
        ([service, operation]) =>
          service === "cloudformation" && operation === "detect-stack-drift",
      ),
    ).toBe(false);
  });

  it("TC-SLACKAPP-221 fails closed when a verification read errors", () => {
    const { calls, output, result } = runFixture({
      verificationFailure: "s3api get-bucket-encryption",
    });
    expect(result.status, output).not.toBe(0);
    expect(output).toMatch(/encryption failed/iu);
    expect(
      calls.some(
        ([service, operation]) =>
          service === "cloudformation" && operation === "detect-stack-drift",
      ),
    ).toBe(false);
  });

  it("TC-SLACKAPP-219 refuses to replace an existing stack's bucket", () => {
    const { calls, output, result } = runFixture({
      bucketName: "example-mem9-decision-artifacts",
      stack: "present",
      stackBucketName: "existing-mem9-decision-artifacts",
    });
    expect(result.status, output).not.toBe(0);
    expect(output).toMatch(/different bucket.*refusing replacement/iu);
    expect(hasMutation(calls)).toBe(false);
  });

  it("TC-SLACKAPP-219 refuses replacement when a legacy stack has no name parameter", () => {
    const { calls, output, result } = runFixture({
      bucketName: "example-mem9-decision-artifacts",
      stack: "present",
      stackBucketName: "mem9-audit-123456789012",
      stackHasBucketParameter: false,
    });
    expect(result.status, output).not.toBe(0);
    expect(output).toMatch(/different bucket.*refusing replacement/iu);
    expect(hasMutation(calls)).toBe(false);
  });

  it("TC-SLACKAPP-221 retries a verified bucket from UPDATE_ROLLBACK_COMPLETE", () => {
    const { calls, output, result } = runFixture({
      stack: "present",
      stackStatus: "UPDATE_ROLLBACK_COMPLETE",
    });
    expect(result.status, output).toBe(0);
    expect(
      calls.some(
        ([service, operation]) =>
          service === "cloudformation" && operation === "update-stack",
      ),
    ).toBe(true);
  });

  it("TC-SLACKAPP-221 accepts a verified no-op retry from UPDATE_ROLLBACK_COMPLETE", () => {
    const { calls, output, result } = runFixture({
      stack: "present",
      stackStatus: "UPDATE_ROLLBACK_COMPLETE",
      updateNoop: true,
    });
    expect(result.status, output).toBe(0);
    expect(output).toContain("No template update was required");
    expect(
      calls.some(
        ([service, operation]) =>
          service === "cloudformation" && operation === "detect-stack-drift",
      ),
    ).toBe(true);
  });

  it("TC-SLACKAPP-221 refuses UPDATE_ROLLBACK_FAILED without mutation", () => {
    const { calls, output, result } = runFixture({
      stack: "present",
      stackStatus: "UPDATE_ROLLBACK_FAILED",
    });
    expect(result.status, output).not.toBe(0);
    expect(output).toMatch(/continue-update-rollback/iu);
    expect(hasMutation(calls)).toBe(false);
  });
});
