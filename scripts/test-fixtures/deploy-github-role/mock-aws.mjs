#!/usr/bin/env node

import { appendFileSync } from "node:fs";

const callLog = process.env.AWS_CALL_LOG;

if (!callLog) {
  process.stderr.write("deploy-role fake aws requires AWS_CALL_LOG\n");
  process.exit(2);
}

const args = process.argv.slice(2);
appendFileSync(callLog, `${JSON.stringify({ args })}\n`);

function optionValue(option) {
  const index = args.indexOf(option);
  return index >= 0 ? args[index + 1] : undefined;
}

function respond(value = "") {
  if (value) process.stdout.write(`${typeof value === "string" ? value : JSON.stringify(value)}\n`);
  process.exit(0);
}

const accountId = "123456789012";
const roleStackName = "github-actions-mem9-on-aws";
const artifactStackName = "decision-artifact-bucket-mem9-on-aws";
const boundaryStackName = "workload-permissions-boundary-mem9-on-aws";
const bucketName = `mem9-audit-${accountId}`;
const applicationRegion = "eu-west-1";
const stackId = (name, region) => `arn:aws:cloudformation:${region}:${accountId}:stack/${name}/fixture-id`;
const stackMetadata = (name, region, parameters) => ({
  StackName: name,
  StackId: stackId(name, region),
  StackStatus: "UPDATE_COMPLETE",
  Parameters: Object.entries(parameters).map(([ParameterKey, ParameterValue]) => ({ ParameterKey, ParameterValue })),
});

const command = args.slice(0, 2).join(" ");

switch (command) {
  case "s3api list-buckets":
    respond("fixture-template-bucket");
    break;
  case "s3api get-bucket-location":
    respond("us-west-1");
    break;
  case "s3 cp":
    respond();
    break;
  case "iam list-open-id-connect-providers":
    respond("None");
    break;
  case "ec2 describe-vpcs":
    respond(`vpc-${"a".repeat(17)}`);
    break;
  case "ec2 describe-subnets":
    respond(`subnet-${"b".repeat(17)}\tsubnet-${"c".repeat(17)}`);
    break;
  case "servicediscovery list-namespaces":
    respond('["ns-fixture"]');
    break;
  case "servicediscovery get-namespace":
    respond("ZFIXTURE123");
    break;
  case "route53 get-hosted-zone":
    respond(`["vpc-${"a".repeat(17)}"]`);
    break;
  case "sts get-caller-identity":
    respond({ Account: accountId, Arn: `arn:aws:sts::${accountId}:assumed-role/fixture/operator`, UserId: "fixture:operator" });
    break;
  case "cloudformation describe-stacks": {
    const region = optionValue("--region");
    const query = optionValue("--query");
    const name = optionValue("--stack-name");
    if (name === roleStackName && region === "us-west-2") {
      if (query?.includes("Outputs")) {
        const suffix = query.includes("PreviewRoleArn") ? "-preview" : query.includes("ProductionRoleArn") ? "-prod" : "";
        respond(`arn:aws:iam::${accountId}:role/${roleStackName}${suffix}`);
      }
      if (process.env.MOCK_ROLE_STACK_ABSENT === "true") {
        process.stderr.write(`An error occurred (ValidationError) when calling the DescribeStacks operation: Stack with id ${name} does not exist\n`);
        process.exit(254);
      }
      respond({ Stacks: [stackMetadata(name, region, {
        ApplicationRegion: process.env.MOCK_APPLICATION_REGION ?? applicationRegion,
        LegacyRoleEnabled: process.env.MOCK_LEGACY_ROLE_ENABLED ?? "true",
        ProjectName: "mem9-on-aws",
        GitHubRepo: "mem9-on-aws",
      })] });
    }
    if (name === artifactStackName && region === applicationRegion) {
      respond({ Stacks: [stackMetadata(name, region, { DecisionArtifactBucketName: bucketName })] });
    }
    if (name === boundaryStackName && region === "us-west-2") {
      respond({ Stacks: [stackMetadata(name, region, {
        ApplicationRegion: applicationRegion,
        DecisionArtifactBucketName: bucketName,
      })] });
    }
    process.stderr.write("unexpected fixture stack identity or region\n");
    process.exit(255);
    break;
  }
  case "cloudformation describe-stack-resource":
    if (optionValue("--stack-name") !== stackId(artifactStackName, applicationRegion) ||
        optionValue("--logical-resource-id") !== "DecisionArtifactBucket" ||
        optionValue("--region") !== applicationRegion) {
      process.stderr.write("unexpected fixture artifact resource identity\n");
      process.exit(255);
    }
    respond({ StackResourceDetail: {
      StackId: stackId(artifactStackName, applicationRegion),
      LogicalResourceId: "DecisionArtifactBucket",
      PhysicalResourceId: bucketName,
      ResourceType: "AWS::S3::Bucket",
      ResourceStatus: "CREATE_COMPLETE",
    } });
    break;
  case "cloudformation create-stack":
    respond();
    break;
  case "cloudformation update-stack":
  case "cloudformation wait":
    respond();
    break;
  default:
    process.stderr.write(`unexpected fake aws command: ${command}\n`);
    process.exit(2);
}
