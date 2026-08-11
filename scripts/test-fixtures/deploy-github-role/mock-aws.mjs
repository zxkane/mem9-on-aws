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
  if (value) process.stdout.write(`${value}\n`);
  process.exit(0);
}

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
  case "sts get-caller-identity":
    respond(
      optionValue("--query") === "Account"
        ? "<aws-account-id>"
        : "arn:aws:sts::<aws-account-id>:assumed-role/fixture/operator",
    );
    break;
  case "cloudformation describe-stacks": {
    const region = optionValue("--region");
    const query = optionValue("--query");
    if (query?.includes("ApplicationRegion")) {
      respond(process.env.MOCK_APPLICATION_REGION ?? "eu-west-1");
    }
    if (query) {
      respond("arn:aws:iam::<aws-account-id>:role/github-actions-mem9-on-aws");
    }
    if (region === "us-west-2") respond("{}");
    process.exit(255);
    break;
  }
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
