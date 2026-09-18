#!/usr/bin/env node
import { execFile } from "node:child_process";
import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { main as runAcceptance } from "./run-human-namespace-e2e.mjs";

const exec = promisify(execFile);
const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`missing ${name}`);
  return value;
};
async function aws(args) {
  const { stdout } = await exec("aws", [
    ...args,
    "--region",
    required("AWS_REGION"),
    "--output",
    "json",
    "--no-cli-pager",
  ]);
  return JSON.parse(stdout);
}

export async function main() {
  const stage = required("MEM9_STAGE");
  if (!/^pr-[1-9][0-9]*$/u.test(stage))
    throw new Error("human acceptance requires a PR stage");
  const prefix = `/mem9-on-aws/${stage}`;
  const names = [
    "cognito/user-pool-id",
    "facade/url",
    "gateway/url",
    "gateway/proxy-function-arn",
  ].map((suffix) => `${prefix}/${suffix}`);
  const parameters = await aws(["ssm", "get-parameters", "--names", ...names]);
  const values = Object.fromEntries(
    parameters.Parameters.map((item) => [item.Name, item.Value]),
  );
  if (parameters.InvalidParameters?.length || names.some((name) => !values[name]))
    throw new Error("preview target parameters are incomplete");
  const identity = await aws(["sts", "get-caller-identity"]);
  const clusters = await aws(["rds", "describe-db-clusters"]);
  const cluster = clusters.DBClusters.find(
    (item) => item.Endpoint === required("MEM9_DB_HOST"),
  );
  if (!cluster) throw new Error("preview database cluster not found");
  const proxyArn = values[`${prefix}/gateway/proxy-function-arn`];
  const proxy = await aws([
    "lambda",
    "get-function-configuration",
    "--function-name",
    proxyArn,
  ]);
  const directory = await mkdtemp(join(tmpdir(), "human-namespace-task-"));
  const deployment = join(directory, "deployment.local.json");
  const fixtures = join(directory, "fixtures.local.json");
  const evidence = join(directory, "evidence.json");
  const manifest = {
    version: 1,
    stage,
    commit: required("MEM9_DEPLOY_COMMIT"),
    accountId: identity.Account,
    region: required("AWS_REGION"),
    userPoolId: values[`${prefix}/cognito/user-pool-id`],
    facadeUrl: values[`${prefix}/facade/url`],
    gatewayUrl: values[`${prefix}/gateway/url`],
    proxyFunctionArn: proxyArn,
    proxyLogGroup:
      proxy.LoggingConfig?.LogGroup ??
      `/aws/lambda/${proxyArn.split(":function:")[1]}`,
    database: {
      host: required("MEM9_DB_HOST"),
      port: Number(required("MEM9_DB_PORT")),
      name: required("MEM9_DB_NAME"),
      resourceId: cluster.DbClusterResourceId,
      clusterId: cluster.DBClusterIdentifier,
      secretArn: required("MEM9_DB_SECRET_ARN"),
      caFile: "/app/global-bundle.pem",
    },
    namespaces: [
      {
        slug: required("MEM9_PREVIEW_NAMESPACE_ALPHA_SLUG"),
        display_name: "PR isolation fixture preview-alpha",
        cognito_group: required("MEM9_PREVIEW_NAMESPACE_ALPHA_GROUP"),
        default_role: "member",
        jit_enabled: true,
        status: "active",
      },
      {
        slug: required("MEM9_PREVIEW_NAMESPACE_BETA_SLUG"),
        display_name: "PR isolation fixture preview-beta",
        cognito_group: required("MEM9_PREVIEW_NAMESPACE_BETA_GROUP"),
        default_role: "member",
        jit_enabled: true,
        status: "active",
      },
    ],
  };
  await writeFile(deployment, JSON.stringify(manifest), { mode: 0o600 });
  await chmod(deployment, 0o600);
  try {
    await runAcceptance([
      "--deployment-file",
      deployment,
      "--fixtures-file",
      fixtures,
      "--evidence-file",
      evidence,
    ]);
  } catch (error) {
    let publicCode = "operator_failure";
    try {
      const failure = JSON.parse(
        await readFile(`${fixtures}.failure.local.json`, "utf8"),
      );
      const candidate =
        failure.name === "HumanAcceptanceError"
          ? failure.message
          : failure.name;
      if (/^[A-Za-z][A-Za-z0-9_]{0,63}$/u.test(candidate))
        publicCode = candidate;
    } catch {
      // The task log remains intentionally content-free.
    }
    error.publicCode = publicCode;
    throw error;
  }
  const result = JSON.parse(await readFile(evidence, "utf8"));
  if (result.success !== true || result.cleanup_complete !== true)
    throw new Error("human acceptance evidence is incomplete");
}

if (
  process.argv[1] &&
  new URL(`file://${process.argv[1]}`).href === import.meta.url
) {
  main().catch((error) => {
    process.stderr.write(
      `human namespace preview acceptance failed (${error.publicCode ?? "operator_failure"})\n`,
    );
    process.exitCode = 1;
  });
}
