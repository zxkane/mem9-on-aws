import type { CognitoOutputs } from "./cognito";
import type { DbOutputs } from "./db";
import { workloadImage } from "./ecr";
import { resolveVpc } from "./vpc";

export function humanAcceptance(
  cluster: sst.aws.Cluster,
  dbOut: DbOutputs,
  cognito: CognitoOutputs | undefined,
): void {
  if (!/^pr-[1-9][0-9]*$/u.test($app.stage) || !cognito) return;
  const [alpha, beta] = cognito.previewNamespaceClients;
  if (!alpha || !beta) throw new Error("preview namespace fixtures required");
  const prefix = `/mem9-on-aws/${$app.stage}/human-acceptance`;
  const tags = { Project: "mem9-on-aws", Stage: $app.stage, ManagedBy: "sst" };
  const region = aws.getRegionOutput().name;
  const { privateSubnetIds } = resolveVpc();
  const task = new sst.aws.Task("Mem9HumanAcceptance", {
    cluster,
    architecture: "arm64",
    cpu: "1 vCPU",
    memory: "2 GB",
    image: workloadImage(
      "bootstrap",
      process.env.MEM9_HUMAN_ACCEPTANCE_IMAGE_TAG || "human-latest",
    ),
    environment: {
      AWS_REGION: region,
      MEM9_STAGE: $app.stage,
      MEM9_DEPLOY_COMMIT: process.env.MEM9_DEPLOY_COMMIT || "",
      MEM9_DB_HOST: dbOut.host,
      MEM9_DB_PORT: dbOut.port.apply(String),
      MEM9_DB_NAME: dbOut.database,
      MEM9_DB_SECRET_ARN: dbOut.secretArn,
      MEM9_PREVIEW_NAMESPACE_ALPHA_SLUG: alpha.namespaceSlug,
      MEM9_PREVIEW_NAMESPACE_ALPHA_GROUP: alpha.cognitoGroup,
      MEM9_PREVIEW_NAMESPACE_BETA_SLUG: beta.namespaceSlug,
      MEM9_PREVIEW_NAMESPACE_BETA_GROUP: beta.cognitoGroup,
    },
    logging: { retention: "1 month" },
    transform: {
      taskDefinition: (args) => {
        args.tags = { ...(args.tags ?? {}), ...tags };
      },
    },
  });

  const parameter = (name: string, suffix: string, value: Input<string>) =>
    new aws.ssm.Parameter(name, {
      name: `${prefix}/${suffix}`,
      type: "String",
      value,
      tags,
    });
  parameter("HumanAcceptanceTaskDefArn", "task-def-arn", task.taskDefinition);
  parameter(
    "HumanAcceptanceClusterName",
    "cluster-name",
    cluster.nodes.cluster.name,
  );
  parameter(
    "HumanAcceptanceTaskSgId",
    "task-sg-id",
    dbOut.taskSecurityGroupId,
  );
  parameter(
    "HumanAcceptanceSubnetIds",
    "subnet-ids",
    privateSubnetIds.apply((ids) => ids.join(",")),
  );
}
