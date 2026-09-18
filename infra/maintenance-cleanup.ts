import type { DbOutputs } from "./db";
import type { EcsOutputs } from "./ecs";
import type { MaintenanceIdentityOutputs } from "./namespace-identity";
import type { TenantIdentityOutputs } from "./tenant-identity";
import { accountId, applicationRegion, workloadImage } from "./ecr";
import { resolveVpc } from "./vpc";
import { taskContainerLogGroupName } from "./consolidation";
import { disableTaskContainerPseudoTerminal } from "./ecs-task-definition";

// Keep the existing cleanup task/execution-role family allowed by the boundary.
export const CLEANUP_CONTAINER_NAME = "Mem9Cleanup";

export interface StandaloneCleanupOutputs {
  taskDefinitionArn: Output<string>;
}

/** One shared operator task. Each invocation must provide its own namespace. */
export function standaloneCleanupTask(
  ecsOut: EcsOutputs,
  dbOut: DbOutputs,
  identity: TenantIdentityOutputs,
  maintenanceIdentity: MaintenanceIdentityOutputs,
): StandaloneCleanupOutputs {
  const prefix = `/mem9-on-aws/${$app.stage}/maintenance/cleanup`;
  const tags = { Project: "mem9-on-aws", Stage: $app.stage, ManagedBy: "sst" };
  const region = applicationRegion();
  const account = accountId();
  const baseUrl = $interpolate`http://${ecsOut.serviceDnsName}:8080`;
  const primaryProject = process.env.MEM9_BEDROCK_PROJECT || "";
  const responsesProject = process.env.MEM9_BEDROCK_PROJECT_OPENAI || "";
  const responsesRegion = process.env.MEM9_LLM_RESPONSES_REGION || "us-west-2";

  // Same inference operations as consolidation, with each regional Project
  // scoped independently. Secrets are injected by the ECS execution role.
  const permissions: sst.aws.FargatePermission[] = [
    {
      actions: ["bedrock-mantle:CreateInference"],
      resources: [
        primaryProject
          ? $interpolate`arn:aws:bedrock-mantle:${region}:${account}:project/${primaryProject}`
          : "*",
        ...(responsesProject
          ? [$interpolate`arn:aws:bedrock-mantle:${responsesRegion}:${account}:project/${responsesProject}`]
          : []),
      ],
    },
    {
      actions: [
        "bedrock-mantle:CallWithBearerToken",
        "bedrock-mantle:GetProject",
        "bedrock-mantle:ListProjects",
        "bedrock-mantle:ListTagsForResource",
      ],
      resources: ["*"],
    },
  ];

  const task = new sst.aws.Task(CLEANUP_CONTAINER_NAME, {
    cluster: ecsOut.cluster,
    architecture: "arm64",
    cpu: "0.5 vCPU",
    memory: "1 GB",
    image: workloadImage("llm-proxy", process.env.MEM9_IMAGE_TAG || "latest"),
    entrypoint: ["node"],
    // The CLI requires --stage and uses --base-url to bypass discovery. It
    // defaults to a dry run; apply requires an explicit operator override.
    command: [
      "/app/scripts/memory-cleanup.mjs",
      "--stage", $app.stage,
      "--base-url", baseUrl,
    ],
    environment: {
      AWS_REGION: region,
      MEM9_STAGE: $app.stage,
      MEM9_BASE_URL: baseUrl,
      MEM9_DB_HOST: dbOut.host,
      MEM9_DB_PORT: dbOut.port.apply(String),
      MEM9_DB_NAME: dbOut.database,
      MEM9_LLM_MODEL: process.env.MEM9_LLM_MODEL || "zai.glm-5",
      MEM9_BEDROCK_PROJECT: primaryProject,
      MEM9_BEDROCK_PROJECT_OPENAI: responsesProject,
      MEM9_LLM_RESPONSES_REGION: responsesRegion,
      MEM9_SERVICE_TRANSPORT_ISSUER: "maintenance:cleanup",
      MEM9_SERVICE_TRANSPORT_SIGNING_REVISION: maintenanceIdentity.revision,
    },
    ssm: {
      MEM9_DB_SECRET: dbOut.secretArn,
      MEM9_TENANT_ID: identity.tenantSecretArn,
      MEM9_SERVICE_TRANSPORT_SIGNING_KEYS:
        maintenanceIdentity.serviceParameterArns.cleanup,
    },
    permissions,
    logging: { retention: "1 month" },
    transform: {
      taskDefinition: (args) => {
        disableTaskContainerPseudoTerminal(args, CLEANUP_CONTAINER_NAME);
        args.tags = { ...(args.tags ?? {}), ...tags };
      },
    },
  });

  const parameters: Array<[string, string, Input<string>]> = [
    ["MaintenanceCleanupTaskDefArn", "task-def-arn", task.taskDefinition],
    ["MaintenanceCleanupClusterName", "cluster-name", ecsOut.clusterName],
    ["MaintenanceCleanupTaskSgId", "task-sg-id", dbOut.taskSecurityGroupId],
    [
      "MaintenanceCleanupSubnetIds", "subnet-ids",
      // Task.subnets can contain nested Outputs; resolve before joining.
      resolveVpc().privateSubnetIds.apply((ids) => ids.join(",")),
    ],
    [
      "MaintenanceCleanupLogGroupName", "log-group-name",
      taskContainerLogGroupName(task, CLEANUP_CONTAINER_NAME, "cleanup"),
    ],
  ];
  for (const [name, suffix, value] of parameters) {
    new aws.ssm.Parameter(name, {
      name: `${prefix}/${suffix}`,
      type: suffix === "subnet-ids" ? "StringList" : "String",
      value,
      tags,
    });
  }

  return { taskDefinitionArn: task.taskDefinition };
}
