#!/usr/bin/env node

import process from "node:process";

function sameSingleValue(values, expected) {
  return Array.isArray(values) && values.length === 1 && values[0] === expected;
}

export function validateNamespaceNetwork({
  lambdaSecurityGroups,
  dbClusters,
  dbHost,
  dbSecurityGroup,
  taskSecurityGroup,
  proxySecurityGroup,
  dbPermissions,
}) {
  if (taskSecurityGroup === proxySecurityGroup) {
    throw new Error("Gateway proxy shares the Aurora-authorized ECS SG");
  }
  if (!sameSingleValue(lambdaSecurityGroups, proxySecurityGroup)) {
    throw new Error("Gateway proxy Lambda does not use only its dedicated SG");
  }
  const clusters = (dbClusters ?? []).filter(
    ({ Endpoint }) => Endpoint === dbHost,
  );
  if (
    clusters.length !== 1 ||
    !sameSingleValue(
      clusters[0].VpcSecurityGroups?.map(
        ({ VpcSecurityGroupId }) => VpcSecurityGroupId,
      ),
      dbSecurityGroup,
    )
  ) {
    throw new Error("Aurora does not use only the expected DB SG");
  }
  if (dbPermissions?.length !== 1) {
    throw new Error("Aurora SG must have one ingress permission");
  }
  const permission = dbPermissions[0];
  if (
    permission.IpProtocol !== "tcp" ||
    permission.FromPort !== 5432 ||
    permission.ToPort !== 5432 ||
    !sameSingleValue(
      permission.UserIdGroupPairs?.map(({ GroupId }) => GroupId),
      taskSecurityGroup,
    ) ||
    (permission.IpRanges?.length ?? 0) !== 0 ||
    (permission.Ipv6Ranges?.length ?? 0) !== 0 ||
    (permission.PrefixListIds?.length ?? 0) !== 0
  ) {
    throw new Error("Aurora SG is not restricted to the ECS/bootstrap SG");
  }
  return { version: 1, network_isolated: true };
}

async function main() {
  let input = "";
  for await (const chunk of process.stdin) input += chunk;
  const result = validateNamespaceNetwork(JSON.parse(input));
  process.stdout.write(
    `${JSON.stringify({
      event: "namespace_connection_network",
      ...result,
    })}\n`,
  );
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  main().catch((error) => {
    process.stderr.write(`namespace network validation failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
