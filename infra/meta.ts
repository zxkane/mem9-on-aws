/**
 * `meta` stack — shared deployment metadata and network exports.
 *
 * Writes a handful of SSM parameters under `/mem9-on-aws/${stage}/...`. It is
 * cheap (SSM Standard parameters are free), deploys in seconds, and serves two
 * purposes:
 *   1. Records the deployed stage and selected VPC for operators.
 *   2. Establishes the SSM export namespace used by the other stacks:
 *      `/mem9-on-aws/${stage}/<component>/<key>`.
 *
 * Other stacks extend this namespace: `.../db/endpoint`, `.../gateway/url`,
 * `.../cognito/client-id`, etc.
 */

import { resolveVpc } from "./vpc";

export interface MetaOutputs {
  ssmPrefix: string;
  vpcId: Output<string>;
  privateSubnetIds: Output<string[]>;
}

export function meta(): MetaOutputs {
  const prefix = `/mem9-on-aws/${$app.stage}`;
  const { vpcId, privateSubnetIds } = resolveVpc();

  const tags = {
    Project: "mem9-on-aws",
    Stage: $app.stage,
    ManagedBy: "sst",
  };

  // Stage marker for deploy diagnostics and cross-module SSM wiring.
  new aws.ssm.Parameter("MetaStageMarker", {
    name: `${prefix}/meta/stage`,
    type: "String",
    value: $app.stage,
    tags,
  });

  // Resolved VPC facts (from vpc.ts) — later stacks + CI read these.
  new aws.ssm.Parameter("MetaVpcId", {
    name: `${prefix}/vpc/id`,
    type: "String",
    value: vpcId,
    tags,
  });

  // Comma-joined subnet id list, stored as an SSM StringList.
  new aws.ssm.Parameter("MetaPrivateSubnetIds", {
    name: `${prefix}/vpc/private-subnet-ids`,
    type: "StringList",
    value: privateSubnetIds.apply((ids) => ids.join(",")),
    tags,
  });

  return { ssmPrefix: prefix, vpcId, privateSubnetIds };
}
