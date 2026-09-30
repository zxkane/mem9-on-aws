import {runtimeRoleName, runtimePreviewStage} from "../scripts/lib/runtime-credentials.mjs";
import {probeRoleName} from "../scripts/lib/runtime-admin-probe-config.mjs";

export interface RuntimeCredentials {
  parameterArn: Output<string>;
  ready: boolean;
  probeParameterArn?: Output<string>;
  executionRoleArn?: Output<string>;
}

/** Stable across preview generations. Only bootstrap receives the owner secret. */
export function runtimeCredentials(): RuntimeCredentials | undefined {
  if (!runtimePreviewStage($app.stage)) return;
  const ready = process.env.MEM9_RUNTIME_READY ?? "0";
  if (!["0", "1"].includes(ready)) throw Error("InvalidRuntimeReady");
  if (ready === "1" && process.env.MEM9_NAMESPACE_REQUIRED !== "1") {
    throw Error("RuntimeRequiresNamespaces");
  }
  const password = new random.RandomPassword("RuntimeDatabasePassword", {length: 48, special: false});
  const salt = new random.RandomPassword("RuntimeDatabaseSalt", {length: 32, special: false});
  const parameter = new aws.ssm.Parameter("RuntimeDatabaseCredential", {
    name: `/mem9-on-aws/${$app.stage}/runtime/database-credential`,
    type: "SecureString",
    value: $jsonStringify({username: runtimeRoleName($app.stage), password: password.result, salt: salt.result}),
    tags: {Project: "mem9-on-aws", Stage: $app.stage, ManagedBy: "sst"},
  });
  // The short-lived preview administrator probe uses an independently generated
  // credential from the approved store; it is never a production credential.
  const probePassword = new random.RandomPassword("RuntimeAdminProbePassword", {length: 48, special: false});
  const probeSalt = new random.RandomPassword("RuntimeAdminProbeSalt", {length: 32, special: false});
  const probe = new aws.ssm.Parameter("RuntimeAdminProbeCredential", {
    name: `/mem9-on-aws/${$app.stage}/runtime/admin-probe-credential`, type: "SecureString",
    value: $jsonStringify({username: probeRoleName($app.stage), password: probePassword.result, salt: probeSalt.result}),
    tags: {Project: "mem9-on-aws", Stage: $app.stage, ManagedBy: "sst"},
  });
  return {parameterArn: parameter.arn, probeParameterArn: probe.arn, ready: ready === "1"};
}
