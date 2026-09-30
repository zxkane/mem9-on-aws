import {runtimeRoleName, runtimeStage} from "../scripts/lib/runtime-credentials.mjs";

export interface RuntimeCredentials {
  parameterArn: Output<string>;
  ready: boolean;
}

/** Stable across preview generations. Only bootstrap receives the owner secret. */
export function runtimeCredentials(): RuntimeCredentials | undefined {
  if (!runtimeStage($app.stage)) return;
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
  return {parameterArn: parameter.arn, ready: ready === "1"};
}
