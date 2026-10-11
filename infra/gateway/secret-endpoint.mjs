/** Deployment-owned AWS endpoint bindings only. The proxy requires both
 * private service routes; other Lambdas keep their regional AWS endpoints. */
export function runtimeSecretEndpoint(env, service, region) {
  const prefixes = { ssm: "MEM9_SECRET_SSM", secretsmanager: "MEM9_SECRET_SECRETSMANAGER" };
  const fail = () => { throw new Error("RuntimeSecretEndpointInvalid"); };
  if (!Object.hasOwn(prefixes, service)) fail();
  const keys = Object.values(prefixes).flatMap(prefix => [prefix + "_VPCE_ID", prefix + "_ENDPOINT_DNS"]);
  if (env.MEM9_SECRET_ENDPOINT_MODE === undefined) {
    if (keys.some(key => Object.hasOwn(env, key))) fail();
    return undefined;
  }
  if (env.MEM9_SECRET_ENDPOINT_MODE !== "private" || !/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(region)) fail();
  for (const [store, prefix] of Object.entries(prefixes)) {
    const id = env[prefix + "_VPCE_ID"], dns = env[prefix + "_ENDPOINT_DNS"];
    if (typeof id !== "string" || !/^vpce-[a-f0-9]+$/.test(id) || typeof dns !== "string" ||
        !new RegExp(`^${id}-[a-z0-9]+\\.${store}\\.${region}\\.vpce\\.amazonaws\\.com$`).test(dns)) fail();
  }
  return "https://" + env[prefixes[service] + "_ENDPOINT_DNS"];
}
