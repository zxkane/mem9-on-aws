/**
 * Stable single-tenant identity shared by bootstrap, mnemo-server, and Gateway.
 *
 * The random tenant id is also the X-API-Key. Secrets Manager is the runtime
 * source for ECS containers; `tenantId` is a Pulumi Output used only to configure
 * the private Gateway proxy Lambda.
 */
export interface TenantIdentityOutputs {
  tenantSecretArn: Output<string>;
  tenantId: Output<string>;
}

export function tenantIdentity(): TenantIdentityOutputs {
  const tags = { Project: "mem9-on-aws", Stage: $app.stage, ManagedBy: "sst" };
  const tenantSecret = new aws.secretsmanager.Secret("Mem9TenantApiKey", {
    namePrefix: `mem9-on-aws-${$app.stage}-tenant-api-key-`,
    description: "mem9 tenant id == X-API-Key (single tenant). Stable across deploys.",
    recoveryWindowInDays: $app.stage === "prod" ? 7 : 0,
    tags,
  });
  const tenantId = new random.RandomId("Mem9TenantId", { byteLength: 16 });
  const secretVersion = new aws.secretsmanager.SecretVersion("Mem9TenantApiKeyValue", {
    secretId: tenantSecret.id,
    secretString: tenantId.hex,
  });

  // Flattening the SecretVersion dependency into the ARN prevents ECS from
  // starting a task before the secret has a current value.
  const tenantSecretArn = secretVersion.arn.apply(() => tenantSecret.arn);

  // Publish the secret's ARN (metadata, not the value) so operator tooling —
  // the memory-cleanup script/E2E (issue #102) — can resolve it through the
  // already-scoped `/mem9-on-aws/<stage>/*` SSM reads instead of needing an
  // account-wide `secretsmanager:ListSecrets` grant on the deploy role.
  new aws.ssm.Parameter("TenantSecretArnParam", {
    name: `/mem9-on-aws/${$app.stage}/tenant/secret-arn`,
    type: "String",
    value: tenantSecretArn,
    tags,
  });
  return { tenantSecretArn, tenantId: tenantId.hex };
}
