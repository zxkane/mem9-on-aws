import { GetParametersCommand, SSMClient } from "@aws-sdk/client-ssm";
import { GetSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { runtimeSecretEndpoint } from "./secret-endpoint.mjs";

export const RUNTIME_SECRET_CACHE_MS = 300_000;
const slots = Object.freeze({
  identity: { env: "MEM9_IDENTITY_SIGNING_KEYS_SECRET_ARN", legacy: "MEM9_IDENTITY_SIGNING_KEYS", store: "secretsmanager", suffix: "identity-signing-keys" },
  tenant: { env: "MEM9_API_KEY_SECRET_ARN", legacy: "MEM9_API_KEY", store: "secretsmanager", suffix: "tenant-api-key" },
  transport: { env: "MEM9_TRANSPORT_SIGNING_KEYS_PARAMETER_ARN", legacy: "MEM9_TRANSPORT_SIGNING_KEYS", store: "ssm", suffix: "namespace/transport-signing-keys" },
  oauth: { env: "OAUTH_STATE_HMAC_KEY_PARAMETER_ARN", legacy: "OAUTH_STATE_HMAC_KEY", store: "ssm", suffix: "oauth/state-hmac-key" },
  webhook: { env: "SLACK_WEBHOOK_URL_PARAMETER_ARN", legacy: "SLACK_WEBHOOK_URL", store: "ssm", suffix: "observability/slack-webhook-url" },
});

/** Fixed Lambda inputs only. No plaintext compatibility path, path listing,
 * caller-selected action, stale-on-error result, or secret-bearing error. */
export function createRuntimeSecretReader({ env = process.env, ssm, secretsManager, now = Date.now } = {}) {
  const cache = new Map();
  let ssmClient = ssm, secretClient = secretsManager;
  return async function read(slot) {
    const spec = slots[slot], stage = env.STAGE, region = env.AWS_REGION, account = env.MEM9_SECRET_ACCOUNT_ID;
    const fail = () => { throw new Error("RuntimeSecretReferenceInvalid"); };
    if (!spec || !/^[a-z][a-z0-9-]{0,63}$/.test(stage ?? "") || !/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(region ?? "") || !/^\d{12}$/.test(account ?? "") || Object.hasOwn(env, spec.legacy)) fail();
    const arn = env[spec.env], prefix = `arn:aws:${spec.store}:${region}:${account}:`;
    if (typeof arn !== "string" || !arn.startsWith(prefix) || arn.length > 2048) fail();
    const name = spec.store === "ssm" ? `/mem9-on-aws/${stage}/${spec.suffix}` : undefined;
    if (spec.store === "ssm") {
      if (arn !== `${prefix}parameter${name}`) fail();
    } else {
      const resource = arn.slice(prefix.length), expected = `secret:mem9-on-aws-${stage}-${spec.suffix}-`;
      if (!resource.startsWith(expected) || !/^[A-Za-z0-9_-]+-[A-Za-z0-9]{6}$/.test(resource.slice(expected.length))) fail();
    }
    const endpoint = runtimeSecretEndpoint(env, spec.store, region);
    const key = `${slot}:${arn}`, previous = cache.get(key);
    if (previous?.pending) return previous.pending;
    if (previous && now() < previous.expiresMs) return previous.value;
    const entry = { pending: undefined, value: undefined, expiresMs: 0 };
    cache.set(key, entry);
    entry.pending = (async () => {
      try {
        const options = { abortSignal: AbortSignal.timeout(5000) };
        let value;
        if (spec.store === "ssm") {
          ssmClient ??= new SSMClient({ region, maxAttempts: 2, ignoreConfiguredEndpointUrls: true, ...(endpoint ? { endpoint } : {}) });
          const response = await ssmClient.send(new GetParametersCommand({ Names: [arn], WithDecryption: true }), options);
          const p = response.Parameters?.[0];
          if (response.InvalidParameters?.length || response.Parameters?.length !== 1 || p.ARN !== arn || p.Name !== name || p.Type !== "SecureString") throw new Error();
          value = p.Value;
        } else {
          secretClient ??= new SecretsManagerClient({ region, maxAttempts: 2, ignoreConfiguredEndpointUrls: true, ...(endpoint ? { endpoint } : {}) });
          const response = await secretClient.send(new GetSecretValueCommand({ SecretId: arn, VersionStage: "AWSCURRENT" }), options);
          if (response.ARN !== arn || !response.VersionStages?.includes("AWSCURRENT") || response.SecretBinary !== undefined) throw new Error();
          value = response.SecretString;
        }
        if (typeof value !== "string" || value.length === 0 || value.includes("\0") || Buffer.byteLength(value) > 4096) throw new Error();
        if (slot === "webhook") {
          const url = new URL(value);
          if (url.protocol !== "https:" || url.username || url.password || url.hash) throw new Error();
        }
        entry.value = value; entry.expiresMs = now() + RUNTIME_SECRET_CACHE_MS;
        return value;
      } catch {
        cache.delete(key);
        throw new Error("RuntimeSecretUnavailable");
      } finally { entry.pending = undefined; }
    })();
    return entry.pending;
  };
}
