import { appendFile } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";

const hexId = /^[0-9a-f]{32}$/;
const attempts = 4;
const failureReasons = new Set([
  "missing_token", "invalid_zone_id", "missing_environment_file", "invalid_timeout",
  "network_or_timeout", "invalid_response", "http_failure", "invalid_zone_response",
  "environment_write_failed", "request_exhausted",
]);

export class CloudflareAccountError extends Error {
  constructor(reason, details = {}) {
    super(reason);
    this.name = "CloudflareAccountError";
    this.reason = reason;
    this.details = details;
  }
}

function apiCodes(body) {
  return Array.isArray(body?.errors)
    ? body.errors
        .map((error) => error?.code)
        .filter((code) => Number.isSafeInteger(code) && code >= 0 && code <= 9_999_999)
        .slice(0, 8)
        .map(String)
    : [];
}

async function release(response) {
  try {
    await response.body?.cancel();
  } catch {
    // Fully consumed or aborted bodies already released their connection.
  }
}

export async function resolveCloudflareAccount({
  env = process.env,
  fetchImpl = globalThis.fetch,
  sleep = delay,
  timeoutMs = 15_000,
  log = (line) => process.stdout.write(`${line}\n`),
  writeEnvironment = (file, value) => appendFile(file, value, "utf8"),
} = {}) {
  if (!env.MEM9_FACADE_CUSTOM_DOMAIN?.trim()) {
    log("::notice::No production custom domain configured; skipping Cloudflare account resolution");
    return { status: "skipped" };
  }
  const token = env.CLOUDFLARE_API_TOKEN;
  const zoneId = env.CLOUDFLARE_ZONE_ID;
  if (typeof token !== "string" || !token.trim()) {
    throw new CloudflareAccountError("missing_token");
  }
  if (typeof zoneId !== "string" || !hexId.test(zoneId)) {
    throw new CloudflareAccountError("invalid_zone_id");
  }
  if (typeof env.GITHUB_ENV !== "string" || !env.GITHUB_ENV.trim()) {
    throw new CloudflareAccountError("missing_environment_file");
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 15_000) {
    throw new CloudflareAccountError("invalid_timeout");
  }

  for (let attempt = 0; attempt < attempts; attempt++) {
    let response;
    try {
      response = await fetchImpl(
        `https://api.cloudflare.com/client/v4/zones/${zoneId}`,
        {
          method: "GET",
          headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
          redirect: "error",
          signal: AbortSignal.timeout(timeoutMs),
        },
      );
    } catch {
      if (attempt < attempts - 1) {
        await sleep(1000 * 2 ** attempt);
        continue;
      }
      throw new CloudflareAccountError("network_or_timeout");
    }

    let body;
    try {
      body = await response.json();
    } catch {
      if (response.ok) {
        await release(response);
        throw new CloudflareAccountError("invalid_response", {
          httpStatus: String(response.status),
        });
      }
    }
    await release(response);
    const details = { httpStatus: String(response.status), apiCodes: apiCodes(body) };
    if (!response.ok) {
      if ((response.status === 429 || response.status >= 500) && attempt < attempts - 1) {
        await sleep(1000 * 2 ** attempt);
        continue;
      }
      throw new CloudflareAccountError("http_failure", details);
    }
    const accountId = body?.result?.account?.id;
    const zoneMatches = body?.result?.id === zoneId;
    const accountPresent = typeof accountId === "string" && accountId.length > 0;
    if (body?.success !== true || !zoneMatches || !accountPresent || !hexId.test(accountId)) {
      throw new CloudflareAccountError("invalid_zone_response", {
        ...details,
        zoneMatches: zoneMatches ? "yes" : "no",
        accountPresent: accountPresent ? "yes" : "no",
      });
    }
    log(`::add-mask::${accountId}`);
    try {
      await writeEnvironment(env.GITHUB_ENV, `CLOUDFLARE_DEFAULT_ACCOUNT_ID=${accountId}\n`);
    } catch {
      throw new CloudflareAccountError("environment_write_failed");
    }
    log("::notice::Cloudflare account resolved for the configured zone");
    return { status: "resolved" };
  }
  throw new CloudflareAccountError("request_exhausted");
}

export function cloudflareFailureDiagnostic(error) {
  const known = error instanceof CloudflareAccountError && failureReasons.has(error.reason);
  const details = known && error.details && typeof error.details === "object" ? error.details : {};
  const diagnostic = {};
  if (typeof details.httpStatus === "string" && /^[1-5][0-9]{2}$/.test(details.httpStatus)) {
    diagnostic.httpStatus = details.httpStatus;
  }
  if (Array.isArray(details.apiCodes)) {
    diagnostic.apiCodes = details.apiCodes
      .filter((code) => typeof code === "string" && /^[0-9]{1,7}$/.test(code))
      .slice(0, 8);
  }
  for (const key of ["zoneMatches", "accountPresent"]) {
    if (["yes", "no"].includes(details[key])) diagnostic[key] = details[key];
  }
  return {
    event: "cloudflare_account_resolution",
    outcome: "failed",
    reason: known ? error.reason : "unexpected_error",
    ...diagnostic,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  resolveCloudflareAccount().catch((error) => {
    process.stderr.write(`${JSON.stringify(cloudflareFailureDiagnostic(error))}\n`);
    process.exitCode = 1;
  });
}
