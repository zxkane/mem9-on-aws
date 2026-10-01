import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CloudflareAccountError,
  cloudflareFailureDiagnostic,
  resolveCloudflareAccount,
} from "./resolve-cloudflare-account.mjs";

const zoneId = "a".repeat(32);
const accountId = "b".repeat(32);
const token = "fixture-token-do-not-log";
const validBody = { success: true, result: { id: zoneId, account: { id: accountId } } };
const dirs = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function response(body = validBody, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: vi.fn().mockResolvedValue(body),
    body: { cancel: vi.fn().mockResolvedValue(undefined) },
  };
}

function fixture(overrides = {}) {
  return {
    env: {
      MEM9_FACADE_CUSTOM_DOMAIN: "memory.example.com",
      CLOUDFLARE_API_TOKEN: token,
      CLOUDFLARE_ZONE_ID: zoneId,
      GITHUB_ENV: "/unused/github-env",
    },
    fetchImpl: vi.fn().mockResolvedValue(response()),
    sleep: vi.fn().mockResolvedValue(undefined),
    log: vi.fn(),
    writeEnvironment: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

describe("Cloudflare account resolution", () => {
  it("TC-CF-ACCOUNT-001/006: queries only the configured zone and masks before export", async () => {
    const f = fixture();
    await expect(resolveCloudflareAccount(f)).resolves.toEqual({ status: "resolved" });
    expect(f.fetchImpl).toHaveBeenCalledExactlyOnceWith(
      `https://api.cloudflare.com/client/v4/zones/${zoneId}`,
      expect.objectContaining({
        method: "GET", redirect: "error",
        headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
        signal: expect.any(AbortSignal),
      }),
    );
    expect(f.log.mock.calls[0]).toEqual([`::add-mask::${accountId}`]);
    expect(f.log.mock.invocationCallOrder[0]).toBeLessThan(f.writeEnvironment.mock.invocationCallOrder[0]);
    expect(f.writeEnvironment).toHaveBeenCalledExactlyOnceWith(
      f.env.GITHUB_ENV, `CLOUDFLARE_DEFAULT_ACCOUNT_ID=${accountId}\n`,
    );
    expect(JSON.stringify(f.log.mock.calls)).not.toContain(token);
  });

  it.each([undefined, "", "  \n\t"])("TC-CF-ACCOUNT-004: skips absent domain %j without HTTP or export", async (domain) => {
    const f = fixture();
    f.env = { MEM9_FACADE_CUSTOM_DOMAIN: domain };
    await expect(resolveCloudflareAccount(f)).resolves.toEqual({ status: "skipped" });
    expect(f.fetchImpl).not.toHaveBeenCalled();
    expect(f.writeEnvironment).not.toHaveBeenCalled();
  });

  it.each([
    ["CLOUDFLARE_API_TOKEN", "", "missing_token"],
    ["CLOUDFLARE_API_TOKEN", " \n", "missing_token"],
    ["CLOUDFLARE_ZONE_ID", undefined, "invalid_zone_id"],
    ["CLOUDFLARE_ZONE_ID", "a".repeat(31), "invalid_zone_id"],
    ["CLOUDFLARE_ZONE_ID", "A".repeat(32), "invalid_zone_id"],
    ["CLOUDFLARE_ZONE_ID", "../accounts", "invalid_zone_id"],
    ["CLOUDFLARE_ZONE_ID", `${zoneId}\n`, "invalid_zone_id"],
    ["GITHUB_ENV", "", "missing_environment_file"],
  ])("TC-CF-ACCOUNT-007: rejects invalid %s %j before network", async (key, value, reason) => {
    const f = fixture();
    f.env[key] = value;
    await expect(resolveCloudflareAccount(f)).rejects.toMatchObject({ reason });
    expect(f.fetchImpl).not.toHaveBeenCalled();
    expect(f.writeEnvironment).not.toHaveBeenCalled();
  });

  it.each([
    null, {}, { success: false, result: validBody.result },
    { success: true, result: { ...validBody.result, id: "c".repeat(32) } },
    { success: true, result: { id: zoneId } },
    ...[null, 123, "", "b".repeat(31), "B".repeat(32), `${accountId}\n`, `${accountId}\nINJECTED=1`].map(
      (id) => ({ success: true, result: { id: zoneId, account: { id } } }),
    ),
  ])("TC-CF-ACCOUNT-003/007: rejects an unusable response %j", async (body) => {
    const res = response(body);
    const f = fixture({ fetchImpl: vi.fn().mockResolvedValue(res) });
    await expect(resolveCloudflareAccount(f)).rejects.toMatchObject({ reason: "invalid_zone_response" });
    expect(f.fetchImpl).toHaveBeenCalledTimes(1);
    expect(res.body.cancel).toHaveBeenCalledOnce();
    expect(f.writeEnvironment).not.toHaveBeenCalled();
  });

  it.each([403, 404, 302])("TC-CF-ACCOUNT-003/006: permanent HTTP %i fails immediately with bounded diagnostics", async (status) => {
    const res = response({ errors: [{ code: 10000, message: token }, { code: token }] }, status);
    const f = fixture({ fetchImpl: vi.fn().mockResolvedValue(res) });
    const error = await resolveCloudflareAccount(f).catch((e) => e);
    expect(cloudflareFailureDiagnostic(error)).toEqual({
      event: "cloudflare_account_resolution", outcome: "failed", reason: "http_failure",
      httpStatus: String(status), apiCodes: ["10000"],
    });
    expect(f.fetchImpl).toHaveBeenCalledOnce();
    expect(f.writeEnvironment).not.toHaveBeenCalled();
    expect(res.body.cancel).toHaveBeenCalledOnce();
  });

  it("TC-CF-ACCOUNT-003/008: malformed JSON releases the body without retry or leakage", async () => {
    const res = response();
    res.json.mockRejectedValue(new Error(token));
    res.body.cancel.mockRejectedValue(new Error(token));
    const f = fixture({ fetchImpl: vi.fn().mockResolvedValue(res) });
    await expect(resolveCloudflareAccount(f)).rejects.toMatchObject({ reason: "invalid_response" });
    expect(f.fetchImpl).toHaveBeenCalledOnce();
    expect(res.body.cancel).toHaveBeenCalledOnce();
    expect(f.writeEnvironment).not.toHaveBeenCalled();
  });

  it.each([429, 500, 503])("TC-CF-ACCOUNT-008: retries HTTP %i at most four times and releases every body", async (status) => {
    const res = response({}, status);
    res.json.mockRejectedValue(new Error(token));
    const f = fixture({ fetchImpl: vi.fn().mockResolvedValue(res) });
    await expect(resolveCloudflareAccount(f)).rejects.toMatchObject({ reason: "http_failure" });
    expect(f.fetchImpl).toHaveBeenCalledTimes(4);
    expect(res.body.cancel).toHaveBeenCalledTimes(4);
    expect(f.sleep.mock.calls).toEqual([[1000], [2000], [4000]]);
    expect(f.writeEnvironment).not.toHaveBeenCalled();
  });

  it("TC-CF-ACCOUNT-008: recovers from mixed transient failures with a fresh timeout for each attempt", async () => {
    const f = fixture({ fetchImpl: vi.fn()
      .mockRejectedValueOnce(new Error(token))
      .mockResolvedValueOnce(response({}, 429))
      .mockResolvedValueOnce(response({}, 503))
      .mockResolvedValueOnce(response()) });
    await expect(resolveCloudflareAccount(f)).resolves.toEqual({ status: "resolved" });
    expect(new Set(f.fetchImpl.mock.calls.map(([, { signal }]) => signal)).size).toBe(4);
    expect(f.sleep.mock.calls).toEqual([[1000], [2000], [4000]]);
  });

  it("TC-CF-ACCOUNT-008: bounds network timeouts and does not expose the thrown exception", async () => {
    const f = fixture({ timeoutMs: 5, fetchImpl: vi.fn(async (_url, { signal }) => {
      await delay(1000, undefined, { signal });
      throw Error("timeout did not fire");
    }) });
    const error = await resolveCloudflareAccount(f).catch((e) => e);
    expect(error.reason).toBe("network_or_timeout");
    expect(f.fetchImpl).toHaveBeenCalledTimes(4);
    expect(f.writeEnvironment).not.toHaveBeenCalled();
  });

  it("TC-CF-ACCOUNT-008: the request timeout also bounds response body consumption", async () => {
    const res = response();
    const f = fixture({ timeoutMs: 5, fetchImpl: vi.fn(async (_url, { signal }) => {
      res.json.mockImplementation(() => delay(1000, validBody, { signal }));
      return res;
    }) });
    await expect(resolveCloudflareAccount(f)).rejects.toMatchObject({ reason: "invalid_response" });
    expect(f.fetchImpl).toHaveBeenCalledOnce();
    expect(res.body.cancel).toHaveBeenCalledOnce();
    expect(f.writeEnvironment).not.toHaveBeenCalled();
  });

  it.each([0, 15_001, NaN, 1.5])("TC-CF-ACCOUNT-008: rejects timeout %j", async (timeoutMs) => {
    const f = fixture({ timeoutMs });
    await expect(resolveCloudflareAccount(f)).rejects.toMatchObject({ reason: "invalid_timeout" });
    expect(f.fetchImpl).not.toHaveBeenCalled();
  });

  it("TC-CF-ACCOUNT-006: export failures and unexpected errors remain redacted", async () => {
    const f = fixture({ writeEnvironment: vi.fn().mockRejectedValue(new Error(token)) });
    const error = await resolveCloudflareAccount(f).catch((e) => e);
    expect(cloudflareFailureDiagnostic(error).reason).toBe("environment_write_failed");
    expect(cloudflareFailureDiagnostic(new Error(token)).reason).toBe("unexpected_error");
    expect(cloudflareFailureDiagnostic(new CloudflareAccountError(token)).reason).toBe("unexpected_error");
    expect(cloudflareFailureDiagnostic(new CloudflareAccountError("http_failure", null)).reason).toBe("http_failure");
    const diagnostic = cloudflareFailureDiagnostic(new CloudflareAccountError("http_failure", {
      httpStatus: token, apiCodes: [token, "10", ...Array(20).fill("42")],
      zoneMatches: token, accountPresent: token, message: token,
    }));
    expect(diagnostic.apiCodes).toHaveLength(8);
    expect(JSON.stringify(diagnostic)).not.toContain(token);
  });
});

it.each([200, 403])("TC-CF-ACCOUNT-003/006: the actual CLI handles HTTP %i without token in argv, logs or env output", (status) => {
  const dir = mkdtempSync(join(tmpdir(), "mem9-cloudflare-cli-"));
  dirs.push(dir);
  const envFile = join(dir, "github-env");
  const preloader = join(dir, "mock-fetch.mjs");
  writeFileSync(envFile, "");
  writeFileSync(preloader, `
    import assert from "node:assert/strict";
    globalThis.fetch = async (url, options) => {
      assert.equal(url, "https://api.cloudflare.com/client/v4/zones/" + process.env.CLOUDFLARE_ZONE_ID);
      assert.equal(options.headers.Authorization, "Bearer " + process.env.CLOUDFLARE_API_TOKEN);
      assert.equal(process.argv.join(" ").includes(process.env.CLOUDFLARE_API_TOKEN), false);
      return new Response(process.env.MOCK_RESPONSE, {status: Number(process.env.MOCK_STATUS)});
    };
  `);
  const result = spawnSync(process.execPath, ["--import", preloader, new URL("./resolve-cloudflare-account.mjs", import.meta.url).pathname], {
    encoding: "utf8", timeout: 5000,
    env: { ...fixture().env, GITHUB_ENV: envFile, MOCK_STATUS: String(status),
      MOCK_RESPONSE: JSON.stringify(status === 200 ? validBody : { errors: [{ code: 10000, message: token }] }) },
  });
  expect(result.status).toBe(status === 200 ? 0 : 1);
  const exported = readFileSync(envFile, "utf8");
  expect(exported).toBe(status === 200 ? `CLOUDFLARE_DEFAULT_ACCOUNT_ID=${accountId}\n` : "");
  expect(result.stdout + result.stderr + exported).not.toContain(token);
  if (status === 403) expect(JSON.parse(result.stderr).httpStatus).toBe("403");
});

it("TC-CF-ACCOUNT-009: rehearsal coordinator digest includes the resolver", () => {
  const source = readFileSync(new URL("./run-production-runtime.mjs", import.meta.url), "utf8");
  const digest = source.slice(source.indexOf("export async function productionCoordinatorDigest()"), source.indexOf("export async function productionSourceTree()"));
  expect(digest).toContain("'scripts/resolve-cloudflare-account.mjs'");
  expect(digest).toContain("for(const path of paths.sort())");
});
