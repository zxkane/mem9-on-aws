import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Config-invariant guard for the root `sst.config.ts`.
 *
 * We do NOT import `sst.config.ts` here: it carries a triple-slash reference to
 * `.sst/platform/config.d.ts`, which only exists after `sst install`, and its
 * SST globals (`$config`, `$transform`) are typed by the deploy-time platform,
 * not by our CI-only shim. So the root config is type-checked at `sst deploy`
 * time, not in this unit run (mirrors the sister project's approach). Instead
 * we read it as text and pin the locked facts, so a future edit that silently
 * removes the region / prod-protection / Lambda runtime trips this test.
 */

const here = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(resolve(here, "../sst.config.ts"), "utf8");

describe("sst.config.ts locked facts", () => {
  it("declares one valid AWS provider region", () => {
    const regions = [
      ...src.matchAll(/region:\s*["']([^"']+)["']/gu),
    ].map((match) => match[1]);
    expect(regions).toHaveLength(1);
    expect(regions[0]).toMatch(/^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$/u);
  });

  it("retains + protects prod state and removes non-prod state", () => {
    expect(src).toMatch(
      /removal:\s*input\?\.stage === ["']prod["'] \? ["']retain["'] : ["']remove["']/,
    );
    expect(src).toMatch(/protect:\s*input\?\.stage === ["']prod["']/);
  });

  it("names the app mem9-on-aws with home aws", () => {
    expect(src).toMatch(/name:\s*["']mem9-on-aws["']/);
    expect(src).toMatch(/home:\s*["']aws["']/);
  });

  it("carries Project/Stage/ManagedBy default tags", () => {
    expect(src).toMatch(/Project:\s*["']mem9-on-aws["']/);
    expect(src).toMatch(/ManagedBy:\s*["']sst["']/);
    expect(src).toMatch(/Stage:/);
  });

  it("forces nodejs24.x on Lambdas via $transform and skips Image functions", () => {
    expect(src).toContain("$transform(aws.lambda.Function");
    expect(src).toMatch(/args\.runtime = ["']nodejs24\.x["']/);
    expect(src).toMatch(/packageType === ["']Image["']/);
  });

  it("initializes Cloudflare only for a configured production custom domain", () => {
    expect(src).toMatch(
      /const cloudflareEnabled =\s*input\?\.stage === ["']prod["']\s*&&\s*Boolean\(process\.env\.MEM9_FACADE_CUSTOM_DOMAIN\?\.trim\(\)\)\s*&&\s*Boolean\(process\.env\.CLOUDFLARE_API_TOKEN\?\.trim\(\)\)/u,
    );
    expect(src).toMatch(
      /\.\.\.\(cloudflareEnabled\s*\?\s*\{\s*cloudflare:\s*\{\s*version:\s*["']6\.19\.0["']\s*\}\s*\}\s*:\s*\{\}\)/u,
    );
  });

  it("wires the meta stack via lazy import", () => {
    expect(src).toMatch(/await import\(["']\.\/infra\/meta["']\)/);
    expect(src).toContain("meta()");
  });
});
