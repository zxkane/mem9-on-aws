import { afterEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";

const output = (value: any): any => ({ value, apply(fn: any) { const next = fn(value); return next?.apply ? next : output(next); } });
const unwrap = (value: any): any => (value?.apply ? unwrap(value.value) : value);

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.resetModules(); });

describe("human acceptance image", () => {
  it("uses the preview repository CI publishes to, whatever the workload image namespace", async () => {
    vi.stubGlobal("$app", { stage: "pr-42" });
    vi.stubGlobal("$interpolate", (parts: TemplateStringsArray, ...values: any[]) =>
      output(parts.reduce((s, p, i) => s + p + (i < values.length ? unwrap(values[i]) : ""), "")));
    vi.stubGlobal("aws", { getCallerIdentityOutput: () => ({ accountId: output("123456789012") }), getRegionOutput: () => ({ name: output("ap-northeast-1") }) });
    for (const namespace of ["mem9-on-aws", "mem9-on-aws/preview"]) {
      vi.stubEnv("MEM9_ECR_NAMESPACE", namespace);
      const { humanAcceptanceImage } = await import("./human-acceptance");
      expect(unwrap(humanAcceptanceImage("pr-human-abc1234")))
        .toBe("123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/preview/bootstrap:pr-human-abc1234");
      vi.resetModules();
    }
  });

  it("matches the repository the CI build job publishes to", async () => {
    const workflow = readFileSync(new URL("../.github/workflows/infra-ci.yml", import.meta.url), "utf8");
    const job = workflow.slice(workflow.indexOf("  build-human-acceptance-image:"));
    const namespace = /\n      ECR_NS: (\S+)\n/u.exec(job)?.[1];
    expect(job).toContain("/${{ env.ECR_NS }}/bootstrap:${{ steps.tag.outputs.human_image_tag }}");
    const { HUMAN_ACCEPTANCE_REPOSITORY } = await import("./human-acceptance");
    expect(`${namespace}/bootstrap`).toBe(HUMAN_ACCEPTANCE_REPOSITORY);
  });
});
