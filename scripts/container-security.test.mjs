import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

const root = new URL("../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root), "utf8");

describe("container security rebuild contract", () => {
  const workflow = parse(read(".github/workflows/infra-ci.yml"));
  const builds = Object.values(workflow.jobs).flatMap((job) => job.steps ?? [])
    .filter((step) => step.uses?.startsWith("docker/build-push-action@"));

  it("refreshes base images and runtime packages for every published image", () => {
    expect(builds).toHaveLength(5);
    for (const build of builds) {
      expect(build.with.pull, build.name).toBe(true);
      expect(build.with["no-cache-filters"].split(/[\s,]+/), build.name).toContain("runtime");
      const dockerfile = read(build.with.file);
      const runtime = dockerfile.split(/FROM .* AS runtime\n/i)[1];
      expect(runtime, build.name).toBeDefined();
      expect(runtime, build.name).toMatch(/apt-get (?:dist-)?upgrade -y|apk upgrade --no-cache/);
    }
  });

  it.each(["qwen3-embed", "llm-proxy"])("keeps curl and libssh2 out of %s", (name) => {
    const source = read(`docker/${name}/Dockerfile`);
    expect(source).toContain("node:24-trixie-slim");
    expect(source).not.toMatch(/apt-get install[^\n]*\bcurl\b/);
    expect(source).toContain("COPY docker/healthcheck.mjs");
  });

  it("keeps Qwen model baking independent from the uncached runtime stage", () => {
    const source = read("docker/qwen3-embed/Dockerfile");
    const build = builds.find((step) => step.with.file.includes("qwen3-embed"));
    expect(source).toContain("AS model");
    expect(source).toContain("COPY --from=model /app/node_modules ./node_modules");
    expect(build.with["no-cache-filters"]).toBe("runtime");
  });

  it("updates Chrome Stable before each ephemeral human acceptance run", () => {
    const dockerfile = read("docker/human-acceptance/Dockerfile");
    const entrypoint = read("docker/human-acceptance/entrypoint.sh");
    expect(dockerfile).toContain("google-chrome-stable");
    expect(dockerfile).toContain("arch=arm64");
    expect(entrypoint).toContain(
      "apt-get install -y -qq --only-upgrade google-chrome-stable",
    );
    expect(entrypoint).toContain("exec gosu node");
  });
});
