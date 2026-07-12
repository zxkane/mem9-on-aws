import { defineConfig } from "vitest/config";

// Root vitest project. The SST app + its unit tests live under `infra/` (see
// `infra/vitest.config.ts`); this config covers the repo-root/sidecar tests:
//   - scripts/**/*.test.ts    (any shell-wrapper helpers gaining tests)
//   - docker/**/*.test.mjs    (the ECS sidecar servers, e.g. llm-proxy)
// Runs with `--passWithNoTests` so CI's `npm test` never fails on an empty glob.
export default defineConfig({
  test: {
    include: ["scripts/**/*.test.ts", "docker/**/*.test.mjs"],
  },
});
