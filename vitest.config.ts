import { defineConfig } from "vitest/config";

// Root vitest project. The SST app + its unit tests live under `infra/` (see
// `infra/vitest.config.ts`, which globs `*.test.ts`); this config covers the
// repo-root/sidecar tests plus the plain-ESM (`.mjs`) Lambda/sidecar handlers:
//   - scripts/**/*.test.ts    (any shell-wrapper helpers gaining tests)
//   - docker/**/*.test.mjs    (the ECS sidecar servers, e.g. llm-proxy)
//   - infra/**/*.test.mjs     (the .mjs Lambda handlers, e.g. gateway proxy-handler)
// Runs with `--passWithNoTests` so CI's `npm test` never fails on an empty glob.
export default defineConfig({
  test: {
    include: ["scripts/**/*.test.ts", "docker/**/*.test.mjs", "infra/**/*.test.mjs"],
  },
});
