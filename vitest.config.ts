import { configDefaults, defineConfig } from "vitest/config";

// Root vitest project. The SST app + its unit tests live under `infra/` (see
// `infra/vitest.config.ts`, which globs `*.test.ts`); this config covers the
// repo-root/sidecar tests plus the plain-ESM (`.mjs`) Lambda/sidecar handlers:
//   - scripts/**/*.test.{ts,mjs} (workflow and deployment command tests)
//   - docker/**/*.test.mjs    (the ECS sidecar servers, e.g. llm-proxy)
//   - infra/**/*.test.mjs     (plain-ESM Lambda handlers, e.g. gateway proxy-handler)
// SST-dependent synthesis tests are owned by the infra project, whose pretest
// materializes the gitignored `.sst/platform` tree.
// Runs with `--passWithNoTests` so CI's `npm test` never fails on an empty glob.
export default defineConfig({
  test: {
    include: [
      "scripts/**/*.test.{ts,mjs}",
      "docker/**/*.test.mjs",
      "infra/**/*.test.mjs",
    ],
    exclude: [
      ...configDefaults.exclude,
      "infra/ecs-task-definition.test.mjs",
    ],
  },
});
