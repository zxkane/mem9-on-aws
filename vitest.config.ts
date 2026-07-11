import { defineConfig } from "vitest/config";

// Root vitest project. The scaffold has no root-level source yet — the SST
// app + its unit tests live under `infra/` (see `infra/vitest.config.ts`).
// This config exists so the CI `npm test` step has a target; it runs with
// `--passWithNoTests` until root-level tooling gains its own tests.
export default defineConfig({
  test: {
    include: ["scripts/**/*.test.ts"],
  },
});
