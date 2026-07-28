#!/usr/bin/env node

import { invokeAwsCli } from "./lib/workload-permissions-boundary-aws.mjs";
import { installSubprocessSignalHandlers } from "./lib/bounded-subprocess.mjs";
import {
  createGithubMaintenanceController,
  executeBoundaryRollout,
  parseRolloutArguments,
  runBoundaryRolloutCli,
} from "./rollout-workload-permissions-boundary.mjs";

const shutdown = installSubprocessSignalHandlers();
try {
  if (process.env.WORKLOAD_BOUNDARY_GATES_VERIFIED !== "true") {
    process.stderr.write(
      "Run the guarded workload permissions-boundary shell wrapper.\n",
    );
    process.exitCode = 2;
  } else {
    const { deadlineAt, reviewedCommit } = parseRolloutArguments(
      process.argv.slice(2),
    );
    const maintenance = createGithubMaintenanceController({
      deadlineAt,
      signal: shutdown.signal,
    });
    await runBoundaryRolloutCli({
      execute: () =>
        executeBoundaryRollout({
          activateProduction: () => maintenance.activateProductionBoundary(),
          deadlineAt,
          invokeAws: (args, options) =>
            invokeAwsCli(args, { ...options, signal: shutdown.signal }),
          reviewedCommit,
          resumeDeploymentWorkflows: () => maintenance.resumeDeployments(),
          signal: shutdown.signal,
          verifyFinalGithubInterlock: ({ reviewedCommit: commit }) =>
            maintenance.verifyFinalInterlock({ reviewedCommit: commit }),
        }),
    });
  }
} catch {
  process.stderr.write(
    "Run the guarded wrapper with one reviewed commit argument.\n",
  );
  process.exitCode = 2;
} finally {
  shutdown.dispose();
  if (shutdown.exitCode !== undefined) {
    process.exitCode = shutdown.exitCode;
  }
}
