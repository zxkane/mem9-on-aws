import { consolidationTimeoutSeconds } from "../scripts/lib/maintenance-runtime.mjs";

export const UNSUPPORTED_MAINTENANCE_FLAGS = [
  "MEM9_SLACK_APPROVAL_ENABLED",
  "MEM9_CLEANUP_SCAN_SCHEDULE_ENABLED",
  "MEM9_CLEANUP_SCAN_ENABLED",
] as const;

/** Refuse incomplete capabilities before constructing any deployment resource. */
export function assertSupportedMaintenanceConfiguration(env: NodeJS.ProcessEnv = process.env): void {
  consolidationTimeoutSeconds(env);
  for (const name of UNSUPPORTED_MAINTENANCE_FLAGS) {
    const value = env[name];
    if (value !== undefined && !["", "0", "false"].includes(value))
      throw new Error("namespace-aware cleanup scan and Slack approval are not supported");
  }
}
