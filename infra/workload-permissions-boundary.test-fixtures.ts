export const EXPECTED_WORKLOAD_ROLE_NAMES = [
  "Mem9AlertRouterRole",
  "Mem9BootstrapExecutionRole",
  "Mem9BootstrapTaskRole",
  "Mem9GatewayServiceRole",
  "Mem9IdentityInterceptorFnRole",
  "Mem9OauthFacadeFnRole",
  "Mem9ProxyFnRole",
  "Mem9ServerExecutionRole",
  "Mem9ServerTaskRole",
] as const;

export const CONSOLIDATION_SCHEDULER_ROLE_NAME =
  "Mem9ConsolidationSchedulerRole";

/**
 * The roles `infra/slack-approval.ts` adds when `MEM9_SLACK_APPROVAL_ENABLED=1`
 * (#123). One `sst.aws.Task` always creates BOTH a task role and an execution
 * role, so both must be admitted or the exact-set assertion in
 * `workload-permissions-boundary.roles.test.ts` fails.
 *
 * Keep `Mem9CleanupExecutionRole-` in `ECS_EXECUTION_ROLE_TOKENS` so the
 * boundary template covers this task's startup secret-injection role.
 * Exercise listed and unlisted roles with synthetic policy/context fixtures;
 * template assertions do not establish the state of any deployed policy.
 *
 * `Mem9CleanupTaskRole` is correctly absent: only the EXECUTION role fetches
 * `valueFrom` secrets during task startup.
 */
export const SLACK_APPROVAL_ROLE_NAMES = [
  "Mem9CleanupExecutionRole",
  "Mem9CleanupTaskRole",
] as const;
