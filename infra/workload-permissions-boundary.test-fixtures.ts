export const EXPECTED_WORKLOAD_ROLE_NAMES = [
  "Mem9AlertRouterRole",
  "Mem9BootstrapExecutionRole",
  "Mem9BootstrapTaskRole",
  "Mem9ConsolidationExecutionRole",
  "Mem9ConsolidationTaskRole",
  "Mem9GatewayServiceRole",
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
 * Neither name appears in the operator-owned boundary's
 * `ECS_EXECUTION_ROLE_TOKENS`, and it does not need to: the task's SecureString
 * reads are gated on `kms:ViaService`, and its Secrets Manager reads resolve
 * under the default `aws/secretsmanager` key, which needs no identity
 * `kms:Decrypt`. Moving either secret to a customer managed key would require
 * adding `Mem9CleanupExecutionRole-` to that deny's exception list.
 */
export const SLACK_APPROVAL_ROLE_NAMES = [
  "Mem9CleanupExecutionRole",
  "Mem9CleanupTaskRole",
] as const;
