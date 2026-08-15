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
 * `Mem9CleanupExecutionRole-` IS on the operator-owned boundary's
 * `ECS_EXECUTION_ROLE_TOKENS` list, and has to be. The reasoning that once said
 * otherwise — the Secrets Manager reads resolve under the default
 * `aws/secretsmanager` key, which needs no identity `kms:Decrypt` ALLOW — is
 * true but irrelevant: the boundary's `SecretCtxRole` statement is an
 * `ArnNotLike` DENY, so an unlisted role is explicitly denied rather than merely
 * ungranted. Simulating each role against the live boundary shows listed ones
 * allowed and unlisted ones explicitDeny. See the BOUNDARY NOTE in
 * `infra/slack-approval.ts` for the measurement.
 *
 * `Mem9CleanupTaskRole` is correctly absent: only the EXECUTION role fetches
 * `valueFrom` secrets during task startup.
 */
export const SLACK_APPROVAL_ROLE_NAMES = [
  "Mem9CleanupExecutionRole",
  "Mem9CleanupTaskRole",
] as const;
