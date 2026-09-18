export const ACTORS = [
  "writer", "peer", "other", "none", "multi", "mover", "revoked",
  "never_used", "emergency", "concurrent", "viewer",
];
export const MOVE_FAULTS = [
  "revoke_commit", "group_remove", "group_add", "group_verify",
  "target_grant", "grant_commit",
];
export const HUMAN_CASES = [
  "reconciliation_twice_and_omission_drift",
  "owned_synthetic_users_ready_without_jit",
  "real_human_oauth_pkce_and_15_minute_tokens",
  "same_group_sharing_cross_group_denial_and_caller_context_replacement",
  "jit_single_membership_and_denial_order",
  "zero_multiple_unrelated_groups_and_concurrent_first_use",
  "managed_revoke_before_first_use_blocks_stale_token_jit",
  "membership_role_and_token_scope_intersection",
  "direct_group_drift_fails_closed",
  "failed_move_tombstone",
  "failed_grant_retry_a_b_a_and_original_team_data_ownership",
  ...MOVE_FAULTS.map((fault) => `move_retry_${fault}`),
  "observed_concurrent_command_serialization",
  "normal_revocation_preserves_accepted_team_work",
  "emergency_revocation_cancels_queued_work",
  "owned_fixture_cleanup_complete",
];

export function verifyHumanOperatorOutput(output) {
  const cases = [];
  const lines = output.trim().split(/\r?\n/);
  for (const line of lines) {
    if (line === "human namespace acceptance: complete") continue;
    const label = line.startsWith("PASS ") ? line.slice(5) : "";
    if (!HUMAN_CASES.includes(label))
      throw new Error("unexpected_or_sensitive_operator_output");
    cases.push(label);
  }
  if (lines.at(-1) !== "human namespace acceptance: complete")
    throw new Error("operator_output_not_complete");
  if (!HUMAN_CASES.every((label) => cases.includes(label)))
    throw new Error("operator_output_cases_incomplete");
  return { output_redacted: true, case_count: cases.length };
}
