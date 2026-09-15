export async function lockNamespaceLifecycle(db) {
  await db.query(
    "SELECT pg_advisory_xact_lock(hashtext('mem9-namespace-reconcile-v1'))",
  );
}

// The caller must first lock/update the namespace or principal in the same
// transaction. A separate statement gets a fresh snapshot after waiting for
// an enqueue. Job-row locks serialize cancellation against atomic apply.
export async function cancelNamespaceIngestJobs(db, namespaceID) {
  await db.query(
    `UPDATE ingest_jobs
     SET state = 'dead', error_class = 'namespace_disabled',
         runtime_finalization_state = CASE
           WHEN runtime_operation_id IS NOT NULL THEN 'finalizing' ELSE NULL END,
         lease_owner = NULL, lease_expires_at = NULL,
         completed_at = statement_timestamp(), updated_at = statement_timestamp()
     WHERE namespace_id = $1 AND state NOT IN ('succeeded', 'dead')`,
    [namespaceID],
  );
}

export async function cancelPrincipalIngestJobs(db, principalIDs, reason) {
  await db.query(
    `UPDATE ingest_jobs
     SET state = 'dead', error_class = $2,
         runtime_finalization_state = CASE
           WHEN runtime_operation_id IS NOT NULL THEN 'finalizing' ELSE NULL END,
         lease_owner = NULL, lease_expires_at = NULL,
         completed_at = statement_timestamp(), updated_at = statement_timestamp()
     WHERE principal_id = ANY($1::varchar[]) AND state NOT IN ('succeeded', 'dead')`,
    [principalIDs, reason],
  );
}
