# Continuum S3 scanning

The public main branch is the only source. A trusted main workflow archives its
exact commit to a write-once S3 key. One operator-bound Continuum environment
selects immutable SHA-specific ZIP archives. A durable ledger maps scan IDs to source commits. Both issue findings
and the patch archive name must identify the same revision before publication;
unknown or mixed lineage requires reconciliation. The integration
has source read and patch write permissions, with no application data access.

A serialized controller records source-change intent before UpdateEnvironment
and a stable scan token before CreateCodeScan, polls service issue artifacts, verifies the patch
hash and delivered S3 object version, and applies only bounded regular runtime
source changes in an empty Git index. It never executes candidate code. A
private S3 receipt binds environment, artifact, source, patch and PR head.

The controller publishes PRs through GITHUB_TOKEN and explicitly dispatches a
separate read-only validation workflow. That workflow checks out the protected
base, validates PR identity/revision/diff before checking out the candidate, and
runs root and infra tests without cloud access, write tokens, caches or artifacts.
The trusted controller verifies the exact workflow, base, head and successful
jobs before publishing required checks and requesting a SHA-conditioned merge.
It explicitly dispatches the existing main production workflow after merge.

GitHub combines Actions PR creation and approval enablement in one repository
setting. The controller uses it to create PRs; it never submits review approvals.
The existing direct-GitHub Continuum lane remains independently disabled.

Snapshots and scan receipts are retained in the private bucket. The controller
coalesces main updates while a scan is active and queues a daily rescan when main
has not changed. Ambiguous source changes or unrecorded scans stop promotion. A
successful scan with zero patches is not an end-to-end fix.
