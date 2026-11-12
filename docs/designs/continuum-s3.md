# Continuum S3 scanning

The public main branch is the only source. A trusted main workflow archives its
exact commit to a write-once S3 key. One operator-bound Continuum environment
selects immutable SHA-specific ZIP archives. A durable ledger maps scan IDs to source commits. Both issue findings
and the patch archive name must identify the same revision before publication;
unknown or mixed lineage requires reconciliation. The integration
has source read and patch write permissions, with no application data access.

A serialized controller records source-change intent before UpdateEnvironment
and a stable scan token before CreateCodeScan, polls service issue artifacts, verifies the patch
hash and delivered S3 object version, and applies only bounded regular source
and configuration text changes in an empty Git index. Credential files,
unsupported formats and non-regular files remain inadmissible. It never executes candidate code. A
private S3 receipt binds environment, artifact, source, patch and PR head.
Known private service identifiers in generated source also block publication,
including identifiers wrapped across comments. The controller never rewrites
patch bytes to make them pass the public-content check.

The controller publishes PRs through GITHUB_TOKEN and explicitly dispatches a
separate read-only validation workflow. That workflow checks out the protected
base, validates PR identity/revision/diff before checking out the candidate, and
runs root and infra tests without cloud access, write tokens, caches or artifacts.
The trusted controller verifies the exact workflow, base, head and successful
jobs before publishing required checks and requesting a SHA-conditioned merge.
It explicitly dispatches the existing main production workflow after merge.

Publication and merge authorization are separate. Runtime-only changes can
merge after isolated CI. Control, infrastructure, dependency and test changes
also need the personal repository owner's approval of the exact PR head.
The controller fetches reviews again after successful CI and rejects foreign,
stale, dismissed and changes-requested approvals. It derives this requirement
from the actual diff, not a label or mutable PR body. Organization-owned
repositories require a separately designed reviewer binding for this lane.
Candidate tests still receive no cloud credentials or write permissions.
An approval submitted while CI runs remains valid for that identical head and
base, including reruns. The fresh check is of the current review decision; it
does not require the owner to repeat an unchanged code review after CI finishes.

For a focused validation, manually dispatch `continuum-s3.yml` with
`patch_sha256` set to the generated patch's SHA-256 digest. That run only
reconciles the matching artifact/receipt and never starts a new scan. Empty
selection retains normal source synchronization and discovery. Selection is
not approval and does not weaken S3 provenance or merge checks.

GitHub combines Actions PR creation and approval enablement in one repository
setting. The controller uses it to create PRs; it never submits review approvals.
The existing direct-GitHub Continuum lane remains independently disabled.

Snapshots and scan receipts are retained in the private bucket. The controller
coalesces main updates while a scan or known issue processing is active and queues
a daily rescan when main has not changed. A successful scan does not mean
remediation has finished. Before rotating the source prefix or starting another
scan, the controller refreshes issue details and waits for terminal issue and
patch-delivery states. Unknown states also hold the source. Terminal failed
deliveries remain unpublishable; they are not counted as successful patches.
An aggregate delivery failure can conceal a pending delivery. Success and
failure counts must cover every destination patch before rotation; incomplete
or mixed failed/skipped counts conservatively retain the source for review.
This gate covers the service's currently listed issues; an empty inventory is
not evidence that no later findings will appear. Ambiguous source changes or
unrecorded scans stop promotion. A successful scan with zero patches is not an
end-to-end fix.

## Repairing rejected remediations

A remediation changed after review follows an owner-authored repair PR. It does
not reuse an immutable artifact receipt or claim the original patch digest. The
repair PR combines overlapping changes and closes superseded generated PRs only
after its own regression tests, review and normal integration checks pass.

Embedding inference uses one warm model process and a bounded request queue.
The HTTP supervisor retains responsive deadlines even when native inference
blocks. It sends one text at a time, preserves single-text maintenance requests,
and kills the active child on timeout or response-socket disconnect. It waits
for child exit before releasing the active job or starting a replacement, so
cancellation cannot admit overlapping model processes. Queued cancellation only
removes that request. Readiness is false while the model reloads; pending work
fails with a retryable response. A model-load failure is fatal to the service.
Fixed event codes and bounded counters provide diagnostics without exception
strings, request contents, arbitrary URL paths or header values.

Private JSON evidence is read through validated descriptors with a bounded
stream. Nonblocking opens reject special files without waiting for a writer;
anchored directory traversal prevents ancestor replacement from redirecting a
read. Tests exercise the real filesystem and process cancellation boundaries,
not only mocked happy paths. Existing runtime credentials, runner selection,
maintenance admission and cloud trust boundaries remain in force.
