# Continuum S3 acceptance

- TC-CS3-001: Archive only tracked files at a verified main SHA; local files and secrets are absent.
- TC-CS3-002: Reject changed digest/size, undelivered patches, wrong bucket/key/version and unsupported artifact shape.
- TC-CS3-003: Bind each scan and patch receipt to its immutable source SHA; never infer a revision from patch prose.
- TC-CS3-004: Reject traversal, binaries, symlinks, executable files, deletions, renames and control/dependency paths before applying patches.
- TC-CS3-005: Apply a real unified diff through an isolated Git index without checking out or executing candidate code.
- TC-CS3-006: Replay publication without duplicate branches/PRs; reject altered PR heads and stale bases.
- TC-CS3-007: Reject foreign/failed/skipped/stale validation runs; only exact main-authored workflow evidence can authorize merge.
- TC-CS3-008: Cloud template isolates source/patch/control prefixes, denies public/plaintext access and limits OIDC to main and immutable repository IDs.
- TC-CS3-009: Live main snapshot upload, environment creation and actual scan status are independently recorded. Zero findings or pending remediation does not prove patch generation.
- TC-CS3-010: A genuine generated patch is promoted only after service/S3/CI verification; deployment must have a successful runtime smoke test.
- TC-CS3-011: A terminal scan with an active issue still uploads the latest main archive but does not change the environment or start another scan. Unknown issue states and pending delivery also hold the source; terminal issues and terminal delivery permit progress.
- TC-CS3-012: Issue-detail transport failures stop source rotation, and an existing scan journal still resumes with the original idempotency token.
- TC-CS3-013: Aggregate FAILED with one failed and one pending patch holds the source. Progress resumes only when validated delivery counts account for every patch; malformed or incomplete counts also hold the source.
- TC-CS3-014: A verified regular-text control patch can be published and tested without cloud credentials, but cannot merge without the personal repository owner's approval of its exact head. Runtime test changes also require this approval.
- TC-CS3-015: Missing, foreign, stale, dismissed or changes-requested reviews never authorize merge. Refresh review evidence after successful CI. No Actions bot review can authorize itself.
- TC-CS3-016: Manual patch selection validates a SHA-256 digest and processes only that artifact/receipt; it does not start another scan or dispatch other patches.
- TC-CS3-017: Reviewable patches retain path, size, mode, credential-file, source-lineage, S3-byte and public-content checks. Publication does not constitute approval.
- TC-CS3-018: Reject private environment/integration/issue/artifact/finding identifiers in generated source, including IDs wrapped across comment lines. Preserve the original patch bytes; do not silently sanitize and claim a digest match.
