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
