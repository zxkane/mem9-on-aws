#!/usr/bin/env bash
# Dedicated isolated smoke; historical DATA preparation scripts stay unchanged.
set -euo pipefail
SMOKE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec node "$SMOKE_ROOT/scripts/run-mnemo-nonroot-smoke.mjs" "$@"
