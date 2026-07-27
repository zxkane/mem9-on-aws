#!/usr/bin/env bash
# Reuse the full image health/migration smoke and enable its strict non-TTY EMF
# byte capture. The workflow supplies the just-built arm64 MNEMO_IMAGE.

set -euo pipefail

export MNEMO_VALIDATE_EMF=true
exec bash scripts/run-mnemo-health-smoke.sh
