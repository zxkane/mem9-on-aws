#!/bin/sh
set -eu

# The task is ephemeral, but its image can be reused by an IaC-only preview.
# Upgrade before Chrome starts so every invocation uses the current stable
# package and no vulnerable browser process remains resident after completion.
apt-get update -qq
apt-get install -y -qq --only-upgrade google-chrome-stable >/dev/null
exec gosu node node /app/scripts/run-human-namespace-task.mjs
