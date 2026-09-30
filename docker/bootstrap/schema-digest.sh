#!/bin/sh
set -eu
cd "${1:?schema directory required}"
export LC_ALL=C
hash_file=$(mktemp)
trap 'rm -f "$hash_file"' EXIT HUP INT TERM
for asset in schema.sql migrations/*.sql runtime-contract.sql; do
  digest=$(sha256sum "$asset") || exit 1
  printf '%s\000%s\n' "$asset" "${digest%% *}" >>"$hash_file"
done
digest=$(sha256sum "$hash_file") || exit 1
printf '%s\n' "${digest%% *}"
