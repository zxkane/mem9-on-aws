#!/usr/bin/env bash

verify_ssm_delete_response() {
  local response_file=$1
  shift
  [[ $# -gt 0 ]] || return 1

  jq -e --args '
    ($ARGS.positional | sort) as $expected
    | ((.InvalidParameters // []) | length == 0)
      and (((.DeletedParameters // []) | sort) == $expected)
  ' "$@" <"$response_file" >/dev/null
}
