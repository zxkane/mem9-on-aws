#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"$MOCK_AWS_LOG"

case "${1:-} ${2:-}" in
  "ecr get-registry-scanning-configuration")
    cat "$MOCK_CURRENT_CONFIG"
    ;;
  "cloudformation describe-stacks")
    if [[ "$MOCK_STACK_STATE" == "missing" ]]; then
      echo "ValidationError: Stack with id ecr-registry-scanning-mem9-on-aws does not exist" >&2
      exit 255
    fi
    printf 'UPDATE_COMPLETE\n'
    ;;
  "cloudformation describe-stack-resources")
    if [[ "$MOCK_STACK_STATE" == "owned" ]]; then
      printf 'true\n'
    else
      printf 'false\n'
    fi
    ;;
  "cloudformation validate-template")
    printf '%s\n' '{"Parameters":[]}'
    ;;
  "cloudformation create-stack")
    printf '%s\n' '{"StackId":"mock-stack-id"}'
    ;;
  "cloudformation update-stack")
    printf '%s\n' '{"StackId":"mock-stack-id"}'
    ;;
  "cloudformation wait")
    ;;
  *)
    echo "Unexpected mock AWS command: $*" >&2
    exit 64
    ;;
esac
