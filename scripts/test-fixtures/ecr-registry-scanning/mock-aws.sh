#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"$MOCK_AWS_LOG"

mutation_happened() {
  [[ -f "${MOCK_AWS_STATE}.put" ||
     -f "${MOCK_AWS_STATE}.created" ||
     -f "${MOCK_AWS_STATE}.updated" ]]
}

case "${1:-} ${2:-}" in
  "ecr get-registry-scanning-configuration")
    if mutation_happened && [[ "${MOCK_MUTATION_CONVERGES:-true}" == "true" ]]; then
      if [[ -f "${MOCK_AWS_STATE}.put" ]]; then
        printf '%s' '{"registryId":"123456789012","scanningConfiguration":'
        cat "$MOCK_PUT_INPUT"
        printf '%s\n' '}'
      else
        cat "$MOCK_DECLARED_CONFIG"
      fi
      exit 0
    fi
    count=0
    [[ -f "$MOCK_AWS_STATE" ]] && read -r count <"$MOCK_AWS_STATE"
    count=$((count + 1))
    printf '%s\n' "$count" >"$MOCK_AWS_STATE"
    if [[ "$count" -gt 1 && -n "${MOCK_SECOND_CURRENT_CONFIG:-}" ]]; then
      cat "$MOCK_SECOND_CURRENT_CONFIG"
    else
      cat "$MOCK_CURRENT_CONFIG"
    fi
    ;;
  "ecr put-registry-scanning-configuration")
    if [[ "${MOCK_PUT_RESULT:-success}" == "failure" ]]; then
      echo "ServerException: mock registry write failed" >&2
      exit 255
    fi
    args=("$@")
    input_reference=""
    for ((index = 0; index < ${#args[@]}; index++)); do
      if [[ "${args[$index]}" == "--cli-input-json" ]]; then
        input_reference="${args[$((index + 1))]:-}"
        break
      fi
    done
    if [[ "$input_reference" != file://* ]]; then
      echo "Mock expected --cli-input-json file://..." >&2
      exit 64
    fi
    cp -- "${input_reference#file://}" "$MOCK_PUT_INPUT"
    touch "${MOCK_AWS_STATE}.put"
    printf '%s\n' '{"registryId":"123456789012"}'
    ;;
  "cloudformation describe-stacks")
    if mutation_happened && [[ "${MOCK_POST_MUTATION_STACK_STATE:-}" == "missing" ]]; then
      echo "ValidationError: Stack with id ecr-registry-scanning-mem9-on-aws does not exist" >&2
      exit 255
    fi
    if [[ "$MOCK_STACK_STATE" == "missing" && ! -f "${MOCK_AWS_STATE}.created" ]]; then
      echo "ValidationError: Stack with id ecr-registry-scanning-mem9-on-aws does not exist" >&2
      exit 255
    fi
    printf 'UPDATE_COMPLETE\n'
    ;;
  "cloudformation describe-stack-resources")
    if mutation_happened && [[ "${MOCK_POST_MUTATION_STACK_STATE:-}" == "unowned" ]]; then
      printf 'false\n'
      exit 0
    fi
    if [[ "$MOCK_STACK_STATE" == "owned" || -f "${MOCK_AWS_STATE}.created" ]]; then
      printf 'true\n'
    else
      printf 'false\n'
    fi
    ;;
  "cloudformation validate-template")
    printf '%s\n' '{"Parameters":[]}'
    ;;
  "cloudformation create-stack")
    touch "${MOCK_AWS_STATE}.created"
    printf '%s\n' '{"StackId":"mock-stack-id"}'
    ;;
  "cloudformation update-stack")
    if [[ "${MOCK_UPDATE_RESULT:-success}" == "no-updates" ]]; then
      echo "ValidationError: No updates are to be performed." >&2
      exit 255
    fi
    touch "${MOCK_AWS_STATE}.updated"
    printf '%s\n' '{"StackId":"mock-stack-id"}'
    ;;
  "cloudformation wait")
    ;;
  *)
    echo "Unexpected mock AWS command: $*" >&2
    exit 64
    ;;
esac
