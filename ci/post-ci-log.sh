#!/bin/sh
set -eu

endpoint=${CI_LOG_ENDPOINT:-http://192.168.86.41:9000/ingest}
context=${1:-ci}
status=${2:-error}
log_file=${3:-}

payload_file=$(mktemp)
cleanup() {
  rm -f "$payload_file"
}
trap cleanup EXIT INT TERM

{
  printf 'timestamp=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'context=%s\n' "$context"
  printf 'status=%s\n' "$status"
  printf 'repository=%s\n' "${FORGEJO_REPOSITORY:-${GITHUB_REPOSITORY:-unknown}}"
  printf 'ref=%s\n' "${FORGEJO_REF:-${GITHUB_REF:-unknown}}"
  printf 'sha=%s\n' "${FORGEJO_SHA:-${GITHUB_SHA:-unknown}}"
  printf 'runner=%s\n' "${RUNNER_NAME:-unknown}"
  printf '\n'
  if [ -n "$log_file" ] && [ -f "$log_file" ]; then
    cat "$log_file"
  else
    cat
  fi
} > "$payload_file"

curl --fail --silent --show-error \
  --header 'Content-Type: text/plain; charset=utf-8' \
  --data-binary @"$payload_file" \
  "$endpoint" >/dev/null || true
