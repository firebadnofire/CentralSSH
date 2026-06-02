#!/bin/sh
set -eu

endpoint=${CI_LOG_ENDPOINT:-http://192.168.86.41:9000/ingest}
context=${1:-ci}
status=${2:-error}
log_file=${3:-}
failed_command=${4:-${FAILED_COMMAND:-}}

filter_log() {
  grep -Ev '^(    Updating crates\.io index| Downloading crates \.\.\.|  Downloaded |   Compiling )' |
    tail -n 250
}

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
  if [ -n "$failed_command" ]; then
    printf 'command=%s\n' "$(printf '%s' "$failed_command" | tr '\n' ' ')"
  fi
  if [ -n "$log_file" ]; then
    printf 'log_file=%s\n' "$log_file"
  fi
  printf 'cwd=%s\n' "$(pwd)"
  printf '\n'
  if [ -n "$log_file" ] && [ -f "$log_file" ]; then
    filter_log < "$log_file"
  else
    filter_log
  fi
} > "$payload_file"

curl --fail --silent --show-error \
  --header 'Content-Type: text/plain; charset=utf-8' \
  --data-binary @"$payload_file" \
  "$endpoint" >/dev/null || true
