#!/bin/sh
set -eu

pty_record_wrapper() {
  output_prefix=$1
  shift

  if [ "${CENTRALSSH_CAP_SCRIPT:-false}" = "true" ]; then
    script_log="$output_prefix.typescript"
    timing_log="$output_prefix.timing"
    if script -q /dev/null true >/dev/null 2>&1; then
      script -q "$script_log" "$@" >/dev/null 2>&1
    elif script -q -t 0 "$timing_log" "$script_log" "$@" >/dev/null 2>&1; then
      :
    else
      "$@"
    fi
  else
    "$@"
  fi
}

write_term_snapshot() {
  out=$1
  {
    echo "TERM=${TERM:-}"
    locale || true
    command -v infocmp >/dev/null 2>&1 && infocmp "${TERM:-xterm-256color}" || true
  } >"$out"
}
