#!/bin/sh
set -eu

preferred_root=${1:-/build-cache}
fallback_root=${2:-$PWD/.ci-host-cache}

probe_write() {
  candidate_root=$1
  mkdir -p "$candidate_root" 2>/dev/null || return 1
  probe_path="${candidate_root}/.cache-write-probe.$$"
  if : >"$probe_path" 2>/dev/null; then
    rm -f "$probe_path"
    return 0
  fi
  return 1
}

if probe_write "$preferred_root"; then
  printf '%s\n' "$preferred_root"
else
  mkdir -p "$fallback_root"
  printf '%s\n' "$fallback_root"
fi
