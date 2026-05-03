#!/bin/sh
set -eu

preferred_root=${1:-/data/cache}
fallback_root=${2:-$PWD/.ci-host-cache}

if mkdir -p "$preferred_root" 2>/dev/null; then
  printf '%s\n' "$preferred_root"
else
  mkdir -p "$fallback_root"
  printf '%s\n' "$fallback_root"
fi
