#!/bin/sh
set -eu

echo "rustc: $(rustc --version)"
echo "cargo: $(cargo --version)"
echo "CARGO_HOME=${CARGO_HOME:-unset}"
echo "CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-unset}"
echo "SCCACHE_DIR=${SCCACHE_DIR:-unset}"
echo "CI_CACHE_KEY=${CI_CACHE_KEY:-unset}"
echo "CI_CACHE_ROOT=${CI_CACHE_ROOT:-unset}"

if command -v sccache >/dev/null 2>&1; then
  sccache --show-stats || true
fi

for path in \
  "${CARGO_HOME:-}/registry" \
  "${CARGO_HOME:-}/git" \
  "${CARGO_TARGET_DIR:-}" \
  "${SCCACHE_DIR:-}"
do
  if [ -n "$path" ] && [ -e "$path" ]; then
    du -sh "$path" 2>/dev/null || true
  fi
done
