#!/bin/sh
set -eu

sccache_version=${1:-0.10.0}

if command -v sccache >/dev/null 2>&1; then
  printf 'sccache already available: '
  sccache --version || true
  exit 0
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is unavailable; skipping sccache installation"
  exit 0
fi

echo "Installing sccache ${sccache_version}"
if cargo install --locked --version "$sccache_version" sccache; then
  sccache --version || true
else
  echo "warning: failed to install sccache ${sccache_version}; continuing without compiler cache" >&2
fi
