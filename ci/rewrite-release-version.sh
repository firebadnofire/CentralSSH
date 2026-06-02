#!/bin/sh
set -eu

repo_root=${REPO_ROOT:-$PWD}

release_env=$(sh "$repo_root/ci/release-version.sh")
eval "$release_env"

cargo_toml="$repo_root/Cargo.toml"
cargo_lock="$repo_root/Cargo.lock"

tmp_manifest=$(mktemp "${TMPDIR:-/tmp}/centralssh-cargo-toml.XXXXXX")
tmp_lock=$(mktemp "${TMPDIR:-/tmp}/centralssh-cargo-lock.XXXXXX")
cleanup() {
  rm -f "$tmp_manifest" "$tmp_lock"
}
trap cleanup EXIT INT TERM

awk -v version="$RELEASE_VERSION" '
  BEGIN { in_package = 0; replaced = 0 }
  /^\[package\]$/ { in_package = 1 }
  /^\[/ && $0 != "[package]" { in_package = 0 }
  in_package && !replaced && /^version[[:space:]]*=[[:space:]]*"/ {
    sub(/^version[[:space:]]*=[[:space:]]*".*"/, "version = \"" version "\"")
    replaced = 1
  }
  { print }
  END { if (!replaced) exit 1 }
' "$cargo_toml" > "$tmp_manifest" || {
  echo "failed to rewrite Cargo.toml version" >&2
  exit 1
}

mv "$tmp_manifest" "$cargo_toml"

if ! (
  cd "$repo_root"
  cargo generate-lockfile --offline
); then
  tmp_lock_updated=$(mktemp "${TMPDIR:-/tmp}/centralssh-cargo-lock.XXXXXX")
  awk -v version="$RELEASE_VERSION" '
    BEGIN { seen = 0; updated = 0 }
    $0 == "name = \"centralssh\"" { seen = 1 }
    seen && !updated && $0 ~ /^version = / {
      print "version = \"" version "\""
      updated = 1
      next
    }
    { print }
    END {
      if (!seen) {
        print "failed to locate centralssh package entry in Cargo.lock" > "/dev/stderr"
        exit 1
      }
      if (!updated) {
        print "failed to update centralssh package version in Cargo.lock" > "/dev/stderr"
        exit 1
      }
    }
  ' "$cargo_lock" > "$tmp_lock_updated" || {
    rm -f "$tmp_lock_updated"
    echo "failed to regenerate Cargo.lock version entry" >&2
    exit 1
  }
  mv "$tmp_lock_updated" "$cargo_lock"
fi

awk -v version="$RELEASE_VERSION" '
  $0 == "name = \"centralssh\"" { seen = 1 }
  seen && $0 ~ /^version = / {
    if ($0 != "version = \"" version "\"") {
      printf "Cargo.lock version mismatch after regeneration: expected %s, found %s\n", version, $0 > "/dev/stderr"
      exit 1
    }
    exit 0
  }
  END {
    if (!seen) {
      print "failed to locate centralssh package entry in Cargo.lock" > "/dev/stderr"
      exit 1
    }
  }
' "$cargo_lock" || exit 1

printf 'release-version: rewrote Cargo.toml and Cargo.lock for %s\n' "$RELEASE_VERSION" >&2
printf 'RELEASE_TAG=%s\n' "$RELEASE_TAG"
printf 'RELEASE_VERSION=%s\n' "$RELEASE_VERSION"
printf 'CENTRALSSH_RELEASE_VERSION=%s\n' "$RELEASE_VERSION"
printf 'CENTRALSSH_DIST_BUILD=1\n'
