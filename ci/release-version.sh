#!/bin/sh
set -eu

repo_root=${REPO_ROOT:-$PWD}
tag=${FORGEJO_REF_NAME:-${GITHUB_REF_NAME:-}}

cargo_version=$(awk -F'"' '/^version = / { print $2; exit }' "$repo_root/Cargo.toml")
[ -n "$cargo_version" ] || {
  echo "failed to resolve Cargo.toml version" >&2
  exit 1
}

printf 'release-version: cargo_version=%s\n' "$cargo_version" >&2

if [ -n "$tag" ]; then
  case "$tag" in
    v*|V*) tag_version=${tag#?} ;;
    *)
      echo "release-version: tag must start with v or V: $tag" >&2
      exit 1
      ;;
  esac
  [ -n "$tag_version" ] || {
    echo "release-version: tag version is empty after stripping prefix: $tag" >&2
    exit 1
  }
  printf 'release-version: release_tag=%s tag_version=%s\n' "$tag" "$tag_version" >&2
  [ "$cargo_version" = "$tag_version" ] || {
    printf 'release-version mismatch: Cargo.toml=%s tag=%s tag_version=%s\n' \
      "$cargo_version" "$tag" "$tag_version" >&2
    exit 1
  }
  printf 'RELEASE_TAG=%s\n' "$tag"
else
  printf 'release-version: no release tag present in environment\n' >&2
  printf 'RELEASE_TAG=\n'
fi

printf 'RELEASE_VERSION=%s\n' "$cargo_version"
