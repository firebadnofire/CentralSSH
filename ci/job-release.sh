#!/bin/sh
set -eu

usage() {
  echo "usage: $0 <artifact-root>" >&2
  exit 1
}

artifact_root=${1:-}
[ -n "$artifact_root" ] || usage
[ -d "$artifact_root" ] || {
  printf 'artifact root does not exist: %s\n' "$artifact_root" >&2
  exit 1
}

repo_root=${REPO_ROOT:-$PWD}

release_env=$(sh "$repo_root/ci/release-version.sh") || exit $?
eval "$release_env"
version=${RELEASE_VERSION:?Missing validated release version}

expected_assets="
centralssh-${version}-linux-amd64-systemd.tar.gz
centralssh-${version}-debian-amd64.deb
centralssh-${version}-fedora-x86_64.rpm
centralssh-${version}-linux-arm64-systemd.tar.gz
centralssh-${version}-debian-arm64.deb
centralssh-${version}-fedora-aarch64.rpm
centralssh-${version}-freebsd-amd64.pkg
centralssh-${version}-freebsd-amd64.tar.gz
centralssh-${version}-freebsd-aarch64.pkg
centralssh-${version}-freebsd-aarch64.tar.gz
"

artifact_paths=
for asset_name in $expected_assets; do
  asset_path=$(find "$artifact_root" -type f -name "$asset_name" | sed -n '1p')
  [ -n "$asset_path" ] || {
    printf 'missing downloaded CI artifact: %s\n' "$asset_name" >&2
    exit 1
  }
  artifact_paths="${artifact_paths}${artifact_paths:+ }$asset_path"
done

set -- $artifact_paths
exec "$repo_root/ci/publish-release.sh" "$@"
