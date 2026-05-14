#!/bin/sh
set -eu
umask 022

usage() {
  echo "usage: $0 <job-name> <artifact>..." >&2
  exit 1
}

job_name=${1:-}
[ -n "$job_name" ] || usage
shift
[ "$#" -gt 0 ] || usage

release_root=${RELEASE_STAGING_ROOT:-/build-cache/centralssh-release-staging}
repository=${FORGEJO_REPOSITORY:-${GITHUB_REPOSITORY:-}}
tag=${FORGEJO_REF_NAME:-${GITHUB_REF_NAME:-}}
commit_sha=${FORGEJO_SHA:-${GITHUB_SHA:-}}

[ -n "$repository" ] || {
  echo "missing repository name for release staging" >&2
  exit 1
}
[ -n "$tag" ] || {
  echo "missing tag name for release staging" >&2
  exit 1
}
[ -n "$commit_sha" ] || {
  echo "missing commit SHA for release staging" >&2
  exit 1
}

repo_key=$(printf '%s' "$repository" | sed 's#[/:@]#_#g')
stage_run="$release_root/$repo_key/$tag/$commit_sha"
stage_dir="$stage_run/$job_name"

mkdir -p "$stage_run"
find "$release_root/$repo_key" -type d -exec chmod 0777 {} + 2>/dev/null || true

probe_file="$stage_run/.centralssh-release-write-probe.$$"
if ! : > "$probe_file" 2>/dev/null; then
  echo "release staging run directory is not writable: $stage_run" >&2
  exit 1
fi
rm -f "$probe_file"

rm -rf "$stage_dir"
mkdir -p "$stage_dir"
chmod 0777 "$stage_dir" 2>/dev/null || true
: > "$stage_dir/manifest.txt"

for artifact_path in "$@"; do
  [ -f "$artifact_path" ] || {
    echo "release artifact does not exist: $artifact_path" >&2
    exit 1
  }
  artifact_name=$(basename "$artifact_path")
  cp "$artifact_path" "$stage_dir/$artifact_name"
  printf '%s\n' "$artifact_name" >> "$stage_dir/manifest.txt"
done

LC_ALL=C sort -o "$stage_dir/manifest.txt" "$stage_dir/manifest.txt"
touch "$stage_dir/.complete"
printf 'staged release artifacts in %s\n' "$stage_dir"
