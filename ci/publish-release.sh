#!/bin/sh
set -eu
umask 022

release_root=${RELEASE_STAGING_ROOT:-/build-cache/centralssh-release-staging}
repository=${FORGEJO_REPOSITORY:-${GITHUB_REPOSITORY:-}}
tag=${FORGEJO_REF_NAME:-${GITHUB_REF_NAME:-}}
commit_sha=${FORGEJO_SHA:-${GITHUB_SHA:-}}
api_url=${FORGEJO_API_URL:-${GITHUB_API_URL:-}}
token=${FORGEJO_TOKEN:-${GITHUB_TOKEN:-}}
work_dir=${RELEASE_WORK_DIR:-${RUNNER_TEMP:-/tmp}/centralssh-release-publish}

[ -n "$repository" ] || {
  echo "missing repository name for release publication" >&2
  exit 1
}
[ -n "$tag" ] || {
  echo "missing tag name for release publication" >&2
  exit 1
}
[ -n "$commit_sha" ] || {
  echo "missing commit SHA for release publication" >&2
  exit 1
}
[ -n "$api_url" ] || {
  echo "missing Forgejo API URL for release publication" >&2
  exit 1
}
[ -n "$token" ] || {
  echo "missing Forgejo token for release publication" >&2
  exit 1
}

version=$(awk -F'"' '/^version = / { print $2; exit }' Cargo.toml)
[ -n "$version" ] || {
  echo "failed to resolve Cargo.toml version" >&2
  exit 1
}

owner=${repository%%/*}
repo=${repository#*/}
repo_key=$(printf '%s' "$repository" | sed 's#[/:@]#_#g')
stage_run="$release_root/$repo_key/$tag/$commit_sha"
dist_dir="$work_dir/dist"
expected_file="$work_dir/expected-assets.txt"
assets_file="$work_dir/release-assets.txt"

rm -rf "$work_dir"
mkdir -p "$dist_dir"

cat > "$expected_file" <<EOF
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
EOF

for job_name in linux-packages-amd64 linux-packages-arm64 freebsd-amd64 freebsd-aarch64; do
  [ -f "$stage_run/$job_name/.complete" ] || {
    echo "missing completed release staging marker for $job_name under $stage_run" >&2
    exit 1
  }
done

: > "$assets_file"
while IFS= read -r asset_name; do
  matches=$(find "$stage_run" -mindepth 2 -maxdepth 2 -type f -name "$asset_name" | LC_ALL=C sort)
  count=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d ' ')
  [ "$count" = "1" ] || {
    echo "expected exactly one staged artifact named $asset_name, found $count" >&2
    exit 1
  }
  asset_path=$(printf '%s\n' "$matches" | sed -n '1p')
  cp "$asset_path" "$dist_dir/$asset_name"
  printf '%s\n' "$dist_dir/$asset_name" >> "$assets_file"
done < "$expected_file"

(
  cd "$dist_dir"
  while IFS= read -r asset_name; do
    sha256sum "$asset_name"
  done < "$expected_file"
) > "$dist_dir/sha256sums"
printf '%s\n' "$dist_dir/sha256sums" >> "$assets_file"

api_request() {
  method=$1
  url=$2
  shift 2
  curl --fail-with-body --silent --show-error \
    --request "$method" \
    --header "Authorization: token ${token}" \
    "$@" \
    "$url"
}

upload_asset() {
  release_id=$1
  asset_path=$2
  asset_name=$(basename "$asset_path")
  asset_name_encoded=$(jq -nr --arg v "$asset_name" '$v|@uri')
  api_request POST "${api_url}/repos/${owner}/${repo}/releases/${release_id}/assets?name=${asset_name_encoded}" \
    --header "Content-Type: application/octet-stream" \
    --data-binary @"$asset_path" >/dev/null
}

release_name="CentralSSH ${tag}"
release_body="Automated CentralSSH release for ${tag}. See sha256sums for checksums."
draft_payload=$(jq -n \
  --arg tag "$tag" \
  --arg name "$release_name" \
  --arg body "$release_body" \
  '{tag_name: $tag, name: $name, body: $body, draft: true, prerelease: false, hide_archive_links: false}')
public_payload=$(jq -n \
  --arg tag "$tag" \
  --arg name "$release_name" \
  --arg body "$release_body" \
  '{tag_name: $tag, name: $name, body: $body, draft: false, prerelease: false, hide_archive_links: false}')

release_json=$(api_request GET "${api_url}/repos/${owner}/${repo}/releases" \
  | jq -c --arg tag "$tag" 'map(select(.tag_name == $tag)) | first // empty')

if [ -z "$release_json" ]; then
  release_json=$(api_request POST "${api_url}/repos/${owner}/${repo}/releases" \
    --header "Content-Type: application/json" \
    --data "$draft_payload")
else
  release_id=$(printf '%s' "$release_json" | jq -r '.id')
  [ -n "$release_id" ] && [ "$release_id" != "null" ] || {
    echo "failed to resolve existing release id for $tag" >&2
    exit 1
  }
  release_json=$(api_request PATCH "${api_url}/repos/${owner}/${repo}/releases/${release_id}" \
    --header "Content-Type: application/json" \
    --data "$draft_payload")
fi

release_id=$(printf '%s' "$release_json" | jq -r '.id')
[ -n "$release_id" ] && [ "$release_id" != "null" ] || {
  echo "failed to resolve release id for $tag" >&2
  exit 1
}

api_request GET "${api_url}/repos/${owner}/${repo}/releases/${release_id}/assets" \
  | jq -r '.[].id' \
  | while IFS= read -r asset_id; do
      [ -n "$asset_id" ] || continue
      api_request DELETE "${api_url}/repos/${owner}/${repo}/releases/${release_id}/assets/${asset_id}" >/dev/null
    done

while IFS= read -r asset_path; do
  upload_asset "$release_id" "$asset_path"
done < "$assets_file"

api_request PATCH "${api_url}/repos/${owner}/${repo}/releases/${release_id}" \
  --header "Content-Type: application/json" \
  --data "$public_payload" >/dev/null

case "$stage_run" in
  "$release_root"/*) rm -rf "$stage_run" 2>/dev/null || true ;;
esac

printf 'published release %s with %s artifacts plus sha256sums\n' "$tag" "$(wc -l < "$expected_file" | tr -d ' ')"
