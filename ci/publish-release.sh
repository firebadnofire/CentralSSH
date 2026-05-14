#!/bin/sh
set -eu
umask 022

repository=${FORGEJO_REPOSITORY:-${GITHUB_REPOSITORY:-}}
tag=${FORGEJO_REF_NAME:-${GITHUB_REF_NAME:-}}
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

release_name="CentralSSH ${tag}"
release_body="Automated CentralSSH release for ${tag}. See sha256sums for checksums."
public_payload=$(jq -n \
  --arg tag "$tag" \
  --arg name "$release_name" \
  --arg body "$release_body" \
  '{tag_name: $tag, name: $name, body: $body, draft: false, prerelease: false, hide_archive_links: false}')

release_json=$(api_request GET "${api_url}/repos/${owner}/${repo}/releases" \
  | jq -c --arg tag "$tag" 'map(select(.tag_name == $tag)) | first // empty')

if [ -z "$release_json" ]; then
  echo "failed to find staged Forgejo release for $tag" >&2
  exit 1
fi

release_id=$(printf '%s' "$release_json" | jq -r '.id')
[ -n "$release_id" ] && [ "$release_id" != "null" ] || {
  echo "failed to resolve release id for $tag" >&2
  exit 1
}

release_assets="$work_dir/release-assets.json"
api_request GET "${api_url}/repos/${owner}/${repo}/releases/${release_id}/assets" > "$release_assets"

download_asset() {
  asset_name=$1
  download_url=$(jq -r --arg name "$asset_name" '.[] | select(.name == $name) | .browser_download_url' "$release_assets" | sed -n '1p')
  [ -n "$download_url" ] && [ "$download_url" != "null" ] || {
    echo "missing staged release asset: $asset_name" >&2
    exit 1
  }
  curl --fail-with-body --silent --show-error --location \
    --header "Authorization: token ${token}" \
    --output "$dist_dir/$asset_name" \
    "$download_url"
  printf '%s\n' "$dist_dir/$asset_name" >> "$assets_file"
}

: > "$assets_file"
while IFS= read -r asset_name; do
  download_asset "$asset_name"
done < "$expected_file"

(
  cd "$dist_dir"
  while IFS= read -r asset_name; do
    sha256sum "$asset_name"
  done < "$expected_file"
) > "$dist_dir/sha256sums"

sha_asset_id=$(jq -r '.[] | select(.name == "sha256sums") | .id' "$release_assets" | sed -n '1p')
if [ -n "$sha_asset_id" ]; then
  api_request DELETE "${api_url}/repos/${owner}/${repo}/releases/${release_id}/assets/${sha_asset_id}" >/dev/null
fi
api_request POST "${api_url}/repos/${owner}/${repo}/releases/${release_id}/assets?name=sha256sums" \
  --form "attachment=@${dist_dir}/sha256sums" >/dev/null

api_request PATCH "${api_url}/repos/${owner}/${repo}/releases/${release_id}" \
  --header "Content-Type: application/json" \
  --data "$public_payload" >/dev/null

printf 'published release %s with %s artifacts plus sha256sums\n' "$tag" "$(wc -l < "$expected_file" | tr -d ' ')"
