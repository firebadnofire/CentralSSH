#!/bin/sh
set -eu
umask 022

token=${GH_KEY:-}
api_url=${GITHUB_MIRROR_API_URL:-https://api.github.com}
upload_url=${GITHUB_MIRROR_UPLOAD_URL:-https://uploads.github.com}
owner=${GITHUB_MIRROR_OWNER:-firebadnofire}
repo=${GITHUB_MIRROR_REPO:-centralssh}
tag=${FORGEJO_REF_NAME:-${GITHUB_REF_NAME:-}}
work_dir=${RELEASE_WORK_DIR:-${RUNNER_TEMP:-/tmp}/centralssh-release-publish}
repo_root=${REPO_ROOT:-$PWD}

[ -n "$token" ] || {
  echo "missing GH_KEY for GitHub release publication" >&2
  exit 1
}
[ -n "$tag" ] || {
  echo "missing tag name for GitHub release publication" >&2
  exit 1
}
command -v curl >/dev/null 2>&1 || {
  echo "curl is required for GitHub release publication" >&2
  exit 1
}
command -v jq >/dev/null 2>&1 || {
  echo "jq is required for GitHub release publication" >&2
  exit 1
}

release_env=$(sh "$repo_root/ci/release-version.sh") || exit $?
eval "$release_env"
version=${RELEASE_VERSION:?Missing validated release version}
release_tag=${RELEASE_TAG:-}
[ "$tag" = "$release_tag" ] || {
  printf 'GitHub release publication tag mismatch: env_tag=%s validated_tag=%s\n' "$tag" "$release_tag" >&2
  exit 1
}

dist_dir="$work_dir/dist"
expected_file="$work_dir/expected-assets.txt"
[ -d "$dist_dir" ] || {
  printf 'missing release dist directory for GitHub publication: %s\n' "$dist_dir" >&2
  exit 1
}
[ -f "$expected_file" ] || {
  printf 'missing expected asset manifest for GitHub publication: %s\n' "$expected_file" >&2
  exit 1
}

log_cmd() {
  printf '+ %s\n' "$*" >&2
}

github_request() {
  method=$1
  url=$2
  shift 2
  response_file=$(mktemp)
  http_code_file=$(mktemp)
  log_cmd "curl --fail-with-body --silent --show-error --request $method $url"
  if curl --fail-with-body --silent --show-error \
    --request "$method" \
    --header "Accept: application/vnd.github+json" \
    --header "Authorization: Bearer ${token}" \
    --header "X-GitHub-Api-Version: 2022-11-28" \
    --output "$response_file" \
    --write-out '%{http_code}' \
    "$@" \
    "$url" >"$http_code_file"; then
    cat "$response_file"
    rm -f "$response_file" "$http_code_file"
    return 0
  fi

  curl_rc=$?
  http_code=$(cat "$http_code_file" 2>/dev/null || printf 'unknown')
  printf 'github request failed: method=%s url=%s curl_exit=%s http_status=%s\n' \
    "$method" "$url" "$curl_rc" "$http_code" >&2
  if [ -s "$response_file" ]; then
    printf 'github response body:\n' >&2
    cat "$response_file" >&2
  fi
  rm -f "$response_file" "$http_code_file"
  exit "$curl_rc"
}

release_name="CentralSSH ${tag}"
release_body="Automated CentralSSH release for ${tag}. See SHA256SUMS and SHA512SUMS for checksums."
payload=$(jq -n \
  --arg tag "$tag" \
  --arg name "$release_name" \
  --arg body "$release_body" \
  '{tag_name: $tag, name: $name, body: $body, draft: false, prerelease: false, make_latest: "true"}')

release_lookup=$(mktemp)
release_status=$(curl --silent --show-error \
  --output "$release_lookup" \
  --write-out '%{http_code}' \
  --header "Accept: application/vnd.github+json" \
  --header "Authorization: Bearer ${token}" \
  --header "X-GitHub-Api-Version: 2022-11-28" \
  "${api_url}/repos/${owner}/${repo}/releases/tags/${tag}")

if [ "$release_status" = "404" ]; then
  release_json=$(github_request POST "${api_url}/repos/${owner}/${repo}/releases" \
    --header "Content-Type: application/json" \
    --data "$payload")
elif [ "$release_status" = "200" ]; then
  release_json=$(cat "$release_lookup")
  release_id=$(printf '%s' "$release_json" | jq -r '.id')
  [ -n "$release_id" ] && [ "$release_id" != "null" ] || {
    echo "failed to resolve existing GitHub release id for $tag" >&2
    rm -f "$release_lookup"
    exit 1
  }
  release_json=$(github_request PATCH "${api_url}/repos/${owner}/${repo}/releases/${release_id}" \
    --header "Content-Type: application/json" \
    --data "$payload")
else
  cat "$release_lookup" >&2
  printf 'failed to look up GitHub release for %s: HTTP %s\n' "$tag" "$release_status" >&2
  rm -f "$release_lookup"
  exit 1
fi
rm -f "$release_lookup"

release_id=$(printf '%s' "$release_json" | jq -r '.id')
[ -n "$release_id" ] && [ "$release_id" != "null" ] || {
  echo "failed to resolve GitHub release id after create/update" >&2
  exit 1
}

release_assets=$(mktemp)
refresh_release_assets() {
  github_request GET "${api_url}/repos/${owner}/${repo}/releases/${release_id}/assets" > "$release_assets"
}

refresh_release_assets

upload_asset() {
  asset_path=$1
  asset_name=$(basename "$asset_path")
  [ -f "$asset_path" ] || {
    printf 'missing GitHub release asset file: %s\n' "$asset_path" >&2
    rm -f "$release_assets"
    exit 1
  }

  asset_id=$(jq -r --arg name "$asset_name" '.[] | select(.name == $name) | .id' "$release_assets" | sed -n '1p')
  if [ -n "$asset_id" ] && [ "$asset_id" != "null" ]; then
    github_request DELETE "${api_url}/repos/${owner}/${repo}/releases/assets/${asset_id}" >/dev/null
    refresh_release_assets
  fi

  asset_name_encoded=$(jq -nr --arg value "$asset_name" '$value|@uri')
  github_request POST "${upload_url}/repos/${owner}/${repo}/releases/${release_id}/assets?name=${asset_name_encoded}" \
    --header "Content-Type: application/octet-stream" \
    --data-binary @"$asset_path" >/dev/null
  refresh_release_assets
}

while IFS= read -r asset_name; do
  [ -n "$asset_name" ] || continue
  upload_asset "$dist_dir/$asset_name"
done < "$expected_file"

upload_asset "$dist_dir/SHA256SUMS"
upload_asset "$dist_dir/SHA512SUMS"

rm -f "$release_assets"
printf 'published GitHub release %s for %s/%s with %s artifacts plus SHA256SUMS and SHA512SUMS\n' \
  "$tag" "$owner" "$repo" "$(wc -l < "$expected_file" | tr -d ' ')"
