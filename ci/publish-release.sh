#!/bin/sh
set -eu
umask 022

usage() {
  echo "usage: $0 <artifact>..." >&2
  exit 1
}

[ "$#" -gt 0 ] || usage

repository=${FORGEJO_REPOSITORY:-${GITHUB_REPOSITORY:-}}
tag=${FORGEJO_REF_NAME:-${GITHUB_REF_NAME:-}}
api_url=${FORGEJO_API_URL:-${GITHUB_API_URL:-}}
token=${FORGEJO_TOKEN:-${GITHUB_TOKEN:-}}
repo_root=${REPO_ROOT:-$PWD}
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

release_env=$(sh "$repo_root/ci/release-version.sh") || exit $?
eval "$release_env"
version=${RELEASE_VERSION:?Missing validated release version}
release_tag=${RELEASE_TAG:-}
[ "$tag" = "$release_tag" ] || {
  printf 'release publication tag mismatch: env_tag=%s validated_tag=%s\n' "$tag" "$release_tag" >&2
  exit 1
}

owner=${repository%%/*}
repo=${repository#*/}
release_name="CentralSSH ${tag}"
release_body="Automated CentralSSH release for ${tag}. See sha256sums for checksums."
draft_payload=$(jq -n \
  --arg tag "$tag" \
  --arg name "$release_name" \
  --arg body "$release_body" \
  '{tag_name: $tag, name: $name, body: $body, draft: true, prerelease: false, hide_archive_links: false}')
publish_payload=$(jq -n \
  --arg tag "$tag" \
  --arg name "$release_name" \
  --arg body "$release_body" \
  '{tag_name: $tag, name: $name, body: $body, draft: false, prerelease: false, hide_archive_links: false}')

printf 'release publication: tag=%s version=%s\n' "$tag" "$version"

api_request() {
  method=$1
  url=$2
  shift 2
  response_file=$(mktemp)
  http_code_file=$(mktemp)
  printf '+ curl --fail-with-body --silent --show-error --request %s %s\n' "$method" "$url" >&2
  if curl --fail-with-body --silent --show-error \
    --request "$method" \
    --header "Authorization: token ${token}" \
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
  printf 'api request failed: method=%s url=%s curl_exit=%s http_status=%s\n' \
    "$method" "$url" "$curl_rc" "$http_code" >&2
  if [ -s "$response_file" ]; then
    printf 'api response body:\n' >&2
    cat "$response_file" >&2
  fi
  rm -f "$response_file" "$http_code_file"
  exit "$curl_rc"
}

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

release_assets=$(api_request GET "${api_url}/repos/${owner}/${repo}/releases/${release_id}/assets")

upload_asset() {
  asset_path=$1
  asset_name=$(basename "$asset_path")
  asset_name_encoded=$(jq -nr --arg v "$asset_name" '$v|@uri')
  existing_asset_id=$(printf '%s' "$release_assets" \
    | jq -r --arg name "$asset_name" '.[] | select(.name == $name) | .id' \
    | sed -n '1p')
  if [ -n "$existing_asset_id" ]; then
    api_request DELETE "${api_url}/repos/${owner}/${repo}/releases/${release_id}/assets/${existing_asset_id}" >/dev/null
    release_assets=$(api_request GET "${api_url}/repos/${owner}/${repo}/releases/${release_id}/assets")
  fi
  api_request POST "${api_url}/repos/${owner}/${repo}/releases/${release_id}/assets?name=${asset_name_encoded}" \
    --form "attachment=@${asset_path}" >/dev/null
  release_assets=$(api_request GET "${api_url}/repos/${owner}/${repo}/releases/${release_id}/assets")
}

artifact_count=0
checksum_file="$work_dir/sha256sums"
rm -rf "$work_dir"
mkdir -p "$work_dir"
: > "$checksum_file"

for artifact_path in "$@"; do
  [ -f "$artifact_path" ] || {
    echo "release artifact does not exist: $artifact_path" >&2
    exit 1
  }
  asset_name=$(basename "$artifact_path")
  case "$asset_name" in
    centralssh-"$version"-*)
      ;;
    *)
      printf 'release artifact version mismatch: expected prefix centralssh-%s- got %s\n' \
        "$version" "$asset_name" >&2
      exit 1
      ;;
  esac
  sha256sum "$artifact_path" >> "$checksum_file"
  upload_asset "$artifact_path"
  artifact_count=$((artifact_count + 1))
done

upload_asset "$checksum_file"

api_request PATCH "${api_url}/repos/${owner}/${repo}/releases/${release_id}" \
  --header "Content-Type: application/json" \
  --data "$publish_payload" >/dev/null

printf 'published release %s with %s artifacts plus sha256sums\n' "$tag" "$artifact_count"
