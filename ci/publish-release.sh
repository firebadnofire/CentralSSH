#!/bin/sh
set -eu
umask 022

repository=${FORGEJO_REPOSITORY:-${GITHUB_REPOSITORY:-}}
tag=${FORGEJO_REF_NAME:-${GITHUB_REF_NAME:-}}
api_url=${FORGEJO_API_URL:-${GITHUB_API_URL:-}}
token=${FORGEJO_TOKEN:-${GITHUB_TOKEN:-}}
work_dir=${RELEASE_WORK_DIR:-${RUNNER_TEMP:-/tmp}/centralssh-release-publish}
repo_root=${REPO_ROOT:-$PWD}

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
command -v curl >/dev/null 2>&1 || {
  echo "curl is required for release publication" >&2
  exit 1
}
command -v jq >/dev/null 2>&1 || {
  echo "jq is required for release publication" >&2
  exit 1
}
command -v sha256sum >/dev/null 2>&1 || {
  echo "sha256sum is required for release publication" >&2
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
printf 'release publication: tag=%s version=%s\n' "$tag" "$version"

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

log_cmd() {
  printf '+ %s\n' "$*" >&2
}

api_request() {
  method=$1
  url=$2
  shift 2
  response_file=$(mktemp)
  http_code_file=$(mktemp)
  log_cmd "curl --fail-with-body --silent --show-error --request $method $url"
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

release_name="CentralSSH ${tag}"
release_body="Automated CentralSSH release for ${tag}. See sha256sums for checksums."
public_payload=$(jq -n \
  --arg tag "$tag" \
  --arg name "$release_name" \
  --arg body "$release_body" \
  '{tag_name: $tag, name: $name, body: $body, draft: false, prerelease: false, hide_archive_links: false}')

release_list=$(api_request GET "${api_url}/repos/${owner}/${repo}/releases")
release_json=$(printf '%s' "$release_list" \
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

refresh_release_assets() {
  api_request GET "${api_url}/repos/${owner}/${repo}/releases/${release_id}/assets" > "$release_assets"
}

log_release_assets() {
  printf 'release asset inventory for %s (release_id=%s):\n' "$tag" "$release_id" >&2
  jq -r '.[] | "  - \(.name) id=\(.id) uuid=\(.uuid) size=\(.size)"' "$release_assets" >&2
}

preflight_expected_assets() {
  missing_count=0
  while IFS= read -r asset_name; do
    asset_json=$(require_release_asset "$asset_name")
    if [ -z "$asset_json" ]; then
      printf 'missing expected release asset: %s\n' "$asset_name" >&2
      missing_count=$((missing_count + 1))
    fi
  done < "$expected_file"

  if [ "$missing_count" -ne 0 ]; then
    printf 'expected release asset list:\n' >&2
    sed 's/^/  - /' "$expected_file" >&2
    log_release_assets
    exit 1
  fi
}

download_asset_via_api() {
  asset_uuid=$1
  asset_name=$2
  output_path=$3

  attachment_base=${api_url%/api/v1}
  attachment_url="${attachment_base}/attachments/${asset_uuid}"
  log_cmd "curl --fail --silent --show-error --location ${attachment_url} (attachment download)"
  curl --fail --silent --show-error --location \
    --header "Authorization: token ${token}" \
    --header "Accept: application/octet-stream" \
    --output "$output_path" \
    "$attachment_url"
}

require_release_asset() {
  asset_name=$1
  jq -c --arg name "$asset_name" '.[] | select(.name == $name) | {id, uuid, name, size}' "$release_assets" | sed -n '1p'
}

download_asset() {
  asset_name=$1
  asset_json=$(require_release_asset "$asset_name")
  [ -n "$asset_json" ] || {
    echo "missing staged release asset: $asset_name" >&2
    log_release_assets
    exit 1
  }

  asset_id=$(printf '%s' "$asset_json" | jq -r '.id')
  asset_uuid=$(printf '%s' "$asset_json" | jq -r '.uuid')
  expected_size=$(printf '%s' "$asset_json" | jq -r '.size')
  output_path="$dist_dir/$asset_name"
  [ -n "$asset_id" ] && [ "$asset_id" != "null" ] || {
    echo "missing staged release asset id: $asset_name" >&2
    log_release_assets
    exit 1
  }
  [ -n "$asset_uuid" ] && [ "$asset_uuid" != "null" ] || {
    echo "missing staged release asset uuid: $asset_name" >&2
    log_release_assets
    exit 1
  }
  [ -n "$expected_size" ] && [ "$expected_size" != "null" ] || {
    echo "missing staged release size metadata: $asset_name" >&2
    log_release_assets
    exit 1
  }

  download_asset_via_api "$asset_uuid" "$asset_name" "$output_path"

  actual_size=$(wc -c < "$output_path" | tr -d ' ')
  if [ "$actual_size" != "$expected_size" ]; then
    printf 'downloaded asset size mismatch for %s: expected=%s actual=%s; refreshing asset metadata and retrying once\n' \
      "$asset_name" "$expected_size" "$actual_size" >&2
    rm -f "$output_path"
    refresh_release_assets
    asset_json=$(require_release_asset "$asset_name")
    [ -n "$asset_json" ] || {
      echo "missing staged release asset after refresh: $asset_name" >&2
      log_release_assets
      exit 1
    }
    asset_id=$(printf '%s' "$asset_json" | jq -r '.id')
    asset_uuid=$(printf '%s' "$asset_json" | jq -r '.uuid')
    expected_size=$(printf '%s' "$asset_json" | jq -r '.size')
    [ -n "$asset_id" ] && [ "$asset_id" != "null" ] || {
      echo "missing staged release asset id after refresh: $asset_name" >&2
      log_release_assets
      exit 1
    }
    [ -n "$asset_uuid" ] && [ "$asset_uuid" != "null" ] || {
      echo "missing staged release asset uuid after refresh: $asset_name" >&2
      log_release_assets
      exit 1
    }
    [ -n "$expected_size" ] && [ "$expected_size" != "null" ] || {
      echo "missing staged release size metadata after refresh: $asset_name" >&2
      log_release_assets
      exit 1
    }
    download_asset_via_api "$asset_uuid" "$asset_name" "$output_path"
    actual_size=$(wc -c < "$output_path" | tr -d ' ')
    [ "$actual_size" = "$expected_size" ] || {
      printf 'downloaded asset size mismatch for %s after retry: expected=%s actual=%s asset_uuid=%s\n' \
        "$asset_name" "$expected_size" "$actual_size" "$asset_uuid" >&2
      exit 1
    }
  fi

  printf '%s\n' "$dist_dir/$asset_name" >> "$assets_file"
}

: > "$assets_file"
log_release_assets
printf 'expected release assets for %s:\n' "$tag" >&2
sed 's/^/  - /' "$expected_file" >&2
preflight_expected_assets
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
