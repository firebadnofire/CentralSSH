#!/bin/sh
set -eu

dist_dir=${1:-dist}
api_url=${FORGEJO_API_URL:-${GITHUB_API_URL:-https://api.github.com}}
repository=${FORGEJO_REPOSITORY:-${GITHUB_REPOSITORY:-}}
token=${FORGEJO_TOKEN:-${GITHUB_TOKEN:-}}
release_tag=${CI_RELEASE_TAG:-${FORGEJO_REF_NAME:-${GITHUB_REF_NAME:-${GITHUB_REF#refs/tags/}}}}

if [ -z "$api_url" ] || [ -z "$repository" ] || [ -z "$token" ] || [ -z "$release_tag" ]; then
  echo "Missing release API context." >&2
  exit 1
fi

if [ ! -d "$dist_dir" ]; then
  echo "Missing dist directory: $dist_dir" >&2
  exit 1
fi

auth_header="Authorization: token ${token}"
release_json=$(curl -fsS -H "$auth_header" \
  "${api_url%/}/repos/${repository}/releases/tags/${release_tag}" 2>/dev/null || true)

if [ -z "$release_json" ]; then
  create_payload=$(jq -n --arg tag "$release_tag" --arg name "$release_tag" \
    '{tag_name:$tag,name:$name,draft:false,prerelease:false}')
  release_json=$(curl -fsS -X POST -H "$auth_header" -H 'Content-Type: application/json' \
    -d "$create_payload" "${api_url%/}/repos/${repository}/releases")
fi

release_id=$(printf '%s' "$release_json" | jq -r '.id')
if [ -z "$release_id" ] || [ "$release_id" = "null" ]; then
  echo "Failed to resolve release id." >&2
  exit 1
fi

for asset_path in "$dist_dir"/*; do
  [ -f "$asset_path" ] || continue
  asset_name=$(basename "$asset_path")
  existing_id=$(printf '%s' "$release_json" | jq -r --arg n "$asset_name" \
    '.assets[]? | select(.name == $n) | .id' 2>/dev/null | head -n1)
  if [ -n "$existing_id" ] && [ "$existing_id" != "null" ]; then
    curl -fsS -X DELETE -H "$auth_header" \
      "${api_url%/}/repos/${repository}/releases/${release_id}/assets/${existing_id}" >/dev/null
  fi

  curl -fsS -X POST \
    -H "$auth_header" \
    -H 'Content-Type: application/octet-stream' \
    --data-binary @"$asset_path" \
    "${api_url%/}/repos/${repository}/releases/${release_id}/assets?name=${asset_name}" >/dev/null
done
