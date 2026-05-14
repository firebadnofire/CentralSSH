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

repository=${FORGEJO_REPOSITORY:-${GITHUB_REPOSITORY:-}}
tag=${FORGEJO_REF_NAME:-${GITHUB_REF_NAME:-}}
api_url=${FORGEJO_API_URL:-${GITHUB_API_URL:-}}
token=${FORGEJO_TOKEN:-${GITHUB_TOKEN:-}}
repo_root=${REPO_ROOT:-$PWD}

release_env=$(sh "$repo_root/ci/release-version.sh") || exit $?
eval "$release_env"
release_version=${RELEASE_VERSION:?Missing validated release version}
release_tag=${RELEASE_TAG:-}

[ -n "$repository" ] || {
  echo "missing repository name for release staging" >&2
  exit 1
}
[ -n "$tag" ] || {
  echo "missing tag name for release staging" >&2
  exit 1
}
[ "$tag" = "$release_tag" ] || {
  printf 'release staging tag mismatch: env_tag=%s validated_tag=%s\n' "$tag" "$release_tag" >&2
  exit 1
}
[ -n "$api_url" ] || {
  echo "missing Forgejo API URL for release staging" >&2
  exit 1
}
[ -n "$token" ] || {
  echo "missing Forgejo token for release staging" >&2
  exit 1
}

owner=${repository%%/*}
repo=${repository#*/}
release_name="CentralSSH ${tag}"
release_body="Automated CentralSSH draft release for ${tag}. Artifacts are staged here until all package jobs pass."

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

release_payload=$(jq -n \
  --arg tag "$tag" \
  --arg name "$release_name" \
  --arg body "$release_body" \
  '{tag_name: $tag, name: $name, body: $body, draft: true, prerelease: false, hide_archive_links: false}')

release_json=$(api_request GET "${api_url}/repos/${owner}/${repo}/releases" \
  | jq -c --arg tag "$tag" 'map(select(.tag_name == $tag)) | first // empty')

if [ -z "$release_json" ]; then
  if release_json=$(api_request POST "${api_url}/repos/${owner}/${repo}/releases" \
      --header "Content-Type: application/json" \
      --data "$release_payload"); then
    :
  else
    release_json=$(api_request GET "${api_url}/repos/${owner}/${repo}/releases" \
      | jq -c --arg tag "$tag" 'map(select(.tag_name == $tag)) | first // empty')
  fi
else
  release_id=$(printf '%s' "$release_json" | jq -r '.id')
  [ -n "$release_id" ] && [ "$release_id" != "null" ] || {
    echo "failed to resolve existing release id for $tag" >&2
    exit 1
  }
  release_json=$(api_request PATCH "${api_url}/repos/${owner}/${repo}/releases/${release_id}" \
    --header "Content-Type: application/json" \
    --data "$release_payload")
fi

release_id=$(printf '%s' "$release_json" | jq -r '.id')
[ -n "$release_id" ] && [ "$release_id" != "null" ] || {
  echo "failed to resolve release id for $tag" >&2
  exit 1
}

upload_asset() {
  asset_path=$1
  asset_name=$(basename "$asset_path")
  asset_name_encoded=$(jq -nr --arg v "$asset_name" '$v|@uri')
  existing_asset_id=$(api_request GET "${api_url}/repos/${owner}/${repo}/releases/${release_id}/assets" \
    | jq -r --arg name "$asset_name" '.[] | select(.name == $name) | .id' \
    | sed -n '1p')
  if [ -n "$existing_asset_id" ]; then
    api_request DELETE "${api_url}/repos/${owner}/${repo}/releases/${release_id}/assets/${existing_asset_id}" >/dev/null
  fi
  api_request POST "${api_url}/repos/${owner}/${repo}/releases/${release_id}/assets?name=${asset_name_encoded}" \
    --form "attachment=@${asset_path}" >/dev/null
}

for artifact_path in "$@"; do
  [ -f "$artifact_path" ] || {
    echo "release artifact does not exist: $artifact_path" >&2
    exit 1
  }
  asset_name=$(basename "$artifact_path")
  case "$asset_name" in
    centralssh-"$release_version"-*)
      ;;
    *)
      printf 'release artifact version mismatch: expected prefix centralssh-%s- got %s\n' \
        "$release_version" "$asset_name" >&2
      exit 1
      ;;
  esac
  upload_asset "$artifact_path"
done

printf 'staged %s release artifacts on draft release %s using version %s\n' \
  "$job_name" "$tag" "$release_version"
