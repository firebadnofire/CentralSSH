#!/bin/sh
set -eu
umask 022

token=${GH_KEY:-}
api_url=${GITHUB_MIRROR_API_URL:-https://api.github.com}
owner=${GITHUB_MIRROR_OWNER:-firebadnofire}
repo=${GITHUB_MIRROR_REPO:-centralssh}
repo_root=${REPO_ROOT:-$PWD}

[ -n "$token" ] || {
  echo "missing GH_KEY for GitHub mirror sync" >&2
  exit 1
}
command -v curl >/dev/null 2>&1 || {
  echo "curl is required for GitHub mirror sync" >&2
  exit 1
}
command -v git >/dev/null 2>&1 || {
  echo "git is required for GitHub mirror sync" >&2
  exit 1
}
command -v jq >/dev/null 2>&1 || {
  echo "jq is required for GitHub mirror sync" >&2
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

repo_json=$(github_request GET "${api_url}/repos/${owner}/${repo}")
repo_name=$(printf '%s' "$repo_json" | jq -r '.full_name')
[ "$repo_name" != "null" ] || {
  echo "GitHub mirror repository lookup returned no full_name for ${owner}/${repo}" >&2
  exit 1
}

cd "$repo_root"

branch_refspecs=
while IFS=' ' read -r ref_name short_name; do
  short_name=${short_name#origin/}
  [ "$short_name" = "HEAD" ] && continue
  branch_refspecs="${branch_refspecs:+$branch_refspecs }${ref_name}:refs/heads/${short_name}"
done <<EOF
$(git for-each-ref --format='%(refname) %(refname:short)' refs/remotes/origin)
EOF

[ -n "$branch_refspecs" ] || {
  echo "no origin remote branches were found to sync to GitHub" >&2
  exit 1
}

remote_url="https://github.com/${owner}/${repo}.git"
auth_header=$(printf 'x-access-token:%s' "$token" | base64 | tr -d '\n')

log_cmd "git push ${remote_url} <origin branches>"
# shellcheck disable=SC2086
git -c "http.${remote_url}.extraheader=AUTHORIZATION: basic ${auth_header}" \
  push "$remote_url" $branch_refspecs
log_cmd "git push ${remote_url} refs/tags/*:refs/tags/*"
git -c "http.${remote_url}.extraheader=AUTHORIZATION: basic ${auth_header}" \
  push "$remote_url" "refs/tags/*:refs/tags/*"

printf 'synced origin branches and tags to GitHub mirror %s/%s\n' "$owner" "$repo"
