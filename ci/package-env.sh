#!/bin/sh
set -eu

mode=${1:-env}

package_name=$(sed -n 's/^name = "\(.*\)"/\1/p' Cargo.toml | head -n1)
package_version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
package_comment=$(sed -n 's/^description = "\(.*\)"/\1/p' Cargo.toml | head -n1)
repo_path=${FORGEJO_REPOSITORY:-${GITHUB_REPOSITORY:-}}
server_url=${FORGEJO_SERVER_URL:-${GITHUB_SERVER_URL:-}}
tag_name=${FORGEJO_REF_NAME:-${GITHUB_REF_NAME:-}}

repo_url=
if [ -n "$repo_path" ] && [ -n "$server_url" ]; then
  repo_url="${server_url%/}/${repo_path}"
fi

emit_env() {
  cat <<EOF
CI_PACKAGE_NAME=${package_name}
CI_PACKAGE_VERSION=${package_version}
CI_PACKAGE_COMMENT=${package_comment}
CI_PACKAGE_ORIGIN=security/${package_name}
CI_PACKAGE_WWW=${repo_url}
CI_PACKAGE_MAINTAINER=root@localhost
CI_PACKAGE_DESC=${package_comment}
CI_RELEASE_TAG=${tag_name}
EOF
}

emit_export() {
  cat <<EOF
export CI_PACKAGE_NAME='${package_name}'
export CI_PACKAGE_VERSION='${package_version}'
export CI_PACKAGE_COMMENT='${package_comment}'
export CI_PACKAGE_ORIGIN='security/${package_name}'
export CI_PACKAGE_WWW='${repo_url}'
export CI_PACKAGE_MAINTAINER='root@localhost'
export CI_PACKAGE_DESC='${package_comment}'
export CI_RELEASE_TAG='${tag_name}'
EOF
}

case "$mode" in
  env)
    emit_env
    ;;
  export)
    emit_export
    ;;
  *)
    echo "usage: $0 [env|export]" >&2
    exit 1
    ;;
esac
