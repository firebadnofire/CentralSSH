#!/bin/sh
set -eu

job_name=${1:?usage: cache-env.sh <job-name> <profile> <target-triple> <cache-root>}
build_profile=${2:?usage: cache-env.sh <job-name> <profile> <target-triple> <cache-root>}
target_triple=${3:?usage: cache-env.sh <job-name> <profile> <target-triple> <cache-root>}
cache_root=${4:?usage: cache-env.sh <job-name> <profile> <target-triple> <cache-root>}
fallback_root=${CI_CACHE_FALLBACK_ROOT:-$PWD/.ci-cache}

hash_stream() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print substr($1, 1, 16)}'
  elif command -v sha256 >/dev/null 2>&1; then
    sha256 -q | cut -c1-16
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print substr($1, 1, 16)}'
  else
    cksum | awk '{print $1}'
  fi
}

sanitize() {
  printf '%s' "$1" | tr '[:upper:]/:' '[:lower:]--' | tr -cs 'a-z0-9._-' '-'
}

ensure_writable_root() {
  candidate_root=$1
  mkdir -p "$candidate_root" 2>/dev/null || return 1
  probe_path="${candidate_root}/.cache-write-probe.$$"
  if : >"$probe_path" 2>/dev/null; then
    rm -f "$probe_path"
    return 0
  fi
  return 1
}

if [ ! -f Cargo.lock ] || [ ! -f Cargo.toml ]; then
  echo "cache-env.sh requires Cargo.lock and Cargo.toml in the working directory" >&2
  exit 1
fi

repo_path=${FORGEJO_REPOSITORY:-${GITHUB_REPOSITORY:-$(basename "$PWD")}}
repo_slug=$(sanitize "$repo_path")
os_name=$(sanitize "$(uname -s)")
arch_name=$(sanitize "$(uname -m)")
rustc_version=$(rustc --version | awk '{print $2}')
cargo_version=$(cargo --version | awk '{print $2}')
feature_flags=${CI_CARGO_FEATURES:-default}
cross_compile=${CI_CROSS_COMPILE:-0}
rustflags_value=${RUSTFLAGS:-}

input_hash=$(
  {
    printf 'Cargo.lock\0'
    cat Cargo.lock
    printf 'Cargo.toml\0'
    cat Cargo.toml
    if [ -f Makefile ]; then
      printf 'Makefile\0'
      cat Makefile
    fi
  } | hash_stream
)

env_hash=$(
  {
    printf 'target=%s\0' "$target_triple"
    printf 'profile=%s\0' "$build_profile"
    printf 'rustc=%s\0' "$rustc_version"
    printf 'cargo=%s\0' "$cargo_version"
    printf 'features=%s\0' "$feature_flags"
    printf 'cross=%s\0' "$cross_compile"
    printf 'rustflags=%s\0' "$rustflags_value"
  } | hash_stream
)

if ensure_writable_root "$cache_root"; then
  actual_cache_root=$cache_root
else
  mkdir -p "$fallback_root"
  if ensure_writable_root "$fallback_root"; then
    actual_cache_root=$fallback_root
  else
    echo "no writable cache root available: preferred=${cache_root} fallback=${fallback_root}" >&2
    exit 1
  fi
fi

cache_key=$(sanitize "${os_name}-${arch_name}-${rustc_version}-${target_triple}-${build_profile}-${input_hash}-${env_hash}")
cargo_home="${actual_cache_root}/cargo-home"
sccache_dir="${actual_cache_root}/sccache/${repo_slug}/${job_name}/${cache_key}"
target_dir="${actual_cache_root}/target/${repo_slug}/${job_name}/${cache_key}"

mkdir -p "${cargo_home}/bin" "$sccache_dir" "$target_dir"

cat <<EOF
export CI_CACHE_KEY='${cache_key}'
export CI_CACHE_ROOT='${actual_cache_root}'
export CARGO_HOME='${cargo_home}'
export SCCACHE_DIR='${sccache_dir}'
export CARGO_TARGET_DIR='${target_dir}'
EOF
