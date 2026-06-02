#!/bin/sh
set -eu

usage() {
  echo "usage: $0 <version> <amd64|aarch64>" >&2
  exit 1
}

version=${1:-}
arch=${2:-}
[ -n "$version" ] || usage
[ -n "$arch" ] || usage
if [ -n "${RELEASE_VERSION:-}" ] && [ "$version" != "$RELEASE_VERSION" ]; then
  printf 'release version mismatch: arg=%s env=%s\n' "$version" "$RELEASE_VERSION" >&2
  exit 1
fi
version=${RELEASE_VERSION:-$version}

repo_root=${REPO_ROOT:-$PWD}
tmp_root=${TMPDIR:-/tmp}
dist_dir=${DIST_DIR:-"$repo_root/dist"}
work_root=${WORK_ROOT:-"$repo_root/.ci-packaging/freebsd-$arch"}
cache_root=$(./ci/select-cache-root.sh /build-cache "$repo_root/.ci-host-cache")
host_pkg_abi=$(pkg config ABI)
runner_cargo_home=${HOME}/.cargo
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}
export PATH
privileged_runtime=0
sudo_cmd=
freebsd_release_name=${FREEBSD_RELEASE_NAME:-${FREEBSD_RELEASE:-}}

if [ "$(id -u)" -eq 0 ]; then
  privileged_runtime=1
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
  sudo_cmd="sudo -n"
  privileged_runtime=1
fi

if [ -z "$freebsd_release_name" ]; then
  if command -v freebsd-version >/dev/null 2>&1; then
    freebsd_release_name=$(freebsd-version -u 2>/dev/null || freebsd-version 2>/dev/null || true)
  fi
fi
if [ -z "$freebsd_release_name" ]; then
  freebsd_release_name=$(uname -r 2>/dev/null || true)
fi
freebsd_release_slug=$(printf '%s' "$freebsd_release_name" | sed 's/[^A-Za-z0-9._-]/-/g')
[ -n "$freebsd_release_slug" ] || {
  echo "missing FreeBSD release name for artifact naming" >&2
  exit 1
}

case "$arch" in
  amd64)
    target_triple=x86_64-unknown-freebsd
    pkg_suffix=freebsd-${freebsd_release_slug}-amd64
    pkg_arch=$host_pkg_abi
    runtime_validation=1
    cargo_toolchain=
    cargo_build_std=
    ;;
  aarch64)
    target_triple=aarch64-unknown-freebsd
    pkg_suffix=freebsd-${freebsd_release_slug}-aarch64
    pkg_arch=$(printf '%s\n' "$host_pkg_abi" | awk -F: 'BEGIN { OFS=":" } { $NF = "aarch64"; print }')
    runtime_validation=0
    cargo_toolchain=+nightly
    cargo_build_std=-Zbuild-std=std,panic_abort
    ;;
  *)
    echo "unsupported native FreeBSD architecture: $arch" >&2
    exit 1
    ;;
esac

eval "$(./ci/cache-env.sh freebsd-native release "$target_triple" "$cache_root")"
if [ "$arch" = "aarch64" ] && [ -x "$runner_cargo_home/bin/rustup" ]; then
  CARGO_HOME=$runner_cargo_home
fi
export PATH="${CARGO_HOME}/bin:$PATH"

app_name=centralssh
pkg_file="$dist_dir/${app_name}-${version}-${pkg_suffix}.pkg"
tarball="$dist_dir/${app_name}-${version}-${pkg_suffix}.tar.gz"
stage_root="$work_root/stage"
archive_root="$work_root/archive/$app_name"
runtime_root=${RUNTIME_ROOT:-"$tmp_root/centralssh-runtime-$arch"}
manifest_path="$work_root/+MANIFEST"
plist_path="$work_root/pkg-plist"

if [ -e "$work_root" ]; then
  if ! rm -rf "$work_root" 2>/dev/null; then
    $sudo_cmd rm -rf "$work_root"
  fi
fi
if [ -e "$runtime_root" ]; then
  if ! rm -rf "$runtime_root" 2>/dev/null; then
    $sudo_cmd rm -rf "$runtime_root"
  fi
fi
cleanup_runtime_root() {
  if [ -e "$runtime_root" ]; then
    if ! rm -rf "$runtime_root" 2>/dev/null; then
      $sudo_cmd rm -rf "$runtime_root" >/dev/null 2>&1 || true
    fi
  fi
}
trap cleanup_runtime_root EXIT INT TERM
mkdir -p "$dist_dir" "$stage_root" "$archive_root" "$runtime_root"

if [ "$arch" = "aarch64" ]; then
  rustup toolchain install nightly --profile minimal
  rustup component add rust-src --toolchain nightly
  export CARGO_TARGET_AARCH64_UNKNOWN_FREEBSD_LINKER=/usr/local/freebsd-sysroot/aarch64/bin/cc
  export CARGO_TARGET_AARCH64_UNKNOWN_FREEBSD_AR=/usr/bin/llvm-ar
  export CARGO_TARGET_AARCH64_UNKNOWN_FREEBSD_RANLIB=/usr/bin/llvm-ranlib
else
  rustup target add "$target_triple"
fi

cargo ${cargo_toolchain:+$cargo_toolchain} fetch --locked
cargo ${cargo_toolchain:+$cargo_toolchain} build ${cargo_build_std:+$cargo_build_std} --locked --release --target "$target_triple"

install -d "$stage_root/usr/local/sbin"
install -m 0755 "$CARGO_TARGET_DIR/$target_triple/release/centralssh" "$stage_root/usr/local/sbin/centralssh"
install -d "$stage_root/usr/local/bin"
install -m 0755 "$repo_root/tools/cssh-keyscan" "$stage_root/usr/local/bin/cssh-keyscan"
install -d -m 0700 "$stage_root/etc/centralssh/users"
install -d -m 0700 "$stage_root/var/log/centralssh"
install -d -m 0700 "$stage_root/etc/centralssh"
install -m 0600 "$repo_root/examples/config.toml" "$stage_root/etc/centralssh/config.toml"
install -m 0600 "$repo_root/examples/servers.toml" "$stage_root/etc/centralssh/servers.toml"
if [ ! -f "$stage_root/etc/centralssh/known_hosts" ]; then
  install -m 0600 /dev/null "$stage_root/etc/centralssh/known_hosts"
fi
if [ ! -f "$stage_root/var/log/centralssh/audit.jsonl" ]; then
  install -m 0600 /dev/null "$stage_root/var/log/centralssh/audit.jsonl"
fi
install -d "$stage_root/usr/local/etc/rc.d"
install -m 0555 "$repo_root/packaging/freebsd/centralssh" "$stage_root/usr/local/etc/rc.d/centralssh"

chmod 0700 "$stage_root/etc/centralssh/users" "$stage_root/var/log/centralssh"

find "$stage_root" -type f | sed "s|^$stage_root/||" | LC_ALL=C sort > "$plist_path"
find "$stage_root" -type d -empty | sed "s|^$stage_root/||" | LC_ALL=C sort -r | sed 's|^|@dir |' >> "$plist_path"

cat > "$manifest_path" <<EOF
name: ${app_name}
version: "${version}"
origin: security/${app_name}
comment: "OpenSSH-compatible hardened SSH gateway"
maintainer: "root@localhost"
www: "https://example.invalid/${app_name}"
prefix: /
arch: ${pkg_arch}
desc: |
  OpenSSH-compatible hardened SSH gateway
EOF

pkg create -M "$manifest_path" -p "$plist_path" -r "$stage_root" -o "$dist_dir"
raw_pkg=$(find "$dist_dir" -maxdepth 1 -type f -name '*.pkg' ! -name "$(basename "$pkg_file")" | head -n1)
[ -n "$raw_pkg" ] || {
  echo "pkg create did not produce a package" >&2
  exit 1
}
cp "$raw_pkg" "$pkg_file"
pkg info -F "$pkg_file" >/dev/null

mkdir -p "$archive_root"
tar -C "$stage_root" -cf - . | tar -C "$archive_root" -xf -
tar -C "$work_root/archive" -czf "$tarball" "$app_name"
tar -tzf "$tarball" >/dev/null

runtime_etc="$runtime_root/etc-centralssh"
runtime_log="$runtime_root/var-log-centralssh"
runtime_keys="$runtime_root/var-lib-centralssh-keys"
rc_script="/usr/local/etc/rc.d/centralssh"
mkdir -p "$runtime_etc" "$runtime_log" "$runtime_keys"
cat > "$runtime_etc/config.toml" <<EOF
[[users]]
name = "ci"
password = "ValidBootstrapPassword-123!"
must_change_password = true
allowed_servers = ["loopback"]

[settings]
user_key_root = "$runtime_keys"
per_user_per_server = true
known_hosts_path = "$runtime_etc/known_hosts"
audit_log_path = "$runtime_log/audit.jsonl"
EOF
cat > "$runtime_etc/servers.toml" <<EOF
[servers]
loopback = "127.0.0.1"
EOF
touch "$runtime_etc/known_hosts" "$runtime_log/audit.jsonl"
chmod 700 "$runtime_etc" "$runtime_log" "$runtime_keys"
chmod 600 "$runtime_etc/config.toml" "$runtime_etc/servers.toml" "$runtime_etc/known_hosts" "$runtime_log/audit.jsonl"

if [ "$runtime_validation" -eq 1 ] && [ "$privileged_runtime" -eq 1 ]; then
  $sudo_cmd chown -R root:wheel "$runtime_root"
fi

if [ "$runtime_validation" -eq 1 ]; then
  if [ "$privileged_runtime" -eq 1 ]; then
    printf 'runtime validation: pkg_file=%s rc_script=%s runtime_root=%s\n' \
      "$pkg_file" "$rc_script" "$runtime_root" >&2
    $sudo_cmd pkg info -F "$pkg_file" >&2
    $sudo_cmd pkg info -l -F "$pkg_file" | grep '/usr/local/etc/rc.d/centralssh$' >&2 || true
    $sudo_cmd pkg add -f "$pkg_file"
    if [ ! -x "$rc_script" ]; then
      printf 'installed rc script missing or not executable: %s\n' "$rc_script" >&2
      $sudo_cmd pkg info centralssh >&2 || true
      $sudo_cmd find /usr/local/etc /usr/local/sbin -maxdepth 3 \( -name centralssh -o -name 'centralssh*' \) -print >&2 || true
      exit 1
    fi
    $sudo_cmd ls -l "$rc_script" >&2
    trap '$sudo_cmd env centralssh_enable=YES centralssh_config="$runtime_etc/config.toml" centralssh_servers="$runtime_etc/servers.toml" centralssh_known_hosts="$runtime_etc/known_hosts" centralssh_user_key_root="$runtime_keys" centralssh_audit_log="$runtime_log/audit.jsonl" centralssh_listen=127.0.0.1:47789 "$rc_script" onestop >/dev/null 2>&1 || true; cleanup_runtime_root' EXIT INT TERM
    printf 'runtime validation: starting rc service\n' >&2
    $sudo_cmd env \
      centralssh_enable=YES \
      centralssh_config="$runtime_etc/config.toml" \
      centralssh_servers="$runtime_etc/servers.toml" \
      centralssh_known_hosts="$runtime_etc/known_hosts" \
      centralssh_user_key_root="$runtime_keys" \
      centralssh_audit_log="$runtime_log/audit.jsonl" \
      centralssh_listen=127.0.0.1:47789 \
      "$rc_script" onestart
    printf 'runtime validation: checking rc status\n' >&2
    $sudo_cmd env \
      centralssh_enable=YES \
      centralssh_config="$runtime_etc/config.toml" \
      centralssh_servers="$runtime_etc/servers.toml" \
      centralssh_known_hosts="$runtime_etc/known_hosts" \
      centralssh_user_key_root="$runtime_keys" \
      centralssh_audit_log="$runtime_log/audit.jsonl" \
      centralssh_listen=127.0.0.1:47789 \
      "$rc_script" onestatus
    printf 'runtime validation: stopping rc service\n' >&2
    $sudo_cmd env \
      centralssh_enable=YES \
      centralssh_config="$runtime_etc/config.toml" \
      centralssh_servers="$runtime_etc/servers.toml" \
      centralssh_known_hosts="$runtime_etc/known_hosts" \
      centralssh_user_key_root="$runtime_keys" \
      centralssh_audit_log="$runtime_log/audit.jsonl" \
      centralssh_listen=127.0.0.1:47789 \
      "$rc_script" onestop || {
        stop_rc=$?
        printf 'runtime validation warning: rc stop returned %s\n' "$stop_rc" >&2
        $sudo_cmd cat /var/run/centralssh.pid >&2 || true
        $sudo_cmd pgrep -fl '/usr/local/sbin/centralssh' >&2 || true
      }
    trap cleanup_runtime_root EXIT INT TERM
  else
    echo "Skipping privileged FreeBSD amd64 runtime validation because non-interactive root access is unavailable" >&2
  fi
else
  echo "Skipping runtime validation for cross-compiled FreeBSD ${arch} artifact" >&2
fi

printf '%s\n%s\n' "$pkg_file" "$tarball"
