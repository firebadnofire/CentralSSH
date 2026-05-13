#!/bin/sh
set -eu

usage() {
  echo "usage: $0 <version> <amd64>" >&2
  exit 1
}

version=${1:-}
arch=${2:-}
[ -n "$version" ] || usage
[ -n "$arch" ] || usage
[ "$arch" = "amd64" ] || {
  echo "unsupported native FreeBSD architecture: $arch" >&2
  exit 1
}

repo_root=${REPO_ROOT:-$PWD}
dist_dir=${DIST_DIR:-"$repo_root/dist"}
work_root=${WORK_ROOT:-"$repo_root/.ci-packaging/freebsd-$arch"}
cache_root=$(./ci/select-cache-root.sh /build-cache "$repo_root/.ci-host-cache")
sudo_cmd=
if [ "$(id -u)" -ne 0 ]; then
  sudo_cmd=sudo
fi

eval "$(./ci/cache-env.sh freebsd-native release x86_64-unknown-freebsd "$cache_root")"
export PATH="${CARGO_HOME}/bin:$PATH"

app_name=centralssh
pkg_suffix=freebsd-amd64
pkg_file="$dist_dir/${app_name}-${version}-${pkg_suffix}.pkg"
tarball="$dist_dir/${app_name}-${version}-${pkg_suffix}.tar.gz"
stage_root="$work_root/stage"
archive_root="$work_root/archive/$app_name"
runtime_root="$work_root/runtime"
manifest_path="$work_root/+MANIFEST"
plist_path="$work_root/pkg-plist"

rm -rf "$work_root"
mkdir -p "$dist_dir" "$stage_root" "$archive_root" "$runtime_root"

cargo fetch --locked
cargo build --locked --release
gmake install DESTDIR="$stage_root" PREFIX=/usr/local

mkdir -p "$stage_root/etc/centralssh/users" "$stage_root/var/log/centralssh"
touch "$stage_root/etc/centralssh/known_hosts" "$stage_root/var/log/centralssh/audit.jsonl"
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
arch: $(pkg config ABI)
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

$sudo_cmd pkg add -f "$pkg_file"
trap '$sudo_cmd env centralssh_enable=YES centralssh_config="$runtime_etc/config.toml" centralssh_servers="$runtime_etc/servers.toml" centralssh_known_hosts="$runtime_etc/known_hosts" centralssh_user_key_root="$runtime_keys" centralssh_audit_log="$runtime_log/audit.jsonl" centralssh_listen=127.0.0.1:47789 service centralssh onestop >/dev/null 2>&1 || true' EXIT INT TERM
$sudo_cmd env \
  centralssh_enable=YES \
  centralssh_config="$runtime_etc/config.toml" \
  centralssh_servers="$runtime_etc/servers.toml" \
  centralssh_known_hosts="$runtime_etc/known_hosts" \
  centralssh_user_key_root="$runtime_keys" \
  centralssh_audit_log="$runtime_log/audit.jsonl" \
  centralssh_listen=127.0.0.1:47789 \
  service centralssh onestart
$sudo_cmd env \
  centralssh_enable=YES \
  centralssh_config="$runtime_etc/config.toml" \
  centralssh_servers="$runtime_etc/servers.toml" \
  centralssh_known_hosts="$runtime_etc/known_hosts" \
  centralssh_user_key_root="$runtime_keys" \
  centralssh_audit_log="$runtime_log/audit.jsonl" \
  centralssh_listen=127.0.0.1:47789 \
  service centralssh onestatus
$sudo_cmd env \
  centralssh_enable=YES \
  centralssh_config="$runtime_etc/config.toml" \
  centralssh_servers="$runtime_etc/servers.toml" \
  centralssh_known_hosts="$runtime_etc/known_hosts" \
  centralssh_user_key_root="$runtime_keys" \
  centralssh_audit_log="$runtime_log/audit.jsonl" \
  centralssh_listen=127.0.0.1:47789 \
  service centralssh onestop
trap - EXIT INT TERM

printf '%s\n%s\n' "$pkg_file" "$tarball"
