#!/bin/sh
set -eu

usage() {
  echo "usage: $0 <version> <amd64|arm64>" >&2
  exit 1
}

version=${1:-}
arch=${2:-}
[ -n "$version" ] || usage
[ -n "$arch" ] || usage

repo_root=${REPO_ROOT:-$PWD}
dist_dir=${DIST_DIR:-"$repo_root/dist"}
work_root=${WORK_ROOT:-"$repo_root/.ci-validate/linux-$arch"}

case "$arch" in
  amd64)
    deb_arch=amd64
    rpm_arch=x86_64
    run_runtime_validation=1
    ;;
  arm64)
    deb_arch=arm64
    rpm_arch=aarch64
    run_runtime_validation=0
    ;;
  *)
    echo "unsupported Linux architecture: $arch" >&2
    exit 1
    ;;
esac

app_name=centralssh
tarball="$dist_dir/${app_name}-${version}-linux-${arch}-systemd.tar.gz"
deb_file="$dist_dir/${app_name}-${version}-debian-${deb_arch}.deb"
rpm_file="$dist_dir/${app_name}-${version}-fedora-${rpm_arch}.rpm"

require_members() {
  archive_listing=$1
  shift
  for member in "$@"; do
    grep -Fxq "$member" "$archive_listing" || {
      echo "archive is missing $member" >&2
      exit 1
    }
  done
}

rm -rf "$work_root"
mkdir -p "$work_root"

test -f "$tarball"
test -f "$deb_file"
test -f "$rpm_file"

tar_listing="$work_root/tar.list"
tar -tzf "$tarball" > "$tar_listing"
require_members "$tar_listing" \
  "centralssh/" \
  "centralssh/Makefile" \
  "centralssh/README.md" \
  "centralssh/op-guide.md" \
  "centralssh/bin/centralssh" \
  "centralssh/bin/cssh-keyscan" \
  "centralssh/examples/config.toml" \
  "centralssh/examples/servers.toml" \
  "centralssh/packaging/systemd/centralssh.service"

dpkg-deb --info "$deb_file" >/dev/null
deb_listing="$work_root/deb.list"
dpkg-deb --contents "$deb_file" > "$deb_listing"
for path in \
  "./usr/local/sbin/centralssh" \
  "./usr/local/bin/cssh-keyscan" \
  "./etc/centralssh/config.toml" \
  "./etc/centralssh/servers.toml" \
  "./etc/centralssh/known_hosts" \
  "./etc/systemd/system/centralssh.service"
do
  grep -Fq " $path" "$deb_listing" || {
    echo "deb package is missing $path" >&2
    exit 1
  }
done

rpm -qip "$rpm_file" >/dev/null
rpm_listing="$work_root/rpm.list"
rpm -qlp "$rpm_file" > "$rpm_listing"
for path in \
  "/usr/local/sbin/centralssh" \
  "/usr/local/bin/cssh-keyscan" \
  "/etc/centralssh/config.toml" \
  "/etc/centralssh/servers.toml" \
  "/etc/centralssh/known_hosts" \
  "/etc/systemd/system/centralssh.service"
do
  grep -Fxq "$path" "$rpm_listing" || {
    echo "rpm package is missing $path" >&2
    exit 1
  }
done

if [ "$run_runtime_validation" -eq 1 ]; then
  extract_root="$work_root/extracted"
  install_root="$work_root/install-root"
  runtime_root="$work_root/runtime"
  mkdir -p "$extract_root" "$install_root" "$runtime_root/etc/centralssh" "$runtime_root/var/lib/centralssh/keys" "$runtime_root/var/log/centralssh"
  tar -C "$extract_root" -xzf "$tarball"
  (
    cd "$extract_root/centralssh"
    make install DESTDIR="$install_root"
  )

  expected_version="$version"
  if [ -n "${CENTRALSSH_DIST_BUILD:-}" ] || [ -n "${CI:-}" ]; then
    expected_version="${version}-dist"
  fi
  for flag in --version -v; do
    version_output=$("$install_root/usr/local/sbin/centralssh" "$flag")
    [ "$version_output" = "centralssh $expected_version" ] || {
      printf 'unexpected %s output: %s\n' "$flag" "$version_output" >&2
      exit 1
    }
  done

  cat > "$runtime_root/etc/centralssh/config.toml" <<EOF
[[users]]
name = "ci"
password = "ValidBootstrapPassword-123!"
must_change_password = true
allowed_servers = ["loopback"]

[settings]
user_key_root = "$runtime_root/var/lib/centralssh/keys"
known_hosts_path = "$runtime_root/etc/centralssh/known_hosts"
audit_log_path = "$runtime_root/var/log/centralssh/audit.jsonl"
per_user_per_server = true
EOF
  cat > "$runtime_root/etc/centralssh/servers.toml" <<EOF
[servers]
loopback = "127.0.0.1"
EOF
  : > "$runtime_root/etc/centralssh/known_hosts"
  : > "$runtime_root/var/log/centralssh/audit.jsonl"
  chmod 700 "$runtime_root/etc/centralssh" "$runtime_root/var/lib/centralssh/keys" "$runtime_root/var/log/centralssh"
  chmod 600 \
    "$runtime_root/etc/centralssh/config.toml" \
    "$runtime_root/etc/centralssh/servers.toml" \
    "$runtime_root/etc/centralssh/known_hosts" \
    "$runtime_root/var/log/centralssh/audit.jsonl"

  listen_addr=127.0.0.1:47788
  runtime_log="$work_root/runtime.log"
  "$install_root/usr/local/sbin/centralssh" \
    --listen "$listen_addr" \
    --config "$runtime_root/etc/centralssh/config.toml" \
    --servers "$runtime_root/etc/centralssh/servers.toml" \
    --known-hosts "$runtime_root/etc/centralssh/known_hosts" \
    --user-key-root "$runtime_root/var/lib/centralssh/keys" \
    --audit-log "$runtime_root/var/log/centralssh/audit.jsonl" \
    >"$runtime_log" 2>&1 &
  daemon_pid=$!
  trap 'kill "$daemon_pid" 2>/dev/null || true' EXIT INT TERM

  ready=0
  i=0
  while [ "$i" -lt 20 ]; do
    if nc -z 127.0.0.1 47788 >/dev/null 2>&1; then
      ready=1
      break
    fi
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      break
    fi
    sleep 1
    i=$((i + 1))
  done

  if [ "$ready" -ne 1 ]; then
    cat "$runtime_log" >&2 || true
    echo "linux runtime validation did not observe CentralSSH listening on $listen_addr" >&2
    exit 1
  fi

  kill "$daemon_pid"
  wait "$daemon_pid" || true
  trap - EXIT INT TERM

  if command -v systemd-analyze >/dev/null 2>&1; then
    if systemd-analyze --help 2>/dev/null | grep -q -- '--root='; then
      systemd-analyze verify --root="$install_root" /etc/systemd/system/centralssh.service >/dev/null
    fi
  fi
fi
