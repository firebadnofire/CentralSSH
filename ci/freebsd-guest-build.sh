#!/bin/sh
set -eu

CURRENT_GUEST_STEP=initializing

set_step() {
  CURRENT_GUEST_STEP=$1
  echo "==> guest: ${CURRENT_GUEST_STEP}"
}

dump_failure_context() {
  exit_code=$?
  if [ "$exit_code" -eq 0 ]; then
    return 0
  fi

  echo "FreeBSD guest build failed during '${CURRENT_GUEST_STEP}' with exit code ${exit_code}" >&2
  sudo service centralssh onestatus >/dev/null 2>&1 || true
  sudo tail -n 200 /var/log/messages >&2 || true
  sockstat -4 -l >&2 || true
  pkg info >/dev/null 2>&1 && pkg info centralssh >&2 || true
  exit "$exit_code"
}
trap dump_failure_context EXIT INT TERM

set_step "preparing workspace"
cd "$HOME/work"

export CARGO_HOME="$HOME/cache/cargo"
export CARGO_TARGET_DIR="$HOME/cache/target"
export PKG_CACHEDIR="$HOME/cache/pkg"
mkdir -p "$CARGO_HOME" "$CARGO_TARGET_DIR" "$PKG_CACHEDIR"

test -f /var/tmp/centralssh-cloudinit-ready
test ! -f /var/tmp/centralssh-cloudinit-failed

set_step "installing build dependencies"
sudo mkdir -p "$PKG_CACHEDIR"
sudo pkg -o PKG_CACHEDIR="$PKG_CACHEDIR" update -f
sudo pkg -o PKG_CACHEDIR="$PKG_CACHEDIR" install -y ca_root_nss git gmake jq rust sudo xz zstd
command -v cargo >/dev/null 2>&1
command -v rustc >/dev/null 2>&1
command -v gmake >/dev/null 2>&1

set_step "building release binary"
cargo fetch --locked
cargo build --locked --release

set_step "deriving package metadata"
eval "$(./ci/package-env.sh export)"
CI_PACKAGE_SUFFIX=${FREEBSD_PACKAGE_SUFFIX:-freebsd-amd64}
CI_PACKAGE_ARCH=$(pkg config ABI)

set_step "staging FreeBSD package tree"
rm -rf stage dist
mkdir -p stage dist
gmake install DESTDIR="$PWD/stage" PREFIX=/usr/local

find "stage" -type f | sed 's|^stage/||' | LC_ALL=C sort > stage/pkg-plist
find "stage" -type d -empty | sed 's|^stage/||' | LC_ALL=C sort -r | sed 's|^|@dir /|' >> stage/pkg-plist

cat > stage/+MANIFEST <<EOF
name: ${CI_PACKAGE_NAME}
version: "${CI_PACKAGE_VERSION}"
origin: ${CI_PACKAGE_ORIGIN}
comment: "${CI_PACKAGE_COMMENT}"
maintainer: ${CI_PACKAGE_MAINTAINER}
www: ${CI_PACKAGE_WWW}
prefix: /
arch: ${CI_PACKAGE_ARCH}
desc: |
  ${CI_PACKAGE_DESC}
EOF

set_step "creating FreeBSD package artifacts"
pkg create -M stage/+MANIFEST -p stage/pkg-plist -r stage -o dist
PKG_FILE=$(find dist -type f -name '*.pkg' | head -n1)
[ -n "$PKG_FILE" ] || {
  echo "pkg create did not produce an artifact" >&2
  exit 1
}

FINAL_PKG_FILE="dist/${CI_PACKAGE_NAME}-${CI_PACKAGE_VERSION}-${CI_PACKAGE_SUFFIX}.pkg"
mv "$PKG_FILE" "$FINAL_PKG_FILE"
tar -C stage -czf "dist/${CI_PACKAGE_NAME}-${CI_PACKAGE_VERSION}-${CI_PACKAGE_SUFFIX}.tar.gz" .
./ci/write-sha256sums.sh "dist/SHA256SUMS-freebsd.txt" dist

set_step "validating FreeBSD package contents"
test -f "$FINAL_PKG_FILE"
pkg info -F "$FINAL_PKG_FILE" >/dev/null
tar -tf "$FINAL_PKG_FILE" | grep -Fx "usr/local/sbin/${CI_PACKAGE_NAME}" >/dev/null
tar -tf "$FINAL_PKG_FILE" | grep -Fx "usr/local/bin/cssh-keyscan" >/dev/null
tar -tf "$FINAL_PKG_FILE" | grep -Fx "usr/local/etc/rc.d/${CI_PACKAGE_NAME}" >/dev/null
tar -tf "$FINAL_PKG_FILE" | grep -Fx "etc/centralssh/config.toml" >/dev/null
tar -tf "$FINAL_PKG_FILE" | grep -Fx "etc/centralssh/servers.toml" >/dev/null
tar -tf "$FINAL_PKG_FILE" | grep -Fx "etc/centralssh/known_hosts" >/dev/null
tar -tf "$FINAL_PKG_FILE" | grep -Fx "var/log/centralssh/audit.jsonl" >/dev/null
tar -tzf "dist/${CI_PACKAGE_NAME}-${CI_PACKAGE_VERSION}-${CI_PACKAGE_SUFFIX}.tar.gz" | grep -Fx "./usr/local/sbin/${CI_PACKAGE_NAME}" >/dev/null

set_step "installing FreeBSD package for runtime validation"
sudo pkg delete -fy "${CI_PACKAGE_NAME}" >/dev/null 2>&1 || true
sudo pkg add -f "$FINAL_PKG_FILE"
pkg info "${CI_PACKAGE_NAME}" >/dev/null
test -x "/usr/local/sbin/${CI_PACKAGE_NAME}"
test -x "/usr/local/bin/cssh-keyscan"
test -x "/usr/local/etc/rc.d/${CI_PACKAGE_NAME}"
test -f /etc/centralssh/config.toml
test -f /etc/centralssh/servers.toml
test -f /etc/centralssh/known_hosts
test -f /var/log/centralssh/audit.jsonl
"/usr/local/sbin/${CI_PACKAGE_NAME}" --help >/dev/null

set_step "preparing service runtime files"
sudo install -d -m 0700 /etc/centralssh /etc/centralssh/users /var/lib/centralssh/keys /var/log/centralssh
cat > /tmp/centralssh-config.toml <<EOF
[[users]]
name = "ci"
password = "TemporaryCiPassw0rd!"
must_change_password = true
allowed_servers = ["loopback"]
EOF
cat > /tmp/centralssh-servers.toml <<EOF
[servers]
loopback = "127.0.0.1"
EOF
sudo install -m 0600 /tmp/centralssh-config.toml /etc/centralssh/config.toml
sudo install -m 0600 /tmp/centralssh-servers.toml /etc/centralssh/servers.toml
sudo install -m 0600 /dev/null /etc/centralssh/known_hosts
sudo install -m 0600 /dev/null /var/log/centralssh/audit.jsonl

set_step "validating rc.d service lifecycle"
sudo sysrc centralssh_enable=YES
sudo service centralssh start
sudo service centralssh status
sockstat -4 -l | grep -F ':7788' >/dev/null
sudo service centralssh stop

set_step "completed successfully"
