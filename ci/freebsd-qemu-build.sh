#!/bin/sh
set -eu

usage() {
  echo "usage: $0 <prepare-image|build> [amd64|aarch64]" >&2
  exit 1
}

command_name=${1:-}
[ -n "$command_name" ] || usage
FREEBSD_ARCH=${FREEBSD_ARCH:-${2:-amd64}}
CURRENT_STEP=initializing
CLOUDINIT_SSH_READY_FILE=/var/tmp/centralssh-sshd-ready
CLOUDINIT_READY_FILE=/var/tmp/centralssh-cloudinit-ready
CLOUDINIT_FAILED_FILE=/var/tmp/centralssh-cloudinit-failed

set_step() {
  CURRENT_STEP=$1
  echo "==> ${CURRENT_STEP}" >&2
}

ensure_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

sanitize() {
  printf '%s' "$1" | tr '[:upper:]/:' '[:lower:]--' | tr -cs 'a-z0-9._-' '-'
}

resolve_arch_settings() {
  case "$FREEBSD_ARCH" in
    amd64)
      FREEBSD_IMAGE_SOURCE_FILENAME="FreeBSD-15.0-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz"
      FREEBSD_IMAGE_URL=${FREEBSD_IMAGE_URL:-https://download.freebsd.org/releases/VM-IMAGES/15.0-RELEASE/amd64/Latest/${FREEBSD_IMAGE_SOURCE_FILENAME}}
      FREEBSD_CHECKSUM_URL=${FREEBSD_CHECKSUM_URL:-https://download.freebsd.org/releases/VM-IMAGES/15.0-RELEASE/amd64/Latest/CHECKSUM.SHA512}
      FREEBSD_QEMU_SYSTEM="qemu-system-x86_64"
      FREEBSD_PACKAGE_SUFFIX="freebsd-amd64"
      ;;
    aarch64)
      FREEBSD_IMAGE_SOURCE_FILENAME="FreeBSD-15.0-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-ufs.qcow2.xz"
      FREEBSD_IMAGE_URL=${FREEBSD_IMAGE_URL:-https://download.freebsd.org/releases/VM-IMAGES/15.0-RELEASE/aarch64/Latest/${FREEBSD_IMAGE_SOURCE_FILENAME}}
      FREEBSD_CHECKSUM_URL=${FREEBSD_CHECKSUM_URL:-https://download.freebsd.org/releases/VM-IMAGES/15.0-RELEASE/aarch64/Latest/CHECKSUM.SHA512}
      FREEBSD_QEMU_SYSTEM="qemu-system-aarch64"
      FREEBSD_PACKAGE_SUFFIX="freebsd-aarch64"
      ;;
    *)
      echo "unsupported FreeBSD architecture: ${FREEBSD_ARCH}" >&2
      exit 1
      ;;
  esac
}

init_paths() {
  REPO_ROOT=${REPO_ROOT:-$PWD}
  FREEBSD_VERSION=15.0
  resolve_arch_settings
  FREEBSD_QEMU_MEM=${FREEBSD_QEMU_MEM:-4096}
  FREEBSD_QEMU_CPUS=${FREEBSD_QEMU_CPUS:-4}
  SSH_USER=${FREEBSD_VM_USER:-ci}
  SSH_HOST=127.0.0.1

  SHARED_CACHE_TOP=$(./ci/select-cache-root.sh /build-cache "$REPO_ROOT/.ci-host-cache")
  CACHE_FINGERPRINT=$(cat "$REPO_ROOT/Cargo.lock" "$REPO_ROOT/Cargo.toml" "$REPO_ROOT/Makefile" 2>/dev/null | sha256sum | cut -c1-16)
  FREEBSD_CACHE_ROOT="${SHARED_CACHE_TOP}/freebsd/centralssh/${CACHE_FINGERPRINT}"
  IMAGE_ROOT="${SHARED_CACHE_TOP}/freebsd/images"
  WORKDIR="${REPO_ROOT}/.ci-qemu/freebsd"
  CACHE_STAGE="${REPO_ROOT}/.ci-cache/freebsd"
  CACHE_EXPORT_STAGE="${REPO_ROOT}/.ci-cache/freebsd-out"
  DIST_DIR="${REPO_ROOT}/dist"
  IMAGE_XZ="${IMAGE_ROOT}/freebsd-${FREEBSD_ARCH}.qcow2.xz"
  BASE_QCOW2="${IMAGE_ROOT}/freebsd-${FREEBSD_ARCH}.qcow2"
  CHECKSUM_FILE="${IMAGE_ROOT}/freebsd-${FREEBSD_ARCH}.CHECKSUM.SHA512"
  OVERLAY_QCOW2="${WORKDIR}/freebsd-overlay.qcow2"
  SEED_DIR="${WORKDIR}/seed"
  SEED_ISO="${WORKDIR}/seed.iso"
  SSH_KEY="${WORKDIR}/id_ed25519"
  SSH_PORT_FILE="${WORKDIR}/ssh-port"
  QEMU_PID_FILE="${WORKDIR}/qemu.pid"
  QEMU_LOG="${WORKDIR}/qemu.log"
  BUILD_SCRIPT="${WORKDIR}/build-freebsd.sh"
  IMAGE_LOCKDIR="${IMAGE_ROOT}/.lock"
  REPO_ARCHIVE="${WORKDIR}/repo.tar.gz"
  CACHE_ARCHIVE="${WORKDIR}/cache.tar.gz"
  REMOTE_HOME="/home/${SSH_USER}"
  SSH_PORT=${FREEBSD_SSH_PORT:-$(awk 'BEGIN{srand(); print 2200 + int(rand()*2000)}')}

  export REPO_ROOT SHARED_CACHE_TOP CACHE_FINGERPRINT FREEBSD_CACHE_ROOT IMAGE_ROOT WORKDIR
  export CACHE_STAGE CACHE_EXPORT_STAGE DIST_DIR IMAGE_XZ BASE_QCOW2 OVERLAY_QCOW2 SEED_DIR
  export SEED_ISO SSH_KEY SSH_PORT_FILE QEMU_PID_FILE QEMU_LOG BUILD_SCRIPT IMAGE_LOCKDIR
  export REPO_ARCHIVE CACHE_ARCHIVE SSH_HOST SSH_PORT SSH_USER REMOTE_HOME
  export FREEBSD_VERSION FREEBSD_ARCH FREEBSD_IMAGE_URL FREEBSD_CHECKSUM_URL
  export FREEBSD_IMAGE_SOURCE_FILENAME FREEBSD_QEMU_MEM FREEBSD_QEMU_CPUS
  export FREEBSD_QEMU_SYSTEM FREEBSD_PACKAGE_SUFFIX CHECKSUM_FILE
}

prepare_dirs() {
  mkdir -p "$IMAGE_ROOT" "$WORKDIR" "$CACHE_STAGE" "$DIST_DIR"
}

acquire_image_lock() {
  while ! mkdir "$IMAGE_LOCKDIR" 2>/dev/null; do
    sleep 2
  done
}

release_image_lock() {
  rmdir "$IMAGE_LOCKDIR" 2>/dev/null || true
}

download_to_file() {
  url=$1
  output=$2
  curl -fsSL "$url" -o "$output"
}

extract_sha512_for_image() {
  checksum_path=$1
  awk -v target="$FREEBSD_IMAGE_SOURCE_FILENAME" '
    $0 ~ ("^SHA512 \\(" target "\\) = ") { print $NF; found = 1; exit }
    $2 == target { print $1; found = 1; exit }
    END { if (!found) exit 1 }
  ' "$checksum_path"
}

verify_image_archive() {
  image_path=$1
  checksum_path=$2
  checksum_value=$(extract_sha512_for_image "$checksum_path") || {
    echo "missing checksum entry for ${FREEBSD_IMAGE_SOURCE_FILENAME}" >&2
    return 1
  }
  checksum_line="${image_path}.sha512"
  printf '%s  %s\n' "$checksum_value" "$image_path" > "$checksum_line"
  if ! sha512sum -c "$checksum_line"; then
    rm -f "$checksum_line"
    return 1
  fi
  rm -f "$checksum_line"
}

refresh_checksum_file() {
  tmp_checksum="${CHECKSUM_FILE}.tmp.$$"
  rm -f "$tmp_checksum"
  download_to_file "$FREEBSD_CHECKSUM_URL" "$tmp_checksum"
  mv "$tmp_checksum" "$CHECKSUM_FILE"
}

redownload_image_archive() {
  tmp_xz="${IMAGE_XZ}.tmp.$$"
  rm -f "$tmp_xz" "$IMAGE_XZ" "$BASE_QCOW2"
  echo "Downloading FreeBSD image: ${FREEBSD_IMAGE_URL}"
  download_to_file "$FREEBSD_IMAGE_URL" "$tmp_xz"
  if ! verify_image_archive "$tmp_xz" "$CHECKSUM_FILE"; then
    rm -f "$tmp_xz"
    echo "FreeBSD image checksum verification failed for ${FREEBSD_ARCH}" >&2
    exit 1
  fi
  mv "$tmp_xz" "$IMAGE_XZ"
}

ensure_verified_image_archive() {
  refresh_checksum_file
  if [ -f "$IMAGE_XZ" ] && verify_image_archive "$IMAGE_XZ" "$CHECKSUM_FILE"; then
    echo "Using cached FreeBSD image archive: ${IMAGE_XZ}"
    return 0
  fi
  rm -f "$IMAGE_XZ" "$BASE_QCOW2"
  redownload_image_archive
}

ensure_base_qcow2() {
  tmp_qcow2="${BASE_QCOW2}.tmp.$$"
  if [ -f "$BASE_QCOW2" ] && qemu-img info "$BASE_QCOW2" >/dev/null 2>&1; then
    echo "Using cached FreeBSD base image: ${BASE_QCOW2}"
    return 0
  fi
  rm -f "$BASE_QCOW2" "$tmp_qcow2"
  xz -dc "$IMAGE_XZ" > "$tmp_qcow2"
  mv "$tmp_qcow2" "$BASE_QCOW2"
  qemu-img info "$BASE_QCOW2" >/dev/null
}

find_aarch64_firmware() {
  for candidate in \
    "${AARCH64_EFI:-}" \
    /usr/share/AAVMF/AAVMF_CODE.fd \
    /usr/share/AAVMF/AAVMF_CODE.ms.fd \
    /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
    /usr/share/edk2/aarch64/QEMU_EFI.fd
  do
    if [ -n "$candidate" ] && [ -f "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  echo "missing aarch64 UEFI firmware; set AARCH64_EFI to a readable firmware image" >&2
  return 1
}

download_base_image() {
  init_paths
  prepare_dirs
  acquire_image_lock
  trap 'rm -f "${IMAGE_XZ}.tmp.$$" "${BASE_QCOW2}.tmp.$$" "${CHECKSUM_FILE}.tmp.$$"; release_image_lock' EXIT INT TERM
  ensure_verified_image_archive
  ensure_base_qcow2
  qemu-img info "$BASE_QCOW2"
}

prepare_seed_iso() {
  mkdir -p "$SEED_DIR"
  pubkey=$(cat "${SSH_KEY}.pub")

  cat > "${SEED_DIR}/user-data" <<EOF
#cloud-config
users:
  - name: ${SSH_USER}
    groups: wheel
    shell: /bin/sh
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ${pubkey}
ssh_pwauth: false
disable_root: false
package_update: false
write_files:
  - path: /var/tmp/centralssh-cloudinit-provision.sh
    permissions: '0700'
    owner: root:wheel
    content: |
      #!/bin/sh
      set -eu
      rm -f "${CLOUDINIT_SSH_READY_FILE}" "${CLOUDINIT_READY_FILE}" "${CLOUDINIT_FAILED_FILE}"
      trap 'rc=\$?; if [ "\$rc" -ne 0 ]; then echo "\$rc" > "${CLOUDINIT_FAILED_FILE}"; fi; exit "\$rc"' EXIT
      sysrc sshd_enable=YES
      service sshd start || service sshd restart
      touch "${CLOUDINIT_SSH_READY_FILE}"
      pkg bootstrap -yf
      pkg install -y sudo ca_root_nss
      touch "${CLOUDINIT_READY_FILE}"
runcmd:
  - /var/tmp/centralssh-cloudinit-provision.sh
EOF

  cat > "${SEED_DIR}/meta-data" <<EOF
instance-id: centralssh-ci
local-hostname: centralssh-freebsd-ci
EOF

  rm -f "$SEED_ISO"
  if command -v cloud-localds >/dev/null 2>&1; then
    cloud-localds "$SEED_ISO" "${SEED_DIR}/user-data" "${SEED_DIR}/meta-data"
  elif command -v genisoimage >/dev/null 2>&1; then
    genisoimage -output "$SEED_ISO" -volid cidata -joliet -rock "${SEED_DIR}/user-data" "${SEED_DIR}/meta-data" >/dev/null 2>&1
  elif command -v xorriso >/dev/null 2>&1; then
    xorriso -as mkisofs -output "$SEED_ISO" -volid cidata -joliet -rock "${SEED_DIR}/user-data" "${SEED_DIR}/meta-data" >/dev/null 2>&1
  else
    echo "no ISO creation tool available" >&2
    exit 1
  fi
}

prepare_ssh_key() {
  rm -f "$SSH_KEY" "${SSH_KEY}.pub"
  ssh-keygen -t ed25519 -N "" -f "$SSH_KEY" >/dev/null
  printf '%s\n' "$SSH_PORT" > "$SSH_PORT_FILE"
}

run_ssh() {
  ssh -i "$SSH_KEY" \
    -p "$SSH_PORT" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes \
    -o BatchMode=yes \
    -o ConnectTimeout=5 \
    "${SSH_USER}@${SSH_HOST}" "$@"
}

wait_for_ssh() {
  i=1
  while [ "$i" -le 180 ]; do
    if run_ssh "test -f '${CLOUDINIT_SSH_READY_FILE}' && echo ready" >/dev/null 2>&1; then
      echo "SSH is ready on port ${SSH_PORT}"
      return 0
    fi
    if run_ssh "test -f '${CLOUDINIT_FAILED_FILE}'" >/dev/null 2>&1; then
      echo "FreeBSD cloud-init provisioning failed; readiness marker was not created" >&2
      return 1
    fi
    sleep 2
    i=$((i + 1))
  done
  echo "Timed out waiting for FreeBSD SSH" >&2
  tail -n 200 "$QEMU_LOG" >&2 || true
  return 1
}

wait_for_guest_provisioning() {
  i=1
  while [ "$i" -le 300 ]; do
    if run_ssh "test -f '${CLOUDINIT_READY_FILE}' && test ! -f '${CLOUDINIT_FAILED_FILE}' && command -v sudo >/dev/null 2>&1 && command -v pkg >/dev/null 2>&1 && echo ready" >/dev/null 2>&1; then
      echo "Guest provisioning completed"
      return 0
    fi
    if run_ssh "test -f '${CLOUDINIT_FAILED_FILE}'" >/dev/null 2>&1; then
      echo "FreeBSD cloud-init provisioning failed after SSH became available" >&2
      return 1
    fi
    sleep 2
    i=$((i + 1))
  done
  echo "Timed out waiting for FreeBSD guest provisioning to finish" >&2
  return 1
}

guest_debug_available() {
  run_ssh 'echo guest-debug-ready' >/dev/null 2>&1
}

dump_guest_debug() {
  if ! guest_debug_available; then
    echo "---- guest debug unavailable (SSH not reachable) ----" >&2
    return 0
  fi

  echo "---- guest process state ----" >&2
  run_ssh 'ps auxww' >&2 || true
  echo "---- guest pkg state ----" >&2
  run_ssh "pkg -vv || sudo pkg -vv" >&2 || true
  echo "---- guest cloud-init markers ----" >&2
  run_ssh "ls -l '${CLOUDINIT_SSH_READY_FILE}' '${CLOUDINIT_READY_FILE}' '${CLOUDINIT_FAILED_FILE}' 2>/dev/null || true" >&2 || true
  echo "---- guest cloud-init.log ----" >&2
  run_ssh "sudo tail -n 200 /var/log/cloud-init.log" >&2 || true
  echo "---- guest cloud-init-output.log ----" >&2
  run_ssh "sudo tail -n 200 /var/log/cloud-init-output.log" >&2 || true
  echo "---- guest messages ----" >&2
  run_ssh "sudo tail -n 200 /var/log/messages" >&2 || true
}

dump_debug() {
  echo "---- host failure context ----" >&2
  echo "last host step: ${CURRENT_STEP}" >&2
  echo "freebsd arch: ${FREEBSD_ARCH}" >&2
  echo "ssh endpoint: ${SSH_USER}@${SSH_HOST}:${SSH_PORT}" >&2
  echo "---- qemu-img info ----" >&2
  qemu-img info "$OVERLAY_QCOW2" >&2 || true
  echo "---- cache usage ----" >&2
  du -sh "$FREEBSD_CACHE_ROOT" "$CACHE_STAGE" "$CACHE_EXPORT_STAGE" 2>/dev/null >&2 || true
  echo "---- qemu log tail ----" >&2
  tail -n 200 "$QEMU_LOG" >&2 || true
  dump_guest_debug
}

shutdown_vm() {
  if [ -f "$QEMU_PID_FILE" ]; then
    qemu_pid=$(cat "$QEMU_PID_FILE" 2>/dev/null || true)
    if [ -n "${qemu_pid:-}" ] && kill -0 "$qemu_pid" 2>/dev/null; then
      run_ssh 'sudo shutdown -p now' >/dev/null 2>&1 || true
      sleep 5
      kill "$qemu_pid" 2>/dev/null || true
      sleep 2
      kill -9 "$qemu_pid" 2>/dev/null || true
    fi
  fi
}

cleanup() {
  exit_code=$?
  if [ "$exit_code" -ne 0 ]; then
    echo "FreeBSD CI step failed during '${CURRENT_STEP}' with exit code ${exit_code}; cleanup is now running" >&2
  fi
  shutdown_vm
  release_image_lock
  if [ "$exit_code" -ne 0 ]; then
    dump_debug
  fi
  exit "$exit_code"
}

create_guest_build_script() {
  repo_path=${FORGEJO_REPOSITORY:-${GITHUB_REPOSITORY:-centralssh/centralssh}}
  server_url=${FORGEJO_SERVER_URL:-${GITHUB_SERVER_URL:-https://github.com}}
  repo_url="${server_url%/}/${repo_path}"

  cat > "$BUILD_SCRIPT" <<EOF
#!/bin/sh
set -eu

cd "\$HOME/work"

export CARGO_HOME="\$HOME/cache/cargo"
export RUSTUP_HOME="\$HOME/cache/rustup"
export CARGO_TARGET_DIR="\$HOME/cache/target"
export SCCACHE_DIR="\$HOME/cache/sccache"
export PKG_CACHEDIR="\$HOME/cache/pkg"
mkdir -p "\$CARGO_HOME" "\$RUSTUP_HOME" "\$CARGO_TARGET_DIR" "\$SCCACHE_DIR" "\$PKG_CACHEDIR"

test -f "${CLOUDINIT_READY_FILE}"
test ! -f "${CLOUDINIT_FAILED_FILE}"
sudo mkdir -p "\$PKG_CACHEDIR"
sudo pkg -o PKG_CACHEDIR="\$PKG_CACHEDIR" update -f
sudo pkg -o PKG_CACHEDIR="\$PKG_CACHEDIR" install -y curl git gmake jq pkg xz zstd ca_root_nss sudo

if [ ! -x "\$CARGO_HOME/bin/rustc" ]; then
  fetch -q -o /tmp/rustup.sh https://sh.rustup.rs
  sh /tmp/rustup.sh -y --no-modify-path --default-toolchain stable
fi

. "\$CARGO_HOME/env"
export PATH="\$CARGO_HOME/bin:\$PATH"

if [ ! -x "\$CARGO_HOME/bin/sccache" ]; then
  cargo install --locked sccache || echo "warning: failed to install sccache; continuing without compiler cache" >&2
fi

if [ -x "\$CARGO_HOME/bin/sccache" ]; then
  export RUSTC_WRAPPER="\$CARGO_HOME/bin/sccache"
fi

cargo fetch --locked
sccache --show-stats || true
cargo build --locked --release
sccache --show-stats || true

CI_PACKAGE_NAME="\$(sed -n 's/^name = \"\\(.*\\)\"/\\1/p' Cargo.toml | head -n1)"
CI_PACKAGE_VERSION="\$(sed -n 's/^version = \"\\(.*\\)\"/\\1/p' Cargo.toml | head -n1)"
CI_PACKAGE_COMMENT="\$(sed -n 's/^description = \"\\(.*\\)\"/\\1/p' Cargo.toml | head -n1)"
CI_PACKAGE_DESC="\${CI_PACKAGE_COMMENT}"
CI_PACKAGE_ORIGIN="security/\${CI_PACKAGE_NAME}"
CI_PACKAGE_MAINTAINER="root@localhost"
CI_PACKAGE_WWW="${repo_url}"
CI_PACKAGE_ARCH="\$(pkg config ABI)"
CI_PACKAGE_SUFFIX="${FREEBSD_PACKAGE_SUFFIX}"
CI_TARBALL_NAME="\${CI_PACKAGE_NAME}-\${CI_PACKAGE_VERSION}-\${CI_PACKAGE_SUFFIX}.tar.gz"
CI_PKG_NAME="\${CI_PACKAGE_NAME}-\${CI_PACKAGE_VERSION}-\${CI_PACKAGE_SUFFIX}.pkg"

rm -rf stage dist archive
mkdir -p stage dist archive

gmake install DESTDIR="\$PWD/stage" PREFIX=/usr/local

mkdir -p "\$PWD/stage/etc/centralssh/users"
mkdir -p "\$PWD/stage/var/log/centralssh"

cp examples/config.toml "\$PWD/stage/etc/centralssh/config.toml"
cp examples/servers.toml "\$PWD/stage/etc/centralssh/servers.toml"
touch "\$PWD/stage/etc/centralssh/known_hosts"
touch "\$PWD/stage/var/log/centralssh/audit.jsonl"

chmod 0700 "\$PWD/stage/etc/centralssh/users"
chmod 0700 "\$PWD/stage/var/log/centralssh"

find "stage" -type f | sed 's|^stage/||' | LC_ALL=C sort > stage/pkg-plist
find "stage" -type d -empty | sed 's|^stage/||' | LC_ALL=C sort -r | sed 's|^|@dir |' >> stage/pkg-plist

cat > stage/+MANIFEST <<MANIFEST
name: \${CI_PACKAGE_NAME}
version: "\${CI_PACKAGE_VERSION}"
origin: \${CI_PACKAGE_ORIGIN}
comment: "\${CI_PACKAGE_COMMENT}"
maintainer: \${CI_PACKAGE_MAINTAINER}
www: \${CI_PACKAGE_WWW}
prefix: /
arch: \${CI_PACKAGE_ARCH}
desc: |
  \${CI_PACKAGE_DESC}
MANIFEST

if ! pkg create -M stage/+MANIFEST -p stage/pkg-plist -r stage -o dist; then
  echo "pkg create failed" >&2
  exit 1
fi

PKG_FILE="\$(find dist -type f -name '*.pkg' | head -n1)"
cp "\$PKG_FILE" "dist/\${CI_PKG_NAME}"
test -f "dist/\${CI_PKG_NAME}"
pkg info -F "dist/\${CI_PKG_NAME}" >/dev/null

mkdir -p archive/\${CI_PACKAGE_NAME}
tar -C stage -cf - . | tar -C archive/\${CI_PACKAGE_NAME} -xf -
tar -C archive -czf "dist/\${CI_TARBALL_NAME}" "\${CI_PACKAGE_NAME}"
test -f "dist/\${CI_TARBALL_NAME}"
tar -tzf "dist/\${CI_TARBALL_NAME}" >/dev/null

sudo pkg add -f "dist/\${CI_PKG_NAME}"
sudo install -d -m 0700 /etc/centralssh /var/lib/centralssh/keys /var/log/centralssh
sudo sh -c "cat > /etc/centralssh/config.toml" <<RUNTIMECFG
[[users]]
name = "ci"
password = "ValidBootstrapPassword-123!"
must_change_password = true
allowed_servers = ["loopback"]

[settings]
user_key_root = "/var/lib/centralssh/keys"
per_user_per_server = true
known_hosts_path = "/etc/centralssh/known_hosts"
audit_log_path = "/var/log/centralssh/audit.jsonl"
RUNTIMECFG
sudo sh -c "cat > /etc/centralssh/servers.toml" <<RUNTIMESRV
[servers]
loopback = "127.0.0.1"
RUNTIMESRV
sudo touch /etc/centralssh/known_hosts /var/log/centralssh/audit.jsonl
sudo chmod 0600 /etc/centralssh/config.toml /etc/centralssh/servers.toml /etc/centralssh/known_hosts /var/log/centralssh/audit.jsonl
sudo sysrc centralssh_enable=YES >/dev/null
sudo sysrc centralssh_listen=127.0.0.1:47789 >/dev/null
sudo service centralssh start
sudo service centralssh status
sudo service centralssh stop
EOF

  chmod +x "$BUILD_SCRIPT"
}

boot_vm_amd64() {
  if [ -e /dev/kvm ]; then
    accel_args="-enable-kvm -cpu host"
  else
    accel_args="-accel tcg"
  fi

  # shellcheck disable=SC2086
  qemu-system-x86_64 \
    $accel_args \
    -m "$FREEBSD_QEMU_MEM" \
    -smp "$FREEBSD_QEMU_CPUS" \
    -drive file="$OVERLAY_QCOW2",if=virtio,format=qcow2 \
    -drive file="$SEED_ISO",if=virtio,media=cdrom,readonly=on,format=raw \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
    -device virtio-net-pci,netdev=net0 \
    -nographic \
    -serial mon:stdio \
    -pidfile "$QEMU_PID_FILE" \
    > "$QEMU_LOG" 2>&1 &
}

boot_vm_aarch64() {
  firmware_path=$(find_aarch64_firmware)
  qemu-system-aarch64 \
    -accel tcg \
    -machine virt \
    -cpu cortex-a72 \
    -m "$FREEBSD_QEMU_MEM" \
    -smp "$FREEBSD_QEMU_CPUS" \
    -bios "$firmware_path" \
    -drive file="$OVERLAY_QCOW2",if=virtio,format=qcow2 \
    -drive file="$SEED_ISO",if=virtio,media=cdrom,readonly=on,format=raw \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
    -device virtio-net-pci,netdev=net0 \
    -nographic \
    -serial mon:stdio \
    -pidfile "$QEMU_PID_FILE" \
    > "$QEMU_LOG" 2>&1 &
}

boot_vm() {
  rm -rf "$WORKDIR"
  mkdir -p "$WORKDIR"
  prepare_ssh_key
  prepare_seed_iso

  qemu-img create -f qcow2 -F qcow2 -b "$BASE_QCOW2" "$OVERLAY_QCOW2" >/dev/null
  qemu-img info "$OVERLAY_QCOW2"

  case "$FREEBSD_ARCH" in
    amd64) boot_vm_amd64 ;;
    aarch64) boot_vm_aarch64 ;;
    *) usage ;;
  esac

  sleep 2
  [ -f "$QEMU_PID_FILE" ] || {
    echo "QEMU pidfile was not created" >&2
    dump_debug
    exit 1
  }
}

transfer_repo() {
  rm -rf "$DIST_DIR"
  mkdir -p "$DIST_DIR"
  tar \
    --exclude='.git' \
    --exclude='.ci-cache' \
    --exclude='.ci-host-cache' \
    --exclude='.ci-qemu' \
    --exclude='target' \
    --exclude='dist' \
    -czf "$REPO_ARCHIVE" .
  cat "$REPO_ARCHIVE" | run_ssh "rm -rf ${REMOTE_HOME}/work && mkdir -p ${REMOTE_HOME}/work && tar -xzf - -C ${REMOTE_HOME}/work"
}

transfer_cache_in() {
  if [ -d "$FREEBSD_CACHE_ROOT" ]; then
    tar -C "$FREEBSD_CACHE_ROOT" -czf "$CACHE_ARCHIVE" .
    cat "$CACHE_ARCHIVE" | run_ssh "mkdir -p ${REMOTE_HOME}/cache && tar -xzf - -C ${REMOTE_HOME}/cache"
  else
    run_ssh "mkdir -p ${REMOTE_HOME}/cache"
  fi
}

run_build() {
  set_step "uploading guest build script"
  cat "$BUILD_SCRIPT" | run_ssh "cat > ${REMOTE_HOME}/build-freebsd.sh && chmod +x ${REMOTE_HOME}/build-freebsd.sh"
  set_step "executing guest build script"
  if run_ssh "sh ${REMOTE_HOME}/build-freebsd.sh"; then
    return 0
  else
    build_exit_code=$?
  fi
  echo "Guest build script failed with exit code ${build_exit_code}; cleanup is now running" >&2
  return "$build_exit_code"
}

download_outputs() {
  set_step "downloading build artifacts"
  mkdir -p "$DIST_DIR"
  run_ssh "tar -C ${REMOTE_HOME}/work/dist -czf - ." | tar -C "$DIST_DIR" -xzf -
  test -n "$(find "$DIST_DIR" -maxdepth 1 -type f -name "*-${FREEBSD_PACKAGE_SUFFIX}.pkg" -print -quit)"

  set_step "exporting guest cache"
  rm -rf "$CACHE_EXPORT_STAGE"
  mkdir -p "$CACHE_EXPORT_STAGE"
  run_ssh "tar -C ${REMOTE_HOME}/cache -czf - ." | tar -C "$CACHE_EXPORT_STAGE" -xzf -
}

store_cache_back() {
  set_step "storing cache back to host"
  tmp_root="${FREEBSD_CACHE_ROOT}.tmp"
  rm -rf "$tmp_root"
  mkdir -p "$tmp_root"
  cp -a "$CACHE_EXPORT_STAGE"/. "$tmp_root"/
  rm -rf "$FREEBSD_CACHE_ROOT"
  mv "$tmp_root" "$FREEBSD_CACHE_ROOT"
}

case "$command_name" in
  prepare-image)
    ensure_command curl
    ensure_command sha512sum
    ensure_command qemu-img
    ensure_command xz
    init_paths
    download_base_image
    ;;
  build)
    init_paths
    ensure_command curl
    ensure_command git
    ensure_command qemu-img
    ensure_command "$FREEBSD_QEMU_SYSTEM"
    ensure_command ssh
    ensure_command ssh-keygen
    ensure_command sha512sum
    ensure_command tar
    ensure_command xz
    prepare_dirs
    download_base_image
    trap cleanup EXIT INT TERM
    set_step "booting FreeBSD VM"
    boot_vm
    set_step "waiting for SSH readiness"
    wait_for_ssh
    set_step "waiting for guest provisioning"
    wait_for_guest_provisioning
    set_step "generating guest build script"
    create_guest_build_script
    set_step "transferring repository"
    transfer_repo
    set_step "transferring cache into guest"
    transfer_cache_in
    run_build
    download_outputs
    store_cache_back
    ;;
  *)
    usage
    ;;
esac
