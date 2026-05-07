#!/bin/sh
set -eu

E2E_LIB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
E2E_REPO_ROOT=$(CDPATH= cd -- "$E2E_LIB_DIR/../.." && pwd)

: "${CENTRALSSH_JUMP_HOST:=192.168.86.89}"
: "${CENTRALSSH_HOST:=192.168.122.141}"
: "${CENTRALSSH_GATEWAY:=192.168.122.151}"
: "${CENTRALSSH_GATEWAY_PORT:=7788}"
: "${CENTRALSSH_JUMP_USER:=cgpt}"
: "${CENTRALSSH_JUMP_KEY:=/Users/william/.ssh/cgpt/cgpt}"
: "${CENTRALSSH_JAIL_USER:=cgpt}"
: "${CENTRALSSH_JAIL_NAME:=myjail2}"
: "${CENTRALSSH_HOST_BUILD_REPO:=/home/cgpt/centralssh-test-host}"
: "${CENTRALSSH_REMOTE_REPO:=/home/cgpt/centralssh-test}"
: "${CENTRALSSH_REMOTE_LAB_ROOT:=/tmp/centralssh-qa}"
: "${CENTRALSSH_ARTIFACT_ROOT:=$E2E_LIB_DIR/artifacts}"
: "${CENTRALSSH_CASE_TIMEOUT:=90}"

timestamp_utc() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

log() {
  printf '%s %s\n' "$(timestamp_utc)" "$*" >&2
}

fail() {
  log "ERROR: $*"
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

require_env() {
  eval "value=\${$1-}"
  [ -n "$value" ] || fail "missing environment variable: $1"
}

host_proxy_command() {
  printf 'ssh -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=2 -J %s %s@%s -W %%h:%%p' \
    "$CENTRALSSH_JUMP_KEY" \
    "$CENTRALSSH_JUMP_HOST" \
    "$CENTRALSSH_JUMP_USER" \
    "$CENTRALSSH_HOST"
}

gateway_proxy_command() {
  printf 'ssh -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=2 -J %s %s@%s -W %%h:%%p' \
    "$CENTRALSSH_JUMP_KEY" \
    "$CENTRALSSH_JUMP_HOST" \
    "$CENTRALSSH_JUMP_USER" \
    "$CENTRALSSH_HOST"
}

host_ssh() {
  ssh -i "$CENTRALSSH_JUMP_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=2 -J "$CENTRALSSH_JUMP_HOST" \
    "$CENTRALSSH_JUMP_USER@$CENTRALSSH_HOST" "$@"
}

jail_ssh() {
  if [ "${CENTRALSSH_RUNTIME_TIER:-jail}" = "host" ]; then
    host_ssh "$@"
    return
  fi
  ssh -i "$CENTRALSSH_JUMP_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=2 -o "ProxyCommand=$(host_proxy_command)" \
    "$CENTRALSSH_JAIL_USER@$CENTRALSSH_GATEWAY" "$@"
}

jail_scp_to() {
  src=$1
  dest=$2
  if [ "${CENTRALSSH_RUNTIME_TIER:-jail}" = "host" ]; then
    scp -O -i "$CENTRALSSH_JUMP_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=2 -J "$CENTRALSSH_JUMP_HOST" "$src" \
      "$CENTRALSSH_JUMP_USER@$CENTRALSSH_HOST:$dest"
    return
  fi
  scp -O -i "$CENTRALSSH_JUMP_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=2 -o "ProxyCommand=$(host_proxy_command)" "$src" \
    "$CENTRALSSH_JAIL_USER@$CENTRALSSH_GATEWAY:$dest"
}

jail_scp_from() {
  src=$1
  dest=$2
  if [ "${CENTRALSSH_RUNTIME_TIER:-jail}" = "host" ]; then
    scp -O -i "$CENTRALSSH_JUMP_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=2 -J "$CENTRALSSH_JUMP_HOST" \
      "$CENTRALSSH_JUMP_USER@$CENTRALSSH_HOST:$src" "$dest"
    return
  fi
  scp -O -i "$CENTRALSSH_JUMP_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=2 -o "ProxyCommand=$(host_proxy_command)" \
    "$CENTRALSSH_JAIL_USER@$CENTRALSSH_GATEWAY:$src" "$dest"
}

json_escape() {
  python3 - <<'PY' "$1"
import json
import sys
print(json.dumps(sys.argv[1]))
PY
}

record_result() {
  stage=$1
  case_name=$2
  status=$3
  detail=${4-}
  detail_json=$(json_escape "$detail")
  printf '{"timestamp":%s,"stage":%s,"case":%s,"status":%s,"detail":%s}\n' \
    "$(json_escape "$(timestamp_utc)")" \
    "$(json_escape "$stage")" \
    "$(json_escape "$case_name")" \
    "$(json_escape "$status")" \
    "$detail_json" >>"$CENTRALSSH_RESULTS_FILE"
}

begin_stage() {
  stage_name=$1
  CENTRALSSH_STAGE_NAME=$stage_name
  CENTRALSSH_STAGE_DIR="$CENTRALSSH_ARTIFACT_DIR/$stage_name"
  mkdir -p "$CENTRALSSH_STAGE_DIR"
  log "BEGIN $stage_name"
}

pass_stage_case() {
  case_name=$1
  detail=${2-}
  record_result "$CENTRALSSH_STAGE_NAME" "$case_name" "pass" "$detail"
}

skip_stage_case() {
  case_name=$1
  detail=${2-}
  record_result "$CENTRALSSH_STAGE_NAME" "$case_name" "skip" "$detail"
}

fail_stage_case() {
  case_name=$1
  detail=${2-}
  record_result "$CENTRALSSH_STAGE_NAME" "$case_name" "fail" "$detail"
  fail "$CENTRALSSH_STAGE_NAME/$case_name: $detail"
}

generated_secret() {
  python3 - <<'PY'
import base64
import secrets
print(base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("="))
PY
}

argon2_hash() {
  password=$1
  salt=$2
  printf '%s' "$password" | argon2 "$salt" -id -e -t 3 -k 65536 -p 1 -l 32
}

totp_code() {
  python3 - <<'PY' "$1"
import base64
import hashlib
import hmac
import struct
import sys
import time

secret = sys.argv[1]
padding = "=" * ((8 - len(secret) % 8) % 8)
key = base64.b32decode(secret + padding, casefold=True)
counter = int(time.time()) // 30
msg = struct.pack(">Q", counter)
digest = hmac.new(key, msg, hashlib.sha1).digest()
offset = digest[-1] & 0x0F
code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
print(f"{code:06d}")
PY
}

write_generated_env() {
  cat >"$CENTRALSSH_GENERATED_ENV_FILE" <<EOF
CENTRALSSH_QA_PROXY_PASSWORD='$CENTRALSSH_QA_PROXY_PASSWORD'
CENTRALSSH_QA_PROXY_TOTP_SECRET='$CENTRALSSH_QA_PROXY_TOTP_SECRET'
CENTRALSSH_QA_CHANGE_BOOTSTRAP_PASSWORD='$CENTRALSSH_QA_CHANGE_BOOTSTRAP_PASSWORD'
CENTRALSSH_QA_CHANGE_NEW_PASSWORD='$CENTRALSSH_QA_CHANGE_NEW_PASSWORD'
CENTRALSSH_QA_ENROLL_PASSWORD='$CENTRALSSH_QA_ENROLL_PASSWORD'
CENTRALSSH_QA_LIMITED_PASSWORD='$CENTRALSSH_QA_LIMITED_PASSWORD'
CENTRALSSH_QA_LIMITED_TOTP_SECRET='$CENTRALSSH_QA_LIMITED_TOTP_SECRET'
CENTRALSSH_QA_MULTI_PASSWORD='$CENTRALSSH_QA_MULTI_PASSWORD'
CENTRALSSH_QA_MULTI_TOTP_SECRET='$CENTRALSSH_QA_MULTI_TOTP_SECRET'
CENTRALSSH_QA_OTHER_PASSWORD='$CENTRALSSH_QA_OTHER_PASSWORD'
EOF
}

ensure_generated_credentials() {
  if [ -f "$CENTRALSSH_GENERATED_ENV_FILE" ] && [ "${CENTRALSSH_REUSE_GENERATED_CREDS:-true}" = "true" ]; then
    # shellcheck disable=SC1090
    . "$CENTRALSSH_GENERATED_ENV_FILE"
    return
  fi

  CENTRALSSH_QA_PROXY_PASSWORD=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 18)
  CENTRALSSH_QA_PROXY_TOTP_SECRET=$(generated_secret)
  CENTRALSSH_QA_CHANGE_BOOTSTRAP_PASSWORD=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 18)
  CENTRALSSH_QA_CHANGE_NEW_PASSWORD="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 18)!Z9"
  CENTRALSSH_QA_ENROLL_PASSWORD=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 18)
  CENTRALSSH_QA_LIMITED_PASSWORD=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 18)
  CENTRALSSH_QA_LIMITED_TOTP_SECRET=$(generated_secret)
  CENTRALSSH_QA_MULTI_PASSWORD=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 18)
  CENTRALSSH_QA_MULTI_TOTP_SECRET=$(generated_secret)
  CENTRALSSH_QA_OTHER_PASSWORD=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 18)
  export CENTRALSSH_QA_PROXY_PASSWORD CENTRALSSH_QA_PROXY_TOTP_SECRET
  export CENTRALSSH_QA_CHANGE_BOOTSTRAP_PASSWORD CENTRALSSH_QA_CHANGE_NEW_PASSWORD
  export CENTRALSSH_QA_ENROLL_PASSWORD CENTRALSSH_QA_LIMITED_PASSWORD CENTRALSSH_QA_LIMITED_TOTP_SECRET
  export CENTRALSSH_QA_MULTI_PASSWORD CENTRALSSH_QA_MULTI_TOTP_SECRET CENTRALSSH_QA_OTHER_PASSWORD
  write_generated_env
}

prepare_artifacts() {
  require_cmd python3
  require_cmd expect
  require_cmd ssh
  require_cmd scp
  require_cmd sftp
  require_cmd tar
  require_cmd argon2

  mkdir -p "$CENTRALSSH_ARTIFACT_ROOT"
  run_id=$(date -u +"%Y%m%dT%H%M%SZ")
  CENTRALSSH_ARTIFACT_DIR="$CENTRALSSH_ARTIFACT_ROOT/$run_id"
  mkdir -p "$CENTRALSSH_ARTIFACT_DIR"
  CENTRALSSH_RESULTS_FILE="$CENTRALSSH_ARTIFACT_DIR/results.jsonl"
  CENTRALSSH_GENERATED_ENV_FILE="$CENTRALSSH_ARTIFACT_DIR/generated.env"
  export CENTRALSSH_ARTIFACT_DIR CENTRALSSH_RESULTS_FILE CENTRALSSH_GENERATED_ENV_FILE
  : >"$CENTRALSSH_RESULTS_FILE"
  ensure_generated_credentials
}

wait_for_tcp() {
  host=$1
  port=$2
  timeout_seconds=$3
  start=$(date +%s)
  while :; do
    if nc -z "$host" "$port" >/dev/null 2>&1; then
      return 0
    fi
    now=$(date +%s)
    if [ $((now - start)) -ge "$timeout_seconds" ]; then
      return 1
    fi
    sleep 1
  done
}

prepare_askpass_dir() {
  askpass_dir=$1
  password=$2
  totp_secret=${3-}
  selection=${4-}

  mkdir -p "$askpass_dir"
  chmod 700 "$askpass_dir"
  askpass_script="$askpass_dir/askpass.sh"
  responses_file="$askpass_dir/askpass.responses"
  state_file="$askpass_dir/askpass.state"

  cat >"$askpass_script" <<'EOF'
#!/bin/sh
set -eu
state_file="$CENTRALSSH_ASKPASS_STATE"
responses_file="$CENTRALSSH_ASKPASS_RESPONSES"
idx=0
if [ -f "$state_file" ]; then
  idx=$(cat "$state_file")
fi
idx=$((idx + 1))
sed -n "${idx}p" "$responses_file"
printf '%s' "$idx" >"$state_file"
EOF
  chmod 700 "$askpass_script"

  : >"$responses_file"
  printf '%s\n' "$password" >>"$responses_file"
  if [ -n "$totp_secret" ]; then
    printf '%s\n' "$(totp_code "$totp_secret")" >>"$responses_file"
  fi
  if [ -n "${selection-}" ]; then
    printf '%s\n' "$selection" >>"$responses_file"
  fi
  rm -f "$state_file"

  CENTRALSSH_ASKPASS_SCRIPT="$askpass_script"
  CENTRALSSH_ASKPASS_RESPONSES="$responses_file"
  CENTRALSSH_ASKPASS_STATE="$state_file"
  export CENTRALSSH_ASKPASS_SCRIPT CENTRALSSH_ASKPASS_RESPONSES CENTRALSSH_ASKPASS_STATE
}

with_gateway_askpass() {
  DISPLAY=:0 \
  SSH_ASKPASS_REQUIRE=force \
  SSH_ASKPASS="$CENTRALSSH_ASKPASS_SCRIPT" \
  CENTRALSSH_ASKPASS_STATE="$CENTRALSSH_ASKPASS_STATE" \
  CENTRALSSH_ASKPASS_RESPONSES="$CENTRALSSH_ASKPASS_RESPONSES" \
  "$@"
}

common_gateway_ssh_args() {
  cat <<EOF
-o ProxyCommand=$(gateway_proxy_command)
-o PreferredAuthentications=keyboard-interactive
-o PubkeyAuthentication=no
-o PasswordAuthentication=no
-o KbdInteractiveAuthentication=yes
-o ConnectTimeout=15
-o ServerAliveInterval=5
-o ServerAliveCountMax=3
-p $CENTRALSSH_GATEWAY_PORT
EOF
}
