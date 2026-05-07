#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -n "${CENTRALSSH_PROFILE_FILE:-}" ]; then
  # shellcheck disable=SC1090
  . "$CENTRALSSH_PROFILE_FILE"
elif [ -n "${CENTRALSSH_E2E_ENV_FILE:-}" ]; then
  # shellcheck disable=SC1090
  . "$CENTRALSSH_E2E_ENV_FILE"
elif [ -f "$SCRIPT_DIR/profiles/freebsd-host-jail-141-151.env" ]; then
  # shellcheck disable=SC1091
  . "$SCRIPT_DIR/profiles/freebsd-host-jail-141-151.env"
fi

: "${CENTRALSSH_JUMP_HOST:=192.168.86.89}"
: "${CENTRALSSH_HOST:=192.168.122.141}"
: "${CENTRALSSH_GATEWAY:=192.168.122.151}"
: "${CENTRALSSH_GATEWAY_PORT:=7788}"
: "${CENTRALSSH_JUMP_USER:=cgpt}"
: "${CENTRALSSH_JUMP_KEY:=/Users/william/.ssh/cgpt/cgpt}"
: "${CENTRALSSH_USER:=qa_proxy}"
: "${CENTRALSSH_PASSWORD:=}"
: "${CENTRALSSH_TOTP_SECRET:=}"
: "${CENTRALSSH_SELECTION:=1}"
: "${CENTRALSSH_REMOTE_COMMAND:=whoami}"

if [ -z "$CENTRALSSH_PASSWORD" ] || [ -z "$CENTRALSSH_TOTP_SECRET" ]; then
  echo "CENTRALSSH_PASSWORD and CENTRALSSH_TOTP_SECRET are required." >&2
  exit 2
fi

tmp_dir="${TMPDIR:-/tmp}/centralssh-e2e-askpass"
mkdir -p "$tmp_dir"
chmod 700 "$tmp_dir"

askpass_script="$tmp_dir/askpass.sh"
responses_file="$tmp_dir/askpass.responses"
state_file="$tmp_dir/askpass.state"

cat >"$askpass_script" <<'EOF'
#!/bin/sh
set -eu
state_file="${TMPDIR:-/tmp}/centralssh-e2e-askpass/askpass.state"
responses_file="${TMPDIR:-/tmp}/centralssh-e2e-askpass/askpass.responses"
idx=0
if [ -f "$state_file" ]; then
  idx=$(cat "$state_file")
fi
idx=$((idx + 1))
sed -n "${idx}p" "$responses_file"
printf '%s' "$idx" > "$state_file"
EOF
chmod 700 "$askpass_script"

totp_code="$(python3 - <<'PY' "$CENTRALSSH_TOTP_SECRET"
import base64
import hashlib
import hmac
import struct
import sys
import time

secret = sys.argv[1]
key = base64.b32decode(secret, casefold=True)
counter = int(time.time()) // 30
msg = struct.pack(">Q", counter)
digest = hmac.new(key, msg, hashlib.sha1).digest()
offset = digest[-1] & 0x0F
code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
print(f"{code:06d}")
PY
)"

printf '%s\n%s\n%s\n' \
  "$CENTRALSSH_PASSWORD" \
  "$totp_code" \
  "$CENTRALSSH_SELECTION" \
  >"$responses_file"
rm -f "$state_file"

DISPLAY=:0 \
SSH_ASKPASS_REQUIRE=force \
SSH_ASKPASS="$askpass_script" \
ssh \
  -o "ProxyCommand=ssh -i $CENTRALSSH_JUMP_KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -J $CENTRALSSH_JUMP_HOST $CENTRALSSH_JUMP_USER@$CENTRALSSH_HOST -W %h:%p" \
  -o UserKnownHostsFile=/dev/null \
  -o StrictHostKeyChecking=no \
  -o PreferredAuthentications=keyboard-interactive \
  -o PubkeyAuthentication=no \
  -o PasswordAuthentication=no \
  -p "$CENTRALSSH_GATEWAY_PORT" \
  "$CENTRALSSH_USER@$CENTRALSSH_GATEWAY" \
  "$CENTRALSSH_REMOTE_COMMAND"
