#!/bin/sh

set -eu

if ! command -v ssh >/dev/null 2>&1; then
    echo "ssh client not found in PATH" >&2
    exit 1
fi

BIN_PATH="${CENTRALSSH_BIN:-/tmp/centralssh-target/debug/centralssh}"
SUCCESS_PORT="${CENTRALSSH_VALIDATE_PQ_PORT:-7799}"
STRICT_PORT="${CENTRALSSH_VALIDATE_PQ_STRICT_PORT:-7800}"

if [ ! -x "$BIN_PATH" ]; then
    echo "centralssh binary not found or not executable: $BIN_PATH" >&2
    echo "Build it first, for example:" >&2
    echo "  CARGO_HOME=/tmp/centralssh-cargo-home CARGO_TARGET_DIR=/tmp/centralssh-target cargo build" >&2
    exit 1
fi

TMPDIR="$(mktemp -d /private/tmp/centralssh-pq-validate-XXXXXX)"
cleanup() {
    if [ -f "$TMPDIR/server.pid" ]; then
        kill "$(cat "$TMPDIR/server.pid")" >/dev/null 2>&1 || true
        wait "$(cat "$TMPDIR/server.pid")" 2>/dev/null || true
    fi
    if [ -f "$TMPDIR/strict-server.pid" ]; then
        kill "$(cat "$TMPDIR/strict-server.pid")" >/dev/null 2>&1 || true
        wait "$(cat "$TMPDIR/strict-server.pid")" 2>/dev/null || true
    fi
    rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

write_config() {
    config_path="$1"
    strict_mode="$2"
    cat >"$config_path" <<EOF
[[users]]
name = "william"
password = "\$argon2id\$v=19\$m=65536,t=3,p=1\$YWFhYWFhYWFhYWFhYWFhYQ\$5SJ0fY5fKQh0nqS5BTPw8P7GIw6Y73Q2xU1j5V6k8To"
must_change_password = false
allowed_servers = ["loopback"]

[settings]
user_key_root = "$TMPDIR/keys"
per_user_per_server = true
known_hosts_path = "$TMPDIR/known_hosts"
audit_log_path = "$TMPDIR/audit.jsonl"
enforce_password_policy = false
min_password_policy = 12

[kex_policy]
frontend_preferred = [
  "mlkem768x25519-sha256",
  "curve25519-sha256",
  "curve25519-sha256@libssh.org",
]
frontend_require_post_quantum = $strict_mode
backend_preferred = [
  "mlkem768x25519-sha256",
  "curve25519-sha256",
  "curve25519-sha256@libssh.org",
]
backend_require_post_quantum = false

[fail2ban]
persist_state = true
state_path = "$TMPDIR/fail2ban_state.json"
EOF
}

mkdir -p "$TMPDIR/keys" "$TMPDIR/log"
chmod 700 "$TMPDIR/keys" "$TMPDIR/log"
: >"$TMPDIR/known_hosts"
ssh-keygen -q -t ed25519 -N '' -f "$TMPDIR/host_ed25519" >/dev/null
chmod 600 "$TMPDIR/known_hosts" "$TMPDIR/host_ed25519"

cat >"$TMPDIR/servers.toml" <<EOF
[servers]
loopback = "127.0.0.1"
EOF
chmod 600 "$TMPDIR/servers.toml"

write_config "$TMPDIR/config.toml" false
chmod 600 "$TMPDIR/config.toml"

echo "Environment:"
echo "  binary: $BIN_PATH"
echo "  tempdir: $TMPDIR"
echo "  success port: $SUCCESS_PORT"
echo "  strict port: $STRICT_PORT"
echo

SUCCESS_CMD="ssh -vv -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 -p $SUCCESS_PORT 127.0.0.1 exit"
STRICT_CMD="ssh -vv -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 -o KexAlgorithms=curve25519-sha256 -p $STRICT_PORT 127.0.0.1 exit"

CENTRALSSH_ENFORCE_STRICT_SECURITY=false \
    "$BIN_PATH" \
    --config "$TMPDIR/config.toml" \
    --servers "$TMPDIR/servers.toml" \
    --known-hosts "$TMPDIR/known_hosts" \
    --user-key-root "$TMPDIR/keys" \
    --audit-log "$TMPDIR/audit.jsonl" \
    --listen "127.0.0.1:$SUCCESS_PORT" >"$TMPDIR/server.log" 2>&1 &
echo $! >"$TMPDIR/server.pid"
sleep 3

set +e
sh -c "$SUCCESS_CMD" >"$TMPDIR/ssh-success.log" 2>&1
SUCCESS_RC=$?
set -e

if ! grep -q "kex: algorithm: mlkem768x25519-sha256" "$TMPDIR/ssh-success.log"; then
    echo "successful path did not negotiate mlkem768x25519-sha256" >&2
    exit 1
fi
if grep -q "WarnWeakCrypto" "$TMPDIR/ssh-success.log"; then
    echo "successful path still triggered the weak-crypto warning" >&2
    exit 1
fi

write_config "$TMPDIR/strict-config.toml" true
chmod 600 "$TMPDIR/strict-config.toml"

CENTRALSSH_ENFORCE_STRICT_SECURITY=false \
    "$BIN_PATH" \
    --config "$TMPDIR/strict-config.toml" \
    --servers "$TMPDIR/servers.toml" \
    --known-hosts "$TMPDIR/known_hosts" \
    --user-key-root "$TMPDIR/keys" \
    --audit-log "$TMPDIR/strict-audit.jsonl" \
    --listen "127.0.0.1:$STRICT_PORT" >"$TMPDIR/strict-server.log" 2>&1 &
echo $! >"$TMPDIR/strict-server.pid"
sleep 3

set +e
sh -c "$STRICT_CMD" >"$TMPDIR/ssh-strict.log" 2>&1
STRICT_RC=$?
set -e

if ! grep -q "no matching key exchange method found" "$TMPDIR/ssh-strict.log"; then
    echo "strict PQ path did not fail with no-matching-KEX" >&2
    exit 1
fi

echo "Successful PQ-hybrid command:"
echo "  $SUCCESS_CMD"
echo "Exit code: $SUCCESS_RC"
echo "Relevant excerpts:"
grep -n "Connection established\|kex: algorithm\|Authentications that can continue\|WarnWeakCrypto" "$TMPDIR/ssh-success.log" || true
echo

echo "Strict PQ rejection command:"
echo "  $STRICT_CMD"
echo "Exit code: $STRICT_RC"
echo "Relevant excerpts:"
grep -n "kex: algorithm\|Unable to negotiate\|no matching key exchange\|Their offer" "$TMPDIR/ssh-strict.log" || true
echo

echo "Frontend policy audit excerpt:"
grep -n "frontend_kex_policy_loaded" "$TMPDIR/audit.jsonl" || true
