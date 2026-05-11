#!/bin/sh
set -eu

umask 077

CONFIG_DIR="/etc/centralssh"
LIB_DIR="/var/lib/centralssh"
KEY_DIR="/var/lib/centralssh/keys"
LOG_DIR="/var/log/centralssh"

KNOWN_HOSTS="$CONFIG_DIR/known_hosts"
AUDIT_LOG="$LOG_DIR/audit.jsonl"

mkdir -p "$CONFIG_DIR" "$LIB_DIR" "$KEY_DIR" "$LOG_DIR"

chmod 0700 \
    "$CONFIG_DIR" \
    "$LIB_DIR" \
    "$KEY_DIR" \
    "$LOG_DIR" 2>/dev/null || true

check_writable() {
    dir="$1"

    if ! test -w "$dir"; then
        echo >&2
        echo "centralssh container startup error:" >&2
        echo "directory is not writable: $dir" >&2
        echo >&2
        echo "This usually means the bind-mounted host directory has incorrect ownership or permissions." >&2
        echo >&2
        echo "Suggested fix:" >&2
        echo "  sudo chown -R root:root ./deploy" >&2
        echo "  chmod 700 ./deploy/etc-centralssh ./deploy/var-lib-centralssh ./deploy/var-log-centralssh" >&2
        echo >&2
        exit 1
    fi
}

check_writable "$CONFIG_DIR"
check_writable "$LOG_DIR"
check_writable "$LIB_DIR"
check_writable "$KEY_DIR"

if [ ! -f "$KNOWN_HOSTS" ]; then
    if ! touch "$KNOWN_HOSTS"; then
        echo "centralssh container startup error: unable to create $KNOWN_HOSTS" >&2
        exit 1
    fi
fi

chmod 0600 "$KNOWN_HOSTS" 2>/dev/null || true

if [ ! -f "$AUDIT_LOG" ]; then
    if ! touch "$AUDIT_LOG"; then
        echo "centralssh container startup error: unable to create $AUDIT_LOG" >&2
        exit 1
    fi
fi

chmod 0600 "$AUDIT_LOG" 2>/dev/null || true

if [ ! -f "$CONFIG_DIR/config.toml" ]; then
    echo "centralssh container startup error: missing $CONFIG_DIR/config.toml" >&2
    echo "Example config is available at /usr/local/share/centralssh/examples/config.toml" >&2
    exit 1
fi

if [ ! -f "$CONFIG_DIR/servers.toml" ]; then
    echo "centralssh container startup error: missing $CONFIG_DIR/servers.toml" >&2
    echo "Example config is available at /usr/local/share/centralssh/examples/servers.toml" >&2
    exit 1
fi

exec "$@"
