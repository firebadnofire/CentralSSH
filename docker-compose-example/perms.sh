#!/bin/sh
set -eu

DEPLOY_DIR="${1:-deploy}"

ETC_DIR="$DEPLOY_DIR/etc-centralssh"
LIB_DIR="$DEPLOY_DIR/var-lib-centralssh"
LOG_DIR="$DEPLOY_DIR/var-log-centralssh"

mkdir -p "$ETC_DIR"
mkdir -p "$LIB_DIR"
mkdir -p "$LOG_DIR"

chown -R root:root "$DEPLOY_DIR"

chmod 700 "$ETC_DIR"
chmod 700 "$LIB_DIR"
chmod 700 "$LOG_DIR"

if [ -f "$ETC_DIR/config.toml" ]; then
    chmod 600 "$ETC_DIR/config.toml"
fi

if [ -f "$ETC_DIR/servers.toml" ]; then
    chmod 600 "$ETC_DIR/servers.toml"
fi

find "$ETC_DIR" -type f -name "*.pem" -exec chmod 600 {} \;
find "$ETC_DIR" -type f -name "*.key" -exec chmod 600 {} \;

find "$LIB_DIR" -type f -exec chmod 600 {} \;

find "$LOG_DIR" -type f -exec chmod 600 {} \;

echo "fixed CentralSSH deploy permissions under: $DEPLOY_DIR"
