#!/bin/sh
set -eu

target="${CENTRALSSH_HEALTHCHECK_TARGET:-127.0.0.1:7788}"
host="${target%:*}"
port="${target##*:}"

banner="$(
    printf 'SSH-2.0-centralssh-healthcheck\r\n' \
    | nc -w 3 "$host" "$port" 2>/dev/null \
    | tr -d '\r' \
    | head -n 1
)"

case "$banner" in
    SSH-2.0-*)
        exit 0
        ;;
    *)
        echo "centralssh healthcheck failed: no SSH banner from $target" >&2
        exit 1
        ;;
esac
