#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
  echo "usage: time-command.sh <command> [args...]" >&2
  exit 1
fi

start_epoch=$(date +%s)
echo "timing-start epoch=${start_epoch} cmd=$*"
"$@"
end_epoch=$(date +%s)
echo "timing-end epoch=${end_epoch} elapsed_seconds=$((end_epoch - start_epoch)) cmd=$*"
