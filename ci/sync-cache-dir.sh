#!/bin/sh
set -eu

mode=${1:?usage: sync-cache-dir.sh <restore|store> <source-dir> <dest-dir>}
source_dir=${2:?usage: sync-cache-dir.sh <restore|store> <source-dir> <dest-dir>}
dest_dir=${3:?usage: sync-cache-dir.sh <restore|store> <source-dir> <dest-dir>}

sync_tree() {
  from_dir=$1
  to_dir=$2
  mkdir -p "$to_dir"
  if [ ! -d "$from_dir" ]; then
    return 0
  fi

  if command -v rsync >/dev/null 2>&1; then
    rsync -a "$from_dir"/ "$to_dir"/
  else
    tar -C "$from_dir" -cf - . | tar -C "$to_dir" -xf -
  fi
}

case "$mode" in
  restore)
    sync_tree "$source_dir" "$dest_dir"
    ;;
  store)
    sync_tree "$dest_dir" "$source_dir"
    ;;
  *)
    echo "unknown mode: $mode" >&2
    exit 1
    ;;
esac
