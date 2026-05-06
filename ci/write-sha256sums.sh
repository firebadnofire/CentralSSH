#!/bin/sh
set -eu

output_file=${1:?usage: write-sha256sums.sh <output-file> <directory>}
target_dir=${2:?usage: write-sha256sums.sh <output-file> <directory>}

checksum_file_name=$(basename "$output_file")
tmp_output="${output_file}.tmp.$$"
tmp_output_name=$(basename "$tmp_output")

checksum_path() {
  file_path=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file_path" | awk '{print $1}'
  elif command -v sha256 >/dev/null 2>&1; then
    sha256 -q "$file_path"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file_path" | awk '{print $1}'
  else
    echo "no SHA256 implementation available" >&2
    exit 1
  fi
}

: > "$tmp_output"
(
  cd "$target_dir"
  find . -type f | sed 's|^\./||' | LC_ALL=C sort
) | while IFS= read -r relative_path; do
  [ -n "$relative_path" ] || continue
  if [ "$relative_path" = "$checksum_file_name" ]; then
    continue
  fi
  if [ "$relative_path" = "$tmp_output_name" ]; then
    continue
  fi
  printf '%s  %s\n' "$(checksum_path "$target_dir/$relative_path")" "$relative_path" >> "$tmp_output"
done

mv "$tmp_output" "$output_file"
