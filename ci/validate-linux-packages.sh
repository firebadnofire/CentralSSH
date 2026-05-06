#!/bin/sh
set -eu

eval "$(./ci/package-env.sh export)"

deb_file="dist/${CI_PACKAGE_NAME}_${CI_PACKAGE_VERSION}_amd64.deb"
rpm_file="dist/${CI_PACKAGE_NAME}-${CI_PACKAGE_VERSION}-1.x86_64.rpm"
tar_file="dist/${CI_PACKAGE_NAME}-${CI_PACKAGE_VERSION}-linux-amd64.tar.gz"
sha_file="dist/SHA256SUMS-linux.txt"

for required_file in "$deb_file" "$rpm_file" "$tar_file" "$sha_file"; do
  [ -f "$required_file" ] || {
    echo "missing expected artifact: $required_file" >&2
    exit 1
  }
done

deb_listing=$(dpkg-deb -c "$deb_file")
printf '%s\n' "$deb_listing" | grep -F "./usr/sbin/${CI_PACKAGE_NAME}" >/dev/null
printf '%s\n' "$deb_listing" | grep -F "./usr/bin/cssh-keyscan" >/dev/null
printf '%s\n' "$deb_listing" | grep -F "./etc/systemd/system/${CI_PACKAGE_NAME}.service" >/dev/null
printf '%s\n' "$deb_listing" | grep -F "./etc/centralssh/config.toml" >/dev/null
printf '%s\n' "$deb_listing" | grep -F "./etc/centralssh/servers.toml" >/dev/null
printf '%s\n' "$deb_listing" | grep -F "./etc/centralssh/known_hosts" >/dev/null
printf '%s\n' "$deb_listing" | grep -F "./var/log/centralssh/audit.jsonl" >/dev/null

rpm -qpl "$rpm_file" | grep -Fx "/usr/sbin/${CI_PACKAGE_NAME}" >/dev/null
rpm -qpl "$rpm_file" | grep -Fx "/usr/bin/cssh-keyscan" >/dev/null
rpm -qpl "$rpm_file" | grep -Fx "/etc/systemd/system/${CI_PACKAGE_NAME}.service" >/dev/null
rpm -qpl "$rpm_file" | grep -Fx "/etc/centralssh/config.toml" >/dev/null
rpm -qpl "$rpm_file" | grep -Fx "/etc/centralssh/servers.toml" >/dev/null
rpm -qpl "$rpm_file" | grep -Fx "/etc/centralssh/known_hosts" >/dev/null
rpm -qpl "$rpm_file" | grep -Fx "/var/log/centralssh/audit.jsonl" >/dev/null

tar -tzf "$tar_file" | grep -Fx "./usr/sbin/${CI_PACKAGE_NAME}" >/dev/null
tar -tzf "$tar_file" | grep -Fx "./usr/bin/cssh-keyscan" >/dev/null
tar -tzf "$tar_file" | grep -Fx "./etc/systemd/system/${CI_PACKAGE_NAME}.service" >/dev/null

grep -F "$(basename "$deb_file")" "$sha_file" >/dev/null
grep -F "$(basename "$rpm_file")" "$sha_file" >/dev/null
grep -F "$(basename "$tar_file")" "$sha_file" >/dev/null
