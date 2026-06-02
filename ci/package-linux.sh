#!/bin/sh
set -eu

usage() {
  echo "usage: $0 <version> <amd64|arm64>" >&2
  exit 1
}

version=${1:-}
arch=${2:-}
[ -n "$version" ] || usage
[ -n "$arch" ] || usage
if [ -n "${RELEASE_VERSION:-}" ] && [ "$version" != "$RELEASE_VERSION" ]; then
  printf 'release version mismatch: arg=%s env=%s\n' "$version" "$RELEASE_VERSION" >&2
  exit 1
fi
version=${RELEASE_VERSION:-$version}

repo_root=${REPO_ROOT:-$PWD}
dist_dir=${DIST_DIR:-"$repo_root/dist"}
work_root=${WORK_ROOT:-"$repo_root/.ci-packaging/linux-$arch"}
target_root=${CARGO_TARGET_DIR:-"$repo_root/target"}

case "$arch" in
  amd64)
    target_triple=x86_64-unknown-linux-gnu
    deb_arch=amd64
    rpm_arch=x86_64
    ;;
  arm64)
    target_triple=aarch64-unknown-linux-gnu
    deb_arch=arm64
    rpm_arch=aarch64
    ;;
  *)
    echo "unsupported Linux architecture: $arch" >&2
    exit 1
    ;;
esac

app_name=centralssh
release_bin="$target_root/$target_triple/release/$app_name"
release_tool="$repo_root/tools/cssh-keyscan"
systemd_tarball="$dist_dir/${app_name}-${version}-linux-${arch}-systemd.tar.gz"
openrc_tarball="$dist_dir/${app_name}-${version}-linux-${arch}-openrc.tar.gz"
deb_file="$dist_dir/${app_name}-${version}-debian-${deb_arch}.deb"
rpm_file="$dist_dir/${app_name}-${version}-fedora-${rpm_arch}.rpm"
staging_root="$work_root/stage"
systemd_archive_root="$work_root/archive-systemd/$app_name"
openrc_archive_root="$work_root/archive-openrc/$app_name"
rpm_topdir="$work_root/rpmbuild"
source_root="$work_root/rpm-source/${app_name}-${version}"
rpm_target_platform="${rpm_arch}-unknown-linux"
rm -rf "$work_root"
mkdir -p "$dist_dir" "$staging_root" "$systemd_archive_root" "$openrc_archive_root"
mkdir -p \
  "$rpm_topdir/BUILD" \
  "$rpm_topdir/BUILDROOT" \
  "$rpm_topdir/RPMS" \
  "$rpm_topdir/SOURCES" \
  "$rpm_topdir/SPECS" \
  "$rpm_topdir/SRPMS"

cargo build --locked --release --target "$target_triple"
test -x "$release_bin"
test -x "$release_tool"

make install \
  DESTDIR="$staging_root" \
  PREFIX=/usr/local \
  CARGO_TARGET_DIR="$target_root" \
  TARGET_TRIPLE="$target_triple" \
  PROFILE=release \
  SYSTEMD_UNIT_DIR=/etc/systemd/system

mkdir -p \
  "$systemd_archive_root/bin" \
  "$systemd_archive_root/examples" \
  "$systemd_archive_root/packaging/systemd"

install -m 0755 "$release_bin" "$systemd_archive_root/bin/$app_name"
install -m 0755 "$release_tool" "$systemd_archive_root/bin/cssh-keyscan"
install -m 0644 "$repo_root/examples/config.toml" "$systemd_archive_root/examples/config.toml"
install -m 0644 "$repo_root/examples/servers.toml" "$systemd_archive_root/examples/servers.toml"
install -m 0644 "$repo_root/packaging/systemd/centralssh.service" "$systemd_archive_root/packaging/systemd/centralssh.service"
install -m 0644 "$repo_root/README-dist.md" "$systemd_archive_root/README.md"
install -m 0644 "$repo_root/op-guide.md" "$systemd_archive_root/op-guide.md"
install -m 0644 "$repo_root/Makefile-dist" "$systemd_archive_root/Makefile"

mkdir -p \
  "$openrc_archive_root/bin" \
  "$openrc_archive_root/examples" \
  "$openrc_archive_root/packaging/openrc"

install -m 0755 "$release_bin" "$openrc_archive_root/bin/$app_name"
install -m 0755 "$release_tool" "$openrc_archive_root/bin/cssh-keyscan"
install -m 0644 "$repo_root/examples/config.toml" "$openrc_archive_root/examples/config.toml"
install -m 0644 "$repo_root/examples/servers.toml" "$openrc_archive_root/examples/servers.toml"
install -m 0644 "$repo_root/packaging/openrc/centralssh" "$openrc_archive_root/packaging/openrc/centralssh"
install -m 0644 "$repo_root/README-openrc-dist.md" "$openrc_archive_root/README.md"
install -m 0644 "$repo_root/op-guide.md" "$openrc_archive_root/op-guide.md"
install -m 0644 "$repo_root/Makefile-openrc-dist" "$openrc_archive_root/Makefile"

tar -C "$work_root/archive-systemd" -czf "$systemd_tarball" "$app_name"
tar -C "$work_root/archive-openrc" -czf "$openrc_tarball" "$app_name"

mkdir -p "$staging_root/DEBIAN"
cat > "$staging_root/DEBIAN/control" <<EOF
Package: $app_name
Version: $version
Section: admin
Priority: optional
Architecture: $deb_arch
Maintainer: CentralSSH CI <root@localhost>
Description: OpenSSH-compatible hardened SSH gateway
EOF
dpkg-deb --build "$staging_root" "$deb_file"

mkdir -p "$source_root"
tar -C "$staging_root" -cf - . | tar -C "$source_root" -xf -

filelist="$work_root/rpm-files.list"
: > "$filelist"
(
  cd "$source_root"
  find . -mindepth 1 | LC_ALL=C sort
) | while IFS= read -r path; do
  rel_path=${path#./}
  full_path="$source_root/$rel_path"
  case "$rel_path" in
    etc/centralssh/config.toml|etc/centralssh/servers.toml|etc/centralssh/known_hosts|var/log/centralssh/audit.jsonl)
      printf '%%config(noreplace) /%s\n' "$rel_path" >> "$filelist"
      ;;
    *)
      if [ -d "$full_path" ]; then
        printf '%%dir /%s\n' "$rel_path" >> "$filelist"
      else
        printf '/%s\n' "$rel_path" >> "$filelist"
      fi
      ;;
  esac
done

tar -C "$work_root/rpm-source" -czf "$rpm_topdir/SOURCES/${app_name}-${version}.tar.gz" "${app_name}-${version}"

cat > "$rpm_topdir/SPECS/${app_name}.spec" <<EOF
Name:           $app_name
Version:        $version
Release:        1
Summary:        OpenSSH-compatible hardened SSH gateway
License:        GPL-3.0-only
Source0:        %{name}-%{version}.tar.gz
AutoReqProv:    no

%description
OpenSSH-compatible hardened SSH gateway.

%prep
%setup -q

%build

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a . %{buildroot}/

%files -f $filelist

%changelog
* Tue May 12 2026 CentralSSH CI <root@localhost> - $version-1
- Automated build
EOF

if [ "$arch" = "arm64" ]; then
  rpmbuild \
    --define "_topdir $rpm_topdir" \
    --define "_build_id_links none" \
    --define "__strip /bin/true" \
    --define "__objdump /bin/true" \
    --define "__brp_strip /bin/true" \
    --define "__brp_strip_comment_note /bin/true" \
    --define "__brp_strip_static_archive /bin/true" \
    --target "$rpm_target_platform" \
    -bb "$rpm_topdir/SPECS/${app_name}.spec"
else
  rpmbuild \
    --define "_topdir $rpm_topdir" \
    --define "_build_id_links none" \
    --target "$rpm_target_platform" \
    -bb "$rpm_topdir/SPECS/${app_name}.spec"
fi

rpm_built=$(find "$rpm_topdir/RPMS" -type f -name '*.rpm' | head -n 1)
[ -n "$rpm_built" ] || {
  echo "rpm build did not produce an artifact" >&2
  exit 1
}
cp "$rpm_built" "$rpm_file"

printf '%s\n%s\n%s\n%s\n' "$systemd_tarball" "$openrc_tarball" "$deb_file" "$rpm_file"
