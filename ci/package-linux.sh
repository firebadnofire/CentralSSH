#!/bin/sh
set -eu

eval "$(./ci/package-env.sh export)"

for required_command in cargo make dpkg-deb rpmbuild tar; do
  command -v "$required_command" >/dev/null 2>&1 || {
    echo "missing required command: $required_command" >&2
    exit 1
  }
done

mkdir -p dist
rm -rf stage/linux stage/rpmbuild
mkdir -p stage/linux
mkdir -p stage/rpmbuild/BUILD
mkdir -p stage/rpmbuild/BUILDROOT
mkdir -p stage/rpmbuild/RPMS
mkdir -p stage/rpmbuild/SOURCES
mkdir -p stage/rpmbuild/SPECS
mkdir -p stage/rpmbuild/SRPMS

./ci/time-command.sh cargo build --locked --release
make install DESTDIR="$PWD/stage/linux" PREFIX=/usr

mkdir -p stage/linux/DEBIAN
cat > stage/linux/DEBIAN/control <<EOF
Package: ${CI_PACKAGE_NAME}
Version: ${CI_PACKAGE_VERSION}
Section: admin
Priority: optional
Architecture: amd64
Maintainer: ${CI_PACKAGE_MAINTAINER}
Description: ${CI_PACKAGE_DESC}
EOF
dpkg-deb --build stage/linux "dist/${CI_PACKAGE_NAME}_${CI_PACKAGE_VERSION}_amd64.deb"
rm -rf stage/linux/DEBIAN

tar -C stage/linux -czf "stage/rpmbuild/SOURCES/${CI_PACKAGE_NAME}-${CI_PACKAGE_VERSION}-linux-root.tar.gz" .
cat > "stage/rpmbuild/SPECS/${CI_PACKAGE_NAME}.spec" <<EOF
Name: ${CI_PACKAGE_NAME}
Version: ${CI_PACKAGE_VERSION}
Release: 1%{?dist}
Summary: ${CI_PACKAGE_COMMENT}
License: GPL-3.0-only
URL: ${CI_PACKAGE_WWW}
BuildArch: x86_64
Source0: ${CI_PACKAGE_NAME}-${CI_PACKAGE_VERSION}-linux-root.tar.gz

%description
${CI_PACKAGE_DESC}

%prep

%build

%install
mkdir -p %{buildroot}
tar -C %{buildroot} -xzf %{SOURCE0}

%files
/usr/sbin/${CI_PACKAGE_NAME}
/usr/bin/cssh-keyscan
/etc/systemd/system/${CI_PACKAGE_NAME}.service
%dir /etc/centralssh
%dir /etc/centralssh/users
/etc/centralssh/config.toml
/etc/centralssh/servers.toml
/etc/centralssh/known_hosts
%dir /var/log/centralssh
/var/log/centralssh/audit.jsonl
EOF
rpmbuild --define "_topdir $PWD/stage/rpmbuild" -bb "stage/rpmbuild/SPECS/${CI_PACKAGE_NAME}.spec"
cp "stage/rpmbuild/RPMS/x86_64/${CI_PACKAGE_NAME}-${CI_PACKAGE_VERSION}-1.x86_64.rpm" \
  "dist/${CI_PACKAGE_NAME}-${CI_PACKAGE_VERSION}-1.x86_64.rpm"

tar -C stage/linux -czf "dist/${CI_PACKAGE_NAME}-${CI_PACKAGE_VERSION}-linux-amd64.tar.gz" .
./ci/write-sha256sums.sh "dist/SHA256SUMS-linux.txt" dist
