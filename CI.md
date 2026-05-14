# CI.md

# Master CI/CD Integration Guide

This document defines the recommended CI/CD architecture for cross-platform builds, packaging, validation, and release publication.

It is intentionally modular.

Do not assume every repository must always build every platform, every package format, or every artifact type. Enable only the targets that are actually relevant to the project.

Supported platform families covered by this guide:

- Linux
- FreeBSD
- macOS
- Windows

Supported package and archive outputs covered by this guide:

- `.tar.gz` (separated by init system when needed, such as `systemd` or `openrc`)
- `.deb`
- `.rpm`
- `.pkg` (FreeBSD)
- `.pkg` (macOS)
- `.dmg`
- `.msi`
- `.zip`
- optional `.pet`

Supported architectures:

- `x86_64`
- `aarch64`

---

# Core principles

The CI design should prioritize:

- native platform correctness where it matters
- deterministic artifact naming
- explicit artifact validation
- explicit release publication
- checksum publication
- modular pipeline design
- minimal bad assumptions about runner environments
- reproducible builds

A successful compile is not enough.

A production release pipeline should prove that:

- the binary builds
- the package contents are correct
- the service or app starts correctly
- the release assets are the expected files
- the published checksums match the artifacts
- equivalent builds from the same source revision, toolchain, and build inputs can reproduce identical checksums

---

# Centralized CI logging

CI systems should support centralized remote log ingestion where practical.

Centralized logs are useful for:

* preserving logs after runner destruction
* debugging ephemeral VM failures
* long-running integration testing
* preserving runtime validation output
* retaining logs beyond CI platform retention windows
* debugging agentic coding workflows

The recommended logging architecture is intentionally lightweight.

Preferred topology:

```text
CI runner
→ Vector HTTP ingestion
→ structured JSON logs
→ append-only log storage
```

Current internal logging endpoint:

```text
http://192.168.86.41:9000/ingest
```

The logging endpoint is intended for trusted internal infrastructure on the local LAN, all known runners exist on the same trusted LAN.

Agentic coding systems operating inside CI environments should use the centralized logging endpoint whenever possible.

This is especially important for:

* long-running autonomous repair loops
* iterative compile/test/fix workflows
* VM-based integration testing
* ephemeral runner debugging
* preserving interactive runtime validation output

Recommended upload pattern:

```sh
make test 2>&1 | curl \
  --data-binary @- \
  http://192.168.86.41:9000/ingest
```

Structured logging is preferred over plain text where practical.

Do not expose internal logging endpoints publicly unless authentication, transport security, rate limiting, and retention policies are implemented appropriately.

CI logs should be treated as potentially sensitive operational data because they may contain:

* stack traces
* environment details
* build metadata
* tokens
* credentials
* deployment information

The logging system should prioritize simplicity, durability, and operational debugging usefulness over unnecessary complexity.

The logging system should also log real runs of the CI system, clearly marked in the logs.

# Runner model

The globally available runners are not all the same kind of environment.

They should be treated according to how they actually execute jobs.

## Linux runner

The Linux runner is the `opensuse-server` host. It provides Docker-backed Linux job environments and should be treated primarily as a container host and release orchestrator, not as a fixed distro target.

Available Linux-oriented labels currently include:

- `ubuntu-22.04`
- `ubuntu-latest`
- `debian`
- `alpine`

These labels represent selectable job environments, not the host operating system itself.

That means a job using:

```yaml
runs-on: ubuntu-22.04
```

should be understood as:

- execute on the Linux runner
- inside an Ubuntu 22.04 container environment

not:

- the runner host itself is Ubuntu 22.04

This distinction matters.

Use the Linux runner for:

- Linux builds
- Linux packaging
- Windows cross-builds
- release orchestration
- checksum generation
- GitHub mirroring
- containerized integration tests

## macOS runner

The macOS runner is host-native.

Prefer:

- `macos-latest`

Do not version-pin macOS labels unless a specific SDK, Xcode, or runtime requirement forces it.

The macOS runner is not treated as a frozen immutable image. It is a native execution environment and should be documented that way.

Use the macOS runner for:

- native macOS builds
- codesigning
- universal package generation
- launchd validation
- native runtime validation

## FreeBSD runner

The FreeBSD runner is host-native.

Prefer:

- `freebsd`

Do not prefer `freebsd-15` in general documentation merely because it exists. The runner is intended to represent a native FreeBSD host environment, not a permanently frozen software image.

Use the FreeBSD runner for:

- native FreeBSD builds
- rc.d validation
- jail testing
- poudriere package builds
- native runtime validation

---

# Recommended runner responsibilities

## Linux runner responsibilities

Recommended responsibilities:

- `.deb`
- `.rpm`
- Linux `.tar.gz`
- Windows `.zip`
- Windows `.msi`
- release asset preparation
- checksum generation
- Forgejo release publication
- GitHub mirroring
- GitHub release publication

## macOS runner responsibilities

Recommended responsibilities:

- macOS native builds
- signing
- universal packaging
- launchd validation
- native macOS runtime validation

## FreeBSD runner responsibilities

Recommended responsibilities:

- FreeBSD native builds
- `.pkg`
- FreeBSD `.tar.gz`
- rc.d validation
- jail-based integration testing
- poudriere builds

---

# Platform strategy

## Linux

Linux jobs should usually run through the Linux runner using containerized environments selected by label.

Linux should typically handle:

- main release orchestration
- package generation for Linux
- checksum generation
- Windows cross-builds
- mirror publication

Linux jobs are generally the most reproducible because they run in explicit container environments.

## FreeBSD

FreeBSD should use native host execution.

Do not lean on Linux-hosted FreeBSD cross-compilation for anything you actually care about operationally.

Native FreeBSD execution matters for:

- libc behavior
- rc subsystem behavior
- jail behavior
- filesystem semantics
- TTY behavior
- PAM or auth integration
- network stack behavior

## macOS

macOS should use native host execution.

macOS pipelines should always produce a signed, non-notarized universal `.pkg`.

If the project genuinely needs a disk image distribution flow, the pipeline may additionally produce a signed, non-notarized universal `.dmg`.

That is the default policy.

Do not write macOS packaging guidance that assumes notarization is mandatory. It is not. For this CI design, the required baseline is:

- signed
- non-notarized
- universal

For macOS deliverables, prefer:

- universal `.pkg`
- universal `.dmg` only when a `.dmg` is operationally justified

Typical reasons a `.dmg` may be justified:

- app bundle distribution
- drag-and-drop installation UX
- desktop-app packaging needs

For CLI or daemon-style software, the universal signed `.pkg` should generally be the primary macOS release artifact.

## Windows

Windows builds should be done cross-platform from the Linux runner.

This is the default and preferred policy.

Use the Linux runner for Windows targets unless the project truly requires native Windows runtime or installer validation.

This is usually sufficient for:

- Go projects
- Rust projects
- CLI tools
- static binaries
- service binaries

Introduce native Windows runners only when the project actually needs them, such as for:

- GUI testing
- COM or .NET integration
- Windows service runtime validation
- installer behavior validation
- driver or kernel-facing integration

---

# Package and archive guidance

The project does not need every artifact in this section. Pick the outputs that match the software.

## Linux outputs

Common Linux outputs:

- `.deb`
- `.rpm`
- `.tar.gz`

Linux tarballs should be separated by init system when service files are included.

Produce separate tarballs for:

- `systemd`
- `openrc`

Do not combine `systemd` and `openrc` assets into one tarball.

## FreeBSD outputs

Common FreeBSD outputs:

- `.pkg`
- `.tar.gz`

Prefer native package generation and native validation.

For packages, use `poudriere` where practical.

## macOS outputs

Required macOS baseline output policy:

- signed, non-notarized universal `.pkg`

Optional macOS output when needed:

- signed, non-notarized universal `.dmg`

Do not produce per-architecture macOS package artifacts unless there is a very specific reason. Prefer universal outputs.

## Windows outputs

Common Windows outputs:

- `.zip`
- `.msi`

For many CLI tools, `.zip` is enough.

Use `.msi` when:

- service installation matters
- enterprise deployment matters
- the install flow needs to behave like a real Windows installer

---

# Architecture support

Where a platform supports architecture-specific builds, support:

- `x86_64`
- `aarch64`

Translate architecture names correctly per ecosystem.

Example mapping:

| Ecosystem | x86_64 | aarch64 |
|---|---|---|
| Go | `amd64` | `arm64` |
| Debian | `amd64` | `arm64` |
| RPM | `x86_64` | `aarch64` |

Do not assume architecture naming is consistent across tools.

---

# Recommended artifact naming

Use deterministic and obvious artifact names.

## Linux

```text
myapp-linux-amd64-systemd.tar.gz
myapp-linux-amd64-openrc.tar.gz
myapp-linux-arm64-systemd.tar.gz
myapp-linux-arm64-openrc.tar.gz

myapp-debian-amd64.deb
myapp-debian-arm64.deb

myapp-fedora-x86_64.rpm
myapp-fedora-aarch64.rpm
```

## FreeBSD

```text
myapp-freebsd-x86_64.tar.gz
myapp-freebsd-aarch64.tar.gz

myapp-freebsd.pkg
```

## macOS

```text
myapp-macos-universal.pkg
myapp-macos-universal.dmg
```

## Windows

```text
myapp-windows-x86_64.zip
myapp-windows-aarch64.zip

myapp-windows-x86_64.msi
myapp-windows-aarch64.msi
```

---

# Linux build guidance

The Linux runner is the main build and release orchestrator.

Recommended usage patterns:

- containerized packaging jobs
- explicit dependency installation
- explicit artifact lists
- explicit checksum generation
- explicit API-driven release publication

When package jobs run across different runner classes, upload their validated artifacts as CI artifacts. A final release job should wait on all required package jobs, derive the normalized semantic version from the pushed tag, rewrite `Cargo.toml`, refresh `Cargo.lock`, download the expected CI artifacts into a fresh release workspace, generate the checksum file there, upload it beside the artifacts, and publish the release in one API-driven pass. If the publish step fails, the emitted error payload should include the failing command and the captured log file path so artifact download and release API failures are explicit.
The pushed git tag is the canonical release version. `Cargo.toml` is rewritten during CI to match that tag, so a stale placeholder in the repository is acceptable as long as the release helper can normalize the tag and the rewrite step succeeds.

## apt-cacher-ng

When using Debian or Ubuntu container jobs on self-hosted infrastructure, configure `apt-cacher-ng`.

Example:

```sh
{
  echo 'Acquire::http::Proxy "http://apt-cacher-ng:3142";'
  echo 'Acquire::https::Proxy "http://apt-cacher-ng:3142";'
} > /etc/apt/apt.conf.d/01proxy
```

This cuts down dependency fetch time and CI waste.

## Build toolchain pinning

Pin toolchain versions when reproducibility matters.

Downloaded toolchains should be checksum-verified before use.

---

# FreeBSD build guidance

Use native FreeBSD execution for actual FreeBSD confidence.

Recommended tools:

- `poudriere`
- `pkg`
- jails
- Bastille or equivalent jail tooling
- ZFS where helpful

Use jail-based testing for:

- package installation
- service startup
- config path validation
- rc.d validation
- network-facing integration testing

---

# macOS build guidance

macOS jobs should run natively and produce universal deliverables.

Required policy:

- produce a signed, non-notarized universal `.pkg`

Optional policy when justified:

- also produce a signed, non-notarized universal `.dmg`

macOS CI should also validate:

- package creation success
- signature presence
- launchd assets if applicable
- basic runtime execution

Do not force notarization into the default CI path unless a repository specifically chooses to require it.

---

# Windows build guidance

Windows builds should be produced on the Linux runner by cross-compilation.

Recommended uses:

- Go cross-builds
- Rust cross-builds
- packaging into `.zip`
- optional `.msi` packaging

This keeps the CI fleet simpler and avoids pointless native Windows runner sprawl.

---

# Validation policy

Artifact creation is not enough.

Every release pipeline should explicitly validate what it produced.

## Tarball validation

Use archive listing checks and require specific members.

Example:

```sh
tar -tzf artifact.tar.gz
```

Validate:

- binary present
- config present
- service files present
- docs present
- expected packaging files present

## Debian validation

Use:

```sh
dpkg-deb --info artifact.deb
dpkg-deb --contents artifact.deb
```

Validate required paths explicitly.

## RPM validation

Use:

```sh
rpm -qip artifact.rpm
rpm -qlp artifact.rpm
```

Validate required paths explicitly.

## macOS validation

Validate at minimum:

- `.pkg` or `.dmg` exists
- artifact is signed
- artifact is universal where required

If launchd assets are part of the product, validate them too.

## Windows validation

Validate at minimum:

- executable exists
- expected support files exist
- archive structure is correct

## FreeBSD validation

Validate at minimum:

- `.pkg` installs
- service starts
- rc.d integration works
- expected config paths exist

---

# Runtime validation

Build success is cheap. Runtime validation is where broken releases get caught.

## Linux runtime validation

For `systemd`:

```sh
systemctl daemon-reload
systemctl enable myapp
systemctl start myapp
systemctl status myapp
```

For `openrc`:

```sh
rc-update add myapp
rc-service myapp start
rc-service myapp status
```

## FreeBSD runtime validation

```sh
sysrc myapp_enable=YES
service myapp start
service myapp status
```

Prefer doing this inside a fresh jail.

## macOS runtime validation

Validate what actually applies to the project.

Examples:

```sh
pkgutil --check-signature myapp-macos-universal.pkg
```

And if launchd is relevant:

```sh
launchctl bootstrap
launchctl print
```

## Windows runtime validation

Only add native Windows runtime validation if the project truly needs it.

Cross-build-only projects do not need fake theater here.

---

# Release asset enumeration

Do not release by blindly uploading whatever happens to be in `dist/`.

Use explicit asset lists.

Prefer:

```sh
asset_paths=(
  "dist/file1"
  "dist/file2"
)
```

instead of:

```sh
find dist -type f
```

Explicit lists prevent:

- stale artifacts
- debug leftovers
- accidental uploads
- malformed releases

---

# Checksums

Every release should publish checksum manifests.

Generate both:

```sh
sha256sum "${asset_paths[@]}" > dist/SHA256SUMS
sha512sum "${asset_paths[@]}" > dist/SHA512SUMS
```

Publish both files as release assets.

Recommended filenames:

- `SHA256SUMS`
- `SHA512SUMS`

---

# Release publication

Prefer explicit API-driven release creation and upload logic for:

- Forgejo
- GitHub mirrors

This avoids brittle release-action assumptions and works better in self-hosted environments.

The Linux runner should usually orchestrate:

- release creation
- asset upload
- checksum upload
- mirror synchronization

---

# Suggested pipeline stages

Use only the stages the repository actually needs.

```text
lint
→ build
→ package
→ artifact-validation
→ runtime-validation
→ integration-testing
→ checksum-generation
→ release-publication
→ mirror-sync
```

Some repositories may only need:

```text
build
→ package
→ artifact-validation
→ checksum-generation
→ release-publication
```

That is fine.

Do not add fake complexity.

---

# Example target combinations

## Linux-only daemon

- Linux `.tar.gz`
- Linux `.deb`
- Linux `.rpm`

## Linux + FreeBSD service

- Linux `.tar.gz`
- Linux `.deb`
- Linux `.rpm`
- FreeBSD `.pkg`
- FreeBSD `.tar.gz`

## Cross-platform CLI

- Linux `.tar.gz`
- macOS universal `.pkg`
- Windows `.zip`

## Desktop application

- macOS universal `.dmg`
- Windows `.msi`
- Linux tarball or distro packages as appropriate

---

# Final policy summary

Use the runners according to what they really are.

- Linux labels are container environments on the Linux runner
- `macos-latest` is a native host runner label and should be preferred
- `freebsd` is a native host runner label and should be preferred
- Windows builds should be cross-built from the Linux runner by default
- macOS pipelines should always produce a signed, non-notarized universal `.pkg`
- macOS may additionally produce a signed, non-notarized universal `.dmg` when needed
- not every project needs every platform, package format, or stage

The point of CI is not to cosmetically compile software.

The point is to produce correct release artifacts and catch bad assumptions before users do.
