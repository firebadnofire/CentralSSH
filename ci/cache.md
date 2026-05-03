# CI Cache Layout

CentralSSH CI uses persistent caches to speed up package builds without changing the source-of-truth build flow.

## What Is Cached

- `CARGO_HOME/registry`: downloaded Cargo registry crates
- `CARGO_HOME/git`: Cargo git checkouts
- `SCCACHE_DIR`: Rust compiler object cache when `sccache` is available
- `CARGO_TARGET_DIR`: build outputs, keyed per job/platform/toolchain/profile/dependency state

If the preferred persistent cache root is mounted read-only or unavailable, the workflow falls back to a writable workspace-local cache directory so the build still succeeds.

Cold builds still run `cargo build --locked --release` directly. Release artifacts are always rebuilt in the job and then packaged from that fresh build.

## Cache Locations

Linux container job:

- Host-mounted `/data/cache/cargo` -> container `/cache/cargo-home`
- Host-mounted `/data/cache/sccache` -> container `/cache/sccache`
- Host-mounted `/data/cache/target/centralssh/linux` -> container `/cache/target`

FreeBSD job:

- Preferred host root: `/data/cache`
- Fallback host root when `/data/cache` is unavailable: `.ci-host-cache/`
- Workspace staging area shared with the VM action: `.ci-cache/freebsd/`
- Persistent VM subdirectories:
  - `.ci-cache/freebsd/cargo`
  - `.ci-cache/freebsd/rustup`
  - `.ci-cache/freebsd/target`
  - `.ci-cache/freebsd/sccache`
  - `.ci-cache/freebsd/pkg`

## Cache Keys

`ci/cache-env.sh` builds explicit target-cache and sccache paths from:

- repo slug
- job name
- OS name
- architecture
- `rustc` version
- `cargo` version
- target triple
- build profile
- hash of `Cargo.lock`, `Cargo.toml`, and `Makefile`
- `RUSTFLAGS`
- `CI_CARGO_FEATURES`
- `CI_CROSS_COMPILE`

Cargo registry and git caches stay under a shared `CARGO_HOME`, which is safe because those contents are immutable or content-addressed by Cargo.

The FreeBSD VM cache bucket is separated by a hash of `Cargo.lock`, `Cargo.toml`, and `Makefile`, so toolchains, package cache, Cargo downloads, and build outputs stay aligned with the dependency graph and packaging inputs.

## Clearing Caches

Delete only what you need:

- Full reset: remove `/data/cache/cargo`, `/data/cache/sccache`, and `/data/cache/target/centralssh`
- FreeBSD fallback reset: remove `.ci-host-cache/` and `.ci-cache/freebsd/`
- Single build state reset: remove the specific keyed directory printed as `CI_CACHE_KEY` in workflow logs

## Debugging

Workflow logs print:

- `rustc --version`
- `cargo --version`
- `CARGO_HOME`
- `CARGO_TARGET_DIR`
- `SCCACHE_DIR`
- `CI_CACHE_KEY`
- `CI_CACHE_ROOT`
- `sccache --show-stats` when available
- disk usage for registry, git, target, and sccache directories

## Caveats

- `sccache` installation is best-effort; the build continues if install fails.
- Target caches are job-local. Do not reuse Linux target caches for FreeBSD or other toolchains.
- No secrets are cached. SSH keys, API tokens, signing material, and `.env` data stay out of cache paths.
