#[path = "src/version_support.rs"]
mod version_support;

use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/version_support.rs");
    println!("cargo:rerun-if-env-changed=CENTRALSSH_RELEASE_VERSION");
    println!("cargo:rerun-if-env-changed=CENTRALSSH_DIST_BUILD");
    println!("cargo:rerun-if-env-changed=CENTRALSSH_VERSION");
    println!("cargo:rerun-if-env-changed=CENTRALSSH_VERSION_SUFFIX");
    println!("cargo:rerun-if-env-changed=CI");

    let release_version = env::var("CENTRALSSH_RELEASE_VERSION")
        .or_else(|_| env::var("CENTRALSSH_VERSION"))
        .ok()
        .or_else(detect_git_tag_version)
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    let suffix = if dist_build_enabled() { "-dist" } else { "" };

    println!("cargo:rustc-env=CENTRALSSH_VERSION={release_version}");
    println!("cargo:rustc-env=CENTRALSSH_VERSION_SUFFIX={suffix}");
}

fn dist_build_enabled() -> bool {
    env_truthy(env::var_os("CENTRALSSH_DIST_BUILD"))
        || env_truthy(env::var_os("CI"))
}

fn env_truthy(value: Option<std::ffi::OsString>) -> bool {
    matches!(
        value.as_deref().and_then(|v| v.to_str()).map(str::trim).map(|v| v.to_ascii_lowercase()),
        Some(ref v) if matches!(v.as_str(), "1" | "true" | "yes" | "on")
    )
}

fn detect_git_tag_version() -> Option<String> {
    let output = Command::new("git")
        .args(["describe", "--tags", "--exact-match", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let tag = String::from_utf8(output.stdout).ok()?;
    version_support::normalize_release_tag(tag.trim()).ok()
}
