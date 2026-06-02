use std::fs;
use std::path::PathBuf;
use std::process::Command;

use tempfile::tempdir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn script_path(name: &str) -> PathBuf {
    repo_root().join("ci").join(name)
}

fn run_sh(script: &PathBuf, envs: &[(&str, &str)], cwd: Option<&std::path::Path>) -> std::process::Output {
    let mut command = Command::new("sh");
    command.arg(script);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().expect("failed to run shell helper")
}

#[test]
fn release_version_script_accepts_valid_tag() {
    let output = run_sh(
        &script_path("release-version.sh"),
        &[("FORGEJO_REF_NAME", "v0.0.36")],
        Some(repo_root().as_path()),
    );
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).expect("release-version output is utf8");
    assert!(stdout.contains("RELEASE_VERSION=0.0.36"));
    assert!(stdout.contains("RELEASE_TAG=v0.0.36"));
}

#[test]
fn release_version_script_rejects_invalid_tag() {
    let output = run_sh(
        &script_path("release-version.sh"),
        &[("FORGEJO_REF_NAME", "not-a-tag")],
        Some(repo_root().as_path()),
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("release-version stderr is utf8");
    assert!(stderr.contains("release tag must start with v or V"));
}

#[test]
fn rewrite_helper_updates_manifest_and_lockfile() {
    let temp = tempdir().expect("tempdir");
    let cargo_toml = temp.path().join("Cargo.toml");
    let cargo_lock = temp.path().join("Cargo.lock");
    let src_dir = temp.path().join("src");
    let ci_dir = temp.path().join("ci");
    fs::create_dir_all(&src_dir).expect("create src dir");
    fs::create_dir_all(&ci_dir).expect("create ci dir");
    fs::copy(script_path("release-version.sh"), ci_dir.join("release-version.sh"))
        .expect("copy release-version.sh");
    fs::copy(
        script_path("rewrite-release-version.sh"),
        ci_dir.join("rewrite-release-version.sh"),
    )
    .expect("copy rewrite-release-version.sh");

    fs::write(
        &cargo_toml,
        r#"[package]
name = "centralssh"
version = "0.0.0-dev"
edition = "2024"

[dependencies]
"#,
    )
    .expect("write Cargo.toml");
    fs::write(src_dir.join("main.rs"), "fn main() {}\n").expect("write src/main.rs");
    fs::write(&cargo_lock, "").expect("write Cargo.lock");

    let output = run_sh(
        &script_path("rewrite-release-version.sh"),
        &[("FORGEJO_REF_NAME", "v0.0.36"), ("REPO_ROOT", temp.path().to_str().expect("temp path"))],
        Some(temp.path()),
    );
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let manifest = fs::read_to_string(&cargo_toml).expect("read rewritten Cargo.toml");
    assert!(manifest.contains("version = \"0.0.36\""));
    assert!(!manifest.contains("version = \"0.0.0-dev\""));

    let lockfile = fs::read_to_string(&cargo_lock).expect("read rewritten Cargo.lock");
    assert!(lockfile.contains("name = \"centralssh\""));
    assert!(lockfile.contains("version = \"0.0.36\""));
}

#[test]
fn runtime_version_output_matches_binary() {
    let expected = format!(
        "centralssh {}{}",
        env!("CENTRALSSH_VERSION"),
        env!("CENTRALSSH_VERSION_SUFFIX")
    );
    let binary = env!("CARGO_BIN_EXE_centralssh");

    for flag in ["--version", "-v"] {
        let output = Command::new(binary)
            .arg(flag)
            .output()
            .expect("run centralssh");
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let stdout = String::from_utf8(output.stdout).expect("version output is utf8");
        assert_eq!(stdout.trim(), expected);
    }
}
