use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ssh_key::{LineEnding, PrivateKey};

use crate::config::{
    ConfigFile, validate_directory_security, validate_file_security, validate_path_has_no_symlinks,
};
use crate::error::{CentralSshError, Result};

const PRIVATE_KEY_FILENAME: &str = "id_ed25519";
const PUBLIC_KEY_FILENAME: &str = "id_ed25519.pub";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyBootstrapReport {
    pub created_user_dirs: usize,
    pub created_server_dirs: usize,
    pub created_private_keys: usize,
    pub created_public_keys: usize,
}

pub fn resolve_user_server_private_key_path(
    user_key_root: &Path,
    username: &str,
    server_name: &str,
    per_user_per_server: bool,
    enforce_strict_security: bool,
) -> Result<PathBuf> {
    validate_component(username, "username")?;
    validate_component(server_name, "server name")?;

    let user_dir = user_key_root.join(username);
    let key_dir = if per_user_per_server {
        user_dir.join(server_name)
    } else {
        user_dir.clone()
    };
    let private_key_path = key_dir.join(PRIVATE_KEY_FILENAME);

    if enforce_strict_security {
        validate_directory_security(user_key_root, 0o700, true)?;
        validate_directory_security(&user_dir, 0o700, true)?;
        if per_user_per_server {
            validate_directory_security(&key_dir, 0o700, true)?;
        }
        validate_file_security(&private_key_path, 0o600, true)?;
    } else {
        validate_existing_regular_directory(user_key_root)?;
        validate_existing_regular_directory(&user_dir)?;
        if per_user_per_server {
            validate_existing_regular_directory(&key_dir)?;
        }
        validate_existing_regular_file(&private_key_path)?;
    }

    Ok(private_key_path)
}

pub fn ensure_user_key_root_directory(user_key_root: &Path) -> Result<bool> {
    ensure_real_directory(user_key_root)
}

pub fn ensure_private_keys_for_config_users(
    user_key_root: &Path,
    config: &ConfigFile,
    per_user_per_server: bool,
) -> Result<KeyBootstrapReport> {
    let mut report = KeyBootstrapReport::default();

    ensure_real_directory(user_key_root)?;

    for user in &config.users {
        validate_component(&user.name, "username")?;
        let user_dir = user_key_root.join(&user.name);
        if ensure_real_directory(&user_dir)? {
            report.created_user_dirs += 1;
        }

        for server_name in &user.allowed_servers {
            validate_component(server_name, "server name")?;
            let key_dir = if per_user_per_server {
                let server_dir = user_dir.join(server_name);
                if ensure_real_directory(&server_dir)? {
                    report.created_server_dirs += 1;
                }
                server_dir
            } else {
                user_dir.clone()
            };

            let key_report = ensure_keypair_files(&key_dir)?;
            if key_report.created_private_key {
                report.created_private_keys += 1;
            }
            if key_report.created_public_key {
                report.created_public_keys += 1;
            }

            if !per_user_per_server {
                break;
            }
        }
    }

    Ok(report)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct KeypairFileReport {
    created_private_key: bool,
    created_public_key: bool,
}

fn validate_component(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 64 {
        return Err(CentralSshError::InvalidConfig(format!(
            "invalid {label}: length must be 1-64 characters"
        )));
    }

    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
    {
        return Err(CentralSshError::InvalidConfig(format!(
            "invalid {label}: only [a-zA-Z0-9._-] are allowed"
        )));
    }

    Ok(())
}

fn ensure_real_directory(path: &Path) -> Result<bool> {
    validate_path_has_no_symlinks(path)?;

    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(CentralSshError::SecurityPolicy {
                path: path.to_path_buf(),
                message: "expected a real directory".to_string(),
            });
        }
        return Ok(false);
    }

    if let Some(parent) = path.parent() {
        validate_path_has_no_symlinks(parent)?;
        fs::create_dir_all(parent)?;
    }

    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(true)
}

fn ensure_keypair_files(user_dir: &Path) -> Result<KeypairFileReport> {
    let private_key_path = user_dir.join(PRIVATE_KEY_FILENAME);
    let public_key_path = user_dir.join(PUBLIC_KEY_FILENAME);
    let mut private_key_created = false;

    validate_path_has_no_symlinks(&private_key_path)?;
    validate_path_has_no_symlinks(&public_key_path)?;

    let private_key = if private_key_path.exists() {
        validate_existing_regular_file(&private_key_path)?;
        ssh_key::private::PrivateKey::read_openssh_file(&private_key_path).map_err(|error| {
            CentralSshError::InvalidConfig(format!(
                "failed to load existing user private key '{}': {error}",
                private_key_path.display()
            ))
        })?
    } else {
        private_key_created = true;
        let private_key =
            PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
                .map_err(|error| {
                    CentralSshError::InvalidConfig(format!(
                        "failed to create user private key: {error}"
                    ))
                })?;
        let encoded = private_key.to_openssh(LineEnding::LF).map_err(|error| {
            CentralSshError::InvalidConfig(format!("failed to encode user private key: {error}"))
        })?;

        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&private_key_path)?;
        file.write_all(encoded.as_bytes())?;
        file.sync_all()?;
        fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600))?;
        private_key
    };

    let public_key_created = if public_key_path.exists() {
        validate_existing_regular_file(&public_key_path)?;
        false
    } else {
        let encoded = private_key.public_key().to_openssh().map_err(|error| {
            CentralSshError::InvalidConfig(format!("failed to encode user public key: {error}"))
        })?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o644)
            .open(&public_key_path)?;
        file.write_all(encoded.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::set_permissions(&public_key_path, fs::Permissions::from_mode(0o644))?;
        true
    };

    Ok(KeypairFileReport {
        created_private_key: private_key_created,
        created_public_key: public_key_created,
    })
}

fn validate_existing_regular_directory(path: &Path) -> Result<()> {
    validate_path_has_no_symlinks(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: "expected a real directory".to_string(),
        });
    }
    Ok(())
}

fn validate_existing_regular_file(path: &Path) -> Result<()> {
    validate_path_has_no_symlinks(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: "expected a real file".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::TempDir;

    use crate::config::{ConfigFile, KexPolicyConfig, SettingsConfig, UserRecord};

    fn valid_config() -> ConfigFile {
        ConfigFile {
            users: vec![UserRecord {
                name: "alice".to_string(),
                password: "BootstrapPass123!".to_string(),
                totp_secret: None,
                must_change_password: true,
                allowed_servers: vec!["git".to_string(), "httpd".to_string()],
            }],
            settings: SettingsConfig::default(),
            kex_policy: KexPolicyConfig::default(),
            fail2ban: None,
        }
    }

    fn canonical_tempdir_path(tempdir: &TempDir) -> PathBuf {
        fs::canonicalize(tempdir.path()).expect("canonicalize tempdir")
    }

    #[test]
    fn resolve_private_key_path_uses_user_and_server_directories() {
        let tempdir = TempDir::new().expect("tempdir");
        let base = fs::canonicalize(tempdir.path()).expect("canonicalize");
        let root = base.join("keys");
        let server_dir = root.join("alice/git");
        fs::create_dir_all(&server_dir).expect("mkdir");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("chmod root");
        fs::set_permissions(root.join("alice"), fs::Permissions::from_mode(0o700))
            .expect("chmod user");
        fs::set_permissions(&server_dir, fs::Permissions::from_mode(0o700)).expect("chmod server");
        let key = server_dir.join("id_ed25519");
        fs::write(&key, b"key").expect("write key");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("chmod key");

        let resolved = resolve_user_server_private_key_path(&root, "alice", "git", true, false)
            .expect("resolve");
        assert_eq!(resolved, key);
    }

    #[test]
    fn resolve_private_key_path_uses_user_directory_when_disabled() {
        let tempdir = TempDir::new().expect("tempdir");
        let base = fs::canonicalize(tempdir.path()).expect("canonicalize");
        let root = base.join("keys");
        let user_dir = root.join("alice");
        fs::create_dir_all(&user_dir).expect("mkdir");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("chmod root");
        fs::set_permissions(&user_dir, fs::Permissions::from_mode(0o700)).expect("chmod user");
        let key = user_dir.join("id_ed25519");
        fs::write(&key, b"key").expect("write key");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("chmod key");

        let resolved = resolve_user_server_private_key_path(&root, "alice", "git", false, false)
            .expect("resolve");
        assert_eq!(resolved, key);
    }

    #[test]
    fn resolve_private_key_path_rejects_symlink() {
        let tempdir = TempDir::new().expect("tempdir");
        let base = fs::canonicalize(tempdir.path()).expect("canonicalize");
        let root = base.join("keys");
        let server_dir = root.join("alice/git");
        fs::create_dir_all(&server_dir).expect("mkdir");
        let key = server_dir.join("id_ed25519");
        let real_key = base.join("real-key");
        fs::write(&real_key, b"key").expect("write");
        symlink(&real_key, &key).expect("symlink");

        let result = resolve_user_server_private_key_path(&root, "alice", "git", true, false);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_private_key_path_rejects_symlink_in_user_only_mode() {
        let tempdir = TempDir::new().expect("tempdir");
        let base = fs::canonicalize(tempdir.path()).expect("canonicalize");
        let root = base.join("keys");
        let user_dir = root.join("alice");
        fs::create_dir_all(&user_dir).expect("mkdir");
        let key = user_dir.join("id_ed25519");
        let real_key = base.join("real-key");
        fs::write(&real_key, b"key").expect("write");
        symlink(&real_key, &key).expect("symlink");

        let result = resolve_user_server_private_key_path(&root, "alice", "git", false, false);
        assert!(result.is_err());
    }

    #[test]
    fn ensure_private_keys_for_config_users_creates_missing_tree() {
        let tempdir = TempDir::new().expect("tempdir");
        let root = canonical_tempdir_path(&tempdir).join("keys");

        let report =
            ensure_private_keys_for_config_users(&root, &valid_config(), true).expect("ensure");

        assert_eq!(
            report,
            KeyBootstrapReport {
                created_user_dirs: 1,
                created_server_dirs: 2,
                created_private_keys: 2,
                created_public_keys: 2,
            }
        );
        assert!(root.join("alice/git/id_ed25519").is_file());
        assert!(root.join("alice/git/id_ed25519.pub").is_file());
        assert!(root.join("alice/httpd/id_ed25519").is_file());
        assert!(root.join("alice/httpd/id_ed25519.pub").is_file());
    }

    #[test]
    fn ensure_private_keys_for_config_users_creates_single_key_in_user_only_mode() {
        let tempdir = TempDir::new().expect("tempdir");
        let root = canonical_tempdir_path(&tempdir).join("keys");

        let report =
            ensure_private_keys_for_config_users(&root, &valid_config(), false).expect("ensure");

        assert_eq!(
            report,
            KeyBootstrapReport {
                created_user_dirs: 1,
                created_server_dirs: 0,
                created_private_keys: 1,
                created_public_keys: 1,
            }
        );
        assert!(root.join("alice/id_ed25519").is_file());
        assert!(root.join("alice/id_ed25519.pub").is_file());
    }

    #[test]
    fn ensure_private_keys_for_config_users_preserves_existing_keys() {
        let tempdir = TempDir::new().expect("tempdir");
        let root = canonical_tempdir_path(&tempdir).join("keys");
        let user_dir = root.join("alice");
        let server_dir = user_dir.join("git");
        fs::create_dir_all(&server_dir).expect("mkdir");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("chmod root");
        fs::set_permissions(&user_dir, fs::Permissions::from_mode(0o700)).expect("chmod user");
        fs::set_permissions(&server_dir, fs::Permissions::from_mode(0o700)).expect("chmod server");

        let private_key =
            PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
                .expect("private key");
        let existing_key = server_dir.join("id_ed25519");
        fs::write(
            &existing_key,
            private_key.to_openssh(LineEnding::LF).expect("encode key"),
        )
        .expect("write key");
        fs::set_permissions(&existing_key, fs::Permissions::from_mode(0o600)).expect("chmod key");

        let mut config = valid_config();
        config.users[0].allowed_servers = vec!["git".to_string()];

        let report = ensure_private_keys_for_config_users(&root, &config, true).expect("ensure");
        let contents = fs::read(&existing_key).expect("read key");
        let encoded_private_key = private_key
            .to_openssh(LineEnding::LF)
            .expect("encode compare");

        assert_eq!(report.created_server_dirs, 0);
        assert_eq!(report.created_private_keys, 0);
        assert_eq!(report.created_public_keys, 1);
        assert_eq!(contents, encoded_private_key.as_bytes());
        assert!(server_dir.join("id_ed25519.pub").is_file());
    }
}
